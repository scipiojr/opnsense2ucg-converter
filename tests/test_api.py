"""
Integration tests for Migrator endpoints and backend state.
"""

import sys
import os
import asyncio
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gui.app import process_xml, state, get_unifi_config_dict
from src.llm.engine import LLMTranslationEngine
from src.unifi.client import UniFiGatewayClient


def test_core_flow():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    # 1. Process XML via async handler
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response = loop.run_until_complete(process_xml(xml_data))

    assert response.status_code == 200
    res_json = json.loads(response.body.decode("utf-8"))
    assert res_json["success"] is True
    assert res_json["summary"]["version"] == "26.7.5"
    assert res_json["summary"]["interfaces_count"] == 6
    assert res_json["summary"]["omitted_count"] >= 2
    assert len(res_json["summary"]["omitted_items"]) >= 2

    # 2. Test Sanitization
    sanitized_xml = state.vault.sanitize_xml(xml_data)
    assert "$2y$10$" not in sanitized_xml
    assert "203.0.113.85" not in sanitized_xml
    audit = state.vault.get_audit_summary()
    assert len(audit) > 0

    # 3. Test Prompt Generation
    data_for_llm = {
        "interfaces": [{"name": i.descr, "vlan": i.vlan_tag, "ip": i.ipaddr} for i in state.opnsense_cfg.interfaces],
        "rules": [{"id": r.id, "iface": r.interface, "action": r.action} for r in state.opnsense_cfg.filter_rules],
    }
    sanitized_dict = state.vault.sanitize_dict(data_for_llm)
    engine = LLMTranslationEngine(state.vault)
    prompt = engine.generate_prompt(sanitized_dict)
    assert "CRITICAL PARADIGM DIFFERENCES" in prompt

    # 4. Test UniFi Target Config
    unifi_dict = get_unifi_config_dict()
    assert len(unifi_dict["networks"]) == 5
    assert len(unifi_dict["fixed_ips"]) == 8
    assert len(unifi_dict["firewall_rules"]) > 0

    # 5. Test Dry-Run on Client
    client = UniFiGatewayClient(host="192.168.1.1", username="admin", password="password")
    report = client.dry_run(state.unifi_cfg)
    assert report["dry_run"] is True
    assert len(report["networks_to_create"]) == 5
    assert len(report["fixed_ips_to_assign"]) == 8
    assert len(report["omitted_items"]) >= 2
    initial_rule_count = len(report["firewall_rules_to_create"])

    # 6. Test Single Rule LLM Assist & Adaptation
    sample_rule = state.unifi_cfg.firewall_rules[2]
    rule_dict = {
        "rule_index": sample_rule.rule_index,
        "name": sample_rule.name,
        "ruleset": sample_rule.ruleset,
        "action": sample_rule.action,
        "protocol": sample_rule.protocol,
        "src_addr": sample_rule.src_address,
        "dst_addr": sample_rule.dst_address,
        "dst_port": sample_rule.dst_port,
    }
    llm_res = engine.assist_single_rule(
        rule_data=rule_dict,
        instruction="Schränke diese Regel auf Web-Traffic TCP Port 80 und 443 ein",
        provider="local",
    )
    assert llm_res["success"] is True
    assert llm_res["updated_rule"]["dst_port"] == "80,443"
    assert "explanation" in llm_res

    # Apply adaptation
    sample_rule.dst_port = "80,443"
    sample_rule.status = "modified"

    # 7. Test Discarding a Rule
    discard_target = state.unifi_cfg.firewall_rules[0]
    discard_target.status = "discarded"
    discard_target.enabled = False

    report_after_discard = client.dry_run(state.unifi_cfg)
    assert len(report_after_discard["firewall_rules_to_create"]) == initial_rule_count - 1

    print("SUCCESS: Core workflow, state tests, and interactive rule management tests passed cleanly!")


def test_upload_export_and_unify_apis():
    from src.gui.app import upload_export_file_api, unify_all_api, export_unified_json_api
    from src.unifi.export_parser import UNIFI_AES_KEY, UNIFI_AES_IV
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from starlette.requests import Request
    import zipfile
    import io

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    class MockRequest:
        def __init__(self, json_data=None, form_data=None, headers=None):
            self._json = json_data or {}
            self._form = form_data or {}
            self.headers = headers or {}

        async def json(self):
            return self._json

        async def form(self):
            return self._form

    # 1. Test invalid / corrupt file upload
    bad_req = MockRequest(json_data={
        "source_type": "uos_server",
        "filename": "corrupt_data.unf",
        "content": "not_valid_at_all_garbage_12345"
    })
    res_bad = loop.run_until_complete(upload_export_file_api(bad_req))
    assert res_bad.status_code == 200
    res_bad_data = json.loads(res_bad.body.decode("utf-8"))
    assert res_bad_data["success"] is False
    assert "Fehler bei der Verarbeitung" in res_bad_data["error"]

    # 2. Test valid UCG JSON export upload
    ucg_req = MockRequest(json_data={
        "source_type": "ucg_max",
        "filename": "ucg_backup.json",
        "content": json.dumps({
            "networks": [{"name": "UCG_CAMERAS", "vlan": 40, "ip_subnet": "192.168.40.1/24"}]
        })
    })
    res_ucg = loop.run_until_complete(upload_export_file_api(ucg_req))
    assert res_ucg.status_code == 200
    res_ucg_data = json.loads(res_ucg.body.decode("utf-8"))
    assert res_ucg_data["success"] is True
    assert res_ucg_data["sources_status"]["ucg_loaded"] is True

    # 3. Test encrypted UOS .unf upload via base64
    uos_data = {
        "wlans": [{"name": "UOS-Secret-WiFi", "security": "wpapsk", "x_passphrase": "pass", "vlan": 40}]
    }
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("settings.json", json.dumps(uos_data))
    zb = zbuf.getvalue()
    pad = 16 - (len(zb) % 16)
    padded = zb + (b"\x00" * pad)
    c = Cipher(algorithms.AES(UNIFI_AES_KEY), modes.CBC(UNIFI_AES_IV))
    enc = c.encryptor()
    encrypted_unf = enc.update(padded) + enc.finalize()

    import base64
    uos_req = MockRequest(json_data={
        "source_type": "uos_server",
        "filename": "uos_server.unf",
        "base64": base64.b64encode(encrypted_unf).decode("ascii")
    })
    res_uos = loop.run_until_complete(upload_export_file_api(uos_req))
    assert res_uos.status_code == 200
    res_uos_data = json.loads(res_uos.body.decode("utf-8"))
    assert res_uos_data["success"] is True
    assert res_uos_data["sources_status"]["uos_loaded"] is True

    # 4. Test unify_all_api
    unify_req = MockRequest()
    res_unify = loop.run_until_complete(unify_all_api(unify_req))
    assert res_unify.status_code == 200
    res_unify_data = json.loads(res_unify.body.decode("utf-8"))
    assert res_unify_data["success"] is True
    assert res_unify_data["summary"]["total_networks"] >= 6  # OPNsense + UCG
    assert res_unify_data["summary"]["total_wlans"] >= 1

    # 5. Test export_unified_json_api
    export_req = MockRequest()
    res_export = loop.run_until_complete(export_unified_json_api(export_req))
    assert res_export.status_code == 200
    assert "attachment; filename=unifi_unified_config.json" in res_export.headers["Content-Disposition"]
    cfg_data = json.loads(res_export.body.decode("utf-8"))
    assert len(cfg_data["networks"]) >= 6

    print("SUCCESS: upload_export_file_api, unify_all_api, and export_unified_json_api tests passed cleanly!")


def test_network_and_fixed_ip_editing():
    from src.gui.app import (
        update_network_api,
        add_network_api,
        delete_network_api,
        update_fixed_ip_api,
        add_fixed_ip_api,
        delete_fixed_ip_api,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    class MockRequest:
        def __init__(self, json_data):
            self._json = json_data

        async def json(self):
            return self._json

    # 1. Test update_network_api (adapt VLAN ID, CIDR, and IP range)
    init_net_count = len(state.unifi_cfg.networks)
    upd_req = MockRequest({
        "index": 1,
        "network": {
            "name": "CUSTOM_OFFICE_NET",
            "vlan_id": 42,
            "gateway_cidr": "192.168.42.1/24",
            "dhcp_enabled": True,
            "dhcp_start": "192.168.42.20",
            "dhcp_stop": "192.168.42.220",
            "purpose": "corporate",
            "domain_name": "office.internal"
        }
    })
    res_upd = loop.run_until_complete(update_network_api(upd_req))
    assert res_upd.status_code == 200
    res_data = json.loads(res_upd.body.decode("utf-8"))
    assert res_data["success"] is True

    updated_net = state.unifi_cfg.networks[1]
    assert updated_net.name == "CUSTOM_OFFICE_NET"
    assert updated_net.vlan_id == 42
    assert updated_net.gateway_cidr == "192.168.42.1/24"
    assert updated_net.dhcp_start == "192.168.42.20"
    assert updated_net.dhcp_stop == "192.168.42.220"

    # 2. Test add_network_api and delete_network_api
    add_req = MockRequest({
        "network": {
            "name": "DMZ_VLAN",
            "vlan_id": 999,
            "gateway_cidr": "10.99.99.1/24",
            "dhcp_enabled": False,
        }
    })
    res_add = loop.run_until_complete(add_network_api(add_req))
    assert res_add.status_code == 200
    assert len(state.unifi_cfg.networks) == init_net_count + 1

    del_req = MockRequest({"index": len(state.unifi_cfg.networks) - 1})
    res_del = loop.run_until_complete(delete_network_api(del_req))
    assert res_del.status_code == 200
    assert len(state.unifi_cfg.networks) == init_net_count

    # 3. Test update_fixed_ip_api (adapt MAC and IP)
    init_fip_count = len(state.unifi_cfg.fixed_ips)
    assert init_fip_count > 0

    fip_upd_req = MockRequest({
        "index": 0,
        "fixed_ip": {
            "mac": "aa:bb:cc:11:22:33",
            "name": "Custom-NAS-Modified",
            "fixed_ip": "192.168.42.55",
            "network_name": "CUSTOM_OFFICE_NET"
        }
    })
    res_fip = loop.run_until_complete(update_fixed_ip_api(fip_upd_req))
    assert res_fip.status_code == 200
    res_fip_data = json.loads(res_fip.body.decode("utf-8"))
    assert res_fip_data["success"] is True

    target_fip = state.unifi_cfg.fixed_ips[0]
    assert target_fip.mac == "aa:bb:cc:11:22:33"
    assert target_fip.name == "Custom-NAS-Modified"
    assert target_fip.fixed_ip == "192.168.42.55"
    assert target_fip.network_name == "CUSTOM_OFFICE_NET"

    # 4. Test add_fixed_ip_api and delete_fixed_ip_api
    add_fip_req = MockRequest({
        "fixed_ip": {
            "mac": "de:ad:be:ef:00:01",
            "name": "Smart-TV-LivingRoom",
            "fixed_ip": "192.168.42.100",
            "network_name": "CUSTOM_OFFICE_NET"
        }
    })
    res_add_fip = loop.run_until_complete(add_fixed_ip_api(add_fip_req))
    assert res_add_fip.status_code == 200
    assert len(state.unifi_cfg.fixed_ips) == init_fip_count + 1

    del_fip_req = MockRequest({"index": len(state.unifi_cfg.fixed_ips) - 1})
    res_del_fip = loop.run_until_complete(delete_fixed_ip_api(del_fip_req))
    assert res_del_fip.status_code == 200
    assert len(state.unifi_cfg.fixed_ips) == init_fip_count

    print("SUCCESS: Network & Fixed IP customization tests (VLAN ID, CIDR, DHCP Range, MAC, IP) passed cleanly!")


def test_unifi_config_dict_fallback_and_uos_safety():
    state.reset()
    assert state.unifi_cfg is None

    # 1. Uninitialized state should still return full schema, never empty dict
    cfg_dict = get_unifi_config_dict()
    assert isinstance(cfg_dict, dict)
    for key in ["networks", "fixed_ips", "firewall_rules", "firewall_groups", "port_forwards", "dns_records", "wlans"]:
        assert key in cfg_dict, f"Key '{key}' must be present in unifi config dict"
        assert isinstance(cfg_dict[key], list), f"Value for '{key}' must be a list"

    # 2. When only UOS is loaded, wlans should be populated and networks should be safe list
    from src.models import UniFiSourceState, UniFiWlan
    mock_uos = UniFiSourceState(source_type="uos_server")
    mock_uos.wlans = [UniFiWlan(name="Home-WLAN", security="wpapsk", vlan_id=10)]
    mock_uos.clients = [{"mac": "11:22:33:44:55:66", "name": "Printer", "fixed_ip": "192.168.1.50", "use_fixedip": True}]
    state.uos_state = mock_uos

    cfg_dict2 = get_unifi_config_dict()
    assert isinstance(cfg_dict2["networks"], list)
    assert len(cfg_dict2["networks"]) == 0
    assert len(cfg_dict2["wlans"]) == 1
    assert cfg_dict2["wlans"][0]["name"] == "Home-WLAN"
    assert len(cfg_dict2["fixed_ips"]) == 1
    assert cfg_dict2["fixed_ips"][0]["mac"] == "11:22:33:44:55:66"

    print("SUCCESS: Defensive UniFi config fallback & UOS schema safety tests passed cleanly!")


def test_vlan_remapping_and_wlan_crud():
    state.reset()
    from src.translator.remapper import remap_ip_address, VlanRemapper
    from src.gui.app import (
        add_wlan_api,
        update_wlan_api,
        delete_wlan_api,
        remap_network_api,
        remap_preview_api,
    )
    from src.models import UniFiTargetConfig, UniFiNetwork, UniFiFixedIp, UniFiWlan, UniFiFirewallRule

    class MockRequest:
        def __init__(self, json_data):
            self._json = json_data

        async def json(self):
            return self._json

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 1. Pure IP / Subnet remapping calculations
    # Host IP shift
    assert remap_ip_address("192.168.99.55", "192.168.99.0/24", "192.168.90.0/24") == "192.168.90.55"
    assert remap_ip_address("192.168.99.1", "192.168.99.1/24", "192.168.90.1/24") == "192.168.90.1"
    # Network CIDR shift
    assert remap_ip_address("192.168.99.0/24", "192.168.99.0/24", "192.168.90.0/24") == "192.168.90.0/24"
    # Unrelated IP stays untouched
    assert remap_ip_address("10.0.0.1", "192.168.99.0/24", "192.168.90.0/24") == "10.0.0.1"

    # 2. Test VlanRemapper.remap cascading changes
    cfg = UniFiTargetConfig()
    cfg.networks = [
        UniFiNetwork(name="LAN", vlan_id=20, gateway_cidr="192.168.99.1/24", dhcp_start="192.168.99.10", dhcp_stop="192.168.99.250")
    ]
    cfg.fixed_ips = [
        UniFiFixedIp(name="NAS-Server", mac="11:22:33:44:55:aa", fixed_ip="192.168.99.55", network_name="LAN")
    ]
    cfg.wlans = [
        UniFiWlan(name="Office-WiFi", security="wpapsk", vlan_id=20)
    ]
    cfg.firewall_rules = [
        UniFiFirewallRule(rule_index=2001, name="Allow-LAN-to-NAS", ruleset="LAN_IN", action="accept", protocol="all",
                          src_address="192.168.99.0/24", dst_address="192.168.99.55")
    ]

    res = VlanRemapper.remap(
        cfg,
        source_vlan=20,
        target_vlan=90,
        source_cidr="192.168.99.1/24",
        target_cidr="192.168.90.1/24",
        target_name="LAN-Office",
        remap_clients=True,
        remap_wlans=True,
        remap_rules=True
    )

    assert res["success"] is True
    assert res["clients_remapped"] == 1
    assert res["wlans_remapped"] == 1
    assert res["rules_remapped"] == 1

    # Verify cascading objects
    assert cfg.networks[0].vlan_id == 90
    assert cfg.networks[0].gateway_cidr == "192.168.90.1/24"
    assert cfg.networks[0].name == "LAN-Office"
    assert cfg.networks[0].dhcp_start == "192.168.90.10"
    assert cfg.networks[0].dhcp_stop == "192.168.90.250"

    assert cfg.fixed_ips[0].fixed_ip == "192.168.90.55"
    assert cfg.fixed_ips[0].network_name == "LAN-Office"

    assert cfg.wlans[0].vlan_id == 90

    assert cfg.firewall_rules[0].src_address == "192.168.90.0/24"
    assert cfg.firewall_rules[0].dst_address == "192.168.90.55"

    # 3. Test Preview & Remap APIs
    state.unifi_cfg = cfg

    # 3a. Preview API
    prev_req = MockRequest({
        "source_vlan_id": 90,
        "new_vlan_id": 95,
        "new_gateway_cidr": "192.168.95.1/24",
        "new_name": "LAN-Migrated",
        "remap_clients": True,
        "remap_wlans": True,
        "remap_rules": True
    })
    prev_res = loop.run_until_complete(remap_preview_api(prev_req))
    assert prev_res.status_code == 200
    prev_data = json.loads(prev_res.body.decode("utf-8"))
    assert prev_data["success"] is True
    assert prev_data["preview"]["clients_count"] == 1
    assert prev_data["preview"]["wlans_count"] == 1
    assert prev_data["preview"]["rules_count"] == 1
    assert prev_data["preview"]["client_diffs"][0]["new_ip"] == "192.168.95.55"

    # 3b. Execute Remap API
    exec_req = MockRequest({
        "source_vlan_id": 90,
        "new_vlan_id": 95,
        "new_gateway_cidr": "192.168.95.1/24",
        "new_name": "LAN-Migrated",
        "remap_clients": True,
        "remap_wlans": True,
        "remap_rules": True
    })
    exec_res = loop.run_until_complete(remap_network_api(exec_req))
    assert exec_res.status_code == 200
    exec_data = json.loads(exec_res.body.decode("utf-8"))
    assert exec_data["success"] is True
    assert cfg.networks[0].vlan_id == 95
    assert cfg.fixed_ips[0].fixed_ip == "192.168.95.55"
    assert cfg.wlans[0].vlan_id == 95

    # 4. Test Wi-Fi WLAN CRUD APIs
    # Add new WLAN
    add_wlan_req = MockRequest({
        "wlan": {
            "name": "Guest-Hotspot",
            "vlan_id": 95,
            "security": "wpapsk",
            "passphrase": "GuestPassword123",
            "is_guest": True,
            "enabled": True
        }
    })
    add_wlan_res = loop.run_until_complete(add_wlan_api(add_wlan_req))
    assert add_wlan_res.status_code == 200
    assert len(cfg.wlans) == 2
    assert cfg.wlans[1].name == "Guest-Hotspot"
    assert cfg.wlans[1].is_guest is True

    # Update WLAN VLAN
    upd_wlan_req = MockRequest({
        "index": 1,
        "wlan": {
            "name": "Guest-Hotspot-V2",
            "vlan_id": 100,
            "security": "wpapsk",
            "passphrase": "GuestPassword123",
            "is_guest": True,
            "enabled": True
        }
    })
    upd_wlan_res = loop.run_until_complete(update_wlan_api(upd_wlan_req))
    assert upd_wlan_res.status_code == 200
    assert cfg.wlans[1].name == "Guest-Hotspot-V2"
    assert cfg.wlans[1].vlan_id == 100

    # Delete WLAN
    del_wlan_req = MockRequest({"index": 1})
    del_wlan_res = loop.run_until_complete(delete_wlan_api(del_wlan_req))
    assert del_wlan_res.status_code == 200
    assert len(cfg.wlans) == 1

    print("SUCCESS: VLAN remapping cascading migration & WLAN CRUD tests passed cleanly!")


def test_opnsense_live_fetch():
    from unittest.mock import patch, MagicMock
    from src.opnsense.client import OPNsenseClient
    from src.gui.app import fetch_opnsense_live_api

    class MockRequest:
        def __init__(self, json_data=None):
            self._json = json_data or {}
        async def json(self):
            return self._json

    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    # 1. Test OPNsenseClient initialization & URL cleaning
    client = OPNsenseClient(host="https://192.168.1.1:8443/", api_key="testkey", api_secret="testsecret", auth_mode="api")
    assert client.host == "192.168.1.1"
    assert client.port == 8443
    assert client.auth_mode == "api"

    # 2. Test successful fetch_config_xml via REST API Basic Auth
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = xml_data

    with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
        fetched_xml = client.fetch_config_xml()
        assert fetched_xml == xml_data
        assert mock_get.called
        args, kwargs = mock_get.call_args
        assert kwargs["auth"] == ("testkey", "testsecret")

    # 3. Test successful fetch_config_xml via Web GUI Session Login
    web_client = OPNsenseClient(host="192.168.1.1", username="root", password="mypassword", auth_mode="web")
    assert web_client.auth_mode == "web"

    # Mock requests.Session for Web GUI Login:
    # 1st get: /index.php (login page)
    # 2nd post: /index.php (submit credentials)
    # 3rd post: /diag_backup.php (download config)
    mock_login_page_resp = MagicMock()
    mock_login_page_resp.status_code = 200
    mock_login_page_resp.text = '<html><form id="iform"><input name="usernamefld"><input name="passwordfld"></form></html>'
    mock_login_page_resp.history = []

    mock_login_post_resp = MagicMock()
    mock_login_post_resp.status_code = 200
    mock_login_post_resp.text = '<html><body class="page-logged-in"><nav>Dashboard</nav></body></html>'

    mock_backup_dl_resp = MagicMock()
    mock_backup_dl_resp.status_code = 200
    mock_backup_dl_resp.text = xml_data

    with patch("requests.Session") as MockSessionClass:
        mock_sess = MockSessionClass.return_value
        # 1st get: /index.php, 2nd get: /diag_backup.php with LegacyCSRF tokens
        mock_diag_get_resp = MagicMock()
        mock_diag_get_resp.status_code = 200
        mock_diag_get_resp.text = '<html><head><script>xhr.setRequestHeader("X-CSRFToken", "mock_csrf_val_123");</script></head><body><form method="post"><input type="hidden" name="mock_csrf_key_abc" value="mock_csrf_val_123" autocomplete="new-password" /></form></body></html>'

        mock_sess.get.side_effect = [mock_login_page_resp, mock_diag_get_resp]
        mock_sess.post.side_effect = [mock_login_post_resp, mock_backup_dl_resp]
        mock_sess.cookies = {}

        fetched_web_xml = web_client.fetch_config_xml()
        assert fetched_web_xml == xml_data
        assert mock_sess.post.call_count >= 2

        # Verify POST /diag_backup.php received CSRF token and header
        dl_post_call = mock_sess.post.call_args_list[-1]
        assert dl_post_call.kwargs["headers"].get("X-CSRFToken") == "mock_csrf_val_123"
        assert dl_post_call.kwargs["data"].get("mock_csrf_key_abc") == "mock_csrf_val_123"

    # 4. Test failure with 401 raises ConnectionError with helpful guidance
    err_resp = MagicMock()
    err_resp.status_code = 401
    err_resp.text = "Unauthorized"
    bad_client = OPNsenseClient(host="192.168.1.1", api_key="wrong", api_secret="wrong", auth_mode="api")
    with patch.object(bad_client.session, "get", return_value=err_resp):
        try:
            bad_client.fetch_config_xml()
            assert False, "Should have raised ConnectionError"
        except ConnectionError as ce:
            assert "401" in str(ce)
            assert "Web-GUI Login" in str(ce)

    # 5. Test fetch_opnsense_live_api endpoint with hint on failure
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    with patch("src.gui.app.OPNsenseClient") as MockCls:
        instance = MockCls.return_value
        instance.fetch_config_xml.return_value = xml_data

        req = MockRequest({
            "host": "192.168.10.1",
            "port": 443,
            "auth_mode": "web",
            "username": "root",
            "password": "secretpassword"
        })
        api_res = loop.run_until_complete(fetch_opnsense_live_api(req))
        assert api_res.status_code == 200
        data = json.loads(api_res.body.decode("utf-8"))
        assert data["success"] is True
        assert data["source"] == "opnsense"
        assert data["host"] == "192.168.10.1"
        assert data["summary"]["version"] == "26.7.5"
        assert data["summary"]["interfaces_count"] == 6
        assert state.opnsense_cfg is not None
        assert state.unifi_cfg is not None

    # 6. Test fetch_opnsense_live_api error returns hint
    with patch("src.gui.app.OPNsenseClient") as MockCls:
        instance = MockCls.return_value
        instance.fetch_config_xml.side_effect = ConnectionError("HTTP 401 Unauthorized")

        bad_req = MockRequest({
            "host": "192.168.10.1",
            "port": 443,
            "auth_mode": "api",
            "api_key": "wrong",
            "api_secret": "wrong"
        })
        bad_api_res = loop.run_until_complete(fetch_opnsense_live_api(bad_req))
        assert bad_api_res.status_code == 200
        bad_data = json.loads(bad_api_res.body.decode("utf-8"))
        assert bad_data["success"] is False
        assert "401" in bad_data["error"]
        assert len(bad_data["hint"]) > 0

    print("SUCCESS: OPNsense live fetch (Web-GUI form login & REST API) tests passed cleanly!")


def _exclusion_fixture_cfg():
    from src.models import (UniFiTargetConfig, UniFiNetwork, UniFiFixedIp, UniFiWlan, UniFiFirewallRule,
                            UniFiFirewallGroup, UniFiPortForward, UniFiDnsRecord)
    cfg = UniFiTargetConfig()
    cfg.networks = [
        UniFiNetwork(name="LAN", vlan_id=20, gateway_cidr="192.168.99.1/24"),
        UniFiNetwork(name="IOT", vlan_id=30, gateway_cidr="192.168.30.1/24"),
    ]
    cfg.fixed_ips = [
        UniFiFixedIp(mac="aa:aa:aa:aa:aa:01", name="NAS", fixed_ip="192.168.99.10", network_name="LAN"),
        UniFiFixedIp(mac="aa:aa:aa:aa:aa:02", name="Printer", fixed_ip="192.168.99.20", network_name="LAN"),
        UniFiFixedIp(mac="aa:aa:aa:aa:aa:03", name="Bulb", fixed_ip="192.168.30.20", network_name="IOT"),
    ]
    cfg.wlans = [UniFiWlan(name="Home", vlan_id=20), UniFiWlan(name="IoT-WiFi", vlan_id=30)]
    cfg.firewall_groups = [
        UniFiFirewallGroup(name="LAN_SERVERS", group_type="address-group", members=["192.168.99.10"]),
        UniFiFirewallGroup(name="MIXED", group_type="address-group", members=["192.168.99.20", "192.168.30.20"]),
    ]
    cfg.firewall_rules = [
        UniFiFirewallRule(name="LAN to NAS", ruleset="LAN_IN", action="accept", rule_index=2000,
                          src_address="192.168.99.0/24", dst_address="192.168.99.10"),
        UniFiFirewallRule(name="IOT block", ruleset="LAN_IN", action="drop", rule_index=2001,
                          src_address="192.168.30.0/24"),
        UniFiFirewallRule(name="Servers group", ruleset="LAN_IN", action="accept", rule_index=2002,
                          dst_firewall_group_names=["LAN_SERVERS"]),
    ]
    cfg.port_forwards = [UniFiPortForward(name="NAS-HTTPS", fwd_ip="192.168.99.10", fwd_port="443", dst_port="8443", protocol="tcp")]
    cfg.dns_records = [UniFiDnsRecord(key="nas.home.arpa", value="192.168.99.10")]
    return cfg


def test_migration_exclusions_engine():
    from src.translator.exclusions import ExclusionEngine

    # 1. Network cascade: everything depending on LAN disappears
    cfg = _exclusion_fixture_cfg()
    excl = [{"item_id": "network:20", "strategy": "cascade"}]
    plan = ExclusionEngine.build_plan(cfg, excl)
    eff = ExclusionEngine.effective_config(cfg, plan)
    assert [n.name for n in eff.networks] == ["IOT"]
    assert [f.name for f in eff.fixed_ips] == ["Bulb"]
    assert [w.name for w in eff.wlans] == ["IoT-WiFi"]
    assert [r.rule_index for r in eff.firewall_rules] == [2001]          # 2000 by address, 2002 via emptied group
    assert [g.name for g in eff.firewall_groups] == ["MIXED"]
    assert eff.firewall_groups[0].members == ["192.168.30.20"]
    assert eff.port_forwards == [] and eff.dns_records == []
    assert any("Port-Weiterleitung" in c["message"] for c in plan.consequences)
    # Non-destructive: original untouched
    assert len(cfg.networks) == 2 and len(cfg.fixed_ips) == 3

    # 2. Network reassign: dependents move to IOT with preserved host offsets
    excl = [{"item_id": "network:20", "strategy": "reassign", "target_vlan": 30}]
    eff = ExclusionEngine.effective_config(cfg, ExclusionEngine.build_plan(cfg, excl))
    assert [n.name for n in eff.networks] == ["IOT"]
    ips = {f.name: (f.fixed_ip, f.network_name) for f in eff.fixed_ips}
    assert ips["NAS"] == ("192.168.30.10", "IOT")
    # Printer .20 collides with Bulb .20 -> reservation dropped with warning
    assert "Printer" not in ips
    assert next(w for w in eff.wlans if w.name == "Home").vlan_id == 30
    assert eff.port_forwards[0].fwd_ip == "192.168.30.10"
    assert eff.dns_records[0].value == "192.168.30.10"
    r2000 = next(r for r in eff.firewall_rules if r.rule_index == 2000)
    assert r2000.src_address == "192.168.30.0/24" and r2000.dst_address == "192.168.30.10"

    # 3. Reassign onto an excluded network falls back to cascade with warning
    excl = [{"item_id": "network:30", "strategy": "cascade"},
            {"item_id": "network:20", "strategy": "reassign", "target_vlan": 30}]
    plan = ExclusionEngine.build_plan(cfg, excl)
    eff = ExclusionEngine.effective_config(cfg, plan)
    assert eff.networks == [] and eff.fixed_ips == []
    assert any("Umzuordnung" in c["message"] for c in plan.consequences)

    # 4. Client cascade vs keep
    excl = [{"item_id": "client:aa:aa:aa:aa:aa:01", "strategy": "cascade"}]
    eff = ExclusionEngine.effective_config(cfg, ExclusionEngine.build_plan(cfg, excl))
    assert "NAS" not in [f.name for f in eff.fixed_ips]
    assert eff.port_forwards == [] and eff.dns_records == []
    assert 2000 not in [r.rule_index for r in eff.firewall_rules]       # dst == NAS ip
    assert 2002 not in [r.rule_index for r in eff.firewall_rules]       # group LAN_SERVERS emptied

    excl = [{"item_id": "client:aa:aa:aa:aa:aa:01", "strategy": "keep"}]
    plan = ExclusionEngine.build_plan(cfg, excl)
    eff = ExclusionEngine.effective_config(cfg, plan)
    assert "NAS" not in [f.name for f in eff.fixed_ips]
    assert len(eff.port_forwards) == 1 and len(eff.dns_records) == 1
    assert sum(1 for c in plan.consequences if c["severity"] == "warning") >= 3

    # 5. Client name restore + WLAN skip
    excl = [{"item_id": "client_name:aa:aa:aa:aa:aa:02", "strategy": "restore", "original_name": "printer-hp"},
            {"item_id": "wlan:Home", "strategy": "skip"}]
    eff = ExclusionEngine.effective_config(cfg, ExclusionEngine.build_plan(cfg, excl))
    assert next(f for f in eff.fixed_ips if f.mac.endswith("02")).name == "printer-hp"
    assert [w.name for w in eff.wlans] == ["IoT-WiFi"]

    # 6. Impact dry-run lists affected dependents
    imp = ExclusionEngine.impact(cfg, [], {"item_id": "network:20", "strategy": "cascade"})
    assert len(imp["affected"]["fixed_ips"]) == 2
    assert "port_forwards" in imp["affected"] and "wlans" in imp["affected"]

    print("SUCCESS: Migration exclusion engine (cascade / reassign / keep / restore) tests passed cleanly!")


def test_migration_exclusions_api():
    from src.gui.app import (exclusion_impact_api, exclude_item_api, include_item_api,
                             export_unified_json_api, unify_all_api)
    from src.models import UniFiSourceState, UniFiWlan

    class MockRequest:
        def __init__(self, json_data=None):
            self._json = json_data or {}

        async def json(self):
            return self._json

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    run = lambda coro: json.loads(loop.run_until_complete(coro).body.decode("utf-8"))

    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        loop.run_until_complete(process_xml(f.read()))
    uos = UniFiSourceState(source_type="uos_server")
    uos.wlans = [UniFiWlan(name="Legacy-SSID", vlan_id=None)]
    state.uos_state = uos
    run(unify_all_api(MockRequest()))

    net = state.unifi_cfg.networks[0]
    item_id = f"network:{net.vlan_id}"
    n_before = len(state.unifi_cfg.networks)

    # Impact preview
    imp = run(exclusion_impact_api(MockRequest({"item_id": item_id, "strategy": "cascade"})))
    assert imp["success"] is True
    assert {s["id"] for s in imp["strategies"]} == {"cascade", "reassign"}
    assert all(t["vlan_id"] != net.vlan_id for t in imp["reassign_targets"])

    # Invalid strategy rejected
    bad = run(exclude_item_api(MockRequest({"item_id": item_id, "strategy": "keep"})))
    assert bad["success"] is False

    # Exclude network + WLAN
    res = run(exclude_item_api(MockRequest({"item_id": item_id, "strategy": "cascade"})))
    assert res["success"] is True
    res = run(exclude_item_api(MockRequest({"item_id": "wlan:Legacy-SSID", "strategy": "skip"})))
    rows = [i for i in res["reconciliation"]["items"] if i["status"] == "excluded"]
    assert {r["item_id"] for r in rows} == {item_id, "wlan:Legacy-SSID"}
    # Review keeps all rows (stable indices) but annotates them
    assert len(res["unifi_mapped"]["networks"]) == n_before
    assert res["unifi_mapped"]["networks"][0]["migration"]["action"] == "excluded"

    # Export contains effective config only
    exported = json.loads(loop.run_until_complete(export_unified_json_api(MockRequest())).body.decode("utf-8"))
    assert len(exported["networks"]) == n_before - 1
    assert "Legacy-SSID" not in [w["name"] for w in exported["wlans"]]
    assert len(exported["excluded_from_migration"]["items"]) == 2

    # Exclusions survive a full re-merge
    res = run(unify_all_api(MockRequest()))
    assert sum(1 for i in res["reconciliation"]["items"] if i["status"] == "excluded") == 2

    # Undo
    res = run(include_item_api(MockRequest({"item_id": item_id})))
    assert res["success"] is True
    exported = json.loads(loop.run_until_complete(export_unified_json_api(MockRequest())).body.decode("utf-8"))
    assert len(exported["networks"]) == n_before
    assert run(include_item_api(MockRequest({"item_id": item_id})))["success"] is False

    print("SUCCESS: Migration exclusion API (impact, exclude, export, re-merge, undo) tests passed cleanly!")


def test_edit_item_and_bulk_resolve_api():
    from src.gui.app import edit_item_api, bulk_resolve_api, unify_all_api
    from src.models import UniFiSourceState

    class MockRequest:
        def __init__(self, json_data=None):
            self._json = json_data or {}

        async def json(self):
            return self._json

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    run = lambda coro: json.loads(loop.run_until_complete(coro).body.decode("utf-8"))

    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        loop.run_until_complete(process_xml(f.read()))

    # Verify initial dynamic_dns and static_routes loaded
    assert len(state.unifi_cfg.dynamic_dns) > 0
    assert len(state.unifi_cfg.static_routes) > 0

    # 1. Test edit_item_api on DynDNS
    ddns_res = run(edit_item_api(MockRequest({
        "category": "dyndns",
        "item_id": "dyndns:remote.home.arpa",
        "updates": {
            "service": "strato",
            "host_name": "home.strato-domain.de",
            "login": "strato-user-123"
        }
    })))
    assert ddns_res["success"] is True
    found_ddns = [d for d in state.unifi_cfg.dynamic_dns if d.host_name == "home.strato-domain.de"]
    assert len(found_ddns) == 1
    assert found_ddns[0].service == "strato"
    assert found_ddns[0].login == "strato-user-123"

    # 2. Test edit_item_api on Static Route
    route_res = run(edit_item_api(MockRequest({
        "category": "route",
        "item_id": "route:10.200.0.0/16",
        "updates": {
            "name": "Updated Branch Route",
            "next_hop": "192.168.1.250",
            "distance": 3
        }
    })))
    assert route_res["success"] is True
    found_route = [r for r in state.unifi_cfg.static_routes if r.network == "10.200.0.0/16"]
    assert len(found_route) == 1
    assert found_route[0].name == "Updated Branch Route"
    assert found_route[0].next_hop == "192.168.1.250"
    assert found_route[0].distance == 3

    # 3. Simulate conflicting UCG state and test bulk_resolve_api
    ucg = UniFiSourceState(source_type="ucg_max")
    ucg.networks = [{
        "name": "CAMERAS",
        "vlan": 30,
        "ip_subnet": "10.99.30.1/24"  # Conflict with OPNsense 192.168.30.1/24
    }]
    state.ucg_state = ucg
    run(unify_all_api(MockRequest()))

    # Check if reconciliation items exist
    assert state.reconciliation_report is not None
    assert len(state.reconciliation_report.items) > 0
    # Bulk resolve with opnsense_wins
    bulk_res_opn = run(bulk_resolve_api(MockRequest({"strategy": "opnsense_wins"})))
    assert bulk_res_opn["success"] is True
    assert bulk_res_opn["conflict_priority"] == "opnsense"
    assert bulk_res_opn["resolved_count"] >= 1

    # Bulk resolve with preserve_ucg
    bulk_res_ucg = run(bulk_resolve_api(MockRequest({"strategy": "preserve_ucg"})))
    assert bulk_res_ucg["success"] is True
    assert bulk_res_ucg["conflict_priority"] == "ucg"

    # Bulk resolve with uos / preserve_uos
    bulk_res_uos = run(bulk_resolve_api(MockRequest({"strategy": "uos"})))
    assert bulk_res_uos["success"] is True
    assert bulk_res_uos["conflict_priority"] == "uos"

    # Reset to manual
    bulk_res_man = run(bulk_resolve_api(MockRequest({"strategy": "manual"})))
    assert bulk_res_man["success"] is True
    assert bulk_res_man["conflict_priority"] == "manual"

    print("SUCCESS: edit_item_api and bulk_resolve_api tests passed cleanly!")


if __name__ == "__main__":
    test_core_flow()
    test_upload_export_and_unify_apis()
    test_network_and_fixed_ip_editing()
    test_unifi_config_dict_fallback_and_uos_safety()
    test_vlan_remapping_and_wlan_crud()
    test_opnsense_live_fetch()
    test_migration_exclusions_engine()
    test_migration_exclusions_api()
    test_edit_item_and_bulk_resolve_api()

