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


if __name__ == "__main__":
    test_core_flow()
    test_upload_export_and_unify_apis()
