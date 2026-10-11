"""
Unit and integration tests for Strategy A (VLAN 10 Management ➔ UniFi Default VLAN 1)
and WAN/VPN exclusion from LAN VLAN lists.
"""

import sys
import os
import asyncio
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.models import (
    UniFiSourceState,
    UniFiTargetConfig,
    UniFiNetwork,
    UniFiFixedIp,
    UniFiWlan,
    UniFiFirewallRule,
)
from src.gui.app import (
    process_xml,
    state,
    get_unifi_config_dict,
    apply_strategy_a_api,
    set_management_network_api,
    remap_network_api,
    update_network_api,
)
from src.translator.merger import MultiSourceMerger


class MockRequest:
    def __init__(self, json_data=None):
        self._json = json_data or {}

    async def json(self):
        return self._json


def test_wan_and_vpn_excluded_from_lan_vlans():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(process_xml(xml_data))
    assert res.status_code == 200

    # Mock UCG state with WAN1, WAN2 and VPN network (RoadWorrior)
    ucg_state = UniFiSourceState(
        source_type="ucg_max",
        host="192.168.1.1",
        version="4.0.6",
        networks=[
            {"name": "Primary (WAN1)", "purpose": "wan", "vlan": None},
            {"name": "Secondary (WAN2)", "purpose": "wan", "vlan": None},
            {"name": "Default", "purpose": "corporate", "vlan": 1, "ip_subnet": "192.168.1.1/24"},
            {"name": "RoadWorrior", "purpose": "vpn", "ip_subnet": "192.168.90.1/24"},
            {"name": "UCG_IOT_EXTRA", "purpose": "corporate", "vlan": 66, "ip_subnet": "192.168.66.1/24"},
        ],
    )
    state.ucg_state = ucg_state

    merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state)
    state.reconciliation_report = merger.reconcile()

    unifi_dict = get_unifi_config_dict()
    target_net_names = [n["name"] for n in unifi_dict["networks"]]

    # Verify that WAN1, WAN2 and RoadWorrior are NOT added to LAN networks
    assert "Primary (WAN1)" not in target_net_names
    assert "Secondary (WAN2)" not in target_net_names
    assert "RoadWorrior" not in target_net_names

    # But regular UCG network (UCG_IOT_EXTRA) is preserved
    assert "UCG_IOT_EXTRA" in target_net_names

    # Check that in ucg_networks list, is_wan and is_vpn flags are properly set
    ucg_nets = unifi_dict.get("ucg_networks", [])
    wan1 = next((n for n in ucg_nets if n["name"] == "Primary (WAN1)"), None)
    assert wan1 is not None
    assert wan1["is_wan"] is True
    assert wan1["vlan_id"] is None

    vpn_net = next((n for n in ucg_nets if n["name"] == "RoadWorrior"), None)
    assert vpn_net is not None
    assert vpn_net["is_vpn"] is True
    assert vpn_net["vlan_id"] is None


def test_apply_strategy_a_automatic_cascade():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(process_xml(xml_data))

    # In sample_opnsense_26_7_5.xml:
    # opt1 is SERVERS with vlan0.10 (192.168.10.1/24)
    # Let's ensure one network has name "management" or VLAN 10
    vlan10_net = next((n for n in state.unifi_cfg.networks if n.vlan_id == 10), None)
    assert vlan10_net is not None
    vlan10_net.name = "management"

    # Add a fixed IP and WLAN on VLAN 10 to test cascading
    state.unifi_cfg.fixed_ips.append(
        UniFiFixedIp(mac="aa:bb:cc:dd:ee:01", name="Switch-Core-16", fixed_ip="192.168.10.2", network_name="management")
    )
    state.unifi_cfg.wlans.append(
        UniFiWlan(name="Mgmt-Tech-SSID", vlan_id=10)
    )
    state.unifi_cfg.firewall_rules.append(
        UniFiFirewallRule(name="Allow Admin Access to VLAN 10", ruleset="LAN_IN", action="accept", rule_index=3500)
    )

    # Apply Strategy A via API
    res = loop.run_until_complete(apply_strategy_a_api(MockRequest()))
    assert res.status_code == 200
    res_data = json.loads(res.body.decode("utf-8"))
    assert res_data["success"] is True

    unifi_dict = get_unifi_config_dict()
    nets = unifi_dict["networks"]

    # 1. VLAN 1 must exist, be named Management (Default) and have CIDR 192.168.10.1/24
    vlan1 = next((n for n in nets if n["vlan_id"] == 1), None)
    assert vlan1 is not None
    assert "Management" in vlan1["name"]
    assert vlan1["gateway_cidr"] == "192.168.10.1/24"
    assert vlan1["is_management"] is True

    # 2. Old separate VLAN 10 must be gone (merged into VLAN 1)
    assert not any(n["vlan_id"] == 10 for n in nets)

    # 3. Fixed IP must now be bound to the new network name
    fip = next((f for f in unifi_dict["fixed_ips"] if f["mac"] == "aa:bb:cc:dd:ee:01"), None)
    assert fip is not None
    assert fip["network_name"] == vlan1["name"]

    # 4. WLAN must now be on VLAN 1
    wlan = next((w for w in unifi_dict["wlans"] if w["name"] == "Mgmt-Tech-SSID"), None)
    assert wlan is not None
    assert wlan["vlan_id"] == 1

    # 5. Rule name must have been updated to VLAN 1
    rule = next((r for r in unifi_dict["firewall_rules"] if r["rule_index"] == 3500), None)
    assert rule is not None
    assert "VLAN 1" in rule["name"]


def test_set_management_network_api():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(process_xml(xml_data))

    # Set VLAN 20 as Management network
    res = loop.run_until_complete(set_management_network_api(MockRequest({"vlan_id": 20})))
    assert res.status_code == 200
    res_data = json.loads(res.body.decode("utf-8"))
    assert res_data["success"] is True

    unifi_dict = get_unifi_config_dict()
    vlan20 = next((n for n in unifi_dict["networks"] if n["vlan_id"] == 20), None)
    assert vlan20 is not None
    assert vlan20["is_management"] is True

    vlan1 = next((n for n in unifi_dict["networks"] if n["vlan_id"] == 1), None)
    assert vlan1 is not None
    assert vlan1["is_management"] is False


def test_update_network_is_management_toggle():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(process_xml(xml_data))

    # Find network with VLAN 10
    vlan10_idx = next(i for i, n in enumerate(state.unifi_cfg.networks) if n.vlan_id == 10)
    vlan10_net = state.unifi_cfg.networks[vlan10_idx]

    # 1. Update network to set is_management = True (Strategy A auto-merge into VLAN 1)
    payload_set = {
        "index": vlan10_idx,
        "network": {
            "name": vlan10_net.name,
            "vlan_id": vlan10_net.vlan_id,
            "gateway_cidr": vlan10_net.gateway_cidr,
            "dhcp_enabled": vlan10_net.dhcp_enabled,
            "dhcp_start": vlan10_net.dhcp_start,
            "dhcp_stop": vlan10_net.dhcp_stop,
            "purpose": vlan10_net.purpose,
            "domain_name": vlan10_net.domain_name,
            "is_management": True,
        },
    }
    res = loop.run_until_complete(update_network_api(MockRequest(payload_set)))
    assert res.status_code == 200
    res_data = json.loads(res.body.decode("utf-8"))
    assert res_data["success"] is True

    # VLAN 1 should now be management
    vlan1 = next((n for n in state.unifi_cfg.networks if n.vlan_id == 1), None)
    assert vlan1 is not None
    assert vlan1.is_management is True

    # 2. Update network to uncheck is_management (0 management networks)
    vlan1_idx = next(i for i, n in enumerate(state.unifi_cfg.networks) if n.vlan_id == 1)
    payload_unset = {
        "index": vlan1_idx,
        "network": {
            "name": vlan1.name,
            "vlan_id": vlan1.vlan_id,
            "gateway_cidr": vlan1.gateway_cidr,
            "dhcp_enabled": vlan1.dhcp_enabled,
            "dhcp_start": vlan1.dhcp_start,
            "dhcp_stop": vlan1.dhcp_stop,
            "purpose": vlan1.purpose,
            "domain_name": vlan1.domain_name,
            "is_management": False,
        },
    }
    res2 = loop.run_until_complete(update_network_api(MockRequest(payload_unset)))
    assert res2.status_code == 200
    res_data2 = json.loads(res2.body.decode("utf-8"))
    assert res_data2["success"] is True

    # Now NO network has is_management == True (0 selected)
    assert not any(n.is_management for n in state.unifi_cfg.networks)

