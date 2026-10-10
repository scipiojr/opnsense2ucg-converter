"""
Unit tests for OPNsense parser, sanitizer vault, and UniFi mapper.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.opnsense.parser import OPNsenseParser
from src.sanitizer.masker import SanitizerVault
from src.translator.mapper import UniFiMapper


def test_parser_and_mapper():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    # 1. Test Parser
    parser = OPNsenseParser(xml_data)
    opn_cfg = parser.parse()

    assert opn_cfg.version == "26.7.5", f"Expected version 26.7.5, got {opn_cfg.version}"
    assert len(opn_cfg.interfaces) == 6, f"Expected 6 interfaces, got {len(opn_cfg.interfaces)}"
    assert len(opn_cfg.static_leases) == 8, f"Expected 8 leases, got {len(opn_cfg.static_leases)}"
    assert len(opn_cfg.aliases) == 5, f"Expected 5 aliases, got {len(opn_cfg.aliases)}"
    assert len(opn_cfg.port_forwards) == 2, f"Expected 2 port forwards, got {len(opn_cfg.port_forwards)}"
    assert len(opn_cfg.filter_rules) == 6, f"Expected 6 filter rules, got {len(opn_cfg.filter_rules)}"
    assert len(opn_cfg.omitted_items) >= 3, f"Expected at least 3 omitted items, got {len(opn_cfg.omitted_items)}"
    omitted_cats = [o.category for o in opn_cfg.omitted_items]
    assert "VPN" in omitted_cats
    assert "Alias" in omitted_cats
    assert "DNS" in omitted_cats

    # 2. Test Sanitizer
    vault = SanitizerVault(anonymize_macs=False)
    sanitized_xml = vault.sanitize_xml(xml_data)

    # Ensure passwords and public WAN IP are scrubbed
    assert "$2y$10$" not in sanitized_xml
    assert "203.0.113.85" not in sanitized_xml
    assert "__SECRET_PASS_001__" in sanitized_xml
    assert "__PUB_IP_001__" in sanitized_xml

    # Test Rehydration
    rehydrated_xml = vault.rehydrate_str(sanitized_xml)
    assert "$2y$10$" in rehydrated_xml
    assert "203.0.113.85" in rehydrated_xml

    # 3. Test UniFi Mapper
    mapper = UniFiMapper(opn_cfg)
    unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)

    # Check Networks
    assert len(unifi_cfg.networks) == 5, f"Expected 5 corporate VLANs, got {len(unifi_cfg.networks)}"
    net_names = [n.name for n in unifi_cfg.networks]
    assert "MANAGEMENT" in net_names
    assert "SERVERS" in net_names
    assert "IOT_SMARTHOME" in net_names

    # Check Fixed IPs
    assert len(unifi_cfg.fixed_ips) == 8

    # Check Firewall Groups
    group_names = [g.name for g in unifi_cfg.firewall_groups]
    assert "RFC1918_Private_Subnets" in group_names
    assert "DNS_SERVERS" in group_names
    assert "WEB_PORTS" in group_names

    # Check Inter-VLAN Drop rule
    inter_vlan_rule = next((r for r in unifi_cfg.firewall_rules if "Inter-VLAN" in r.name), None)
    assert inter_vlan_rule is not None
    assert inter_vlan_rule.action == "drop"
    assert inter_vlan_rule.ruleset == "LAN_IN"

    print("SUCCESS: All unit tests passed!")


if __name__ == "__main__":
    test_parser_and_mapper()
