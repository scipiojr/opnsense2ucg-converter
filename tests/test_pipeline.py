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
    assert len(opn_cfg.filter_rules) == 7, f"Expected 7 filter rules, got {len(opn_cfg.filter_rules)}"
    floating_opn = next((r for r in opn_cfg.filter_rules if r.is_floating), None)
    assert floating_opn is not None, "Floating rule should be parsed"
    assert floating_opn.direction == "out"
    assert len(opn_cfg.omitted_items) >= 2, f"Expected at least 2 omitted items, got {len(opn_cfg.omitted_items)}"
    omitted_cats = [o.category for o in opn_cfg.omitted_items]
    assert "VPN" in omitted_cats
    assert "Plugins" in omitted_cats

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

    # Check that floating rule mapped to WAN_OUT
    floating_unifi = next((r for r in unifi_cfg.firewall_rules if "[Floating]" in r.name), None)
    assert floating_unifi is not None, "Floating rule should map to UniFi rule"
    assert floating_unifi.ruleset == "WAN_OUT"
    assert floating_unifi.action == "drop"
    assert floating_unifi.dst_port == "25"

    print("SUCCESS: All unit tests passed!")


def test_vdsl_modem_management_migration():
    """
    Tests detection and migration of a VDSL modem (e.g. DrayTek Vigor)
    connected via dual interface / VLAN as discussed in OPNsense forum.
    """
    xml_with_modem = """<?xml version="1.0"?>
    <opnsense>
      <version>26.7.5</version>
      <interfaces>
        <wan>
          <enable>1</enable>
          <if>vlan0.7</if>
          <descr>WAN_VDSL_TELEKOM</descr>
          <ipaddr>pppoe</ipaddr>
        </wan>
        <lan>
          <enable>1</enable>
          <if>igb0</if>
          <descr>LAN_CORP</descr>
          <ipaddr>192.168.1.1</ipaddr>
          <subnet>24</subnet>
        </lan>
        <opt1>
          <enable>1</enable>
          <if>igb1</if>
          <descr>DrayTek Vigor 165 Modem</descr>
          <ipaddr>192.168.2.2</ipaddr>
          <subnet>24</subnet>
          <gateway>192.168.2.1</gateway>
        </opt1>
      </interfaces>
      <vlans>
        <vlan>
          <if>igb1</if>
          <tag>7</tag>
          <vlanif>vlan0.7</vlanif>
          <descr>Telekom Internet VLAN</descr>
        </vlan>
      </vlans>
    </opnsense>
    """
    parser = OPNsenseParser(xml_with_modem)
    opn_cfg = parser.parse()

    # 1. Verify parser detected the modem connection
    assert opn_cfg.modem_management is not None
    assert opn_cfg.modem_management.detected is True
    assert opn_cfg.modem_management.parent_if == "igb1"
    assert opn_cfg.modem_management.modem_ip == "192.168.2.1"
    assert opn_cfg.modem_management.gateway_ip == "192.168.2.2"
    assert opn_cfg.modem_management.allocated_vlan == 99

    # Check omitted items contains hardware guidance
    modem_omitted = next((o for o in opn_cfg.omitted_items if "VDSL-Modem" in o.name), None)
    assert modem_omitted is not None
    assert "VLAN 99" in modem_omitted.recommendation

    # 2. Verify UniFi Mapper creates dedicated network & pinhole rule
    mapper = UniFiMapper(opn_cfg)
    unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)

    # Dedicated network
    modem_net = next((n for n in unifi_cfg.networks if n.vlan_id == 99), None)
    assert modem_net is not None
    assert modem_net.gateway_cidr == "192.168.2.2/24"
    assert modem_net.dhcp_enabled is False
    assert "Modem" in modem_net.name

    # Pinhole firewall rule
    pinhole_rule = next((r for r in unifi_cfg.firewall_rules if "Modem WebUI" in r.name), None)
    assert pinhole_rule is not None
    assert pinhole_rule.action == "accept"
    assert pinhole_rule.ruleset == "LAN_IN"
    assert pinhole_rule.dst_address == "192.168.2.1"
    assert pinhole_rule.dst_port == "80,443"

    # Inter-VLAN Block rule must have a higher index (execute AFTER the pinhole)
    inter_vlan_rule = next((r for r in unifi_cfg.firewall_rules if "Inter-VLAN" in r.name), None)
    assert inter_vlan_rule is not None
    assert inter_vlan_rule.rule_index > pinhole_rule.rule_index

    # 3. Test programmatic helper function add_modem_management_network
    added = mapper.add_modem_management_network(unifi_cfg, vlan_id=99)
    assert added.vlan_id == 99


if __name__ == "__main__":
    test_parser_and_mapper()
    test_vdsl_modem_management_migration()
