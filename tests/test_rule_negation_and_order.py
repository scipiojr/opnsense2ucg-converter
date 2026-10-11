"""
Tests for firewall rule negation (source, destination, rule-level)
and rule evaluation ordering / GUI editor operations.
"""

import os
import sys
import json
import asyncio
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.models import (
    OPNsenseConfig,
    OPNsenseFilterRule,
    OPNsenseInterface,
    UniFiTargetConfig,
    UniFiFirewallRule,
)
from src.opnsense.parser import OPNsenseParser
from src.translator.mapper import UniFiMapper
from src.unifi.client import UniFiGatewayClient
from src.gui.app import (
    state,
    process_xml,
    get_unifi_config_dict,
    update_rule_api,
    reorder_rules_api,
)


class MockRequest:
    def __init__(self, json_data):
        self._json = json_data

    async def json(self):
        return self._json


def test_parse_negated_rules_xml():
    xml_data = """<?xml version="1.0"?>
    <opnsense>
      <version>26.7.5</version>
      <interfaces>
        <lan>
          <enable>1</enable>
          <if>igb0</if>
          <ipaddr>192.168.1.1</ipaddr>
          <subnet>24</subnet>
          <descr>LAN</descr>
        </lan>
        <opt1>
          <enable>1</enable>
          <if>igb1</if>
          <ipaddr>192.168.10.1</ipaddr>
          <subnet>24</subnet>
          <descr>SERVERS</descr>
        </opt1>
      </interfaces>
      <filter>
        <!-- Rule 1: Normal rule -->
        <rule>
          <type>pass</type>
          <interface>lan</interface>
          <protocol>tcp</protocol>
          <source>
            <network>lan</network>
          </source>
          <destination>
            <network>any</network>
          </destination>
          <descr>Allow LAN TCP</descr>
        </rule>
        <!-- Rule 2: Negated destination (<not/>) e.g. Allow LAN to NOT RFC1918 (Internet only) -->
        <rule>
          <type>pass</type>
          <interface>lan</interface>
          <protocol>any</protocol>
          <source>
            <network>lan</network>
          </source>
          <destination>
            <address>RFC1918</address>
            <not/>
          </destination>
          <descr>Allow LAN to NOT RFC1918</descr>
        </rule>
        <!-- Rule 3: Negated source (<not>1</not>) -->
        <rule>
          <type>block</type>
          <interface>opt1</interface>
          <protocol>any</protocol>
          <source>
            <network>192.168.10.50</network>
            <not>1</not>
          </source>
          <destination>
            <network>any</network>
          </destination>
          <descr>Block everyone except trusted admin host</descr>
        </rule>
        <!-- Rule 4: Negated rule action (<invert>yes</invert>) -->
        <rule>
          <type>pass</type>
          <interface>lan</interface>
          <protocol>udp</protocol>
          <source>
            <network>lan</network>
          </source>
          <destination>
            <network>any</network>
          </destination>
          <descr>Rule with inverted logic</descr>
          <invert>yes</invert>
        </rule>
        <!-- Rule 5: Floating rule -->
        <rule>
          <floating>yes</floating>
          <direction>out</direction>
          <interface>wan</interface>
          <type>block</type>
          <protocol>tcp</protocol>
          <source>
            <network>any</network>
          </source>
          <destination>
            <network>any</network>
            <port>25</port>
          </destination>
          <descr>Block Outbound SMTP</descr>
          <quick>yes</quick>
        </rule>
      </filter>
    </opnsense>
    """
    parser = OPNsenseParser(xml_data)
    cfg = parser.parse()

    rules = cfg.filter_rules
    assert len(rules) == 5

    # Rule 1: Not negated
    assert rules[0].src_inverted is False
    assert rules[0].dst_inverted is False
    assert rules[0].rule_inverted is False

    # Rule 2: Destination negated
    assert rules[1].src_inverted is False
    assert rules[1].dst_inverted is True
    assert rules[1].rule_inverted is False

    # Rule 3: Source negated
    assert rules[2].src_inverted is True
    assert rules[2].dst_inverted is False
    assert rules[2].rule_inverted is False

    # Rule 4: Rule inverted
    assert rules[3].rule_inverted is True

    # Rule 5: Floating
    assert rules[4].is_floating is True


def test_mapper_preserves_negation_and_orders_floating_first():
    xml_data = """<?xml version="1.0"?>
    <opnsense>
      <version>26.7.5</version>
      <interfaces>
        <lan>
          <enable>1</enable>
          <if>igb0</if>
          <ipaddr>192.168.1.1</ipaddr>
          <subnet>24</subnet>
          <descr>LAN</descr>
        </lan>
      </interfaces>
      <filter>
        <rule>
          <type>pass</type>
          <interface>lan</interface>
          <protocol>tcp</protocol>
          <source>
            <network>lan</network>
          </source>
          <destination>
            <network>any</network>
          </destination>
          <descr>LAN Rule 1</descr>
        </rule>
        <rule>
          <type>pass</type>
          <interface>lan</interface>
          <protocol>any</protocol>
          <source>
            <network>lan</network>
          </source>
          <destination>
            <network>RFC1918</network>
            <not/>
          </destination>
          <descr>LAN Rule 2 NOT RFC1918</descr>
        </rule>
        <rule>
          <floating>yes</floating>
          <direction>out</direction>
          <interface>wan</interface>
          <type>block</type>
          <protocol>tcp</protocol>
          <source>
            <network>any</network>
          </source>
          <destination>
            <network>any</network>
            <port>25</port>
          </destination>
          <descr>Floating Outbound SMTP</descr>
          <quick>yes</quick>
        </rule>
      </filter>
    </opnsense>
    """
    parser = OPNsenseParser(xml_data)
    opn_cfg = parser.parse()

    mapper = UniFiMapper(opn_cfg)
    unifi_cfg = mapper.map_all()

    # Verify that floating rule was ordered before interface rules
    user_rules = [r for r in unifi_cfg.firewall_rules if "OPNsense" in r.origin]
    assert len(user_rules) == 3

    # First user rule should be the Floating rule because floating rules have higher precedence
    assert "[Floating]" in user_rules[0].name
    assert user_rules[0].ruleset == "WAN_OUT"
    assert user_rules[0].action == "drop"

    # Second rule should be LAN Rule 1
    assert "LAN Rule 1" in user_rules[1].name
    assert user_rules[1].src_inverted is False
    assert user_rules[1].dst_inverted is False

    # Third rule should be LAN Rule 2 with dst_inverted=True
    assert "LAN Rule 2 NOT RFC1918" in user_rules[2].name
    assert user_rules[2].dst_inverted is True
    assert "!Ziel" in user_rules[2].description

    # Ensure rule indices are strictly ascending
    indices = [r.rule_index for r in unifi_cfg.firewall_rules]
    assert indices == sorted(indices)


def test_unifi_client_payload_opposite_flags():
    client = UniFiGatewayClient(host="192.168.1.1", username="admin", password="password")

    rule_with_negation = UniFiFirewallRule(
        name="Allow to Non-RFC1918",
        ruleset="LAN_IN",
        action="accept",
        rule_index=2005,
        protocol="all",
        src_address="192.168.1.0/24",
        dst_address="10.0.0.0/8",
        src_inverted=True,
        dst_inverted=True,
    )

    # Mock session
    captured_payload = {}

    def mock_post(url, json=None, timeout=10):
        nonlocal captured_payload
        captured_payload = json
        class MockResp:
            status_code = 200
            def json(self):
                return {"data": [{"_id": "rule_123"}]}
        return MockResp()

    client.session.post = mock_post
    client.logged_in = True

    client._create_firewall_rule(rule_with_negation, {})

    assert captured_payload.get("src_address_match_opposite") is True
    assert captured_payload.get("dst_address_match_opposite") is True
    assert captured_payload.get("src_firewallgroup_match_opposite") is True
    assert captured_payload.get("dst_firewallgroup_match_opposite") is True


def test_api_update_rule_negation_and_index():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(process_xml(xml_data))
    assert res.status_code == 200

    target_rule = state.unifi_cfg.firewall_rules[2]
    original_idx = target_rule.rule_index

    # Update negation flags and change index
    update_payload = {
        "rule_index": original_idx,
        "name": "Updated IoT Rule with NOT Dest",
        "src_inverted": True,
        "dst_inverted": True,
        "rule_inverted": False,
        "new_index": 2010,
    }
    req = MockRequest(update_payload)
    up_res = loop.run_until_complete(update_rule_api(req))
    assert up_res.status_code == 200
    res_data = json.loads(up_res.body.decode("utf-8"))
    assert res_data["success"] is True

    # Verify updated rule in state
    found_rule = next((r for r in state.unifi_cfg.firewall_rules if r.name == "Updated IoT Rule with NOT Dest"), None)
    assert found_rule is not None
    assert found_rule.src_inverted is True
    assert found_rule.dst_inverted is True
    assert found_rule.rule_index == 2010

    # Verify serialized dict has these properties
    unifi_dict = get_unifi_config_dict()
    rule_dict = next((r for r in unifi_dict["firewall_rules"] if r["name"] == "Updated IoT Rule with NOT Dest"), None)
    assert rule_dict is not None
    assert rule_dict["src_inverted"] is True
    assert rule_dict["dst_inverted"] is True


def test_api_reorder_rules():
    state.reset()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(process_xml(xml_data))
    assert res.status_code == 200

    rule_a = state.unifi_cfg.firewall_rules[1]
    rule_b = state.unifi_cfg.firewall_rules[2]
    name_a = rule_a.name
    name_b = rule_b.name
    idx_a = rule_a.rule_index
    idx_b = rule_b.rule_index

    # Move rule_b UP
    reorder_payload = {
        "rule_index": idx_b,
        "direction": "up",
    }
    req = MockRequest(reorder_payload)
    reorder_res = loop.run_until_complete(reorder_rules_api(req))
    assert reorder_res.status_code == 200

    # Rule B should now be at position 1 with the lower index
    new_rule_at_1 = state.unifi_cfg.firewall_rules[1]
    new_rule_at_2 = state.unifi_cfg.firewall_rules[2]
    assert new_rule_at_1.name == name_b
    assert new_rule_at_2.name == name_a
    assert new_rule_at_1.rule_index == idx_a
    assert new_rule_at_2.rule_index == idx_b
