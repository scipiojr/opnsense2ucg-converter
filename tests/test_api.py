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
    assert res_json["summary"]["omitted_count"] >= 3
    assert len(res_json["summary"]["omitted_items"]) >= 3

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
    assert len(report["omitted_items"]) >= 3

    print("SUCCESS: Core workflow and state tests passed cleanly!")


if __name__ == "__main__":
    test_core_flow()
