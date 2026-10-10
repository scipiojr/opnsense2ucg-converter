"""
Unit and integration tests for MultiSourceMerger (3-Way Reconciliation: OPNsense + UCG-Max + UOS Server).
"""

import sys
import os
import asyncio
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.models import (
    UniFiSourceState,
    UniFiWlan,
    UniFiDevice,
    UniFiTargetConfig,
    UniFiNetwork,
    UniFiFixedIp,
)
from src.gui.app import process_xml, state, get_unifi_config_dict
from src.translator.merger import MultiSourceMerger


def test_three_way_reconciliation():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    # 1. Parse OPNsense config
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(process_xml(xml_data))
    assert res.status_code == 200

    # 2. Mock UCG-Max Live State (Existing partially configured gateway)
    # VLAN 10 exists and matches
    # VLAN 30 exists but has conflicting subnet
    # VLAN 88 is a UCG-only network
    ucg_state = UniFiSourceState(
        source_type="ucg_max",
        host="192.168.1.1",
        version="4.0.6",
        networks=[
            {"name": "OFFICE_MGMT", "vlan": 10, "ip_subnet": "192.168.10.1/24"},
            {"name": "CAMERAS", "vlan": 30, "ip_subnet": "10.99.30.1/24"},  # Conflict with OPNsense 192.168.30.1/24
            {"name": "UCG_LAB_NET", "vlan": 88, "ip_subnet": "172.16.88.1/24"},  # UCG-only
        ],
        clients=[
            {"mac": "bc:24:11:22:33:44", "name": "UCG-Local-Workstation"},
        ],
    )

    # 3. Mock UOS Server Live State (Existing Controller with Wi-Fi APs and switches)
    uos_state = UniFiSourceState(
        source_type="uos_server",
        host="192.168.1.5",
        version="8.6.9",
        wlans=[
            UniFiWlan(
                name="Office-Corporate-WLAN",
                security="wpa2",
                x_passphrase="SecretWpaKey123",
                vlan_id=10,
                is_guest=False,
            ),
            UniFiWlan(
                name="Guest-Freifunk",
                security="open",
                x_passphrase="",
                vlan_id=99,
                is_guest=True,
            ),
        ],
        devices=[
            UniFiDevice(
                name="AP-Wohnzimmer-U6-Pro",
                mac="68:d7:9a:11:22:33",
                model="u6-pro",
                ip="192.168.1.50",
                device_type="uap",
                adopted=True,
            ),
            UniFiDevice(
                name="Switch-Keller-Lite16",
                mac="68:d7:9a:44:55:66",
                model="usw-lite-16-poe",
                ip="192.168.1.51",
                device_type="usw",
                adopted=True,
            ),
        ],
        clients=[
            # Match static lease from OPNsense: mac "00:15:5d:12:34:56" (NAS-Storage)
            {"mac": "00:15:5d:12:34:56", "name": "Synology DiskStation DS920+ (Büro)"},
        ],
    )

    # 4. Run MultiSourceMerger
    merger = MultiSourceMerger(
        opnsense_cfg=state.opnsense_cfg,
        unifi_target=state.unifi_cfg,
        ucg_state=ucg_state,
        uos_state=uos_state,
    )
    report = merger.reconcile()

    # 5. Assertions on Reconciliation Report
    assert report.ucg_connected is True
    assert report.uos_connected is True
    assert report.ucg_version == "4.0.6"
    assert report.uos_version == "8.6.9"

    # Network tests
    assert report.summary["networks_aligned"] >= 1
    assert report.summary["networks_conflicts"] >= 1
    assert report.summary["networks_preserved"] >= 1
    assert report.summary["wlans_imported"] == 2
    assert report.summary["clients_enriched"] >= 1
    assert report.summary["devices_mapped"] == 2

    # Check that WLANs were transferred to target config
    assert len(state.unifi_cfg.wlans) == 2
    assert state.unifi_cfg.wlans[0].name == "Office-Corporate-WLAN"
    assert state.unifi_cfg.wlans[0].vlan_id == 10

    # Check client enrichment
    nas_fixed = next((f for f in state.unifi_cfg.fixed_ips if f.mac.lower() == "00:15:5d:12:34:56"), None)
    assert nas_fixed is not None
    assert nas_fixed.name == "Synology DiskStation DS920+ (Büro)"

    # 6. Verify serialization in get_unifi_config_dict()
    state.ucg_state = ucg_state
    state.uos_state = uos_state
    state.reconciliation_report = report
    unifi_dict = get_unifi_config_dict()

    assert "reconciliation" in unifi_dict
    assert unifi_dict["reconciliation"]["ucg_connected"] is True
    assert len(unifi_dict["reconciliation"]["items"]) > 5
    assert len(unifi_dict["wlans"]) == 2

    print("SUCCESS: 3-Way Multi-Source Reconciliation & Merger tests passed cleanly!")


if __name__ == "__main__":
    test_three_way_reconciliation()
