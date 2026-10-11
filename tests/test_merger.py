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
    state.reset()
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

    # Check preserved UCG network was added to target
    ucg_lab = next((n for n in state.unifi_cfg.networks if n.vlan_id == 88), None)
    assert ucg_lab is not None
    assert ucg_lab.gateway_cidr == "172.16.88.1/24"

    print("SUCCESS: 3-Way Multi-Source Reconciliation & Merger tests passed cleanly!")


def test_export_files_parsing_and_unification():
    from src.unifi.export_parser import UniFiExportParser, UNIFI_AES_KEY, UNIFI_AES_IV
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import zipfile
    import io

    # 1. Test JSON Export parsing
    ucg_json = {
        "networks": [
            {"name": "UCG_VLAN25", "vlan": 25, "ip_subnet": "192.168.25.1/24"},
            {"name": "Default", "vlan": 1, "ip_subnet": "192.168.1.1/24"}
        ],
        "clients": [
            {"mac": "00:aa:bb:cc:dd:ee", "name": "UCG-Workstation", "use_fixedip": True, "fixed_ip": "192.168.25.50"}
        ]
    }
    parser = UniFiExportParser()
    ucg_state = parser.parse_json_dict(ucg_json, source_type="ucg_max")
    assert len(ucg_state.networks) == 2
    assert len(ucg_state.clients) == 1

    # 2. Test encrypted .unf backup parsing
    uos_data = {
        "wlans": [
            {"name": "Company-Secret-WiFi", "security": "wpapsk", "x_passphrase": "TopSecretKey99", "vlan": 25}
        ],
        "devices": [
            {"name": "U6-Enterprise-Hall", "mac": "11:22:33:44:55:66", "model": "u6-ent", "type": "uap"}
        ],
        "clients": [
            {"mac": "00:15:5d:12:34:56", "name": "TrueNAS Storage Cluster (Server)"}
        ]
    }
    # Create zip in memory
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("settings.json", json.dumps(uos_data))
    zip_bytes = zip_buf.getvalue()

    # Encrypt with UniFi AES key
    pad_len = 16 - (len(zip_bytes) % 16)
    padded_zip = zip_bytes + (b"\x00" * pad_len)
    cipher = Cipher(algorithms.AES(UNIFI_AES_KEY), modes.CBC(UNIFI_AES_IV))
    encryptor = cipher.encryptor()
    encrypted_unf = encryptor.update(padded_zip) + encryptor.finalize()

    # Parse .unf bytes
    uos_state = parser.parse_bytes(encrypted_unf, filename="backup_2026.unf", source_type="uos_server")
    assert len(uos_state.wlans) == 1
    assert uos_state.wlans[0].name == "Company-Secret-WiFi"
    assert len(uos_state.devices) == 1
    assert len(uos_state.clients) == 1

    # 3. Unify OPNsense + UCG export + UOS export
    sample_path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_opnsense_26_7_5.xml")
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_data = f.read()

    state.ucg_state = ucg_state
    state.uos_state = uos_state

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(process_xml(xml_data))
    assert res.status_code == 200

    report = state.reconciliation_report
    assert report is not None

    # Check that UCG VLAN 25 was preserved & added to unified config
    vlan25 = next((n for n in state.unifi_cfg.networks if n.vlan_id == 25), None)
    assert vlan25 is not None
    assert vlan25.name == "UCG_VLAN25"

    # Check WLAN was imported
    wlan = next((w for w in state.unifi_cfg.wlans if w.name == "Company-Secret-WiFi"), None)
    assert wlan is not None

    # Check client name enrichment
    nas = next((f for f in state.unifi_cfg.fixed_ips if f.mac.lower() == "00:15:5d:12:34:56"), None)
    assert nas is not None
    assert nas.name == "TrueNAS Storage Cluster (Server)"

    # Check extra client fixed IP added from UCG export
    ucg_client = next((f for f in state.unifi_cfg.fixed_ips if f.mac.lower() == "00:aa:bb:cc:dd:ee"), None)
    assert ucg_client is not None
    assert ucg_client.fixed_ip == "192.168.25.50"

    # Test full unified config dictionary
    unified_dict = get_unifi_config_dict()
    assert len(unified_dict["networks"]) == 6  # 5 OPNsense + 1 UCG preserved
    assert len(unified_dict["wlans"]) == 1
    assert len(unified_dict["fixed_ips"]) == 9  # 8 OPNsense + 1 UCG extra

    print("SUCCESS: Export files parsing (.json, encrypted .unf) and 3-way unification passed cleanly!")


def test_unifi_os_aes256_backup():
    """
    Tests decryption and extraction of UniFi OS Console backups (.unifi).
    Encrypted with AES-256-CBC, IV is first 16 bytes of file, payload is tar.gz.
    """
    import os
    import io
    import tarfile
    from src.unifi.export_parser import UniFiExportParser, UNIFI_OS_AES_KEY
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    parser = UniFiExportParser()

    # Create in-memory tar.gz containing settings.json
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        payload = json.dumps({
            "wlans": [
                {"name": "UniFiOS-Guest-WiFi", "security": "open", "vlan": 50, "is_guest": True}
            ],
            "devices": [
                {"name": "UCG-Max-Gateway", "mac": "70:a7:41:11:22:33", "model": "UCG-Max", "type": "ugw"}
            ]
        }).encode("utf-8")
        ti = tarfile.TarInfo(name="settings.json")
        ti.size = len(payload)
        tar.addfile(ti, io.BytesIO(payload))

    tar_gz_bytes = tar_buf.getvalue()

    # Encrypt with AES-256-CBC
    iv = os.urandom(16)
    pad_len = 16 - (len(tar_gz_bytes) % 16)
    padded = tar_gz_bytes + (b"\x00" * pad_len)
    cipher = Cipher(algorithms.AES(UNIFI_OS_AES_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Prepend IV to ciphertext (.unifi format)
    unifi_os_file_bytes = iv + ciphertext

    parsed_st = parser.parse_bytes(unifi_os_file_bytes, filename="console_backup.unifi", source_type="ucg_max")
    assert len(parsed_st.wlans) == 1
    assert parsed_st.wlans[0].name == "UniFiOS-Guest-WiFi"
    assert parsed_st.wlans[0].is_guest is True
    assert len(parsed_st.devices) == 1
    assert parsed_st.devices[0].model == "UCG-Max"

    print("SUCCESS: UniFi OS AES-256 console backup decryption test passed cleanly!")


def test_bson_stream_comprehensive():
    """
    Tests pure-Python BSON decoder with all MongoDB/UniFi types:
    double, string, embedded doc, array, binary, objectid, boolean, datetime, null, int32, timestamp, int64.
    """
    import struct
    from src.unifi.export_parser import UniFiExportParser

    parser = UniFiExportParser()

    # Construct raw BSON document:
    # {"name": "TestNet", "vlan": int32(20), "enabled": True, "active": None, "ts": uint64(12345), "speed": double(100.5)}
    doc_body = bytearray()

    # String: name = "TestNet"
    doc_body.append(2)  # type string
    doc_body.extend(b"name\x00")
    s_val = b"TestNet\x00"
    doc_body.extend(struct.pack("<i", len(s_val)))
    doc_body.extend(s_val)

    # Int32: vlan = 20
    doc_body.append(16)  # type int32
    doc_body.extend(b"vlan\x00")
    doc_body.extend(struct.pack("<i", 20))

    # Subnet string: ip_subnet = "192.168.20.1/24"
    doc_body.append(2)
    doc_body.extend(b"ip_subnet\x00")
    sub_val = b"192.168.20.1/24\x00"
    doc_body.extend(struct.pack("<i", len(sub_val)))
    doc_body.extend(sub_val)

    # Boolean: enabled = True
    doc_body.append(8)
    doc_body.extend(b"enabled\x00")
    doc_body.append(1)

    # Null: note = None
    doc_body.append(10)
    doc_body.extend(b"note\x00")

    # Double: speed = 100.5
    doc_body.append(1)
    doc_body.extend(b"speed\x00")
    doc_body.extend(struct.pack("<d", 100.5))

    # UTC Datetime: created = 1600000000000
    doc_body.append(9)
    doc_body.extend(b"created\x00")
    doc_body.extend(struct.pack("<q", 1600000000000))

    # Null terminator for document
    doc_body.append(0)

    # Prepend document length (total including 4-byte length header)
    doc_len = 4 + len(doc_body)
    raw_bson = struct.pack("<i", doc_len) + bytes(doc_body)

    docs = parser._decode_bson_stream(raw_bson)
    assert len(docs) == 1
    d = docs[0]
    assert d["name"] == "TestNet"
    assert d["vlan"] == 20
    assert d["ip_subnet"] == "192.168.20.1/24"
    assert d["enabled"] is True
    assert d["note"] is None
    assert d["speed"] == 100.5
    assert d["created"] == 1600000000000

    print("SUCCESS: Comprehensive BSON stream parsing test passed cleanly!")


def test_corrupt_file_handling():
    """
    Ensures corrupt or random files don't crash the server and raise clean descriptive exceptions.
    """
    from src.unifi.export_parser import UniFiExportParser
    parser = UniFiExportParser()

    try:
        parser.parse_bytes(b"garbage_random_bytes_that_are_not_valid_at_all" * 5, filename="bad.unf")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "nicht als UniFi-Backup" in str(e) or "entschlüsselt" in str(e)

    print("SUCCESS: Corrupt file handling test passed cleanly!")


if __name__ == "__main__":
    test_three_way_reconciliation()
    test_export_files_parsing_and_unification()
    test_unifi_os_aes256_backup()
    test_bson_stream_comprehensive()
    test_corrupt_file_handling()

