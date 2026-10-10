"""
Parser for UniFi Controller / Gateway export and backup files.
Supports:
1. JSON export files (*.json) - Direct REST API dumps, site exports, and collection backups.
2. UniFi Network Backup files (*.unf) - AES-128-CBC encrypted ZIP archives with BSON/JSON database dumps.
3. ZIP / Tarball archives containing UniFi database collections.
"""

import gzip
import io
import json
import logging
import os
import struct
import zipfile
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from src.models import (
    UniFiSourceState,
    UniFiWlan,
    UniFiDevice,
)

logger = logging.getLogger(__name__)

# Ubiquiti standard static keys for .unf backup decryption
UNIFI_AES_KEY = b"bcyangkmluohmars"
UNIFI_AES_IV = b"ubntenterpriseap"


class UniFiExportParser:
    """
    Parses UniFi export and backup files (*.unf, *.json, *.zip) into UniFiSourceState.
    """

    def __init__(self):
        pass

    def parse_file(self, file_path: str, source_type: str = "generic") -> UniFiSourceState:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Export file not found: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()
        return self.parse_bytes(data, filename=os.path.basename(file_path), source_type=source_type)

    def parse_bytes(self, data: bytes, filename: str = "", source_type: str = "generic") -> UniFiSourceState:
        filename_lower = filename.lower()

        # 1. Try direct JSON parsing
        if filename_lower.endswith(".json") or data.strip().startswith((b"{", b"[")):
            try:
                text = data.decode("utf-8", errors="replace").strip()
                parsed_json = json.loads(text)
                return self.parse_json_dict(parsed_json, source_type=source_type)
            except Exception as e:
                logger.debug(f"Direct JSON parse failed: {e}")

        # 2. Try .unf or ZIP backup extraction
        return self._parse_unf_or_zip(data, source_type=source_type)

    def parse_json_dict(self, data: Union[Dict[str, Any], List[Any]], source_type: str = "generic") -> UniFiSourceState:
        """
        Parses JSON structures into a unified UniFiSourceState.
        """
        networks: List[Dict[str, Any]] = []
        wlans: List[UniFiWlan] = []
        devices: List[UniFiDevice] = []
        clients: List[Dict[str, Any]] = []
        firewall_rules: List[Dict[str, Any]] = []

        if isinstance(data, list):
            # Array of items
            for item in data:
                if isinstance(item, dict):
                    if any(k in item for k in ("networks", "wlans", "devices", "clients", "networkconf", "wlanconf", "device", "user", "firewallrule")):
                        self._extract_collections_from_dict(item, networks, wlans, devices, clients, firewall_rules)
                    else:
                        self._classify_and_append_dict(item, networks, wlans, devices, clients, firewall_rules)
        elif isinstance(data, dict):
            self._extract_collections_from_dict(data, networks, wlans, devices, clients, firewall_rules)

        version = ""
        if isinstance(data, dict):
            version = str(data.get("version", data.get("meta", {}).get("version", "")))

        return UniFiSourceState(
            source_type=source_type,
            version=version,
            networks=networks,
            wlans=wlans,
            devices=devices,
            clients=clients,
            firewall_rules=firewall_rules,
            raw_summary={
                "networks_count": len(networks),
                "wlans_count": len(wlans),
                "devices_count": len(devices),
                "clients_count": len(clients),
                "firewall_rules_count": len(firewall_rules),
            },
        )

    def _extract_collections_from_dict(
        self,
        data: Dict[str, Any],
        networks: List[Dict[str, Any]],
        wlans: List[UniFiWlan],
        devices: List[UniFiDevice],
        clients: List[Dict[str, Any]],
        firewall_rules: List[Dict[str, Any]],
    ) -> None:
        # 1. Networks
        raw_nets = data.get("networks") or data.get("networkconf") or data.get("network_conf") or []
        if isinstance(raw_nets, list):
            networks.extend(raw_nets)

        # 2. WLANs
        raw_wlans = data.get("wlans") or data.get("wlanconf") or data.get("wlan_conf") or []
        if isinstance(raw_wlans, list):
            for w in raw_wlans:
                if isinstance(w, dict):
                    wlans.append(self._dict_to_wlan(w))

        # 3. Devices
        raw_devs = data.get("devices") or data.get("device") or data.get("devices_stat") or []
        if isinstance(raw_devs, list):
            for d in raw_devs:
                if isinstance(d, dict):
                    devices.append(self._dict_to_device(d))

        # 4. Clients / Users
        raw_clients = data.get("clients") or data.get("user") or data.get("users") or []
        if isinstance(raw_clients, list):
            clients.extend(raw_clients)

        # 5. Firewall Rules
        raw_rules = data.get("firewall_rules") or data.get("firewallrule") or data.get("rules") or []
        if isinstance(raw_rules, list):
            firewall_rules.extend(raw_rules)

        # If wrapped in "data" (e.g. UniFi REST API export)
        if "data" in data and isinstance(data["data"], list):
            for item in data["data"]:
                if isinstance(item, dict):
                    self._classify_and_append_dict(item, networks, wlans, devices, clients, firewall_rules)

    def _parse_unf_or_zip(self, data: bytes, source_type: str = "generic") -> UniFiSourceState:
        """
        Decrypts .unf (AES-128-CBC) if needed and extracts db.gz / BSON / JSON.
        """
        zip_bytes = data

        # Check if file is already a ZIP archive
        if not data.startswith(b"PK\x03\x04"):
            # Attempt AES decryption
            if not HAS_CRYPTO:
                raise RuntimeError("cryptography library required to decrypt UniFi .unf backup files")

            try:
                # Truncate to multiple of 16 for AES block size
                block_len = (len(data) // 16) * 16
                cipher = Cipher(algorithms.AES(UNIFI_AES_KEY), modes.CBC(UNIFI_AES_IV))
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(data[:block_len]) + decryptor.finalize()
                if decrypted.startswith(b"PK\x03\x04"):
                    zip_bytes = decrypted
                else:
                    raise ValueError("Decrypted stream does not contain valid ZIP header")
            except Exception as e:
                logger.error(f"Failed to decrypt .unf file: {e}")
                raise ValueError(f"Could not decrypt UniFi backup file: {e}")

        # Extract files from ZIP archive
        docs: List[Dict[str, Any]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                for name in z.namelist():
                    file_content = z.read(name)
                    if name == "db.gz" or name.endswith(".gz"):
                        try:
                            decompressed = gzip.decompress(file_content)
                            docs.extend(self._decode_bson_stream(decompressed))
                        except Exception as e:
                            logger.warning(f"Error reading gzip BSON {name}: {e}")
                    elif name.endswith(".json"):
                        try:
                            json_data = json.loads(file_content.decode("utf-8", errors="replace"))
                            if isinstance(json_data, list):
                                docs.extend(json_data)
                            elif isinstance(json_data, dict):
                                docs.append(json_data)
                        except Exception as e:
                            logger.warning(f"Error reading JSON {name}: {e}")
        except Exception as e:
            logger.error(f"Error unpacking backup zip: {e}")
            raise ValueError(f"Error unpacking UniFi backup zip archive: {e}")

        return self.parse_json_dict(docs, source_type=source_type)

    def _decode_bson_stream(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Decodes sequential BSON documents from a raw byte stream (db.gz dump).
        Pure-Python implementation without external pymongo dependency.
        """
        docs: List[Dict[str, Any]] = []
        pos = 0
        total_len = len(data)

        while pos < total_len - 4:
            doc_len = struct.unpack("<i", data[pos:pos + 4])[0]
            if doc_len <= 4 or pos + doc_len > total_len:
                break
            try:
                doc = self._parse_single_bson_doc(data[pos + 4:pos + doc_len - 1])
                if doc:
                    docs.append(doc)
            except Exception:
                pass
            pos += doc_len

        return docs

    def _parse_single_bson_doc(self, data: bytes) -> Dict[str, Any]:
        """
        Parses key-value pairs of a single BSON document body.
        """
        res: Dict[str, Any] = {}
        pos = 0
        total = len(data)

        while pos < total:
            elem_type = data[pos]
            if elem_type == 0:
                break
            pos += 1

            name_end = data.find(b"\x00", pos)
            if name_end == -1:
                break
            name = data[pos:name_end].decode("utf-8", errors="replace")
            pos = name_end + 1

            if elem_type == 1:  # Double (8 bytes)
                if pos + 8 > total:
                    break
                val = struct.unpack("<d", data[pos:pos + 8])[0]
                pos += 8
            elif elem_type == 2:  # String (int32 length + bytes)
                if pos + 4 > total:
                    break
                s_len = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 4
                if pos + s_len > total:
                    break
                val = data[pos:pos + s_len - 1].decode("utf-8", errors="replace")
                pos += s_len
            elif elem_type == 3:  # Embedded Document
                if pos + 4 > total:
                    break
                doc_len = struct.unpack("<i", data[pos:pos + 4])[0]
                if pos + doc_len > total:
                    break
                val = self._parse_single_bson_doc(data[pos + 4:pos + doc_len - 1])
                pos += doc_len
            elif elem_type == 4:  # Array
                if pos + 4 > total:
                    break
                arr_len = struct.unpack("<i", data[pos:pos + 4])[0]
                if pos + arr_len > total:
                    break
                arr_doc = self._parse_single_bson_doc(data[pos + 4:pos + arr_len - 1])
                val = [v for _, v in sorted(arr_doc.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)]
                pos += arr_len
            elif elem_type == 7:  # ObjectId (12 bytes)
                if pos + 12 > total:
                    break
                val = data[pos:pos + 12].hex()
                pos += 12
            elif elem_type == 8:  # Boolean (1 byte)
                if pos + 1 > total:
                    break
                val = bool(data[pos])
                pos += 1
            elif elem_type == 16:  # 32-bit integer (4 bytes)
                if pos + 4 > total:
                    break
                val = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 4
            elif elem_type == 18:  # 64-bit integer (8 bytes)
                if pos + 8 > total:
                    break
                val = struct.unpack("<q", data[pos:pos + 8])[0]
                pos += 8
            else:
                # Unsupported type: skip document parse
                break

            res[name] = val

        return res

    def _classify_and_append_dict(
        self,
        item: Dict[str, Any],
        networks: List[Dict[str, Any]],
        wlans: List[UniFiWlan],
        devices: List[UniFiDevice],
        clients: List[Dict[str, Any]],
        firewall_rules: List[Dict[str, Any]],
    ) -> None:
        """
        Detects whether an untyped dictionary is a network, WLAN, device, client, or rule.
        """
        # Network detection
        if "ip_subnet" in item or "gateway_ip" in item or ("vlan" in item and "purpose" in item):
            networks.append(item)
            return

        # WLAN detection
        if "x_passphrase" in item or ("security" in item and "wlan_id" in item) or ("wpa" in item and "name" in item):
            wlans.append(self._dict_to_wlan(item))
            return

        # Device detection (AP, Switch, Gateway)
        if "mac" in item and ("model" in item or item.get("type") in ["uap", "usw", "ugw", "uxg"]):
            devices.append(self._dict_to_device(item))
            return

        # Client / User detection
        if "mac" in item and ("use_fixedip" in item or "fixed_ip" in item or "hostname" in item or "is_guest" in item):
            clients.append(item)
            return

        # Firewall rule detection
        if "ruleset" in item and "action" in item:
            firewall_rules.append(item)
            return

    def _dict_to_wlan(self, w: Dict[str, Any]) -> UniFiWlan:
        return UniFiWlan(
            name=w.get("name") or w.get("ssid", "UniFi-SSID"),
            security=w.get("security", "wpapsk"),
            x_passphrase=w.get("x_passphrase", ""),
            vlan_id=w.get("vlan") or w.get("vlan_id"),
            is_guest=bool(w.get("is_guest", False)),
            enabled=bool(w.get("enabled", True)),
            network_id=w.get("networkconf_id") or w.get("network_id"),
        )

    def _dict_to_device(self, d: Dict[str, Any]) -> UniFiDevice:
        return UniFiDevice(
            name=d.get("name") or d.get("model", "UniFi Device"),
            mac=d.get("mac", ""),
            model=d.get("model", ""),
            ip=d.get("ip", ""),
            device_type=d.get("type", "uap"),
            adopted=bool(d.get("adopted", True)),
        )
