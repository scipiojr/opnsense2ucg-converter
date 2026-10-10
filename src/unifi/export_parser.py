"""
Parser for UniFi Controller / Gateway export and backup files.
Supports:
1. JSON export files (*.json) - Direct REST API dumps, site exports, and collection backups.
2. UniFi Network Backup files (*.unf) - AES-128-CBC encrypted ZIP archives with BSON/JSON database dumps.
3. UniFi OS Console Backup files (*.unifi) - AES-256-CBC encrypted TAR/GZIP archives.
4. Raw unencrypted ZIP, GZIP, and TAR archives containing UniFi database collections.
"""

import gzip
import io
import json
import logging
import os
import struct
import tarfile
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

# Ubiquiti standard static keys for .unf backup decryption (AES-128-CBC)
UNIFI_AES_KEY = b"bcyangkmluohmars"
UNIFI_AES_IV = b"ubntenterpriseap"

# UniFi OS / Console static key (AES-256-CBC, e.g. UDM Pro, UCG-Max, Cloud Key)
UNIFI_OS_AES_KEY = bytes.fromhex("e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f")


class UniFiExportParser:
    """
    Parses UniFi export and backup files (*.unf, *.unifi, *.json, *.zip, *.tar.gz)
    into a structured UniFiSourceState.
    """

    def __init__(self):
        pass

    def parse_file(self, file_path: str, source_type: str = "generic") -> UniFiSourceState:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Export-Datei nicht gefunden: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()
        return self.parse_bytes(data, filename=os.path.basename(file_path), source_type=source_type)

    def parse_bytes(self, data: bytes, filename: str = "", source_type: str = "generic") -> UniFiSourceState:
        if not data:
            raise ValueError("Die hochgeladene Datei ist leer (0 Bytes).")

        filename_lower = filename.lower()

        # Strip UTF-8 BOM if present
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]

        # 1. Try direct JSON parsing
        stripped = data.strip()
        if filename_lower.endswith(".json") or stripped.startswith((b"{", b"[")):
            try:
                text = data.decode("utf-8", errors="replace").strip()
                parsed_json = json.loads(text)
                return self.parse_json_dict(parsed_json, source_type=source_type)
            except Exception as e:
                logger.debug(f"Direct JSON parse failed: {e}")

        # 2. Resilient backup archive extraction (.unf, .unifi, .zip, .tar.gz, .tar)
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
        Decrypts .unf (AES-128-CBC) or .unifi (AES-256-CBC) if encrypted,
        and extracts db.gz / BSON / JSON / TAR contents.
        """
        # Step 1: Try direct extraction if unencrypted (ZIP, TAR, GZIP, BSON)
        docs = self._extract_documents_from_bytes(data)
        if docs:
            return self.parse_json_dict(docs, source_type=source_type)

        # Step 2: Attempt AES decryption
        if not HAS_CRYPTO:
            raise RuntimeError(
                "Die Python-Bibliothek 'cryptography' ist erforderlich, um verschlüsselte UniFi .unf/.unifi Backups zu öffnen."
            )

        decrypted_candidates: List[bytes] = []

        # Attempt A: Classic UniFi Network .unf (AES-128-CBC)
        for offset in (0, 16, 4):
            if len(data) > offset + 16:
                dec = self._try_decrypt_aes(data[offset:], UNIFI_AES_KEY, UNIFI_AES_IV)
                if dec:
                    decrypted_candidates.append(dec)

        # Attempt B: UniFi OS Console backup .unifi (AES-256-CBC)
        # IV is the first 16 bytes of data, ciphertext follows
        if len(data) > 32:
            iv = data[:16]
            ct = data[16:]
            dec = self._try_decrypt_aes(ct, UNIFI_OS_AES_KEY, iv)
            if dec:
                decrypted_candidates.append(dec)

        # Attempt C: UniFi OS with 4-byte header + 16-byte IV
        if len(data) > 36:
            iv = data[4:20]
            ct = data[20:]
            dec = self._try_decrypt_aes(ct, UNIFI_OS_AES_KEY, iv)
            if dec:
                decrypted_candidates.append(dec)

        # Test all decrypted candidate streams
        for candidate in decrypted_candidates:
            extracted = self._extract_documents_from_bytes(candidate)
            if extracted:
                return self.parse_json_dict(extracted, source_type=source_type)

        raise ValueError(
            "Die Datei konnte nicht als UniFi-Backup (.unf / .unifi / .zip / .json) entschlüsselt oder gelesen werden. "
            "Bitte prüfen Sie, ob die Datei intakt ist oder exportieren Sie eine JSON-/Site-Sicherung im UniFi Controller."
        )

    def _try_decrypt_aes(self, ct_bytes: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """
        Attempts AES CBC decryption with NoPadding (block size 16 truncation).
        """
        try:
            block_len = (len(ct_bytes) // 16) * 16
            if block_len < 16:
                return None
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            return decryptor.update(ct_bytes[:block_len]) + decryptor.finalize()
        except Exception as e:
            logger.debug(f"AES decryption attempt failed: {e}")
            return None

    def _extract_documents_from_bytes(self, data: bytes, depth: int = 0) -> List[Dict[str, Any]]:
        """
        Recursively unpacks ZIP archives, GZIP streams, TAR archives, BSON streams, and JSON payloads.
        """
        if depth > 3 or len(data) < 4:
            return []

        docs: List[Dict[str, Any]] = []

        # 1. Check for ZIP archive (PK\x03\x04 signature anywhere in data)
        pk_idx = data.find(b"PK\x03\x04")
        if pk_idx != -1:
            try:
                with zipfile.ZipFile(io.BytesIO(data[pk_idx:])) as z:
                    for name in z.namelist():
                        try:
                            file_content = z.read(name)
                            name_lower = name.lower()
                            if name_lower.endswith(".json"):
                                parsed = json.loads(file_content.decode("utf-8", errors="replace"))
                                if isinstance(parsed, list):
                                    docs.extend(parsed)
                                elif isinstance(parsed, dict):
                                    docs.append(parsed)
                            elif name_lower == "db.gz" or name_lower.endswith(".gz"):
                                try:
                                    decomp = gzip.decompress(file_content)
                                    nested = self._extract_documents_from_bytes(decomp, depth=depth + 1)
                                    if nested:
                                        docs.extend(nested)
                                    else:
                                        bson_items = self._decode_bson_stream(decomp)
                                        if bson_items:
                                            docs.extend(bson_items)
                                except Exception as gz_err:
                                    logger.debug(f"GZ decompress error for {name}: {gz_err}")
                            elif name_lower == "db" or name_lower.endswith(".bson"):
                                bson_items = self._decode_bson_stream(file_content)
                                if bson_items:
                                    docs.extend(bson_items)
                            elif name_lower.endswith(".unf"):
                                nested = self._extract_documents_from_bytes(file_content, depth=depth + 1)
                                if nested:
                                    docs.extend(nested)
                        except Exception as e:
                            logger.debug(f"Error reading zip entry {name}: {e}")
                if docs:
                    return docs
            except Exception as e:
                logger.debug(f"Zip extraction failed: {e}")

        # 2. Check for GZIP stream (\x1f\x8b signature anywhere in data)
        gz_idx = data.find(b"\x1f\x8b")
        if gz_idx != -1:
            try:
                decomp = gzip.decompress(data[gz_idx:])
                # Try BSON first
                bson_items = self._decode_bson_stream(decomp)
                if bson_items:
                    return bson_items
                # Try nested archives (TAR / ZIP / JSON)
                nested = self._extract_documents_from_bytes(decomp, depth=depth + 1)
                if nested:
                    return nested
            except Exception as e:
                logger.debug(f"GZIP stream processing failed: {e}")

        # 3. Check for TAR archive
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    try:
                        f = tar.extractfile(member)
                        if not f:
                            continue
                        content = f.read()
                        m_name = member.name.lower()
                        if m_name.endswith(".json"):
                            parsed = json.loads(content.decode("utf-8", errors="replace"))
                            if isinstance(parsed, list):
                                docs.extend(parsed)
                            elif isinstance(parsed, dict):
                                docs.append(parsed)
                        elif m_name.endswith(".gz") or m_name.endswith(".unf"):
                            nested = self._extract_documents_from_bytes(content, depth=depth + 1)
                            if nested:
                                docs.extend(nested)
                        elif m_name == "db" or m_name.endswith(".bson"):
                            bson_items = self._decode_bson_stream(content)
                            if bson_items:
                                docs.extend(bson_items)
                    except Exception as e:
                        logger.debug(f"Error reading tar member {member.name}: {e}")
                if docs:
                    return docs
        except Exception as e:
            logger.debug(f"Tar archive check failed: {e}")

        # 4. Check for direct BSON stream
        bson_items = self._decode_bson_stream(data)
        if bson_items:
            return bson_items

        # 5. Check for direct JSON
        stripped = data.strip()
        if stripped.startswith((b"{", b"[")):
            try:
                parsed = json.loads(stripped.decode("utf-8", errors="replace"))
                if isinstance(parsed, list):
                    return parsed
                elif isinstance(parsed, dict):
                    return [parsed]
            except Exception:
                pass

        return []

    def _decode_bson_stream(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Decodes sequential BSON documents from a raw byte stream (db.gz dump).
        Pure-Python implementation without external pymongo dependency.
        """
        docs: List[Dict[str, Any]] = []
        pos = 0
        total_len = len(data)

        while pos < total_len - 4:
            # Skip leading zero padding bytes
            if data[pos] == 0:
                pos += 1
                continue

            doc_len = struct.unpack("<i", data[pos:pos + 4])[0]
            if doc_len <= 4 or pos + doc_len > total_len:
                # Seek next byte
                pos += 1
                continue

            try:
                if data[pos + doc_len - 1] == 0:
                    doc = self._parse_single_bson_doc(data[pos + 4:pos + doc_len - 1])
                    if doc:
                        docs.append(doc)
            except Exception as e:
                logger.debug(f"BSON doc decode exception at {pos}: {e}")

            pos += doc_len

        return docs

    def _parse_single_bson_doc(self, data: bytes) -> Dict[str, Any]:
        """
        Parses key-value pairs of a single BSON document body.
        Supports standard MongoDB/UniFi types: Double, String, Document, Array,
        Binary, ObjectId, Boolean, UTC Datetime, Null, Regex, Int32, Timestamp, Int64, Decimal128.
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
            elif elem_type == 2:  # String
                if pos + 4 > total:
                    break
                s_len = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 4
                if pos + s_len > total or s_len < 1:
                    break
                val = data[pos:pos + s_len - 1].decode("utf-8", errors="replace")
                pos += s_len
            elif elem_type == 3:  # Embedded Document
                if pos + 4 > total:
                    break
                doc_len = struct.unpack("<i", data[pos:pos + 4])[0]
                if pos + doc_len > total or doc_len < 5:
                    break
                val = self._parse_single_bson_doc(data[pos + 4:pos + doc_len - 1])
                pos += doc_len
            elif elem_type == 4:  # Array
                if pos + 4 > total:
                    break
                arr_len = struct.unpack("<i", data[pos:pos + 4])[0]
                if pos + arr_len > total or arr_len < 5:
                    break
                arr_doc = self._parse_single_bson_doc(data[pos + 4:pos + arr_len - 1])
                val = [v for _, v in sorted(arr_doc.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)]
                pos += arr_len
            elif elem_type == 5:  # Binary data
                if pos + 5 > total:
                    break
                bin_len = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 5
                if pos + bin_len > total or bin_len < 0:
                    break
                val = data[pos:pos + bin_len].hex()
                pos += bin_len
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
            elif elem_type == 9:  # UTC Datetime (8 bytes int64)
                if pos + 8 > total:
                    break
                val = struct.unpack("<q", data[pos:pos + 8])[0]
                pos += 8
            elif elem_type == 10:  # Null
                val = None
            elif elem_type == 11:  # Regex (cstring + cstring)
                p_end = data.find(b"\x00", pos)
                if p_end == -1:
                    break
                pat = data[pos:p_end].decode("utf-8", errors="replace")
                pos = p_end + 1
                o_end = data.find(b"\x00", pos)
                if o_end == -1:
                    break
                opts = data[pos:o_end].decode("utf-8", errors="replace")
                pos = o_end + 1
                val = f"/{pat}/{opts}"
            elif elem_type == 16:  # 32-bit integer (4 bytes)
                if pos + 4 > total:
                    break
                val = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 4
            elif elem_type == 17:  # Timestamp (8 bytes uint64)
                if pos + 8 > total:
                    break
                val = struct.unpack("<Q", data[pos:pos + 8])[0]
                pos += 8
            elif elem_type == 18:  # 64-bit integer (8 bytes)
                if pos + 8 > total:
                    break
                val = struct.unpack("<q", data[pos:pos + 8])[0]
                pos += 8
            elif elem_type == 19:  # 128-bit decimal (16 bytes)
                if pos + 16 > total:
                    break
                val = data[pos:pos + 16].hex()
                pos += 16
            else:
                # Unknown type: stop parsing this document safely
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
        Supports direct MongoDB document formats and UniFi API formats.
        """
        col = str(item.get("_collection", "")).lower()
        if col in ("networkconf", "network"):
            networks.append(item)
            return
        elif col in ("wlanconf", "wlan"):
            wlans.append(self._dict_to_wlan(item))
            return
        elif col in ("device", "devices"):
            devices.append(self._dict_to_device(item))
            return
        elif col in ("user", "client", "clients"):
            clients.append(item)
            return
        elif col in ("firewallrule", "firewall_rule"):
            firewall_rules.append(item)
            return

        # Network detection
        if "ip_subnet" in item or "gateway_ip" in item or ("vlan" in item and "purpose" in item):
            networks.append(item)
            return

        # WLAN detection
        if (
            "x_passphrase" in item
            or ("security" in item and "wlan_id" in item)
            or ("wpa" in item and "name" in item)
            or ("security" in item and "name" in item and ("is_guest" in item or "wlan_bands" in item or "hide_ssid" in item))
        ):
            wlans.append(self._dict_to_wlan(item))
            return

        # Device detection (AP, Switch, Gateway)
        if "mac" in item and ("model" in item or item.get("type") in ["uap", "usw", "ugw", "uxg", "udm", "ucg"] or "adopted" in item):
            devices.append(self._dict_to_device(item))
            return

        # Client / User detection
        if "mac" in item and ("use_fixedip" in item or "fixed_ip" in item or "hostname" in item or "is_guest" in item or "noted" in item):
            clients.append(item)
            return

        # Firewall rule detection
        if ("ruleset" in item and "action" in item) or ("rule_index" in item and "action" in item):
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
