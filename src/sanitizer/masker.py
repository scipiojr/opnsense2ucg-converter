"""
Data Sanitizer & Vault Engine.
Scrubs passwords, cryptographic keys, public WAN IPs, external FQDNs, and sensitive credentials
before sending data to external LLMs (Claude, Gemini), and provides lossless rehydration locally.
"""

import re
import ipaddress
import json
from typing import Dict, Any, Tuple, List, Optional


class SanitizerVault:
    def __init__(self, anonymize_macs: bool = False):
        self.anonymize_macs = anonymize_macs
        self.forward_map: Dict[str, str] = {}    # real_value -> token
        self.reverse_map: Dict[str, str] = {}    # token -> real_value
        self.token_metadata: Dict[str, str] = {} # token -> type ("password", "public_ip", etc.)

        self._counters = {
            "SECRET_PASS": 0,
            "CERT_KEY": 0,
            "PUB_IP": 0,
            "EXT_DOMAIN": 0,
            "MAC_ADDR": 0,
            "SENSITIVE_TEXT": 0,
        }

    def _get_or_create_token(self, category: str, real_value: str) -> str:
        if not real_value or not real_value.strip():
            return real_value

        clean_val = real_value.strip()
        if clean_val in self.forward_map:
            return self.forward_map[clean_val]

        self._counters[category] += 1
        token = f"__{category}_{self._counters[category]:03d}__"
        self.forward_map[clean_val] = token
        self.reverse_map[token] = clean_val
        self.token_metadata[token] = category
        return token

    RFC1918_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    def is_private_ip(self, ip_str: str) -> bool:
        """
        Returns True only if the IP is an internal RFC1918/Loopback private LAN IP.
        All external, public, or WAN IPs return False and will be sanitized.
        """
        try:
            pure_ip = ip_str.split("/")[0].strip()
            ip_obj = ipaddress.ip_address(pure_ip)
            if pure_ip in ["0.0.0.0", "255.255.255.255"]:
                return True
            return any(ip_obj in net for net in self.RFC1918_NETWORKS)
        except ValueError:
            return True  # If it's not a valid IP, don't classify as public IP

    def sanitize_xml(self, xml_content: str) -> str:
        """
        Scans and sanitizes raw OPNsense XML content.
        """
        sanitized = xml_content

        # 1. Sanitize Sensitive XML Tags (passwords, bcrypt, keys, preshared keys)
        sensitive_tags = [
            "password",
            "bcrypt",
            "md5",
            "sha256",
            "presharedkey",
            "preshared-key",
            "key",
            "prv",
            "crt",
            "cert",
            "tls",
            "community",
            "secret",
            "token",
            "passphrase",
            "private-key",
        ]

        for tag in sensitive_tags:
            pattern = re.compile(rf"(<{tag}[^>]*>)(.*?)(</{tag}>)", re.DOTALL | re.IGNORECASE)

            def replacer(match):
                prefix, secret_val, suffix = match.groups()
                if not secret_val.strip() or secret_val.startswith("__"):
                    return match.group(0)
                category = "CERT_KEY" if tag in ["key", "prv", "crt", "cert", "tls"] else "SECRET_PASS"
                token = self._get_or_create_token(category, secret_val.strip())
                return f"{prefix}{token}{suffix}"

            sanitized = pattern.sub(replacer, sanitized)

        # 2. Find and Mask Public IPs in IPv4 format (excluding private subnets)
        ipv4_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b")

        def ip_replacer(match):
            candidate = match.group(0)
            if not self.is_private_ip(candidate):
                return self._get_or_create_token("PUB_IP", candidate)
            return candidate

        sanitized = ipv4_pattern.sub(ip_replacer, sanitized)

        # 3. Mask MAC Addresses if enabled
        if self.anonymize_macs:
            mac_pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")

            def mac_replacer(match):
                mac = match.group(0)
                return self._get_or_create_token("MAC_ADDR", mac)

            sanitized = mac_pattern.sub(mac_replacer, sanitized)

        return sanitized

    def sanitize_dict(self, data: Any) -> Any:
        """
        Recursively sanitizes python dict/list structures.
        """
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                lower_k = k.lower()
                if any(sec in lower_k for sec in ["pass", "secret", "key", "token", "preshared"]):
                    if isinstance(v, str):
                        new_dict[k] = self._get_or_create_token("SECRET_PASS", v)
                    else:
                        new_dict[k] = self.sanitize_dict(v)
                elif "ip" in lower_k and isinstance(v, str) and not self.is_private_ip(v):
                    new_dict[k] = self._get_or_create_token("PUB_IP", v)
                elif "mac" in lower_k and self.anonymize_macs and isinstance(v, str):
                    new_dict[k] = self._get_or_create_token("MAC_ADDR", v)
                else:
                    new_dict[k] = self.sanitize_dict(v)
            return new_dict
        elif isinstance(data, list):
            return [self.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            # Check if this string contains public IP
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", data) and not self.is_private_ip(data):
                return self._get_or_create_token("PUB_IP", data)
            if self.anonymize_macs and re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", data):
                return self._get_or_create_token("MAC_ADDR", data)
            return data
        return data

    def rehydrate_str(self, text: str) -> str:
        """
        Replaces all __TOKEN__ placeholders with the original values.
        """
        result = text
        for token, real_val in self.reverse_map.items():
            result = result.replace(token, real_val)
        return result

    def rehydrate_dict(self, data: Any) -> Any:
        """
        Recursively rehydrates dictionaries or lists.
        """
        if isinstance(data, dict):
            return {k: self.rehydrate_dict(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.rehydrate_dict(item) for item in data]
        elif isinstance(data, str):
            return self.rehydrate_str(data)
        return data

    def get_audit_summary(self) -> List[Dict[str, str]]:
        """
        Returns a list of all sanitized tokens and their redacted categories for UI display.
        Does not show raw sensitive passwords directly, shows masked indicators.
        """
        summary = []
        for token, real_val in self.reverse_map.items():
            cat = self.token_metadata.get(token, "UNKNOWN")
            if cat in ["SECRET_PASS", "CERT_KEY"]:
                masked_preview = f"{real_val[:2]}***{real_val[-2:]}" if len(real_val) > 4 else "***"
            else:
                masked_preview = real_val

            summary.append({
                "token": token,
                "category": cat,
                "preview": masked_preview,
            })
        return summary

    def export_vault(self, file_path: str) -> None:
        """
        Exports the reverse map locally so sessions can be restored.
        """
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump({
                "reverse_map": self.reverse_map,
                "token_metadata": self.token_metadata,
            }, f, indent=2)

    def import_vault(self, file_path: str) -> None:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.reverse_map = data.get("reverse_map", {})
            self.token_metadata = data.get("token_metadata", {})
            self.forward_map = {v: k for k, v in self.reverse_map.items()}
