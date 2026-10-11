"""
UniFi OS / UniFi Cloud Gateway Max (UCG-Max) API Client.
Supports UniFi OS authentication (v3.x / v4.x), Dry-Run validation, and provisioning:
- Virtual Networks / Corporate VLANs
- Firewall Groups (Address / Port)
- Firewall Rules (LAN_IN, WAN_IN, LAN_LOCAL)
- Port Forwards
- Fixed IP Reservations
"""

import json
import logging
import urllib3
import requests
from typing import Dict, Any, List, Optional, Tuple
from src.models import (
    UniFiTargetConfig,
    UniFiNetwork,
    UniFiFirewallGroup,
    UniFiFirewallRule,
    UniFiPortForward,
    UniFiFixedIp,
    UniFiSourceState,
    UniFiWlan,
    UniFiDevice,
    UniFiDynDns,
    UniFiStaticRoute,
)

# Suppress self-signed certificate warnings for local gateway access
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class UniFiGatewayClient:
    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        api_key: Optional[str] = None,
        site: str = "default",
        port: int = 443,
        verify_ssl: bool = False,
    ):
        self.host = host.replace("http://", "").replace("https://", "").rstrip("/")
        # If user specified port in host string (e.g. 192.168.1.5:8443)
        if ":" in self.host:
            parts = self.host.split(":")
            self.host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        self.username = username
        self.password = password
        self.api_key = api_key
        self.site = site
        self.port = port
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.csrf_token = ""
        self.logged_in = False
        self.last_login_error = ""

        self.base_url = f"https://{self.host}:{self.port}"
        # On UniFi OS consoles (UDM, UCG-Max), network endpoints are proxied
        self.api_prefix = f"{self.base_url}/proxy/network/api/s/{self.site}"

    def login(self) -> bool:
        """
        Authenticates against UniFi OS Console (UCG-Max / UDM / CloudKey) or standalone UniFi Network Server (UOS).
        Supports modern UniFi OS /api/auth/login, CSRF headers, and legacy Network Application /api/login.
        """
        self.last_login_error = ""

        if self.api_key:
            self.session.headers.update({
                "X-API-KEY": self.api_key,
                "Accept": "application/json",
            })
            self.logged_in = True
            return True

        # Standard headers required by UniFi OS CSRF / Origin checks
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Referer": f"{self.base_url}/manage",
            "Origin": self.base_url,
        })

        # 1. Try modern UniFi OS authentication endpoint (/api/auth/login)
        uos_login_url = f"{self.base_url}/api/auth/login"
        payload_candidates = [
            {"username": self.username, "password": self.password, "rememberMe": True},
            {"username": self.username, "password": self.password},
            {"username": self.username, "password": self.password, "token": ""},
        ]

        for payload in payload_candidates:
            try:
                res = self.session.post(uos_login_url, json=payload, timeout=8)
                if res.status_code == 200:
                    csrf = res.headers.get("x-csrf-token") or res.headers.get("csrf-token") or ""
                    if csrf:
                        self.csrf_token = csrf
                        self.session.headers.update({"x-csrf-token": self.csrf_token})
                    self.api_prefix = f"{self.base_url}/proxy/network/api/s/{self.site}"
                    self.logged_in = True
                    return True
                elif res.status_code == 401:
                    # UniFi OS rejected credentials
                    err_detail = "Ungültige Anmeldedaten"
                    try:
                        err_json = res.json()
                        if "error" in err_json and isinstance(err_json["error"], dict):
                            err_detail = err_json["error"].get("message", "Unauthorized")
                        elif "meta" in err_json and isinstance(err_json["meta"], dict):
                            err_detail = err_json["meta"].get("msg", "Unauthorized")
                    except Exception:
                        pass
                    self.last_login_error = (
                        f"UniFi OS Authentifizierungsfehler ({err_detail}). "
                        "Wichtig: Für den lokalen Zugriff muss ein lokales Administratorkonto verwendet werden "
                        "(in UniFi OS unter 'Admins' -> 'Lokale Zugangsdaten'). "
                        "Ubiquiti SSO/Cloud-Konten mit aktivierter Zwei-Faktor-Authentifizierung (2FA) können per Passwort nicht lokal abgefragt werden. "
                        "Alternativ können Sie einen API-Key oder ein Backup (.unf/.unifi/.json) nutzen."
                    )
            except Exception as e:
                logger.debug(f"UniFi OS /api/auth/login attempt error: {e}")

        # 2. Try classic standalone Network Application login endpoints (/api/login, /api/s/{site}/login)
        for legacy_path in [f"{self.base_url}/api/login", f"{self.base_url}/api/s/{self.site}/login"]:
            try:
                res = self.session.post(
                    legacy_path,
                    json={"username": self.username, "password": self.password, "remember": True},
                    timeout=8
                )
                if res.status_code == 200:
                    csrf = res.headers.get("x-csrf-token") or res.headers.get("csrf-token") or ""
                    if csrf:
                        self.csrf_token = csrf
                        self.session.headers.update({"x-csrf-token": self.csrf_token})
                    self.api_prefix = f"{self.base_url}/api/s/{self.site}"
                    self.logged_in = True
                    return True
                elif res.status_code == 401 and not self.last_login_error:
                    self.last_login_error = "UniFi Network Authentifizierungsfehler (HTTP 401: Benutzername oder Passwort ungültig)."
            except Exception as e:
                logger.debug(f"Legacy login {legacy_path} attempt error: {e}")

        if not self.last_login_error:
            self.last_login_error = f"Verbindung zu UniFi unter {self.host}:{self.port} fehlgeschlagen (keine Antwort oder Timeout)."

        logger.error(f"Login failed: {self.last_login_error}")
        return False

    def test_connection(self) -> Tuple[bool, str]:
        try:
            if not self.login():
                return False, self.last_login_error or f"Authentication failed on {self.host}:{self.port}."
            # Verify network application responds
            sys_info_url = f"{self.api_prefix}/stat/sysinfo"
            res = self.session.get(sys_info_url, timeout=10)
            if res.status_code == 200:
                info = res.json().get("data", [{}])[0]
                version = info.get("version", "unknown")
                hostname = info.get("hostname", self.host)
                return True, f"Successfully connected to UniFi ({hostname}, Version {version})"
            return True, f"Authenticated with UniFi, but network API returned status {res.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def fetch_live_state(self, source_type: str = "ucg_max") -> UniFiSourceState:
        """
        Queries all live configuration objects from the UniFi controller / gateway:
        networks, WLAN SSIDs, adopted devices, known clients / fixed IPs, and firewall rules.
        """
        if not self.logged_in:
            if not self.login():
                raise RuntimeError(self.last_login_error or f"Konnte nicht an {self.host}:{self.port} authentifizieren.")

        version = "unknown"
        try:
            res = self.session.get(f"{self.api_prefix}/stat/sysinfo", timeout=10)
            if res.status_code == 200:
                version = res.json().get("data", [{}])[0].get("version", "unknown")
        except Exception:
            pass

        # 1. Networks
        networks = []
        try:
            res = self.session.get(f"{self.api_prefix}/rest/networkconf", timeout=10)
            if res.status_code == 200:
                networks = res.json().get("data", [])
        except Exception as e:
            logger.warning(f"Failed to fetch networks: {e}")

        # 2. WLAN SSIDs
        wlans = []
        try:
            res = self.session.get(f"{self.api_prefix}/rest/wlanconf", timeout=10)
            if res.status_code == 200:
                for w in res.json().get("data", []):
                    wlans.append(
                        UniFiWlan(
                            name=w.get("name", ""),
                            security=w.get("security", "wpapsk"),
                            x_passphrase=w.get("x_passphrase", ""),
                            vlan_id=w.get("vlan", None),
                            is_guest=w.get("is_guest", False),
                            enabled=w.get("enabled", True),
                            network_id=w.get("networkconf_id", None),
                        )
                    )
        except Exception as e:
            logger.warning(f"Failed to fetch wlanconf: {e}")

        # 3. Adopted Devices (APs & Switches)
        devices = []
        try:
            res = self.session.get(f"{self.api_prefix}/stat/device", timeout=10)
            if res.status_code == 200:
                for d in res.json().get("data", []):
                    devices.append(
                        UniFiDevice(
                            name=d.get("name") or d.get("model", "UniFi Device"),
                            mac=d.get("mac", ""),
                            model=d.get("model", ""),
                            ip=d.get("ip", ""),
                            device_type=d.get("type", "uap"),
                            adopted=d.get("adopted", True),
                        )
                    )
        except Exception as e:
            logger.warning(f"Failed to fetch devices: {e}")

        # 4. Clients / Fixed IPs
        clients = []
        try:
            res = self.session.get(f"{self.api_prefix}/rest/user", timeout=10)
            if res.status_code == 200:
                clients = res.json().get("data", [])
        except Exception as e:
            logger.warning(f"Failed to fetch clients: {e}")

        # 5. Firewall Rules
        firewall_rules = []
        try:
            res = self.session.get(f"{self.api_prefix}/rest/firewallrule", timeout=10)
            if res.status_code == 200:
                firewall_rules = res.json().get("data", [])
        except Exception as e:
            logger.warning(f"Failed to fetch firewall rules: {e}")

        return UniFiSourceState(
            source_type=source_type,
            host=self.host,
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

    def dry_run(self, target_config: UniFiTargetConfig) -> Dict[str, Any]:
        """
        Simulates the rollout without altering the device.
        Produces an audit report detailing all actions to be performed.
        """
        report = {
            "dry_run": True,
            "target_gateway": self.host,
            "networks_to_create": [],
            "firewall_groups_to_create": [],
            "firewall_rules_to_create": [],
            "port_forwards_to_create": [],
            "fixed_ips_to_assign": [],
            "dns_records_to_create": [
                {"key": r.key, "value": r.value, "type": r.record_type}
                for r in getattr(target_config, "dns_records", [])
            ],
            "traffic_rules_to_create": [
                {"name": tr.name, "action": tr.action, "target": tr.target}
                for tr in getattr(target_config, "traffic_rules", [])
            ],
            "wireguard_servers_to_create": [
                {"name": wg.name, "port": wg.port, "tunnel": wg.tunnel_subnet}
                for wg in getattr(target_config, "wireguard_servers", [])
            ],
            "dynamic_dns_to_create": [
                {"service": d.service, "host_name": d.host_name, "interface": d.interface}
                for d in getattr(target_config, "dynamic_dns", [])
                if getattr(d, "status", "accepted") != "excluded"
            ],
            "static_routes_to_create": [
                {"name": r.name, "network": r.network, "next_hop": r.next_hop, "distance": r.distance}
                for r in getattr(target_config, "static_routes", [])
                if getattr(r, "status", "accepted") != "excluded"
            ],
            "dns_forwardings_to_create": [
                {"domain": f.domain, "forward_to_ip": f.forward_to_ip}
                for f in getattr(target_config, "dns_forwardings", [])
                if getattr(f, "status", "accepted") != "excluded"
            ],
            "ntp_settings": (
                {"upstream_servers": ntp.upstream_servers}
                if (ntp := getattr(target_config, "ntp_settings", None)) else None
            ),
            "syslog_settings": (
                {"server": sl.server, "port": sl.port, "enabled": sl.enabled}
                if (sl := getattr(target_config, "syslog_settings", None)) else None
            ),
            "snmp_settings": (
                {"community": sn.community, "enabled": sn.enabled}
                if (sn := getattr(target_config, "snmp_settings", None)) else None
            ),
            "smart_queue": (
                {"enabled": sq.enabled, "down_kbps": sq.down_rate_kbps, "up_kbps": sq.up_rate_kbps}
                if (sq := getattr(target_config, "smart_queue", None)) else None
            ),
            "omitted_items": [
                {
                    "category": o.category,
                    "name": o.name,
                    "reason": o.reason,
                    "recommendation": o.recommendation,
                    "severity": o.severity,
                }
                for o in getattr(target_config, "omitted_items", [])
            ],
            "warnings": [],
        }

        # Check networks
        for net in target_config.networks:
            report["networks_to_create"].append({
                "name": net.name,
                "vlan": net.vlan_id,
                "cidr": net.gateway_cidr,
                "dhcp": f"{net.dhcp_start} - {net.dhcp_stop}" if net.dhcp_enabled else "disabled",
            })

        # Check groups
        for grp in target_config.firewall_groups:
            report["firewall_groups_to_create"].append({
                "name": grp.name,
                "type": grp.group_type,
                "members_count": len(grp.members),
                "members": grp.members,
            })

        # Check rules
        for rule in target_config.firewall_rules:
            if not rule.enabled or getattr(rule, "status", "accepted") == "discarded":
                continue
            report["firewall_rules_to_create"].append({
                "index": rule.rule_index,
                "ruleset": rule.ruleset,
                "action": rule.action,
                "name": rule.name,
                "protocol": rule.protocol,
                "description": rule.description,
            })

        # Check port forwards
        for pf in target_config.port_forwards:
            report["port_forwards_to_create"].append({
                "name": pf.name,
                "external_port": pf.dst_port,
                "target": f"{pf.fwd_ip}:{pf.fwd_port}",
                "protocol": pf.protocol,
            })

        # Check fixed IPs
        for fip in target_config.fixed_ips:
            report["fixed_ips_to_assign"].append({
                "mac": fip.mac,
                "name": fip.name,
                "fixed_ip": fip.fixed_ip,
                "network": fip.network_name,
            })

        # Check for Inter-VLAN warning
        has_block_rule = any(
            r.ruleset == "LAN_IN" and r.action == "drop" and "RFC1918" in str(r.src_firewall_group_names)
            for r in target_config.firewall_rules
        )
        if not has_block_rule:
            report["warnings"].append(
                "WARNING: No Inter-VLAN Block Drop rule detected on LAN_IN. In UniFi, corporate VLANs will be able to communicate freely unless explicitly blocked!"
            )

        return report

    def deploy(self, target_config: UniFiTargetConfig) -> Dict[str, Any]:
        """
        Executes live provisioning on the UniFi Cloud Gateway Max.
        """
        if not self.logged_in and not self.login():
            raise RuntimeError(f"Cannot deploy: Authentication to {self.host} failed.")

        results = {
            "created_networks": 0,
            "created_groups": 0,
            "created_rules": 0,
            "created_port_forwards": 0,
            "assigned_fixed_ips": 0,
            "errors": [],
        }

        # Step 1: Create Firewall Groups first (rules reference them)
        group_id_map: Dict[str, str] = {}
        for grp in target_config.firewall_groups:
            try:
                gid = self._create_firewall_group(grp)
                group_id_map[grp.name] = gid
                results["created_groups"] += 1
            except Exception as e:
                results["errors"].append(f"Firewall group '{grp.name}' error: {str(e)}")

        # Step 2: Create Networks
        network_id_map: Dict[str, str] = {}
        for net in target_config.networks:
            try:
                nid = self._create_network(net)
                network_id_map[net.name] = nid
                results["created_networks"] += 1
            except Exception as e:
                results["errors"].append(f"Network '{net.name}' error: {str(e)}")

        # Step 3: Create Firewall Rules
        for rule in target_config.firewall_rules:
            if not rule.enabled or getattr(rule, "status", "accepted") == "discarded":
                continue
            try:
                self._create_firewall_rule(rule, group_id_map)
                results["created_rules"] += 1
            except Exception as e:
                results["errors"].append(f"Firewall rule '{rule.name}' error: {str(e)}")

        # Step 4: Create Port Forwards
        for pf in target_config.port_forwards:
            try:
                self._create_port_forward(pf)
                results["created_port_forwards"] += 1
            except Exception as e:
                results["errors"].append(f"Port Forward '{pf.name}' error: {str(e)}")

        # Step 5: Assign Fixed IPs
        for fip in target_config.fixed_ips:
            try:
                nid = network_id_map.get(fip.network_name)
                self._create_fixed_ip(fip, network_id=nid)
                results["assigned_fixed_ips"] += 1
            except Exception as e:
                results["errors"].append(f"Fixed IP '{fip.name} ({fip.mac})' error: {str(e)}")

        # Step 6: Create Static DNS Records
        results["created_dns_records"] = 0
        for dns_rec in getattr(target_config, "dns_records", []):
            try:
                self._create_dns_record(dns_rec)
                results["created_dns_records"] += 1
            except Exception as e:
                results["errors"].append(f"DNS Record '{dns_rec.key}' error: {str(e)}")

        # Step 7: Create Traffic Rules (Domain / Region blocking)
        results["created_traffic_rules"] = 0
        for tr in getattr(target_config, "traffic_rules", []):
            try:
                self._create_traffic_rule(tr)
                results["created_traffic_rules"] += 1
            except Exception as e:
                results["errors"].append(f"Traffic Rule '{tr.name}' error: {str(e)}")

        # Step 8: Create Dynamic DNS
        results["created_dynamic_dns"] = 0
        for ddns in getattr(target_config, "dynamic_dns", []):
            if getattr(ddns, "status", "accepted") == "excluded":
                continue
            try:
                self._create_dynamic_dns(ddns)
                results["created_dynamic_dns"] += 1
            except Exception as e:
                results["errors"].append(f"Dynamic DNS '{ddns.host_name}' error: {str(e)}")

        # Step 9: Create Static Routes
        results["created_static_routes"] = 0
        for r in getattr(target_config, "static_routes", []):
            if getattr(r, "status", "accepted") == "excluded":
                continue
            try:
                self._create_static_route(r)
                results["created_static_routes"] += 1
            except Exception as e:
                results["errors"].append(f"Static Route '{r.name}' error: {str(e)}")

        return results

    def _create_dns_record(self, rec) -> str:
        url = f"{self.api_prefix}/rest/dnsrecord"
        payload = {
            "key": rec.key,
            "record_type": rec.record_type,
            "value": rec.value,
            "enabled": rec.enabled,
        }
        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_traffic_rule(self, tr) -> str:
        url = f"{self.api_prefix}/rest/trafficrule"
        payload = {
            "description": tr.name,
            "action": tr.action.lower(),
            "target": tr.target.lower(),
            "domains": tr.domains,
            "regions": tr.regions,
            "enabled": True,
        }
        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_network(self, net: UniFiNetwork) -> str:
        url = f"{self.api_prefix}/rest/networkconf"
        payload = {
            "name": net.name,
            "purpose": net.purpose,
            "vlan": str(net.vlan_id) if net.vlan_id > 1 else "",
            "vlan_enabled": net.vlan_id > 1,
            "ip_subnet": net.gateway_cidr,
            "dhcpd_enabled": net.dhcp_enabled,
            "dhcp_start": net.dhcp_start if net.dhcp_enabled else "",
            "dhcp_stop": net.dhcp_stop if net.dhcp_enabled else "",
            "domain_name": net.domain_name,
        }
        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_firewall_group(self, grp: UniFiFirewallGroup) -> str:
        url = f"{self.api_prefix}/rest/firewallgroup"
        payload = {
            "name": grp.name,
            "group_type": grp.group_type,
            "group_members": grp.members,
        }
        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_firewall_rule(self, rule: UniFiFirewallRule, group_map: Dict[str, str]) -> str:
        url = f"{self.api_prefix}/rest/firewallrule"
        
        src_group_ids = [group_map[g] for g in rule.src_firewall_group_names if g in group_map]
        dst_group_ids = [group_map[g] for g in rule.dst_firewall_group_names if g in group_map]

        payload = {
            "name": rule.name,
            "ruleset": rule.ruleset,
            "action": rule.action,
            "rule_index": rule.rule_index,
            "enabled": rule.enabled,
            "protocol": rule.protocol,
            "logging": rule.logging,
            "state_established": rule.state_established,
            "state_related": rule.state_related,
            "state_invalid": rule.state_invalid,
            "src_firewallgroup_ids": src_group_ids,
            "dst_firewallgroup_ids": dst_group_ids,
        }
        if rule.src_address:
            payload["src_address"] = rule.src_address
        if rule.dst_address:
            payload["dst_address"] = rule.dst_address
        if rule.dst_port:
            payload["dst_port"] = rule.dst_port

        if getattr(rule, "src_inverted", False):
            payload["src_firewallgroup_match_opposite"] = True
            payload["src_address_match_opposite"] = True
            payload["src_network_match_opposite"] = True
            payload["src_mac_match_opposite"] = True

        if getattr(rule, "dst_inverted", False):
            payload["dst_firewallgroup_match_opposite"] = True
            payload["dst_address_match_opposite"] = True
            payload["dst_network_match_opposite"] = True
            payload["dst_port_match_opposite"] = True

        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_port_forward(self, pf: UniFiPortForward) -> str:
        url = f"{self.api_prefix}/rest/portforward"
        payload = {
            "name": pf.name,
            "fwd_port": pf.fwd_port,
            "dst_port": pf.dst_port,
            "fwd": pf.fwd_ip,
            "proto": pf.protocol,
            "enabled": pf.enabled,
        }
        if pf.src_ip:
            payload["src"] = pf.src_ip

        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_fixed_ip(self, fip: UniFiFixedIp, network_id: Optional[str] = None) -> str:
        url = f"{self.api_prefix}/rest/user"
        payload = {
            "mac": fip.mac,
            "name": fip.name,
            "fixed_ip": fip.fixed_ip,
            "use_fixedip": True,
        }
        if network_id:
            payload["network_id"] = network_id

        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_dynamic_dns(self, ddns: UniFiDynDns) -> str:
        url = f"{self.api_prefix}/rest/dynamicdns"
        payload = {
            "service": ddns.service.lower(),
            "host_name": ddns.host_name,
            "login": ddns.login,
            "x_password": ddns.password,
            "interface": ddns.interface.lower(),
            "server": ddns.server or "",
        }
        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")

    def _create_static_route(self, r: UniFiStaticRoute) -> str:
        url = f"{self.api_prefix}/rest/routing"
        payload = {
            "description": r.name,
            "static_route_network": r.network,
            "static_route_next_hop": r.next_hop,
            "static_route_distance": r.distance,
            "type": "nexthop-route",
            "enabled": r.enabled,
        }
        res = self.session.post(url, json=payload, timeout=10)
        if res.status_code in [200, 201]:
            data = res.json().get("data", [{}])[0]
            return data.get("_id", "")
        raise RuntimeError(f"HTTP {res.status_code}: {res.text}")
