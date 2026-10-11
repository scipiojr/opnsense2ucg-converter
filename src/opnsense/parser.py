"""
Parser for OPNsense configuration XML (config.xml).
Extracts Interfaces, VLANs, DHCP settings (ISC & Kea), Aliases, NAT rules, and Firewall filter rules.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple
from src.models import (
    OPNsenseConfig,
    OPNsenseInterface,
    OPNsenseStaticLease,
    OPNsenseDhcpRange,
    OPNsenseAlias,
    OPNsensePortForward,
    OPNsenseFilterRule,
    OPNsenseDnsHost,
    OPNsenseWireGuard,
    OPNsenseTrafficShaper,
    OPNsenseModemManagement,
    OmittedItem,
)


class OPNsenseParser:
    def __init__(self, xml_content: str):
        self.raw_xml = xml_content
        self.root = ET.fromstring(xml_content.strip())
        self.version = self._extract_version()

    def _extract_version(self) -> str:
        version_el = self.root.find(".//version")
        if version_el is not None and version_el.text:
            return version_el.text.strip()
        theme_el = self.root.find(".//theme")
        return "OPNsense (unknown version)"

    def parse(self) -> OPNsenseConfig:
        config = OPNsenseConfig(version=self.version, raw_xml=self.raw_xml)
        
        # 1. Parse VLAN definitions
        vlans_map = self._parse_vlans()

        # 2. Parse Interfaces
        config.interfaces = self._parse_interfaces(vlans_map)

        # 2b. Detect Modem Management (VDSL / DrayTek WebUI access)
        config.modem_management = self._detect_modem_management(config.interfaces, vlans_map)

        # 3. Parse DHCP (ISC dhcpd & Kea)
        config.dhcp_ranges, config.static_leases = self._parse_dhcp()

        # 4. Parse Aliases
        config.aliases = self._parse_aliases()

        # 5. Parse NAT Port Forwards
        config.port_forwards = self._parse_nat()

        # 6. Parse Firewall Filter Rules
        config.filter_rules = self._parse_filter_rules()

        # 7. Parse Advanced Extended Services (DNS Overrides, WireGuard, QoS)
        config.dns_hosts = self._parse_dns_hosts()
        config.wireguard_servers = self._parse_wireguard()
        config.traffic_shaper = self._parse_traffic_shaper()

        # 8. Detect Remaining Omitted / Non-migrated Items
        config.omitted_items = self._detect_omitted_items(config)

        return config

    def _parse_vlans(self) -> Dict[str, Tuple[int, str, str]]:
        """
        Extracts VLANs and maps vlanif (e.g. 'vlan0.10' or 'igb0_vlan10') to (tag, parent_if, descr).
        """
        vlans: Dict[str, Tuple[int, str, str]] = {}
        for vlan in self.root.findall(".//vlans/vlan"):
            vlanif = self._get_text(vlan, "vlanif")
            tag_str = self._get_text(vlan, "tag")
            parent_if = self._get_text(vlan, "if")
            descr = self._get_text(vlan, "descr")

            if tag_str.isdigit():
                tag = int(tag_str)
                if vlanif:
                    vlans[vlanif] = (tag, parent_if, descr)
                # Also index by generated tag key in case interface uses format like vlan0.<tag>
                vlans[f"vlan_{tag}"] = (tag, parent_if, descr)
        return vlans

    def _parse_interfaces(self, vlans_map: Dict[str, Tuple[int, str, str]]) -> List[OPNsenseInterface]:
        interfaces: List[OPNsenseInterface] = []
        interfaces_node = self.root.find("interfaces")
        if interfaces_node is None:
            return interfaces

        for if_node in interfaces_node:
            if_id = if_node.tag
            descr = self._get_text(if_node, "descr") or if_id.upper()
            physical_if = self._get_text(if_node, "if")
            ipaddr = self._get_text(if_node, "ipaddr") or ""
            subnet = self._get_text(if_node, "subnet") or ""
            gateway = self._get_text(if_node, "gateway") or None
            enabled = self._get_text(if_node, "enable") != "0" and if_node.find("enable") is not None

            # Detect VLAN tag
            vlan_tag: Optional[int] = None
            if physical_if in vlans_map:
                vlan_tag = vlans_map[physical_if][0]
            elif "." in physical_if:
                # e.g. igb0.10 or vlan0.20
                parts = physical_if.split(".")
                if len(parts) == 2 and parts[1].isdigit():
                    vlan_tag = int(parts[1])
            elif "_vlan" in physical_if:
                parts = physical_if.split("_vlan")
                if len(parts) == 2 and parts[1].isdigit():
                    vlan_tag = int(parts[1])

            interfaces.append(
                OPNsenseInterface(
                    id=if_id,
                    descr=descr,
                    physical_if=physical_if,
                    ipaddr=ipaddr,
                    subnet=subnet,
                    gateway=gateway,
                    vlan_tag=vlan_tag,
                    enabled=enabled,
                )
            )
        return interfaces

    def _detect_modem_management(
        self,
        interfaces: List[OPNsenseInterface],
        vlans_map: Dict[str, Tuple[int, str, str]],
    ) -> Optional[OPNsenseModemManagement]:
        """
        Detects if a VDSL modem management connection is present in OPNsense
        (e.g., dual-connected via an untagged parent interface or separate VLAN,
        as in DrayTek Vigor / Zyxel bridge mode setups).
        """
        wan_if = next((i for i in interfaces if i.id.lower() == "wan"), None)
        if not wan_if:
            return None

        # Determine WAN parent physical interface
        wan_phys = wan_if.physical_if
        wan_parent = wan_phys
        if wan_phys in vlans_map:
            wan_parent = vlans_map[wan_phys][1]
        elif "." in wan_phys:
            wan_parent = wan_phys.split(".")[0]
        elif "_vlan" in wan_phys:
            wan_parent = wan_phys.split("_vlan")[0]

        candidate_if: Optional[OPNsenseInterface] = None
        detection_reason = ""

        for iface in interfaces:
            if iface.id.lower() in ("wan", "lan") or not iface.ipaddr:
                continue

            # Determine this interface's physical parent
            if_phys = iface.physical_if
            if_parent = if_phys
            if if_phys in vlans_map:
                if_parent = vlans_map[if_phys][1]
            elif "." in if_phys:
                if_parent = if_phys.split(".")[0]
            elif "_vlan" in if_phys:
                if_parent = if_phys.split("_vlan")[0]

            descr_lower = iface.descr.lower()
            id_lower = iface.id.lower()
            has_modem_name = any(k in descr_lower or k in id_lower for k in ("modem", "draytek", "vigor", "vdsl", "dsl_mgmt"))

            # 1. Shares physical parent interface with WAN (Classic OPNsense Dual-Attachment on WAN NIC)
            if if_parent == wan_parent and if_parent:
                candidate_if = iface
                detection_reason = f"Teilt physischen WAN-Port ({wan_parent}) mit Interface '{iface.descr}'"
                break

            # 2. Explicit Modem / DrayTek name
            if has_modem_name:
                candidate_if = iface
                detection_reason = f"Interface '{iface.descr}' ist namentlich als Modem-Interface deklariert"
                break

            # 3. Known modem management IP subnet (e.g. 192.168.2.x, typical for DrayTek/Zyxel)
            if iface.ipaddr.startswith("192.168.2.") and iface.id.lower() != "lan":
                candidate_if = iface
                detection_reason = f"Interface '{iface.descr}' nutzt Standard-Modem-Subnetz 192.168.2.0/24"
                break

        if not candidate_if:
            return None

        # Determine modem IP (target WebUI)
        gateway_ip = candidate_if.ipaddr
        subnet = candidate_if.subnet or "24"
        modem_ip = candidate_if.gateway or ""

        if not modem_ip:
            if gateway_ip.endswith(".2"):
                # e.g. OPNsense has 192.168.2.2, modem has 192.168.2.1
                modem_ip = gateway_ip[:-1] + "1"
            elif gateway_ip.startswith("192.168.2."):
                modem_ip = "192.168.2.1"
            else:
                prefix = gateway_ip.rsplit(".", 1)[0]
                modem_ip = f"{prefix}.1"

        # Determine allocated VLAN (avoid collision with existing VLANs)
        used_vlans = {i.vlan_tag for i in interfaces if i.vlan_tag is not None}
        used_vlans.add(1)
        allocated_vlan = candidate_if.vlan_tag if (candidate_if.vlan_tag and candidate_if.vlan_tag > 1) else None
        if not allocated_vlan:
            for candidate_vlan in [99, 98, 97, 199, 200, 299]:
                if candidate_vlan not in used_vlans:
                    allocated_vlan = candidate_vlan
                    break
            if not allocated_vlan:
                allocated_vlan = max(used_vlans) + 1

        return OPNsenseModemManagement(
            detected=True,
            interface_id=candidate_if.id,
            interface_descr=candidate_if.descr or "MODEM_MGMT",
            parent_if=wan_parent,
            modem_ip=modem_ip,
            gateway_ip=gateway_ip,
            subnet=subnet,
            existing_vlan=candidate_if.vlan_tag,
            allocated_vlan=allocated_vlan,
            reason=detection_reason,
        )

    def _parse_dhcp(self) -> Tuple[List[OPNsenseDhcpRange], List[OPNsenseStaticLease]]:
        ranges: List[OPNsenseDhcpRange] = []
        static_leases: List[OPNsenseStaticLease] = []

        # 1. ISC DHCP (<dhcpd>)
        dhcpd_node = self.root.find("dhcpd")
        if dhcpd_node is not None:
            for if_node in dhcpd_node:
                if_id = if_node.tag
                enable = if_node.find("enable") is not None
                if not enable:
                    continue

                range_node = if_node.find("range")
                range_from = self._get_text(range_node, "from") if range_node is not None else ""
                range_to = self._get_text(range_node, "to") if range_node is not None else ""
                gateway = self._get_text(if_node, "gateway")

                dns_servers = []
                for dns_tag in ["dnsserver", "dns1", "dns2"]:
                    for dns_el in if_node.findall(dns_tag):
                        if dns_el.text:
                            dns_servers.append(dns_el.text.strip())

                if range_from and range_to:
                    ranges.append(
                        OPNsenseDhcpRange(
                            interface=if_id,
                            range_from=range_from,
                            range_to=range_to,
                            dns_servers=dns_servers,
                            gateway=gateway,
                        )
                    )

                for sm in if_node.findall("staticmap"):
                    mac = self._get_text(sm, "mac").lower().replace("-", ":")
                    ip = self._get_text(sm, "ipaddr")
                    hostname = self._get_text(sm, "hostname")
                    descr = self._get_text(sm, "descr") or hostname or ip
                    if mac and ip:
                        static_leases.append(
                            OPNsenseStaticLease(
                                mac=mac,
                                ipaddr=ip,
                                hostname=hostname or descr or "device",
                                descr=descr,
                                interface=if_id,
                            )
                        )

        # 2. Kea DHCP (<kea>)
        kea_reservations = self.root.findall(".//kea/dhcp4/subnets/subnet")
        for subnet in kea_reservations:
            subnet_str = self._get_text(subnet, "subnet")
            # Parse Kea reservations
            for res in subnet.findall(".//reservations/reservation"):
                mac = self._get_text(res, "hw_address").lower().replace("-", ":")
                ip = self._get_text(res, "ip_address")
                hostname = self._get_text(res, "hostname")
                descr = self._get_text(res, "description") or hostname or ip
                if mac and ip:
                    # check if already added
                    if not any(sl.mac == mac and sl.ipaddr == ip for sl in static_leases):
                        static_leases.append(
                            OPNsenseStaticLease(
                                mac=mac,
                                ipaddr=ip,
                                hostname=hostname or descr or "device",
                                descr=descr,
                                interface="kea",
                            )
                        )

        return ranges, static_leases

    def _parse_aliases(self) -> List[OPNsenseAlias]:
        aliases: List[OPNsenseAlias] = []
        # OPNsense stores aliases in <aliases><alias> or <firewall><aliases><alias>
        alias_nodes = self.root.findall(".//aliases/alias")
        for node in alias_nodes:
            name = self._get_text(node, "name")
            alias_type = self._get_text(node, "type") or "host"
            descr = self._get_text(node, "descr")

            raw_content = self._get_text(node, "content") or self._get_text(node, "address")
            content_items: List[str] = []
            if raw_content:
                # Can be space, newline, or comma separated
                items = raw_content.replace(",", " ").replace("\n", " ").split()
                content_items = [it.strip() for it in items if it.strip()]

            if name:
                aliases.append(
                    OPNsenseAlias(
                        name=name,
                        type=alias_type,
                        content=content_items,
                        descr=descr,
                    )
                )
        return aliases

    def _parse_nat(self) -> List[OPNsensePortForward]:
        port_forwards: List[OPNsensePortForward] = []
        for rule in self.root.findall(".//nat/rule"):
            # Check if this is a port forward (nordr is not set or empty)
            nordr = self._get_text(rule, "nordr")
            if nordr:
                continue  # skip no-redirect rules

            interface = self._get_text(rule, "interface") or "wan"
            protocol = self._get_text(rule, "protocol") or "tcp"
            target_ip = self._get_text(rule, "target")
            local_port = self._get_text(rule, "local-port")
            descr = self._get_text(rule, "descr")
            disabled = rule.find("disabled") is not None

            # Destination
            dst_node = rule.find("destination")
            dst_ip = "any"
            dst_port = ""
            if dst_node is not None:
                dst_ip = self._get_text(dst_node, "network") or self._get_text(dst_node, "address") or "any"
                dst_port = self._get_text(dst_node, "port")

            # Source
            src_node = rule.find("source")
            src_ip = "any"
            src_port = "any"
            if src_node is not None:
                src_ip = self._get_text(src_node, "network") or self._get_text(src_node, "address") or "any"
                src_port = self._get_text(src_node, "port") or "any"

            if target_ip and (local_port or dst_port):
                port_forwards.append(
                    OPNsensePortForward(
                        interface=interface,
                        protocol=protocol,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port or local_port,
                        target_ip=target_ip,
                        target_port=local_port or dst_port,
                        descr=descr,
                        enabled=not disabled,
                    )
                )
        return port_forwards

    def _parse_filter_rules(self) -> List[OPNsenseFilterRule]:
        filter_rules: List[OPNsenseFilterRule] = []
        rule_nodes = self.root.findall(".//filter/rule")
        
        for idx, rule in enumerate(rule_nodes):
            floating_val = self._get_text(rule, "floating")
            is_floating = floating_val.lower() in ("yes", "1", "true") or rule.find("floating") is not None
            action = self._get_text(rule, "type") or "pass"
            raw_interface = self._get_text(rule, "interface")
            interface = raw_interface if raw_interface else ("any" if is_floating else "lan")
            direction = self._get_text(rule, "direction") or "in"
            protocol = self._get_text(rule, "protocol") or "any"
            descr = self._get_text(rule, "descr")
            disabled = rule.find("disabled") is not None
            log = rule.find("log") is not None
            quick = self._get_text(rule, "quick") != "no"

            # Parse Source
            src_node = rule.find("source")
            src = "any"
            src_port = "any"
            src_inv = False
            if src_node is not None:
                src = (
                    self._get_text(src_node, "network")
                    or self._get_text(src_node, "address")
                    or "any"
                )
                src_port = self._get_text(src_node, "port") or "any"
                src_inv = src_node.find("not") is not None

            # Parse Destination
            dst_node = rule.find("destination")
            dst = "any"
            dst_port = "any"
            dst_inv = False
            if dst_node is not None:
                dst = (
                    self._get_text(dst_node, "network")
                    or self._get_text(dst_node, "address")
                    or "any"
                )
                dst_port = self._get_text(dst_node, "port") or "any"
                dst_inv = dst_node.find("not") is not None

            filter_rules.append(
                OPNsenseFilterRule(
                    id=f"rule_{idx+1}",
                    interface=interface,
                    direction=direction,
                    action=action,
                    protocol=protocol,
                    src=src,
                    src_port=src_port,
                    dst=dst,
                    dst_port=dst_port,
                    descr=descr,
                    enabled=not disabled,
                    log=log,
                    is_quick=quick,
                    is_floating=is_floating,
                    src_inverted=src_inv,
                    dst_inverted=dst_inv,
                )
            )

        return filter_rules

    def _parse_dns_hosts(self) -> List[OPNsenseDnsHost]:
        dns_hosts: List[OPNsenseDnsHost] = []
        for host_node in self.root.findall(".//unbound/hosts"):
            host = self._get_text(host_node, "host")
            domain = self._get_text(host_node, "domain")
            ip = self._get_text(host_node, "ip")
            descr = self._get_text(host_node, "descr")
            if ip and (host or domain):
                dns_hosts.append(OPNsenseDnsHost(host=host, domain=domain, ip=ip, descr=descr))
        return dns_hosts

    def _parse_wireguard(self) -> List[OPNsenseWireGuard]:
        wg_list: List[OPNsenseWireGuard] = []
        for s_node in self.root.findall(".//wireguard/server"):
            name = self._get_text(s_node, "name") or "WireGuard-Server"
            port_str = self._get_text(s_node, "port") or "51820"
            port = int(port_str) if port_str.isdigit() else 51820
            tunnel = self._get_text(s_node, "tunnel_address") or "10.10.0.1/24"
            pub = self._get_text(s_node, "pubkey")
            wg_list.append(OPNsenseWireGuard(name=name, port=port, tunnel_address=tunnel, public_key=pub))
        return wg_list

    def _parse_traffic_shaper(self) -> Optional[OPNsenseTrafficShaper]:
        shaper_node = self.root.find(".//dnshaper")
        if shaper_node is None:
            shaper_node = self.root.find(".//trafficshaper")
        if shaper_node is None:
            return None

        down = 0
        up = 0
        for pipe in shaper_node.findall(".//pipe"):
            bw_str = self._get_text(pipe, "bandwidth")
            descr = self._get_text(pipe, "descr").lower()
            if bw_str.isdigit():
                bw = int(bw_str)
                if "up" in descr:
                    up = bw
                else:
                    down = bw
        if down or up:
            return OPNsenseTrafficShaper(down_rate_kbps=down, up_rate_kbps=up)
        return None

    def _detect_omitted_items(self, config: Optional[OPNsenseConfig] = None) -> List[OmittedItem]:
        """
        Scans OPNsense XML for features that cannot be mapped 1:1,
        accounting for all elements that our extended translator now automates.
        """
        omitted: List[OmittedItem] = []

        # 1. OpenVPN & IPsec (WireGuard is now auto-converted as UniFi blueprint)
        if self.root.find(".//openvpn") is not None or self.root.find(".//openvpn-server") is not None:
            omitted.append(
                OmittedItem(
                    category="VPN",
                    name="OpenVPN Server / Client Instanzen",
                    reason="OpenVPN-Server und CA-Zertifikatsketten werden in UniFi OS nativ verwaltet und können nicht als rohe pf-Objekte importiert werden.",
                    recommendation="Unter 'Settings > VPN > VPN Server' als OpenVPN einrichten oder idealerweise auf das nun automatisch vorbereitete WireGuard umstellen.",
                    severity="action_required",
                )
            )

        if self.root.find(".//ipsec") is not None:
            omitted.append(
                OmittedItem(
                    category="VPN",
                    name="IPsec Tunnel (Phase 1 & Phase 2)",
                    reason="IPsec-Spezifika (IKEv1/v2 Proposals, PSK, P1/P2) müssen in UniFi über das native Site-to-Site Interface konfiguriert werden.",
                    recommendation="In UniFi unter 'Settings > VPN > Site-to-Site VPN' als IPsec Tunnel neu konfigurieren.",
                    severity="action_required",
                )
            )

        # 2. Floating Rules with non-standard pf evaluation (non-quick)
        for idx, rule in enumerate(self.root.findall(".//filter/rule")):
            floating_val = self._get_text(rule, "floating")
            floating = floating_val.lower() in ("yes", "1", "true") or rule.find("floating") is not None
            descr = self._get_text(rule, "descr") or f"Regel #{idx+1}"

            if floating:
                quick = self._get_text(rule, "quick") != "no"
                if not quick:
                    omitted.append(
                        OmittedItem(
                            category="Firewall",
                            name=f"Floating Rule '{descr}' (Non-Quick)",
                            reason="Diese Floating Rule verwendet 'non-quick' (in FreeBSD/pf gewinnt die letzte passende Regel). UniFi arbeitet strikt nach First-Match-Priorität (von oben nach unten).",
                            recommendation="Die Regel wurde konvertiert. Prüfen Sie die Positionierung in der UniFi Firewall-Regelliste.",
                            severity="info",
                        )
                    )

        # 3. FreeBSD User Accounts & Plugins
        users = self.root.findall(".//system/user")
        if users:
            usernames = [self._get_text(u, "name") for u in users if self._get_text(u, "name") != "root"]
            if usernames:
                omitted.append(
                    OmittedItem(
                        category="System",
                        name=f"FreeBSD Benutzerkonten ({', '.join(usernames)})",
                        reason="UniFi OS besitzt eine eigene Linux-Benutzerverwaltung mit Rollen und 2FA und übernimmt keine FreeBSD-Passworthashes.",
                        recommendation="Zusätzliche Administratoren in UniFi OS unter 'Admins & Users' einladen.",
                        severity="info",
                    )
                )

        if self.root.find(".//installedpackages") is not None:
            omitted.append(
                OmittedItem(
                    category="Plugins",
                    name="OPNsense Erweiterungspakete (z.B. Zenarmor, HAProxy, ACME)",
                    reason="FreeBSD-Plugins können auf UniFi OS nicht installiert werden. Viele Funktionen (IDS/IPS, DPI, Adblock) sind in UniFi OS bereits nativ integriert.",
                    recommendation="Integrierte Schutzfunktionen in UniFi unter 'Settings > Security > CyberSecure' (Suspicious Activity / IDS/IPS) aktivieren.",
                    severity="info",
                )
            )

        # 4. VDSL Modem Management (Bridge WebUI access)
        if config and config.modem_management and config.modem_management.detected:
            mm = config.modem_management
            omitted.append(
                OmittedItem(
                    category="Hardware / WAN",
                    name=f"VDSL-Modem WebUI & Management ({mm.modem_ip})",
                    reason=(
                        f"In OPNsense lief das Modem über Interface '{mm.interface_id}' ({mm.parent_if}). "
                        "UniFi OS unterstützt kein direktes IP-Aliasing auf PPPoE-WAN-Ports im Web-GUI."
                    ),
                    recommendation=(
                        f"Dediziertes UniFi-Netzwerk 'MODEM_MGMT' (VLAN {mm.allocated_vlan}, Subnetz {mm.gateway_ip}/{mm.subnet}) "
                        f"sowie Pinhole-Firewall-Regel für {mm.modem_ip} (Ports 80/443) wurden angelegt. "
                        f"Verbinden Sie Port 2 des Modems mit einem Port (z.B. UCG Port 4 oder Switch) mit nativem VLAN {mm.allocated_vlan}."
                    ),
                    severity="info",
                )
            )

        return omitted

    @staticmethod
    def _get_text(node: Optional[ET.Element], child_tag: str) -> str:
        if node is None:
            return ""
        child = node.find(child_tag)
        if child is not None and child.text:
            return child.text.strip()
        return ""
