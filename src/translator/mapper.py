"""
Translates OPNsense data structures to UniFi Network configurations.
Handles the fundamental architectural paradigm shifts:
- OPNsense (Interface-centric, Default-Deny between VLANs)
- UniFi Network (Central Corporate Networks, Default-Allow between VLANs)
Ensures UniFi LAN_IN rules include established/related state and explicit RFC1918 Inter-VLAN isolation.
"""

import ipaddress
from typing import List, Dict, Optional, Tuple, Set
from src.models import (
    OPNsenseConfig,
    OPNsenseInterface,
    OPNsenseStaticLease,
    OPNsenseAlias,
    OPNsensePortForward,
    OPNsenseFilterRule,
    UniFiTargetConfig,
    UniFiNetwork,
    UniFiFirewallGroup,
    UniFiFirewallRule,
    UniFiFixedIp,
    UniFiPortForward,
    UniFiNatRule,
    UniFiDnsRecord,
    UniFiDnsForwarding,
    UniFiDynDns,
    UniFiStaticRoute,
    UniFiMultiWan,
    UniFiNtpSetting,
    UniFiSyslog,
    UniFiSnmp,
    UniFiMulticast,
    UniFiUpnp,
    UniFiTrafficRoute,
    UniFiTrafficRule,
    UniFiWireGuardServer,
    UniFiSmartQueue,
)


class UniFiMapper:
    def __init__(self, opnsense_config: OPNsenseConfig):
        self.cfg = opnsense_config
        self.rfc1918_group_name = "RFC1918_Private_Subnets"

    def map_all(self, enforce_inter_vlan_block: bool = True) -> UniFiTargetConfig:
        target = UniFiTargetConfig()

        # 1. Map Networks / VLANs
        target.networks = self.map_networks()

        # 2. Map Aliases to Firewall Groups
        target.firewall_groups = self.map_firewall_groups()

        # 3. Map Fixed IP Leases
        target.fixed_ips = self.map_fixed_ips(target.networks)

        # 4. Map Port Forwards & NAT Rules
        target.port_forwards = self.map_port_forwards()
        target.nat_rules = self.map_nat_rules()

        # 5. Map Firewall Rules with UniFi Security Architecture
        target.firewall_rules = self.map_firewall_rules(
            networks=target.networks,
            firewall_groups=target.firewall_groups,
            enforce_inter_vlan_block=enforce_inter_vlan_block,
        )

        # 6. Map Extended Services (DNS Records, Traffic Rules, WireGuard, Smart Queues)
        target.dns_records = self.map_dns_records()
        target.dns_forwardings = self.map_dns_forwardings()
        target.dynamic_dns = self.map_dyndns()
        target.static_routes = self.map_static_routes()
        target.multi_wan = self.map_multi_wan()
        target.ntp_settings = self.map_ntp_settings()
        target.syslog_settings = self.map_syslog()
        target.snmp_settings = self.map_snmp()
        target.multicast_settings = self.map_multicast()
        target.upnp_settings = self.map_upnp()
        target.traffic_rules = self.map_traffic_rules()
        target.wireguard_servers = self.map_wireguard()
        target.smart_queue = self.map_smart_queue()

        # 7. Pass Remaining Omitted Items
        target.omitted_items = list(self.cfg.omitted_items)
        target.modem_management = self.cfg.modem_management

        return target

    def map_networks(self) -> List[UniFiNetwork]:
        networks: List[UniFiNetwork] = []

        # Find DHCP ranges map by interface
        dhcp_map = {r.interface: r for r in self.cfg.dhcp_ranges}

        # Check existing used VLANs
        used_vlans = {iface.vlan_tag for iface in self.cfg.interfaces if iface.vlan_tag is not None}
        used_vlans.add(1)

        for iface in self.cfg.interfaces:
            # Skip WAN interfaces
            if iface.id.lower() == "wan" or iface.ipaddr.lower() == "dhcp" or not iface.ipaddr:
                continue

            is_modem = (
                self.cfg.modem_management
                and self.cfg.modem_management.detected
                and self.cfg.modem_management.interface_id == iface.id
            )

            # LAN interface is always the default management network (VLAN 1)
            if iface.id.lower() == "lan":
                vlan_id = 1
                dhcp_info = dhcp_map.get(iface.id)
                dhcp_enabled = dhcp_info is not None
                net_name = iface.descr or "LAN"
            elif is_modem:
                vlan_id = self.cfg.modem_management.allocated_vlan
                dhcp_enabled = False
                net_name = iface.descr if ("modem" in iface.descr.lower() and "mgmt" not in iface.descr.lower()) else "Modem-WebUI"
            elif iface.vlan_tag is not None:
                vlan_id = iface.vlan_tag
                dhcp_info = dhcp_map.get(iface.id)
                dhcp_enabled = dhcp_info is not None
                net_name = iface.descr or iface.id.upper()
            else:
                # Non-LAN interface without VLAN tag: allocate an unused VLAN (>= 50)
                next_vlan = 50
                while next_vlan in used_vlans:
                    next_vlan += 1
                used_vlans.add(next_vlan)
                vlan_id = next_vlan
                dhcp_info = dhcp_map.get(iface.id)
                dhcp_enabled = dhcp_info is not None
                net_name = iface.descr or iface.id.upper()

            # Gateway CIDR
            subnet_bits = iface.subnet if iface.subnet else "24"
            gateway_cidr = f"{iface.ipaddr}/{subnet_bits}"

            # DHCP range
            dhcp_info = dhcp_map.get(iface.id)
            dhcp_start = dhcp_info.range_from if (dhcp_info and dhcp_enabled) else ""
            dhcp_stop = dhcp_info.range_to if (dhcp_info and dhcp_enabled) else ""
            dns_servers = dhcp_info.dns_servers if (dhcp_info and dhcp_enabled) else []

            networks.append(
                UniFiNetwork(
                    name=net_name,
                    vlan_id=vlan_id,
                    gateway_cidr=gateway_cidr,
                    purpose="corporate",
                    dhcp_enabled=dhcp_enabled,
                    dhcp_start=dhcp_start,
                    dhcp_stop=dhcp_stop,
                    dns_servers=dns_servers,
                    domain_name=getattr(self.cfg, "system_domain", "") or "local",
                    is_management=(vlan_id == 1),
                )
            )

        # If modem management is detected/configured, ensure its dedicated network exists and is distinct
        if self.cfg.modem_management and self.cfg.modem_management.detected:
            mm = self.cfg.modem_management
            modem_vlan = mm.allocated_vlan or 99
            has_modem_net = any(
                n.vlan_id == modem_vlan or (n.vlan_id != 1 and ("modem" in n.name.lower() or n.name == "MODEM_MGMT"))
                for n in networks
            )
            if not has_modem_net and modem_vlan != 1:
                gw_cidr = f"{mm.gateway_ip}/{mm.subnet or '24'}" if mm.gateway_ip else "192.168.2.2/24"
                modem_name = mm.interface_descr if (mm.interface_descr and "modem" in mm.interface_descr.lower() and "mgmt" not in mm.interface_descr.lower()) else "Modem-WebUI"
                networks.append(
                    UniFiNetwork(
                        name=modem_name,
                        vlan_id=modem_vlan,
                        gateway_cidr=gw_cidr,
                        purpose="corporate",
                        dhcp_enabled=False,
                        is_management=False,
                    )
                )

        return networks

    def map_firewall_groups(self) -> List[UniFiFirewallGroup]:
        groups: List[UniFiFirewallGroup] = []

        # 1. Always create the standard RFC1918 Group for UniFi inter-VLAN isolation rules
        rfc1918 = UniFiFirewallGroup(
            name=self.rfc1918_group_name,
            group_type="address-group",
            members=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        )
        groups.append(rfc1918)

        # 2. Map OPNsense Aliases
        # In OPNsense, aliases can be hosts, networks, ports
        for alias in self.cfg.aliases:
            if not alias.content:
                continue

            atype = alias.type.lower()
            if atype in ["port"]:
                group_type = "port-group"
            else:
                group_type = "address-group"

            # Clean and validate members
            clean_members = []
            for item in alias.content:
                # UniFi port group accepts ports or port ranges like 80, 443, 8000-8080
                clean_members.append(item.strip())

            if clean_members:
                groups.append(
                    UniFiFirewallGroup(
                        name=alias.name,
                        group_type=group_type,
                        members=clean_members,
                    )
                )

        return groups

    def map_fixed_ips(self, networks: List[UniFiNetwork]) -> List[UniFiFixedIp]:
        fixed_ips: List[UniFiFixedIp] = []

        # Helper to find network by IP
        def find_network_name(ip_str: str) -> str:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                for net in networks:
                    if "/" in net.gateway_cidr:
                        net_obj = ipaddress.ip_network(net.gateway_cidr, strict=False)
                        if ip_obj in net_obj:
                            return net.name
            except ValueError:
                pass
            return networks[0].name if networks else "Default"

        for lease in self.cfg.static_leases:
            net_name = find_network_name(lease.ipaddr)
            name = lease.hostname or lease.descr or f"Client-{lease.mac[-5:].replace(':', '')}"

            fixed_ips.append(
                UniFiFixedIp(
                    mac=lease.mac,
                    name=name,
                    fixed_ip=lease.ipaddr,
                    network_name=net_name,
                )
            )

        return fixed_ips

    def map_port_forwards(self) -> List[UniFiPortForward]:
        port_forwards: List[UniFiPortForward] = []

        for pf in self.cfg.port_forwards:
            if not pf.enabled:
                continue

            proto_map = {
                "tcp": "tcp",
                "udp": "udp",
                "tcp/udp": "both",
                "any": "both",
            }
            proto = proto_map.get(pf.protocol.lower(), "both")
            name = pf.descr or f"Forward-{pf.target_port}"

            port_forwards.append(
                UniFiPortForward(
                    name=name,
                    fwd_ip=pf.target_ip,
                    fwd_port=pf.target_port,
                    dst_port=pf.dst_port,
                    protocol=proto,
                    src_ip=pf.src_ip if pf.src_ip != "any" else "",
                    enabled=pf.enabled,
                )
            )

        return port_forwards

    def map_nat_rules(self) -> List[UniFiNatRule]:
        """
        Translates OPNsense Source NAT (Outbound) and 1:1 NAT into UniFi Target NAT rules.
        """
        nat_rules: List[UniFiNatRule] = []

        # 1. Map Source NAT (Outbound)
        for snat in getattr(self.cfg, "source_nats", []):
            if not snat.enabled:
                continue

            # Standard WAN masquerade rules are native in UniFi OS
            is_generic_wan = (
                snat.interface.lower() in ("wan", "opt_wan")
                and (snat.destination_net == "any")
                and not snat.target
                and not snat.static_nat_port
                and not snat.nonat
            )
            status = "native" if is_generic_wan else "accepted"
            rule_type = "masquerade" if (not snat.target and not snat.nonat) else "snat"
            origin = "OPNsense Source NAT (Standard Masquerade)" if is_generic_wan else "OPNsense Source NAT"
            if snat.static_nat_port:
                origin += " [Static Port / VoIP]"

            nat_rules.append(
                UniFiNatRule(
                    name=snat.descr or f"SNAT-{snat.interface.upper()}-{snat.source_net}",
                    nat_type=rule_type,
                    interface=snat.interface.upper(),
                    source_address=snat.source_net,
                    destination_address=snat.destination_net,
                    translated_ip=snat.target or "(Interface IP)",
                    translated_port=snat.target_port,
                    static_port=snat.static_nat_port,
                    enabled=snat.enabled,
                    description=snat.descr or ("Standard WAN Masquerade" if is_generic_wan else "Benutzerdefiniertes Source NAT"),
                    origin=origin,
                    status=status,
                )
            )

        # 2. Map One-to-One NAT (1:1 BINAT)
        for oto in getattr(self.cfg, "onetoone_nats", []):
            if not oto.enabled:
                continue

            nat_rules.append(
                UniFiNatRule(
                    name=oto.descr or f"1to1-{oto.internal_net}-{oto.external_net}",
                    nat_type="1to1",
                    interface=oto.interface.upper(),
                    source_address=oto.internal_net,
                    destination_address="any",
                    translated_ip=oto.external_net,
                    static_port=True,
                    enabled=oto.enabled,
                    description=oto.descr or f"1:1 BINAT Zuordnung ({oto.internal_net} <-> {oto.external_net})",
                    origin="OPNsense 1:1 NAT",
                    status="accepted",
                )
            )

        return nat_rules

    def map_firewall_rules(
        self,
        networks: List[UniFiNetwork],
        firewall_groups: List[UniFiFirewallGroup],
        enforce_inter_vlan_block: bool = True,
    ) -> List[UniFiFirewallRule]:
        """
        Synthesizes UniFi firewall rules based on OPNsense filter rules and UniFi best practices.
        """
        rules: List[UniFiFirewallRule] = []
        rule_idx = 2000

        # Known group names
        group_names = {g.name: g.group_type for g in firewall_groups}

        # ---------------------------------------------------------------------
        # UniFi Step 1: Allow Established and Related Sessions on LAN_IN
        # ---------------------------------------------------------------------
        rules.append(
            UniFiFirewallRule(
                name="Allow Established/Related Sessions",
                ruleset="LAN_IN",
                action="accept",
                rule_index=rule_idx,
                state_established=True,
                state_related=True,
                logging=False,
                origin="UniFi Core / State Engine",
                description="Crucial foundation rule in UniFi: allows return traffic for established connections",
            )
        )
        rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 2: Drop Invalid State on LAN_IN
        # ---------------------------------------------------------------------
        rules.append(
            UniFiFirewallRule(
                name="Drop Invalid State",
                ruleset="LAN_IN",
                action="drop",
                rule_index=rule_idx,
                state_invalid=True,
                logging=False,
                origin="UniFi Core / State Engine",
                description="Drops malformed or out-of-order packets",
            )
        )
        rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 2b: Pinhole Rule for VDSL Modem WebUI (Ports 80/443)
        # ---------------------------------------------------------------------
        if self.cfg.modem_management and self.cfg.modem_management.detected:
            modem_ip = self.cfg.modem_management.modem_ip
            rules.append(
                UniFiFirewallRule(
                    name="Allow Admin/LAN to Modem WebUI",
                    ruleset="LAN_IN",
                    action="accept",
                    rule_index=rule_idx,
                    enabled=True,
                    protocol="tcp",
                    dst_address=modem_ip,
                    dst_port="80,443",
                    state_new=True,
                    state_established=True,
                    state_related=True,
                    logging=False,
                    origin="Modem Management Pinhole",
                    description=f"Erlaubt WebUI-Zugriff (Port 80/443) auf das VDSL-Modem ({modem_ip}) vor der Inter-VLAN-Blocksperre",
                )
            )
            rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 3: Map user filter rules from OPNsense
        # Preserves evaluation order: Floating rules first (OPNsense behavior),
        # followed by interface rules in exact sequence order.
        # ---------------------------------------------------------------------
        # Precompute interface subnet CIDRs for resolving interface references (e.g. 'lan', 'opt1')
        iface_subnets = {}
        for iface in self.cfg.interfaces:
            if iface.ipaddr and iface.subnet:
                try:
                    net = ipaddress.ip_network(f"{iface.ipaddr}/{iface.subnet}", strict=False)
                    iface_subnets[iface.id.lower()] = str(net)
                except ValueError:
                    iface_subnets[iface.id.lower()] = f"{iface.ipaddr}/{iface.subnet}"
            elif iface.ipaddr:
                iface_subnets[iface.id.lower()] = iface.ipaddr

        # Stable sort: Floating rules first, preserving relative original XML sequence
        ordered_opn_rules = sorted(
            self.cfg.filter_rules,
            key=lambda r: (0 if r.is_floating else 1)
        )

        for opn_rule in ordered_opn_rules:
            if not opn_rule.enabled:
                continue

            # Determine UniFi ruleset:
            if opn_rule.is_floating:
                # Floating Rules apply cross-interface based on traffic direction:
                if opn_rule.direction.lower() == "out":
                    if any(w in opn_rule.interface.lower() for w in ["wan", "any", "all"]):
                        ruleset = "WAN_OUT"
                    else:
                        ruleset = "LAN_OUT"
                elif opn_rule.direction.lower() == "in":
                    if "wan" in opn_rule.interface.lower():
                        ruleset = "WAN_IN"
                    else:
                        # In UniFi, LAN_IN applies globally to all internal networks
                        ruleset = "LAN_IN"
                else:  # direction == "any"
                    ruleset = "LAN_IN"
            elif opn_rule.interface.lower() == "wan":
                ruleset = "WAN_IN"
            else:
                ruleset = "LAN_IN"

            rule_inv = getattr(opn_rule, "rule_inverted", False)
            raw_action = "accept" if opn_rule.action == "pass" else "drop"
            # If rule logic is inverted, flip action
            action = ("drop" if raw_action == "accept" else "accept") if rule_inv else raw_action
            proto = self._normalize_proto(opn_rule.protocol)

            # Match groups or addresses / resolve interface subnets
            src_groups = [opn_rule.src] if opn_rule.src in group_names and group_names[opn_rule.src] == "address-group" else []
            dst_groups = [opn_rule.dst] if opn_rule.dst in group_names and group_names[opn_rule.dst] == "address-group" else []

            if not src_groups and opn_rule.src != "any":
                src_addr = iface_subnets.get(opn_rule.src.lower(), opn_rule.src)
            else:
                src_addr = None

            if not dst_groups and opn_rule.dst != "any":
                dst_addr = iface_subnets.get(opn_rule.dst.lower(), opn_rule.dst)
            else:
                dst_addr = None

            dst_port = opn_rule.dst_port if opn_rule.dst_port != "any" else None

            src_inv = getattr(opn_rule, "src_inverted", False)
            dst_inv = getattr(opn_rule, "dst_inverted", False)

            negation_tags = []
            if src_inv:
                negation_tags.append("!Quelle")
            if dst_inv:
                negation_tags.append("!Ziel")
            if rule_inv:
                negation_tags.append("!Regel-Aktion")
            neg_note = f" [{', '.join(negation_tags)}]" if negation_tags else ""

            prefix = "[Floating] " if opn_rule.is_floating else ""
            rule_name = f"{prefix}{opn_rule.descr}" if opn_rule.descr else f"{prefix}Migrated-{opn_rule.interface}-{opn_rule.id}"
            floating_note = " (Floating Rule)" if opn_rule.is_floating else ""

            rules.append(
                UniFiFirewallRule(
                    name=rule_name,
                    ruleset=ruleset,
                    action=action,
                    rule_index=rule_idx,
                    enabled=opn_rule.enabled,
                    protocol=proto,
                    src_firewall_group_names=src_groups,
                    dst_firewall_group_names=dst_groups,
                    src_address=src_addr,
                    dst_address=dst_addr,
                    dst_port=dst_port,
                    logging=opn_rule.log,
                    origin="OPNsense Floating Rule" if opn_rule.is_floating else "OPNsense Filter Rule",
                    description=f"OPNsense interface: {opn_rule.interface}{floating_note}, Dir: {opn_rule.direction}. {opn_rule.descr}{neg_note}",
                    src_inverted=src_inv,
                    dst_inverted=dst_inv,
                    rule_inverted=rule_inv,
                )
            )
            rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 4: Local Gateway Services on LAN_LOCAL
        # In OPNsense, interfaces only reach local services if permitted.
        # On UCG-Max, we must allow DNS/DHCP but block WebGUI/SSH from untrusted VLANs.
        # ---------------------------------------------------------------------
        rules.append(
            UniFiFirewallRule(
                name="Allow DNS to Gateway (LAN_LOCAL)",
                ruleset="LAN_LOCAL",
                action="accept",
                rule_index=rule_idx,
                protocol="tcp_udp",
                dst_port="53",
                origin="Gateway Service (LAN_LOCAL)",
                description="Allows internal clients to resolve DNS queries via UCG-Max",
            )
        )
        rule_idx += 1

        rules.append(
            UniFiFirewallRule(
                name="Allow DHCP to Gateway (LAN_LOCAL)",
                ruleset="LAN_LOCAL",
                action="accept",
                rule_index=rule_idx,
                protocol="udp",
                dst_port="67",
                origin="Gateway Service (LAN_LOCAL)",
                description="Allows DHCP broadcast requests to reach UCG-Max DHCP daemon",
            )
        )
        rule_idx += 1

        # Block Gateway Management (WebGUI 443/80, SSH 22) from non-management VLANs
        rules.append(
            UniFiFirewallRule(
                name="Block Gateway Management from Non-Management VLANs (LAN_LOCAL)",
                ruleset="LAN_LOCAL",
                action="drop",
                rule_index=rule_idx,
                protocol="tcp",
                src_firewall_group_names=[self.rfc1918_group_name],
                dst_port="22,80,443",
                logging=True,
                origin="Gateway Härtung (LAN_LOCAL)",
                description="Prevents untrusted VLANs (IoT, Cameras, Guests) from accessing UCG-Max Admin UI/SSH",
            )
        )
        rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 5: Internet Default-Deny for isolated OPNsense interfaces
        # In OPNsense, an interface without a pass rule to 'any' has NO internet.
        # In UniFi, LAN_IN defaults to accept non-RFC1918 traffic.
        # We find interfaces with NO outbound/internet rule and explicitly block them.
        # ---------------------------------------------------------------------
        interfaces_with_internet = set()
        for r in self.cfg.filter_rules:
            if r.enabled and r.action == "pass" and (r.dst == "any" or r.dst_inverted):
                interfaces_with_internet.add(r.interface.lower())

        for iface in self.cfg.interfaces:
            if iface.id.lower() == "wan" or not iface.ipaddr:
                continue
            if iface.id.lower() not in interfaces_with_internet:
                # This interface had NO internet permission in OPNsense
                rules.append(
                    UniFiFirewallRule(
                        name=f"Block Internet for Isolated {iface.descr} (Default Deny)",
                        ruleset="LAN_IN",
                        action="drop",
                        rule_index=rule_idx,
                        protocol="all",
                        src_address=f"{iface.ipaddr}/{iface.subnet}" if iface.subnet else iface.ipaddr,
                        dst_address=None,
                        logging=True,
                        origin="Default-Deny (Internet-Isolation)",
                        description=f"In OPNsense, {iface.id} had no pass rule to 'any'. Emulates OPNsense default-deny for Internet.",
                    )
                )
                rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 6: Inter-VLAN Block Rule (Default Deny Emulation)
        # ---------------------------------------------------------------------
        if enforce_inter_vlan_block:
            # We place this at rule 2999 (or after all pinholes)
            rules.append(
                UniFiFirewallRule(
                    name="Block All Inter-VLAN Traffic (Default Deny)",
                    ruleset="LAN_IN",
                    action="drop",
                    rule_index=max(2999, rule_idx + 10),
                    protocol="all",
                    src_firewall_group_names=[self.rfc1918_group_name],
                    dst_firewall_group_names=[self.rfc1918_group_name],
                    logging=True,
                    origin="Default-Deny (Inter-VLAN Parität)",
                    description=(
                        "CRITICAL SECURITY RULE: UniFi defaults to allowing all inter-VLAN routing! "
                        "This rule restores OPNsense's default-deny isolation between private subnets."
                    ),
                )
            )

        return rules

    @staticmethod
    def _normalize_proto(proto: str) -> str:
        proto_lower = proto.lower()
        if proto_lower in ["tcp", "udp", "icmp"]:
            return proto_lower
        elif proto_lower in ["tcp/udp", "tcp_udp"]:
            return "tcp_udp"
        return "all"

    def map_dns_records(self) -> List[UniFiDnsRecord]:
        records: List[UniFiDnsRecord] = []
        for h in getattr(self.cfg, "dns_hosts", []):
            fqdn = f"{h.host}.{h.domain}" if h.host and h.domain else (h.host or h.domain)
            if fqdn and h.ip:
                records.append(UniFiDnsRecord(key=fqdn, value=h.ip, record_type="A", enabled=True))
        return records

    def map_traffic_rules(self) -> List[UniFiTrafficRule]:
        traffic_rules: List[UniFiTrafficRule] = []
        for alias in self.cfg.aliases:
            atype = alias.type.lower()
            if atype in ["url", "urltable", "url_table"]:
                traffic_rules.append(
                    UniFiTrafficRule(
                        name=f"Block-{alias.name}",
                        action="BLOCK",
                        target="DOMAIN",
                        domains=alias.content,
                        description=f"Auto-migrated from OPNsense URL/Table alias '{alias.name}'",
                    )
                )
            elif atype == "geoip":
                traffic_rules.append(
                    UniFiTrafficRule(
                        name=f"CountryBlock-{alias.name}",
                        action="BLOCK",
                        target="REGION",
                        regions=alias.content,
                        description=f"Auto-migrated from OPNsense GeoIP alias '{alias.name}'",
                    )
                )
        return traffic_rules

    def map_wireguard(self) -> List[UniFiWireGuardServer]:
        servers: List[UniFiWireGuardServer] = []
        for wg in getattr(self.cfg, "wireguard_servers", []):
            servers.append(
                UniFiWireGuardServer(
                    name=wg.name,
                    port=wg.port,
                    tunnel_subnet=wg.tunnel_address,
                    enabled=True,
                )
            )
        return servers

    def map_smart_queue(self) -> Optional[UniFiSmartQueue]:
        shaper = getattr(self.cfg, "traffic_shaper", None)
        if shaper and (shaper.down_rate_kbps > 0 or shaper.up_rate_kbps > 0):
            return UniFiSmartQueue(
                enabled=True,
                down_rate_kbps=shaper.down_rate_kbps,
                up_rate_kbps=shaper.up_rate_kbps,
            )
        return None

    def add_modem_management_network(
        self,
        target: UniFiTargetConfig,
        vlan_id: int = 99,
        modem_ip: str = "192.168.2.1",
        gateway_cidr: str = "192.168.2.2/24",
    ) -> UniFiNetwork:
        """
        Manually or programmatically attaches a dedicated Modem-Management network
        and corresponding pinhole rule to a UniFi target configuration.
        """
        existing = next((
            n for n in target.networks
            if n.vlan_id != 1 and not getattr(n, "is_management", False)
            and (n.vlan_id == vlan_id or n.name in ["MODEM_MGMT", "Modem-WebUI"] or "modem" in n.name.lower())
        ), None)
        if not existing:
            modem_net = UniFiNetwork(
                name="Modem-WebUI",
                vlan_id=vlan_id,
                gateway_cidr=gateway_cidr,
                purpose="corporate",
                dhcp_enabled=False,
                is_management=False,
            )
            target.networks.append(modem_net)
        else:
            modem_net = existing
            modem_net.is_management = False

        has_rule = any(r.dst_address == modem_ip for r in target.firewall_rules)
        if not has_rule:
            rule_idx = 2050
            while any(r.rule_index == rule_idx for r in target.firewall_rules):
                rule_idx += 1
            target.firewall_rules.insert(
                2,
                UniFiFirewallRule(
                    name="Allow Admin/LAN to Modem WebUI",
                    ruleset="LAN_IN",
                    action="accept",
                    rule_index=rule_idx,
                    enabled=True,
                    protocol="tcp",
                    dst_address=modem_ip,
                    dst_port="80,443",
                    state_new=True,
                    state_established=True,
                    state_related=True,
                    logging=False,
                    origin="Modem Management Pinhole",
                    description=f"Erlaubt WebUI-Zugriff (Port 80/443) auf das VDSL-Modem ({modem_ip}) vor der Inter-VLAN-Blocksperre",
                ),
            )

        return modem_net

    def map_dns_forwardings(self) -> List[UniFiDnsForwarding]:
        forwardings: List[UniFiDnsForwarding] = []
        for o in getattr(self.cfg, "dns_domain_overrides", []):
            forwardings.append(UniFiDnsForwarding(domain=o.domain, forward_to_ip=o.ip, enabled=True))
        return forwardings

    def map_dyndns(self) -> List[UniFiDynDns]:
        dyndns_targets: List[UniFiDynDns] = []
        # Service normalizer for UniFi Network
        service_map = {
            "dyndns": "dyndns",
            "dyndns2": "dyndns",
            "cloudflare": "cloudflare",
            "strato": "strato",
            "duckdns": "duckdns",
            "noip": "noip",
            "freedns": "freedns",
            "namecheap": "namecheap",
            "ovh": "ovh",
            "he": "he",
        }
        for d in getattr(self.cfg, "dynamic_dns", []):
            srv_lower = d.service.lower()
            unifi_srv = service_map.get(srv_lower, "custom")
            iface_str = "WAN2" if "opt" in d.interface.lower() or "wan2" in d.interface.lower() else "WAN"
            dyndns_targets.append(
                UniFiDynDns(
                    service=unifi_srv,
                    host_name=d.host,
                    login=d.username,
                    password=d.password,
                    interface=iface_str,
                    server=d.server,
                    enabled=d.enabled,
                    description=d.descr or f"DynDNS ({unifi_srv})",
                )
            )
        return dyndns_targets

    def map_static_routes(self) -> List[UniFiStaticRoute]:
        routes: List[UniFiStaticRoute] = []
        for idx, r in enumerate(getattr(self.cfg, "static_routes", [])):
            name = r.descr or f"Route_{idx+1}_{r.network.replace('/', '_')}"
            routes.append(
                UniFiStaticRoute(
                    name=name,
                    network=r.network,
                    next_hop=r.gateway,
                    distance=1,
                    enabled=r.enabled,
                )
            )
        return routes

    def map_multi_wan(self) -> Optional[UniFiMultiWan]:
        groups = getattr(self.cfg, "gateway_groups", [])
        if not groups:
            return None
        # Check first active group
        primary_group = groups[0]
        tiers = [m.get("tier", 1) for m in primary_group.members]
        # If all tiers are 1 -> Distributed Load Balancing; else Failover
        is_distributed = len(tiers) > 1 and len(set(tiers)) == 1
        return UniFiMultiWan(
            mode="distributed" if is_distributed else "failover",
            load_balance_percentage=50 if is_distributed else 0,
            wan1_echo_server="1.1.1.1",
            wan2_echo_server="8.8.8.8",
            wan2_port="Port 4",
        )

    def map_ntp_settings(self) -> Optional[UniFiNtpSetting]:
        ntp = getattr(self.cfg, "system_ntp", None)
        if not ntp:
            return None
        return UniFiNtpSetting(
            upstream_servers=ntp.timeservers or ["0.pool.ntp.org", "1.pool.ntp.org"],
            dhcp_option42_enabled=True,
        )

    def map_syslog(self) -> Optional[UniFiSyslog]:
        sl = getattr(self.cfg, "syslog", None)
        if not sl or not sl.enabled:
            return None
        return UniFiSyslog(enabled=sl.enabled, server=sl.server, port=sl.port)

    def map_snmp(self) -> Optional[UniFiSnmp]:
        sn = getattr(self.cfg, "snmp", None)
        if not sn or not sn.enabled:
            return None
        return UniFiSnmp(enabled=sn.enabled, community=sn.community)

    def map_multicast(self) -> Optional[UniFiMulticast]:
        mc = getattr(self.cfg, "multicast", None)
        if not mc or not mc.enabled:
            return None
        return UniFiMulticast(mdns_enabled=True, igmp_snooping_enabled=True)

    def map_upnp(self) -> Optional[UniFiUpnp]:
        up = getattr(self.cfg, "upnp", None)
        if not up or not up.enabled:
            return None
        return UniFiUpnp(enabled=up.enabled, wan_interface="WAN")

