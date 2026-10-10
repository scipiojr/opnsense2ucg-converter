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

        # 4. Map Port Forwards
        target.port_forwards = self.map_port_forwards()

        # 5. Map Firewall Rules with UniFi Security Architecture
        target.firewall_rules = self.map_firewall_rules(
            networks=target.networks,
            firewall_groups=target.firewall_groups,
            enforce_inter_vlan_block=enforce_inter_vlan_block,
        )

        # 6. Pass Omitted / Non-migrated Items
        target.omitted_items = list(self.cfg.omitted_items)

        return target

    def map_networks(self) -> List[UniFiNetwork]:
        networks: List[UniFiNetwork] = []

        # Find DHCP ranges map by interface
        dhcp_map = {r.interface: r for r in self.cfg.dhcp_ranges}

        for iface in self.cfg.interfaces:
            # Skip WAN interfaces
            if iface.id.lower() == "wan" or iface.ipaddr.lower() == "dhcp" or not iface.ipaddr:
                continue

            # Determine VLAN ID
            # LAN is typically untagged / VLAN 1 (Default corporate in UniFi)
            vlan_id = iface.vlan_tag if iface.vlan_tag is not None else (1 if iface.id.lower() == "lan" else 0)

            # Gateway CIDR
            subnet_bits = iface.subnet if iface.subnet else "24"
            gateway_cidr = f"{iface.ipaddr}/{subnet_bits}"

            # DHCP range
            dhcp_info = dhcp_map.get(iface.id)
            dhcp_enabled = dhcp_info is not None
            dhcp_start = dhcp_info.range_from if dhcp_info else ""
            dhcp_stop = dhcp_info.range_to if dhcp_info else ""
            dns_servers = dhcp_info.dns_servers if dhcp_info else []

            net_name = iface.descr or iface.id.upper()

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
                description="Drops malformed or out-of-order packets",
            )
        )
        rule_idx += 1

        # ---------------------------------------------------------------------
        # UniFi Step 3: Map user filter rules from OPNsense
        # ---------------------------------------------------------------------
        for opn_rule in self.cfg.filter_rules:
            if not opn_rule.enabled:
                continue

            # Determine UniFi ruleset:
            # - Rules on 'wan' go to WAN_IN (or WAN_LOCAL if destination is gateway)
            # - Rules on LAN/VLAN interfaces go to LAN_IN (or LAN_LOCAL if dst is gateway/dns)
            if opn_rule.interface.lower() == "wan":
                ruleset = "WAN_IN"
            else:
                ruleset = "LAN_IN"

            action = "accept" if opn_rule.action == "pass" else "drop"
            proto = self._normalize_proto(opn_rule.protocol)

            # Match groups or addresses
            src_groups = [opn_rule.src] if opn_rule.src in group_names and group_names[opn_rule.src] == "address-group" else []
            dst_groups = [opn_rule.dst] if opn_rule.dst in group_names and group_names[opn_rule.dst] == "address-group" else []

            src_addr = opn_rule.src if not src_groups and opn_rule.src != "any" else None
            dst_addr = opn_rule.dst if not dst_groups and opn_rule.dst != "any" else None
            dst_port = opn_rule.dst_port if opn_rule.dst_port != "any" else None

            rule_name = opn_rule.descr or f"Migrated-{opn_rule.interface}-{opn_rule.id}"

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
                    description=f"OPNsense source interface: {opn_rule.interface}. {opn_rule.descr}",
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
