"""
VLAN & Subnet Remapping and Migration Module.
Handles cascading translation when a VLAN ID or Subnet CIDR is changed or merged across systems.
Example: Migrating OPNsense VLAN 20 (192.168.99.0/24) -> UniFi VLAN 90 (192.168.90.0/24).
"""

import ipaddress
import logging
from typing import Dict, Any, List, Optional
from src.models import (
    UniFiTargetConfig,
    UniFiNetwork,
    UniFiFixedIp,
    UniFiWlan,
    UniFiFirewallRule,
    UniFiFirewallGroup,
)

logger = logging.getLogger(__name__)


def remap_ip_address(addr_str: str, source_cidr: str, target_cidr: str) -> str:
    """
    Translates a host IP or subnet CIDR from source_cidr to target_cidr while preserving host offset.
    e.g. remap_ip_address("192.168.99.55", "192.168.99.1/24", "192.168.90.1/24") -> "192.168.90.55"
    e.g. remap_ip_address("192.168.99.0/24", "192.168.99.1/24", "192.168.90.1/24") -> "192.168.90.0/24"
    """
    if not addr_str or not source_cidr or not target_cidr:
        return addr_str

    addr_clean = addr_str.strip()
    try:
        src_net = ipaddress.ip_network(source_cidr.strip(), strict=False)
        tgt_net = ipaddress.ip_network(target_cidr.strip(), strict=False)

        # 1. Check if addr_clean is a subnet CIDR itself
        if "/" in addr_clean:
            try:
                candidate_net = ipaddress.ip_network(addr_clean, strict=False)
                if candidate_net == src_net:
                    return f"{tgt_net.network_address}/{tgt_net.prefixlen}"
            except ValueError:
                pass

        # 2. Check if addr_clean is a single host IP
        ip_obj = ipaddress.ip_address(addr_clean)
        if ip_obj in src_net:
            offset = int(ip_obj) - int(src_net.network_address)
            new_ip_int = int(tgt_net.network_address) + offset
            # Validate within target network bounds
            if offset < tgt_net.num_addresses - 1 and offset > 0:
                return str(ipaddress.ip_address(new_ip_int))
    except Exception:
        # Not a valid IP/CIDR or doesn't belong to subnet
        pass

    return addr_str


class VlanRemapper:
    """
    Orchestrates cascading updates across networks, static leases (fixed IPs),
    Wi-Fi WLANs, firewall rules, firewall groups, port forwards, and DNS overrides.
    """

    @staticmethod
    def remap(
        unifi_cfg: UniFiTargetConfig,
        source_vlan: int,
        target_vlan: int,
        source_cidr: Optional[str] = None,
        target_cidr: Optional[str] = None,
        target_name: Optional[str] = None,
        remap_clients: bool = True,
        remap_wlans: bool = True,
        remap_rules: bool = True,
    ) -> Dict[str, Any]:
        result = {
            "success": True,
            "source_vlan": source_vlan,
            "target_vlan": target_vlan,
            "source_cidr": source_cidr,
            "target_cidr": target_cidr,
            "clients_remapped": 0,
            "wlans_remapped": 0,
            "rules_remapped": 0,
            "groups_remapped": 0,
            "forwards_remapped": 0,
            "dns_remapped": 0,
            "merged_with_existing": False,
            "details": [],
        }

        # 1. Locate the source network
        source_net: Optional[UniFiNetwork] = None
        for net in unifi_cfg.networks:
            if net.vlan_id == source_vlan:
                source_net = net
                break

        if not source_net:
            # Fallback: find by CIDR if provided
            if source_cidr:
                clean_sc = source_cidr.split("/")[0]
                for net in unifi_cfg.networks:
                    if clean_sc in net.gateway_cidr:
                        source_net = net
                        source_vlan = net.vlan_id
                        break

        if not source_net:
            result["success"] = False
            result["error"] = f"Quell-Netzwerk mit VLAN-ID {source_vlan} nicht gefunden."
            return result

        old_name = source_net.name
        old_cidr = source_net.gateway_cidr
        actual_source_cidr = source_cidr or old_cidr
        actual_target_cidr = target_cidr or old_cidr
        new_name = target_name or (source_net.name if target_vlan == source_vlan else f"{source_net.name}_VLAN{target_vlan}")

        # 2. Check if a target network already exists (e.g. from UCG)
        existing_target_net: Optional[UniFiNetwork] = None
        if target_vlan != source_vlan:
            for net in unifi_cfg.networks:
                if net is not source_net and net.vlan_id == target_vlan:
                    existing_target_net = net
                    break

        if existing_target_net:
            # Merge source into existing target network
            result["merged_with_existing"] = True
            final_net = existing_target_net
            if target_cidr:
                final_net.gateway_cidr = target_cidr
            if target_name:
                final_net.name = target_name
            # Remove redundant source network
            unifi_cfg.networks.remove(source_net)
            result["details"].append(f"VLAN {source_vlan} mit bestehendem Ziel-Netzwerk '{final_net.name}' (VLAN {target_vlan}) zusammengeführt.")
        else:
            final_net = source_net
            final_net.vlan_id = target_vlan
            final_net.gateway_cidr = actual_target_cidr
            if target_name:
                final_net.name = target_name

            # Update DHCP pool range if CIDR changed
            if actual_source_cidr != actual_target_cidr:
                try:
                    tgt_net = ipaddress.ip_network(actual_target_cidr, strict=False)
                    tgt_prefix = f"{tgt_net.network_address}".rsplit(".", 1)[0]
                    final_net.dhcp_start = f"{tgt_prefix}.10"
                    final_net.dhcp_stop = f"{tgt_prefix}.250"
                except Exception:
                    pass

            result["details"].append(f"Netzwerk '{final_net.name}' auf VLAN {target_vlan} ({actual_target_cidr}) aktualisiert.")

        # 3. Remap Fixed Client IPs
        for fip in unifi_cfg.fixed_ips:
            updated = False
            # Network name binding
            if fip.network_name == old_name:
                fip.network_name = final_net.name
                updated = True

            # IP Address remapping
            if remap_clients and actual_source_cidr and actual_target_cidr and actual_source_cidr != actual_target_cidr:
                new_ip = remap_ip_address(fip.fixed_ip, actual_source_cidr, actual_target_cidr)
                if new_ip != fip.fixed_ip:
                    fip.fixed_ip = new_ip
                    updated = True

            if updated:
                result["clients_remapped"] += 1

        # 4. Remap Wi-Fi WLANs
        if remap_wlans:
            for wlan in getattr(unifi_cfg, "wlans", []):
                if wlan.vlan_id == source_vlan:
                    wlan.vlan_id = target_vlan
                    result["wlans_remapped"] += 1
                    result["details"].append(f"WLAN SSID '{wlan.name}' auf VLAN {target_vlan} umgehängt.")

        # 5. Remap Firewall Rules
        if remap_rules and actual_source_cidr and actual_target_cidr and actual_source_cidr != actual_target_cidr:
            for r in getattr(unifi_cfg, "firewall_rules", []):
                rule_changed = False
                if r.src_address:
                    new_src = remap_ip_address(r.src_address, actual_source_cidr, actual_target_cidr)
                    if new_src != r.src_address:
                        r.src_address = new_src
                        rule_changed = True

                if r.dst_address:
                    new_dst = remap_ip_address(r.dst_address, actual_source_cidr, actual_target_cidr)
                    if new_dst != r.dst_address:
                        r.dst_address = new_dst
                        rule_changed = True

                # Check description/name references
                if f"VLAN {source_vlan}" in r.name:
                    r.name = r.name.replace(f"VLAN {source_vlan}", f"VLAN {target_vlan}")
                    rule_changed = True

                if rule_changed:
                    result["rules_remapped"] += 1

        # 6. Remap Firewall Groups
        if actual_source_cidr and actual_target_cidr and actual_source_cidr != actual_target_cidr:
            for g in getattr(unifi_cfg, "firewall_groups", []):
                new_members = []
                group_changed = False
                for m in g.members:
                    new_m = remap_ip_address(m, actual_source_cidr, actual_target_cidr)
                    if new_m != m:
                        group_changed = True
                    new_members.append(new_m)
                if group_changed:
                    g.members = new_members
                    result["groups_remapped"] += 1

        # 7. Remap Port Forwards
        if actual_source_cidr and actual_target_cidr and actual_source_cidr != actual_target_cidr:
            for p in getattr(unifi_cfg, "port_forwards", []):
                new_fwd = remap_ip_address(p.fwd_ip, actual_source_cidr, actual_target_cidr)
                if new_fwd != p.fwd_ip:
                    p.fwd_ip = new_fwd
                    result["forwards_remapped"] += 1

        # 8. Remap DNS Records
        if actual_source_cidr and actual_target_cidr and actual_source_cidr != actual_target_cidr:
            for d in getattr(unifi_cfg, "dns_records", []):
                new_val = remap_ip_address(d.value, actual_source_cidr, actual_target_cidr)
                if new_val != d.value:
                    d.value = new_val
                    result["dns_remapped"] += 1

        return result
