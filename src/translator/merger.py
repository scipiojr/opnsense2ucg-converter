"""
Reconciliation & Merger Module for Multi-Source Migration.
Merges:
1. OPNsense master firewall/routing config (config.xml)
2. Existing UCG-Max live state (already partially configured gateway)
3. Existing UOS server live state (Wi-Fi SSIDs, APs, friendly client names)
"""

import logging
from typing import Dict, Any, List, Optional
from src.models import (
    OPNsenseConfig,
    UniFiTargetConfig,
    UniFiSourceState,
    ReconciliationReport,
    ReconciliationItem,
    UniFiWlan,
    UniFiFixedIp,
    UniFiNetwork,
)
from src.translator.exclusions import (
    network_item_id,
    wlan_item_id,
    client_item_id,
    client_name_item_id,
    device_item_id,
    dyndns_item_id,
    route_item_id,
    dns_fwd_item_id,
)

logger = logging.getLogger(__name__)


class MultiSourceMerger:
    def __init__(
        self,
        opnsense_cfg: OPNsenseConfig,
        unifi_target: UniFiTargetConfig,
        ucg_state: Optional[UniFiSourceState] = None,
        uos_state: Optional[UniFiSourceState] = None,
        vlan_remaps: Optional[List[Dict[str, Any]]] = None,
        exclusions: Optional[List[Dict[str, Any]]] = None,
    ):
        self.opn_cfg = opnsense_cfg
        self.target = unifi_target
        self.ucg_state = ucg_state
        self.uos_state = uos_state
        self.vlan_remaps = vlan_remaps or []
        self.exclusions = {e["item_id"]: e for e in (exclusions or []) if e.get("item_id")}

    def _mark_exclusions(self, items: List[ReconciliationItem]) -> int:
        """Flags excluded items and keeps excluded entries visible even if the merge no longer produces them."""
        seen = set()
        for item in items:
            excl = self.exclusions.get(item.item_id)
            if not excl:
                continue
            seen.add(item.item_id)
            item.exclusion = excl
            item.status = "excluded"
            item.action = "skip_migration"
            item.explanation = f"Wird NICHT migriert ({excl.get('strategy_label') or excl.get('strategy', '')}). Ursprünglich: {item.explanation}"
        for item_id, excl in self.exclusions.items():
            if item_id in seen:
                continue
            kind = item_id.split(":", 1)[0]
            items.append(ReconciliationItem(
                category={"client_name": "client"}.get(kind, kind),
                key=excl.get("label") or item_id,
                status="excluded",
                action="skip_migration",
                explanation="Wird NICHT migriert (Eintrag ist in den aktuellen Quellen nicht mehr als Abweichung sichtbar).",
                item_id=item_id,
                exclusion=excl,
            ))
        return len(self.exclusions)

    def reconcile(self) -> ReconciliationReport:
        items: List[ReconciliationItem] = []
        summary = {
            "networks_aligned": 0,
            "networks_to_create": 0,
            "networks_conflicts": 0,
            "networks_preserved": 0,
            "wlans_imported": 0,
            "clients_enriched": 0,
            "devices_mapped": 0,
        }

        # ---------------------------------------------------------------------
        # 1. Networks Reconciliation (OPNsense vs. Existing UCG-Max)
        # ---------------------------------------------------------------------
        existing_ucg_nets_by_vlan: Dict[int, Dict[str, Any]] = {}
        existing_ucg_nets_by_name: Dict[str, Dict[str, Any]] = {}

        if self.ucg_state and self.ucg_state.networks:
            for net in self.ucg_state.networks:
                purpose = str(net.get("purpose", "corporate")).lower()
                name_l = str(net.get("name", "")).lower()
                if purpose in ["wan", "vpn", "remote-user-vpn"] or "wireguard" in name_l or "roadworrior" in name_l:
                    continue
                vlan = net.get("vlan", 1) or net.get("vlan_id", 1)
                name = net.get("name", "")
                existing_ucg_nets_by_vlan[int(vlan)] = net
                existing_ucg_nets_by_name[name.lower()] = net

        remap_by_source_vlan = {int(r["source_vlan"]): r for r in self.vlan_remaps if "source_vlan" in r}
        covered_ucg_vlans = set()

        for target_net in self.target.networks:
            vlan = target_net.vlan_id
            target_cidr = target_net.gateway_cidr.split("/")[0] if "/" in target_net.gateway_cidr else target_net.gateway_cidr

            remap_rule = remap_by_source_vlan.get(vlan)
            mapped_target_vlan = int(remap_rule.get("target_vlan", vlan)) if remap_rule else vlan

            match = (
                existing_ucg_nets_by_vlan.get(mapped_target_vlan)
                or existing_ucg_nets_by_vlan.get(vlan)
                or existing_ucg_nets_by_name.get(target_net.name.lower())
            )

            if remap_rule and match:
                ucg_ip = match.get("ip_subnet", "") or match.get("gateway_ip", "")
                items.append(
                    ReconciliationItem(
                        category="network", item_id=network_item_id(vlan),
                        key=f"VLAN {vlan} ➔ VLAN {mapped_target_vlan} ({target_net.name})",
                        opnsense_val=target_net.gateway_cidr,
                        ucg_val=ucg_ip or f"VLAN {mapped_target_vlan}",
                        status="aligned",
                        action="remapped_and_merged",
                        explanation=f"Netzwerk manuell von VLAN {vlan} auf UCG-Netzwerk VLAN {mapped_target_vlan} ({match.get('name', 'UCG-Net')}) gemappt und zusammengeführt.",
                    )
                )
                summary["networks_aligned"] += 1
                covered_ucg_vlans.add(mapped_target_vlan)
                covered_ucg_vlans.add(vlan)
            elif match:
                covered_ucg_vlans.add(int(match.get("vlan", vlan)))
                ucg_ip = match.get("ip_subnet", "") or match.get("gateway_ip", "")
                # Compare subnets
                if not ucg_ip or ucg_ip.startswith(target_cidr[:8]):  # Subnet prefix match
                    items.append(
                        ReconciliationItem(
                            category="network", item_id=network_item_id(vlan),
                            key=f"VLAN {vlan} ({target_net.name})",
                            opnsense_val=target_net.gateway_cidr,
                            ucg_val=ucg_ip or f"VLAN {match.get('vlan', vlan)}",
                            status="aligned",
                            action="update_existing_on_ucg",
                            explanation=f"Netzwerk existiert bereits auf UCG-Max ({match.get('name')}). Wird aktualisiert statt dupliziert.",
                        )
                    )
                    summary["networks_aligned"] += 1
                else:
                    items.append(
                        ReconciliationItem(
                            category="network", item_id=network_item_id(vlan),
                            key=f"VLAN {vlan} ({target_net.name})",
                            opnsense_val=target_net.gateway_cidr,
                            ucg_val=ucg_ip,
                            status="conflict",
                            action="manual_decision_needed",
                            explanation=f"Subnetz-Abweichung: OPNsense nutzt {target_net.gateway_cidr}, auf dem UCG-Max ist jedoch {ucg_ip} konfiguriert.",
                        )
                    )
                    summary["networks_conflicts"] += 1
            else:
                items.append(
                    ReconciliationItem(
                        category="network", item_id=network_item_id(vlan),
                        key=f"VLAN {vlan} ({target_net.name})",
                        opnsense_val=target_net.gateway_cidr,
                        ucg_val=None,
                        status="create",
                        action="create_new_on_ucg",
                        explanation="Netzwerk fehlt auf UCG-Max und wird neu angelegt.",
                    )
                )
                summary["networks_to_create"] += 1

        # Check networks present on UCG but not in OPNsense
        if self.ucg_state and self.ucg_state.networks:
            planned_vlans = {n.vlan_id for n in self.target.networks} | covered_ucg_vlans
            for net in self.ucg_state.networks:
                purpose = str(net.get("purpose", "corporate")).lower()
                name_l = str(net.get("name", "")).lower()
                if purpose in ["wan", "vpn", "remote-user-vpn"] or "wireguard" in name_l or "roadworrior" in name_l:
                    continue
                vlan = int(net.get("vlan", 1) or net.get("vlan_id", 1))
                if vlan not in planned_vlans and net.get("name") not in ["Default", "default"]:
                    cidr = net.get("ip_subnet", "") or net.get("gateway_ip", "")
                    items.append(
                        ReconciliationItem(
                            category="network", item_id=network_item_id(vlan),
                            key=f"VLAN {vlan} ({net.get('name')})",
                            opnsense_val=None,
                            ucg_val=cidr or "aktiv",
                            status="preserve_ucg",
                            action="keep_untouched",
                            explanation="Existiert nur auf UCG-Max und wird sicher in die einheitliche Konfiguration übernommen.",
                        )
                    )
                    # Include into unified target config so export is complete
                    self.target.networks.append(
                        UniFiNetwork(
                            name=net.get("name", f"UCG_VLAN_{vlan}"),
                            vlan_id=vlan,
                            gateway_cidr=cidr,
                            purpose=net.get("purpose", "corporate"),
                            dhcp_enabled=bool(net.get("dhcpd_enabled", True)),
                        )
                    )
                    planned_vlans.add(vlan)
                    summary["networks_preserved"] += 1

        # ---------------------------------------------------------------------
        # 2. WLAN / Wi-Fi SSIDs Ingestion (From UOS Server)
        # ---------------------------------------------------------------------
        if self.uos_state and self.uos_state.wlans:
            for wlan in self.uos_state.wlans:
                # Add to target wlans if not already present
                existing = next((w for w in self.target.wlans if w.name == wlan.name), None)
                if not existing:
                    self.target.wlans.append(wlan)

                vlan_info = f"VLAN {wlan.vlan_id}" if wlan.vlan_id else "Default (Untagged)"
                items.append(
                    ReconciliationItem(
                        category="wlan", item_id=wlan_item_id(wlan.name),
                        key=f"SSID: {wlan.name}",
                        opnsense_val=None,
                        ucg_val=None,
                        uos_val=f"{wlan.security.upper()} ({vlan_info})",
                        status="import_uos",
                        action="provision_on_ucg",
                        explanation=f"WLAN '{wlan.name}' aus bisherigem UOS-Server übernommen. Wird auf UCG-Max bereitgestellt.",
                    )
                )
                summary["wlans_imported"] += 1

        # ---------------------------------------------------------------------
        # 3. Client Enrichment (Friendly Names from UOS Server -> OPNsense IPs)
        # ---------------------------------------------------------------------
        uos_clients_by_mac: Dict[str, str] = {}
        if self.uos_state and self.uos_state.clients:
            for c in self.uos_state.clients:
                mac = c.get("mac", "").lower()
                name = c.get("name") or c.get("hostname")
                if mac and name:
                    uos_clients_by_mac[mac] = name

        # Also check UCG clients
        if self.ucg_state and self.ucg_state.clients:
            for c in self.ucg_state.clients:
                mac = c.get("mac", "").lower()
                name = c.get("name") or c.get("hostname")
                if mac and name and mac not in uos_clients_by_mac:
                    uos_clients_by_mac[mac] = name

        opn_names_by_mac: Dict[str, str] = {}
        if self.opn_cfg:
            for lease in self.opn_cfg.static_leases:
                if lease.mac:
                    opn_names_by_mac[lease.mac.lower()] = lease.hostname or lease.descr or ""

        for fixed in self.target.fixed_ips:
            mac_clean = fixed.mac.lower()
            if mac_clean in uos_clients_by_mac:
                friendly_name = uos_clients_by_mac[mac_clean]
                old_name = opn_names_by_mac.get(mac_clean) or fixed.name
                if friendly_name != old_name:
                    fixed.name = friendly_name
                    items.append(
                        ReconciliationItem(
                            category="client",
                            item_id=client_name_item_id(mac_clean),
                            key=f"Client {fixed.fixed_ip} ({fixed.mac})",
                            opnsense_val=old_name,
                            ucg_val=None,
                            uos_val=friendly_name,
                            status="aligned",
                            action="enrich_hostname",
                            explanation=f"Technischer Hostname '{old_name}' durch lesbaren Namen '{friendly_name}' aus dem UniFi Server angereichert.",
                        )
                    )
                    summary["clients_enriched"] += 1

        # Incorporate any additional fixed IPs from UOS / UCG not present in OPNsense
        existing_target_macs = {f.mac.lower() for f in self.target.fixed_ips}
        all_unifi_clients = (self.uos_state.clients if self.uos_state else []) + (self.ucg_state.clients if self.ucg_state else [])
        for c in all_unifi_clients:
            mac = c.get("mac", "").lower()
            fixed_ip = c.get("fixed_ip") or c.get("ip")
            if mac and fixed_ip and (c.get("use_fixedip", False) or "fixed_ip" in c):
                if mac not in existing_target_macs:
                    name = c.get("name") or c.get("hostname", f"Device-{mac[-5:]}")
                    self.target.fixed_ips.append(
                        UniFiFixedIp(
                            mac=mac,
                            name=name,
                            fixed_ip=fixed_ip,
                            network_name=c.get("network_id", "Corporate"),
                        )
                    )
                    existing_target_macs.add(mac)
                    items.append(
                        ReconciliationItem(
                            category="client",
                            item_id=client_item_id(mac),
                            key=f"Client {fixed_ip} ({mac})",
                            opnsense_val=None,
                            ucg_val=fixed_ip if self.ucg_state else None,
                            uos_val=f"{name} ({fixed_ip})" if self.uos_state else None,
                            status="import_uos",
                            action="import_fixed_ip",
                            explanation=f"Feste IP-Reservierung für '{name}' aus UniFi-Export übernommen.",
                        )
                    )
                    summary["clients_enriched"] += 1

        # ---------------------------------------------------------------------
        # 4. Adopted Devices (APs & Switches from UOS Server)
        # ---------------------------------------------------------------------
        if self.uos_state and self.uos_state.devices:
            for dev in self.uos_state.devices:
                items.append(
                    ReconciliationItem(
                        category="device", item_id=device_item_id(dev.mac),
                        key=f"{dev.name} ({dev.model.upper()})",
                        opnsense_val=None,
                        ucg_val=None,
                        uos_val=f"MAC: {dev.mac} | IP: {dev.ip}",
                        status="aligned",
                        action="prepare_adoption",
                        explanation=f"UniFi Access Point / Switch erkannt. Bereit für Übernahme via 'set-inform http://<ucg-ip>:8080/inform'.",
                    )
                )
                summary["devices_mapped"] += 1

        # ---------------------------------------------------------------------
        # 5. Dynamic DNS (DynDNS)
        # ---------------------------------------------------------------------
        for dyn in getattr(self.target, "dynamic_dns", []):
            items.append(
                ReconciliationItem(
                    category="dyndns",
                    item_id=dyndns_item_id(dyn.host_name),
                    key=f"DynDNS {dyn.host_name}",
                    opnsense_val=f"{dyn.service.upper()} ({dyn.host_name}) auf {dyn.interface}",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="create_dyndns",
                    explanation=f"Dynamic DNS für '{dyn.host_name}' ({dyn.service}) wird auf dem UCG-Max neu angelegt.",
                )
            )

        # ---------------------------------------------------------------------
        # 6. Static Routes
        # ---------------------------------------------------------------------
        for r in getattr(self.target, "static_routes", []):
            items.append(
                ReconciliationItem(
                    category="route",
                    item_id=route_item_id(r.network),
                    key=f"Route {r.network}",
                    opnsense_val=f"Ziel {r.network} via {r.next_hop}",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="create_static_route",
                    explanation=f"Statische Route '{r.network}' mit Next-Hop {r.next_hop} wird auf dem UCG-Max angelegt.",
                )
            )

        # ---------------------------------------------------------------------
        # 7. DNS Forwarding / Domain Overrides
        # ---------------------------------------------------------------------
        for df in getattr(self.target, "dns_forwardings", []):
            items.append(
                ReconciliationItem(
                    category="dns_fwd",
                    item_id=dns_fwd_item_id(df.domain),
                    key=f"DNS Forward {df.domain}",
                    opnsense_val=f"Domäne {df.domain} ➔ {df.forward_to_ip}",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="create_dns_forwarding",
                    explanation=f"Bedingte DNS-Weiterleitung für '{df.domain}' an internen DNS {df.forward_to_ip}.",
                )
            )

        # ---------------------------------------------------------------------
        # 8. Multi-WAN / Gateway Groups
        # ---------------------------------------------------------------------
        if getattr(self.target, "multi_wan", None):
            mw = self.target.multi_wan
            items.append(
                ReconciliationItem(
                    category="multi_wan",
                    item_id="multi_wan:config",
                    key="Multi-WAN Modus",
                    opnsense_val="Gateway-Gruppe aus OPNsense",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="configure_multi_wan",
                    explanation=f"Multi-WAN Modus: {mw.mode.upper()} ({mw.wan2_port} als WAN2, Echo-Server: {mw.wan1_echo_server}).",
                )
            )

        # ---------------------------------------------------------------------
        # 9. System & Zeitserver (NTP, Syslog, SNMP)
        # ---------------------------------------------------------------------
        if getattr(self.target, "ntp_settings", None):
            ntp = self.target.ntp_settings
            items.append(
                ReconciliationItem(
                    category="system",
                    item_id="system:ntp",
                    key="Zeitserver (NTP)",
                    opnsense_val=", ".join(ntp.upstream_servers),
                    ucg_val=None,
                    uos_val=None,
                    status="aligned",
                    action="configure_ntp",
                    explanation=f"Upstream NTP-Server ({', '.join(ntp.upstream_servers)}) und DHCP Option 42 für VLANs.",
                )
            )
        if getattr(self.target, "syslog_settings", None) and self.target.syslog_settings.enabled:
            sl = self.target.syslog_settings
            items.append(
                ReconciliationItem(
                    category="system",
                    item_id="system:syslog",
                    key="Remote Syslog",
                    opnsense_val=f"{sl.server}:{sl.port}",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="configure_syslog",
                    explanation=f"Zentraler Syslog-Server {sl.server}:{sl.port} wird für alle Gateway-Events eingerichtet.",
                )
            )
        if getattr(self.target, "snmp_settings", None) and self.target.snmp_settings.enabled:
            sn = self.target.snmp_settings
            items.append(
                ReconciliationItem(
                    category="system",
                    item_id="system:snmp",
                    key="SNMP Monitoring",
                    opnsense_val=f"Community: {sn.community}",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="configure_snmp",
                    explanation=f"SNMPv2c Monitoring mit Community-String '{sn.community}' wird aktiviert.",
                )
            )

        # ---------------------------------------------------------------------
        # 10. Dienste & Multicast (mDNS, UPnP)
        # ---------------------------------------------------------------------
        if getattr(self.target, "multicast_settings", None):
            items.append(
                ReconciliationItem(
                    category="services",
                    item_id="services:multicast",
                    key="Multicast & mDNS",
                    opnsense_val="mDNS Repeater / IGMP Proxy",
                    ucg_val=None,
                    uos_val=None,
                    status="aligned",
                    action="configure_multicast",
                    explanation="Multicast DNS (mDNS) und IGMP Snooping netzwerkweit für IoT-Casting (Sonos, AirPlay) aktiviert.",
                )
            )
        if getattr(self.target, "upnp_settings", None) and self.target.upnp_settings.enabled:
            items.append(
                ReconciliationItem(
                    category="services",
                    item_id="services:upnp",
                    key="UPnP Gateway-Dienst",
                    opnsense_val="miniupnpd aktiv",
                    ucg_val=None,
                    uos_val=None,
                    status="create",
                    action="configure_upnp",
                    explanation="UPnP für automatische Portfreigaben (Gaming / Konsolen) auf WAN aktiviert.",
                )
            )

        summary["excluded"] = self._mark_exclusions(items)

        report = ReconciliationReport(
            ucg_connected=bool(self.ucg_state and self.ucg_state.networks),
            uos_connected=bool(self.uos_state and (self.uos_state.wlans or self.uos_state.devices)),
            ucg_version=self.ucg_state.version if self.ucg_state else "",
            uos_version=self.uos_state.version if self.uos_state else "",
            items=items,
            summary=summary,
        )

        self.target.reconciliation_report = report
        return report
