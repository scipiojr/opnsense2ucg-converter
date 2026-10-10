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
)

logger = logging.getLogger(__name__)


class MultiSourceMerger:
    def __init__(
        self,
        opnsense_cfg: OPNsenseConfig,
        unifi_target: UniFiTargetConfig,
        ucg_state: Optional[UniFiSourceState] = None,
        uos_state: Optional[UniFiSourceState] = None,
    ):
        self.opn_cfg = opnsense_cfg
        self.target = unifi_target
        self.ucg_state = ucg_state
        self.uos_state = uos_state

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
                vlan = net.get("vlan", 1) or net.get("vlan_id", 1)
                name = net.get("name", "")
                existing_ucg_nets_by_vlan[int(vlan)] = net
                existing_ucg_nets_by_name[name.lower()] = net

        for target_net in self.target.networks:
            vlan = target_net.vlan_id
            target_cidr = target_net.gateway_cidr.split("/")[0] if "/" in target_net.gateway_cidr else target_net.gateway_cidr

            match = existing_ucg_nets_by_vlan.get(vlan) or existing_ucg_nets_by_name.get(target_net.name.lower())

            if match:
                ucg_ip = match.get("ip_subnet", "") or match.get("gateway_ip", "")
                # Compare subnets
                if not ucg_ip or ucg_ip.startswith(target_cidr[:8]):  # Subnet prefix match
                    items.append(
                        ReconciliationItem(
                            category="network",
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
                            category="network",
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
                        category="network",
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
            planned_vlans = {n.vlan_id for n in self.target.networks}
            for net in self.ucg_state.networks:
                vlan = int(net.get("vlan", 1) or net.get("vlan_id", 1))
                if vlan not in planned_vlans and net.get("name") not in ["Default", "default"]:
                    items.append(
                        ReconciliationItem(
                            category="network",
                            key=f"VLAN {vlan} ({net.get('name')})",
                            opnsense_val=None,
                            ucg_val=net.get("ip_subnet", "aktiv"),
                            status="preserve_ucg",
                            action="keep_untouched",
                            explanation="Existiert nur auf UCG-Max und wird sicher beibehalten (kein Löschen).",
                        )
                    )
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
                        category="wlan",
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

        for fixed in self.target.fixed_ips:
            mac_clean = fixed.mac.lower()
            if mac_clean in uos_clients_by_mac:
                friendly_name = uos_clients_by_mac[mac_clean]
                if friendly_name != fixed.name:
                    old_name = fixed.name
                    fixed.name = friendly_name
                    items.append(
                        ReconciliationItem(
                            category="client",
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

        # ---------------------------------------------------------------------
        # 4. Adopted Devices (APs & Switches from UOS Server)
        # ---------------------------------------------------------------------
        if self.uos_state and self.uos_state.devices:
            for dev in self.uos_state.devices:
                items.append(
                    ReconciliationItem(
                        category="device",
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
