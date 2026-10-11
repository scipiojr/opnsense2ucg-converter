"""
Migration Exclusion Engine.

Allows single entries of the 3-way reconciliation (networks, WLANs, clients,
devices) to be excluded from migration ("nicht migrieren") and resolves the
consequences on dependent objects.

Design:
- Non-destructive: the merged target config (state.unifi_cfg) stays untouched.
  Exclusions are stored separately and applied as an overlay ("plan").
  This keeps manual edits intact, survives re-merges and makes undo trivial.
- The plan is index-based on the current target config so the UI can annotate
  rows, while exports / deploys use the "effective" config (plan applied to a
  deep copy).

Strategies for dependents:
- network: "cascade"  -> dependent fixed IPs, WLANs, rules, groups, port
                         forwards and DNS records are excluded as well
           "reassign" -> dependents are moved into another network (target_vlan);
                         IPs keep their host offset in the new subnet
- client:  "cascade"  -> DNS records, port forwards, rules and group members
                         pointing to the client IP are removed
           "keep"     -> references stay, but are flagged (IP no longer reserved)
- client_name: restores the original OPNsense hostname (no dependents)
- wlan / device: no configuration dependents, only informational consequences
"""

import copy
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.models import UniFiTargetConfig
from src.translator.remapper import remap_ip_address

logger = logging.getLogger(__name__)

LIST_KEYS = ["networks", "fixed_ips", "wlans", "firewall_rules", "firewall_groups", "port_forwards", "dns_records"]

STRATEGIES = {
    "network": ["cascade", "reassign"],
    "client": ["cascade", "keep"],
    "client_name": ["restore"],
    "wlan": ["skip"],
    "device": ["skip"],
}


# -----------------------------------------------------------------------------
# Stable item identifiers (shared by merger, API and UI)
# -----------------------------------------------------------------------------
def network_item_id(vlan: Any) -> str:
    return f"network:{int(vlan) if vlan is not None else 1}"


def wlan_item_id(ssid: str) -> str:
    return f"wlan:{ssid}"


def client_item_id(mac: str) -> str:
    return f"client:{(mac or '').lower()}"


def client_name_item_id(mac: str) -> str:
    return f"client_name:{(mac or '').lower()}"


def device_item_id(mac: str) -> str:
    return f"device:{(mac or '').lower()}"


def parse_item_id(item_id: str) -> Tuple[str, str]:
    kind, _, ref = (item_id or "").partition(":")
    return kind, ref


# -----------------------------------------------------------------------------
# IP helpers
# -----------------------------------------------------------------------------
def _as_network(cidr: Optional[str]):
    if not cidr:
        return None
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None


def _addr_in_net(addr: Optional[str], net) -> bool:
    """True if a host IP or subnet string lies inside net."""
    if not addr or net is None:
        return False
    a = addr.strip()
    if a.lower() in ("any", "", "none"):
        return False
    try:
        if "/" in a:
            cand = ipaddress.ip_network(a, strict=False)
            return cand.version == net.version and cand.subnet_of(net)
        return ipaddress.ip_address(a) in net
    except ValueError:
        return False


def _same_host(addr: Optional[str], ip: str) -> bool:
    if not addr or not ip:
        return False
    a = addr.strip()
    return a == ip or a == f"{ip}/32"


# -----------------------------------------------------------------------------
# Plan building
# -----------------------------------------------------------------------------
class ExclusionPlan:
    def __init__(self):
        self.entries: Dict[str, Dict[int, Dict[str, Any]]] = {k: {} for k in LIST_KEYS}
        self.consequences: List[Dict[str, Any]] = []
        self.devices_excluded: List[str] = []

    # --- helpers -------------------------------------------------------------
    def is_excluded(self, list_key: str, idx: int) -> bool:
        return self.entries[list_key].get(idx, {}).get("action") == "excluded"

    def exclude(self, list_key: str, idx: int, reason: str, source: str):
        if self.is_excluded(list_key, idx):
            return False
        self.entries[list_key][idx] = {"action": "excluded", "reason": reason, "source": source}
        return True

    def modify(self, list_key: str, idx: int, changes: Dict[str, Any], reason: str, source: str, action: str = "modified"):
        if self.is_excluded(list_key, idx):
            return False
        entry = self.entries[list_key].setdefault(idx, {"action": action, "reason": reason, "source": source, "changes": {}})
        entry.setdefault("changes", {}).update(changes)
        entry["reason"] = reason
        entry["action"] = action
        return True

    def consequence(self, source: str, severity: str, message: str):
        self.consequences.append({"source": source, "severity": severity, "message": message})

    def counts(self) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for k, entries in self.entries.items():
            c = {"excluded": 0, "modified": 0}
            for e in entries.values():
                c["excluded" if e["action"] == "excluded" else "modified"] += 1
            out[k] = c
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entries": {k: {str(i): v for i, v in e.items()} for k, e in self.entries.items()},
            "consequences": self.consequences,
            "counts": self.counts(),
            "devices_excluded": self.devices_excluded,
        }


class ExclusionEngine:
    """Builds plans and effective configs from a list of exclusion entries."""

    @staticmethod
    def build_plan(cfg: UniFiTargetConfig, exclusions: List[Dict[str, Any]]) -> ExclusionPlan:
        plan = ExclusionPlan()
        if not cfg or not exclusions:
            return plan

        # Order matters: networks first (largest blast radius), then clients, then the rest
        order = {"network": 0, "client": 1, "client_name": 2, "wlan": 3, "device": 4}
        for excl in sorted(exclusions, key=lambda e: order.get(parse_item_id(e.get("item_id", ""))[0], 9)):
            kind, ref = parse_item_id(excl.get("item_id", ""))
            try:
                if kind == "network":
                    ExclusionEngine._plan_network(cfg, plan, excl, int(ref))
                elif kind == "client":
                    ExclusionEngine._plan_client(cfg, plan, excl, ref)
                elif kind == "client_name":
                    ExclusionEngine._plan_client_name(cfg, plan, excl, ref)
                elif kind == "wlan":
                    ExclusionEngine._plan_wlan(cfg, plan, excl, ref)
                elif kind == "device":
                    plan.devices_excluded.append(ref)
                    plan.consequence(excl["item_id"], "info",
                                     f"Gerät {excl.get('label') or ref} wird nicht auf den UCG-Max übernommen und bleibt am bisherigen Controller adoptiert.")
            except Exception as exc:  # never break the whole plan because of one entry
                logger.exception("Failed to plan exclusion %s", excl)
                plan.consequence(excl.get("item_id", "?"), "warning", f"Ausschluss konnte nicht ausgewertet werden: {exc}")
        return plan

    # --- network ------------------------------------------------------------
    @staticmethod
    def _plan_network(cfg: UniFiTargetConfig, plan: ExclusionPlan, excl: Dict[str, Any], vlan: int):
        src = excl["item_id"]
        idx = next((i for i, n in enumerate(cfg.networks) if int(n.vlan_id) == vlan), None)
        if idx is None:
            plan.consequence(src, "info", f"Netzwerk VLAN {vlan} ist in der Zielkonfiguration nicht (mehr) vorhanden – nichts zu tun.")
            return
        net = cfg.networks[idx]
        subnet = _as_network(net.gateway_cidr)
        strategy = excl.get("strategy", "cascade")

        target_net = None
        target_idx = None
        if strategy == "reassign":
            tv = excl.get("target_vlan")
            target_idx = next((i for i, n in enumerate(cfg.networks)
                               if tv is not None and int(n.vlan_id) == int(tv) and i != idx), None)
            if target_idx is None or plan.is_excluded("networks", target_idx):
                plan.consequence(src, "warning",
                                 f"Ziel-Netzwerk VLAN {tv} für die Umzuordnung fehlt oder ist selbst ausgeschlossen – abhängige Einträge werden stattdessen mit ausgeschlossen.")
                strategy = "cascade"
            else:
                target_net = cfg.networks[target_idx]

        plan.exclude("networks", idx, f"Netzwerk '{net.name}' (VLAN {vlan}) wird nicht migriert.", src)
        tgt_subnet = _as_network(target_net.gateway_cidr) if target_net else None
        reason_reassign = (f"Umgezogen von '{net.name}' (VLAN {vlan}) nach '{target_net.name}' (VLAN {target_net.vlan_id})."
                           if target_net else "")
        reason_cascade = f"Abhängig von ausgeschlossenem Netzwerk '{net.name}' (VLAN {vlan})."

        # Fixed IPs ------------------------------------------------------------
        used_target_ips = {f.fixed_ip for i, f in enumerate(cfg.fixed_ips)
                           if target_net and _addr_in_net(f.fixed_ip, tgt_subnet)}
        for i, f in enumerate(cfg.fixed_ips):
            if not (f.network_name == net.name or _addr_in_net(f.fixed_ip, subnet)):
                continue
            if strategy == "reassign":
                new_ip = remap_ip_address(f.fixed_ip, net.gateway_cidr, target_net.gateway_cidr)
                if new_ip == f.fixed_ip and not _addr_in_net(f.fixed_ip, tgt_subnet):
                    plan.exclude("fixed_ips", i, f"{reason_cascade} IP {f.fixed_ip} passt nicht in {target_net.gateway_cidr}.", src)
                    plan.consequence(src, "warning", f"Feste IP {f.fixed_ip} ({f.name}) konnte nicht umgerechnet werden und entfällt.")
                    continue
                if new_ip in used_target_ips:
                    plan.exclude("fixed_ips", i, f"{reason_cascade} IP-Kollision mit {new_ip} im Zielnetz.", src)
                    plan.consequence(src, "warning",
                                     f"IP-Kollision: {f.name} würde {new_ip} erhalten, die im Zielnetz bereits vergeben ist – Reservierung entfällt.")
                    continue
                used_target_ips.add(new_ip)
                plan.modify("fixed_ips", i, {"fixed_ip": new_ip, "network_name": target_net.name}, reason_reassign, src, "reassigned")
            else:
                plan.exclude("fixed_ips", i, reason_cascade, src)

        # WLANs ----------------------------------------------------------------
        for i, w in enumerate(cfg.wlans):
            if w.vlan_id is None or int(w.vlan_id) != vlan:
                continue
            if strategy == "reassign":
                plan.modify("wlans", i, {"vlan_id": int(target_net.vlan_id)}, reason_reassign, src, "reassigned")
            else:
                plan.exclude("wlans", i, reason_cascade, src)
                plan.consequence(src, "warning", f"WLAN '{w.name}' war an VLAN {vlan} gebunden und wird ebenfalls nicht migriert.")

        # Firewall groups -------------------------------------------------------
        removed_groups = set()
        for i, g in enumerate(cfg.firewall_groups):
            inside = [m for m in g.members if _addr_in_net(m, subnet)]
            if not inside:
                continue
            if strategy == "reassign":
                new_members = [remap_ip_address(m, net.gateway_cidr, target_net.gateway_cidr) for m in g.members]
                plan.modify("firewall_groups", i, {"members": new_members}, reason_reassign, src, "reassigned")
            elif len(inside) == len(g.members):
                plan.exclude("firewall_groups", i, f"{reason_cascade} Alle Mitglieder lagen im Subnetz.", src)
                removed_groups.add(g.name)
            else:
                plan.modify("firewall_groups", i, {"members": [m for m in g.members if m not in inside]},
                            f"{reason_cascade} {len(inside)} Mitglied(er) entfernt.", src)

        # Firewall rules -------------------------------------------------------
        for i, r in enumerate(cfg.firewall_rules):
            hits_addr = _addr_in_net(r.src_address, subnet) or _addr_in_net(r.dst_address, subnet)
            hits_group = bool(removed_groups & set((r.src_firewall_group_names or []) + (r.dst_firewall_group_names or [])))
            if not (hits_addr or hits_group):
                continue
            if strategy == "reassign" and hits_addr:
                plan.modify("firewall_rules", i, {
                    "src_address": remap_ip_address(r.src_address, net.gateway_cidr, target_net.gateway_cidr) if r.src_address else r.src_address,
                    "dst_address": remap_ip_address(r.dst_address, net.gateway_cidr, target_net.gateway_cidr) if r.dst_address else r.dst_address,
                }, reason_reassign, src, "reassigned")
                plan.consequence(src, "info", f"Regel '{r.name}' gilt nun für {target_net.name} – bitte prüfen, ob die Freigabe dort gewollt ist.")
            else:
                plan.exclude("firewall_rules", i, reason_cascade, src)

        # Port forwards ---------------------------------------------------------
        for i, p in enumerate(cfg.port_forwards):
            if not _addr_in_net(p.fwd_ip, subnet):
                continue
            if strategy == "reassign":
                plan.modify("port_forwards", i, {"fwd_ip": remap_ip_address(p.fwd_ip, net.gateway_cidr, target_net.gateway_cidr)},
                            reason_reassign, src, "reassigned")
            else:
                plan.exclude("port_forwards", i, reason_cascade, src)
                plan.consequence(src, "warning", f"Port-Weiterleitung '{p.name}' ({p.dst_port} ➔ {p.fwd_ip}) entfällt – Dienst ist von außen nicht mehr erreichbar.")

        # DNS records ----------------------------------------------------------
        for i, d in enumerate(cfg.dns_records):
            if not _addr_in_net(d.value, subnet):
                continue
            if strategy == "reassign":
                plan.modify("dns_records", i, {"value": remap_ip_address(d.value, net.gateway_cidr, target_net.gateway_cidr)},
                            reason_reassign, src, "reassigned")
            else:
                plan.exclude("dns_records", i, reason_cascade, src)

    # --- client (fixed IP) --------------------------------------------------
    @staticmethod
    def _plan_client(cfg: UniFiTargetConfig, plan: ExclusionPlan, excl: Dict[str, Any], mac: str):
        src = excl["item_id"]
        idx = next((i for i, f in enumerate(cfg.fixed_ips) if f.mac.lower() == mac), None)
        if idx is None:
            plan.consequence(src, "info", f"Keine feste IP für {mac} in der Zielkonfiguration – nichts zu tun.")
            return
        f = cfg.fixed_ips[idx]
        ip = f.fixed_ip
        strategy = excl.get("strategy", "cascade")
        plan.exclude("fixed_ips", idx, f"Reservierung für '{f.name}' wird nicht migriert.", src)
        plan.consequence(src, "info", f"'{f.name}' erhält künftig eine dynamische IP per DHCP statt {ip}.")
        reason = f"Verweist auf nicht migrierte Reservierung {ip} ({f.name})."

        def handle(list_key: str, i: int, label: str):
            if strategy == "cascade":
                plan.exclude(list_key, i, reason, src)
            else:
                plan.consequence(src, "warning", f"{label} verweist weiterhin auf {ip} – nach DHCP-Neuvergabe evtl. falsches Ziel.")

        for i, d in enumerate(cfg.dns_records):
            if _same_host(d.value, ip):
                handle("dns_records", i, f"DNS-Eintrag '{d.key}'")
        for i, p in enumerate(cfg.port_forwards):
            if _same_host(p.fwd_ip, ip):
                handle("port_forwards", i, f"Port-Weiterleitung '{p.name}'")
        for i, r in enumerate(cfg.firewall_rules):
            if _same_host(r.src_address, ip) or _same_host(r.dst_address, ip):
                handle("firewall_rules", i, f"Firewall-Regel '{r.name}'")
        for i, g in enumerate(cfg.firewall_groups):
            if any(_same_host(m, ip) for m in g.members):
                if strategy == "cascade":
                    remaining = [m for m in g.members if not _same_host(m, ip)]
                    if remaining:
                        plan.modify("firewall_groups", i, {"members": remaining}, reason, src)
                    else:
                        plan.exclude("firewall_groups", i, reason, src)
                        for j, r in enumerate(cfg.firewall_rules):
                            if g.name in (r.src_firewall_group_names or []) + (r.dst_firewall_group_names or []):
                                plan.exclude("firewall_rules", j, f"Gruppe '{g.name}' ist leer geworden.", src)
                else:
                    plan.consequence(src, "warning", f"Gruppe '{g.name}' enthält weiterhin {ip}.")

    @staticmethod
    def _plan_client_name(cfg: UniFiTargetConfig, plan: ExclusionPlan, excl: Dict[str, Any], mac: str):
        src = excl["item_id"]
        idx = next((i for i, f in enumerate(cfg.fixed_ips) if f.mac.lower() == mac), None)
        original = excl.get("original_name")
        if idx is None or not original:
            return
        plan.modify("fixed_ips", idx, {"name": original}, "Namensanreicherung verworfen – OPNsense-Hostname bleibt.", src)

    @staticmethod
    def _plan_wlan(cfg: UniFiTargetConfig, plan: ExclusionPlan, excl: Dict[str, Any], ssid: str):
        src = excl["item_id"]
        idx = next((i for i, w in enumerate(cfg.wlans) if w.name == ssid), None)
        if idx is None:
            return
        plan.exclude("wlans", idx, f"WLAN '{ssid}' wird nicht migriert.", src)
        plan.consequence(src, "warning", f"Geräte, die nur über '{ssid}' verbunden sind, verlieren nach der Umstellung den WLAN-Zugang.")

    # -----------------------------------------------------------------------
    # Applying
    # -----------------------------------------------------------------------
    @staticmethod
    def effective_config(cfg: UniFiTargetConfig, plan: ExclusionPlan) -> UniFiTargetConfig:
        """Returns a deep copy of cfg with the plan applied (used for export/deploy)."""
        eff = copy.deepcopy(cfg)
        for key in LIST_KEYS:
            entries = plan.entries.get(key, {})
            if not entries:
                continue
            src_list = getattr(eff, key, [])
            new_list = []
            for i, obj in enumerate(src_list):
                e = entries.get(i)
                if e and e["action"] == "excluded":
                    continue
                if e and e.get("changes"):
                    for attr, val in e["changes"].items():
                        setattr(obj, attr, val)
                new_list.append(obj)
            setattr(eff, key, new_list)
        return eff

    @staticmethod
    def impact(cfg: UniFiTargetConfig, existing: List[Dict[str, Any]], candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Dry-run: what changes if `candidate` is added to the existing exclusions?"""
        others = [e for e in existing if e.get("item_id") != candidate.get("item_id")]
        before = ExclusionEngine.build_plan(cfg, others)
        after = ExclusionEngine.build_plan(cfg, others + [candidate])

        labels = {
            "networks": lambda o: f"{o.name} (VLAN {o.vlan_id}, {o.gateway_cidr})",
            "fixed_ips": lambda o: f"{o.name} – {o.fixed_ip} ({o.mac})",
            "wlans": lambda o: f"SSID {o.name}" + (f" (VLAN {o.vlan_id})" if o.vlan_id else ""),
            "firewall_rules": lambda o: f"#{o.rule_index} {o.name}",
            "firewall_groups": lambda o: f"{o.name} ({len(o.members)} Mitglieder)",
            "port_forwards": lambda o: f"{o.name}: {o.dst_port} ➔ {o.fwd_ip}:{o.fwd_port}",
            "dns_records": lambda o: f"{o.key} ➔ {o.value}",
        }
        affected: Dict[str, List[Dict[str, Any]]] = {}
        for key in LIST_KEYS:
            items = getattr(cfg, key, [])
            rows = []
            for i, e in after.entries[key].items():
                if before.entries[key].get(i) == e:
                    continue
                try:
                    label = labels[key](items[i])
                except Exception:
                    label = f"#{i}"
                rows.append({"index": i, "label": label, "action": e["action"], "reason": e["reason"],
                             "changes": e.get("changes", {})})
            if rows:
                affected[key] = rows
        new_consequences = [c for c in after.consequences if c["source"] == candidate.get("item_id")]
        return {"affected": affected, "consequences": new_consequences}
