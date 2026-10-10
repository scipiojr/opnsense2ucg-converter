"""
Starlette-based Web Application & API backend for OPNsense-to-UniFi Migrator.
Provides interactive REST endpoints for upload, sanitization, LLM prompting, review, and deployment.
"""

import json
import logging
import os
from typing import Dict, Any, Optional

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

from src.models import (
    OPNsenseConfig,
    UniFiTargetConfig,
    UniFiSourceState,
    ReconciliationReport,
    UniFiNetwork,
    UniFiFixedIp,
    UniFiWlan,
)
from src.opnsense.parser import OPNsenseParser
from src.opnsense.client import OPNsenseClient
from src.sanitizer.masker import SanitizerVault
from src.translator.mapper import UniFiMapper
from src.translator.merger import MultiSourceMerger
from src.translator.remapper import VlanRemapper, remap_ip_address
from src.llm.engine import LLMTranslationEngine
from src.unifi.client import UniFiGatewayClient
from src.unifi.export_parser import UniFiExportParser


# Global Session State
class SessionState:
    raw_xml: str = ""
    opnsense_filename: str = ""
    opnsense_cfg: Optional[OPNsenseConfig] = None
    vault: SanitizerVault = SanitizerVault()
    unifi_cfg: Optional[UniFiTargetConfig] = None
    llm_explanation: str = ""
    llm_recommendations: list = []
    ucg_filename: str = ""
    ucg_state: Optional[UniFiSourceState] = None
    uos_filename: str = ""
    uos_state: Optional[UniFiSourceState] = None
    reconciliation_report: Optional[ReconciliationReport] = None
    vlan_remaps: list = []

    def reset(self):
        self.raw_xml = ""
        self.opnsense_filename = ""
        self.opnsense_cfg = None
        self.vault = SanitizerVault()
        self.unifi_cfg = None
        self.llm_explanation = ""
        self.llm_recommendations = []
        self.ucg_filename = ""
        self.ucg_state = None
        self.uos_filename = ""
        self.uos_state = None
        self.reconciliation_report = None
        self.vlan_remaps = []


state = SessionState()


def get_html_content() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>OPNsense to UniFi Migrator</h1>"


async def index_view(request: Request) -> HTMLResponse:
    return HTMLResponse(get_html_content())


async def load_sample_api(request: Request) -> JSONResponse:
    sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "examples", "sample_opnsense_26_7_5.xml")
    if not os.path.exists(sample_path):
        return JSONResponse({"success": False, "error": "Sample file not found"}, status_code=404)

    with open(sample_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    return await process_xml(xml_content)


async def upload_xml_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        xml_content = body.get("xml_content", "")
        if not xml_content.strip():
            return JSONResponse({"success": False, "error": "No XML content provided"}, status_code=400)
        return await process_xml(xml_content)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


def _apply_xml_content(xml_content: str) -> Dict[str, Any]:
    state.raw_xml = xml_content
    parser = OPNsenseParser(xml_content)
    state.opnsense_cfg = parser.parse()

    # Reset Vault & Mapper
    state.vault = SanitizerVault(anonymize_macs=False)
    mapper = UniFiMapper(state.opnsense_cfg)
    state.unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)

    if state.ucg_state or state.uos_state:
        merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
        state.reconciliation_report = merger.reconcile()

    summary_data = {
        "version": state.opnsense_cfg.version,
        "interfaces_count": len(state.opnsense_cfg.interfaces),
        "static_leases_count": len(state.opnsense_cfg.static_leases),
        "aliases_count": len(state.opnsense_cfg.aliases),
        "port_forwards_count": len(state.opnsense_cfg.port_forwards),
        "filter_rules_count": len(state.opnsense_cfg.filter_rules),
        "omitted_count": len(state.opnsense_cfg.omitted_items),
        "omitted_items": [
            {
                "category": o.category,
                "name": o.name,
                "reason": o.reason,
                "recommendation": o.recommendation,
                "severity": o.severity,
            }
            for o in state.opnsense_cfg.omitted_items
        ],
        "interfaces": [
            {
                "id": i.id,
                "descr": i.descr,
                "ip": f"{i.ipaddr}/{i.subnet}" if i.subnet else i.ipaddr,
                "vlan": i.vlan_tag or "Untagged",
                "device": i.physical_if,
            }
            for i in state.opnsense_cfg.interfaces
        ],
        "static_leases": [
            {
                "mac": l.mac,
                "ip": l.ipaddr,
                "hostname": l.hostname,
                "descr": l.descr,
                "iface": l.interface,
            }
            for l in state.opnsense_cfg.static_leases
        ],
        "aliases": [
            {
                "name": a.name,
                "type": a.type,
                "content": a.content,
                "descr": a.descr,
            }
            for a in state.opnsense_cfg.aliases
        ],
        "filter_rules": [
            {
                "id": r.id,
                "iface": r.interface,
                "action": r.action,
                "proto": r.protocol,
                "src": r.src,
                "dst": r.dst,
                "dst_port": r.dst_port,
                "descr": r.descr,
            }
            for r in state.opnsense_cfg.filter_rules
        ],
    }

    return {
        "success": True,
        "summary": summary_data,
        "unifi_mapped": get_unifi_config_dict(),
    }


async def process_xml(xml_content: str) -> JSONResponse:
    data = _apply_xml_content(xml_content)
    return JSONResponse(data)


def get_unifi_config_dict() -> Dict[str, Any]:
    networks_from_sources = []
    if state.ucg_state and state.ucg_state.networks:
        for n in state.ucg_state.networks:
            if isinstance(n, dict):
                dhcp_en = n.get("dhcpd_enabled", n.get("dhcp_enabled", True))
                d_start = n.get("dhcpd_start", n.get("dhcp_start", "")) or ""
                d_stop = n.get("dhcpd_stop", n.get("dhcp_stop", "")) or ""
                d_range = f"{d_start} - {d_stop}" if dhcp_en and (d_start or d_stop) else ("DHCP Aktiv" if dhcp_en else "Manuell / Statisch")
                networks_from_sources.append({
                    "name": n.get("name", "UCG-Net"),
                    "vlan_id": n.get("vlan", n.get("vlan_id", 1)),
                    "gateway_cidr": n.get("ip_subnet", n.get("gateway_cidr", "")),
                    "dhcp_enabled": dhcp_en,
                    "dhcp_start": d_start,
                    "dhcp_stop": d_stop,
                    "dhcp_range": d_range,
                    "purpose": n.get("purpose", "corporate"),
                    "domain_name": n.get("domain_name", "local"),
                })
            else:
                d_start = getattr(n, "dhcp_start", "") or ""
                d_stop = getattr(n, "dhcp_stop", "") or ""
                d_range = f"{d_start} - {d_stop}" if n.dhcp_enabled and (d_start or d_stop) else ("DHCP Aktiv" if n.dhcp_enabled else "Manuell / Statisch")
                networks_from_sources.append({
                    "name": n.name,
                    "vlan_id": n.vlan_id,
                    "gateway_cidr": n.gateway_cidr,
                    "dhcp_enabled": n.dhcp_enabled,
                    "dhcp_start": d_start,
                    "dhcp_stop": d_stop,
                    "dhcp_range": d_range,
                    "purpose": getattr(n, "purpose", "corporate") or "corporate",
                    "domain_name": getattr(n, "domain_name", "local") or "local",
                })

    if not state.unifi_cfg:
        rep = state.reconciliation_report
        wlans_from_sources = []
        if state.uos_state and state.uos_state.wlans:
            wlans_from_sources = [
                {
                    "name": w.name,
                    "security": w.security,
                    "vlan_id": w.vlan_id,
                    "is_guest": w.is_guest,
                    "enabled": getattr(w, "enabled", True),
                }
                for w in state.uos_state.wlans
            ]
        elif state.ucg_state and state.ucg_state.wlans:
            wlans_from_sources = [
                {
                    "name": w.name,
                    "security": w.security,
                    "vlan_id": w.vlan_id,
                    "is_guest": w.is_guest,
                    "enabled": getattr(w, "enabled", True),
                }
                for w in state.ucg_state.wlans
            ]

        fixed_from_sources = []
        src_clients = (state.ucg_state.clients if state.ucg_state else []) + (state.uos_state.clients if state.uos_state else [])
        for c in src_clients:
            if isinstance(c, dict):
                if c.get("use_fixedip") or c.get("fixed_ip"):
                    fixed_from_sources.append({
                        "mac": c.get("mac", ""),
                        "name": c.get("name") or c.get("hostname") or "Client",
                        "fixed_ip": c.get("fixed_ip", ""),
                        "network_name": c.get("network_name", "Default"),
                    })
            else:
                if getattr(c, "use_fixedip", False) or getattr(c, "fixed_ip", None):
                    fixed_from_sources.append({
                        "mac": getattr(c, "mac", ""),
                        "name": getattr(c, "name", "") or getattr(c, "hostname", "") or "Client",
                        "fixed_ip": getattr(c, "fixed_ip", "") or "",
                        "network_name": getattr(c, "network_name", "Default") or "Default",
                    })

        return {
            "networks": networks_from_sources,
            "firewall_groups": [],
            "firewall_rules": [],
            "fixed_ips": fixed_from_sources,
            "port_forwards": [],
            "dns_records": [],
            "traffic_rules": [],
            "wireguard_servers": [],
            "smart_queue": None,
            "omitted_items": [],
            "wlans": wlans_from_sources,
            "reconciliation": (
                {
                    "ucg_connected": rep.ucg_connected,
                    "uos_connected": rep.uos_connected,
                    "ucg_version": rep.ucg_version,
                    "uos_version": rep.uos_version,
                    "summary": rep.summary,
                    "items": [
                        {
                            "category": item.category,
                            "key": item.key,
                            "opnsense_val": item.opnsense_val,
                            "ucg_val": item.ucg_val,
                            "uos_val": item.uos_val,
                            "status": item.status,
                            "action": item.action,
                            "explanation": item.explanation,
                        }
                        for item in rep.items
                    ],
                }
                if rep else None
            ),
            "ucg_networks": networks_from_sources,
        }
    return {
        "networks": [
            {
                "name": n.name,
                "vlan_id": n.vlan_id,
                "gateway_cidr": n.gateway_cidr,
                "dhcp_enabled": n.dhcp_enabled,
                "dhcp_start": getattr(n, "dhcp_start", "") or "",
                "dhcp_stop": getattr(n, "dhcp_stop", "") or "",
                "dhcp_range": f"{n.dhcp_start} - {n.dhcp_stop}" if n.dhcp_enabled and (getattr(n, "dhcp_start", "") or getattr(n, "dhcp_stop", "")) else ("DHCP Aktiv" if n.dhcp_enabled else "Manuell / Statisch"),
                "purpose": getattr(n, "purpose", "corporate") or "corporate",
                "domain_name": getattr(n, "domain_name", "local") or "local",
            }
            for n in state.unifi_cfg.networks
        ],
        "firewall_groups": [
            {
                "name": g.name,
                "group_type": g.group_type,
                "members": g.members,
            }
            for g in state.unifi_cfg.firewall_groups
        ],
        "firewall_rules": [
            {
                "rule_index": r.rule_index,
                "name": r.name,
                "ruleset": r.ruleset,
                "action": r.action,
                "protocol": r.protocol,
                "src_groups": r.src_firewall_group_names,
                "dst_groups": r.dst_firewall_group_names,
                "src_addr": r.src_address or "",
                "dst_addr": r.dst_address or "",
                "dst_port": r.dst_port or "",
                "logging": r.logging,
                "description": r.description,
                "status": getattr(r, "status", "accepted"),
                "origin": getattr(r, "origin", "OPNsense"),
                "llm_notes": getattr(r, "llm_notes", ""),
                "enabled": r.enabled,
            }
            for r in state.unifi_cfg.firewall_rules
        ],
        "fixed_ips": [
            {
                "mac": f.mac,
                "name": f.name,
                "fixed_ip": f.fixed_ip,
                "network_name": f.network_name,
            }
            for f in state.unifi_cfg.fixed_ips
        ],
        "port_forwards": [
            {
                "name": p.name,
                "dst_port": p.dst_port,
                "fwd_ip": p.fwd_ip,
                "fwd_port": p.fwd_port,
                "protocol": p.protocol,
            }
            for p in state.unifi_cfg.port_forwards
        ],
        "dns_records": [
            {
                "key": r.key,
                "value": r.value,
                "type": r.record_type,
            }
            for r in getattr(state.unifi_cfg, "dns_records", [])
        ],
        "traffic_rules": [
            {
                "name": tr.name,
                "action": tr.action,
                "target": tr.target,
                "domains": tr.domains,
                "regions": tr.regions,
            }
            for tr in getattr(state.unifi_cfg, "traffic_rules", [])
        ],
        "wireguard_servers": [
            {
                "name": wg.name,
                "port": wg.port,
                "tunnel_subnet": wg.tunnel_subnet,
            }
            for wg in getattr(state.unifi_cfg, "wireguard_servers", [])
        ],
        "smart_queue": (
            {
                "enabled": sq.enabled,
                "down_rate_kbps": sq.down_rate_kbps,
                "up_rate_kbps": sq.up_rate_kbps,
            }
            if (sq := getattr(state.unifi_cfg, "smart_queue", None)) else None
        ),
        "omitted_items": [
            {
                "category": o.category,
                "name": o.name,
                "reason": o.reason,
                "recommendation": o.recommendation,
                "severity": o.severity,
            }
            for o in getattr(state.unifi_cfg, "omitted_items", [])
        ],
        "wlans": [
            {
                "name": w.name,
                "security": w.security,
                "vlan_id": w.vlan_id,
                "is_guest": w.is_guest,
                "enabled": w.enabled,
            }
            for w in getattr(state.unifi_cfg, "wlans", [])
        ],
        "reconciliation": (
            {
                "ucg_connected": rep.ucg_connected,
                "uos_connected": rep.uos_connected,
                "ucg_version": rep.ucg_version,
                "uos_version": rep.uos_version,
                "summary": rep.summary,
                "items": [
                    {
                        "category": item.category,
                        "key": item.key,
                        "opnsense_val": item.opnsense_val,
                        "ucg_val": item.ucg_val,
                        "uos_val": item.uos_val,
                        "status": item.status,
                        "action": item.action,
                        "explanation": item.explanation,
                    }
                    for item in rep.items
                ],
            }
            if (rep := getattr(state.unifi_cfg, "reconciliation_report", None) or state.reconciliation_report) else None
        ),
        "ucg_networks": networks_from_sources,
    }


async def sanitize_api(request: Request) -> JSONResponse:
    body = await request.json()
    anonymize_macs = body.get("anonymize_macs", False)

    state.vault = SanitizerVault(anonymize_macs=anonymize_macs)
    sanitized_xml = state.vault.sanitize_xml(state.raw_xml)
    audit = state.vault.get_audit_summary()

    return JSONResponse({
        "success": True,
        "audit_summary": audit,
        "sanitized_xml_preview": sanitized_xml[:3000] + ("\n... [truncated for preview]" if len(sanitized_xml) > 3000 else ""),
    })


async def generate_prompt_api(request: Request) -> JSONResponse:
    if not state.opnsense_cfg:
        return JSONResponse({"success": False, "error": "No config loaded"}, status_code=400)

    # Prepare structured summary for the LLM
    data_for_llm = {
        "interfaces": [
            {"name": i.descr, "vlan": i.vlan_tag, "ip": i.ipaddr, "subnet": i.subnet}
            for i in state.opnsense_cfg.interfaces
        ],
        "aliases": [
            {"name": a.name, "type": a.type, "members": a.content}
            for a in state.opnsense_cfg.aliases
        ],
        "filter_rules": [
            {
                "id": r.id,
                "interface": r.interface,
                "action": r.action,
                "protocol": r.protocol,
                "src": r.src,
                "dst": r.dst,
                "dst_port": r.dst_port,
                "descr": r.descr,
            }
            for r in state.opnsense_cfg.filter_rules
        ],
        "port_forwards": [
            {"name": p.descr, "ext_port": p.dst_port, "target": f"{p.target_ip}:{p.target_port}", "proto": p.protocol}
            for p in state.opnsense_cfg.port_forwards
        ],
    }

    # Sanitize dictionary values
    sanitized_dict = state.vault.sanitize_dict(data_for_llm)

    engine = LLMTranslationEngine(state.vault)
    prompt = engine.generate_prompt(sanitized_dict)

    return JSONResponse({
        "success": True,
        "prompt": prompt,
    })


async def run_llm_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        provider = body.get("provider", "gemini")
        api_key = body.get("api_key", "")
        model = body.get("model", "")
        prompt = body.get("prompt", "")

        if not api_key:
            return JSONResponse({"success": False, "error": "API Key is required to call external LLM"}, status_code=400)

        engine = LLMTranslationEngine(state.vault)
        if provider == "gemini":
            result = engine.call_gemini(prompt, api_key=api_key, model=model or "gemini-2.5-flash")
        elif provider == "claude":
            result = engine.call_claude(prompt, api_key=api_key, model=model or "claude-3-7-sonnet-20250219")
        else:
            return JSONResponse({"success": False, "error": f"Unknown provider {provider}"}, status_code=400)

        # De-anonymize / rehydrate the LLM response
        rehydrated_result = state.vault.rehydrate_dict(result)
        state.llm_explanation = rehydrated_result.get("explanation", "")
        state.llm_recommendations = rehydrated_result.get("recommendations", [])

        return JSONResponse({
            "success": True,
            "result": rehydrated_result,
        })
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def apply_offline_llm_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        raw_text = body.get("json_text", "")
        engine = LLMTranslationEngine(state.vault)
        parsed = engine.parse_offline_response(raw_text)
        rehydrated = state.vault.rehydrate_dict(parsed)
        state.llm_explanation = rehydrated.get("explanation", "")
        state.llm_recommendations = rehydrated.get("recommendations", [])

        return JSONResponse({"success": True, "result": rehydrated})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=400)


async def test_connection_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        host = body.get("host", "192.168.1.1")
        username = body.get("username", "")
        password = body.get("password", "")
        api_key = body.get("api_key", None)

        client = UniFiGatewayClient(host=host, username=username, password=password, api_key=api_key)
        ok, msg = client.test_connection()
        return JSONResponse({"success": ok, "message": msg})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def dry_run_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi target config available"}, status_code=400)

        body = await request.json()
        host = body.get("host", "192.168.1.1")
        username = body.get("username", "")
        password = body.get("password", "")

        client = UniFiGatewayClient(host=host, username=username, password=password)
        report = client.dry_run(state.unifi_cfg)

        return JSONResponse({"success": True, "report": report})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def deploy_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi target config available"}, status_code=400)

        body = await request.json()
        host = body.get("host", "192.168.1.1")
        username = body.get("username", "")
        password = body.get("password", "")

        client = UniFiGatewayClient(host=host, username=username, password=password)
        results = client.deploy(state.unifi_cfg)

        return JSONResponse({"success": True, "results": results})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def export_json_api(request: Request) -> JSONResponse:
    if not state.unifi_cfg:
        return JSONResponse({"success": False, "error": "No UniFi configuration ready"}, status_code=400)

    cfg_dict = get_unifi_config_dict()
    return JSONResponse(cfg_dict, headers={"Content-Disposition": "attachment; filename=unifi_ucg_max_config.json"})


async def toggle_rule_status_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi config ready"}, status_code=400)
        body = await request.json()
        rule_index = body.get("rule_index")
        new_status = body.get("status")  # "accepted" or "discarded"

        found = False
        for r in state.unifi_cfg.firewall_rules:
            if r.rule_index == rule_index:
                r.status = new_status
                r.enabled = (new_status != "discarded")
                found = True
                break

        if not found:
            return JSONResponse({"success": False, "error": f"Rule with index {rule_index} not found"}, status_code=404)

        return JSONResponse({"success": True, "rule_index": rule_index, "status": new_status, "rules": get_unifi_config_dict()["firewall_rules"]})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def update_rule_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi config ready"}, status_code=400)
        body = await request.json()
        rule_index = body.get("rule_index")

        for r in state.unifi_cfg.firewall_rules:
            if r.rule_index == rule_index:
                if "name" in body:
                    r.name = body["name"]
                if "ruleset" in body:
                    r.ruleset = body["ruleset"]
                if "action" in body:
                    r.action = body["action"]
                if "protocol" in body:
                    r.protocol = body["protocol"]
                if "src_addr" in body:
                    r.src_address = body["src_addr"] or None
                if "dst_addr" in body:
                    r.dst_address = body["dst_addr"] or None
                if "dst_port" in body:
                    r.dst_port = str(body["dst_port"]) or None
                if "logging" in body:
                    r.logging = bool(body["logging"])
                if "description" in body:
                    r.description = body["description"]
                r.status = "modified"
                r.enabled = True
                return JSONResponse({"success": True, "rules": get_unifi_config_dict()["firewall_rules"]})

        return JSONResponse({"success": False, "error": f"Rule with index {rule_index} not found"}, status_code=404)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def bulk_rule_status_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi config ready"}, status_code=400)
        body = await request.json()
        new_status = body.get("status", "accepted")
        indices = body.get("indices", None)

        for r in state.unifi_cfg.firewall_rules:
            if indices is None or r.rule_index in indices:
                r.status = new_status
                r.enabled = (new_status != "discarded")

        return JSONResponse({"success": True, "status": new_status, "rules": get_unifi_config_dict()["firewall_rules"]})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def llm_assist_rule_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi config ready"}, status_code=400)
        body = await request.json()
        rule_index = body.get("rule_index")
        instruction = body.get("instruction", "")
        provider = body.get("provider", "local")
        api_key = body.get("api_key", "")
        model = body.get("model", "")

        target_rule = next((r for r in state.unifi_cfg.firewall_rules if r.rule_index == rule_index), None)
        if not target_rule:
            return JSONResponse({"success": False, "error": f"Rule with index {rule_index} not found"}, status_code=404)

        rule_dict = {
            "rule_index": target_rule.rule_index,
            "name": target_rule.name,
            "ruleset": target_rule.ruleset,
            "action": target_rule.action,
            "protocol": target_rule.protocol,
            "src_addr": target_rule.src_address or "",
            "dst_addr": target_rule.dst_address or "",
            "dst_port": target_rule.dst_port or "",
            "logging": target_rule.logging,
            "description": target_rule.description,
            "origin": getattr(target_rule, "origin", "OPNsense"),
        }

        engine = LLMTranslationEngine(state.vault)
        result = engine.assist_single_rule(
            rule_data=rule_dict,
            instruction=instruction,
            provider=provider,
            api_key=api_key,
            model=model,
        )
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def apply_llm_suggestion_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "No UniFi config ready"}, status_code=400)
        body = await request.json()
        rule_index = body.get("rule_index")
        updated = body.get("updated_rule", {})
        explanation = body.get("explanation", "")

        for r in state.unifi_cfg.firewall_rules:
            if r.rule_index == rule_index:
                if "name" in updated:
                    r.name = updated["name"]
                if "ruleset" in updated:
                    r.ruleset = updated["ruleset"]
                if "action" in updated:
                    r.action = updated["action"]
                if "protocol" in updated:
                    r.protocol = updated["protocol"]
                if "src_addr" in updated:
                    r.src_address = updated["src_addr"] or None
                if "dst_addr" in updated:
                    r.dst_address = updated["dst_addr"] or None
                if "dst_port" in updated:
                    r.dst_port = str(updated["dst_port"]) or None
                if "logging" in updated:
                    r.logging = bool(updated["logging"])
                if "description" in updated:
                    r.description = updated["description"]
                r.status = "modified"
                r.enabled = True
                if explanation:
                    r.llm_notes = explanation
                return JSONResponse({"success": True, "rules": get_unifi_config_dict()["firewall_rules"]})

        return JSONResponse({"success": False, "error": f"Rule with index {rule_index} not found"}, status_code=404)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def fetch_opnsense_live_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        host = body.get("host", "192.168.1.1")
        port = int(body.get("port", 443))
        protocol = body.get("protocol", "https")
        auth_mode = body.get("auth_mode", "auto")
        api_key = (body.get("api_key") or "").strip()
        api_secret = (body.get("api_secret") or "").strip()
        username = (body.get("username") or "").strip()
        password = (body.get("password") or "").strip()

        client = OPNsenseClient(
            host=host,
            port=port,
            protocol=protocol,
            api_key=api_key,
            api_secret=api_secret,
            username=username,
            password=password,
            auth_mode=auth_mode,
            verify_ssl=False,
        )

        xml_content = client.fetch_config_xml()
        state.opnsense_filename = f"live-opnsense-{host}.xml"
        result = _apply_xml_content(xml_content)
        result["source"] = "opnsense"
        result["host"] = host
        return JSONResponse(result)
    except Exception as e:
        logger.exception("Error in fetch_opnsense_live_api")
        err_str = str(e)
        hint = ""
        if "401" in err_str or "unauthorized" in err_str.lower() or "falscher benutzername" in err_str.lower():
            hint = "Tipp: Für Web-Passwörter bitte 'Web-GUI Login' wählen. Für REST-API bitte unter System > Access > Users > [User] > API-Keys (+) einen Schlüssel erzeugen."
        return JSONResponse({"success": False, "error": err_str, "hint": hint}, status_code=200)


async def fetch_ucg_live_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        host = body.get("host", "192.168.1.1")
        username = body.get("username", "")
        password = body.get("password", "")
        api_key = body.get("api_key") or None
        port = int(body.get("port", 443))
        site = body.get("site", "default")

        client = UniFiGatewayClient(
            host=host,
            username=username,
            password=password,
            api_key=api_key,
            site=site,
            port=port,
        )

        live_state = client.fetch_live_state(source_type="ucg_max")
        state.ucg_state = live_state

        if state.opnsense_cfg and state.unifi_cfg:
            merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
            state.reconciliation_report = merger.reconcile()

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "source": "ucg_max",
            "host": host,
            "version": live_state.version,
            "summary": live_state.raw_summary,
            "reconciliation": unifi_dict.get("reconciliation"),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error in fetch_ucg_live_api")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def fetch_uos_live_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        host = body.get("host", "192.168.1.5")
        username = body.get("username", "")
        password = body.get("password", "")
        api_key = body.get("api_key") or None
        port = int(body.get("port", 8443))
        site = body.get("site", "default")

        client = UniFiGatewayClient(
            host=host,
            username=username,
            password=password,
            api_key=api_key,
            site=site,
            port=port,
        )

        live_state = client.fetch_live_state(source_type="uos_server")
        state.uos_state = live_state

        if state.opnsense_cfg and state.unifi_cfg:
            merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
            state.reconciliation_report = merger.reconcile()

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "source": "uos_server",
            "host": host,
            "version": live_state.version,
            "summary": live_state.raw_summary,
            "wlans_count": len(live_state.wlans),
            "devices_count": len(live_state.devices),
            "wlans": unifi_dict.get("wlans", []),
            "reconciliation": unifi_dict.get("reconciliation"),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error in fetch_uos_live_api")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def reconcile_sources_api(request: Request) -> JSONResponse:
    try:
        if not state.opnsense_cfg or not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Bitte laden Sie zuerst die OPNsense XML-Konfiguration."}, status_code=400)

        merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
        report = merger.reconcile()
        state.reconciliation_report = report

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "reconciliation": unifi_dict.get("reconciliation"),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


async def upload_export_file_api(request: Request) -> JSONResponse:
    try:
        content_type = request.headers.get("content-type", "")
        file_bytes = b""
        filename = ""
        source_type = "generic"

        if "multipart/form-data" in content_type:
            form = await request.form()
            file_obj = form.get("file")
            source_type = str(form.get("source_type", "generic"))
            if file_obj:
                filename = getattr(file_obj, "filename", "export.bin")
                file_bytes = await file_obj.read()
        else:
            body = await request.json()
            source_type = str(body.get("source_type", "generic"))
            filename = str(body.get("filename", "export.json"))
            if "content" in body:
                file_bytes = body["content"].encode("utf-8")
            elif "base64" in body:
                import base64
                file_bytes = base64.b64decode(body["base64"])

        if not file_bytes:
            return JSONResponse({"success": False, "error": "Keine Dateidaten empfangen."}, status_code=400)

        export_parser = UniFiExportParser()

        if source_type == "opnsense" or (filename.lower().endswith(".xml") and source_type not in ("ucg_max", "uos_server")):
            if not filename.lower().endswith(".xml") and not file_bytes.strip().startswith(b"<"):
                return JSONResponse({
                    "success": False,
                    "error": f"Für die OPNsense-Quelle wird eine XML-Datei benötigt (z. B. config.xml). Hochgeladen wurde: {filename}"
                }, status_code=200)
            xml_text = file_bytes.decode("utf-8", errors="replace")
            state.raw_xml = xml_text
            state.opnsense_filename = filename
            parser = OPNsenseParser(xml_text)
            state.opnsense_cfg = parser.parse()
            state.vault = SanitizerVault(anonymize_macs=False)
            mapper = UniFiMapper(state.opnsense_cfg)
            state.unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)
            source_summary = {
                "source": "opnsense",
                "filename": filename,
                "interfaces_count": len(state.opnsense_cfg.interfaces),
                "leases_count": len(state.opnsense_cfg.static_leases),
                "rules_count": len(state.opnsense_cfg.filter_rules),
            }
        elif source_type == "ucg_max":
            ucg_st = export_parser.parse_bytes(file_bytes, filename=filename, source_type="ucg_max")
            state.ucg_state = ucg_st
            state.ucg_filename = filename
            source_summary = {
                "source": "ucg_max",
                "filename": filename,
                "summary": ucg_st.raw_summary,
            }
        elif source_type == "uos_server":
            uos_st = export_parser.parse_bytes(file_bytes, filename=filename, source_type="uos_server")
            state.uos_state = uos_st
            state.uos_filename = filename
            source_summary = {
                "source": "uos_server",
                "filename": filename,
                "summary": uos_st.raw_summary,
            }
        else:
            return JSONResponse({"success": False, "error": f"Unbekannter Quelltyp: {source_type}"}, status_code=200)

        # Automatically reconcile if OPNsense is loaded and either UCG or UOS export is present
        if state.opnsense_cfg and state.unifi_cfg and (state.ucg_state or state.uos_state):
            merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
            state.reconciliation_report = merger.reconcile()

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "source_info": source_summary,
            "sources_status": {
                "opnsense_loaded": state.opnsense_cfg is not None,
                "opnsense_file": state.opnsense_filename,
                "ucg_loaded": state.ucg_state is not None,
                "ucg_file": state.ucg_filename,
                "ucg_summary": state.ucg_state.raw_summary if state.ucg_state else {},
                "uos_loaded": state.uos_state is not None,
                "uos_file": state.uos_filename,
                "uos_summary": state.uos_state.raw_summary if state.uos_state else {},
            },
            "reconciliation": unifi_dict.get("reconciliation"),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error processing export file upload")
        return JSONResponse({"success": False, "error": f"Fehler bei der Verarbeitung von '{filename}': {str(e)}"}, status_code=200)


async def unify_all_api(request: Request) -> JSONResponse:
    try:
        if not state.opnsense_cfg or not state.unifi_cfg:
            return JSONResponse({
                "success": False,
                "error": "Bitte laden Sie zuerst die OPNsense XML-Konfiguration als Master-Quelle."
            }, status_code=200)

        # Fresh baseline from OPNsense
        mapper = UniFiMapper(state.opnsense_cfg)
        state.unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)

        # Merge with UCG-Max export and UOS Server export
        merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
        report = merger.reconcile()
        state.reconciliation_report = report

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "message": "Alle drei Konfigurationsquellen wurden erfolgreich zu einer einheitlichen UniFi-Konfiguration vereint!",
            "reconciliation": unifi_dict.get("reconciliation"),
            "unifi_mapped": unifi_dict,
            "summary": {
                "total_networks": len(unifi_dict.get("networks", [])),
                "total_wlans": len(unifi_dict.get("wlans", [])),
                "total_fixed_ips": len(unifi_dict.get("fixed_ips", [])),
                "total_rules": len(unifi_dict.get("firewall_rules", [])),
                "total_groups": len(unifi_dict.get("firewall_groups", [])),
                "sources_merged": {
                    "opnsense": state.opnsense_filename or "Geladen",
                    "ucg_max": state.ucg_filename or ("Live-Abfrage" if state.ucg_state else "Nicht vorhanden"),
                    "uos_server": state.uos_filename or ("Live-Abfrage" if state.uos_state else "Nicht vorhanden"),
                }
            }
        })
    except Exception as e:
        logger.exception("Error during 3-way consolidation")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def export_unified_json_api(request: Request) -> JSONResponse:
    if not state.unifi_cfg:
        return JSONResponse({"success": False, "error": "Keine vereinte Konfiguration vorhanden. Bitte zuerst Dateien laden."}, status_code=200)

    cfg_dict = get_unifi_config_dict()
    return JSONResponse(
        cfg_dict,
        headers={"Content-Disposition": "attachment; filename=unifi_unified_config.json"}
    )


async def update_network_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        idx = int(body.get("index", -1))
        net_data = body.get("network", {})
        cascade = bool(body.get("cascade", True))
        remap_clients = bool(body.get("remap_clients", True))
        remap_wlans = bool(body.get("remap_wlans", True))
        remap_rules = bool(body.get("remap_rules", True))

        if not state.unifi_cfg or idx < 0 or idx >= len(state.unifi_cfg.networks):
            return JSONResponse({"success": False, "error": "Ungültiger Netzwerk-Index."}, status_code=200)

        target = state.unifi_cfg.networks[idx]
        old_name = target.name
        old_vlan = target.vlan_id
        old_cidr = target.gateway_cidr

        new_name = str(net_data.get("name", target.name)).strip()
        vlan_id = int(net_data.get("vlan_id", target.vlan_id))
        gateway_cidr = str(net_data.get("gateway_cidr", target.gateway_cidr)).strip()
        dhcp_enabled = bool(net_data.get("dhcp_enabled", target.dhcp_enabled))
        dhcp_start = str(net_data.get("dhcp_start", getattr(target, "dhcp_start", ""))).strip()
        dhcp_stop = str(net_data.get("dhcp_stop", getattr(target, "dhcp_stop", ""))).strip()
        purpose = str(net_data.get("purpose", getattr(target, "purpose", "corporate"))).strip()
        domain_name = str(net_data.get("domain_name", getattr(target, "domain_name", "local"))).strip()

        if not new_name:
            return JSONResponse({"success": False, "error": "Netzwerkname darf nicht leer sein."}, status_code=200)
        if vlan_id < 1 or vlan_id > 4094:
            return JSONResponse({"success": False, "error": "VLAN ID muss zwischen 1 und 4094 liegen."}, status_code=200)
        if "/" not in gateway_cidr:
            return JSONResponse({"success": False, "error": "Gateway muss im CIDR-Format sein (z. B. 192.168.10.1/24)."}, status_code=200)

        if cascade and (old_vlan != vlan_id or old_cidr != gateway_cidr or old_name != new_name):
            remap_res = VlanRemapper.remap(
                state.unifi_cfg,
                source_vlan=old_vlan,
                target_vlan=vlan_id,
                source_cidr=old_cidr,
                target_cidr=gateway_cidr,
                target_name=new_name,
                remap_clients=remap_clients,
                remap_wlans=remap_wlans,
                remap_rules=remap_rules,
            )
            target = next((n for n in state.unifi_cfg.networks if n.vlan_id == vlan_id), target)
            target.dhcp_enabled = dhcp_enabled
            if dhcp_start:
                target.dhcp_start = dhcp_start
            if dhcp_stop:
                target.dhcp_stop = dhcp_stop
            target.purpose = purpose
            target.domain_name = domain_name

            if old_vlan != vlan_id:
                state.vlan_remaps.append({
                    "source_vlan": old_vlan,
                    "target_vlan": vlan_id,
                    "source_cidr": old_cidr,
                    "target_cidr": gateway_cidr,
                    "target_name": new_name,
                })

            if state.opnsense_cfg and (state.ucg_state or state.uos_state):
                merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
                state.reconciliation_report = merger.reconcile()

            msg = f"Netzwerk '{new_name}' (VLAN {vlan_id}) aktualisiert (Kaskadiert: {remap_res['clients_remapped']} Clients, {remap_res['wlans_remapped']} WLANs)."
        else:
            target.name = new_name
            target.vlan_id = vlan_id
            target.gateway_cidr = gateway_cidr
            target.dhcp_enabled = dhcp_enabled
            target.dhcp_start = dhcp_start
            target.dhcp_stop = dhcp_stop
            target.purpose = purpose
            target.domain_name = domain_name

            if old_name != new_name:
                for f in state.unifi_cfg.fixed_ips:
                    if f.network_name == old_name:
                        f.network_name = new_name
            msg = f"Netzwerk '{new_name}' (VLAN {vlan_id}) erfolgreich aktualisiert."

        return JSONResponse({
            "success": True,
            "message": msg,
            "reconciliation": get_unifi_config_dict().get("reconciliation"),
            "unifi_mapped": get_unifi_config_dict()
        })
    except Exception as e:
        logger.exception("Error updating network")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def remap_network_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Keine Konfiguration geladen."}, status_code=200)

        body = await request.json()
        source_vlan = int(body.get("source_vlan", body.get("source_vlan_id", 1)))
        target_vlan = int(body.get("target_vlan", body.get("new_vlan_id", source_vlan)))
        source_cidr = body.get("source_cidr")
        target_cidr = body.get("target_cidr", body.get("new_gateway_cidr"))
        target_name = body.get("target_name", body.get("new_name"))
        merge_target_vlan_id = body.get("merge_target_vlan_id")
        if merge_target_vlan_id is not None and str(merge_target_vlan_id).strip() != "":
            target_vlan = int(merge_target_vlan_id)
        remap_clients = bool(body.get("remap_clients", True))
        remap_wlans = bool(body.get("remap_wlans", True))
        remap_rules = bool(body.get("remap_rules", True))

        remap_result = VlanRemapper.remap(
            state.unifi_cfg,
            source_vlan=source_vlan,
            target_vlan=target_vlan,
            source_cidr=source_cidr,
            target_cidr=target_cidr,
            target_name=target_name,
            remap_clients=remap_clients,
            remap_wlans=remap_wlans,
            remap_rules=remap_rules,
        )

        if not remap_result["success"]:
            return JSONResponse({"success": False, "error": remap_result.get("error", "Remapping fehlgeschlagen.")}, status_code=200)

        remap_entry = {
            "source_vlan": source_vlan,
            "target_vlan": target_vlan,
            "source_cidr": source_cidr,
            "target_cidr": target_cidr,
            "target_name": target_name,
        }
        existing_rule_idx = next((i for i, r in enumerate(state.vlan_remaps) if r.get("source_vlan") == source_vlan), None)
        if existing_rule_idx is not None:
            state.vlan_remaps[existing_rule_idx] = remap_entry
        else:
            state.vlan_remaps.append(remap_entry)

        if state.opnsense_cfg and (state.ucg_state or state.uos_state):
            merger = MultiSourceMerger(state.opnsense_cfg, state.unifi_cfg, state.ucg_state, state.uos_state, vlan_remaps=state.vlan_remaps)
            state.reconciliation_report = merger.reconcile()

        unifi_dict = get_unifi_config_dict()
        msg = f"VLAN {source_vlan} erfolgreich auf VLAN {target_vlan} migriert: {remap_result['clients_remapped']} Client-IPs, {remap_result['wlans_remapped']} WLANs und {remap_result['rules_remapped']} Firewall-Regeln angepasst."
        return JSONResponse({
            "success": True,
            "message": msg,
            "remap_result": remap_result,
            "reconciliation": unifi_dict.get("reconciliation"),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error in remap_network_api")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def remap_preview_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Keine Konfiguration geladen."}, status_code=200)

        body = await request.json()
        source_vlan = int(body.get("source_vlan", body.get("source_vlan_id", 1)))
        target_vlan = int(body.get("target_vlan", body.get("new_vlan_id", source_vlan)))
        source_cidr = body.get("source_cidr", "")
        target_cidr = body.get("target_cidr", body.get("new_gateway_cidr", ""))

        source_net = next((n for n in state.unifi_cfg.networks if n.vlan_id == source_vlan), None)
        if not source_net and source_cidr:
            clean_sc = source_cidr.split("/")[0]
            source_net = next((n for n in state.unifi_cfg.networks if clean_sc in n.gateway_cidr), None)

        if not source_net:
            return JSONResponse({"success": False, "error": f"VLAN {source_vlan} nicht gefunden."}, status_code=200)

        actual_src_cidr = source_cidr or source_net.gateway_cidr
        actual_tgt_cidr = target_cidr or actual_src_cidr

        affected_clients = []
        for f in state.unifi_cfg.fixed_ips:
            if actual_src_cidr != actual_tgt_cidr:
                new_ip = remap_ip_address(f.fixed_ip, actual_src_cidr, actual_tgt_cidr)
                if new_ip != f.fixed_ip:
                    affected_clients.append({
                        "name": f.name,
                        "mac": f.mac,
                        "old_ip": f.fixed_ip,
                        "new_ip": new_ip,
                    })

        affected_wlans = []
        for w in getattr(state.unifi_cfg, "wlans", []):
            if w.vlan_id == source_vlan:
                affected_wlans.append({
                    "name": w.name,
                    "old_vlan": source_vlan,
                    "new_vlan": target_vlan,
                })

        affected_rules = []
        if actual_src_cidr != actual_tgt_cidr:
            for r in getattr(state.unifi_cfg, "firewall_rules", []):
                old_src = r.src_address or ""
                old_dst = r.dst_address or ""
                new_src = remap_ip_address(old_src, actual_src_cidr, actual_tgt_cidr) if old_src else ""
                new_dst = remap_ip_address(old_dst, actual_src_cidr, actual_tgt_cidr) if old_dst else ""
                if (new_src and new_src != old_src) or (new_dst and new_dst != old_dst):
                    affected_rules.append({
                        "name": r.name,
                        "old_src": old_src,
                        "new_src": new_src,
                    })

        summary_text = f"Migration von {source_net.name} (VLAN {source_vlan}, {actual_src_cidr}) ➔ VLAN {target_vlan} ({actual_tgt_cidr})"
        return JSONResponse({
            "success": True,
            "preview": {
                "source_vlan": source_vlan,
                "target_vlan": target_vlan,
                "source_network_name": source_net.name,
                "source_cidr": actual_src_cidr,
                "target_cidr": actual_tgt_cidr,
                "summary": summary_text,
                "clients_count": len(affected_clients),
                "wlans_count": len(affected_wlans),
                "rules_count": len(affected_rules),
                "client_diffs": affected_clients,
                "wlan_diffs": affected_wlans,
                "affected_clients": affected_clients,
                "affected_wlans": affected_wlans,
                "affected_rules_count": len(affected_rules),
            }
        })
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def update_wlan_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Keine Konfiguration geladen."}, status_code=200)

        body = await request.json()
        idx = int(body.get("index", -1))
        wlan_data = body.get("wlan", {})

        wlans = getattr(state.unifi_cfg, "wlans", [])
        if idx < 0 or idx >= len(wlans):
            return JSONResponse({"success": False, "error": "Ungültiger WLAN-Index."}, status_code=200)

        target_wlan = wlans[idx]
        name = str(wlan_data.get("name", target_wlan.name)).strip()
        vlan_val = wlan_data.get("vlan_id")
        if vlan_val is not None and str(vlan_val).strip() != "" and str(vlan_val).lower() != "null":
            vlan_id = int(vlan_val)
        else:
            vlan_id = None

        security = str(wlan_data.get("security", target_wlan.security)).strip()
        x_passphrase = str(wlan_data.get("x_passphrase", getattr(target_wlan, "x_passphrase", ""))).strip()
        is_guest = bool(wlan_data.get("is_guest", target_wlan.is_guest))
        enabled = bool(wlan_data.get("enabled", target_wlan.enabled))

        if not name:
            return JSONResponse({"success": False, "error": "WLAN-Name darf nicht leer sein."}, status_code=200)

        target_wlan.name = name
        target_wlan.vlan_id = vlan_id
        target_wlan.security = security
        target_wlan.x_passphrase = x_passphrase
        target_wlan.is_guest = is_guest
        target_wlan.enabled = enabled

        if state.uos_state and state.uos_state.wlans:
            for uw in state.uos_state.wlans:
                if uw.name == name or uw.name == target_wlan.name:
                    uw.vlan_id = vlan_id
                    uw.security = security
                    uw.x_passphrase = x_passphrase
                    uw.is_guest = is_guest

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "message": f"WLAN '{name}' (VLAN {vlan_id if vlan_id else 'Untagged'}) erfolgreich aktualisiert.",
            "wlans": unifi_dict.get("wlans", []),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error in update_wlan_api")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def add_wlan_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Keine Konfiguration geladen."}, status_code=200)

        body = await request.json()
        wlan_data = body.get("wlan", {})
        name = str(wlan_data.get("name", "")).strip()
        vlan_val = wlan_data.get("vlan_id")
        if vlan_val is not None and str(vlan_val).strip() != "" and str(vlan_val).lower() != "null":
            vlan_id = int(vlan_val)
        else:
            vlan_id = None

        security = str(wlan_data.get("security", "wpapsk")).strip()
        x_passphrase = str(wlan_data.get("x_passphrase", "")).strip()
        is_guest = bool(wlan_data.get("is_guest", False))
        enabled = bool(wlan_data.get("enabled", True))

        if not name:
            return JSONResponse({"success": False, "error": "WLAN-Name darf nicht leer sein."}, status_code=200)

        new_wlan = UniFiWlan(
            name=name,
            vlan_id=vlan_id,
            security=security,
            x_passphrase=x_passphrase,
            is_guest=is_guest,
            enabled=enabled,
        )
        if not hasattr(state.unifi_cfg, "wlans"):
            state.unifi_cfg.wlans = []
        state.unifi_cfg.wlans.append(new_wlan)

        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "message": f"Neues WLAN '{name}' angelegt.",
            "wlans": unifi_dict.get("wlans", []),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error in add_wlan_api")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def delete_wlan_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Keine Konfiguration geladen."}, status_code=200)

        body = await request.json()
        idx = int(body.get("index", -1))
        wlans = getattr(state.unifi_cfg, "wlans", [])
        if idx < 0 or idx >= len(wlans):
            return JSONResponse({"success": False, "error": "Ungültiger WLAN-Index."}, status_code=200)

        removed = wlans.pop(idx)
        unifi_dict = get_unifi_config_dict()
        return JSONResponse({
            "success": True,
            "message": f"WLAN '{removed.name}' gelöscht.",
            "wlans": unifi_dict.get("wlans", []),
            "unifi_mapped": unifi_dict,
        })
    except Exception as e:
        logger.exception("Error in delete_wlan_api")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def add_network_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Bitte laden Sie zuerst eine Konfiguration."}, status_code=200)
        body = await request.json()
        net_data = body.get("network", {})
        name = str(net_data.get("name", "")).strip()
        vlan_id = int(net_data.get("vlan_id", 1))
        gateway_cidr = str(net_data.get("gateway_cidr", "192.168.1.1/24")).strip()
        dhcp_enabled = bool(net_data.get("dhcp_enabled", True))
        dhcp_start = str(net_data.get("dhcp_start", "")).strip()
        dhcp_stop = str(net_data.get("dhcp_stop", "")).strip()
        purpose = str(net_data.get("purpose", "corporate")).strip()
        domain_name = str(net_data.get("domain_name", "local")).strip()

        if not name:
            return JSONResponse({"success": False, "error": "Netzwerkname darf nicht leer sein."}, status_code=200)
        if any(n.vlan_id == vlan_id for n in state.unifi_cfg.networks):
            return JSONResponse({"success": False, "error": f"Ein Netzwerk mit VLAN ID {vlan_id} existiert bereits."}, status_code=200)

        new_net = UniFiNetwork(
            name=name,
            vlan_id=vlan_id,
            gateway_cidr=gateway_cidr,
            purpose=purpose,
            dhcp_enabled=dhcp_enabled,
            dhcp_start=dhcp_start,
            dhcp_stop=dhcp_stop,
            domain_name=domain_name,
        )
        state.unifi_cfg.networks.append(new_net)
        return JSONResponse({
            "success": True,
            "message": f"Netzwerk '{name}' (VLAN {vlan_id}) hinzugefügt.",
            "unifi_mapped": get_unifi_config_dict()
        })
    except Exception as e:
        logger.exception("Error adding network")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def delete_network_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        idx = int(body.get("index", -1))
        if not state.unifi_cfg or idx < 0 or idx >= len(state.unifi_cfg.networks):
            return JSONResponse({"success": False, "error": "Ungültiger Netzwerk-Index."}, status_code=200)
        deleted = state.unifi_cfg.networks.pop(idx)
        return JSONResponse({
            "success": True,
            "message": f"Netzwerk '{deleted.name}' gelöscht.",
            "unifi_mapped": get_unifi_config_dict()
        })
    except Exception as e:
        logger.exception("Error deleting network")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def update_fixed_ip_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        idx = int(body.get("index", -1))
        f_data = body.get("fixed_ip", {})
        if not state.unifi_cfg or idx < 0 or idx >= len(state.unifi_cfg.fixed_ips):
            return JSONResponse({"success": False, "error": "Ungültiger Index für feste IP."}, status_code=200)

        target = state.unifi_cfg.fixed_ips[idx]
        mac = str(f_data.get("mac", target.mac)).strip().lower()
        name = str(f_data.get("name", target.name)).strip()
        fixed_ip = str(f_data.get("fixed_ip", target.fixed_ip)).strip()
        network_name = str(f_data.get("network_name", target.network_name)).strip()

        if not mac:
            return JSONResponse({"success": False, "error": "MAC-Adresse darf nicht leer sein."}, status_code=200)
        if not fixed_ip:
            return JSONResponse({"success": False, "error": "IP-Adresse darf nicht leer sein."}, status_code=200)

        target.mac = mac
        target.name = name or "Gerät"
        target.fixed_ip = fixed_ip
        target.network_name = network_name

        return JSONResponse({
            "success": True,
            "message": f"Feste IP für '{target.name}' ({fixed_ip}) erfolgreich aktualisiert.",
            "unifi_mapped": get_unifi_config_dict()
        })
    except Exception as e:
        logger.exception("Error updating fixed IP")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def add_fixed_ip_api(request: Request) -> JSONResponse:
    try:
        if not state.unifi_cfg:
            return JSONResponse({"success": False, "error": "Bitte laden Sie zuerst eine Konfiguration."}, status_code=200)
        body = await request.json()
        f_data = body.get("fixed_ip", {})
        mac = str(f_data.get("mac", "")).strip().lower()
        name = str(f_data.get("name", "Neues Gerät")).strip()
        fixed_ip = str(f_data.get("fixed_ip", "")).strip()
        network_name = str(f_data.get("network_name", "")).strip()

        if not mac or not fixed_ip:
            return JSONResponse({"success": False, "error": "MAC-Adresse und IP-Adresse sind erforderlich."}, status_code=200)

        new_fip = UniFiFixedIp(
            mac=mac,
            name=name,
            fixed_ip=fixed_ip,
            network_name=network_name or (state.unifi_cfg.networks[0].name if state.unifi_cfg.networks else "Default")
        )
        state.unifi_cfg.fixed_ips.append(new_fip)
        return JSONResponse({
            "success": True,
            "message": f"Feste IP für '{name}' ({fixed_ip}) hinzugefügt.",
            "unifi_mapped": get_unifi_config_dict()
        })
    except Exception as e:
        logger.exception("Error adding fixed IP")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


async def delete_fixed_ip_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        idx = int(body.get("index", -1))
        if not state.unifi_cfg or idx < 0 or idx >= len(state.unifi_cfg.fixed_ips):
            return JSONResponse({"success": False, "error": "Ungültiger Index."}, status_code=200)
        deleted = state.unifi_cfg.fixed_ips.pop(idx)
        return JSONResponse({
            "success": True,
            "message": f"Feste IP für '{deleted.name}' gelöscht.",
            "unifi_mapped": get_unifi_config_dict()
        })
    except Exception as e:
        logger.exception("Error deleting fixed IP")
        return JSONResponse({"success": False, "error": str(e)}, status_code=200)


routes = [
    Route("/", endpoint=index_view, methods=["GET"]),
    Route("/api/load-sample", endpoint=load_sample_api, methods=["POST"]),
    Route("/api/upload-xml", endpoint=upload_xml_api, methods=["POST"]),
    Route("/api/sanitize", endpoint=sanitize_api, methods=["POST"]),
    Route("/api/generate-prompt", endpoint=generate_prompt_api, methods=["POST"]),
    Route("/api/run-llm", endpoint=run_llm_api, methods=["POST"]),
    Route("/api/apply-offline-llm", endpoint=apply_offline_llm_api, methods=["POST"]),
    Route("/api/test-connection", endpoint=test_connection_api, methods=["POST"]),
    Route("/api/dry-run", endpoint=dry_run_api, methods=["POST"]),
    Route("/api/deploy", endpoint=deploy_api, methods=["POST"]),
    Route("/api/export-unifi-json", endpoint=export_json_api, methods=["GET"]),
    Route("/api/rules/toggle-status", endpoint=toggle_rule_status_api, methods=["POST"]),
    Route("/api/rules/update", endpoint=update_rule_api, methods=["POST"]),
    Route("/api/rules/bulk-status", endpoint=bulk_rule_status_api, methods=["POST"]),
    Route("/api/rules/llm-assist", endpoint=llm_assist_rule_api, methods=["POST"]),
    Route("/api/rules/apply-llm-suggestion", endpoint=apply_llm_suggestion_api, methods=["POST"]),
    Route("/api/sources/fetch-opnsense", endpoint=fetch_opnsense_live_api, methods=["POST"]),
    Route("/api/sources/fetch-ucg", endpoint=fetch_ucg_live_api, methods=["POST"]),
    Route("/api/sources/fetch-uos", endpoint=fetch_uos_live_api, methods=["POST"]),
    Route("/api/sources/reconcile", endpoint=reconcile_sources_api, methods=["POST"]),
    Route("/api/sources/upload-export", endpoint=upload_export_file_api, methods=["POST"]),
    Route("/api/sources/unify-all", endpoint=unify_all_api, methods=["POST"]),
    Route("/api/sources/export-unified-json", endpoint=export_unified_json_api, methods=["GET"]),
    Route("/api/networks/update", endpoint=update_network_api, methods=["POST"]),
    Route("/api/networks/add", endpoint=add_network_api, methods=["POST"]),
    Route("/api/networks/delete", endpoint=delete_network_api, methods=["POST"]),
    Route("/api/networks/remap", endpoint=remap_network_api, methods=["POST"]),
    Route("/api/networks/remap-preview", endpoint=remap_preview_api, methods=["POST"]),
    Route("/api/wlans/update", endpoint=update_wlan_api, methods=["POST"]),
    Route("/api/wlans/add", endpoint=add_wlan_api, methods=["POST"]),
    Route("/api/wlans/delete", endpoint=delete_wlan_api, methods=["POST"]),
    Route("/api/fixed-ips/update", endpoint=update_fixed_ip_api, methods=["POST"]),
    Route("/api/fixed-ips/add", endpoint=add_fixed_ip_api, methods=["POST"]),
    Route("/api/fixed-ips/delete", endpoint=delete_fixed_ip_api, methods=["POST"]),
]

app = Starlette(debug=True, routes=routes)


