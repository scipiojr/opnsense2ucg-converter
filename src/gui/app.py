"""
Starlette-based Web Application & API backend for OPNsense-to-UniFi Migrator.
Provides interactive REST endpoints for upload, sanitization, LLM prompting, review, and deployment.
"""

import json
import os
from typing import Dict, Any, Optional

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

from src.models import OPNsenseConfig, UniFiTargetConfig
from src.opnsense.parser import OPNsenseParser
from src.sanitizer.masker import SanitizerVault
from src.translator.mapper import UniFiMapper
from src.llm.engine import LLMTranslationEngine
from src.unifi.client import UniFiGatewayClient


# Global Session State
class SessionState:
    raw_xml: str = ""
    opnsense_cfg: Optional[OPNsenseConfig] = None
    vault: SanitizerVault = SanitizerVault()
    unifi_cfg: Optional[UniFiTargetConfig] = None
    llm_explanation: str = ""
    llm_recommendations: list = []


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


async def process_xml(xml_content: str) -> JSONResponse:
    state.raw_xml = xml_content
    parser = OPNsenseParser(xml_content)
    state.opnsense_cfg = parser.parse()

    # Reset Vault & Mapper
    state.vault = SanitizerVault(anonymize_macs=False)
    mapper = UniFiMapper(state.opnsense_cfg)
    state.unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)

    return JSONResponse({
        "success": True,
        "summary": {
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
        },
        "unifi_mapped": get_unifi_config_dict(),
    })


def get_unifi_config_dict() -> Dict[str, Any]:
    if not state.unifi_cfg:
        return {}
    return {
        "networks": [
            {
                "name": n.name,
                "vlan_id": n.vlan_id,
                "gateway_cidr": n.gateway_cidr,
                "dhcp_enabled": n.dhcp_enabled,
                "dhcp_range": f"{n.dhcp_start} - {n.dhcp_stop}" if n.dhcp_enabled else "Static",
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
]

app = Starlette(debug=True, routes=routes)
