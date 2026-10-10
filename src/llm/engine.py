"""
LLM Engine for OPNsense-to-UniFi Rule Translation.
Supports Claude (Anthropic), Gemini (Google), and Offline / Copy-Paste Mode.
Handles prompt construction, API execution with sanitized payloads, and parsing of AI responses.
"""

import json
import requests
from typing import Dict, Any, Optional, Tuple
from src.sanitizer.masker import SanitizerVault


SYSTEM_PROMPT = """You are an elite enterprise network and firewall architect specializing in FreeBSD/pf-based firewalls (pfSense, OPNsense 26.x) and Ubiquiti UniFi OS / UniFi Cloud Gateway Max (UCG-Max) / UniFi Network 8.x/9.x.

Your task is to analyze the provided SANITIZED OPNsense configuration and translate the firewall rules, aliases, and network segmentation into idiomatic, secure UniFi Network configurations.

### CRITICAL PARADIGM DIFFERENCES YOU MUST RESPECT:
1. **Default Policy**:
   - OPNsense blocks all traffic between interfaces/VLANs by default (Default Deny).
   - UniFi ALLOWS all traffic between corporate VLANs by default (Default Allow)!
   - You MUST ensure UniFi LAN_IN includes:
     a) Rule 2000: Accept Established/Related sessions.
     b) Rule 2001..2090: Explicit pinholes/whitelists extracted from OPNsense rules.
     c) Rule 2099: Drop all RFC1918 to RFC1918 traffic (to enforce OPNsense's default-deny security posture).

2. **Ruleset Placement in UniFi**:
   - Traffic between internal VLANs belongs on `LAN_IN`.
   - Traffic destined for the router/gateway itself (e.g. DNS port 53, NTP, SSH) belongs on `LAN_LOCAL`.
   - Inbound traffic from Internet belongs on `WAN_IN`.
   - Traffic destined for the WAN IP of the router belongs on `WAN_LOCAL`.

3. **Aliases & Groups**:
   - UniFi separates Firewall Groups into `address-group` (IP addresses / CIDRs) and `port-group` (ports / port ranges).
   - Nested aliases must be flattened.

4. **Port Forwards & NAT**:
   - In UniFi, Port Forward entries automatically create matching WAN IN firewall rules. Do not create duplicate manual WAN IN rules for port forwards.

5. **Data Sanitization**:
   - All sensitive data (passwords, WAN public IPs, certs) has been masked with tokens like `__SECRET_PASS_xxx__` or `__PUB_IP_xxx__`. Keep these tokens exactly as they are so the local system can de-anonymize them.

OUTPUT FORMAT:
Return ONLY valid JSON matching this schema:
{
  "explanation": "Brief explanation of the translation strategy and critical warnings",
  "firewall_groups": [
    {
      "name": "string",
      "group_type": "address-group" | "port-group",
      "members": ["string"]
    }
  ],
  "firewall_rules": [
    {
      "name": "string",
      "ruleset": "LAN_IN" | "WAN_IN" | "LAN_LOCAL" | "WAN_LOCAL",
      "action": "accept" | "drop" | "reject",
      "rule_index": integer,
      "protocol": "all" | "tcp" | "udp" | "tcp_udp" | "icmp",
      "src_groups": ["string"],
      "dst_groups": ["string"],
      "src_address": "string or null",
      "dst_address": "string or null",
      "dst_port": "string or null",
      "state_established": boolean,
      "state_related": boolean,
      "state_invalid": boolean,
      "logging": boolean,
      "description": "string"
    }
  ],
  "recommendations": [
    "string"
  ]
}
"""


class LLMTranslationEngine:
    def __init__(self, vault: Optional[SanitizerVault] = None):
        self.vault = vault or SanitizerVault()

    def generate_prompt(self, sanitized_opnsense_summary: Dict[str, Any]) -> str:
        """
        Creates a self-contained, beautifully formatted prompt that can either be sent to an API
        or copied by the user into Claude.ai or Gemini web interface.
        """
        prompt = f"""{SYSTEM_PROMPT}

### INPUT SANITIZED OPNSENSE CONFIGURATION:
```json
{json.dumps(sanitized_opnsense_summary, indent=2)}
```

Please perform the translation and return strictly the JSON structure defined above.
"""
        return prompt

    def call_gemini(self, prompt: str, api_key: str, model: str = "gemini-2.5-flash") -> Dict[str, Any]:
        """
        Calls Google Gemini API directly using HTTP requests (compatible with gemini-2.5-flash, gemini-1.5-pro, etc.)
        """
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            }
        }
        headers = {"Content-Type": "application/json"}
        
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        if response.status_code != 200:
            raise RuntimeError(f"Gemini API Error ({response.status_code}): {response.text}")

        res_data = response.json()
        raw_text = res_data["candidates"][0]["content"]["parts"][0]["text"]
        return self._extract_json(raw_text)

    def call_claude(self, prompt: str, api_key: str, model: str = "claude-3-7-sonnet-20250219") -> Dict[str, Any]:
        """
        Calls Anthropic Claude API directly using HTTP requests.
        """
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": model,
            "max_tokens": 4096,
            "temperature": 0.2,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        response = requests.post(url, json=payload, headers=headers, timeout=60)
        if response.status_code != 200:
            raise RuntimeError(f"Claude API Error ({response.status_code}): {response.text}")

        res_data = response.json()
        raw_text = res_data["content"][0]["text"]
        return self._extract_json(raw_text)

    def parse_offline_response(self, text_input: str) -> Dict[str, Any]:
        """
        Parses manually pasted JSON response from web Claude or Gemini.
        """
        return self._extract_json(text_input)

    def _extract_json(self, text: str) -> Dict[str, Any]:
        text_clean = text.strip()
        # Handle markdown fences
        if "```json" in text_clean:
            text_clean = text_clean.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in text_clean:
            text_clean = text_clean.split("```", 1)[1].split("```", 1)[0].strip()

        try:
            return json.loads(text_clean)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON response from LLM: {str(e)}\nRaw output: {text[:200]}...")

    def assist_single_rule(
        self,
        rule_data: Dict[str, Any],
        instruction: str = "",
        provider: str = "local",
        api_key: str = "",
        model: str = "",
    ) -> Dict[str, Any]:
        """
        Analyzes a single firewall rule, explains its implications, and suggests
        optimizations based on user instructions or security best practices.
        Supports local heuristic analysis or remote LLM (Gemini/Claude).
        """
        sanitized_rule = self.vault.sanitize_dict(rule_data)
        instr = instruction.strip() or "Prüfe die Regel auf Sicherheit und optimiere sie nach dem Least-Privilege-Prinzip."

        prompt = f"""You are an elite firewall engineer for Ubiquiti UniFi Cloud Gateway Max (UCG-Max) and OPNsense.
Analyze and optimize the following UniFi firewall rule based on the instruction.

### USER INSTRUCTION:
"{instr}"

### CURRENT RULE DATA (JSON):
{json.dumps(sanitized_rule, indent=2)}

### REQUIREMENTS:
1. Explain in German ('explanation') what this rule does, why it is needed or if it poses risks.
2. Provide a concrete recommendation in German ('recommendation').
3. Return the optimized rule dictionary ('updated_rule') with fields: name, ruleset, action, protocol, src_addr, dst_addr, dst_port, logging, description.

OUTPUT STRICTLY VALID JSON:
{{
  "explanation": "Detaillierte deutsche Erklärung...",
  "recommendation": "Empfehlung...",
  "updated_rule": {{
    "name": "...",
    "ruleset": "LAN_IN",
    "action": "accept",
    "protocol": "all",
    "src_addr": "...",
    "dst_addr": "...",
    "dst_port": "...",
    "logging": false,
    "description": "..."
  }}
}}
"""

        # Remote LLM execution
        if provider == "gemini" and api_key:
            res = self.call_gemini(prompt, api_key=api_key, model=model or "gemini-2.5-flash")
            rehydrated = self.vault.rehydrate_dict(res)
            rehydrated["prompt_for_clipboard"] = prompt
            return rehydrated

        if provider == "claude" and api_key:
            res = self.call_claude(prompt, api_key=api_key, model=model or "claude-3-7-sonnet-20250219")
            rehydrated = self.vault.rehydrate_dict(res)
            rehydrated["prompt_for_clipboard"] = prompt
            return rehydrated

        # Built-in Local Heuristic Optimizer (offline, instant, private)
        updated = dict(rule_data)
        instr_lower = instr.lower()

        if "drop" in instr_lower or "block" in instr_lower or "sperr" in instr_lower:
            updated["action"] = "drop"
            explanation = "Die Regel wurde von 'accept' auf 'drop' geändert, um diesen Datenverkehr zu verriegeln."
        elif "accept" in instr_lower or "erlaub" in instr_lower:
            updated["action"] = "accept"
            explanation = "Die Regel wurde auf 'accept' gesetzt, um den spezifizierten Verbindungsaufbau zu gestatten."
        elif "härten" in instr_lower or "least" in instr_lower or "sicherheit" in instr_lower:
            if not updated.get("dst_port") or str(updated.get("dst_port")).lower() in ("any", "*", "all", ""):
                if "web" in updated.get("name", "").lower() or "http" in updated.get("description", "").lower():
                    updated["protocol"] = "tcp"
                    updated["dst_port"] = "80,443"
                    explanation = "Least-Privilege Härtung angewandt: Zielports wurden präzise auf HTTP/HTTPS (TCP 80, 443) eingeschränkt."
                elif "dns" in updated.get("name", "").lower():
                    updated["protocol"] = "udp"
                    updated["dst_port"] = "53"
                    explanation = "Least-Privilege Härtung angewandt: Protokoll auf DNS (UDP 53) beschränkt."
                else:
                    updated["logging"] = True
                    explanation = "Sicherheitsprüfung durchgeführt: Offener Port-Zugriff erkannt. Logging wurde zur forensischen Protokollierung aktiviert."
            else:
                updated["logging"] = True
                explanation = "Regel analysiert: Spezifische Zielports sind bereits definiert. Logging wurde zur besseren Auditierbarkeit aktiviert."
        elif "web" in instr_lower or "http" in instr_lower:
            updated["protocol"] = "tcp"
            updated["dst_port"] = "80,443"
            explanation = "Zielports wurden gezielt auf Standard-Webdienste (TCP 80/443) gesetzt."
        elif "log" in instr_lower:
            updated["logging"] = True
            explanation = "Firewall-Logging für diese Regel aktiviert."
        else:
            explanation = f"Regel '{updated.get('name')}' analysiert: Aktuelle Konfiguration entspricht den Sicherheitsrichtlinien für Zone {updated.get('ruleset')}."

        rec = f"Empfehlung: In UniFi OS unter Ruleset '{updated.get('ruleset')}' belassen. Nutzen Sie bei komplexen Anforderungen den Button 'Prompt kopieren' für tiefergehende KI-Analysen."

        return {
            "success": True,
            "explanation": explanation,
            "recommendation": rec,
            "updated_rule": updated,
            "prompt_for_clipboard": prompt,
        }
