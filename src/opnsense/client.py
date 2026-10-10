"""
OPNsense REST API & Web GUI Client.
Supports live fetching of configuration backup (config.xml) via:
1. OPNsense REST API Key & Secret (HTTP Basic Auth on /api/core/backup/download/this)
2. Alternative API endpoint (/api/backup/backup/download)
3. Web GUI Session Login (form login on /index.php with CSRF handling and cookie session)
"""

import logging
import re
import urllib3
import requests
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class OPNsenseClient:
    def __init__(
        self,
        host: str,
        port: int = 443,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        protocol: str = "https",
        verify_ssl: bool = False,
        timeout: int = 15,
    ):
        self.host = host.replace("http://", "").replace("https://", "").rstrip("/")
        if ":" in self.host:
            parts = self.host.split(":")
            self.host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        self.port = port
        self.protocol = protocol
        self.api_key = (api_key or "").strip()
        self.api_secret = (api_secret or "").strip()
        self.username = (username or "").strip()
        self.password = (password or "").strip()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()

    @property
    def base_url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    def fetch_config_xml(self) -> str:
        """
        Fetches config.xml from the OPNsense firewall.
        Tries API Key/Secret first, then falls back to user/pass or session login.
        """
        errors = []

        # 1. Try API Key & Secret (or username/password as basic auth)
        auth_pairs = []
        if self.api_key and self.api_secret:
            auth_pairs.append((self.api_key, self.api_secret, "API-Key & Secret"))
        if self.username and self.password:
            auth_pairs.append((self.username, self.password, "Benutzername & Passwort (Basic Auth)"))

        for auth_user, auth_pass, label in auth_pairs:
            for endpoint in ["/api/core/backup/download/this", "/api/backup/backup/download"]:
                url = f"{self.base_url}{endpoint}"
                try:
                    logger.info("Attempting OPNsense API fetch on %s using %s", url, label)
                    resp = self.session.get(
                        url,
                        auth=(auth_user, auth_pass),
                        verify=self.verify_ssl,
                        timeout=self.timeout,
                    )
                    if resp.status_code == 200:
                        content = resp.text
                        if self._is_valid_opnsense_xml(content):
                            logger.info("Successfully fetched OPNsense config.xml via %s (%s)", endpoint, label)
                            return content
                        else:
                            preview = resp.text[:120].replace("\n", " ").strip()
                            errors.append(f"{label} ({endpoint}): Antwort ist kein gültiges XML ({preview}...)")
                    elif resp.status_code == 401:
                        errors.append(f"{label} ({endpoint}): HTTP 401 Unauthorized - Bitte API-Key und API-Secret in OPNsense prüfen.")
                    elif resp.status_code == 403:
                        errors.append(f"{label} ({endpoint}): HTTP 403 Forbidden - Benutzer hat keine Berechtigung für Backup-Download.")
                    elif resp.status_code == 404:
                        errors.append(f"{label} ({endpoint}): HTTP 404 Nicht gefunden.")
                    else:
                        errors.append(f"{label} ({endpoint}): HTTP {resp.status_code}")
                except Exception as exc:
                    errors.append(f"{label} ({endpoint}): {str(exc)}")

        # 2. Try Web GUI Session Login (if username and password provided)
        if self.username and self.password:
            try:
                xml = self._fetch_via_web_gui_session()
                if xml:
                    return xml
            except Exception as exc:
                errors.append(f"Web GUI Session Login: {str(exc)}")

        err_msg = "; ".join(errors) if errors else "Keine Zugangsdaten angegeben (weder API-Key/Secret noch Benutzer/Passwort)."
        raise ConnectionError(
            f"Konnte OPNsense Konfiguration von {self.base_url} nicht abrufen: {err_msg}"
        )

    def _is_valid_opnsense_xml(self, content: str) -> bool:
        if not content or not isinstance(content, str):
            return False
        content_lower = content.lower()
        return ("<opnsense" in content_lower or "<pfsense" in content_lower) and ("<interfaces" in content_lower or "<system" in content_lower)

    def _fetch_via_web_gui_session(self) -> Optional[str]:
        """
        Attempts to authenticate to OPNsense web GUI via form login and download backup.
        """
        login_url = f"{self.base_url}/index.php"
        logger.info("Attempting OPNsense web GUI login on %s", login_url)
        resp = self.session.get(login_url, verify=self.verify_ssl, timeout=self.timeout)
        if resp.status_code != 200:
            return None

        # Extract CSRF token if present
        csrf_token = None
        m = re.search(r'name=["\'](?:csrf_token|__csrf_magic)["\']\s+value=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        if m:
            csrf_token = m.group(1)
        elif "csrf_token" in self.session.cookies:
            csrf_token = self.session.cookies.get("csrf_token")

        login_data = {
            "usernamefld": self.username,
            "passwordfld": self.password,
            "login": "Login",
        }
        if csrf_token:
            login_data["csrf_token"] = csrf_token

        post_resp = self.session.post(login_url, data=login_data, verify=self.verify_ssl, timeout=self.timeout)
        if post_resp.status_code not in (200, 302):
            return None

        for endpoint in ["/api/core/backup/download/this", "/system_backup.php?action=download"]:
            dl_url = f"{self.base_url}{endpoint}"
            dl_resp = self.session.get(dl_url, verify=self.verify_ssl, timeout=self.timeout)
            if dl_resp.status_code == 200 and self._is_valid_opnsense_xml(dl_resp.text):
                return dl_resp.text

        return None
