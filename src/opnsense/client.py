"""
OPNsense REST API & Web GUI Client.
Supports live fetching of configuration backup (config.xml) via:
1. Web GUI Session Login (form login on /index.php with cookie & CSRF handling -> download via /diag_backup.php)
2. OPNsense REST API Key & Secret (HTTP Basic Auth on /api/core/backup/download/this)
3. Alternative Core API endpoints (/api/backup/backup/download)
"""

import logging
import re
from typing import Optional
import urllib3
import requests

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
        auth_mode: str = "auto",
        protocol: str = "https",
        verify_ssl: bool = False,
        timeout: int = 15,
    ):
        clean_host = (host or "").strip()
        if clean_host.startswith("http://"):
            protocol = "http"
            clean_host = clean_host[7:]
        elif clean_host.startswith("https://"):
            protocol = "https"
            clean_host = clean_host[8:]

        clean_host = clean_host.rstrip("/")
        if ":" in clean_host:
            parts = clean_host.split(":")
            clean_host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        self.host = clean_host
        self.port = port
        self.protocol = protocol
        self.api_key = (api_key or "").strip()
        self.api_secret = (api_secret or "").strip()
        self.username = (username or "").strip()
        self.password = (password or "").strip()
        self.auth_mode = auth_mode.lower()  # "auto", "web", "api"
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()

    @property
    def base_url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    def fetch_config_xml(self) -> str:
        """
        Fetches config.xml from the OPNsense firewall.
        Tries Web-GUI session login or API Key/Secret based on auth_mode and provided credentials.
        """
        errors = []

        # If user explicitly wants Web-GUI Login or provided username & password
        should_try_web = self.auth_mode == "web" or (
            self.auth_mode == "auto" and bool(self.username and self.password)
        )
        should_try_api = self.auth_mode == "api" or (
            self.auth_mode == "auto" and bool(self.api_key and self.api_secret)
        )

        # In auto mode, if username looks like "root" or standard user, try web first
        if should_try_web:
            try:
                xml = self._fetch_via_web_gui_session()
                if xml:
                    return xml
            except Exception as exc:
                logger.warning("OPNsense Web-GUI Login failed: %s", exc)
                errors.append(f"Web-GUI Login: {str(exc)}")

        if should_try_api:
            try:
                xml = self._fetch_via_rest_api()
                if xml:
                    return xml
            except Exception as exc:
                logger.warning("OPNsense REST API fetch failed: %s", exc)
                errors.append(f"API: {str(exc)}")

        # Fallback in auto mode: if API was tried first and failed, try web if credentials exist
        if not should_try_web and self.username and self.password:
            try:
                xml = self._fetch_via_web_gui_session()
                if xml:
                    return xml
            except Exception as exc:
                errors.append(f"Web-GUI Login: {str(exc)}")

        # Fallback: if user typed API key in username field or vice-versa
        if not should_try_api and self.username and self.password and not errors:
            self.api_key = self.username
            self.api_secret = self.password
            try:
                xml = self._fetch_via_rest_api()
                if xml:
                    return xml
            except Exception as exc:
                errors.append(f"API: {str(exc)}")

        err_msg = "; ".join(errors) if errors else "Keine Zugangsdaten angegeben."
        raise ConnectionError(
            f"Konnte OPNsense Konfiguration von {self.base_url} nicht abrufen: {err_msg}"
        )

    def _is_valid_opnsense_xml(self, content: str) -> bool:
        if not content or not isinstance(content, str):
            return False
        content_lower = content.lower()
        return ("<opnsense" in content_lower or "<pfsense" in content_lower) and (
            "<interfaces" in content_lower or "<system" in content_lower
        )

    def _fetch_via_web_gui_session(self) -> Optional[str]:
        """
        Authenticates to OPNsense web GUI via form login (/index.php) and downloads
        backup directly via /diag_backup.php or session-based API endpoint.
        """
        user = self.username or self.api_key
        pwd = self.password or self.api_secret
        if not user or not pwd:
            raise ValueError("Benutzername und Passwort für Web-GUI Login erforderlich.")

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        })

        login_url = f"{self.base_url}/index.php"
        logger.info("Connecting to OPNsense login page: %s", login_url)
        try:
            resp = session.get(login_url, verify=self.verify_ssl, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            raise ConnectionError(f"Verbindung zu {login_url} fehlgeschlagen: {str(e)}")

        if resp.status_code != 200:
            raise ConnectionError(f"OPNsense Login-Seite lieferte HTTP {resp.status_code}")

        # Update protocol/port if redirected (e.g., http -> https)
        if resp.history:
            final_url = resp.url
            if final_url.startswith("https://") and self.protocol != "https":
                self.protocol = "https"
                login_url = f"{self.base_url}/index.php"

        # Extract CSRF token if present
        csrf_token = None
        m = re.search(r'name=["\'](?:csrf_token|__csrf_magic)["\']\s+value=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        if m:
            csrf_token = m.group(1)
        elif "csrf_token" in session.cookies:
            csrf_token = session.cookies.get("csrf_token")

        login_data = {
            "usernamefld": user,
            "passwordfld": pwd,
            "login": "1",
        }
        if csrf_token:
            login_data["csrf_token"] = csrf_token

        post_headers = {
            "Origin": self.base_url,
            "Referer": login_url,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        logger.info("Submitting OPNsense web login form for user '%s'", user)
        post_resp = session.post(
            login_url,
            data=login_data,
            headers=post_headers,
            verify=self.verify_ssl,
            timeout=self.timeout,
            allow_redirects=True,
        )

        resp_text_lower = post_resp.text.lower()
        if "wrong username or password" in resp_text_lower or "falscher benutzername oder passwort" in resp_text_lower:
            raise PermissionError("Falscher OPNsense Benutzername oder Passwort.")
        if "must support cookies" in resp_text_lower:
            raise ConnectionError("OPNsense Cookie-Prüfung fehlgeschlagen.")
        if "dns rebind attack" in resp_text_lower:
            raise ConnectionError("OPNsense meldet DNS-Rebind Schutz. Bitte IP-Adresse statt Hostname nutzen.")
        if "http_referer" in resp_text_lower and "does not match" in resp_text_lower:
            raise ConnectionError("OPNsense meldet Referer-Konflikt.")

        # If still stuck on login form
        if 'name="usernamefld"' in post_resp.text and 'name="passwordfld"' in post_resp.text and '<body class="page-login"' in post_resp.text:
            raise PermissionError("Login fehlgeschlagen: Die Login-Maske wurde erneut angezeigt (Passwort prüfen).")

        # Session authenticated! Now download config.xml
        # 1. Primary: POST to /diag_backup.php (standard OPNsense configuration download)
        diag_backup_url = f"{self.base_url}/diag_backup.php"
        logger.info("Downloading config.xml via POST %s", diag_backup_url)
        dl_resp = session.post(
            diag_backup_url,
            data={"download": "Download configuration", "donotbackuprrd": "yes"},
            headers={"Origin": self.base_url, "Referer": diag_backup_url},
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if dl_resp.status_code == 200 and self._is_valid_opnsense_xml(dl_resp.text):
            logger.info("Successfully fetched config.xml via POST /diag_backup.php")
            return dl_resp.text

        # 2. Secondary: POST to /diag_backup.php with alt button value
        dl_resp2 = session.post(
            diag_backup_url,
            data={"download": "1", "donotbackuprrd": "yes"},
            headers={"Origin": self.base_url, "Referer": diag_backup_url},
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if dl_resp2.status_code == 200 and self._is_valid_opnsense_xml(dl_resp2.text):
            logger.info("Successfully fetched config.xml via POST (alt) /diag_backup.php")
            return dl_resp2.text

        # 3. Tertiary: Session-based GET /api/core/backup/download/this
        api_backup_url = f"{self.base_url}/api/core/backup/download/this"
        logger.info("Trying session GET on %s", api_backup_url)
        dl_resp3 = session.get(
            api_backup_url,
            headers={"Referer": self.base_url},
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if dl_resp3.status_code == 200 and self._is_valid_opnsense_xml(dl_resp3.text):
            logger.info("Successfully fetched config.xml via session GET %s", api_backup_url)
            return dl_resp3.text

        raise ValueError(
            f"Login erfolgreich, aber der Download lieferte kein gültiges XML (HTTP {dl_resp.status_code})."
        )

    def _fetch_via_rest_api(self) -> Optional[str]:
        """
        Fetches configuration using OPNsense REST API Key & Secret with HTTP Basic Auth.
        """
        key = self.api_key or self.username
        secret = self.api_secret or self.password
        if not key or not secret:
            raise ValueError("API-Key und API-Secret erforderlich.")

        errors = []
        endpoints = [
            "/api/core/backup/download/this",
            "/api/backup/backup/download",
            "/api/backup/backup/download/?format=plain",
        ]

        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                logger.info("Attempting OPNsense API fetch on %s", url)
                resp = self.session.get(
                    url,
                    auth=(key, secret),
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    content = resp.text
                    if self._is_valid_opnsense_xml(content):
                        logger.info("Successfully fetched OPNsense config.xml via API %s", endpoint)
                        return content
                    else:
                        preview = resp.text[:100].replace("\n", " ").strip()
                        errors.append(f"{endpoint}: Kein XML ({preview}...)")
                elif resp.status_code == 401:
                    errors.append(
                        f"{endpoint}: HTTP 401 Unauthorized - Ungültiger API-Key oder Secret. "
                        f"(Hinweis: Für normale Web-Passwörter bitte 'Web-GUI Login' wählen!)"
                    )
                elif resp.status_code == 403:
                    errors.append(
                        f"{endpoint}: HTTP 403 Forbidden - Benutzer benötigt das Recht 'Diagnostics: Configuration History'."
                    )
                elif resp.status_code == 404:
                    errors.append(f"{endpoint}: HTTP 404 Nicht gefunden.")
                else:
                    errors.append(f"{endpoint}: HTTP {resp.status_code}")
            except Exception as exc:
                errors.append(f"{endpoint}: {str(exc)}")

        raise ConnectionError("; ".join(errors))

