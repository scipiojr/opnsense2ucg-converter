# OPNsense (26.x) zu UniFi Cloud Gateway Max (UCG-Max) Migration Suite

Ein Python-gestütztes Tool mit interaktiver Web- & Desktop-GUI zur automatisierten Migration aller Netzwerkeinstellungen von **OPNsense (z.B. Version 26.7.5)** auf ein **Ubiquiti UniFi Cloud Gateway Max (UCG-Max)**.

---

## 🚀 Kernfunktionen

- **VLANs & Subnetze**: Automatische Konvertierung von OPNsense Interfaces (`lan`, `opt1`... und `vlan0.x`) in UniFi Corporate Virtual Networks mit korrekten Gateway-CIDRs und DHCP-Bereichen.
- **Feste IP-Reservierungen (DHCP Static Leases)**: Übernahme aller statischen DHCP-Einträge (`mac`, `ipaddr`, `hostname`) in UniFi Client Device Fixed IPs.
- **Aliase & Gruppen**: Konvertierung von OPNsense Aliasen in UniFi `address-group` und `port-group` Firewall Groups mit automatischer Entschachtelung.
- **NAT & Port Forwarding**: Übernahme von Port-Weiterleitungen in UniFi Port Forward Regeln.
- **Firewall-Regelwerk & Default-Policy-Korrektur**:
  - **OPNsense**: Blockiert standardmäßig jeden Datenverkehr zwischen Schnittstellen (*Default Deny*).
  - **UniFi**: Erlaubt standardmäßig die freie Kommunikation zwischen allen Corporate-Netzwerken (*Default Allow*)!
  - **Lösung des Tools**: Generiert automatisch die sichere UniFi-Regelstruktur auf `LAN_IN`:
    1. Regel 2000: `Allow Established/Related`
    2. Regel 2001: `Drop Invalid State`
    3. Regel 2002–2090: Erkannte Ausnahmen / Pinholes (z.B. IoT zu DNS, Smart Home zu Home Assistant)
    4. Regel 2099: `Block All Inter-VLAN Traffic` (Drop RFC1918 zu RFC1918) zur Wiederherstellung der OPNsense-Sicherheit!
- **Datenschutz & LLM-Anonymisierung**:
  - Reversible Maskierung aller Passwörter, Bcrypt-Hashes, VPN-Schlüssel, externen WAN-IPs und FQDNs vor der Übermittlung an LLMs (Claude / Gemini).
  - Rehydrierung der echten Werte lokal nach der KI-Übersetzung.
- **LLM-Regelübersetzer**:
  - Unterstützung für Google Gemini (z.B. 2.5 Flash / Pro) und Anthropic Claude (3.7 Sonnet).
  - Offline-Modus: Generiert fertige Prompts zum Kopieren in ChatGPT / Claude / Gemini Web mit 1-Klick-Re-Import.
- **Dry-Run & Simulation**:
  - Risikoarmer Verbindungstest und vollständige Rollout-Simulation gegen das Cloud Gateway Max vor echten Änderungen.

---

## 🛠️ Schnellstart

### 1. Web-Dashboard starten (Empfohlen)
```powershell
py -3.13 main.py
```
Öffnet automatisch das Dashboard unter [http://127.0.0.1:8080](http://127.0.0.1:8080).

### 2. Desktop-GUI starten
```powershell
py -3.13 gui_desktop.py
```

### 3. Tests ausführen
```powershell
py -3.13 tests/test_pipeline.py
py -3.13 tests/test_api.py
```

---

## 📋 Hardware- & Switch-Migrationsplan

1. **Bisherigen UOS-Server sichern**:
   - Site-Backup (`.unf`) exportieren.
   - Device SSH Authentication Credentials notieren.
2. **UCG-Max vorbereiten & konfigurieren**:
   - UCG-Max WAN an Modem anschließen.
   - Konfiguration mittels dieses Tools via Dry-Run prüfen und übertragen.
3. **UniFi Lite / Pro PoE Switche integrieren**:
   - Switche per Uplink an LAN-Port des UCG-Max anschließen und adoptieren.
   - Port-Profile konfigurieren:
     - Uplinks zu UCG-Max & UniFi APs: *Trunk (All VLANs)*.
     - PoE-Ports für Protect Kameras: *Native VLAN Kameras (z.B. VLAN 30)*.
     - Kabel-IoT: *Native VLAN IoT (z.B. VLAN 20)*.
4. **UniFi APs umziehen**:
   - APs an die neuen PoE-Ports umstecken.
   - Inform-URL via SSH setzen (`set-inform http://192.168.1.1:8080/inform`) oder Migrations-Assistent nutzen.
   - Alten UOS-Server abschalten.
