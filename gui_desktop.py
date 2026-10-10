"""
Native Tkinter Desktop GUI for OPNsense to UniFi Cloud Gateway Max Migrator.
Provides a quick desktop interface for file selection, inspection, prompt generation, and launching the Web UI.
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
import webbrowser

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.opnsense.parser import OPNsenseParser
from src.sanitizer.masker import SanitizerVault
from src.translator.mapper import UniFiMapper
from src.llm.engine import LLMTranslationEngine


class DesktopMigratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OPNsense -> UniFi Cloud Gateway Max Migrator")
        self.geometry("900x650")
        self.minsize(750, 500)

        self.raw_xml = ""
        self.opn_cfg = None
        self.vault = SanitizerVault()
        self.unifi_cfg = None

        self._build_ui()

    def _build_ui(self):
        # Top banner
        header = tk.Frame(self, bg="#0f172a", padx=15, pady=12)
        header.pack(fill=tk.X)

        title_lbl = tk.Label(
            header,
            text="OPNsense 26.x zu UniFi Cloud Gateway Max Migrator",
            font=("Segoe UI", 13, "bold"),
            fg="#38bdf8",
            bg="#0f172a",
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            header,
            text="VLANs, NAT, Firewall Rules, Aliase, Fixed IPs & LLM-Prompt Sanitization",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a",
        )
        sub_lbl.pack(anchor="w")

        # Top Button Toolbar
        toolbar = tk.Frame(self, padx=15, pady=8, bg="#f8fafc")
        toolbar.pack(fill=tk.X)

        btn_load = ttk.Button(toolbar, text="OPNsense config.xml öffnen...", command=self.open_file)
        btn_load.pack(side=tk.LEFT, padx=4)

        btn_demo = ttk.Button(toolbar, text="Demo-Konfiguration laden", command=self.load_demo)
        btn_demo.pack(side=tk.LEFT, padx=4)

        btn_web = ttk.Button(toolbar, text="Vollständiges Web-Dashboard starten", command=self.launch_web_dashboard)
        btn_web.pack(side=tk.RIGHT, padx=4)

        # Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Tab 1: Overview
        self.tab_overview = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_overview, text="1. Analyse & Übersicht")
        self._build_overview_tab()

        # Tab 2: Sanitizer
        self.tab_sanitize = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sanitize, text="2. Datenschutz & Vault")
        self._build_sanitize_tab()

        # Tab 3: LLM Prompt
        self.tab_llm = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_llm, text="3. LLM Prompt-Generator")
        self._build_llm_tab()

        # Tab 4: UniFi Config
        self.tab_unifi = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_unifi, text="4. UniFi Zielkonfiguration")
        self._build_unifi_tab()

        # Status Bar
        self.status_var = tk.StringVar(value="Bereit. Bitte OPNsense config.xml öffnen.")
        status_bar = tk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", font=("Segoe UI", 8), bg="#e2e8f0", padx=10, pady=4)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _build_overview_tab(self):
        frame = self.tab_overview

        stats_box = ttk.LabelFrame(frame, text="Erkannte Netzwerk-Objekte", padding=10)
        stats_box.pack(fill=tk.X, padx=10, pady=5)

        self.stats_lbl = ttk.Label(stats_box, text="Noch keine Datei geladen.", font=("Segoe UI", 10))
        self.stats_lbl.pack(anchor="w")

        tree_frame = ttk.Frame(frame, padding=5)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("type", "name", "vlan_ip", "details")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        self.tree.heading("type", text="Kategorie")
        self.tree.heading("name", text="Name / ID")
        self.tree.heading("vlan_ip", text="VLAN / IP / Port")
        self.tree.heading("details", text="Beschreibung / Details")

        self.tree.column("type", width=120)
        self.tree.column("name", width=150)
        self.tree.column("vlan_ip", width=180)
        self.tree.column("details", width=350)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.scroll)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_sanitize_tab(self):
        frame = self.tab_sanitize

        top = ttk.Frame(frame, padding=10)
        top.pack(fill=tk.X)

        self.anon_mac_var = tk.BooleanVar(value=False)
        chk_mac = ttk.Checkbutton(top, text="MAC-Adressen ebenfalls pseudonymisieren (__MAC_ADDR_xxx__)", variable=self.anon_mac_var)
        chk_mac.pack(side=tk.LEFT)

        btn_run_san = ttk.Button(top, text="Datenschutz-Prüfung ausführen", command=self.run_sanitization)
        btn_run_san.pack(side=tk.RIGHT)

        lbl = ttk.Label(frame, text="Audit-Tabelle der bereinigten Geheimnisse & WAN-IPs:")
        lbl.pack(anchor="w", padx=10, pady=2)

        tree_f = ttk.Frame(frame, padding=5)
        tree_f.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.vault_tree = ttk.Treeview(tree_f, columns=("token", "cat", "preview"), show="headings", height=12)
        self.vault_tree.heading("token", text="Generierter Token")
        self.vault_tree.heading("cat", text="Kategorie")
        self.vault_tree.heading("preview", text="Maskierte Vorschau")
        self.vault_tree.column("token", width=200)
        self.vault_tree.column("cat", width=150)
        self.vault_tree.column("preview", width=350)

        self.vault_tree.pack(fill=tk.BOTH, expand=True)

    def _build_llm_tab(self):
        frame = self.tab_llm

        top = ttk.Frame(frame, padding=10)
        top.pack(fill=tk.X)

        btn_gen = ttk.Button(top, text="Bereinigten Prompt generieren", command=self.generate_prompt)
        btn_gen.pack(side=tk.LEFT, padx=5)

        btn_copy = ttk.Button(top, text="Prompt in Zwischenablage kopieren", command=self.copy_prompt)
        btn_copy.pack(side=tk.LEFT, padx=5)

        self.prompt_text = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 9), padx=10, pady=10)
        self.prompt_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _build_unifi_tab(self):
        frame = self.tab_unifi

        top = ttk.Frame(frame, padding=10)
        top.pack(fill=tk.X)

        btn_exp = ttk.Button(top, text="Als unifi_config.json exportieren", command=self.export_unifi_json)
        btn_exp.pack(side=tk.LEFT, padx=5)

        self.unifi_text = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 9), padx=10, pady=10)
        self.unifi_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("XML Backups", "*.xml"), ("All Files", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.process_xml(f.read())

    def load_demo(self):
        demo_path = os.path.join(os.path.dirname(__file__), "examples", "sample_opnsense_26_7_5.xml")
        if os.path.exists(demo_path):
            with open(demo_path, "r", encoding="utf-8") as f:
                self.process_xml(f.read())
        else:
            messagebox.showerror("Fehler", "Demo-Datei nicht gefunden.")

    def process_xml(self, xml_content: str):
        self.raw_xml = xml_content
        parser = OPNsenseParser(xml_content)
        self.opn_cfg = parser.parse()

        # Mapper
        mapper = UniFiMapper(self.opn_cfg)
        self.unifi_cfg = mapper.map_all(enforce_inter_vlan_block=True)

        # Update stats
        self.stats_lbl.config(
            text=(
                f"OPNsense Version: {self.opn_cfg.version} | "
                f"Interfaces/VLANs: {len(self.opn_cfg.interfaces)} | "
                f"Feste DHCP-Leases: {len(self.opn_cfg.static_leases)} | "
                f"Aliase: {len(self.opn_cfg.aliases)} | "
                f"NAT Forwards: {len(self.opn_cfg.port_forwards)} | "
                f"Filter-Regeln: {len(self.opn_cfg.filter_rules)}"
            )
        )

        # Clear and fill Treeview
        for row in self.tree.get_children():
            self.tree.delete(row)

        for i in self.opn_cfg.interfaces:
            self.tree.insert("", tk.END, values=("Interface/VLAN", i.descr, f"VLAN {i.vlan_tag or '1'} ({i.ipaddr})", f"Gerät: {i.physical_if}"))

        for l in self.opn_cfg.static_leases:
            self.tree.insert("", tk.END, values=("DHCP Lease", l.hostname, l.ipaddr, f"MAC: {l.mac} ({l.descr})"))

        for r in self.opn_cfg.filter_rules:
            self.tree.insert("", tk.END, values=("Firewall-Regel", r.descr or r.id, f"{r.interface} ({r.action.upper()})", f"{r.src} -> {r.dst}:{r.dst_port}"))

        self.run_sanitization()
        self.generate_prompt()
        self._update_unifi_view()

        self.status_var.set(f"Konfiguration erfolgreich geladen ({len(self.opn_cfg.interfaces)} Interfaces, {len(self.opn_cfg.filter_rules)} Regeln)")

    def run_sanitization(self):
        if not self.raw_xml:
            return
        self.vault = SanitizerVault(anonymize_macs=self.anon_mac_var.get())
        self.vault.sanitize_xml(self.raw_xml)
        summary = self.vault.get_audit_summary()

        for row in self.vault_tree.get_children():
            self.vault_tree.delete(row)

        for item in summary:
            self.vault_tree.insert("", tk.END, values=(item["token"], item["category"], item["preview"]))

    def generate_prompt(self):
        if not self.opn_cfg:
            return
        data = {
            "interfaces": [{"name": i.descr, "vlan": i.vlan_tag, "ip": i.ipaddr} for i in self.opn_cfg.interfaces],
            "rules": [{"id": r.id, "iface": r.interface, "action": r.action, "src": r.src, "dst": r.dst} for r in self.opn_cfg.filter_rules],
            "aliases": [{"name": a.name, "type": a.type, "members": a.content} for a in self.opn_cfg.aliases]
        }
        sanitized = self.vault.sanitize_dict(data)
        engine = LLMTranslationEngine(self.vault)
        prompt = engine.generate_prompt(sanitized)

        self.prompt_text.delete("1.0", tk.END)
        self.prompt_text.insert(tk.END, prompt)

    def copy_prompt(self):
        prompt = self.prompt_text.get("1.0", tk.END).strip()
        if prompt:
            self.clipboard_clear()
            self.clipboard_append(prompt)
            messagebox.showinfo("Kopiert", "Prompt wurde in die Zwischenablage kopiert.")

    def _update_unifi_view(self):
        if not self.unifi_cfg:
            return
        data = {
            "networks": [{"name": n.name, "vlan": n.vlan_id, "cidr": n.gateway_cidr} for n in self.unifi_cfg.networks],
            "firewall_rules": [{"index": r.rule_index, "ruleset": r.ruleset, "action": r.action, "name": r.name} for r in self.unifi_cfg.firewall_rules],
            "fixed_ips": [{"mac": f.mac, "ip": f.fixed_ip, "name": f.name} for f in self.unifi_cfg.fixed_ips],
        }
        self.unifi_text.delete("1.0", tk.END)
        self.unifi_text.insert(tk.END, json.dumps(data, indent=2))

    def export_unifi_json(self):
        if not self.unifi_cfg:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.unifi_text.get("1.0", tk.END))
            messagebox.showinfo("Gespeichert", f"Konfiguration gespeichert unter:\n{path}")

    def launch_web_dashboard(self):
        webbrowser.open("http://127.0.0.1:8080")


if __name__ == "__main__":
    app = DesktopMigratorApp()
    app.mainloop()
