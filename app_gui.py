# -*- coding: utf-8 -*-
"""
Aplicación de Escritorio Nativa de Windows para el SGSI & SOC Framework.
Incluye Servidor en Vivo 100% Automatizado (se inicia en segundo plano automáticamente),
receptor Syslog y dashboards en tiempo real.
"""

import os
import sys
import csv
import socket
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# Importar módulos del core
from core.risk_calculator import RiskCalculator
from core.soa_manager import SoAManager
from core.asset_manager import AssetManager
from core.incident_manager import IncidentManager
from core.gsheets_manager import GSheetsManager
from soc_engine.log_parser import LogParser
from soc_engine.threat_detector import ThreatDetector
from soc_engine.syslog_collector import SyslogCollector
from soc_engine.threat_intel_manager import ThreatIntelManager
from simulators.generate_sample_telemetry import simulate_soc_activity
from dashboards.dashboard_generator import DashboardGenerator
from dashboards.live_server import LiveDashboardHandler, HTTPServer

class SGSISOCApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("🛡️ SGSI (ISO/IEC 27001:2022) & SOC Manager - Windows Desktop App")
        self.geometry("1180x750")
        self.minsize(980, 620)
        
        # Colores institucionales
        self.color_primary = "#1B365D"    # Azul institucional
        self.color_accent = "#2980B9"     # Azul brillante
        self.color_bg = "#F4F7F9"         # Fondo claro
        self.color_card = "#FFFFFF"       # Fondo tarjetas

        self.configure(bg=self.color_bg)

        # Estado del colector Syslog y Servidor Live
        self.syslog_collector = None
        self.syslog_thread = None
        self.live_server = None
        self.live_server_port = 8080

        # Estilos TTK
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        
        self._configure_styles()
        self._create_header()
        self._create_tabs()
        self._create_footer()

        # Iniciar Servidor en Vivo automáticamente en segundo plano
        self._auto_start_live_server()

        # Cargar datos iniciales
        self.refresh_kpis()
        self.load_incidents_table()
        self.load_risks_table()
        self.load_soa_table()
        self.load_assets_table()

    def _is_port_in_use(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    def _auto_start_live_server(self):
        """Inicia el servidor de Dashboards en vivo en un hilo de fondo si no está activo"""
        if not self._is_port_in_use(self.live_server_port):
            try:
                self.live_server = HTTPServer(('0.0.0.0', self.live_server_port), LiveDashboardHandler)
                server_thread = threading.Thread(target=self.live_server.serve_forever, daemon=True)
                server_thread.start()
                print(f"[Auto-Live Server] Servidor en vivo iniciado automáticamente en puerto {self.live_server_port}.")
            except Exception as e:
                print(f"[Auto-Live Server] Error al iniciar servidor automático: {e}")

    def _configure_styles(self):
        self.style.configure("TNotebook", background=self.color_bg, borderwidth=0)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[16, 8], background="#E2E8F0")
        self.style.map("TNotebook.Tab", background=[("selected", self.color_primary)], foreground=[("selected", "white")])
        
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=26)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#EAEEF3", foreground="#1B365D")
        self.style.map("Treeview", background=[("selected", "#3498DB")])

        self.style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"), background=self.color_primary, foreground="white")
        self.style.map("Primary.TButton", background=[("active", self.color_accent)])

    def _create_header(self):
        header_frame = tk.Frame(self, bg=self.color_primary, height=65)
        header_frame.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(
            header_frame,
            text="🛡️ SISTEMA DE GESTIÓN DE SEGURIDAD (SGSI) & SOC",
            font=("Segoe UI", 12, "bold"),
            bg=self.color_primary,
            fg="white"
        )
        title_lbl.pack(side=tk.LEFT, padx=15, pady=12)

        # Botón Actualizar Todo
        btn_refresh_all = tk.Button(
            header_frame,
            text="🔄 Actualizar Todo",
            font=("Segoe UI", 9, "bold"),
            bg="#34495E",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=lambda: self.refresh_all_data(show_msg=True)
        )
        btn_refresh_all.pack(side=tk.RIGHT, padx=6, pady=12)

        # Botón Sincronizar Google Sheets
        btn_gsheets = tk.Button(
            header_frame,
            text="☁️ Google Sheets...",
            font=("Segoe UI", 9, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_open_gsheets_modal
        )
        btn_gsheets.pack(side=tk.RIGHT, padx=6, pady=12)

        dir_btn = tk.Button(
            header_frame,
            text="👔 Dash Dirección",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_open_direccion_dashboard
        )
        dir_btn.pack(side=tk.RIGHT, padx=6, pady=12)

        ciso_btn = tk.Button(
            header_frame,
            text="🛡️ Dash CISO",
            font=("Segoe UI", 9, "bold"),
            bg="#8E44AD",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_open_ciso_dashboard
        )
        ciso_btn.pack(side=tk.RIGHT, padx=6, pady=12)

    def refresh_all_data(self, show_msg: bool = False):
        """Recarga todas las tablas, recalcula KPIs y regenera los dashboards HTML en vivo"""
        self.load_incidents_table()
        self.refresh_kpis()
        self.load_risks_table()
        self.load_soa_table()
        self.load_assets_table()
        
        try:
            dash_gen = DashboardGenerator()
            dash_gen.generate_ciso_dashboard()
            dash_gen.generate_direccion_dashboard()
        except Exception as e:
            print(f"[DashboardGen Error] {e}")

        inc_count = len(IncidentManager().get_all_incidents())
        self.status_lbl.config(
            text=f"🟢 Servidor en Vivo Activo: http://localhost:{self.live_server_port} | Telemetría: {inc_count} incidentes al día ({datetime.now().strftime('%H:%M:%S')})",
            fg="#27AE60"
        )
        if show_msg:
            messagebox.showinfo("Actualización Completada", f"¡Tablas, KPIs y Dashboards actualizados con éxito!\nTotal incidentes registrados: {inc_count}")

    def _create_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Tab 1: Dashboard & KPIs
        self.tab_kpis = tk.Frame(self.notebook, bg=self.color_bg)
        self.notebook.add(self.tab_kpis, text="  📊 Resumen & KPIs  ")
        self._build_tab_kpis()

        # Tab 2: SOC & Telemetría
        self.tab_soc = tk.Frame(self.notebook, bg=self.color_bg)
        self.notebook.add(self.tab_soc, text="  🚨 Centro de Operaciones SOC  ")
        self._build_tab_soc()

        # Tab 3: SGSI - Matriz de Riesgos (ISO 27005)
        self.tab_risks = tk.Frame(self.notebook, bg=self.color_bg)
        self.notebook.add(self.tab_risks, text="  ⚖️ Matriz de Riesgos (ISO 27005)  ")
        self._build_tab_risks()

        # Tab 4: SGSI - Declaración SoA (ISO 27001)
        self.tab_soa = tk.Frame(self.notebook, bg=self.color_bg)
        self.notebook.add(self.tab_soa, text="  📜 Controles SoA (ISO 27001)  ")
        self._build_tab_soa()

        # Tab 5: SGSI - Inventario de Activos (ISO 27001 / Ley 21.663)
        self.tab_assets = tk.Frame(self.notebook, bg=self.color_bg)
        self.notebook.add(self.tab_assets, text="  🏢 Inventario de Activos (ISO 27001 / Ley 21.663)  ")
        self._build_tab_assets()

    def _create_footer(self):
        footer_frame = tk.Frame(self, bg="#E2E8F0", height=28)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_lbl = tk.Label(
            footer_frame,
            text=f"🟢 Servidor en Vivo Activo: http://localhost:{self.live_server_port} | Syslog: UDP 1514 disponible",
            font=("Segoe UI", 8),
            bg="#E2E8F0",
            fg="#27AE60"
        )
        self.status_lbl.pack(side=tk.LEFT, padx=15, pady=4)

        time_lbl = tk.Label(
            footer_frame,
            text=f"Sesión: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            font=("Segoe UI", 8),
            bg="#E2E8F0",
            fg="#555555"
        )
        time_lbl.pack(side=tk.RIGHT, padx=15, pady=4)

    # -------------------------------------------------------------------------
    # TAB 1: DASHBOARD & KPIS
    # -------------------------------------------------------------------------
    def _build_tab_kpis(self):
        top_cards = tk.Frame(self.tab_kpis, bg=self.color_bg)
        top_cards.pack(fill=tk.X, padx=10, pady=15)

        self.card_total = self._create_metric_card(top_cards, "TOTAL INCIDENTES", "0", "#2980B9", 0)
        self.card_mttd = self._create_metric_card(top_cards, "MTTD (Detección)", "0 min", "#8E44AD", 1)
        self.card_mttr = self._create_metric_card(top_cards, "MTTR (Respuesta)", "0 min", "#27AE60", 2)
        self.card_critical = self._create_metric_card(top_cards, "ALERTAS CRÍTICAS", "0", "#E74C3C", 3)

        launch_frame = tk.Frame(self.tab_kpis, bg=self.color_bg)
        launch_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        btn_ciso_dash = tk.Button(
            launch_frame,
            text="🛡️ Abrir Dashboard CISO en Vivo (Auto-actualizable en Navegador)",
            font=("Segoe UI", 10, "bold"),
            bg="#8E44AD",
            fg="white",
            relief=tk.FLAT,
            padx=15,
            pady=8,
            command=self.action_open_ciso_dashboard
        )
        btn_ciso_dash.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        btn_dir_dash = tk.Button(
            launch_frame,
            text="👔 Abrir Dashboard Dirección en Vivo (Auto-actualizable en Navegador)",
            font=("Segoe UI", 10, "bold"),
            bg="#1B365D",
            fg="white",
            relief=tk.FLAT,
            padx=15,
            pady=8,
            command=self.action_open_direccion_dashboard
        )
        btn_dir_dash.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)

        bottom_frame = tk.Frame(self.tab_kpis, bg=self.color_bg)
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        f_sev = tk.LabelFrame(bottom_frame, text=" Distribución por Severidad ", font=("Segoe UI", 10, "bold"), bg=self.color_card, padx=10, pady=10)
        f_sev.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.txt_severity = tk.Text(f_sev, font=("Consolas", 10), bg="#FAFAFA", relief=tk.FLAT, height=10)
        self.txt_severity.pack(fill=tk.BOTH, expand=True)

        f_threat = tk.LabelFrame(bottom_frame, text=" Tipos de Amenaza Detectadas ", font=("Segoe UI", 10, "bold"), bg=self.color_card, padx=10, pady=10)
        f_threat.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        self.txt_threats = tk.Text(f_threat, font=("Consolas", 10), bg="#FAFAFA", relief=tk.FLAT, height=10)
        self.txt_threats.pack(fill=tk.BOTH, expand=True)

    def _create_metric_card(self, parent, title, val, color, col_idx):
        card = tk.Frame(parent, bg=self.color_card, bd=1, relief=tk.SOLID, padx=15, pady=12)
        card.grid(row=0, column=col_idx, padx=8, sticky="nsew")
        parent.grid_columnconfigure(col_idx, weight=1)

        lbl_t = tk.Label(card, text=title, font=("Segoe UI", 8, "bold"), bg=self.color_card, fg="#7F8C8D")
        lbl_t.pack(anchor="w")

        lbl_v = tk.Label(card, text=val, font=("Segoe UI", 18, "bold"), bg=self.color_card, fg=color)
        lbl_v.pack(anchor="w", pady=(5, 0))
        return lbl_v

    def refresh_kpis(self):
        inc_mgr = IncidentManager()
        kpis = inc_mgr.compute_kpis()

        self.card_total.config(text=str(kpis["total_incidents"]))
        self.card_mttd.config(text=f"{kpis['avg_mttd_min']} min")
        self.card_mttr.config(text=f"{kpis['avg_mttr_min']} min")
        
        crit_count = kpis["by_severity"].get("Crítica", 0) + kpis["by_severity"].get("Critica", 0)
        self.card_critical.config(text=str(crit_count))

        self.txt_severity.delete("1.0", tk.END)
        for s, c in kpis["by_severity"].items():
            self.txt_severity.insert(tk.END, f"  • {s:<15}: {c:>3} incidentes\n")

        self.txt_threats.delete("1.0", tk.END)
        for t, c in kpis["by_threat"].items():
            self.txt_threats.insert(tk.END, f"  • {t:<22}: {c:>3} eventos\n")

    # -------------------------------------------------------------------------
    # TAB 2: SOC & TELEMETRÍA
    # -------------------------------------------------------------------------
    def _build_tab_soc(self):
        actions_bar = tk.Frame(self.tab_soc, bg=self.color_bg)
        actions_bar.pack(fill=tk.X, padx=10, pady=8)

        self.btn_syslog = tk.Button(
            actions_bar,
            text="📡 Iniciar Receptor Syslog en Vivo (UDP 1514)",
            font=("Segoe UI", 9, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.toggle_syslog_server
        )
        self.btn_syslog.pack(side=tk.LEFT, padx=5)

        btn_ingest = tk.Button(
            actions_bar,
            text="📂 Ingestar Archivo de Logs Real...",
            font=("Segoe UI", 9, "bold"),
            bg=self.color_primary,
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_ingest_log_file
        )
        btn_ingest.pack(side=tk.LEFT, padx=5)

        btn_sim = tk.Button(
            actions_bar,
            text="⚡ Simular Ataques",
            font=("Segoe UI", 9),
            bg="#E67E22",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=5,
            command=self.action_simulate_soc
        )
        btn_sim.pack(side=tk.LEFT, padx=5)

        btn_mitigate = tk.Button(
            actions_bar,
            text="🛡️ Responder / Mitigar...",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_mitigate_incident
        )
        btn_mitigate.pack(side=tk.LEFT, padx=5)

        btn_cti = tk.Button(
            actions_bar,
            text="🌐 Feeds CTI...",
            font=("Segoe UI", 9, "bold"),
            bg="#8E44AD",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_open_cti_modal
        )
        btn_cti.pack(side=tk.LEFT, padx=5)

        btn_ref = tk.Button(
            actions_bar,
            text="🔄 Actualizar",
            font=("Segoe UI", 9, "bold"),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=lambda: self.refresh_all_data(show_msg=True)
        )
        btn_ref.pack(side=tk.RIGHT, padx=5)

        cols = ("ID", "Fecha/Hora", "Título", "Severidad", "IP Origen", "Host Origen", "IP Destino", "Host Destino", "Técnica MITRE", "Estado")
        self.tree_incidents = ttk.Treeview(self.tab_soc, columns=cols, show="headings", selectmode="browse")
        
        self.tree_incidents.heading("ID", text="ID")
        self.tree_incidents.heading("Fecha/Hora", text="Fecha/Hora")
        self.tree_incidents.heading("Título", text="Título")
        self.tree_incidents.heading("Severidad", text="Severidad")
        self.tree_incidents.heading("IP Origen", text="IP Origen")
        self.tree_incidents.heading("Host Origen", text="Host Origen")
        self.tree_incidents.heading("IP Destino", text="IP Destino")
        self.tree_incidents.heading("Host Destino", text="Host Destino")
        self.tree_incidents.heading("Técnica MITRE", text="Técnica MITRE")
        self.tree_incidents.heading("Estado", text="Estado")

        self.tree_incidents.column("ID", width=75, anchor="center")
        self.tree_incidents.column("Fecha/Hora", width=125)
        self.tree_incidents.column("Título", width=180)
        self.tree_incidents.column("Severidad", width=75, anchor="center")
        self.tree_incidents.column("IP Origen", width=95, anchor="center")
        self.tree_incidents.column("Host Origen", width=130)
        self.tree_incidents.column("IP Destino", width=95, anchor="center")
        self.tree_incidents.column("Host Destino", width=140)
        self.tree_incidents.column("Técnica MITRE", width=130)
        self.tree_incidents.column("Estado", width=75, anchor="center")

        scroll_y = ttk.Scrollbar(self.tab_soc, orient=tk.VERTICAL, command=self.tree_incidents.yview)
        self.tree_incidents.configure(yscrollcommand=scroll_y.set)

        self.tree_incidents.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

        self.tree_incidents.bind("<Double-1>", lambda event: self.action_mitigate_incident())

    def toggle_syslog_server(self):
        if self.syslog_collector and self.syslog_collector.running:
            self.syslog_collector.stop()
            self.btn_syslog.config(text="📡 Iniciar Receptor Syslog en Vivo (UDP 1514)", bg="#27AE60")
            self.status_lbl.config(text="Receptor Syslog: Detenido")
            messagebox.showinfo("Syslog Server", "Receptor Syslog detenido.")
        else:
            self.syslog_collector = SyslogCollector(port=1514)
            
            def on_incident_detected(inc_id, threat):
                self.after(100, lambda: [self.load_incidents_table(), self.refresh_kpis()])

            self.syslog_thread = threading.Thread(
                target=self.syslog_collector.start_listening,
                args=(on_incident_detected,),
                daemon=True
            )
            self.syslog_thread.start()
            self.btn_syslog.config(text="🛑 Detener Receptor Syslog (Escuchando en :1514)", bg="#C0392B")
            self.status_lbl.config(text="📡 Receptor Syslog ACTIVO en tiempo real (Puerto UDP 1514)")
            messagebox.showinfo("Syslog Server Activo", "Receptor Syslog UDP iniciado en el puerto 1514.\nPuedes configurar tus firewalls y servidores para reenviar logs a esta IP.")

    def load_incidents_table(self):
        for item in self.tree_incidents.get_children():
            self.tree_incidents.delete(item)

        inc_mgr = IncidentManager()
        incidents = inc_mgr.get_all_incidents()
        for inc in reversed(incidents):
            src_host = inc.get("Host_Origen") or inc.get("src_host") or inc.get("Usuario_Involucrado", "-")
            dst_ip = inc.get("IP_Destino") or inc.get("IP_Destino_Activo", "-")
            dst_host = inc.get("Host_Destino") or inc.get("IP_Destino_Activo", "-")

            self.tree_incidents.insert("", tk.END, values=(
                inc.get("ID_Incidente", ""),
                inc.get("Fecha_Hora", ""),
                inc.get("Titulo_Incidente", ""),
                inc.get("Severidad", ""),
                inc.get("IP_Origen", ""),
                src_host,
                dst_ip,
                dst_host,
                inc.get("Tecnica_MITRE", ""),
                inc.get("Estado", "")
            ))

    def action_simulate_soc(self):
        simulate_soc_activity()
        self.load_incidents_table()
        self.refresh_kpis()
        messagebox.showinfo("SOC Simulation", "¡Simulación de ciberataques completada!\nNuevos incidentes agregados a la matriz.")

    def action_ingest_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Seleccionar archivo de logs de Firewall o Servidor",
            filetypes=[("Archivos de Log", "*.log *.txt *.csv"), ("Todos los archivos", "*.*")]
        )
        if not file_path:
            return

        detector = ThreatDetector()
        inc_mgr = IncidentManager()
        count = 0
        detected = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                count += 1
                parsed = LogParser.parse_line(line)
                threats = detector.analyze_event(parsed)
                for t in threats:
                    inc_mgr.add_incident(t)
                    detected += 1

        self.load_incidents_table()
        self.refresh_kpis()
        messagebox.showinfo("Ingesta Finalizada", f"Se procesaron {count} líneas del log.\nIncidentes detectados y registrados: {detected}")

    def action_mitigate_incident(self):
        selected = self.tree_incidents.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Incidente", "Por favor selecciona un incidente de la tabla para gestionar la respuesta/mitigación.")
            return

        item = self.tree_incidents.item(selected[0])
        inc_id = item["values"][0]

        inc_mgr = IncidentManager()
        incidents = inc_mgr.get_all_incidents()
        target = None
        for inc in incidents:
            if inc.get("ID_Incidente") == inc_id:
                target = inc
                break

        if not target:
            messagebox.showerror("Error", f"No se encontró el incidente {inc_id}.")
            return

        self._open_incident_modal(target)

    def _open_incident_modal(self, inc: dict):
        modal = tk.Toplevel(self)
        inc_id = inc.get("ID_Incidente", "")
        sev = inc.get("Severidad", "Media")
        modal.title(f"🛡️ Gestión de Respuesta y Mitigación - {inc_id}")
        modal.geometry("700x620")
        modal.minsize(660, 580)
        modal.configure(bg=self.color_bg)
        modal.grab_set()

        hdr = tk.Frame(modal, bg=self.color_primary, padx=15, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text=f"🚨 Incidente {inc_id}: {inc.get('Titulo_Incidente', '')}",
            font=("Segoe UI", 11, "bold"),
            bg=self.color_primary,
            fg="white"
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text=f"Severidad: {sev.upper()} | Táctica MITRE: {inc.get('Tactica_MITRE', '')} ({inc.get('Tecnica_MITRE', '')})",
            font=("Segoe UI", 8),
            bg=self.color_primary,
            fg="#D1D5DB"
        ).pack(anchor="w")

        form = tk.Frame(modal, bg=self.color_bg, padx=15, pady=10)
        form.pack(fill=tk.BOTH, expand=True)

        # Telemetría de Origen y Destino
        f_tel = tk.LabelFrame(form, text=" 📡 Vector de Amenaza & Telemetría Registrada ", font=("Segoe UI", 8, "bold"), bg=self.color_card, padx=10, pady=6)
        f_tel.pack(fill=tk.X, pady=4)
        
        t_src = f"Origen: {inc.get('IP_Origen', '-')} ({inc.get('Host_Origen', '-')})"
        t_dst = f"Destino: {inc.get('IP_Destino', '-')} ({inc.get('Host_Destino', '-')})"
        t_mttd = f"MTTD (Detección): {inc.get('MTTD_Minutos', '1')} min | Fecha: {inc.get('Fecha_Hora', '')}"
        
        tk.Label(f_tel, text=t_src, font=("Segoe UI", 8, "bold"), bg=self.color_card, fg="#C0392B").pack(anchor="w")
        tk.Label(f_tel, text=t_dst, font=("Segoe UI", 8, "bold"), bg=self.color_card, fg="#2980B9").pack(anchor="w")
        tk.Label(f_tel, text=t_mttd, font=("Segoe UI", 8), bg=self.color_card, fg="#64748B").pack(anchor="w")
        tk.Label(f_tel, text=f"Detalle: {inc.get('Descripcion_Hallazgo', '')}", font=("Segoe UI", 8), bg=self.color_card, fg="#333333", wraplength=620, justify=tk.LEFT).pack(anchor="w", pady=(3, 0))

        # Formulario de Respuesta y Mitigación
        f_resp = tk.LabelFrame(form, text=" ⚡ Protocolo de Respuesta Operativa (Playbook / Mitigación) ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=8)
        f_resp.pack(fill=tk.BOTH, expand=True, pady=8)

        # Estado del Incidente
        r1 = tk.Frame(f_resp, bg=self.color_card)
        r1.pack(fill=tk.X, pady=4)
        tk.Label(r1, text="Estado de Resolución:", font=("Segoe UI", 9, "bold"), bg=self.color_card, width=20, anchor="w").pack(side=tk.LEFT)
        cb_status = ttk.Combobox(r1, values=["Cerrado", "En Mitigacion", "Abierto", "Falso Positivo"], font=("Segoe UI", 9), width=18, state="readonly")
        cb_status.set(inc.get("Estado", "Cerrado"))
        cb_status.pack(side=tk.LEFT)

        # MTTR (Tiempo de Respuesta en Minutos)
        r2 = tk.Frame(f_resp, bg=self.color_card)
        r2.pack(fill=tk.X, pady=4)
        tk.Label(r2, text="MTTR (Respuesta en Minutos):", font=("Segoe UI", 9, "bold"), bg=self.color_card, width=26, anchor="w").pack(side=tk.LEFT)
        
        init_mttr = 10
        try:
            init_mttr = int(float(inc.get("MTTR_Minutos", 10) or 10))
        except:
            init_mttr = 10
        if init_mttr <= 0:
            init_mttr = 10

        lbl_mttr_val = tk.Label(r2, text=f"{init_mttr} min", font=("Segoe UI", 10, "bold"), bg=self.color_card, fg="#27AE60", width=8)
        scale_mttr = ttk.Scale(r2, from_=1, to=120, orient=tk.HORIZONTAL, value=init_mttr, command=lambda v: lbl_mttr_val.config(text=f"{int(float(v))} min"))
        scale_mttr.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        lbl_mttr_val.pack(side=tk.LEFT)

        # Acción Correctiva
        r3 = tk.Frame(f_resp, bg=self.color_card)
        r3.pack(fill=tk.X, pady=4)
        tk.Label(r3, text="Acción Correctiva / Playbook:", font=("Segoe UI", 9, "bold"), bg=self.color_card, width=24, anchor="w").pack(side=tk.LEFT)
        
        cb_preset_actions = ttk.Combobox(r3, values=[
            "Bloqueo perimetral IP en Firewall FortiGate / WAF",
            "Aislamiento de red de Endpoint EDR y análisis forense",
            "Revocación de credenciales, forzado de MFA y reseteo de sesión",
            "Parcheo de vulnerabilidad y sanitización WAF",
            "Verificación de integridad de backups y reglas de filtrado",
            "Desestimado por regla de falso positivo tras inspección de tráfico"
        ], font=("Segoe UI", 8), width=45)
        cb_preset_actions.set(inc.get("Accion_Correctiva", "Bloqueo perimetral IP en Firewall FortiGate / WAF"))
        cb_preset_actions.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Responsable SOC
        r4 = tk.Frame(f_resp, bg=self.color_card)
        r4.pack(fill=tk.X, pady=4)
        tk.Label(r4, text="Responsable de Mitigación:", font=("Segoe UI", 9, "bold"), bg=self.color_card, width=24, anchor="w").pack(side=tk.LEFT)
        e_resp = tk.Entry(r4, font=("Segoe UI", 9))
        e_resp.insert(0, inc.get("Responsable_SOC", "Analista SOC L1 / Equipo CISO"))
        e_resp.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Botones
        btn_box = tk.Frame(modal, bg=self.color_bg, pady=10)
        btn_box.pack(fill=tk.X, side=tk.BOTTOM)

        def save_mitigation():
            st = cb_status.get().strip()
            action_txt = cb_preset_actions.get().strip()
            mttr_val = int(scale_mttr.get())
            owner_txt = e_resp.get().strip()

            updated = {
                "Estado": st,
                "Accion_Correctiva": action_txt,
                "MTTR_Minutos": str(mttr_val),
                "Responsable_SOC": owner_txt
            }

            inc_mgr = IncidentManager()
            if inc_mgr.update_incident(inc_id, updated):
                self.load_incidents_table()
                self.refresh_kpis()
                try:
                    DashboardGenerator().generate_all()
                except:
                    pass
                self.status_lbl.config(
                    text=f"✅ Incidente {inc_id} mitiguado y actualizado a '{st}' (MTTR: {mttr_val} min) ({datetime.now().strftime('%H:%M:%S')})",
                    fg="#27AE60"
                )
                messagebox.showinfo(
                    "Mitigación Registrada",
                    f"¡Incidente {inc_id} actualizado con éxito!\n"
                    f"Estado: {st}\n"
                    f"MTTR registrado: {mttr_val} minutos\n\n"
                    "Los Dashboards CISO y Dirección se han sincronizado y actualizado automáticamente en vivo.",
                    parent=modal
                )
                modal.destroy()
            else:
                messagebox.showerror("Error", "No se pudo actualizar el incidente.", parent=modal)

        tk.Button(
            btn_box,
            text="💾 Aplicar Mitigación & Actualizar Dashboards",
            font=("Segoe UI", 10, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=18,
            pady=6,
            command=save_mitigation
        ).pack(side=tk.RIGHT, padx=15)

        tk.Button(
            btn_box,
            text="Cancelar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=modal.destroy
        ).pack(side=tk.RIGHT)

    def action_open_cti_modal(self):
        modal = tk.Toplevel(self)
        modal.title("🌐 Cyber Threat Intelligence (CTI) - Feeds Dinámicos de Amenazas")
        modal.geometry("640x520")
        modal.minsize(600, 480)
        modal.configure(bg=self.color_bg)
        modal.grab_set()

        hdr = tk.Frame(modal, bg="#4A235A", padx=15, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text="🌐 Ciberinteligencia de Amenazas (CTI Feeds en Vivo)",
            font=("Segoe UI", 11, "bold"),
            bg="#4A235A",
            fg="white"
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text="Correlación en tiempo real con CSIRT Nacional, Feodo Tracker (Abuse.ch), MISP y Tor Project",
            font=("Segoe UI", 8),
            bg="#4A235A",
            fg="#D7BDE2"
        ).pack(anchor="w")

        body = tk.Frame(modal, bg=self.color_bg, padx=15, pady=12)
        body.pack(fill=tk.BOTH, expand=True)

        intel_mgr = ThreatIntelManager()
        total_loaded = len(intel_mgr.iocs)
        last_sync = intel_mgr.last_updated or "Caché inicial local"

        f_stats = tk.LabelFrame(body, text=" 📊 Estado Actual de los Feeds de CTI ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=8)
        f_stats.pack(fill=tk.X, pady=(0, 8))

        lbl_total = tk.Label(f_stats, text=f"Total de Indicadores (IoCs) en Memoria: {total_loaded:,} IPs y C2s", font=("Segoe UI", 10, "bold"), bg=self.color_card, fg="#8E44AD")
        lbl_total.pack(anchor="w", pady=2)
        
        lbl_sync = tk.Label(f_stats, text=f"Última Actualización Online: {last_sync}", font=("Segoe UI", 8), bg=self.color_card, fg="#64748B")
        lbl_sync.pack(anchor="w", pady=2)

        f_sources = tk.LabelFrame(body, text=" 🛡️ Fuentes Abiertas Conectadas ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=8)
        f_sources.pack(fill=tk.BOTH, expand=True, pady=4)

        sources_info = [
            ("🇨🇱 CSIRT Nacional & Gobierno", "IoCs de campañas dirigidas a Chile, malware bancario y ransomware."),
            ("🤖 Feodo Tracker (Abuse.ch)", "Servidores C2 activos de botnets (QakBot, Emotet, Dridex, TrickBot)."),
            ("🧅 Tor Project Official List", "Nodos de salida Tor para detección de tráfico anónimo y evasión perimetral."),
            ("🛡️ MISP & AlienVault OTX", "Listas de IPs maliciosas globales y vectores de explotación web (SQLi / XSS)."),
            ("🚫 AbuseIPDB Global Blocklist", "IPs con reporte de escaneo masivo, fuerza bruta SSH y botnets activas.")
        ]

        for name, desc in sources_info:
            r = tk.Frame(f_sources, bg=self.color_card)
            r.pack(fill=tk.X, pady=3)
            tk.Label(r, text=f"• {name}:", font=("Segoe UI", 8, "bold"), bg=self.color_card, fg="#1F2937").pack(side=tk.LEFT)
            tk.Label(r, text=f" {desc}", font=("Segoe UI", 8), bg=self.color_card, fg="#4B5563").pack(side=tk.LEFT)

        lbl_status_cti = tk.Label(body, text="", font=("Segoe UI", 8), bg=self.color_bg, fg="#27AE60")
        lbl_status_cti.pack(anchor="w", pady=4)

        # Botones
        btn_box = tk.Frame(modal, bg=self.color_bg, pady=10)
        btn_box.pack(fill=tk.X, side=tk.BOTTOM)

        def sync_cti_online():
            lbl_status_cti.config(text="⏳ Conectando con Feodo Tracker y Tor Project... Por favor espera...", fg="#E67E22")
            modal.update()

            def run_sync():
                res = intel_mgr.update_feeds_online(timeout_sec=8)
                def on_done():
                    if res.get("success"):
                        lbl_total.config(text=f"Total de Indicadores (IoCs) en Memoria: {res['total_iocs']:,} IPs y C2s")
                        lbl_sync.config(text=f"Última Actualización Online: {res['last_updated']}")
                        lbl_status_cti.config(
                            text=f"✅ ¡Feeds actualizados con éxito! ({res['total_iocs']:,} IoCs cargados)",
                            fg="#27AE60"
                        )
                        messagebox.showinfo(
                            "CTI Actualizado",
                            f"¡Inteligencia de Amenazas actualizada!\n"
                            f"Total IoCs activos: {res['total_iocs']:,}\n"
                            f"Fuentes sincronizadas: {', '.join(res['sources'])}",
                            parent=modal
                        )
                    else:
                        lbl_status_cti.config(text=f"⚠️ Conexión parcial: {res.get('errors', ['Error desconocido'])}", fg="#C0392B")
                self.after(100, on_done)

            threading.Thread(target=run_sync, daemon=True).start()

        tk.Button(
            btn_box,
            text="🚀 Actualizar Feeds CTI en Vivo (Internet)",
            font=("Segoe UI", 10, "bold"),
            bg="#8E44AD",
            fg="white",
            relief=tk.FLAT,
            padx=16,
            pady=6,
            command=sync_cti_online
        ).pack(side=tk.RIGHT, padx=15)

        tk.Button(
            btn_box,
            text="Cerrar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=modal.destroy
        ).pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # TAB 3: MATRIZ DE RIESGOS (ISO 27005) - ADMINISTRADOR INTERACTIVO
    # -------------------------------------------------------------------------
    def _build_tab_risks(self):
        actions_bar = tk.Frame(self.tab_risks, bg=self.color_bg)
        actions_bar.pack(fill=tk.X, padx=10, pady=8)

        # Botón Agregar Riesgo
        btn_add = tk.Button(
            actions_bar,
            text="➕ Agregar Riesgo",
            font=("Segoe UI", 9, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_add_risk
        )
        btn_add.pack(side=tk.LEFT, padx=4)

        # Botón Editar Riesgo
        btn_edit = tk.Button(
            actions_bar,
            text="✏️ Editar Riesgo",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_edit_risk
        )
        btn_edit.pack(side=tk.LEFT, padx=4)

        # Botón Eliminar Riesgo
        btn_del = tk.Button(
            actions_bar,
            text="🗑️ Eliminar",
            font=("Segoe UI", 9, "bold"),
            bg="#E74C3C",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_delete_risk
        )
        btn_del.pack(side=tk.LEFT, padx=4)

        # Botón Recalcular Matriz
        btn_recalc = tk.Button(
            actions_bar,
            text="⚙️ Recalcular Matriz ISO 27005",
            font=("Segoe UI", 9, "bold"),
            bg=self.color_primary,
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_recalculate_risks
        )
        btn_recalc.pack(side=tk.LEFT, padx=4)

        # Nota informativa
        lbl_hint = tk.Label(
            actions_bar,
            text="💡 Doble clic en cualquier fila para editar rápidamente",
            font=("Segoe UI", 8, "italic"),
            bg=self.color_bg,
            fg="#7F8C8D"
        )
        lbl_hint.pack(side=tk.LEFT, padx=12)

        # Botón Refrescar
        btn_refresh = tk.Button(
            actions_bar,
            text="🔄 Actualizar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=8,
            pady=5,
            command=self.load_risks_table
        )
        btn_refresh.pack(side=tk.RIGHT, padx=4)

        cols = ("ID", "Activo", "Amenaza", "Vulnerabilidad", "Riesgo Inherente", "Eficacia", "Riesgo Residual", "Estrategia", "Responsable", "Fecha")
        self.tree_risks = ttk.Treeview(self.tab_risks, columns=cols, show="headings", selectmode="browse")

        self.tree_risks.heading("ID", text="ID")
        self.tree_risks.heading("Activo", text="Activo")
        self.tree_risks.heading("Amenaza", text="Amenaza Identificada")
        self.tree_risks.heading("Vulnerabilidad", text="Vulnerabilidad / Causa")
        self.tree_risks.heading("Riesgo Inherente", text="Riesgo Inherente")
        self.tree_risks.heading("Eficacia", text="Eficacia Controles")
        self.tree_risks.heading("Riesgo Residual", text="Riesgo Residual")
        self.tree_risks.heading("Estrategia", text="Estrategia")
        self.tree_risks.heading("Responsable", text="Responsable")
        self.tree_risks.heading("Fecha", text="Fecha Revisión")

        self.tree_risks.column("ID", width=70, anchor="center")
        self.tree_risks.column("Activo", width=80, anchor="center")
        self.tree_risks.column("Amenaza", width=190)
        self.tree_risks.column("Vulnerabilidad", width=170)
        self.tree_risks.column("Riesgo Inherente", width=115, anchor="center")
        self.tree_risks.column("Eficacia", width=95, anchor="center")
        self.tree_risks.column("Riesgo Residual", width=105, anchor="center")
        self.tree_risks.column("Estrategia", width=85, anchor="center")
        self.tree_risks.column("Responsable", width=110)
        self.tree_risks.column("Fecha", width=90, anchor="center")

        scroll_y = ttk.Scrollbar(self.tab_risks, orient=tk.VERTICAL, command=self.tree_risks.yview)
        self.tree_risks.configure(yscrollcommand=scroll_y.set)

        self.tree_risks.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

        # Doble clic para editar
        self.tree_risks.bind("<Double-1>", lambda event: self.action_edit_risk())

    def load_risks_table(self):
        for item in self.tree_risks.get_children():
            self.tree_risks.delete(item)

        calc = RiskCalculator()
        risks = calc.get_all_risks()
        for r in risks:
            self.tree_risks.insert("", tk.END, values=(
                r.get("ID_Riesgo", ""),
                r.get("ID_Activo", ""),
                r.get("Amenaza", ""),
                r.get("Vulnerabilidad", ""),
                f"{r.get('Nivel_Riesgo_Inherente', '')} ({r.get('Categoria_Riesgo_Inherente', '')})",
                r.get("Eficacia_Controles_Pct", ""),
                f"{r.get('Nivel_Riesgo_Residual', '')} ({r.get('Categoria_Riesgo_Residual', '')})",
                r.get("Estrategia_Tratamiento", ""),
                r.get("Responsable", ""),
                r.get("Fecha_Revision", "")
            ))

    def action_recalculate_risks(self):
        calc = RiskCalculator()
        calc.process_risk_matrix()
        self.load_risks_table()
        try:
            DashboardGenerator().generate_all()
        except:
            pass
        messagebox.showinfo("Cálculo de Riesgos", "¡Matriz de Riesgos ISO 27005 recalculada y actualizada con éxito!")

    def action_add_risk(self):
        self._open_risk_modal(existing_risk=None)

    def action_edit_risk(self):
        selected = self.tree_risks.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Riesgo", "Por favor selecciona un riesgo de la lista para editar.")
            return

        item = self.tree_risks.item(selected[0])
        risk_id = item["values"][0]

        calc = RiskCalculator()
        all_risks = calc.get_all_risks()
        target_risk = None
        for r in all_risks:
            if r.get("ID_Riesgo") == risk_id:
                target_risk = r
                break

        if not target_risk:
            messagebox.showerror("Error", f"No se encontró el registro del riesgo {risk_id}.")
            return

        self._open_risk_modal(existing_risk=target_risk)

    def action_delete_risk(self):
        selected = self.tree_risks.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Riesgo", "Por favor selecciona un riesgo de la lista para eliminar.")
            return

        item = self.tree_risks.item(selected[0])
        risk_id = item["values"][0]
        amenaza = item["values"][2]

        if messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que deseas eliminar permanentemente el riesgo {risk_id}?\n\n'{amenaza}'"):
            calc = RiskCalculator()
            if calc.delete_risk(risk_id):
                self.load_risks_table()
                try:
                    DashboardGenerator().generate_all()
                except:
                    pass
                messagebox.showinfo("Eliminado", f"El riesgo {risk_id} fue eliminado correctamente.")
            else:
                messagebox.showerror("Error", "No se pudo eliminar el riesgo.")

    def _open_risk_modal(self, existing_risk: dict = None):
        modal = tk.Toplevel(self)
        is_edit = existing_risk is not None
        modal.title("✏️ Modificar Riesgo ISO 27005" if is_edit else "➕ Registrar Nuevo Riesgo ISO 27005")
        modal.geometry("720x680")
        modal.minsize(680, 620)
        modal.configure(bg=self.color_bg)
        modal.grab_set()

        # Header modal
        hdr = tk.Frame(modal, bg=self.color_primary, padx=15, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text="✏️ Editor de Matriz de Riesgos ISO/IEC 27005" if is_edit else "➕ Registro de Nuevo Riesgo ISO/IEC 27005",
            font=("Segoe UI", 11, "bold"),
            bg=self.color_primary,
            fg="white"
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text="Define el activo, la amenaza, probabilidad, impacto y la eficacia de las salvaguardas ISO 27001.",
            font=("Segoe UI", 8),
            bg=self.color_primary,
            fg="#D1D5DB"
        ).pack(anchor="w")

        # Contenedor scrollable o directo
        form_frame = tk.Frame(modal, bg=self.color_bg, padx=15, pady=10)
        form_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Fila ID e ID Activo
        row1 = tk.Frame(form_frame, bg=self.color_bg)
        row1.pack(fill=tk.X, pady=4)

        tk.Label(row1, text="ID Riesgo:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=12, anchor="w").pack(side=tk.LEFT)
        e_id = tk.Entry(row1, font=("Segoe UI", 9), width=15)
        if is_edit:
            e_id.insert(0, existing_risk.get("ID_Riesgo", ""))
            e_id.config(state="readonly")
        else:
            calc = RiskCalculator()
            risks = calc.get_all_risks()
            next_idx = len(risks) + 1
            e_id.insert(0, f"RSG-{next_idx:03d}")
        e_id.pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(row1, text="Activo Afectado:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=14, anchor="w").pack(side=tk.LEFT)
        
        # Cargar lista de activos disponibles
        activos_list = ["ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006"]
        activos_csv = os.path.join("templates_google", "01_inventario_activos_template.csv")
        if os.path.exists(activos_csv):
            try:
                with open(activos_csv, "r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    activos_list = [f"{r.get('ID_Activo')} - {r.get('Nombre_Activo', '')[:25]}" for r in reader]
            except:
                pass

        cb_asset = ttk.Combobox(row1, values=activos_list, font=("Segoe UI", 9), width=30)
        curr_asset = existing_risk.get("ID_Activo", "ACT-001") if is_edit else (activos_list[0] if activos_list else "ACT-001")
        # Seleccionar si coincide
        matched = False
        for a in activos_list:
            if curr_asset in a:
                cb_asset.set(a)
                matched = True
                break
        if not matched:
            cb_asset.set(curr_asset)
        cb_asset.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 2. Amenaza
        row2 = tk.Frame(form_frame, bg=self.color_bg)
        row2.pack(fill=tk.X, pady=4)
        tk.Label(row2, text="Amenaza:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=12, anchor="w").pack(side=tk.LEFT)
        e_threat = tk.Entry(row2, font=("Segoe UI", 9))
        e_threat.insert(0, existing_risk.get("Amenaza", "") if is_edit else "")
        e_threat.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 3. Vulnerabilidad
        row3 = tk.Frame(form_frame, bg=self.color_bg)
        row3.pack(fill=tk.X, pady=4)
        tk.Label(row3, text="Vulnerabilidad:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=12, anchor="w").pack(side=tk.LEFT)
        e_vuln = tk.Entry(row3, font=("Segoe UI", 9))
        e_vuln.insert(0, existing_risk.get("Vulnerabilidad", "") if is_edit else "")
        e_vuln.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 4. Probabilidad e Impacto Inherente
        row4 = tk.Frame(form_frame, bg=self.color_bg)
        row4.pack(fill=tk.X, pady=6)

        prob_options = ["1 - Muy Baja", "2 - Baja", "3 - Media", "4 - Alta", "5 - Muy Alta / Crítica"]
        imp_options = ["1 - Despreciable", "2 - Menor", "3 - Moderado", "4 - Mayor", "5 - Catastrófico"]

        tk.Label(row4, text="Probabilidad (1-5):", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=15, anchor="w").pack(side=tk.LEFT)
        cb_prob = ttk.Combobox(row4, values=prob_options, font=("Segoe UI", 9), width=16, state="readonly")
        p_val = int(existing_risk.get("Probabilidad_Inherente_1a5", 3)) if is_edit else 3
        cb_prob.set(prob_options[min(max(p_val - 1, 0), 4)])
        cb_prob.pack(side=tk.LEFT, padx=(0, 15))

        tk.Label(row4, text="Impacto (1-5):", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=12, anchor="w").pack(side=tk.LEFT)
        cb_imp = ttk.Combobox(row4, values=imp_options, font=("Segoe UI", 9), width=16, state="readonly")
        i_val = int(existing_risk.get("Impacto_Inherente_1a5", 3)) if is_edit else 3
        cb_imp.set(imp_options[min(max(i_val - 1, 0), 4)])
        cb_imp.pack(side=tk.LEFT)

        # 5. Salvaguardas y Controles
        row5 = tk.Frame(form_frame, bg=self.color_bg)
        row5.pack(fill=tk.X, pady=4)
        tk.Label(row5, text="Controles Aplicados:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=16, anchor="w").pack(side=tk.LEFT)
        e_controls = tk.Entry(row5, font=("Segoe UI", 9))
        e_controls.insert(0, existing_risk.get("Controles_Aplicados", "") if is_edit else "A.8.7 (Antimalware), A.8.13 (Backups)")
        e_controls.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 6. Eficacia Controles (%) con Slider
        row6 = tk.Frame(form_frame, bg=self.color_bg)
        row6.pack(fill=tk.X, pady=4)
        tk.Label(row6, text="Eficacia Controles:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=16, anchor="w").pack(side=tk.LEFT)
        
        eff_init = 70
        if is_edit:
            try:
                eff_init = int(str(existing_risk.get("Eficacia_Controles_Pct", "70%")).replace("%", "").strip())
            except:
                eff_init = 70

        lbl_eff_val = tk.Label(row6, text=f"{eff_init}%", font=("Segoe UI", 10, "bold"), bg=self.color_bg, fg="#2980B9", width=6)
        
        def on_slider_move(val):
            v = int(float(val))
            lbl_eff_val.config(text=f"{v}%")
            update_live_calc()

        scale_eff = ttk.Scale(row6, from_=0, to=100, orient=tk.HORIZONTAL, value=eff_init, command=on_slider_move)
        scale_eff.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        lbl_eff_val.pack(side=tk.LEFT)

        # 7. Estrategia y Responsable
        row7 = tk.Frame(form_frame, bg=self.color_bg)
        row7.pack(fill=tk.X, pady=4)

        tk.Label(row7, text="Estrategia:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=12, anchor="w").pack(side=tk.LEFT)
        cb_strat = ttk.Combobox(row7, values=["Mitigar", "Aceptar", "Transferir", "Evitar"], font=("Segoe UI", 9), width=12, state="readonly")
        cb_strat.set(existing_risk.get("Estrategia_Tratamiento", "Mitigar") if is_edit else "Mitigar")
        cb_strat.pack(side=tk.LEFT, padx=(0, 15))

        tk.Label(row7, text="Responsable:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=11, anchor="w").pack(side=tk.LEFT)
        e_owner = tk.Entry(row7, font=("Segoe UI", 9), width=18)
        e_owner.insert(0, existing_risk.get("Responsable", "CISO") if is_edit else "CISO")
        e_owner.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 8. Fecha Revisión
        row8 = tk.Frame(form_frame, bg=self.color_bg)
        row8.pack(fill=tk.X, pady=4)
        tk.Label(row8, text="Fecha Revisión:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=14, anchor="w").pack(side=tk.LEFT)
        e_date = tk.Entry(row8, font=("Segoe UI", 9), width=15)
        e_date.insert(0, existing_risk.get("Fecha_Revision", datetime.now().strftime("%Y-%m-%d")) if is_edit else datetime.now().strftime("%Y-%m-%d"))
        e_date.pack(side=tk.LEFT)

        # ---------------------------------------------------------------------
        # TARJETA DE CÁLCULO DINÁMICO EN VIVO (PREVIEW)
        # ---------------------------------------------------------------------
        f_calc = tk.LabelFrame(form_frame, text=" ⚡ Cálculo Dinámico ISO 27005 en Tiempo Real ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=10)
        f_calc.pack(fill=tk.X, pady=12)

        calc_grid = tk.Frame(f_calc, bg=self.color_card)
        calc_grid.pack(fill=tk.X)

        # Inherente Box
        b_inh = tk.Frame(calc_grid, bg="#FDEDEC", padx=10, pady=8, bd=1, relief=tk.SOLID)
        b_inh.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tk.Label(b_inh, text="RIESGO INHERENTE", font=("Segoe UI", 8, "bold"), bg="#FDEDEC", fg="#7F8C8D").pack()
        lbl_inh_score = tk.Label(b_inh, text="15 (Alto)", font=("Segoe UI", 13, "bold"), bg="#FDEDEC", fg="#E74C3C")
        lbl_inh_score.pack()

        # Flecha
        tk.Label(calc_grid, text="➡️", font=("Segoe UI", 16), bg=self.color_card, fg="#7F8C8D").pack(side=tk.LEFT, padx=4)

        # Residual Box
        b_res = tk.Frame(calc_grid, bg="#EAFAF1", padx=10, pady=8, bd=1, relief=tk.SOLID)
        b_res.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tk.Label(b_res, text="RIESGO RESIDUAL", font=("Segoe UI", 8, "bold"), bg="#EAFAF1", fg="#7F8C8D").pack()
        lbl_res_score = tk.Label(b_res, text="4 (Bajo)", font=("Segoe UI", 13, "bold"), bg="#EAFAF1", fg="#27AE60")
        lbl_res_score.pack()

        # Tratamiento Sugerido
        lbl_sugg = tk.Label(f_calc, text="Tratamiento Recomendado: Mitigar", font=("Segoe UI", 9, "italic"), bg=self.color_card, fg="#2C3E50")
        lbl_sugg.pack(pady=(6, 0))

        def update_live_calc(*args):
            try:
                p_str = cb_prob.get().split(" - ")[0].strip()
                p = int(p_str) if p_str.isdigit() else 3
                i_str = cb_imp.get().split(" - ")[0].strip()
                i = int(i_str) if i_str.isdigit() else 3
                eff = float(scale_eff.get())

                calc = RiskCalculator()
                res = calc.calculate_residual(p, i, eff)

                inh_txt = f"{res['inherent_score']} ({res['inherent_level']})"
                res_txt = f"{res['residual_score']} ({res['residual_level']})"
                
                lbl_inh_score.config(text=inh_txt)
                lbl_res_score.config(text=res_txt)
                lbl_sugg.config(text=f"Tratamiento Recomendado según ISO 27005: {res['treatment_strategy']}")
            except Exception as e:
                pass

        cb_prob.bind("<<ComboboxSelected>>", update_live_calc)
        cb_imp.bind("<<ComboboxSelected>>", update_live_calc)
        update_live_calc()

        # ---------------------------------------------------------------------
        # BOTONES DE ACCIÓN (GUARDAR / CANCELAR)
        # ---------------------------------------------------------------------
        btn_box = tk.Frame(modal, bg=self.color_bg, pady=10)
        btn_box.pack(fill=tk.X, side=tk.BOTTOM)

        def save_and_close():
            r_id = e_id.get().strip()
            asset_raw = cb_asset.get().strip()
            # Extraer solo ID si tiene formato ACT-XXX - Nombre
            asset_id = asset_raw.split(" - ")[0].strip() if " - " in asset_raw else asset_raw
            threat = e_threat.get().strip()
            vuln = e_vuln.get().strip()
            
            p_val_str = cb_prob.get().split(" - ")[0].strip()
            p_val = int(p_val_str) if p_val_str.isdigit() else 3
            i_val_str = cb_imp.get().split(" - ")[0].strip()
            i_val = int(i_val_str) if i_val_str.isdigit() else 3

            ctrls = e_controls.get().strip()
            eff_val = int(scale_eff.get())
            strat = cb_strat.get().strip()
            owner = e_owner.get().strip()
            date_val = e_date.get().strip()

            if not threat:
                messagebox.showwarning("Campo Obligatorio", "Por favor ingresa la Amenaza identificada.", parent=modal)
                return

            risk_payload = {
                "ID_Riesgo": r_id,
                "ID_Activo": asset_id,
                "Amenaza": threat,
                "Vulnerabilidad": vuln,
                "Probabilidad_Inherente_1a5": str(p_val),
                "Impacto_Inherente_1a5": str(i_val),
                "Controles_Aplicados": ctrls,
                "Eficacia_Controles_Pct": f"{eff_val}%",
                "Estrategia_Tratamiento": strat,
                "Responsable": owner,
                "Fecha_Revision": date_val
            }

            calc = RiskCalculator()
            saved_id = calc.save_risk(risk_payload)
            self.load_risks_table()

            # Regenerar Dashboards en segundo plano
            try:
                DashboardGenerator().generate_all()
            except:
                pass

            messagebox.showinfo("Guardado Exitoso", f"¡El riesgo {saved_id} ha sido registrado y calculado con éxito!", parent=modal)
            modal.destroy()

        tk.Button(
            btn_box,
            text="💾 Guardar Riesgo",
            font=("Segoe UI", 10, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=18,
            pady=6,
            command=save_and_close
        ).pack(side=tk.RIGHT, padx=15)

        tk.Button(
            btn_box,
            text="Cancelar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=modal.destroy
        ).pack(side=tk.RIGHT, padx=5)

    # -------------------------------------------------------------------------
    # TAB 4: DECLARACIÓN DE APLICABILIDAD SoA (ISO 27001) - ADMINISTRADOR
    # -------------------------------------------------------------------------
    def _build_tab_soa(self):
        # 1. Barra de Filtros y Búsqueda
        filter_bar = tk.Frame(self.tab_soa, bg=self.color_bg)
        filter_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(filter_bar, text="🔍 Buscar:", font=("Segoe UI", 9, "bold"), bg=self.color_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.soa_search_entry = tk.Entry(filter_bar, font=("Segoe UI", 9), width=20)
        self.soa_search_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.soa_search_entry.bind("<KeyRelease>", lambda event: self.filter_soa_table())

        tk.Label(filter_bar, text="Dominio:", font=("Segoe UI", 9, "bold"), bg=self.color_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.soa_domain_cb = ttk.Combobox(filter_bar, values=[
            "Todos los Dominios",
            "Controles Organizacionales",
            "Controles de Personas",
            "Controles Físicos",
            "Controles Tecnológicos"
        ], font=("Segoe UI", 9), width=22, state="readonly")
        self.soa_domain_cb.set("Todos los Dominios")
        self.soa_domain_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.soa_domain_cb.bind("<<ComboboxSelected>>", lambda event: self.filter_soa_table())

        tk.Label(filter_bar, text="Estado:", font=("Segoe UI", 9, "bold"), bg=self.color_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.soa_state_cb = ttk.Combobox(filter_bar, values=[
            "Todos los Estados",
            "Implementado",
            "En Proceso",
            "Planificado",
            "No Implementado",
            "No Aplica"
        ], font=("Segoe UI", 9), width=16, state="readonly")
        self.soa_state_cb.set("Todos los Estados")
        self.soa_state_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.soa_state_cb.bind("<<ComboboxSelected>>", lambda event: self.filter_soa_table())

        btn_clear_filter = tk.Button(
            filter_bar,
            text="🧹 Limpiar",
            font=("Segoe UI", 8),
            bg="#E2E8F0",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=6,
            pady=2,
            command=self.clear_soa_filters
        )
        btn_clear_filter.pack(side=tk.LEFT)

        # Contador de controles filtrados
        self.soa_count_lbl = tk.Label(filter_bar, text="93 controles", font=("Segoe UI", 9, "bold"), bg=self.color_bg, fg="#2980B9")
        self.soa_count_lbl.pack(side=tk.RIGHT, padx=5)

        # 2. Barra de Acciones Rápidas
        actions_bar = tk.Frame(self.tab_soa, bg=self.color_bg)
        actions_bar.pack(fill=tk.X, padx=10, pady=(2, 6))

        btn_edit_ctrl = tk.Button(
            actions_bar,
            text="✏️ Editar Control...",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_edit_soa_control
        )
        btn_edit_ctrl.pack(side=tk.LEFT, padx=(0, 6))

        btn_open_ctrl_evid = tk.Button(
            actions_bar,
            text="👁️ Abrir Evidencia",
            font=("Segoe UI", 9),
            bg="#34495E",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_open_soa_evidence
        )
        btn_open_ctrl_evid.pack(side=tk.LEFT, padx=(0, 6))

        tk.Label(actions_bar, text="| Acciones Rápidas:", font=("Segoe UI", 9), bg=self.color_bg, fg="#7F8C8D").pack(side=tk.LEFT, padx=4)

        btn_quick_impl = tk.Button(
            actions_bar,
            text="✅ Implementado (100%)",
            font=("Segoe UI", 8, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=3,
            command=lambda: self.action_quick_soa_status("Implementado", 100)
        )
        btn_quick_impl.pack(side=tk.LEFT, padx=3)

        btn_quick_proc = tk.Button(
            actions_bar,
            text="🔄 En Proceso (50%)",
            font=("Segoe UI", 8, "bold"),
            bg="#F39C12",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=3,
            command=lambda: self.action_quick_soa_status("En Proceso", 50)
        )
        btn_quick_proc.pack(side=tk.LEFT, padx=3)

        btn_quick_plan = tk.Button(
            actions_bar,
            text="📅 Planificado (15%)",
            font=("Segoe UI", 8),
            bg="#34495E",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=3,
            command=lambda: self.action_quick_soa_status("Planificado", 15)
        )
        btn_quick_plan.pack(side=tk.LEFT, padx=3)

        btn_quick_no_impl = tk.Button(
            actions_bar,
            text="❌ No Implementado (0%)",
            font=("Segoe UI", 8),
            bg="#C0392B",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=3,
            command=lambda: self.action_quick_soa_status("No Implementado", 0)
        )
        btn_quick_no_impl.pack(side=tk.LEFT, padx=3)

        # 3. Tabla SoA
        cols = ("Código", "Nombre del Control", "Dominio", "Aplica", "Estado", "Madurez %", "Responsable", "Evidencia")
        self.tree_soa = ttk.Treeview(self.tab_soa, columns=cols, show="headings", selectmode="browse")

        self.tree_soa.heading("Código", text="Código")
        self.tree_soa.heading("Nombre del Control", text="Nombre del Control")
        self.tree_soa.heading("Dominio", text="Dominio")
        self.tree_soa.heading("Aplica", text="Aplica")
        self.tree_soa.heading("Estado", text="Estado")
        self.tree_soa.heading("Madurez %", text="Madurez %")
        self.tree_soa.heading("Responsable", text="Responsable")
        self.tree_soa.heading("Evidencia", text="Evidencia Documental")

        self.tree_soa.column("Código", width=70, anchor="center")
        self.tree_soa.column("Nombre del Control", width=270)
        self.tree_soa.column("Dominio", width=150)
        self.tree_soa.column("Aplica", width=55, anchor="center")
        self.tree_soa.column("Estado", width=95, anchor="center")
        self.tree_soa.column("Madurez %", width=75, anchor="center")
        self.tree_soa.column("Responsable", width=130)
        self.tree_soa.column("Evidencia", width=130)

        scroll_y = ttk.Scrollbar(self.tab_soa, orient=tk.VERTICAL, command=self.tree_soa.yview)
        self.tree_soa.configure(yscrollcommand=scroll_y.set)

        self.tree_soa.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

        # Doble clic para editar
        self.tree_soa.bind("<Double-1>", lambda event: self.action_edit_soa_control())

    def clear_soa_filters(self):
        self.soa_search_entry.delete(0, tk.END)
        self.soa_domain_cb.set("Todos los Dominios")
        self.soa_state_cb.set("Todos los Estados")
        self.filter_soa_table()

    def filter_soa_table(self):
        query = self.soa_search_entry.get().strip().lower()
        domain_sel = self.soa_domain_cb.get().strip()
        state_sel = self.soa_state_cb.get().strip()

        for item in self.tree_soa.get_children():
            self.tree_soa.delete(item)

        soa_mgr = SoAManager()
        controls = soa_mgr.get_all_controls()
        count = 0

        for r in controls:
            code = r.get("Codigo_Control", "")
            name = r.get("Nombre_Control", "")
            dom = r.get("Dominio", "")
            st = r.get("Estado_Implementacion", "")
            resp = r.get("Responsable", "")

            # Filtro texto
            if query and (query not in code.lower() and query not in name.lower() and query not in resp.lower()):
                continue

            # Filtro dominio
            if domain_sel != "Todos los Dominios" and dom != domain_sel:
                continue

            # Filtro estado
            if state_sel != "Todos los Estados" and st != state_sel:
                continue

            self.tree_soa.insert("", tk.END, values=(
                code,
                name,
                dom,
                r.get("Aplica", ""),
                st,
                f"{r.get('Porcentaje_Madurez', '')}%",
                resp,
                r.get("Evidencia_Documental", "")
            ))
            count += 1

        cnt_impl = sum(1 for c in controls if c.get("Estado_Implementacion") == "Implementado")
        cnt_proc = sum(1 for c in controls if c.get("Estado_Implementacion") == "En Proceso")
        cnt_plan = sum(1 for c in controls if c.get("Estado_Implementacion") == "Planificado")
        cnt_no_impl = sum(1 for c in controls if c.get("Estado_Implementacion") == "No Implementado")
        cnt_na = sum(1 for c in controls if c.get("Estado_Implementacion") == "No Aplica")

        if query or domain_sel != "Todos los Dominios" or state_sel != "Todos los Estados":
            self.soa_count_lbl.config(text=f"Filtro: {count}/{len(controls)} | ✅ Impl: {cnt_impl} | ❌ No Impl: {cnt_no_impl}")
        else:
            self.soa_count_lbl.config(text=f"Total: {len(controls)} | ✅ Impl: {cnt_impl} | 🔄 Proc: {cnt_proc} | 📅 Plan: {cnt_plan} | ❌ No Impl: {cnt_no_impl} | ⚪ N/A: {cnt_na}")

    def load_soa_table(self):
        self.filter_soa_table()

    def action_quick_soa_status(self, status: str, maturity: int):
        selected = self.tree_soa.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Control", "Por favor selecciona uno o más controles de la tabla para aplicar el cambio rápido.")
            return

        soa_mgr = SoAManager()
        updated_codes = []
        for s in selected:
            item = self.tree_soa.item(s)
            code = item["values"][0]
            updated_codes.append(code)

        count = soa_mgr.batch_set_status(updated_codes, status, maturity)
        self.load_soa_table()
        self.load_assets_table()

        try:
            DashboardGenerator().generate_all()
        except:
            pass

        self.status_lbl.config(text=f"✅ {count} controles SoA actualizados a '{status}' ({maturity}%) ({datetime.now().strftime('%H:%M:%S')})", fg="#27AE60")

    def action_open_soa_evidence(self):
        selected = self.tree_soa.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Control", "Por favor selecciona un control de la tabla para ver su evidencia documental.")
            return

        item = self.tree_soa.item(selected[0])
        code = item["values"][0]
        name = item["values"][1]
        evid = str(item["values"][7]).strip() if len(item["values"]) > 7 else ""

        if not evid:
            messagebox.showinfo("Sin Evidencia", f"El control {code} no tiene una evidencia documental registrada.")
            return

        if evid.startswith("http://") or evid.startswith("https://") or evid.startswith("www."):
            webbrowser.open(evid)
        elif os.path.exists(evid):
            try:
                os.startfile(os.path.abspath(evid))
            except Exception as ex:
                messagebox.showerror("Error al abrir archivo", f"No se pudo abrir el archivo:\n{ex}")
        else:
            # Check relative paths
            alt_paths = [
                os.path.join(os.getcwd(), evid),
                os.path.join(os.path.expanduser("~"), "Google Drive", evid),
                os.path.join(os.path.expanduser("~"), "OneDrive", evid),
            ]
            found = False
            for p in alt_paths:
                if os.path.exists(p):
                    try:
                        os.startfile(os.path.abspath(p))
                        found = True
                        break
                    except:
                        pass
            if not found:
                messagebox.showinfo(
                    "Evidencia Documental",
                    f"Control: {code} - {name}\n\n"
                    f"Referencia registrada: {evid}\n\n"
                    "💡 Para vincular y abrir directamente el archivo local o de Google Drive:\n"
                    "Haz doble clic en el control o presiona '✏️ Editar Control...' y utiliza el botón '📁 Examinar...'."
                )

    def action_edit_soa_control(self):
        selected = self.tree_soa.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Control", "Por favor selecciona un control de la tabla para editar.")
            return

        item = self.tree_soa.item(selected[0])
        code = item["values"][0]

        soa_mgr = SoAManager()
        controls = soa_mgr.get_all_controls()
        target_ctrl = None
        for c in controls:
            if c.get("Codigo_Control") == code:
                target_ctrl = c
                break

        if not target_ctrl:
            messagebox.showerror("Error", f"No se encontró el control {code}.")
            return

        self._open_soa_modal(target_ctrl)

    def _open_soa_modal(self, ctrl: dict):
        modal = tk.Toplevel(self)
        code = ctrl.get("Codigo_Control", "")
        modal.title(f"✏️ Administrar Control ISO 27001:2022 - {code}")
        modal.geometry("700x590")
        modal.minsize(660, 540)
        modal.configure(bg=self.color_bg)
        modal.grab_set()

        # Header modal
        hdr = tk.Frame(modal, bg=self.color_primary, padx=15, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text=f"📜 Control {code}: {ctrl.get('Nombre_Control', '')}",
            font=("Segoe UI", 11, "bold"),
            bg=self.color_primary,
            fg="white"
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text=f"Dominio: {ctrl.get('Dominio', '')} | Declaración de Aplicabilidad (SoA)",
            font=("Segoe UI", 8),
            bg=self.color_primary,
            fg="#D1D5DB"
        ).pack(anchor="w")

        form_frame = tk.Frame(modal, bg=self.color_bg, padx=15, pady=12)
        form_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Aplica y Estado
        row1 = tk.Frame(form_frame, bg=self.color_bg)
        row1.pack(fill=tk.X, pady=6)

        tk.Label(row1, text="¿Aplica al SGSI?:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=15, anchor="w").pack(side=tk.LEFT)
        cb_aplica = ttk.Combobox(row1, values=["SI", "NO"], font=("Segoe UI", 9), width=8, state="readonly")
        cb_aplica.set(ctrl.get("Aplica", "SI"))
        cb_aplica.pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(row1, text="Estado de Implementación:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=22, anchor="w").pack(side=tk.LEFT)
        cb_state = ttk.Combobox(row1, values=["Implementado", "En Proceso", "Planificado", "No Implementado", "No Aplica"], font=("Segoe UI", 9), width=16, state="readonly")
        cb_state.set(ctrl.get("Estado_Implementacion", "No Implementado"))
        cb_state.pack(side=tk.LEFT)

        # 2. Madurez % con Slider
        row2 = tk.Frame(form_frame, bg=self.color_bg)
        row2.pack(fill=tk.X, pady=6)

        tk.Label(row2, text="Porcentaje Madurez:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=16, anchor="w").pack(side=tk.LEFT)
        
        mad_init = 0
        try:
            mad_init = int(float(str(ctrl.get("Porcentaje_Madurez", "0")).replace("%", "").strip()))
        except:
            mad_init = 0

        lbl_mad_val = tk.Label(row2, text=f"{mad_init}%", font=("Segoe UI", 10, "bold"), bg=self.color_bg, fg="#2980B9", width=6)

        def on_mad_slider(val):
            lbl_mad_val.config(text=f"{int(float(val))}%")

        scale_mad = ttk.Scale(row2, from_=0, to=100, orient=tk.HORIZONTAL, value=mad_init, command=on_mad_slider)
        scale_mad.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        lbl_mad_val.pack(side=tk.LEFT)

        # Sincronizar estado con slider automáticamente
        def on_state_change(event):
            st = cb_state.get()
            if st == "Implementado":
                scale_mad.set(100)
                cb_aplica.set("SI")
            elif st == "En Proceso":
                scale_mad.set(50)
                cb_aplica.set("SI")
            elif st == "Planificado":
                scale_mad.set(15)
                cb_aplica.set("SI")
            elif st == "No Implementado":
                scale_mad.set(0)
                cb_aplica.set("SI")
            elif st == "No Aplica":
                scale_mad.set(0)
                cb_aplica.set("NO")
            lbl_mad_val.config(text=f"{int(scale_mad.get())}%")

        cb_state.bind("<<ComboboxSelected>>", on_state_change)

        # 3. Responsable
        row3 = tk.Frame(form_frame, bg=self.color_bg)
        row3.pack(fill=tk.X, pady=6)
        tk.Label(row3, text="Responsable / Custodio:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        e_resp = tk.Entry(row3, font=("Segoe UI", 9))
        e_resp.insert(0, ctrl.get("Responsable", "Equipo de Seguridad / CISO"))
        e_resp.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 4. Justificación de Inclusión / Exclusión
        row4 = tk.Frame(form_frame, bg=self.color_bg)
        row4.pack(fill=tk.X, pady=6)
        tk.Label(row4, text="Justificación SoA:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        e_just = tk.Entry(row4, font=("Segoe UI", 9))
        e_just.insert(0, ctrl.get("Justificacion_Inclusion_Exclusion", "Requisito mandatorio de gestion y reduccion de riesgos"))
        e_just.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 5. Evidencia Documental
        row5 = tk.Frame(form_frame, bg=self.color_bg)
        row5.pack(fill=tk.X, pady=6)
        tk.Label(row5, text="Evidencia Documental:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        e_evid = tk.Entry(row5, font=("Segoe UI", 9))
        e_evid.insert(0, ctrl.get("Evidencia_Documental", f"Doc-Ref-{code.replace('.', '_')}.pdf"))
        e_evid.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        def browse_evidence():
            file_selected = filedialog.askopenfilename(
                title=f"Seleccionar Archivo de Evidencia para {code}",
                filetypes=[
                    ("Documentos y Evidencias", "*.pdf;*.docx;*.doc;*.xlsx;*.xls;*.pptx;*.txt;*.png;*.jpg;*.jpeg;*.zip;*.csv"),
                    ("Archivos PDF (*.pdf)", "*.pdf"),
                    ("Documentos Office (*.docx, *.xlsx)", "*.docx;*.xlsx;*.pptx"),
                    ("Todos los archivos (*.*)", "*.*")
                ],
                parent=modal
            )
            if file_selected:
                e_evid.delete(0, tk.END)
                e_evid.insert(0, file_selected)

        def open_evidence():
            path_or_url = e_evid.get().strip()
            if not path_or_url:
                messagebox.showwarning("Sin Evidencia", "El campo de evidencia documental está vacío.", parent=modal)
                return
            
            if path_or_url.startswith("http://") or path_or_url.startswith("https://") or path_or_url.startswith("www."):
                webbrowser.open(path_or_url)
            elif os.path.exists(path_or_url):
                try:
                    os.startfile(os.path.abspath(path_or_url))
                except Exception as ex:
                    messagebox.showerror("Error al abrir", f"No se pudo abrir el archivo:\n{ex}", parent=modal)
            else:
                alt_paths = [
                    os.path.join(os.getcwd(), path_or_url),
                    os.path.join(os.path.expanduser("~"), "Google Drive", path_or_url),
                    os.path.join(os.path.expanduser("~"), "OneDrive", path_or_url),
                ]
                found = False
                for p in alt_paths:
                    if os.path.exists(p):
                        try:
                            os.startfile(os.path.abspath(p))
                            found = True
                            break
                        except:
                            pass
                if not found:
                    messagebox.showinfo(
                        "Información de Evidencia",
                        f"Referencia de Evidencia:\n{path_or_url}\n\n"
                        "💡 Tip: Para abrir el archivo directamente con este botón, presiona '📁 Examinar...' "
                        "y selecciona el archivo ubicado en tu carpeta sincronizada de Google Drive o disco local.",
                        parent=modal
                    )

        btn_browse_evid = tk.Button(
            row5,
            text="📁 Examinar...",
            font=("Segoe UI", 8, "bold"),
            bg=self.color_accent,
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=2,
            command=browse_evidence
        )
        btn_browse_evid.pack(side=tk.LEFT, padx=(0, 4))

        btn_open_evid = tk.Button(
            row5,
            text="👁️ Abrir",
            font=("Segoe UI", 8),
            bg="#34495E",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=2,
            command=open_evidence
        )
        btn_open_evid.pack(side=tk.LEFT)

        # 6. Tarjeta de Resumen SoA
        f_info = tk.LabelFrame(form_frame, text=" ℹ️ Directriz de Cumplimiento ISO/IEC 27001:2022 ", font=("Segoe UI", 8, "bold"), bg=self.color_card, padx=10, pady=8)
        f_info.pack(fill=tk.X, pady=10)
        tk.Label(
            f_info,
            text=f"El control {code} pertenece a la categoría de {ctrl.get('Dominio', '')}.\n"
                 f"Al cambiar el estado o la madurez, los Dashboards CISO y Dirección se actualizarán automáticamente en tiempo real.",
            font=("Segoe UI", 8),
            bg=self.color_card,
            fg="#555555",
            justify=tk.LEFT
        ).pack(anchor="w")

        # Botones Guardar / Cancelar
        btn_box = tk.Frame(modal, bg=self.color_bg, pady=10)
        btn_box.pack(fill=tk.X, side=tk.BOTTOM)

        def save_soa_changes():
            aplica = cb_aplica.get().strip()
            estado = cb_state.get().strip()
            madurez = int(scale_mad.get())
            responsable = e_resp.get().strip()
            justificacion = e_just.get().strip()
            evidencia = e_evid.get().strip()

            updated = {
                "Aplica": aplica,
                "Estado_Implementacion": estado,
                "Porcentaje_Madurez": str(madurez),
                "Responsable": responsable,
                "Justificacion_Inclusion_Exclusion": justificacion,
                "Evidencia_Documental": evidencia
            }

            soa_mgr = SoAManager()
            if soa_mgr.update_control(code, updated):
                self.load_soa_table()
                try:
                    DashboardGenerator().generate_all()
                except:
                    pass
                messagebox.showinfo("Control Actualizado", f"¡El control {code} ha sido actualizado correctamente!", parent=modal)
                modal.destroy()
            else:
                messagebox.showerror("Error", "No se pudo actualizar el control.", parent=modal)

        tk.Button(
            btn_box,
            text="💾 Guardar Cambios",
            font=("Segoe UI", 10, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=18,
            pady=6,
            command=save_soa_changes
        ).pack(side=tk.RIGHT, padx=15)

        tk.Button(
            btn_box,
            text="Cancelar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=modal.destroy
        ).pack(side=tk.RIGHT, padx=5)

    # -------------------------------------------------------------------------
    # ACCIONES DE DASHBOARDS EN VIVO
    # -------------------------------------------------------------------------
    def action_open_ciso_dashboard(self):
        self._auto_start_live_server()
        webbrowser.open(f"http://localhost:{self.live_server_port}/ciso")

    def action_open_direccion_dashboard(self):
        self._auto_start_live_server()
        webbrowser.open(f"http://localhost:{self.live_server_port}/direccion")

    # -------------------------------------------------------------------------
    # MODAL SINCRONIZACIÓN GOOGLE SHEETS
    # -------------------------------------------------------------------------
    def action_open_gsheets_modal(self):
        modal = tk.Toplevel(self)
        modal.title("☁️ Sincronización con Google Sheets & Drive")
        modal.geometry("680x560")
        modal.minsize(620, 520)
        modal.configure(bg=self.color_bg)
        modal.grab_set()

        # Header modal
        hdr = tk.Frame(modal, bg=self.color_primary, padx=15, pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text="☁️ Traspaso de Datos a Google Sheets (Acceso Remoto)",
            font=("Segoe UI", 12, "bold"),
            bg=self.color_primary,
            fg="white"
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text="Sincroniza tus Activos, Matriz de Riesgos ISO 27005, SoA ISO 27001 e Incidentes SOC a la nube.",
            font=("Segoe UI", 8),
            bg=self.color_primary,
            fg="#D1D5DB"
        ).pack(anchor="w", pady=(2, 0))

        content = tk.Frame(modal, bg=self.color_bg, padx=15, pady=10)
        content.pack(fill=tk.BOTH, expand=True)

        # Opción 1: Exportación Inmediata de CSVs (100% Garantizada y sin permisos de Google)
        f_csv = tk.LabelFrame(content, text=" ⭐ Opción Recomendada: Carga Directa en Google Sheets (Sin Scripts ni Errores) ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=12)
        f_csv.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            f_csv,
            text="Los 4 archivos CSV con toda la información (Activos, Riesgos ISO 27005, SoA ISO 27001 e Incidentes SOC) están listos y actualizados en tu equipo.\n"
                 "Solo haz clic en 'Abrir Carpeta', y en tu Google Sheet ve a Archivo > Importar > Subir y arrástralos:",
            font=("Segoe UI", 8),
            bg=self.color_card,
            fg="#2C3E50",
            justify=tk.LEFT
        ).pack(anchor="w", pady=(0, 8))

        def open_drive_folder():
            folder = os.path.abspath("sync_drive")
            os.makedirs(folder, exist_ok=True)
            os.startfile(folder)

        def do_local_sync():
            mgr = GSheetsManager(mode="local_sync")
            res = mgr.sync_all_framework_data()
            self.refresh_all_data()
            open_drive_folder()
            messagebox.showinfo("Archivos Listos", f"¡Las 4 matrices han sido actualizadas y la carpeta se abrió en tu pantalla!\n\nSolo arrastra los archivos a tu Google Sheet en:\nArchivo > Importar > Subir.")

        btn_box_csv = tk.Frame(f_csv, bg=self.color_card)
        btn_box_csv.pack(fill=tk.X)

        tk.Button(
            btn_box_csv,
            text="📁 1. Abrir Carpeta con los 4 CSVs Listos",
            font=("Segoe UI", 10, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=do_local_sync
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(
            btn_box_csv,
            text="🌐 2. Abrir Google Sheet 'SGSI'",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=lambda: webbrowser.open("https://docs.google.com/spreadsheets/u/0/")
        ).pack(side=tk.LEFT, padx=6)

        # Opción 2: Webhook Google Apps Script
        f1 = tk.LabelFrame(content, text=" Opción Alternativa: Webhook de Google Apps Script ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=10)
        f1.pack(fill=tk.X)

        cfg = GSheetsManager.get_saved_config()
        saved_url = cfg.get("webhook_url", "")

        url_entry_box = tk.Frame(f1, bg=self.color_card)
        url_entry_box.pack(fill=tk.X, pady=(4, 6))

        url_entry = tk.Entry(url_entry_box, font=("Consolas", 9), relief=tk.SOLID, bd=1)
        url_entry.insert(0, saved_url)
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6), ipady=3)

        lbl_status_sync = tk.Label(f1, text="Estado: Listo para conectar", font=("Segoe UI", 8, "italic"), bg=self.color_card, fg="#7F8C8D")

        def test_webhook_connection():
            webhook_url = url_entry.get().strip()
            if not webhook_url:
                messagebox.showwarning("URL requerida", "Por favor introduce la URL de la Web App de Google Apps Script.")
                return

            lbl_status_sync.config(text="⏳ Probando conexión con Google...", fg="#2980B9")
            modal.update()

            def run_test_thread():
                mgr = GSheetsManager(mode="local_sync")
                res = mgr.test_connection(webhook_url)
                if res.get("status") == "success":
                    sheet_name = res.get("sheet_name", "SGSI")
                    self.after(0, lambda: [
                        lbl_status_sync.config(text=f"🟢 {res.get('message')}", fg="#27AE60"),
                        messagebox.showinfo("Conexión Exitosa", f"¡Conexión verificada con Google Sheets!\n\nHoja detectada: {sheet_name}")
                    ])
                else:
                    err = res.get("message", "Error desconocido")
                    self.after(0, lambda: [
                        lbl_status_sync.config(text=f"❌ {err}", fg="#E74C3C"),
                        messagebox.showerror("Fallo de Conexión", f"No se pudo conectar con la Web App:\n{err}")
                    ])

            threading.Thread(target=run_test_thread, daemon=True).start()

        tk.Button(
            url_entry_box,
            text="🧪 Probar",
            font=("Segoe UI", 8),
            bg="#E2E8F0",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=8,
            pady=3,
            command=test_webhook_connection
        ).pack(side=tk.RIGHT)

        def do_webhook_sync():
            webhook_url = url_entry.get().strip()
            if not webhook_url:
                messagebox.showwarning("URL requerida", "Por favor introduce la URL de la Web App de Google Apps Script.")
                return

            lbl_status_sync.config(text="⏳ Enviando matrices a Google Sheets...", fg="#2980B9")
            modal.update()

            def run_sync_thread():
                mgr = GSheetsManager(mode="local_sync")
                res = mgr.sync_to_google_sheets_webhook(webhook_url)
                if res.get("status") == "success":
                    rows = res.get("rows_synced", {})
                    self.after(0, lambda: [
                        lbl_status_sync.config(text="✅ ¡Sincronización con Google Sheets exitosa!", fg="#27AE60"),
                        messagebox.showinfo("Google Sheets Sincronizado", "¡Traspaso completado con éxito a tu Google Sheet!")
                    ])
                else:
                    err = res.get("message", "Error desconocido")
                    self.after(0, lambda: [
                        lbl_status_sync.config(text=f"❌ Error: {err[:50]}...", fg="#E74C3C"),
                        messagebox.showerror("Error en Sincronización", f"No se pudo completar el traspaso:\n{err}")
                    ])

            threading.Thread(target=run_sync_thread, daemon=True).start()

        btn_box_wh = tk.Frame(f1, bg=self.color_card)
        btn_box_wh.pack(fill=tk.X, pady=(2, 0))

        tk.Button(
            btn_box_wh,
            text="🚀 Sincronizar vía Webhook",
            font=("Segoe UI", 9, "bold"),
            bg="#34495E",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=do_webhook_sync
        ).pack(side=tk.LEFT, padx=(0, 5))

        lbl_status_sync.pack(anchor="w", pady=(4, 0))

        # Botón Cerrar
        tk.Button(
            modal,
            text="Cerrar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=15,
            pady=4,
            command=modal.destroy
        ).pack(side=tk.BOTTOM, pady=10)


    # =========================================================================
    # TAB 5: INVENTARIO DE ACTIVOS DE INFORMACIÓN (ISO 27001 CONTROL 5.9 & LEY 21.663)
    # =========================================================================
    def _build_tab_assets(self):
        # 1. Barra de Filtros
        filter_bar = tk.Frame(self.tab_assets, bg=self.color_bg)
        filter_bar.pack(fill=tk.X, padx=10, pady=(6, 2))

        tk.Label(filter_bar, text="🔍 Buscar:", font=("Segoe UI", 9, "bold"), bg=self.color_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.asset_search_entry = tk.Entry(filter_bar, font=("Segoe UI", 9), width=18)
        self.asset_search_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.asset_search_entry.bind("<KeyRelease>", lambda event: self.filter_assets_table())

        tk.Label(filter_bar, text="Tipo de Activo:", font=("Segoe UI", 9, "bold"), bg=self.color_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.asset_type_cb = ttk.Combobox(filter_bar, values=[
            "Todos los Tipos",
            "Informacion / Base de Datos",
            "Hardware / Servidor Virtual",
            "Hardware / Endpoint",
            "Software / Repositorio",
            "Red / Comunicaciones",
            "Servicio / Almacenamiento",
            "Instalaciones / Datacenter",
            "Personas / Roles Clave"
        ], font=("Segoe UI", 9), width=22, state="readonly")
        self.asset_type_cb.set("Todos los Tipos")
        self.asset_type_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.asset_type_cb.bind("<<ComboboxSelected>>", lambda event: self.filter_assets_table())

        tk.Label(filter_bar, text="Criticidad:", font=("Segoe UI", 9, "bold"), bg=self.color_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.asset_crit_cb = ttk.Combobox(filter_bar, values=[
            "Todas las Criticidades",
            "Crítico",
            "Alto",
            "Medio",
            "Bajo"
        ], font=("Segoe UI", 9), width=16, state="readonly")
        self.asset_crit_cb.set("Todas las Criticidades")
        self.asset_crit_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.asset_crit_cb.bind("<<ComboboxSelected>>", lambda event: self.filter_assets_table())

        btn_clear = tk.Button(
            filter_bar,
            text="🧹 Limpiar",
            font=("Segoe UI", 8),
            bg="#E2E8F0",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=6,
            pady=2,
            command=self.clear_assets_filters
        )
        btn_clear.pack(side=tk.LEFT)

        self.assets_count_lbl = tk.Label(filter_bar, text="0 activos", font=("Segoe UI", 9, "bold"), bg=self.color_bg, fg="#2980B9")
        self.assets_count_lbl.pack(side=tk.RIGHT, padx=5)

        # 2. Barra de Acciones
        actions_bar = tk.Frame(self.tab_assets, bg=self.color_bg)
        actions_bar.pack(fill=tk.X, padx=10, pady=(2, 6))

        btn_new = tk.Button(
            actions_bar,
            text="➕ Nuevo Activo...",
            font=("Segoe UI", 9, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_new_asset
        )
        btn_new.pack(side=tk.LEFT, padx=(0, 6))

        btn_edit = tk.Button(
            actions_bar,
            text="✏️ Editar Activo...",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_edit_asset
        )
        btn_edit.pack(side=tk.LEFT, padx=(0, 6))

        btn_del = tk.Button(
            actions_bar,
            text="🗑️ Eliminar",
            font=("Segoe UI", 9),
            bg="#E74C3C",
            fg="white",
            relief=tk.FLAT,
            padx=8,
            pady=4,
            command=self.action_delete_asset
        )
        btn_del.pack(side=tk.LEFT, padx=(0, 6))

        # 3. Tabla de Activos
        cols = ("ID", "Nombre del Activo", "Tipo", "Propietario (Owner)", "Custodio", "Ubicación", "C (1-5)", "I (1-5)", "A (1-5)", "Criticidad", "Nivel", "Estado")
        self.tree_assets = ttk.Treeview(self.tab_assets, columns=cols, show="headings", selectmode="browse")

        self.tree_assets.heading("ID", text="ID")
        self.tree_assets.heading("Nombre del Activo", text="Nombre del Activo de Información")
        self.tree_assets.heading("Tipo", text="Tipo de Activo")
        self.tree_assets.heading("Propietario (Owner)", text="Propietario (Asset Owner)")
        self.tree_assets.heading("Custodio", text="Custodio Técnico")
        self.tree_assets.heading("Ubicación", text="Ubicación Física/Lógica")
        self.tree_assets.heading("C (1-5)", text="C")
        self.tree_assets.heading("I (1-5)", text="I")
        self.tree_assets.heading("A (1-5)", text="A")
        self.tree_assets.heading("Criticidad", text="Score (3-15)")
        self.tree_assets.heading("Nivel", text="Nivel Criticidad")
        self.tree_assets.heading("Estado", text="Estado")

        self.tree_assets.column("ID", width=65, anchor="center")
        self.tree_assets.column("Nombre del Activo", width=220)
        self.tree_assets.column("Tipo", width=150)
        self.tree_assets.column("Propietario (Owner)", width=130)
        self.tree_assets.column("Custodio", width=120)
        self.tree_assets.column("Ubicación", width=130)
        self.tree_assets.column("C (1-5)", width=35, anchor="center")
        self.tree_assets.column("I (1-5)", width=35, anchor="center")
        self.tree_assets.column("A (1-5)", width=35, anchor="center")
        self.tree_assets.column("Criticidad", width=75, anchor="center")
        self.tree_assets.column("Nivel", width=90, anchor="center")
        self.tree_assets.column("Estado", width=75, anchor="center")

        scroll_y = ttk.Scrollbar(self.tab_assets, orient=tk.VERTICAL, command=self.tree_assets.yview)
        self.tree_assets.configure(yscrollcommand=scroll_y.set)

        self.tree_assets.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

        self.tree_assets.bind("<Double-1>", lambda event: self.action_edit_asset())
        self.load_assets_table()

    def clear_assets_filters(self):
        self.asset_search_entry.delete(0, tk.END)
        self.asset_type_cb.set("Todos los Tipos")
        self.asset_crit_cb.set("Todas las Criticidades")
        self.filter_assets_table()

    def filter_assets_table(self):
        query = self.asset_search_entry.get().strip().lower()
        type_sel = self.asset_type_cb.get().strip()
        crit_sel = self.asset_crit_cb.get().strip()

        for item in self.tree_assets.get_children():
            self.tree_assets.delete(item)

        asset_mgr = AssetManager()
        assets = asset_mgr.get_all_assets()
        count = 0

        for a in assets:
            aid = a.get("ID_Activo", "")
            name = a.get("Nombre_Activo", "")
            atype = a.get("Tipo_Activo", "")
            owner = a.get("Propietario", "")
            custodian = a.get("Custodio", "")
            loc = a.get("Ubicacion", "")
            c = a.get("Confidencialidad_1a5", "3")
            i = a.get("Integridad_1a5", "3")
            dis = a.get("Disponibilidad_1a5", "3")
            score = a.get("Criticidad_Calculada", "9")
            nivel = a.get("Nivel_Criticidad", "Medio")
            st = a.get("Estado", "Activo")

            # Filtro texto
            if query and (query not in aid.lower() and query not in name.lower() and query not in owner.lower() and query not in custodian.lower() and query not in loc.lower()):
                continue

            # Filtro tipo
            if type_sel != "Todos los Tipos" and atype != type_sel:
                continue

            # Filtro criticidad
            if crit_sel != "Todas las Criticidades":
                clean_crit = crit_sel.lower().replace("í", "i")
                clean_nivel = nivel.lower().replace("í", "i")
                if clean_crit not in clean_nivel:
                    continue

            self.tree_assets.insert("", tk.END, values=(
                aid, name, atype, owner, custodian, loc, c, i, dis, score, nivel, st
            ))
            count += 1

        crit_c = sum(1 for x in assets if "crit" in x.get("Nivel_Criticidad", "").lower())
        alto_c = sum(1 for x in assets if "alt" in x.get("Nivel_Criticidad", "").lower())
        med_c = sum(1 for x in assets if "med" in x.get("Nivel_Criticidad", "").lower())
        baj_c = sum(1 for x in assets if "baj" in x.get("Nivel_Criticidad", "").lower())

        if query or type_sel != "Todos los Tipos" or crit_sel != "Todas las Criticidades":
            self.assets_count_lbl.config(text=f"Filtro: {count}/{len(assets)} | 🔴 Críticos: {crit_c} | 🟠 Altos: {alto_c}")
        else:
            self.assets_count_lbl.config(text=f"Total: {len(assets)} | 🔴 Críticos: {crit_c} | 🟠 Altos: {alto_c} | 🟡 Medios: {med_c} | 🟢 Bajos: {baj_c}")

    def load_assets_table(self):
        if hasattr(self, 'tree_assets'):
            self.filter_assets_table()

    def action_new_asset(self):
        self._open_asset_modal({}, is_new=True)

    def action_edit_asset(self):
        selected = self.tree_assets.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Activo", "Por favor selecciona un activo de la tabla para editar.")
            return

        item = self.tree_assets.item(selected[0])
        aid = item["values"][0]

        asset_mgr = AssetManager()
        assets = asset_mgr.get_all_assets()
        target = None
        for a in assets:
            if a.get("ID_Activo") == aid:
                target = a
                break

        if not target:
            messagebox.showerror("Error", f"No se encontró el activo {aid}.")
            return

        self._open_asset_modal(target, is_new=False)

    def action_delete_asset(self):
        selected = self.tree_assets.selection()
        if not selected:
            messagebox.showwarning("Seleccionar Activo", "Por favor selecciona un activo para eliminar.")
            return

        item = self.tree_assets.item(selected[0])
        aid = item["values"][0]
        name = item["values"][1]

        if messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que deseas eliminar el activo '{aid}: {name}'?\nEsta acción actualizará los inventarios y dashboards."):
            asset_mgr = AssetManager()
            if asset_mgr.delete_asset(aid):
                self.load_assets_table()
                try:
                    DashboardGenerator().generate_all()
                except:
                    pass
                self.status_lbl.config(text=f"🗑️ Activo {aid} eliminado correctamente ({datetime.now().strftime('%H:%M:%S')})", fg="#E74C3C")
                messagebox.showinfo("Activo Eliminado", f"El activo {aid} ha sido eliminado.")

    def _open_asset_modal(self, asset: dict, is_new: bool = False):
        modal = tk.Toplevel(self)
        aid = asset.get("ID_Activo", "Nuevo")
        modal.title(f"{'➕ Registrar Nuevo Activo de Información' if is_new else f'✏️ Administrar Activo - {aid}'}")
        modal.geometry("690x620")
        modal.minsize(650, 580)
        modal.configure(bg=self.color_bg)
        modal.grab_set()

        hdr = tk.Frame(modal, bg=self.color_primary, padx=15, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text=f"🏢 {'Registro de Nuevo Activo' if is_new else f'Activo {aid}: {asset.get('Nombre_Activo', '')}'}",
            font=("Segoe UI", 11, "bold"),
            bg=self.color_primary,
            fg="white"
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text="Cumplimiento ISO/IEC 27001:2022 Control 5.9 • Ley Marco de Ciberseguridad N° 21.663 • Ley N° 19.628",
            font=("Segoe UI", 8),
            bg=self.color_primary,
            fg="#D1D5DB"
        ).pack(anchor="w")

        form = tk.Frame(modal, bg=self.color_bg, padx=15, pady=10)
        form.pack(fill=tk.BOTH, expand=True)

        # 1. Nombre
        r1 = tk.Frame(form, bg=self.color_bg)
        r1.pack(fill=tk.X, pady=4)
        tk.Label(r1, text="Nombre del Activo:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        e_name = tk.Entry(r1, font=("Segoe UI", 9))
        e_name.insert(0, asset.get("Nombre_Activo", ""))
        e_name.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 2. Tipo y Estado
        r2 = tk.Frame(form, bg=self.color_bg)
        r2.pack(fill=tk.X, pady=4)
        tk.Label(r2, text="Tipo de Activo:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        cb_type = ttk.Combobox(r2, values=[
            "Informacion / Base de Datos",
            "Hardware / Servidor Virtual",
            "Hardware / Endpoint",
            "Software / Repositorio",
            "Red / Comunicaciones",
            "Servicio / Almacenamiento",
            "Instalaciones / Datacenter",
            "Personas / Roles Clave"
        ], font=("Segoe UI", 9), width=24, state="readonly")
        cb_type.set(asset.get("Tipo_Activo", "Informacion / Base de Datos"))
        cb_type.pack(side=tk.LEFT, padx=(0, 15))

        tk.Label(r2, text="Estado:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=8, anchor="w").pack(side=tk.LEFT)
        cb_st = ttk.Combobox(r2, values=["Activo", "En Mantenimiento", "Retirado / Decomisado"], font=("Segoe UI", 9), width=15, state="readonly")
        cb_st.set(asset.get("Estado", "Activo"))
        cb_st.pack(side=tk.LEFT)

        # 3. Propietario (Owner) y Custodio
        r3 = tk.Frame(form, bg=self.color_bg)
        r3.pack(fill=tk.X, pady=4)
        tk.Label(r3, text="Propietario (Owner):", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        e_owner = tk.Entry(r3, font=("Segoe UI", 9), width=24)
        e_owner.insert(0, asset.get("Propietario", "CISO / Jefatura de Área"))
        e_owner.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(r3, text="Custodio:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=9, anchor="w").pack(side=tk.LEFT)
        e_cust = tk.Entry(r3, font=("Segoe UI", 9))
        e_cust.insert(0, asset.get("Custodio", "Administrador de Sistemas / DBA"))
        e_cust.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 4. Ubicación
        r4 = tk.Frame(form, bg=self.color_bg)
        r4.pack(fill=tk.X, pady=4)
        tk.Label(r4, text="Ubicación Física/Lógica:", font=("Segoe UI", 9, "bold"), bg=self.color_bg, width=18, anchor="w").pack(side=tk.LEFT)
        e_loc = tk.Entry(r4, font=("Segoe UI", 9))
        e_loc.insert(0, asset.get("Ubicacion", "Datacenter SERMIG / Google Cloud"))
        e_loc.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 5. Marco CIA (Confidencialidad, Integridad, Disponibilidad)
        f_cia = tk.LabelFrame(form, text=" 🛡️ Valoración de Seguridad Tríada CIA (Escala 1 a 5) ", font=("Segoe UI", 9, "bold"), bg=self.color_card, padx=12, pady=8)
        f_cia.pack(fill=tk.X, pady=8)

        # C
        r_c = tk.Frame(f_cia, bg=self.color_card)
        r_c.pack(fill=tk.X, pady=3)
        tk.Label(r_c, text="Confidencialidad (C):", font=("Segoe UI", 8, "bold"), bg=self.color_card, width=18, anchor="w").pack(side=tk.LEFT)
        lbl_c_val = tk.Label(r_c, text=str(asset.get("Confidencialidad_1a5", 3)), font=("Segoe UI", 9, "bold"), bg=self.color_card, fg="#8E44AD", width=3)
        s_c = ttk.Scale(r_c, from_=1, to=5, orient=tk.HORIZONTAL, value=int(asset.get("Confidencialidad_1a5", 3)), command=lambda v: [lbl_c_val.config(text=str(int(float(v)))), recalc_badge()])
        s_c.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        lbl_c_val.pack(side=tk.LEFT)

        # I
        r_i = tk.Frame(f_cia, bg=self.color_card)
        r_i.pack(fill=tk.X, pady=3)
        tk.Label(r_i, text="Integridad (I):", font=("Segoe UI", 8, "bold"), bg=self.color_card, width=18, anchor="w").pack(side=tk.LEFT)
        lbl_i_val = tk.Label(r_i, text=str(asset.get("Integridad_1a5", 3)), font=("Segoe UI", 9, "bold"), bg=self.color_card, fg="#2980B9", width=3)
        s_i = ttk.Scale(r_i, from_=1, to=5, orient=tk.HORIZONTAL, value=int(asset.get("Integridad_1a5", 3)), command=lambda v: [lbl_i_val.config(text=str(int(float(v)))), recalc_badge()])
        s_i.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        lbl_i_val.pack(side=tk.LEFT)

        # A
        r_a = tk.Frame(f_cia, bg=self.color_card)
        r_a.pack(fill=tk.X, pady=3)
        tk.Label(r_a, text="Disponibilidad (A):", font=("Segoe UI", 8, "bold"), bg=self.color_card, width=18, anchor="w").pack(side=tk.LEFT)
        lbl_a_val = tk.Label(r_a, text=str(asset.get("Disponibilidad_1a5", 3)), font=("Segoe UI", 9, "bold"), bg=self.color_card, fg="#27AE60", width=3)
        s_a = ttk.Scale(r_a, from_=1, to=5, orient=tk.HORIZONTAL, value=int(asset.get("Disponibilidad_1a5", 3)), command=lambda v: [lbl_a_val.config(text=str(int(float(v)))), recalc_badge()])
        s_a.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        lbl_a_val.pack(side=tk.LEFT)

        # Resultado Criticidad
        r_res = tk.Frame(f_cia, bg=self.color_card)
        r_res.pack(fill=tk.X, pady=(6, 2))
        tk.Label(r_res, text="Criticidad Calculada:", font=("Segoe UI", 9, "bold"), bg=self.color_card).pack(side=tk.LEFT)
        lbl_score_badge = tk.Label(r_res, text="Score: 9 (Medio)", font=("Segoe UI", 9, "bold"), bg="#F39C12", fg="white", padx=8, pady=2)
        lbl_score_badge.pack(side=tk.LEFT, padx=10)

        def recalc_badge():
            c = int(s_c.get())
            i = int(s_i.get())
            a = int(s_a.get())
            score, nivel = AssetManager.calculate_criticality(c, i, a)
            color = "#DC2626" if nivel == "Critico" else "#EA580C" if nivel == "Alto" else "#F59E0B" if nivel == "Medio" else "#10B981"
            lbl_score_badge.config(text=f"Score: {score}/15 • Nivel: {nivel.upper()}", bg=color)

        recalc_badge()

        # Botones
        btn_box = tk.Frame(modal, bg=self.color_bg, pady=10)
        btn_box.pack(fill=tk.X, side=tk.BOTTOM)

        def save_asset():
            name = e_name.get().strip()
            if not name:
                messagebox.showwarning("Campo Obligatorio", "Por favor ingresa el nombre del activo.", parent=modal)
                return

            c = int(s_c.get())
            i = int(s_i.get())
            a = int(s_a.get())

            data = {
                "Nombre_Activo": name,
                "Tipo_Activo": cb_type.get().strip(),
                "Propietario": e_owner.get().strip(),
                "Custodio": e_cust.get().strip(),
                "Ubicacion": e_loc.get().strip(),
                "Confidencialidad_1a5": str(c),
                "Integridad_1a5": str(i),
                "Disponibilidad_1a5": str(a),
                "Estado": cb_st.get().strip()
            }

            asset_mgr = AssetManager()
            if is_new:
                new_id = asset_mgr.add_asset(data)
                self.load_assets_table()
                try:
                    DashboardGenerator().generate_all()
                except:
                    pass
                self.status_lbl.config(text=f"✅ Nuevo activo {new_id} registrado exitosamente ({datetime.now().strftime('%H:%M:%S')})", fg="#27AE60")
                messagebox.showinfo("Activo Registrado", f"¡Activo {new_id} registrado correctamente!", parent=modal)
            else:
                asset_mgr.update_asset(aid, data)
                self.load_assets_table()
                try:
                    DashboardGenerator().generate_all()
                except:
                    pass
                self.status_lbl.config(text=f"✅ Activo {aid} actualizado exitosamente ({datetime.now().strftime('%H:%M:%S')})", fg="#27AE60")
                messagebox.showinfo("Activo Actualizado", f"¡Activo {aid} actualizado correctamente!", parent=modal)

            modal.destroy()

        tk.Button(
            btn_box,
            text="💾 Guardar Activo",
            font=("Segoe UI", 10, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=18,
            pady=6,
            command=save_asset
        ).pack(side=tk.RIGHT, padx=15)

        tk.Button(
            btn_box,
            text="Cancelar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            command=modal.destroy
        ).pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # ACCIÓN SINCRONIZAR GENÉRICA
    # -------------------------------------------------------------------------
    def action_sync_data(self):
        self.action_open_gsheets_modal()

if __name__ == "__main__":
    app = SGSISOCApp()
    app.mainloop()

