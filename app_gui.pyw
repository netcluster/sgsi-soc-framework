# -*- coding: utf-8 -*-
"""
Aplicación de Escritorio Nativa de Windows para el SGSI & SOC Framework.
Desarrollada con Tkinter / TTK (100% nativa, sin dependencias externas pesadas).
Incluye receptor Syslog en vivo, dashboards CISO/Dirección y sincronización Google.
"""

import os
import sys
import csv
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# Importar módulos del core
from core.risk_calculator import RiskCalculator
from core.incident_manager import IncidentManager
from core.gsheets_manager import GSheetsManager
from soc_engine.log_parser import LogParser
from soc_engine.threat_detector import ThreatDetector
from soc_engine.syslog_collector import SyslogCollector
from simulators.generate_sample_telemetry import simulate_soc_activity
from dashboards.dashboard_generator import DashboardGenerator

class SGSISOCApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("🛡️ SGSI (ISO/IEC 27001:2022) & SOC Manager - Windows Desktop App")
        self.geometry("1180x750")
        self.minsize(980, 620)
        
        # Configurar colores institucionales
        self.color_primary = "#1B365D"    # Azul institucional
        self.color_accent = "#2980B9"     # Azul brillante
        self.color_bg = "#F4F7F9"         # Fondo claro
        self.color_card = "#FFFFFF"       # Fondo tarjetas

        self.configure(bg=self.color_bg)

        # Estado del colector Syslog
        self.syslog_collector = None
        self.syslog_thread = None

        # Configurar estilos TTK
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        
        self._configure_styles()
        self._create_header()
        self._create_tabs()
        self._create_footer()

        # Cargar datos iniciales
        self.refresh_kpis()
        self.load_incidents_table()
        self.load_risks_table()
        self.load_soa_table()

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

        # Botones de Dashboards
        ciso_btn = tk.Button(
            header_frame,
            text="🛡️ Dashboard CISO",
            font=("Segoe UI", 9, "bold"),
            bg="#8E44AD",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_open_ciso_dashboard
        )
        ciso_btn.pack(side=tk.RIGHT, padx=6, pady=12)

        dir_btn = tk.Button(
            header_frame,
            text="👔 Dashboard Dirección",
            font=("Segoe UI", 9, "bold"),
            bg="#2980B9",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_open_direccion_dashboard
        )
        dir_btn.pack(side=tk.RIGHT, padx=6, pady=12)

        sync_btn = tk.Button(
            header_frame,
            text="🔄 Sync Google",
            font=("Segoe UI", 9, "bold"),
            bg="#27AE60",
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            command=self.action_sync_data
        )
        sync_btn.pack(side=tk.RIGHT, padx=6, pady=12)

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

    def _create_footer(self):
        footer_frame = tk.Frame(self, bg="#E2E8F0", height=28)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_lbl = tk.Label(
            footer_frame,
            text="Listo | Receptor Syslog: Inactivo (Puerto UDP 1514 disponible)",
            font=("Segoe UI", 8),
            bg="#E2E8F0",
            fg="#555555"
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
            text="🛡️ Abrir Dashboard Interactivo del CISO (Gráficos MITRE / Riesgos / SOC)",
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
            text="👔 Abrir Dashboard de la Dirección del Servicio (Cumplimiento ISO / Negocio)",
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

        btn_ref = tk.Button(
            actions_bar,
            text="🔄 Actualizar",
            font=("Segoe UI", 9),
            bg="#BDC3C7",
            fg="#2C3E50",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.load_incidents_table
        )
        btn_ref.pack(side=tk.RIGHT, padx=5)

        cols = ("ID", "Fecha/Hora", "Título", "Severidad", "Estado", "Técnica MITRE", "IP Origen", "Activo Afectado")
        self.tree_incidents = ttk.Treeview(self.tab_soc, columns=cols, show="headings", selectmode="browse")
        
        self.tree_incidents.heading("ID", text="ID")
        self.tree_incidents.heading("Fecha/Hora", text="Fecha/Hora")
        self.tree_incidents.heading("Título", text="Título")
        self.tree_incidents.heading("Severidad", text="Severidad")
        self.tree_incidents.heading("Estado", text="Estado")
        self.tree_incidents.heading("Técnica MITRE", text="Técnica MITRE")
        self.tree_incidents.heading("IP Origen", text="IP Origen")
        self.tree_incidents.heading("Activo Afectado", text="Activo Afectado")

        self.tree_incidents.column("ID", width=80, anchor="center")
        self.tree_incidents.column("Fecha/Hora", width=130)
        self.tree_incidents.column("Título", width=220)
        self.tree_incidents.column("Severidad", width=80, anchor="center")
        self.tree_incidents.column("Estado", width=90, anchor="center")
        self.tree_incidents.column("Técnica MITRE", width=170)
        self.tree_incidents.column("IP Origen", width=100, anchor="center")
        self.tree_incidents.column("Activo Afectado", width=140)

        scroll_y = ttk.Scrollbar(self.tab_soc, orient=tk.VERTICAL, command=self.tree_incidents.yview)
        self.tree_incidents.configure(yscrollcommand=scroll_y.set)

        self.tree_incidents.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

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
            self.tree_incidents.insert("", tk.END, values=(
                inc.get("ID_Incidente", ""),
                inc.get("Fecha_Hora", ""),
                inc.get("Titulo_Incidente", ""),
                inc.get("Severidad", ""),
                inc.get("Estado", ""),
                inc.get("Tecnica_MITRE", ""),
                inc.get("IP_Origen", ""),
                inc.get("IP_Destino_Activo", "")
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

    # -------------------------------------------------------------------------
    # TAB 3: MATRIZ DE RIESGOS (ISO 27005)
    # -------------------------------------------------------------------------
    def _build_tab_risks(self):
        actions_bar = tk.Frame(self.tab_risks, bg=self.color_bg)
        actions_bar.pack(fill=tk.X, padx=10, pady=8)

        btn_recalc = tk.Button(
            actions_bar,
            text="⚙️ Recalcular Matriz de Riesgos ISO 27005",
            font=("Segoe UI", 9, "bold"),
            bg=self.color_primary,
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.action_recalculate_risks
        )
        btn_recalc.pack(side=tk.LEFT, padx=5)

        cols = ("ID", "Activo", "Amenaza", "Vulnerabilidad", "Riesgo Inherente", "Eficacia", "Riesgo Residual", "Estrategia")
        self.tree_risks = ttk.Treeview(self.tab_risks, columns=cols, show="headings", selectmode="browse")

        self.tree_risks.heading("ID", text="ID")
        self.tree_risks.heading("Activo", text="Activo")
        self.tree_risks.heading("Amenaza", text="Amenaza")
        self.tree_risks.heading("Vulnerabilidad", text="Vulnerabilidad")
        self.tree_risks.heading("Riesgo Inherente", text="Riesgo Inherente")
        self.tree_risks.heading("Eficacia", text="Eficacia Controles")
        self.tree_risks.heading("Riesgo Residual", text="Riesgo Residual")
        self.tree_risks.heading("Estrategia", text="Estrategia")

        self.tree_risks.column("ID", width=70, anchor="center")
        self.tree_risks.column("Activo", width=90, anchor="center")
        self.tree_risks.column("Amenaza", width=200)
        self.tree_risks.column("Vulnerabilidad", width=180)
        self.tree_risks.column("Riesgo Inherente", width=110, anchor="center")
        self.tree_risks.column("Eficacia", width=100, anchor="center")
        self.tree_risks.column("Riesgo Residual", width=100, anchor="center")
        self.tree_risks.column("Estrategia", width=90, anchor="center")

        scroll_y = ttk.Scrollbar(self.tab_risks, orient=tk.VERTICAL, command=self.tree_risks.yview)
        self.tree_risks.configure(yscrollcommand=scroll_y.set)

        self.tree_risks.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

    def load_risks_table(self):
        for item in self.tree_risks.get_children():
            self.tree_risks.delete(item)

        risk_file = os.path.join("templates_google", "02_matriz_riesgos_template.csv")
        if not os.path.exists(risk_file):
            return

        with open(risk_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for r in reader:
                self.tree_risks.insert("", tk.END, values=(
                    r.get("ID_Riesgo", ""),
                    r.get("ID_Activo", ""),
                    r.get("Amenaza", ""),
                    r.get("Vulnerabilidad", ""),
                    f"{r.get('Nivel_Riesgo_Inherente', '')} ({r.get('Categoria_Riesgo_Inherente', '')})",
                    r.get("Eficacia_Controles_Pct", ""),
                    f"{r.get('Nivel_Riesgo_Residual', '')} ({r.get('Categoria_Riesgo_Residual', '')})",
                    r.get("Estrategia_Tratamiento", "")
                ))

    def action_recalculate_risks(self):
        risk_calc = RiskCalculator()
        risk_file = os.path.join("templates_google", "02_matriz_riesgos_template.csv")
        risk_calc.process_risk_matrix(risk_file, risk_file)
        self.load_risks_table()
        messagebox.showinfo("Cálculo de Riesgos", "¡Matriz de Riesgos ISO 27005 recalculada y actualizada con éxito!")

    # -------------------------------------------------------------------------
    # TAB 4: DECLARACIÓN DE APLICABILIDAD SoA (ISO 27001)
    # -------------------------------------------------------------------------
    def _build_tab_soa(self):
        info_bar = tk.Frame(self.tab_soa, bg=self.color_bg)
        info_bar.pack(fill=tk.X, padx=10, pady=8)

        lbl = tk.Label(
            info_bar,
            text="Catálogo de los 93 Controles de Seguridad ISO/IEC 27001:2022 (Organizacional, Personas, Físico, Tecnológico)",
            font=("Segoe UI", 9, "italic"),
            bg=self.color_bg,
            fg="#555555"
        )
        lbl.pack(side=tk.LEFT, padx=5)

        cols = ("Código", "Nombre del Control", "Dominio", "Aplica", "Estado", "Madurez %", "Responsable")
        self.tree_soa = ttk.Treeview(self.tab_soa, columns=cols, show="headings", selectmode="browse")

        self.tree_soa.heading("Código", text="Código")
        self.tree_soa.heading("Nombre del Control", text="Nombre del Control")
        self.tree_soa.heading("Dominio", text="Dominio")
        self.tree_soa.heading("Aplica", text="Aplica")
        self.tree_soa.heading("Estado", text="Estado")
        self.tree_soa.heading("Madurez %", text="Madurez %")
        self.tree_soa.heading("Responsable", text="Responsable")

        self.tree_soa.column("Código", width=70, anchor="center")
        self.tree_soa.column("Nombre del Control", width=280)
        self.tree_soa.column("Dominio", width=160)
        self.tree_soa.column("Aplica", width=60, anchor="center")
        self.tree_soa.column("Estado", width=100, anchor="center")
        self.tree_soa.column("Madurez %", width=80, anchor="center")
        self.tree_soa.column("Responsable", width=150)

        scroll_y = ttk.Scrollbar(self.tab_soa, orient=tk.VERTICAL, command=self.tree_soa.yview)
        self.tree_soa.configure(yscrollcommand=scroll_y.set)

        self.tree_soa.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

    def load_soa_table(self):
        for item in self.tree_soa.get_children():
            self.tree_soa.delete(item)

        soa_file = os.path.join("templates_google", "03_soa_iso27001_template.csv")
        if not os.path.exists(soa_file):
            return

        with open(soa_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for r in reader:
                self.tree_soa.insert("", tk.END, values=(
                    r.get("Codigo_Control", ""),
                    r.get("Nombre_Control", ""),
                    r.get("Dominio", ""),
                    r.get("Aplica", ""),
                    r.get("Estado_Implementacion", ""),
                    f"{r.get('Porcentaje_Madurez', '')}%",
                    r.get("Responsable", "")
                ))

    # -------------------------------------------------------------------------
    # ACCIONES DE DASHBOARDS PYTHON
    # -------------------------------------------------------------------------
    def action_open_ciso_dashboard(self):
        generator = DashboardGenerator()
        path = generator.generate_ciso_dashboard()
        webbrowser.open(f"file:///{os.path.abspath(path)}")

    def action_open_direccion_dashboard(self):
        generator = DashboardGenerator()
        path = generator.generate_direccion_dashboard()
        webbrowser.open(f"file:///{os.path.abspath(path)}")

    # -------------------------------------------------------------------------
    # ACCIÓN SINCRONIZAR
    # -------------------------------------------------------------------------
    def action_sync_data(self):
        manager = GSheetsManager(mode="auto")
        res = manager.sync_all_framework_data()
        
        self.refresh_kpis()
        self.load_incidents_table()
        self.load_risks_table()
        
        folder = res.get("sync_folder", "sync_drive")
        messagebox.showinfo(
            "Sincronización Exitosa",
            f"¡Datos del SGSI & SOC sincronizados correctamente!\n\n"
            f"Modo: {res['mode'].upper()}\n"
            f"Carpeta Google Drive: {folder}\n"
            f"Todos los archivos CSV están actualizados."
        )

if __name__ == "__main__":
    app = SGSISOCApp()
    app.mainloop()
