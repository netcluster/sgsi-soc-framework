# -*- coding: utf-8 -*-
"""
Orquestador Principal del Sistema de Gestión de Seguridad de la Información (SGSI)
y Centro de Operaciones de Seguridad (SOC).
Soporta generación de dashboards Python interactivos (CISO y Dirección del Servicio),
sincronización dual con Google y gestión de riesgos ISO 27005.
"""

import os
import sys
import argparse
from core.risk_calculator import RiskCalculator
from core.incident_manager import IncidentManager
from core.gsheets_manager import GSheetsManager
from soc_engine.log_parser import LogParser
from soc_engine.threat_detector import ThreatDetector
from simulators.generate_sample_telemetry import simulate_soc_activity
from dashboards.dashboard_generator import DashboardGenerator

def print_banner():
    print("=" * 70)
    print("      SISTEMA DE GESTION DE SEGURIDAD DE LA INFORMACION (SGSI)")
    print("          & DASHBOARD SOC (GOOGLE TOOLS + PYTHON ENGINE)")
    print("=" * 70)

def action_recalculate_risks():
    print("\n[+] Recalculando Matriz de Riesgos ISO 27005...")
    risk_calc = RiskCalculator()
    input_file = os.path.join("templates_google", "02_matriz_riesgos_template.csv")
    results = risk_calc.process_risk_matrix(input_file, input_file)
    print(f"[OK] {len(results)} riesgos procesados y actualizados con éxito en '{input_file}'.")

def action_show_kpis():
    print("\n[+] Resumen Ejecutivo de Métricas y KPIs del SOC & SGSI:")
    inc_mgr = IncidentManager()
    kpis = inc_mgr.compute_kpis()
    
    print("-" * 50)
    print(f"Total de Incidentes Registrados: {kpis['total_incidents']}")
    print(f"MTTD Promedio (Tiempo Medio de Detección): {kpis['avg_mttd_min']} minutos")
    print(f"MTTR Promedio (Tiempo Medio de Respuesta): {kpis['avg_mttr_min']} minutos")
    print("\nDistribución por Severidad:")
    for sev, count in kpis['by_severity'].items():
        print(f"  - {sev}: {count}")
    print("\nDistribución por Estado:")
    for stat, count in kpis['by_status'].items():
        print(f"  - {stat}: {count}")
    print("\nDistribución por Tipo de Amenaza:")
    for threat, count in kpis['by_threat'].items():
        print(f"  - {threat}: {count}")
    print("-" * 50)

def action_generate_dashboards():
    print("\n[+] Generando Dashboards Especializados en Python (Plotly HTML)...")
    generator = DashboardGenerator()
    res = generator.generate_all()
    print(f"[OK] Dashboard CISO listo en: {res['ciso_dashboard']}")
    print(f"[OK] Dashboard Dirección listo en: {res['direccion_dashboard']}")

def action_sync(mode: str = "auto", creds_file: str = "config/google_credentials.json", share_email: str = None):
    print(f"\n[+] Ejecutando Sincronizador de Datos (Modo solicitado: {mode.upper()})...")
    manager = GSheetsManager(
        mode=mode,
        creds_file=creds_file,
        share_email=share_email
    )
    res = manager.sync_all_framework_data()
    print(f"\n[INFO] Modo de sincronización efectivo: {res['mode'].upper()}")
    print(f"[INFO] Carpeta local sincronizada para Google Drive: {res['sync_folder']}")

def action_ingest_logs(log_file: str):
    if not os.path.exists(log_file):
        print(f"[ERROR] Archivo no encontrado: {log_file}")
        return
    print(f"\n[+] Ingestando y analizando logs desde '{log_file}'...")
    detector = ThreatDetector()
    inc_mgr = IncidentManager()
    
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        count = 0
        inc_count = 0
        for line in f:
            count += 1
            parsed = LogParser.parse_line(line)
            threats = detector.analyze_event(parsed)
            for t in threats:
                inc_id = inc_mgr.add_incident(t)
                inc_count += 1
                print(f"  [*] Incidente Registrado: {inc_id} -> {t['title']}")
        print(f"\n[OK] {count} líneas procesadas. {inc_count} nuevos incidentes detectados.")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SGSI & SOC Management CLI")
    parser.add_argument("--action", choices=["calculate-risks", "show-kpis", "simulate-soc", "ingest-logs", "sync", "generate-dashboards", "all"], 
                        default="all", help="Acción a ejecutar")
    parser.add_argument("--sync-mode", choices=["auto", "service_account", "local_sync"], default="auto",
                        help="Modo de sincronización con Google (auto, service_account con GCP o local_sync CSV)")
    parser.add_argument("--creds-file", type=str, default="config/google_credentials.json",
                        help="Ruta al archivo JSON de credenciales de Google Service Account")
    parser.add_argument("--share-email", type=str, default=None,
                        help="Email de Google al que dar permisos de edición si se crea la hoja vía API")
    parser.add_argument("--log-file", type=str, default="simulators/sample_raw_logs.log", 
                        help="Ruta de archivo de logs para ingesta")

    args = parser.parse_args()

    if args.action in ["calculate-risks", "all"]:
        action_recalculate_risks()

    if args.action == "simulate-soc":
        simulate_soc_activity()

    if args.action == "ingest-logs":
        action_ingest_logs(args.log_file)

    if args.action in ["sync", "all"]:
        action_sync(mode=args.sync_mode, creds_file=args.creds_file, share_email=args.share_email)

    if args.action in ["generate-dashboards", "all"]:
        action_generate_dashboards()

    if args.action in ["show-kpis", "all"]:
        action_show_kpis()

if __name__ == "__main__":
    main()
