# -*- coding: utf-8 -*-
"""
Servidor Web de Dashboards en Tiempo Real (Live Server).
Sirve los Dashboards del CISO y Dirección con actualización automática en vivo (Live Polling / SSE),
refrescando gráficos Plotly, KPIs y tablas de incidentes en tiempo real sin recargar la página.
"""

import os
import sys
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Asegurar path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.incident_manager import IncidentManager
from core.risk_calculator import RiskCalculator
from dashboards.dashboard_generator import DashboardGenerator

class LiveDashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        html_dir = os.path.join(base_dir, "dashboards", "html")

        # 1. API en tiempo real para datos de incidentes y KPIs
        if parsed.path == "/api/live-data":
            inc_mgr = IncidentManager(os.path.join(base_dir, "templates_google", "04_registro_incidentes_template.csv"))
            incidents = inc_mgr.get_all_incidents()
            kpis = inc_mgr.compute_kpis()

            response_data = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "kpis": kpis,
                "recent_incidents": incidents[-10:],
                "total": len(incidents)
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response_data, ensure_ascii=False).encode('utf-8'))
            return

        # 2. Rutas para los Dashboards
        if parsed.path in ["/", "/ciso"]:
            generator = DashboardGenerator()
            file_path = generator.generate_ciso_dashboard()
            self._serve_file(file_path, "text/html; charset=utf-8")
        elif parsed.path == "/direccion":
            generator = DashboardGenerator()
            file_path = generator.generate_direccion_dashboard()
            self._serve_file(file_path, "text/html; charset=utf-8")
        else:
            self.send_error(404, "Página no encontrada")

    def _serve_file(self, file_path, content_type):
        if not os.path.exists(file_path):
            self.send_error(404, "Archivo no encontrado")
            return
        with open(file_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        # Silenciar logs continuos en consola
        return

def run_live_server(host="0.0.0.0", port=8080):
    server = HTTPServer((host, port), LiveDashboardHandler)
    print(f"\n[Live Dashboard Server] 🚀 Servidor en Vivo ACTIVO en http://localhost:{port}")
    print(f"  • Dashboard CISO (En Vivo):      http://localhost:{port}/ciso")
    print(f"  • Dashboard Dirección (En Vivo): http://localhost:{port}/direccion\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("[Live Dashboard Server] Servidor detenido.")

if __name__ == "__main__":
    run_live_server()
