# -*- coding: utf-8 -*-
"""
Receptor Syslog UDP en Tiempo Real para el SOC.
Permite a Firewalls (Fortinet, Palo Alto, pfSense), Servidores Linux, WAFs y Routers
enviar sus logs directamente al motor del SOC para detección en vivo.
"""

import socket
import sys
import os
import threading
from datetime import datetime

# Asegurar path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from soc_engine.log_parser import LogParser
from soc_engine.threat_detector import ThreatDetector
from core.incident_manager import IncidentManager

class SyslogCollector:
    def __init__(self, host: str = "0.0.0.0", port: int = 1514):
        self.host = host
        self.port = port
        self.running = False
        self.detector = ThreatDetector()
        self.incident_mgr = IncidentManager()
        self.sock = None

    def start_listening(self, callback_on_incident=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.running = True
        print(f"[Syslog Collector] Escuchando logs UDP en tiempo real en {self.host}:{self.port}...")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                log_line = data.decode('utf-8', errors='ignore').strip()
                if not log_line:
                    continue

                # Parsear y detectar amenazas
                parsed = LogParser.parse_line(log_line)
                threats = self.detector.analyze_event(parsed)

                for t in threats:
                    t["src_ip"] = t.get("src_ip", addr[0])
                    inc_id = self.incident_mgr.add_incident(t)
                    print(f"  🚨 [EN VIVO] Amenaza detectada desde {addr[0]}: [{inc_id}] {t['title']} ({t['severity']})")
                    if callback_on_incident:
                        callback_on_incident(inc_id, t)

            except Exception as e:
                if self.running:
                    print(f"[Syslog Collector] Error recibiendo log: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
            print("[Syslog Collector] Servidor Syslog detenido.")

if __name__ == "__main__":
    collector = SyslogCollector(port=1514)
    try:
        collector.start_listening()
    except KeyboardInterrupt:
        collector.stop()
