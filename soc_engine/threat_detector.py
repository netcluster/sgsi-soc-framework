# -*- coding: utf-8 -*-
"""
Motor de Detección de Amenazas y Correlación de Eventos para el SOC.
Analiza streams de logs e identifica vectores de ataque en tiempo real o por lotes
(Soporta Syslog Linux, Web Nginx/Apache y Firewalls FortiGate/Palo Alto).
"""

import re
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any
from soc_engine.mitre_mapper import MitreMapper

class ThreatDetector:
    def __init__(self, brute_force_limit: int = 5, scan_threshold: int = 8):
        self.brute_force_limit = brute_force_limit
        self.scan_threshold = scan_threshold
        self.auth_failures = defaultdict(list)
        self.ip_dest_ports = defaultdict(set)
        self.connection_fails = defaultdict(int)

    def analyze_event(self, log_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analiza un evento normalizado y retorna una lista de incidentes si detecta amenazas."""
        incidents = []
        if not log_event:
            return incidents

        fmt = log_event.get("format", "")
        msg = log_event.get("message", "")
        raw = log_event.get("raw", "")
        uri = log_event.get("uri", "")
        client_ip = log_event.get("client_ip", "")
        timestamp = log_event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # =====================================================================
        # A. ANÁLISIS DE LOGS DE FIREWALL / FORTIGATE / RED
        # =====================================================================
        if fmt == "fortigate_traffic":
            src_ip = log_event.get("src_ip", "0.0.0.0")
            src_host = log_event.get("src_host", "")
            dst_ip = log_event.get("dst_ip", "0.0.0.0")
            dst_host = log_event.get("dst_host", "")
            dst_port = str(log_event.get("dst_port", ""))
            action = log_event.get("action", "").lower()
            service = log_event.get("service", "")
            policyname = log_event.get("policyname", "")
            level = log_event.get("level", "notice").lower()
            crscore = int(log_event.get("crscore", "0") or 0)
            log_msg = log_event.get("msg", "")

            # 1. Regla Crítica: Sondeo de Metadatos Cloud / SSRF (169.254.169.254)
            if dst_ip == "169.254.169.254":
                mitre = MitreMapper.map_event("cloud_metadata_probe")
                incidents.append({
                    "timestamp": timestamp,
                    "title": f"Intento de Acceso a Metadatos Cloud (SSRF) desde {src_ip}",
                    "threat_type": mitre["threat_type"],
                    "severity": mitre["severity"],
                    "mitre_tactic": mitre["tactic"],
                    "mitre_technique": mitre["technique"],
                    "src_ip": src_ip,
                    "src_host": src_host or f"Host ({src_ip})",
                    "dst_ip": dst_ip,
                    "dst_host": dst_host or "AWS/Cloud Metadata API",
                    "target_asset": f"Cloud Metadata ({dst_ip}:{dst_port})",
                    "user": "Host Interno",
                    "description": f"El host {src_ip} ({src_host}) intentó consultar la API de metadatos de instancia cloud 169.254.169.254 (Acción: {action}).",
                    "corrective_action": "Aislar host emisor, revisar procesos que originan peticiones HTTP de metadatos y aplicar bloqueo perimetral.",
                    "mttd_min": 1,
                    "mttr_min": 30,
                    "status": "Abierto"
                })

            # 2. Regla: Detección de Reconocimiento / Escaneo de Puertos (Port Scan)
            if action in ["timeout", "client-rst", "server-rst", "deny", "drop"]:
                if dst_port:
                    self.ip_dest_ports[src_ip].add(f"{dst_ip}:{dst_port}")
                
                if len(self.ip_dest_ports[src_ip]) == self.scan_threshold:
                    mitre = MitreMapper.map_event("port_scan")
                    incidents.append({
                        "timestamp": timestamp,
                        "title": f"Escaneo de Puertos / Reconocimiento de Red desde {src_ip}",
                        "threat_type": mitre["threat_type"],
                        "severity": mitre["severity"],
                        "mitre_tactic": mitre["tactic"],
                        "mitre_technique": mitre["technique"],
                        "src_ip": src_ip,
                        "src_host": src_host or f"Host ({src_ip})",
                        "dst_ip": dst_ip,
                        "dst_host": dst_host or "Múltiples Destinos de Red",
                        "target_asset": "Múltiples Destinos de Red",
                        "user": "N/A",
                        "description": f"Se detectaron {len(self.ip_dest_ports[src_ip])} conexiones fallidas/bloqueadas consecutivas desde {src_host} hacia distintos puertos/destinos.",
                        "corrective_action": f"Bloquear tráfico de {src_ip} en firewall e inspeccionar posibles herramientas de escaneo (Nmap/Masscan).",
                        "mttd_min": 2,
                        "mttr_min": 15,
                        "status": "Abierto"
                    })
                    self.ip_dest_ports[src_ip] = set()

            # 3. Regla: Fallos de Conexión y Alertas Warning del Firewall
            if level == "warning" or crscore >= 5 or "Connection Failed" in log_msg:
                self.connection_fails[src_ip] += 1
                if self.connection_fails[src_ip] == 5:
                    mitre = MitreMapper.map_event("firewall_connection_failure")
                    incidents.append({
                        "timestamp": timestamp,
                        "title": f"Múltiples Fallos de Conexión / Alerta Firewall desde {src_ip}",
                        "threat_type": mitre["threat_type"],
                        "severity": mitre["severity"],
                        "mitre_tactic": mitre["tactic"],
                        "mitre_technique": mitre["technique"],
                        "src_ip": src_ip,
                        "src_host": src_host or f"Host ({src_ip})",
                        "dst_ip": dst_ip,
                        "dst_host": dst_host or f"Servicio {service} ({dst_ip})",
                        "target_asset": f"Servicio {service} ({dst_ip})",
                        "user": "Host de Red",
                        "description": f"El firewall reportó eventos de nivel warning ({log_msg or 'Fallo de conexión'}) para {src_host} hacia {dst_host}.",
                        "corrective_action": "Revisar configuración de política y verificar integridad del enlace o endpoint emisor.",
                        "mttd_min": 3,
                        "mttr_min": 20,
                        "status": "Cerrado"
                    })
                    self.connection_fails[src_ip] = 0

            # 4. Regla: Sondeo de Servicios Sensibles / Puertos no Estándar (9876, 9100, 8883, 8500)
            if dst_port in ["9876", "9100", "8500"] and action == "timeout":
                self.connection_fails[f"{src_ip}_{dst_port}"] += 1
                if self.connection_fails[f"{src_ip}_{dst_port}"] == 3:
                    mitre = MitreMapper.map_event("suspicious_internal_port")
                    incidents.append({
                        "timestamp": timestamp,
                        "title": f"Sondeo no autorizado de puerto {dst_port} ({service}) hacia {dst_ip}",
                        "threat_type": mitre["threat_type"],
                        "severity": mitre["severity"],
                        "mitre_tactic": mitre["tactic"],
                        "mitre_technique": mitre["technique"],
                        "src_ip": src_ip,
                        "src_host": src_host or f"Host ({src_ip})",
                        "dst_ip": dst_ip,
                        "dst_host": dst_host or f"Servicio Interno ({dst_ip}:{dst_port})",
                        "target_asset": f"Servicio Interno {dst_ip}:{dst_port}",
                        "user": "Host Interno",
                        "description": f"Intentos repetidos y timeout de comunicación desde {src_host} hacia el puerto sensible {dst_port} ({dst_host}).",
                        "corrective_action": "Verificar si el servicio es legítimo o si corresponde a movimiento lateral / sondeo interno.",
                        "mttd_min": 4,
                        "mttr_min": 25,
                        "status": "Abierto"
                    })
                    self.connection_fails[f"{src_ip}_{dst_port}"] = 0

            return incidents

        # =====================================================================
        # B. ANÁLISIS DE LOGS TRADICIONALES (SYSLOG, NGINX, APACHE, WINDOWS)
        # =====================================================================
        # 1. Regla: Fuerza Bruta SSH / Auth Failure
        if "Failed password for" in msg or "authentication failure" in msg.lower() or "login failed" in msg.lower():
            ip_match = re.search(r'from\s+([\d\.]+)', msg) or re.search(r'ip[=:]\s*([\d\.]+)', msg, re.IGNORECASE)
            user_match = re.search(r'for\s+(?:invalid user\s+)?(\w+)', msg) or re.search(r'user[=:]\s*(\w+)', msg, re.IGNORECASE)
            
            src_ip = ip_match.group(1) if ip_match else (client_ip if client_ip else "IP_Desconocida")
            user = user_match.group(1) if user_match else "admin"

            self.auth_failures[src_ip].append(datetime.now())
            if len(self.auth_failures[src_ip]) >= self.brute_force_limit:
                mitre = MitreMapper.map_event("ssh_bruteforce")
                incidents.append({
                    "timestamp": timestamp,
                    "title": f"Ataque de Fuerza Bruta detectado desde {src_ip}",
                    "threat_type": mitre["threat_type"],
                    "severity": mitre["severity"],
                    "mitre_tactic": mitre["tactic"],
                    "mitre_technique": mitre["technique"],
                    "src_ip": src_ip,
                    "target_asset": log_event.get("host", "Servidor Linux"),
                    "user": user,
                    "description": f"Se registraron {len(self.auth_failures[src_ip])} intentos fallidos de autenticación de forma consecutiva.",
                    "corrective_action": f"Bloquear IP {src_ip} en firewall perimetral y activar captcha/MFA.",
                    "mttd_min": 2,
                    "mttr_min": 15,
                    "status": "Abierto"
                })
                self.auth_failures[src_ip] = []

        # 2. Regla: Inyección SQL (SQLi)
        sqli_patterns = [
            r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
            r'(\b(select|union|insert|delete|drop|update)\b.*\b(from|where|table)\b)',
            r'(\b(or|and)\b\s+[\d\w]+\s*=\s*[\d\w]+)'
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, uri, re.IGNORECASE) or re.search(pattern, raw, re.IGNORECASE):
                mitre = MitreMapper.map_event("sql_injection")
                src_ip = client_ip if client_ip else "190.14.33.10"
                incidents.append({
                    "timestamp": timestamp,
                    "title": f"Intento de Inyección SQL en endpoint web",
                    "threat_type": mitre["threat_type"],
                    "severity": mitre["severity"],
                    "mitre_tactic": mitre["tactic"],
                    "mitre_technique": mitre["technique"],
                    "src_ip": src_ip,
                    "target_asset": "ACT-002 (Servidor Web ERP)",
                    "user": log_event.get("user", "anon_client"),
                    "description": f"Se detectó payload SQLi en la petición HTTP: {uri[:80]}",
                    "corrective_action": "Bloqueo por WAF y sanitización de sentencias SQL preparadas (Prepared Statements).",
                    "mttd_min": 1,
                    "mttr_min": 20,
                    "status": "Abierto"
                })
                break

        # 3. Regla: Cross-Site Scripting (XSS)
        xss_patterns = [r'<script.*?>', r'javascript:', r'onerror\s*=', r'onload\s*=']
        for pattern in xss_patterns:
            if re.search(pattern, uri, re.IGNORECASE) or re.search(pattern, raw, re.IGNORECASE):
                mitre = MitreMapper.map_event("xss_attack")
                src_ip = client_ip if client_ip else "201.21.90.4"
                incidents.append({
                    "timestamp": timestamp,
                    "title": "Intento de Ataque Cross-Site Scripting (XSS)",
                    "threat_type": mitre["threat_type"],
                    "severity": mitre["severity"],
                    "mitre_tactic": mitre["tactic"],
                    "mitre_technique": mitre["technique"],
                    "src_ip": src_ip,
                    "target_asset": "ACT-002 (Servidor Web ERP)",
                    "user": log_event.get("user", "anon_client"),
                    "description": f"Vector de ataque XSS detectado en la URL solicitada: {uri[:80]}",
                    "corrective_action": "Configurar encabezados Content-Security-Policy (CSP) y filtro WAF.",
                    "mttd_min": 1,
                    "mttr_min": 15,
                    "status": "Cerrado"
                })
                break

        # 4. Regla: Ejecución sospechosa de PowerShell
        if "-enc" in raw.lower() or "-encodedcommand" in raw.lower() or "bypass -noprofile" in raw.lower():
            mitre = MitreMapper.map_event("powershell_obfuscated")
            incidents.append({
                "timestamp": timestamp,
                "title": "Ejecución de PowerShell con parámetros de evasión",
                "threat_type": mitre["threat_type"],
                "severity": mitre["severity"],
                "mitre_tactic": mitre["tactic"],
                "mitre_technique": mitre["technique"],
                "src_ip": "127.0.0.1 (Endpoint)",
                "target_asset": "ACT-004 (Laptops de Personal)",
                "user": "SYSTEM / Usuario Local",
                "description": f"Comando PowerShell codificado o con bandera bypass ejecutado localmente: {raw[:90]}",
                "corrective_action": "Aislamiento de red del endpoint, revisión forense y bloqueo de scripts no firmados.",
                "mttd_min": 3,
                "mttr_min": 40,
                "status": "En Mitigacion"
            })

        return incidents
