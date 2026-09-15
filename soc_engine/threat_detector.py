# -*- coding: utf-8 -*-
"""
Motor de Detección de Amenazas y Correlación de Eventos para el SOC.
Analiza streams de logs e identifica vectores de ataque en tiempo real o por lotes.
"""

import re
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any
from soc_engine.mitre_mapper import MitreMapper

class ThreatDetector:
    def __init__(self, brute_force_limit: int = 5):
        self.brute_force_limit = brute_force_limit
        self.auth_failures = defaultdict(list)
        self.port_scans = defaultdict(set)

    def analyze_event(self, log_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analiza un evento normalizado y retorna una lista de incidentes si detecta amenazas."""
        incidents = []
        if not log_event:
            return incidents

        msg = log_event.get("message", "")
        raw = log_event.get("raw", "")
        uri = log_event.get("uri", "")
        client_ip = log_event.get("client_ip", "")

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
                    "title": f"Ataque de Fuerza Bruta detectado desde {src_ip}",
                    "threat_type": mitre["threat_type"],
                    "severity": mitre["severity"],
                    "mitre_tactic": mitre["tactic"],
                    "mitre_technique": mitre["technique"],
                    "src_ip": src_ip,
                    "target_asset": log_event.get("host", "ACT-002 (Web ERP)"),
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

        # 4. Regla: Ejecución sospechosa de PowerShell / Scripting Ofuscado
        if "-enc" in raw.lower() or "-encodedcommand" in raw.lower() or "bypass -noprofile" in raw.lower():
            mitre = MitreMapper.map_event("powershell_obfuscated")
            incidents.append({
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
