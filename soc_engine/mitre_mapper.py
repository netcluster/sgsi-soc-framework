# -*- coding: utf-8 -*-
"""
Mapeador MITRE ATT&CK (Enterprise Framework) para el SOC.
Asocia eventos de seguridad detectados con Tácticas, Técnicas y Niveles de Severidad estándar.
"""

class MitreMapper:
    MITRE_RULES = {
        "ssh_bruteforce": {
            "tactic": "Credential Access",
            "technique": "T1110 - Brute Force",
            "threat_type": "Fuerza Bruta",
            "severity": "Alta"
        },
        "rdp_bruteforce": {
            "tactic": "Credential Access",
            "technique": "T1110.001 - Password Guessing",
            "threat_type": "Fuerza Bruta",
            "severity": "Alta"
        },
        "port_scan": {
            "tactic": "Reconnaissance",
            "technique": "T1046 - Network Service Scanning",
            "threat_type": "Reconocimiento de Red",
            "severity": "Media"
        },
        "cloud_metadata_probe": {
            "tactic": "Credential Access",
            "technique": "T1552.005 - Cloud Instance Metadata API",
            "threat_type": "Sondeo de Metadatos Cloud / SSRF",
            "severity": "Crítica"
        },
        "firewall_connection_failure": {
            "tactic": "Reconnaissance",
            "technique": "T1046 - Network Service Discovery",
            "threat_type": "Fallo Reiterado de Conexión / Bloqueo Firewall",
            "severity": "Media"
        },
        "suspicious_internal_port": {
            "tactic": "Discovery",
            "technique": "T1021 - Remote Services Probing",
            "threat_type": "Sondeo de Servicios Internos No Autorizados",
            "severity": "Media"
        },
        "sql_injection": {
            "tactic": "Initial Access",
            "technique": "T1190 - Exploit Public-Facing Application",
            "threat_type": "Inyección SQL",
            "severity": "Crítica"
        },
        "xss_attack": {
            "tactic": "Initial Access",
            "technique": "T1189 - Drive-by Compromise",
            "threat_type": "Cross-Site Scripting (XSS)",
            "severity": "Media"
        },
        "dns_tunneling": {
            "tactic": "Exfiltration",
            "technique": "T1048.003 - Exfiltration Over Alternative Protocol",
            "threat_type": "Fuga de Información",
            "severity": "Crítica"
        },
        "powershell_obfuscated": {
            "tactic": "Execution",
            "technique": "T1059.001 - PowerShell Command and Scripting",
            "threat_type": "Malware / Execution",
            "severity": "Crítica"
        },
        "privilege_escalation": {
            "tactic": "Privilege Escalation",
            "technique": "T1068 - Exploitation for Privilege Escalation",
            "threat_type": "Escalación de Privilegios",
            "severity": "Alta"
        },
        "unauthorized_access": {
            "tactic": "Defense Evasion",
            "technique": "T1078 - Valid Accounts",
            "threat_type": "Acceso No Autorizado",
            "severity": "Media"
        },
        "phishing_email": {
            "tactic": "Initial Access",
            "technique": "T1566 - Phishing",
            "threat_type": "Ingeniería Social",
            "severity": "Media"
        }
    }

    @classmethod
    def map_event(cls, event_type: str) -> dict:
        """Devuelve los metadatos MITRE asociados al evento detectado."""
        return cls.MITRE_RULES.get(event_type, {
            "tactic": "General Defense",
            "technique": "T1000 - Generic Security Event",
            "threat_type": "Anomalía de Red",
            "severity": "Baja"
        })
