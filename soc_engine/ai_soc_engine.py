# -*- coding: utf-8 -*-
"""
Motor de Inteligencia Artificial Open Source para el SOC (SERMIG 2026).
Proporciona capacidades proactivas de triage, correlación CTI, generación
de comandos de mitigación inmediata (SOAR) y redacción de notificaciones
legales para el CSIRT de Gobierno / ANCI bajo la Ley N° 21.663.

Soporta:
1. Conexión a LLMs locales mediante Ollama API (Llama 3.2, Mistral, Qwen 2.5, DeepSeek).
2. Motor Heurístico Experto Embebido (100% autónomo, funciona sin GPU ni dependencias externas).
"""

import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, Any, List, Optional

class AISocEngine:
    def __init__(self, ollama_url: str = "http://localhost:11434", default_model: str = "llama3.2"):
        self.ollama_url = ollama_url.rstrip("/")
        self.default_model = default_model
        self._cached_ollama_status: Optional[bool] = None

    def is_ollama_available(self) -> bool:
        """Verifica si el servicio local de Ollama está activo y respondiendo."""
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags", headers={"User-Agent": "SGSI-SOC-AI/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name", "") for m in data.get("models", [])]
                    if models:
                        if not any(self.default_model in m for m in models):
                            self.default_model = models[0]
                    self._cached_ollama_status = True
                    return True
        except Exception:
            pass
        self._cached_ollama_status = False
        return False

    def get_status_summary(self) -> Dict[str, Any]:
        """Retorna el estado actual del motor de IA."""
        available = self.is_ollama_available()
        return {
            "mode": "LLM Open Source Local (Ollama)" if available else "Motor Heurístico Experto Autónomo",
            "provider": f"Ollama ({self.default_model})" if available else "Python Rule-Based & CTI Inference Engine",
            "is_llm_active": available,
            "cost": "$0 USD (Open Source / Soberanía Local)",
            "compliance": "Cumple Ley 19.628 y Ley 21.663 (Cero fuga de datos a internet)"
        }

    def generate_firewall_commands(self, src_ip: str, dst_ip: str = "any", port: str = "any") -> Dict[str, str]:
        """Genera comandos de mitigación perimetral listos para copiar y ejecutar en distintos firewalls."""
        if not src_ip or src_ip in ("Desconocido", "-", "127.0.0.1", "0.0.0.0"):
            src_ip = "IP_ATACANTE"

        clean_ip = src_ip.split(":")[0] if ":" in src_ip else src_ip

        return {
            "Fortinet FortiOS CLI": (
                f"config firewall address\n"
                f"    edit \"BLOQUEO_SOC_{clean_ip}\"\n"
                f"        set subnet {clean_ip}/32\n"
                f"        set comment \"Bloqueo automatico SOC SERMIG 2026\"\n"
                f"    next\n"
                f"end\n"
                f"config firewall policy\n"
                f"    edit 0\n"
                f"        set name \"DENY_SOC_{clean_ip}\"\n"
                f"        set srcintf \"any\"\n"
                f"        set dstintf \"any\"\n"
                f"        set srcaddr \"BLOQUEO_SOC_{clean_ip}\"\n"
                f"        set dstaddr \"all\"\n"
                f"        set action deny\n"
                f"        set schedule \"always\"\n"
                f"        set service \"ALL\"\n"
                f"    next\n"
                f"end"
            ),
            "Cisco ASA / Firepower": (
                f"access-list OUTSIDE_IN line 1 extended deny ip host {clean_ip} any\n"
                f"shun {clean_ip}\n"
                f"# Aplicado bloqueo inmediato de trafico entrante para {clean_ip}"
            ),
            "Linux iptables / UFW": (
                f"iptables -I INPUT -s {clean_ip} -j DROP\n"
                f"iptables -I FORWARD -s {clean_ip} -j DROP\n"
                f"# O con UFW: ufw insert 1 deny from {clean_ip} to any"
            ),
            "Windows Defender Firewall (PowerShell)": (
                f"New-NetFirewallRule -DisplayName \"SOC_Bloqueo_{clean_ip}\" "
                f"-Direction Inbound -Action Block -RemoteAddress \"{clean_ip}\" "
                f"-Description \"Bloqueo perimetral generado por SOC SERMIG 2026\""
            )
        }

    def generate_csirt_notification(self, incident: Dict[str, Any]) -> str:
        """Genera un borrador formal de notificación de incidente bajo el Art. 7 de la Ley N° 21.663."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        title = incident.get("title") or incident.get("tipo") or "Incidente de Ciberseguridad"
        severity = incident.get("severity") or incident.get("severidad") or "Alta"
        src_ip = incident.get("src_ip") or incident.get("ip_origen") or "Desconocida"
        dst_asset = incident.get("target_asset") or incident.get("activo_afectado") or "Infraestructura SERMIG"
        mitre_tech = incident.get("mitre_technique") or "T1071 - Application Layer Protocol"
        desc = incident.get("description") or incident.get("descripcion") or "Detección de actividad anómala."
        action = incident.get("corrective_action") or incident.get("accion_correctiva") or "Aislamiento y bloqueo perimetral."

        notification = f"""================================================================================
NOTIFICACIÓN OBLIGATORIA DE INCIDENTE DE CIBERSEGURIDAD (LEY N° 21.663)
Destinatario: CSIRT de Gobierno / Agencia Nacional de Ciberseguridad (ANCI)
Organismo Emisor: Servicio Nacional de Migraciones (SERMIG)
Fecha y Hora de Detección: {now_str}
================================================================================

1. IDENTIFICACIÓN DEL INCIDENTE
--------------------------------------------------------------------------------
* Tipo de Incidente / Amenaza : {title}
* Nivel de Severidad Preliminar : {severity.upper()}
* Activo Institucional Afectado : {dst_asset}
* Origen de la Amenaza (IP/Host) : {src_ip}
* Mapeo Táctico MITRE ATT&CK    : {mitre_tech}

2. DESCRIPCIÓN DE LOS HECHOS
--------------------------------------------------------------------------------
{desc}

3. IMPACTO PRELIMINAR Y AFECTACIÓN
--------------------------------------------------------------------------------
* Confidencialidad : Controlada bajo protocolos de aislamiento.
* Integridad        : En proceso de verificación forense.
* Disponibilidad    : Servicios críticos operativos con mitigación activa.
* Compromiso de Datos Personales (Ley 19.628): No evidenciado / En revisión preventiva.

4. MEDIDAS DE CONTENCIÓN Y MITIGACIÓN ADOPTADAS
--------------------------------------------------------------------------------
* {action}
* Bloqueo perimetral de IOCs asociados en Firewalls institucionales.
* Revocación preventiva de sesiones y preservación de logs para análisis forense.

5. CONTACTO DEL RESPONSABLE INSTITUCIONAL (CISO)
--------------------------------------------------------------------------------
* Responsable: Equipo de Respuesta a Incidentes (CSIRT-SERMIG / SOC)
* Correo de Contacto: seguridad.informacion@serviciomigraciones.cl
* Estado del Incidente: EN PROCESO DE CONTENCIÓN / MITIGADO
================================================================================"""
        return notification

    def diagnose_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Realiza un diagnóstico exhaustivo del incidente usando Ollama (si está activo) o el Motor Heurístico."""
        if self.is_ollama_available():
            try:
                llm_result = self._query_ollama(incident)
                if llm_result:
                    return llm_result
            except Exception:
                pass

        return self._heuristic_diagnosis(incident)

    def _query_ollama(self, incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Consulta al modelo local de Ollama con un prompt especializado de ciberseguridad."""
        prompt = f"""Eres un Analista Experto de Ciberseguridad de Nivel 3 en el SOC del Servicio Nacional de Migraciones (SERMIG) de Chile.
Analiza el siguiente incidente y responde estrictamente con un JSON estructurado:

Incidente:
- Título: {incident.get('title') or incident.get('tipo')}
- Severidad: {incident.get('severity') or incident.get('severidad')}
- IP Origen: {incident.get('src_ip') or incident.get('ip_origen')}
- Activo Afectado: {incident.get('target_asset') or incident.get('activo_afectado')}
- Mapeo MITRE: {incident.get('mitre_technique')}
- Descripción: {incident.get('description') or incident.get('descripcion')}

El JSON debe tener exactamente estos campos:
{{
  "resumen_ejecutivo": "Explicación breve y concisa de la amenaza en español",
  "vector_ataque": "Cómo opera el atacante y objetivo principal",
  "riesgo_institucional": "Impacto potencial en la continuidad operacional y datos de SERMIG",
  "recomendacion_inmediata": "Acción prioritaria que debe tomar el operador del SOC",
  "normativa_iso27001": "Controles ISO 27001:2022 aplicables (ej. A.5.24, A.8.15)"
}}
Responde ÚNICAMENTE el código JSON sin texto adicional."""

        payload = {
            "model": self.default_model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_response = data.get("response", "")
            parsed = json.loads(raw_response)
            
            src_ip = incident.get("src_ip") or incident.get("ip_origen") or ""
            return {
                "engine_used": f"Ollama LLM ({self.default_model})",
                "resumen": parsed.get("resumen_ejecutivo", "Análisis completado por IA local."),
                "vector": parsed.get("vector_ataque", "Vector identificado."),
                "riesgo": parsed.get("riesgo_institucional", "Riesgo evaluado."),
                "recomendacion": parsed.get("recomendacion_inmediata", "Aplicar contención inmediata."),
                "iso_controls": parsed.get("normativa_iso27001", "A.5.24 - Gestión de Incidentes"),
                "firewall_commands": self.generate_firewall_commands(src_ip),
                "csirt_report": self.generate_csirt_notification(incident)
            }

    def _heuristic_diagnosis(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Diagnóstico heurístico y contextual autónomo sin dependencias externas."""
        title = (incident.get("title") or incident.get("tipo") or "").lower()
        desc = (incident.get("description") or incident.get("descripcion") or "").lower()
        src_ip = incident.get("src_ip") or incident.get("ip_origen") or "Desconocida"
        severity = incident.get("severity") or incident.get("severidad") or "Media"

        if "cti match" in title or "feodo" in desc or "botnet" in desc or "c2" in desc:
            resumen = "Conexión detectada hacia infraestructura maliciosa catalogada en listas de Inteligencia de Amenazas (CTI) activas."
            vector = "Establecimiento de canal de Comando y Control (C2 / C&C). El malware intenta recibir instrucciones remotas o exfiltrar credenciales."
            riesgo = "Crítico. Compromiso de terminales internos, potencial despliegue de ransomware o robo de bases de datos de identidad."
            recomendacion = f"Aislar inmediatamente el host local de la red física/Wi-Fi, bloquear {src_ip} en el Firewall perimetral y recolectar dump de memoria RAM."
            iso = "A.8.7 (Protección contra Malware), A.8.16 (Actividades de Monitoreo), A.5.24 (Gestión de Incidentes)"
        elif "fuerza bruta" in title or "brute" in desc or "ssh" in title or "rdp" in title:
            resumen = "Múltiples intentos fallidos de autenticación en un corto período de tiempo contra servicios de acceso remoto."
            vector = "Ataque de diccionario o pulverización de contraseñas (Password Spraying) buscando credenciales de usuarios válidos."
            riesgo = "Alto. Riesgo de acceso no autorizado con privilegios elevados y posterior movimiento lateral en la red de SERMIG."
            recomendacion = f"Bloquear la IP {src_ip} mediante regla perimetral, forzar cambio de contraseña de usuarios afectados y habilitar MFA obligatorio."
            iso = "A.5.17 (Información de Autenticación), A.8.5 (Autenticación Segura), A.8.18 (Gestión de Derechos de Acceso Privilegiados)"
        elif "escaneo" in title or "scan" in desc or "port" in desc:
            resumen = "Sondeo secuencial o masivo de puertos TCP/UDP desde una fuente externa o interna anómala."
            vector = "Reconocimiento y enumeración de servicios expuestos para identificar versiones vulnerables previo a la explotación."
            riesgo = "Medio a Alto. Fase preparatoria de un ataque dirigido hacia servidores de aplicaciones o bases de datos."
            recomendacion = f"Bloquear la IP origen en listas de denegación temporal (Rate Limiting) y verificar que puertos de gestión no estén expuestos a internet."
            iso = "A.8.20 (Seguridad en Redes), A.8.22 (Segregación de Redes), A.8.8 (Gestión de Vulnerabilidades Técnicas)"
        elif "sql" in title or "inyeccion" in desc or "web" in title or "xss" in desc:
            resumen = "Envío de payloads maliciosos orientados a subvertir la lógica de consultas de bases de datos o aplicaciones web."
            vector = "Explotación de vulnerabilidad de inyección en endpoints web institucionales para extraer o manipular registros."
            riesgo = "Crítico. Compromiso directo de la confidencialidad de datos personales protegidos por la Ley N° 19.628."
            recomendacion = f"Habilitar regla WAF (Web Application Firewall) para el parámetro vulnerable, bloquear IP {src_ip} y auditar consultas recientes en BD."
            iso = "A.8.26 (Requisitos de Seguridad en Aplicaciones), A.8.28 (Codificación Segura), A.5.33 (Protección de Registros)"
        else:
            resumen = f"Actividad anómala reportada en el SOC categorizada con severidad {severity}."
            vector = "Comportamiento que se desvía de la línea base operativa o activación de alertas de telemetría."
            riesgo = f"Riesgo proporcional a severidad {severity}. Requiere validación de analista N1/N2."
            recomendacion = f"Verificar logs en el host destino, contrastar IP {src_ip} con feeds CTI y aplicar contención según playbook estándar."
            iso = "A.5.24 (Planificación y Preparación para Incidentes), A.8.15 (Registro y Monitoreo)"

        return {
            "engine_used": "Motor Heurístico Experto Autónomo (Zero-Dependency)",
            "resumen": resumen,
            "vector": vector,
            "riesgo": riesgo,
            "recomendacion": recomendacion,
            "iso_controls": iso,
            "firewall_commands": self.generate_firewall_commands(src_ip),
            "csirt_report": self.generate_csirt_notification(incident)
        }
