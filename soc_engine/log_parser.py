# -*- coding: utf-8 -*-
"""
Parser de logs y eventos de seguridad multiformato para el SOC.
Soporta: Syslog (RFC 3164 / 5424), Nginx/Apache Web Logs, JSON Logs y Eventos Genéricos.
"""

import re
from datetime import datetime
from typing import Dict, Any, Optional

class LogParser:
    # Regex para Syslog estándar (Linux / Firewalls / Routers)
    SYSLOG_REGEX = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\.\-]+)\s+(?P<process>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
    )
    
    # Regex para Nginx / Apache Combined Access Log
    WEB_LOG_REGEX = re.compile(
        r'^(?P<client_ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<time_local>[^\]]+)\]\s+\"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<proto>[^\"]+)\"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)'
    )

    @classmethod
    def parse_line(cls, line: str) -> Dict[str, Any]:
        """Detecta automáticamente el formato y parsea la línea."""
        line = line.strip()
        if not line:
            return {}

        # 1. Probar Syslog
        sys_match = cls.SYSLOG_REGEX.match(line)
        if sys_match:
            d = sys_match.groupdict()
            return {
                "format": "syslog",
                "timestamp": d["timestamp"],
                "host": d["host"],
                "process": d["process"],
                "message": d["message"],
                "raw": line
            }

        # 2. Probar Web Access Log
        web_match = cls.WEB_LOG_REGEX.match(line)
        if web_match:
            d = web_match.groupdict()
            return {
                "format": "web_access",
                "timestamp": d["time_local"],
                "client_ip": d["client_ip"],
                "user": d["user"],
                "method": d["method"],
                "uri": d["uri"],
                "status": int(d["status"]),
                "raw": line
            }

        # 3. Fallback Genérico
        return {
            "format": "generic",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": "local",
            "message": line,
            "raw": line
        }
