# -*- coding: utf-8 -*-
"""
Parser de logs y eventos de seguridad multiformato para el SOC.
Soporta:
1. FortiGate / FortiOS Logs de Tráfico y Seguridad (pares clave=valor).
2. Syslog estándar (RFC 3164 / 5424 / Linux auth).
3. Nginx / Apache Combined Web Access Logs.
4. CEF / JSON / Eventos Genéricos de Firewall.
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

    # Regex para extracción rápida de pares key=value o key="value" (FortiGate, Palo Alto, CEF)
    KV_REGEX = re.compile(r'(?P<key>[\w\.\-]+)=(?:\"(?P<qval>[^\"]*)\"|(?P<val>[^\s]+))')

    @classmethod
    def parse_line(cls, line: str) -> Dict[str, Any]:
        """Detecta automáticamente el formato y parsea la línea."""
        line = line.strip()
        if not line:
            return {}

        # 1. Probar formato FortiGate / Clave=Valor (Ej: date=2026-09-15 time=09:05:17 ... srcip=...)
        if ("type=" in line and "srcip=" in line) or ("subtype=" in line and "dstip=" in line) or line.startswith("date="):
            kv_dict = {}
            for match in cls.KV_REGEX.finditer(line):
                k = match.group("key")
                v = match.group("qval") if match.group("qval") is not None else match.group("val")
                kv_dict[k] = v

            date_str = kv_dict.get("date", datetime.now().strftime("%Y-%m-%d"))
            time_str = kv_dict.get("time", datetime.now().strftime("%H:%M:%S"))
            timestamp = f"{date_str} {time_str}"

            return {
                "format": "fortigate_traffic",
                "timestamp": timestamp,
                "src_ip": kv_dict.get("srcip", "0.0.0.0"),
                "src_port": kv_dict.get("srcport", ""),
                "dst_ip": kv_dict.get("dstip", "0.0.0.0"),
                "dst_port": kv_dict.get("dstport", ""),
                "action": kv_dict.get("action", ""),
                "service": kv_dict.get("service", ""),
                "policyname": kv_dict.get("policyname", ""),
                "level": kv_dict.get("level", "notice"),
                "crlevel": kv_dict.get("crlevel", ""),
                "crscore": kv_dict.get("crscore", "0"),
                "msg": kv_dict.get("msg", ""),
                "proto": kv_dict.get("proto", ""),
                "sentbyte": int(kv_dict.get("sentbyte", 0) or 0),
                "rcvdbyte": int(kv_dict.get("rcvdbyte", 0) or 0),
                "devtype": kv_dict.get("devtype", "Firewall"),
                "raw": line,
                "kv": kv_dict
            }

        # 2. Probar Syslog estándar
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

        # 3. Probar Web Access Log
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

        # 4. Fallback Genérico
        return {
            "format": "generic",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": "local",
            "message": line,
            "raw": line
        }
