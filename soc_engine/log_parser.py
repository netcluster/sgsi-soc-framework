# -*- coding: utf-8 -*-
"""
Parser de logs y eventos de seguridad multiformato para el SOC.
Soporta extracción enriquecida de IP Origen, Nombre de Host Origen, IP Destino y Host Destino.
"""

import re
import socket
from datetime import datetime
from typing import Dict, Any, Optional

class LogParser:
    SYSLOG_REGEX = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\.\-]+)\s+(?P<process>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
    )
    
    WEB_LOG_REGEX = re.compile(
        r'^(?P<client_ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<time_local>[^\]]+)\]\s+\"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<proto>[^\"]+)\"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)'
    )

    KV_REGEX = re.compile(r'(?P<key>[\w\.\-]+)=(?:\"(?P<qval>[^\"]*)\"|(?P<val>[^\s]+))')

    # Cache de nombres de host para optimizar rendimiento
    _dns_cache = {}

    @classmethod
    def resolve_hostname(cls, ip: str) -> str:
        """Resuelve o formatea un nombre descriptivo para una IP"""
        if not ip or ip == "0.0.0.0":
            return "Desconocido"
        if ip in cls._dns_cache:
            return cls._dns_cache[ip]

        # Mapeo rápido de subredes conocidas
        if ip.startswith("10.123."):
            name = f"Host-SanAntonio ({ip})"
        elif ip.startswith("10.100."):
            name = f"Srv-Datacenter ({ip})"
        elif ip.startswith("10.105."):
            name = f"Wifi-Client ({ip})"
        elif ip.startswith("10.109."):
            name = f"LAN-Workstation ({ip})"
        elif ip == "169.254.169.254":
            name = "AWS/Cloud-Metadata-API"
        elif ip.startswith("127.") or ip == "localhost":
            name = "Localhost-Endpoint"
        else:
            name = ip

        cls._dns_cache[ip] = name
        return name

    @classmethod
    def parse_line(cls, line: str) -> Dict[str, Any]:
        """Detecta automáticamente el formato y extrae IPs y nombres de host."""
        line = line.strip()
        if not line:
            return {}

        # 1. Probar formato FortiGate / Clave=Valor
        if ("type=" in line and "srcip=" in line) or ("subtype=" in line and "dstip=" in line) or line.startswith("date="):
            kv = {}
            for match in cls.KV_REGEX.finditer(line):
                k = match.group("key")
                v = match.group("qval") if match.group("qval") is not None else match.group("val")
                kv[k] = v

            date_str = kv.get("date", datetime.now().strftime("%Y-%m-%d"))
            time_str = kv.get("time", datetime.now().strftime("%H:%M:%S"))
            timestamp = f"{date_str} {time_str}"

            src_ip = kv.get("srcip", "0.0.0.0")
            dst_ip = kv.get("dstip", "0.0.0.0")

            # Construir nombre de host origen (priorizando srcname > osname/vendor > subnet)
            src_name = kv.get("srcname") or kv.get("hostname") or kv.get("user")
            if not src_name:
                os_desc = []
                if kv.get("osname"): os_desc.append(kv.get("osname"))
                if kv.get("devtype"): os_desc.append(kv.get("devtype"))
                if kv.get("srchwvendor"): os_desc.append(kv.get("srchwvendor"))
                src_name = " / ".join(os_desc) if os_desc else cls.resolve_hostname(src_ip)

            # Construir nombre de host destino (priorizando dstname > policyname/service > country)
            dst_name = kv.get("dstname")
            if not dst_name:
                dst_parts = []
                if kv.get("service"): dst_parts.append(kv.get("service"))
                if kv.get("dstcountry") and kv.get("dstcountry") != "Reserved": dst_parts.append(kv.get("dstcountry"))
                if kv.get("policyname"): dst_parts.append(f"[{kv.get('policyname')}]")
                dst_name = " ".join(dst_parts) if dst_parts else cls.resolve_hostname(dst_ip)

            return {
                "format": "fortigate_traffic",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_host": src_name,
                "src_port": kv.get("srcport", ""),
                "dst_ip": dst_ip,
                "dst_host": dst_name,
                "dst_port": kv.get("dstport", ""),
                "action": kv.get("action", ""),
                "service": kv.get("service", ""),
                "policyname": kv.get("policyname", ""),
                "level": kv.get("level", "notice"),
                "crlevel": kv.get("crlevel", ""),
                "crscore": kv.get("crscore", "0"),
                "msg": kv.get("msg", ""),
                "proto": kv.get("proto", ""),
                "sentbyte": int(kv.get("sentbyte", 0) or 0),
                "rcvdbyte": int(kv.get("rcvdbyte", 0) or 0),
                "devtype": kv.get("devtype", "Firewall"),
                "raw": line,
                "kv": kv
            }

        # 2. Probar Syslog estándar
        sys_match = cls.SYSLOG_REGEX.match(line)
        if sys_match:
            d = sys_match.groupdict()
            host = d["host"]
            return {
                "format": "syslog",
                "timestamp": d["timestamp"],
                "src_ip": host,
                "src_host": host,
                "dst_ip": "127.0.0.1",
                "dst_host": "Servidor-Local",
                "process": d["process"],
                "message": d["message"],
                "raw": line
            }

        # 3. Probar Web Access Log
        web_match = cls.WEB_LOG_REGEX.match(line)
        if web_match:
            d = web_match.groupdict()
            client_ip = d["client_ip"]
            return {
                "format": "web_access",
                "timestamp": d["time_local"],
                "src_ip": client_ip,
                "src_host": d["user"] if d["user"] != "-" else cls.resolve_hostname(client_ip),
                "dst_ip": "10.0.1.15",
                "dst_host": "Servidor-Web-ERP",
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
            "src_ip": "local",
            "src_host": "Host-Local",
            "dst_ip": "local",
            "dst_host": "Servicio-Local",
            "message": line,
            "raw": line
        }
