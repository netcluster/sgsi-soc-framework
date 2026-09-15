# -*- coding: utf-8 -*-
import re
from collections import Counter

log_path = r"C:\Users\RICARDO.ALFARO\Documents\sgsi_soc_framework\memory-traffic-forward-2026_09_15.log"

actions = Counter()
services = Counter()
levels = Counter()
crlevels = Counter()
dstports = Counter()
srcips = Counter()
threat_patterns = Counter()

count = 0
with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        count += 1
        
        # Parse key=value pairs
        m_act = re.search(r'action="?([^"\s]+)', line)
        if m_act:
            actions[m_act.group(1)] += 1

        m_lvl = re.search(r'level="?([^"\s]+)', line)
        if m_lvl:
            levels[m_lvl.group(1)] += 1

        m_crl = re.search(r'crlevel="?([^"\s]+)', line)
        if m_crl:
            crlevels[m_crl.group(1)] += 1

        m_srv = re.search(r'service="?([^"\s]+)', line)
        if m_srv:
            services[m_srv.group(1)] += 1

        m_sip = re.search(r'srcip=([^\s]+)', line)
        if m_sip:
            srcips[m_sip.group(1)] += 1

        m_dip = re.search(r'dstip=([^\s]+)', line)
        m_dpt = re.search(r'dstport=([^\s]+)', line)
        
        # Check suspicious actions
        if m_act and m_act.group(1) in ['deny', 'drop', 'block', 'timeout', 'client-rst', 'server-rst', 'ip-conn']:
            threat_patterns[m_act.group(1)] += 1

print(f"Total de líneas analizadas en log real: {count}")
print("\nAcciones:", actions.most_common(10))
print("\nNiveles de Severidad del Firewall:", levels.most_common(10))
print("\nNivel de Riesgo (crlevel):", crlevels.most_common(10))
print("\nTop Servicios de Red:", services.most_common(10))
print("\nTop IPs Origen con mayor tráfico:", srcips.most_common(10))
print("\nPatrones de Tráfico Sospechoso/Bloqueado:", threat_patterns.most_common(10))
