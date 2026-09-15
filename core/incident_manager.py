# -*- coding: utf-8 -*-
"""
Gestor de Incidentes de Seguridad de la Información para SGSI y SOC.
Registra, audita y calcula KPIs operativos (MTTD, MTTR, Severidad, SLAs).
"""

import csv
import os
from datetime import datetime
from typing import List, Dict, Any

class IncidentManager:
    def __init__(self, incidents_csv: str = None):
        self.incidents_csv = incidents_csv or os.path.join("templates_google", "04_registro_incidentes_template.csv")

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.incidents_csv):
            return []
        with open(self.incidents_csv, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            return list(reader)

    def add_incident(self, incident_data: Dict[str, Any]) -> str:
        """Agrega un nuevo incidente detectado al registro histórico."""
        incidents = self.get_all_incidents()
        next_num = len(incidents) + 1
        year = datetime.now().year
        incident_id = f"INC-{year}-{next_num:03d}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        new_row = {
            "ID_Incidente": incident_id,
            "Fecha_Hora": incident_data.get("timestamp", now_str),
            "Titulo_Incidente": incident_data.get("title", "Alerta SOC"),
            "Tipo_Amenaza": incident_data.get("threat_type", "Desconocido"),
            "Severidad": incident_data.get("severity", "Media"),
            "Estado": incident_data.get("status", "Abierto"),
            "Tactica_MITRE": incident_data.get("mitre_tactic", "N/A"),
            "Tecnica_MITRE": incident_data.get("mitre_technique", "N/A"),
            "IP_Origen": incident_data.get("src_ip", "0.0.0.0"),
            "Host_Origen": incident_data.get("src_host", incident_data.get("user", "N/A")),
            "IP_Destino": incident_data.get("dst_ip", incident_data.get("target_asset", "N/A")),
            "Host_Destino": incident_data.get("dst_host", incident_data.get("target_asset", "N/A")),
            "IP_Destino_Activo": incident_data.get("target_asset", incident_data.get("dst_ip", "N/A")),
            "Usuario_Involucrado": incident_data.get("user", "N/A"),
            "MTTD_Minutos": incident_data.get("mttd_min", 5),
            "MTTR_Minutos": incident_data.get("mttr_min", 0),
            "Descripcion_Hallazgo": incident_data.get("description", ""),
            "Accion_Correctiva": incident_data.get("corrective_action", "En analisis"),
            "Responsable_SOC": incident_data.get("owner", "Analista SOC L1")
        }

        incidents.append(new_row)
        fieldnames = list(new_row.keys())
        with open(self.incidents_csv, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(incidents)

        return incident_id

    def compute_kpis(self) -> Dict[str, Any]:
        """Calcula KPIs clave del SOC (MTTD, MTTR, severidad, estado y tipos de amenaza)"""
        incidents = self.get_all_incidents()
        if not incidents:
            return {
                "total_incidents": 0,
                "avg_mttd_min": 0,
                "avg_mttr_min": 0,
                "by_severity": {},
                "by_status": {},
                "by_threat": {}
            }

        total = len(incidents)
        mttd_sum = 0
        mttr_sum = 0
        mttr_closed_count = 0
        by_severity = {}
        by_status = {}
        by_threat = {}

        for inc in incidents:
            sev = inc.get("Severidad", "Media")
            stat = inc.get("Estado", "Abierto")
            threat = inc.get("Tipo_Amenaza", "Otros")

            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_status[stat] = by_status.get(stat, 0) + 1
            by_threat[threat] = by_threat.get(threat, 0) + 1

            mttd = float(inc.get("MTTD_Minutos", 0) or 0)
            mttd_sum += mttd

            if stat == "Cerrado":
                mttr = float(inc.get("MTTR_Minutos", 0) or 0)
                mttr_sum += mttr
                mttr_closed_count += 1

        avg_mttd = round(mttd_sum / total, 1) if total > 0 else 0
        avg_mttr = round(mttr_sum / mttr_closed_count, 1) if mttr_closed_count > 0 else 0

        return {
            "total_incidents": total,
            "avg_mttd_min": avg_mttd,
            "avg_mttr_min": avg_mttr,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_threat": by_threat
        }
