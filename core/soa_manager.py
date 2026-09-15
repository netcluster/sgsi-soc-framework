# -*- coding: utf-8 -*-
"""
Gestor de la Declaración de Aplicabilidad (SoA) ISO/IEC 27001:2022.
Permite administrar, actualizar estados de madurez, responsables y justificaciones
de los 93 controles de seguridad con persistencia y sincronización dual.
"""

import csv
import json
import os
import shutil
from typing import List, Dict, Any

class SoAManager:
    def __init__(self, template_path: str = None, sync_path: str = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.template_path = template_path or os.path.join(base_dir, 'templates_google', '03_soa_iso27001_template.csv')
        self.sync_path = sync_path or os.path.join(base_dir, 'sync_drive', '03_soa_iso27001.csv')

    def get_all_controls(self, file_path: str = None) -> List[Dict[str, Any]]:
        target = file_path or self.template_path
        if not os.path.exists(target):
            return []
        with open(target, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            return list(reader)

    def _sync_to_drive(self, source_path: str):
        try:
            os.makedirs(os.path.dirname(self.sync_path), exist_ok=True)
            shutil.copy2(source_path, self.sync_path)
        except Exception as e:
            print(f'[SoAManager Sync Error] {e}')

    def update_control(self, control_code: str, updated_data: Dict[str, Any], file_path: str = None) -> bool:
        target = file_path or self.template_path
        controls = self.get_all_controls(target)
        found = False

        for idx, c in enumerate(controls):
            if c.get('Codigo_Control', '').strip() == control_code.strip():
                for k, v in updated_data.items():
                    controls[idx][k] = str(v)
                found = True
                break

        if not found:
            return False

        fieldnames = [
            'Codigo_Control', 'Nombre_Control', 'Dominio', 'Aplica',
            'Justificacion_Inclusion_Exclusion', 'Estado_Implementacion',
            'Porcentaje_Madurez', 'Evidencia_Documental', 'Responsable'
        ]

        with open(target, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(controls)

        self._sync_to_drive(target)
        return True

    def batch_set_status(self, control_codes: List[str], status: str, maturity_pct: int, file_path: str = None) -> int:
        target = file_path or self.template_path
        controls = self.get_all_controls(target)
        count = 0

        for idx, c in enumerate(controls):
            if c.get('Codigo_Control', '').strip() in control_codes:
                controls[idx]['Estado_Implementacion'] = status
                controls[idx]['Porcentaje_Madurez'] = str(maturity_pct)
                if status == "No Aplica":
                    controls[idx]['Aplica'] = "NO"
                elif status in ["Implementado", "En Proceso", "Planificado", "No Implementado"]:
                    controls[idx]['Aplica'] = "SI"
                count += 1

        if count > 0:
            fieldnames = [
                'Codigo_Control', 'Nombre_Control', 'Dominio', 'Aplica',
                'Justificacion_Inclusion_Exclusion', 'Estado_Implementacion',
                'Porcentaje_Madurez', 'Evidencia_Documental', 'Responsable'
            ]
            with open(target, mode='w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(controls)

            self._sync_to_drive(target)

        return count