# -*- coding: utf-8 -*-
"""
Gestor del Inventario de Activos de Información (SGSI ISO/IEC 27001:2022 Control 5.9 / Ley N° 21.663).
Permite administrar el ciclo de vida de los activos, propietarios (Owners), custodios (Custodians),
ubicación lógica/física y la valoración de la Tríada CIA (Confidencialidad, Integridad, Disponibilidad).
Incluye controles de seguridad basados en OWASP Top 10 (Saneamiento contra CSV/Formula Injection,
validación de tipos y persistencia íntegra).
"""

import csv
import os
import shutil
import re
from typing import List, Dict, Any, Optional

def sanitize_owasp_csv_field(val: Any) -> str:
    """
    Saneamiento OWASP contra CSV / Formula Injection (OWASP A03 / A08).
    Previene la inyección de fórmulas de hojas de cálculo (=, +, -, @, tab, retorno).
    """
    s = str(val or '').strip()
    if s.startswith(('=', '+', '-', '@', '\t', '\r')):
        s = "'" + s
    return s

class AssetManager:
    def __init__(self, template_path: str = None, sync_path: str = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.template_path = template_path or os.path.join(base_dir, 'templates_google', '01_inventario_activos_template.csv')
        self.sync_path = sync_path or os.path.join(base_dir, 'sync_drive', '01_inventario_activos.csv')

    @staticmethod
    def calculate_criticality(c: int, i: int, a: int) -> tuple:
        """
        Calcula la criticidad global según estándar ISO 27005 y directrices ANCI / SERMIG:
        Criticidad = C + I + A (Escala 3 a 15)
        Niveles:
          - Crítico: 13 a 15
          - Alto: 10 a 12
          - Medio: 7 a 9
          - Bajo: 3 a 6
        """
        c = max(1, min(5, int(c)))
        i = max(1, min(5, int(i)))
        a = max(1, min(5, int(a)))
        score = c + i + a
        if score >= 13:
            nivel = 'Critico'
        elif score >= 10:
            nivel = 'Alto'
        elif score >= 7:
            nivel = 'Medio'
        else:
            nivel = 'Bajo'
        return score, nivel

    def get_all_assets(self, file_path: str = None) -> List[Dict[str, Any]]:
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
            print(f'[AssetManager Sync Error] {e}')

    def add_asset(self, asset_data: Dict[str, Any], file_path: str = None) -> str:
        target = file_path or self.template_path
        assets = self.get_all_assets(target)

        existing_ids = [a.get('ID_Activo', '') for a in assets]
        max_num = 0
        for aid in existing_ids:
            match = re.search(r'ACT-(\d+)', aid)
            if match:
                max_num = max(max_num, int(match.group(1)))
        new_id = f"ACT-{str(max_num + 1).zfill(3)}"

        c = int(asset_data.get('Confidencialidad_1a5', 3))
        i = int(asset_data.get('Integridad_1a5', 3))
        a = int(asset_data.get('Disponibilidad_1a5', 3))
        score, nivel = self.calculate_criticality(c, i, a)

        new_asset = {
            'ID_Activo': new_id,
            'Nombre_Activo': sanitize_owasp_csv_field(asset_data.get('Nombre_Activo', '')),
            'Tipo_Activo': sanitize_owasp_csv_field(asset_data.get('Tipo_Activo', 'Informacion / Base de Datos')),
            'Propietario': sanitize_owasp_csv_field(asset_data.get('Propietario', 'CISO / Jefatura')),
            'Custodio': sanitize_owasp_csv_field(asset_data.get('Custodio', 'Administrador de Sistemas')),
            'Ubicacion': sanitize_owasp_csv_field(asset_data.get('Ubicacion', 'Datacenter SERMIG / Cloud')),
            'Confidencialidad_1a5': str(c),
            'Integridad_1a5': str(i),
            'Disponibilidad_1a5': str(a),
            'Criticidad_Calculada': str(score),
            'Nivel_Criticidad': nivel,
            'Estado': sanitize_owasp_csv_field(asset_data.get('Estado', 'Activo'))
        }

        assets.append(new_asset)
        self._save_assets(assets, target)
        return new_id

    def update_asset(self, asset_id: str, updated_data: Dict[str, Any], file_path: str = None) -> bool:
        target = file_path or self.template_path
        assets = self.get_all_assets(target)
        found = False

        for idx, a in enumerate(assets):
            if a.get('ID_Activo', '').strip() == asset_id.strip():
                for k, v in updated_data.items():
                    if k != 'ID_Activo':
                        assets[idx][k] = sanitize_owasp_csv_field(v)
                
                c = int(assets[idx].get('Confidencialidad_1a5', 3))
                i = int(assets[idx].get('Integridad_1a5', 3))
                a_val = int(assets[idx].get('Disponibilidad_1a5', 3))
                score, nivel = self.calculate_criticality(c, i, a_val)
                assets[idx]['Criticidad_Calculada'] = str(score)
                assets[idx]['Nivel_Criticidad'] = nivel
                
                found = True
                break

        if not found:
            return False

        self._save_assets(assets, target)
        return True

    def delete_asset(self, asset_id: str, file_path: str = None) -> bool:
        target = file_path or self.template_path
        assets = self.get_all_assets(target)
        initial_len = len(assets)
        assets = [a for a in assets if a.get('ID_Activo', '').strip() != asset_id.strip()]

        if len(assets) == initial_len:
            return False

        self._save_assets(assets, target)
        return True

    def _save_assets(self, assets: List[Dict[str, Any]], target: str):
        fieldnames = [
            'ID_Activo', 'Nombre_Activo', 'Tipo_Activo', 'Propietario',
            'Custodio', 'Ubicacion', 'Confidencialidad_1a5', 'Integridad_1a5',
            'Disponibilidad_1a5', 'Criticidad_Calculada', 'Nivel_Criticidad', 'Estado'
        ]
        with open(target, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(assets)

        self._sync_to_drive(target)
