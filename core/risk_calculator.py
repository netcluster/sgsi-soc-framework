# -*- coding: utf-8 -*-
"""
Módulo de Evaluación de Riesgos ISO/IEC 27005 para el SGSI.
Calcula Riesgo Inherente, Eficacia de Controles y Riesgo Residual.
Provee operaciones CRUD completas con persistencia y sincronización.
"""

import csv
import json
import os
import shutil
from typing import List, Dict, Any

class RiskCalculator:
    def __init__(self, template_path: str = None, sync_path: str = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.template_path = template_path or os.path.join(base_dir, "templates_google", "02_matriz_riesgos_template.csv")
        self.sync_path = sync_path or os.path.join(base_dir, "sync_drive", "02_matriz_riesgos.csv")
        self.categories = {
            (1, 4): ("Bajo", "Aceptable", "#2ECC71"),
            (5, 9): ("Medio", "Tolerable", "#F39C12"),
            (10, 16): ("Alto", "Inaceptable", "#E67E22"),
            (17, 25): ("Extremo", "Crítico Inmediato", "#E74C3C")
        }

    def categorize_risk(self, score: int) -> tuple:
        """Retorna (Nivel, Tratamiento Recomendado, Color Hex)"""
        for (low, high), (level, treatment, color) in self.categories.items():
            if low <= score <= high:
                return level, treatment, color
        return "Desconocido", "Revisar", "#95A5A6"

    def calculate_residual(self, prob_inh: int, imp_inh: int, control_eff_pct: float) -> dict:
        """
        Calcula el riesgo residual basado en la eficacia porcentual de controles.
        """
        inherent_score = int(prob_inh) * int(imp_inh)
        inh_level, inh_action, _ = self.categorize_risk(inherent_score)

        # Reducción de probabilidad e impacto según eficacia
        reduction_factor = max(0.0, min(1.0, float(control_eff_pct) / 100.0))
        
        prob_res = max(1, round(int(prob_inh) * (1.0 - (reduction_factor * 0.7))))
        imp_res = max(1, round(int(imp_inh) * (1.0 - (reduction_factor * 0.5))))
        residual_score = prob_res * imp_res
        res_level, res_action, _ = self.categorize_risk(residual_score)

        return {
            "inherent_score": inherent_score,
            "inherent_level": inh_level,
            "prob_residual": prob_res,
            "imp_residual": imp_res,
            "residual_score": residual_score,
            "residual_level": res_level,
            "treatment_strategy": "Mitigar" if residual_score > 4 else "Aceptar"
        }

    def get_all_risks(self, file_path: str = None) -> List[Dict[str, Any]]:
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
            print(f"[RiskCalculator Sync Error] {e}")

    def save_risk(self, risk_data: Dict[str, Any], file_path: str = None) -> str:
        """Agrega o edita un riesgo en la matriz y recalcula sus valores"""
        target = file_path or self.template_path
        risks = self.get_all_risks(target)
        
        risk_id = str(risk_data.get("ID_Riesgo", "")).strip()
        if not risk_id:
            # Generar nuevo ID secuencial RSG-XXX
            existing_ids = [r.get("ID_Riesgo", "") for r in risks if r.get("ID_Riesgo", "").startswith("RSG-")]
            max_num = 0
            for rid in existing_ids:
                try:
                    num = int(rid.replace("RSG-", ""))
                    if num > max_num:
                        max_num = num
                except:
                    pass
            risk_id = f"RSG-{max_num + 1:03d}"
            risk_data["ID_Riesgo"] = risk_id

        # Recalcular métricas
        p_inh = int(risk_data.get("Probabilidad_Inherente_1a5", 3))
        i_inh = int(risk_data.get("Impacto_Inherente_1a5", 3))
        eff_raw = str(risk_data.get("Eficacia_Controles_Pct", "50%")).replace('%', '').strip()
        eff = float(eff_raw) if eff_raw else 50.0

        calc = self.calculate_residual(p_inh, i_inh, eff)
        risk_data["Probabilidad_Inherente_1a5"] = str(p_inh)
        risk_data["Impacto_Inherente_1a5"] = str(i_inh)
        risk_data["Nivel_Riesgo_Inherente"] = str(calc["inherent_score"])
        risk_data["Categoria_Riesgo_Inherente"] = calc["inherent_level"]
        risk_data["Eficacia_Controles_Pct"] = f"{int(eff)}%"
        risk_data["Probabilidad_Residual_1a5"] = str(calc["prob_residual"])
        risk_data["Impacto_Residual_1a5"] = str(calc["imp_residual"])
        risk_data["Nivel_Riesgo_Residual"] = str(calc["residual_score"])
        risk_data["Categoria_Riesgo_Residual"] = calc["residual_level"]
        risk_data["Estrategia_Tratamiento"] = risk_data.get("Estrategia_Tratamiento") or calc["treatment_strategy"]

        # Buscar si ya existe para actualizar o insertar
        updated = False
        for idx, r in enumerate(risks):
            if r.get("ID_Riesgo") == risk_id:
                risks[idx] = risk_data
                updated = True
                break

        if not updated:
            risks.append(risk_data)

        # Escribir CSV
        fieldnames = [
            "ID_Riesgo", "ID_Activo", "Amenaza", "Vulnerabilidad",
            "Probabilidad_Inherente_1a5", "Impacto_Inherente_1a5",
            "Nivel_Riesgo_Inherente", "Categoria_Riesgo_Inherente",
            "Controles_Aplicados", "Eficacia_Controles_Pct",
            "Probabilidad_Residual_1a5", "Impacto_Residual_1a5",
            "Nivel_Riesgo_Residual", "Categoria_Riesgo_Residual",
            "Estrategia_Tratamiento", "Responsable", "Fecha_Revision"
        ]

        with open(target, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(risks)

        self._sync_to_drive(target)
        return risk_id

    def delete_risk(self, risk_id: str, file_path: str = None) -> bool:
        """Elimina un riesgo por su ID"""
        target = file_path or self.template_path
        risks = self.get_all_risks(target)
        new_risks = [r for r in risks if r.get("ID_Riesgo") != risk_id]

        if len(new_risks) == len(risks):
            return False

        if new_risks:
            fieldnames = list(new_risks[0].keys())
        else:
            fieldnames = [
                "ID_Riesgo", "ID_Activo", "Amenaza", "Vulnerabilidad",
                "Probabilidad_Inherente_1a5", "Impacto_Inherente_1a5",
                "Nivel_Riesgo_Inherente", "Categoria_Riesgo_Inherente",
                "Controles_Aplicados", "Eficacia_Controles_Pct",
                "Probabilidad_Residual_1a5", "Impacto_Residual_1a5",
                "Nivel_Riesgo_Residual", "Categoria_Riesgo_Residual",
                "Estrategia_Tratamiento", "Responsable", "Fecha_Revision"
            ]

        with open(target, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(new_risks)

        self._sync_to_drive(target)
        return True

    def process_risk_matrix(self, input_csv: str = None, output_csv: str = None) -> List[Dict[str, Any]]:
        """Procesa un archivo CSV de riesgos y recalcula todas las métricas"""
        in_path = input_csv or self.template_path
        out_path = output_csv or self.template_path
        results = []
        if not os.path.exists(in_path):
            raise FileNotFoundError(f"No se encontró el archivo de riesgos: {in_path}")

        with open(in_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                p_inh = int(row.get('Probabilidad_Inherente_1a5', 3))
                i_inh = int(row.get('Impacto_Inherente_1a5', 3))
                eff_raw = str(row.get('Eficacia_Controles_Pct', '50%')).replace('%', '').strip()
                eff = float(eff_raw) if eff_raw else 50.0

                calc = self.calculate_residual(p_inh, i_inh, eff)
                row['Nivel_Riesgo_Inherente'] = str(calc['inherent_score'])
                row['Categoria_Riesgo_Inherente'] = calc['inherent_level']
                row['Probabilidad_Residual_1a5'] = str(calc['prob_residual'])
                row['Impacto_Residual_1a5'] = str(calc['imp_residual'])
                row['Nivel_Riesgo_Residual'] = str(calc['residual_score'])
                row['Categoria_Riesgo_Residual'] = calc['residual_level']
                row['Estrategia_Tratamiento'] = calc['treatment_strategy']
                results.append(row)

        if results:
            with open(out_path, mode='w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)

        self._sync_to_drive(out_path)
        return results
