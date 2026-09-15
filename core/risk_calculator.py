# -*- coding: utf-8 -*-
"""
Módulo de Evaluación de Riesgos ISO/IEC 27005 para el SGSI.
Calcula Riesgo Inherente, Eficacia de Controles y Riesgo Residual.
"""

import csv
import json
import os
from typing import List, Dict, Any

class RiskCalculator:
    def __init__(self):
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
        inherent_score = prob_inh * imp_inh
        inh_level, inh_action, _ = self.categorize_risk(inherent_score)

        # Reducción de probabilidad e impacto según eficacia
        reduction_factor = max(0.0, min(1.0, control_eff_pct / 100.0))
        
        prob_res = max(1, round(prob_inh * (1.0 - (reduction_factor * 0.7))))
        imp_res = max(1, round(imp_inh * (1.0 - (reduction_factor * 0.5))))
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

    def process_risk_matrix(self, input_csv: str, output_csv: str = None) -> List[Dict[str, Any]]:
        """Procesa un archivo CSV de riesgos y recalcula todas las métricas"""
        results = []
        if not os.path.exists(input_csv):
            raise FileNotFoundError(f"No se encontró el archivo de riesgos: {input_csv}")

        with open(input_csv, mode='r', encoding='utf-8-sig') as f:
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

        if output_csv and results:
            with open(output_csv, mode='w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)

        return results
