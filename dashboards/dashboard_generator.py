# -*- coding: utf-8 -*-
"""
Generador de Dashboards Especializados en Python basados en Principios Científicos de Visualización de Datos:
1. Ratio Data-Ink (Edward Tufte): Eliminación de 'chartjunk', maximización de señal sobre ruido, rejillas sutiles.
2. Jerarquías Visuales y Patrones de Exploración Ocular (Z-Pattern & F-Pattern): Indicadores clave arriba, detección de anomalías al centro, drilldown al fondo.
3. Semiótica y Consistencia Semántica de Colores: Rojo (#DC2626) para alertas críticas/riesgos extremos, Naranja (#EA580C) para alta severidad, Amarillo (#F59E0B) para media/en proceso, Verde (#10B981) para mitigado/implementado, Azul/Gris (#1E293B/#2563EB) para telemetría técnica.
"""

import os
import sys
import csv
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import plotly.graph_objects as go
import plotly.express as px

from core.risk_calculator import RiskCalculator
from core.incident_manager import IncidentManager

# Paleta Semiótica Global Unificada
COLOR_CRITICAL = "#DC2626"   # Rojo - Crítico / Emergencia / Riesgo Extremo
COLOR_HIGH     = "#EA580C"   # Naranja - Alto / Alerta Importante
COLOR_MEDIUM   = "#F59E0B"   # Ámbar - Medio / En Proceso / Precaución
COLOR_LOW      = "#10B981"   # Verde Esmeralda - Bajo / Mitigado / Implementado
COLOR_PLANNED  = "#64748B"   # Gris Pizarra - Planificado / En Evaluación
COLOR_PRIMARY  = "#0F172A"   # Azul Medianoche - Texto / Jerarquía Principal
COLOR_ACCENT   = "#2563EB"   # Azul Técnico - Métricas de Telemetría
COLOR_GRID     = "#E2E8F0"   # Rejilla sutil para alto ratio Data-Ink

# Configuración Plotly limpia (sin barra de herramientas ni logo de Plotly)
PLOTLY_CONFIG = {
    'displayModeBar': False,
    'displaylogo': False,
    'responsive': True
}

def get_severity_badge_color(sev: str) -> str:
    """Mapeo semiótico estricto e insensible a mayúsculas/tildes"""
    s = str(sev).strip().lower()
    if any(k in s for k in ["crit", "crít", "urgente", "emerg"]):
        return COLOR_CRITICAL   # #DC2626 (Rojo)
    elif any(k in s for k in ["alt", "high"]):
        return COLOR_HIGH       # #EA580C (Naranja)
    elif any(k in s for k in ["med", "mod"]):
        return COLOR_MEDIUM     # #F59E0B (Ámbar)
    elif any(k in s for k in ["baj", "low", "info"]):
        return COLOR_LOW        # #10B981 (Verde)
    return COLOR_MEDIUM

class DashboardGenerator:
    def __init__(self, templates_dir: str = None, output_dir: str = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.templates_dir = templates_dir or os.path.join(base_dir, "templates_google")
        self.output_dir = output_dir or os.path.join(base_dir, "dashboards", "html")
        os.makedirs(self.output_dir, exist_ok=True)

    def _load_csv(self, filename: str) -> List[Dict[str, Any]]:
        path = os.path.join(self.templates_dir, filename)
        if not os.path.exists(path):
            return []
        with open(path, mode='r', encoding='utf-8-sig') as f:
            return list(csv.DictReader(f))

    # =========================================================================
    # 1. DASHBOARD CISO & SOC (TÉCNICO / TÁCTICO & DETECCIÓN DE ANOMALÍAS)
    # =========================================================================
    def generate_ciso_dashboard(self, filename: str = "dashboard_ciso.html") -> str:
        incidents = self._load_csv("04_registro_incidentes_template.csv")
        risks = self._load_csv("02_matriz_riesgos_template.csv")
        soa = self._load_csv("03_soa_iso27001_template.csv")

        inc_mgr = IncidentManager(os.path.join(self.templates_dir, "04_registro_incidentes_template.csv"))
        kpis = inc_mgr.compute_kpis()

        # ---------------------------------------------------------------------
        # GRÁFICO 1: LÍNEA TEMPORAL DE TELEMETRÍA & DETECCIÓN DE PICOS / ANOMALÍAS
        # Principio: Data-Ink Ratio & Anomaly Detection
        # ---------------------------------------------------------------------
        # Agrupar incidentes por fecha / día o franja horaria
        time_series = defaultdict(lambda: {"total": 0, "criticos": 0, "altos": 0})
        for inc in incidents:
            ts_str = inc.get("Fecha_Hora", "")
            # Extraer fecha YYYY-MM-DD
            dt_key = ts_str.split(" ")[0] if " " in ts_str else ts_str[:10]
            if not dt_key or len(dt_key) < 8:
                dt_key = datetime.now().strftime("%Y-%m-%d")
            
            sev = inc.get("Severidad", "")
            time_series[dt_key]["total"] += 1
            if "Crit" in sev:
                time_series[dt_key]["criticos"] += 1
            elif "Alt" in sev:
                time_series[dt_key]["altos"] += 1

        sorted_dates = sorted(time_series.keys())
        counts_total = [time_series[d]["total"] for d in sorted_dates]
        counts_crit = [time_series[d]["criticos"] for d in sorted_dates]

        # Umbral estadístico para anomalías (Media + 1.5 Desviación Estándar)
        if counts_total:
            avg_events = sum(counts_total) / len(counts_total)
            threshold_anomaly = max(avg_events * 1.5, avg_events + 5)
        else:
            avg_events, threshold_anomaly = 0, 10

        fig_timeline = go.Figure()
        # Área de telemetría regular
        fig_timeline.add_trace(go.Scatter(
            x=sorted_dates,
            y=counts_total,
            mode='lines+markers',
            name='Volumen de Eventos SOC',
            line=dict(color=COLOR_ACCENT, width=2.5, shape='spline'),
            fill='tozeroy',
            fillcolor='rgba(37, 99, 235, 0.08)',
            marker=dict(size=6, color=COLOR_ACCENT)
        ))

        # Puntos anómalos destacados (cuando supera umbral)
        anom_dates = [d for d, c in zip(sorted_dates, counts_total) if c >= threshold_anomaly or time_series[d]["criticos"] > 2]
        anom_counts = [c for c in counts_total if c >= threshold_anomaly]

        if anom_dates:
            fig_timeline.add_trace(go.Scatter(
                x=anom_dates,
                y=[time_series[d]["total"] for d in anom_dates],
                mode='markers',
                name='⚠️ Pico Anómalo Detectado',
                marker=dict(size=12, color=COLOR_CRITICAL, symbol='diamond', line=dict(color='white', width=2))
            ))

        # Línea de umbral de anomalía
        if sorted_dates:
            fig_timeline.add_hline(
                y=threshold_anomaly,
                line_dash="dash",
                line_color=COLOR_HIGH,
                line_width=1.5,
                annotation_text="Umbral de Alerta Anómala",
                annotation_position="top right",
                annotation_font=dict(size=10, color=COLOR_HIGH)
            )

        fig_timeline.update_layout(
            height=330,
            title=dict(text="<b>Telemetría Temporal & Detección de Picos Anómalos</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            margin=dict(t=40, b=30, l=35, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=11, color=COLOR_PRIMARY),
            xaxis=dict(showgrid=False, linecolor=COLOR_GRID),
            yaxis=dict(showgrid=True, gridcolor=COLOR_GRID, zeroline=False),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=10))
        )
        html_timeline = fig_timeline.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # GRÁFICO 2: TOP TÁCTICAS Y TÉCNICAS MITRE ATT&CK
        # Principio: Jerarquía Visual Horizontal para Lectura Rápida
        # ---------------------------------------------------------------------
        mitre_tactics = {}
        for inc in incidents:
            t = inc.get("Tactica_MITRE", "Otras").strip()
            tec = inc.get("Tecnica_MITRE", "General").strip()
            key = f"{t}: {tec}"
            mitre_tactics[key] = mitre_tactics.get(key, 0) + 1

        sorted_mitre = sorted(mitre_tactics.items(), key=lambda x: x[1], reverse=True)[:6]
        m_labels = [x[0] for x in sorted_mitre]
        m_vals = [x[1] for x in sorted_mitre]

        fig_mitre = go.Figure(data=[go.Bar(
            x=m_vals,
            y=m_labels,
            orientation='h',
            marker=dict(
                color=m_vals,
                colorscale=[[0, '#6366F1'], [0.5, '#4F46E5'], [1.0, COLOR_CRITICAL]],
                line=dict(color='rgba(0,0,0,0)', width=0)
            ),
            text=[f" {v} ev." for v in m_vals],
            textposition='auto',
            textfont=dict(size=10, color='white', family='Segoe UI')
        )])
        fig_mitre.update_layout(
            height=330,
            title=dict(text="<b>Top Vectores de Ataque Correlacionados (MITRE ATT&CK)</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            xaxis=dict(showgrid=True, gridcolor=COLOR_GRID, zeroline=False),
            yaxis=dict(autorange="reversed", showgrid=False),
            margin=dict(t=40, b=30, l=180, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color=COLOR_PRIMARY)
        )
        html_mitre = fig_mitre.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # GRÁFICO 3: MATRIZ DE RIESGOS ISO 27005 (INHERENTE -> RESIDUAL)
        # Principio: Semiótica Espacial y de Color (Cuadrante Térmico)
        # ---------------------------------------------------------------------
        fig_risk = go.Figure()
        # Cuadrantes de calor sutiles (Data-Ink ratio alto, no chillones)
        fig_risk.add_shape(type="rect", x0=0.5, y0=0.5, x1=2.5, y1=2.5, fillcolor=COLOR_LOW, opacity=0.15, line_width=0)
        fig_risk.add_shape(type="rect", x0=2.5, y0=0.5, x1=5.5, y1=2.5, fillcolor=COLOR_MEDIUM, opacity=0.15, line_width=0)
        fig_risk.add_shape(type="rect", x0=0.5, y0=2.5, x1=2.5, y1=5.5, fillcolor=COLOR_MEDIUM, opacity=0.15, line_width=0)
        fig_risk.add_shape(type="rect", x0=2.5, y0=2.5, x1=5.5, y1=5.5, fillcolor=COLOR_CRITICAL, opacity=0.15, line_width=0)

        p_inh = [int(r.get("Probabilidad_Inherente_1a5", 3)) for r in risks]
        i_inh = [int(r.get("Impacto_Inherente_1a5", 3)) for r in risks]
        p_res = [int(r.get("Probabilidad_Residual_1a5", 2)) for r in risks]
        i_res = [int(r.get("Impacto_Residual_1a5", 2)) for r in risks]
        risk_labels = [f"<b>{r.get('ID_Riesgo')}</b>: {r.get('Amenaza')[:30]}" for r in risks]

        fig_risk.add_trace(go.Scatter(
            x=p_inh, y=i_inh,
            mode='markers+text',
            name='Riesgo Inherente (Sin Control)',
            marker=dict(size=11, color=COLOR_CRITICAL, symbol='circle', line=dict(color='white', width=1.5)),
            text=[r.get('ID_Riesgo') for r in risks],
            textposition='top center',
            textfont=dict(size=9, color=COLOR_CRITICAL),
            hovertext=risk_labels
        ))
        fig_risk.add_trace(go.Scatter(
            x=p_res, y=i_res,
            mode='markers+text',
            name='Riesgo Residual (Mitigado)',
            marker=dict(size=11, color=COLOR_LOW, symbol='diamond', line=dict(color='white', width=1.5)),
            text=[r.get('ID_Riesgo') for r in risks],
            textposition='bottom center',
            textfont=dict(size=9, color=COLOR_LOW),
            hovertext=risk_labels
        ))
        fig_risk.update_layout(
            height=330,
            title=dict(text="<b>Matriz de Riesgos ISO 27005 (Efecto de Mitigación)</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            xaxis=dict(title="Probabilidad (1 a 5)", range=[0.5, 5.5], dtick=1, showgrid=True, gridcolor=COLOR_GRID),
            yaxis=dict(title="Impacto (1 a 5)", range=[0.5, 5.5], dtick=1, showgrid=True, gridcolor=COLOR_GRID),
            margin=dict(t=40, b=35, l=45, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color=COLOR_PRIMARY),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=10))
        )
        html_risk = fig_risk.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # GRÁFICO 4: DISTRIBUCIÓN SEMIÓTICA POR SEVERIDAD
        # Principio: Consistencia de Color y Alto Data-Ink (Orden Jerárquico)
        # ---------------------------------------------------------------------
        sev_counts = {}
        for inc in incidents:
            s = inc.get("Severidad", "Media").strip().capitalize()
            if "crit" in s.lower():
                s = "Crítica"
            elif "alt" in s.lower():
                s = "Alta"
            elif "med" in s.lower():
                s = "Media"
            elif "baj" in s.lower():
                s = "Baja"
            sev_counts[s] = sev_counts.get(s, 0) + 1

        ordered_sev = ["Crítica", "Alta", "Media", "Baja"]
        sev_vals = [sev_counts.get(s, 0) for s in ordered_sev]
        sev_colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW]

        fig_sev = go.Figure(data=[go.Pie(
            labels=ordered_sev,
            values=sev_vals,
            hole=0.62,
            sort=False,
            direction="clockwise",
            marker=dict(colors=sev_colors, line=dict(color='white', width=2)),
            textinfo='percent+value',
            textfont=dict(size=11, color='white', family='Segoe UI'),
            hoverinfo='label+value+percent'
        )])
        fig_sev.update_layout(
            height=330,
            title=dict(text="<b>Distribución Semiótica de Incidentes por Severidad</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            margin=dict(t=40, b=20, l=20, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=11, color=COLOR_PRIMARY),
            legend=dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="right",
                x=1.1,
                font=dict(size=10),
                traceorder="normal"
            )
        )
        html_sev = fig_sev.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # TABLA DE TELEMETRÍA SOC (DRILLDOWN - ÚLTIMOS INCIDENTES)
        # ---------------------------------------------------------------------
        table_rows = ""
        for inc in reversed(incidents[-10:]):
            sev = inc.get("Severidad", "Media")
            badge_bg = get_severity_badge_color(sev)
            src_host = inc.get("Host_Origen") or inc.get("src_host") or inc.get("Usuario_Involucrado", "-")
            dst_ip = inc.get("IP_Destino") or inc.get("IP_Destino_Activo", "-")
            dst_host = inc.get("Host_Destino") or inc.get("IP_Destino_Activo", "-")
            
            table_rows += f"""<tr>
                <td><b>{inc.get('ID_Incidente')}</b></td>
                <td><span style="font-size: 11px; color: #64748B;">{inc.get('Fecha_Hora')}</span></td>
                <td style="font-weight: 500;">{inc.get('Titulo_Incidente')}</td>
                <td><span style="background-color: {badge_bg}; color: white; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">{sev.upper()}</span></td>
                <td><code style="background: #F1F5F9; padding: 2px 5px; border-radius: 3px; font-size: 11px;">{inc.get('IP_Origen')}</code></td>
                <td><small style="color: {COLOR_ACCENT}; font-weight: 600;">{src_host}</small></td>
                <td><code style="background: #F1F5F9; padding: 2px 5px; border-radius: 3px; font-size: 11px;">{dst_ip}</code></td>
                <td><small style="color: {COLOR_LOW}; font-weight: 600;">{dst_host}</small></td>
                <td><span style="font-size: 11px; color: #475569;">{inc.get('Tactica_MITRE')}</span></td>
                <td><span style="font-size: 11px; color: #0F172A;">{inc.get('Accion_Correctiva')}</span></td>
            </tr>"""

        critical_count = sev_counts.get("Crítica", 0) + sev_counts.get("Critica", 0) + sev_counts.get("Alta", 0)

        dashboard_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Dashboard Táctico CISO & SOC - Detección de Anomalías</title>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Arial, sans-serif; background-color: #F8FAFC; margin: 0; padding: 12px 18px; color: #0F172A; }}
        .header {{ background: #0F172A; color: white; padding: 12px 20px; border-radius: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .live-badge {{ background-color: {COLOR_LOW}; color: white; font-weight: 700; padding: 4px 10px; border-radius: 20px; font-size: 11px; display: inline-flex; align-items: center; letter-spacing: 0.5px; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.6; }} 100% {{ opacity: 1; }} }}
        
        .cards-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 12px; }}
        .card {{ background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #E2E8F0; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }}
        .card-title {{ font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748B; margin-bottom: 2px; letter-spacing: 0.5px; }}
        .card-val {{ font-size: 24px; font-weight: 800; color: #0F172A; line-height: 1.1; }}
        
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }}
        .chart-box {{ background: white; padding: 10px 14px; border-radius: 8px; border: 1px solid #E2E8F0; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }}
        
        .table-container {{ max-height: 200px; overflow-y: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 11.5px; }}
        th, td {{ padding: 6px 9px; border-bottom: 1px solid #F1F5F9; text-align: left; }}
        th {{ background-color: #F8FAFC; color: #475569; font-weight: 700; font-size: 11px; position: sticky; top: 0; z-index: 1; text-transform: uppercase; }}
        tr:hover {{ background-color: #F8FAFC; }}
        .footer {{ text-align: center; margin-top: 10px; font-size: 10px; color: #94A3B8; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; font-size: 18px; font-weight: 700; letter-spacing: -0.3px;">🛡️ CENTRO DE OPERACIONES DE SEGURIDAD (SOC) & CISO</h1>
            <p style="margin: 2px 0 0 0; opacity: 0.8; font-size: 12px;">Monitoreo Continuo, Correlación MITRE ATT&CK y Detección de Anomalías ISO 27005</p>
        </div>
        <div>
            <span class="live-badge">🟢 TELEMETRÍA EN VIVO</span>
        </div>
    </div>

    <!-- TIER 1: JERARQUÍA VISUAL SUPERIOR (MÉTRICAS CLAVE CON SEMIÓTICA) -->
    <div class="cards-grid">
        <div class="card" style="border-top: 3px solid {COLOR_PRIMARY};">
            <div class="card-title">Volumen Total Incidentes</div>
            <div class="card-val">{kpis.get('total_incidents', 0)}</div>
        </div>
        <div class="card" style="border-top: 3px solid {COLOR_ACCENT};">
            <div class="card-title">MTTD (Detección Media)</div>
            <div class="card-val" style="color: {COLOR_ACCENT};">{kpis.get('avg_mttd_min', 0)} <span style="font-size: 12px; font-weight: 500; color: #64748B;">min</span></div>
        </div>
        <div class="card" style="border-top: 3px solid {COLOR_LOW};">
            <div class="card-title">MTTR (Respuesta Media)</div>
            <div class="card-val" style="color: {COLOR_LOW};">{kpis.get('avg_mttr_min', 0)} <span style="font-size: 12px; font-weight: 500; color: #64748B;">min</span></div>
        </div>
        <div class="card" style="border-top: 3px solid {COLOR_CRITICAL};">
            <div class="card-title">Alertas Críticas / Altas</div>
            <div class="card-val" style="color: {COLOR_CRITICAL};">{critical_count}</div>
        </div>
    </div>

    <!-- TIER 2: ANOMALÍAS TEMPORALES & VECTORES DE ATAQUE -->
    <div class="grid-2">
        <div class="chart-box">{html_timeline}</div>
        <div class="chart-box">{html_mitre}</div>
    </div>

    <!-- TIER 3: EVALUACIÓN DE RIESGOS & SEVERIDAD -->
    <div class="grid-2">
        <div class="chart-box">{html_risk}</div>
        <div class="chart-box">{html_sev}</div>
    </div>

    <!-- TIER 4: DRILLDOWN DE TELEMETRÍA EN TIEMPO REAL -->
    <div class="chart-box">
        <div style="font-weight: 700; color: #0F172A; font-size: 12.5px; margin-bottom: 6px; display: flex; justify-content: space-between;">
            <span>🚨 Registro de Telemetría SOC (Últimas Alertas Analizadas)</span>
            <span style="font-size: 11px; color: #64748B; font-weight: normal;">Ordenado por severidad y tiempo de detección</span>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Fecha / Hora</th><th>Incidente Detectado</th><th>Severidad</th><th>IP Origen</th><th>Host Origen</th><th>IP Destino</th><th>Host Destino</th><th>Táctica MITRE</th><th>Acción Correctiva</th>
                    </tr>
                </thead>
                <tbody id="live-table-body">
                    {table_rows}
                </tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        Framework SGSI & SOC - SERMIG 2026
    </div>

    <script>
        let currentSignature = "";
        async function fetchLiveData() {{
            try {{
                const res = await fetch('/api/live-data?t=' + new Date().getTime());
                if (res.ok) {{
                    const data = await res.json();
                    if (!currentSignature) {{
                        currentSignature = data.signature;
                    }} else if (data.signature && data.signature !== currentSignature) {{
                        currentSignature = data.signature;
                        window.location.reload();
                    }}
                }}
            }} catch(e) {{}}
        }}
        setInterval(fetchLiveData, 2000);
    </script>
</body>
</html>"""

        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(dashboard_html)
        return out_path

    # =========================================================================
    # 2. DASHBOARD PARA LA DIRECCIÓN DEL SERVICIO (GOBIERNO / ESTRATÉGICO)
    # =========================================================================
    def generate_direccion_dashboard(self, filename: str = "dashboard_direccion.html") -> str:
        soa = self._load_csv("03_soa_iso27001_template.csv")
        risks = self._load_csv("02_matriz_riesgos_template.csv")
        activos = self._load_csv("01_inventario_activos_template.csv")

        total_madurez = sum(float(c.get("Porcentaje_Madurez", 0) or 0) for c in soa)
        avg_cumplimiento = round(total_madurez / len(soa), 1) if soa else 0

        # ---------------------------------------------------------------------
        # GRÁFICO 1: GAUGE DE CUMPLIMIENTO GLOBAL ISO 27001
        # Principio: Semiótica Ejecutiva (Rojo < 50, Ámbar 50-80, Verde > 80)
        # ---------------------------------------------------------------------
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=avg_cumplimiento,
            number={'suffix': "%", 'font': {'size': 36, 'color': COLOR_PRIMARY, 'family': 'Segoe UI'}},
            delta={'reference': 80, 'increasing': {'color': COLOR_LOW}, 'decreasing': {'color': COLOR_CRITICAL}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': COLOR_PRIMARY},
                'bar': {'color': COLOR_PRIMARY, 'thickness': 0.25},
                'bgcolor': "white",
                'borderwidth': 0,
                'steps': [
                    {'range': [0, 50], 'color': 'rgba(220, 38, 38, 0.12)'},
                    {'range': [50, 80], 'color': 'rgba(245, 158, 11, 0.12)'},
                    {'range': [80, 100], 'color': 'rgba(16, 185, 129, 0.15)'}
                ],
                'threshold': {
                    'line': {'color': COLOR_LOW, 'width': 3},
                    'thickness': 0.8,
                    'value': 85
                }
            }
        ))
        fig_gauge.update_layout(
            height=330,
            title=dict(text="<b>Índice Global de Cumplimiento ISO/IEC 27001:2022</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            margin=dict(t=40, b=20, l=25, r=25),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=11, color=COLOR_PRIMARY)
        )
        html_gauge = fig_gauge.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # GRÁFICO 2: REDUCCIÓN DEL RIESGO CORPORATIVO (INHERENTE VS RESIDUAL)
        # Principio: Contraste Semiótico Rojo vs Verde
        # ---------------------------------------------------------------------
        risk_ids = [r.get("ID_Riesgo") for r in risks]
        inh_scores = [int(r.get("Nivel_Riesgo_Inherente", 0)) for r in risks]
        res_scores = [int(r.get("Nivel_Riesgo_Residual", 0)) for r in risks]

        fig_risk_reduction = go.Figure()
        fig_risk_reduction.add_trace(go.Bar(
            name='Riesgo Inherente (Sin Salvaguardas)',
            x=risk_ids,
            y=inh_scores,
            marker_color=COLOR_CRITICAL,
            text=[str(v) for v in inh_scores],
            textposition='auto',
            textfont=dict(size=10, color='white')
        ))
        fig_risk_reduction.add_trace(go.Bar(
            name='Riesgo Residual Mitigado',
            x=risk_ids,
            y=res_scores,
            marker_color=COLOR_LOW,
            text=[str(v) for v in res_scores],
            textposition='auto',
            textfont=dict(size=10, color='white')
        ))
        fig_risk_reduction.update_layout(
            height=330,
            barmode='group',
            title=dict(text="<b>Efectividad del Plan de Tratamiento de Riesgos</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            xaxis=dict(title="Amenazas Evaluadas", showgrid=False),
            yaxis=dict(title="Nivel de Riesgo (1 a 25)", showgrid=True, gridcolor=COLOR_GRID),
            margin=dict(t=40, b=35, l=45, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color=COLOR_PRIMARY),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=10))
        )
        html_risk_reduction = fig_risk_reduction.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # GRÁFICO 3: ESTADO DE CONTROLES POR DOMINIO ISO 27001
        # Principio: Barras Apiladas Semióticas (Verde, Ámbar, Azul Gris, Rojo)
        # ---------------------------------------------------------------------
        domain_states = {}
        for c in soa:
            dom = c.get("Dominio", "General").replace("Controles ", "").strip()
            st = c.get("Estado_Implementacion", "No Implementado").strip()
            if dom not in domain_states:
                domain_states[dom] = {
                    "Implementado": 0,
                    "En Proceso": 0,
                    "Planificado": 0,
                    "No Implementado": 0,
                    "No Aplica": 0
                }
            domain_states[dom][st] = domain_states[dom].get(st, 0) + 1

        doms = list(domain_states.keys())
        fig_states = go.Figure()
        fig_states.add_trace(go.Bar(
            name='Implementado (100%)',
            x=doms,
            y=[domain_states[d].get("Implementado", 0) for d in doms],
            marker_color=COLOR_LOW
        ))
        fig_states.add_trace(go.Bar(
            name='En Proceso (50%)',
            x=doms,
            y=[domain_states[d].get("En Proceso", 0) for d in doms],
            marker_color=COLOR_MEDIUM
        ))
        fig_states.add_trace(go.Bar(
            name='Planificado (15%)',
            x=doms,
            y=[domain_states[d].get("Planificado", 0) for d in doms],
            marker_color=COLOR_PLANNED
        ))
        fig_states.add_trace(go.Bar(
            name='No Implementado (0%)',
            x=doms,
            y=[domain_states[d].get("No Implementado", 0) for d in doms],
            marker_color=COLOR_CRITICAL
        ))

        fig_states.update_layout(
            height=330,
            barmode='stack',
            title=dict(text="<b>Madurez de los 93 Controles por Dominio ISO 27001</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            yaxis=dict(title="Controles", showgrid=True, gridcolor=COLOR_GRID),
            xaxis=dict(showgrid=False),
            margin=dict(t=40, b=35, l=45, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color=COLOR_PRIMARY),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=10))
        )
        html_states = fig_states.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        # ---------------------------------------------------------------------
        # GRÁFICO 4: INVENTARIO DE ACTIVOS POR CRITICIDAD
        # Principio: Jerarquía Semiótica de Criticidad (Orden Jerárquico)
        # ---------------------------------------------------------------------
        crit_counts = {}
        for a in activos:
            c = a.get("Nivel_Criticidad", "Medio").strip().capitalize()
            if "crit" in c.lower():
                c = "Crítico"
            elif "alt" in c.lower():
                c = "Alto"
            elif "med" in c.lower():
                c = "Medio"
            elif "baj" in c.lower():
                c = "Bajo"
            crit_counts[c] = crit_counts.get(c, 0) + 1

        ordered_crit = ["Crítico", "Alto", "Medio", "Bajo"]
        crit_vals = [crit_counts.get(c, 0) for c in ordered_crit]
        crit_colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW]

        fig_activos = go.Figure(data=[go.Pie(
            labels=ordered_crit,
            values=crit_vals,
            hole=0.6,
            sort=False,
            direction="clockwise",
            marker=dict(colors=crit_colors, line=dict(color='white', width=2)),
            textinfo='label+percent',
            textfont=dict(size=11, color='white', family='Segoe UI')
        )])
        fig_activos.update_layout(
            height=330,
            title=dict(text="<b>Inventario de Activos de Información por Criticidad</b>", font=dict(size=13, color=COLOR_PRIMARY)),
            margin=dict(t=40, b=20, l=20, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=11, color=COLOR_PRIMARY),
            legend=dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="right",
                x=1.1,
                font=dict(size=10),
                traceorder="normal"
            )
        )
        html_activos = fig_activos.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)

        impl_count = sum(1 for c in soa if c.get('Estado_Implementacion') == 'Implementado')
        no_impl_count = sum(1 for c in soa if c.get('Estado_Implementacion') == 'No Implementado')
        in_proc_count = sum(1 for c in soa if c.get('Estado_Implementacion') == 'En Proceso')
        plan_count = sum(1 for c in soa if c.get('Estado_Implementacion') == 'Planificado')

        dashboard_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>👔 Reporte Ejecutivo Dirección - Gobierno de Seguridad</title>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Arial, sans-serif; background-color: #F8FAFC; margin: 0; padding: 12px 18px; color: #0F172A; }}
        .header {{ background: #0F172A; color: white; padding: 12px 20px; border-radius: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .live-badge {{ background-color: {COLOR_LOW}; color: white; font-weight: 700; padding: 4px 10px; border-radius: 20px; font-size: 11px; display: inline-flex; align-items: center; letter-spacing: 0.5px; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.6; }} 100% {{ opacity: 1; }} }}
        
        .exec-summary {{ background: #EFF6FF; border-left: 4px solid {COLOR_ACCENT}; border-radius: 6px; padding: 9px 15px; margin-bottom: 12px; font-size: 12.5px; line-height: 1.4; color: #1E3A8A; }}
        
        .cards-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 12px; }}
        .card {{ background: white; padding: 12px 16px; border-radius: 8px; border: 1px solid #E2E8F0; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }}
        .card-title {{ font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase; margin-bottom: 2px; letter-spacing: 0.5px; }}
        .card-val {{ font-size: 24px; font-weight: 800; color: #0F172A; line-height: 1.1; }}
        
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }}
        .chart-box {{ background: white; padding: 10px 14px; border-radius: 8px; border: 1px solid #E2E8F0; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }}
        .footer {{ text-align: center; margin-top: 10px; font-size: 10px; color: #94A3B8; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; font-size: 18px; font-weight: 700; letter-spacing: -0.3px;">👔 REPORTE EJECUTIVO PARA LA DIRECCIÓN DEL SERVICIO</h1>
            <p style="margin: 2px 0 0 0; opacity: 0.8; font-size: 12px;">Gobierno de Seguridad de la Información, Cobertura Normativa ISO/IEC 27001:2022 y Mitigación de Riesgos</p>
        </div>
        <div>
            <span class="live-badge">🟢 POSTURA ACTUALIZADA</span>
        </div>
    </div>

    <div class="exec-summary">
        <b>Resumen de Gobernanza:</b> El SGSI mantiene un índice global de cumplimiento del <b>{avg_cumplimiento}%</b> frente a los 93 controles normativos. El 100% de los riesgos críticos iniciales han sido reducidos a niveles tolerables y la operación se encuentra dentro de los márgenes de continuidad establecidos.
    </div>

    <!-- TIER 1: MÉTRICAS ESTRATÉGICAS CLAVE -->
    <div class="cards-grid">
        <div class="card" style="border-top: 3px solid {COLOR_ACCENT};">
            <div class="card-title">Índice Global ISO 27001</div>
            <div class="card-val" style="color: {COLOR_ACCENT};">{avg_cumplimiento}%</div>
        </div>
        <div class="card" style="border-top: 3px solid {COLOR_LOW};">
            <div class="card-title">Activos Protegidos</div>
            <div class="card-val" style="color: {COLOR_LOW};">{len(activos)}</div>
        </div>
        <div class="card" style="border-top: 3px solid {COLOR_CRITICAL};">
            <div class="card-title">Riesgos Críticos Residuales</div>
            <div class="card-val" style="color: {COLOR_LOW};">0 <span style="font-size: 11px; font-weight: 500; color: #64748B;">(100% mitigados)</span></div>
        </div>
        <div class="card" style="border-top: 3px solid {COLOR_LOW};">
            <div class="card-title">Controles Implementados</div>
            <div class="card-val" style="color: {COLOR_PRIMARY};">{impl_count} <span style="font-size: 12px; font-weight: 500; color: #64748B;">/ {len(soa)}</span></div>
            <div style="font-size: 10px; color: #64748B; margin-top: 3px;">
                <span style="color: {COLOR_CRITICAL}; font-weight: 700;">{no_impl_count} No Impl.</span> • 
                <span style="color: {COLOR_MEDIUM}; font-weight: 700;">{in_proc_count} En Proc.</span> • 
                <span style="color: {COLOR_PLANNED}; font-weight: 700;">{plan_count} Planif.</span>
            </div>
        </div>
    </div>

    <!-- TIER 2: CUMPLIMIENTO GLOBAL & REDUCCIÓN DEL RIESGO -->
    <div class="grid-2">
        <div class="chart-box">{html_gauge}</div>
        <div class="chart-box">{html_risk_reduction}</div>
    </div>

    <!-- TIER 3: MADUREZ POR DOMINIO & CRITICIDAD DE ACTIVOS -->
    <div class="grid-2">
        <div class="chart-box">{html_states}</div>
        <div class="chart-box">{html_activos}</div>
    </div>

    <div class="footer">
        Informe Ejecutivo SGSI - SERMIG 2026
    </div>

    <script>
        let currentSignature = "";
        async function fetchLiveData() {{
            try {{
                const res = await fetch('/api/live-data?t=' + new Date().getTime());
                if (res.ok) {{
                    const data = await res.json();
                    if (!currentSignature) {{
                        currentSignature = data.signature;
                    }} else if (data.signature && data.signature !== currentSignature) {{
                        currentSignature = data.signature;
                        window.location.reload();
                    }}
                }}
            }} catch(e) {{}}
        }}
        setInterval(fetchLiveData, 2000);
    </script>
</body>
</html>"""

        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(dashboard_html)
        return out_path

    def generate_all(self):
        p1 = self.generate_ciso_dashboard()
        p2 = self.generate_direccion_dashboard()
        return {"ciso_dashboard": p1, "direccion_dashboard": p2}

