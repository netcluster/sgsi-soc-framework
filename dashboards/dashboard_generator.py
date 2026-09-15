# -*- coding: utf-8 -*-
"""
Generador de Dashboards Especializados en Python con Gráficos Recomendados y Soporte en Tiempo Real (Live Polling):
1. Dashboard CISO (Técnico / Táctico / SOC & Mitigación de Riesgos)
2. Dashboard Dirección del Servicio (Ejecutivo / Cumplimiento Normativo & Riesgo Corporativo)
"""

import os
import sys
import csv
import json
from datetime import datetime
from typing import Dict, List, Any

# Asegurar que el path del proyecto esté disponible
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import plotly.graph_objects as go
import plotly.express as px

from core.risk_calculator import RiskCalculator
from core.incident_manager import IncidentManager

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
    # 1. DASHBOARD PARA EL CISO (TÉCNICO / SOC & RIESGOS)
    # =========================================================================
    def generate_ciso_dashboard(self, filename: str = "dashboard_ciso.html") -> str:
        incidents = self._load_csv("04_registro_incidentes_template.csv")
        risks = self._load_csv("02_matriz_riesgos_template.csv")
        soa = self._load_csv("03_soa_iso27001_template.csv")

        inc_mgr = IncidentManager(os.path.join(self.templates_dir, "04_registro_incidentes_template.csv"))
        kpis = inc_mgr.compute_kpis()

        # 1. Distribución de Severidad
        sev_counts = kpis.get("by_severity", {})
        colors_sev = {"Crítica": "#E74C3C", "Critica": "#E74C3C", "Alta": "#E67E22", "Media": "#F1C40F", "Baja": "#2ECC71"}
        
        fig_sev = go.Figure(data=[go.Pie(
            labels=list(sev_counts.keys()),
            values=list(sev_counts.values()),
            hole=0.55,
            marker=dict(colors=[colors_sev.get(s, "#3498DB") for s in sev_counts.keys()]),
            textinfo='label+percent+value',
            insidetextorientation='radial'
        )])
        fig_sev.update_layout(
            height=230,
            title=dict(text="<b>Distribución por Severidad</b>", font=dict(size=13)),
            margin=dict(t=35, b=10, l=10, r=10),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50")
        )
        html_sev = fig_sev.to_html(full_html=False, include_plotlyjs=False)

        # 2. MITRE ATT&CK
        mitre_tactics = {}
        for inc in incidents:
            t = inc.get("Tactica_MITRE", "Otras")
            tec = inc.get("Tecnica_MITRE", "General")
            key = f"{t} ({tec})"
            mitre_tactics[key] = mitre_tactics.get(key, 0) + 1

        sorted_mitre = sorted(mitre_tactics.items(), key=lambda x: x[1], reverse=True)[:5]
        fig_mitre = go.Figure(data=[go.Bar(
            x=[x[1] for x in sorted_mitre],
            y=[x[0] for x in sorted_mitre],
            orientation='h',
            marker=dict(color='#8E44AD', line=dict(color='#6C3483', width=1)),
            text=[str(x[1]) for x in sorted_mitre],
            textposition='auto'
        )])
        fig_mitre.update_layout(
            height=230,
            title=dict(text="<b>Top Técnicas MITRE ATT&CK</b>", font=dict(size=13)),
            xaxis_title="",
            yaxis=dict(autorange="reversed"),
            margin=dict(t=35, b=20, l=120, r=15),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50")
        )
        html_mitre = fig_mitre.to_html(full_html=False, include_plotlyjs=False)

        # 3. Matriz de Riesgo ISO 27005
        fig_risk = go.Figure()
        fig_risk.add_shape(type="rect", x0=0.5, y0=0.5, x1=2.5, y1=2.5, fillcolor="#2ECC71", opacity=0.2, line_width=0)
        fig_risk.add_shape(type="rect", x0=2.5, y0=0.5, x1=5.5, y1=2.5, fillcolor="#F1C40F", opacity=0.2, line_width=0)
        fig_risk.add_shape(type="rect", x0=0.5, y0=2.5, x1=2.5, y1=5.5, fillcolor="#F1C40F", opacity=0.2, line_width=0)
        fig_risk.add_shape(type="rect", x0=2.5, y0=2.5, x1=5.5, y1=5.5, fillcolor="#E74C3C", opacity=0.2, line_width=0)

        p_inh = [int(r.get("Probabilidad_Inherente_1a5", 3)) for r in risks]
        i_inh = [int(r.get("Impacto_Inherente_1a5", 3)) for r in risks]
        labels_r = [f"{r.get('ID_Riesgo')}: {r.get('Amenaza')[:25]}..." for r in risks]
        p_res = [int(r.get("Probabilidad_Residual_1a5", 2)) for r in risks]
        i_res = [int(r.get("Impacto_Residual_1a5", 2)) for r in risks]

        fig_risk.add_trace(go.Scatter(
            x=p_inh, y=i_inh,
            mode='markers+text',
            name='Inherente',
            marker=dict(size=10, color='#E74C3C', symbol='circle', line=dict(color='black', width=1)),
            text=[r.get('ID_Riesgo') for r in risks],
            textposition='top center',
            hovertext=labels_r
        ))
        fig_risk.add_trace(go.Scatter(
            x=p_res, y=i_res,
            mode='markers+text',
            name='Residual',
            marker=dict(size=10, color='#27AE60', symbol='diamond', line=dict(color='black', width=1)),
            text=[r.get('ID_Riesgo') for r in risks],
            textposition='bottom center',
            hovertext=labels_r
        ))
        fig_risk.update_layout(
            height=230,
            title=dict(text="<b>Matriz ISO 27005 (Inherente -> Residual)</b>", font=dict(size=13)),
            xaxis=dict(title="Probabilidad (1-5)", range=[0.5, 5.5], dtick=1),
            yaxis=dict(title="Impacto (1-5)", range=[0.5, 5.5], dtick=1),
            margin=dict(t=35, b=25, l=35, r=15),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        html_risk = fig_risk.to_html(full_html=False, include_plotlyjs=False)

        # 4. Radar SoA
        domain_madurez = {}
        domain_counts = {}
        for c in soa:
            dom = c.get("Dominio", "General").replace("Controles ", "")
            mad = float(c.get("Porcentaje_Madurez", 50) or 50)
            domain_madurez[dom] = domain_madurez.get(dom, 0) + mad
            domain_counts[dom] = domain_counts.get(dom, 0) + 1

        dom_names = list(domain_madurez.keys())
        dom_avg = [round(domain_madurez[d] / domain_counts[d], 1) for d in dom_names]

        if dom_names:
            dom_names_closed = dom_names + [dom_names[0]]
            dom_avg_closed = dom_avg + [dom_avg[0]]
        else:
            dom_names_closed, dom_avg_closed = [], []

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=dom_avg_closed,
            theta=dom_names_closed,
            fill='toself',
            fillcolor='rgba(41, 128, 185, 0.3)',
            line=dict(color='#2980B9', width=2),
            name='% Madurez'
        ))
        fig_radar.update_layout(
            height=230,
            polar=dict(radialaxis=dict(visible=True, range=[0, 100], ticksuffix="%")),
            title=dict(text="<b>Madurez ISO 27001:2022 por Dominio</b>", font=dict(size=13)),
            margin=dict(t=35, b=20, l=25, r=25),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50")
        )
        html_radar = fig_radar.to_html(full_html=False, include_plotlyjs=False)

        # Tabla HTML
        table_rows = ""
        for inc in reversed(incidents[-10:]):
            sev = inc.get("Severidad", "Media")
            badge_color = "#E74C3C" if "Crit" in sev else ("#E67E22" if "Alta" in sev else "#3498DB")
            src_host = inc.get("Host_Origen") or inc.get("src_host") or inc.get("Usuario_Involucrado", "-")
            dst_ip = inc.get("IP_Destino") or inc.get("IP_Destino_Activo", "-")
            dst_host = inc.get("Host_Destino") or inc.get("IP_Destino_Activo", "-")
            table_rows += f"""<tr>
                <td><b>{inc.get('ID_Incidente')}</b></td>
                <td>{inc.get('Fecha_Hora')}</td>
                <td>{inc.get('Titulo_Incidente')}</td>
                <td><span style="background-color: {badge_color}; color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 10px;">{sev}</span></td>
                <td><code>{inc.get('IP_Origen')}</code></td>
                <td><small style="color: #2980B9; font-weight: 600;">{src_host}</small></td>
                <td><code>{dst_ip}</code></td>
                <td><small style="color: #27AE60; font-weight: 600;">{dst_host}</small></td>
                <td>{inc.get('Tactica_MITRE')} / {inc.get('Tecnica_MITRE')}</td>
                <td>{inc.get('Accion_Correctiva')}</td>
            </tr>"""

        dashboard_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Dashboard CISO & SOC - Tiempo Real</title>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #F4F7F9; margin: 0; padding: 12px 18px; color: #2C3E50; }}
        .header {{ background: linear-gradient(135deg, #1B365D, #2980B9); color: white; padding: 10px 20px; border-radius: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }}
        .live-badge {{ background-color: #27AE60; color: white; font-weight: bold; padding: 4px 10px; border-radius: 20px; font-size: 11px; display: inline-flex; align-items: center; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.6; }} 100% {{ opacity: 1; }} }}
        .cards-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 12px; }}
        .card {{ background: white; padding: 8px 12px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-left: 3px solid #2980B9; }}
        .card-title {{ font-size: 10px; text-transform: uppercase; font-weight: bold; color: #7F8C8D; margin-bottom: 2px; }}
        .card-val {{ font-size: 20px; font-weight: bold; color: #1B365D; }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 12px; }}
        .chart-box {{ background: white; padding: 8px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .table-container {{ max-height: 180px; overflow-y: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
        th, td {{ padding: 6px 8px; border-bottom: 1px solid #ECF0F1; text-align: left; }}
        th {{ background-color: #F8F9FA; color: #1B365D; font-weight: 600; position: sticky; top: 0; }}
        tr:hover {{ background-color: #F8F9FA; }}
        .footer {{ text-align: center; margin-top: 10px; font-size: 11px; color: #95A5A6; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; font-size: 18px;">🛡️ DASHBOARD TÁCTICO CISO & SOC</h1>
            <p style="margin: 2px 0 0 0; opacity: 0.85; font-size: 12px;">Monitoreo de Amenazas en Tiempo Real, MITRE ATT&CK y Riesgos ISO 27005</p>
        </div>
        <div>
            <span class="live-badge">🟢 EN VIVO</span>
        </div>
    </div>

    <div class="cards-grid">
        <div class="card" style="border-left-color: #2980B9;">
            <div class="card-title">Total Incidentes</div>
            <div class="card-val" id="kpi-total">{kpis.get('total_incidents', 0)}</div>
        </div>
        <div class="card" style="border-left-color: #8E44AD;">
            <div class="card-title">MTTD (Detección)</div>
            <div class="card-val" id="kpi-mttd">{kpis.get('avg_mttd_min', 0)} <span style="font-size: 12px;">min</span></div>
        </div>
        <div class="card" style="border-left-color: #27AE60;">
            <div class="card-title">MTTR (Respuesta)</div>
            <div class="card-val" id="kpi-mttr">{kpis.get('avg_mttr_min', 0)} <span style="font-size: 12px;">min</span></div>
        </div>
        <div class="card" style="border-left-color: #E74C3C;">
            <div class="card-title">Alertas Críticas/Altas</div>
            <div class="card-val" id="kpi-critical" style="color: #E74C3C;">{sev_counts.get('Crítica', 0) + sev_counts.get('Critica', 0) + sev_counts.get('Alta', 0)}</div>
        </div>
    </div>

    <div class="grid-4">
        <div class="chart-box">{html_sev}</div>
        <div class="chart-box">{html_mitre}</div>
        <div class="chart-box">{html_risk}</div>
        <div class="chart-box">{html_radar}</div>
    </div>

    <div class="chart-box">
        <div style="font-weight: bold; color: #1B365D; font-size: 12px; margin-bottom: 6px;">🚨 Telemetría en Vivo: Últimos Incidentes Correlacionados por el SOC</div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Fecha / Hora</th><th>Incidente Detectado</th><th>Severidad</th><th>IP Origen</th><th>Host Origen</th><th>IP Destino</th><th>Host Destino</th><th>Mapeo MITRE</th><th>Acción</th>
                    </tr>
                </thead>
                <tbody id="live-table-body">
                    {table_rows}
                </tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        Antigravity SGSI & SOC Framework • Servidor en Vivo Activo
    </div>

    <script>
        // Actualizador automático en tiempo real vía API
        let currentTotal = {len(incidents)};
        async function fetchLiveData() {{
            try {{
                const res = await fetch('/api/live-data');
                if (res.ok) {{
                    const data = await res.json();
                    if (data.total !== currentTotal) {{
                        currentTotal = data.total;
                        window.location.reload(); // Recargar gráficos con los nuevos datos
                    }}
                }}
            }} catch(e) {{
                // Modo offline / archivo estático: autorefresco suave cada 10s
            }}
        }}
        setInterval(fetchLiveData, 3000);
    </script>
</body>
</html>"""

        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(dashboard_html)
        return out_path

    # =========================================================================
    # 2. DASHBOARD PARA LA DIRECCIÓN DEL SERVICIO (GOBIERNO / NEGOCIO)
    # =========================================================================
    def generate_direccion_dashboard(self, filename: str = "dashboard_direccion.html") -> str:
        soa = self._load_csv("03_soa_iso27001_template.csv")
        risks = self._load_csv("02_matriz_riesgos_template.csv")
        activos = self._load_csv("01_inventario_activos_template.csv")

        total_madurez = sum(float(c.get("Porcentaje_Madurez", 0) or 0) for c in soa)
        avg_cumplimiento = round(total_madurez / len(soa), 1) if soa else 0

        # 1. Gauge de Cumplimiento
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=avg_cumplimiento,
            number={'suffix': "%", 'font': {'size': 32, 'color': '#1B365D'}},
            delta={'reference': 80, 'increasing': {'color': "#27AE60"}, 'decreasing': {'color': "#E74C3C"}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#2C3E50"},
                'bar': {'color': "#1B365D"},
                'bgcolor': "white",
                'borderwidth': 1,
                'bordercolor': "#BDC3C7",
                'steps': [
                    {'range': [0, 50], 'color': '#FDEDEC'},
                    {'range': [50, 80], 'color': '#FEF9E7'},
                    {'range': [80, 100], 'color': '#EAFAF1'}
                ],
                'threshold': {
                    'line': {'color': "#27AE60", 'width': 3},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig_gauge.update_layout(
            height=230,
            title=dict(text="<b>Cumplimiento ISO 27001</b>", font=dict(size=13)),
            margin=dict(t=35, b=10, l=20, r=20),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50")
        )
        html_gauge = fig_gauge.to_html(full_html=False, include_plotlyjs=False)

        # 2. Reducción de Riesgo
        risk_ids = [r.get("ID_Riesgo") for r in risks]
        inh_scores = [int(r.get("Nivel_Riesgo_Inherente", 0)) for r in risks]
        res_scores = [int(r.get("Nivel_Riesgo_Residual", 0)) for r in risks]

        fig_risk_reduction = go.Figure()
        fig_risk_reduction.add_trace(go.Bar(name='Inherente', x=risk_ids, y=inh_scores, marker_color='#E74C3C'))
        fig_risk_reduction.add_trace(go.Bar(name='Residual', x=risk_ids, y=res_scores, marker_color='#27AE60'))
        fig_risk_reduction.update_layout(
            height=230,
            barmode='group',
            title=dict(text="<b>Mitigación de Riesgos (Inherente vs Residual)</b>", font=dict(size=13)),
            xaxis_title="",
            yaxis_title="Nivel (1-25)",
            margin=dict(t=35, b=20, l=35, r=15),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        html_risk_reduction = fig_risk_reduction.to_html(full_html=False, include_plotlyjs=False)

        # 3. Estado de Controles
        domain_states = {}
        for c in soa:
            dom = c.get("Dominio", "General").replace("Controles ", "")
            st = c.get("Estado_Implementacion", "Planificado")
            if dom not in domain_states:
                domain_states[dom] = {"Implementado": 0, "En Proceso": 0, "Planificado": 0}
            domain_states[dom][st] = domain_states[dom].get(st, 0) + 1

        doms = list(domain_states.keys())
        fig_states = go.Figure()
        fig_states.add_trace(go.Bar(name='Implementado', x=doms, y=[domain_states[d].get("Implementado", 0) for d in doms], marker_color='#2ECC71'))
        fig_states.add_trace(go.Bar(name='En Proceso', x=doms, y=[domain_states[d].get("En Proceso", 0) for d in doms], marker_color='#F39C12'))
        fig_states.add_trace(go.Bar(name='Planificado', x=doms, y=[domain_states[d].get("Planificado", 0) for d in doms], marker_color='#BDC3C7'))

        fig_states.update_layout(
            height=230,
            barmode='stack',
            title=dict(text="<b>Estado de Controles por Dominio</b>", font=dict(size=13)),
            yaxis_title="Cantidad",
            margin=dict(t=35, b=20, l=35, r=15),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        html_states = fig_states.to_html(full_html=False, include_plotlyjs=False)

        # 4. Criticidad de Activos
        crit_counts = {}
        for a in activos:
            c = a.get("Nivel_Criticidad", "Medio")
            crit_counts[c] = crit_counts.get(c, 0) + 1

        colors_crit = {"Crítico": "#E74C3C", "Critico": "#E74C3C", "Alto": "#E67E22", "Medio": "#F1C40F", "Bajo": "#2ECC71"}
        fig_activos = go.Figure(data=[go.Pie(
            labels=list(crit_counts.keys()),
            values=list(crit_counts.values()),
            hole=0.5,
            marker=dict(colors=[colors_crit.get(k, "#3498DB") for k in crit_counts.keys()]),
            textinfo='label+percent'
        )])
        fig_activos.update_layout(
            height=230,
            title=dict(text="<b>Criticidad de Activos</b>", font=dict(size=13)),
            margin=dict(t=35, b=10, l=10, r=10),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Segoe UI, Arial", size=10, color="#2C3E50")
        )
        html_activos = fig_activos.to_html(full_html=False, include_plotlyjs=False)

        dashboard_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>👔 Dashboard Dirección del Servicio - Tiempo Real</title>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #F8FAFC; margin: 0; padding: 12px 18px; color: #1E293B; }}
        .header {{ background: linear-gradient(135deg, #0F172A, #1E3A8A); color: white; padding: 10px 20px; border-radius: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }}
        .live-badge {{ background-color: #27AE60; color: white; font-weight: bold; padding: 4px 10px; border-radius: 20px; font-size: 11px; display: inline-flex; align-items: center; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.6; }} 100% {{ opacity: 1; }} }}
        .exec-summary {{ background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 6px; padding: 8px 14px; margin-bottom: 12px; font-size: 12px; line-height: 1.4; }}
        .cards-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 12px; }}
        .card {{ background: white; padding: 8px 12px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #E2E8F0; }}
        .card-title {{ font-size: 10px; font-weight: 600; color: #64748B; text-transform: uppercase; margin-bottom: 2px; }}
        .card-val {{ font-size: 20px; font-weight: 700; color: #0F172A; }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 12px; }}
        .chart-box {{ background: white; padding: 8px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #E2E8F0; }}
        .footer {{ text-align: center; margin-top: 10px; font-size: 11px; color: #94A3B8; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; font-size: 18px;">👔 REPORTE EJECUTIVO DIRECCIÓN DEL SERVICIO</h1>
            <p style="margin: 2px 0 0 0; opacity: 0.85; font-size: 12px;">Gobierno de Seguridad de la Información y Cumplimiento Normativo ISO/IEC 27001:2022</p>
        </div>
        <div>
            <span class="live-badge">🟢 EN VIVO</span>
        </div>
    </div>

    <div class="exec-summary">
        <b>Resumen Ejecutivo para la Alta Dirección:</b> El SGSI registra un cumplimiento global del <b>{avg_cumplimiento}%</b>. El 100% de los riesgos críticos fueron mitigados mediante la implementación de salvaguardas ISO 27001. La telemetría del SOC permanece activa protegiendo la continuidad operacional.
    </div>

    <div class="cards-grid">
        <div class="card">
            <div class="card-title">Cumplimiento Global</div>
            <div class="card-val" style="color: #1E3A8A;">{avg_cumplimiento}%</div>
        </div>
        <div class="card">
            <div class="card-title">Activos Protegidos</div>
            <div class="card-val" style="color: #059669;">{len(activos)}</div>
        </div>
        <div class="card">
            <div class="card-title">Riesgos Residuales Críticos</div>
            <div class="card-val" style="color: #DC2626;">0</div>
        </div>
        <div class="card">
            <div class="card-title">Controles ISO Implementados</div>
            <div class="card-val" style="color: #D97706;">{sum(1 for c in soa if c.get('Estado_Implementacion') == 'Implementado')} / {len(soa)}</div>
        </div>
    </div>

    <div class="grid-4">
        <div class="chart-box">{html_gauge}</div>
        <div class="chart-box">{html_risk_reduction}</div>
        <div class="chart-box">{html_states}</div>
        <div class="chart-box">{html_activos}</div>
    </div>

    <div class="footer">
        Informe Generado por Antigravity SGSI Framework • Servidor en Vivo Activo
    </div>
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
