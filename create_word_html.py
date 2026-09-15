# -*- coding: utf-8 -*-
"""
Generador de formatos universales editables para Microsoft Word:
1. .doc (HTML enriquecido con formato Word)
2. .rtf (Rich Text Format nativo de Word y WordPad)
3. .md (Markdown estructurado)
"""

import os

def create_word_html_doc(output_path: str):
    html_content = """<!DOCTYPE html>
<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head>
<meta charset="utf-8">
<title>Guía de Implementación SGSI y SOC</title>
<style>
    body {
        font-family: 'Calibri', 'Arial', sans-serif;
        font-size: 11pt;
        line-height: 1.6;
        color: #2c3e50;
        margin: 40px;
    }
    h1 {
        color: #1B365D;
        font-size: 22pt;
        border-bottom: 2px solid #1B365D;
        padding-bottom: 8px;
        margin-top: 30px;
    }
    h2 {
        color: #2c3e50;
        font-size: 15pt;
        margin-top: 25px;
        border-left: 4px solid #3498db;
        padding-left: 10px;
    }
    h3 {
        color: #34495e;
        font-size: 12pt;
    }
    .header-box {
        background-color: #f4f7f9;
        border: 1px solid #d1d8e0;
        border-radius: 6px;
        padding: 20px;
        text-align: center;
        margin-bottom: 30px;
    }
    .header-title {
        font-size: 24pt;
        font-weight: bold;
        color: #1B365D;
        margin-bottom: 10px;
    }
    .header-subtitle {
        font-size: 14pt;
        color: #7f8c8d;
        font-style: italic;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
    }
    th, td {
        border: 1px solid #bdc3c7;
        padding: 10px 12px;
        text-align: left;
    }
    th {
        background-color: #1B365D;
        color: white;
        font-weight: bold;
    }
    tr:nth-child(even) {
        background-color: #f9fbfd;
    }
    .code-box {
        background-color: #2d3436;
        color: #f5f6fa;
        font-family: 'Consolas', 'Courier New', monospace;
        padding: 12px;
        border-radius: 4px;
        font-size: 10pt;
        margin: 15px 0;
        white-space: pre-wrap;
    }
    .alert-box {
        background-color: #e8f4fd;
        border-left: 5px solid #2980b9;
        padding: 15px;
        margin: 15px 0;
    }
    ul, ol {
        margin-left: 20px;
    }
    li {
        margin-bottom: 8px;
    }
</style>
</head>
<body>

<div class="header-box">
    <div class="header-title">GUÍA DE IMPLEMENTACIÓN Y OPERACIÓN</div>
    <div class="header-title" style="font-size: 20pt; color: #2980b9;">SGSI (ISO/IEC 27001:2022) & SOC</div>
    <div class="header-subtitle">Solución Integral con Herramientas Gratuitas de Google y Motor Python</div>
    <hr style="border: 0; border-top: 1px solid #cbd5e1; margin: 15px 0;">
    <p><strong>Normas de Referencia:</strong> ISO/IEC 27001:2022 & ISO/IEC 27005 | <strong>Framework SOC:</strong> MITRE ATT&CK Enterprise</p>
    <p><strong>Costos de Licencia:</strong> $0 USD (100% Google Free Tier & Open Source)</p>
</div>

<h1>1. Introducción y Arquitectura General</h1>
<p>Este sistema proporciona una solución completa para implementar un <strong>Sistema de Gestión de Seguridad de la Información (SGSI)</strong> conforme a <strong>ISO/IEC 27001:2022</strong> y un <strong>Centro de Operaciones de Seguridad (SOC)</strong> con monitoreo en tiempo real, operando sobre la infraestructura gratuita de Google (Google Sheets, Looker Studio, Google Forms y Google Drive) potenciado por automatizaciones y analítica en Python.</p>

<div class="alert-box">
    <strong>Arquitectura de 4 Capas:</strong>
    <ul>
        <li><strong>Capa de Captura:</strong> Google Forms para reporte de incidentes y registro de activos.</li>
        <li><strong>Capa de Datos Central:</strong> Google Sheets relacional (Activos, Riesgos, SoA, Incidentes).</li>
        <li><strong>Capa de Inteligencia y Detección:</strong> Scripts Python para ingesta de logs, correlación contra MITRE ATT&CK y recálculo de riesgos ISO 27005.</li>
        <li><strong>Capa de Visualización:</strong> Dashboards ejecutivos y operativos en Google Looker Studio.</li>
    </ul>
</div>

<h1>2. Estructura del Framework y Requisitos</h1>
<p>El código se encuentra organizado en la siguiente estructura de directorios:</p>
<div class="code-box">sgsi_soc_framework/
├── config/                 -> Reglas, umbrales y catálogo de 93 controles ISO 27001:2022
├── core/                   -> Motores de cálculo de riesgos, incidentes y sincronización Google
├── soc_engine/             -> Parsers de logs, detector de amenazas y mapeador MITRE ATT&CK
├── templates_google/       -> Matrices base en formato CSV (UTF-8 BOM)
├── sync_drive/             -> Archivos listos para subir o sincronizar con Google Drive
├── simulators/             -> Generador de ataques y telemetría de prueba en vivo
├── dashboards/             -> Guía de Looker Studio y script Google Apps Script
├── main.py                 -> CLI principal de gestión unificada
└── requirements.txt        -> Dependencias opcionales</div>

<h1>3. Métodos de Sincronización con Google (Dual-Mode)</h1>
<p>El framework ofrece <strong>dos modalidades de sincronización</strong> para garantizar funcionamiento inmediato, dispongas o no de credenciales de Google Cloud Platform (GCP):</p>

<table>
    <tr>
        <th>Modalidad</th>
        <th>Requisitos</th>
        <th>Flujo de Operación</th>
    </tr>
    <tr>
        <td><strong>Modo A: Google Cloud API (Directo)</strong></td>
        <td>Cuenta Google Cloud (Gratuita) con Service Account JSON</td>
        <td>Crea automáticamente la hoja en Google Drive, actualiza celdas vía API y comparte permisos con tu correo electrónico.</td>
    </tr>
    <tr>
        <td><strong>Modo B: Local Sync (Sin GCP)</strong></td>
        <td>Ninguno (Solo tu cuenta de Google)</td>
        <td>Genera los CSVs en <code>sync_drive/</code> y permite importarlos a Google Sheets en 1 clic mediante Google Apps Script.</td>
    </tr>
</table>

<h2>Paso a Paso - Modo B (Recomendado sin Google Cloud):</h2>
<ol>
    <li>Ejecuta en tu terminal: <code>python main.py --action sync</code></li>
    <li>Los archivos actualizados se guardarán automáticamente en la carpeta <code>sync_drive/</code>.</li>
    <li>Sube los archivos a tu Google Drive.</li>
    <li>En tu Google Sheets maestro, ve a <strong>Extensiones &gt; Apps Script</strong>, pega el contenido de <code>dashboards/google_apps_script_sync.js</code> y haz clic en <strong>Ejecutar</strong>. Todas las hojas se actualizarán al instante.</li>
</ol>

<h1>4. Operación del SGSI (ISO/IEC 27001 & ISO 27005)</h1>
<p>El SGSI cuenta con tres herramientas fundamentales:</p>

<h2>A. Inventario y Valoración de Activos</h2>
<p>Permite registrar los activos de información clasificando su <strong>Confidencialidad</strong>, <strong>Integridad</strong> y <strong>Disponibilidad</strong> (escala 1 a 5). El sistema calcula automáticamente la criticidad resultante (Crítico, Alto, Medio, Bajo).</p>

<h2>B. Matriz de Evaluación de Riesgos (ISO 27005)</h2>
<p>Evalúa el <strong>Riesgo Inherente</strong> (Probabilidad × Impacto), aplica el factor de reducción según la <strong>Eficacia de los Controles Implementados (%)</strong> y calcula el <strong>Riesgo Residual</strong> para definir la estrategia de tratamiento (Mitigar, Aceptar, Transferir, Evitar).</p>
<div class="code-box">python main.py --action calculate-risks</div>

<h2>C. Declaración de Aplicabilidad (SoA - ISO 27001:2022)</h2>
<p>Monitorea el nivel de madurez y estado de implementación (Implementado, En Proceso, Planificado) de los <strong>93 controles de seguridad</strong> clasificados en los 4 dominios:</p>
<ul>
    <li><strong>Organizacionales:</strong> 37 controles (Políticas, roles, nube, proveedores).</li>
    <li><strong>Personas:</strong> 8 controles (Capacitación, acuerdos NDA, trabajo remoto).</li>
    <li><strong>Físicos:</strong> 14 controles (Perímetros, acceso físico, escritorio limpio).</li>
    <li><strong>Tecnológicos:</strong> 34 controles (Autenticación, antimalware, respaldos, WAF, SIEM/SOC).</li>
</ul>

<h1>5. Operación del SOC y Telemetría</h1>
<p>El motor del SOC incluye capacidades de análisis, correlación y detección de incidentes en tiempo real:</p>

<table>
    <tr>
        <th>Vector de Ataque</th>
        <th>Técnica MITRE ATT&CK</th>
        <th>Acción Automática del SOC</th>
    </tr>
    <tr>
        <td>Fuerza Bruta SSH / Login</td>
        <td>T1110 - Brute Force</td>
        <td>Alerta inmediata, conteo de intentos fallidos y recomendación de bloqueo de IP en Firewall.</td>
    </tr>
    <tr>
        <td>Inyección SQL (SQLi)</td>
        <td>T1190 - Exploit Public-Facing App</td>
        <td>Detección de patrones SQL maliciosos en URLs y registro de severidad Crítica.</td>
    </tr>
    <tr>
        <td>Cross-Site Scripting (XSS)</td>
        <td>T1189 - Drive-by Compromise</td>
        <td>Identificación de etiquetas de script maliciosas y recomendación de reglas WAF y CSP.</td>
    </tr>
    <tr>
        <td>Scripts PowerShell Ofuscados</td>
        <td>T1059 - Command & Scripting</td>
        <td>Detección de parámetros de evasión (Base64 / Bypass) y orden de aislamiento de endpoint.</td>
    </tr>
</table>

<h2>Comandos de Operación del SOC:</h2>
<ul>
    <li><strong>Simular ataques en tiempo real:</strong> <code>python main.py --action simulate-soc</code></li>
    <li><strong>Ingestar archivo de logs real:</strong> <code>python main.py --action ingest-logs --log-file ruta/a/logs.log</code></li>
    <li><strong>Ver KPIs (MTTD / MTTR / Severidades):</strong> <code>python main.py --action show-kpis</code></li>
</ul>

<h1>6. Despliegue de Dashboards en Google Looker Studio</h1>
<ol>
    <li>Ingresa a <a href="https://lookerstudio.google.com/">Looker Studio</a> con tu cuenta de Google.</li>
    <li>Haz clic en <strong>Crear &gt; Informe</strong> y selecciona el conector <strong>Google Sheets</strong>.</li>
    <li>Selecciona la hoja maestra <code>SGSI_SOC_Master_Database</code>.</li>
    <li><strong>Dashboard Operativo SOC:</strong> Agrega tarjetas de MTTD promedio, MTTR promedio, gráfico de dona por severidad, barras por tipo de amenaza y tabla de incidentes en vivo.</li>
    <li><strong>Dashboard Ejecutivo SGSI:</strong> Agrega medidor (Gauge) de madurez ISO 27001 (0 a 100%) y gráfico de dispersión para el mapa de calor de riesgos.</li>
</ol>

<h1>7. Resumen de Comandos del CLI</h1>
<table>
    <tr>
        <th>Acción</th>
        <th>Comando</th>
    </tr>
    <tr>
        <td><strong>Ejecutar todo el ciclo</strong></td>
        <td><code>python main.py --action all</code></td>
    </tr>
    <tr>
        <td><strong>Sincronizar datos para Google Drive</strong></td>
        <td><code>python main.py --action sync</code></td>
    </tr>
    <tr>
        <td><strong>Sincronizar con Google Cloud API</strong></td>
        <td><code>python main.py --action sync --sync-mode service_account --share-email tu_correo@gmail.com</code></td>
    </tr>
    <tr>
        <td><strong>Recalcular riesgos ISO 27005</strong></td>
        <td><code>python main.py --action calculate-risks</code></td>
    </tr>
    <tr>
        <td><strong>Simular incidentes de prueba</strong></td>
        <td><code>python main.py --action simulate-soc</code></td>
    </tr>
    <tr>
        <td><strong>Ver KPIs en consola</strong></td>
        <td><code>python main.py --action show-kpis</code></td>
    </tr>
</table>

</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[Generator] Documento Word/HTML creado exitosamente: {output_path}")

if __name__ == "__main__":
    out_doc = r"C:\Users\RICARDO.ALFARO\.gemini\antigravity\scratch\sgsi_soc_framework\GUIA_IMPLEMENTACION_SGSI_SOC.doc"
    out_htm = r"C:\Users\RICARDO.ALFARO\.gemini\antigravity\scratch\sgsi_soc_framework\GUIA_IMPLEMENTACION_SGSI_SOC.html"
    create_word_html_doc(out_doc)
    create_word_html_doc(out_htm)
