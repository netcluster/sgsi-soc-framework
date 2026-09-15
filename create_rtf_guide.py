# -*- coding: utf-8 -*-
"""
Generador de formato RTF (Rich Text Format) para apertura universal en Word / WordPad.
"""

def generate_rtf(output_path: str):
    rtf_content = r"""{\rtf1\ansi\ansicpg1252\deff0\deflang1034{\fonttbl{\f0\fswiss\fprq2\fcharset0 Calibri;}{\f1\fnil\fprq2\fcharset0 Arial;}{\f2\fmodern\fprq1\fcharset0 Consolas;}}
{\colortbl ;\red27\green54\blue93;\red41\green128\blue185;\red52\green73\blue94;\red240\green244\blue248;\red232\green244\blue253;}
\viewkind4\uc1\pard\qc\b\f1\fs36\cf1 GUIA DE IMPLEMENTACION Y OPERACION\par
\fs28\cf2 SGSI (ISO/IEC 27001:2022) & SOC\b0\par
\i\fs22\cf3 Solucion Integral con Herramientas Gratuitas de Google y Motor Python\i0\par
\par\pard\qj\f0\fs22
\cf0 =========================================================================================\par
\b\fs26\cf1 1. INTRODUCCION Y ARQUITECTURA GENERAL\b0\fs22\cf0\par
Este manual describe la implementacion de un Sistema de Gestion de Seguridad de la Informacion (SGSI) bajo la norma ISO/IEC 27001:2022 y un Centro de Operaciones de Seguridad (SOC) con telemetria en tiempo real, utilizando herramientas gratuitas de Google (Google Sheets, Looker Studio, Google Forms, Drive) y scripts de analisis y deteccion en Python.\par
\par
\b Componentes Principales:\b0\par
1. \b Google Sheets:\b0 Base de datos maestra relacional (Activos, Riesgos, SoA e Incidentes).\par
2. \b Google Forms:\b0 Captura y reporte descentralizado de incidentes y altas de activos.\par
3. \b Google Looker Studio:\b0 Dashboards ejecutivos y operativos en tiempo real.\par
4. \b Motor Python:\b0 Ingesta de logs, deteccion de ciberataques contra MITRE ATT&CK, calculo de riesgos segun ISO 27005 y sincronizacion automatizada.\par
\par
=========================================================================================\par
\b\fs26\cf1 2. METODOS DE SINCRONIZACION CON GOOGLE (DUAL-MODE)\b0\fs22\cf0\par
El sistema cuenta con 2 modalidades de operacion:\par
\par
\b [MODO A] Con Google Cloud Platform (API Directa):\b0\par
- Requiere cuenta gratuita en Google Cloud y Service Account JSON (config/google_credentials.json).\par
- Crea la hoja y actualiza celdas directamente en la nube.\par
- Comando: \f2\fs20 python main.py --action sync --sync-mode service_account --share-email tu_correo@gmail.com\f0\fs22\par
\par
\b [MODO B] Sin Google Cloud Platform (Local Sync + Google Apps Script):\b0\par
- No requiere ninguna configuracion en GCP.\par
- Paso 1: Ejecutar \f2\fs20 python main.py --action sync\f0\fs22 (genera los CSVs en sync_drive/).\par
- Paso 2: Subir la carpeta sync_drive/ a Google Drive.\par
- Paso 3: En Google Sheets, ir a Extensiones > Apps Script, pegar el script 'dashboards/google_apps_script_sync.js' y hacer clic en Ejecutar para importar todo en 1 clic.\par
\par
=========================================================================================\par
\b\fs26\cf1 3. OPERACION DEL SGSI (ISO/IEC 27001 & ISO 27005)\b0\fs22\cf0\par
- \b Inventario de Activos:\b0 Clasificacion de Confidencialidad, Integridad y Disponibilidad (1 a 5).\par
- \b Evaluacion de Riesgos:\b0 Riesgo Inherente = Probabilidad x Impacto. Calculo automatico del Riesgo Residual en base a la eficacia de los controles.\par
- \b Declaracion de Aplicabilidad (SoA):\b0 Monitoreo de los 93 controles de seguridad clasificados en los 4 dominios (Organizacionales, Personas, Fisicos, Tecnologicos).\par
- \b Comando de Recalculo:\b0 \f2\fs20 python main.py --action calculate-risks\f0\fs22\par
\par
=========================================================================================\par
\b\fs26\cf1 4. OPERACION DEL SOC Y REGLAS DE DETECCION\b0\fs22\cf0\par
- \b Fuerza Bruta SSH (MITRE T1110):\b0 Deteccion de intentos fallidos reiterados.\par
- \b Inyeccion SQL (MITRE T1190):\b0 Deteccion de patrones maliciosos en peticiones web.\par
- \b Cross-Site Scripting (MITRE T1189):\b0 Deteccion de vectores XSS.\par
- \b Scripts Ofuscados (MITRE T1059):\b0 Deteccion de ejecucion PowerShell con Base64 o Bypass.\par
\par
\b Comandos del SOC:\b0\par
- Simular ataques en vivo: \f2\fs20 python main.py --action simulate-soc\f0\fs22\par
- Ingestar archivo de logs real: \f2\fs20 python main.py --action ingest-logs --log-file ruta/a/logs.log\f0\fs22\par
- Ver metricas y KPIs (MTTD/MTTR): \f2\fs20 python main.py --action show-kpis\f0\fs22\par
\par
=========================================================================================\par
\b\fs26\cf1 5. DASHBOARDS EN GOOGLE LOOKER STUDIO (GRATIS)\b0\fs22\cf0\par
1. Conectar Google Sheets en lookerstudio.google.com.\par
2. \b Dashboard SOC:\b0 Tarjetas MTTD y MTTR, dona de severidades, barras por tipo de amenaza y tabla de alertas en vivo.\par
3. \b Dashboard SGSI:\b0 Medidor de madurez ISO 27001 (0-100%) y mapa de calor de riesgos.\par
\par
=========================================================================================\par
\b\fs26\cf1 6. RESUMEN DE COMANDOS DEL CLI\b0\fs22\cf0\par
- Ejecutar todo el ciclo: \f2\fs20 python main.py --action all\f0\fs22\par
- Sincronizar datos: \f2\fs20 python main.py --action sync\f0\fs22\par
- Recalcular riesgos: \f2\fs20 python main.py --action calculate-risks\f0\fs22\par
- Simular telemetria SOC: \f2\fs20 python main.py --action simulate-soc\f0\fs22\par
- Mostrar KPIs: \f2\fs20 python main.py --action show-kpis\f0\fs22\par
}
"""
    with open(output_path, "w", encoding="latin-1") as f:
        f.write(rtf_content)
    print(f"[RTF Generator] Archivo RTF creado exitosamente: {output_path}")

if __name__ == "__main__":
    out_rtf = r"C:\Users\RICARDO.ALFARO\.gemini\antigravity\scratch\sgsi_soc_framework\GUIA_IMPLEMENTACION_SGSI_SOC.rtf"
    generate_rtf(out_rtf)
