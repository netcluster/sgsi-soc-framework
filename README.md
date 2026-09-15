# SGSI & SOC Framework (Google Ecosystem + Python)

Sistema de Gestión de Seguridad de la Información (**SGSI**) alineado a **ISO/IEC 27001:2022** y Centro de Operaciones de Seguridad (**SOC**) con telemetría en tiempo real, desarrollado enteramente con **herramientas 100% gratuitas de Google** (Google Sheets, Looker Studio, Google Forms, Google Drive) y un motor de automatización, análisis y detección en **Python**.

---

## 🚀 Estructura del Framework

```text
sgsi_soc_framework/
│
├── config/
│   ├── config.yaml               # Configuración de reglas, SLAs y umbrales de riesgo
│   └── iso27001_controls.json    # Catálogo de los 93 controles ISO 27001:2022
│
├── core/
│   ├── risk_calculator.py        # Motor de evaluación de riesgos ISO 27005 (Inherente vs Residual)
│   ├── incident_manager.py       # Gestor del ciclo de vida de incidentes y cálculo de KPIs (MTTD/MTTR)
│   └── gsheets_manager.py        # Integración con Google Sheets API y modo local sync
│
├── soc_engine/
│   ├── log_parser.py             # Parser multiformato (Syslog, Nginx/Apache, JSON, Windows Auth)
│   ├── threat_detector.py        # Motor de detección de amenazas (Fuerza bruta, SQLi, XSS, PowerShell)
│   └── mitre_mapper.py           # Mapeo a Tácticas y Técnicas MITRE ATT&CK
│
├── templates_google/             # Matrices base para importar a Google Sheets
│   ├── 01_inventario_activos_template.csv
│   ├── 02_matriz_riesgos_template.csv
│   ├── 03_soa_iso27001_template.csv
│   └── 04_registro_incidentes_template.csv
│
├── simulators/
│   └── generate_sample_telemetry.py  # Generador y simulador de ataques para pruebas SOC
│
├── dashboards/
│   └── LOOKER_STUDIO_GUIDE.md   # Guía paso a paso para desplegar los Dashboards en Looker Studio
│
├── main.py                       # CLI unificado del SGSI & SOC
└── requirements.txt
```

---

## 🛠️ Modos de Uso y Comandos CLI

El CLI `main.py` permite gestionar de forma automática todas las operaciones del SGSI y SOC:

### 1. Ver Resumen y KPIs de Seguridad en Consola
```bash
python main.py --action show-kpis
```

### 2. Recalcular la Matriz de Riesgos (ISO 27005)
Recalcula automáticamente los niveles de riesgo inherente, la reducción por eficacia de controles y el riesgo residual:
```bash
python main.py --action calculate-risks
```

### 3. Simular Flujo de Ataques y Telemetría SOC
Genera ataques en vivo (fuerza bruta, inyecciones SQL, XSS, scripts PowerShell), los correlaciona contra MITRE ATT&CK y los inyecta en la hoja de incidentes:
```bash
python main.py --action simulate-soc
```

### 4. Ingestar y Analizar un Archivo de Logs Real
```bash
python main.py --action ingest-logs --log-file ruta/a/tus_logs.log
```

---

## 📊 Despliegue de los Dashboards en Google Looker Studio

Para visualizar el SOC y el SGSI en tiempo real:
1. Sube los archivos CSV de `templates_google/` a tu cuenta de Google Drive / Google Sheets.
2. Abre [Google Looker Studio](https://lookerstudio.google.com/) y crea un nuevo informe conectando las hojas.
3. Sigue la guía detallada en `dashboards/LOOKER_STUDIO_GUIDE.md` para configurar los paneles con tarjetas de KPIs, mapas de calor, matrices MITRE ATT&CK y estado de cumplimiento ISO 27001.
