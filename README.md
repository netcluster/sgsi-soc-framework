# 🛡️ SGSI & SOC Framework (SERMIG 2026)

**Sistema de Gestión de Seguridad de la Información (SGSI)** alineado a **ISO/IEC 27001:2022** y **Centro de Operaciones de Seguridad (SOC)** con telemetría en tiempo real, desarrollado enteramente en **Python 3** (con interfaz de escritorio nativa y Dashboards interactivos en vivo) e integración de sincronización dual con **Google Workspace** (Google Sheets, Google Drive y Google Forms).

---

## 🏛️ Marco Normativo y Estándares Aplicados

* **Normas Internacionales**:
  * **ISO/IEC 27001:2022**: Sistema de Gestión de Seguridad de la Información y Declaración de Aplicabilidad (SoA) con los 93 controles normativos.
  * **ISO/IEC 27005**: Gestión y evaluación matricial de riesgos (Riesgo Inherente vs. Riesgo Residual Mitigado).
  * **MITRE ATT&CK**: Mapeo y correlación de vectores tácticos y técnicos de ataque.
* **Normativa Legal Chilena**:
  * **Ley N° 21.663** *(Ley Marco de Ciberseguridad)*: Gestión de activos esenciales, reporte de incidentes significativos y articulación con el CSIRT Nacional / ANCI.
  * **Ley N° 19.628** *(Protección de la Vida Privada / Datos Personales)*: Clasificación de bases de datos sensibles ($C=5, I=5$, Nivel Crítico).
  * **Ley N° 21.459** *(Delitos Informáticos)* y **Decreto Supremo N° 83** *(SGSI en el Estado)*.
* **Seguridad en el Desarrollo**:
  * **OWASP Top 10**: Sanitización estricta contra inyección de fórmulas CSV (`sanitize_owasp_csv_field`), separación de roles (*Asset Owner* vs. *Custodian*) y verificación continua de integridad.

---

## 🚀 Arquitectura del Proyecto

```text
sgsi_soc_framework/
│
├── app_gui.py                        # Aplicación de escritorio nativa (Tkinter)
├── app_gui.pyw                       # Acceso directo para ejecución silenciosa en Windows
├── main.py                           # CLI unificado para operaciones por consola
├── generate_all.py                   # Orquestador del pipeline completo
├── MANUAL_DE_OPERACION_SGSI_SOC_SERMIG_2026.docx  # Manual oficial en formato Word
│
├── core/
│   ├── asset_manager.py              # Gestor de Activos (Ley 21.663 / Control 5.9) y Tríada CIA
│   ├── risk_calculator.py            # Motor de evaluación de riesgos ISO 27005 (Inherente vs Residual)
│   ├── soa_manager.py                # Gestor de la Declaración SoA (93 controles ISO 27001:2022)
│   ├── incident_manager.py           # Ciclo de vida de incidentes, playbooks y KPIs (MTTD/MTTR)
│   └── gsheets_manager.py            # Integración dual con Google Sheets / Google Drive
│
├── soc_engine/
│   ├── log_parser.py                 # Parser multiformato (Syslog, FortiGate, Nginx/Apache, JSON)
│   ├── threat_detector.py            # Motor de detección de amenazas y correlación MITRE ATT&CK
│   ├── threat_intel_manager.py       # Gestor de CTI (Feodo Tracker Abuse.ch, Tor Project, CSIRT)
│   ├── syslog_collector.py           # Servidor receptor Syslog en vivo (UDP 1514)
│   └── mitre_mapper.py               # Catálogo de tácticas y técnicas MITRE ATT&CK
│
├── dashboards/
│   ├── dashboard_generator.py        # Generador de Dashboards interactivos Plotly HTML
│   ├── live_server.py                # Servidor Web local (puerto 8080) con recarga automática en 2s
│   └── html/
│       ├── dashboard_ciso.html       # Dashboard Táctico CISO & SOC
│       └── dashboard_direccion.html  # Reporte Ejecutivo para la Dirección del Servicio
│
├── templates_google/                 # Archivos CSV maestros normalizados (UTF-8 BOM)
│   ├── 01_inventario_activos_template.csv
│   ├── 02_matriz_riesgos_template.csv
│   ├── 03_soa_iso27001_template.csv
│   └── 04_registro_incidentes_template.csv
│
├── sync_drive/                       # Carpeta de réplica sincronizada para Google Drive
└── config/
    ├── config.yaml                   # Umbrales de severidad, SLAs y parámetros del framework
    ├── iso27001_controls.json        # Catálogo de los 93 controles normativos
    └── threat_intel_cache.json       # Caché persistente de IoCs de Ciberinteligencia
```

---

## 🖥️ Módulos y Funcionalidades de la Aplicación de Escritorio

La aplicación principal (`app_gui.py` o `app_gui.pyw`) provee una interfaz gráfica completa organizada en 5 pestañas:

1. **📊 Resumen & KPIs**:
   * Indicadores clave en tiempo real: Volumen de incidentes, **MTTD** (Detección media), **MTTR** (Respuesta media) y distribución semiótica por severidad.
   * Accesos directos a los Dashboards Web CISO y Dirección.

2. **🚨 Centro de Operaciones SOC & Ciberinteligencia (CTI)**:
   * **Receptor Syslog en Vivo (UDP 1514)**: Escucha y procesa eventos de red de firewalls FortiGate y servidores en tiempo real.
   * **Ingesta de Archivos de Logs**: Análisis forense de archivos `.log` o `.txt`.
   * **Simulador de Ciberataques**: Generador de pruebas controladas (Fuerza Bruta SSH, SQLi, SSRF, Port Scan, XSS).
   * **🛡️ Responder / Mitigar...**: Formulario de respuesta a incidentes con asignación de playbooks, cambio de estado y registro de MTTR con actualización inmediata de los dashboards.
   * **🌐 Feeds CTI...**: Descarga y correlación en vivo de más de 1.350 IoCs activos desde *Feodo Tracker (Abuse.ch)*, *Tor Project* y *CSIRT Nacional*.

3. **⚖️ Matriz de Gestión de Riesgos (ISO/IEC 27005)**:
   * Alta, edición y eliminación de riesgos con cálculo dinámico de **Riesgo Inherente** y **Riesgo Residual** ($P \times I$).
   * Selección de salvaguardas y valoración de eficacia mitigadora.

4. **📜 Declaración de Aplicabilidad SoA (ISO/IEC 27001:2022)**:
   * Control y seguimiento de los 93 controles en sus 4 dominios (*Organizacionales, Personas, Físicos, Tecnológicos*).
   * Escala de estados: *Implementado (100%)*, *En Proceso (50%)*, *Planificado (15%)*, *No Implementado (0%)* y *No Aplica (0%)*.
   * **📁 Explorador de Evidencia Documental**: Botón `📁 Examinar...` para vincular archivos físicos (PDF, Word, Excel, carpetas de Google Drive) y botón `👁️ Abrir` para visualización directa.

5. **🏢 Inventario de Activos de Información (Ley N° 21.663 / Control 5.9)**:
   * Registro y ciclo de vida de activos esenciales.
   * Asignación de **Propietario de la Información (*Asset Owner*)** y **Custodio Técnico (*Custodian*)**.
   * Valoración de la **Tríada CIA** (Confidencialidad, Integridad, Disponibilidad 1-5) con cómputo dinámico de Criticidad (3 a 15) y clasificación de nivel (*Crítico, Alto, Medio, Bajo*).

---

## 📈 Dashboards Especializados en Tiempo Real

El sistema incluye un servidor web integrado (`http://localhost:8080`) con **recarga automática en 2 segundos** ante cualquier cambio en las matrices o incidentes:

* **🛡️ Dashboard Táctico CISO & SOC** (`http://localhost:8080/ciso`):
  * Serie temporal de eventos con **detección de picos anómalos** (marcadores de alerta estadística).
  * Top vectores de ataque correlacionados con **MITRE ATT&CK**.
  * Cuadrante térmico de la Matriz de Riesgos ISO 27005 (Efecto de Mitigación Inherente $\rightarrow$ Residual).
  * Distribución semiótica por severidad y tabla de telemetría operativa en vivo.
  * Pie de página institucional: `Framework SGSI & SOC - SERMIG 2026`.

* **👔 Reporte Ejecutivo para la Dirección del Servicio** (`http://localhost:8080/direccion`):
  * Velocímetro (*Gauge*) con el **Índice Global de Cumplimiento ISO 27001**.
  * Efectividad del Plan de Tratamiento de Riesgos Corporativos.
  * Barras apiladas de madurez de los 93 controles por dominio normativo.
  * Distribución del Inventario de Activos por criticidad.
  * Pie de página institucional: `Informe Ejecutivo SGSI - SERMIG 2026`.

---

## ⚡ Comandos de Ejecución y CLI

### 1. Iniciar la Aplicación de Escritorio
```bash
# Modo consola interactivo
python app_gui.py

# O ejecución silenciosa en Windows (sin consola negra)
pythonw app_gui.pyw
```

### 2. Comandos CLI (`main.py`)
```bash
# Ver KPIs y resumen en consola
python main.py --action show-kpis

# Recalcular matriz de riesgos ISO 27005
python main.py --action calculate-risks

# Simular telemetría y ataques SOC
python main.py --action simulate-soc

# Regenerar los Dashboards HTML
python main.py --action generate-dashboards

# Ingestar un archivo de logs real
python main.py --action ingest-logs --log-file ruta/a/logs.log
```

---

## 📄 Documentación Oficial

El repositorio incluye el manual completo con la justificación técnica, marco legal chileno, principios de visualización científica y guía paso a paso para usuarios y analistas:
* [`MANUAL_DE_OPERACION_SGSI_SOC_SERMIG_2026.docx`](file:///C:/Users/RICARDO.ALFARO/Documents/sgsi_soc_framework/MANUAL_DE_OPERACION_SGSI_SOC_SERMIG_2026.docx)
