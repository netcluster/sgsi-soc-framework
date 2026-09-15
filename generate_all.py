import csv
import json
import os

base_dir = os.path.join(os.getcwd(), 'templates_google')
os.makedirs(base_dir, exist_ok=True)

# 1. Inventario de Activos
activos_headers = [
    'ID_Activo', 'Nombre_Activo', 'Tipo_Activo', 'Propietario', 'Custodio', 'Ubicacion',
    'Confidencialidad_1a5', 'Integridad_1a5', 'Disponibilidad_1a5', 'Criticidad_Calculada', 'Nivel_Criticidad', 'Estado'
]
activos_rows = [
    ['ACT-001', 'Base de Datos de Clientes (PostgreSQL)', 'Informacion / Base de Datos', 'Gerente Comercial', 'DBA Lead', 'Google Cloud SQL', 5, 5, 4, 14, 'Critico', 'Activo'],
    ['ACT-002', 'Servidor de Aplicacion Web ERP', 'Hardware / Servidor Virtual', 'Gerente de TI', 'Sysadmin', 'GCP Compute Engine', 4, 4, 5, 13, 'Alto', 'Activo'],
    ['ACT-003', 'Codigo Fuente Core Platform', 'Software / Repositorio', 'CTO', 'DevSecOps Lead', 'GitHub Enterprise', 5, 4, 4, 13, 'Alto', 'Activo'],
    ['ACT-004', 'Laptops de Personal Clave', 'Hardware / Endpoint', 'Jefe de Soporte', 'Usuarios Finales', 'Oficina Central / Remoto', 3, 3, 3, 9, 'Medio', 'Activo'],
    ['ACT-005', 'Firewall Perimetral y VPN', 'Red / Comunicaciones', 'CISO', 'Ingeniero de Redes', 'Datacenter / Edge', 4, 5, 5, 14, 'Critico', 'Activo'],
    ['ACT-006', 'Sistema de Respaldo Cloud', 'Servicio / Almacenamiento', 'CISO', 'Sysadmin', 'Google Cloud Storage', 4, 5, 4, 13, 'Alto', 'Activo']
]

with open(os.path.join(base_dir, '01_inventario_activos_template.csv'), 'w', newline='', encoding='utf-8-sig') as f:
    writer = csv.writer(f)
    writer.writerow(activos_headers)
    writer.writerows(activos_rows)

# 2. Matriz de Riesgos (ISO 27005)
riesgos_headers = [
    'ID_Riesgo', 'ID_Activo', 'Amenaza', 'Vulnerabilidad', 'Probabilidad_Inherente_1a5', 'Impacto_Inherente_1a5', 
    'Nivel_Riesgo_Inherente', 'Categoria_Riesgo_Inherente', 'Controles_Aplicados', 'Eficacia_Controles_Pct',
    'Probabilidad_Residual_1a5', 'Impacto_Residual_1a5', 'Nivel_Riesgo_Residual', 'Categoria_Riesgo_Residual',
    'Estrategia_Tratamiento', 'Responsable', 'Fecha_Revision'
]
riesgos_rows = [
    ['RSG-001', 'ACT-001', 'Ransomware / Cifrado no autorizado', 'Falta de EDR en servidores legacy', 4, 5, 20, 'Extremo', 'A.8.7 (Antimalware), A.8.13 (Backups inmutables)', '70%', 2, 4, 8, 'Medio', 'Mitigar', 'CISO', '2026-10-01'],
    ['RSG-002', 'ACT-002', 'Ataque de Denegacion de Servicio (DDoS)', 'Ancho de banda saturable', 3, 4, 12, 'Alto', 'A.8.20 (WAF Cloud Armor), Rate Limiting', '80%', 1, 3, 3, 'Bajo', 'Mitigar', 'Ingeniero Cloud', '2026-10-15'],
    ['RSG-003', 'ACT-003', 'Fuga de credenciales en repositorios', 'Hardcoding de API keys en commits', 4, 4, 16, 'Alto', 'A.8.28 (Pre-commit hooks git-secrets / Trufflehog)', '85%', 1, 3, 3, 'Bajo', 'Mitigar', 'DevSecOps Lead', '2026-10-15'],
    ['RSG-004', 'ACT-004', 'Robo / Extravio de dispositivo portatil', 'Falta de cifrado de disco completo', 3, 3, 9, 'Medio', 'A.8.1 (BitLocker forzado por MDM)', '90%', 2, 1, 2, 'Bajo', 'Aceptar', 'Jefe de Soporte', '2026-11-01'],
    ['RSG-005', 'ACT-005', 'Acceso no autorizado por fuerza bruta VPN', 'Autenticacion con solo usuario/contrasena', 5, 5, 25, 'Extremo', 'A.8.5 (MFA Obligatorio con Google Authenticator)', '95%', 1, 2, 2, 'Bajo', 'Mitigar', 'Sysadmin', '2026-09-30']
]

with open(os.path.join(base_dir, '02_matriz_riesgos_template.csv'), 'w', newline='', encoding='utf-8-sig') as f:
    writer = csv.writer(f)
    writer.writerow(riesgos_headers)
    writer.writerows(riesgos_rows)

# 3. Declaracion de Aplicabilidad (SoA ISO 27001:2022)
with open(os.path.join('config', 'iso27001_controls.json'), 'r', encoding='utf-8') as f:
    controls_data = json.load(f)

soa_headers = [
    'Codigo_Control', 'Nombre_Control', 'Dominio', 'Aplica', 'Justificacion_Inclusion_Exclusion', 
    'Estado_Implementacion', 'Porcentaje_Madurez', 'Evidencia_Documental', 'Responsable'
]
soa_rows = []
idx = 0
for domain in controls_data['domains']:
    dom_name = domain['name']
    for ctrl in domain['controls']:
        idx += 1
        estado = 'Implementado' if idx % 3 != 0 else ('En Proceso' if idx % 2 == 0 else 'Planificado')
        madurez = 100 if estado == 'Implementado' else (50 if estado == 'En Proceso' else 15)
        clean_code = ctrl['code'].replace('.', '_')
        soa_rows.append([
            ctrl['code'],
            ctrl['name'],
            dom_name,
            'SI',
            'Requisito mandatorio de gestion y reduccion de riesgos',
            estado,
            madurez,
            f'Doc-Ref-{clean_code}.pdf',
            'Equipo de Seguridad / CISO'
        ])

with open(os.path.join(base_dir, '03_soa_iso27001_template.csv'), 'w', newline='', encoding='utf-8-sig') as f:
    writer = csv.writer(f)
    writer.writerow(soa_headers)
    writer.writerows(soa_rows)

# 4. Registro de Incidentes SOC / SGSI
incidentes_headers = [
    'ID_Incidente', 'Fecha_Hora', 'Titulo_Incidente', 'Tipo_Amenaza', 'Severidad', 'Estado',
    'Tactica_MITRE', 'Tecnica_MITRE', 'IP_Origen', 'IP_Destino_Activo', 'Usuario_Involucrado',
    'MTTD_Minutos', 'MTTR_Minutos', 'Descripcion_Hallazgo', 'Accion_Correctiva', 'Responsable_SOC'
]
incidentes_rows = [
    ['INC-2026-001', '2026-09-08 08:14:22', 'Multiples intentos fallidos de autenticacion SSH', 'Fuerza Bruta', 'Alta', 'Cerrado', 'Credential Access', 'T1110 - Brute Force', '185.220.101.5', 'ACT-002 (10.0.1.15)', 'admin_backup', 5, 25, 'Bloqueo automatico de IP via Fail2ban y notificacion', 'IP agregada a lista negra de firewall perimetral', 'Analista L1'],
    ['INC-2026-002', '2026-09-09 11:30:00', 'Deteccion de correo de suplantacion de identidad (Phishing)', 'Ingenieria Social', 'Media', 'Cerrado', 'Initial Access', 'T1566 - Phishing', '198.51.100.44', 'ACT-004 (Workstation 12)', 'carlos.m@empresa.com', 12, 45, 'Usuario reporto correo sospechoso con enlace apocrifo de nomina', 'Purga de buzones y capacitacion de concientizacion', 'Analista L2'],
    ['INC-2026-003', '2026-09-10 19:45:10', 'Escaneo masivo de puertos TCP SYN', 'Reconocimiento', 'Baja', 'Cerrado', 'Reconnaissance', 'T1046 - Network Service Scanning', '45.154.255.89', 'ACT-005 (Perimetro)', 'N/A', 2, 10, 'Sondeo de puertos 80, 443, 3389, 8080 en gateway perimetral', 'Reglas perimetrales de drop silencioso activadas', 'Analista L1'],
    ['INC-2026-004', '2026-09-11 03:22:05', 'Ejecucion de script PowerShell sospechoso en endpoint', 'Malware / Execution', 'Critica', 'En Mitigacion', 'Execution', 'T1059.001 - PowerShell', 'Localhost', 'ACT-004 (Workstation 05)', 'maria.l@empresa.com', 3, 60, 'EDR detecto llamada a script codificado en Base64 descargando payload', 'Endpoint aislado de la red, recoleccion de memoria RAM forense', 'Analista L3 / Lead'],
    ['INC-2026-005', '2026-09-12 14:05:50', 'Intento de acceso a recurso confidencial fuera de horario', 'Acceso No Autorizado', 'Media', 'Cerrado', 'Defense Evasion', 'T1078 - Valid Accounts', '200.89.45.12', 'ACT-001 (PostgreSQL)', 'juan.p@empresa.com', 8, 30, 'Intento de lectura de tabla de salarios desde IP no corporativa', 'Sesion revocada, reseteo preventivo de credenciales', 'Analista L2'],
    ['INC-2026-006', '2026-09-13 09:12:11', 'Exfiltracion potencial de datos via DNS tunneling', 'Fuga de Informacion', 'Critica', 'En Investigacion', 'Exfiltration', 'T1048 - Exfiltration Over Alternative Protocol', '10.0.3.40', 'ACT-006 (Cloud Storage)', 'svc_storage', 4, 0, 'Trafico anomalo de consultas DNS TXT de alta frecuencia a dominio no categorizado', 'Bloqueo en servidor DNS resolver y contencion del host', 'Analista L3 / Lead'],
    ['INC-2026-007', '2026-09-13 16:50:33', 'Ataque de Cross-Site Scripting (XSS) en portal web', 'Vulnerabilidad Web', 'Media', 'Cerrado', 'Initial Access', 'T1190 - Exploit Public-Facing App', '103.22.182.19', 'ACT-002 (Web ERP)', 'anon_client', 1, 15, 'Payload <script> detectado y mitigado en WAF', 'Regla de WAF ajustada y parche de sanitizacion desplegado', 'Analista L1'],
    ['INC-2026-008', '2026-09-14 02:40:19', 'Modificacion no autorizada de archivo critico de sistema', 'Integridad / Manipulacion', 'Alta', 'Abierto', 'Persistence', 'T1505 - Server Software Component', 'Localhost', 'ACT-002 (Web ERP)', 'root_session', 2, 0, 'FIM (File Integrity Monitoring) reporto cambio en /etc/pam.d/sshd', 'Servidor colocado en cuarentena y rollback de snapshot', 'Analista L2']
]

with open(os.path.join(base_dir, '04_registro_incidentes_template.csv'), 'w', newline='', encoding='utf-8-sig') as f:
    writer = csv.writer(f)
    writer.writerow(incidentes_headers)
    writer.writerows(incidentes_rows)

print('Templates generated successfully.')
