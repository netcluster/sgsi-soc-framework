# -*- coding: utf-8 -*-
"""
Integración con Google Sheets y Google Drive para el SGSI y SOC.
Soporte Dual:
1. Modo 'service_account': API directa de Google Sheets (Crea hojas, actualiza celdas, comparte con tu email de Google).
2. Modo 'local_sync': Exportación automatizada de CSVs listos para Google Drive y Google Looker Studio sin necesidad de GCP.
"""

import os
import csv
import json
import shutil
from typing import List, Dict, Any, Optional

class GSheetsManager:
    def __init__(
        self,
        mode: str = "auto",
        creds_file: str = "config/google_credentials.json",
        spreadsheet_name: str = "SGSI_SOC_Master_Database",
        sync_drive_dir: str = "sync_drive",
        share_email: Optional[str] = None
    ):
        self.mode = mode.lower()
        self.creds_file = creds_file
        self.spreadsheet_name = spreadsheet_name
        self.sync_drive_dir = sync_drive_dir
        self.share_email = share_email
        self.client = None
        self.sheet = None
        
        os.makedirs(self.sync_drive_dir, exist_ok=True)

        # Autodetección de modo
        if self.mode in ["auto", "service_account", "api"]:
            if os.path.exists(self.creds_file):
                self._initialize_google_api()
            else:
                if self.mode in ["service_account", "api"]:
                    print(f"[GSheetsManager] [AVISO] No se encontró el archivo de credenciales '{self.creds_file}'.")
                    print("[GSheetsManager] Cambiando automáticamente a Modo 'Local Sync' (CSVs para Google Drive).")
                self.mode = "local_sync"
        else:
            self.mode = "local_sync"

    def _initialize_google_api(self):
        """Inicializa el cliente gspread y autentica con Google Cloud"""
        try:
            import gspread
            from oauth2client.service_account import ServiceAccountCredentials
            
            scope = [
                'https://spreadsheets.google.com/feeds',
                'https://www.googleapis.com/auth/drive'
            ]
            creds = ServiceAccountCredentials.from_json_keyfile_name(self.creds_file, scope)
            self.client = gspread.authorize(creds)
            
            # Buscar o crear la hoja de cálculo principal
            try:
                self.sheet = self.client.open(self.spreadsheet_name)
                print(f"[GSheetsManager] [Google Cloud API] Conectado a la hoja existente: '{self.spreadsheet_name}'.")
            except Exception:
                print(f"[GSheetsManager] [Google Cloud API] Creando nueva hoja en Google Drive: '{self.spreadsheet_name}'...")
                self.sheet = self.client.create(self.spreadsheet_name)
                if self.share_email:
                    self.sheet.share(self.share_email, perm_type='user', role='writer')
                    print(f"[GSheetsManager] Permiso de edición compartido con: {self.share_email}")

            self.mode = "service_account"
        except ImportError:
            print("[GSheetsManager] [AVISO] Las librerías 'gspread' u 'oauth2client' no están instaladas.")
            print("[GSheetsManager] Para usar la API directa: pip install gspread oauth2client")
            print("[GSheetsManager] Continuando en Modo 'Local Sync' CSV.")
            self.mode = "local_sync"
        except Exception as e:
            print(f"[GSheetsManager] Error autenticando con Google API: {e}. Fallback a Modo 'Local Sync'.")
            self.mode = "local_sync"

    def sync_dataset(self, worksheet_title: str, rows_data: List[Dict[str, Any]], filename_csv: str = None) -> Dict[str, Any]:
        """
        Sincroniza un conjunto de datos según el modo activo (API de Google y/o archivo CSV local para Drive).
        """
        if not rows_data:
            return {"status": "empty", "rows": 0}

        csv_name = filename_csv or f"{worksheet_title.lower().replace(' ', '_')}.csv"
        drive_path = os.path.join(self.sync_drive_dir, csv_name)

        # 1. SIEMPRE genera el archivo CSV con UTF-8 BOM en sync_drive/
        with open(drive_path, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows_data[0].keys()))
            writer.writeheader()
            writer.writerows(rows_data)

        sync_result = {
            "dataset": worksheet_title,
            "rows": len(rows_data),
            "csv_path": drive_path,
            "api_synced": False,
            "mode": self.mode
        }

        # 2. Si el modo API está activo, sincroniza en la nube de Google
        if self.mode == "service_account" and self.sheet:
            try:
                try:
                    ws = self.sheet.worksheet(worksheet_title)
                except Exception:
                    ws = self.sheet.add_worksheet(title=worksheet_title, rows=len(rows_data)+20, cols=len(rows_data[0])+5)

                headers = list(rows_data[0].keys())
                matrix_values = [headers]
                for r in rows_data:
                    matrix_values.append([str(r.get(h, '')) for h in headers])

                ws.clear()
                ws.update('A1', matrix_values)
                sync_result["api_synced"] = True
                print(f"[GSheetsManager] [Google Cloud API] Hoja '{worksheet_title}' sincronizada en la nube ({len(rows_data)} filas).")
            except Exception as e:
                print(f"[GSheetsManager] Error actualizando hoja '{worksheet_title}' vía API: {e}")

        if not sync_result["api_synced"]:
            print(f"[GSheetsManager] [Local Sync] Archivo listo para Google Drive / Looker Studio: '{drive_path}' ({len(rows_data)} filas).")

        return sync_result

    @staticmethod
    def get_saved_config() -> Dict[str, Any]:
        cfg_path = os.path.join("config", "gsheets_config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    @staticmethod
    def save_config(config_dict: Dict[str, Any]):
        os.makedirs("config", exist_ok=True)
        cfg_path = os.path.join("config", "gsheets_config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False)

    def sync_to_google_sheets_webhook(self, webhook_url: str) -> Dict[str, Any]:
        """Envía todas las matrices del SGSI y SOC a una hoja de Google Sheets vía Google Apps Script Webhook"""
        import urllib.request
        import urllib.error

        if not webhook_url or not webhook_url.startswith("http"):
            return {"status": "error", "message": "URL de Webhook inválida."}

        from core.risk_calculator import RiskCalculator
        from core.incident_manager import IncidentManager

        # Recopilar todos los datasets
        activos_csv = os.path.join("templates_google", "01_inventario_activos_template.csv")
        activos_data = []
        if os.path.exists(activos_csv):
            with open(activos_csv, "r", encoding="utf-8-sig") as f:
                activos_data = list(csv.DictReader(f))

        riesgos_csv = os.path.join("templates_google", "02_matriz_riesgos_template.csv")
        risk_calc = RiskCalculator()
        riesgos_data = risk_calc.process_risk_matrix(riesgos_csv)

        soa_csv = os.path.join("templates_google", "03_soa_iso27001_template.csv")
        soa_data = []
        if os.path.exists(soa_csv):
            with open(soa_csv, "r", encoding="utf-8-sig") as f:
                soa_data = list(csv.DictReader(f))

        inc_mgr = IncidentManager()
        incidentes_data = inc_mgr.get_all_incidents()

        payload = {
            "datasets": {
                "01_Inventario_Activos": activos_data,
                "02_Matriz_Riesgos": riesgos_data,
                "03_SoA_ISO27001": soa_data,
                "04_Registro_Incidentes": incidentes_data
            }
        }

        # Guardar URL en config
        self.save_config({"webhook_url": webhook_url, "last_sync": datetime.now().isoformat()})

        data_bytes = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data_bytes,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                res_body = response.read().decode('utf-8')
                res_json = json.loads(res_body)
                return {
                    "status": "success",
                    "response": res_json,
                    "rows_synced": {
                        "activos": len(activos_data),
                        "riesgos": len(riesgos_data),
                        "soa": len(soa_data),
                        "incidentes": len(incidentes_data)
                    }
                }
        except urllib.error.HTTPError as e:
            # Manejar posibles redirecciones de Google Apps Script 302
            if e.code == 302:
                redirect_url = e.headers.get('Location')
                if redirect_url:
                    req_redir = urllib.request.Request(redirect_url, data=data_bytes, headers={'Content-Type': 'application/json'}, method='POST')
                    with urllib.request.urlopen(req_redir, timeout=30) as redir_resp:
                        res_body = redir_resp.read().decode('utf-8')
                        return {"status": "success", "response": json.loads(res_body)}
            return {"status": "error", "message": f"Error HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def sync_all_framework_data(self) -> Dict[str, Any]:
        """Sincroniza las 4 matrices fundamentales del SGSI y SOC"""
        from core.risk_calculator import RiskCalculator
        from core.incident_manager import IncidentManager

        print(f"\n[+] Iniciando sincronización integral (Modo: {self.mode.upper()})...")

        # 1. Activos
        activos_csv = os.path.join("templates_google", "01_inventario_activos_template.csv")
        activos_data = []
        if os.path.exists(activos_csv):
            with open(activos_csv, "r", encoding="utf-8-sig") as f:
                activos_data = list(csv.DictReader(f))
        r1 = self.sync_dataset("01_Inventario_Activos", activos_data, "01_inventario_activos.csv")

        # 2. Riesgos (ISO 27005)
        riesgos_csv = os.path.join("templates_google", "02_matriz_riesgos_template.csv")
        risk_calc = RiskCalculator()
        riesgos_data = risk_calc.process_risk_matrix(riesgos_csv)
        r2 = self.sync_dataset("02_Matriz_Riesgos", riesgos_data, "02_matriz_riesgos.csv")

        # 3. SoA ISO 27001
        soa_csv = os.path.join("templates_google", "03_soa_iso27001_template.csv")
        soa_data = []
        if os.path.exists(soa_csv):
            with open(soa_csv, "r", encoding="utf-8-sig") as f:
                soa_data = list(csv.DictReader(f))
        r3 = self.sync_dataset("03_SoA_ISO27001", soa_data, "03_soa_iso27001.csv")

        # 4. Incidentes SOC
        inc_mgr = IncidentManager()
        incidentes_data = inc_mgr.get_all_incidents()
        r4 = self.sync_dataset("04_Registro_Incidentes", incidentes_data, "04_registro_incidentes.csv")

        print("\n[OK] Sincronización completa finalizada.")
        return {
            "mode": self.mode,
            "results": [r1, r2, r3, r4],
            "sync_folder": os.path.abspath(self.sync_drive_dir)
        }
