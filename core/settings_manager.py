# -*- coding: utf-8 -*-
"""
Módulo de Gestión de Parámetros y Configuración Institucional (Settings).
Framework SGSI & SOC (SERMIG 2026).
Permite parametrizar el nombre de la empresa/servicio, autoridades CISO,
puertos de red, URLs de servicios y opciones generales.
"""

import os
import json
from typing import Dict, Any

class SettingsManager:
    DEFAULT_SETTINGS = {
        "org_name": "Servicio Nacional de Migraciones",
        "org_code": "SERMIG",
        "framework_period": "2026",
        "ciso_name": "Ricardo Alfaro Jiménez",
        "ciso_email": "seguridad.informacion@serviciomigraciones.cl",
        "ciso_phone": "+56 2 2550 0000",
        "org_address": "San Antonio 580, Santiago, Chile",
        "live_server_port": 8080,
        "syslog_port": 1514,
        "ollama_url": "http://localhost:11434",
        "default_ai_model": "llama3.2",
        "gsheets_webhook_url": ""
    }

    def __init__(self, config_dir: str = None):
        if config_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.config_dir = os.path.join(base_dir, "config")
        else:
            self.config_dir = config_dir

        self.settings_file = os.path.join(self.config_dir, "organization_settings.json")
        os.makedirs(self.config_dir, exist_ok=True)
        self._ensure_settings()

    def _ensure_settings(self):
        """Crea el archivo de configuración con valores por defecto si no existe."""
        if not os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "w", encoding="utf-8") as f:
                    json.dump(self.DEFAULT_SETTINGS, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"[ERROR SettingsManager] No se pudo inicializar settings: {e}")

    def get_settings(self) -> Dict[str, Any]:
        """Obtiene el diccionario completo de configuración."""
        if not os.path.exists(self.settings_file):
            self._ensure_settings()
        try:
            with open(self.settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in self.DEFAULT_SETTINGS.items():
                    if k not in data:
                        data[k] = v
                return data
        except Exception:
            return self.DEFAULT_SETTINGS.copy()

    def get(self, key: str, default: Any = None) -> Any:
        """Obtiene un parámetro específico por clave."""
        settings = self.get_settings()
        return settings.get(key, default if default is not None else self.DEFAULT_SETTINGS.get(key))

    def save_settings(self, settings_dict: Dict[str, Any]) -> bool:
        """Guarda la configuración actualizada en disco."""
        try:
            current = self.DEFAULT_SETTINGS.copy()
            if os.path.exists(self.settings_file):
                try:
                    with open(self.settings_file, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                        current.update(loaded)
                except Exception:
                    pass
            current.update(settings_dict)
            with open(self.settings_file, "w", encoding="utf-8") as f:
                json.dump(current, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[ERROR SettingsManager] No se pudo guardar settings: {e}")
            return False
