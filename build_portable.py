# -*- coding: utf-8 -*-
"""
Script de Empaquetado Portable para Windows del SGSI & SOC Framework (SERMIG 2026).
Utiliza PyInstaller para generar una distribución 100% autónoma que no requiere Python instalado.
"""

import os
import sys
import shutil
import subprocess

def build_portable_package():
    print("=" * 70)
    print("   EMPAQUETADOR PORTABLE WINDOWS - SGSI & SOC FRAMEWORK (SERMIG 2026)")
    print("=" * 70)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, "dist")
    build_dir = os.path.join(base_dir, "build")
    output_app_dir = os.path.join(dist_dir, "SGSI_SOC_SERMIG_2026_Portable")

    icon_path = os.path.join(base_dir, "la-seguridad-cibernetica.ico")
    icon_arg = f"--icon={icon_path}" if os.path.exists(icon_path) else ""

    # Limpieza previa limpia de directorios
    subprocess.run(["powershell", "-Command", "Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue"], cwd=base_dir)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--name=SGSI_SOC_SERMIG_2026_Portable",
        f"--add-data=templates_google;templates_google",
        f"--add-data=config;config",
        f"--add-data=dashboards/html;dashboards/html",
        f"--add-data=MANUAL_DE_OPERACION_SGSI_SOC_SERMIG_2026.docx;.",
        "app_gui.py"
    ]
    if icon_arg:
        cmd.insert(4, icon_arg)

    print("\n[+] Compilando ejecutable con PyInstaller...")
    print(f"[CMD] {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, cwd=base_dir)
    if result.returncode != 0:
        print("\n[ERROR] Fallo la compilacion de PyInstaller.")
        return False

    # Copiar recursos adicionales de soporte si no existen
    for folder in ["templates_google", "sync_drive", "config"]:
        src = os.path.join(base_dir, folder)
        dst = os.path.join(output_app_dir, folder)
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                shutil.copytree(src, dst)
            except Exception as e:
                print(f"[ADVERTENCIA] No se pudo copiar {folder}: {e}")

    manual_src = os.path.join(base_dir, "MANUAL_DE_OPERACION_SGSI_SOC_SERMIG_2026.docx")
    if os.path.exists(manual_src):
        try:
            shutil.copy2(manual_src, output_app_dir)
        except Exception:
            pass

    # Crear lanzador directo
    launcher_bat = os.path.join(output_app_dir, "Iniciar_SGSI_SOC_SERMIG.bat")
    with open(launcher_bat, "w", encoding="utf-8") as f:
        f.write("@echo off\n")
        f.write("cd /d \"%~dp0\"\n")
        f.write("start \"\" \"SGSI_SOC_SERMIG_2026_Portable.exe\"\n")

    print("\n" + "=" * 70)
    print(" [OK] EMPAQUETADO PORTABLE COMPLETADO CON EXITO!")
    print(f" [RUTA] Carpeta Portable generada en:\n   {output_app_dir}")
    print("\n [INFO] Puedes comprimir esta carpeta en un archivo ZIP y copiarla a cualquier")
    print("        computador con Windows 10/11 o Windows Server (no requiere Python).")
    print("=" * 70)
    return True

if __name__ == "__main__":
    build_portable_package()
