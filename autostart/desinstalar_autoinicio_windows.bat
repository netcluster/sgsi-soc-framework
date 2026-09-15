@echo off
title Desinstalador de Auto-Inicio en Windows
set TARGET_VBS=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SGSI_SOC_Live_Background.vbs

if exist "%TARGET_VBS%" (
    del "%TARGET_VBS%"
    echo [OK] Servicio de auto-inicio desinstalado correctamente.
) else (
    echo [INFO] El servicio de auto-inicio no estaba instalado.
)
pause
