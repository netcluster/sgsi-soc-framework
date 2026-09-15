@echo off
title Instalador de Auto-Inicio en Windows - SGSI & SOC Live Server
echo ======================================================================
echo    INSTALANDO SERVICIO DE AUTO-INICIO EN SEGUNDO PLANO (WINDOWS)
echo ======================================================================

set STARTUP_FOLDER=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
set TARGET_VBS=%STARTUP_FOLDER%\SGSI_SOC_Live_Background.vbs

echo Set WshShell = CreateObject("WScript.Shell") > "%TARGET_VBS%"
echo WshShell.CurrentDirectory = "C:\Users\RICARDO.ALFARO\Documents\sgsi_soc_framework" >> "%TARGET_VBS%"
echo WshShell.Run "pythonw.exe dashboards\live_server.py", 0, False >> "%TARGET_VBS%"
echo Set WshShell = Nothing >> "%TARGET_VBS%"

echo.
echo [OK] El servidor en vivo se ha configurado para iniciar automaticamente con Windows.
echo      Archivo registrado en: %TARGET_VBS%
echo.
echo A partir de ahora, tus dashboards en vivo (http://localhost:8080/ciso) estaran
echo siempre activos en segundo plano sin que tengas que abrir ninguna consola.
echo ======================================================================
pause
