# -*- coding: utf-8 -*-
"""
Lanzador silencioso de Windows para la Aplicación de Escritorio del SGSI & SOC Framework.
Importa y ejecuta directamente app_gui.py asegurando consistencia total.
"""
import os
import sys

# Asegurar que el directorio de trabajo actual esté en sys.path
base_dir = os.path.dirname(os.path.abspath(__file__))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from app_gui import SGSISOCApp

if __name__ == "__main__":
    app = SGSISOCApp()
    app.mainloop()
