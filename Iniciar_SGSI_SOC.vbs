Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\RICARDO.ALFARO\Documents\sgsi_soc_framework"
WshShell.Run "pythonw.exe app_gui.pyw", 0, False
Set WshShell = Nothing
