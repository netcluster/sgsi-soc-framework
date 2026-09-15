/**
 * GOOGLE APPS SCRIPT: Sincronizador Automático de SGSI y SOC
 * -------------------------------------------------------------
 * Este script es 100% GRATUITO y se ejecuta dentro de Google Sheets.
 * Te permite importar automáticamente los archivos CSV sincronizados en Google Drive
 * hacia las hojas de cálculo correspondientes sin necesidad de Google Cloud Platform (GCP).
 * 
 * INSTRUCCIONES DE INSTALACIÓN:
 * 1. En tu Google Sheets maestro, ve a: Extensiones > Apps Script.
 * 2. Borra el código existente y pega este archivo completo.
 * 3. Modifica la variable FOLDER_NAME si tu carpeta en Google Drive tiene otro nombre.
 * 4. Guarda y haz clic en "Ejecutar" > "importarTodosLosCSVs".
 * 5. (Opcional) Crea un Activador (Reloj) para que se ejecute automáticamente cada 15 minutos.
 */

const FOLDER_NAME = "sync_drive"; // Nombre de la carpeta en tu Google Drive donde subes los CSVs

const MAPPING = {
  "01_inventario_activos.csv": "01_Inventario_Activos",
  "02_matriz_riesgos.csv": "02_Matriz_Riesgos",
  "03_soa_iso27001.csv": "03_SoA_ISO27001",
  "04_registro_incidentes.csv": "04_Registro_Incidentes"
};

function importarTodosLosCSVs() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const folders = DriveApp.getFoldersByName(FOLDER_NAME);
  
  if (!folders.hasNext()) {
    Logger.log("No se encontró la carpeta '" + FOLDER_NAME + "' en tu Google Drive.");
    return;
  }
  
  const folder = folders.next();
  
  for (const [csvFile, sheetName] of Object.entries(MAPPING)) {
    const files = folder.getFilesByName(csvFile);
    if (files.hasNext()) {
      const file = files.next();
      const csvData = Utilities.parseCsv(file.getBlob().getDataAsString("UTF-8"));
      
      let sheet = ss.getSheetByName(sheetName);
      if (!sheet) {
        sheet = ss.insertSheet(sheetName);
      }
      
      sheet.clear();
      if (csvData.length > 0) {
        sheet.getRange(1, 1, csvData.length, csvData[0].length).setValues(csvData);
        Logger.log("Hoja '" + sheetName + "' actualizada con éxito desde " + csvFile);
      }
    } else {
      Logger.log("Archivo no encontrado en Drive: " + csvFile);
    }
  }
}

/**
 * Menú personalizado al abrir la hoja de cálculo
 */
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu("🛡️ SGSI & SOC Sync")
    .addItem("🔄 Sincronizar Datos desde Google Drive", "importarTodosLosCSVs")
    .addToUi();
}
