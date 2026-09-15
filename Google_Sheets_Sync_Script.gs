/**
 * SGSI (ISO/IEC 27001:2022) & SOC Framework - Google Sheets Synchronization Script
 * 
 * Instrucciones de uso rápido:
 * 1. Crea una hoja de cálculo nueva en Google Sheets (https://sheets.new).
 * 2. En el menú superior, ve a: Extensiones > Apps Script.
 * 3. Borra todo el código existente y pega este archivo completo.
 * 4. Haz clic en "Implementar" (Deploy) > "Nueva implementación" (New deployment).
 * 5. Selecciona Tipo: "Aplicación web" (Web App).
 * 6. Configura:
 *    - Ejecutar como: "Yo" (Tu cuenta de Google).
 *    - Quién tiene acceso: "Cualquiera" (Anyone).
 * 7. Haz clic en "Implementar", autoriza los permisos y copia la URL de la aplicación web.
 * 8. Pega la URL en la aplicación de escritorio SGSI & SOC (Botón 'Sincronizar Google Sheets').
 */

function doPost(e) {
  try {
    var contents = JSON.parse(e.postData.contents);
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    
    var datasets = contents.datasets || {};
    var syncedTabs = [];

    for (var sheetName in datasets) {
      if (datasets.hasOwnProperty(sheetName)) {
        var rows = datasets[sheetName];
        if (rows && rows.length > 0) {
          updateSheetData(ss, sheetName, rows);
          syncedTabs.push(sheetName);
        }
      }
    }

    return ContentService.createTextOutput(JSON.stringify({
      status: "success",
      message: "Sincronización completada exitosamente.",
      synced_sheets: syncedTabs,
      timestamp: new Date().toISOString()
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    service: "SGSI & SOC Google Sheets Webhook Receiver",
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}

function updateSheetData(ss, sheetName, rowsData) {
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
  } else {
    sheet.clear();
  }

  if (rowsData.length === 0) return;

  var headers = Object.keys(rowsData[0]);
  var values = [headers];

  for (var i = 0; i < rowsData.length; i++) {
    var row = [];
    for (var j = 0; j < headers.length; j++) {
      var val = rowsData[i][headers[j]];
      row.push(val !== undefined && val !== null ? val : "");
    }
    values.push(row);
  }

  var range = sheet.getRange(1, 1, values.length, headers.length);
  range.setValues(values);

  // Formato visual profesional
  var headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground("#1B365D");
  headerRange.setFontColor("#FFFFFF");
  headerRange.setFontWeight("bold");
  headerRange.setHorizontalAlignment("center");
  
  sheet.setFrozenRows(1);
  sheet.autoResizeColumns(1, headers.length);
}
