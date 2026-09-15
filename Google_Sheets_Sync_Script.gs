/**
 * ===================================================================
 * 🛡️ SISTEMA SGSI (ISO/IEC 27001:2022) & SOC - GOOGLE SHEETS SYNC
 * ===================================================================
 * 
 * INSTRUCCIONES DE INSTALACIÓN (Solo se hace una vez - 1 minuto):
 * 1. Abre tu hoja "SGSI" en Google Sheets (https://sheets.new).
 * 2. En el menú superior: Extensiones > Apps Script.
 * 3. Borra todo el código que aparezca y PEGA ESTE ARCHIVO COMPLETO.
 * 4. Haz clic en "Implementar" > "Nueva implementación".
 * 5. Tipo: "Aplicación web".
 * 6. Configura:
 *    - Descripción: SGSI SOC Sync
 *    - Ejecutar como: "Yo" (tu correo de Google)
 *    - Quién tiene acceso: "Cualquier persona" (Anyone)
 * 7. Haz clic en "Implementar" y autoriza los permisos.
 * 8. COPIA LA URL DE LA APLICACIÓN WEB (termina en /exec) y pégala en la App de Windows.
 * ===================================================================
 */

function doGet(e) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  return ContentService.createTextOutput(JSON.stringify({
    status: "ok",
    service: "SGSI & SOC Google Sheets Webhook Receiver",
    spreadsheet_name: ss.getName(),
    spreadsheet_url: ss.getUrl(),
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}

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
      spreadsheet_name: ss.getName(),
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

  // Formato visual ejecutivo institucional
  var headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground("#1B365D");
  headerRange.setFontColor("#FFFFFF");
  headerRange.setFontWeight("bold");
  headerRange.setHorizontalAlignment("center");
  
  sheet.setFrozenRows(1);
  sheet.autoResizeColumns(1, headers.length);
}
