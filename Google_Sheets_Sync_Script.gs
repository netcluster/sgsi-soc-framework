/**
 * ===================================================================
 * 🛡️ SISTEMA SGSI (ISO/IEC 27001:2022) & SOC - GOOGLE SHEETS SYNC
 * ===================================================================
 * 
 * INSTRUCCIONES DE INSTALACIÓN (Solo se hace una vez - 1 minuto):
 * 1. Abre tu hoja "SGSI" en Google Sheets (https://sheets.new).
 * 2. En el menú superior: Extensiones > Apps Script.
 * 3. Borra todo el código que aparezca y PEGA ESTE ARCHIVO COMPLETO.
 * 4. Haz clic en el icono de Guardar (Ctrl+S).
 * 5. Haz clic en "Implementar" (Deploy) > "Nueva implementación" (New deployment)
 *    (O si ya existía: "Administrar implementaciones" > Editar ✏️ > Versión: "Nueva versión").
 * 6. Tipo: "Aplicación web".
 * 7. Configura:
 *    - Descripción: SGSI SOC Cloud Sync
 *    - Ejecutar como: "Yo" (tu correo de Google)
 *    - Quién tiene acceso: "Cualquier persona" (Anyone)
 * 8. Haz clic en "Implementar", autoriza los permisos y copia la URL (termina en /exec).
 * 9. Pega la URL en la aplicación de escritorio y pulsa "Sincronizar".
 * ===================================================================
 */

function sanitizarParaCelda(valor) {
  if (valor === null || valor === undefined) return "";
  var s = String(valor);
  if (!s) return "";
  var primerCar = s.charAt(0);
  if (primerCar === '=' || primerCar === '+' || primerCar === '-' || primerCar === '@') {
    if (!isNaN(Number(s))) return valor;
    return "'" + s;
  }
  return valor;
}

function doGet(e) {
  var sheetName = "SGSI";
  try {
    sheetName = SpreadsheetApp.getActiveSpreadsheet().getName();
  } catch (err) {}

  return ContentService.createTextOutput(JSON.stringify({
    status: "ok",
    mensaje: "Servidor Google Apps Script activo para SGSI & SOC.",
    spreadsheet_name: sheetName,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      throw new Error("No se recibieron datos en la petición POST.");
    }

    var payload = JSON.parse(e.postData.contents);
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var accion = payload.accion || "subir_todo";

    if (accion === "ping") {
      return ContentService.createTextOutput(JSON.stringify({
        status: "ok",
        mensaje: "Conexión exitosa con Google Sheets.",
        spreadsheet_name: ss.getName(),
        spreadsheet_url: ss.getUrl()
      })).setMimeType(ContentService.MimeType.JSON);
    }

    var datasets = payload.datasets || payload.datos || {};
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

    // Forzar guardado inmediato en los servidores de Google
    SpreadsheetApp.flush();

    return ContentService.createTextOutput(JSON.stringify({
      status: "success",
      message: "Matrices del SGSI & SOC sincronizadas exitosamente en Google Sheets.",
      spreadsheet_name: ss.getName(),
      spreadsheet_url: ss.getUrl(),
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

  if (!rowsData || rowsData.length === 0) return;

  var headers = Object.keys(rowsData[0]);
  var values = [headers];

  for (var i = 0; i < rowsData.length; i++) {
    var row = [];
    for (var j = 0; j < headers.length; j++) {
      var val = rowsData[i][headers[j]];
      row.push(val !== undefined && val !== null ? sanitizarParaCelda(val) : "");
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
}
