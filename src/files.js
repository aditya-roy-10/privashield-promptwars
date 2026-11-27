/* =====================================================================
   PRIVASHIELD — files.js. FileReader upload, Papa Parse CSV
      (per-cell redaction, formula-injection warning), Blob download.
      Note: files.js imports the scan entry point `process` from
      main.js — a runtime-only circular import (both sides use each
      other only inside event handlers / function bodies, never during
      module evaluation), which ES modules handle safely.
   ===================================================================== */

import Papa from 'papaparse';
import { isFormulaCell } from './sanitizer.js';
import { detect } from './engine.js';
import { applyRedactions, replacementFor } from './redaction.js';
import { state, sigOf, $, els, toast, scanCache } from './session.js';
import { guardExport } from './advanced.js';
import { process } from './main.js';

export function setFileChip(name){
  if (name){ $("fileChipName").textContent = name; $("fileChip").classList.add("show"); }
  else { $("fileChip").classList.remove("show"); }
}

export function loadText(text, name, kind){
  els.input.value = text;
  state.fileName = name || null;
  state.fileKind = kind || "txt";
  state.csvMeta = null;
  state.decisions = {}; /* review choices belong to the previous document */
  state.overrides = {}; /* per-entity mode overrides belong to it too */
  state.pseudoStore.reset(); /* new document loaded — pseudonym mapping resets (Stage 4 requirement) */
  $("statCsv").style.display = "none";
  $("csvWarn").classList.remove("show");
  if (kind === "csv" && Papa){
    var parsed = Papa.parse(text, { skipEmptyLines:true });
    var cellsWithPii = 0, formulaCells = 0;
    parsed.data.forEach(function(row){
      row.forEach(function(cell){
        var cs = String(cell == null ? "" : cell);
        if (detect(cs).length) cellsWithPii++;
        if (isFormulaCell(cs)) formulaCells++;
      });
    });
    state.csvMeta = { rows: parsed.data.length, cols: parsed.data[0] ? parsed.data[0].length : 0, cellsWithPii: cellsWithPii, formulaCells: formulaCells };
    $("statCsv").style.display = "";
    $("statCsv").textContent = "CSV · " + state.csvMeta.rows + " rows × " + state.csvMeta.cols + " cols · " + cellsWithPii + " cell(s) contain PII (Papa Parse)";
    if (formulaCells){
      $("csvWarnText").innerHTML = "<strong>Spreadsheet formula risk — " + formulaCells + " cell(s).</strong> Cells beginning with =, +, − or @ can execute as formulas when this file is opened in a spreadsheet app. The exported CSV prefixes any such cell with a leading apostrophe so it opens as inert text.";
      $("csvWarn").classList.add("show");
    }
  }
  setFileChip(name);
  process();
  toast(name ? ("Loaded " + name + " — processed locally") : "Sample data loaded — processed locally");
}

export function handleFile(file){
  if (!file) return;
  var lower = file.name.toLowerCase();
  var isCsv = lower.endsWith(".csv");
  var isTxt = lower.endsWith(".txt") || file.type === "text/plain" || file.type === "text/csv";
  if (!isCsv && !isTxt){ toast("Only .txt and .csv files are supported.", true); return; }
  if (file.size > 10 * 1024 * 1024){ toast("File is larger than 10 MB — too big for in-browser Stage 1 processing.", true); return; }
  var reader = new FileReader();
  reader.onload = function(){ loadText(String(reader.result || ""), file.name, isCsv ? "csv" : "txt"); };
  reader.onerror = function(){ toast("Could not read that file.", true); };
  reader.readAsText(file);
}

export function buildDownloadContent(){
  if (state.fileKind === "csv" && Papa && state.csvMeta){
    /* Per-cell redaction: headers, row/column order, quoted commas and
       multiline quoted values survive because Papa Parse owns the
       structure end to end. The Stage 4 plan is honoured by
       type+normalized value, since cell-local offsets differ from the
       whole-document scan: exclusions, switched-off categories, KEEP
       overrides and per-value mode overrides all carry into the
       export, and pseudonym aliases come from the shared document
       store — so a value repeated across rows keeps ONE alias and
       cross-row relationships survive. The mapping itself is never
       written into the file. */
    var excludedVals = {}, overrideByVal = {};
    state.matches.forEach(function(m){
      var key = m.type + "|" + m.normalized;
      if (m.userDecision === "EXCLUDED") excludedVals[key] = true;
      var ovr = state.overrides[sigOf(m)];
      if (ovr && !overrideByVal[key]) overrideByVal[key] = ovr;
    });
    var neutralized = 0;
    var parsed = Papa.parse(state.text, { skipEmptyLines:false });
    var outRows = parsed.data.map(function(row){
      return row.map(function(cell){
        var cellStr = String(cell == null ? "" : cell);
        var cellMatches = detect(cellStr);
        var out = applyRedactions(cellStr, cellMatches, function(x){
          var key = x.type + "|" + x.normalized;
          if (excludedVals[key]) return null;
          if (!state.categories[x.type]) return null;
          var mode = overrideByVal[key] || state.mode;
          if (mode === "KEEP") return null;
          return replacementFor(x, mode, state.pseudoStore);
        });
        if (isFormulaCell(out)){ out = "'" + out; neutralized++; }
        return out;
      });
    });
    state.lastCsvNeutralized = neutralized;
    return { content: Papa.unparse(outRows), mime:"text/csv", ext:"csv" };
  }
  state.lastCsvNeutralized = 0;
  return { content: state.sanitized, mime:"text/plain", ext:"txt" };
}

export function doDownload(d){
  var base = state.fileName ? state.fileName.replace(/\.(txt|csv)$/i, "") : "privashield-output";
  var blob = new Blob([d.content], { type: d.mime + ";charset=utf-8" });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url; a.download = base + ".sanitized." + d.ext;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1500);
  var extra = state.lastCsvNeutralized ? " · " + state.lastCsvNeutralized + " formula cell(s) neutralized" : "";
  var keptDl = state.matches.length - state.redactedCount;
  toast("Sanitized ." + d.ext + " downloaded — " + state.redactedCount + " value(s) redacted (" + state.mode + " mode)" + (keptDl ? ", " + keptDl + " value(s) left visible" : "") + extra + ". Pseudonym mapping was not exported.");
}

export function downloadSanitized(skipGuard){
  if (!state.text){ toast("Nothing to download yet — add some input first.", true); return; }
  if (!skipGuard && !guardExport("auto")) return; /* Stage 6: Leak Guard warning before export */
  doDownload(buildDownloadContent());
}

/* Stage 5 export panel: explicit format choice. TXT always exports
   the sanitized document as-is; CSV uses the per-cell pipeline for
   CSV input, and wraps plain-text input as a single quoted
   "sanitized_text" column so the format choice always works. */
export function downloadAs(kind, skipGuard){
  if (!state.text){ toast("Nothing to download yet — add some input first.", true); return; }
  if (!skipGuard && !guardExport(kind)) return; /* Stage 6: Leak Guard warning before export */
  if (kind === "csv"){
    if (state.fileKind === "csv" && Papa && state.csvMeta){ doDownload(buildDownloadContent()); return; }
    if (!Papa){ toast("CSV export unavailable — the bundled CSV parser failed to initialise.", true); return; }
    var cell = state.sanitized;
    state.lastCsvNeutralized = 0;
    if (isFormulaCell(cell)){ cell = "'" + cell; state.lastCsvNeutralized = 1; }
    doDownload({ content: Papa.unparse([["sanitized_text"], [cell]]), mime:"text/csv", ext:"csv" });
    return;
  }
  state.lastCsvNeutralized = 0;
  doDownload({ content: state.sanitized, mime:"text/plain", ext:"txt" });
}

export function copySanitized(){
  if (!state.text){ toast("Nothing to copy yet.", true); return; }
  var txt = state.sanitized;
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(function(){ toast("Sanitized text copied to clipboard."); }, function(){ fallbackCopy(txt); });
  } else fallbackCopy(txt);
}

export function fallbackCopy(txt){
  var ta = document.createElement("textarea");
  ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); toast("Sanitized text copied to clipboard."); }
  catch(e){ toast("Copy failed — select the sanitized panel text manually.", true); }
  ta.remove();
}

export function clearSession(){
  els.input.value = "";
  state.fileName = null; state.fileKind = "txt"; state.csvMeta = null;
  state.decisions = {};
  state.overrides = {};
  state.pseudoStore.reset(); /* session cleared — pseudonym mapping wiped with everything else */
  scanCache.text = null; scanCache.matches = [];
  $("fileInput").value = "";
  $("statCsv").style.display = "none";
  $("csvWarn").classList.remove("show");
  setFileChip(null);
  process();
  toast("Session cleared — all in-memory data wiped.");
  els.input.focus();
}
