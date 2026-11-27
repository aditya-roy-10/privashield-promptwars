/* =====================================================================
   PRIVASHIELD — files.js. FileReader upload, Papa Parse CSV
      (per-cell redaction, formula-injection warning), Blob download.
      Uses setScanHandler() / optional callback instead of importing
      main.js directly, keeping dependencies strictly acyclic.
   ===================================================================== */

import Papa from 'papaparse';
import { isFormulaCell } from './sanitizer.js';
import { detect } from './engine.js';
import { applyRedactions, replacementFor } from './redaction.js';
import { state, sigOf, $, els, toast, scanCache } from './session.js';
import { guardExport } from './advanced.js';

export const MAX_FILE_BYTES = 10 * 1024 * 1024;
const BLOB_REVOKE_DELAY_MS = 1500;

let scanHandler = () => {};

/** Register the application scan callback (called by main.js on bootstrap). */
export function setScanHandler(fn) {
  scanHandler = typeof fn === 'function' ? fn : () => {};
}

/** Trigger a client-side Blob download without touching any server. */
export function downloadBlob(content, filename, mime) {
  try {
    const blob = new Blob([content], { type: `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), BLOB_REVOKE_DELAY_MS);
    return true;
  } catch (err) {
    console.error('PRIVASHIELD download failed:', err);
    toast('Download failed — your browser blocked local file creation.', true);
    return false;
  }
}

export function setFileChip(name) {
  if (name) {
    $('fileChipName').textContent = name;
    $('fileChip').classList.add('show');
  } else {
    $('fileChip').classList.remove('show');
  }
}

/** Load document text into the workspace, reset per-document state, and trigger scanning. */
export function loadText(text, name, kind, onScan) {
  els.input.value = text;
  state.fileName = name || null;
  state.fileKind = kind || 'txt';
  state.csvMeta = null;
  state.decisions = {};
  state.overrides = {};
  state.pseudoStore.reset();
  $('statCsv').style.display = 'none';
  $('csvWarn').classList.remove('show');

  if (kind === 'csv') {
    const parsed = Papa.parse(text, { skipEmptyLines: true });
    let cellsWithPii = 0;
    let formulaCells = 0;
    parsed.data.forEach((row) => {
      row.forEach((cell) => {
        const cs = String(cell == null ? '' : cell);
        if (detect(cs).length) cellsWithPii++;
        if (isFormulaCell(cs)) formulaCells++;
      });
    });
    state.csvMeta = {
      rows: parsed.data.length,
      cols: parsed.data[0] ? parsed.data[0].length : 0,
      cellsWithPii,
      formulaCells
    };
    $('statCsv').style.display = '';
    $('statCsv').textContent = `CSV · ${state.csvMeta.rows} rows × ${state.csvMeta.cols} cols · ${cellsWithPii} cell(s) contain PII (Papa Parse)`;
    if (formulaCells) {
      $('csvWarnText').innerHTML = `<strong>Spreadsheet formula risk — ${formulaCells} cell(s).</strong> Cells beginning with =, +, − or @ can execute as formulas when this file is opened in a spreadsheet app. The exported CSV prefixes any such cell with a leading apostrophe so it opens as inert text.`;
      $('csvWarn').classList.add('show');
    }
  }

  setFileChip(name);
  (typeof onScan === 'function' ? onScan : scanHandler)();
  toast(name ? `Loaded ${name} — processed locally` : 'Sample data loaded — processed locally');
}

export function handleFile(file, onScan) {
  if (!file) return;
  const lower = file.name.toLowerCase();
  const isCsv = lower.endsWith('.csv');
  const isTxt = lower.endsWith('.txt') || file.type === 'text/plain' || file.type === 'text/csv';
  if (!isCsv && !isTxt) {
    toast('Only .txt and .csv files are supported.', true);
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    toast('File is larger than 10 MB — too big for safe in-browser processing.', true);
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    loadText(String(reader.result || ''), file.name, isCsv ? 'csv' : 'txt', onScan);
  };
  reader.onerror = () => {
    const detail = reader.error?.message ? ` (${reader.error.message})` : '';
    toast(`Could not read that file${detail}.`, true);
  };
  reader.readAsText(file);
}

export function buildDownloadContent() {
  if (state.fileKind === 'csv' && state.csvMeta) {
    const excludedVals = {};
    const overrideByVal = {};
    state.matches.forEach((m) => {
      const key = `${m.type}|${m.normalized}`;
      if (m.userDecision === 'EXCLUDED') excludedVals[key] = true;
      const ovr = state.overrides[sigOf(m)];
      if (ovr && !overrideByVal[key]) overrideByVal[key] = ovr;
    });
    let neutralized = 0;
    const parsed = Papa.parse(state.text, { skipEmptyLines: false });
    const outRows = parsed.data.map((row) => row.map((cell) => {
      const cellStr = String(cell == null ? '' : cell);
      const cellMatches = detect(cellStr);
      let out = applyRedactions(cellStr, cellMatches, (x) => {
        const key = `${x.type}|${x.normalized}`;
        if (excludedVals[key]) return null;
        if (!state.categories[x.type]) return null;
        const mode = overrideByVal[key] || state.mode;
        if (mode === 'KEEP') return null;
        return replacementFor(x, mode, state.pseudoStore);
      });
      if (isFormulaCell(out)) {
        out = `'${out}`;
        neutralized++;
      }
      return out;
    }));
    state.lastCsvNeutralized = neutralized;
    return { content: Papa.unparse(outRows), mime: 'text/csv', ext: 'csv' };
  }
  state.lastCsvNeutralized = 0;
  return { content: state.sanitized, mime: 'text/plain', ext: 'txt' };
}

export function doDownload(d) {
  const base = state.fileName ? state.fileName.replace(/\.(txt|csv)$/i, '') : 'privashield-output';
  if (!downloadBlob(d.content, `${base}.sanitized.${d.ext}`, d.mime)) return;
  const extra = state.lastCsvNeutralized ? ` · ${state.lastCsvNeutralized} formula cell(s) neutralized` : '';
  const keptDl = state.matches.length - state.redactedCount;
  toast(`Sanitized .${d.ext} downloaded — ${state.redactedCount} value(s) redacted (${state.mode} mode)${keptDl ? `, ${keptDl} value(s) left visible` : ''}${extra}. Pseudonym mapping was not exported.`);
}

export function downloadSanitized(skipGuard) {
  if (!state.text) {
    toast('Nothing to download yet — add some input first.', true);
    return;
  }
  if (!skipGuard && !guardExport('auto')) return;
  doDownload(buildDownloadContent());
}

export function downloadAs(kind, skipGuard) {
  if (!state.text) {
    toast('Nothing to download yet — add some input first.', true);
    return;
  }
  if (!skipGuard && !guardExport(kind)) return;
  if (kind === 'csv') {
    if (state.fileKind === 'csv' && state.csvMeta) {
      doDownload(buildDownloadContent());
      return;
    }
    let cell = state.sanitized;
    state.lastCsvNeutralized = 0;
    if (isFormulaCell(cell)) {
      cell = `'${cell}`;
      state.lastCsvNeutralized = 1;
    }
    doDownload({ content: Papa.unparse([['sanitized_text'], [cell]]), mime: 'text/csv', ext: 'csv' });
    return;
  }
  state.lastCsvNeutralized = 0;
  doDownload({ content: state.sanitized, mime: 'text/plain', ext: 'txt' });
}

export function copySanitized() {
  if (!state.text) {
    toast('Nothing to copy yet.', true);
    return;
  }
  const txt = state.sanitized;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(
      () => toast('Sanitized text copied to clipboard.'),
      () => fallbackCopy(txt)
    );
  } else {
    fallbackCopy(txt);
  }
}

export function fallbackCopy(txt) {
  const ta = document.createElement('textarea');
  ta.value = txt;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    const ok = document.execCommand('copy');
    if (ok) toast('Sanitized text copied to clipboard.');
    else toast('Copy failed — select the sanitized panel text manually.', true);
  } catch (err) {
    console.warn('PRIVASHIELD clipboard fallback failed:', err);
    toast('Copy failed — select the sanitized panel text manually.', true);
  } finally {
    ta.remove();
  }
}

export function clearSession(onScan) {
  els.input.value = '';
  state.fileName = null;
  state.fileKind = 'txt';
  state.csvMeta = null;
  state.decisions = {};
  state.overrides = {};
  state.pseudoStore.reset();
  scanCache.text = null;
  scanCache.matches = [];
  $('fileInput').value = '';
  $('statCsv').style.display = 'none';
  $('csvWarn').classList.remove('show');
  setFileChip(null);
  (typeof onScan === 'function' ? onScan : scanHandler)();
  toast('Session cleared — all in-memory data wiped.');
  els.input.focus();
}
