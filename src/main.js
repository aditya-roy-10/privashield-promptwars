/* =====================================================================
   PRIVASHIELD — main.js. App bootstrap: scan pipeline, Web Worker
      orchestration, mode/category controls, locate/sync-scroll, and
      workspace event wiring. Entry point for Vite.
   ===================================================================== */

import { SAMPLE_TEXT, PROMPT_LOG_MD, DEMO_SAMPLES } from './sampleData.js';
import { TYPE_META } from './detectors.js';
import { detectAll, engineStats, freshEngineStats, setEngineStats, setLuhnRejected } from './engine.js';
import { state, sigOf, $, els, bindElements, toast, scanCache, restartFlash } from './session.js';
import { applyDecisions, reviewAction } from './review.js';
import { markPresetCustom, applyPreset, renderAdvanced, resolveLeak, hideExportGuard, pendingExport, SENSITIVITY } from './advanced.js';
import { downloadReport } from './report.js';
import { setScanHandler, downloadBlob, loadText, handleFile, clearSession, downloadSanitized, downloadAs, copySanitized } from './files.js';
import { WORKER_THRESHOLD, createEngineWorker } from './perf.js';
import { render } from './render.js';
import { initRouter } from './router.js';
import { runTests } from './tests.js';

const DEBOUNCE_DELAY_MS = 250;
const MODE_BUTTON_IDS = { FULL: 'modeFull', PARTIAL: 'modePartial', PSEUDO: 'modePseudo' };

let workerObj = null;
let workerReq = 0;
let workerPendingText = null;
let workerFailed = false;
let debounce = null;
let syncOn = true;
let syncGuard = false;

function runSynchronousFallback() {
  ++workerReq;
  workerPendingText = null;
  const t = els.input.value;
  scanCache.text = t;
  if (!t) {
    scanCache.matches = [];
    setEngineStats(freshEngineStats());
    setLuhnRejected(0);
  } else {
    scanCache.matches = detectAll(t);
  }
  finishProcess();
}

function getWorker() {
  if (workerObj || workerFailed) return workerObj;
  workerObj = createEngineWorker();
  if (!workerObj) {
    workerFailed = true;
    return null;
  }
  workerObj.onmessage = (e) => {
    if (!e.data || e.data.id !== workerReq) return;
    if (e.data.error) {
      console.warn('PRIVASHIELD worker scan error; falling back to main thread:', e.data.error);
      workerFailed = true;
      workerObj = null;
      runSynchronousFallback();
      return;
    }
    const doneText = workerPendingText;
    workerPendingText = null;
    setEngineStats(e.data.stats);
    setLuhnRejected(engineStats.rejectedLuhn);
    scanCache.text = doneText;
    scanCache.matches = e.data.matches;
    if (els.input.value === doneText) finishProcess();
    else process();
  };
  workerObj.onerror = (err) => {
    console.warn('PRIVASHIELD Web Worker error; falling back to synchronous scan:', err?.message || err);
    workerFailed = true;
    workerObj = null;
    runSynchronousFallback();
  };
  return workerObj;
}

export function process() {
  clearTimeout(debounce);
  const text = els.input.value;
  state.text = text;
  if (text === scanCache.text) {
    ++workerReq;
    workerPendingText = null;
    finishProcess();
    return;
  }
  if (!text) {
    ++workerReq;
    workerPendingText = null;
    scanCache.text = text;
    scanCache.matches = [];
    setEngineStats(freshEngineStats());
    setLuhnRejected(0);
    finishProcess();
    return;
  }
  if (text.length >= WORKER_THRESHOLD && window.Worker) {
    const w = getWorker();
    if (w) {
      workerPendingText = text;
      const id = ++workerReq;
      $('procStatus').innerHTML = `<span class="dot"></span> SCANNING — large input (${text.length.toLocaleString()} chars) in background Web Worker`;
      w.postMessage({ id, text });
      return;
    }
  }
  ++workerReq;
  workerPendingText = null;
  scanCache.text = text;
  scanCache.matches = detectAll(text);
  finishProcess();
}

function finishProcess() {
  state.matches = scanCache.matches;
  applyDecisions();
  render();
}

function setMode(mode) {
  state.mode = mode;
  markPresetCustom();
  Object.entries(MODE_BUTTON_IDS).forEach(([k, btnId]) => {
    const btn = $(btnId);
    if (btn) btn.classList.toggle('active', state.mode === k);
  });
  applyDecisions();
  render();
  toast(
    mode === 'FULL'
      ? 'Full Mask — every approved value becomes [REDACTED].'
      : mode === 'PARTIAL'
        ? 'Partial Mask — verification fragments remain visible. Treat the output as still sensitive.'
        : 'Pseudonymization — repeated values share one stable alias for this document session.'
  );
}

function toggleCategory(type) {
  state.categories[type] = !state.categories[type];
  markPresetCustom();
  const chip = document.querySelector(`.cat-chip[data-cat="${type}"]`);
  if (chip) chip.classList.toggle('off', !state.categories[type]);
  applyDecisions();
  render();
  toast(
    `${TYPE_META[type].label}${state.categories[type] ? ' redaction ON.' : ' redaction OFF — those values stay visible in the output.'}`,
    !state.categories[type]
  );
}

function setOverride(id, mode) {
  const m = state.matches.find((x) => x.id === id);
  if (!m) return;
  const sig = sigOf(m);
  if (!mode) delete state.overrides[sig];
  else state.overrides[sig] = mode;
  applyDecisions();
  render();
  toast(mode ? `${id} override: ${mode} for this occurrence only.` : `${id} override cleared — global mode applies.`);
}

function syncScrollFrom(src) {
  const gSrc = src === els.highlight ? $('gutterOrig') : $('gutterSan');
  gSrc.scrollTop = src.scrollTop;
  if (!syncOn || syncGuard) return;
  const dst = src === els.highlight ? els.sanitized : els.highlight;
  const gDst = dst === els.highlight ? $('gutterOrig') : $('gutterSan');
  const maxSrc = src.scrollHeight - src.clientHeight;
  const maxDst = dst.scrollHeight - dst.clientHeight;
  const ratio = maxSrc > 0 ? src.scrollTop / maxSrc : 0;
  syncGuard = true;
  dst.scrollTop = ratio * maxDst;
  gDst.scrollTop = dst.scrollTop;
  syncGuard = false;
}

function locateMatch(m) {
  if (!m) return;
  const mark = els.highlight.querySelector(`mark[data-start="${m.start}"]`);
  if (!mark) {
    toast('That occurrence is not in the current view.', true);
    return;
  }
  const r = mark.getBoundingClientRect();
  const pr = els.highlight.getBoundingClientRect();
  els.highlight.scrollTop += (r.top - pr.top) - els.highlight.clientHeight / 2 + r.height / 2;
  syncScrollFrom(els.highlight);
  restartFlash(mark, 'flash');
  els.highlight.scrollIntoView({ block: 'center' });
}

function locateDetection(id) {
  const m = state.matches.find((x) => x.id === id) || null;
  locateMatch(m);
}

function locateType(type) {
  const m = state.matches.find((x) => x.type === type) || null;
  if (!m) {
    toast(`No ${TYPE_META[type].label} detections in the current document.`);
    return;
  }
  locateMatch(m);
}

/* ---------------- Bootstrap & Event Wiring ---------------- */
bindElements();
setScanHandler(process);

els.input.addEventListener('input', () => {
  clearTimeout(debounce);
  debounce = setTimeout(process, DEBOUNCE_DELAY_MS);
});

els.findings.addEventListener('click', (e) => {
  const loc = e.target?.closest?.('button[data-locate]');
  if (loc) {
    locateDetection(loc.getAttribute('data-locate'));
    return;
  }
  const btn = e.target?.closest?.('button[data-act]');
  if (!btn) return;
  reviewAction(btn.getAttribute('data-id'), btn.getAttribute('data-act'), render);
});

els.findings.addEventListener('change', (e) => {
  const sel = e.target?.getAttribute?.('data-ovr') ? e.target : null;
  if (!sel) return;
  setOverride(sel.getAttribute('data-ovr'), sel.value || null);
});

Object.values(MODE_BUTTON_IDS).forEach((id) => {
  $(id).addEventListener('click', function () {
    setMode(this.getAttribute('data-mode'));
  });
});

document.querySelectorAll('.cat-chip').forEach((chip) => {
  chip.addEventListener('click', function () {
    toggleCategory(this.getAttribute('data-cat'));
  });
});

$('btnSample').addEventListener('click', () => loadText(SAMPLE_TEXT, null, 'txt'));
$('btnUpload').addEventListener('click', () => $('fileInput').click());
$('fileInput').addEventListener('change', (e) => handleFile(e.target.files[0]));
$('fileChipClear').addEventListener('click', () => clearSession());

$('btnDownload').addEventListener('click', () => downloadSanitized());
$('btnDownload2').addEventListener('click', () => downloadSanitized());
$('btnCopy').addEventListener('click', copySanitized);
$('btnCopy2').addEventListener('click', copySanitized);
$('btnCopy3').addEventListener('click', copySanitized);
$('btnExportTxt').addEventListener('click', () => downloadAs('txt'));
$('btnExportCsv').addEventListener('click', () => downloadAs('csv'));
$('btnExportCopy').addEventListener('click', copySanitized);
$('btnClear').addEventListener('click', () => clearSession());
$('btnClear2').addEventListener('click', () => clearSession());

$('btnRunTests').addEventListener('click', () => {
  const r = runTests();
  toast(r.fail ? `Test suite: ${r.pass} passed, ${r.fail} FAILED` : `Test suite: all ${r.pass} fixtures passed`, !!r.fail);
});

$('btnLogDownload').addEventListener('click', () => {
  if (downloadBlob(PROMPT_LOG_MD, 'PROMPT_LOG.md', 'text/markdown')) {
    toast('PROMPT_LOG.md downloaded.');
  }
});

const dropWrap = $('dropWrap');
['dragenter', 'dragover'].forEach((ev) => {
  dropWrap.addEventListener(ev, (e) => {
    e.preventDefault();
    dropWrap.classList.add('dragging');
  });
});
['dragleave', 'drop'].forEach((ev) => {
  dropWrap.addEventListener(ev, (e) => {
    e.preventDefault();
    if (ev === 'dragleave' && dropWrap.contains(e.relatedTarget)) return;
    dropWrap.classList.remove('dragging');
  });
});
dropWrap.addEventListener('drop', (e) => {
  const f = e.dataTransfer?.files?.[0];
  if (f) handleFile(f);
});
['dragover', 'drop'].forEach((ev) => {
  window.addEventListener(ev, (e) => e.preventDefault());
});

$('btnTheme').addEventListener('click', function () {
  const light = document.documentElement.getAttribute('data-theme') !== 'light';
  if (light) document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  this.setAttribute('aria-pressed', light ? 'true' : 'false');
  $('themeLabel').textContent = light ? 'Light' : 'Dark';
  $('themeIconSun').style.display = light ? 'none' : '';
  $('themeIconMoon').style.display = light ? '' : 'none';
  toast(light ? 'Light theme on — kept for this session only, nothing is stored.' : 'Dark theme on.');
});

$('btnPrivacy').addEventListener('click', function () {
  const open = $('privacyPanel').classList.toggle('show');
  this.setAttribute('aria-expanded', open ? 'true' : 'false');
});

document.querySelectorAll('.ent[data-enttype]').forEach((card) => {
  card.addEventListener('click', function () {
    locateType(this.getAttribute('data-enttype'));
  });
});

[els.highlight, els.sanitized].forEach((p) => {
  p.addEventListener('scroll', () => syncScrollFrom(p));
});

$('btnSync').addEventListener('click', function () {
  syncOn = !syncOn;
  this.setAttribute('aria-pressed', syncOn ? 'true' : 'false');
  toast(syncOn ? 'Synchronized scrolling on — both panes move together.' : 'Synchronized scrolling off — panes scroll independently.');
});

$('btnExpand').addEventListener('click', function () {
  const expanded = $('diffGrid').classList.toggle('expanded');
  this.setAttribute('aria-pressed', expanded ? 'true' : 'false');
  this.lastChild.textContent = expanded ? ' Collapse ' : ' Expand ';
  toast(expanded ? 'Comparison workspace expanded.' : 'Comparison workspace restored.');
});

document.querySelectorAll('.preset-btn').forEach((b) => {
  b.addEventListener('click', function () {
    applyPreset(this.getAttribute('data-preset'), setMode);
  });
});

document.querySelectorAll('[data-demo]').forEach((b) => {
  b.addEventListener('click', function () {
    const key = this.getAttribute('data-demo');
    if (DEMO_SAMPLES[key]) {
      loadText(DEMO_SAMPLES[key], null, 'txt');
      toast('Synthetic demo loaded — every value in it is fictional.');
    }
  });
});

$('weightsGrid').addEventListener('change', (e) => {
  const inp = e.target?.getAttribute?.('data-weight') ? e.target : null;
  if (!inp) return;
  const t = inp.getAttribute('data-weight');
  let v = parseFloat(inp.value);
  if (Number.isNaN(v) || v < 0) v = 0;
  if (v > 50) v = 50;
  inp.value = v;
  SENSITIVITY[t] = v;
  renderAdvanced();
  toast(`Sensitivity weight for ${TYPE_META[t].label} set to ${v} — exposure scores recomputed.`);
});

$('leakList').addEventListener('click', (e) => {
  const btn = e.target?.closest?.('button[data-leak-resolve]');
  if (btn) resolveLeak(parseInt(btn.getAttribute('data-leak-resolve'), 10));
});

$('btnGuardReview').addEventListener('click', () => {
  hideExportGuard();
  const sec = document.querySelector('[aria-label="Leak Guard and privacy exposure score"]');
  if (sec) {
    sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    restartFlash(sec);
  }
});

$('btnGuardProceed').addEventListener('click', () => {
  const k = pendingExport;
  hideExportGuard();
  if (k === 'csv' || k === 'txt') downloadAs(k, true);
  else downloadSanitized(true);
});

$('btnGuardCancel').addEventListener('click', () => {
  hideExportGuard();
  toast('Export cancelled — nothing was downloaded.');
});

$('btnReportTxt').addEventListener('click', () => downloadReport('txt'));
$('btnReportJson').addEventListener('click', () => downloadReport('json'));

initRouter({ onDemoLoad: () => loadText(SAMPLE_TEXT, null, 'txt') });
process();
runTests();
