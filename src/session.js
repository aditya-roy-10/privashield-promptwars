/* =====================================================================
   PRIVASHIELD — session.js. The in-memory session: document state,
      review decisions, per-entity overrides, pseudonym store, scan
      cache, element handles and toast. Nothing here is persisted.
   ===================================================================== */

import { createPseudoStore, replacementFor } from './redaction.js';

/* ---------------- report.js / app state ----------------
   Stage 3 state: scanCache memoizes the last detection run (text →
   matches) so review actions never re-scan; decisions holds manual
   review choices in memory only, keyed by type|start|end signature. */
export var state = { text:"", matches:[], activeMatches:[], sanitized:"", fileName:null, fileKind:"txt", csvMeta:null, decisions:{}, lastCsvNeutralized:0,
  mode:"FULL", categories:{ EMAIL:true, PHONE:true, IP:true, PAN:true, AADHAAR:true, CREDIT_CARD:true },
  overrides:{}, pseudoStore:createPseudoStore(), plan:{}, redactedCount:0,
  preset:"general", leak:null, exposure:null };

export function sigOf(m){ return m.type + "|" + m.start + "|" + m.end; }

/* Effective mode for one detection: a per-entity override wins over
   the global mode; "KEEP" (or an EXCLUDED review decision, or a
   category switched off) means the value stays visible. */
export function effectiveMode(m){
  var ovr = state.overrides[sigOf(m)];
  if (ovr) return ovr;
  return state.mode;
}

export function isKeptVisible(m){
  if (m.userDecision === "EXCLUDED") return true;
  if (!state.categories[m.type]) return true;
  if (effectiveMode(m) === "KEEP") return true;
  return false;
}

export function planReplacement(m){
  if (isKeptVisible(m)) return null;
  return replacementFor(m, effectiveMode(m), state.pseudoStore);
}

export var $ = function(id){ return document.getElementById(id); };

export const els = {};
export function bindElements(){
  els.input = $("inputText");
  els.highlight = $("highlightView");
  els.sanitized = $("sanitizedView");
  els.findings = $("findingsBody");
  els.toast = $("toast");
}

export var toastTimer = null;

export function toast(msg, isErr){
  if (!els.toast) return; /* no DOM yet (Node/test context) — silent no-op */
  els.toast.textContent = msg;
  els.toast.className = isErr ? "show err" : "show";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function(){ els.toast.className = ""; }, 3200);
  /* Stage 5: mirror action feedback into the export panel's status
     line so confirmations persist after the toast fades. */
  var es = $("exportStatus");
  if (es && !isErr && (msg.indexOf("downloaded") !== -1 || msg.indexOf("copied") !== -1)) es.textContent = msg;
}

/* ---------------- scan pipeline (Stage 3 performance) ----------------
   - Live detection is debounced (see wiring, 250 ms).
   - Results are memoized per exact input text: approve/exclude clicks
     re-render from the cache instead of re-running every detector.
   - Inputs ≥ 20,000 chars are scanned in a Web Worker built from this
     page's own engine modules (validators + detectors + context +
     engine, sliced out of the script text), so typing never freezes
     the UI. Any worker failure falls back to a synchronous scan. */
export var scanCache = { text:null, matches:[] };
