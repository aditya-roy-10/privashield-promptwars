/* =====================================================================
   PRIVASHIELD — session.js. The in-memory session: document state,
      review decisions, per-entity overrides, pseudonym store, scan
      cache, element handles and toast. Nothing here is persisted.
   ===================================================================== */

import { createPseudoStore, replacementFor } from './redaction.js';

export const TOAST_DURATION_MS = 3200;

export const state = {
  text: '',
  matches: [],
  activeMatches: [],
  sanitized: '',
  fileName: null,
  fileKind: 'txt',
  csvMeta: null,
  decisions: {},
  lastCsvNeutralized: 0,
  mode: 'FULL',
  categories: { EMAIL: true, PHONE: true, IP: true, PAN: true, AADHAAR: true, CREDIT_CARD: true },
  overrides: {},
  pseudoStore: createPseudoStore(),
  plan: {},
  redactedCount: 0,
  preset: 'general',
  leak: null,
  exposure: null
};

export function sigOf(m) {
  return `${m.type}|${m.start}|${m.end}`;
}

/** Effective redaction mode for one detection (per-entity override beats global mode). */
export function effectiveMode(m) {
  const ovr = state.overrides[sigOf(m)];
  return ovr || state.mode;
}

export function isKeptVisible(m) {
  if (m.userDecision === 'EXCLUDED') return true;
  if (!state.categories[m.type]) return true;
  if (effectiveMode(m) === 'KEEP') return true;
  return false;
}

export function planReplacement(m) {
  if (isKeptVisible(m)) return null;
  return replacementFor(m, effectiveMode(m), state.pseudoStore);
}

export const $ = (id) => document.getElementById(id);

export const els = {};

export function bindElements() {
  els.input = $('inputText');
  els.highlight = $('highlightView');
  els.sanitized = $('sanitizedView');
  els.findings = $('findingsBody');
  els.toast = $('toast');
}

/** Restart a one-shot CSS highlight/flash animation on an element. */
export function restartFlash(el, cls = 'flash-target') {
  if (!el) return;
  el.classList.remove(cls);
  void el.offsetWidth;
  el.classList.add(cls);
}

export let toastTimer = null;

export function toast(msg, isErr) {
  if (!els.toast) return; /* no DOM yet (Node/test context) — silent no-op */
  els.toast.textContent = msg;
  els.toast.className = isErr ? 'show err' : 'show';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.className = '';
  }, TOAST_DURATION_MS);
  const es = $('exportStatus');
  if (es && !isErr && (msg.includes('downloaded') || msg.includes('copied'))) es.textContent = msg;
}

export const scanCache = { text: null, matches: [] };
