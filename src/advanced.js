/* =====================================================================
   PRIVASHIELD — advanced.js (Stage 6). Leak Guard second pass,
      Privacy Exposure Score, industry presets, export guard.
      applyPreset takes the mode setter as a parameter so this module
      stays independent of the app shell.
   ===================================================================== */

import { detectAll, engineStats, getLuhnRejected, setEngineStats, setLuhnRejected } from './engine.js';
import { TYPE_META } from './detectors.js';
import { state, sigOf, effectiveMode, $, els, toast, restartFlash } from './session.js';
import { escapeHtml, truncateVal } from './sanitizer.js';

export const SENSITIVITY = { AADHAAR: 10, CREDIT_CARD: 10, PAN: 8, PHONE: 6, EMAIL: 5, IP: 3 };

export const PARTIAL_RESIDUAL_FACTOR = 0.4;

export function scoreFromRaw(raw) {
  if (!(raw > 0)) return 0;
  return Math.min(100, Math.round(100 * (1 - 1 / (1 + raw / 50))));
}

export function rawWeight(list) {
  let s = 0;
  (list || []).forEach((m) => {
    s += SENSITIVITY[m.type] || 0;
  });
  return s;
}

export function partialRawWeight(matches) {
  let s = 0;
  matches.forEach((m) => {
    if (state.plan[sigOf(m)] != null && effectiveMode(m) === 'PARTIAL') {
      s += (SENSITIVITY[m.type] || 0) * PARTIAL_RESIDUAL_FACTOR;
    }
  });
  return s;
}

/** Compute deterministic 0–100 exposure heuristic before/after sanitization. */
export function computeExposure(matches, residualMatches, partialRaw) {
  const before = scoreFromRaw(rawWeight(matches));
  const after = scoreFromRaw(rawWeight(residualMatches) + (partialRaw || 0));
  let reduction = null;
  if (before > 0 && after <= before) reduction = Math.round(((before - after) / before) * 100);
  return { before, after, reduction };
}

/**
 * Re-scan the sanitized output with the production engine while preserving
 * `engineStats` and `luhnRejected` from the primary scan.
 */
export function leakScan(text) {
  if (!text) return [];
  const savedStats = engineStats;
  const savedLuhn = getLuhnRejected();
  const found = detectAll(text);
  setEngineStats(savedStats);
  setLuhnRejected(savedLuhn);
  return found;
}

export function classifyResidual(f, matches) {
  let src = null;
  for (let i = 0; i < matches.length; i++) {
    if (matches[i].type === f.type && matches[i].normalized === f.normalized) {
      src = matches[i];
      break;
    }
  }
  let reason = 'UNRESOLVED';
  if (src) {
    if (src.userDecision === 'EXCLUDED') reason = 'EXCLUDED';
    else if (!state.categories[src.type]) reason = 'CATEGORY_OFF';
    else if (effectiveMode(src) === 'KEEP') reason = 'KEEP_OVERRIDE';
  }
  return { source: src, reason };
}

export function runLeakGuard() {
  const found = leakScan(state.sanitized);
  const items = found.map((f) => {
    const c = classifyResidual(f, state.matches);
    return {
      type: f.type,
      value: f.value,
      normalized: f.normalized,
      validationStatus: f.validationStatus,
      reviewStatus: f.reviewStatus,
      start: f.start,
      end: f.end,
      source: c.source,
      reason: c.reason
    };
  });
  let partialCount = 0;
  state.matches.forEach((m) => {
    if (state.plan[sigOf(m)] != null && effectiveMode(m) === 'PARTIAL') partialCount++;
  });
  state.leak = { matches: items, partialCount, at: new Date() };
  return state.leak;
}

export const REASON_LABEL = {
  EXCLUDED: 'Excluded in review',
  CATEGORY_OFF: 'Category switched off',
  KEEP_OVERRIDE: 'Keep override',
  UNRESOLVED: 'Not resolved'
};

export function renderAdvanced() {
  const leak = runLeakGuard();
  const exp = computeExposure(state.matches, leak.matches, partialRawWeight(state.matches));
  state.exposure = exp;
  $('expBefore').textContent = exp.before;
  const ea = $('expAfter');
  ea.textContent = exp.after;
  ea.classList.toggle('zero', exp.after === 0);
  $('expReduction').textContent = exp.reduction === null ? '—' : `${exp.reduction}%`;
  $('expBarBefore').style.width = `${exp.before}%`;
  const eb = $('expBarAfter');
  eb.style.width = `${exp.after}%`;
  eb.classList.toggle('zero', exp.after === 0);
  $('leakScannedAt').textContent = state.text
    ? `Last re-scan ${leak.at.toLocaleTimeString()} · output ${state.sanitized.length.toLocaleString()} chars`
    : 'Not scanned yet';
  const st = $('leakStatus');
  const stx = $('leakStatusText');
  const n = leak.matches.length;
  const partials = leak.partialCount;
  if (!state.text) {
    st.className = 'leak-status ok';
    stx.innerHTML = '<strong>No document loaded.</strong> Load or paste a document — Leak Guard re-scans the sanitized output automatically after every change.';
  } else if (n) {
    st.className = 'leak-status bad';
    stx.innerHTML = `<strong>${n} supported PII match${n === 1 ? '' : 'es'} remain${n === 1 ? 's' : ''} in the sanitized output.</strong> Resolve ${n === 1 ? 'it' : 'them'} below, or expect a warning before any download.${partials ? ` Plus ${partials} partially masked value(s) whose retained fragments still count as residual exposure.` : ''}`;
  } else if (partials) {
    st.className = 'leak-status ok';
    stx.innerHTML = `<strong>No supported PII patterns remain in the output.</strong> ${partials} value(s) are partially masked — their retained fragments (for example last-4 digits) still count toward residual exposure and may enable re-identification. Uses the same engine as the primary scan and shares its blind spots; not a claim of complete anonymization.`;
  } else {
    st.className = 'leak-status ok';
    stx.innerHTML = '<strong>No supported PII patterns remain in the sanitized output.</strong> Leak Guard uses the same pattern/checksum engine as the primary scan (so it shares the same blind spots) — a clear pass is not a claim of complete privacy or guaranteed anonymization.';
  }
  $('leakList').innerHTML = leak.matches.map((it, idx) => {
    const meta = TYPE_META[it.type];
    return `<div class="leak-item">` +
      `<span class="type-tag" style="--tc:${meta.color}"><i></i>${meta.label.toUpperCase()}</span>` +
      `<span class="mono">${escapeHtml(truncateVal(it.value))}</span>` +
      `<span class="reason-tag">${REASON_LABEL[it.reason]}</span>` +
      `<span style="color:var(--ink-faint);font-size:11.5px">${it.validationStatus.replace(/_/g, ' ')}</span>` +
      `<button class="rev-btn plain" type="button" data-leak-resolve="${idx}">Resolve</button>` +
    `</div>`;
  }).join('');
}

/** Scroll to and highlight the original detection (or sanitized location) behind a Leak Guard item. */
export function resolveLeak(idx) {
  const leak = state.leak;
  if (!leak || !leak.matches[idx]) return;
  const it = leak.matches[idx];
  if (it.source) {
    const mark = els.highlight.querySelector(`mark[data-start="${it.source.start}"]`);
    if (mark) {
      const r = mark.getBoundingClientRect();
      const pr = els.highlight.getBoundingClientRect();
      els.highlight.scrollTop += (r.top - pr.top) - els.highlight.clientHeight / 2 + r.height / 2;
      restartFlash(mark, 'flash');
    }
    const sec = $('sec-inspector');
    if (sec) {
      sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
      restartFlash(sec);
    }
    toast(`${it.source.id} is the detection behind this remaining match — Restore it, change its Override, or re-enable its category to resolve it.`, true);
  } else {
    const ratio = state.sanitized.length ? it.start / state.sanitized.length : 0;
    els.sanitized.scrollTop = ratio * Math.max(0, els.sanitized.scrollHeight - els.sanitized.clientHeight);
    els.sanitized.scrollIntoView({ block: 'center' });
    toast('This pattern appears in the sanitized output but not in the original detection list — the sanitized pane is scrolled to its position.', true);
  }
}

export let pendingExport = null;

export function exportBlocked() {
  const leak = state.leak;
  return !!(leak && (leak.matches.length || leak.partialCount));
}

export function guardExport(kind) {
  if (!state.text || !exportBlocked()) return true;
  pendingExport = kind;
  const leak = state.leak;
  const parts = [];
  if (leak.matches.length) parts.push(`${leak.matches.length} supported PII match(es) still present in the output`);
  if (leak.partialCount) parts.push(`${leak.partialCount} partially masked value(s) retaining identifying fragments`);
  $('exportGuardText').innerHTML = `<strong>Export paused — Leak Guard:</strong> ${parts.join(' · ')}. The file you are about to download carries that exposure. Review the remaining matches, export anyway if that is deliberate, or cancel.`;
  $('exportGuard').classList.add('show');
  $('exportGuard').scrollIntoView({ behavior: 'smooth', block: 'center' });
  toast('Export paused — Leak Guard found unresolved exposure.', true);
  return false;
}

export function hideExportGuard() {
  $('exportGuard').classList.remove('show');
  pendingExport = null;
}

export const PRESETS = {
  general: {
    label: 'General purpose',
    mode: 'FULL',
    note: 'General purpose — Full Mask, all six categories redacted. Presets choose a default redaction mode and document the workflow emphasis; they never switch a category off — all six categories always stay detected.'
  },
  healthcare: {
    label: 'Healthcare',
    mode: 'PSEUDO',
    note: 'Healthcare — Pseudonymization: patient contact details, Aadhaar and IPs become stable aliases, so follow-up notes stay linkable to the same patient across a chart without exposing raw identifiers. All six categories remain detected and redacted.'
  },
  finance: {
    label: 'Finance',
    mode: 'FULL',
    note: 'Finance — Full Mask: cards, PAN and Aadhaar are removed outright for statements, KYC exports and payment logs shared outside the finance team. All six categories remain detected and redacted.'
  },
  hr: {
    label: 'Human resources',
    mode: 'PSEUDO',
    note: 'Human resources — Pseudonymization: candidate emails, phones and PANs become stable aliases, so the same applicant stays recognisable across a resume packet and interview notes. All six categories remain detected and redacted.'
  },
  support: {
    label: 'Customer support',
    mode: 'PARTIAL',
    note: 'Customer support — Partial Mask: agents keep last-4 verification fragments for cards and phones while the bulk of each identifier is masked. Partial output is still sensitive — see the warning under the redaction controls. All six categories remain detected and redacted.'
  }
};

export let applyingPreset = false;

export function refreshPresetUI(note) {
  if (typeof document === 'undefined') return; /* Node/test context */
  document.querySelectorAll('.preset-btn').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-preset') === state.preset);
  });
  if (note) $('presetNote').textContent = note;
}

export function markPresetCustom() {
  if (applyingPreset || state.preset === 'custom') return;
  state.preset = 'custom';
  refreshPresetUI('Custom configuration — the mode or category filters were changed after a preset was applied. Nothing was silently excluded: the category chips above show exactly what is currently redacted.');
}

export function applyPreset(key, setModeFn) {
  const p = PRESETS[key];
  if (!p) return;
  applyingPreset = true;
  state.preset = key;
  Object.keys(state.categories).forEach((t) => {
    state.categories[t] = true;
    if (typeof document !== 'undefined') {
      const chip = document.querySelector(`.cat-chip[data-cat="${t}"]`);
      if (chip) chip.classList.remove('off');
    }
  });
  if (setModeFn) setModeFn(p.mode);
  applyingPreset = false;
  refreshPresetUI(p.note);
  toast(`${p.label} preset applied — ${p.mode === 'FULL' ? 'Full Mask' : p.mode === 'PARTIAL' ? 'Partial Mask' : 'Pseudonymization'}, all six categories on.`);
}
