/* =====================================================================
   PRIVASHIELD — engine.js (Stages 2–3). detectAll(text) returns
      Detection objects {id, type, value, start, end, normalized,
      validationStatus, confidence, reviewStatus} after validation,
      overlap resolution and context annotation.
   ===================================================================== */

import { DETECTORS } from './detectors.js';
import { ambiguousSweep, annotateContext, isBarePhoneBenignRef } from './context.js';

/**
 * @typedef {Object} Detection
 * @property {string} id
 * @property {string} type
 * @property {string} label
 * @property {"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"} severity
 * @property {number} prio
 * @property {string} value
 * @property {number} start
 * @property {number} end
 * @property {string} normalized
 * @property {string} validationStatus
 * @property {string} validationDetail
 * @property {"HIGH"|"MEDIUM"|"LOW"} confidence
 * @property {"CONFIRMED"|"NEEDS_REVIEW"} reviewStatus
 * @property {string|null} [contextSupport]
 * @property {string|null} [contextBenign]
 * @property {string[]} [overlapNote]
 * @property {string|null} [userDecision]
 * @property {string} [baseReview]
 * @property {string|null} [replacement]
 */

export function freshEngineStats() {
  return { rejectedLuhn: 0, rejectedIP: 0, rejectedOther: 0, overlapsResolved: 0, ambiguousSurfaced: 0 };
}

export let engineStats = freshEngineStats();

export let luhnRejected = 0; /* legacy alias used by the report header note */

/**
 * Run all detectors, boundary checks, validators, overlap resolution,
 * ambiguity sweep, and context annotation against `text`.
 * @param {string} text
 * @returns {Detection[]}
 */
export function detectAll(text) {
  engineStats = freshEngineStats();
  if (!text) {
    luhnRejected = 0;
    return [];
  }
  const candidates = [];
  DETECTORS.forEach((det) => {
    const re = new RegExp(det.pattern.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = m[0];
      const start = m.index;
      const end = start + value.length;
      if (value.length === 0) {
        re.lastIndex++;
        continue;
      }
      const before = start > 0 ? text[start - 1] : '';
      const after = end < text.length ? text[end] : '';
      if (det.digitBoundary && (/\d/.test(before) || /\d/.test(after))) continue;
      if (det.alnumBoundary && (/[A-Za-z0-9]/.test(before) || /[A-Za-z0-9]/.test(after))) continue;
      if (det.ipBoundary) {
        const prev2 = start > 1 ? text[start - 2] : '';
        const next2 = end + 1 < text.length ? text[end + 1] : '';
        const beforeBad = /[0-9A-Fa-f]/.test(before) || ((before === '.' || before === ':') && /[0-9A-Fa-f:.]/.test(prev2));
        const afterBad = /[0-9A-Fa-f]/.test(after) || ((after === '.' || after === ':') && /[0-9A-Fa-f:.]/.test(next2));
        if (beforeBad || afterBad) continue;
      }
      const res = det.validate(value);
      if (!res || (det.type === 'PHONE' && isBarePhoneBenignRef(text, start, end, value))) {
        if (det.type === 'CREDIT_CARD') engineStats.rejectedLuhn++;
        else if (det.type === 'IP') engineStats.rejectedIP++;
        else engineStats.rejectedOther++;
        continue;
      }
      candidates.push({
        type: det.type,
        label: det.label,
        severity: det.severity,
        prio: det.prio,
        value,
        start,
        end,
        normalized: res.normalized,
        validationStatus: res.status,
        validationDetail: res.detail,
        confidence: res.confidence,
        reviewStatus: res.review
      });
      if (re.lastIndex === start) re.lastIndex++;
    }
  });

  /* Overlap resolution: detector priority, then CONFIRMED beats
     NEEDS_REVIEW, then longer match, then earlier position. */
  candidates.sort((a, b) => {
    if (a.prio !== b.prio) return a.prio - b.prio;
    const ra = a.reviewStatus === 'CONFIRMED' ? 0 : 1;
    const rb = b.reviewStatus === 'CONFIRMED' ? 0 : 1;
    if (ra !== rb) return ra - rb;
    const la = a.end - a.start;
    const lb = b.end - b.start;
    if (lb !== la) return lb - la;
    return a.start - b.start;
  });

  let accepted = [];
  candidates.forEach((c) => {
    let winner = null;
    for (let i = 0; i < accepted.length; i++) {
      if (c.start < accepted[i].end && accepted[i].start < c.end) {
        winner = accepted[i];
        break;
      }
    }
    if (!winner) {
      accepted.push(c);
    } else {
      engineStats.overlapsResolved++;
      if (!winner.overlapNote) winner.overlapNote = [];
      if (!winner.overlapNote.includes(c.type)) winner.overlapNote.push(c.type);
    }
  });

  accepted.forEach((a) => {
    if (a.overlapNote) {
      a.validationDetail += ` Overlap resolved: this span also matched ${a.overlapNote.join(' / ')} candidate(s) — the stronger validation evidence won, so it is counted and redacted exactly once.`;
    }
  });

  /* Ambiguous matches are preserved for manual review, not dropped. */
  const swept = ambiguousSweep(text, accepted, engineStats);
  engineStats.ambiguousSurfaced = swept.length;
  accepted = accepted.concat(swept);
  accepted.sort((a, b) => a.start - b.start);
  accepted.forEach((e) => annotateContext(text, e));
  accepted.forEach((e, i) => {
    e.id = `DET-${String(i + 1).padStart(4, '0')}`;
  });
  luhnRejected = engineStats.rejectedLuhn;
  return accepted;
}

/** Backwards-compatible alias used by files.js CSV handling. */
export function detect(text) {
  return detectAll(text);
}

export function setEngineStats(s) {
  engineStats = s;
}

export function setLuhnRejected(n) {
  luhnRejected = n;
}

export function getLuhnRejected() {
  return luhnRejected;
}
