/* =====================================================================
   PRIVASHIELD — engine.js (Stages 2–3). detectAll(text) returns
      Detection objects {id, type, value, start, end, normalized,
      validationStatus, confidence, reviewStatus} after validation,
      overlap resolution and context annotation.
   ===================================================================== */

import { DETECTORS } from './detectors.js';
import { ambiguousSweep, annotateContext, isBarePhoneBenignRef } from './context.js';

export function freshEngineStats(){ return { rejectedLuhn:0, rejectedIP:0, rejectedOther:0, overlapsResolved:0, ambiguousSurfaced:0 }; }

export var engineStats = freshEngineStats();

export var luhnRejected = 0;

 /* legacy alias used by the report header note */

export function detectAll(text){
  engineStats = freshEngineStats();
  if (!text) { luhnRejected = 0; return []; }
  var candidates = [];
  DETECTORS.forEach(function(det){
    var re = new RegExp(det.pattern.source, "g");
    var m;
    while ((m = re.exec(text)) !== null){
      var value = m[0], start = m.index, end = start + value.length;
      if (value.length === 0){ re.lastIndex++; continue; }
      var before = start > 0 ? text[start - 1] : "";
      var after = end < text.length ? text[end] : "";
      if (det.digitBoundary && (/\d/.test(before) || /\d/.test(after))) continue;
      if (det.alnumBoundary && (/[A-Za-z0-9]/.test(before) || /[A-Za-z0-9]/.test(after))) continue;
      if (det.ipBoundary){
        var prev2 = start > 1 ? text[start - 2] : "";
        var next2 = end + 1 < text.length ? text[end + 1] : "";
        var beforeBad = /[0-9A-Fa-f]/.test(before) || ((before === "." || before === ":") && /[0-9A-Fa-f:.]/.test(prev2));
        var afterBad = /[0-9A-Fa-f]/.test(after) || ((after === "." || after === ":") && /[0-9A-Fa-f:.]/.test(next2));
        if (beforeBad || afterBad) continue;
      }
      var res = det.validate(value);
      if (!res || (det.type === "PHONE" && isBarePhoneBenignRef(text, start, end, value))){
        if (det.type === "CREDIT_CARD") engineStats.rejectedLuhn++;
        else if (det.type === "IP") engineStats.rejectedIP++;
        else engineStats.rejectedOther++;
        continue;
      }
      candidates.push({ type:det.type, label:det.label, severity:det.severity, prio:det.prio,
        value:value, start:start, end:end, normalized:res.normalized,
        validationStatus:res.status, validationDetail:res.detail,
        confidence:res.confidence, reviewStatus:res.review });
      if (re.lastIndex === start) re.lastIndex++;
    }
  });
  /* Overlap resolution: detector priority, then CONFIRMED beats
     NEEDS_REVIEW, then longer match, then earlier position. Losers are
     NOT double-highlighted or double-redacted — the winner records
     which rival types it suppressed, so the conflict stays auditable. */
  candidates.sort(function(a, b){
    if (a.prio !== b.prio) return a.prio - b.prio;
    var ra = a.reviewStatus === "CONFIRMED" ? 0 : 1, rb = b.reviewStatus === "CONFIRMED" ? 0 : 1;
    if (ra !== rb) return ra - rb;
    var la = a.end - a.start, lb = b.end - b.start;
    if (lb !== la) return lb - la;
    return a.start - b.start;
  });
  var accepted = [];
  candidates.forEach(function(c){
    var winner = null;
    for (var i = 0; i < accepted.length; i++){
      if (c.start < accepted[i].end && accepted[i].start < c.end){ winner = accepted[i]; break; }
    }
    if (!winner) accepted.push(c);
    else {
      engineStats.overlapsResolved++;
      if (!winner.overlapNote) winner.overlapNote = [];
      if (winner.overlapNote.indexOf(c.type) === -1) winner.overlapNote.push(c.type);
    }
  });
  accepted.forEach(function(a){
    if (a.overlapNote) a.validationDetail += " Overlap resolved: this span also matched " + a.overlapNote.join(" / ") + " candidate(s) — the stronger validation evidence won, so it is counted and redacted exactly once.";
  });
  /* Ambiguous matches are preserved for manual review, not dropped. */
  var swept = ambiguousSweep(text, accepted);
  engineStats.ambiguousSurfaced = swept.length;
  accepted = accepted.concat(swept);
  accepted.sort(function(a, b){ return a.start - b.start; });
  accepted.forEach(function(e){ annotateContext(text, e); });
  accepted.forEach(function(e, i){ e.id = "DET-" + String(i + 1).padStart(4, "0"); });
  luhnRejected = engineStats.rejectedLuhn;
  return accepted;
}

/* Backwards-compatible name used by files.js CSV handling. */
export function detect(text){ return detectAll(text); }

export function setEngineStats(s){ engineStats = s; }
export function setLuhnRejected(n){ luhnRejected = n; }
export function getLuhnRejected(){ return luhnRejected; }
