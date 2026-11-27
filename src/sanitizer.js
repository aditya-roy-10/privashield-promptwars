/* =====================================================================
   PRIVASHIELD — sanitizer.js. Offset-safe replacement and the
      mode-aware highlighted/sanitized views.
   ===================================================================== */

import { TYPE_META } from './detectors.js';
import { state, sigOf, effectiveMode } from './session.js';

export function sanitize(text, matches){
  var out = "", last = 0;
  matches.forEach(function(m){
    out += text.slice(last, m.start) + "[REDACTED]";
    last = m.end;
  });
  out += text.slice(last);
  return out;
}

export function escapeHtml(s){
  return String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

export function renderHighlighted(text, matches){
  var out = "", last = 0;
  matches.forEach(function(m){
    out += escapeHtml(text.slice(last, m.start));
    var cls = "t-" + m.type + (m.reviewStatus === "NEEDS_REVIEW" ? " candidate" : "") + (m.userDecision === "EXCLUDED" ? " excluded" : "");
    var title = TYPE_META[m.type].label + " · " + m.validationStatus.replace(/_/g, " ") + (m.reviewStatus === "NEEDS_REVIEW" ? " · NEEDS REVIEW" : "") + (m.userDecision === "EXCLUDED" ? " · EXCLUDED — left unredacted by reviewer" : "");
    out += '<mark class="' + cls + '" data-start="' + m.start + '" title="' + escapeHtml(title) + '">' + escapeHtml(m.value) + "</mark>";
    last = m.end;
  });
  out += escapeHtml(text.slice(last));
  return out;
}

export function renderSanitizedHtml(sanitized){
  return escapeHtml(sanitized).replace(/\[REDACTED\]/g, '<span class="redacted">[REDACTED]</span>');
}

/* Stage 4 rich sanitized view: replacements are styled by the mode
   that produced them (green = full mask, amber = partial, blue =
   pseudonym); kept-visible values render as plain text. */
export function renderSanitizedRich(text, matches){
  var out = "", last = 0;
  matches.forEach(function(m){
    out += escapeHtml(text.slice(last, m.start));
    var rep = state.plan[sigOf(m)];
    if (rep === null || rep === undefined) out += escapeHtml(m.value);
    else {
      var em = effectiveMode(m);
      var cls = em === "PARTIAL" ? "partial" : em === "PSEUDO" ? "pseudo" : "redacted";
      out += '<span class="' + cls + '">' + escapeHtml(rep) + "</span>";
    }
    last = m.end;
  });
  out += escapeHtml(text.slice(last));
  return out;
}

export function truncateVal(v){
  if (v.length <= 14) return v;
  return v.slice(0, 6) + "…" + v.slice(-4);
}

/* A cell whose first non-space character is =, +, − or @ can be
   interpreted as a formula by spreadsheet applications (CSV
   injection). Exported CSVs prefix such cells with an apostrophe. */
export function isFormulaCell(s){
  return /^\s*[=+\-@]/.test(s) && s.trim().length > 1;
}
