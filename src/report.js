/* =====================================================================
   PRIVASHIELD — report.js. Sanitization audit report (text/JSON
      + SHA-256 via Web Crypto). Built purely from counts and metadata:
      NO original PII, NO raw text, NO original filename, NO mapping.
   ===================================================================== */

import { DETECTORS } from './detectors.js';
import { SENSITIVITY, PARTIAL_RESIDUAL_FACTOR, computeExposure, partialRawWeight, runLeakGuard } from './advanced.js';
import { state, sigOf, $, toast } from './session.js';
import { engineStats } from './engine.js';

export var APP_VERSION = "1.0.0";

/* --- Sanitization audit report ---
   Built purely from counts and metadata: NO original PII, NO raw
   text, NO original filename, NO pseudonym mapping. Labelled as
   an application-generated report, not a compliance certificate. */
export function sha256Hex(str){
  if (typeof window === "undefined" || !(window.crypto && crypto.subtle && crypto.subtle.digest && window.TextEncoder)) return Promise.resolve(null);
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(str)).then(function(buf){
    return Array.prototype.map.call(new Uint8Array(buf), function(b){ return ("0" + b.toString(16)).slice(-2); }).join("");
  }).catch(function(){ return null; });
}

export function buildAuditReport(){
  var leak = state.leak || runLeakGuard();
  var exp = state.exposure || computeExposure(state.matches, leak.matches, partialRawWeight(state.matches));
  var per = {};
  DETECTORS.forEach(function(d){
    per[d.type] = { occurrences:0, unique:{}, validated:0, candidates:0, redacted:0, excluded:0, keptVisible:0 };
  });
  var uniqueAll = {};
  state.matches.forEach(function(m){
    var p = per[m.type];
    if (!p) return;
    p.occurrences++;
    p.unique[m.normalized] = true;
    uniqueAll[m.type + "|" + m.normalized] = true;
    if (m.reviewStatus === "NEEDS_REVIEW") p.candidates++; else p.validated++;
    if (m.userDecision === "EXCLUDED") p.excluded++;
    if (state.plan[sigOf(m)] != null) p.redacted++; else p.keptVisible++;
  });
  var leakByType = {};
  leak.matches.forEach(function(it){ leakByType[it.type] = (leakByType[it.type] || 0) + 1; });
  var bytes = state.text.length;
  try { bytes = new TextEncoder().encode(state.text).length; } catch (e) { /* char count fallback */ }
  return {
    report: "PRIVASHIELD — application-generated sanitization audit report",
    disclaimer: "This is an application-generated sanitization audit report, not an official compliance certificate. It records what this tool detected and replaced during one browser session. It contains no original PII, no raw document text, no original filename and no pseudonym mapping.",
    appVersion: APP_VERSION,
    generatedAt: new Date().toISOString(),
    document: {
      type: state.fileKind === "csv" ? "CSV" : "Text",
      source: state.fileName ? "uploaded file (name withheld from this report)" : "pasted or built-in sample text",
      sizeBytes: bytes,
      sizeChars: state.text.length
    },
    preset: state.preset,
    redactionMode: state.mode,
    totals: {
      detectedOccurrences: state.matches.length,
      uniqueEntities: Object.keys(uniqueAll).length,
      redactedOccurrences: state.redactedCount,
      excludedOccurrences: state.matches.filter(function(m){ return m.userDecision === "EXCLUDED"; }).length,
      keptVisibleOccurrences: state.matches.length - state.redactedCount
    },
    categories: DETECTORS.map(function(d){
      var p = per[d.type];
      return { type:d.type, label:d.label, occurrences:p.occurrences, uniqueEntities:Object.keys(p.unique).length, validated:p.validated, candidates:p.candidates, redacted:p.redacted, excluded:p.excluded, keptVisible:p.keptVisible, redactionEnabled: !!state.categories[d.type] };
    }),
    validation: {
      note: "Validation is mathematical / structural consistency only (Luhn for cards, Verhoeff for Aadhaar, octet rules for IPs, holder codes for PAN) — never identity verification.",
      rejectedByLuhn: engineStats.rejectedLuhn,
      rejectedByIpValidation: engineStats.rejectedIP,
      rejectedByFormatRules: engineStats.rejectedOther,
      overlapsResolved: engineStats.overlapsResolved,
      ambiguousCandidatesSurfaced: engineStats.ambiguousSurfaced
    },
    leakGuard: {
      method: "Second detection pass over the sanitized output using the same engine (shares the same pattern/checksum blind spots)",
      remainingSupportedMatches: leak.matches.length,
      remainingByType: leakByType,
      partiallyMaskedOccurrences: leak.partialCount,
      note: "A remaining count of 0 means no supported patterns were found by the same detection engine — it is not a guarantee of complete anonymization."
    },
    exposureScore: {
      metric: "Estimated privacy exposure (heuristic) — not a regulatory compliance score",
      before: exp.before,
      after: exp.after,
      reductionPercent: exp.reduction,
      sensitivityWeights: SENSITIVITY,
      partialMaskResidualFactor: PARTIAL_RESIDUAL_FACTOR,
      methodology: "score = 100 x (1 - 1/(1 + weightedTotal/50)), computed over detected occurrences. Residual counts Leak Guard matches at full weight plus partially masked values at the residual factor of their weight. A score of 0 means no residual exposure measured by the supported scoring rules, not a guarantee of complete anonymization."
    },
    sanitizedOutputSha256: null,
    knownLimitations: [
      "Detection covers six supported PII categories only; free-text names, postal addresses and obfuscated identifiers can be missed.",
      "Checksum / format validation is mathematical consistency, not identity verification.",
      "Partial masking retains identifying fragments that may enable re-identification; pseudonymized output preserves linkability and can be reversed if the mapping is available.",
      "Leak Guard re-scans with the same pattern/checksum engine as the primary scan and shares the same blind spots; a clear result or exposure score of 0 is not a guarantee of complete anonymization.",
      "The exposure score is an illustrative heuristic with configurable weights, not a regulatory compliance measurement."
    ]
  };
}

export function reportToText(r){
  var L = [];
  L.push("PRIVASHIELD — SANITIZATION AUDIT REPORT");
  L.push("Application-generated report — NOT an official compliance certificate.");
  L.push(r.disclaimer);
  L.push("");
  L.push("Generated:          " + r.generatedAt);
  L.push("Application version: " + r.appVersion);
  L.push("Document:           " + r.document.type + " · " + r.document.source + " · " + r.document.sizeBytes + " bytes (" + r.document.sizeChars + " chars)");
  L.push("Industry preset:    " + r.preset);
  L.push("Redaction mode:     " + r.redactionMode);
  L.push("");
  L.push("TOTALS");
  L.push("  Detected occurrences:   " + r.totals.detectedOccurrences);
  L.push("  Unique entities:        " + r.totals.uniqueEntities);
  L.push("  Redacted occurrences:   " + r.totals.redactedOccurrences);
  L.push("  Excluded by reviewer:   " + r.totals.excludedOccurrences);
  L.push("  Kept visible:           " + r.totals.keptVisibleOccurrences);
  L.push("");
  L.push("CATEGORIES (occurrences · unique · validated · candidates · redacted · excluded · kept visible · redaction on)");
  r.categories.forEach(function(c){
    L.push("  " + c.label + ": " + c.occurrences + " · " + c.uniqueEntities + " · " + c.validated + " · " + c.candidates + " · " + c.redacted + " · " + c.excluded + " · " + c.keptVisible + " · " + (c.redactionEnabled ? "yes" : "no"));
  });
  L.push("");
  L.push("VALIDATION RESULTS");
  L.push("  " + r.validation.note);
  L.push("  Rejected by Luhn: " + r.validation.rejectedByLuhn + " · by IP validation: " + r.validation.rejectedByIpValidation + " · by format rules: " + r.validation.rejectedByFormatRules);
  L.push("  Overlaps resolved: " + r.validation.overlapsResolved + " · ambiguous candidates surfaced for review: " + r.validation.ambiguousCandidatesSurfaced);
  L.push("");
  L.push("LEAK GUARD — SECOND PASS OVER THE SANITIZED OUTPUT");
  L.push("  Remaining supported PII matches: " + r.leakGuard.remainingSupportedMatches);
  var bt = Object.keys(r.leakGuard.remainingByType);
  L.push("  Remaining by type: " + (bt.length ? bt.map(function(t){ return t + " × " + r.leakGuard.remainingByType[t]; }).join(", ") : "none"));
  L.push("  Partially masked occurrences (residual fragments): " + r.leakGuard.partiallyMaskedOccurrences);
  L.push("  " + r.leakGuard.note);
  L.push("");
  L.push("PRIVACY EXPOSURE SCORE (estimated heuristic — not a compliance score)");
  L.push("  Before sanitization: " + r.exposureScore.before + " / 100");
  L.push("  Residual after:      " + r.exposureScore.after + " / 100");
  L.push("  Reduction:           " + (r.exposureScore.reductionPercent === null ? "n/a" : r.exposureScore.reductionPercent + "%"));
  L.push("  Sensitivity weights: " + Object.keys(r.exposureScore.sensitivityWeights).map(function(t){ return t + "=" + r.exposureScore.sensitivityWeights[t]; }).join(", ") + " · partial-mask residual factor " + r.exposureScore.partialMaskResidualFactor);
  L.push("  Methodology: " + r.exposureScore.methodology);
  L.push("");
  L.push("SANITIZED OUTPUT INTEGRITY");
  L.push("  SHA-256: " + (r.sanitizedOutputSha256 || "unavailable in this browser context (Web Crypto requires a secure context)"));
  L.push("");
  L.push("KNOWN LIMITATIONS");
  r.knownLimitations.forEach(function(k){ L.push("  - " + k); });
  return L.join("\n");
}

export function downloadReport(kind){
  if (!state.text){ toast("Nothing to report yet — add some input first.", true); return; }
  sha256Hex(state.sanitized).then(function(hash){
    var r = buildAuditReport();
    r.sanitizedOutputSha256 = hash;
    var isJson = kind === "json";
    var content = isJson ? JSON.stringify(r, null, 2) : reportToText(r);
    var blob = new Blob([content], { type: (isJson ? "application/json" : "text/plain") + ";charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "privashield-audit-report." + (isJson ? "json" : "txt"); /* fixed name — the original filename never enters a report or its filename */
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function(){ URL.revokeObjectURL(url); }, 1500);
    $("reportStatus").textContent = "Audit report (" + (isJson ? "JSON" : "text") + ") generated " + new Date().toLocaleTimeString() + " — counts, categories and validation results only; no PII, no original filename, no pseudonym mapping.";
    var rh = $("reportHash");
    rh.style.display = "";
    rh.textContent = hash
      ? "SHA-256 of the sanitized output at generation time: " + hash
      : "SHA-256 unavailable in this browser context (Web Crypto requires a secure context) — the report records it as null rather than inventing one.";
    toast("Sanitization audit report downloaded (" + (isJson ? "JSON" : "text") + ").");
  });
}
