/* =====================================================================
   PRIVASHIELD — context.js (Stage 3). Context is supporting
      evidence only — never the sole detection rule.
   ===================================================================== */

import { TYPE_META } from './detectors.js';
import { engineStats } from './engine.js';

export var CONTEXT_WINDOW = 80;

export var TYPE_KEYWORDS = {
  EMAIL:["email","e-mail","mail"],
  PHONE:["phone","mobile","call","contact","tel","whatsapp"],
  IP:["ip","ipv4","ipv6"],
  PAN:["pan"],
  AADHAAR:["aadhaar","aadhar","uid"],
  CREDIT_CARD:["card","visa","mastercard","amex","credit","debit"]
};

export var BENIGN_KEYWORDS = ["order","invoice","ref","reference","transaction","txn","timestamp","total","amount","version","ticket","receipt","bill"];

export function keywordIn(windowText, keywords){
  var lower = " " + windowText.toLowerCase() + " ";
  for (var i = 0; i < keywords.length; i++){
    var kw = keywords[i].replace(/-/g, "\\-");
    if (new RegExp("[^a-z0-9]" + kw + "[^a-z0-9]").test(lower)) return keywords[i];
  }
  return null;
}

export function contextWindow(text, start, end){
  return text.slice(Math.max(0, start - CONTEXT_WINDOW), Math.min(text.length, end + CONTEXT_WINDOW));
}

export function isBarePhoneBenignRef(text, start, end, value){
  if (!/^[6-9]\d{9}$/.test(value)) return false;
  var ben = closestKeyword(text, start, end, BENIGN_KEYWORDS);
  if (!ben.kw) return false;
  var sup = closestKeyword(text, start, end, TYPE_KEYWORDS.PHONE);
  return !sup.kw || ben.dist <= sup.dist;
}

export function annotateContext(text, det){
  var w = contextWindow(text, det.start, det.end);
  var support = keywordIn(w, TYPE_KEYWORDS[det.type] || []);
  var benign = keywordIn(w, BENIGN_KEYWORDS);
  det.contextSupport = support;
  det.contextBenign = benign;
  if (support) det.validationDetail += " Context: keyword '" + support + "' nearby supports this classification.";
  if (benign && det.reviewStatus === "NEEDS_REVIEW") det.validationDetail += " Caution: '" + benign + "' nearby — this could be a transaction / order reference rather than an identifier; verify before treating it as PII.";
  if (support && det.reviewStatus === "CONFIRMED" && det.confidence === "MEDIUM") det.confidence = "HIGH";
}

export function closestKeyword(text, start, end, keywords){
  var wStart = Math.max(0, start - CONTEXT_WINDOW);
  var w = text.slice(wStart, Math.min(text.length, end + CONTEXT_WINDOW));
  var lower = " " + w.toLowerCase() + " ";
  var best = Infinity, bestKw = null;
  for (var i = 0; i < keywords.length; i++){
    var kw = keywords[i].replace(/-/g, "\\-");
    var re = new RegExp("[^a-z0-9]" + kw + "[^a-z0-9]", "g"), m;
    while ((m = re.exec(lower)) !== null){
      var kwStart = wStart + m.index;
      var kwEnd = kwStart + keywords[i].length;
      var dist = kwEnd <= start ? (start - kwEnd) : kwStart >= end ? (kwStart - end) : 0;
      if (dist < best){ best = dist; bestKw = keywords[i]; }
    }
  }
  return { dist: best, kw: bestKw };
}

/* Ambiguity sweep: digit runs (10–19 digits) that no detector accepted,
   re-surfaced as NEEDS_REVIEW candidates ONLY when a type keyword sits
   nearby and no benign reference keyword sits at least as close.
   Uncertain cases stay visible to the user instead of being silently dropped. */
export function ambiguousSweep(text, accepted){
  var out = [];
  var re = /\d+(?:[ -]\d+)*/g, m;
  while ((m = re.exec(text)) !== null){
    var value = m[0], start = m.index, end = start + value.length;
    if (/^\d{4}[-/]\d{1,2}[-/]\d{1,2}/.test(value)) continue; /* date-led run — a timestamp, not an identifier */
    if (text[end] === ":" && /\d/.test(text[end + 1] || "")) continue; /* time fragment, e.g. the 09 in 09:14:22 */
    var digits = value.replace(/\D/g, "");
    if (digits.length < 10 || digits.length > 19) continue;
    var type = digits.length === 10 ? "PHONE" : digits.length === 12 ? "AADHAAR" : digits.length >= 13 ? "CREDIT_CARD" : null;
    if (!type) continue;
    var w = contextWindow(text, start, end);
    var sup = closestKeyword(text, start, end, TYPE_KEYWORDS[type]);
    if (!sup.kw) continue;                       /* context is required — never promote on digits alone */
    var ben = closestKeyword(text, start, end, BENIGN_KEYWORDS);
    if (ben.kw && ben.dist <= sup.dist) continue; /* closer/equal benign order/invoice/transaction wording vetoes promotion */
    var kw = sup.kw;
    var meta = TYPE_META[type];
    var detail = "Digit string failed " + (type === "CREDIT_CARD" ? "Luhn checksum" : type === "AADHAAR" ? "Verhoeff / format rules" : "phone format rules") + ", but the keyword '" + kw + "' nearby suggests it may be a " + meta.label.toLowerCase() + " — surfaced as an ambiguous candidate for manual review instead of being silently dropped.";
    var covering = accepted.filter(function(a){ return start < a.end && a.start < end; });
    if (covering.length){
      /* Context arbitration: a covering NEEDS_REVIEW candidate of a
         different type, with no keyword support of its own, yields to
         the keyword-supported reading of the full digit run (e.g. the
         first 12 digits of a Luhn-failing card are not an Aadhaar
         candidate when the line says "card"). Confirmed detections and
         same-type coverage are never displaced. */
      var arbitrable = covering.every(function(a){
        return a.reviewStatus === "NEEDS_REVIEW" && a.type !== type && !keywordIn(w, TYPE_KEYWORDS[a.type] || []);
      });
      if (!arbitrable) continue;
      var suppressed = [];
      covering.forEach(function(a){
        accepted.splice(accepted.indexOf(a), 1);
        suppressed.push(a.type);
        engineStats.overlapsResolved++;
      });
      detail += " Context arbitration: overlapping " + suppressed.join(" / ") + " candidate(s) had no supporting keyword and were suppressed — this span is counted once, as " + type + ".";
    }
    out.push({ type:type, label:meta.label, severity:meta.severity, prio:99,
      value:value, start:start, end:end, normalized:digits,
      validationStatus:"AMBIGUOUS", confidence:"LOW", reviewStatus:"NEEDS_REVIEW",
      validationDetail:detail });
  }
  return out;
}
