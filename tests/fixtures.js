/* =====================================================================
   PRIVASHIELD — tests/fixtures.js. Synthetic fixtures only — no
      real identifiers. Shared by the in-page suite (src/tests.js) and
      the Node suite (tests/privashield.test.js).
   ===================================================================== */

import Papa from 'papaparse';
import { detectAll, detect } from '../src/engine.js';
import { createPseudoStore, partialMask, replacementFor, applyRedactions } from '../src/redaction.js';
import { sanitize, isFormulaCell } from '../src/sanitizer.js';
import { state, sigOf, planReplacement } from '../src/session.js';
import { leakScan, classifyResidual, computeExposure, partialRawWeight, SENSITIVITY, PARTIAL_RESIDUAL_FACTOR, PRESETS, applyPreset, refreshPresetUI } from '../src/advanced.js';
import { DEMO_SAMPLES } from '../src/sampleData.js';
import { buildAuditReport } from '../src/report.js';

export const TEST_FIXTURES = [
  { type:"EMAIL", input:"reach aarav.sharma+alerts@mail.example.co.in today", expect:"CONFIRMED", note:"plus-addressing + subdomain" },
  { type:"EMAIL", input:"first.last+tag@sub.domain.example.com", expect:"CONFIRMED", note:"plus tag + multi-level subdomain" },
  { type:"EMAIL", input:"plain@example.com", expect:"CONFIRMED", note:"standard address" },
  { type:"EMAIL", input:"user@domain", expect:"NONE", note:"missing TLD" },
  { type:"EMAIL", input:"user@@example.com", expect:"NONE", note:"double @" },
  { type:"EMAIL", input:"user@example..com", expect:"NONE", note:"empty domain label" },
  { type:"EMAIL", input:"user@.com", expect:"NONE", note:"domain starts with dot" },
  { type:"PHONE", input:"call +91 98765 43210 now", expect:"CONFIRMED", note:"+91 spaced Indian mobile" },
  { type:"PHONE", input:"0091 98200 11223", expect:"CONFIRMED", note:"0091 prefix" },
  { type:"PHONE", input:"00919820011223", expect:"CONFIRMED", note:"0091 continuous" },
  { type:"PHONE", input:"mobile 98110 24680", expect:"CONFIRMED", note:"bare Indian mobile, grouped 5-5" },
  { type:"PHONE", input:"+1 (415) 555-0132", expect:"CONFIRMED", note:"US intl. with parentheses" },
  { type:"PHONE", input:"+44 20 7946 0958", expect:"CONFIRMED", note:"UK intl. format" },
  { type:"PHONE", input:"desk 011-4155-8899", expect:"CONFIRMED", note:"Indian landline STD format" },
  { type:"PHONE", input:"12345", expect:"NONE", note:"too short" },
  { type:"PHONE", input:"+91 12345 67890", expect:"NONE", note:"+91 but subscriber starts 1 (invalid)" },
  { type:"PHONE", input:"98765 4321", expect:"NONE", note:"9 digits only" },
  { type:"IP", input:"host 192.168.1.42 up", expect:"CONFIRMED", note:"private IPv4" },
  { type:"IP", input:"2001:0db8:85a3:0000:0000:8a2e:0370:7334", expect:"CONFIRMED", note:"full IPv6" },
  { type:"IP", input:"2001:db8::1", expect:"CONFIRMED", note:"compressed IPv6" },
  { type:"IP", input:"addr ::1 loopback", expect:"CONFIRMED", note:"IPv6 loopback" },
  { type:"IP", input:"fe80::a634:d9ff:fe07:c5a8", expect:"CONFIRMED", note:"link-local compressed" },
  { type:"IP", input:"::ffff:192.168.0.1", expect:"CONFIRMED", note:"IPv4-embedded IPv6" },
  { type:"IP", input:"999.10.2.3", expect:"NONE", note:"octet > 255" },
  { type:"IP", input:"256.256.256.256", expect:"NONE", note:"all octets > 255" },
  { type:"IP", input:"2001:::1", expect:"NONE", note:"triple colon" },
  { type:"IP", input:"1.2.3", expect:"NONE", note:"only 3 octets" },
  { type:"IP", input:"2001:db8:85a3", expect:"NONE", note:"too few IPv6 groups, no compression" },
  { type:"PAN", input:"PAN AAAPL1234C on file", expect:"CONFIRMED", note:"holder code P (Individual)" },
  { type:"PAN", input:"AAACT1234F", expect:"CONFIRMED", note:"holder code C (Company)" },
  { type:"PAN", input:"ABCDE1234F", expect:"NEEDS_REVIEW", note:"shape ok, 4th char D not a holder code" },
  { type:"PAN", input:"ABCD1234F", expect:"NONE", note:"only 4 leading letters" },
  { type:"PAN", input:"ABCDE12345", expect:"NONE", note:"ends with digit" },
  { type:"PAN", input:"abcde1234f", expect:"NONE", note:"lowercase rejected" },
  { type:"AADHAAR", input:"Aadhaar 2345 6789 0124", expect:"CONFIRMED", note:"Verhoeff-valid, spaced" },
  { type:"AADHAAR", input:"uid 345678901238", expect:"CONFIRMED", note:"Verhoeff-valid, continuous" },
  { type:"AADHAAR", input:"Aadhaar 2345 6789 0123", expect:"NEEDS_REVIEW", note:"format ok, Verhoeff fails" },
  { type:"AADHAAR", input:"1234 5678 9012", expect:"NONE", note:"leading digit 1 not allowed" },
  { type:"AADHAAR", input:"0000 1111 2222", expect:"NONE", note:"leading digit 0 not allowed" },
  { type:"AADHAAR", input:"2345 6789 012", expect:"NONE", note:"11 digits only" },
  { type:"CREDIT_CARD", input:"card 4111 1111 1111 1111", expect:"CONFIRMED", note:"Visa test, spaced, Luhn ok" },
  { type:"CREDIT_CARD", input:"4222222222222", expect:"CONFIRMED", note:"13-digit Visa, Luhn ok" },
  { type:"CREDIT_CARD", input:"3782 822463 10005", expect:"CONFIRMED", note:"Amex 4-6-5 grouping, Luhn ok" },
  { type:"CREDIT_CARD", input:"5500-0055-5555-5559", expect:"CONFIRMED", note:"Mastercard hyphenated, Luhn ok" },
  { type:"CREDIT_CARD", input:"6011 1111 1111 1117", expect:"CONFIRMED", note:"Discover, Luhn ok" },
  { type:"CREDIT_CARD", input:"card 4111 1111 1111 1112", expect:"NEEDS_REVIEW", note:"Luhn fails — Stage 3: 'card' context promotes it to an ambiguous candidate for manual review, not a silent reject" },
  { type:"CREDIT_CARD", input:"1234567890123456", expect:"NONE", note:"sequential 16 digits, Luhn fails" },
  { type:"CREDIT_CARD", input:"411111111111", expect:"NONE", note:"12 digits, below minimum length" }
];

/* ---------------- Stage 3 regression fixtures ----------------
   Overlap resolution, context-aware classification, and robust text
   handling (multiple entities per line, repeats, multiline, Unicode,
   tabs / NBSP, surrounding punctuation, timestamps, order numbers,
   empty input). Modes: default = first-of-type reviewStatus;
   "count" = detections of type; "total" = all detections;
   "none" = zero detections of any type. */
export const STAGE3_FIXTURES = [
  { type:"CREDIT_CARD", input:"card 4111 1111 1111 1111 charged", mode:"total", expectCount:1, note:"overlap: grouped card wins over the Aadhaar-fragment candidate inside it — counted once" },
  { type:"EMAIL", input:"mail a@b.co.in or user@example.com, call +91 98765 43210", mode:"total", expectCount:3, note:"multiple entities on the same line" },
  { type:"EMAIL", input:"user@example.com and again user@example.com", mode:"count", expectCount:2, note:"repeated identifier detected at both positions" },
  { type:"EMAIL", input:"संपर्क करें: user@example.com धन्यवाद ✓", expect:"CONFIRMED", note:"Unicode text surrounding an email" },
  { type:"EMAIL", input:"(user@example.com),", expect:"CONFIRMED", note:"punctuation surrounding identifier" },
  { type:"PHONE", input:"reach me at [+91 98765 43210].", expect:"CONFIRMED", note:"brackets + full stop around phone" },
  { type:"PHONE", input:"mobile:\t+91 98765 43210", expect:"CONFIRMED", note:"tab whitespace before phone" },
  { type:"AADHAAR", input:"aadhaar 2345 6789 0124", expect:"CONFIRMED", note:"non-breaking spaces as group separators" },
  { type:"EMAIL", input:"line1 user@example.com\nline2 +91 98765 43210\nline3 192.168.0.1", mode:"total", expectCount:3, note:"multiline document, one entity per line" },
  { type:"CREDIT_CARD", input:"card number 4111 1111 1111 1112 on file", expect:"NEEDS_REVIEW", note:"context promotion: Luhn-failing digits + 'card' keyword → ambiguous candidate" },
  { type:"AADHAAR", input:"aadhaar 1234 5678 9012 recorded", expect:"NEEDS_REVIEW", note:"context promotion: leading-1 digits + 'aadhaar' keyword → ambiguous candidate" },
  { type:"PHONE", input:"mobile 12345 67890 unreachable", expect:"NEEDS_REVIEW", note:"context promotion: invalid subscriber start + 'mobile' keyword → ambiguous candidate" },
  { type:"CREDIT_CARD", input:"invoice ref 1234567890123456 settled", expect:"NONE", note:"benign context veto: invoice/reference wording blocks card promotion" },
  { type:"PHONE", input:"order 1234567890 shipped", mode:"none", note:"order number is not a phone — no detection, no promotion" },
  { type:"IP", input:"logged at 2026-11-27 09:14:22.105 done", mode:"none", note:"timestamp fragments are not identifiers" },
  { type:"EMAIL", input:"", mode:"none", note:"empty input scans cleanly" }
];

/* CSV handling tests — run only when Papa Parse is available. */
export const CSV_TESTS = [
  { name:"quoted comma + multiline cell survive parse", run:function(){
      const rows = Papa.parse('name,note\n"Meera, K","mail meera@example.com\nsecond line"', { skipEmptyLines:true }).data;
      return rows.length === 2 && rows[1][0] === "Meera, K" && rows[1][1].indexOf("\n") !== -1;
  } },
  { name:"per-cell redaction keeps rows/cols, removes PII", run:function(){
      const src = 'name,email\n"Meera, K",meera@example.com';
      const rows = Papa.parse(src, { skipEmptyLines:false }).data;
      const out = rows.map(function(r){ return r.map(function(c){ const s = String(c == null ? "" : c); return sanitize(s, detect(s)); }); });
      const back = Papa.parse(Papa.unparse(out), { skipEmptyLines:false }).data;
      return back.length === 2 && back[1].length === 2 && back[1][0] === "Meera, K" && back[1][1] === "[REDACTED]";
  } },
  { name:"formula-leading cells flagged as spreadsheet risk", run:function(){
      return isFormulaCell("=2+5") && isFormulaCell("  @SUM(1+1)") && !isFormulaCell("normal text") && !isFormulaCell("[REDACTED]");
  } },
  { name:"headers preserved through sanitize round-trip", run:function(){
      const src = "name,email,phone\nAsha,asha@example.com,+91 98765 43210";
      const rows = Papa.parse(src, { skipEmptyLines:false }).data;
      const out = rows.map(function(r){ return r.map(function(c){ const s = String(c == null ? "" : c); return sanitize(s, detect(s)); }); });
      return out[0].join(",") === "name,email,phone" && out[1][1] === "[REDACTED]" && out[1][2] === "[REDACTED]";
  } }
];

/* ---------------- Stage 4 redaction tests ----------------
   Every mode, repeated identifiers, normalization variants, mode
   switching, manual overrides and mapping reset. All run against the
   production redaction module with fresh, throwaway stores — except
   the override test, which exercises the real state wiring and
   restores it afterwards. */
export function detOf(text, type){
  const all = detectAll(text);
  for (let i = 0; i < all.length; i++) if (all[i].type === type) return all[i];
  return null;
}

export const REDACTION_TESTS = [
  { name:"FULL: email replaced with [REDACTED], surrounding text untouched", run:function(){
      const t = "mail user@example.com end", ds = detectAll(t), s = createPseudoStore();
      return applyRedactions(t, ds, function(m){ return replacementFor(m, "FULL", s); }) === "mail [REDACTED] end";
  } },
  { name:"FULL: multiple entities, structure and punctuation preserved", run:function(){
      const t = "a user@example.com, ip 192.168.1.42!", ds = detectAll(t), s = createPseudoStore();
      return applyRedactions(t, ds, function(m){ return replacementFor(m, "FULL", s); }) === "a [REDACTED], ip [REDACTED]!";
  } },
  { name:"PARTIAL email: first/last local chars + domain ending only", run:function(){
      const d = detOf("aarav.sharma@example.com", "EMAIL");
      return d && partialMask(d) === "a***a@e***.com";
  } },
  { name:"PARTIAL phone: all but final four digits masked", run:function(){
      const d = detOf("call +91 98765 43210", "PHONE");
      return d && partialMask(d) === "***-***-3210";
  } },
  { name:"PARTIAL Aadhaar: XXXX XXXX + final four", run:function(){
      const d = detOf("Aadhaar 2345 6789 0124", "AADHAAR");
      return d && partialMask(d) === "XXXX XXXX 0124";
  } },
  { name:"PARTIAL PAN: first 2 + last 2 retained, middle masked", run:function(){
      const d = detOf("PAN AAAPL1234C", "PAN");
      return d && partialMask(d) === "AA******4C";
  } },
  { name:"PARTIAL card: **** **** **** + final four, no full digits leak", run:function(){
      const d = detOf("card 4111 1111 1111 1111", "CREDIT_CARD");
      const out = d && partialMask(d);
      return out === "**** **** **** 1111" && out.indexOf("4111") === -1;
  } },
  { name:"PARTIAL IPv4: first two octets kept, rest concealed", run:function(){
      const d = detOf("host 192.168.1.42", "IP");
      return d && partialMask(d) === "192.168.*.*";
  } },
  { name:"PARTIAL IPv6: only the first group kept", run:function(){
      const d = detOf("addr 2001:db8::1", "IP");
      return d && partialMask(d) === "2001:****:****:****:****";
  } },
  { name:"PSEUDO: repeated email gets the SAME alias at both positions", run:function(){
      const t = "user@example.com then user@example.com again", ds = detectAll(t), s = createPseudoStore();
      const out = applyRedactions(t, ds, function(m){ return replacementFor(m, "PSEUDO", s); });
      return out === "EMAIL_001 then EMAIL_001 again" && s.size() === 1;
  } },
  { name:"PSEUDO: different emails get DIFFERENT aliases", run:function(){
      const t = "a@x.com and b@y.com", ds = detectAll(t), s = createPseudoStore();
      const out = applyRedactions(t, ds, function(m){ return replacementFor(m, "PSEUDO", s); });
      return out === "EMAIL_001 and EMAIL_002" && s.size() === 2;
  } },
  { name:"PSEUDO: phone formatting variants share one alias (normalization)", run:function(){
      const t = "call +91 98765 43210 or 9876543210", ds = detectAll(t), s = createPseudoStore();
      const phones = ds.filter(function(m){ return m.type === "PHONE"; });
      if (phones.length !== 2) return false;
      return s.getAlias(phones[0]) === "PHONE_001" && s.getAlias(phones[1]) === "PHONE_001" && s.size() === 1;
  } },
  { name:"PSEUDO: card formatting variants share one alias (normalization)", run:function(){
      const t = "cards 4111 1111 1111 1111 and 4111111111111111", ds = detectAll(t), s = createPseudoStore();
      const cards = ds.filter(function(m){ return m.type === "CREDIT_CARD"; });
      if (cards.length !== 2) return false;
      return s.getAlias(cards[0]) === "CARD_001" && s.getAlias(cards[1]) === "CARD_001";
  } },
  { name:"PSEUDO: aliases stable across mode switching (FULL detour changes nothing)", run:function(){
      const d = detOf("user@example.com", "EMAIL"), s = createPseudoStore();
      const a1 = replacementFor(d, "PSEUDO", s);
      replacementFor(d, "FULL", s); replacementFor(d, "PARTIAL", s);
      const a2 = replacementFor(d, "PSEUDO", s);
      return a1 === "EMAIL_001" && a2 === "EMAIL_001" && s.size() === 1;
  } },
  { name:"PSEUDO: per-type counters are independent (EMAIL_001 and PHONE_001 coexist)", run:function(){
      const t = "user@example.com +91 98765 43210", ds = detectAll(t), s = createPseudoStore();
      const out = applyRedactions(t, ds, function(m){ return replacementFor(m, "PSEUDO", s); });
      return out === "EMAIL_001 PHONE_001";
  } },
  { name:"RESET: mapping reset wipes aliases and restarts counters", run:function(){
      const s = createPseudoStore();
      const d1 = detOf("first@example.com", "EMAIL");
      if (s.getAlias(d1) !== "EMAIL_001") return false;
      s.reset();
      if (s.size() !== 0) return false;
      const d2 = detOf("second@example.com", "EMAIL");
      return s.getAlias(d2) === "EMAIL_001"; /* a different value reuses 001 only because the store was reset */
  } },
  { name:"OVERRIDE: one occurrence forced to PARTIAL while global mode is FULL (real state wiring)", run:function(){
      const savedMode = state.mode, savedOvr = state.overrides, savedStore = state.pseudoStore;
      try {
        state.mode = "FULL"; state.overrides = {}; state.pseudoStore = createPseudoStore();
        const t = "user@example.com and other@example.com", ds = detectAll(t);
        if (ds.length !== 2) return false;
        ds.forEach(function(m){ m.userDecision = null; });
        state.overrides[sigOf(ds[0])] = "PARTIAL";
        const r0 = planReplacement(ds[0]), r1 = planReplacement(ds[1]);
        return r0 === "u***r@e***.com" && r1 === "[REDACTED]";
      } finally {
        state.mode = savedMode; state.overrides = savedOvr; state.pseudoStore = savedStore;
      }
  } },
  { name:"OVERRIDE KEEP + category off leave values visible (plan returns null)", run:function(){
      const savedOvr = state.overrides, savedCats = state.categories;
      try {
        state.overrides = {}; state.categories = { EMAIL:true, PHONE:true, IP:true, PAN:true, AADHAAR:true, CREDIT_CARD:true };
        const d = detOf("user@example.com", "EMAIL"); d.userDecision = null;
        state.overrides[sigOf(d)] = "KEEP";
        if (planReplacement(d) !== null) return false;
        delete state.overrides[sigOf(d)];
        state.categories.EMAIL = false;
        return planReplacement(d) === null;
      } finally {
        state.overrides = savedOvr; state.categories = savedCats;
      }
  } },
  { name:"COUNTS: total occurrences, unique entities and redacted are separate numbers", run:function(){
      const t = "user@example.com user@example.com +91 98765 43210", ds = detectAll(t), s = createPseudoStore();
      const uniq = {}; ds.forEach(function(m){ uniq[m.type + "|" + m.normalized] = true; });
      const out = applyRedactions(t, ds, function(m){ return replacementFor(m, "FULL", s); });
      return ds.length === 3 && Object.keys(uniq).length === 2 && out === "[REDACTED] [REDACTED] [REDACTED]";
  } },
  { name:"OFFSETS: long pseudonym replacements never corrupt following text", run:function(){
      const t = "x user@example.com y 192.168.1.42 z", ds = detectAll(t), s = createPseudoStore();
      const out = applyRedactions(t, ds, function(m){ return replacementFor(m, "PSEUDO", s); });
      return out === "x EMAIL_001 y IP_001 z";
  } },
  { name:"CSV PSEUDO: same value across rows keeps one alias, structure preserved", run:function(){
      if (!Papa) return true;
      const src = "name,email\nAsha,asha@example.com\nBala,asha@example.com";
      const rows = Papa.parse(src, { skipEmptyLines:false }).data;
      const s = createPseudoStore();
      const out = rows.map(function(r){ return r.map(function(c){ const cs = String(c == null ? "" : c); return applyRedactions(cs, detect(cs), function(x){ return replacementFor(x, "PSEUDO", s); }); }); });
      return out[0].join(",") === "name,email" && out[1][1] === "EMAIL_001" && out[2][1] === "EMAIL_001" && s.size() === 1;
  } }
];

/* ---------------- Stage 6 tests ----------------
   Leak Guard second pass, exposure-score determinism, preset
   integrity (no silent category exclusion), demo-lab coverage and
   audit-report contents (including the no-PII-in-report rule). */
export const STAGE6_TESTS = [
  { name:"LEAK GUARD: fully masked output re-scans clean (0 remaining)", run:function(){
      const t = "mail user@example.com, card 4111 1111 1111 1111, ip 192.168.1.42";
      const ds = detectAll(t), s = createPseudoStore();
      const out = applyRedactions(t, ds, function(m){ return replacementFor(m, "FULL", s); });
      return leakScan(out).length === 0;
  } },
  { name:"LEAK GUARD: a value left in the output is found by the second pass", run:function(){
      const found = leakScan("mail user@example.com end");
      return found.length === 1 && found[0].type === "EMAIL";
  } },
  { name:"LEAK GUARD: excluded detection is classified with reason EXCLUDED", run:function(){
      const ds = detectAll("mail user@example.com end");
      ds[0].userDecision = "EXCLUDED";
      const c = classifyResidual({ type:"EMAIL", normalized:ds[0].normalized }, ds);
      return c.reason === "EXCLUDED" && c.source === ds[0];
  } },
  { name:"LEAK GUARD: partial masks leave no scannable pattern but still count as residual exposure", run:function(){
      const savedMode = state.mode, savedPlan = state.plan;
      try {
        state.mode = "PARTIAL";
        const t = "card 4111 1111 1111 1111", ds = detectAll(t), s = createPseudoStore();
        ds.forEach(function(m){ m.userDecision = null; });
        const plan = {};
        ds.forEach(function(m){ plan[sigOf(m)] = replacementFor(m, "PARTIAL", s); });
        state.plan = plan;
        const pw = partialRawWeight(ds);
        const out = applyRedactions(t, ds, function(m){ return plan[sigOf(m)]; });
        return leakScan(out).length === 0 && pw === SENSITIVITY.CREDIT_CARD * PARTIAL_RESIDUAL_FACTOR;
      } finally { state.mode = savedMode; state.plan = savedPlan; }
  } },
  { name:"EXPOSURE: empty document scores 0 before and after, reduction n/a", run:function(){
      const e = computeExposure([], [], 0);
      return e.before === 0 && e.after === 0 && e.reduction === null;
  } },
  { name:"EXPOSURE: deterministic — one Aadhaar scores 17, full removal is a 100% reduction", run:function(){
      const ds = detectAll("Aadhaar 2345 6789 0124");
      const e1 = computeExposure(ds, [], 0), e2 = computeExposure(ds, [], 0);
      return e1.before === 17 && e1.after === 0 && e1.reduction === 100 && e2.before === 17;
  } },
  { name:"EXPOSURE: kept-visible residual keeps the after score at the before score", run:function(){
      const ds = detectAll("mail user@example.com");
      const e = computeExposure(ds, ds, 0);
      return e.before === 9 && e.after === 9 && e.reduction === 0;
  } },
  { name:"PRESETS: every preset has a valid redaction mode and an explanatory note", run:function(){
      return Object.keys(PRESETS).every(function(k){
        const p = PRESETS[k];
        return ["FULL","PARTIAL","PSEUDO"].indexOf(p.mode) !== -1 && typeof p.note === "string" && p.note.length > 20;
      });
  } },
  { name:"PRESETS: applying Finance sets FULL mode and re-enables every category (no silent exclusion)", run:function(){
      const sm = state.mode, sc = state.categories, sp = state.preset;
      try {
        state.categories = { EMAIL:false, PHONE:true, IP:true, PAN:true, AADHAAR:true, CREDIT_CARD:true };
        applyPreset("finance", function(m){ state.mode = m; });
        return state.mode === "FULL" && state.preset === "finance" && Object.keys(state.categories).every(function(t){ return state.categories[t]; });
      } finally {
        state.mode = sm; state.categories = sc; state.preset = sp;
        refreshPresetUI(PRESETS[sp] ? PRESETS[sp].note : null);
      }
  } },
  { name:"DEMO LAB: every synthetic sample is labelled and exercises at least 3 PII categories", run:function(){
      return Object.keys(DEMO_SAMPLES).every(function(k){
        const txt = DEMO_SAMPLES[k];
        if (txt.indexOf("SYNTHETIC DEMO") !== 0) return false;
        const types = {};
        detectAll(txt).forEach(function(m){ types[m.type] = true; });
        return Object.keys(types).length >= 3;
      });
  } },
  { name:"AUDIT: report totals match the scan and the JSON contains no original PII values", run:function(){
      const saved = { text:state.text, matches:state.matches, sanitized:state.sanitized, mode:state.mode, plan:state.plan, rc:state.redactedCount, leak:state.leak, exp:state.exposure, dec:state.decisions, ovr:state.overrides };
      try {
        state.text = "mail user@example.com or user@example.com, card 4111 1111 1111 1111";
        state.decisions = {}; state.overrides = {};
        state.matches = detectAll(state.text);
        state.matches.forEach(function(m){ m.userDecision = null; m.baseReview = m.reviewStatus; });
        state.mode = "FULL";
        state.plan = {}; state.redactedCount = 0;
        state.matches.forEach(function(m){ const rep = planReplacement(m); state.plan[sigOf(m)] = rep; if (rep !== null) state.redactedCount++; });
        state.sanitized = applyRedactions(state.text, state.matches, function(m){ return state.plan[sigOf(m)]; });
        state.leak = null; state.exposure = null;
        const r = buildAuditReport();
        const json = JSON.stringify(r);
        return r.totals.detectedOccurrences === 3 && r.totals.uniqueEntities === 2 && r.totals.redactedOccurrences === 3 &&
               r.leakGuard.remainingSupportedMatches === 0 && r.exposureScore.before > 0 && r.exposureScore.after === 0 &&
               json.indexOf("user@example.com") === -1 && json.indexOf("4111") === -1 && r.redactionMode === "FULL";
      } finally {
        state.text = saved.text; state.matches = saved.matches; state.sanitized = saved.sanitized; state.mode = saved.mode; state.plan = saved.plan;
        state.redactedCount = saved.rc; state.leak = saved.leak; state.exposure = saved.exp; state.decisions = saved.dec; state.overrides = saved.ovr;
      }
  } }
];

export function evalFixture(f){
  const all = detectAll(f.input);
  if (f.mode === "none") return { got: all.length ? all.length + " detection(s)" : "NONE", ok: all.length === 0 };
  if (f.mode === "total") return { got: all.length + " total", ok: all.length === f.expectCount };
  if (f.mode === "count"){
    const c = all.filter(function(e){ return e.type === f.type; }).length;
    return { got: c + " × " + f.type, ok: c === f.expectCount };
  }
  const found = all.filter(function(e){ return e.type === f.type; });
  const got = found.length ? found[0].reviewStatus : "NONE";
  return { got: got, ok: got === f.expect };
}
