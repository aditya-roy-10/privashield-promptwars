/* =====================================================================
   PRIVASHIELD — main.js. App bootstrap: scan pipeline, render,
      analytics, locate, mode/category controls, wiring and the hash
      router (landing #/ · workspace #/app). Entry point for Vite.
   ===================================================================== */

import { SAMPLE_TEXT, PROMPT_LOG_MD, DEMO_SAMPLES } from './sampleData.js';
import { TYPE_META, SEV_WEIGHT, DETECTORS } from './detectors.js';
import { detectAll, engineStats, freshEngineStats, setEngineStats, setLuhnRejected } from './engine.js';
import { state, sigOf, $, els, bindElements, toast, scanCache } from './session.js';
import { escapeHtml, renderHighlighted, renderSanitizedHtml, renderSanitizedRich, truncateVal } from './sanitizer.js';
import { applyDecisions, reviewAction } from './review.js';
import { markPresetCustom, refreshPresetUI, applyPreset, renderAdvanced, resolveLeak, hideExportGuard, pendingExport, SENSITIVITY } from './advanced.js';
import { downloadReport } from './report.js';
import { loadText, handleFile, clearSession, downloadSanitized, downloadAs, copySanitized } from './files.js';
import { WORKER_THRESHOLD, createEngineWorker } from './perf.js';
import { runTests } from './tests.js';

var workerObj = null, workerReq = 0, workerPendingText = null, workerFailed = false;

function getWorker(){
  if (workerObj || workerFailed) return workerObj;
  try {
    workerObj = createEngineWorker();
    if (!workerObj){ workerFailed = true; return null; }
    workerObj.onmessage = function(e){
      if (!e.data || e.data.id !== workerReq) return; /* stale response — a newer scan or reset superseded it */
      var doneText = workerPendingText;
      workerPendingText = null;
      setEngineStats(e.data.stats); setLuhnRejected(engineStats.rejectedLuhn);
      scanCache.text = doneText; scanCache.matches = e.data.matches;
      if (els.input.value === doneText) finishProcess(); else process();
    };
    workerObj.onerror = function(){
      workerFailed = true; workerObj = null;
      ++workerReq; workerPendingText = null;
      var t = els.input.value;
      scanCache.text = t;
      if (!t){ scanCache.matches = []; setEngineStats(freshEngineStats()); setLuhnRejected(0); }
      else { scanCache.matches = detectAll(t); }
      finishProcess();
    };
    return workerObj;
  } catch (e) { workerFailed = true; return null; }
}

export function process(){
  clearTimeout(debounce);
  var text = els.input.value;
  state.text = text;
  if (text === scanCache.text){ ++workerReq; workerPendingText = null; finishProcess(); return; }
  if (!text){ ++workerReq; workerPendingText = null; scanCache.text = text; scanCache.matches = []; setEngineStats(freshEngineStats()); setLuhnRejected(0); finishProcess(); return; }
  if (text.length >= WORKER_THRESHOLD && window.Worker){
    var w = getWorker();
    if (w){
      workerPendingText = text;
      var id = ++workerReq;
      $("procStatus").innerHTML = '<span class="dot"></span> SCANNING — large input (' + text.length.toLocaleString() + ' chars) in background Web Worker';
      w.postMessage({ id:id, text:text });
      return;
    }
  }
  ++workerReq; workerPendingText = null;
  scanCache.text = text; scanCache.matches = detectAll(text);
  finishProcess();
}

function finishProcess(){
  state.matches = scanCache.matches;
  applyDecisions();
  render();
}

/* Stage 4 controls — all three re-render from the cached scan, so
   switching is instant and no detector re-runs. The pseudonym store
   is deliberately NOT touched here: aliases must survive mode and
   filter changes within the same document session. */
function setMode(mode){
  state.mode = mode;
  markPresetCustom();
  ["FULL","PARTIAL","PSEUDO"].forEach(function(k){
    var btn = $("mode" + (k === "FULL" ? "Full" : k === "PARTIAL" ? "Partial" : "Pseudo"));
    if (btn) btn.classList.toggle("active", state.mode === k);
  });
  applyDecisions();
  render();
  toast(mode === "FULL" ? "Full Mask — every approved value becomes [REDACTED]." : mode === "PARTIAL" ? "Partial Mask — verification fragments remain visible. Treat the output as still sensitive." : "Pseudonymization — repeated values share one stable alias for this document session.");
}

function toggleCategory(type){
  state.categories[type] = !state.categories[type];
  markPresetCustom();
  var chip = document.querySelector('.cat-chip[data-cat="' + type + '"]');
  if (chip) chip.classList.toggle("off", !state.categories[type]);
  applyDecisions();
  render();
  toast(TYPE_META[type].label + (state.categories[type] ? " redaction ON." : " redaction OFF — those values stay visible in the output."), !state.categories[type]);
}

function setOverride(id, mode){
  var m = null;
  state.matches.forEach(function(x){ if (x.id === id) m = x; });
  if (!m) return;
  var sig = sigOf(m);
  if (!mode) delete state.overrides[sig];
  else state.overrides[sig] = mode;
  applyDecisions();
  render();
  toast(mode ? (id + " override: " + mode + " for this occurrence only.") : (id + " override cleared — global mode applies."));
}

function render(){
  var text = state.text, matches = state.matches, active = state.activeMatches;
  var excludedCount = matches.length - active.length;
  /* stats */
  var chars = text.length;
  var words = text.trim() ? text.trim().split(/\s+/).length : 0;
  var lines = text ? text.split("\n").length : 0;
  $("statChars").textContent = chars.toLocaleString() + " chars";
  $("statWords").textContent = words.toLocaleString() + " words";
  $("statLines").textContent = lines.toLocaleString() + " lines";
  $("statUpdated").textContent = text ? "Processed locally · " + new Date().toLocaleTimeString() : "Awaiting input";

  /* counts + validated/candidate splits — active (non-excluded) set */
  var counts = { EMAIL:0, PHONE:0, IP:0, PAN:0, AADHAAR:0, CREDIT_CARD:0 };
  var confirmed = { EMAIL:0, PHONE:0, IP:0, PAN:0, AADHAAR:0, CREDIT_CARD:0 };
  var checksumValid = { AADHAAR:0, CREDIT_CARD:0 };
  var approvedCand = { AADHAAR:0, CREDIT_CARD:0 };
  var candCount = { EMAIL:0, PHONE:0, IP:0, PAN:0, AADHAAR:0, CREDIT_CARD:0 };
  var ipV6 = 0;
  active.forEach(function(m){
    counts[m.type]++;
    if (m.reviewStatus === "CONFIRMED") confirmed[m.type]++; else candCount[m.type]++;
    if (m.type === "AADHAAR" || m.type === "CREDIT_CARD"){
      if (m.validationStatus === "CHECKSUM_VALID") checksumValid[m.type]++;
      else if (m.reviewStatus === "CONFIRMED") approvedCand[m.type]++;
    }
    if (m.type === "IP" && m.value.indexOf(":") !== -1) ipV6++;
  });
  Object.keys(counts).forEach(function(k){ $("cnt-" + k).textContent = counts[k]; });
  function subLine(k, base){
    if (!counts[k]) return base;
    var s = "<b>" + confirmed[k] + " validated</b>";
    if (candCount[k]) s += ' · <span class="cand">' + candCount[k] + " candidate</span>";
    return s;
  }
  $("sub-EMAIL").innerHTML = subLine("EMAIL", "format-validated");
  $("sub-PHONE").innerHTML = subLine("PHONE", "normalized to E.164-style");
  $("sub-IP").innerHTML = counts.IP ? ("<b>" + (counts.IP - ipV6) + " IPv4</b> · <b>" + ipV6 + " IPv6</b>") : "v4 + v6";
  $("sub-PAN").innerHTML = subLine("PAN", "structure-validated");
  $("sub-AADHAAR").innerHTML = counts.AADHAAR ? ("<b>" + checksumValid.AADHAAR + " checksum-valid</b>" + (approvedCand.AADHAAR ? " · " + approvedCand.AADHAAR + " approved" : "") + (candCount.AADHAAR ? ' · <span class="cand">' + candCount.AADHAAR + " candidate</span>" : "")) : "checksum vs candidate split";
  $("sub-CREDIT_CARD").innerHTML = counts.CREDIT_CARD ? ("<b>" + checksumValid.CREDIT_CARD + " Luhn-valid</b>" + (approvedCand.CREDIT_CARD ? " · " + approvedCand.CREDIT_CARD + " approved" : "") + (candCount.CREDIT_CARD ? ' · <span class="cand">' + candCount.CREDIT_CARD + " candidate</span>" : "")) : "Luhn-validated only";

  var unique = {};
  active.forEach(function(m){ unique[m.type + "|" + m.normalized] = true; });
  var uniqueCount = Object.keys(unique).length;

  /* risk — computed on the active set: excluded values stay exposed */
  var raw = 0;
  active.forEach(function(m){ raw += SEV_WEIGHT[TYPE_META[m.type].severity] || 5; });
  var risk = Math.min(100, raw);
  var riskLabel = "—", riskColor = "var(--emerald)";
  if (matches.length){
    if (risk >= 70){ riskLabel = "SEVERE"; riskColor = "#f87171"; }
    else if (risk >= 40){ riskLabel = "HIGH"; riskColor = "#fb923c"; }
    else if (risk >= 18){ riskLabel = "MEDIUM"; riskColor = "#fbbf24"; }
    else { riskLabel = "LOW"; riskColor = "#34d399"; }
  }
  $("kpiTotal").textContent = matches.length;
  $("kpiTotalSub").textContent = matches.length ? (active.length + " to redact across " + Object.keys(counts).filter(function(k){return counts[k]>0;}).length + " entity types" + (excludedCount ? " · " + excludedCount + " excluded" : "")) : (text ? "No PII detected in current input" : "No input processed yet");
  $("kpiUnique").textContent = uniqueCount;
  $("riskFill").style.width = risk + "%";
  $("riskFill").style.background = riskColor;
  $("kpiRiskSub").textContent = active.length ? ("Exposure risk " + riskLabel + " · " + risk + " / 100") : "Exposure risk —";
  var candTotal = active.filter(function(m){ return m.reviewStatus === "NEEDS_REVIEW"; }).length;
  $("procStatus").innerHTML = '<span class="dot"></span> ' + (!text ? "IDLE — awaiting input" : (matches.length ? ("PII FOUND — " + active.length + " to redact" + (candTotal ? " · " + candTotal + " candidate(s) need review" : "") + (excludedCount ? " · " + excludedCount + " excluded" : "")) : "CLEAN — scanned locally, nothing matched"));

  /* views */
  if (!text){
    els.highlight.className = "codebox empty";
    els.highlight.textContent = "Detections will be highlighted here as you type.";
    els.sanitized.className = "codebox empty";
    els.sanitized.textContent = "Sanitized text will appear here — replacements follow the redaction mode selected above.";
  } else {
    els.highlight.className = "codebox";
    els.highlight.innerHTML = renderHighlighted(text, matches);
    els.sanitized.className = "codebox";
    els.sanitized.innerHTML = renderSanitizedRich(text, matches);
  }
  /* Stage 5: line-number gutters — sanitized output preserves the
     original line structure (replacements never contain newlines),
     so both panes share the same numbering. */
  var gutterText = "";
  if (text){ var nums = []; for (var ln = 1; ln <= lines; ln++) nums.push(ln); gutterText = nums.join("\n"); }
  $("gutterOrig").textContent = gutterText;
  $("gutterSan").textContent = gutterText;

  /* Stage 4 stats — total occurrences, unique entities and redacted
     occurrences are three different numbers and are shown separately */
  var allUnique = {};
  matches.forEach(function(m){ allUnique[m.type + "|" + m.normalized] = true; });
  var keptCount = matches.length - state.redactedCount;
  $("rsTotal").textContent = matches.length;
  $("rsUnique").textContent = Object.keys(allUnique).length;
  $("kpiUnique").textContent = Object.keys(allUnique).length;
  $("rsRedacted").textContent = state.redactedCount;
  $("rsKept").textContent = keptCount;
  /* Stage 5 headline cards: redacted occurrences + remaining matches */
  $("kpiRedacted").textContent = state.redactedCount;
  $("kpiRedactedSub").textContent = matches.length ? ("Replaced in the sanitized output · " + state.mode + " mode") : "Replaced in the sanitized output";
  $("kpiRemaining").textContent = keptCount;
  $("kpiRemainingSub").textContent = matches.length ? (keptCount ? "Still visible — excluded, category off or Keep override" : "Nothing left visible — full coverage") : "Supported matches still visible in the output";
  renderAnalytics();
  renderAdvanced();
  $("partialWarn").classList.toggle("show", state.mode === "PARTIAL" || Object.keys(state.overrides).some(function(k){ return state.overrides[k] === "PARTIAL"; }));
  $("pseudoWarn").classList.toggle("show", state.mode === "PSEUDO" || Object.keys(state.overrides).some(function(k){ return state.overrides[k] === "PSEUDO"; }));
  var modeNames = { FULL:"FULL MASK → [REDACTED]", PARTIAL:"PARTIAL MASK → type-specific fragments", PSEUDO:"PSEUDONYMIZATION → stable aliases" };
  $("engineNote").textContent = "Mode: " + modeNames[state.mode] + " · context-aware · manual review on";
  $("modeNote").innerHTML = state.mode === "FULL"
    ? "<strong>Full Mask</strong> — every approved detection is replaced with <code style=\"font-family:var(--mono)\">[REDACTED]</code>. Surrounding text and document structure are preserved exactly; replacements are applied against the original offsets, so later matches never shift."
    : state.mode === "PARTIAL"
    ? "<strong>Partial Mask</strong> — type-specific policies: email keeps its first/last local characters and domain ending, phone &amp; card keep only the last 4 digits, Aadhaar shows <code style=\"font-family:var(--mono)\">XXXX XXXX 1234</code>, PAN keeps its first 2 and last 2 characters, IPv4 keeps its first two octets and IPv6 only its first group. <strong>Warning:</strong> these fragments can still identify someone — see the warning below."
    : "<strong>Consistent Pseudonymization</strong> — each unique normalized value gets one stable alias (<code style=\"font-family:var(--mono)\">EMAIL_001</code>, <code style=\"font-family:var(--mono)\">PHONE_001</code>, <code style=\"font-family:var(--mono)\">CARD_001</code>…); repeats and formatting variants share it, so relationships across the document (and across CSV rows) survive. Aliases stay stable when you switch modes or filters in this session. This is <strong>not</strong> irreversible anonymization — see the warning below.";
  var pm = $("pseudoMap");
  if (state.pseudoStore.size()){
    pm.classList.add("show");
    pm.innerHTML = state.pseudoStore.aliases().map(function(a){ return '<span class="pm-chip">' + escapeHtml(a) + "</span>"; }).join("") +
      '<span class="pm-note">' + state.pseudoStore.size() + " alias(es) assigned in this document session. The alias list above shows placeholders only — the original-to-alias mapping itself is never displayed as a table, never exported, and lives only in this tab's memory.</span>";
  } else {
    pm.classList.remove("show");
    pm.innerHTML = "";
  }
  $("sanLegend").innerHTML = state.mode === "PSEUDO"
    ? '<i style="background:#38bdf8"></i><span class="pseudo" style="font-family:var(--mono);font-size:11px">EMAIL_001</span>&nbsp;stable alias per unique value · same value, same alias, everywhere'
    : state.mode === "PARTIAL"
    ? '<i style="background:var(--amber)"></i><span class="partial" style="font-family:var(--mono);font-size:11px">**** **** **** 1111</span>&nbsp;partial mask · verification fragments remain visible — still sensitive'
    : '<i style="background:var(--emerald)"></i><span class="redacted" style="font-family:var(--mono);font-size:11px">[REDACTED]</span>&nbsp;marks every removed value · safe to share';
  $("hlCount").textContent = active.length + " highlighted" + (candTotal ? " · " + candTotal + " candidate" : "") + (excludedCount ? " · " + excludedCount + " excluded" : "");
  var rej = [];
  if (engineStats.rejectedLuhn) rej.push(engineStats.rejectedLuhn + " rejected by Luhn");
  if (engineStats.rejectedIP) rej.push(engineStats.rejectedIP + " rejected by IP validation");
  if (engineStats.rejectedOther) rej.push(engineStats.rejectedOther + " rejected by format rules");
  if (engineStats.overlapsResolved) rej.push(engineStats.overlapsResolved + " overlap(s) resolved");
  if (engineStats.ambiguousSurfaced) rej.push(engineStats.ambiguousSurfaced + " ambiguous candidate(s) surfaced by context");
  $("luhnNote").textContent = rej.length ? rej.join(" · ") : "";

  /* kept-visible warning: excluded values, KEEP overrides and
     switched-off categories all leave plain text in the output */
  if (keptCount){
    var reasons = [];
    if (excludedCount) reasons.push(excludedCount + " excluded by reviewer");
    var catOff = matches.filter(function(m){ return !state.categories[m.type] && m.userDecision !== "EXCLUDED"; }).length;
    if (catOff) reasons.push(catOff + " in switched-off categories");
    var keepOvr = matches.filter(function(m){ return state.overrides[sigOf(m)] === "KEEP" && m.userDecision !== "EXCLUDED" && state.categories[m.type]; }).length;
    if (keepOvr) reasons.push(keepOvr + " set to Keep by override");
    $("reviewWarn").classList.add("show");
    $("reviewWarnText").innerHTML = "<strong>" + keptCount + " detection" + (keptCount > 1 ? "s remain" : " remains") + " visible.</strong> " + reasons.join(" · ") + " — those values appear in plain text in the sanitized output and in any downloaded file. Change them from the findings register if that was not intended.";
  } else {
    $("reviewWarn").classList.remove("show");
  }

  /* buttons */
  var has = text.length > 0;
  $("btnDownload").disabled = !has; $("btnDownload2").disabled = !has;
  $("btnCopy").disabled = !has; $("btnCopy2").disabled = !has;
  $("btnCopy3").disabled = !has;
  $("btnExportTxt").disabled = !has; $("btnExportCsv").disabled = !has; $("btnExportCopy").disabled = !has;
  $("btnReportTxt").disabled = !has; $("btnReportJson").disabled = !has;

  /* findings */
  if (!matches.length){
    els.findings.innerHTML = '<tr class="empty-row"><td colspan="11">' + (text ? "Scan complete — no PII detected in this input." : "No detections yet. Load the sample data or paste text containing PII.") + "</td></tr>";
    return;
  }
  var lineStarts = [0];
  for (var i = 0; i < text.length; i++){ if (text[i] === "\n") lineStarts.push(i + 1); }
  function posOf(m){
    var lo = 0, hi = lineStarts.length - 1;
    while (lo < hi){ var mid = Math.ceil((lo + hi) / 2); if (lineStarts[mid] <= m.start) lo = mid; else hi = mid - 1; }
    return "L" + (lo + 1) + " · " + m.start + "–" + m.end;
  }
  els.findings.innerHTML = matches.map(function(m){
    var meta = TYPE_META[m.type];
    var sevClass = meta.severity === "CRITICAL" ? "crit" : meta.severity === "HIGH" ? "high" : meta.severity === "MEDIUM" ? "med" : "low";
    var isCand = m.reviewStatus === "NEEDS_REVIEW";
    var isExcluded = m.userDecision === "EXCLUDED";
    var pill = '<span class="val-pill ' + (isCand ? "cand" : "ok") + '" title="' + escapeHtml(m.validationDetail) + '">' + m.validationStatus.replace(/_/g, " ") + "</span>" +
               (isCand ? '<div class="review-cand">NEEDS REVIEW</div>' : "") +
               (m.userDecision === "APPROVED" ? '<div class="review-cand" style="color:var(--emerald-bright)">APPROVED BY REVIEWER</div>' : "");
    var reviewCell;
    if (isExcluded){
      reviewCell = '<span class="rev-state">EXCLUDED — KEPT VISIBLE</span><button class="rev-btn plain" type="button" data-act="restore" data-id="' + m.id + '">Restore</button>';
    } else {
      reviewCell = (isCand && m.userDecision !== "APPROVED" ? '<button class="rev-btn" type="button" data-act="approve" data-id="' + m.id + '">Approve</button>' : "") +
                   (m.userDecision === "APPROVED" ? '<span class="rev-state ok">APPROVED</span>' : "") +
                   '<button class="rev-btn warn" type="button" data-act="exclude" data-id="' + m.id + '">Exclude</button>';
    }
    reviewCell = '<button class="rev-btn plain" type="button" data-locate="' + m.id + '" title="Scroll the original document to this occurrence">Locate</button>' + reviewCell;
    return '<tr' + (isExcluded ? ' class="excluded"' : "") + ">" +
      '<td class="mono">' + m.id + "</td>" +
      '<td><span class="type-tag" style="--tc:' + meta.color + '"><i></i>' + meta.label.toUpperCase() + "</span></td>" +
      '<td class="mono" title="' + escapeHtml(m.value) + '">' + escapeHtml(truncateVal(m.value)) + "</td>" +
      '<td class="mono" title="' + escapeHtml(m.normalized) + '">' + escapeHtml(truncateVal(m.normalized)) + "</td>" +
      "<td>" + pill + "</td>" +
      '<td><span class="conf ' + m.confidence + '">' + m.confidence + "</span></td>" +
      '<td><span class="sev ' + sevClass + '">' + meta.severity + "</span></td>" +
      '<td class="mono">' + posOf(m) + "</td>" +
      (m.replacement === null || m.replacement === undefined ? '<td class="mono" style="color:var(--amber)">KEPT — NOT REDACTED</td>' : '<td class="mono" style="color:var(--emerald-bright)">' + escapeHtml(truncateVal(m.replacement)) + "</td>") +
      '<td><select class="ovr" data-ovr="' + m.id + '" aria-label="Redaction override for ' + m.id + '">' +
        '<option value=""' + (!state.overrides[sigOf(m)] ? " selected" : "") + ">Auto (" + state.mode + ")</option>" +
        '<option value="FULL"' + (state.overrides[sigOf(m)] === "FULL" ? " selected" : "") + ">Full mask</option>" +
        '<option value="PARTIAL"' + (state.overrides[sigOf(m)] === "PARTIAL" ? " selected" : "") + ">Partial mask</option>" +
        '<option value="PSEUDO"' + (state.overrides[sigOf(m)] === "PSEUDO" ? " selected" : "") + ">Pseudonym</option>" +
        '<option value="KEEP"' + (state.overrides[sigOf(m)] === "KEEP" ? " selected" : "") + ">Keep visible</option>" +
      "</select></td>" +
      "<td>" + reviewCell + "</td>" +
    "</tr>";
  }).join("");
}

/* ---------------- Stage 5: analytics + locate ----------------
   Every number below is computed from state.matches / state.plan at
   render time — nothing is hardcoded. The donut is hand-built SVG
   arcs (stroke-dasharray segments) in the per-type colours, with
   text labels in the legend so colour is never the only signal. */
function renderAnalytics(){
  var total = state.matches.length;
  $("analyticsEmpty").style.display = total ? "none" : "";
  $("analyticsGrid").style.display = total ? "" : "none";
  $("analyticsNote").textContent = total ? (total + " detection(s) · " + state.redactedCount + " redacted · " + (total - state.redactedCount) + " remaining") : "No data yet";
  if (!total) return;
  var per = {}, order = [];
  DETECTORS.forEach(function(d){ per[d.type] = 0; order.push(d.type); });
  state.matches.forEach(function(m){ per[m.type]++; });
  var C = 2 * Math.PI * 70, off = 0, segs = "";
  order.forEach(function(t){
    if (!per[t]) return;
    var frac = per[t] / total, len = Math.max(0, frac * C - 2);
    segs += '<circle cx="95" cy="95" r="70" fill="none" stroke-width="26" style="stroke:' + TYPE_META[t].color + '" stroke-dasharray="' + len.toFixed(1) + " " + (C - len).toFixed(1) + '" stroke-dashoffset="' + (-off).toFixed(1) + '" transform="rotate(-90 95 95)"><title>' + TYPE_META[t].label + ": " + per[t] + "</title></circle>";
    off += frac * C;
  });
  $("donutChart").innerHTML = segs +
    '<text x="95" y="93" text-anchor="middle" style="fill:var(--ink);font-family:var(--mono);font-size:30px;font-weight:700">' + total + "</text>" +
    '<text x="95" y="115" text-anchor="middle" style="fill:var(--ink-faint);font-size:11px">detections</text>';
  $("donutLegend").innerHTML = order.filter(function(t){ return per[t]; }).map(function(t){
    return '<span><i style="background:' + TYPE_META[t].color + '"></i>' + TYPE_META[t].label + " · " + per[t] + "</span>";
  }).join("");
  var max = Math.max.apply(null, order.map(function(t){ return per[t]; }));
  $("catBars").innerHTML = order.map(function(t){
    var pct = max ? Math.round(per[t] / max * 100) : 0;
    return '<div class="catbar" style="--cc:' + TYPE_META[t].color + '"><span class="cb-label"><i></i>' + TYPE_META[t].label + '</span><div class="cb-track"><div class="cb-fill" style="width:' + pct + '%"></div></div><span class="cb-num">' + per[t] + "</span></div>";
  }).join("");
  var pctCov = Math.round(state.redactedCount / total * 100);
  $("coverageFill").style.width = pctCov + "%";
  $("coverageText").textContent = state.redactedCount + " of " + total + " redacted · " + pctCov + "%" + (total - state.redactedCount ? " · " + (total - state.redactedCount) + " remaining visible" : " · full coverage");
}

function locateDetection(id){
  var m = null;
  state.matches.forEach(function(x){ if (x.id === id) m = x; });
  locateMatch(m);
}

function locateType(type){
  var m = null;
  state.matches.forEach(function(x){ if (!m && x.type === type) m = x; });
  if (!m){ toast("No " + TYPE_META[type].label + " detections in the current document."); return; }
  locateMatch(m);
}

/* ---------------- wiring ---------------- */
var debounce = null;

/* drag & drop — whole input panel + window guard */
var dropWrap = $("dropWrap");

bindElements();

/* Click-to-locate: scroll the original pane so the occurrence sits
   centred, flash its highlight, and bring the workspace into view. */
function locateMatch(m){
  if (!m) return;
  var mark = els.highlight.querySelector('mark[data-start="' + m.start + '"]');
  if (!mark){ toast("That occurrence is not in the current view.", true); return; }
  var r = mark.getBoundingClientRect(), pr = els.highlight.getBoundingClientRect();
  els.highlight.scrollTop += (r.top - pr.top) - els.highlight.clientHeight / 2 + r.height / 2;
  syncScrollFrom(els.highlight);
  mark.classList.remove("flash");
  void mark.offsetWidth; /* restart the flash animation */
  mark.classList.add("flash");
  els.highlight.scrollIntoView({ block:"center" });
}

els.input.addEventListener("input", function(){
  clearTimeout(debounce);
  debounce = setTimeout(process, 250); /* debounced live detection — no scan per keystroke */
});

/* Manual review actions (event delegation on the findings register) */
els.findings.addEventListener("click", function(e){
  var loc = e.target && e.target.closest ? e.target.closest("button[data-locate]") : null;
  if (loc){ locateDetection(loc.getAttribute("data-locate")); return; }
  var btn = e.target && e.target.closest ? e.target.closest("button[data-act]") : null;
  if (!btn) return;
  reviewAction(btn.getAttribute("data-id"), btn.getAttribute("data-act"), render);
});

/* Stage 4: per-entity redaction override dropdowns */
els.findings.addEventListener("change", function(e){
  var sel = e.target && e.target.getAttribute ? (e.target.getAttribute("data-ovr") ? e.target : null) : null;
  if (!sel) return;
  setOverride(sel.getAttribute("data-ovr"), sel.value || null);
});

/* Stage 4: redaction mode switch + category filters */
["modeFull","modePartial","modePseudo"].forEach(function(id){
  $(id).addEventListener("click", function(){ setMode(this.getAttribute("data-mode")); });
});

document.querySelectorAll(".cat-chip").forEach(function(chip){
  chip.addEventListener("click", function(){ toggleCategory(this.getAttribute("data-cat")); });
});

$("btnSample").addEventListener("click", function(){ loadText(SAMPLE_TEXT, null, "txt"); });

$("btnUpload").addEventListener("click", function(){ $("fileInput").click(); });

$("fileInput").addEventListener("change", function(e){ handleFile(e.target.files[0]); });

$("fileChipClear").addEventListener("click", clearSession);

$("btnDownload").addEventListener("click", function(){ downloadSanitized(); });

$("btnDownload2").addEventListener("click", function(){ downloadSanitized(); });

$("btnCopy").addEventListener("click", copySanitized);

$("btnCopy2").addEventListener("click", copySanitized);

$("btnClear").addEventListener("click", clearSession);

$("btnRunTests").addEventListener("click", function(){
  var r = runTests();
  toast(r.fail ? ("Test suite: " + r.pass + " passed, " + r.fail + " FAILED") : ("Test suite: all " + r.pass + " fixtures passed"), !!r.fail);
});

$("btnLogDownload").addEventListener("click", function(){
  var blob = new Blob([PROMPT_LOG_MD], { type:"text/markdown;charset=utf-8" });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url; a.download = "PROMPT_LOG.md";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1500);
  toast("PROMPT_LOG.md downloaded.");
});

["dragenter","dragover"].forEach(function(ev){
  dropWrap.addEventListener(ev, function(e){ e.preventDefault(); dropWrap.classList.add("dragging"); });
});

["dragleave","drop"].forEach(function(ev){
  dropWrap.addEventListener(ev, function(e){
    e.preventDefault();
    if (ev === "dragleave" && dropWrap.contains(e.relatedTarget)) return;
    dropWrap.classList.remove("dragging");
  });
});

dropWrap.addEventListener("drop", function(e){
  var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) handleFile(f);
});

["dragover","drop"].forEach(function(ev){
  window.addEventListener(ev, function(e){ e.preventDefault(); });
});

/* ---------------- Stage 5 wiring ----------------
   Theme toggle (session-only, nothing persisted), privacy panel,
   comparison sync-scroll / expand, category-card locate, and the
   export panel buttons. */
$("btnTheme").addEventListener("click", function(){
  var light = document.documentElement.getAttribute("data-theme") !== "light";
  if (light) document.documentElement.setAttribute("data-theme", "light");
  else document.documentElement.removeAttribute("data-theme");
  this.setAttribute("aria-pressed", light ? "true" : "false");
  $("themeLabel").textContent = light ? "Light" : "Dark";
  $("themeIconSun").style.display = light ? "none" : "";
  $("themeIconMoon").style.display = light ? "" : "none";
  toast(light ? "Light theme on — kept for this session only, nothing is stored." : "Dark theme on.");
});

$("btnPrivacy").addEventListener("click", function(){
  var panel = $("privacyPanel");
  var open = panel.classList.toggle("show");
  this.setAttribute("aria-expanded", open ? "true" : "false");
});

document.querySelectorAll(".ent[data-enttype]").forEach(function(card){
  card.addEventListener("click", function(){ locateType(this.getAttribute("data-enttype")); });
});

var syncOn = true, syncGuard = false;

function syncScrollFrom(src){
  var gSrc = src === els.highlight ? $("gutterOrig") : $("gutterSan");
  gSrc.scrollTop = src.scrollTop;
  if (!syncOn || syncGuard) return;
  var dst = src === els.highlight ? els.sanitized : els.highlight;
  var gDst = dst === els.highlight ? $("gutterOrig") : $("gutterSan");
  var maxSrc = src.scrollHeight - src.clientHeight, maxDst = dst.scrollHeight - dst.clientHeight;
  var ratio = maxSrc > 0 ? src.scrollTop / maxSrc : 0;
  syncGuard = true;
  dst.scrollTop = ratio * maxDst;
  gDst.scrollTop = dst.scrollTop;
  syncGuard = false;
}

[els.highlight, els.sanitized].forEach(function(p){
  p.addEventListener("scroll", function(){ syncScrollFrom(p); });
});

$("btnSync").addEventListener("click", function(){
  syncOn = !syncOn;
  this.setAttribute("aria-pressed", syncOn ? "true" : "false");
  toast(syncOn ? "Synchronized scrolling on — both panes move together." : "Synchronized scrolling off — panes scroll independently.");
});

$("btnExpand").addEventListener("click", function(){
  var grid = $("diffGrid");
  var expanded = grid.classList.toggle("expanded");
  this.setAttribute("aria-pressed", expanded ? "true" : "false");
  this.lastChild.textContent = expanded ? " Collapse " : " Expand ";
  toast(expanded ? "Comparison workspace expanded." : "Comparison workspace restored.");
});

$("btnCopy3").addEventListener("click", copySanitized);

$("btnExportTxt").addEventListener("click", function(){ downloadAs("txt"); });

$("btnExportCsv").addEventListener("click", function(){ downloadAs("csv"); });

$("btnExportCopy").addEventListener("click", copySanitized);

/* ---------------- Stage 6 wiring ----------------
   Presets, demo lab, editable sensitivity weights, Leak Guard
   resolve buttons, the export guard actions, audit report
   downloads and the transparency panel's clear-session control. */
document.querySelectorAll(".preset-btn").forEach(function(b){
  b.addEventListener("click", function(){ applyPreset(this.getAttribute("data-preset"), setMode); });
});

document.querySelectorAll("[data-demo]").forEach(function(b){
  b.addEventListener("click", function(){
    var key = this.getAttribute("data-demo");
    if (DEMO_SAMPLES[key]){
      loadText(DEMO_SAMPLES[key], null, "txt");
      toast("Synthetic demo loaded — every value in it is fictional.");
    }
  });
});

$("weightsGrid").addEventListener("change", function(e){
  var inp = e.target && e.target.getAttribute && e.target.getAttribute("data-weight") ? e.target : null;
  if (!inp) return;
  var t = inp.getAttribute("data-weight");
  var v = parseFloat(inp.value);
  if (isNaN(v) || v < 0) v = 0;
  if (v > 50) v = 50;
  inp.value = v;
  SENSITIVITY[t] = v;
  renderAdvanced();
  toast("Sensitivity weight for " + TYPE_META[t].label + " set to " + v + " — exposure scores recomputed.");
});

$("leakList").addEventListener("click", function(e){
  var btn = e.target && e.target.closest ? e.target.closest("button[data-leak-resolve]") : null;
  if (btn) resolveLeak(parseInt(btn.getAttribute("data-leak-resolve"), 10));
});

$("btnGuardReview").addEventListener("click", function(){
  hideExportGuard();
  var sec = document.querySelector('[aria-label="Leak Guard and privacy exposure score"]');
  if (sec){
    sec.scrollIntoView({ behavior:"smooth", block:"start" });
    sec.classList.remove("flash-target");
    void sec.offsetWidth;
    sec.classList.add("flash-target");
  }
});

$("btnGuardProceed").addEventListener("click", function(){
  var k = pendingExport;
  hideExportGuard();
  if (k === "csv" || k === "txt") downloadAs(k, true);
  else downloadSanitized(true);
});

$("btnGuardCancel").addEventListener("click", function(){
  hideExportGuard();
  toast("Export cancelled — nothing was downloaded.");
});

$("btnReportTxt").addEventListener("click", function(){ downloadReport("txt"); });

$("btnReportJson").addEventListener("click", function(){ downloadReport("json"); });

$("btnClear2").addEventListener("click", clearSession);

/* =====================================================================
   Stage 5B — landing page, hash router (#/ landing · #/app workspace),
   workspace sidebar, scroll-spy, reveal animations, mobile menu and
   theme sync. Privacy: routing only toggles element visibility — it
   never reads, copies, persists or transmits the document. The
   in-memory session (text, review decisions, pseudonym store) is
   left exactly as it was when the user switches views.
   ===================================================================== */
document.documentElement.classList.add("js");
(function(){
  var nav = document.getElementById("landingNav");
  var landing = document.getElementById("landingView");
  var app = document.getElementById("appView");
  var menu = document.getElementById("mobileMenu");
  var btnMenu = document.getElementById("btnMenu");
  var inApp = false;

  function setHash(h){
    if (location.hash !== h){
      try { history.pushState(null, "", h); } catch (e) { location.hash = h; }
    }
  }
  function flashTarget(el){
    if (!el) return;
    el.scrollIntoView({ behavior:"smooth", block:"start" });
    el.classList.remove("flash-target");
    void el.offsetWidth; /* restart the animation */
    el.classList.add("flash-target");
  }
  function markSide(id){
    document.querySelectorAll("#appSidebar .side-item[data-go]").forEach(function(b){
      b.classList.toggle("active", b.getAttribute("data-go") === id);
    });
  }
  function showApp(target){
    inApp = true;
    nav.hidden = true; landing.hidden = true; app.hidden = false;
    setHash("#/app");
    closeMenu();
    if (target){
      var el = document.getElementById(target);
      if (el){
        if (target === "privacyPanel" && !el.classList.contains("show")){
          el.classList.add("show");
          var bp = document.getElementById("btnPrivacy");
          if (bp) bp.setAttribute("aria-expanded", "true");
        }
        markSide(target); setTimeout(function(){ flashTarget(el); }, 60); return;
      }
    }
    window.scrollTo(0, 0);
  }
  function showLanding(anchor){
    inApp = false;
    app.hidden = true; nav.hidden = false; landing.hidden = false;
    setHash(anchor ? ("#" + anchor) : "#/");
    if (anchor){
      var el = document.getElementById(anchor);
      if (el) setTimeout(function(){ el.scrollIntoView({ behavior:"smooth", block:"start" }); }, 60);
    } else {
      window.scrollTo(0, 0);
    }
  }
  function closeMenu(){
    if (menu) menu.classList.remove("open");
    if (btnMenu) btnMenu.setAttribute("aria-expanded", "false");
  }

  /* --- CTAs: Launch App / Start Sanitizing / footer app links --- */
  document.querySelectorAll("[data-app-link]").forEach(function(el){
    el.addEventListener("click", function(e){
      if (el.tagName === "A") e.preventDefault();
      showApp(el.getAttribute("data-app-target") || null);
    });
  });
  /* --- Try Live Demo: workspace + synthetic sample, via the real loader --- */
  document.querySelectorAll("[data-demo-link]").forEach(function(el){
    el.addEventListener("click", function(e){
      if (el.tagName === "A") e.preventDefault();
      showApp("sec-workspace");
      if (typeof loadText === "function" && typeof SAMPLE_TEXT === "string"){
        loadText(SAMPLE_TEXT, null, "txt");
      }
    });
  });
  /* --- Landing anchor links (also used after returning from the app) --- */
  document.querySelectorAll("[data-navlink]").forEach(function(el){
    el.addEventListener("click", function(e){
      var id = el.getAttribute("data-navlink");
      closeMenu();
      if (inApp){
        e.preventDefault();
        showLanding(id === "home" ? null : id);
      }
      /* in the landing view the plain href="#section" behaviour applies */
    });
  });
  /* --- Mobile menu --- */
  if (btnMenu) btnMenu.addEventListener("click", function(){
    var open = menu.classList.toggle("open");
    this.setAttribute("aria-expanded", open ? "true" : "false");
  });

  /* --- Workspace sidebar --- */
  document.querySelectorAll("#appSidebar .side-item[data-go]").forEach(function(btn){
    btn.addEventListener("click", function(){
      var id = btn.getAttribute("data-go");
      markSide(id);
      flashTarget(document.getElementById(id));
    });
  });
  var sidePrivacy = document.getElementById("sidePrivacy");
  if (sidePrivacy) sidePrivacy.addEventListener("click", function(){
    var panel = document.getElementById("privacyPanel");
    var btn = document.getElementById("btnPrivacy");
    if (panel && !panel.classList.contains("show")){
      panel.classList.add("show");
      if (btn) btn.setAttribute("aria-expanded", "true");
    }
    if (panel) flashTarget(panel);
  });
  var sideHome = document.getElementById("sideHome");
  if (sideHome) sideHome.addEventListener("click", function(){ showLanding(null); });

  /* --- Theme: the landing toggle flips data-theme; an observer keeps
         both toggles' labels and icons in sync (session-only). --- */
  function syncThemeUI(){
    var light = document.documentElement.getAttribute("data-theme") === "light";
    [["btnTheme", "themeLabel", "themeIconSun", "themeIconMoon"],
     ["btnThemeL", null, null, null]].forEach(function(cfg){
      var b = document.getElementById(cfg[0]);
      if (!b) return;
      b.setAttribute("aria-pressed", light ? "true" : "false");
      if (cfg[1]) document.getElementById(cfg[1]).textContent = light ? "Light" : "Dark";
      var sun = cfg[2] ? document.getElementById(cfg[2]) : b.querySelector(".ic-sun");
      var moon = cfg[3] ? document.getElementById(cfg[3]) : b.querySelector(".ic-moon");
      if (sun) sun.style.display = light ? "none" : "";
      if (moon) moon.style.display = light ? "" : "none";
      var lbl = b.querySelector(".theme-lbl");
      if (lbl) lbl.textContent = light ? "Light" : "Dark";
    });
  }
  var btnThemeL = document.getElementById("btnThemeL");
  if (btnThemeL) btnThemeL.addEventListener("click", function(){
    var light = document.documentElement.getAttribute("data-theme") !== "light";
    if (light) document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
  });
  new MutationObserver(syncThemeUI).observe(document.documentElement, { attributes:true, attributeFilter:["data-theme"] });
  syncThemeUI();

  /* --- Scroll-spy: highlight the nav link for the section in view --- */
  var spyLinks = {};
  document.querySelectorAll("[data-navlink]").forEach(function(a){
    var k = a.getAttribute("data-navlink");
    (spyLinks[k] = spyLinks[k] || []).push(a);
  });
  function setActiveNav(id){
    Object.keys(spyLinks).forEach(function(k){
      spyLinks[k].forEach(function(a){ a.classList.toggle("active", k === id); });
    });
  }
  if (window.IntersectionObserver){
    var spy = new IntersectionObserver(function(entries){
      entries.forEach(function(en){
        if (en.isIntersecting) setActiveNav(en.target.id === "home" ? "home" : en.target.id);
      });
    }, { rootMargin:"-38% 0px -55% 0px" });
    ["home","features","how","use-cases","privacy","about"].forEach(function(id){
      var s = document.getElementById(id);
      if (s) spy.observe(s);
    });
    /* --- Reveal on scroll (subtle, clarity-first) --- */
    var rev = new IntersectionObserver(function(entries){
      entries.forEach(function(en){
        if (en.isIntersecting){ en.target.classList.add("in"); rev.unobserve(en.target); }
      });
    }, { threshold:0.12 });
    document.querySelectorAll(".reveal").forEach(function(el){ rev.observe(el); });
  } else {
    document.querySelectorAll(".reveal").forEach(function(el){ el.classList.add("in"); });
  }

  /* --- Routing: initial load + browser back/forward --- */
  function routeFromHash(){
    var h = location.hash || "";
    if (h.indexOf("#/app") === 0){ if (!inApp) showApp(null); }
    else if (h === "#/" || h === "" || h === "#"){ if (inApp) showLanding(null); }
    else if (inApp){ showLanding(h.slice(1)); }
  }
  window.addEventListener("hashchange", routeFromHash);
  if ((location.hash || "").indexOf("#/app") === 0) showApp(null);
})();

process();

runTests();
