/* =====================================================================
   PRIVASHIELD — render.js. Cohesive DOM rendering for KPI summary cards,
      live comparison panes, findings inspector, and SVG analytics.
   ===================================================================== */

import { DETECTORS, TYPE_META } from './detectors.js';
import { engineStats } from './engine.js';
import { state, sigOf, $, els } from './session.js';
import { escapeHtml, renderHighlighted, renderSanitizedRich, truncateVal } from './sanitizer.js';
import { renderAdvanced } from './advanced.js';
import { computeDocumentStats, computeEntityBreakdown, computeLineStarts, formatLinePosition } from './stats.js';

const MODE_NAMES = {
  FULL: 'FULL MASK → [REDACTED]',
  PARTIAL: 'PARTIAL MASK → type-specific fragments',
  PSEUDO: 'PSEUDONYMIZATION → stable aliases'
};

const ACTION_BUTTON_IDS = [
  'btnDownload', 'btnDownload2', 'btnCopy', 'btnCopy2', 'btnCopy3',
  'btnExportTxt', 'btnExportCsv', 'btnExportCopy', 'btnReportTxt', 'btnReportJson'
];

function formatSubLine(counts, confirmed, candCount, k, base) {
  if (!counts[k]) return base;
  let s = `<b>${confirmed[k]} validated</b>`;
  if (candCount[k]) s += ` · <span class="cand">${candCount[k]} candidate</span>`;
  return s;
}

function formatChecksumSubLine(counts, checksumValid, approvedCand, candCount, k, validLabel, emptyLabel) {
  if (!counts[k]) return emptyLabel;
  let s = `<b>${checksumValid[k]} ${validLabel}</b>`;
  if (approvedCand[k]) s += ` · ${approvedCand[k]} approved`;
  if (candCount[k]) s += ` · <span class="cand">${candCount[k]} candidate</span>`;
  return s;
}

function renderSummaryCards(text, matches, active, docStats, summary) {
  $('statChars').textContent = `${docStats.chars.toLocaleString()} chars`;
  $('statWords').textContent = `${docStats.words.toLocaleString()} words`;
  $('statLines').textContent = `${docStats.lines.toLocaleString()} lines`;
  $('statUpdated').textContent = text ? `Processed locally · ${new Date().toLocaleTimeString()}` : 'Awaiting input';

  Object.keys(summary.counts).forEach((k) => {
    $(`cnt-${k}`).textContent = summary.counts[k];
  });

  $('sub-EMAIL').innerHTML = formatSubLine(summary.counts, summary.confirmed, summary.candCount, 'EMAIL', 'format-validated');
  $('sub-PHONE').innerHTML = formatSubLine(summary.counts, summary.confirmed, summary.candCount, 'PHONE', 'normalized to E.164-style');
  $('sub-IP').innerHTML = summary.counts.IP
    ? `<b>${summary.counts.IP - summary.ipV6} IPv4</b> · <b>${summary.ipV6} IPv6</b>`
    : 'v4 + v6';
  $('sub-PAN').innerHTML = formatSubLine(summary.counts, summary.confirmed, summary.candCount, 'PAN', 'structure-validated');
  $('sub-AADHAAR').innerHTML = formatChecksumSubLine(
    summary.counts, summary.checksumValid, summary.approvedCand, summary.candCount,
    'AADHAAR', 'checksum-valid', 'checksum vs candidate split'
  );
  $('sub-CREDIT_CARD').innerHTML = formatChecksumSubLine(
    summary.counts, summary.checksumValid, summary.approvedCand, summary.candCount,
    'CREDIT_CARD', 'Luhn-valid', 'Luhn-validated only'
  );

  $('kpiTotal').textContent = matches.length;
  $('kpiTotalSub').textContent = matches.length
    ? `${active.length} to redact across ${summary.activeTypeCount} entity types${summary.excludedCount ? ` · ${summary.excludedCount} excluded` : ''}`
    : (text ? 'No PII detected in current input' : 'No input processed yet');

  $('riskFill').style.width = `${summary.risk}%`;
  $('riskFill').style.background = summary.riskColor;
  $('kpiRiskSub').textContent = active.length ? `Exposure risk ${summary.riskLabel} · ${summary.risk} / 100` : 'Exposure risk —';

  $('procStatus').innerHTML = `<span class="dot"></span> ${
    !text
      ? 'IDLE — awaiting input'
      : matches.length
        ? `PII FOUND — ${active.length} to redact${summary.candTotal ? ` · ${summary.candTotal} candidate(s) need review` : ''}${summary.excludedCount ? ` · ${summary.excludedCount} excluded` : ''}`
        : 'CLEAN — scanned locally, nothing matched'
  }`;

  $('rsTotal').textContent = matches.length;
  $('rsUnique').textContent = summary.uniqueAllCount;
  $('kpiUnique').textContent = summary.uniqueAllCount;
  $('rsRedacted').textContent = state.redactedCount;
  $('rsKept').textContent = summary.keptCount;

  $('kpiRedacted').textContent = state.redactedCount;
  $('kpiRedactedSub').textContent = matches.length
    ? `Replaced in the sanitized output · ${state.mode} mode`
    : 'Replaced in the sanitized output';
  $('kpiRemaining').textContent = summary.keptCount;
  $('kpiRemainingSub').textContent = matches.length
    ? (summary.keptCount ? 'Still visible — excluded, category off or Keep override' : 'Nothing left visible — full coverage')
    : 'Supported matches still visible in the output';
}

function renderComparisonPanes(text, matches, active, docStats, summary) {
  if (!text) {
    els.highlight.className = 'codebox empty';
    els.highlight.textContent = 'Detections will be highlighted here as you type.';
    els.sanitized.className = 'codebox empty';
    els.sanitized.textContent = 'Sanitized text will appear here — replacements follow the redaction mode selected above.';
  } else {
    els.highlight.className = 'codebox';
    els.highlight.innerHTML = renderHighlighted(text, matches);
    els.sanitized.className = 'codebox';
    els.sanitized.innerHTML = renderSanitizedRich(text, matches);
  }

  let gutterText = '';
  if (text) {
    const nums = [];
    for (let ln = 1; ln <= docStats.lines; ln++) nums.push(ln);
    gutterText = nums.join('\n');
  }
  $('gutterOrig').textContent = gutterText;
  $('gutterSan').textContent = gutterText;

  const ovrVals = Object.values(state.overrides);
  $('partialWarn').classList.toggle('show', state.mode === 'PARTIAL' || ovrVals.includes('PARTIAL'));
  $('pseudoWarn').classList.toggle('show', state.mode === 'PSEUDO' || ovrVals.includes('PSEUDO'));
  $('engineNote').textContent = `Mode: ${MODE_NAMES[state.mode]} · context-aware · manual review on`;

  $('modeNote').innerHTML = state.mode === 'FULL'
    ? '<strong>Full Mask</strong> — every approved detection is replaced with <code style="font-family:var(--mono)">[REDACTED]</code>. Surrounding text and document structure are preserved exactly; replacements are applied against the original offsets, so later matches never shift.'
    : state.mode === 'PARTIAL'
      ? '<strong>Partial Mask</strong> — type-specific policies: email keeps its first/last local characters and domain ending, phone &amp; card keep only the last 4 digits, Aadhaar shows <code style="font-family:var(--mono)">XXXX XXXX 1234</code>, PAN keeps its first 2 and last 2 characters, IPv4 keeps its first two octets and IPv6 only its first group. <strong>Warning:</strong> these fragments can still identify someone — see the warning below.'
      : '<strong>Consistent Pseudonymization</strong> — each unique normalized value gets one stable alias (<code style="font-family:var(--mono)">EMAIL_001</code>, <code style="font-family:var(--mono)">PHONE_001</code>, <code style="font-family:var(--mono)">CARD_001</code>…); repeats and formatting variants share it, so relationships across the document (and across CSV rows) survive. Aliases stay stable when you switch modes or filters in this session. This is <strong>not</strong> irreversible anonymization — see the warning below.';

  const pm = $('pseudoMap');
  if (state.pseudoStore.size()) {
    pm.classList.add('show');
    pm.innerHTML = `${state.pseudoStore.aliases().map((a) => `<span class="pm-chip">${escapeHtml(a)}</span>`).join('')}<span class="pm-note">${state.pseudoStore.size()} alias(es) assigned in this document session. The alias list above shows placeholders only — the original-to-alias mapping itself is never displayed as a table, never exported, and lives only in this tab's memory.</span>`;
  } else {
    pm.classList.remove('show');
    pm.innerHTML = '';
  }

  $('sanLegend').innerHTML = state.mode === 'PSEUDO'
    ? '<i style="background:#38bdf8"></i><span class="pseudo" style="font-family:var(--mono);font-size:11px">EMAIL_001</span>&nbsp;stable alias per unique value · same value, same alias, everywhere'
    : state.mode === 'PARTIAL'
      ? '<i style="background:var(--amber)"></i><span class="partial" style="font-family:var(--mono);font-size:11px">**** **** **** 1111</span>&nbsp;partial mask · verification fragments remain visible — still sensitive'
      : '<i style="background:var(--emerald)"></i><span class="redacted" style="font-family:var(--mono);font-size:11px">[REDACTED]</span>&nbsp;marks every removed value · safe to share';

  $('hlCount').textContent = `${active.length} highlighted${summary.candTotal ? ` · ${summary.candTotal} candidate` : ''}${summary.excludedCount ? ` · ${summary.excludedCount} excluded` : ''}`;

  const rej = [];
  if (engineStats.rejectedLuhn) rej.push(`${engineStats.rejectedLuhn} rejected by Luhn`);
  if (engineStats.rejectedIP) rej.push(`${engineStats.rejectedIP} rejected by IP validation`);
  if (engineStats.rejectedOther) rej.push(`${engineStats.rejectedOther} rejected by format rules`);
  if (engineStats.overlapsResolved) rej.push(`${engineStats.overlapsResolved} overlap(s) resolved`);
  if (engineStats.ambiguousSurfaced) rej.push(`${engineStats.ambiguousSurfaced} ambiguous candidate(s) surfaced by context`);
  $('luhnNote').textContent = rej.join(' · ');

  if (summary.keptCount) {
    const reasons = [];
    if (summary.keptReasons.excludedCount) reasons.push(`${summary.keptReasons.excludedCount} excluded by reviewer`);
    if (summary.keptReasons.catOffCount) reasons.push(`${summary.keptReasons.catOffCount} in switched-off categories`);
    if (summary.keptReasons.keepOvrCount) reasons.push(`${summary.keptReasons.keepOvrCount} set to Keep by override`);
    $('reviewWarn').classList.add('show');
    $('reviewWarnText').innerHTML = `<strong>${summary.keptCount} detection${summary.keptCount > 1 ? 's remain' : ' remains'} visible.</strong> ${reasons.join(' · ')} — those values appear in plain text in the sanitized output and in any downloaded file. Change them from the findings register if that was not intended.`;
  } else {
    $('reviewWarn').classList.remove('show');
  }

  const hasText = text.length > 0;
  ACTION_BUTTON_IDS.forEach((id) => {
    $(id).disabled = !hasText;
  });
}

function renderFindingsTable(text, matches) {
  if (!matches.length) {
    els.findings.innerHTML = `<tr class="empty-row"><td colspan="11">${
      text ? 'Scan complete — no PII detected in this input.' : 'No detections yet. Load the sample data or paste text containing PII.'
    }</td></tr>`;
    return;
  }

  const lineStarts = computeLineStarts(text);
  els.findings.innerHTML = matches.map((m) => {
    const meta = TYPE_META[m.type];
    const sevClass = meta.severity === 'CRITICAL' ? 'crit' : meta.severity === 'HIGH' ? 'high' : meta.severity === 'MEDIUM' ? 'med' : 'low';
    const isCand = m.reviewStatus === 'NEEDS_REVIEW';
    const isExcluded = m.userDecision === 'EXCLUDED';
    const ovr = state.overrides[sigOf(m)] || '';

    const pill = `<span class="val-pill ${isCand ? 'cand' : 'ok'}" title="${escapeHtml(m.validationDetail)}">${m.validationStatus.replace(/_/g, ' ')}</span>` +
      (isCand ? '<div class="review-cand">NEEDS REVIEW</div>' : '') +
      (m.userDecision === 'APPROVED' ? '<div class="review-cand" style="color:var(--emerald-bright)">APPROVED BY REVIEWER</div>' : '');

    let reviewCell;
    if (isExcluded) {
      reviewCell = `<span class="rev-state">EXCLUDED — KEPT VISIBLE</span><button class="rev-btn plain" type="button" data-act="restore" data-id="${m.id}">Restore</button>`;
    } else {
      reviewCell = `${isCand && m.userDecision !== 'APPROVED' ? `<button class="rev-btn" type="button" data-act="approve" data-id="${m.id}">Approve</button>` : ''}` +
        `${m.userDecision === 'APPROVED' ? '<span class="rev-state ok">APPROVED</span>' : ''}` +
        `<button class="rev-btn warn" type="button" data-act="exclude" data-id="${m.id}">Exclude</button>`;
    }
    reviewCell = `<button class="rev-btn plain" type="button" data-locate="${m.id}" title="Scroll the original document to this occurrence">Locate</button>${reviewCell}`;

    const repCell = m.replacement == null
      ? '<td class="mono" style="color:var(--amber)">KEPT — NOT REDACTED</td>'
      : `<td class="mono" style="color:var(--emerald-bright)">${escapeHtml(truncateVal(m.replacement))}</td>`;

    return `<tr${isExcluded ? ' class="excluded"' : ''}>` +
      `<td class="mono">${m.id}</td>` +
      `<td><span class="type-tag" style="--tc:${meta.color}"><i></i>${meta.label.toUpperCase()}</span></td>` +
      `<td class="mono" title="${escapeHtml(m.value)}">${escapeHtml(truncateVal(m.value))}</td>` +
      `<td class="mono" title="${escapeHtml(m.normalized)}">${escapeHtml(truncateVal(m.normalized))}</td>` +
      `<td>${pill}</td>` +
      `<td><span class="conf ${m.confidence}">${m.confidence}</span></td>` +
      `<td><span class="sev ${sevClass}">${meta.severity}</span></td>` +
      `<td class="mono">${formatLinePosition(lineStarts, m)}</td>` +
      repCell +
      `<td><select class="ovr" data-ovr="${m.id}" aria-label="Redaction override for ${m.id}">` +
        `<option value=""${!ovr ? ' selected' : ''}>Auto (${state.mode})</option>` +
        `<option value="FULL"${ovr === 'FULL' ? ' selected' : ''}>Full mask</option>` +
        `<option value="PARTIAL"${ovr === 'PARTIAL' ? ' selected' : ''}>Partial mask</option>` +
        `<option value="PSEUDO"${ovr === 'PSEUDO' ? ' selected' : ''}>Pseudonym</option>` +
        `<option value="KEEP"${ovr === 'KEEP' ? ' selected' : ''}>Keep visible</option>` +
      `</select></td>` +
      `<td>${reviewCell}</td>` +
    `</tr>`;
  }).join('');
}

/** Render live SVG entity-distribution donut chart, category bars, and redaction coverage. */
export function renderAnalytics(summary) {
  const total = state.matches.length;
  $('analyticsEmpty').style.display = total ? 'none' : '';
  $('analyticsGrid').style.display = total ? '' : 'none';
  $('analyticsNote').textContent = total
    ? `${total} detection(s) · ${state.redactedCount} redacted · ${total - state.redactedCount} remaining`
    : 'No data yet';
  if (!total) return;

  const per = summary.distribution;
  const order = DETECTORS.map((d) => d.type);
  const C = 2 * Math.PI * 70;
  let off = 0;
  let segs = '';
  order.forEach((t) => {
    if (!per[t]) return;
    const frac = per[t] / total;
    const len = Math.max(0, frac * C - 2);
    segs += `<circle cx="95" cy="95" r="70" fill="none" stroke-width="26" style="stroke:${TYPE_META[t].color}" stroke-dasharray="${len.toFixed(1)} ${(C - len).toFixed(1)}" stroke-dashoffset="${(-off).toFixed(1)}" transform="rotate(-90 95 95)"><title>${TYPE_META[t].label}: ${per[t]}</title></circle>`;
    off += frac * C;
  });

  $('donutChart').innerHTML = `${segs}<text x="95" y="93" text-anchor="middle" style="fill:var(--ink);font-family:var(--mono);font-size:30px;font-weight:700">${total}</text><text x="95" y="115" text-anchor="middle" style="fill:var(--ink-faint);font-size:11px">detections</text>`;
  $('donutLegend').innerHTML = order
    .filter((t) => per[t])
    .map((t) => `<span><i style="background:${TYPE_META[t].color}"></i>${TYPE_META[t].label} · ${per[t]}</span>`)
    .join('');

  const max = Math.max(...order.map((t) => per[t]));
  $('catBars').innerHTML = order.map((t) => {
    const pct = max ? Math.round((per[t] / max) * 100) : 0;
    return `<div class="catbar" style="--cc:${TYPE_META[t].color}"><span class="cb-label"><i></i>${TYPE_META[t].label}</span><div class="cb-track"><div class="cb-fill" style="width:${pct}%"></div></div><span class="cb-num">${per[t]}</span></div>`;
  }).join('');

  const pctCov = Math.round((state.redactedCount / total) * 100);
  $('coverageFill').style.width = `${pctCov}%`;
  $('coverageText').textContent = `${state.redactedCount} of ${total} redacted · ${pctCov}%${total - state.redactedCount ? ` · ${total - state.redactedCount} remaining visible` : ' · full coverage'}`;
}

/** Render the complete workspace UI from current in-memory `state`. */
export function render() {
  const text = state.text;
  const matches = state.matches;
  const active = state.activeMatches;
  const docStats = computeDocumentStats(text);
  const summary = computeEntityBreakdown(matches, active, state.overrides, state.categories, state.redactedCount);

  renderSummaryCards(text, matches, active, docStats, summary);
  renderAnalytics(summary);
  renderAdvanced();
  renderComparisonPanes(text, matches, active, docStats, summary);
  renderFindingsTable(text, matches);
}
