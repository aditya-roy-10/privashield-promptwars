/* =====================================================================
   PRIVASHIELD — stats.js. Pure, DOM-free calculation helpers for
      document metrics, entity breakdowns, exposure risk and line offsets.
   ===================================================================== */

import { DETECTORS, TYPE_META, SEV_WEIGHT } from './detectors.js';
import { sigOf } from './session.js';

/** Compute character, word, and logical line counts for `text`. */
export function computeDocumentStats(text) {
  return {
    chars: text.length,
    words: text.trim() ? text.trim().split(/\s+/).length : 0,
    lines: text ? text.split('\n').length : 0
  };
}

/** Build an array of 0-based line start character indices for fast position lookup. */
export function computeLineStarts(text) {
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') lineStarts.push(i + 1);
  }
  return lineStarts;
}

/** Format `L<line> · <start>–<end>` for a detection offset using `lineStarts`. */
export function formatLinePosition(lineStarts, det) {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (lineStarts[mid] <= det.start) lo = mid;
    else hi = mid - 1;
  }
  return `L${lo + 1} · ${det.start}–${det.end}`;
}

/**
 * Compute all dashboard entity counts, validation splits, unique counts,
 * kept-visible reasons, exposure risk tier, and distribution totals.
 */
export function computeEntityBreakdown(matches, activeMatches, overrides, categories, redactedCount) {
  const counts = {};
  const confirmed = {};
  const candCount = {};
  const distribution = {};
  DETECTORS.forEach((d) => {
    counts[d.type] = 0;
    confirmed[d.type] = 0;
    candCount[d.type] = 0;
    distribution[d.type] = 0;
  });

  const checksumValid = { AADHAAR: 0, CREDIT_CARD: 0 };
  const approvedCand = { AADHAAR: 0, CREDIT_CARD: 0 };
  let ipV6 = 0;
  const uniqueActive = {};

  activeMatches.forEach((m) => {
    counts[m.type]++;
    uniqueActive[`${m.type}|${m.normalized}`] = true;
    if (m.reviewStatus === 'CONFIRMED') confirmed[m.type]++;
    else candCount[m.type]++;

    if (m.type === 'AADHAAR' || m.type === 'CREDIT_CARD') {
      if (m.validationStatus === 'CHECKSUM_VALID') checksumValid[m.type]++;
      else if (m.reviewStatus === 'CONFIRMED') approvedCand[m.type]++;
    }
    if (m.type === 'IP' && m.value.includes(':')) ipV6++;
  });

  const allUnique = {};
  matches.forEach((m) => {
    distribution[m.type]++;
    allUnique[`${m.type}|${m.normalized}`] = true;
  });

  let raw = 0;
  activeMatches.forEach((m) => {
    raw += SEV_WEIGHT[TYPE_META[m.type].severity] || 5;
  });
  const risk = Math.min(100, raw);
  let riskLabel = '—';
  let riskColor = 'var(--emerald)';
  if (matches.length) {
    if (risk >= 70) { riskLabel = 'SEVERE'; riskColor = '#f87171'; }
    else if (risk >= 40) { riskLabel = 'HIGH'; riskColor = '#fb923c'; }
    else if (risk >= 18) { riskLabel = 'MEDIUM'; riskColor = '#fbbf24'; }
    else { riskLabel = 'LOW'; riskColor = '#34d399'; }
  }

  const excludedCount = matches.length - activeMatches.length;
  const keptCount = matches.length - redactedCount;
  const catOffCount = matches.filter((m) => !categories[m.type] && m.userDecision !== 'EXCLUDED').length;
  const keepOvrCount = matches.filter(
    (m) => overrides[sigOf(m)] === 'KEEP' && m.userDecision !== 'EXCLUDED' && categories[m.type]
  ).length;

  return {
    counts,
    confirmed,
    checksumValid,
    approvedCand,
    candCount,
    ipV6,
    distribution,
    uniqueActiveCount: Object.keys(uniqueActive).length,
    uniqueAllCount: Object.keys(allUnique).length,
    excludedCount,
    keptCount,
    candTotal: activeMatches.filter((m) => m.reviewStatus === 'NEEDS_REVIEW').length,
    activeTypeCount: Object.values(counts).filter((n) => n > 0).length,
    keptReasons: { excludedCount, catOffCount, keepOvrCount },
    risk,
    riskLabel,
    riskColor
  };
}
