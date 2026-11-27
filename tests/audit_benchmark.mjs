/* PRIVASHIELD — Independent Labeled Synthetic Benchmark & Audit Suite
   Run with: npm run test:audit  (node --test tests/audit_benchmark.mjs)
   Kept separate from tests/privashield.test.js so the original 104-test
   baseline remains exact. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Papa from 'papaparse';

import { detectAll, detect } from '../src/engine.js';
import { escapeHtml, renderHighlighted, renderSanitizedRich, isFormulaCell } from '../src/sanitizer.js';
import { createPseudoStore, replacementFor, applyRedactions, partialMask } from '../src/redaction.js';
import { state, sigOf, planReplacement } from '../src/session.js';
import { applyDecisions, reviewAction } from '../src/review.js';
import { leakScan, classifyResidual, computeExposure, applyPreset } from '../src/advanced.js';
import { buildAuditReport, reportToText } from '../src/report.js';

/* =====================================================================
   1. INDEPENDENT LABELED SYNTHETIC BENCHMARK DATASET
      Hand-authored ground-truth cases with realistic distractors,
      mixed-context benign keywords, and known regex blind spots.
   ===================================================================== */
const BENCHMARK_CASES = [
  {
    id: 'BM-01-MIXED-FINANCE',
    note: 'Valid card, PAN, email, and phone immediately adjacent to benign words (order, invoice, transaction, reference)',
    text: [
      'Order #884120 invoice ref TXN-2026-9910: customer email neha.kapoor+billing@finops.example.in',
      'Transaction reference 9988776655443322 (non-Luhn internal ref) paid using Visa 4111 1111 1111 1111,',
      'invoice contact +91 98201 55443, PAN AAACP7788K, settlement gateway 192.0.2.44.'
    ].join('\n'),
    expected: [
      { type: 'EMAIL', normalized: 'neha.kapoor+billing@finops.example.in', status: 'CONFIRMED' },
      { type: 'CREDIT_CARD', normalized: '4111111111111111', status: 'CONFIRMED' },
      { type: 'PHONE', normalized: '+919820155443', status: 'CONFIRMED' },
      { type: 'PAN', normalized: 'AAACP7788K', status: 'CONFIRMED' },
      { type: 'IP', normalized: '192.0.2.44', status: 'CONFIRMED' }
    ]
  },
  {
    id: 'BM-02-MIXED-ORDER-AND-AMBIGUOUS-CARD',
    note: 'Order number + distant benign keyword must not hide explicitly labelled ambiguous card',
    text: 'Order 1234567890 shipped; retry failed for card 4111 1111 1111 1112.',
    expected: [
      { type: 'CREDIT_CARD', normalized: '4111111111111112', status: 'NEEDS_REVIEW' }
    ]
  },
  {
    id: 'BM-03-MIXED-INVOICE-AND-AADHAAR',
    note: 'Valid Verhoeff Aadhaar and ambiguous Aadhaar next to invoice/reference words',
    text: 'Invoice #5501 reference: Aadhaar 2345 6789 0124 verified; legacy ref check — Aadhaar 1234 5678 9012.',
    expected: [
      { type: 'AADHAAR', normalized: '2345 6789 0124', status: 'CONFIRMED' },
      { type: 'AADHAAR', normalized: '123456789012', status: 'NEEDS_REVIEW' }
    ]
  },
  {
    id: 'BM-04-DISTRACTORS-NO-PII',
    note: 'Realistic false-positive distractors: timestamps, semver/IP-like versions, order/invoice numbers, Luhn-failing numeric IDs',
    text: [
      'Build v2.14.901.33 deployed at 2026-11-27 14:05:59.412 UTC.',
      'Order 1234567890, invoice 9876543210, transaction ref 1234567890123456, receipt 000011112222.',
      'Host 300.12.4.1 unreachable; malformed mail ops@@example..com.'
    ].join('\n'),
    expected: []
  },
  {
    id: 'BM-05-IPV6-AND-INTL-PHONES',
    note: 'IPv6 forms + international phones + PAN candidate',
    text: 'Relay 2001:db8:85a3::8a2e:370:7334 and ::ffff:198.51.100.12; US desk +1 (415) 555-0199; legacy PAN ABCDE9876Z.',
    expected: [
      { type: 'IP', normalized: '2001:db8:85a3::8a2e:370:7334', status: 'CONFIRMED' },
      { type: 'IP', normalized: '::ffff:198.51.100.12', status: 'CONFIRMED' },
      { type: 'PHONE', normalized: '+14155550199', status: 'CONFIRMED' },
      { type: 'PAN', normalized: 'ABCDE9876Z', status: 'NEEDS_REVIEW' }
    ]
  },
  {
    id: 'BM-06-AMBIGUOUS-PHONE-NO-VETO-BY-TICKET',
    note: 'Support ticket prefix must not suppress explicitly labelled mobile number needing review',
    text: 'Support ticket #402: caller mobile 12345 67890 dropped.',
    expected: [
      { type: 'PHONE', normalized: '1234567890', status: 'NEEDS_REVIEW' }
    ]
  },
  {
    id: 'BM-07-UNLABELLED-LUHN-FAIL-CARD',
    note: 'Unlabelled 16-digit Luhn-failing card-like string is never confirmed; remains unflagged without card context',
    text: 'Reference batch 4111111111111112 completed.',
    expected: []
  }
];

function scoreBenchmark(cases) {
  let tp = 0, fp = 0, fn = 0;
  const perCase = [];
  for (const c of cases) {
    const got = detectAll(c.text);
    const matchedGot = new Set();
    const matchedExp = new Set();
    for (let ei = 0; ei < c.expected.length; ei++) {
      const exp = c.expected[ei];
      const gi = got.findIndex((g, idx) =>
        !matchedGot.has(idx) && g.type === exp.type && g.normalized === exp.normalized && g.reviewStatus === exp.status
      );
      if (gi !== -1) {
        matchedGot.add(gi);
        matchedExp.add(ei);
        tp++;
      } else {
        fn++;
      }
    }
    for (let gi = 0; gi < got.length; gi++) {
      if (!matchedGot.has(gi)) fp++;
    }
    perCase.push({ id: c.id, expected: c.expected.length, got: got.length, tp: matchedExp.size, fp: got.length - matchedGot.size, fn: c.expected.length - matchedExp.size });
  }
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall = tp + fn ? tp / (tp + fn) : 1;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 1;
  return { tp, fp, fn, precision, recall, f1, perCase };
}

test('benchmark: independent labeled synthetic suite achieves 100% precision and recall on supported mixed-context cases', () => {
  const res = scoreBenchmark(BENCHMARK_CASES);
  assert.equal(res.fp, 0, 'Unexpected false positives: ' + JSON.stringify(res.perCase));
  assert.equal(res.fn, 0, 'Unexpected false negatives: ' + JSON.stringify(res.perCase));
  assert.equal(res.tp, 13);
  assert.equal(res.precision, 1);
  assert.equal(res.recall, 1);
  assert.equal(res.f1, 1);
});

test('context: genuine identifiers adjacent to order/invoice/transaction/reference are never dropped', () => {
  const txt = [
    'order aarav.sharma@example.com',
    'invoice +91 98765 43210',
    'transaction 203.0.113.10',
    'reference AAAPL1234C',
    'order 2345 6789 0124',
    'invoice 4111 1111 1111 1111'
  ].join(' | ');
  const ds = detectAll(txt);
  assert.equal(ds.length, 6);
  assert.deepEqual(ds.map(d => d.type), ['EMAIL', 'PHONE', 'IP', 'PAN', 'AADHAAR', 'CREDIT_CARD']);
  assert.ok(ds.every(d => d.reviewStatus === 'CONFIRMED'));
});

test('luhn: Luhn-invalid card-like numbers are NEVER confirmed credit card detections', () => {
  const samples = [
    'card 4111 1111 1111 1112',
    'visa 5500-0055-5555-5550',
    '1234567890123456',
    '4242424242424241'
  ];
  for (const s of samples) {
    const cards = detectAll(s).filter(d => d.type === 'CREDIT_CARD');
    for (const c of cards) {
      assert.notEqual(c.reviewStatus, 'CONFIRMED');
      assert.notEqual(c.validationStatus, 'CHECKSUM_VALID');
    }
  }
});

test('xss: escapeHtml and rich renderers neutralize HTML/script payloads', () => {
  const payload = '<script>alert(1)</script><img src=x onerror="alert(2)" data-x=\'y\'> user@example.com';
  const matches = detectAll(payload);
  assert.equal(matches.length, 1);
  const hl = renderHighlighted(payload, matches);
  assert.equal(hl.includes('<script>'), false);
  assert.equal(hl.includes('<img'), false);
  assert.ok(hl.includes('&lt;script&gt;'));
  assert.ok(hl.includes('&#39;'));

  const savedPlan = state.plan;
  const savedMode = state.mode;
  try {
    state.mode = 'FULL';
    state.plan = { [sigOf(matches[0])]: '[REDACTED]' };
    const san = renderSanitizedRich(payload, matches);
    assert.equal(san.includes('<script>'), false);
    assert.equal(san.includes('<img'), false);
    assert.ok(san.includes('&lt;script&gt;'));
  } finally {
    state.plan = savedPlan;
    state.mode = savedMode;
  }
  assert.equal(escapeHtml(`a&b<c>d"e'f`), 'a&amp;b&lt;c&gt;d&quot;e&#39;f');
});

test('worker: worker.js processes large input and returns matching detections and stats', async () => {
  let posted = null;
  const origSelf = globalThis.self;
  try {
    globalThis.self = { postMessage(msg) { posted = msg; } };
    await import('../src/worker.js');
    const big = ('mail user@example.com card 4111 1111 1111 1111\n').repeat(600);
    assert.ok(big.length >= 20000);
    globalThis.self.onmessage({ data: { id: 7, text: big } });
    assert.ok(posted);
    assert.equal(posted.id, 7);
    assert.equal(posted.matches.length, 1200);
  } finally {
    globalThis.self = origSelf;
  }
});

test('leak-guard: detects excluded residuals and discloses shared blind spot on obfuscated PII', () => {
  const blindText = 'Contact John Doe at user at example dot com or 123 Main Street';
  assert.equal(detectAll(blindText).length, 0);
  assert.equal(leakScan(blindText).length, 0); // shared engine blind spot

  const raw = 'mail user@example.com and +91 98765 43210';
  const ds = detectAll(raw);
  ds[0].userDecision = 'EXCLUDED';
  const c = classifyResidual({ type: 'EMAIL', normalized: ds[0].normalized }, ds);
  assert.equal(c.reason, 'EXCLUDED');
  const exp = computeExposure(ds, [ds[0]], 0);
  assert.ok(exp.before > 0 && exp.after > 0);
});

test('report: audit report never leaks original PII, PII-bearing filenames, raw text, or alias mapping', () => {
  const saved = {
    text: state.text, matches: state.matches, sanitized: state.sanitized,
    fileName: state.fileName, fileKind: state.fileKind, mode: state.mode,
    plan: state.plan, rc: state.redactedCount, leak: state.leak, exp: state.exposure,
    decisions: state.decisions, ovr: state.overrides, store: state.pseudoStore
  };
  try {
    state.text = 'Secret doc: priya.nair@example.net card 4111 1111 1111 1111 pan AAAPL1234C';
    state.fileName = 'priya.nair@example.net-4111111111111111.csv';
    state.fileKind = 'csv';
    state.mode = 'PSEUDO';
    state.decisions = {};
    state.overrides = {};
    state.pseudoStore = createPseudoStore();
    state.matches = detectAll(state.text);
    applyDecisions();
    state.leak = null;
    state.exposure = null;

    const r = buildAuditReport();
    const txt = reportToText(r);
    const json = JSON.stringify(r);
    for (const secret of ['priya.nair@example.net', '4111', 'AAAPL1234C', 'EMAIL_001', 'CARD_001', 'Secret doc']) {
      assert.equal(json.includes(secret), false, `JSON leaked: ${secret}`);
      assert.equal(txt.includes(secret), false, `Text report leaked: ${secret}`);
    }
    assert.ok(r.exposureScore.methodology.includes('heuristic') || r.exposureScore.metric.includes('heuristic'));
    assert.ok(r.exposureScore.methodology.includes('score of 0'));
  } finally {
    Object.assign(state, {
      text: saved.text, matches: saved.matches, sanitized: saved.sanitized,
      fileName: saved.fileName, fileKind: saved.fileKind, mode: saved.mode,
      plan: saved.plan, redactedCount: saved.rc, leak: saved.leak, exposure: saved.exp,
      decisions: saved.decisions, overrides: saved.overrides, pseudoStore: saved.store
    });
  }
});

test('csv: preserves quoted commas, multiline fields, sanitizes headers, and neutralizes formula injection', () => {
  const csv = 'owner,email,note\n"Iyer, Meera","meera@example.com","line1\nline2"\n"=1+1","+91 98765 43210","@SUM(A1)"';
  const rows = Papa.parse(csv, { skipEmptyLines: false }).data;
  const store = createPseudoStore();
  const out = rows.map(row => row.map(c => {
    const s = String(c == null ? '' : c);
    const red = applyRedactions(s, detect(s), m => replacementFor(m, 'FULL', store));
    return isFormulaCell(red) ? "'" + red : red;
  }));
  const reparsed = Papa.parse(Papa.unparse(out), { skipEmptyLines: false }).data;
  assert.equal(reparsed[0].join(','), 'owner,email,note');
  assert.equal(reparsed[1][0], 'Iyer, Meera');
  assert.equal(reparsed[1][1], '[REDACTED]');
  assert.equal(reparsed[1][2], 'line1\nline2');
  assert.equal(reparsed[2][0], "'=1+1");
  assert.equal(reparsed[2][1], '[REDACTED]');
  assert.equal(reparsed[2][2], "'@SUM(A1)");
});

test('csp: production dist/index.html enforces strict CSP compatible with Vite assets and workers', () => {
  const distHtmlPath = path.join(process.cwd(), 'dist', 'index.html');
  assert.ok(fs.existsSync(distHtmlPath), 'dist/index.html must exist (run npm run build)');
  const distHtml = fs.readFileSync(distHtmlPath, 'utf8');
  const m = distHtml.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/);
  assert.ok(m, 'Production CSP meta tag missing from dist/index.html');
  const csp = m[1];
  assert.ok(csp.includes("default-src 'none'"));
  assert.ok(csp.includes("script-src 'self'"));
  assert.equal(csp.includes("script-src 'self' 'unsafe-inline'"), false);
  assert.ok(csp.includes("worker-src 'self'"));
  assert.ok(csp.includes("connect-src 'none'"));
  assert.ok(csp.includes("object-src 'none'"));
});

test('release: landing nav, CTAs, mobile menu, sidebar, export controls, firebase.json and v1.0.0 consistency', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
  const fb = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'firebase.json'), 'utf8'));
  const html = fs.readFileSync(path.join(process.cwd(), 'index.html'), 'utf8');
  const mainJs = fs.readFileSync(path.join(process.cwd(), 'src', 'main.js'), 'utf8');
  const reportJs = fs.readFileSync(path.join(process.cwd(), 'src', 'report.js'), 'utf8');

  assert.equal(pkg.version, '1.0.0');
  assert.ok(reportJs.includes('APP_VERSION = "1.0.0"'));
  assert.equal(fb.hosting.public, 'dist');
  const cspHeader = fb.hosting.headers[0].headers.find(h => h.key === 'Content-Security-Policy');
  assert.ok(cspHeader && cspHeader.value.includes("connect-src 'none'") && cspHeader.value.includes("frame-ancestors 'none'"));

  // Verify hero, nav, mobile menu, CTAs, sidebar targets and export buttons exist in index.html + main.js
  for (const id of [
    'landingNav', 'landingView', 'appView', 'btnMenu', 'mobileMenu', 'appSidebar',
    'sidePrivacy', 'sideHome', 'privacyPanel', 'btnSample', 'btnUpload',
    'btnCopy', 'btnDownload', 'btnCopy2', 'btnDownload2', 'btnCopy3',
    'btnExportTxt', 'btnExportCsv', 'btnExportCopy',
    'btnGuardReview', 'btnGuardProceed', 'btnGuardCancel',
    'btnReportTxt', 'btnReportJson', 'btnLogDownload'
  ]) {
    assert.ok(html.includes(`id="${id}"`), `Missing HTML element #${id}`);
  }
  for (const target of ['sec-dashboard', 'sec-workspace', 'sec-inspector', 'sec-reports', 'sec-promptlog', 'privacyPanel']) {
    assert.ok(html.includes(`id="${target}"`), `Missing target section #${target}`);
  }
  for (const section of ['home', 'features', 'how', 'use-cases', 'privacy', 'about']) {
    assert.ok(html.includes(`id="${section}"`) && html.includes(`data-navlink="${section}"`), `Missing nav section #${section}`);
  }
  assert.ok(html.includes('Start Sanitizing') && html.includes('Try Live Demo'));
  assert.ok(mainJs.includes('[data-app-link]') && mainJs.includes('[data-demo-link]') && mainJs.includes('#appSidebar .side-item[data-go]'));
});
