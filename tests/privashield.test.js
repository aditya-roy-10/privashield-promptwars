/* PRIVASHIELD — Node test suite (node:test, no extra framework).
   Mirrors the in-page suite (100 checks: 48 engine fixtures, 16 stage-3
   fixtures, 4 CSV tests, 21 redaction tests, 11 stage-6 tests) plus
   workflow smoke tests against the sample dataset.
   Run with: npm test   (node --test tests/) */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TEST_FIXTURES, STAGE3_FIXTURES, CSV_TESTS, REDACTION_TESTS, STAGE6_TESTS, evalFixture } from './fixtures.js';
import { detectAll } from '../src/engine.js';
import { createPseudoStore, replacementFor, applyRedactions } from '../src/redaction.js';
import { SAMPLE_TEXT } from '../src/sampleData.js';
import { leakScan, computeExposure } from '../src/advanced.js';

for (const f of TEST_FIXTURES) {
  test(`engine: ${f.type} — ${f.note} (${f.input})`, () => {
    const r = evalFixture(f);
    assert.equal(r.ok, true, `expected ${f.expect}, got ${r.got}`);
  });
}
for (const f of STAGE3_FIXTURES) {
  test(`stage3: ${f.note} (${JSON.stringify(f.input)})`, () => {
    const r = evalFixture(f);
    assert.equal(r.ok, true, `expected ${JSON.stringify(f.expect ?? f.expectCount)}, got ${r.got}`);
  });
}
for (const t of CSV_TESTS) {
  test(`csv: ${t.name}`, () => assert.equal(t.run(), true));
}
for (const t of REDACTION_TESTS) {
  test(`redaction: ${t.name}`, () => assert.equal(t.run(), true));
}
for (const t of STAGE6_TESTS) {
  test(`stage6: ${t.name}`, () => assert.equal(t.run(), true));
}

/* --- workflow smoke tests against the sample dataset --- */
test('workflow: sample scan yields 44 detections with the expected distribution', () => {
  const ds = detectAll(SAMPLE_TEXT);
  const counts = {};
  ds.forEach(m => { counts[m.type] = (counts[m.type] || 0) + 1; });
  assert.equal(ds.length, 44);
  assert.deepEqual(counts, { EMAIL: 11, PHONE: 9, IP: 11, PAN: 5, AADHAAR: 3, CREDIT_CARD: 5 });
});
test('workflow: FULL mode redacts 44/44', () => {
  const ds = detectAll(SAMPLE_TEXT);
  const s = createPseudoStore();
  const out = applyRedactions(SAMPLE_TEXT, ds, m => replacementFor(m, 'FULL', s));
  assert.equal((out.match(/\[REDACTED\]/g) || []).length, 44);
});
test('workflow: PSEUDO assigns 39 aliases for 39 unique values', () => {
  const ds = detectAll(SAMPLE_TEXT);
  const s = createPseudoStore();
  applyRedactions(SAMPLE_TEXT, ds, m => replacementFor(m, 'PSEUDO', s));
  assert.equal(s.size(), 39);
});
test('workflow: FULL mode exposure 84 -> 0 (100% reduction), Leak Guard clean', () => {
  const ds = detectAll(SAMPLE_TEXT);
  const s = createPseudoStore();
  const out = applyRedactions(SAMPLE_TEXT, ds, m => replacementFor(m, 'FULL', s));
  const e = computeExposure(ds, leakScan(out), 0);
  assert.equal(e.before, 84);
  assert.equal(e.after, 0);
  assert.equal(e.reduction, 100);
  assert.equal(leakScan(out).length, 0);
});
