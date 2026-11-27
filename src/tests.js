/* =====================================================================
   PRIVASHIELD — tests.js. The in-page test runner (100 checks):
      renders grouped results into the DOM. The same fixtures run
      under node:test via tests/privashield.test.js.
   ===================================================================== */

import { TEST_FIXTURES, STAGE3_FIXTURES, CSV_TESTS, REDACTION_TESTS, STAGE6_TESTS, evalFixture } from '../tests/fixtures.js';
import { TYPE_META } from './detectors.js';
import { escapeHtml } from './sanitizer.js';
import { $ } from './session.js';

export function runTests() {
  const groups = {};
  const order = [];
  let pass = 0;
  let fail = 0;
  let total = 0;

  function pushGroup(name, item) {
    if (!groups[name]) {
      groups[name] = [];
      order.push(name);
    }
    groups[name].push(item);
  }

  TEST_FIXTURES.forEach((f) => {
    const r = evalFixture(f);
    total++;
    if (r.ok) pass++;
    else fail++;
    pushGroup(TYPE_META[f.type].label, { f, got: r.got, ok: r.ok, expectLabel: f.expect });
  });

  STAGE3_FIXTURES.forEach((f) => {
    const r = evalFixture(f);
    total++;
    if (r.ok) pass++;
    else fail++;
    const lbl = f.mode === 'none' ? 'NONE' : f.mode === 'total' ? `${f.expectCount} total` : f.mode === 'count' ? `${f.expectCount} × ${f.type}` : f.expect;
    pushGroup('Stage 3 · context / overlap / robustness', { f, got: r.got, ok: r.ok, expectLabel: lbl });
  });

  const runGroupTests = (list, groupName, defaultNote) => {
    list.forEach((t) => {
      let ok = false;
      let err = '';
      try {
        ok = !!t.run();
      } catch (e) {
        err = String(e);
      }
      total++;
      if (ok) pass++;
      else fail++;
      pushGroup(groupName, {
        f: { input: t.name, note: err || defaultNote },
        got: ok ? 'OK' : 'FAIL',
        ok,
        expectLabel: 'OK'
      });
    });
  };

  runGroupTests(REDACTION_TESTS, 'Stage 4 · redaction modes', 'mode / consistency assertion');
  runGroupTests(STAGE6_TESTS, 'Stage 6 · leak guard / exposure / presets / audit', 'advanced-feature assertion');
  runGroupTests(CSV_TESTS, 'CSV handling (Papa Parse)', 'structural assertion');

  $('testSummary').innerHTML = `<b>${pass} / ${total} passed</b>${fail ? ` · <span class="fail">${fail} failed</span>` : ' · all green'}`;
  $('testResults').innerHTML = order.map((t) => {
    const rows = groups[t];
    const gp = rows.filter((r) => r.ok).length;
    const items = rows.map((r) => (
      `<div class="test-case"><span class="st ${r.ok ? 'p' : 'f'}">${r.ok ? 'PASS' : 'FAIL'}</span><span><code>${escapeHtml(r.f.input)}</code> — ${escapeHtml(r.f.note)} → expect ${escapeHtml(r.expectLabel)}${r.ok ? '' : `, got ${escapeHtml(r.got)}`}</span></div>`
    )).join('');
    return `<div class="test-group"><h3>${escapeHtml(t)} <span class="gscore">${gp}/${rows.length}</span></h3>${items}</div>`;
  }).join('');

  return { pass, fail, total };
}
