/* =====================================================================
   PRIVASHIELD — tests.js. The in-page test runner (100 checks):
      renders grouped results into the DOM. The same fixtures run
      under node:test via tests/privashield.test.js.
   ===================================================================== */

import Papa from 'papaparse';
import { TEST_FIXTURES, STAGE3_FIXTURES, CSV_TESTS, REDACTION_TESTS, STAGE6_TESTS, evalFixture } from '../tests/fixtures.js';
import { TYPE_META } from './detectors.js';
import { escapeHtml } from './sanitizer.js';
import { $ } from './session.js';

export function runTests(){
  var groups = {}, order = [];
  var pass = 0, fail = 0, total = 0;
  function pushGroup(name, item){ if (!groups[name]){ groups[name] = []; order.push(name); } groups[name].push(item); }
  TEST_FIXTURES.forEach(function(f){
    var r = evalFixture(f); total++;
    if (r.ok) pass++; else fail++;
    pushGroup(TYPE_META[f.type].label, { f:f, got:r.got, ok:r.ok, expectLabel: f.expect });
  });
  STAGE3_FIXTURES.forEach(function(f){
    var r = evalFixture(f); total++;
    if (r.ok) pass++; else fail++;
    var lbl = f.mode === "none" ? "NONE" : f.mode === "total" ? f.expectCount + " total" : f.mode === "count" ? f.expectCount + " × " + f.type : f.expect;
    pushGroup("Stage 3 · context / overlap / robustness", { f:f, got:r.got, ok:r.ok, expectLabel: lbl });
  });
  REDACTION_TESTS.forEach(function(t){
    var ok = false, err = "";
    try { ok = !!t.run(); } catch (e) { err = String(e); }
    total++;
    if (ok) pass++; else fail++;
    pushGroup("Stage 4 · redaction modes", { f:{ input:t.name, note: err || "mode / consistency assertion" }, got: ok ? "OK" : "FAIL", ok: ok, expectLabel: "OK" });
  });
  STAGE6_TESTS.forEach(function(t){
    var ok = false, err = "";
    try { ok = !!t.run(); } catch (e) { err = String(e); }
    total++;
    if (ok) pass++; else fail++;
    pushGroup("Stage 6 · leak guard / exposure / presets / audit", { f:{ input:t.name, note: err || "advanced-feature assertion" }, got: ok ? "OK" : "FAIL", ok: ok, expectLabel: "OK" });
  });
  if (Papa){
    CSV_TESTS.forEach(function(t){
      var ok = false, err = "";
      try { ok = !!t.run(); } catch (e) { err = String(e); }
      total++;
      if (ok) pass++; else fail++;
      pushGroup("CSV handling (Papa Parse)", { f:{ input:t.name, note: err || "structural assertion" }, got: ok ? "OK" : "FAIL", ok: ok, expectLabel: "OK" });
    });
  }
  $("testSummary").innerHTML = "<b>" + pass + " / " + total + " passed</b>" + (fail ? ' · <span class="fail">' + fail + " failed</span>" : " · all green");
  $("testResults").innerHTML = order.map(function(t){
    var rows = groups[t];
    var gp = rows.filter(function(r){ return r.ok; }).length;
    var html = '<div class="test-group"><h3>' + escapeHtml(t) + ' <span class="gscore">' + gp + "/" + rows.length + "</span></h3>";
    rows.forEach(function(r){
      html += '<div class="test-case"><span class="st ' + (r.ok ? "p" : "f") + '">' + (r.ok ? "PASS" : "FAIL") + "</span><span><code>" + escapeHtml(r.f.input) + "</code> — " + escapeHtml(r.f.note) + " → expect " + escapeHtml(r.expectLabel) + (r.ok ? "" : ", got " + escapeHtml(r.got)) + "</span></div>";
    });
    return html + "</div>";
  }).join("");
  return { pass:pass, fail:fail, total:total };
}
