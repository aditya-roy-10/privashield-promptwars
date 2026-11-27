/* =====================================================================
   PRIVASHIELD — review.js (Stage 3). Manual review: approve /
      exclude per detection. reviewAction takes the render callback
      so this module stays independent of the app shell.
   ===================================================================== */

import { applyRedactions } from './redaction.js';
import { state, sigOf, planReplacement, toast } from './session.js';

/* Manual review: APPROVED promotes a candidate to CONFIRMED (still
   redacted); EXCLUDED leaves that one occurrence visible in the
   sanitized output and is called out by the warning banner. */
export function applyDecisions(){
  state.matches.forEach(function(m){
    if (!m.baseReview) m.baseReview = m.reviewStatus;
    var d = state.decisions[sigOf(m)] || null;
    m.userDecision = d;
    m.reviewStatus = (d === "APPROVED") ? "CONFIRMED" : m.baseReview;
  });
  state.activeMatches = state.matches.filter(function(m){ return m.userDecision !== "EXCLUDED"; });
  /* Stage 4 plan: one replacement decision per detection, computed
     once per render. Pseudonym aliases are requested in document
     order so numbering follows first appearance, and the store is
     reused across renders — aliases stay stable when the mode or
     the category filters change mid-session. */
  state.plan = {};
  state.redactedCount = 0;
  state.matches.forEach(function(m){
    var rep = planReplacement(m);
    state.plan[sigOf(m)] = rep;
    if (rep !== null) state.redactedCount++;
    m.replacement = rep;
  });
  state.sanitized = state.text ? applyRedactions(state.text, state.matches, function(m){ return state.plan[sigOf(m)]; }) : "";
}

export function reviewAction(id, action, renderFn){
  var m = null;
  state.matches.forEach(function(x){ if (x.id === id) m = x; });
  if (!m) return;
  var sig = sigOf(m);
  if (action === "approve"){ state.decisions[sig] = "APPROVED"; toast(id + " approved — confirmed and kept in the redaction set."); }
  else if (action === "exclude"){ state.decisions[sig] = "EXCLUDED"; toast(id + " excluded — this value will remain visible in the sanitized output.", true); }
  else { delete state.decisions[sig]; toast(id + " restored to its automatic status."); }
  applyDecisions();
  if (renderFn) renderFn();
}
