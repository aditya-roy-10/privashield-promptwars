/* =====================================================================
   PRIVASHIELD — review.js (Stage 3). Manual review: approve /
      exclude per detection. reviewAction takes the render callback
      so this module stays independent of the app shell.
   ===================================================================== */

import { applyRedactions } from './redaction.js';
import { state, sigOf, planReplacement, toast } from './session.js';

/**
 * Recompute active detections, per-detection replacement plan, and
 * sanitized output from current `state.matches`, `state.decisions`,
 * `state.overrides`, and `state.categories`.
 */
export function applyDecisions() {
  state.matches.forEach((m) => {
    if (!m.baseReview) m.baseReview = m.reviewStatus;
    const d = state.decisions[sigOf(m)] || null;
    m.userDecision = d;
    m.reviewStatus = d === 'APPROVED' ? 'CONFIRMED' : m.baseReview;
  });
  state.activeMatches = state.matches.filter((m) => m.userDecision !== 'EXCLUDED');
  state.plan = {};
  state.redactedCount = 0;
  state.matches.forEach((m) => {
    const rep = planReplacement(m);
    state.plan[sigOf(m)] = rep;
    if (rep !== null) state.redactedCount++;
    m.replacement = rep;
  });
  state.sanitized = state.text ? applyRedactions(state.text, state.matches, (m) => state.plan[sigOf(m)]) : '';
}

/**
 * Record a reviewer decision ('approve' | 'exclude' | 'restore') for `id`
 * and re-render via `renderFn`.
 */
export function reviewAction(id, action, renderFn) {
  const m = state.matches.find((x) => x.id === id) || null;
  if (!m) return;
  const sig = sigOf(m);
  if (action === 'approve') {
    state.decisions[sig] = 'APPROVED';
    toast(`${id} approved — confirmed and kept in the redaction set.`);
  } else if (action === 'exclude') {
    state.decisions[sig] = 'EXCLUDED';
    toast(`${id} excluded — this value will remain visible in the sanitized output.`, true);
  } else {
    delete state.decisions[sig];
    toast(`${id} restored to its automatic status.`);
  }
  applyDecisions();
  if (renderFn) renderFn();
}
