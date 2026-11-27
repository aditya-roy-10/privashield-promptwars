# PRIVASHIELD — TEST_REPORT.md

**Release:** `v1.0.0` (Prompt 06B — Antigravity Migration, Security/Accuracy Audit & Firebase Hosting Prep)  
**Date:** 2026-11-27  
**Stack:** Vanilla JavaScript (ES modules) · HTML · CSS · Vite 6.4.6 · Papa Parse 5.4.1 · Node 24.22.3 (`node:test`)

---

## 1. Test Count Reconciliation

Three distinct test counts exist in this repository and are preserved honestly without inflating or altering the Stage 7 baseline:

| Suite | Entry Point | Count | Scope |
|---|---|---:|---|
| In-browser Detection Test Suite | `src/tests.js` (Workspace → Tests) | **100** | 48 Stage 2 engine fixtures + 16 Stage 3 regressions + 4 CSV tests + 21 Stage 4 redaction tests + 11 Stage 6 tests from `tests/fixtures.js` |
| Baseline CLI Suite | `npm test` (`tests/privashield.test.js`) | **104** | Exact 100 shared fixture checks above + 4 Node workflow smoke tests on `SAMPLE_TEXT` (Muse baseline preserved) |
| Independent Audit & Benchmark Suite | `npm run test:audit` (`tests/audit_benchmark.mjs`) | **10** | Independent labeled synthetic benchmark (`BM-01`..`BM-07`), mixed-context checks, Luhn non-confirmation, XSS escaping, `worker.js` large-input scan, Leak Guard blind-spot check, audit-report leak test, CSV safety, production CSP check, and `v1.0.0` release/UI/Firebase structural check |

*Windows PowerShell note:* On this system, `npm.ps1` is blocked by the PowerShell execution policy (`UnauthorizedAccess`), so npm scripts execute via `npm.cmd test`, `npm.cmd run build`, `npm.cmd run test:audit`, `npm.cmd run dev`, and `npm.cmd run preview`.

---

## 2. Actual CLI & Build Results

### Baseline Suite (`npm.cmd test`)
- **Result:** **104 / 104 passing**, 0 failed, 0 skipped.
- Sample dataset (`SAMPLE_TEXT`) workflow checks verified: 44 detections (`EMAIL: 11, PHONE: 9, IP: 11, PAN: 5, AADHAAR: 3, CREDIT_CARD: 5`), `FULL` redacts 44/44, `PSEUDO` assigns 39 aliases for 39 unique normalized values, `FULL` exposure drops 84 → 0 (100% reduction), Leak Guard clean.

### Independent Audit & Benchmark Suite (`npm.cmd run test:audit`)
- **Result:** **10 / 10 passing**, 0 failed, 0 skipped.
- **Benchmark (`BM-01` through `BM-07`, 13 labeled ground-truth entities + distractors):**
  - Initial run caught **2 real engine defects** before fixes were applied:
    1. `BM-01-MIXED-FINANCE` (`FN = 1`): `ipBoundary` in `src/engine.js` rejected `192.0.2.44.` at the end of a sentence because the trailing `.` matched `/[0-9A-Fa-f:.]/`. Fixed in `src/engine.js` so `.` / `:` only blocks when adjacent to `[0-9A-Fa-f:.]`, preserving rejection of multi-dot `1.2.3.4.5`.
    2. `BM-04-DISTRACTORS-NO-PII` (`FP = 1`): `invoice 9876543210` matched `[6-9]\d{9}` as a `CONFIRMED` phone number despite being an unformatted 10-digit integer immediately labelled `invoice`. Fixed via `isBarePhoneBenignRef()` in `src/context.js` / `src/engine.js` while keeping formatted phones adjacent to benign keywords (`invoice +91 98765 43210`) confirmed.
  - Post-fix benchmark metrics: **TP = 13, FP = 0, FN = 0, Precision = 1.00, Recall = 1.00, F1 = 1.00**.

### Production Build (`npm.cmd run build`)
- **Result:** Built cleanly with Vite 6.4.6 (`23 modules transformed`) into `dist/`:
  - `dist/index.html` (contains injected `<meta http-equiv="Content-Security-Policy" ...>`)
  - `dist/assets/index-*.css`
  - `dist/assets/index-*.js`
  - `dist/assets/worker-*.js` (separate module worker bundle)

---

## 3. Security & Architecture Audit Findings

| Area | Audited Files | Findings & Status |
|---|---|---|
| **1. Context & benign keywords** | `src/context.js`, `src/engine.js` | Valid/confirmed identifiers next to `order`, `invoice`, `transaction`, `reference` bypass benign vetoes and are never silently dropped. Updated `ambiguousSweep` to use `closestKeyword()` so distant benign words do not suppress closer explicitly labelled ambiguous candidates; fixed `ipBoundary` trailing period false negative and bare 10-digit benign-ref false positive. |
| **2. `innerHTML` & XSS** | `src/main.js`, `src/sanitizer.js`, `src/advanced.js`, `src/files.js`, `src/tests.js` | All user-controlled text/values pass through `escapeHtml()`. Hardened `escapeHtml()` to also escape `'` (`&#39;`) and handle nullish inputs; added `escapeHtml()` to `expectLabel`/`got` in `src/tests.js`; verified `<script>` / `<img onerror=...>` payloads render inertly. |
| **3. Web Worker & async** | `src/perf.js`, `src/worker.js`, `src/main.js` | Fixed race condition where clearing a session or editing below 20k chars while a worker scan was in-flight did not invalidate `workerReq`, and pending 250 ms `debounce` was not cancelled on `process()`. Verified `worker.js` message handling on >20k chars and `onerror` synchronous fallback logic. |
| **4. Leak Guard** | `src/advanced.js`, `index.html`, `src/report.js` | Verified Leak Guard re-scans `state.sanitized` using `detectAll()` (restoring `engineStats`), classifies `EXCLUDED` / `CATEGORY_OFF` / `KEEP_OVERRIDE` / `UNRESOLVED`, and tracks partial-mask residual count. Updated UI and reports to disclose explicitly that Leak Guard shares the primary engine's blind spots. |
| **5. Audit reports** | `src/report.js` | Verified JSON and `.txt` audit reports contain counts/metadata only — tested with PII in document text, PII in filename (`priya.nair@example.net-4111111111111111.csv`), and `PSEUDO` mode (`EMAIL_001`, `CARD_001`). Zero PII, zero filenames, zero raw text, and zero alias mappings appear in either output. |
| **6. CSV & downloads** | `src/files.js`, `src/sanitizer.js` | Verified Papa Parse preserves headers, row/column structure, quoted commas, and multiline cells; sanitizes PII per cell including headers; neutralizes formula-leading cells (`=`, `+`, `-`, `@`) with a leading `'` on export. |
| **7. Luhn-invalid cards** | `src/validators.js`, `src/context.js`, `src/main.js` | `validateCard()` rejects all Luhn failures; `ambiguousSweep()` surfaces card-keyword-supported failures only as `NEEDS_REVIEW` (`AMBIGUOUS`). Fixed `sub-CREDIT_CARD` (and `sub-AADHAAR`) in `src/main.js` so candidate counts appear and reviewer-approved Luhn-failing candidates are never labelled `Luhn-valid`. |
| **8. Exposure heuristic** | `src/advanced.js`, `src/report.js`, `index.html` | Labeled explicitly as an estimated heuristic (`score = 100 * (1 - 1/(1 + total/50))`), not a compliance score. Explicitly states that a score of `0` means no residual exposure measured by the supported scoring rules, not guaranteed anonymization. |
| **9. Production CSP** | `vite.config.js`, `dist/index.html` | Enforced via Vite build plugin in `dist/index.html`: `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self'; connect-src 'none'; font-src 'self'; base-uri 'self'; form-action 'none'; object-src 'none'`. `vite preview` also sends `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Verified `script-src` has no `'unsafe-inline'` or `'unsafe-eval'` and `connect-src` is `'none'`. |
| **10. Release & Firebase Hosting** | `firebase.json`, `.firebaserc`, `package.json`, `index.html`, `src/report.js`, `DEMO_SCRIPT.md` | Set release `v1.0.0` consistently across `package.json`, `APP_VERSION`, and UI; verified hero, nav, mobile menu, CTAs, workspace sidebar, and all export/guard/report controls; configured `.firebaserc` (`privashield-promptwars`) and deployed `dist/` (`4` files) to `https://privashield-promptwars.web.app`. Verified HTTP `200` and all HTTP security headers on the live URL and assets. |
| **13–14. Documentation accuracy** | `README.md`, `index.html`, `PROMPT_LOG.md`, `DEMO_SCRIPT.md`, `src/sampleData.js` | Corrected Web Worker claim (workers normally have network access; PRIVASHIELD makes zero calls and production CSP sets `connect-src 'none'`), corrected partial masking reversibility claim (lossy but retains identifying fragments enabling potential re-identification; pseudonymization preserves linkability and is reversible if the mapping is available), added `DEMO_SCRIPT.md`, and updated both repo and in-app prompt logs. |

---

## 4. Local Server & Browser Offline Verification Status

- **Vite Dev Server (`npm.cmd run dev`, `http://localhost:5174/`):** Verified HTTP 200 responses for `/`, `/src/main.js`, `/src/worker.js`, and `/src/styles.css`.
- **Vite Production Preview (`npm.cmd run preview -- --port 4173 --strictPort`, `http://localhost:4173/`):** Verified HTTP 200 response for `dist/index.html` (`98,144` bytes) with both HTTP `Content-Security-Policy` response header and embedded `<meta http-equiv="Content-Security-Policy">` tag.
- **Firebase Hosting Live Deployment (`https://privashield-promptwars.web.app/`):** Deployed `4` files from `dist/` cleanly for project `privashield-promptwars`. Verified HTTP `200` on `/`, `/assets/index-B79yaOz1.css`, `/assets/index-CAOXWNsL.js`, and `/assets/worker-WrqIq1dY.js`, along with live `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and immutable `/assets/**` `Cache-Control` headers.
- **Live Chrome Interactive / Offline Browser Test:** **Not executed (blocked by environment).** Invoking the Chrome DevTools MCP browser agent against both local preview and `https://privashield-promptwars.web.app/` failed immediately with:
  > `Could not connect to Chrome. Check if Chrome is running and remote debugging is enabled by going to chrome://inspect/#remote-debugging.`  
  > `Cause: ENOENT: no such file or directory, open 'C:\Users\Aditya Roy\AppData\Local\Google\Chrome\User Data\DevToolsActivePort'`

  To run the live offline browser test against the production build in this environment:
  1. Launch Google Chrome with remote debugging enabled (`chrome://inspect/#remote-debugging`).
  2. Run `npm.cmd run build && npm.cmd run preview -- --port 4173 --strictPort`.
  3. Open `http://localhost:4173/`, switch Chrome DevTools Network tab to **Offline**, and verify zero CSP console errors, 100/100 in-page tests, sample loader, all three redaction modes, manual review, Web Worker on ≥20k chars, Leak Guard, and Blob downloads.
