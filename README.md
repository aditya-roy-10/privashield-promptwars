# PRIVASHIELD

> **Share the data. Not the identity.**

PRIVASHIELD is a browser-based PII detection, classification and
sanitization tool. Paste text or upload a TXT/CSV file and it finds
emails, phone numbers, IP addresses, PAN numbers, Aadhaar numbers and
credit/debit card numbers, classifies them with context awareness,
lets you review each finding, and exports a sanitized copy — with a
full audit report.

## Privacy architecture — 100% client-side

- **No backend, no database, no external AI APIs, no telemetry.**
- Your documents are **never transmitted, uploaded, or persistently
  stored**. Everything runs in the browser tab.
- The sample data shipped with the app is **entirely synthetic** —
  fictional names, documentation-range IPs (`203.0.113.x`), and
  format-valid test identifiers. No real PII anywhere in the repo.
- The Web Worker used for large inputs runs the same local engine code in
  the same tab and has no DOM access. While browser Web Workers can normally
  make network requests, PRIVASHIELD's worker makes zero network calls, and the
  production Content Security Policy (`connect-src 'none'`) restricts outbound
  connections across both the main thread and workers.
- The pseudonymization alias map lives only in memory for the current
  document and is never written to disk or included in any export.
- The audit report is built purely from counts and metadata — it
  contains **no original PII values, no raw text, no original
  filename, and no alias mapping**.
- The app makes **zero runtime network requests** (Papa Parse ships
  as an npm dependency; fonts use the local system stack).

## Quick start

**Prerequisites:** Node.js 18+ and npm.

```bash
npm install
npm run dev      # start the dev server (Vite)
npm run build    # production build into dist/
npm run preview  # serve the production build locally
npm test         # run the test suite (node:test, no extra framework)
```

Open the dev server URL in a browser. The landing page lives at `#/`
and the workspace at `#/app`.

## What it does

- **Detection** — one detector per entity type (Email, Phone, IP,
  PAN, Aadhaar, Credit Card), each with a format validator:
  Luhn for cards, Verhoeff for Aadhaar, IPv4/IPv6 parsers, PAN
  holder-code rules, email/phone rules.
- **Context-aware classification** — ±80-character keyword evidence,
  a benign-context veto (docs, examples, test data, placeholders)
  and an ambiguity sweep that resolves overlaps (e.g. a 12-digit
  run that is an Aadhaar, not a phone number).
- **Manual review** — approve or exclude individual detections before
  export; excluded items keep their original text.
- **Three redaction modes** — FULL (`[REDACTED]`), PARTIAL (per-type
  masking policies, e.g. `j•••@example.com`), and PSEUDO
  (consistent document-scoped aliases such as `EMAIL_1`,
  `AADHAAR_2`).
- **CSV support** — per-cell redaction via Papa Parse; headers, row /
  column order, quoted commas and multiline values survive, and
  formula-leading cells are neutralized against CSV injection.
- **Leak Guard** — a second pass over the sanitized output that
  catches residual fragments, plus a Privacy Exposure Score
  (0–100) before/after redaction.
- **Industry presets** — Finance, Healthcare, HR, Legal, Support
  (each sets a redaction mode and re-enables every category).
- **Audit certificate** — sanitization report (text/JSON) with
  SHA-256 of the sanitized output; the report deliberately contains
  no original values.
- **Synthetic demo lab** — four labelled sample documents (finance,
  healthcare, HR, support) to try the tool without pasting real data.
- **In-page test suite** — the 100 core fixture checks run in the browser
  (workspace → Tests) and also form the first 100 checks of `npm test`.

## Project structure

```
privashield/
├─ index.html              landing page (#/) + workspace (#/app), hash router
├─ package.json            vite + papaparse (v1.0.0)
├─ vite.config.js          production CSP build plugin + preview headers
├─ eslint.config.mjs       ESLint flat config (browser, worker, Node suites)
├─ firebase.json           static Firebase Hosting config (public: dist)
├─ tsconfig.json           TypeScript config (non-emitting editor aid; code is JS)
├─ README.md
├─ PROMPT_LOG.md           stage-by-stage build & audit record
├─ TEST_REPORT.md          reconciled test counts, benchmark & audit report
├─ DEMO_SCRIPT.md          synthetic live demonstration script
├─ src/
│  ├─ main.js              app bootstrap · scan/worker pipeline · mode controls · workspace wiring
│  ├─ stats.js             pure document stats · entity breakdowns · risk & line offsets
│  ├─ render.js            KPI summary · comparison panes · findings table · SVG analytics
│  ├─ router.js            landing navigation · hash router (#/ ↔ #/app) · sidebar · theme sync
│  ├─ validators.js       Luhn · Verhoeff · IPv4/IPv6 · PAN holder codes · email/phone rules
│  ├─ detectors.js        one detector + validator per type
│  ├─ context.js          ±80-char keyword evidence · closest-keyword veto · ambiguity sweep
│  ├─ engine.js           candidates → validation → overlap resolution → Detection objects
│  ├─ redaction.js        FULL [REDACTED] · PARTIAL per-type policies · PSEUDO alias store
│  ├─ sanitizer.js        offset-safe replacement · mode-aware views · HTML escaping · formula check
│  ├─ session.js          in-memory session state · decisions · overrides · toast · flash helper
│  ├─ review.js           approve / exclude per detection
│  ├─ perf.js             Web Worker scan for inputs ≥ 20k chars
│  ├─ worker.js           worker entry (engine only, no DOM)
│  ├─ files.js            FileReader · Papa Parse CSV · per-cell redaction · Blob downloads
│  ├─ advanced.js         Leak Guard · exposure score · presets · demo lab · export guard
│  ├─ report.js           sanitization audit report (text/JSON + SHA-256)
│  ├─ sampleData.js       synthetic noisy dataset · demo lab data · PROMPT_LOG text
│  ├─ tests.js            in-page test runner (100 checks)
│  └─ styles.css          dark navy / emerald theme
└─ tests/
   ├─ fixtures.js         synthetic fixtures (100 shared checks)
   ├─ privashield.test.js baseline node:test runner — 104 tests (npm test)
   └─ audit_benchmark.mjs independent benchmark & security checks (npm run test:audit)
```

## Tests

There are three complementary test counts in this repository:

1. **In-browser Detection Test Suite (`src/tests.js`, workspace → Tests):**
   **100/100** fixture checks (48 Stage 2 engine fixtures, 16 Stage 3
   context/overlap/robustness regressions, 4 CSV tests, 21 Stage 4
   redaction tests, and 11 Stage 6 tests) from `tests/fixtures.js`.
2. **Baseline CLI Suite (`npm test` → `tests/privashield.test.js`):**
   **104/104 passing** — the exact 100 shared fixture checks above plus 4
   Node workflow smoke tests against `SAMPLE_TEXT` (44 detections; FULL
   redacts 44/44; PSEUDO assigns 39 aliases for 39 unique values;
   exposure 84 → 0, 100% reduction, Leak Guard clean). This preserves
   Muse's 104-test baseline.
3. **Independent Audit & Benchmark Suite (`npm run test:audit` →
   `tests/audit_benchmark.mjs`):** runs an independent labeled synthetic
   benchmark (with mixed-context documents and distractors) plus security,
   XSS, worker, CSV, Leak Guard, audit-report, and production-CSP checks,
   recorded in `TEST_REPORT.md`.

Note: the `test` script is `node --test` (bare). The directory form
`node --test tests/` is rejected by Node 24 on this machine (it tries
to load the directory as a module); the bare form discovers
`tests/privashield.test.js` automatically and preserves the 104-test
baseline.

## Build & Firebase Hosting Deployment

**Live URL:** https://privashield-promptwars.web.app  
**Firebase Project ID:** `privashield-promptwars` (Project Number `472431115869`)

`npm run build` produces `dist/` (Vite 6.4.6) and injects a production
Content Security Policy (`default-src 'none'; script-src 'self';
style-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self';
connect-src 'none'; font-src 'self'; base-uri 'self'; form-action 'none';
object-src 'none'`) into `dist/index.html`.

`firebase.json` and `.firebaserc` deploy only `dist/` to classic static
Firebase Hosting (zero Firebase runtime SDKs, Auth, Firestore, Functions, or
Analytics) with SPA rewrites, immutable asset caching under `/assets/**`, and
HTTP security headers (`Content-Security-Policy` including `frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, and `Permissions-Policy`).

To lint, test, build, and deploy updates (on Windows PowerShell, use `.cmd` shims):

```bash
npm.cmd run lint
npm.cmd test
npm.cmd run test:audit
npm.cmd run build
firebase.cmd deploy --only hosting --project privashield-promptwars
```

See [TEST_REPORT.md](TEST_REPORT.md) for the full audit and benchmark results,
and [DEMO_SCRIPT.md](DEMO_SCRIPT.md) for the live synthetic demonstration walkthrough.

## Known limitations

- **Intentional vanilla-JavaScript architecture.**
  PRIVASHIELD ships as a dependency-light, modular **vanilla-JavaScript**
  static app (ES modules + Vite + Papa Parse) with an acyclic dependency
  graph across detection, state, stats, rendering, and routing modules.
  There is no React or TypeScript runtime layer.
- **Regex/pattern detection cannot guarantee complete anonymization.**
  Detection is pattern + format-validation + context evidence; novel
  formats, obfuscated values (e.g. "zero three" instead of "03") and
  values split across lines can be missed. Always review the
  findings and run Leak Guard before sharing a document.
- **Partial masking retains identifying fragments; pseudonymization preserves linkability.**
  `PARTIAL` masking is lossy rather than cryptographically reversible, yet it
  deliberately retains fragments (such as last-4 digits or domain characters)
  that may enable re-identification when combined with other data.
  `PSEUDO` aliases are consistent within a document, preserving linkability
  and allowing reversal if the alias mapping (or original document) is
  available. Only `FULL` redaction removes the matched characters entirely
  (and unsupported PII patterns can still remain outside engine scope).
  The alias map is never exported — it exists in tab memory only while the
  session is open.
- **Aadhaar Verhoeff/format validation is mathematical, not identity
  verification.** A 12-digit number that passes Verhoeff is
  *format-valid*; it says nothing about whether the number belongs
  to a real person.
- **The Web Worker is a best-effort optimization.** If the worker
  fails to start (e.g. strict CSP, `file://` serving), the app falls
  back to a synchronous scan on the main thread.
- **CSV formula neutralization** prefixes formula-leading cells with
  an apostrophe on export; it does not protect against every
  spreadsheet-injection variant.

## Prompt log

See [PROMPT_LOG.md](PROMPT_LOG.md) — the stage-by-stage build, audit,
deployment, and Prompt 09 code-quality refactoring record.
