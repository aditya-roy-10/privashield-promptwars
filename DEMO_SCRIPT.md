# PRIVASHIELD — Live Demo Script (`v1.0.0`)

**Tagline:** *Share the data. Not the identity.*  
**Safety rule:** All inputs below are **100% synthetic** — never paste or upload real personal or confidential data during a demo.

---

## 1. Landing Page & Trust Architecture (`#/`)

1. Open the app at `#/` (either `npm run preview` locally or the static Firebase Hosting URL once deployed).
2. Show the sticky navigation (`Home`, `Features`, `How It Works`, `Use Cases`, `Privacy`, `About`), theme toggle (`Dark` / `Light`), and `Launch App` button.
3. Highlight the hero section:
   - Headline: **Share the data. Not the identity.**
   - Client-Side Processing badge and three guarantees: *No sign-up required*, *No backend processing*, *No sensitive document transmission*.
   - Optional: open browser DevTools (`F12` → Network) to show zero outbound requests during scanning and sanitization.
4. Click **Try Live Demo** in the hero to jump straight into `#/app` with the synthetic noisy dataset loaded automatically.
   *(Alternatively, click **Start Sanitizing** to open an empty workspace, or test **Back to Home** in the sidebar to show hash routing preserves the in-memory document.)*

---

## 2. Detection, Validation & Analytics (`#/app`)

1. Point out the live KPI cards computed from the loaded synthetic dataset:
   - **44** total detected occurrences across all 6 categories (`Email 11`, `Phone 9`, `IP 11`, `PAN 5`, `Aadhaar 3`, `Credit card 5`).
   - **39** unique normalized identifiers.
   - **44** redacted occurrences in `FULL` mode, **0** remaining supported PII matches.
2. Explain **Validation ≠ Verification**:
   - Cards require Luhn (`4111 1111 1111 1111` passes; `1234567890123456` next to `order total` is rejected).
   - Aadhaar uses Verhoeff (`2345 6789 0124` is `CHECKSUM_VALID`; `2345 6789 0123` surfaces as `FORMAT_CANDIDATE` / `NEEDS_REVIEW`).
   - PAN validates holder code (`AAAPL1234C` vs `ABCDE1234F` candidate).
   - Mixed-context handling keeps genuine identifiers next to `order`/`invoice`/`transaction`/`reference` while surfacing `"card number 4111 1111 1111 1112"` as an ambiguous candidate for human review rather than confirming it.
3. Click any category card or **Locate** in the Detection Inspector to scroll and flash that occurrence in the **Original — highlighted** pane.

---

## 3. Three Redaction Modes & Industry Presets

1. **Full Mask (`FULL`):** Every approved detection becomes `[REDACTED]`. Exposure heuristic drops from **84 → 0** (`100%` reduction), and Leak Guard reports no supported PII patterns remaining.
2. **Partial Mask (`PARTIAL`):** Click **Partial Mask** (or apply the **Customer support** preset). Show per-type masking (`a***a@m***.in`, `***-***-3210`, `XXXX XXXX 0124`, `**** **** **** 1111`, `192.168.*.*`). Point out the explicit warning: partial masking retains identifying fragments that may enable re-identification.
3. **Pseudonymization (`PSEUDO`):** Click **Pseudonymize** (or apply **Healthcare** / **Human resources**). Show repeated values and formatting variants (`+91 98110 24680` and `98110 24680`) sharing one stable alias (`PHONE_001`..), **39** alias chips in memory only, and the explicit notice that pseudonymization preserves linkability and is not irreversible anonymization.
4. Click **Finance** preset to return cleanly to `FULL` mode with all 6 categories enabled.

---

## 4. Manual Review, Leak Guard & Export Guard

1. In the **Detection Inspector**, click **Exclude** on one detection (e.g., `DET-0001`).
2. Observe instant UI updates without re-scanning:
   - **Remaining PII matches** rises to `1` and the red review warning banner appears.
   - **Leak Guard** re-scans the sanitized output, lists the residual value with reason **Excluded in review**, and raises the residual exposure score.
3. Click **Download .txt** in the Export panel: the **Export guard** pauses the download and offers *Review remaining matches*, *Export anyway*, or *Cancel export*.
4. Click **Cancel export**, then click **Restore** on `DET-0001` (or **Resolve** in Leak Guard) to return remaining matches to `0`.

---

## 5. Exports, Audit Report & Session Wipe

1. Click **Download .txt** or **Download .csv** (for CSV uploads, Papa Parse preserves quoted commas, multiline fields, and neutralizes formula-leading cells starting with `=`, `+`, `-`, `@`).
2. Click **Download report (.txt)** or **Download report (.json)** in **Sanitization audit report**:
   - Show the generated Web Crypto **SHA-256** digest of the sanitized output.
   - Point out the report contains counts and metadata only — zero original PII, zero raw text, zero original filename, and zero alias mappings — and is labelled an application-generated report, not a compliance certificate.
3. Open **Tests** → **Run tests** (or point to `100 / 100 passed` in-page), and mention CLI verification (`104/104` baseline + `9/9` audit/benchmark checks).
4. Finish by clicking **Clear session** to wipe all in-memory text, decisions, and pseudonym mappings.
