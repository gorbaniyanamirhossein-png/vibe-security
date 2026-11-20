# Changelog — Vibe Security Attestation (VSA)

All notable changes to this project. The format is inspired by Keep a Changelog.
Versions before 1.0 may include breaking changes; each entry says so.

## [0.2] — 2026-11-20

First critical review of v0.1 found 12 problems; all 12 are fixed here. **Breaking
changes:** `vibe_security_version` is now `"0.2"`; verified files MUST be signed;
badge text now carries a date.

### Fixed

- **Verified-tier impersonation (critical).** In v0.1 the verifier's name was plain text,
  so anyone could claim a well-known verifier had checked their app. Verified files now
  carry `verifier.public_key` (ECDSA P-256 JWK) and a `signature` (base64url, 86 chars)
  over the JCS canonical form of the file. P-256 was chosen because it is native to the
  Web Cryptography API — signing and verification work in a phone browser with no
  library and no server. Readers MUST also compare the key against one the verifier
  publishes on their own domain or profile (spec §4.4).
- **Empty files could earn a badge.** A file with all 10 checks `not_tested` was valid
  in v0.1. Badges now require every check answered (§1 rule 7); the page refuses to
  generate until all 10 are answered.
- **Badges had no binding to the file.** Anyone could paste the verified badge with no
  file behind it. A badge is now valid only if its link resolves to a valid, unexpired
  file of the same tier (§5.3); the page's check mode verifies this automatically when
  given an app URL.
- **Spec/validator mismatch on verified methods.** v0.1's spec said every verified check
  MUST use `probe` or `manual`, but the validators only enforced it for `pass`. Clarified:
  `pass` requires `probe` or `manual`; `not_applicable` requires `manual`; enforced in
  both validators (§2.12).
- **Notes could leak secrets.** Free-text notes had no protection. Notes MUST NOT contain
  secrets (§3.3); the page warns live while the builder types and again before generating.
- **Page wiped note inputs.** In v0.1, clicking a result button re-rendered the whole
  check list and visually cleared typed notes. The page now updates cards in place.
- **`validate.py` ignored `format` and crashed on bad dates.** `format` is now enforced
  via a format checker, and date parsing fails gracefully instead of raising.

### Added

- **Optional `app.contact`** — a way to reach the builder about the app's security
  (readers who find a problem need somewhere to report it).
- **Optional `stack`** — `backend` (supabase / firebase / other / none) and `builder`
  (lovable / replit / bolt / v0 / cursor / other), so readers can interpret the checks.
- **Dated badges.** Self-checked badges show the attestation month
  (`self-checked · 2026-11`); verified badges show the expiry month
  (`verified · exp 2027-02`). A stale badge no longer looks identical to a fresh one.
- **Domain-match check.** The page's check mode compares the file's `app.url` domain with
  the domain it was fetched from and reports a mismatch.
- **Verifier tools tab** in the static page: generate a P-256 keypair (WebCrypto) and sign
  an attestation file in the browser. The same signing is available offline via `sign.js`.
- **`sign.js` / `verify.js`** — dependency-free Node tools for keypair generation, signing,
  and offline signature verification.
- **Dynamic, live page.** Animated progress ring, live pass/fail summary, live badge
  preview, per-check fix hints that appear when a check is marked `fail`, and a sticky
  progress bar. Respects `prefers-reduced-motion`.

### Changed

- Automated probing from the page moved from "planned for v0.2" to "planned for v0.3".
- `validate.py` now runs 35 checks (was 21), including signature verification via
  `node verify.js` and a tampered-file negative test.

## [0.1] — 2026-11-20

First draft.

- 10 live-deployment checks with severity, plain-language meaning, test method, and fix
  pointer (spec §2).
- 4-step verification method `vsa-4-step`: Locate → Probe → Confirm → Report (spec §3).
- File format `/.well-known/vibe-security.json`, modeled on RFC 9116 `security.txt`,
  with a 90-day expiry (spec §4).
- Two tiers: `self-declared` and `verified` (spec §1, §6).
- Two static SVG badges (spec §5).
- Single-file static self-check page: 3-step generator + check mode (spec §7).
- JSON Schema, two illustrative example files, `validate.py` (21 checks).
- No registry, no signatures, no paid layer.

[0.2]: VSA-SPEC-v0.2.md
[0.1]: VSA-SPEC-v0.1.md
