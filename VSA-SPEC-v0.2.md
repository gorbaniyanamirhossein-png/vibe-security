# Vibe Security Attestation (VSA) — Specification v0.2

**Status:** Draft 0.2 — 20 November 2026 (supersedes v0.1 of the same day)
**Author:** Amirhossein Gorbaniyan
**License (this document):** CC BY 4.0 — Creative Commons Attribution 4.0 International
**License (JSON Schema and code):** Apache License 2.0
**Name note:** The project name, the file name `vibe-security.json`, and the check IDs are
provisional in v0.x and may change before v1.0. v0.2 is a breaking change over v0.1: the
`vibe_security_version` value, the verified tier (now signed), and the badge text all
changed. See the changelog in §10.

---

## 0. Summary

Hundreds of thousands of apps are now built with AI coding tools (Lovable, Replit, Bolt, v0,
Cursor). The dominant failure mode is not buggy code — it is the **live deployment**: databases
left world-readable, storage buckets left public, privileged keys shipped in browser code.
Documented cases include ~2,000 apps leaking sensitive data (RedAccess, May 2026), 24,664
Lovable sites returning database records without login (Crissy Field / Handelsblatt, November
2026), 72,000 profile photos leaked from a public bucket (Tea, June 2026), and 1.5 million
auth tokens leaked from a misconfigured database (Moltbook, February 2026).

Scanners exist. Checklists exist. What does not exist is a **publishable, machine-readable
attestation**: a small standard file an app serves from its own domain, stating which
live-deployment checks it passed, when, and who attested it — plus a badge that links to it.

VSA is that file. It is a transparency label, not a security guarantee — the way a nutrition
label states facts about food without claiming the food is healthy. Anyone can publish it;
anyone can verify it; no central authority, server, or account is required.

**Out of scope for v0.2:** automated probing from the static page (planned for v0.3), a
central registry of attestations, and any paid verification service. The paid layer
(independent verification) is defined in §6 as a role, not built here. **New in v0.2:**
signed verified files (§4.4), badge eligibility rules (§1 rule 7, §5.3), builder contact
and stack fields (§4.2), and a dynamic static page with a verifier signing tab (§7).

---

## 1. Trust model

VSA has two attestation tiers. The tier is a statement about **who checked**, not about how
secure the app is.

| Tier | `attestation` value | Who checks | Badge |
|---|---|---|---|
| Self-declared | `self-declared` | The app's own builder | `vibe-security · self-checked` |
| Verified | `verified` | An independent verifier named in the file, using the 4-step method (§3) | `vibe-security · verified` |

Rules:

1. **A self-declared file is a claim by the builder.** It may contain `fail` results — a
   self-declared file that honestly reports failures is more useful than one that hides them.
   Readers MUST NOT treat self-declared as independently confirmed.
2. **A verified file requires all of:** a named verifier (`verifier.name` and
   `verifier.contact`), `verifier.method` equal to `vsa-4-step`, every applicable check
   (`result` other than `not_applicable`) equal to `pass`, an unexpired `expires_at`,
   and a valid signature over the file (§4.4). If any applicable check is `fail` or
   `not_tested`, or the signature is missing or invalid, the file MUST NOT use the
   `verified` tier or the verified badge.
3. **A pass is point-in-time.** Deployments change daily. That is why `expires_at` is
   required (§4) and why no attestation is valid for more than 90 days.
4. **A pass is not a penetration test.** The 10 checks cover the deployment failures that
   have actually taken down vibe-coded apps. They do not cover business logic, payment
   flows, or targeted attacks. The file and the badge MUST NOT claim the app is "secure";
   they claim only that the listed checks passed on the listed date.
5. **No central authority.** Anyone can be a verifier. Trust in a verified file comes from
   the named verifier's reputation, not from this specification. VSA defines the format
   and the method; it does not accredit verifiers.
6. **The file's location is the ownership proof.** The file MUST be served from the app's
   own domain at `/.well-known/vibe-security.json` (§4). Only someone who controls the
   deployment can place a file there — the same principle as `security.txt` (RFC 9116) and
   the ownership proofs used by hosted scanners (meta tag, text file, or DNS record).
7. **Badge eligibility.** A badge (either tier) MUST only be shown for a file with no
   `not_tested` check: a file that answers nothing says nothing. The static page (§7)
   refuses to generate a badge until all 10 checks are answered. A file with `fail`
   results MAY still carry the self-checked badge — honest failure reporting is more
   useful than hiding failures — but the page warns the builder before generating it.

---

## 2. The 10 checks

Every check is testable **from outside the running app**, with **read-only** requests, by
someone who does not have the source code. Each check has a stable ID, a severity, a plain
test, and a fix pointer. Severities follow the judgment of the sources cited: the five
`critical` checks are the ones that have taken down real apps.

| # | ID | Check (plain words) | Severity |
|---|---|---|---|
| 1 | `database-rls` | No database table can be read without logging in | Critical |
| 2 | `storage-private` | No private file can be downloaded without logging in | Critical |
| 3 | `no-privileged-key` | No master/admin key is inside the app's browser code | Critical |
| 4 | `no-exposed-config` | No `.env`, `.git`, or config file is publicly served | Critical |
| 5 | `no-sourcemap-leak` | No source map is publicly served (or it contains no secrets) | High |
| 6 | `api-requires-auth` | Sensitive API routes refuse anonymous requests; no cross-user read | Critical |
| 7 | `security-headers` | Served over HTTPS with baseline security headers | Medium |
| 8 | `cors-restricted` | No wildcard CORS on API/data origins | High |
| 9 | `cookies-secure` | Auth cookies carry Secure + HttpOnly + SameSite | Medium |
| 10 | `no-debug-endpoints` | No public debug/admin/docs endpoint exposing live data | Medium |

### 2.1 `database-rls` (Critical)

**Test:** Using only the app's public (anonymous) credentials as found in its own frontend
code, request rows from each table/collection. **Pass** = every request returns zero rows or
is refused (HTTP 401/403). **Fail** = any request returns rows.
**Why:** The single most common vibe-coding disaster. RedAccess (May 2026) found ~2,000 apps
exposing sensitive data; Crissy Field (November 2026) found 24,664 Lovable sites returning
database records without login.
**Fix pointer:** Enable Row Level Security (Supabase) or equivalent rules (Firebase/Firestore)
and deny anonymous read on every table that holds user data.

### 2.2 `storage-private` (Critical)

**Test:** Request a private object (e.g. a user upload) and a bucket listing without logging
in. **Pass** = refused (401/403/404). **Fail** = the object downloads or the listing succeeds.
**Why:** Tea (June 2026): 72,000 profile photos leaked from a public bucket without RLS.
**Fix pointer:** Make buckets private by default; serve user files through signed URLs.

### 2.3 `no-privileged-key` (Critical)

**Test:** Search the shipped frontend code (JS bundles) for privileged credentials: Supabase
`service_role` keys, Firebase admin credentials, private API keys, database connection
strings. **Pass** = none found. **Fail** = any found.
**Why:** A service-role key in browser code lets anyone read, change, or delete all data
(BuilderAudit sample report, November 2026). Anonymous/public keys are expected in frontend
code and are NOT a failure — only privileged keys are.
**Fix pointer:** Move privileged operations to server-side functions; rotate any exposed key
immediately (removing it from code is not enough — it is already public).

### 2.4 `no-exposed-config` (Critical)

**Test:** Request `/.env`, `/.git/config`, `/config.json`, and similar paths. **Pass** = all
refused (401/403/404). **Fail** = any returns file contents.
**Why:** A served `.env` hands over every secret at once. Covered by the vibe-check scanner
and BuilderAudit.
**Fix pointer:** Never deploy config files to the public directory; block dotfiles at the
host/CDN level.

### 2.5 `no-sourcemap-leak` (High)

**Test:** Request `/*.js.map` for the shipped bundles. **Pass** = refused, or served maps
contain no secrets and no original source the builder considers private. **Fail** = a map
serves original source containing secrets.
**Why:** Public source maps reconstruct the original source, including secrets left in it
(vibe-check category 5).
**Fix pointer:** Disable source maps in production builds, or host them privately.

### 2.6 `api-requires-auth` (Critical)

**Test:** Call each sensitive API route without authentication, and (with two test accounts
where the app has accounts) request one user's data as the other user. **Pass** = anonymous
calls refused and cross-user reads refused. **Fail** = any anonymous or cross-user access
succeeds.
**Why:** Unprotected API routes and broken access control (IDOR) are vibe-check categories
2 and 4 — both critical, both found in real apps.
**Fix pointer:** Add auth middleware to every API route; check ownership on every read/write,
not just on login.

### 2.7 `security-headers` (Medium)

**Test:** Read the response headers of the app's main page. **Pass** = served over HTTPS and
at least a baseline set is present: `X-Content-Type-Options: nosniff` and framing protection
(`Content-Security-Policy` with `frame-ancestors`, or `X-Frame-Options`). A full CSP is
better but not required for v0.1. **Fail** = served over plain HTTP, or no baseline headers.
**Fix pointer:** Set headers at the host/CDN level (Vercel, Netlify, and Cloudflare all
support header configuration without code changes).

### 2.8 `cors-restricted` (High)

**Test:** Send a CORS preflight (`OPTIONS`) request to each API/data origin from an unrelated
origin. **Pass** = the response does not allow arbitrary origins (`Access-Control-Allow-Origin:
*` with credentials, or a reflected arbitrary origin). **Fail** = any origin is allowed.
**Why:** Wildcard CORS lets any website call the app's API as the visiting user (vibe-check
category 9).
**Fix pointer:** Allow only the app's own origins; never reflect the `Origin` header.

### 2.9 `cookies-secure` (Medium)

**Test:** Inspect the `Set-Cookie` headers of the login/session flow. **Pass** = auth cookies
carry `Secure`, `HttpOnly`, and `SameSite` (Lax or Strict). **Fail** = any auth cookie misses
one of the three. **Not applicable** = the app uses no cookie-based auth (e.g. token in
`Authorization` header only).
**Fix pointer:** Set the three flags in the auth configuration; most frameworks support this
in one place.

### 2.10 `no-debug-endpoints` (Medium)

**Test:** Request common debug/admin paths (`/debug`, `/admin`, `/api/docs`, `/graphql`
introspection, `/.env`-style test pages) without authentication. **Pass** = all refused, or
served pages expose no live data and no internals. **Fail** = any exposes live data, internal
paths, or admin function.
**Why:** Verbose errors and exposed debug/API-docs endpoints are vibe-check category 15;
AI builders routinely leave debug mode and docs endpoints on.
**Fix pointer:** Disable debug mode in production; put docs and admin behind authentication.

### 2.11 Result vocabulary

Each check carries exactly one `result`:

| Result | Meaning |
|---|---|
| `pass` | Tested as specified in §2 and §3; the condition holds. |
| `fail` | Tested; the condition does not hold. The `note` SHOULD say what failed (redacted — §3.3). |
| `not_applicable` | The check cannot apply to this app (e.g. `cookies-secure` for an app with no cookie auth). The `note` SHOULD say why. |
| `not_tested` | Not tested in this attestation. A file with any `not_tested` check MUST NOT use the `verified` tier (§1 rule 2). |

### 2.12 Method vocabulary

Each check carries a `method` naming how it was tested:

| Method | Meaning |
|---|---|
| `probe` | Live read-only requests against the running app (§3 step 2). |
| `manual` | A human test following §2 (e.g. two-account IDOR check). |
| `scanner` | Output of a scanner tool (e.g. vibe-check, BuilderAudit) reviewed by a human. |

For the `verified` tier, the method rule is strict: every check with result `pass` MUST
use `probe` or `manual`, and every check with result `not_applicable` MUST use `manual`
(determining that a check does not apply is a judgment call, not a probe). A scanner-only
result is not sufficient for verification: the verifier MUST confirm scanner output with
at least one independent probe (§3 step 3). (`fail` and `not_tested` cannot appear in a
verified file at all — §1 rule 2.)

---

## 3. The 4-step verification method (`vsa-4-step`)

Every verification — self-declared or independent — SHOULD follow these four steps in order.
Independent verifiers MUST follow them.

### Step 1 — Locate

Find the app's public URL and its data endpoints from public sources only: the frontend code
the app itself ships (which names its Supabase/Firebase project URL and anonymous key), and
the app's own pages. Record the app URL and the endpoints found. Do not use credentials the
app did not publish, and do not use another user's account.

### Step 2 — Probe (read-only)

Send anonymous read-only requests against the running app, one check at a time (§2):

- Only `GET`, `HEAD`, and `OPTIONS` requests. Never `POST`, `PUT`, `DELETE`, or any request
  that writes, changes, or deletes data.
- Never try to break in: no password guessing, no token forgery, no calling functions that
  send email, charge cards, or trigger side effects.
- Cap the probe at ~80 requests per app (the same cap BuilderAudit uses), so a verification
  is indistinguishable from a handful of ordinary visits.
- Only probe apps you own or are authorized to test. Probing someone else's app without
  permission may be unlawful in your jurisdiction.

### Step 3 — Confirm

For every `fail` and every `pass` that decides the tier, confirm with a second independent
request: re-request with a fresh session, or through a different path that tests the same
condition. This rules out caching, one-off errors, and stale deployments. Record redacted
evidence only (§3.3).

### Step 4 — Report

Write the attestation file (§4): one result per check, the method used, the date, and the
expiry. For the `verified` tier, add the verifier's name and contact. Publish the file at
`/.well-known/vibe-security.json` on the app's own domain, or hand it to the builder to
publish. Never publish evidence that contains user data.

### 3.1 What the method does not do

It does not test business logic, payment flows, or anything that requires logging in as a
real user. It does not look at source code (that is what linters such as VibeGuard do).
It does not prove the absence of vulnerabilities — it proves that ten specific, named
conditions held on one date.

### 3.2 Time budget

A full 4-step verification of a typical vibe-coded app takes 30–90 minutes by hand. That is
deliberate: the method is designed to be performable with a phone and a browser, without a
server, by one person.

### 3.3 Evidence rules

- Record **status codes and counts only** (e.g. "anon SELECT returned 0 rows on all 3
  tables", "GET /.env returned 404"). Never record user data, keys, or file contents.
- If a probe accidentally returns user data, stop, delete the response, and report the check
  as `fail` with the note "returned user data" — do not store or share what was returned.
- The `note` field of each check SHOULD be one sentence. Notes are public: the file is
  served from the app's own domain for anyone to read.
- **Notes MUST NOT contain secrets or user data.** No keys, tokens, passwords, or personal
  data — not even redacted fragments. Validators SHOULD warn when a note matches a
  secret-like pattern (`service_role`, `sk-`, `eyJ`, `AKIA`, `-----BEGIN`, database URLs
  with passwords). The static page (§7) warns live while the builder types.

---

## 4. The file format

### 4.1 Location and serving

- The file MUST be served at `/.well-known/vibe-security.json` on the app's own domain,
  over HTTPS, with `Content-Type: application/json`.
- The path follows the well-known URI convention (RFC 8615), the same convention
  `security.txt` uses (RFC 9116). The location is the ownership proof (§1 rule 6).
- A copy MAY also be served at `/vibe-security.json` for convenience, but the well-known
  path is canonical; readers MUST use it.

### 4.2 Fields

| Field | Required | Type | Rule |
|---|---|---|---|
| `vibe_security_version` | Yes | string | MUST be `"0.2"` for this version. |
| `app.name` | Yes | string | Human-readable app name, 1–100 chars. |
| `app.url` | Yes | string (URI) | The app's public HTTPS URL. MUST match the domain serving this file. |
| `app.contact` | No | string (URI) | A way to reach the builder about the app's security (`https:` URL or `mailto:`). Recommended: readers who find a problem should have somewhere to report it. |
| `stack.backend` | No | string (enum) | The app's data backend: `supabase`, `firebase`, `other`, or `none` (no backend). Helps readers interpret the checks. |
| `stack.builder` | No | string (enum) | The tool the app was built with: `lovable`, `replit`, `bolt`, `v0`, `cursor`, or `other`. |
| `attested_at` | Yes | string (date-time) | RFC 3339 timestamp of the attestation. |
| `expires_at` | Yes | string (date-time) | RFC 3339 timestamp. MUST be after `attested_at` and no more than 90 days after it. After this time the file MUST be treated as stale. |
| `attestation` | Yes | string (enum) | `"self-declared"` or `"verified"`. |
| `checks` | Yes | array | MUST contain exactly the 10 checks of §2, each once, in any order. |
| `checks[].id` | Yes | string (enum) | One of the 10 IDs in §2. |
| `checks[].result` | Yes | string (enum) | `pass`, `fail`, `not_applicable`, or `not_tested` (§2.11). |
| `checks[].method` | Yes | string (enum) | `probe`, `manual`, or `scanner` (§2.12). |
| `checks[].note` | No | string | One sentence, redacted (§3.3). Max 300 chars. MUST NOT contain secrets. |
| `verifier` | If verified | object or null | Required when `attestation` is `"verified"`; MUST be `null` otherwise. |
| `verifier.name` | If verified | string | Name of the independent verifier (person or organization). |
| `verifier.contact` | If verified | string (URI) | A way to reach the verifier (`https:` URL or `mailto:`). |
| `verifier.method` | If verified | string | MUST be `"vsa-4-step"`. |
| `verifier.public_key` | If verified | object (JWK) | The verifier's ECDSA P-256 public key as a JSON Web Key: `{"kty":"EC","crv":"P-256","x":"…","y":"…"}` with base64url coordinates (§4.4). |
| `signature` | If verified | string | Base64url (no padding, 86 chars) of the ECDSA P-256 signature over the canonical form of the file without this field (§4.4). MUST be absent when `attestation` is `"self-declared"`. |

The JSON Schema for this format is `schema/vibe-security.schema.json` (Apache 2.0). The
schema enforces structure, enums, and the 10-check set. Two rules cannot be expressed in
JSON Schema and MUST be enforced by validators (the static page, §7, enforces both):

- `expires_at` is after `attested_at` and no more than 90 days after it.
- `app.url` matches the domain serving the file (checked by the reader, not the file).

### 4.3 Example (self-declared, illustrative)

```json
{
  "vibe_security_version": "0.2",
  "app": {
    "name": "Example Notes App",
    "url": "https://notes.example-app.com",
    "contact": "mailto:security@example-app.com"
  },
  "stack": { "backend": "supabase", "builder": "lovable" },
  "attested_at": "2026-11-20T00:00:00Z",
  "expires_at": "2027-02-18T00:00:00Z",
  "attestation": "self-declared",
  "checks": [
    { "id": "database-rls", "result": "pass", "method": "probe", "note": "Anon SELECT returned 0 rows on all 3 tables." },
    { "id": "storage-private", "result": "pass", "method": "probe", "note": "Private object request returned 403." },
    { "id": "no-privileged-key", "result": "pass", "method": "manual", "note": "Searched shipped bundles; only the public anon key present." },
    { "id": "no-exposed-config", "result": "pass", "method": "probe", "note": "GET /.env and /.git/config returned 404." },
    { "id": "no-sourcemap-leak", "result": "pass", "method": "probe", "note": "No .map files served." },
    { "id": "api-requires-auth", "result": "pass", "method": "manual", "note": "Anonymous API calls refused; cross-user read refused." },
    { "id": "security-headers", "result": "pass", "method": "probe", "note": "HTTPS with nosniff and frame-ancestors." },
    { "id": "cors-restricted", "result": "pass", "method": "probe", "note": "Preflight from unrelated origin refused." },
    { "id": "cookies-secure", "result": "not_applicable", "method": "manual", "note": "Token auth only; no auth cookies." },
    { "id": "no-debug-endpoints", "result": "pass", "method": "probe", "note": "/debug and /api/docs return 404." }
  ],
  "verifier": null
}
```

The example above is illustrative: `notes.example-app.com` is not a real app. Full example
files (self-declared and verified, the verified one carrying a real signature) are in
`examples/`.

### 4.4 Signatures (verified tier only)

v0.1's verified tier had a hole: the verifier's name was plain text, so anyone could claim
a well-known verifier had checked their app. v0.2 closes it with signatures. Self-declared
files are never signed — there is nothing to impersonate, because the builder signs nothing.

- **Algorithm:** ECDSA with curve P-256 and SHA-256. Chosen because it is native to the
  Web Cryptography API in every modern browser — signing and verification work on a phone
  with no library and no server. (Ed25519 would need a bundled library; P-256 needs none.)
- **What is signed:** the canonical form of the file with the `signature` field removed.
- **Canonical form:** JSON Canonicalization Scheme (JCS, RFC 8785). VSA files contain no
  numbers, so in practice this is: recursively sort object keys by UTF-16 code units, then
  `JSON.stringify` with no whitespace. The reference implementation is `canonicalize()` in
  `sign.js` and in the static page — both produce byte-identical output, verified by the
  test suite.
- **Signature encoding:** the 64-byte raw ECDSA signature (`r || s`, IEEE P1363 format)
  encoded as base64url with no padding (86 characters). This is the format WebCrypto
  produces and Node's `crypto.sign` produces with `dsaEncoding: 'ieee-p1363'`.
- **Public key:** `verifier.public_key` is a JSON Web Key (JWK, RFC 7517):
  `{"kty":"EC","crv":"P-256","x":"…","y":"…"}` with base64url coordinates — the format
  WebCrypto imports and exports natively.
- **Verification steps (what a reader MUST do):** (1) check the file against the schema
  and the tier rules; (2) remove `signature`, canonicalize, and verify the signature
  against `verifier.public_key`; (3) compare `verifier.public_key` against a key the
  verifier publishes on their own domain or profile — the key inside the file is
  self-asserted, and a signature only proves the holder of the matching private key
  signed it. A signature that verifies against an unknown key proves nothing about
  identity. The static page (§7) performs steps 1–2 and reminds the reader to do step 3.
- **Key handling for verifiers:** generate the keypair in the static page's verifier tab
  (WebCrypto) or with `sign.js`; store the private key in a password manager or secure
  note — never in the file, never in a public place. If a private key leaks, the verifier
  MUST generate a new keypair and re-issue affected files; there is no revocation list
  in v0.2.

---

## 5. The badge

The badge is a static image that links to the attestation file. It is static on purpose: a
dynamic badge would need a server, and VSA has no server.

### 5.1 Badge files

Two badge SVGs are published with this specification (in the project repository, served
through any static host or CDN). The badge text carries a date so a reader can tell at a
glance whether the attestation is fresh — v0.1 badges had no date, and a stale badge looked
identical to a fresh one.

| Tier | Badge text | Colour |
|---|---|---|
| Self-declared | `vibe-security · self-checked · 2026-11` | Blue |
| Verified | `vibe-security · verified · exp 2027-02` | Green |

The self-checked badge shows the attestation month (`YYYY-MM` of `attested_at`); the
verified badge shows the expiry month (`exp YYYY-MM` of `expires_at`). The static page
generates the badge with the right date automatically.

### 5.2 Embed snippet

```html
<a href="https://YOUR-APP.com/.well-known/vibe-security.json">
  <img src="https://cdn.jsdelivr.net/gh/USER/vibe-security@main/badges/verified.svg"
       alt="vibe-security: verified">
</a>
```

Replace `USER` with the repository owner and `verified.svg` with `self-checked.svg` for the
self-declared tier. The link MUST point to the app's own attestation file, not to the
specification site — the badge is only meaningful if the reader can check the file behind it.

### 5.3 Badge rules

- The verified badge MUST only be shown while the file is unexpired and meets §1 rule 2.
  When the file expires or a check newly fails, the badge MUST be removed or replaced with
  the self-checked badge.
- **A badge is valid only if its link resolves.** A badge is a static image — anyone can
  copy it. A badge counts as valid only when the link behind it returns a valid,
  unexpired file of the same tier for the same app. Readers SHOULD click through; the
  static page's check mode (§7) does this automatically when given an app URL: it fetches
  the file, checks the domain matches, validates the tier, and reports the badge status.
  A badge whose link 404s or returns a mismatched file is not a valid badge, whatever it
  says.
- The badge MUST NOT say "secure". It says what tier the attestation is and how fresh it
  is. Any badge text claiming the app is secure is a misuse of the format.
- Anyone MAY copy the badge SVG files; they are Apache 2.0.

---

## 6. The verified tier (role definition, not a service)

This section defines what "verified" means so that any independent person can offer it. It
does not create a service, a registry, or a business. The paid layer is a future step (§9):
it is added only after real demand is demonstrated.

A verification is valid only if:

1. The verifier is independent of the builder (not the same person, not the same team).
2. The verifier followed the 4-step method (§3) and recorded `verifier.method` as
   `vsa-4-step`.
3. Every applicable check passed (§1 rule 2).
4. The verifier is named in the file with a working contact, so a reader can ask them
   about the verification.
5. The file carries the verifier's public key and a valid signature (§4.4).
6. The file is unexpired.

A verifier who issues a verified file without following the method, or who verifies their
own app, is misusing the format. Readers SHOULD check the verifier's contact, the
`attested_at` date, and the signature (steps in §4.4) before trusting a verified badge.
There is no central revocation list in v0.2; a builder who disagrees with a verification
removes the file, and the badge link then 404s — which is itself visible.

---

## 7. The static page

A single-file static page (`page/index.html`, Apache 2.0) accompanies this specification.
It runs entirely in the visitor's browser — no server, no account, no data leaving the
device — and works on a phone. v0.2 rebuilt it as a live, dynamic page: progress, summary,
and badge preview update as you answer; failing checks reveal their fix pointer on the
spot; notes are scanned live for secret-like patterns.

It has three tabs:

1. **Make a file** — three steps: enter the app (name, URL, optional contact and stack);
   answer the 10 checks (each with a one-line explanation, a one-line "how to test" hint,
   and — when marked `fail` — its fix pointer from §2); get the file and the badge. The
   page refuses to generate until all 10 checks are answered (§1 rule 7) and warns live
   if a note looks like it contains a secret (§3.3). The generated badge carries the
   attestation month (§5.1).
2. **Check a file** — paste a file's contents, or enter an app URL to fetch it from
   `/.well-known/vibe-security.json`. The page validates the file (schema rules, expiry,
   tier rules), verifies the signature for verified files (WebCrypto, §4.4), checks the
   file's `app.url` domain matches the domain it was fetched from, and reports a verdict
   — valid / expired / invalid — with the reason in plain words, including the badge
   status (§5.3).
3. **Verifier tools** — for independent verifiers: generate an ECDSA P-256 keypair
   (WebCrypto; the private key never leaves the browser — copy it into a password
   manager), and sign an attestation file: paste the file and the private key, get back
   the signed file with `verifier.public_key` and `signature` filled in. The same
   signing is available offline via `sign.js` (Node, no dependencies).

Deliberately NOT in v0.2: automated probing from the page. Browsers limit cross-origin
requests, and a probe that runs without the builder understanding it would be a footgun.
Automated probing is planned for v0.3 as an opt-in, same-origin helper.

---

## 8. Prior art and differentiation

| Neighbour | What it is | Why VSA is different |
|---|---|---|
| vibe-check (benavlabs, 155★) | Checklist + live scanner + AI audit prompt; `--json` output | A scanner and a checklist, not a publishable attestation format; no well-known file, no badge, no tiers. VSA's checks are informed by its categories 1–5, 8–9, 15. |
| BuilderAudit (Nov 2026) | Hosted service: 14 checks, free scan, $19 full report | A service with a server, not an open format; reports are per-site and private. VSA is a format anyone can publish and read without a service. |
| VibeGuard (141★) | Code linter: 47 rules, A–F grade, JSON report | Lints source code; does not test the live deployment. Its `attesta-report.json` is a sample scan output of a project named `attesta-ai`, not an attestation format (verified 20 Nov 2026). |
| raroque/vibe-security-skill (1,240★) | Agent skill for auditing vibe-coded apps | An audit skill for builders, not a publishable attestation. |
| Ingenious AI badge (Oct 2026) | Badge from a static scan of a GitHub repo | Scans code only; deployment misconfiguration (the dominant leak pattern) is invisible to it. |
| security.txt (RFC 9116) | Well-known file for vulnerability disclosure contact | The model for VSA's file location and expiry rule — but it carries contact info, not attestation results. Complementary, not competing. |
| OpenSSF Scorecard | Repo health score | Scores repositories, not live deployments; no attestation file. |

**The claim, stated narrowly:** no open, publishable, machine-readable format exists for
attesting a vibe-coded app's live-deployment security from its own domain, with a badge and
two tiers. Scanners check; checklists guide; VSA publishes. The grade is PARTIAL, not GAP:
the scanning half of the problem is crowded, and the format's value depends on adoption.

---

## 9. Honest limits and risks

1. **Self-declaration can lie.** A builder can publish a file claiming passes they never
   tested. That is why the verified tier exists, and why self-declared files must be read
   as claims, not confirmations. The format cannot fix dishonesty; it can only make claims
   checkable and dated.
2. **The badge is only as valuable as the format is known.** A "verified" badge means
   nothing until readers recognize it. Adoption — not the format itself — is the hard part.
3. **Point-in-time, and dates are self-reported.** An app can pass on Monday and leak on
   Tuesday after a redeploy. The 90-day expiry limits staleness but does not remove it.
   A signature proves who signed, not when: a backdated `attested_at` is still possible.
   Readers SHOULD treat old dates with suspicion.
4. **Ten checks are not full security.** Payment flows, business logic, and targeted
   attacks are out of scope. A verified file must never be presented as a pentest.
5. **Scanners are free.** The paid verification layer must prove human value over free
   scans (judgment, the two-account test, the written report) or nobody will pay for it.
6. **No registry, no revocation list in v0.2.** There is no central list of attestations;
   discovery happens through badges and links. A leaked verifier key can only be handled
   by the verifier publishing a new key and re-issuing files.
7. **Key distribution is the reader's job.** A signature that verifies against an unknown
   key proves nothing about identity (§4.4 step 3). Until verifiers publish their keys
   in stable places, this check is weak in practice.
8. **Legal exposure for verifiers.** A verifier who publishes a `fail` about someone
   else's app should state facts (status codes, counts) and keep evidence redacted. This
   specification is not legal advice.
9. **Name and file collisions.** `.vibe-security.json` already exists as a scanner config
   file name in one repo (korayda4/Vibe-Security); VSA's file lives at the well-known path
   and is a different thing, but the similar name may confuse. The v0.x names are
   provisional (§0).

---

## 10. License and versioning

- This specification: CC BY 4.0. You may share and adapt it, including commercially, with
  attribution.
- The JSON Schema, the static page, and the badge files: Apache License 2.0.
- Versioning: `0.x` versions may change the format in breaking ways; each breaking change
  is listed in the changelog below. `1.0` will freeze the check IDs and the field names.

### Changelog

- **0.2 (20 November 2026):** Breaking changes: `vibe_security_version` is now `"0.2"`;
  verified files MUST carry `verifier.public_key` (JWK) and a P-256 `signature` (§4.4);
  badge text now carries a date (§5.1). New optional fields: `app.contact`, `stack`
  (§4.2). New rules: badge eligibility requires all checks answered (§1 rule 7); badge
  validity requires the link to resolve (§5.3); notes MUST NOT contain secrets, with live
  warnings (§3.3); verified method rule clarified (§2.12). Static page rebuilt: live
  progress/summary/badge preview, fix hints on fail, signature verification, verifier
  signing tab (§7). Full history in `CHANGELOG.md`.
- **0.1 (20 November 2026):** First draft. 10 checks, 4-step method, file format,
  two tiers, two badges, static page. No registry, no signatures, no paid layer.

---

## Appendix A — Sources

- RedAccess, May 2026 — ~2,000 vibe-coded apps leaking sensitive data (via Axios / WIRED
  coverage).
- Crissy Field / Handelsblatt, November 2026 — 159,041 Lovable projects scanned; 24,664
  sites returning database records without login.
- Tea app, June 2026 — 72,000 profile photos leaked from a public bucket.
- Moltbook, February 2026 — 1.5M auth tokens, 35,000 emails leaked via misconfigured DB.
- Escape, October 2025 / June 2026 — 5,600 vibe-coded apps scanned; 2,000+ vulnerabilities.
- Carnegie Mellon SusVibes (ICML 2026) — 57% of SWE-agent solutions functionally correct,
  11.8% secure.
- vibe-check (benavlabs/vibe-check) — 17 vulnerability categories; live scanner.
- BuilderAudit (builderaudit.vercel.app) — 14 checks; free scan; $19 report; ~80 requests.
- VibeGuard (zeroFhacker/vibeguard) — 47-rule code linter; `attesta-report.json` verified
  20 November 2026 to be a sample scan output, not an attestation format.
- RFC 9116 — security.txt. RFC 8615 — well-known URIs.

## Appendix B — Files in this package

- `VSA-SPEC-v0.2.md` — this specification (CC BY 4.0). `VSA-SPEC-v0.1.md` is kept as history.
- `CHANGELOG.md` — version history (CC BY 4.0).
- `schema/vibe-security.schema.json` — JSON Schema (Apache 2.0).
- `examples/self-declared.example.json` — illustrative self-declared file.
- `examples/verified.example.json` — illustrative verified file with a real P-256 signature.
- `page/index.html` — static self-check page (Apache 2.0).
- `sign.js` — keypair generation and file signing (Node, no dependencies; Apache 2.0).
- `verify.js` — offline signature verification (Node, no dependencies; Apache 2.0).
- `validate.py` — validation script for examples and the schema (Apache 2.0).
- `README.md` — short introduction and how to use the package.
