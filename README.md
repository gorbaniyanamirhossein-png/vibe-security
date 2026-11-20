# Vibe Security Attestation (VSA) — v0.2

A publishable, machine-readable security check for apps built with AI tools
(Lovable, Replit, Bolt, v0, Cursor). No server, no account, no central authority.

**The idea in one line:** a small standard file (`/.well-known/vibe-security.json`) an app
serves from its own domain, stating which of 10 live-deployment security checks it passed,
when, and who attested it — plus a badge that links to it. A transparency label, not a
security guarantee. Verified files are cryptographically signed (ECDSA P-256).

## Files

| File | What it is | License |
|---|---|---|
| `VSA-SPEC-v0.2.md` | The specification: 10 checks, 4-step verification method, signatures, file format, badge, trust model | CC BY 4.0 |
| `VSA-SPEC-v0.1.md` | The first draft, kept as history | CC BY 4.0 |
| `CHANGELOG.md` | Version history, including the 12 problems v0.2 fixed | CC BY 4.0 |
| `schema/vibe-security.schema.json` | JSON Schema for the attestation file | Apache 2.0 |
| `examples/self-declared.example.json` | Illustrative self-declared file (fictional app) | CC BY 4.0 |
| `examples/verified.example.json` | Illustrative verified file with a real P-256 signature | CC BY 4.0 |
| `page/index.html` | Static self-check page: make a file, check a file, verifier tools. Runs fully in the browser, works on a phone | Apache 2.0 |
| `sign.js` | Keypair generation and file signing (Node, no dependencies) | Apache 2.0 |
| `verify.js` | Offline signature verification (Node, no dependencies) | Apache 2.0 |
| `validate.py` | Validation script: schema + expiry + tier rules + signatures, including negative tests (35 checks) | Apache 2.0 |

## Quick start (builder)

1. Open `page/index.html` in a browser (or host it anywhere static — GitHub Pages works).
2. Enter your app, answer the 10 checks, generate `vibe-security.json`.
3. Upload the file to `/.well-known/vibe-security.json` on your app's domain.
4. Paste the badge snippet into your app. Done — the file expires in 90 days.

## Quick start (verifier)

1. Open `page/index.html` → **Verifier tools** → generate a keypair. Publish the public
   key on your profile; keep the private key in a password manager.
2. Run the 4-step method on the app (§3 of the spec), fill in the checks, and sign the
   file in the same tab — or offline with `node sign.js sign <file> <private.jwk> <name> <contact>`.
3. Anyone can verify the signature in the page's **Check a file** tab or with
   `node verify.js <file>`.

## The 10 checks

1. No table readable without login · 2. No private file downloadable without login ·
3. No master key in browser code · 4. No `.env` / `.git` served · 5. No source-map leak ·
6. API routes need login · 7. HTTPS + headers · 8. No wildcard CORS ·
9. Secure auth cookies · 10. No public debug endpoints.

## Tiers

- **Self-declared** — the builder's own claim. May honestly report failures. Never signed.
- **Verified** — an independent verifier ran the 4-step method, all applicable checks
  passed, and the file carries the verifier's public key and signature.

A pass is point-in-time and is **not** a penetration test.

## Status

Draft 0.2 — 20 November 2026. Names, file name, and check IDs are provisional until v1.0.
Prior art and honest limits are in §8–§9 of the specification.
