#!/usr/bin/env node
// VSA v0.2 offline signature verification.
// Usage: node verify.js <file.json>
// Prints VALID or INVALID and exits 0 or 1. Checks only the signature;
// full validation (schema, expiry, tier rules) is validate.py's job.
// License: Apache 2.0.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const { canonicalize, b64urlDecode } = require('./sign.js');

function verifySignature(obj) {
  if (obj.attestation !== 'verified') return { ok: false, reason: 'not a verified-tier file' };
  if (!obj.signature) return { ok: false, reason: 'no signature field' };
  if (!obj.verifier || !obj.verifier.public_key) return { ok: false, reason: 'no verifier public key' };
  const unsigned = JSON.parse(JSON.stringify(obj));
  delete unsigned.signature;
  const data = Buffer.from(canonicalize(unsigned), 'utf8');
  const sig = b64urlDecode(obj.signature);
  if (sig.length !== 64) return { ok: false, reason: `signature must be 64 bytes, got ${sig.length}` };
  const key = crypto.createPublicKey({ key: obj.verifier.public_key, format: 'jwk' });
  const ok = crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  return ok
    ? { ok: true, reason: `signature valid (verifier: ${obj.verifier.name})` }
    : { ok: false, reason: 'signature does not match the file contents' };
}

function main() {
  const file = process.argv[2];
  if (!file) { console.error('Usage: node verify.js <file.json>'); process.exit(2); }
  const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
  const res = verifySignature(obj);
  console.log(res.ok ? 'VALID: ' + res.reason : 'INVALID: ' + res.reason);
  if (res.ok) {
    console.log('Reminder: also compare the public key against a key the verifier');
    console.log('publishes on their own domain/profile (spec section 4.4, step 3).');
  }
  process.exit(res.ok ? 0 : 1);
}

if (require.main === module) main();
module.exports = { verifySignature };
