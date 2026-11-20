#!/usr/bin/env node
// VSA v0.2 signing tool — keypair generation and file signing.
// ECDSA P-256 + SHA-256 over the JCS canonical form of the file without
// the `signature` field. No dependencies; uses Node's built-in crypto.
// License: Apache 2.0.
//
// Usage:
//   node sign.js keygen [--out-prefix NAME]
//       Prints a fresh P-256 keypair as JWK. With --out-prefix, writes
//       NAME.private.jwk and NAME.public.jwk instead of printing.
//   node sign.js sign <unsigned.json> <private.jwk> <name> <contact> [--out FILE]
//       Signs a verified-tier file (attestation "verified", verifier null),
//       filling verifier {name, contact, method, public_key} and signature.
//       Prints the signed file, or writes it with --out.
//
// The private key never leaves the machine running this command.
'use strict';
const crypto = require('crypto');
const fs = require('fs');

// JCS canonicalization for VSA files (no numbers in the format):
// recursively sort object keys by UTF-16 code units, then JSON.stringify
// with no whitespace. Must stay byte-identical to canonicalize() in
// page/index.html — the test suite checks this.
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const pad = (4 - (str.length % 4)) % 4;
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad), 'base64');
}

function publicJwk(privateJwk) {
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const pub = crypto.createPublicKey(key).export({ format: 'jwk' });
  return { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y };
}

function signFile(obj, privateJwk, verifierName, verifierContact) {
  if (obj.attestation !== 'verified') throw new Error('only verified-tier files can be signed');
  if (obj.signature) throw new Error('file already has a signature');
  const checks = obj.checks || [];
  for (const c of checks) {
    if (c.result === 'fail' || c.result === 'not_tested') {
      throw new Error(`cannot sign: check ${c.id} is ${c.result}`);
    }
    if (c.result === 'pass' && c.method === 'scanner') {
      throw new Error(`cannot sign: verified pass on ${c.id} needs probe or manual, not scanner-only`);
    }
    if (c.result === 'not_applicable' && c.method !== 'manual') {
      throw new Error(`cannot sign: not_applicable on ${c.id} needs method manual`);
    }
  }
  const signed = JSON.parse(JSON.stringify(obj));
  signed.verifier = {
    name: verifierName,
    contact: verifierContact,
    method: 'vsa-4-step',
    public_key: publicJwk(privateJwk),
  };
  const unsigned = JSON.parse(JSON.stringify(signed));
  delete unsigned.signature;
  const data = Buffer.from(canonicalize(unsigned), 'utf8');
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const sig = crypto.sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' });
  signed.signature = b64urlEncode(sig);
  return signed;
}

function keygen(outPrefix) {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const priv = privateKey.export({ format: 'jwk' });
  const pub = { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y };
  const privOut = { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y, d: priv.d };
  if (outPrefix) {
    fs.writeFileSync(`${outPrefix}.private.jwk`, JSON.stringify(privOut, null, 2) + '\n');
    fs.writeFileSync(`${outPrefix}.public.jwk`, JSON.stringify(pub, null, 2) + '\n');
    console.log(`Wrote ${outPrefix}.private.jwk (KEEP SECRET) and ${outPrefix}.public.jwk`);
  } else {
    console.log('Private JWK (KEEP SECRET — store in a password manager, never publish):');
    console.log(JSON.stringify(privOut));
    console.log('Public JWK (publish this on your profile so readers can match it):');
    console.log(JSON.stringify(pub));
  }
}

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (cmd === 'keygen') {
    const i = args.indexOf('--out-prefix');
    keygen(i >= 0 ? args[i + 1] : null);
    return;
  }
  if (cmd === 'sign') {
    const [file, keyFile, name, contact] = args.slice(1, 5);
    if (!file || !keyFile || !name || !contact) {
      console.error('Usage: node sign.js sign <unsigned.json> <private.jwk> <name> <contact> [--out FILE]');
      process.exit(2);
    }
    const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
    const priv = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    const signed = signFile(obj, priv, name, contact);
    const out = JSON.stringify(signed, null, 2) + '\n';
    const i = args.indexOf('--out');
    if (i >= 0) { fs.writeFileSync(args[i + 1], out); console.log(`Wrote ${args[i + 1]}`); }
    else process.stdout.write(out);
    return;
  }
  console.error('Usage: node sign.js keygen [--out-prefix NAME] | node sign.js sign <unsigned.json> <private.jwk> <name> <contact> [--out FILE]');
  process.exit(2);
}

if (require.main === module) main();
module.exports = { canonicalize, b64urlEncode, b64urlDecode, publicJwk, signFile };
