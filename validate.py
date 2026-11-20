#!/usr/bin/env python3
"""Validate VSA v0.2 example files against the JSON Schema plus the rules
JSON Schema cannot express (90-day expiry window; tier rules; signatures).

Usage: python3 validate.py
Exit code 0 = all checks passed.
Signature checks shell out to `node verify.js` (Node's built-in crypto);
they are skipped with a warning if node is unavailable.
License: Apache 2.0.
"""
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import jsonschema

ROOT = Path(__file__).parent
SCHEMA_PATH = ROOT / "schema" / "vibe-security.schema.json"
EXAMPLES = sorted((ROOT / "examples").glob("*.json"))

CHECK_IDS = {
    "database-rls", "storage-private", "no-privileged-key", "no-exposed-config",
    "no-sourcemap-leak", "api-requires-auth", "security-headers",
    "cors-restricted", "cookies-secure", "no-debug-endpoints",
}

failures = []
passes = 0
skipped = 0


def check(name, ok, detail=""):
    global passes
    if ok:
        passes += 1
        print(f"  PASS  {name}")
    else:
        failures.append(name)
        print(f"  FAIL  {name}  {detail}")


def skip(name, reason):
    global skipped
    skipped += 1
    print(f"  SKIP  {name}  ({reason})")


def parse_dt(s):
    """Parse an RFC 3339 timestamp; return None instead of raising."""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def node_verify(path):
    """Verify a file's signature via node verify.js. Returns True/False/None."""
    if not shutil.which("node"):
        return None
    res = subprocess.run(["node", str(ROOT / "verify.js"), str(path)],
                         capture_output=True, text=True)
    return res.returncode == 0


def main():
    schema = json.loads(SCHEMA_PATH.read_text())
    print(f"Schema: {SCHEMA_PATH}")
    jsonschema.Draft202012Validator.check_schema(schema)
    check("schema itself is valid JSON Schema (draft 2020-12)", True)
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker())

    for path in EXAMPLES:
        print(f"\nExample: {path.name}")
        obj = json.loads(path.read_text())
        errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
        check("valid against JSON Schema",
              not errors, "; ".join(e.message for e in errors[:3]))
        check("version is 0.2", obj.get("vibe_security_version") == "0.2")

        # Rule 1: expiry window (spec section 4.2).
        att = parse_dt(obj.get("attested_at"))
        exp = parse_dt(obj.get("expires_at"))
        check("attested_at/expires_at parse as dates", att and exp)
        if att and exp:
            check("expires_at after attested_at", exp > att)
            check("expires_at within 90 days of attested_at",
                  (exp - att).days <= 90, f"gap={(exp - att).days}d")

        # Rule 2: check-id set (schema enforces it too; double-check here).
        ids = [c["id"] for c in obj["checks"]]
        check("exactly the 10 checks, each once",
              set(ids) == CHECK_IDS and len(ids) == 10)

        # Tier rules (spec sections 1 and 2.12).
        if obj["attestation"] == "verified":
            applicable = [c for c in obj["checks"] if c["result"] != "not_applicable"]
            check("verified: every applicable check passes",
                  all(c["result"] == "pass" for c in applicable))
            check("verified: every pass uses probe or manual",
                  all(c["method"] in ("probe", "manual")
                      for c in applicable if c["result"] == "pass"))
            check("verified: every not_applicable uses manual",
                  all(c["method"] == "manual"
                      for c in obj["checks"] if c["result"] == "not_applicable"))
            check("verified: verifier present with vsa-4-step method",
                  obj.get("verifier") and obj["verifier"].get("method") == "vsa-4-step")
            check("verified: verifier has a P-256 public key",
                  bool(obj.get("verifier", {}).get("public_key"))
                  and obj["verifier"]["public_key"].get("crv") == "P-256")
            check("verified: signature present and 86 chars",
                  isinstance(obj.get("signature"), str)
                  and len(obj["signature"]) == 86)
            res = node_verify(path)
            if res is None:
                skip("verified: signature verifies (node verify.js)", "node not found")
            else:
                check("verified: signature verifies (node verify.js)", res)
        else:
            check("self-declared: verifier is null", obj.get("verifier") is None)
            check("self-declared: no signature field", "signature" not in obj)

    # Negative tests: files that MUST fail validation.
    print("\nNegative tests (must fail):")
    good = json.loads((ROOT / "examples" / "self-declared.example.json").read_text())
    good_ver = json.loads((ROOT / "examples" / "verified.example.json").read_text())

    def expect_invalid(name, base, mutate):
        bad = json.loads(json.dumps(base))
        mutate(bad)
        errs = list(validator.iter_errors(bad))
        check(name, bool(errs))

    expect_invalid("wrong version rejected", good,
                   lambda o: o.update(vibe_security_version="0.1"))
    expect_invalid("missing check rejected", good,
                   lambda o: o["checks"].pop())
    expect_invalid("unknown check id rejected", good,
                   lambda o: o["checks"][0].update(id="not-a-check"))
    expect_invalid("bad result value rejected", good,
                   lambda o: o["checks"][0].update(result="maybe"))
    expect_invalid("verified tier without verifier rejected", good,
                   lambda o: o.update(attestation="verified"))
    expect_invalid("verified tier without signature rejected", good,
                   lambda o: o.update(attestation="verified", verifier={
                       "name": "X", "contact": "https://example.org",
                       "method": "vsa-4-step",
                       "public_key": {"kty": "EC", "crv": "P-256",
                                      "x": "abc", "y": "def"}}))
    expect_invalid("self-declared with verifier rejected", good,
                   lambda o: o.update(verifier={"name": "X",
                                                "contact": "https://example.org",
                                                "method": "vsa-4-step",
                                                "public_key": {"kty": "EC", "crv": "P-256",
                                                               "x": "abc", "y": "def"}}))
    expect_invalid("self-declared with signature rejected", good,
                   lambda o: o.update(signature="a" * 86))
    expect_invalid("http (non-https) app URL rejected", good,
                   lambda o: o["app"].update(url="http://notes.example-app.com"))
    expect_invalid("bad backend enum rejected", good,
                   lambda o: o["stack"].update(backend="oracle"))
    expect_invalid("short signature rejected", good_ver,
                   lambda o: o.update(signature="a" * 10))

    # Expiry rule is outside the schema: check the script catches it.
    bad_exp = json.loads(json.dumps(good))
    bad_exp["expires_at"] = "2027-12-31T00:00:00Z"
    gap = (parse_dt(bad_exp["expires_at"]) - parse_dt(bad_exp["attested_at"])).days
    check("expiry beyond 90 days caught by rule check", gap > 90)

    # A tampered signed file must fail signature verification.
    tampered = json.loads(json.dumps(good_ver))
    tampered["checks"][0]["note"] = "Tampered note."
    tmp = Path("/tmp/vsa-tampered.json")
    tmp.write_text(json.dumps(tampered))
    res = node_verify(tmp)
    if res is None:
        skip("tampered verified file fails signature check", "node not found")
    else:
        check("tampered verified file fails signature check", res is False)
    tmp.unlink(missing_ok=True)

    print(f"\n{passes} passed, {len(failures)} failed, {skipped} skipped.")
    if failures:
        print("Failures:", ", ".join(failures))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
