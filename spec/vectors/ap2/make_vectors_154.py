#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.5.4 conformance vectors (SPEC §5) and of the 1.5.4 `requires_backend` declarations (SPEC §7).

The three vectors are DERIVED from the frozen `valid_signed.json`: one byte of one producer signature is changed (the
producer block is outside the digest, §3, so nothing is re-sealed) and they regenerate byte for byte (no new key, no
clock). Each states the producer block of a pack that is already not `valid`; what 1.5.4 fixes is what the block reports.

  producer_mldsa_fails_pinned        Ed25519 valid, ML-DSA-65 signature altered, both keys pinned, no policy flag
                                     -> REJECT, producer_trusted null (1.5.3: true) — no trust statement on a failed block
  producer_classical_fails_pinned    Ed25519 signature altered, ML-DSA-65 valid, both keys pinned, require_pq
                                     -> REJECT, pq_protected false and policy_ok false (1.5.3: both true), producer_trusted null
  producer_classical_fails_unpinned  the same bytes with no pinned set and no policy flag
                                     -> REJECT, pq_protected false (1.5.3: true)

`--declare-backend` (run once for 1.5.4, idempotent) writes `"requires_backend": ["ml-dsa-65"]` into every expected file
whose `normative` block the reference verifier reproduces only with an ML-DSA-65 backend: measured by running the
reference twice on every vector, with and without the backend, and comparing each run with the expected block. The test
`test_requires_backend_is_the_measured_dependence` repeats that measurement on every run of the suite.
"""
import base64
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPENCORE = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _OPENCORE)
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

BASE = {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": True, "pq_protected": False,
        "producer_present": True, "producer_ok": False, "producer_trusted": None, "rfc3161_claimed": False,
        "rfc3161_verified": None, "self_asserted_only": True, "anchors_verified": 0}


def _load(name):
    with open(os.path.join(_HERE, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def _write_json(path, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)


def _altered(pack: dict, alg: str) -> dict:
    """The pack with the first byte of the `alg` producer signature XOR 0x01 (strict base64 kept: re-encoded)."""
    pack = json.loads(json.dumps(pack))
    entries = [s for s in pack["producer_signatures"]["signatures"] if s["sig_alg"] == alg]
    assert len(entries) == 1, (alg, len(entries))
    raw = bytearray(base64.b64decode(entries[0]["signature_b64"], validate=True))
    raw[0] ^= 0x01
    entries[0]["signature_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    return pack


def _expected(name, desc, policy, **normative):
    return {"vector": name, "description": desc, "policy": policy, "normative": dict(BASE, **normative)}


def write_vectors() -> None:
    base = _load("valid_signed")
    pins = _load("valid_signed.expected")["policy"]["trusted_producer_keys"]
    no_flags = {"require_anchor": False, "require_pq": False, "require_producer": False}
    mldsa_bad, classical_bad = _altered(base, "ml-dsa-65"), _altered(base, "ed25519")
    out = [
        ("producer_mldsa_fails_pinned", mldsa_bad, _expected(
            "producer_mldsa_fails_pinned",
            "valid_signed with one byte of the ML-DSA-65 producer signature changed; the relying party pins both producer "
            "keys and sets no policy flag. The block is not ok, so the pack is not valid; producer_trusted is null: a block "
            "that did not verify carries no trust statement (SPEC §5, 1.5.4 — 1.5.3 reported true, since both keys are pinned).",
            dict(no_flags, trusted_producer_keys=pins))),
        ("producer_classical_fails_pinned", classical_bad, _expected(
            "producer_classical_fails_pinned",
            "valid_signed with one byte of the Ed25519 producer signature changed; the ML-DSA-65 signature still verifies "
            "and both keys are pinned, under require_pq. pq_protected is false: it is stated only on a block that is ok "
            "(SPEC §5, 1.5.4), so require_pq is not met either and policy_ok is false (1.5.3: pq_protected true, "
            "producer_trusted true, policy_ok true, valid false).",
            dict(no_flags, require_pq=True, trusted_producer_keys=pins), policy_ok=False)),
        ("producer_classical_fails_unpinned", classical_bad, _expected(
            "producer_classical_fails_unpinned",
            "The bytes of producer_classical_fails_pinned with no pinned set and no policy flag: pq_protected is false "
            "because the block is not ok, whatever the ML-DSA-65 entry says (SPEC §5, 1.5.4 — 1.5.3 reported true).",
            dict(no_flags, trusted_producer_keys=None))),
    ]
    for name, pack, exp in out:
        _write_json(os.path.join(_HERE, name + ".json"), pack)
        _write_json(os.path.join(_HERE, name + ".expected.json"), exp)


def measured_backend_dependence() -> list:
    """Vectors whose expected `normative` block the reference reproduces with the ML-DSA-65 backend and not without it."""
    import run_ap2_conformance as rc
    sigsuite = ap2._sigsuite
    saved = sigsuite.MLDSA_AVAILABLE
    if not saved:
        raise SystemExit("this measurement needs an ML-DSA-65 backend (cryptography >= 48 on OpenSSL >= 3.5)")
    try:
        with_b = {r["vector"]: r["status"] for r in rc.run(honour_requirements=False)["results"]}
        sigsuite.MLDSA_AVAILABLE = False
        without = {r["vector"]: r["status"] for r in rc.run(honour_requirements=False)["results"]}
    finally:
        sigsuite.MLDSA_AVAILABLE = saved
    bad = [v for v, s in with_b.items() if s != "PASS"]
    if bad:
        raise SystemExit(f"the reference does not reproduce {bad} WITH the backend: fix that first")
    return sorted(v for v, s in without.items() if s != "PASS")


def declare_backend() -> list:
    dep = set(measured_backend_dependence())
    for name in sorted(f[:-len(".expected.json")] for f in os.listdir(_HERE) if f.endswith(".expected.json")):
        p = os.path.join(_HERE, name + ".expected.json")
        with open(p, encoding="utf-8") as f:
            exp = json.load(f)
        if name in dep:
            exp["requires_backend"] = ["ml-dsa-65"]
        else:
            exp.pop("requires_backend", None)
        _write_json(p, exp)
    return sorted(dep)


if __name__ == "__main__":
    if sys.argv[1:] == ["--declare-backend"]:
        print(json.dumps(declare_backend()))
    elif sys.argv[1:] == []:
        write_vectors(); print("1.5.4 vectors written to", _HERE)
    else:
        raise SystemExit("usage: make_vectors_154.py [--declare-backend]")
