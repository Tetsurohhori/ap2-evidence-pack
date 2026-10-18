#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""ap2-evidence-pack conformance runner (reference implementation side).

A verifier claims ap2-evidence-pack conformance iff, for every <name>.json in this
directory, verified under the policy in <name>.expected.json, it reproduces the
vector's `normative` block exactly. This runner checks the reference
`ap2_evidence.verify_evidence`; a third-party implementation (Rust, Go, JS, …)
claims conformance the same way against its own verifier, mapping its receipt onto
the normative fields (see SPEC_AP2_EVIDENCE.md §6 for their definitions).

A vector whose `requires` lists a tool absent on this machine, or whose `requires_backend` (1.5.4) names a
cryptographic backend this verifier does not have (`"ml-dsa-65"`: the reference's ML-DSA-65 backend, the receipt's
`mldsa_backend`), is reported SKIP — honestly not verified, never silently passed, never a disagreement. Exit 0 =
conformant (no FAIL). The expected files are a closed format of their own (SPEC §7, 1.5.4): a key, a policy key, a
report key or a backend name this runner does not know, a policy value of the wrong type, a file that is not a regular
UTF-8 JSON file or repeats a key, and a pack without its expected file (or the reverse) are errors of the vector set
(exit 2), never ignored and never counted as a verifier's FAIL.

  python3 run_ap2_conformance.py
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPENCORE = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _OPENCORE)
import ap2_evidence as ap2  # noqa: E402
sigsuite = ap2._sigsuite   # the signature suite the reference really uses (its ML-DSA-65 backend)

# 1.5.4 — SPEC §7: the closed schema of <name>.expected.json
EXPECTED_KEYS = {"vector", "description", "policy", "normative", "report", "requires", "requires_backend"}
POLICY_KEYS = {"trusted_producer_keys", "require_pq", "require_producer", "require_anchor", "min_anchors"}
REPORT_KEYS = {"ignored", "refused"}
NORMATIVE_KEYS = {"valid", "digest_ok", "bindings_ok", "policy_ok", "pq_protected", "producer_present", "producer_ok",
                  "producer_trusted", "rfc3161_claimed", "rfc3161_verified", "self_asserted_only", "anchors_verified"}
BACKENDS = {"ml-dsa-65": lambda: bool(sigsuite.MLDSA_AVAILABLE)}


class VectorSetError(Exception):
    """An expected file outside the closed schema of SPEC §7: the vector set is broken, not the verifier."""


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"duplicate key(s) {sorted({k for k in keys if keys.count(k) > 1})}")
    return dict(pairs)


def _load_expected(path: str, name: str):
    if not os.path.isfile(path):   # a FIFO would block, a directory would be a traceback
        raise VectorSetError(f"{name}: the expected file is not a regular file")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError) as e:   # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise VectorSetError(f"{name}: unreadable expected file ({type(e).__name__}: {e}) (SPEC §7)") from None


def check_expected(exp, name: str) -> None:
    def closed(obj, allowed, where):
        if not isinstance(obj, dict):
            raise VectorSetError(f"{name}: {where} must be an object")
        unknown = sorted(set(obj) - allowed)
        if unknown:
            raise VectorSetError(f"{name}: unknown key(s) {unknown} in {where} (SPEC §7)")
    closed(exp, EXPECTED_KEYS, "the expected file")
    if exp.get("vector") != name or not isinstance(exp.get("description"), str):
        raise VectorSetError(f"{name}: `vector` must be the file's name and `description` a string")
    closed(exp.get("policy"), POLICY_KEYS, "policy")
    pol = exp["policy"]
    for k in ("require_pq", "require_producer", "require_anchor"):
        if k in pol and not isinstance(pol[k], bool):
            raise VectorSetError(f"{name}: policy {k} must be a boolean (SPEC §7)")
    if "min_anchors" in pol and not (type(pol["min_anchors"]) is int and pol["min_anchors"] >= 1):
        raise VectorSetError(f"{name}: policy min_anchors must be a positive integer (SPEC §7)")
    tpk = pol.get("trusted_producer_keys")
    if tpk is not None and not (isinstance(tpk, dict) and all(
            isinstance(v, str) or (isinstance(v, list) and v and all(isinstance(x, str) for x in v)) for v in tpk.values())):
        raise VectorSetError(f"{name}: policy trusted_producer_keys must be null or {{sig_alg: key or [keys]}} (SPEC §7)")
    closed(exp.get("normative"), NORMATIVE_KEYS, "normative")
    if set(exp["normative"]) != NORMATIVE_KEYS:
        raise VectorSetError(f"{name}: normative must carry all twelve fields, missing {sorted(NORMATIVE_KEYS - set(exp['normative']))}")
    if "report" in exp:
        closed(exp["report"], REPORT_KEYS, "report")
    for key, known in (("requires", None), ("requires_backend", BACKENDS)):
        if key in exp:
            v = exp[key]
            if not isinstance(v, list) or not v or not all(isinstance(t, str) for t in v) or len(set(v)) != len(v):
                raise VectorSetError(f"{name}: {key} must be a non-empty list of distinct strings")
            if known is not None and set(v) - set(known):
                raise VectorSetError(f"{name}: {key} names unknown backend(s) {sorted(set(v) - set(known))} (SPEC §7)")


def _normalize(r: dict) -> dict:
    """Map a verify receipt onto the NORMATIVE fields — nothing else is compared, so an
    implementation may format its receipt however it likes as long as these facts match."""
    prod = r.get("producer_signatures", {})
    rfc = r.get("rfc3161", {})
    return {"valid": r.get("valid"), "digest_ok": r.get("digest_ok"),
            "bindings_ok": r.get("bindings_ok"), "policy_ok": r.get("policy_ok"),
            "pq_protected": r.get("pq_protected"),
            "producer_present": prod.get("present"), "producer_ok": prod.get("ok"),
            "producer_trusted": prod.get("trusted"),
            "rfc3161_claimed": rfc.get("claimed"), "rfc3161_verified": rfc.get("verified"),
            "self_asserted_only": r.get("self_asserted_only"),
            "anchors_verified": r.get("anchors_verified")}   # 1.5.0 — SPEC §3.3, the twelfth normative field


def run(verify_fn=None, honour_requirements: bool = True, backends=None, vector_dir=None) -> dict:
    """`backends` ({name: bool}) states the backends of the verifier under test when it is not the reference (default:
    the reference's own). `honour_requirements=False` runs every vector whatever it requires — only for measuring what a
    vector depends on (make_vectors_154.py, test_requires_backend_is_the_measured_dependence), never for a claim."""
    verify_fn = verify_fn or ap2.verify_evidence
    vdir = vector_dir or _HERE
    have = {b: probe() for b, probe in BACKENDS.items()} if backends is None else dict(backends)
    if set(have) != set(BACKENDS):
        raise ValueError(f"backends must state exactly {sorted(BACKENDS)}")
    results, conformant = [], True
    exp_paths = sorted(glob.glob(os.path.join(vdir, "*.expected.json")))
    packs = {os.path.basename(p)[:-len(".json")] for p in glob.glob(os.path.join(vdir, "*.json")) if not p.endswith(".expected.json")}
    names = {os.path.basename(p)[:-len(".expected.json")] for p in exp_paths}
    if packs != names:
        raise VectorSetError(f"packs without an expected file {sorted(packs - names)}, expected files without a pack {sorted(names - packs)} (SPEC §7)")
    for exp_path in exp_paths:
        name = os.path.basename(exp_path)[:-len(".expected.json")]
        exp = _load_expected(exp_path, name)
        check_expected(exp, name)
        if not os.path.isfile(os.path.join(vdir, f"{name}.json")):
            raise VectorSetError(f"{name}: the pack is not a regular file")
        missing = [t for t in exp.get("requires", []) if not shutil.which(t)]
        missing += [b for b in exp.get("requires_backend", []) if not have[b]]
        if missing and honour_requirements:
            results.append({"vector": name, "status": "SKIP",
                            "note": f"requires {missing} — NOT verified on this machine"})
            continue
        pol = exp.get("policy", {})
        receipt = verify_fn(
            os.path.join(vdir, f"{name}.json"),
            trusted_producer_keys=pol.get("trusted_producer_keys"),
            require_pq=bool(pol.get("require_pq")),
            require_producer=bool(pol.get("require_producer")),
            require_anchor=bool(pol.get("require_anchor")),
            **({"min_anchors": pol["min_anchors"]} if "min_anchors" in pol else {}))
        got = _normalize(receipt)
        want = exp["normative"]
        diffs = {k: {"want": want[k], "got": got.get(k)}
                 for k in want if got.get(k) != want[k]}
        if "ignored" in exp.get("report", {}):   # 1.4.0 (SPEC §7/§9.2): the per-artifact list of names ignored under a standard's rule
            got_ignored = [a.get("ignored") for a in (receipt.get("artifacts") or [])]
            if got_ignored != exp["report"]["ignored"]:
                diffs["report.ignored"] = {"want": exp["report"]["ignored"], "got": got_ignored}
        if "refused" in exp.get("report", {}):   # 1.5.0 (SPEC §7): the exact refusal text, not any refusal
            if receipt.get("refused") != exp["report"]["refused"]:
                diffs["report.refused"] = {"want": exp["report"]["refused"], "got": receipt.get("refused")}
        ok = not diffs
        conformant = conformant and ok
        results.append({"vector": name, "status": "PASS" if ok else "FAIL",
                        **({"diffs": diffs} if diffs else {})})
    return {"conformant": conformant and any(r["status"] == "PASS" for r in results),
            "results": results}


def main() -> int:
    try:
        r = run()
    except VectorSetError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2
    print(json.dumps(r, indent=1))
    return 0 if r["conformant"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
