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
EXPECTED_KEYS = {"vector", "description", "policy", "normative", "report", "requires", "requires_backend", "states"}
POLICY_KEYS = {"trusted_producer_keys", "require_pq", "require_producer", "require_anchor", "min_anchors",
               "trust_set_complete", "tsa_cert", "trust_anchor"}   # 1.6.0: the last three
# 1.6.0 — SPEC §6.9/§7: the `states` block every expected file carries (closed, like the rest of the file)
STATES_KEYS = {"admission", "refusal_class", "subjects", "policy"}
SUBJECTS = ("sealed_content", "holder_binding", "time_anchor", "producer_signature", "issuer_identity")
STATE_VALUES = {"verified", "contradicted", "indeterminate", "not_evaluated"}
REASONS = {"digest_mismatch", "artifact_invalid", "binding_mismatch", "kb_signature_invalid", "sd_hash_mismatch",
           "not_present", "holder_key_unknown", "token_invalid", "token_missing", "tsa_not_checked", "tsa_invalid",
           "instrument_failure", "signature_invalid", "self_asserted", "key_unresolved", "backend_missing", "ca_certified",
           "chain_broken", "chain_unresolved", "no_trust_anchor", "divergence", "absence"}
UNMET = ("require_producer", "require_pq", "require_anchor", "min_anchors", "trusted_producer_keys", "trust_set_complete")
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


def check_expected(exp, name: str, vdir: str = None) -> None:
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
    for k in ("require_pq", "require_producer", "require_anchor", "trust_set_complete"):
        if k in pol and not isinstance(pol[k], bool):
            raise VectorSetError(f"{name}: policy {k} must be a boolean (SPEC §7)")
    if "min_anchors" in pol and not (type(pol["min_anchors"]) is int and pol["min_anchors"] >= 1):
        raise VectorSetError(f"{name}: policy min_anchors must be a positive integer (SPEC §7)")
    tpk = pol.get("trusted_producer_keys")
    if tpk is not None and not (isinstance(tpk, dict) and all(
            isinstance(v, str) or (isinstance(v, list) and v and all(isinstance(x, str) for x in v)) for v in tpk.values())):
        raise VectorSetError(f"{name}: policy trusted_producer_keys must be null or {{sig_alg: key or [keys]}} (SPEC §7)")
    for k in ("tsa_cert", "trust_anchor"):   # 1.6.0: a file beside the vectors, named without a directory
        if k in pol and not (isinstance(pol[k], str) and pol[k] and os.path.basename(pol[k]) == pol[k] and os.path.isfile(os.path.join(vdir or _HERE, pol[k]))):
            raise VectorSetError(f"{name}: policy {k} must name a file of the vector set (SPEC §7)")
    closed(exp.get("normative"), NORMATIVE_KEYS, "normative")
    if set(exp["normative"]) != NORMATIVE_KEYS:
        raise VectorSetError(f"{name}: normative must carry all twelve fields, missing {sorted(NORMATIVE_KEYS - set(exp['normative']))}")
    if "report" in exp:
        closed(exp["report"], REPORT_KEYS, "report")
    if "states" not in exp:
        raise VectorSetError(f"{name}: missing the states block (SPEC §7, 1.6.0)")
    st = exp["states"]
    closed(st, STATES_KEYS, "states")
    if set(st) != STATES_KEYS:
        raise VectorSetError(f"{name}: states must carry {sorted(STATES_KEYS)}")
    if st["admission"] == "refused":
        if st["refusal_class"] not in ("format_unsupported", "unknown_member", "malformed") or st["subjects"] is not None or st["policy"] is not None:
            raise VectorSetError(f"{name}: a refused states block has a refusal_class and null subjects and policy (SPEC §6.9)")
    elif st["admission"] == "admitted":
        if st["refusal_class"] is not None:
            raise VectorSetError(f"{name}: an admitted states block has refusal_class null")
        closed(st["subjects"], set(SUBJECTS), "states.subjects")
        if set(st["subjects"]) != set(SUBJECTS):
            raise VectorSetError(f"{name}: states.subjects must carry {list(SUBJECTS)}")
        for sname, sv in st["subjects"].items():
            closed(sv, {"state", "reasons"}, f"states.subjects.{sname}")
            if sv.get("state") not in STATE_VALUES or not isinstance(sv.get("reasons"), list) or set(sv["reasons"]) - REASONS:
                raise VectorSetError(f"{name}: states.subjects.{sname} outside the vocabulary of SPEC §6.9")
        closed(st["policy"], {"met", "unmet"}, "states.policy")
        if not isinstance(st["policy"].get("met"), bool) or not isinstance(st["policy"].get("unmet"), list) or set(st["policy"]["unmet"]) - set(UNMET):
            raise VectorSetError(f"{name}: states.policy outside SPEC §6.9")
    else:
        raise VectorSetError(f"{name}: states.admission must be admitted or refused")
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


def states_block(r: dict) -> dict:
    """1.6.0 — SPEC §7: the part of a receipt the `states` block of an expected file states (`detail` is free text)."""
    subj = r.get("states")
    return {"admission": r.get("admission"), "refusal_class": r.get("refusal_class"),
            "subjects": None if subj is None else {k: {"state": v.get("state"), "reasons": v.get("reasons")} for k, v in subj.items()},
            "policy": r.get("policy")}


def verify_with_policy(verify_fn, pack_path: str, pol: dict, vdir: str) -> dict:
    """Call a verifier with the policy of an expected file; the 1.6.0 inputs are passed only when the file sets them, so a
    verifier of an earlier revision is still callable on the earlier vectors."""
    extra = {}
    if "min_anchors" in pol:
        extra["min_anchors"] = pol["min_anchors"]
    if pol.get("trust_set_complete"):
        extra["trust_set_complete"] = True
    for k in ("tsa_cert", "trust_anchor"):
        if k in pol:
            extra[k] = os.path.join(vdir, pol[k])
    return verify_fn(pack_path, trusted_producer_keys=pol.get("trusted_producer_keys"), require_pq=bool(pol.get("require_pq")),
                     require_producer=bool(pol.get("require_producer")), require_anchor=bool(pol.get("require_anchor")), **extra)


def run(verify_fn=None, honour_requirements: bool = True, backends=None, vector_dir=None, tools=None) -> dict:
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
        check_expected(exp, name, vdir)
        if not os.path.isfile(os.path.join(vdir, f"{name}.json")):
            raise VectorSetError(f"{name}: the pack is not a regular file")
        # 1.6.0: `tools` ({name: bool}) states the tools the verifier under test can use when it is not the reference (the JS
        # verifier calls no openssl: its vectors that need openssl are SKIP, never a pass and never a disagreement)
        missing = [t for t in exp.get("requires", []) if not (shutil.which(t) if tools is None else tools.get(t, False))]
        missing += [b for b in exp.get("requires_backend", []) if not have[b]]
        if missing and honour_requirements:
            results.append({"vector": name, "status": "SKIP",
                            "note": f"requires {missing} — NOT verified on this machine"})
            continue
        receipt = verify_with_policy(verify_fn, os.path.join(vdir, f"{name}.json"), exp.get("policy", {}), vdir)
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
        got_states = states_block(receipt)   # 1.6.0 — SPEC §6.9/§7
        if got_states != exp["states"]:
            diffs["states"] = {"want": exp["states"], "got": got_states}
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
