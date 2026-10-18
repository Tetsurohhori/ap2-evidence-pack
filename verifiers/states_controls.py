#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The pre-registered controls of the 1.6.0 receipt (SPEC §6.9), run GENERATIVELY over the schema-mutant corpus.

For every file of the corpus (`schema_mutants.Corpus`: every conformance vector and every mutation of every object) the
reference verifier is run under four inputs — the record's own flags, no flags, the producer keys of `valid_signed`
pinned, and a pinned set that holds none of the pack's keys — and every receipt is checked against:

  C1  no `contradicted` reason without a check that ran and failed (each reason is tied to the field that measured it);
  C2  no `verified` subject with a check that did not run (a TSA not checked, no pins, no trust anchor, a KB-JWT unknown);
  C3  `valid` == admitted AND no subject but issuer_identity contradicted AND no producer entry SKIP AND policy.met — the
      equation of SPEC §6.9. The equation pre-registered in the design (every subject, no SKIP clause) is counted too:
      its failures are REPORTED, they are what SPEC §6.9 corrects;
  C4  pins: a pinned set never creates or removes a contradiction; a set that holds none of the keys never yields a
      `verified` producer signature; pinning the right keys never lowers the producer state;
  C5  a refusal carries `states` and `policy` null and a `refusal_class`; an admitted pack carries the five subjects.

`--old <root>` also runs a verifier of an earlier revision on the same files and compares `valid`: SPEC §6.9 does not
change `valid` (the §9.1 change moves a pack that was already not valid from artifact error to refusal).

The bench can fail: `run(sabotage=...)` replaces one rule of the derivation in-process (see SABOTAGES) and the test suite
requires every sabotage to turn the bench red."""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import schema_mutants as M  # noqa: E402

RANK = {"contradicted": 0, "not_evaluated": 1, "indeterminate": 1, "verified": 2}


def _pins():
    with open(os.path.join(ROOT, "spec", "vectors", "ap2", "valid_signed.expected.json"), encoding="utf-8") as f:
        return json.load(f)["policy"]["trusted_producer_keys"]


WRONG_PINS = {"ed25519": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}


def independent_binding_match(ap2, path):
    """The §4 binding set recomputed HERE from the pack's recorded compact serializations and resolved claims (equal to the
    verifier's recomputation exactly when `claims_match`): True / False, or None when the file is not a pack."""
    try:
        with open(path, encoding="utf-8") as f:
            ev = json.load(f)
        arts = [{"name": a["name"], "compact": a["sd_jwt_compact"], "resolved_claims": a["resolved_claims"]} for a in ev["artifacts"]]
        return sorted(ap2._canon(b) for b in ap2.find_bindings(arts)) == sorted(ap2._canon(b) for b in ev.get("bindings", []))
    except Exception:  # noqa: BLE001
        return None


def check_receipt(r: dict, kw: dict, bind_match=None) -> list:
    """C1, C2, C3, C5 on one receipt. Returns a list of violations (strings)."""
    v = []
    if r.get("admission") == "refused":
        if r.get("states") is not None or r.get("policy") is not None or r.get("refusal_class") not in ("format_unsupported", "unknown_member", "malformed"):
            v.append("C5 refused receipt with states/policy or no class")
        if r.get("valid") is not False:
            v.append("C3 refused but valid")
        return v
    if r.get("admission") != "admitted" or set(r.get("states") or {}) != {"sealed_content", "holder_binding", "time_anchor", "producer_signature", "issuer_identity"}:
        return ["C5 admitted receipt without the five subjects"]
    st = r["states"]; arts = r.get("artifacts") or []; prod = r.get("producer_signatures") or {}
    sigs = prod.get("signatures") or []
    block = r.get("_rfc_block") if "_rfc_block" in r else (r.get("rfc3161") if not r.get("anchors") and (r.get("rfc3161") or {}).get("claimed") else None)
    toks = ([block] if block else []) + list(r.get("anchors") or [])   # without `anchors` the receipt's rfc3161 IS the block
    # C1 — each contradicted reason is tied to a measured failure
    measured_fail = {
        "digest_mismatch": r.get("digest_ok") is False,
        "artifact_invalid": (not arts) or any("error" in a or a.get("signature_ok") is not True or a.get("claims_match") is not True for a in arts),
        "binding_mismatch": bind_match is False or any(t.get("imprint_ok") is False for t in toks if t),
        "kb_signature_invalid": any((a.get("kb_jwt") or {}).get("signature_ok") is False for a in arts),
        "sd_hash_mismatch": any((a.get("kb_jwt") or {}).get("sd_hash_ok") is False for a in arts),
        "token_invalid": (r.get("rfc3161") or {}).get("verified") is False,
        "token_missing": (r.get("rfc3161") or {}).get("verified") is False,
        "signature_invalid": any(s.get("status") == "FAIL" for s in sigs) or prod.get("scheme_ok") is False or (prod.get("present") and not sigs),
        "chain_broken": r.get("chain_verified") is False,
    }
    for name, s in st.items():
        if s["state"] == "contradicted":
            for reason in s["reasons"]:
                if reason in measured_fail and not measured_fail[reason]:
                    v.append(f"C1 {name}: {reason} with no measured failure")
            if not any(reason in measured_fail for reason in s["reasons"]):
                v.append(f"C1 {name}: contradicted with no failing reason")
    # C2 — verified only on checks that ran
    if st["time_anchor"]["state"] == "verified" and not (kw.get("tsa_cert") and toks and all(t.get("tsa_verified") is True for t in toks if t)):
        v.append("C2 time_anchor verified without a TSA check")
    if st["producer_signature"]["state"] == "verified" and not (kw.get("trusted_producer_keys") and sigs and all(s.get("status") == "PASS" and s.get("key_trusted") is True for s in sigs)):
        v.append("C2 producer_signature verified without pinned keys")
    if st["issuer_identity"]["state"] == "verified" and r.get("chain_verified") is not True:
        v.append("C2 issuer_identity verified without a validated chain")
    if st["holder_binding"]["state"] == "verified" and not any((a.get("kb_jwt") or {}).get("verified") is True for a in arts):
        v.append("C2 holder_binding verified without a KB-JWT that verified")
    if st["sealed_content"]["state"] == "verified" and not (r.get("digest_ok") is True and bind_match is True and arts
                                                             and all("error" not in a and a.get("signature_ok") is True and a.get("claims_match") is True for a in arts)):
        v.append("C2 sealed_content verified without digest and bindings")
    # C3 — the valid equation of SPEC §6.9
    contradicted = {n for n, s in st.items() if s["state"] == "contradicted"}
    skip = any(s.get("status") == "SKIP" for s in sigs)
    eq = (not (contradicted - {"issuer_identity"})) and not skip and r["policy"]["met"]
    if eq != r["valid"]:
        v.append(f"C3 valid={r['valid']} but the equation gives {eq}")
    return v


def design_equation(r: dict) -> bool:
    """The equation as pre-registered in the design (DISEGNO §4): every subject, no clause for a SKIP entry."""
    if r.get("admission") != "admitted":
        return False
    return not any(s["state"] == "contradicted" for s in r["states"].values()) and r["policy"]["met"]


def _sabotage(ap2, which):
    """One rule of the derivation replaced in-process: each MUST turn the bench red (the bench can fail)."""
    orig_anchor, orig_derive = ap2._anchor_element, ap2.derive_states
    if which == "binding_not_run_is_verified":   # the defect this bench found in the first 1.6.0 draft
        def d(**kw):
            if kw["binding_set_match"] is not None and any((r.get("kb_jwt") or {}).get("verified") is False for r in kw["art_results"]):
                kw = dict(kw, binding_set_match=None)
            return orig_derive(**kw)
        ap2.derive_states = d
    elif which == "tsa_not_checked_is_verified":
        ap2._anchor_element = lambda r, req: ("verified", None) if r.get("verified") is True else orig_anchor(r, req)
    elif which == "skip_is_contradicted":
        def d(**kw):
            out = orig_derive(**kw)
            if "backend_missing" in out["producer_signature"]["reasons"]:
                out["producer_signature"] = {"state": "contradicted", "reasons": ["signature_invalid"]}
            return out
        ap2.derive_states = d
    elif which == "self_asserted_is_verified":
        def d(**kw):
            out = orig_derive(**kw)
            if set(out["producer_signature"]["reasons"]) == {"self_asserted"}:
                out["producer_signature"] = {"state": "verified", "reasons": []}
            return out
        ap2.derive_states = d
    elif which == "key_unresolved_is_signature_invalid":
        def d(**kw):
            out = orig_derive(**kw)
            if "key_unresolved" in out["producer_signature"]["reasons"]:
                out["producer_signature"] = {"state": "contradicted", "reasons": ["signature_invalid"]}
            return out
        ap2.derive_states = d
    elif which == "precedence_reversed":
        orig_subject = ap2._subject

        def s(elements):
            out = orig_subject(elements)
            if out["state"] == "contradicted" and any(e[0] == "verified" for e in elements):
                out = dict(out, state="verified")
            return out
        ap2._subject = s
    elif which is not None:
        raise ValueError(which)


SABOTAGES = ("binding_not_run_is_verified", "tsa_not_checked_is_verified", "skip_is_contradicted", "self_asserted_is_verified",
             "key_unresolved_is_signature_invalid", "precedence_reversed")


def run(quick=True, py_root=ROOT, old_root=None, sabotage=None, baselines_only=False, log=lambda *a: None) -> dict:
    sys.path.insert(0, py_root)
    import ap2_evidence as ap2  # noqa: E402
    assert os.path.realpath(os.path.dirname(ap2.__file__)) == os.path.realpath(py_root), (ap2.__file__, py_root)
    _sabotage(ap2, sabotage)
    # the block's own token result is not in the receipt: keep it for C1/C2 (the aggregate `rfc3161` is)
    orig_derive = ap2.derive_states

    def keep_block(**kw):
        out = orig_derive(**kw)
        keep_block.last = kw["rfc_block"] if kw["ts_block"].get("anchored") else None
        return out
    ap2.derive_states = keep_block
    pins = _pins(); tsa = os.path.join(ROOT, "spec", "vectors", "ap2", "anchor_probe_tsa.crt")
    d = tempfile.mkdtemp(prefix="ap2-states-")
    viol, n, design_fail, valid_by_case, manifest = [], 0, 0, {}, []
    try:
        c = M.Corpus(d, quick); c.build()
        vd = os.path.join(ROOT, "spec", "vectors", "ap2")
        # packs the mutant corpus does not hold: a failing KB-JWT WITH a recorded binding that the content does not support
        # (the binding check must run although bindings_ok is false by §6 step 3), and the x5c vectors under a trust anchor
        for name in ("holder_kb_signature_invalid", "holder_sd_hash_mismatch", "holder_key_unknown", "kb_jwt_valid"):
            with open(os.path.join(vd, name + ".json"), encoding="utf-8") as f:
                ev = json.load(f)
            ev["bindings"] = [{"in": ev["artifacts"][0]["name"], "claim": "items[0]", "commits_to": ev["artifacts"][0]["name"], "encoding": "hex"}]
            c.recs.append({"name": f"extra/{name}/wrong-binding", "path": c.write(M.rehash(ev)), "flags": [], "kind": "extra"})
        extra_kw = {}
        for name in ("issuer_x5c_no_anchor", "issuer_x5c_chain_broken"):
            for ca in ("issuer_ca.crt", "issuer_other_ca.crt"):
                nm = f"extra/{name}/trust-anchor-{ca}"
                c.recs.append({"name": nm, "path": os.path.join(vd, name + ".json"), "flags": [], "kind": "extra"})
                extra_kw[nm] = {"trust_anchor": os.path.join(vd, ca)}
        if baselines_only:   # the vectors and the extra packs only (the test suite's sabotage runs)
            c.recs = [r for r in c.recs if r.get("kind") in ("baseline", "extra")]
        for rec in c.recs:
            base_kw = dict(M.kwargs_for(rec["flags"]), **extra_kw.get(rec["name"], {}))
            ta = {k: v for k, v in base_kw.items() if k == "trust_anchor"}
            variants = {"own": base_kw, "none": dict(ta, trusted_producer_keys=None), "pins": dict(ta, trusted_producer_keys=pins),
                        "wrong": dict(ta, trusted_producer_keys=WRONG_PINS)}
            if rec.get("kind") == "baseline":
                variants["tsa"] = dict(base_kw, tsa_cert=tsa)
            states = {}
            bm = independent_binding_match(ap2, rec["path"])
            for vn, kw in variants.items():
                try:
                    r = ap2.verify_evidence(rec["path"], **kw)
                except ap2.Ap2WriteError as e:
                    r = e.receipt or {"crash": str(e)}
                except Exception as e:  # noqa: BLE001
                    r = {"crash": f"{type(e).__name__}: {e}"}
                n += 1
                if "crash" in r:
                    viol.append((rec["name"], vn, "crash " + r["crash"])); continue
                if r.get("admission") == "admitted":
                    r["_rfc_block"] = keep_block.last
                for x in check_receipt(r, kw, bm):
                    viol.append((rec["name"], vn, x))
                design_fail += design_equation(r) != r["valid"]
                states[vn] = r.get("states")
                valid_by_case[f"{rec['name']}|{vn}"] = r["valid"]
                manifest.append({"case": f"{rec['name']}|{vn}", "path": rec["path"], "kw": kw})
            # C4 — pins
            if all(states.get(k) for k in ("none", "pins", "wrong")):
                def contra(s):
                    return {k for k, x in s.items() if x["state"] == "contradicted"}
                if not (contra(states["none"]) == contra(states["pins"]) == contra(states["wrong"])):
                    viol.append((rec["name"], "pins", "C4 a pinned set changed the contradicted subjects"))
                if states["wrong"]["producer_signature"]["state"] == "verified":
                    viol.append((rec["name"], "wrong", "C4 producer verified under a set that holds none of its keys"))
                if RANK[states["pins"]["producer_signature"]["state"]] < RANK[states["none"]["producer_signature"]["state"]]:
                    viol.append((rec["name"], "pins", "C4 pinning the right keys lowered the producer state"))
        old_diff = None
        if old_root:
            mf = os.path.join(d, "manifest.json")
            with open(mf, "w", encoding="utf-8") as f:
                json.dump(manifest, f)
            code = ("import json,sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a; out = {}\n"
                    "for m in json.load(open(sys.argv[2])):\n"
                    "    kw = {k: v for k, v in m['kw'].items() if k != 'trust_set_complete'}\n"
                    "    try: out[m['case']] = a.verify_evidence(m['path'], **kw)['valid']\n"
                    "    except a.Ap2WriteError: out[m['case']] = 'write-error'\n"
                    "print(json.dumps(out))")
            p = subprocess.run([sys.executable, "-B", "-c", code, old_root, mf], capture_output=True, text=True, timeout=3600)
            old = json.loads(p.stdout)
            old_diff = sorted(k for k in valid_by_case if old.get(k) != valid_by_case[k])
        return {"files": len(c.recs), "receipts": n, "violations": viol, "design_equation_failures": design_fail,
                "valid_differs_from_old": old_diff, "ok": not viol and not old_diff}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--old", help="root of an earlier revision: compare `valid` on every file")
    ap.add_argument("--sabotage", choices=SABOTAGES)
    a = ap.parse_args(argv)
    r = run(quick=not a.full, old_root=a.old, sabotage=a.sabotage)
    print(json.dumps({k: (v if k != "violations" else v[:20]) for k, v in r.items()}, indent=1))
    print(f"files {r['files']}, receipts {r['receipts']}, violations {len(r['violations'])}, "
          f"design-equation failures {r['design_equation_failures']}, valid differs from --old: "
          f"{'not measured' if r['valid_differs_from_old'] is None else len(r['valid_differs_from_old'])}")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
