#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.6.0 — SPEC §6.9/§6.10: admission, refusal_class, states, policy; the pre-registered controls and their positive controls."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "verifiers"))
import ap2_evidence as ap2  # noqa: E402
import states_controls as SC  # noqa: E402

VEC = os.path.join(_HERE, "spec", "vectors", "ap2")
JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
HAVE_NODE = shutil.which("node") is not None


def _write(d, name, ev):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False)
    return p


def _load(name):
    with open(os.path.join(VEC, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


class TestStatesBench(unittest.TestCase):
    def test_generative_controls_hold(self):
        r = SC.run(quick=True)
        self.assertGreater(r["receipts"], 20000, r["receipts"])
        self.assertEqual(r["violations"], [], r["violations"][:10])

    def test_every_sabotage_turns_the_bench_red(self):
        """The bench can fail: each rule of the derivation replaced in-process (a subprocess per sabotage: one reference
        per process) must leave at least one violation, on the vectors and the extra packs alone."""
        code = ("import sys; sys.path.insert(0, %r); import states_controls as S; "
                "r = S.run(quick=True, sabotage=sys.argv[1], baselines_only=True); print(len(r['violations']))") % os.path.join(_HERE, "verifiers")
        for sb in SC.SABOTAGES:
            with self.subTest(sabotage=sb):
                out = subprocess.run([sys.executable, "-B", "-c", code, sb], capture_output=True, text=True, timeout=600)
                self.assertEqual(out.returncode, 0, out.stderr[-600:])
                self.assertGreater(int(out.stdout.split()[-1]), 0, sb)
        out = subprocess.run([sys.executable, "-B", "-c", code.replace("sabotage=sys.argv[1]", "sabotage=None"), "x"],
                             capture_output=True, text=True, timeout=600)
        self.assertEqual(out.stdout.split()[-1], "0", out.stderr[-600:])   # the control: no sabotage, no violation


class TestReceiptShape(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS half is not measurable")
    def test_kb_signature_and_sd_hash_both_false_is_kb_signature_invalid(self):
        """1.6.0 review (SPEC §6.9, `holder_binding`): a KB-JWT whose signature AND sd_hash are both false is stated once,
        `kb_signature_invalid`. No vector has both: the mutant that names `sd_hash_mismatch` first survived every suite."""
        import base64
        sys.path.insert(0, os.path.join(_HERE, "verifiers"))
        import differential_oracle as O
        ev = _load("holder_kb_signature_invalid")   # signed by another key than cnf.jwk, sd_hash right
        a = ev["artifacts"][0]
        head, _, kb = a["sd_jwt_compact"].rpartition("~")
        h, p, s = kb.split(".")
        pay = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        pay["sd_hash"] = "A" * 43   # another presentation
        p2 = base64.urlsafe_b64encode(json.dumps(pay, separators=(",", ":")).encode()).decode().rstrip("=")
        a["sd_jwt_compact"] = head + "~" + ".".join((h, p2, s))
        path = _write(self.d, "both.json", O.rehash(ev))
        r = ap2.verify_evidence(path)
        kbr = r["artifacts"][0]["kb_jwt"]
        self.assertEqual((kbr["signature_ok"], kbr["sd_hash_ok"], r["valid"]), (False, False, False))   # both false: the case
        self.assertEqual(r["states"]["holder_binding"], {"state": "contradicted", "reasons": ["kb_signature_invalid"]})
        out = subprocess.run(["node", JS, path], capture_output=True, text=True)
        self.assertEqual(json.loads(out.stdout)["states"]["holder_binding"], r["states"]["holder_binding"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent: chain validation not measured")
    def test_x5c_entry_not_strict_base64_is_chain_broken(self):
        """1.6.0 review (SPEC §6.9, `issuer_identity`): an x5c entry after the leaf that is not strict base64 is
        `chain_broken`. No vector has one: the mutant that drops that branch (-> chain_unresolved) survived every suite.
        Control: the same chain with the entry removed validates (`ca_certified`)."""
        import base64, datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        sys.path.insert(0, os.path.join(_HERE, "verifiers"))
        import differential_oracle as O
        b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
        sk, ca = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        nums = sk.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "review CA")])
        t0, t1 = datetime.datetime(2026, 1, 1), datetime.datetime(2046, 1, 1)
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "review subject")]))
                .issuer_name(ca_name).public_key(sk.public_key()).serial_number(2).not_valid_before(t0).not_valid_after(t1).sign(ca, hashes.SHA256()))
        ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca.public_key()).serial_number(3)
                   .not_valid_before(t0).not_valid_after(t1).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(ca, hashes.SHA256()))
        anchor = os.path.join(self.d, "ca.pem")
        with open(anchor, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        leaf_b64 = base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()
        base = _load("valid_signed")
        got = {}
        for name, x5c in (("control", [leaf_b64]), ("bad-entry", [leaf_b64, "%%%not-base64"])):
            hdr = json.dumps({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": x5c}, separators=(",", ":"))
            si = b64u(hdr.encode()) + "." + b64u(b'{"iss":"x"}')
            r_, s_ = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
            ev = {"evidence_format": base["evidence_format"], "subject": "review", "created_utc": "2026-10-18T00:00:00Z",
                  "artifacts": [{"name": "intent", "sd_jwt_compact": si + "." + b64u(r_.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~",
                                 "header": json.loads(hdr), "key": {"jwk": jwk, "provenance_class": "x5c_header"}, "resolved_claims": {"iss": "x"},
                                 "kb_jwt": {"present": False}, "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}],
                  "bindings": [], "honest_scope": base["honest_scope"]}
            r = ap2.verify_evidence(_write(self.d, name + ".json", O.rehash(ev)), trust_anchor=anchor)
            got[name] = r["states"]["issuer_identity"]
        self.assertEqual(got["control"], {"state": "verified", "reasons": ["ca_certified"]})
        self.assertEqual((got["bad-entry"]["state"], got["bad-entry"]["reasons"]), ("contradicted", ["chain_broken"]))

    def test_refusal_classes(self):
        ev = _load("valid_signed")
        cases = {"format_unsupported": dict(ev, evidence_format="ap2-evidence-pack/2.0"),
                 "malformed": dict(ev, subject=5),
                 "unknown_member": dict(ev, retention_profile="x")}
        bad_scope = dict(ev, honest_scope=ev["honest_scope"] + " ")
        cases_scope = {"format_unsupported": bad_scope}
        for cls, e in list(cases.items()) + list(cases_scope.items()):
            r = ap2.verify_evidence(_write(self.d, "p.json", e))
            self.assertEqual((r["admission"], r["refusal_class"], r["states"], r["policy"], r["valid"]), ("refused", cls, None, None, False))
            self.assertEqual(r["states_vocabulary"], "ap2-evidence-pack/states-1")
            self.assertIsNone(r["producer_signatures"]["ok"])   # always present (1.6.0)
        p = os.path.join(self.d, "notjson.json")
        with open(p, "wb") as f:
            f.write(b"\xef\xbb\xbf{}")
        self.assertEqual(ap2.verify_evidence(p)["refusal_class"], "malformed")

    def test_unknown_key_in_an_artifact_sub_object_is_a_refusal_but_a_wrong_type_stays_an_artifact_error(self):
        ev = _load("valid_signed")
        for sub in ("key", "kb_jwt", "verified_at_build"):
            e = json.loads(json.dumps(ev)); e["artifacts"][1][sub]["zz"] = 1
            r = ap2.verify_evidence(_write(self.d, "p.json", e))
            self.assertEqual((r["refusal_class"], r["refused"]), ("unknown_member", f'artifacts[1].{sub}: unknown key "zz" (SPEC §9.1)'))
        e = json.loads(json.dumps(ev)); e["artifacts"][0]["kb_jwt"]["present"] = "no"   # wrong type: still that artifact's error
        r = ap2.verify_evidence(_write(self.d, "p.json", e))
        self.assertEqual(r["admission"], "admitted")
        self.assertIn("error", r["artifacts"][0])
        self.assertEqual(r["states"]["sealed_content"]["state"], "contradicted")

    def test_producer_ok_always_present(self):
        for name in sorted(f[:-14] for f in os.listdir(VEC) if f.endswith(".expected.json")):
            r = ap2.verify_evidence(os.path.join(VEC, name + ".json"))
            self.assertIn("ok", r["producer_signatures"], name)

    def test_trust_set_complete_is_a_disposition_never_a_failed_signature(self):
        with open(os.path.join(VEC, "unpinned_producer.expected.json"), encoding="utf-8") as f:
            pins = json.load(f)["policy"]["trusted_producer_keys"]
        p = os.path.join(VEC, "unpinned_producer.json")
        a = ap2.verify_evidence(p, trusted_producer_keys=pins)
        b = ap2.verify_evidence(p, trusted_producer_keys=pins, trust_set_complete=True)
        self.assertEqual(a["states"], b["states"])   # the state is the same: key_unresolved, not signature_invalid
        self.assertEqual(b["states"]["producer_signature"]["state"], "not_evaluated")
        self.assertEqual((a["policy"]["unmet"], b["policy"]["unmet"]), (["trusted_producer_keys"], ["trusted_producer_keys", "trust_set_complete"]))
        self.assertEqual((a["valid"], b["valid"], a["policy_ok"], b["policy_ok"]), (False, False, True, True))   # policy_ok: the 1.5.x four inputs
        c = ap2.verify_evidence(os.path.join(VEC, "valid_signed.json"), trust_set_complete=True)   # no pins: nothing unresolved
        self.assertEqual((c["valid"], c["policy"]["unmet"]), (True, []))

    def test_valid_equation_on_every_vector(self):
        """SPEC §6.9: valid == no subject but issuer_identity contradicted AND no SKIP entry AND policy.met (admitted), with
        C1/C2/C5 on every vector; the design's equation fails exactly on the two vectors SPEC §6.9 names."""
        sys.path.insert(0, VEC)
        import run_ap2_conformance as rc
        design_fail = []
        for name in sorted(f[:-14] for f in os.listdir(VEC) if f.endswith(".expected.json")):
            with open(os.path.join(VEC, name + ".expected.json"), encoding="utf-8") as f:
                exp = json.load(f)
            if "openssl" in exp.get("requires", []) and not shutil.which("openssl"):
                continue
            path = os.path.join(VEC, name + ".json")
            r = rc.verify_with_policy(ap2.verify_evidence, path, exp["policy"], VEC)
            kw = {k: v for k, v in exp["policy"].items() if k in ("tsa_cert", "trust_anchor", "trusted_producer_keys")}
            self.assertEqual(SC.check_receipt(r, kw, SC.independent_binding_match(ap2, path)), [], name)
            if SC.design_equation(r) != r["valid"]:
                design_fail.append(name)
        if ap2._sigsuite.MLDSA_AVAILABLE:   # without the backend every ML-DSA-65 entry is SKIP: more packs fall outside the design's equation
            self.assertEqual(design_fail, (["issuer_x5c_chain_broken"] if shutil.which("openssl") else []) + ["producer_backend_missing"])

    @unittest.skipUnless(HAVE_NODE, "node absent")
    def test_js_refuses_trust_anchor_and_takes_trust_set_complete(self):
        p = os.path.join(VEC, "issuer_x5c_no_anchor.json")
        out = subprocess.run(["node", JS, p, "--trust-anchor", os.path.join(VEC, "issuer_ca.crt")], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout), (2, ""))   # 1.5.4: exit 0, chain_verified null — a flag that did nothing
        with open(os.path.join(VEC, "unpinned_producer.expected.json"), encoding="utf-8") as f:
            pins = json.load(f)["policy"]["trusted_producer_keys"]
        fl = [x for alg, ks in pins.items() for k in ks for x in ("--trusted-producer-key", f"{alg}={k}")]
        out = subprocess.run(["node", JS, os.path.join(VEC, "unpinned_producer.json"), *fl, "--trust-set-complete"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        self.assertEqual(json.loads(out.stdout)["policy"]["unmet"], ["trusted_producer_keys", "trust_set_complete"])
        out = subprocess.run(["node", JS, p, "--trust-set-complete=1"], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout), (2, ""))

    def test_cli_trust_set_complete_grammar(self):
        py = [sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "verify", os.path.join(VEC, "valid_signed.json")]
        out = subprocess.run(py + ["--trust-set-complete=1"], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout), (2, ""))
        out = subprocess.run(py + ["--trust-set-complete"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_openssl_absent_is_instrument_failure_and_the_exit_follows_valid(self):
        """SPEC §6.10: openssl ABSENT is not 74 (as in 1.5.x): the subject is not_evaluated/instrument_failure and the exit is
        the verdict's. PATH without openssl, in a subprocess."""
        env = dict(os.environ, PATH=tempfile.mkdtemp(dir=self.d))
        py = [sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "verify", os.path.join(VEC, "anchor_valid.json"),
              "--tsa-cert", os.path.join(VEC, "anchor_probe_tsa.crt")]
        out = subprocess.run(py, capture_output=True, text=True, env=env)
        r = json.loads(out.stdout)
        self.assertEqual((out.returncode, r["valid"]), (0, True))
        self.assertEqual(r["states"]["time_anchor"], {"state": "not_evaluated", "reasons": ["instrument_failure"],
                                                      "detail": "openssl absent — TSA signature/chain NOT verified"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
