#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""One-shot conformance entry point: the ap2-evidence-pack conformance vectors
(spec/vectors/ap2/), the NIST ACVP ML-DSA-65 sigVer subset, and the pqcrypto
signature-suite bench, all in a single run."""
import importlib
import json
import glob
import os
import shutil
import subprocess
import tempfile
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "pqcrypto"))
sys.path.insert(0, os.path.join(_HERE, "spec", "vectors", "ap2"))
import ap2_evidence as ap2  # noqa: E402


class TestAp2ConformanceVectors(unittest.TestCase):
    def test_reference_verifier_is_conformant(self):
        import run_ap2_conformance as rc
        r = rc.run()
        self.assertTrue(r["conformant"], r)
        statuses = {x["vector"]: x["status"] for x in r["results"]}
        self.assertEqual(len(statuses), 42, statuses)   # 1.1.0: + anchor_valid (real token, probe TSA) and anchor_wrong_digest; 1.4.0: + 9 closed-schema vectors (SPEC §9); 1.5.0: + 9 anchors vectors (SPEC §3.3); 1.5.4: + 3 producer-block vectors (SPEC §5); 1.6.0: + 13 states vectors (SPEC §6.9)
        self.assertEqual(statuses.get("kb_jwt_valid"), "PASS", statuses)   # 1.4.0: the KB-JWT positive control
        # the set must contain the positive control — an always-reject verifier must fail
        self.assertEqual(statuses.get("valid_signed"), "PASS", statuses)

    def test_hostile_files_are_refusal_receipts_never_tracebacks(self):
        # 1.1.0 acceptance profile: non-UTF-8, 100000-deep, float, 2^53+1, lone surrogate, NaN, BOM, non-object, missing path,
        # directory -> a receipt with valid False and `refused`, never an exception (1.0.2 raised on the first two and on
        # missing paths, and accepted float / big int / lone surrogate with a recomputed digest)
        import tempfile, hashlib
        base_text = open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"), encoding="utf-8").read(); base = json.loads(base_text)
        def rehash(ev):
            e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
            ev = dict(ev); ev["evidence_digest_sha256"] = hashlib.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode()).hexdigest(); ev.pop("producer_signatures", None); return ev
        d = tempfile.mkdtemp()
        files = {"raw": json.dumps(rehash(dict(base, subject="x\ufffd")), ensure_ascii=False).encode("utf-8").replace("\ufffd".encode("utf-8"), b"\xff", 1),
                 "deep": b"[" * 100000, "float": json.dumps(rehash(dict(base, extra=1.0))).encode(), "big": json.dumps(rehash(dict(base, extra=9007199254740993))).encode(),
                 "nan": base_text.replace('"created_utc"', '"x": NaN, "created_utc"', 1).encode(), "bom": ("\ufeff" + base_text).encode("utf-8"), "list": b"[1]"}
        lone = dict(base, subject="\ud800"); e2 = {k: v for k, v in lone.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
        lone["evidence_digest_sha256"] = hashlib.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode("utf-8", "surrogatepass")).hexdigest(); lone.pop("producer_signatures", None)
        files["lone"] = json.dumps(lone).encode()
        for name, data in files.items():
            p = os.path.join(d, name + ".json"); open(p, "wb").write(data)
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], name); self.assertFalse(r["digest_ok"], name); self.assertIn("refused", r, name)
        for p in (os.path.join(d, "nope.json"), d):
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"]); self.assertIn("unreadable", r["refused"])
        ok = os.path.join(d, "ok.json"); open(ok, "w", encoding="utf-8").write(json.dumps(rehash(dict(base, subject="café ≥ 1 😀")), ensure_ascii=False))
        self.assertTrue(ap2.verify_evidence(ok)["valid"])          # positive control: non-ASCII IS in profile

    def test_provenance_class_is_reconciled_and_format_is_pinned(self):
        # review r5: `provenance_class` is the field honest_scope sends the relying party to, and it was pure assertion —
        # relabelling jwk_header as x5c_header made self_asserted_only False with no x5c anywhere; out-of-enum values passed.
        # `evidence_format` and the §1 MUSTs were never read, so a "…/2.0" pack verified under the 1.0 rules.
        import tempfile, copy
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"))); d = tempfile.mkdtemp()
        def write(name, ev):
            p = os.path.join(d, name + ".json"); json.dump(ev, open(p, "w")); return p
        for name, v in (("x5c-without-x5c", "x5c_header"), ("out-of-enum", "qualified_eidas_certificate"), ("list", ["jwk_header"])):
            e = copy.deepcopy(base)
            for a in e["artifacts"]: a["key"]["provenance_class"] = v
            r = ap2.verify_evidence(write(name, O.rehash(e)))
            self.assertFalse(r["valid"], name); self.assertIn("provenance_class", r["artifacts"][0]["error"], name)
        e = copy.deepcopy(base)   # positive control: the honest label verifies and keeps self_asserted_only true
        r = ap2.verify_evidence(write("intact", O.rehash(e)))
        self.assertTrue(r["valid"]); self.assertEqual(r["provenance_classes"], ["jwk_header"]); self.assertTrue(r["self_asserted_only"])
        # r7: self_asserted_only is FAIL-CLOSED — a label alone must not clear it, and deleting the field is a refusal
        for name, v in (("supplied", "supplied"), ("jwks_fetched", "jwks_fetched")):
            e = copy.deepcopy(base)
            for a in e["artifacts"]: a["key"]["provenance_class"] = v
            r = ap2.verify_evidence(write("sa-" + name, O.rehash(e)))
            self.assertTrue(r["valid"], name); self.assertTrue(r["self_asserted_only"], name)   # the label is not evidence
        for name, v in (("null", None), ("absent", "__DEL__")):
            e = copy.deepcopy(base)
            for a in e["artifacts"]:
                if v == "__DEL__": a["key"].pop("provenance_class", None)
                else: a["key"]["provenance_class"] = v
            r = ap2.verify_evidence(write("sa-" + name, O.rehash(e)))
            self.assertFalse(r["valid"], name); self.assertIn("provenance_class", r["artifacts"][0]["error"], name)
        # r8: offline NOTHING clears the flag — r7 read "issued by someone else" off subject != issuer, two DN strings the
        # forger writes himself (measured: a leaf self-signed with its own key, declaring CN=DigiCert Global Root CA, cleared
        # it). Only a chain validated to a trust anchor the relying party supplies does, and that needs openssl.
        cases = dict(O._x5c_cases(base)); anchor = os.path.join(d, "probe_ca.pem"); open(anchor, "wb").write(O._x5c_cases.ca_pem)
        for name in ("canonical", "ca-issued-leaf"):
            r = ap2.verify_evidence(write("x5c-" + name, O.rehash(cases[name])))
            self.assertTrue(r["valid"], name); self.assertTrue(r["self_asserted_only"], name); self.assertIsNone(r["chain_verified"], name)
        if shutil.which("openssl"):   # positive control of the ONE path that clears it
            r = ap2.verify_evidence(write("x5c-ca2", O.rehash(cases["ca-issued-leaf"])), trust_anchor=anchor)
            self.assertTrue(r["valid"]); self.assertFalse(r["self_asserted_only"]); self.assertTrue(r["chain_verified"])
            r = ap2.verify_evidence(write("x5c-self2", O.rehash(cases["canonical"])), trust_anchor=anchor)   # negative control: the self-signed leaf does not chain to it
            self.assertTrue(r["self_asserted_only"]); self.assertFalse(r["chain_verified"])

        for name, mut, frag in (("format2", lambda e: e.__setitem__("evidence_format", "ap2-evidence-pack/2.0"), "evidence_format"),
                                ("noformat", lambda e: e.pop("evidence_format", None), "evidence_format"),
                                ("nosubject", lambda e: e.pop("subject", None), "subject"),
                                ("nocreated", lambda e: e.pop("created_utc", None), "created_utc"),
                                ("noscope", lambda e: e.pop("honest_scope", None), "honest_scope")):
            e = copy.deepcopy(base); mut(e); r = ap2.verify_evidence(write(name, O.rehash(e)))
            self.assertFalse(r["valid"], name); self.assertIn(frag, r["refused"], name)

    def test_build_refuses_what_verify_refuses(self):
        # review r5: `build` wrote a pack with an empty artifact name (exit 0, success receipt) that both verifiers then
        # refused. The SD-JWT here is VALID, so the only thing that can make build refuse is the name — otherwise the
        # test would pass for the wrong reason (an unparsable artifact raises anyway).
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        sk, n = O._fresh_key(); compact = O._sign_compact(sk, n, '{"iss":"x"}'); d = tempfile.mkdtemp()
        ap2.build_evidence([{"name": "intent", "sd_jwt": compact}], os.path.join(d, "ok.json"))   # positive control: it builds
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "", "sd_jwt": compact}], os.path.join(d, "o.json"))

    def test_honesty_flag_and_scope_are_fail_closed(self):
        # final check before release: `any()` over zero artifacts printed the GREEN value — an empty pack reported
        # "no self-asserted key here" — and the sealed scope must be the format's, not the pack's (SPEC §1/§8).
        import tempfile, copy
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"))); d = tempfile.mkdtemp()
        e = copy.deepcopy(base); e["artifacts"] = []; e["bindings"] = []
        p = os.path.join(d, "empty.json"); json.dump(O.rehash(e), open(p, "w"))
        r = ap2.verify_evidence(p)
        self.assertFalse(r["valid"]); self.assertTrue(r["self_asserted_only"], "an empty pack is not 'no self-asserted key'")
        e = copy.deepcopy(base); e["honest_scope"] = base["honest_scope"].replace("Proves:", "Proves everything:")
        p = os.path.join(d, "scope.json"); json.dump(O.rehash(e), open(p, "w"))
        r = ap2.verify_evidence(p)
        self.assertFalse(r["valid"]); self.assertIn("honest_scope", r["refused"])
        self.assertTrue(r["self_asserted_only"])   # a refusal receipt never prints the green value either

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS receipt is not measured")
    def test_both_receipts_carry_the_same_field_names(self):
        # r10 lesson, measured twice in one day: a trailing `//` comment silently swallowed the rest of its line — first a
        # shape check (dead code for a whole round), then `policy_ok` (gone from the JS receipt). Neither broke the syntax.
        # This compares the KEY SETS of the two receipts, so the next field that disappears into a comment turns red here.
        import subprocess, tempfile
        V = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")
        def receipts(path, flags=()):
            py = ap2.verify_evidence(path)
            out = subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), path, *flags], capture_output=True, text=True)
            return py, json.loads(out.stdout)
        py, js = receipts(V)
        self.assertEqual(sorted(py), sorted(js), "top-level receipt fields differ between the verifiers")
        for a, b in zip(py["artifacts"], js["artifacts"]):
            self.assertEqual(sorted(a), sorted(b), f"artifact receipt fields differ for {a.get('name')!r}")
        self.assertEqual(sorted(py["rfc3161"]), sorted(js["rfc3161"]), "rfc3161 receipt fields differ")
        # and on a pack WITH a KB-JWT — the branch where the two receipts had drifted apart (the reference carried a
        # `note`, the JS did not, and neither recorded the aud/nonce/iat the sealed scope says are recorded)
        import base64
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")   # noqa: E731
        base = json.load(open(V)); sk, n = O._fresh_key()
        kb = ".".join([b64u(b'{"alg":"ES256","typ":"kb+jwt"}'), b64u(b'{"aud":"m","nonce":"n1","iat":1,"sd_hash":"x"}'), b64u(b"\x00" * 64)])
        ev = O._fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', '{"iss":"x"}', {"iss": "x"}, kb=kb)
        kbp = os.path.join(tempfile.mkdtemp(), "kb.json"); json.dump(O.rehash(ev), open(kbp, "w"))
        py, js = receipts(kbp)
        self.assertEqual(sorted(py["artifacts"][0]["kb_jwt"]), sorted(js["artifacts"][0]["kb_jwt"]), "KB-JWT receipt fields differ")
        self.assertEqual(py["artifacts"][0]["kb_jwt"]["claims_recorded_not_validated"],
                         js["artifacts"][0]["kb_jwt"]["claims_recorded_not_validated"], "the recorded KB-JWT claims differ")
        self.assertIn("aud", py["artifacts"][0]["kb_jwt"]["claims_recorded_not_validated"])

        d = tempfile.mkdtemp(); bad = os.path.join(d, "bad.json")   # and on a refusal, where the shapes had also drifted
        open(bad, "w").write('{"evidence_format":"nope"}')
        py, js = receipts(bad)
        self.assertEqual(sorted(py), sorted(js), "refusal receipt fields differ between the verifiers")

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent: chain validation not measured")
    def test_expired_leaf_clears_the_flag_only_at_a_proven_time(self):
        # r9: `openssl verify` checks validity at the CURRENT clock, so a leaf valid 2020-2021 — the ordinary case for a
        # format whose claim is "verifies offline years later" — could never clear self_asserted_only. The chain is now
        # validated at the genTime of a TSA-VERIFIED token when there is one, exactly as the TSA chain is (SPEC §3.2).
        import base64, datetime, tempfile, json as _json
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")   # noqa: E731
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"))); d = tempfile.mkdtemp()
        ca = ec.generate_private_key(ec.SECP256R1()); sk = ec.generate_private_key(ec.SECP256R1()); n = sk.public_key().public_numbers()
        caname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe CA")])
        cacert = (x509.CertificateBuilder().subject_name(caname).issuer_name(caname).public_key(ca.public_key()).serial_number(1)
                  .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca, hashes.SHA256()))
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wallet.example")]))
                .issuer_name(caname).public_key(sk.public_key()).serial_number(2)
                .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2021, 1, 1)).sign(ca, hashes.SHA256()))
        hdr = _json.dumps({"alg": "ES256", "typ": "ap2-mandate+sd-jwt",
                           "x5c": [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()]}, separators=(",", ":"))
        si = b64u(hdr.encode()) + "." + b64u(b'{"iss":"wallet"}')
        r, s_ = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        ev = {"evidence_format": base["evidence_format"], "subject": "probe", "created_utc": "2020-06-01T00:00:00Z",
              "artifacts": [{"name": "intent", "sd_jwt_compact": si + "." + b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~",
                             "header": _json.loads(hdr),
                             "key": {"jwk": {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))},
                                     "provenance_class": "x5c_header"},
                             "resolved_claims": {"iss": "wallet"}, "kb_jwt": {"present": False},
                             "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}],
              "bindings": [], "honest_scope": base["honest_scope"]}
        ev = O.rehash(ev); p = os.path.join(d, "expired.json"); _json.dump(ev, open(p, "w"))
        anchor = os.path.join(d, "ca.pem"); open(anchor, "wb").write(cacert.public_bytes(serialization.Encoding.PEM))
        r1 = ap2.verify_evidence(p, trust_anchor=anchor)   # today's clock: the leaf is long expired
        self.assertTrue(r1["self_asserted_only"]); self.assertFalse(r1["chain_verified"])
        self.assertEqual(r1["artifacts"][0]["x5c_leaf"]["subject"], "CN=wallet.example")   # the receipt names the leaf (r9)
        orig = ap2._verify_rfc3161                         # a TSA-verified genTime inside the leaf's validity
        ap2._verify_rfc3161 = lambda *a, **k: {"verified": True, "granted": True, "imprint_ok": True,
                                               "gen_time": "20200601000000Z", "tsa_verified": True}
        try:
            ev["rfc3161_timestamp"] = {"anchored": True, "tsr_b64": "AA=="}; _json.dump(ev, open(p, "w"))
            r2 = ap2.verify_evidence(p, trust_anchor=anchor, tsa_cert="x")
        finally:
            ap2._verify_rfc3161 = orig
        self.assertFalse(r2["self_asserted_only"]); self.assertTrue(r2["chain_verified"])

    def test_build_side_x5c_and_jwks_errors_are_receipts(self):
        # r7: `build` tracebacked (bare ValueError / URLError) on a leaf wrapped at 76 columns, a non-certificate, a
        # non-string entry, an unreachable JWKS — the verify side had been made fail-closed in r1, build had not
        import base64 as _b64, datetime, textwrap, subprocess
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        b64u = lambda b: _b64.urlsafe_b64encode(b).decode().rstrip("=")   # noqa: E731
        sk = ec.generate_private_key(ec.SECP256R1())
        nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe")])
        cert = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(sk.public_key()).serial_number(1)
                .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1)).sign(sk, hashes.SHA256()))
        leaf = _b64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(); d = tempfile.mkdtemp()
        def mandate(x5c_entry):
            hdr = json.dumps({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": [x5c_entry]}, separators=(",", ":"))
            si = b64u(hdr.encode()) + "." + b64u(b'{"iss":"x"}')
            r, s_ = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
            p = os.path.join(d, "m.sdjwt"); open(p, "w").write(si + "." + b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~"); return p
        for name, entry in (("wrapped", "\n".join(textwrap.wrap(leaf, 76))), ("not-a-cert", "AAAA"), ("non-string", 1)):
            out = subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "build", os.path.join(d, "o.json"), "intent=" + mandate(entry)], capture_output=True, text=True)
            self.assertEqual(out.returncode, 1, (name, out.stderr[-200:])); self.assertIn("error", json.loads(out.stderr)); self.assertNotIn("Traceback", out.stderr)
        out = subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "build", os.path.join(d, "ok.json"), "intent=" + mandate(leaf)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr[-200:])   # positive control: the canonical leaf builds

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier is not measured, so 'one grammar' is not measurable")
    def test_cli_grammar_is_one_with_the_js_verifier(self):
        import subprocess
        V = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")
        clis = [[sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "verify"],
                ["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")]]
        for extra in ([], [V, "--no-such"], [V, V], [""], ["--help"], ["-h"], ["--", V], [V, "--require-pq=1"], [V, "--trusted-producer-key", ""],
                      [V, "--trusted-producer-key"], [V, "--trusted-producer-key", "--require-pq"], [V, "--trusted-producer-key", "abc"], [V, "--trusted-producer-key", "", "--trusted-producer-key", "ed25519=AA=="], [V, "--tsa-cert", ""],
                      [V, "--tsa-cert", os.path.join(_HERE, "no-such.pem")], [V, "--tsa-cert", os.devnull], [V, "--tsa-cert", _HERE]):   # 1.6.0 review: a certificate that cannot be read
            for cli in clis:
                out = subprocess.run(cli + extra, capture_output=True, text=True)
                self.assertEqual(out.returncode, 2, (cli[0], extra, out.stdout[:80], out.stderr[-120:])); self.assertEqual(out.stdout, "")
        for cli in clis:
            out = subprocess.run(cli + [V], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, cli[0]); self.assertTrue(json.loads(out.stdout)["valid"])
        for cli in clis:   # the control of the 1.6.0 review cases: a readable certificate is no usage error
            out = subprocess.run(cli + [V, "--tsa-cert", os.path.join(_HERE, "spec", "vectors", "ap2", "anchor_probe_tsa.crt")], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, (cli[0], out.stderr[-120:]))
        for extra in (["--trust-anchor", os.path.join(_HERE, "no-such.pem")], ["--trust-anchor", os.devnull]):   # the reference only (JS: always usage)
            out = subprocess.run(clis[0] + [V] + extra, capture_output=True, text=True)
            self.assertEqual((out.returncode, out.stdout), (2, ""), extra)
            self.assertIn("cannot read", out.stderr)
        # r3: the BARE invocation (no subcommand at all) — the reference printed its help on stdout with exit 2, the JS verifier usage on stderr
        for cli in ([sys.executable, os.path.join(_HERE, "ap2_evidence.py")], clis[1]):   # r5: clis[-1] was the Python entry when node was absent, so the JS bare case never ran
            out = subprocess.run(cli, capture_output=True, text=True)
            self.assertEqual(out.returncode, 2, cli[0]); self.assertEqual(out.stdout, "", cli[0]); self.assertNotEqual(out.stderr, "", cli[0])

    @unittest.skipUnless(shutil.which("node"), "node absent: 'in both verifiers' is not measurable")
    def test_wrong_json_shapes_are_refusals_in_both_verifiers(self):
        # review r1: artifacts / key / jwk / rfc3161_timestamp / producer_signatures of the wrong type were TypeError /
        # AttributeError tracebacks in the reference; {} as a producer block was "absent" (valid True)
        import copy, subprocess, tempfile
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"))); d = tempfile.mkdtemp()
        muts = {"artifacts-null": lambda e: e.__setitem__("artifacts", None), "artifacts-string": lambda e: e.__setitem__("artifacts", "x"),
                "artifacts-list-of-null": lambda e: e.__setitem__("artifacts", [None]), "key-null": lambda e: e["artifacts"][0].__setitem__("key", None),
                "jwk-list": lambda e: e["artifacts"][0]["key"].__setitem__("jwk", [1]), "rfc3161-null": lambda e: e.__setitem__("rfc3161_timestamp", None),
                "rfc3161-string": lambda e: e.__setitem__("rfc3161_timestamp", "x"), "producer-string": lambda e: e.__setitem__("producer_signatures", "x"),
                "producer-empty": lambda e: e.__setitem__("producer_signatures", {}), "producer-list": lambda e: e.__setitem__("producer_signatures", []),
                "producer-sigs-null-entry": lambda e: e.__setitem__("producer_signatures", {"signatures": [None]})}
        for name, mut in muts.items():
            e = copy.deepcopy(base); mut(e); p = os.path.join(d, name + ".json"); json.dump(e, open(p, "w"))
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], name)
            out = subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), p], capture_output=True, text=True)
            self.assertFalse(json.loads(out.stdout)["valid"], name)

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent: TSA verification not measured")
    def test_rfc3161_binding_vs_tsa_authenticity(self):
        # a self-forged TimeStampResp (status 0, imprint = digest, no signer) satisfies BINDING (SPEC §3.2) but not the TSA
        # check; the real probe token passes both with its certificate; the real token for another digest fails binding
        import base64, tempfile
        vdir = os.path.join(_HERE, "spec", "vectors", "ap2"); cert = os.path.join(vdir, "anchor_probe_tsa.crt")
        r = ap2.verify_evidence(os.path.join(vdir, "anchor_valid.json"), require_anchor=True, tsa_cert=cert)
        self.assertTrue(r["valid"]); self.assertTrue(r["rfc3161"]["verified"]); self.assertTrue(r["rfc3161"]["tsa_verified"])
        r = ap2.verify_evidence(os.path.join(vdir, "anchor_wrong_digest.json"), require_anchor=True, tsa_cert=cert)
        self.assertFalse(r["valid"]); self.assertFalse(r["rfc3161"]["verified"])
        base = json.load(open(os.path.join(vdir, "valid_signed.json")))
        def der(tag, body):
            n = len(body); lb = bytes([n]) if n < 128 else bytes([0x82, n >> 8, n & 0xFF]); return bytes([tag]) + lb + body
        dg = bytes.fromhex(base["evidence_digest_sha256"])
        tst = der(0x30, der(0x02, b"\x01") + der(0x06, bytes.fromhex("2a03")) + der(0x30, der(0x30, der(0x06, bytes.fromhex("608648016503040201"))) + der(0x04, dg)) + der(0x02, b"\x01") + der(0x18, b"20260922100000Z"))
        eci = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010904")) + der(0xA0, der(0x04, tst))); sd = der(0x30, der(0x02, b"\x03") + der(0x31, b"") + eci + der(0x31, b""))
        resp = der(0x30, der(0x30, der(0x02, b"\x00")) + der(0x30, der(0x06, bytes.fromhex("2a864886f70d010702")) + der(0xA0, sd)))
        e = dict(base); e["rfc3161_timestamp"] = {"anchored": True, "tsa_url": "forged", "tsr_b64": base64.b64encode(resp).decode()}
        p = os.path.join(tempfile.mkdtemp(), "forged.json"); json.dump(e, open(p, "w"))
        r = ap2.verify_evidence(p, require_anchor=True); self.assertTrue(r["rfc3161"]["verified"]); self.assertTrue(r["valid"])       # binding only: passes (declared)
        r = ap2.verify_evidence(p, require_anchor=True, tsa_cert=cert); self.assertFalse(r["rfc3161"]["tsa_verified"]); self.assertFalse(r["valid"])

    def test_signed_payload_shapes_are_artifact_errors_in_the_reference(self):
        # review r2: the §3.1 profile inside the SD-JWT and the imposed shapes — each case is a fresh ES256-signed single-artifact
        # pack with the digest recomputed, built by the oracle's helper, so only the artifact layer decides; the same builder's
        # well-formed pack is the positive control (valid True). 1.1.0 r1 read the payload with json.loads (dup key last-wins,
        # BOM skipped), verified 31/33-byte JWK coordinates, raised TypeError on `_sd: null` and AttributeError on `cnf: null`.
        import tempfile, base64, hashlib
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")))
        sk, n = O._fresh_key(); H = '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}'; d = tempfile.mkdtemp()
        kb = ".".join(base64.urlsafe_b64encode(x).decode().rstrip("=") for x in (b'{"alg":"ES256","typ":"kb+jwt"}', b'{"sd_hash":"x"}', b"\x00" * 64))
        disc = base64.urlsafe_b64encode(b'["salt",[1],"v"]').decode().rstrip("="); dig = base64.urlsafe_b64encode(hashlib.sha256(disc.encode()).digest()).decode().rstrip("=")
        bad = {"dup": ('{"iss":"x","amount":"1","amount":"999"}', {"iss": "x", "amount": "999"}, {}), "bom": (b'\xef\xbb\xbf{"iss":"x"}', {"iss": "x"}, {}),
               "sd-null": ('{"iss":"x","_sd":null}', {"iss": "x"}, {}), "sd-object": ('{"iss":"x","_sd":{}}', {"iss": "x"}, {}), "sd-int": ('{"iss":"x","_sd":[1]}', {"iss": "x"}, {}),
               "sd_alg-null": ('{"iss":"x","_sd_alg":null}', {"iss": "x"}, {}), "dots-list": ('{"iss":"x","a":[{"...":[1]}]}', {"iss": "x", "a": []}, {}),
               "disc-name-list": ('{"iss":"x","_sd":["%s"]}' % dig, {"iss": "x"}, {"disclosures": [disc]}),
               "cnf-null": ('{"iss":"x","cnf":null}', {"iss": "x", "cnf": None}, {"kb": kb}), "cnf-string": ('{"iss":"x","cnf":"k"}', {"iss": "x", "cnf": "k"}, {"kb": kb}),
               "cnf-jwk-empty": ('{"iss":"x","cnf":{"jwk":{}}}', {"iss": "x", "cnf": {"jwk": {}}}, {"kb": kb}),
               "jwk-x-33": ('{"iss":"x"}', {"iss": "x"}, {"jwk_x_bytes": n.x.to_bytes(33, "big")})}
        for name, (payload, resolved, kw) in bad.items():
            p = os.path.join(d, name + ".json"); json.dump(O._fresh_pack(base, sk, n, H, payload, resolved, **kw), open(p, "w"))
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], name); self.assertTrue(r["digest_ok"], name); self.assertIn("error", r["artifacts"][0], name)
        p = os.path.join(d, "ok.json"); json.dump(O._fresh_pack(base, sk, n, H, '{"iss":"x","_sd":[],"_sd_alg":"sha-256"}', {"iss": "x"}), open(p, "w"))
        self.assertTrue(ap2.verify_evidence(p)["valid"])   # positive control of the builder
        # r4: strict base64url measured by the unit suite too (the ablation of that layer alone left the suite green): the same
        # signature segment padded, with a space, with '+' — a lenient decoder verifies it, the profile refuses it
        ok = O._fresh_pack(base, sk, n, H, '{"iss":"x"}', {"iss": "x"}); c = ok["artifacts"][0]["sd_jwt_compact"]; jwt, rest = c.split("~", 1); h_, p_, s_ = jwt.split(".")
        for nm, sig in (("padded", s_ + "=="), ("space", s_[:10] + " " + s_[10:]), ("plus", s_.replace("-", "+", 1) if "-" in s_ else s_[:-1] + "+")):
            e = json.loads(json.dumps(ok)); e["artifacts"][0]["sd_jwt_compact"] = ".".join([h_, p_, sig]) + "~" + rest; p = os.path.join(d, "b64" + nm + ".json"); json.dump(O.rehash(e), open(p, "w"))
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], nm); self.assertIn("error", r["artifacts"][0], nm)
        # top-level shapes of r2: anchored must be a boolean (refusal), provenance_class a string (artifact error), sig_alg a string (FAIL entry)
        e = dict(base); e["rfc3161_timestamp"] = {"anchored": []}; p = os.path.join(d, "anch.json"); json.dump(e, open(p, "w"))
        r = ap2.verify_evidence(p); self.assertFalse(r["valid"]); self.assertIn("anchored", r["refused"])
        e = json.loads(json.dumps(base)); e["artifacts"][0]["key"]["provenance_class"] = ["x"]; p = os.path.join(d, "prov.json"); json.dump(O.rehash(e), open(p, "w"))
        r = ap2.verify_evidence(p); self.assertFalse(r["valid"]); self.assertIn("provenance_class", r["artifacts"][0]["error"])
        e = json.loads(json.dumps(base)); e["producer_signatures"]["signatures"].append({"sig_alg": ["ed25519"], "public_key_b64": "AA==", "signature_b64": "AA=="}); p = os.path.join(d, "alg.json"); json.dump(e, open(p, "w"))
        r = ap2.verify_evidence(p, trusted_producer_keys={"ed25519": [base["producer_signatures"]["signatures"][0]["public_key_b64"]]})
        self.assertFalse(r["valid"]); self.assertEqual(r["producer_signatures"]["signatures"][-1]["status"], "FAIL")

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier is not measured")
    def test_js_verifier_is_conformant_on_all_normative_fields(self):
        # the JS verifier through the SAME conformance runner as the reference: every normative field of every vector
        import subprocess, run_ap2_conformance as rc
        probe = subprocess.run(["node", "-e", "const{createPublicKey}=require('node:crypto');try{createPublicKey({key:Buffer.concat([Buffer.from('308207b2300b0609608648016503040312038207a100','hex'),Buffer.alloc(1952)]),format:'der',type:'spki'});console.log('yes')}catch{console.log('no')}"], capture_output=True, text=True)
        if probe.stdout.strip() != "yes":   # r2: on a Node build without ML-DSA-65 (OpenSSL < 3.5) the ML-DSA vectors are SKIP in the JS verifier, so 8/8 is NOT measured — skip, never a pass
            self.skipTest("Node build without ML-DSA-65 (OpenSSL < 3.5): JS conformance on the ML-DSA vectors not measured here")
        def js_verify(path, trusted_producer_keys=None, require_pq=False, require_producer=False, require_anchor=False, min_anchors=None,
                      trust_set_complete=False):   # no **_: an option nobody passes on is an error, not silence (1.5.0)
            flags = ["--trust-set-complete"] if trust_set_complete else []
            for alg, keys in (trusted_producer_keys or {}).items():
                for k in ([keys] if isinstance(keys, str) else keys): flags += ["--trusted-producer-key", f"{alg}={k}"]
            for flag, on in (("--require-producer", require_producer), ("--require-pq", require_pq), ("--require-anchor", require_anchor)):
                if on: flags.append(flag)
            if min_anchors is not None:
                flags += ["--min-anchors", str(min_anchors)]
            out = subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), path] + flags, capture_output=True, text=True)
            return json.loads(out.stdout)
        r = rc.run(verify_fn=js_verify, backends={"ml-dsa-65": True}, tools={"openssl": False})   # the probe above: this Node checks ML-DSA-65; it calls no openssl
        self.assertTrue(r["conformant"], r)
        self.assertEqual(len(r["results"]), 42)   # 1.5.0: + 9 anchors vectors; 1.5.4: + 3 producer-block vectors; 1.6.0: + 13 states vectors
        needs_openssl = sorted(n[:-len(".expected.json")] for n in os.listdir(os.path.join(_HERE, "spec", "vectors", "ap2")) if n.endswith(".expected.json")
                               and "openssl" in json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", n), encoding="utf-8")).get("requires", []))
        self.assertEqual(sorted(x["vector"] for x in r["results"] if x["status"] == "SKIP"), needs_openssl)   # SKIP = exactly the openssl vectors (1.6.0)
        self.assertEqual([x for x in r["results"] if x["status"] not in ("PASS", "SKIP")], [])



class TestExpectedFilesAndBackend(unittest.TestCase):
    """1.5.4 — SPEC §7: `requires_backend` is the MEASURED dependence of each vector on an ML-DSA-65 backend, a verifier
    without the backend counts those vectors SKIP (not FAIL, never PASS), and the expected files are a closed format."""
    VDIR = os.path.join(_HERE, "spec", "vectors", "ap2")

    def _copy(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        for f in os.listdir(self.VDIR):
            if f.endswith(".json") or f.endswith(".crt"):
                shutil.copy(os.path.join(self.VDIR, f), d)
        return d

    def test_requires_backend_is_the_measured_dependence(self):
        import run_ap2_conformance as rc
        import make_vectors_154 as mv
        if not ap2._sigsuite.MLDSA_AVAILABLE:
            self.skipTest("no ML-DSA-65 backend here: the dependence cannot be measured")
        declared = sorted(json.load(open(p, encoding="utf-8"))["vector"] for p in glob.glob(os.path.join(self.VDIR, "*.expected.json"))
                          if "requires_backend" in json.load(open(p, encoding="utf-8")))
        self.assertEqual(declared, mv.measured_backend_dependence())
        self.assertEqual(len(declared), 21, declared)   # 1.6.0: 21 (the states block also depends on the backend)
        self.assertTrue(ap2._sigsuite.MLDSA_AVAILABLE)   # the measurement restored the backend

    def test_without_the_backend_the_marked_vectors_are_skip_and_the_rest_pass(self):
        import run_ap2_conformance as rc
        saved = ap2._sigsuite.MLDSA_AVAILABLE
        ap2._sigsuite.MLDSA_AVAILABLE = False
        try:
            r = rc.run()
            st = {x["vector"]: x["status"] for x in r["results"]}
            self.assertTrue(r["conformant"], r)
            self.assertEqual(sum(v == "SKIP" for v in st.values()), 21, st)
            self.assertEqual(sum(v == "PASS" for v in st.values()), 21, st)
            # the bench can fail: the same run with one marker removed reports that vector FAIL, not SKIP
            d = self._copy(); p = os.path.join(d, "valid_signed.expected.json")
            e = json.load(open(p, encoding="utf-8")); del e["requires_backend"]; json.dump(e, open(p, "w", encoding="utf-8"))
            r2 = rc.run(vector_dir=d)
            self.assertFalse(r2["conformant"])
            self.assertEqual([x["vector"] for x in r2["results"] if x["status"] == "FAIL"], ["valid_signed"])
        finally:
            ap2._sigsuite.MLDSA_AVAILABLE = saved

    def test_expected_files_are_closed(self):
        import run_ap2_conformance as rc
        d = self._copy()
        self.assertTrue(rc.run(vector_dir=d)["conformant"])   # positive control: the unchanged copy passes
        p = os.path.join(d, "digest_mismatch.expected.json"); orig = json.load(open(p, encoding="utf-8"))
        for mut in (lambda e: e.__setitem__("requires_mldsa", True), lambda e: e.__setitem__("requires_backend", ["ml-dsa-87"]),
                    lambda e: e.__setitem__("requires_backend", []), lambda e: e.__setitem__("requires_backend", "ml-dsa-65"),
                    lambda e: e["policy"].__setitem__("require_pqc", True), lambda e: e["normative"].__setitem__("mldsa_backend", True),
                    lambda e: e["normative"].pop("anchors_verified"), lambda e: e.__setitem__("report", {"refusal": "x"}),
                    lambda e: e.__setitem__("vector", "another"), lambda e: e.__setitem__("requires", ["openssl", "openssl"])):
            e = json.loads(json.dumps(orig)); mut(e); json.dump(e, open(p, "w", encoding="utf-8"))
            with self.assertRaises(rc.VectorSetError):
                rc.run(vector_dir=d)
        json.dump(orig, open(p, "w", encoding="utf-8"))
        self.assertTrue(rc.run(vector_dir=d)["conformant"])

    def test_broken_vector_set_is_exit_2_not_a_fail(self):
        # NEMESIS 1.5.4: a broken expected file was a traceback (exit 1, read as "not conformant"), a repeated key kept its
        # last value in silence, a policy "false" string was require_pq true, a missing pack was the verifier's FAIL
        import run_ap2_conformance as rc
        d = self._copy(); p = os.path.join(d, "digest_mismatch.expected.json"); raw = open(p, encoding="utf-8").read()
        pack = os.path.join(d, "digest_mismatch.json")
        self.assertTrue(rc.run(vector_dir=d)["conformant"])   # positive control
        def restore():
            if os.path.isdir(p) and not os.path.islink(p): os.rmdir(p)
            elif os.path.lexists(p): os.remove(p)
            open(p, "w", encoding="utf-8").write(raw)
        e = json.loads(raw)
        cases = {
            "truncated": lambda: open(p, "w").write(raw[:-5]),
            "not utf-8": lambda: open(p, "wb").write(raw.encode().replace(b'"description": "', b'"description": "\xff', 1)),
            "repeated key": lambda: open(p, "w").write(raw.rstrip()[:-1] + ', "requires_backend": ["ml-dsa-87"], "requires_backend": ["ml-dsa-65"]}'),
            "directory": lambda: (os.remove(p), os.mkdir(p)),
            "policy string": lambda: json.dump(dict(e, policy=dict(e["policy"], require_pq="false")), open(p, "w")),
            "min_anchors 0": lambda: json.dump(dict(e, policy=dict(e["policy"], min_anchors=0)), open(p, "w")),
            "min_anchors bool": lambda: json.dump(dict(e, policy=dict(e["policy"], min_anchors=True)), open(p, "w")),
            "pins not an object": lambda: json.dump(dict(e, policy=dict(e["policy"], trusted_producer_keys=5)), open(p, "w")),
        }
        if hasattr(os, "mkfifo"):
            cases["fifo"] = lambda: (os.remove(p), os.mkfifo(p))
        for what, mutate in cases.items():
            mutate()
            with self.assertRaises(rc.VectorSetError, msg=what):
                rc.run(vector_dir=d)
            restore()
        self.assertTrue(rc.run(vector_dir=d)["conformant"])
        os.rename(pack, pack + ".gone")
        with self.assertRaises(rc.VectorSetError):
            rc.run(vector_dir=d)
        os.rename(pack + ".gone", pack); shutil.copy(pack, os.path.join(d, "zz_orphan.json"))
        with self.assertRaises(rc.VectorSetError):
            rc.run(vector_dir=d)
        os.remove(os.path.join(d, "zz_orphan.json"))
        self.assertTrue(rc.run(vector_dir=d)["conformant"])
        self.assertEqual(subprocess.run([sys.executable, os.path.join(self.VDIR, "run_ap2_conformance.py")],
                                        capture_output=True, text=True).returncode, 0)


class TestNotOkBlockStatesNothing(unittest.TestCase):
    """NEMESIS 1.5.4 — SPEC §5: every way a producer block can be not ok, not only a failing entry: a `scheme` that does
    not match its entries, a SKIP entry, no entry. The mutants `pq = pq and n_fail == 0 and n_skip == 0` (reference) and
    `pq && nFail === 0 && nSkip === 0` (JS) passed every other test and the oracle."""

    def _cases(self):
        vd = os.path.join(_HERE, "spec", "vectors", "ap2")
        base = json.load(open(os.path.join(vd, "valid_signed.json"), encoding="utf-8"))
        pins = json.load(open(os.path.join(vd, "valid_signed.expected.json"), encoding="utf-8"))["policy"]["trusted_producer_keys"]
        sigs = base["producer_signatures"]["signatures"]
        def with_block(**kw):   # the producer block is outside the digest (SPEC §3): nothing to re-seal
            e = json.loads(json.dumps(base)); e["producer_signatures"].update(kw); return e
        unknown = dict(sigs[0], sig_alg="ed448")
        return pins, {"scheme classical-only over a hybrid block": with_block(scheme="classical-only"),
                      "hybrid with the ML-DSA-65 entry alone": with_block(signatures=[s for s in sigs if s["sig_alg"] == "ml-dsa-65"]),
                      "an entry of an unknown sig_alg (SKIP)": with_block(signatures=sigs + [unknown]),
                      "no entry": with_block(signatures=[])}

    def _check(self, verify):
        pins, cases = self._cases(); d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        for what, ev in cases.items():
            p = os.path.join(d, "x.json"); json.dump(ev, open(p, "w", encoding="utf-8"))
            for pin in (pins, None):
                r = verify(p, pin)
                prod = r["producer_signatures"]
                self.assertIs(prod["ok"], False, what); self.assertIs(r["valid"], False, what)
                self.assertIsNone(prod["trusted"], (what, pin is not None)); self.assertIs(r["pq_protected"], False, (what, pin is not None))
                self.assertIs(r["policy_ok"], False, what)   # require_pq is asked: never met by a block that is not ok

    def test_reference(self):
        if not ap2._sigsuite.MLDSA_AVAILABLE:
            self.skipTest("no ML-DSA-65 backend: the valid ML-DSA-65 entry these cases need cannot verify")
        self._check(lambda p, pin: ap2.verify_evidence(p, trusted_producer_keys=pin, require_pq=True))

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier is not measured")
    def test_js(self):
        probe = subprocess.run(["node", "-e", "const{createPublicKey}=require('node:crypto');try{createPublicKey({key:Buffer.concat([Buffer.from('308207b2300b0609608648016503040312038207a100','hex'),Buffer.alloc(1952)]),format:'der',type:'spki'});console.log('yes')}catch{console.log('no')}"], capture_output=True, text=True)
        if probe.stdout.strip() != "yes":
            self.skipTest("Node build without ML-DSA-65: not measured here")
        js = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
        def verify(p, pin):
            flags = ["--require-pq"]
            for alg, keys in (pin or {}).items():
                for k in keys: flags += ["--trusted-producer-key", f"{alg}={k}"]
            return json.loads(subprocess.run(["node", js, p] + flags, capture_output=True, text=True).stdout)
        self._check(verify)


class TestSignatureEntryNamesTheKey(unittest.TestCase):
    """SPEC §9 / CHANGELOG 1.4.0: a key nobody defined is never silent — a FAIL entry names it, identically in both verifiers."""

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS note is not measured")
    def test_fail_entry_note_names_unknown_and_missing_keys(self):
        import subprocess
        with open(os.path.join(_HERE, "spec", "vectors", "ap2", "anchor_valid.json"), encoding="utf-8") as f:
            ev = json.load(f)
        e0 = ev["producer_signatures"]["signatures"][0]
        e0.update({"zz_extra": 1, "1": 2, "\U0001F600k": 3, "\uFFFDk": 4, "zz": 5})   # integer-like key, non-BMP vs BMP order, a prefix after its extension
        del e0["signature_b64"]
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(ev, f, ensure_ascii=False)
            py = ap2.verify_evidence(path)
            js = json.loads(subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), path],
                                           capture_output=True, text=True).stdout)
        finally:
            shutil.rmtree(d)
        # 1.6.0 — SPEC §9.1/§6.9 (not additive): an unknown key in an entry is a refusal of class unknown_member naming the
        # first unknown key by code point (1.4.1–1.5.4: a FAIL entry whose note named them all)
        want = 'producer_signatures.signatures[0]: unknown key "1" (SPEC §9.1)'
        for r in (py, js):
            self.assertFalse(r["valid"])
            self.assertEqual((r["admission"], r["refusal_class"], r["refused"], r["states"]), ("refused", "unknown_member", want, None))

    def _both(self, ev):
        import subprocess
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(ev, f, ensure_ascii=False)
            py = ap2.verify_evidence(path)
            js = json.loads(subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), path],
                                           capture_output=True, text=True).stdout)
        finally:
            shutil.rmtree(d)
        return py, js

    def _anchor_valid(self):
        with open(os.path.join(_HERE, "spec", "vectors", "ap2", "anchor_valid.json"), encoding="utf-8") as f:
            return json.load(f)

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS refusal is not measured")
    def test_closed_object_names_the_same_first_key_in_both(self):
        """1.4.1: with several unknown keys the refusal names the first by code point in both verifiers (1.4.0: Python named
        the first in file order, JS the first of Object.keys, which puts array-index keys such as "1" first). Each case is
        chosen so that file order, Object.keys order, UTF-16 order and code-point order do not all pick the same key."""
        cases = [({"zz": 1, "\U0001F600k": 2, "\uFFFDk": 3, "1": 4}, "1"),       # file order: "zz"
                 ({"zz": 1, "1": 2, "!x": 3}, "!x"),                               # Object.keys: "1"; file order: "zz"
                 ({"\U0001F600k": 1, "\uFFFDk": 2}, "\uFFFDk")]                   # file order and UTF-16 order: the emoji
        for extra, first in cases:
            ev = self._anchor_valid()
            ev["rfc3161_timestamp"].update(extra)
            py, js = self._both(ev)
            want = "rfc3161_timestamp: unknown key " + json.dumps(first, ensure_ascii=False) + " (SPEC §9.1)"
            for r in (py, js):
                self.assertFalse(r["valid"])
                self.assertEqual(r["refused"], want, extra)

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS note is not measured")
    def test_fail_entry_note_lists_several_missing_keys_by_code_point(self):
        """1.4.1: the missing keys are sorted by code point (not the set's iteration order, which follows PYTHONHASHSEED,
        nor the JS insertion order), with the same separators in both verifiers."""
        ev = self._anchor_valid()
        e1 = ev["producer_signatures"]["signatures"][1]
        for k in ("public_key_b64", "signature_b64", "post_quantum"):
            del e1[k]
        py, js = self._both(ev)
        want = 'entry is not the closed shape of SPEC §9.1; missing ["post_quantum","public_key_b64","signature_b64"]'
        for r in (py, js):
            self.assertEqual(r["producer_signatures"]["signatures"][1]["status"], "FAIL")
            self.assertEqual(r["producer_signatures"]["signatures"][1]["note"], want)
        import subprocess
        code = ("import sys; sys.path.insert(0, %r); import sigsuite; "
                "print(sigsuite._entry_shape_note({'sig_alg': 'ed25519'}))") % os.path.join(_HERE, "pqcrypto")
        for seed in ("0", "1", "2", "3", "4", "5"):
            out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                                 env=dict(os.environ, PYTHONHASHSEED=seed)).stdout.strip()
            self.assertEqual(out, want, "PYTHONHASHSEED=" + seed)

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS note is not measured")
    def test_fail_entry_without_string_sig_alg_names_the_keys(self):
        """1.4.1: an entry whose sig_alg is absent or not a string is a FAIL entry that names its unknown and missing keys
        too (in 1.4.0 it carried no note at all, in both verifiers)."""
        for mutate in (lambda e: (e.pop("sig_alg"), e.update({"x_unknown": 1})), lambda e: e.update({"sig_alg": 5, "x_unknown": 1})):
            ev = self._anchor_valid()   # 1.6.0: with an unknown key the entry is a refusal (unknown_member), whatever else it lacks
            mutate(ev["producer_signatures"]["signatures"][0])
            for r in self._both(ev):
                self.assertEqual((r["refusal_class"], r["refused"]), ("unknown_member", 'producer_signatures.signatures[0]: unknown key "x_unknown" (SPEC §9.1)'))
        for mutate, want in (
                (lambda e: e.pop("sig_alg"), 'entry is not the closed shape of SPEC §9.1; missing ["sig_alg"]'),
                (lambda e: e.update({"sig_alg": 5}), 'entry is not the closed shape of SPEC §9.1')):
            ev = self._anchor_valid()
            mutate(ev["producer_signatures"]["signatures"][0])
            py, js = self._both(ev)
            for r in (py, js):
                self.assertFalse(r["valid"])
                s0 = r["producer_signatures"]["signatures"][0]
                self.assertEqual((s0["status"], s0["sig_alg"], s0.get("note")), ("FAIL", None, want))
        for not_an_object in (5, "ed25519", [], None):   # an entry that is not an object has no keys to name: no note, in both
            ev = self._anchor_valid()
            ev["producer_signatures"]["signatures"][0] = not_an_object
            py, js = self._both(ev)
            for r in (py, js):
                self.assertEqual(r["producer_signatures"]["signatures"][0], {"sig_alg": None, "status": "FAIL", "post_quantum": False,
                                                                              "key_trusted": None}, not_an_object)


def load_tests(loader, tests, pattern):
    # pull the out-of-glob suites into this CI-visible file
    for mod in ("test_acvp_mldsa65", "test_pqsig"):
        tests.addTests(loader.loadTestsFromModule(importlib.import_module(mod)))
    return tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
