#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.5.0 — SPEC §3.3 `anchors`: the builder side (`stamp` / add_anchor, `build --tsa` repeated) and the `--min-anchors`
grammar of both verifiers. The TSA is a real one run locally (openssl `ts -reply`, a throwaway self-signed timeStamping
certificate) put in place of the HTTP request; every file is a copy in a temporary directory, removed at the end."""
import base64
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

VDIR = os.path.join(_HERE, "spec", "vectors", "ap2")
HAVE_OPENSSL = shutil.which("openssl") is not None
HAVE_NODE = shutil.which("node") is not None
JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")


def _rb(p):
    with open(p, "rb") as f:
        return f.read()


def _rjson(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


class LocalTSA:
    def __init__(self, d, cn):
        self.d = d; self.key, self.crt = os.path.join(d, cn + ".key"), os.path.join(d, cn + ".crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", self.key,
                        "-out", self.crt, "-days", "30", "-subj", "/CN=" + cn, "-addext", "extendedKeyUsage=critical,timeStamping",
                        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature"], check=True, capture_output=True)
        self.serial = os.path.join(d, cn + ".serial")
        with open(self.serial, "w") as f:
            f.write("01\n")
        self.cnf = os.path.join(d, cn + ".cnf")
        with open(self.cnf, "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t\n[ t ]\nserial = {self.serial}\ncrypto_device = builtin\nsigner_cert = {self.crt}\n"
                    f"signer_key = {self.key}\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\nordering = no\n"
                    f"tsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n")

    def stamp(self, digest_hex, tsa_url, timeout=20):
        """Stands in for ap2._rfc3161_stamp: the same return shape, a real token from this TSA."""
        q, r = os.path.join(self.d, "q.tsq"), os.path.join(self.d, "r.tsr")
        subprocess.run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q], check=True, capture_output=True)
        subprocess.run(["openssl", "ts", "-reply", "-config", self.cnf, "-queryfile", q, "-out", r], check=True, capture_output=True)
        with open(r, "rb") as f:
            return {"anchored": True, "tsa_url": tsa_url, "tsr_b64": base64.b64encode(f.read()).decode()}


@unittest.skipUnless(HAVE_OPENSSL, "openssl absent: the local TSA cannot run")
class TestStamp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-anchors-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.tsa = LocalTSA(self.d, "tsaA"); self.tsb = LocalTSA(self.d, "tsaB")
        self.pack = os.path.join(self.d, "p.json"); shutil.copy(os.path.join(VDIR, "valid_signed.json"), self.pack)
        self._orig = ap2._rfc3161_stamp
        self.addCleanup(setattr, ap2, "_rfc3161_stamp", self._orig)
        self.by_url = {"https://a.example": self.tsa, "https://b.example": self.tsb}
        ap2._rfc3161_stamp = lambda digest, url, timeout=20: self.by_url[url].stamp(digest, url) if url in self.by_url else {"anchored": False, "note": "unreachable"}

    def _bundle(self):
        p = os.path.join(self.d, "bundle.pem")
        with open(p, "wb") as f:
            for t in (self.tsa, self.tsb):
                f.write(_rb(t.crt))
        return p

    def test_stamp_adds_an_anchor_and_leaves_the_sealed_content_and_the_signatures_alone(self):
        before = _rjson(self.pack)
        out = ap2.add_anchor(self.pack, "https://a.example")
        after = _rjson(self.pack)
        self.assertEqual(out["anchors"], 1)
        for k in before:
            self.assertEqual(after[k], before[k], k)          # nothing but `anchors` moved: digest, producer block, content
        self.assertEqual(set(after) - set(before), {"anchors"})
        r = ap2.verify_evidence(self.pack, require_anchor=True)
        self.assertTrue(r["valid"]); self.assertEqual(r["anchors_verified"], 1)
        self.assertEqual([a["verified"] for a in r["anchors"]], [True])

    def test_two_tsas_count_two_and_a_bundle_verifies_both(self):
        ap2.add_anchor(self.pack, "https://a.example"); ap2.add_anchor(self.pack, "https://b.example")
        r = ap2.verify_evidence(self.pack, min_anchors=2)
        self.assertTrue(r["valid"] and r["policy_ok"]); self.assertEqual(r["anchors_verified"], 2)
        r = ap2.verify_evidence(self.pack, min_anchors=2, tsa_cert=self._bundle())
        self.assertTrue(r["policy_ok"]); self.assertEqual([a["tsa_verified"] for a in r["anchors"]], [True, True])
        r = ap2.verify_evidence(self.pack, min_anchors=2, tsa_cert=self.tsa.crt)     # only A's certificate: B does not count
        self.assertFalse(r["policy_ok"]); self.assertEqual(r["anchors_verified"], 1)

    def test_two_tokens_of_one_tsa_count_two_as_declared(self):
        """SPEC §3.3 declares it: distinct tokens of the SAME TSA are two anchors (they share its key). Pinned so a change
        of that rule is a visible decision, not a drift."""
        ap2.add_anchor(self.pack, "https://a.example"); ap2.add_anchor(self.pack, "https://a.example")
        self.assertEqual(ap2.verify_evidence(self.pack, min_anchors=2)["anchors_verified"], 2)

    def test_stamp_refuses_a_pack_whose_content_does_not_match_its_digest_and_leaves_it_unchanged(self):
        ev = _rjson(self.pack); ev["subject"] = "altered after sealing"
        with open(self.pack, "w") as f:
            json.dump(ev, f)
        raw = _rb(self.pack)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.add_anchor(self.pack, "https://a.example")
        self.assertEqual(_rb(self.pack), raw)

    def test_a_tsa_that_gives_no_token_writes_nothing(self):
        raw = _rb(self.pack)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.add_anchor(self.pack, "https://down.example")
        self.assertEqual(_rb(self.pack), raw)
        self.assertFalse(os.path.exists(self.pack + ".tmp-stamp"))

    def test_build_with_three_tsas_first_in_the_block_others_in_anchors_failures_reported_not_written(self):
        sk_pack = _rjson(os.path.join(VDIR, "valid_signed.json"))
        arts = [{"name": a["name"], "sd_jwt": a["sd_jwt_compact"]} for a in sk_pack["artifacts"]]
        out = os.path.join(self.d, "b.json")
        res = ap2.build_evidence(arts, out, tsa_url="https://a.example", extra_tsa_urls=["https://b.example", "https://down.example"])
        ev = _rjson(out)
        self.assertTrue(ev["rfc3161_timestamp"]["anchored"]); self.assertEqual(len(ev["anchors"]), 1)
        self.assertEqual(res["anchors_added"], 1); self.assertEqual([f["tsa_url"] for f in res["anchors_failed"]], ["https://down.example"])
        self.assertEqual(ap2.verify_evidence(out, min_anchors=2)["anchors_verified"], 2)

    def test_build_with_one_tsa_writes_no_anchors_key(self):
        """A pack built with one TSA stays readable by 1.4.x verifiers: no `anchors` key at all."""
        sk_pack = _rjson(os.path.join(VDIR, "valid_signed.json"))
        arts = [{"name": a["name"], "sd_jwt": a["sd_jwt_compact"]} for a in sk_pack["artifacts"]]
        out = os.path.join(self.d, "one.json")
        ap2.build_evidence(arts, out, tsa_url="https://a.example")
        self.assertNotIn("anchors", _rjson(out))


class TestMinAnchorsGrammar(unittest.TestCase):
    """--min-anchors: ASCII digits, >= 1, at most six digits — the same usage error (exit 2, no verdict) in both verifiers."""
    BAD = ["0", "-1", "01", "1.0", "", "x", "１", "١", "1234567", "2 "]

    def _py(self, *args):
        return subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "verify", os.path.join(VDIR, "anchor_valid.json"), *args],
                              capture_output=True, text=True)

    def _js(self, *args):
        return subprocess.run(["node", JS, os.path.join(VDIR, "anchor_valid.json"), *args], capture_output=True, text=True)

    def test_bad_values_are_usage_errors(self):
        for v in self.BAD:
            for run in (self._py,) + ((self._js,) if HAVE_NODE else ()):
                p = run("--min-anchors", v)
                self.assertEqual(p.returncode, 2, (run.__name__, v, p.stdout[:200], p.stderr[:200]))
                self.assertEqual(p.stdout.strip(), "", (run.__name__, v))

    def test_good_values_give_the_same_verdict(self):
        for v, want in (("1", True), ("2", False)):
            for run in (self._py,) + ((self._js,) if HAVE_NODE else ()):
                for form in (["--min-anchors", v], ["--min-anchors=" + v]):
                    p = run(*form)
                    r = json.loads(p.stdout)
                    self.assertEqual((r["policy_ok"], r["anchors_verified"]), (want, 1), (run.__name__, form))


if __name__ == "__main__":
    unittest.main(verbosity=2)
