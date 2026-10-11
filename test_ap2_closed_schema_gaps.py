#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Closed schema (SPEC §9.1) — the cases the generative bench does not derive (review of 2026-10-11).

verifiers/schema_mutants.py adds unknown keys, hostile types and deletions, but never ADDS a listed optional key with a
valid value, never flips `kb_jwt.present`, never puts a non-string inside a list of strings, never edits a recorded KB value,
and never compares the ORDER of the §9.2 report on names outside the Basic Multilingual Plane. Mutation on 1.4.0 showed the
consequence: dropping the 1.0–1.3 spelling `tsa` (in either verifier), dropping `jwks_url`, removing the `present` check,
loosening `x5c_chain_sha256` to any list, or sorting the report by UTF-16 code unit in JS left every test green. Each case
here runs in BOTH verifiers (the JS one when node is present) and compares them; every case also has its must-pass twin.
Temporary directories are removed at the end.
"""
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
sys.path.insert(0, os.path.join(_HERE, "verifiers"))
import ap2_evidence as ap2  # noqa: E402
import schema_mutants as M  # noqa: E402

JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
HAVE_NODE = shutil.which("node") is not None
VDIR = os.path.join(_HERE, "spec", "vectors", "ap2")


class TestClosedSchemaGaps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2-gaps-")
        with open(os.path.join(VDIR, "valid_signed.json"), encoding="utf-8") as f:
            cls.base = M.strip(json.load(f))           # sealed content only, resealed: no producer, no anchor
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _both(self, ev):
        self.__class__.n += 1
        p = os.path.join(self.d, f"c{self.n}.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write(ev if isinstance(ev, str) else json.dumps(ev, ensure_ascii=False))
        py = ap2.verify_evidence(p)
        js = None
        if HAVE_NODE:
            out = subprocess.run(["node", JS, p], capture_output=True, text=True, timeout=120)
            js = json.loads(out.stdout)
            self.assertEqual(M.norm(py), M.norm(js), "the two verifiers disagree")
        return py, js

    def test_every_listed_optional_key_with_a_valid_value_changes_nothing(self):
        ref, _ = self._both(self.base)
        self.assertTrue(ref["valid"], ref)
        cases = [("rfc3161_timestamp", {"anchored": False, "tsa": "https://tsa.example.invalid", "note": "n"}),       # 1.0–1.3 spelling
                 ("rfc3161_timestamp", {"anchored": False, "tsa_url": "https://tsa.example.invalid"}),
                 ("rfc3161_timestamp", {"anchored": False, "tsr_b64": "AA=="})]                                      # not anchored: not read
        for top, val in cases:
            with self.subTest(top=top, val=val):
                ev = copy.deepcopy(self.base); ev[top] = val
                r, _ = self._both(ev)
                self.assertEqual(M.norm(r), M.norm(ref))
        for k, v in (("note", "n"), ("x5c_chain_sha256", ["00" * 32]), ("jwks_url", "https://example.invalid/jwks"),
                     ("jwks_sha256", "00" * 32), ("fetched_utc", "2026-10-11T00:00:00Z")):
            with self.subTest(key=k):
                ev = copy.deepcopy(self.base); ev["artifacts"][0]["key"][k] = v
                r, _ = self._both(M.rehash(ev))
                self.assertTrue(r["valid"], r)
                self.assertNotIn("error", r["artifacts"][0])

    def test_a_list_of_strings_with_a_non_string_is_an_artifact_error(self):
        for bad in ([1], ["ab", None], [[]]):
            with self.subTest(bad=bad):
                ev = copy.deepcopy(self.base); ev["artifacts"][0]["key"]["x5c_chain_sha256"] = bad
                r, _ = self._both(M.rehash(ev))
                self.assertFalse(r["valid"])
                self.assertIn("x5c_chain_sha256", r["artifacts"][0].get("error", ""))

    def test_kb_jwt_present_must_match_the_compact_serialization(self):
        ev = copy.deepcopy(self.base)
        self.assertFalse(ev["artifacts"][0]["kb_jwt"]["present"])
        ev["artifacts"][0]["kb_jwt"]["present"] = True
        r, _ = self._both(M.rehash(ev))
        self.assertFalse(r["valid"])
        self.assertIn("kb_jwt.present", r["artifacts"][0].get("error", ""))

    def _built_kb_pack(self, with_cnf=True):
        F = M.Fresh("x")
        H = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": F.jwk}
        P = {"iss": "w", "mandate_type": "intent", **({"cnf": {"jwk": F.hjwk}} if with_cnf else {})}
        iss = F.sign(F.sk, json.dumps(H, separators=(",", ":")).encode(), json.dumps(P, separators=(",", ":")).encode()) + "~"
        out = os.path.join(self.d, f"built{self.n}{int(with_cnf)}.json")
        ap2.build_evidence([{"name": "intent", "sd_jwt": iss + F.kb(iss)}], out)
        with open(out, encoding="utf-8") as f:
            return json.load(f)

    def test_recorded_kb_values_must_equal_the_recomputation(self):
        for with_cnf in (True, False):
            built = self._built_kb_pack(with_cnf)
            r, _ = self._both(built)                      # the builder's own record: must pass (must-pass twin)
            self.assertTrue(r["valid"], r)
            kb = built["artifacts"][0]["kb_jwt"]
            edits = [("claims_recorded_not_validated", dict(kb.get("claims_recorded_not_validated", {}), x_unknown=1)),
                     ("claims_recorded_not_validated", dict(kb.get("claims_recorded_not_validated", {}), aud="someone else")),
                     ("verified", True if kb.get("verified") is not True else False),
                     ("signature_ok", not kb.get("signature_ok", False)), ("sd_hash_ok", not kb.get("sd_hash_ok", False))]
            for k, v in edits:
                with self.subTest(with_cnf=with_cnf, key=k, value=v):
                    ev = copy.deepcopy(built); ev["artifacts"][0]["kb_jwt"][k] = v
                    r, _ = self._both(M.rehash(ev))
                    self.assertFalse(r["valid"], r)
                    self.assertIn("kb_jwt." + k, r["artifacts"][0].get("error", ""))

    def test_the_report_is_sorted_by_code_point(self):
        F = M.Fresh(self.base["honest_scope"])
        H = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": F.jwk, "\U0001F600x": "a", "！x": "b", "zz": "c"}
        P = {"iss": "w", "mandate_type": "intent"}
        r, js = self._both(F.pack(H, P))
        want = ["zz", "！x", "\U0001F600x"]          # U+007A < U+FF01 < U+1F600 (UTF-16 code units would put the emoji second)
        self.assertEqual(r["artifacts"][0]["ignored"]["header"], want)
        if js is not None:
            self.assertEqual(js["artifacts"][0]["ignored"]["header"], want)


if __name__ == "__main__":
    unittest.main(verbosity=1)
