#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The closed schema (SPEC §9) under generative mutation — CI entry point of verifiers/schema_mutants.py.

Every object at every level of every conformance vector and of freshly signed packs is mutated (unknown keys, wrong
types, missing keys, duplicate keys, key order, escaped spellings, JOSE/JWT/JWK/cnf/KB-JWT extensions, crit, out-of-grammar
files); each mutation's expected class comes from the SPEC tables, and both verifiers must meet it and agree with each
other. The quick subset runs here (a few thousand mutations, seconds); `--full` is the release measurement.

The bench can fail: on the 1.3.0 verifiers the same corpus passes silently on every §9.1 unknown-key mutation (the
positive control, run by hand — one process loads one reference — and recorded in CHANGELOG 1.4.0). This file also keeps
a small built-in control: a reference copy whose top-level closure is removed must turn the quick bench red.

The corpus lives in a directory of its own under TMPDIR and is removed when the run ends, pass or fail.
"""
import os
import shutil
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "verifiers"))
import schema_mutants as M  # noqa: E402

HAVE_NODE = shutil.which("node") is not None


class TestClosedSchemaMutants(unittest.TestCase):
    def test_every_mutation_gets_its_spec_class_in_both_verifiers(self):
        res = M.run(quick=True, py_root=_HERE, js=os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs") if HAVE_NODE else None)
        self.assertGreater(res["mutations"], 1000, res)
        for cls in (M.REFUSE, M.ARTERR, M.SIGFAIL, M.REPORT, M.UNCHANGED, M.CLAIMS_MISMATCH):
            self.assertIn(cls, res["per_class"], "a class of the SPEC table was never exercised")
        self.assertEqual(res["unmet"]["py"], [], res["unmet"]["py"][:10])
        if HAVE_NODE:
            self.assertEqual(res["unmet"]["js"], [], res["unmet"]["js"][:10])
            self.assertEqual(res["disagreements"], 0, res)
        self.assertEqual(res["silent"], {"py": 0, "js": 0}, res["silent"])
        self.assertTrue(res["ok"], res)

    def test_bench_turns_red_on_a_reference_without_the_closure(self):
        # positive control, in-process: a copy of the reference with the top-level closure removed. The subprocess is the
        # only way to load a second ap2_evidence (one process, one reference — by design of the bench).
        import subprocess
        d = tempfile.mkdtemp(prefix="ap2-mutants-control-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copytree(_HERE, os.path.join(d, "ref"), ignore=shutil.ignore_patterns(".git", "__pycache__", "dist", "*.egg-info"))
        src = os.path.join(d, "ref", "ap2_evidence.py")
        with open(src, encoding="utf-8") as f:
            s = f.read()
        anchor = '        _check_closed(ev, "top level", _TOP_KEYS)\n'
        self.assertIn(anchor, s)
        with open(src, "w", encoding="utf-8") as f:
            f.write(s.replace(anchor, ""))
        code = ("import sys; sys.path.insert(0, %r); import schema_mutants as M; r = M.run(quick=True, py_root=%r, js=None); "
                "print(len(r['unmet']['py']), r['silent']['py'])") % (os.path.join(_HERE, "verifiers"), os.path.join(d, "ref"))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=600)
        self.assertEqual(out.returncode, 0, out.stderr[-800:])
        unmet, silent = map(int, out.stdout.split()[-2:])
        self.assertGreater(unmet, 0, "the sabotaged reference passed the bench: the bench cannot fail")
        self.assertGreater(silent, 0, "the sabotaged reference showed no silent acceptance: the silence counter cannot fail")

    def test_bench_turns_red_on_a_reference_without_the_160_refusal(self):
        """1.6.0 positive control: a copy of the reference WITHOUT the unknown-key refusal of artifacts[i] and signatures[i]
        (the 1.5.x behaviour: artifact error / FAIL entry) must leave mutations without their class."""
        import subprocess
        d = tempfile.mkdtemp(prefix="ap2-mutants-control160-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copytree(_HERE, os.path.join(d, "ref"), ignore=shutil.ignore_patterns(".git", "__pycache__", "dist", "*.egg-info"))
        src = os.path.join(d, "ref", "ap2_evidence.py")
        with open(src, encoding="utf-8") as f:
            s = f.read()
        anchors = ['            _check_unknown(a, f"artifacts[{i}]", _ARTIFACT_KEYS)\n',
                   '            _check_unknown(e, f"producer_signatures.signatures[{i}]", _sigsuite.ENTRY_KEYS)\n']
        for anchor in anchors:
            self.assertIn(anchor, s)
            s = s.replace(anchor, anchor.replace("_check_unknown(", "(lambda *_: None)("))
        with open(src, "w", encoding="utf-8") as f:
            f.write(s)
        code = ("import sys; sys.path.insert(0, %r); import schema_mutants as M; r = M.run(quick=True, py_root=%r, js=None); "
                "print(len(r['unmet']['py']), sum(1 for u in r['unmet']['py'] if '/artifacts[' in str(u) or '/signatures[' in str(u)))") % (
                    os.path.join(_HERE, "verifiers"), os.path.join(d, "ref"))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=600)
        self.assertEqual(out.returncode, 0, out.stderr[-800:])
        unmet, in_scope = map(int, out.stdout.split()[-2:])
        self.assertGreater(unmet, 0, "the 1.5.x behaviour passed the 1.6.0 bench: the bench cannot fail")
        self.assertEqual(unmet, in_scope, "only the artifact and signature-entry mutations may turn red")


if __name__ == "__main__":
    unittest.main(verbosity=2)
