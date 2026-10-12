#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The JS verifier's receipt reaches a PIPE whole (1.5.1).

process.exit() right after console.log to a pipe dropped every byte past 64 KiB: an evidence file with a
100 000-character unknown key gave 65 536 bytes of broken JSON on `| cat` (measured 2026-10-12 on 1.5.0).
The test reads the receipt through a real pipe (`node … | cat`), not through subprocess capture."""
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_BASE = os.path.join(_HERE, "spec", "vectors", "ap2", "anchors_unknown_key.json")


@unittest.skipUnless(shutil.which("node") and shutil.which("cat") and shutil.which("sh"), "node, cat and sh needed")
class TestJsReceiptThroughPipe(unittest.TestCase):
    def _receipt(self, extra_key_len):
        with open(_BASE, encoding="utf-8") as f:
            ev = json.load(f)
        ev["x" * extra_key_len] = 1
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            out = subprocess.run(["sh", "-c", "node %s %s | cat" % (shlex.quote(_JS), shlex.quote(p))],
                                 capture_output=True)
        return out.stdout

    def test_receipt_over_64_kib_is_whole(self):
        raw = self._receipt(100000)
        self.assertGreater(len(raw), 65536, len(raw))
        r = json.loads(raw.decode("utf-8"))   # a cut receipt is not JSON
        self.assertIs(r["valid"], False)

    def test_small_receipt_unchanged(self):
        r = json.loads(self._receipt(10).decode("utf-8"))
        self.assertIs(r["valid"], False)


if __name__ == "__main__":
    unittest.main()
