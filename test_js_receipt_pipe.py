#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The JS verifier's receipt reaches a PIPE whole, with its exit code (1.5.1).

process.exit() right after console.log to a pipe dropped every byte past the pipe buffer (64 KiB on Linux): an evidence
file with a 100 000-character unknown key gave 65 536 bytes of broken JSON on `| cat`, and a VALID pack whose receipt
passed 64 KiB exited 0 with a cut receipt (measured 2026-10-12 on 1.5.0). The verifier writes into a real OS pipe whose
other end is `cat` (two processes joined by the kernel, not subprocess capture), and its own exit code is read from the
verifier process, not from the end of the pipe: 0 valid, 1 not valid, 2 usage with nothing on stdout."""
import hashlib
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

_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_VEC = os.path.join(_HERE, "spec", "vectors", "ap2")


def _through_pipe(args):
    """node <verifier> <args> | (sleep 0.5; cat) — returns (the verifier's exit code, what cat received, the verifier's stderr).
    The reader starts late on purpose: an exit deferred by one event-loop turn (setImmediate) still cut the receipt for a
    reader that was not already draining, and a reader that drains at once hid it (measured 2026-10-12)."""
    with tempfile.TemporaryFile() as err:
        node = subprocess.Popen(["node", _JS] + list(args), stdout=subprocess.PIPE, stderr=err)
        cat = subprocess.Popen(["sh", "-c", "sleep 0.5; exec cat"], stdin=node.stdout, stdout=subprocess.PIPE)
        node.stdout.close()   # cat holds the only read end: a real pipe between two processes
        out, _ = cat.communicate(timeout=120)
        rc = node.wait(timeout=120)
        err.seek(0)
        return rc, out, err.read()


@unittest.skipUnless(shutil.which("node") and shutil.which("cat") and shutil.which("sh") and shutil.which("sleep"), "node, sh, sleep and cat needed")
class TestJsReceiptThroughPipe(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _write(self, ev):
        p = os.path.join(self.d, "ev.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(ev, f)
        return p

    def _unknown_key(self, n):
        with open(os.path.join(_VEC, "anchors_unknown_key.json"), encoding="utf-8") as f:
            ev = json.load(f)
        ev["x" * n] = 1
        return self._write(ev)

    def _valid_with_copies(self, n):
        """valid_signed's two mandates, n renamed copies each, re-sealed: a VALID pack whose receipt grows with n."""
        with open(os.path.join(_VEC, "valid_signed.json"), encoding="utf-8") as f:
            ev = json.load(f)
        for k in ("producer_signatures", "rfc3161_timestamp", "anchors"):
            ev.pop(k, None)
        ev["artifacts"] = [dict(a, name="%s_%d" % (a["name"], i)) for i in range(n) for a in ev["artifacts"]]
        ev["bindings"] = ap2.find_bindings([{"name": a["name"], "compact": a["sd_jwt_compact"], "resolved_claims": a["resolved_claims"]}
                                            for a in ev["artifacts"]])
        ev["evidence_digest_sha256"] = hashlib.sha256(ap2._canon({k: v for k, v in ev.items() if k not in ap2._DIGEST_EXCLUDED})).hexdigest()
        return self._write(ev)

    def test_receipt_over_64_kib_is_whole_and_exits_1(self):
        rc, raw, _ = _through_pipe([self._unknown_key(100000)])
        self.assertGreater(len(raw), 65536, len(raw))
        r = json.loads(raw.decode("utf-8"))   # a cut receipt is not JSON
        self.assertIs(r["valid"], False)
        self.assertEqual(rc, 1)

    def test_valid_receipt_over_64_kib_is_whole_and_exits_0(self):
        rc, raw, _ = _through_pipe([self._valid_with_copies(200)])
        self.assertGreater(len(raw), 65536, len(raw))
        r = json.loads(raw.decode("utf-8"))
        self.assertIs(r["valid"], True)
        self.assertEqual(rc, 0)

    def test_small_receipts_and_exit_codes(self):
        rc, raw, _ = _through_pipe([self._unknown_key(10)])
        self.assertIs(json.loads(raw.decode("utf-8"))["valid"], False)
        self.assertEqual(rc, 1)
        rc, raw, _ = _through_pipe([os.path.join(_VEC, "valid_signed.json")])
        self.assertIs(json.loads(raw.decode("utf-8"))["valid"], True)
        self.assertEqual(rc, 0)

    def test_usage_is_exit_2_with_nothing_on_stdout(self):
        for args in ([], [os.path.join(_VEC, "valid_signed.json"), "--no-such"]):
            rc, raw, err = _through_pipe(args)
            self.assertEqual((rc, raw), (2, b""), args)
            self.assertIn(b"usage:", err)


if __name__ == "__main__":
    unittest.main()
