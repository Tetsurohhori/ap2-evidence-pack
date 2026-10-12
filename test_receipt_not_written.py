#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""A receipt that was not written whole is exit 74 (EX_IOERR), never the verdict's 0/1 (1.5.2).

Measured on 1.5.1 (2026-10-12): with stdout on /dev/full or on a pipe whose reader had gone, `ap2_evidence.py` exited 120
("Exception ignored" from the interpreter's final flush, a code no contract names) for the vectors' receipts and 1 with a
traceback for a receipt larger than the stream buffer (a valid pack included), and with stdout closed (`>&-`) it exited
0 or 1 with nothing on stderr; the Node verifier exited 0 or 1 with nothing on stderr on /dev/full and on the closed pipe;
`build` into a path it cannot write raised a traceback (exit 1, the "not valid" code). Every case here runs the real CLI in
a child process with a real file descriptor: /dev/full (ENOSPC), a pipe whose read end is already closed (EPIPE), fd 1
closed before exec, and a regular file as the control (verdict code and receipt unchanged)."""
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

_PY = [sys.executable, os.path.join(_HERE, "ap2_evidence.py")]
_NODE = shutil.which("node")
_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_VEC = os.path.join(_HERE, "spec", "vectors", "ap2")
_VALID = os.path.join(_VEC, "anchor_valid.json")
_INVALID = os.path.join(_VEC, "digest_mismatch.json")
_OPENSSL = shutil.which("openssl")
_DEVFULL = os.path.exists("/dev/full")


def _run(cmd, mode, cwd=None, stderr_mode="capture"):
    """Run cmd with stdout in `mode`: "file" (a regular file), "devfull" (/dev/full), "pipe" (a pipe whose read end is
    closed before the child starts: EPIPE on the first write), "closed" (fd 1 closed before exec). Returns
    (exit code, bytes on stdout in "file" mode else None, stderr bytes)."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        stdout, pre, close_after = out, None, None
        if mode == "devfull":
            stdout = close_after = open("/dev/full", "wb")
        elif mode == "pipe":
            r, w = os.pipe()
            os.close(r)
            stdout = close_after = os.fdopen(w, "wb")
        elif mode == "closed":
            stdout, pre = None, (lambda: os.close(1))
        se = err
        if stderr_mode == "devfull":
            se = open("/dev/full", "wb")
        elif stderr_mode == "closed":   # fd 2 closed before exec
            se, pre0 = None, pre
            pre = (lambda: (pre0 and pre0(), os.close(2)))
        try:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=se, preexec_fn=pre, cwd=cwd, timeout=300)
        finally:
            if close_after is not None:
                close_after.close()
            if se is not err and se is not None:
                se.close()
        out.seek(0)
        err.seek(0)
        return p.returncode, (out.read() if mode == "file" else None), err.read()


@unittest.skipUnless(_DEVFULL and os.name == "posix", "/dev/full and POSIX file descriptors needed")
class TestPythonVerify(unittest.TestCase):
    def test_file_mode_is_the_control(self):   # verdict code and the receipt byte for byte, as before 1.5.2
        for path, code in ((_VALID, 0), (_INVALID, 1)):
            rc, out, err = _run(_PY + ["verify", path], "file")
            self.assertEqual(rc, code, err)
            self.assertEqual(out, (json.dumps(ap2.verify_evidence(path), indent=1) + "\n").encode("ascii"))
            self.assertEqual(err, b"")

    def test_lost_receipt_is_74_with_one_line_on_stderr(self):
        for mode, why in (("devfull", b"No space left on device"), ("pipe", b"Broken pipe"), ("closed", b"stdout is closed")):
            for path in (_VALID, _INVALID):
                with self.subTest(mode=mode, input=os.path.basename(path)):
                    rc, _, err = _run(_PY + ["verify", path], mode)
                    self.assertEqual(rc, 74, err)
                    self.assertTrue(err.startswith(b"receipt not written: "), err)
                    self.assertIn(why, err)
                    self.assertEqual(err.count(b"\n"), 1, err)   # one line, no "Exception ignored", no traceback

    def test_stderr_failing_too_is_still_74(self):
        for mode in ("devfull", "pipe", "closed"):
            for emode in ("devfull", "closed"):
                with self.subTest(mode=mode, stderr=emode):
                    rc, _, _ = _run(_PY + ["verify", _VALID], mode, stderr_mode=emode)
                    self.assertEqual(rc, 74)

    def test_receipt_over_64_kib_reaches_a_slow_reader_whole(self):   # the flush must not cut what a pipe delivers late
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(_VEC, "anchors_unknown_key.json"), encoding="utf-8") as f:
                ev = json.load(f)
            ev["x" * 100000] = 1
            p = os.path.join(d, "ev.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            prod = subprocess.Popen(_PY + ["verify", p], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            cat = subprocess.Popen(["sh", "-c", "sleep 0.5; exec cat"], stdin=prod.stdout, stdout=subprocess.PIPE)
            prod.stdout.close()
            raw, _ = cat.communicate(timeout=120)
            self.assertEqual(prod.wait(timeout=120), 1)
            self.assertGreater(len(raw), 65536)
            self.assertIs(json.loads(raw.decode("utf-8"))["valid"], False)
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(_NODE and _DEVFULL and os.name == "posix", "node, /dev/full and POSIX file descriptors needed")
class TestJsVerify(unittest.TestCase):
    def test_file_mode_is_the_control(self):
        for path, code in ((_VALID, 0), (_INVALID, 1)):
            rc, out, err = _run([_NODE, _JS, path], "file")
            self.assertEqual(rc, code, err)
            self.assertIs(json.loads(out.decode("utf-8"))["valid"], code == 0)
            self.assertEqual(out, subprocess.run([_NODE, _JS, path], capture_output=True).stdout)
            self.assertEqual(err, b"")

    def test_lost_receipt_is_74_with_one_line_on_stderr(self):
        for mode, why in (("devfull", b"ENOSPC"), ("pipe", b"EPIPE")):
            for path in (_VALID, _INVALID):
                with self.subTest(mode=mode, input=os.path.basename(path)):
                    rc, _, err = _run([_NODE, _JS, path], mode)
                    self.assertEqual(rc, 74, err)
                    self.assertEqual(err, b"receipt not written: " + why + b"\n")

    def test_stderr_failing_too_is_still_74(self):
        for mode in ("devfull", "pipe"):
            with self.subTest(mode=mode):
                rc, _, _ = _run([_NODE, _JS, _VALID], mode, stderr_mode="devfull")
                self.assertEqual(rc, 74)

    def test_usage_with_stderr_full_is_74_and_with_stderr_closed_is_2(self):
        # 1.5.2 review: console.error dropped ENOSPC and exited 2 (the Python CLI: 120 on 1.5.1). Closed stderr: Node
        # reopens fd 2 on /dev/null (the same limit as a closed stdout), so the usage exit 2 stays.
        for args in ([], ["--bogus", _VALID]):
            with self.subTest(args=args):
                self.assertEqual(_run_err([_NODE, _JS] + args, "full"), (74, b""))
                self.assertEqual(_run_err([_NODE, _JS] + args, "closed"), (2, b""))
                rc, out, err = _run([_NODE, _JS] + args, "file")
                self.assertEqual((rc, out), (2, b"")); self.assertTrue(err.startswith(b"usage: "), err)

    def test_closed_stdout_is_not_visible_to_node(self):
        # the README's stated limit: Node reopens a closed fd 1 on /dev/null, so the write succeeds and the exit is the
        # verdict's. If a Node release changes that, this test goes red and the README sentence has to change with it.
        for path, code in ((_VALID, 0), (_INVALID, 1)):
            rc, _, err = _run([_NODE, _JS, path], "closed")
            self.assertEqual((rc, err), (code, b""))


def _big_valid_pack(d):
    """valid_signed's two mandates copied 200 times under new names, re-sealed: a VALID pack whose receipt is ~84 KB."""
    import test_js_receipt_pipe as T
    cls = [c for c in vars(T).values() if isinstance(c, type) and issubclass(c, unittest.TestCase)][0]
    t = cls("test_valid_receipt_over_64_kib_is_whole_and_exits_0")
    t.setUp()
    try:
        p = os.path.join(d, "big_valid.json")
        shutil.copy(t._valid_with_copies(200), p)
        return p
    finally:
        t.tearDown()


@unittest.skipUnless(os.name == "posix", "RLIMIT_FSIZE needed")
class TestShortWriteToAFile(unittest.TestCase):
    """1.5.2 review: stdout on a regular file that stops growing (RLIMIT_FSIZE, as `ulimit -f 4`): Node wrote 4 096 bytes of
    the receipt and exited 0 (no error reported); it must be 74 with the reason, as the Python CLI (EFBIG, "File too large")."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_fsz_")
        cls.big = _big_valid_pack(cls.d)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _run_limited(self, cmd, limit):
        import resource
        import signal

        def pre():
            signal.signal(signal.SIGXFSZ, signal.SIG_DFL)   # as from a plain shell
            if limit is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, preexec_fn=pre, timeout=300)
            out.seek(0); err.seek(0)
            return p.returncode, out.read(), err.read()

    def _check(self, cmd, why):
        rc, out, err = self._run_limited(cmd, None)   # the control: the whole receipt, exit 0
        self.assertEqual((rc, err), (0, b""))
        self.assertIs(json.loads(out.decode("utf-8"))["valid"], True)
        self.assertGreater(len(out), 4096)
        rc, out, err = self._run_limited(cmd, 4096)
        self.assertEqual(rc, 74, err)
        self.assertLessEqual(len(out), 4096)
        self.assertTrue(err.startswith(b"receipt not written: ") and why in err and err.count(b"\n") == 1, err)

    def test_python(self):
        self._check(_PY + ["verify", self.big], b"File too large")

    @unittest.skipUnless(_NODE, "node needed")
    def test_js(self):
        self._check([_NODE, _JS, self.big], b"EFBIG")


class _Tsa:
    """A local RFC 3161 TSA (openssl ts -reply) behind a local HTTP server; "html" answers a 503 page instead."""

    CNF = ("[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {d}/serial\ncrypto_device = builtin\nsigner_cert = {d}/tsa.crt\n"
           "certs = {d}/ca.crt\nsigner_key = {d}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\n"
           "accuracy = secs:1\nordering = yes\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n"
           "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n")

    def __init__(self):
        self.d = d = tempfile.mkdtemp(prefix="tsa_")
        j = lambda n: os.path.join(d, n)  # noqa: E731
        with open(j("tsa.cnf"), "w") as f:
            f.write(self.CNF.format(d=d))
        with open(j("serial"), "w") as f:
            f.write("01\n")
        ssl = lambda *a: subprocess.run([_OPENSSL] + list(a), check=True, capture_output=True)  # noqa: E731
        ssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("ca.key"),
            "-out", j("ca.crt"), "-subj", "/CN=test-ca", "-days", "2")
        ssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
            "-out", j("tsa.csr"), "-subj", "/CN=test-tsa")
        ssl("x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
            "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")
        lock = threading.Lock()

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                q = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/html":
                    body = b"<html><body>503 Service Unavailable</body></html>"
                else:
                    with lock:
                        with open(j("q.tsq"), "wb") as f:
                            f.write(q)
                        ssl("ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1", "-out", j("r.tsr"))
                        with open(j("r.tsr"), "rb") as f:
                            body = f.read()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.d, ignore_errors=True)


@unittest.skipUnless(_DEVFULL and os.name == "posix", "/dev/full and POSIX file descriptors needed")
class TestBuildAndStamp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_74_")
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=cls.d, check=True,
                       capture_output=True)
        with open(os.path.join(cls.d, "not_sdjwt.txt"), "w") as f:
            f.write("this is not an SD-JWT\n")
        cls.tsa = _Tsa() if _OPENSSL else None

    @classmethod
    def tearDownClass(cls):
        if cls.tsa:
            cls.tsa.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def _build(self, out, mode, art="checkout=checkout.sdjwt"):
        return _run(_PY + ["build", out, art, "payment=payment.sdjwt"], mode, cwd=self.d)

    def test_build_file_mode_is_the_control(self):
        out = os.path.join(self.d, "ctl.json")
        rc, raw, err = self._build(out, "file")
        self.assertEqual((rc, err), (0, b""))
        r = json.loads(raw.decode("ascii"))
        with open(out, encoding="utf-8") as f:
            self.assertEqual(r["evidence_digest_sha256"], json.load(f)["evidence_digest_sha256"])
        self.assertTrue(ap2.verify_evidence(out)["valid"])

    def test_build_lost_receipt_is_74(self):
        for mode in ("devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                rc, _, err = self._build(os.path.join(self.d, "b_%s.json" % mode), mode)
                self.assertEqual(rc, 74, err)
                self.assertTrue(err.startswith(b"receipt not written: ") and err.count(b"\n") == 1, err)

    def test_build_refused_stays_1_in_every_mode(self):   # the refusal goes to stderr: nothing on stdout to lose
        for mode in ("file", "devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                rc, raw, err = self._build(os.path.join(self.d, "r.json"), mode, art="checkout=not_sdjwt.txt")
                self.assertEqual(rc, 1, err)
                self.assertIn(b'"error"', err)
                if mode == "file":
                    self.assertEqual(raw, b"")

    def test_the_write_error_is_an_ap2_error_and_an_oserror(self):   # CHANGELOG 1.5.2: both, for callers of either
        self.assertTrue(issubclass(ap2.Ap2WriteError, ap2.Ap2EvidenceError))
        self.assertTrue(issubclass(ap2.Ap2WriteError, OSError))
        with self.assertRaises(ap2.Ap2WriteError):
            ap2.build_evidence([{"name": "checkout", "sd_jwt": open(os.path.join(self.d, "checkout.sdjwt")).read().strip()}],
                               os.path.join(self.d, "no_such_dir", "x.json"))

    def test_build_into_a_pack_path_it_cannot_write_is_74(self):
        for out in (os.path.join(self.d, "no_such_dir", "ev.json"), "/dev/full"):
            with self.subTest(out=out):
                rc, raw, err = self._build(out, "file")
                self.assertEqual(rc, 74, err)
                self.assertEqual(raw, b"")   # no receipt claiming a pack that is not there
                self.assertTrue(err.startswith(b"receipt not written: cannot write the pack ") and err.count(b"\n") == 1, err)

    def _pack(self, name):
        out = os.path.join(self.d, name)
        rc, _, err = self._build(out, "file")
        self.assertEqual(rc, 0, err)
        return out

    def _anchors(self, path):
        with open(path, encoding="utf-8") as f:
            return len(json.load(f).get("anchors", []))

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_file_mode_is_the_control(self):
        p = self._pack("s_ctl.json")
        rc, raw, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url], "file")
        self.assertEqual((rc, err), (0, b""))
        self.assertEqual(json.loads(raw.decode("ascii"))["anchors"], 1)
        self.assertEqual(self._anchors(p), 1)

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_lost_receipt_is_74_and_the_pack_holds_the_anchor(self):
        for mode in ("devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                p = self._pack("s_%s.json" % mode)
                rc, _, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url], mode)
                self.assertEqual(rc, 74, err)
                self.assertTrue(err.startswith(b"receipt not written: ") and err.count(b"\n") == 1, err)
                self.assertEqual(self._anchors(p), 1)   # the CHANGELOG says so: the pack was stamped, the receipt was lost
                self.assertTrue(ap2.verify_evidence(p, require_anchor=True, min_anchors=1)["valid"])

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_refused_stays_1_in_every_mode(self):
        p = self._pack("s_ref.json")
        with open(p, "rb") as f:
            before = hashlib.sha256(f.read()).hexdigest()
        for mode in ("file", "devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                rc, _, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url + "html"], mode)
                self.assertEqual(rc, 1, err)
                self.assertIn(b"no anchor obtained", err)
        with open(p, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), before)

    @unittest.skipUnless(_OPENSSL and hasattr(os, "geteuid") and os.geteuid() != 0, "openssl and a non-root user needed")
    def test_stamp_into_a_directory_it_cannot_write_is_74_and_the_pack_is_unchanged(self):
        sub = os.path.join(self.d, "ro")
        os.mkdir(sub)
        p = os.path.join(sub, "ev.json")
        shutil.copy(self._pack("s_ro_src.json"), p)
        with open(p, "rb") as f:
            before = f.read()
        os.chmod(sub, 0o555)
        try:
            rc, raw, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url], "file")
        finally:
            os.chmod(sub, 0o755)
        self.assertEqual(rc, 74, err)
        self.assertEqual(raw, b"")
        self.assertTrue(err.startswith(b"receipt not written: cannot write the stamped pack") and err.count(b"\n") == 1, err)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), before)


def _run_err(cmd, emode, cwd=None):
    """stdout on a regular file, stderr "full" (/dev/full) or "closed" (fd 2 closed before exec)."""
    with tempfile.TemporaryFile() as out:
        se, pre = None, None
        if emode == "full":
            se = open("/dev/full", "wb")
        else:
            pre = lambda: os.close(2)  # noqa: E731
        try:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=se, preexec_fn=pre, cwd=cwd, timeout=300)
        finally:
            if se is not None:
                se.close()
        out.seek(0)
        return p.returncode, out.read()


@unittest.skipUnless(_DEVFULL and os.name == "posix", "/dev/full and POSIX file descriptors needed")
class TestStderrLost(unittest.TestCase):
    """1.5.2 review: a usage message or a refusal that cannot reach stderr is EX_IOERR (74), never the interpreter's 120
    (stderr full) and never on stdout (stderr closed: argparse and print() fell back to stdout, exit 1 or 2)."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_74e_")
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=cls.d, check=True,
                       capture_output=True)
        with open(os.path.join(cls.d, "not_sdjwt.txt"), "w") as f:
            f.write("this is not an SD-JWT\n")
        cls.bad = os.path.join(cls.d, "bad_digest.json")   # stamp refuses it before any TSA is asked
        shutil.copy(_INVALID, cls.bad)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_usage_and_refusal_with_stderr_lost_are_74_and_stdout_stays_empty(self):
        cases = (["verify"], ["verify", "--bogus", "x"], ["-h"], [],
                 ["build", os.path.join(self.d, "r.json"), "checkout=not_sdjwt.txt", "payment=payment.sdjwt"],
                 ["stamp", self.bad, "--tsa", "http://127.0.0.1:9/"])
        for emode in ("full", "closed"):
            for args in cases:
                with self.subTest(stderr=emode, args=args):
                    rc, out = _run_err(_PY + args, emode, cwd=self.d)
                    self.assertEqual((rc, out), (74, b""))

    def test_control_stderr_lost_with_nothing_to_say_keeps_the_verdict(self):
        for emode in ("full", "closed"):
            for path, code in ((_VALID, 0), (_INVALID, 1)):
                with self.subTest(stderr=emode, input=os.path.basename(path)):
                    rc, out = _run_err(_PY + ["verify", path], emode)
                    self.assertEqual(rc, code)
                    self.assertEqual(json.loads(out.decode("ascii"))["valid"], code == 0)

    def test_control_usage_and_refusal_codes_with_a_working_stderr(self):
        rc, out, err = _run(_PY + ["verify"], "file")
        self.assertEqual((rc, out), (2, b"")); self.assertIn(b"usage", err)
        rc, out, err = _run(_PY + ["build", os.path.join(self.d, "r2.json"), "checkout=not_sdjwt.txt", "payment=payment.sdjwt"],
                            "file", cwd=self.d)
        self.assertEqual((rc, out), (1, b"")); self.assertTrue(err.startswith(b'{"error": '), err)
        rc, out, err = _run(_PY + ["stamp", self.bad, "--tsa", "http://127.0.0.1:9/"], "file")
        self.assertEqual((rc, out), (1, b"")); self.assertIn(b"not stamped", err)


if __name__ == "__main__":
    unittest.main()
