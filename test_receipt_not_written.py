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
import stat
import subprocess
import sys
import tempfile
import threading
import time
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


def _cpu_seconds(pid):
    """utime + stime of a live process, all its threads, from /proc (Linux)."""
    with open(f"/proc/{pid}/stat", "rb") as f:
        fields = f.read().rsplit(b")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def _run_prefilled(cmd, which=1, env=None, cwd=None, other_devfull=False):
    """fd `which` (1 = stdout, 2 = stderr) is a NON-BLOCKING pipe that is already full when the process starts, and
    nobody reads it for a while: the process must wait asleep, as on a blocking pipe — still alive, and in some 1-second
    window (looked at from the 1st to the 10th second, so a slow start is not taken for a spin) using under 0.2 s of CPU,
    which a loop retrying EAGAIN never does — and once the pipe is drained what it had to say must arrive whole. The other
    stream goes to a regular file (or /dev/full). Returns (idle, rc, bytes after the filler or None, the other stream's bytes)."""
    import fcntl
    r, w = os.pipe()
    fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
    filled = 0
    while True:
        try:
            filled += os.write(w, b"P" * 4096)
        except BlockingIOError:
            break
    other = tempfile.TemporaryFile()
    dest = open("/dev/full", "wb") if other_devfull else other
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=w if which == 1 else dest,
                             stderr=w if which == 2 else dest, cwd=cwd, env=dict(os.environ, **(env or {})))
    finally:
        os.close(w)
        if dest is not other:
            dest.close()
    idle, t0 = False, time.time()
    time.sleep(1.0)
    while p.poll() is None and time.time() - t0 < 10:
        try:
            c0 = _cpu_seconds(p.pid)
            time.sleep(1.0)
            c1 = _cpu_seconds(p.pid)
        except OSError:   # exited during the window
            break
        if p.poll() is not None:
            break
        if c1 - c0 < 0.2:
            idle = True
            break
    chunks = []
    while True:
        b = os.read(r, 1 << 16)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    rc = p.wait(timeout=120)
    other.seek(0)
    rest = other.read()
    other.close()
    data = b"".join(chunks)
    return idle, rc, (data[filled:] if data[:filled] == b"P" * filled else None), rest


@unittest.skipUnless(os.name == "posix" and os.path.exists("/proc/self/stat"), "POSIX pipes and /proc needed")
class TestWholeOrWaited(unittest.TestCase):
    """1.5.2, second pass (13/10/2026, measured on a410964 with real processes): with PYTHONUNBUFFERED=1 (or -u) the
    receipt went to a raw FileIO whose short write the text layer dropped in silence (exit 0 or 1 with 24 bytes of it on a
    file of 1 000 bytes under `ulimit -f 1`; exit 0 through `| head -c 100` with a receipt of 84 620 bytes); a full
    non-blocking stdout read 1 s late gave 74 with 65 536 bytes in the pipe (buffered) or 0 with them (unbuffered); a
    refusal, a usage message or the "receipt not written" line on a full non-blocking stderr was lost (74, or 120 on
    1.5.1), the JS usage line too. Now every one of them is written whole or waited for."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_wow_")
        cls.big = _big_valid_pack(cls.d)
        with open(os.path.join(cls.d, "not_sdjwt.txt"), "w") as f:
            f.write("this is not an SD-JWT\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _fsize_cut(self, cmd, env):
        """stdout appended to a file that already holds 1 000 bytes, under RLIMIT_FSIZE 1 024: 24 bytes, then EFBIG."""
        import resource
        import signal
        o = os.path.join(self.d, "cut")
        with open(o, "wb") as f:
            f.write(b"x" * 1000)

        def pre():
            signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
        with open(o, "ab") as f, tempfile.TemporaryFile() as err:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=err, preexec_fn=pre,
                               env=dict(os.environ, **env), timeout=300)
            err.seek(0)
            return p.returncode, err.read()

    def test_unbuffered_short_write_is_74(self):
        u = {"PYTHONUNBUFFERED": "1"}
        for path in (_VALID, _INVALID, self.big):
            with self.subTest(input=os.path.basename(path)):
                rc, err = self._fsize_cut(_PY + ["verify", path], u)
                self.assertEqual(rc, 74, err)
                self.assertTrue(err.startswith(b"receipt not written: ") and b"File too large" in err and err.count(b"\n") == 1, err)
        rc, err = self._fsize_cut(_PY + ["verify", _VALID], {})   # the control: buffered was 74 already
        self.assertEqual(rc, 74, err)

    def test_unbuffered_big_receipt_to_a_reader_that_left_is_74(self):
        p = subprocess.run(["bash", "-c", '{ sleep 0.2; exec "$@"; } | head -c 100 >/dev/null; exit "${PIPESTATUS[0]}"', "_"]
                           + _PY + ["verify", self.big], env=dict(os.environ, PYTHONUNBUFFERED="1"),
                           stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
        self.assertEqual(p.returncode, 74, p.stderr)
        self.assertTrue(p.stderr.startswith(b"receipt not written: "), p.stderr)

    def _whole_when_drained(self, cmd, env=None):
        with tempfile.TemporaryFile() as f:
            ctl = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.DEVNULL,
                                 env=dict(os.environ, **(env or {})), timeout=300)
            f.seek(0)
            whole = f.read()
        idle, rc, got, err = _run_prefilled(cmd, 1, env)
        self.assertTrue(idle, "no 1-second window under 0.2 s of CPU: a spin, or it never waited")
        self.assertEqual((rc, err), (ctl.returncode, b""))
        self.assertEqual(got, whole)

    def test_full_non_blocking_stdout_is_waited_for_python(self):
        for env in ({}, {"PYTHONUNBUFFERED": "1"}):
            for path in (_VALID, self.big):
                with self.subTest(env=env, input=os.path.basename(path)):
                    self._whole_when_drained(_PY + ["verify", path], env)

    @unittest.skipUnless(_NODE, "node needed")
    def test_full_non_blocking_stdout_is_waited_for_js(self):   # libuv waited already: a guard
        for path in (_VALID, self.big):
            with self.subTest(input=os.path.basename(path)):
                self._whole_when_drained([_NODE, _JS, path])

    def _stderr_waited(self, cmd, code, start, stdout_devfull=False):
        idle, rc, got, out = _run_prefilled(cmd, 2, cwd=self.d, other_devfull=stdout_devfull)
        self.assertTrue(idle, "no 1-second window under 0.2 s of CPU: a spin, or it never waited")
        self.assertEqual(rc, code, got)
        self.assertTrue(got is not None and got.startswith(start) and got.endswith(b"\n"), got)
        self.assertEqual(out, b"")

    def test_full_non_blocking_stderr_is_waited_for_python(self):
        bad = os.path.join(_VEC, "digest_mismatch.json")
        self._stderr_waited(_PY + ["verify"], 2, b"usage: ")
        self._stderr_waited(_PY + ["build", os.path.join(self.d, "r.json"), "checkout=not_sdjwt.txt"], 1, b'{"error": ')
        self._stderr_waited(_PY + ["stamp", bad, "--tsa", "http://127.0.0.1:9/"], 1, b'{"error": ')
        self._stderr_waited(_PY + ["verify", _VALID], 74, b"receipt not written: ", stdout_devfull=True)

    @unittest.skipUnless(_NODE, "node needed")
    def test_full_non_blocking_stderr_is_waited_for_js(self):
        self._stderr_waited([_NODE, _JS], 2, b"usage: ")
        self._stderr_waited([_NODE, _JS, "--bogus", _VALID], 2, b"usage: ")
        self._stderr_waited([_NODE, _JS, _VALID], 74, b"receipt not written: ", stdout_devfull=True)

    def test_encodings_are_the_text_layers(self):
        """The receipt's bytes are the ones Python's own stdout text layer writes for the same text, in five encodings (a
        byte order mark included or not as that layer decides: utf-16 and utf-32 write one on a new file, none on a pipe or
        after bytes already in the file) and one error handler, to a new file, appended to a file and to a pipe, buffered
        and unbuffered. The reference is a second process writing the same text with sys.stdout.write."""
        text_path = os.path.join(self.d, "receipt.txt")
        with open(text_path, "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps(ap2.verify_evidence(_VALID), indent=1) + "\n")
        ref = [sys.executable, "-c", "import sys; sys.stdout.write(open(sys.argv[1], encoding='utf-8', newline='').read())", text_path]

        def out_of(argv, enc, dest, env):
            e = dict(os.environ, PYTHONIOENCODING=enc, **env)
            if dest == "pipe":
                return subprocess.run(argv, env=e, capture_output=True, timeout=120).stdout
            o = os.path.join(self.d, "o")
            with open(o, "wb") as f:
                f.write(b"PRE" if dest == "append" else b"")
            with open(o, "ab" if dest == "append" else "wb") as f:
                subprocess.run(argv, env=e, stdout=f, timeout=120)
            with open(o, "rb") as f:
                return f.read()
        for enc in ("utf-8", "utf-16", "utf-32", "utf-8-sig", "latin-1", "ascii:backslashreplace"):
            for dest in ("file", "append", "pipe"):
                for env in ({}, {"PYTHONUNBUFFERED": "1"}):
                    with self.subTest(enc=enc, dest=dest, env=env):
                        a, b = out_of(_PY + ["verify", _VALID], enc, dest, env), out_of(ref, enc, dest, env)
                        self.assertGreater(len(b), 10)
                        self.assertEqual(a, b)

    def test_in_process_streams(self):
        """main() in process with sys.stdout replaced: a StringIO (no bytes below it), a TextIOWrapper over io.BytesIO
        (pytest's capsys: bytes below, no descriptor) with and without write_through, and one the caller wrote to first."""
        import io
        for make in (io.StringIO, lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True),
                     lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            s = make()
            saved = sys.stdout
            sys.stdout = s
            try:
                rc = ap2.main(["verify", _VALID])
            finally:
                sys.stdout = saved
            text = s.getvalue() if isinstance(s, io.StringIO) else s.buffer.getvalue().decode("utf-8")
            self.assertEqual((rc, json.loads(text)["valid"]), (0, True), type(s).__name__)
        s = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        s.write("before\n")
        saved = sys.stdout
        sys.stdout = s
        try:
            rc = ap2.main(["verify", _VALID])
        finally:
            sys.stdout = saved
        head, _, rest = s.buffer.getvalue().decode("utf-8").partition("\n")
        self.assertEqual((rc, head, json.loads(rest)["valid"]), (0, "before", True))


@unittest.skipUnless(os.name == "posix", "POSIX permissions and RLIMIT_FSIZE needed")
class TestPackWrittenWholeOrNotAtAll(unittest.TestCase):
    """1.5.2, second pass: `build` (and `sign_evidence`) opened the pack path with "w" and wrote into it, so a write that
    failed part way (a full disk, `ulimit -f`) truncated an earlier pack at that path (measured on 1.5.1 and a410964:
    5 891 bytes became 2 048 and the pack no longer verified). Now the pack goes to a temporary file in the same directory
    and is renamed onto the path only when whole."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_atomic_")
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=cls.d, check=True,
                       capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _build(self, out, limit=None, tsa=None):
        import resource
        import signal

        def pre():
            signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
            if limit is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        cmd = _PY + ["build", out, "checkout=checkout.sdjwt", "payment=payment.sdjwt"] + (["--tsa", tsa] if tsa else [])
        with tempfile.TemporaryFile() as o, tempfile.TemporaryFile() as e:
            p = subprocess.run(cmd, cwd=self.d, stdin=subprocess.DEVNULL, stdout=o, stderr=e, preexec_fn=pre, timeout=300)
            o.seek(0); e.seek(0)
            return p.returncode, o.read(), e.read()

    def _leftovers(self, d):
        return [n for n in os.listdir(d) if n.endswith(".tmp")]

    def test_a_failed_build_leaves_the_earlier_pack_as_it_was(self):
        sub = tempfile.mkdtemp(dir=self.d)
        out = os.path.join(sub, "ev.json")
        rc, _, err = self._build(out)
        self.assertEqual(rc, 0, err)
        with open(out, "rb") as f:
            before = f.read()
        self.assertGreater(len(before), 2048)
        rc, raw, err = self._build(out, limit=2048)
        self.assertEqual(rc, 74, err)
        self.assertEqual(raw, b"")
        self.assertTrue(err.startswith(b"receipt not written: cannot write the pack ") and b"File too large" in err, err)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self._leftovers(sub), [])
        self.assertTrue(ap2.verify_evidence(out)["valid"])

    def test_a_failed_first_build_leaves_nothing(self):
        sub = tempfile.mkdtemp(dir=self.d)
        rc, _, err = self._build(os.path.join(sub, "ev.json"), limit=2048)
        self.assertEqual(rc, 74, err)
        self.assertEqual(os.listdir(sub), [])

    def test_mode_symlink_and_read_only(self):
        sub = tempfile.mkdtemp(dir=self.d)
        new = os.path.join(sub, "new.json")
        with open(os.path.join(sub, "ref"), "w"):
            pass
        rc, _, err = self._build(new)
        self.assertEqual(rc, 0, err)
        self.assertEqual(stat.S_IMODE(os.stat(new).st_mode), stat.S_IMODE(os.stat(os.path.join(sub, "ref")).st_mode))
        os.chmod(new, 0o640)
        rc, _, err = self._build(new)
        self.assertEqual(rc, 0, err)
        self.assertEqual(stat.S_IMODE(os.stat(new).st_mode), 0o640)   # the pack it replaces keeps its permissions
        link = os.path.join(sub, "link.json")
        os.symlink("new.json", link)
        rc, raw, err = self._build(link)
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.islink(link))   # the file it names is replaced, the link stays
        self.assertEqual(json.loads(raw.decode("ascii"))["out"], link)
        if os.geteuid() != 0:
            os.chmod(new, 0o444)
            with open(new, "rb") as f:
                before = f.read()
            rc, _, err = self._build(new)
            self.assertEqual(rc, 74, err)
            self.assertIn(b"PermissionError", err)
            with open(new, "rb") as f:
                self.assertEqual(f.read(), before)
        self.assertEqual(self._leftovers(sub), [])

    def test_a_path_that_is_not_a_regular_file_is_written_directly(self):
        rc, raw, err = self._build(os.devnull)
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(raw.decode("ascii"))["out"], os.devnull)
        self.assertTrue(os.path.exists(os.devnull) and not os.path.isfile(os.devnull))

    def test_a_directory_is_refused_before_any_tsa_is_asked(self):
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(1)
                self.send_response(503)
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            sub = tempfile.mkdtemp(dir=self.d)
            rc, raw, err = self._build(sub, tsa="http://127.0.0.1:%d/" % srv.server_address[1])
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual((rc, raw, hits), (74, b"", []), err)
        self.assertEqual(err, ("receipt not written: cannot write the pack %r: IsADirectoryError: Is a directory\n" % sub).encode())

    def test_the_stderr_line_keeps_the_streams_error_handler(self):
        """stderr's own error handler (backslashreplace) decides how a character it cannot encode is written: a pack path
        with a non-ASCII character under PYTHONIOENCODING=ascii still gives the whole line, escaped as the text layer
        escapes it, and 74 — never a line lost to a strict encoder."""
        out = os.path.join(self.d, "no_such_d\u00fcr", "ev.json")
        p = subprocess.run(_PY + ["build", out, "checkout=checkout.sdjwt", "payment=payment.sdjwt"], cwd=self.d,
                           stdin=subprocess.DEVNULL, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="ascii"), timeout=300)
        self.assertEqual((p.returncode, p.stdout), (74, b""), p.stderr)
        line = "receipt not written: cannot write the pack %r: FileNotFoundError: No such file or directory\n" % out
        self.assertEqual(p.stderr, line.encode("ascii", "backslashreplace"))

    def test_sign_evidence_leaves_the_pack_as_it_was_when_it_cannot_write(self):
        sub = tempfile.mkdtemp(dir=self.d)
        out = os.path.join(sub, "ev.json")
        rc, _, err = self._build(out)
        self.assertEqual(rc, 0, err)
        with open(out, "rb") as f:
            before = f.read()
        code = ("import resource, signal, sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a; "
                "signal.signal(signal.SIGXFSZ, signal.SIG_IGN); resource.setrlimit(resource.RLIMIT_FSIZE, (2048, 2048))\n"
                "try:\n a.sign_evidence(sys.argv[2])\nexcept OSError as e:\n print(type(e).__name__); sys.exit(3)\n")
        p = subprocess.run([sys.executable, "-c", code, _HERE, out], capture_output=True, timeout=300)
        self.assertEqual(p.returncode, 3, p.stderr)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self._leftovers(sub), [])


@unittest.skipUnless(_OPENSSL and os.name == "posix", "openssl and RLIMIT_FSIZE needed")
class TestOpensslTemporaryFiles(unittest.TestCase):
    """1.5.2, second pass: `verify --tsa-cert` and `verify --trust-anchor` hand openssl files in a temporary directory, and
    `stamp` / `build --tsa` wrote the query there. Measured on a410964 (13/10/2026) with no writable temporary file
    (`ulimit -f 0`): `verify --tsa-cert` on a valid pack raised a traceback (exit 1, the "not valid" code), `--trust-anchor`
    reported the artifact as an error (a valid pack "not valid", exit 1) and `stamp` raised a traceback (exit 1). Now a check
    that cannot be run here is exit 74 with one line, and the TSA query is read from openssl's stdout."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(_HERE, "verifiers"))
        import differential_oracle as O
        cls.d = tempfile.mkdtemp(prefix="ap2_tmpf_")
        with open(os.path.join(_VEC, "valid_signed.json"), encoding="utf-8") as f:
            base = json.load(f)
        cases = dict(O._x5c_cases(base))
        cls.x5c = os.path.join(cls.d, "x5c.json")
        with open(cls.x5c, "w", encoding="utf-8") as f:
            json.dump(O.rehash(cases["ca-issued-leaf"]), f)
        cls.ca = os.path.join(cls.d, "ca.pem")
        with open(cls.ca, "wb") as f:
            f.write(O._x5c_cases.ca_pem)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _run(self, cmd, limit):
        import resource

        def pre():
            if limit is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, preexec_fn=pre, timeout=300)
        return p.returncode, p.stdout, p.stderr

    def _check(self, cmd, field):
        rc, out, err = self._run(cmd, None)   # the control: the check runs and passes
        self.assertEqual((rc, err), (0, b""))
        self.assertIn(field, out)
        # 0: no temporary directory passes tempfile's probe; 100: the probe passes, the file openssl reads does not fit
        for limit, why in ((0, b"no usable temporary directory"), (100, b"OSError: File too large")):
            rc, out, err = self._run(cmd, limit)
            self.assertEqual((rc, out), (74, b""), err)
            self.assertEqual(err, b"receipt not written: cannot write a temporary file for openssl: " + why + b"\n")

    def test_verify_tsa_cert(self):
        self._check(_PY + ["verify", os.path.join(_VEC, "anchor_valid.json"), "--tsa-cert",
                           os.path.join(_VEC, "anchor_probe_tsa.crt"), "--require-anchor"], b'"tsa_verified": true')

    def test_verify_trust_anchor(self):
        self._check(_PY + ["verify", self.x5c, "--trust-anchor", self.ca], b'"chain_verified": true')

    def test_library_raises_the_write_error(self):   # never a check reported as failed
        code = ("import resource, sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a; "
                "resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))\n"
                "try:\n a.verify_evidence(sys.argv[2], trust_anchor=sys.argv[3])\n"
                "except a.Ap2WriteError as e:\n print(str(e)); sys.exit(3)\n")
        p = subprocess.run([sys.executable, "-c", code, _HERE, self.x5c, self.ca], capture_output=True, timeout=300)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertTrue(p.stdout.startswith(b"cannot write a temporary file for openssl"), p.stdout)

    def test_stamp_query_needs_no_temporary_file(self):
        tsa = _Tsa()
        try:
            sub = tempfile.mkdtemp(dir=self.d)
            subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=sub, check=True,
                           capture_output=True)
            p = os.path.join(sub, "ev.json")
            rc, _, err = _run(_PY + ["build", p, "checkout=checkout.sdjwt", "payment=payment.sdjwt"], "file", cwd=sub)
            self.assertEqual(rc, 0, err)
            with open(p, "rb") as f:
                before = f.read()
            # under RLIMIT_FSIZE 0 the token is obtained (no temporary file), then the pack cannot be written: 74, unchanged
            rc, out, err = self._run(_PY + ["stamp", p, "--tsa", tsa.url], 0)
            self.assertEqual((rc, out), (74, b""), err)
            self.assertTrue(err.startswith(b"receipt not written: cannot write the stamped pack"), err)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), before)
            rc, out, err = self._run(_PY + ["stamp", p, "--tsa", tsa.url], None)
            self.assertEqual((rc, err), (0, b""))
            self.assertEqual(json.loads(out.decode("ascii"))["anchors"], 1)
        finally:
            tsa.close()


if __name__ == "__main__":
    unittest.main()
