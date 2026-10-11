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


def _der_tlv_bytes(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 0x80 else (b"\x81" + bytes([n]) if n < 0x100 else b"\x82" + n.to_bytes(2, "big"))
    return bytes([tag]) + ln + body


def _rewrapped(tsr):
    """The same TimeStampResp re-encoded around the SAME signed token: bytes after it, a statusString, a longer length."""
    _, st, en = ap2._der_tlv(tsr, 0)
    s_end = ap2._der_tlv(tsr, st)[2]
    status_body = tsr[ap2._der_tlv(tsr, st)[1]:s_end]
    token = tsr[s_end:en]
    return {"trailing-byte": tsr + b"\x00", "trailing-tlv": tsr + b"\x05\x00",
            "status-string": _der_tlv_bytes(0x30, _der_tlv_bytes(0x30, status_body + _der_tlv_bytes(0x30, _der_tlv_bytes(0x0C, b"copy"))) + token),
            "long-length": b"\x30\x84" + (en - st).to_bytes(4, "big") + tsr[st:en]}


class TestAnchorIdentity(unittest.TestCase):
    """SPEC §3.3: two entries are one anchor when the TSTInfo the TSA signed is the same. Measured on b3edfc8: the token of
    anchor_valid re-wrapped four ways counted as a SECOND anchor in both verifiers, and under --tsa-cert in the reference
    (openssl ts -verify accepts all four), so --min-anchors 2 --tsa-cert passed on ONE timestamp."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-ident-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.ev = _rjson(os.path.join(VDIR, "anchor_valid.json"))
        self.tsr = base64.b64decode(self.ev["rfc3161_timestamp"]["tsr_b64"])

    def _pack(self, name, tok):
        e = copy.deepcopy(self.ev); e["anchors"] = [{"mechanism": "rfc3161", "tsr_b64": base64.b64encode(tok).decode()}]
        p = os.path.join(self.d, name + ".json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(e, f)
        return p

    def test_a_rewrapped_copy_is_one_anchor_in_both_verifiers(self):
        crt = os.path.join(VDIR, "anchor_probe_tsa.crt")
        for name, tok in _rewrapped(self.tsr).items():
            p = self._pack(name, tok)
            r = ap2.verify_evidence(p, min_anchors=2)
            self.assertEqual([a["verified"] for a in r["anchors"]], [True], name)   # the binding still verifies: it IS the token
            self.assertEqual((r["anchors_verified"], r["policy_ok"], r["valid"]), (1, False, False), name)
            if HAVE_OPENSSL:
                r = ap2.verify_evidence(p, min_anchors=2, tsa_cert=crt)
                self.assertEqual(r["anchors"][0]["tsa_verified"], True, name)   # openssl accepts the wrapper: only the identity rule stops it
                self.assertEqual((r["anchors_verified"], r["policy_ok"]), (1, False), name)
            if HAVE_NODE:
                j = json.loads(subprocess.run(["node", JS, p, "--min-anchors", "2"], capture_output=True, text=True).stdout)
                self.assertEqual((j["anchors_verified"], j["policy_ok"]), (1, False), ("js", name))

    def test_two_different_tsas_still_count_two(self):   # the control: the identity rule does not merge distinct timestamps
        p = os.path.join(VDIR, "anchors_two_valid.json")
        self.assertEqual(ap2.verify_evidence(p, min_anchors=2)["anchors_verified"], 2)
        if HAVE_NODE:
            j = json.loads(subprocess.run(["node", JS, p, "--min-anchors", "2"], capture_output=True, text=True).stdout)
            self.assertEqual(j["anchors_verified"], 2)


class TestAnchorAggregateAndTexts(unittest.TestCase):
    """A failing entry fails the pack even when another entry verifies (README: "an anchor is never ignored because another
    one verifies"): every vector has ONE entry, so `any` -> `all` in the aggregate survived the whole suite on b3edfc8.
    And the exact refusal texts of the entry checks the vectors do not reach."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-agg-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.ev = _rjson(os.path.join(VDIR, "anchors_two_valid.json"))
        self.bad = _rjson(os.path.join(VDIR, "anchors_entry_wrong_digest.json"))["anchors"][0]

    def _both(self, anchors, name):
        e = copy.deepcopy(self.ev); e["anchors"] = anchors
        p = os.path.join(self.d, name + ".json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(e, f)
        out = [ap2.verify_evidence(p)]
        if HAVE_NODE:
            out.append(json.loads(subprocess.run(["node", JS, p], capture_output=True, text=True).stdout))
        return out

    def test_one_failing_entry_among_good_ones_fails_the_pack(self):
        good = self.ev["anchors"][0]
        for order in ([good, self.bad], [self.bad, good]):
            for r in self._both(order, "agg"):
                self.assertEqual((r["rfc3161"]["claimed"], r["rfc3161"]["verified"], r["valid"]), (True, False, False))
                self.assertEqual([a["verified"] for a in r["anchors"]], [x is good for x in order])
                self.assertTrue(all(a["claimed"] is True and a["mechanism"] == "rfc3161" for a in r["anchors"]))

    def test_an_entry_with_every_optional_key_is_accepted(self):   # the closed list must not be closed too far (note, tsa_url)
        good = dict(self.ev["anchors"][0], tsa_url="https://tsa.example", note="renewal \u00e9\U0001F600")
        for r in self._both([good], "opt"):
            self.assertEqual((r.get("refused"), r["valid"], r["anchors_verified"]), (None, True, 2))

    def test_entry_refusal_texts_are_exact_in_both(self):
        for entry, want in (([1], "anchors[0] must be an object (SPEC §9.1)"), ([None], "anchors[0] must be an object (SPEC §9.1)"),
                            ([{}], "anchors[0]: missing mechanism (SPEC §9.1)"),
                            ([{"mechanism": 1}], "anchors[0]: mechanism must be a string (SPEC §9.1)"),
                            ([{"mechanism": ["rfc3161"]}], "anchors[0]: mechanism must be a string (SPEC §9.1)"),
                            ([{"mechanism": "x \U0001F600"}], 'anchors[0]: mechanism "x \U0001F600" is not defined by this revision (SPEC §3.3)'),
                            ([{"mechanism": "rfc3161", "tsr_b64": "AAAA", "note": None}], "anchors[0]: note must be a string (SPEC §9.1)")):
            for r in self._both(entry, "txt"):
                self.assertEqual(r.get("refused"), want, entry)
                self.assertEqual(r.get("anchors_verified"), 0, entry)


def _x5c_pack_with_tokens(d, not_after):
    """A pack whose only artifact carries an x5c leaf issued by a local CA and valid until `not_after`."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    base = _rjson(os.path.join(VDIR, "valid_signed.json"))
    sk = ec.generate_private_key(ec.SECP256R1()); n = sk.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    ca = ec.generate_private_key(ec.SECP256R1()); can = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gen_time probe CA")])
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gen_time probe")])).issuer_name(can)
            .public_key(sk.public_key()).serial_number(2).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(not_after).sign(ca, hashes.SHA256()))
    cac = (x509.CertificateBuilder().subject_name(can).issuer_name(can).public_key(ca.public_key()).serial_number(3)
           .not_valid_before(now - datetime.timedelta(days=2)).not_valid_after(now + datetime.timedelta(days=30))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca, hashes.SHA256()))
    anchor = os.path.join(d, "ca.pem")
    with open(anchor, "wb") as f:
        f.write(cac.public_bytes(serialization.Encoding.PEM))
    hdr = json.dumps({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()]}, separators=(",", ":"))
    si = b64u(hdr.encode()) + "." + b64u(b'{"iss":"x"}')
    r, s = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    ev = {"evidence_format": base["evidence_format"], "subject": "earliest gen_time", "created_utc": "2026-10-11T00:00:00Z",
          "artifacts": [{"name": "intent", "sd_jwt_compact": si + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~",
                         "header": json.loads(hdr), "key": {"jwk": jwk, "provenance_class": "x5c_header"}, "resolved_claims": {"iss": "x"},
                         "kb_jwt": {"present": False}, "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}],
          "bindings": [], "honest_scope": base["honest_scope"]}
    ev["evidence_digest_sha256"] = __import__("hashlib").sha256(ap2._canon({k: v for k, v in ev.items() if k not in ap2._DIGEST_EXCLUDED})).hexdigest()
    return ev, anchor


@unittest.skipUnless(HAVE_OPENSSL, "openssl absent: the local TSA cannot run")
class TestEarliestGenTime(unittest.TestCase):
    """SPEC §3.3: x5c chains are validated at the EARLIEST gen_time among the TSA-verified anchors. The CHANGELOG said this
    rule was not pinned (it needs a chained x5c and two TSAs): here a leaf valid for two more seconds, a token from TSA A
    now, a token from TSA B after the leaf expired. Wall clock: about four seconds of waiting, margins of two seconds."""

    def test_the_earliest_tsa_verified_time_is_used_wherever_it_sits(self):
        import datetime
        import time
        d = tempfile.mkdtemp(prefix="ap2-gt-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        ta, tb = LocalTSA(d, "gtA"), LocalTSA(d, "gtB")
        t0 = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)
        ev, anchor = _x5c_pack_with_tokens(d, t0 + datetime.timedelta(seconds=2))
        tok_a = ta.stamp(ev["evidence_digest_sha256"], "a")["tsr_b64"]
        while datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) < t0 + datetime.timedelta(seconds=4):
            time.sleep(0.2)
        tok_b = tb.stamp(ev["evidence_digest_sha256"], "b")["tsr_b64"]
        bundle = os.path.join(d, "bundle.pem")
        with open(bundle, "wb") as f:
            f.write(_rb(ta.crt) + _rb(tb.crt))

        def chain(block, anchors, **kw):
            e = copy.deepcopy(ev); e["rfc3161_timestamp"] = block
            if anchors:
                e["anchors"] = [{"mechanism": "rfc3161", "tsr_b64": t} for t in anchors]
            p = os.path.join(d, "p.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(e, f)
            r = ap2.verify_evidence(p, trust_anchor=anchor, **kw)
            self.assertTrue(r["valid"], r.get("refused"))
            return r["chain_verified"]
        self.assertIs(chain({"anchored": True, "tsr_b64": tok_a}, None, tsa_cert=bundle), True)    # controls: A alone, inside the leaf's life
        self.assertIs(chain({"anchored": True, "tsr_b64": tok_b}, None, tsa_cert=bundle), False)   # B alone, after it
        self.assertIs(chain({"anchored": True, "tsr_b64": tok_b}, [tok_a], tsa_cert=bundle), True)   # earliest in `anchors`
        self.assertIs(chain({"anchored": True, "tsr_b64": tok_a}, [tok_b], tsa_cert=bundle), True)   # earliest in the block
        self.assertIs(chain({"anchored": False}, [tok_b, tok_a], tsa_cert=bundle), True)
        self.assertIs(chain({"anchored": True, "tsr_b64": tok_b}, [tok_a]), False)   # no --tsa-cert: no time is PROVEN, current time
        self.assertIs(chain({"anchored": True, "tsr_b64": tok_b}, [tok_a], tsa_cert=tb.crt), False)   # A not TSA-verified: it proves nothing

    def test_gen_time_order_key_reads_the_fraction(self):
        self.assertLess(ap2._gt_key("20261011120000Z"), ap2._gt_key("20261011120000.5Z"))   # as strings, '.' < 'Z' put .5 first
        self.assertLess(ap2._gt_key("20261011120000.25Z"), ap2._gt_key("20261011120000.3Z"))
        self.assertLess(ap2._gt_key("20261011115959.999Z"), ap2._gt_key("20261011120000Z"))


@unittest.skipUnless(HAVE_OPENSSL, "openssl absent: the local TSA cannot run")
class TestStampWrite(unittest.TestCase):
    """add_anchor / `stamp` write path, measured on b3edfc8: a fixed temporary name (a planted symlink there was written
    through), the pack's mode reset to the umask (0600 -> 0644), six concurrent stamps keeping one anchor while all reported
    success, an OSError as a traceback, and `--tsa A --tsa B` stamping B only."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-sw-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.pack = os.path.join(self.d, "p.json"); shutil.copy(os.path.join(VDIR, "valid_signed.json"), self.pack)
        self.tsas = {}
        self._orig = ap2._rfc3161_stamp; self.addCleanup(setattr, ap2, "_rfc3161_stamp", self._orig)

        def fake(digest, url, timeout=20):
            if url not in self.tsas:
                if not url.startswith("https://ok"):
                    return {"anchored": False, "note": "unreachable"}
                dd = os.path.join(self.d, "tsa-" + str(len(self.tsas))); os.makedirs(dd, exist_ok=True)
                self.tsas[url] = LocalTSA(dd, "t")
            return self.tsas[url].stamp(digest, url)
        ap2._rfc3161_stamp = fake

    def _cli(self, *args):
        import contextlib
        import io
        o, e = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                rc = ap2.main(list(args))
            except SystemExit as x:
                rc = x.code
        return rc, o.getvalue(), e.getvalue()

    def test_a_pack_of_another_format_is_not_stamped(self):
        ev = _rjson(self.pack); ev["evidence_format"] = "ap2-evidence-pack/9.9"
        ev["evidence_digest_sha256"] = __import__("hashlib").sha256(ap2._canon({k: v for k, v in ev.items() if k not in ap2._DIGEST_EXCLUDED})).hexdigest()
        with open(self.pack, "w") as f:
            json.dump(ev, f)
        raw = _rb(self.pack)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.add_anchor(self.pack, "https://ok1")
        self.assertEqual(_rb(self.pack), raw)

    def test_an_empty_anchors_list_is_not_stamped(self):
        ev = _rjson(self.pack); ev["anchors"] = []
        with open(self.pack, "w") as f:
            json.dump(ev, f)
        raw = _rb(self.pack)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.add_anchor(self.pack, "https://ok1")
        self.assertEqual(_rb(self.pack), raw)

    def test_a_failing_write_leaves_the_pack_and_no_temporary_file(self):
        raw = _rb(self.pack); before = sorted(os.listdir(self.d))
        real_dump = ap2.json.dump

        def half_then_fail(obj, f, **kw):
            f.write('{"half": '); raise OSError(28, "No space left on device")
        ap2.json.dump = half_then_fail
        try:
            with self.assertRaises(ap2.Ap2EvidenceError):
                ap2.add_anchor(self.pack, "https://ok1")
        finally:
            ap2.json.dump = real_dump
        self.assertEqual(_rb(self.pack), raw)
        self.assertEqual(sorted(x for x in os.listdir(self.d) if not x.startswith("tsa-")), [x for x in before if not x.startswith("tsa-")])

    def test_mode_symlink_and_leftovers(self):
        os.chmod(self.pack, 0o640)   # neither the umask default (0644) nor mkstemp's (0600): only a copied mode keeps it
        link = os.path.join(self.d, "link.json"); os.symlink(self.pack, link)
        ap2.add_anchor(link, "https://ok1")
        self.assertTrue(os.path.islink(link))                       # the link stays a link, the pack it names is stamped
        self.assertEqual(len(_rjson(self.pack)["anchors"]), 1)
        self.assertEqual(os.stat(self.pack).st_mode & 0o777, 0o640)
        self.assertEqual(sorted(x for x in os.listdir(self.d) if not x.startswith("tsa-")), ["link.json", "p.json"])

    def test_concurrent_stamps_keep_every_anchor(self):
        import threading
        n = 6
        for i in range(n):   # the TSAs exist before the race (each with its own directory)
            dd = os.path.join(self.d, "tsa-%d" % i); os.makedirs(dd)
            self.tsas["https://ok%d" % i] = LocalTSA(dd, "t")
        barrier, errors = threading.Barrier(n), []

        def one(i):
            barrier.wait()
            try:
                ap2.add_anchor(self.pack, "https://ok%d" % i)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
        ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(sorted(a["tsa_url"] for a in _rjson(self.pack)["anchors"]), sorted("https://ok%d" % i for i in range(n)))

    def test_cli_stamp_takes_one_tsa_and_build_takes_many(self):
        raw = _rb(self.pack)
        rc, out, err = self._cli("stamp", self.pack, "--tsa", "https://ok1", "--tsa", "https://ok2")
        self.assertEqual((rc, out), (2, "")); self.assertEqual(_rb(self.pack), raw)
        rc, out, err = self._cli("stamp", self.pack, "--tsa=https://ok1")
        self.assertEqual(rc, 0, err); self.assertEqual(len(_rjson(self.pack)["anchors"]), 1)
        ap2.add_anchor(self.pack, "https://ok2")   # appended, in stamping order
        self.assertEqual([a["tsa_url"] for a in _rjson(self.pack)["anchors"]], ["https://ok1", "https://ok2"])
        sk = _rjson(os.path.join(VDIR, "valid_signed.json"))
        args = []
        for a in sk["artifacts"]:
            p = os.path.join(self.d, a["name"] + ".sdjwt")
            with open(p, "w") as f:
                f.write(a["sd_jwt_compact"])
            args.append(a["name"] + "=" + p)
        out_pack = os.path.join(self.d, "built.json")
        rc, out, err = self._cli("build", out_pack, *args, "--tsa", "https://ok1", "--tsa", "https://ok2", "--tsa", "https://down")
        self.assertEqual(rc, 0, err)
        ev = _rjson(out_pack)
        self.assertEqual(ev["rfc3161_timestamp"]["tsa_url"], "https://ok1")
        self.assertEqual([a["tsa_url"] for a in ev["anchors"]], ["https://ok2"])
        self.assertEqual([f["tsa_url"] for f in json.loads(out)["anchors_failed"]], ["https://down"])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes into a read-only directory")
    def test_an_unwritable_directory_is_a_refusal_not_a_traceback(self):
        ro = os.path.join(self.d, "ro"); os.makedirs(ro); p = os.path.join(ro, "p.json"); shutil.copy(self.pack, p)
        os.chmod(ro, 0o555); self.addCleanup(os.chmod, ro, 0o755)
        rc, out, err = self._cli("stamp", p, "--tsa", "https://ok1")
        self.assertEqual(rc, 1); self.assertIn("not stamped", err)


class TestMinAnchorsApi(unittest.TestCase):
    """min_anchors is an integer >= 1 at the API too: on b3edfc8, 0 / NaN / -1 disabled the policy in silence, "2" was a
    TypeError in the reference, NaN passed every pack in the JS verifier."""

    def test_python(self):
        p = os.path.join(VDIR, "anchor_valid.json")
        for bad in (0, -1, True, "2", 2.0, float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ap2.verify_evidence(p, min_anchors=bad)
        self.assertEqual(ap2.verify_evidence(p, min_anchors=1)["policy_ok"], True)

    @unittest.skipUnless(HAVE_NODE, "node absent")
    def test_js(self):
        src = ("import { verifyEvidence } from %s; const out = [];"
               "for (const v of [0, -1, NaN, 1.5, '2', true]) { try { verifyEvidence(%s, { minAnchors: v }); out.push('accepted'); } catch (e) { out.push(e.name); } }"
               "out.push(verifyEvidence(%s, { minAnchors: 2 }).policy_ok); console.log(JSON.stringify(out));"
               % (json.dumps("file://" + JS), json.dumps(os.path.join(VDIR, "anchor_valid.json")), json.dumps(os.path.join(VDIR, "anchor_valid.json"))))
        r = subprocess.run(["node", "--input-type=module", "-e", src], capture_output=True, text=True)
        self.assertEqual(json.loads(r.stdout), ["TypeError"] * 6 + [False], r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
