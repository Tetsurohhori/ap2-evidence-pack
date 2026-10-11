#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.5.0 conformance vectors (SPEC §3.3, `anchors`) — provenance of the frozen files.

Every vector is DERIVED from the frozen `valid_signed.json` / `anchor_valid.json` (same sealed content, same producer
signatures: `anchors` lies outside the digest). The new tokens come from a second probe TSA created here with openssl
(self-signed, extendedKeyUsage critical timeStamping, 20 years; its certificate ships as `anchor_probe_tsa2.crt`, its key
is not kept), so the files are frozen once written. Each expected verdict is written from SPEC §3.3, not from a verifier.

  anchors_two_valid           anchor_valid + a token from a second TSA, min_anchors 2  -> ACCEPT, anchors_verified 2
  anchors_copied_token        anchor_valid + its OWN token again, min_anchors 2        -> REJECT on policy (one anchor, not two)
  anchors_min_not_met         anchor_valid alone, min_anchors 2                        -> REJECT on policy
  anchors_only                valid_signed + one token in `anchors` only, require_anchor -> ACCEPT (no rfc3161_timestamp token)
  anchors_entry_garbage       anchor_valid + an entry whose token is not a TimeStampResp -> REJECT (a failing anchor fails the pack)
  anchors_entry_wrong_digest  anchor_valid + a real token for another digest           -> REJECT (imprint mismatch)
  anchors_unknown_mechanism   anchor_valid + {"mechanism": "bitcoin-ots", ...}          -> REJECT (refusal naming it)
  anchors_unknown_key         anchor_valid + an rfc3161 entry with a key nobody defined -> REJECT (refusal naming it)
  anchors_empty               anchor_valid + "anchors": []                              -> REJECT (refusal)
"""
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))

REFUSAL = {"valid": False, "digest_ok": False, "bindings_ok": False, "policy_ok": False, "pq_protected": False,
           "producer_present": False, "producer_ok": None, "producer_trusted": None, "rfc3161_claimed": False,
           "rfc3161_verified": None, "self_asserted_only": True, "anchors_verified": 0}


def _load(name):
    with open(os.path.join(_HERE, name), encoding="utf-8") as f:
        return json.load(f)


def _write(name, pack, desc, policy, normative, refused=None):
    with open(os.path.join(_HERE, f"{name}.json"), "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(_HERE, f"{name}.expected.json"), "w", encoding="utf-8") as f:
        exp = {"vector": name, "description": desc, "policy": policy, "normative": normative}
        if refused is not None:   # SPEC §7: the exact refusal text — any refusal is not enough (a 1.4.x verifier refuses these too, for another reason)
            exp["report"] = {"refused": refused}
        json.dump(exp, f, ensure_ascii=False, indent=1, sort_keys=True)


class ProbeTSA:
    """A throwaway RFC 3161 TSA: openssl `ts -reply` with a self-signed timeStamping certificate."""

    def __init__(self, d):
        self.d = d
        self.key, self.crt = os.path.join(d, "tsa.key"), os.path.join(d, "tsa.crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", self.key, "-out", self.crt, "-days", "7300", "-subj", "/CN=probe TSA 2",
                        "-addext", "extendedKeyUsage=critical,timeStamping", "-addext", "basicConstraints=critical,CA:FALSE",
                        "-addext", "keyUsage=critical,digitalSignature"], check=True, capture_output=True)
        with open(os.path.join(d, "serial"), "w") as f:
            f.write("01\n")
        self.cnf = os.path.join(d, "tsa.cnf")
        with open(self.cnf, "w") as f:
            f.write(f"""[ tsa ]
default_tsa = t
[ t ]
dir = {d}
serial = {d}/serial
crypto_device = builtin
signer_cert = {self.crt}
signer_key = {self.key}
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")

    def token_b64(self, digest_hex):
        q, r = os.path.join(self.d, "q.tsq"), os.path.join(self.d, "r.tsr")
        subprocess.run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q], check=True, capture_output=True)
        subprocess.run(["openssl", "ts", "-reply", "-config", self.cnf, "-queryfile", q, "-out", r], check=True, capture_output=True)
        with open(r, "rb") as f:
            return base64.b64encode(f.read()).decode()


def main() -> int:
    valid_signed, anchor_valid = _load("valid_signed.json"), _load("anchor_valid.json")
    vs_exp, av_exp = _load("valid_signed.expected.json"), _load("anchor_valid.expected.json")
    assert valid_signed["evidence_digest_sha256"] == anchor_valid["evidence_digest_sha256"]
    digest = anchor_valid["evidence_digest_sha256"]
    d = tempfile.mkdtemp(prefix="ap2-tsa2-")
    try:
        tsa = ProbeTSA(d)
        shutil.copy(tsa.crt, os.path.join(_HERE, "anchor_probe_tsa2.crt"))
        tok2 = tsa.token_b64(digest)
        other = tsa.token_b64(hashlib.sha256(b"another pack").hexdigest())
    finally:
        shutil.rmtree(d, ignore_errors=True)   # the probe key is not kept: these tokens are frozen as written

    av_norm = av_exp["normative"]

    def with_anchors(base, entries):
        p = copy.deepcopy(base); p["anchors"] = entries; return p

    _write("anchors_two_valid", with_anchors(anchor_valid, [{"mechanism": "rfc3161", "tsr_b64": tok2, "tsa_url": "probe-tsa-2"}]),
           "anchor_valid plus a token from a second probe TSA (certificate anchor_probe_tsa2.crt) in `anchors`: two DISTINCT "
           "anchors bound to the recomputed digest, so min_anchors 2 is met (SPEC §3.3). The sealed content and the producer "
           "signatures are those of anchor_valid: `anchors` lies outside the digest.",
           {"min_anchors": 2}, dict(av_norm, anchors_verified=2))
    _write("anchors_copied_token", with_anchors(anchor_valid, [{"mechanism": "rfc3161", "tsr_b64": anchor_valid["rfc3161_timestamp"]["tsr_b64"]}]),
           "anchor_valid with its own rfc3161_timestamp token copied into `anchors`: the same token bytes are ONE anchor "
           "(SPEC §3.3), so min_anchors 2 is not met and the pack is not valid on policy alone.",
           {"min_anchors": 2}, dict(av_norm, anchors_verified=1, policy_ok=False, valid=False))
    _write("anchors_min_not_met", copy.deepcopy(anchor_valid),
           "anchor_valid unchanged under min_anchors 2: one verified anchor, two required — rejected on policy (SPEC §3.3).",
           {"min_anchors": 2}, dict(av_norm, anchors_verified=1, policy_ok=False, valid=False))
    vs_pol = dict(vs_exp["policy"], require_anchor=True)
    _write("anchors_only", with_anchors(valid_signed, [{"mechanism": "rfc3161", "tsr_b64": tok2}]),
           "valid_signed (rfc3161_timestamp not anchored) with one token in `anchors` only, under require_anchor and the "
           "valid_signed producer policy: the anchor counts wherever it is carried (SPEC §3.3).",
           vs_pol, dict(vs_exp["normative"], rfc3161_claimed=True, rfc3161_verified=True, anchors_verified=1))
    _write("anchors_entry_garbage", with_anchors(anchor_valid, [{"mechanism": "rfc3161", "tsr_b64": base64.b64encode(b"not a TimeStampResp").decode()}]),
           "anchor_valid plus an `anchors` entry whose token is not a TimeStampResp: a claimed anchor that fails rejects the "
           "pack even though the rfc3161_timestamp token verifies — an anchor is never ignored because another one verifies "
           "(SPEC §3.3).",
           {}, dict(av_norm, rfc3161_verified=False, valid=False, anchors_verified=1))
    _write("anchors_entry_wrong_digest", with_anchors(anchor_valid, [{"mechanism": "rfc3161", "tsr_b64": other}]),
           "anchor_valid plus a REAL granted token from the second probe TSA for another digest: the messageImprint does not "
           "equal the recomputed digest, so that anchor fails and so does the pack (SPEC §3.2, §3.3).",
           {}, dict(av_norm, rfc3161_verified=False, valid=False, anchors_verified=1))
    _write("anchors_unknown_mechanism", with_anchors(anchor_valid, [{"mechanism": "bitcoin-ots", "proof_b64": "AAAA"}]),
           "anchor_valid plus an entry whose mechanism this revision does not define: a refusal naming it — never skipped, "
           "so the pack cannot look as if it carried an anchor nobody checked (SPEC §3.3).",
           {}, REFUSAL, refused='anchors[0]: mechanism "bitcoin-ots" is not defined by this revision (SPEC §3.3)')
    _write("anchors_unknown_key", with_anchors(anchor_valid, [{"mechanism": "rfc3161", "tsr_b64": tok2, "x_unknown_2026": 1}]),
           "anchor_valid plus an rfc3161 entry carrying a key nobody defined: the entry is a closed object, so this is a "
           "refusal naming the key (SPEC §9.1).",
           {}, REFUSAL, refused='anchors[0]: unknown key "x_unknown_2026" (SPEC §9.1)')
    _write("anchors_empty", with_anchors(anchor_valid, []),
           "anchor_valid plus an empty `anchors` list: when present it MUST be non-empty — a refusal (SPEC §3.3).",
           {}, REFUSAL, refused="top level: anchors must be a non-empty list (SPEC §9.1)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
