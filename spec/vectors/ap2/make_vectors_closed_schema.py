#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.4.0 conformance vectors (SPEC §9, closed schema) — provenance of the frozen files.

Two families. The DERIVED vectors are computed from the frozen `valid_signed.json` and regenerate byte for byte
(no new key, no clock); the FRESH vectors are signed with keys generated here and are frozen once written, like the
original set (`make_vectors.py`). Run only to rebuild deliberately.

  unknown_key_top_level        valid_signed + a sealed top-level key nobody defined       -> REJECT (refusal, §9.1)
  unknown_key_anchor_block     valid_signed bytes + a key inside rfc3161_timestamp        -> REJECT (refusal, §9.1) — the
                               mutation measured on 2026-10-10 that 1.3.0 verified as valid: true
  unknown_key_producer_entry   valid_signed bytes + a key inside the ML-DSA-65 entry      -> REJECT (FAIL entry, §9.1)
  unknown_key_artifact         valid_signed + a key inside an artifact entry              -> REJECT (artifact error, §9.1)
  key_jwk_member_ignored       valid_signed + an unregistered member in a snapshotted JWK -> ACCEPT, reported (RFC 7517 §4)
  header_param_ignored         a signed header with an unregistered parameter             -> ACCEPT, reported (RFC 7515 §4)
  header_crit_unknown          a signed header with crit naming that parameter            -> REJECT (RFC 7515 §4.1.11)
  kb_jwt_valid                 a holder-bound mandate whose KB-JWT verifies               -> ACCEPT (the KB-JWT positive control)
  kb_jwt_typ_missing           the same KB-JWT without typ: kb+jwt                        -> REJECT (RFC 9901 §4.3)
"""
import base64
import copy
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPENCORE = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _OPENCORE)
import ap2_evidence as ap2  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

REFUSAL = {"valid": False, "digest_ok": False, "bindings_ok": False, "policy_ok": False, "pq_protected": False,
           "producer_present": False, "producer_ok": None, "producer_trusted": None, "rfc3161_claimed": False,
           "rfc3161_verified": None, "self_asserted_only": True}
ACCEPT_PLAIN = {"valid": True, "digest_ok": True, "bindings_ok": True, "policy_ok": True, "pq_protected": False,
                "producer_present": False, "producer_ok": None, "producer_trusted": None, "rfc3161_claimed": False,
                "rfc3161_verified": None, "self_asserted_only": True}
ARTIFACT_ERROR = dict(ACCEPT_PLAIN, valid=False, bindings_ok=False)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _signer():
    sk = ec.generate_private_key(ec.SECP256R1()); n = sk.public_key().public_numbers()
    return sk, {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}


def _sign_jwt(sk, header: dict, payload: dict) -> str:
    si = f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}.{_b64u(json.dumps(payload, separators=(',', ':')).encode())}"
    r, s = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _load(name):
    with open(os.path.join(_HERE, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def _write(name: str, pack: dict, expected: dict) -> None:
    with open(os.path.join(_HERE, f"{name}.json"), "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(_HERE, f"{name}.expected.json"), "w", encoding="utf-8") as f:
        json.dump(expected, f, ensure_ascii=False, indent=1, sort_keys=True)


def _expected(name, desc, policy, normative, report=None):
    # 1.5.0 — SPEC §3.3: the twelfth normative field; none of these vectors carries a verifying anchor besides anchor_valid
    e = {"vector": name, "description": desc, "policy": policy, "normative": {"anchors_verified": 0, **normative}}
    if report is not None:
        e["report"] = report
    return e


def rehash(ev: dict) -> dict:
    """Seal the content again and drop the producer signatures (they signed the old digest)."""
    e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    ev = dict(ev); ev["evidence_digest_sha256"] = hashlib.sha256(ap2._canon(e2)).hexdigest(); ev.pop("producer_signatures", None)
    return ev


def _artifact(name, compact, header, jwk, resolved, kb_present):
    return {"name": name, "sd_jwt_compact": compact, "header": header,
            "key": {"jwk": jwk, "provenance_class": "jwk_header", "note": "key embedded in the protected header (self-asserted)"},
            "resolved_claims": resolved, "kb_jwt": {"present": kb_present},
            "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}


def _pack(scope, subject, artifacts):
    return rehash({"evidence_format": ap2.EVIDENCE_FORMAT, "subject": subject, "created_utc": "2026-10-10T00:00:00Z",
                   "artifacts": artifacts, "bindings": [], "honest_scope": scope})


def main() -> int:
    base = _load("valid_signed"); strict = _load("valid_signed.expected")["policy"]
    nopolicy = {}

    # ── derived from the frozen positive control ───────────────────────────────────────────────────────────────────
    e = copy.deepcopy(base); e["retention_profile"] = "dispute"
    _write("unknown_key_top_level", rehash(e), _expected(
        "unknown_key_top_level",
        "The valid pack SEALED with a top-level key this format does not define (digest recomputed over it, producer "
        "signatures dropped). SPEC §9.1: the top-level object is closed — a refusal naming the key, never a silent pass. "
        "On 1.3.0 this pack was valid: true.", nopolicy, REFUSAL))

    e = copy.deepcopy(base); e["rfc3161_timestamp"]["additional_anchors"] = [{"mechanism": "bitcoin-ots", "ots_b64": "AA=="}]
    _write("unknown_key_anchor_block", e, _expected(
        "unknown_key_anchor_block",
        "The valid pack, bytes unchanged in the sealed content and in the producer signatures, with a key nobody defined "
        "inside rfc3161_timestamp (outside the digest). Measured 2026-10-10 on 1.3.0: valid: true, nothing in the receipt. "
        "SPEC §9.1: refusal naming the key.", strict, REFUSAL))

    e = copy.deepcopy(base); pq = next(s for s in e["producer_signatures"]["signatures"] if s["sig_alg"] == "ml-dsa-65"); pq["kid"] = "producer-2026"
    _write("unknown_key_producer_entry", e, _expected(
        "unknown_key_producer_entry",
        "The valid pack with a key nobody defined inside the ML-DSA-65 producer-signature entry (the signature itself still "
        "verifies). SPEC §9.1: the entry is a closed object, so it is a FAIL entry — the block is not ok, pq_protected is "
        "false, the pack is not valid. On 1.3.0 the entry was PASS.", nopolicy,
        {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": True, "pq_protected": False,
         "producer_present": True, "producer_ok": False, "producer_trusted": None, "rfc3161_claimed": False,
         "rfc3161_verified": None, "self_asserted_only": True}))

    e = copy.deepcopy(base); e["artifacts"][0]["issuer_verified"] = True
    _write("unknown_key_artifact", rehash(e), _expected(
        "unknown_key_artifact",
        "The valid pack SEALED with a key nobody defined inside an artifact entry — a claim a relying party could read as "
        "evidence. SPEC §9.1: the entry is closed, so it is that artifact's error and the pack is not valid.",
        nopolicy, ARTIFACT_ERROR))

    e = copy.deepcopy(base); e["artifacts"][0]["key"]["jwk"]["ext"] = "x"
    _write("key_jwk_member_ignored", rehash(e), _expected(
        "key_jwk_member_ignored",
        "The valid pack SEALED with an unregistered member inside a snapshotted JWK. A JWK is RFC 7517's object, and §4 "
        "says members not understood MUST be ignored — so the pack is valid and the member is REPORTED in "
        "artifacts[0].ignored.key_jwk (SPEC §9.2).", nopolicy, ACCEPT_PLAIN,
        report={"ignored": [{"key_jwk": ["ext"]}, {}]}))

    # ── fresh keys ─────────────────────────────────────────────────────────────────────────────────────────────────
    sk, jwk = _signer()
    hdr = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk, "ap2_ext": "x"}
    pay = {"iss": "user-wallet", "mandate_type": "intent", "max_amount": "150.00 EUR"}
    compact = _sign_jwt(sk, hdr, pay) + "~"
    _write("header_param_ignored", _pack(base["honest_scope"], "ap2 conformance vector (closed schema)", [_artifact("intent", compact, hdr, jwk, pay, False)]),
           _expected("header_param_ignored",
                     "A signed header carrying a parameter JOSE does not register (ap2_ext). RFC 7515 §4: not understood, not "
                     "in crit -> MUST be ignored. The pack is valid and the name is REPORTED in artifacts[0].ignored.header "
                     "(SPEC §9.2).", nopolicy, ACCEPT_PLAIN, report={"ignored": [{"header": ["ap2_ext"]}]}))

    hdr_c = dict(hdr, crit=["ap2_ext"])
    compact_c = _sign_jwt(sk, hdr_c, pay) + "~"
    _write("header_crit_unknown", _pack(base["honest_scope"], "ap2 conformance vector (closed schema)", [_artifact("intent", compact_c, hdr_c, jwk, pay, False)]),
           _expected("header_crit_unknown",
                     "The same header with crit: [\"ap2_ext\"]. RFC 7515 §4.1.11: an extension named in crit that the recipient "
                     "does not understand makes the JWS INVALID — this format understands no extension, so the artifact errors "
                     "and the pack is not valid (SPEC §9.2).", nopolicy, ARTIFACT_ERROR))

    hsk, hjwk = _signer()
    hdr_k = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk}
    pay_k = {"iss": "user-wallet", "mandate_type": "cart", "cnf": {"jwk": hjwk}, "items": ["book-123"]}
    presentation = _sign_jwt(sk, hdr_k, pay_k) + "~"
    kb_pay = {"iat": 1760054400, "aud": "merchant-books", "nonce": "n-7f3a", "sd_hash": _b64u(hashlib.sha256(presentation.encode("ascii")).digest())}
    kb_ok = _sign_jwt(hsk, {"alg": "ES256", "typ": "kb+jwt"}, kb_pay)
    _write("kb_jwt_valid", _pack(base["honest_scope"], "ap2 conformance vector (closed schema)", [_artifact("cart", presentation + kb_ok, hdr_k, jwk, pay_k, True)]),
           _expected("kb_jwt_valid",
                     "A holder-bound mandate: the issuer payload carries cnf.jwk and the KB-JWT (typ kb+jwt; iat, aud, nonce, "
                     "sd_hash present — RFC 9901 §4.3) verifies under it. The positive control of the KB-JWT path: a verifier "
                     "that rejects every KB-JWT fails here.", nopolicy, ACCEPT_PLAIN, report={"ignored": [{}]}))

    kb_notyp = _sign_jwt(hsk, {"alg": "ES256"}, kb_pay)
    _write("kb_jwt_typ_missing", _pack(base["honest_scope"], "ap2 conformance vector (closed schema)", [_artifact("cart", presentation + kb_notyp, hdr_k, jwk, pay_k, True)]),
           _expected("kb_jwt_typ_missing",
                     "The same holder-bound mandate whose KB-JWT header has no typ. RFC 9901 §4.3: typ REQUIRED, MUST be kb+jwt "
                     "(§7.3 step 5.d). The signature would verify; the artifact errors anyway and the pack is not valid "
                     "(SPEC §9.2). On 1.3.0 this pack was valid: true.", nopolicy, ARTIFACT_ERROR))
    print("closed-schema vectors written to", _HERE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
