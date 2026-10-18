#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.6.0 conformance vectors (SPEC §6.9 states, §6.10, §9.1) and of the `states` block of every
expected file (SPEC §7) — provenance of the frozen files.

Every cell of the SPEC §6.9 table that a pack can produce has a vector here or in the earlier sets. The `states` block of
each NEW vector below is written by hand from the §6.9 table (pre-registered, not copied from a verifier); `--check`
compares it with the reference verifier and stops on any difference. `--states` writes into the EARLIER expected files
the block the reference verifier gives them (their packs are unchanged; the block is reviewed in the 1.6.0 report).

  holder_kb_signature_invalid    KB-JWT signed by another key than cnf.jwk          -> holder_binding contradicted
  holder_sd_hash_mismatch        KB-JWT whose sd_hash commits to another presentation -> holder_binding contradicted
  holder_key_unknown             KB-JWT and no cnf.jwk                               -> holder_binding not_evaluated, valid
  sealed_binding_mismatch        valid_signed with a recorded binding renamed, sealed  -> sealed_content contradicted
  time_token_missing             valid_signed bytes, rfc3161_timestamp anchored with no token -> time_anchor contradicted
  time_tsa_verified              anchor_valid bytes under --tsa-cert (its TSA)       -> time_anchor verified (openssl)
  time_tsa_invalid               anchor_valid bytes under --tsa-cert (another TSA)   -> time_anchor not_evaluated (openssl)
  producer_backend_missing       valid_signed bytes + an entry of an undefined sig_alg -> producer_signature not_evaluated
  producer_trust_set_complete    unpinned_producer bytes + --trust-set-complete       -> policy.unmet trust_set_complete
  issuer_x5c_no_anchor           an x5c-keyed mandate, no --trust-anchor             -> issuer_identity not_evaluated
  issuer_x5c_ca_certified        the same under its CA                               -> issuer_identity verified (openssl)
  issuer_x5c_chain_unresolved    the same under another CA                           -> issuer_identity not_evaluated (openssl)
  issuer_x5c_chain_broken        leaf + intermediate whose signature is altered      -> issuer_identity contradicted (openssl)

  python3 make_vectors_160.py            write the 1.6.0 vectors (fresh keys: rebuild only deliberately)
  python3 make_vectors_160.py --states   write the `states` block of every expected file that lacks it
  python3 make_vectors_160.py --check    compare the hand-written blocks with the reference verifier
"""
import base64
import copy
import datetime
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPENCORE = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _OPENCORE)
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

BASE = {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": True, "pq_protected": False,
        "producer_present": False, "producer_ok": None, "producer_trusted": None, "rfc3161_claimed": False,
        "rfc3161_verified": None, "self_asserted_only": True, "anchors_verified": 0}
NP = {"state": "not_evaluated", "reasons": ["not_present"]}
V = {"state": "verified", "reasons": []}
SA2 = {"state": "not_evaluated", "reasons": ["self_asserted", "self_asserted"]}
SA1 = {"state": "not_evaluated", "reasons": ["self_asserted"]}


def S(sealed, holder, time_, producer, issuer, met=True, unmet=()):
    return {"admission": "admitted", "refusal_class": None,
            "subjects": {"sealed_content": sealed, "holder_binding": holder, "time_anchor": time_,
                         "producer_signature": producer, "issuer_identity": issuer},
            "policy": {"met": met, "unmet": list(unmet)}}


def _load(name):
    with open(os.path.join(_HERE, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)


def _exp(name, desc, policy, states, requires=None, **normative):
    e = {"vector": name, "description": desc, "policy": policy, "normative": dict(BASE, **normative), "states": states}
    if requires:
        e["requires"] = requires
    return e


def states_of_receipt(r: dict) -> dict:
    """The `states` block of an expected file (SPEC §7): what a conformant verifier reproduces — `detail` is free text."""
    subj = r.get("states")
    return {"admission": r.get("admission"), "refusal_class": r.get("refusal_class"),
            "subjects": None if subj is None else {k: {"state": v["state"], "reasons": v["reasons"]} for k, v in subj.items()},
            "policy": r.get("policy")}


# ── x5c material: a root, an intermediate, a leaf (P-256), valid 2026-01-01 .. 2126-01-01 ─────────────────────────
def _x5c_material():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    nb, na = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc), datetime.datetime(2126, 1, 1, tzinfo=datetime.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def cert(subject_cn, pub, issuer_cn, issuer_sk, ca, serial):
        b = (x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn)).public_key(pub)
             .serial_number(serial).not_valid_before(nb).not_valid_after(na)
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                          encipher_only=False, decipher_only=False), critical=True))
        return b.sign(issuer_sk, hashes.SHA256())
    root_sk, other_sk, inter_sk, leaf_sk = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    root = cert("ap2 conformance root CA", root_sk.public_key(), "ap2 conformance root CA", root_sk, True, 1)
    other = cert("ap2 conformance OTHER root CA", other_sk.public_key(), "ap2 conformance OTHER root CA", other_sk, True, 2)
    inter = cert("ap2 conformance intermediate CA", inter_sk.public_key(), "ap2 conformance root CA", root_sk, True, 3)
    leaf = cert("ap2 conformance mandate issuer", leaf_sk.public_key(), "ap2 conformance intermediate CA", inter_sk, False, 4)
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    broken = bytearray(der(inter)); broken[-3] ^= 0x01   # a byte of the intermediate's signature value (the DER ends with it)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)  # noqa: E731
    return {"leaf_sk": leaf_sk, "chain": [der(leaf), der(inter)], "broken_chain": [der(leaf), bytes(broken)],
            "root_pem": pem(root), "other_pem": pem(other)}


def write_vectors() -> None:
    import make_vectors_closed_schema as mc
    base = _load("valid_signed")
    scope = base["honest_scope"]
    nopol = {}
    out = []

    # ── holder_binding ───────────────────────────────────────────────────────────────────────────────────────────
    sk, jwk = mc._signer(); hsk, hjwk = mc._signer(); other_hsk, _ = mc._signer()
    hdr = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk}
    pay = {"iss": "user-wallet", "mandate_type": "cart", "cnf": {"jwk": hjwk}, "items": ["book-123"]}
    pres = mc._sign_jwt(sk, hdr, pay) + "~"
    kb_pay = {"iat": 1760054400, "aud": "merchant-books", "nonce": "n-7f3a", "sd_hash": mc._b64u(hashlib.sha256(pres.encode("ascii")).digest())}
    kb_other_key = mc._sign_jwt(other_hsk, {"alg": "ES256", "typ": "kb+jwt"}, kb_pay)
    out.append(("holder_kb_signature_invalid", mc._pack(scope, "ap2 conformance vector (1.6.0)", [mc._artifact("cart", pres + kb_other_key, hdr, jwk, pay, True)]),
                _exp("holder_kb_signature_invalid",
                     "A holder-bound mandate (cnf.jwk) whose KB-JWT is signed by another key. The KB-JWT verifies false, so the "
                     "artifact fails (SPEC §6 step 2) and the binding set is not recomputed; the issuer signature and the claims "
                     "verify, so sealed_content is verified and holder_binding is contradicted (SPEC §6.9).", nopol,
                     S(V, {"state": "contradicted", "reasons": ["kb_signature_invalid"]}, NP, NP, SA1), bindings_ok=False)))
    kb_bad_hash = mc._sign_jwt(hsk, {"alg": "ES256", "typ": "kb+jwt"}, dict(kb_pay, sd_hash=mc._b64u(hashlib.sha256(b"another presentation~").digest())))
    out.append(("holder_sd_hash_mismatch", mc._pack(scope, "ap2 conformance vector (1.6.0)", [mc._artifact("cart", pres + kb_bad_hash, hdr, jwk, pay, True)]),
                _exp("holder_sd_hash_mismatch",
                     "A KB-JWT signed by the cnf.jwk holder key whose sd_hash commits to another presentation (RFC 9901 §4.3): "
                     "the signature verifies, the commitment does not — holder_binding contradicted, sd_hash_mismatch.", nopol,
                     S(V, {"state": "contradicted", "reasons": ["sd_hash_mismatch"]}, NP, NP, SA1), bindings_ok=False)))
    pay_nc = {"iss": "user-wallet", "mandate_type": "cart", "items": ["book-123"]}
    pres_nc = mc._sign_jwt(sk, hdr, pay_nc) + "~"
    kb_nc = mc._sign_jwt(hsk, {"alg": "ES256", "typ": "kb+jwt"}, dict(kb_pay, sd_hash=mc._b64u(hashlib.sha256(pres_nc.encode("ascii")).digest())))
    out.append(("holder_key_unknown", mc._pack(scope, "ap2 conformance vector (1.6.0)", [mc._artifact("cart", pres_nc + kb_nc, hdr, jwk, pay_nc, True)]),
                _exp("holder_key_unknown",
                     "A KB-JWT and no cnf.jwk in the issuer payload: the holder key is unknown, the KB-JWT is recorded and never "
                     "fails the pack by itself (SPEC §6 step 2) — valid, holder_binding not_evaluated/holder_key_unknown: a check "
                     "that did not run is not painted verified inside sealed_content (SPEC §6.9).", nopol,
                     S(V, {"state": "not_evaluated", "reasons": ["holder_key_unknown"]}, NP, NP, SA1), valid=True)))

    # ── sealed_content: the recorded binding set differs from the recomputed one ─────────────────────────────────
    e = copy.deepcopy(base); e["bindings"][0]["claim"] = "intent_mandate_hash_renamed"
    out.append(("sealed_binding_mismatch", mc.rehash(e),
                _exp("sealed_binding_mismatch",
                     "valid_signed with its recorded binding renamed and the content sealed again (producer signatures dropped): "
                     "every artifact verifies, the recomputed binding set differs (SPEC §4) — sealed_content contradicted, "
                     "binding_mismatch.", nopol,
                     S({"state": "contradicted", "reasons": ["binding_mismatch"]}, NP, NP, NP, SA2), bindings_ok=False)))

    # ── time_anchor ──────────────────────────────────────────────────────────────────────────────────────────────
    e = copy.deepcopy(base); e["rfc3161_timestamp"] = {"anchored": True}
    out.append(("time_token_missing", e,
                _exp("time_token_missing",
                     "valid_signed bytes (sealed content and producer signatures unchanged) with rfc3161_timestamp claiming an "
                     "anchor and carrying no token (SPEC §6 step 4: rfc3161_verified false) — time_anchor contradicted, "
                     "token_missing.", nopol,
                     S(V, NP, {"state": "contradicted", "reasons": ["token_missing"]}, SA2, SA2),
                     producer_present=True, producer_ok=True, pq_protected=True, rfc3161_claimed=True, rfc3161_verified=False)))
    anchor_valid = _load("anchor_valid"); av_exp = _load("anchor_valid.expected")
    av_norm = {k: v for k, v in av_exp["normative"].items()}
    out.append(("time_tsa_verified", anchor_valid,
                _exp("time_tsa_verified",
                     "anchor_valid's bytes verified with --tsa-cert anchor_probe_tsa.crt, the certificate of the TSA that issued "
                     "the token: binding and TSA signature verify — time_anchor verified (SPEC §3.2, §6.9). Needs openssl.",
                     dict(av_exp["policy"], tsa_cert="anchor_probe_tsa.crt"),
                     S(V, NP, V, SA2, SA2), requires=["openssl"], **av_norm)))
    out.append(("time_tsa_invalid", anchor_valid,
                _exp("time_tsa_invalid",
                     "anchor_valid's bytes verified with --tsa-cert anchor_probe_tsa2.crt, a certificate of ANOTHER TSA: the "
                     "binding verifies, the TSA signature does not, so the anchor is not counted (SPEC §3.3) — "
                     "time_anchor not_evaluated/tsa_invalid (the input is not shown altered: another TSA may have issued it).",
                     dict(av_exp["policy"], tsa_cert="anchor_probe_tsa2.crt"),
                     S(V, NP, {"state": "not_evaluated", "reasons": ["tsa_invalid"]}, SA2, SA2), requires=["openssl"],
                     **dict(av_norm, anchors_verified=0))))

    # ── producer_signature ───────────────────────────────────────────────────────────────────────────────────────
    e = copy.deepcopy(base)
    e["producer_signatures"]["signatures"].append({"sig_alg": "slh-dsa-sha2-128s", "public_key_b64": "AAAA", "signature_b64": "AAAA", "post_quantum": False})
    out.append(("producer_backend_missing", e,
                _exp("producer_backend_missing",
                     "valid_signed bytes with a third producer entry whose sig_alg this format does not define: the entry is "
                     "SKIP, the block is not ok and the pack is not valid (SPEC §5) — producer_signature not_evaluated with "
                     "backend_missing for that entry, never contradicted: no check ran on it (SPEC §6.9).", nopol,
                     S(V, NP, NP, {"state": "not_evaluated", "reasons": ["self_asserted", "self_asserted", "backend_missing"]}, SA2),
                     producer_present=True, producer_ok=False)))
    up = _load("unpinned_producer"); up_exp = _load("unpinned_producer.expected")
    out.append(("producer_trust_set_complete", up,
                _exp("producer_trust_set_complete",
                     "unpinned_producer's bytes and pinned set, with --trust-set-complete: the producer keys stay key_unresolved "
                     "(never signature_invalid, SPEC §6.9) and the declared-complete set adds the disposition "
                     "policy.unmet trust_set_complete; policy_ok keeps its 1.5.x meaning (the four 1.5.x policy inputs).",
                     dict(up_exp["policy"], trust_set_complete=True),
                     S(V, NP, NP, {"state": "not_evaluated", "reasons": ["key_unresolved", "key_unresolved"]}, SA2,
                       met=False, unmet=["trusted_producer_keys", "trust_set_complete"]),
                     **up_exp["normative"])))

    # ── issuer_identity ──────────────────────────────────────────────────────────────────────────────────────────
    m = _x5c_material()
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401
    leaf_jwk = ap2._jwk_from_pubkey(m["leaf_sk"].public_key())

    def x5c_pack(chain):
        h = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": [base64.b64encode(c).decode("ascii") for c in chain]}
        p = {"iss": "issuer-bank", "mandate_type": "intent", "max_amount": "150.00 EUR"}
        compact = mc._sign_jwt(m["leaf_sk"], h, p) + "~"
        art = mc._artifact("intent", compact, h, leaf_jwk, p, False)
        art["key"] = {"jwk": leaf_jwk, "provenance_class": "x5c_header", "note": "key from the x5c leaf of the signed header"}
        return mc._pack(scope, "ap2 conformance vector (1.6.0)", [art])
    with open(os.path.join(_HERE, "issuer_ca.crt"), "wb") as f:
        f.write(m["root_pem"])
    with open(os.path.join(_HERE, "issuer_other_ca.crt"), "wb") as f:
        f.write(m["other_pem"])
    good, broken = x5c_pack(m["chain"]), x5c_pack(m["broken_chain"])
    plain_valid = dict(valid=True)
    out.append(("issuer_x5c_no_anchor", good,
                _exp("issuer_x5c_no_anchor",
                     "A mandate whose key is the leaf of an x5c chain in its signed header (leaf, intermediate), no --trust-anchor: "
                     "offline, the certificate proves only what the signer wrote — issuer_identity not_evaluated/no_trust_anchor.",
                     nopol, S(V, NP, NP, NP, {"state": "not_evaluated", "reasons": ["no_trust_anchor"]}), **plain_valid)))
    out.append(("issuer_x5c_ca_certified", good,
                _exp("issuer_x5c_ca_certified",
                     "The same pack under --trust-anchor issuer_ca.crt, the root that issued the intermediate: the chain validates "
                     "— issuer_identity verified with the qualifier ca_certified (a CA under YOUR anchor certified this key, never "
                     "'this is the issuer', SPEC §6 step 7); self_asserted_only false. Needs openssl.",
                     {"trust_anchor": "issuer_ca.crt"},
                     S(V, NP, NP, NP, {"state": "verified", "reasons": ["ca_certified"]}), requires=["openssl"],
                     valid=True, self_asserted_only=False)))
    out.append(("issuer_x5c_chain_unresolved", good,
                _exp("issuer_x5c_chain_unresolved",
                     "The same pack under --trust-anchor issuer_other_ca.crt, a root that did not issue it: the chain does not "
                     "reach the relying party's anchor — issuer_identity not_evaluated/chain_unresolved (krausz §5.4.2: not "
                     "resolved in the relying party's material is not a defect of the input). Needs openssl.",
                     {"trust_anchor": "issuer_other_ca.crt"},
                     S(V, NP, NP, NP, {"state": "not_evaluated", "reasons": ["chain_unresolved"]}), requires=["openssl"], **plain_valid)))
    out.append(("issuer_x5c_chain_broken", broken,
                _exp("issuer_x5c_chain_broken",
                     "An x5c chain whose intermediate certificate carries an altered signature, under --trust-anchor issuer_ca.crt: "
                     "openssl reports a certificate signature failure — issuer_identity contradicted/chain_broken. The pack "
                     "stays valid: a chain never decided `valid` (SPEC §6 step 7, unchanged), so this is the one contradicted "
                     "subject outside the `valid` equation (SPEC §6.9). Needs openssl.",
                     {"trust_anchor": "issuer_ca.crt"},
                     S(V, NP, NP, NP, {"state": "contradicted", "reasons": ["chain_broken"]}), requires=["openssl"], **plain_valid)))

    for name, pack, exp in out:
        _write_json(os.path.join(_HERE, name + ".json"), pack)
        _write_json(os.path.join(_HERE, name + ".expected.json"), exp)


def _run_ref(name):
    import run_ap2_conformance as rc
    exp = rc._load_expected(os.path.join(_HERE, name + ".expected.json"), name)
    return rc.verify_with_policy(ap2.verify_evidence, os.path.join(_HERE, name + ".json"), exp.get("policy", {}), _HERE)


def write_states() -> list:
    """Write the reference's `states` block into every expected file that lacks one (the earlier vectors)."""
    done = []
    for f in sorted(os.listdir(_HERE)):
        if not f.endswith(".expected.json"):
            continue
        name = f[:-len(".expected.json")]
        p = os.path.join(_HERE, f)
        with open(p, encoding="utf-8") as fh:
            exp = json.load(fh)
        if "states" in exp:
            continue
        exp["states"] = states_of_receipt(_run_ref(name))
        _write_json(p, exp); done.append(name)
    return done


def check() -> int:
    bad = 0
    for f in sorted(os.listdir(_HERE)):
        if f.endswith(".expected.json"):
            name = f[:-len(".expected.json")]
            with open(os.path.join(_HERE, f), encoding="utf-8") as fh:
                exp = json.load(fh)
            got = states_of_receipt(_run_ref(name))
            if got != exp.get("states"):
                bad += 1; print("DIFF", name, json.dumps(exp.get("states")), json.dumps(got))
    print("states blocks that differ from the reference:", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == []:
        write_vectors(); print("1.6.0 vectors written to", _HERE)
    elif sys.argv[1:] == ["--states"]:
        print(json.dumps(write_states()))
    elif sys.argv[1:] == ["--check"]:
        raise SystemExit(check())
    else:
        raise SystemExit("usage: make_vectors_160.py [--states | --check]")
