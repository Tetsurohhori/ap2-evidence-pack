#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ap2-evidence-pack — dispute evidence for agentic-payment mandates (standalone).

SPDX-License-Identifier: Apache-2.0
Copyright 2026 Roberto Locatelli

Relicensed by the copyright holder from the AGPL original in the OMEGA/CryptoValid
repository, to match the Apache-2.0 licensing of the AP2 ecosystem.

WHY (measured, 2026-08-21): the AP2 spec (Agent Payments Protocol, ap2-protocol.org) tells
implementers WHAT to keep for dispute resolution — "storing the SD-JWTs, along with their
disclosures, for the Mandates in their compact serialization" — but not HOW: no retention
mechanics, no issuer-key snapshotting, no long-term validation, no tamper-evidence; mandate
retrieval is declared outside the scope. An ECDSA JWT is verifiable at dispute time ONLY if
the issuer's key material is still resolvable; years later JWKS endpoints die and keys rotate.

WHAT THIS IS (deliberately thin — an adversarial review killed the "full vault" idea):
a library + CLI that turns a set of AP2-style SD-JWT mandates into ONE self-contained
evidence file that verifies OFFLINE years later:
  - parses SD-JWT compact serialization (issuer-JWT ~ disclosure* ~ [kb-jwt]) and resolves
    selective disclosures fail-closed (unmatched/duplicate/malformed disclosure -> reject);
  - verifies the ES256 (ECDSA P-256) signature and SNAPSHOTS the key material used, tagging
    it with an explicit PROVENANCE CLASS instead of pretending all captures are equal:
      x5c_header          key from the JWT's x5c leaf cert (chain recorded, PKI path NOT
                          validated to a trust anchor here — declared)
      jwk_header          key embedded in the protected header (self-asserted)
      supplied            key material handed in by the caller (caller vouches)
      jwks_fetched        key fetched from an https JWKS URL at build time (TLS witness
                          at capture — a witness, not a proof of issuer control)
  - discovers hash BINDINGS between artifacts (e.g. a cart mandate committing to the
    checkout_jwt) by recomputing sha-256 over each artifact's exact compact serialization
    and matching it against every string claim of the others — the primary quantity,
    not a proxy field;
  - seals everything into a canonical JSON evidence file with a SHA-256 digest and an
    OPTIONAL RFC 3161 timestamp (inlined TSA client; re-check = binding, plus the TSA's
    signature/chain with `--tsa-cert`), so the "key material existed and verified at
    time T" claim can be anchored to a third party.

HONEST SCOPE: proves that these exact artifacts, with this key material, verified at
build time, and (if stamped and the TSA verified against its certificate) that all of
it existed at the TSA's time — offline,
vendor-free, years later. It does NOT prove the issuer authorised the key (that is the
provenance class's job to DECLARE), does NOT confer eIDAS art. 45j qualified-archive legal
presumption (a QTSP service does), and validates x5c chains only when the relying party supplies a trust anchor
(`--trust-anchor`, SPEC §6.7): nothing about a chain is sealed in the file itself.
ES256 only, by design; other algs are rejected loudly, never half-verified.

Usage:
  python3 ap2_evidence.py build out.json checkout=checkout.sdjwt payment=payment.sdjwt \
          [--key name=jwk.json] [--jwks-url name=https://...] [--tsa URL]
  python3 ap2_evidence.py verify out.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
for _pqc in ("pqcrypto", "ap2_pqcrypto"):        # the clone has pqcrypto/; the wheel installs it as ap2_pqcrypto/ (1.3.0)
    if os.path.isfile(os.path.join(_HERE, _pqc, "sigsuite.py")):   # the file, not the directory: PyPI's pqcrypto/ may sit beside the wheel
        sys.path.insert(0, os.path.join(_HERE, _pqc))
        break
import sigsuite as _sigsuite  # noqa: E402  (crypto-agile hybrid classical + ML-DSA-65 producer signatures)

EVIDENCE_FORMAT = "ap2-evidence-pack/1.0"

HONEST_SCOPE = (
    "Proves: these exact SD-JWT artifacts, with the snapshotted key material (see each "
    "key's provenance_class), verified at build time; the RFC 3161 token (if present) binds this digest to a "
    "TimeStampResp, and attests the TSA's clock only once the relying party has verified the TSA's signature "
    "(--tsa-cert): a self-issued token satisfies the binding alone. Does NOT prove the issuer authorised "
    "the key beyond what the provenance class states, does NOT confer eIDAS qualified-"
    "archive legal presumption, and does NOT by itself validate x5c chains to a trust anchor "
    "— that is an act of the relying party at verification time, with `--trust-anchor`, reported in "
    "`chain_verified` and in each artifact's `x5c_leaf` (SPEC §6.7): the x5c bytes are sealed inside the signed header, the "
    "validation RESULT never is — and "
    "never proves the truth of the recorded transaction itself. When a producer signature is present, it protects the SEALED CONTENT (the file minus the digest, the anchor block and the signatures themselves - so a removed or downgraded time anchor is caught only under a require-anchor policy), and authenticity ONLY for a relying party that has PINNED the producer public key out of band (an embedded key alone proves consistency, not authenticity), across the retention window (hybrid: a classical signature + FIPS-204 ML-DSA-65, surviving the quantum transition per NIST IR 8547); it does NOT retro-protect the underlying ES256 mandate signature - for the existed-before-a-quantum-adversary claim you still need a trusted time anchor (RFC 3161 / RFC 4998 renewal). 'valid' means each "
    "artifact verifies and the SEALED CONTENT is intact — NOT that the file as a whole is unaltered (the anchor block lies "
    "outside the digest), NOT that the mandates form a bound "
    "chain (read `bindings`) nor that self-asserted keys prove issuer identity (read "
    "`provenance_classes`/`self_asserted_only`). KB-JWT holder binding is verified "
    "when the issuer payload carries cnf.jwk; without cnf.jwk it is recorded as "
    "present-but-unverifiable, never painted green. KB-JWT aud/nonce/iat are RECORDED "
    "for the auditor, not validated — their expected values are transaction context "
    "this tool cannot know offline.")

HONEST_SCOPE_SHA256 = hashlib.sha256(HONEST_SCOPE.encode("utf-8")).hexdigest()   # r8: pinned in SPEC §1, so both verifiers refuse a rewritten scope


class Ap2EvidenceError(ValueError):
    """Fail-closed parse/verify error (message is auditor-readable, never a traceback)."""


class Ap2WriteError(Ap2EvidenceError, OSError):
    """1.5.2 — the output file (the pack `build` writes, the pack `stamp` rewrites) could not be written. Also an OSError,
    which is what `build_evidence` raised there before. The CLI exits 74 (EX_IOERR) on it, whatever the outcome was."""


# ────────────────────────────────────────────────────────── b64url / hashing

def _no_dup_pairs(pairs):
    """Reject duplicate JSON object keys: a crafted pack could otherwise carry two
    values for one key (parser keeps the last) so its meaning diverges from its digest."""
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Ap2EvidenceError(f"duplicate JSON key {k!r} (rejected fail-closed)")
        seen[k] = v
    return seen


# ── acceptance profile of the evidence file (1.1.0; SPEC §3): what cannot be re-serialised byte for byte by every
# JSON implementation is refused, so a third-party verifier computes the same canonical bytes or refuses the same file.
MAX_JSON_DEPTH = 512
MAX_EVIDENCE_BYTES = 64 << 20
_SAFE_INT = (1 << 53) - 1


def _no_float(text: str):
    raise Ap2EvidenceError(f"float {text!r} in the evidence file (not portable: use a string)")


def _bounded_int(text: str) -> int:
    v = int(text)
    if abs(v) > _SAFE_INT:
        raise Ap2EvidenceError("integer outside the portable range +/-(2^53-1)")
    return v


def _no_constant(name: str):
    raise Ap2EvidenceError(f"non-JSON constant {name}")


def _nesting_depth(text: str) -> int:
    depth = mx = 0; in_str = esc = False
    for ch in text:
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == '"': in_str = False
        elif ch == '"': in_str = True
        elif ch in "[{":
            depth += 1; mx = max(mx, depth)
        elif ch in "]}": depth -= 1
    return mx


def _hex4(s: str, i: int):
    h = s[i:i + 4]
    return int(h, 16) if len(h) == 4 and all(c in "0123456789abcdefABCDEF" for c in h) else None


def _has_lone_surrogate(text: str) -> bool:
    i, n = 0, len(text)
    while i < n:
        if text[i] != "\\":
            i += 1; continue
        if i + 1 < n and text[i + 1] == "u" and i + 5 < n:
            cp = _hex4(text, i + 2)
            if cp is None:
                i += 2; continue
            if 0xD800 <= cp <= 0xDBFF:
                if i + 7 >= n or text[i + 6] != "\\" or text[i + 7] != "u": return True
                lo = _hex4(text, i + 8)
                if lo is None or not (0xDC00 <= lo <= 0xDFFF): return True
                i += 12; continue
            if 0xDC00 <= cp <= 0xDFFF: return True
            i += 6; continue
        i += 2
    return False


def loads_strict(text: str):
    """Strict JSON for the evidence file: no duplicate keys, no floats, integers within +/-(2^53-1), no NaN/Infinity,
    nesting <= 512 by linear pre-scan, no lone UTF-16 surrogate escape. Raises Ap2EvidenceError."""
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise Ap2EvidenceError(f"json_too_deep: nesting exceeds {MAX_JSON_DEPTH}")
    if _has_lone_surrogate(text):
        raise Ap2EvidenceError("lone_surrogate: unpaired UTF-16 surrogate escape")
    try:
        return json.loads(text, object_pairs_hook=_no_dup_pairs, parse_float=_no_float, parse_int=_bounded_int, parse_constant=_no_constant)
    except RecursionError as e:
        raise Ap2EvidenceError("json_too_deep") from e
    except ValueError as e:
        if isinstance(e, Ap2EvidenceError): raise
        raise Ap2EvidenceError(f"not JSON: {str(e)[:80]}") from e


_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)


def read_evidence_file(path: str):
    """Read + decode + parse the evidence file under the profile. UTF-8 strict (a raw byte is a refusal, never U+FFFD),
    a size bound before reading, an unreadable path is a refusal — all Ap2EvidenceError, never a traceback.
    The file is opened WITHOUT blocking and read only if the OPEN descriptor is a regular file, at most
    MAX_EVIDENCE_BYTES bytes: measured 25/09/2026, a FIFO in its place blocked both verifiers and a symlink to /dev/zero
    passed the size check (a device reports size 0) and was read until memory ran out, in both."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):   # refused BEFORE it is opened (opening a device can act on it)
            raise Ap2EvidenceError("unreadable evidence file: not a regular file")
        fd = os.open(path, _OPEN_FLAGS)
        try:                                          # fstat on the open descriptor: closes the race with a swap in between
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Ap2EvidenceError("unreadable evidence file: not a regular file")
            if st.st_size > MAX_EVIDENCE_BYTES:
                raise Ap2EvidenceError(f"evidence file exceeds {MAX_EVIDENCE_BYTES} bytes")
            with os.fdopen(os.dup(fd), "rb") as f:
                raw = f.read(MAX_EVIDENCE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_EVIDENCE_BYTES:   # a file that grows while it is read is refused, never buffered past the bound
            raise Ap2EvidenceError(f"evidence file exceeds {MAX_EVIDENCE_BYTES} bytes")
    except OSError as e:
        raise Ap2EvidenceError(f"unreadable evidence file: {type(e).__name__}") from e
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Ap2EvidenceError("evidence file is not valid UTF-8") from e
    if text.startswith("\ufeff"):
        raise Ap2EvidenceError("evidence file starts with a BOM")
    ev = loads_strict(text)
    if not isinstance(ev, dict):
        raise Ap2EvidenceError("evidence file is not a JSON object")
    return ev


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _loads_segment(raw: bytes, what: str):
    """JWT-level JSON (header, payload, disclosure, KB-JWT) under the SAME profile as the evidence file (SPEC §3.1): strict
    UTF-8, no BOM, no duplicate keys, no floats/NaN, bounded integers, bounded depth. 1.1.0 r2: the reference used
    `json.loads` here (last duplicate key wins, BOM skipped) while the JS verifier was strict — a signed payload
    `{"amount":"1","amount":"999"}` certified "999" in one verifier and was refused in the other."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Ap2EvidenceError(f"{what} is not valid UTF-8") from e
    if text.startswith("\ufeff"):
        raise Ap2EvidenceError(f"{what} starts with a BOM")
    return loads_strict(text)


def _b64url_decode(s: str) -> bytes:
    """RFC 7515 base64url, strict: alphabet only, no padding, no whitespace, canonical trailing bits (1.1.0: whitespace was
    stripped and padding added silently, so a segment could be spelled several ways for one meaning)."""
    if not isinstance(s, str) or not s or any(c not in _B64URL for c in s) or len(s) % 4 == 1:
        raise Ap2EvidenceError("invalid base64url segment")
    pad = -len(s) % 4
    try:
        raw = base64.urlsafe_b64decode(s + "=" * pad)
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"invalid base64url segment: {type(e).__name__}") from e
    if _b64url(raw) != s:
        raise Ap2EvidenceError("non-canonical base64url segment (trailing bits)")
    return raw


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sha256_b64url(data: bytes) -> str:
    return _b64url(hashlib.sha256(data).digest())


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ────────────────────────────────────────────────────────── SD-JWT parsing

def parse_sd_jwt(compact: str) -> Dict:
    """Split an SD-JWT compact serialization: <jwt>~<disclosure>*~[<kb-jwt>].
    A trailing '~' means no key-binding JWT. Returns raw parts, decoded header/payload."""
    compact = compact.strip()
    if "~" in compact:
        parts = compact.split("~")
        jwt, middle, kb = parts[0], parts[1:-1], parts[-1] or None
    else:
        jwt, middle, kb = compact, [], None
    seg = jwt.split(".")
    if len(seg) != 3:
        raise Ap2EvidenceError("issuer JWT must have 3 dot-separated segments")
    try:
        header = _loads_segment(_b64url_decode(seg[0]), "JWT header")
        payload = _loads_segment(_b64url_decode(seg[1]), "JWT payload")
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"JWT header/payload not valid JSON/base64url: {e}") from e
    return {"compact": compact, "jwt": jwt, "header": header, "payload": payload,
            "signature": _b64url_decode(seg[2]),
            "signing_input": f"{seg[0]}.{seg[1]}".encode("ascii"),
            "disclosures": [d for d in middle if d], "kb_jwt": kb}


def _disclosure_digest(disclosure_b64: str) -> str:
    # SD-JWT: digest = b64url(sha-256(ASCII of the base64url-encoded disclosure))
    return _sha256_b64url(disclosure_b64.encode("ascii"))


def resolve_disclosures(payload: Dict, disclosures: List[str]) -> Dict:
    """Replace _sd digests / '...' array placeholders with the disclosed claims.
    Fail-closed: duplicate digests, malformed disclosures, or disclosures that match
    nothing are ERRORS (per SD-JWT processing rules), never silently ignored."""
    # 1.1.0 r2: the SHAPE of the SD-JWT fields is imposed (present-with-null is not absent — `dict.get(k, default)` and
    # JS `??` disagreed): `_sd_alg` absent or exactly "sha-256"; `_sd` absent or a list of strings; `{"...": x}` with x a string
    if "_sd_alg" in payload and payload["_sd_alg"] != "sha-256":
        raise Ap2EvidenceError(f"_sd_alg {payload['_sd_alg']!r} unsupported (sha-256 only, declared)")
    by_digest: Dict[str, Tuple[str, list]] = {}
    for d in disclosures:
        try:
            arr = _loads_segment(_b64url_decode(d), "disclosure")
        except (ValueError, Ap2EvidenceError) as e:
            raise Ap2EvidenceError(f"malformed disclosure: {e}") from e
        if not isinstance(arr, list) or len(arr) not in (2, 3):
            raise Ap2EvidenceError("disclosure must be [salt,name,value] or [salt,value]")
        dig = _disclosure_digest(d)
        if dig in by_digest:
            raise Ap2EvidenceError("duplicate disclosure digest (rejected fail-closed)")
        by_digest[dig] = (d, arr)
    used = set()

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k in ("_sd", "_sd_alg"):
                    continue
                out[k] = walk(v)
            sd = node.get("_sd", [])
            if not isinstance(sd, list) or any(not isinstance(x, str) for x in sd):
                raise Ap2EvidenceError("_sd must be a list of digest strings")
            for dig in sd:
                if dig in by_digest:
                    d, arr = by_digest[dig]
                    if len(arr) != 3:
                        raise Ap2EvidenceError("object disclosure must be [salt,name,value]")
                    if not isinstance(arr[1], str):
                        raise Ap2EvidenceError("disclosed claim name must be a string")
                    if arr[1] in out:
                        raise Ap2EvidenceError(f"disclosed claim {arr[1]!r} collides")
                    out[arr[1]] = walk(arr[2])
                    used.add(dig)
            return out
        if isinstance(node, list):
            out_l = []
            for item in node:
                if isinstance(item, dict) and set(item.keys()) == {"..."}:
                    dig = item["..."]
                    if not isinstance(dig, str):
                        raise Ap2EvidenceError("array disclosure placeholder must be a digest string")
                    if dig in by_digest:
                        d, arr = by_digest[dig]
                        if len(arr) != 2:
                            raise Ap2EvidenceError("array disclosure must be [salt,value]")
                        out_l.append(walk(arr[1]))
                        used.add(dig)
                    # undisclosed array element: omitted (that is selective disclosure)
                else:
                    out_l.append(walk(item))
            return out_l
        return node

    resolved = walk(payload)
    unused = set(by_digest) - used
    if unused:
        raise Ap2EvidenceError(f"{len(unused)} disclosure(s) match no digest in the "
                               "payload (rejected fail-closed)")
    return resolved


# ────────────────────────────────────────────────────────── ES256 verification

def _pubkey_from_jwk(jwk: Dict):
    from cryptography.hazmat.primitives.asymmetric import ec
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise Ap2EvidenceError("only EC/P-256 JWKs are supported (ES256, declared)")
    xb, yb = _b64url_decode(jwk.get("x")), _b64url_decode(jwk.get("y"))
    if len(xb) != 32 or len(yb) != 32:   # RFC 7518 §6.2.1.2-3: the full octet length of the coordinate (r2: 31/33 bytes verified here, refused by JS)
        raise Ap2EvidenceError("JWK x/y must be exactly 32 bytes")
    x = int.from_bytes(xb, "big")
    y = int.from_bytes(yb, "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _load_x5c_leaf(x5c: List[str]):
    """The leaf CERTIFICATE (not just its key): r7 also reads subject/issuer, to tell a self-signed leaf (still self-asserted)
    from one someone else issued."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    try:   # r7: a leaf wrapped at 76 columns, not a certificate, or not a string used to be a bare ValueError -> traceback out of `build`
        leaf = x509.load_der_x509_certificate(_sigsuite._unb64(x5c[0]))   # r6: strict RFC 4648 — b64decode() dropped a space/newline, the JS verifier refused it
    except Ap2EvidenceError:
        raise
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"x5c leaf is not a strict-base64 DER certificate: {type(e).__name__}") from e
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise Ap2EvidenceError("x5c leaf key is not EC P-256 (ES256 only, declared)")
    return leaf


def _pubkey_from_x5c_leaf(x5c: List[str]):
    return _load_x5c_leaf(x5c).public_key()


def _jwk_from_pubkey(pub) -> Dict:
    nums = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": _b64url(nums.x.to_bytes(32, "big")),
            "y": _b64url(nums.y.to_bytes(32, "big"))}


def verify_es256(signing_input: bytes, signature: bytes, jwk: Dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(signature) != 64:
        raise Ap2EvidenceError(f"ES256 signature must be 64 bytes, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        _pubkey_from_jwk(jwk).verify(encode_dss_signature(r, s), signing_input,
                                     ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


PROVENANCE_CLASSES = frozenset({"supplied", "x5c_header", "jwk_header", "jwks_fetched"})

# ── closed schema (SPEC §9, 1.4.0). Measured 2026-10-10 on 1.3.0: a key nobody defined, inside rfc3161_timestamp, the
# producer block or a signature entry, was accepted with valid: true and no trace in the receipt. Every object this format
# defines is now an exhaustive key list (§9.1: unknown = refusal / artifact error / FAIL entry, with the key named); every
# object a standard defines follows that standard's rule for the unknown (§9.2: ignored AND reported).
_JOSE_HEADER_REGISTERED = frozenset({"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"})   # RFC 7515 §4.1, RFC 7519 §5
_JWK_REGISTERED = frozenset({"kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "d"})   # RFC 7517 §4, RFC 7518 §6.2
_CNF_REGISTERED = frozenset({"jwk", "jwe", "jku", "kid"})                                                                     # RFC 7800 §3.1
_KB_CLAIMS_REGISTERED = frozenset({"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "sd_hash"})                      # RFC 7519 §4.1, RFC 9901 §4.3


def _is_str(v): return isinstance(v, str)
def _is_bool(v): return isinstance(v, bool)
def _is_obj(v): return isinstance(v, dict)
def _is_list(v): return isinstance(v, list)
def _is_str_or_none(v): return v is None or isinstance(v, str)
def _is_bool_or_none(v): return v is None or isinstance(v, bool)
def _is_true(v): return v is True
def _is_list_of_str(v): return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _jkey(k) -> str:
    return json.dumps(k, ensure_ascii=False)   # the same spelling as JSON.stringify in the JS verifier


def _check_closed(obj, what: str, allowed: Dict[str, tuple], err=None):
    """SPEC §9.1: `allowed` maps every key of the object to (predicate, description, required). An object that is not a
    dict, a key outside `allowed`, a wrong type or a missing required key raises `err` (Ap2EvidenceError by default) with
    the object and the key named — the same three messages the JS verifier produces."""
    err = err or Ap2EvidenceError
    if not isinstance(obj, dict):
        raise err(f"{what} must be an object (SPEC §9.1)")
    unknown = sorted(k for k in obj if k not in allowed)   # 1.4.1: the first unknown key by code point, not by file order
    if unknown:                                            # (JS Object.keys puts integer-like keys first: the two named different keys)
        raise err(f"{what}: unknown key {_jkey(unknown[0])} (SPEC §9.1)")
    for k, (pred, desc, required) in allowed.items():
        if k in obj:
            if not pred(obj[k]):
                raise err(f"{what}: {k} must be {desc} (SPEC §9.1)")
        elif required:
            raise err(f"{what}: missing {k} (SPEC §9.1)")


_TOP_KEYS = {"evidence_format": (_is_str, "a string", True), "subject": (_is_str, "a string", True), "created_utc": (_is_str, "a string", True),
             "artifacts": (_is_list, "a list", True), "bindings": (_is_list, "a list", False), "honest_scope": (_is_str, "a string", True),
             "evidence_digest_sha256": (_is_str, "a string", True), "rfc3161_timestamp": (_is_obj, "an object", False), "producer_signatures": (_is_obj, "an object", False),
             "anchors": (lambda v: isinstance(v, list) and len(v) > 0, "a non-empty list", False)}   # 1.5.0 — SPEC §3.3
_ANCHOR_MECHANISMS = ("rfc3161",)   # SPEC §3.3: the mechanisms this revision defines; any other is a refusal naming it
_ANCHOR_RFC3161_KEYS = {"mechanism": (lambda v: v == "rfc3161", '"rfc3161"', True), "tsr_b64": (_is_str, "a string", True),
                        "tsa_url": (_is_str, "a string", False), "note": (_is_str, "a string", False)}
_DIGEST_EXCLUDED = ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures", "anchors")   # SPEC §3 (1.5.0: + anchors)
_RFC3161_KEYS = {"anchored": (_is_bool, "a boolean", True), "tsr_b64": (_is_str, "a string", False),   # tsr_b64 ABSENT under anchored: §6.4 says rfc3161_verified false, not a refusal
                 "tsa_url": (_is_str, "a string", False), "tsa": (_is_str, "a string", False), "note": (_is_str, "a string", False)}
_PRODUCER_KEYS = {"scheme": (lambda v: v in ("hybrid", "classical-only"), '"hybrid" or "classical-only"', True),
                  "over": (lambda v: v == "evidence_digest_sha256", '"evidence_digest_sha256"', True), "signatures": (_is_list, "a list", True)}
_BINDING_KEYS = {"in": (_is_str, "a string", True), "claim": (_is_str, "a string", True), "commits_to": (_is_str, "a string", True),
                 "encoding": (lambda v: v in ("hex", "b64url"), '"hex" or "b64url"', True)}
_ARTIFACT_KEYS = {"name": (_is_str, "a string", True), "sd_jwt_compact": (_is_str, "a string", True), "header": (_is_obj, "an object", True),
                  "key": (_is_obj, "an object", True), "resolved_claims": (lambda v: True, "", True), "kb_jwt": (_is_obj, "an object", True),
                  "verified_at_build": (_is_obj, "an object", True)}
_KEY_KEYS = {"jwk": (_is_obj, "an object", True), "provenance_class": (_is_str, "a string", True), "note": (_is_str, "a string", False),
             "x5c_chain_sha256": (_is_list_of_str, "a list of strings", False), "jwks_url": (_is_str, "a string", False),
             "jwks_sha256": (_is_str, "a string", False), "fetched_utc": (_is_str, "a string", False)}
_KB_COPY_KEYS = {"present": (_is_bool, "a boolean", True), "verified": (_is_bool_or_none, "a boolean or null", False), "signature_ok": (_is_bool, "a boolean", False),
                 "sd_hash_ok": (_is_bool, "a boolean", False), "note": (_is_str_or_none, "a string or null", False), "claims_recorded_not_validated": (_is_obj, "an object", False)}
_VAB_KEYS = {"signature_ok": (_is_true, "true", True), "disclosures_ok": (_is_true, "true", True)}
_KB_RECOMPUTED = ("verified", "signature_ok", "sd_hash_ok", "claims_recorded_not_validated")   # each, when present in the copy, MUST equal the recomputation (SPEC §9.1)


def _jose_header_ignored(header: Dict, what: str) -> List[str]:
    """RFC 7515 §4: header parameters not understood MUST be ignored — unless named in `crit` (§4.1.11), where an extension
    the recipient does not understand makes the JWS INVALID. This format understands no extension, so a well-formed `crit`
    is always a rejection; a malformed one (not a non-empty list of distinct strings, naming a registered parameter or one
    absent from the header — all "MUST NOT" for producers) is one too. Returns the ignored names, sorted, for the receipt."""
    if "crit" in header:
        crit = header["crit"]
        if (not isinstance(crit, list) or not crit or any(not isinstance(c, str) for c in crit) or len(set(crit)) != len(crit)
                or any(c in _JOSE_HEADER_REGISTERED or c not in header for c in crit)):
            raise Ap2EvidenceError(f"{what}: malformed crit (RFC 7515 §4.1.11)")
        raise Ap2EvidenceError(f"{what}: crit names extension(s) this verifier does not understand (RFC 7515 §4.1.11: the JWS is invalid)")
    return sorted(k for k in header if k not in _JOSE_HEADER_REGISTERED)


def _unknown_members(obj, registered) -> List[str]:
    return sorted(k for k in obj if k not in registered) if isinstance(obj, dict) else []


def _check_provenance(pc, parsed: Dict, key: Dict, trust_anchor: Optional[str] = None, at_time: Optional[str] = None):
    """1.1.0 r5: the provenance class is the field the honest_scope sends the relying party to, and it was the one field
    entirely under the pack author's control — relabelling `jwk_header` as `x5c_header` flipped `self_asserted_only` to
    False with no x5c anywhere. The two header-derived classes are now RECONCILED against the header the verifier just
    parsed; `supplied` and `jwks_fetched` remain capture-time assertions that cannot be checked offline (SPEC §2).

    Returns (self_asserted, leaf_identity): r8: offline, "issued by someone else" is NOT establishable — r7 read it off
    `subject != issuer`, two DN strings the forger writes himself (measured: a leaf self-signed with its own key, declaring
    `CN=DigiCert Global Root CA` as issuer, cleared the flag in both verifiers while the pack stayed `valid`). The only thing
    that can clear it is a CHAIN validated to a trust anchor the RELYING PARTY supplies (`--trust-anchor`, same idiom as
    `--tsa-cert`): without one, every class — `jwk_header`, `x5c_header`, `supplied`, `jwks_fetched` — is self-asserted."""
    if pc not in ("jwk_header", "x5c_header"):
        return True, None
    header = parsed.get("header") if isinstance(parsed.get("header"), dict) else {}
    jwk = key.get("jwk") or {}
    if pc == "jwk_header":
        hj = header.get("jwk")
        if not isinstance(hj, dict) or any(hj.get(f) != jwk.get(f) for f in ("kty", "crv", "x", "y")):
            raise Ap2EvidenceError("provenance_class jwk_header but the signed header carries no matching jwk")
        return True, None
    x5c = header.get("x5c")
    if not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], str):
        raise Ap2EvidenceError("provenance_class x5c_header but the signed header carries no x5c")
    try:
        cert = _load_x5c_leaf(x5c)
        leaf = _jwk_from_pubkey(cert.public_key())
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"provenance_class x5c_header but the x5c leaf is unusable: {type(e).__name__}") from e
    if any(leaf.get(f) != jwk.get(f) for f in ("kty", "crv", "x", "y")):
        raise Ap2EvidenceError("provenance_class x5c_header but the x5c leaf key differs from the snapshotted jwk")
    # r9: the receipt names WHO the certificate was issued to. A cleared flag means "a CA under your anchor certified this
    # key", never "the key belongs to the mandate's issuer" — an auditor cannot tell CN=the-bank from CN=attacker without this.
    ident = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
             "serial": format(cert.serial_number, "x"),
             "not_valid_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "not_valid_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "sha256": hashlib.sha256(cert.public_bytes(_serialization().Encoding.DER)).hexdigest()}
    ident["chain_verified"] = None     # r11: always present, as in the JS receipt — None = not measured
    if trust_anchor is None:
        return True, ident   # no anchor: the certificate proves only that the key is in a blob the signer wrote
    chain_ok = _verify_x5c_chain(x5c, trust_anchor, at_time=at_time)
    ident["chain_verified"] = chain_ok
    return (chain_ok is not True), ident   # only a chain that really validated clears it (None = openssl absent = unmeasurable)


def _serialization():
    from cryptography.hazmat.primitives import serialization
    return serialization


def _verify_x5c_chain(x5c: List[str], trust_anchor: str, at_time: Optional[str] = None, timeout: int = 15) -> Optional[bool]:
    """Validate the x5c chain to a PEM trust anchor with `openssl verify` (the reference only, like `openssl ts -verify` for
    the TSA — the JS verifier reports `chain_verified: null` and never clears `self_asserted_only`: declared divergence).

    `at_time` (r9) is the TSTInfo `genTime` of a TSA-VERIFIED RFC 3161 token, when there is one: the chain is then validated
    AT that time (`openssl verify -attime`), because a signing certificate lives 1-3 years and this format exists to verify
    years later — measured: a leaf valid 2020-2021 whose chain is fine under the anchor was `chain_verified: false` at
    today's clock, so the ONLY mechanism that clears `self_asserted_only` never fired in the scenario the format is for.
    Without a proven time the current clock is used, as `openssl verify` does by default.

    Returns True/False, or None when openssl is absent (r9: unmeasurable is not the same as failed — `self_asserted_only`
    stays fail-closed either way)."""
    import shutil
    import subprocess
    import tempfile
    exe = shutil.which("openssl")
    if not exe:
        return None          # r9: not measurable here, which is not the same as "the chain failed"
    d = tempfile.mkdtemp()
    try:
        def pem(b: bytes) -> bytes:
            body = base64.b64encode(b).decode()
            return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE-----\n").encode()
        try:
            chain = [_sigsuite._unb64(c) for c in x5c]
        except Exception:  # noqa: BLE001
            return False
        leaf_path = os.path.join(d, "leaf.pem")
        with open(leaf_path, "wb") as f:
            f.write(pem(chain[0]))
        cmd = [exe, "verify", "-CAfile", trust_anchor]
        if at_time:
            import calendar
            import time as _t
            try:
                cmd += ["-attime", str(calendar.timegm(_t.strptime(at_time.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")))]
            except ValueError:
                pass
        if len(chain) > 1:
            unt = os.path.join(d, "untrusted.pem")
            with open(unt, "wb") as f:
                f.write(b"".join(pem(c) for c in chain[1:]))
            cmd += ["-untrusted", unt]
        r = subprocess.run(cmd + [leaf_path], capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0 and ": OK" in (r.stdout or "")
    except Exception:  # noqa: BLE001
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _snapshot_key(parsed: Dict, supplied_jwk: Optional[Dict] = None,
                  jwks_url: Optional[str] = None, timeout: int = 20) -> Dict:
    """Choose the verification key and record WHERE it came from (provenance class).
    Precedence: SUPPLIED key first (the caller's explicit trust decision MUST override
    self-asserted header material — otherwise a self-consistent forgery with an embedded
    jwk would outrank the genuine key an auditor provides; found by pro-level self-attack
    2026-08-21), then x5c header > jwk header > fetched JWKS. Fail-closed if none."""
    header = parsed["header"]
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"alg {header.get('alg')!r} unsupported: ES256 only "
                               "(other algs are rejected, never half-verified)")
    if supplied_jwk:
        return {"jwk": supplied_jwk, "provenance_class": "supplied",
                "note": "key material supplied by the caller (caller vouches); "
                        "overrides any self-asserted header key by design"}
    if header.get("x5c"):
        if not isinstance(header["x5c"], list) or len(header["x5c"]) > 10:
            raise Ap2EvidenceError("x5c chain absent or too long (>10 certs): refused "
                                   "(a huge chain is a DoS vector, not a key)")
        pub = _pubkey_from_x5c_leaf(header["x5c"])
        try:
            chain_fp = [hashlib.sha256(_sigsuite._unb64(c)).hexdigest() for c in header["x5c"]]   # r6: strict, like the leaf
        except Exception as e:  # noqa: BLE001 — r7: a receipt, not a traceback
            raise Ap2EvidenceError(f"x5c chain entry is not strict base64: {type(e).__name__}") from e
        return {"jwk": _jwk_from_pubkey(pub), "provenance_class": "x5c_header",
                "x5c_chain_sha256": chain_fp,
                "note": "leaf cert key verified the signature; chain recorded, PKI path "
                        "NOT validated to a trust anchor here (declared)"}
    if header.get("jwk"):
        return {"jwk": {k: header["jwk"][k] for k in ("kty", "crv", "x", "y")
                        if k in header["jwk"]},
                "provenance_class": "jwk_header",
                "note": "key embedded in the protected header (self-asserted)"}
    if jwks_url:
        if not jwks_url.startswith("https://"):
            raise Ap2EvidenceError("JWKS URL must be https:// (TLS is the whole witness)")
        try:   # r7: an unreachable endpoint or a non-JSON body used to be a URLError/JSONDecodeError traceback
            with urllib.request.urlopen(jwks_url, timeout=timeout) as r:  # nosec B310 - https enforced above
                raw = r.read(1024 * 1024 + 1)      # cap: un JWKS gigante = DoS, non una chiave
        except Exception as e:  # noqa: BLE001
            raise Ap2EvidenceError(f"JWKS fetch failed: {type(e).__name__}") from e
        if len(raw) > 1024 * 1024:
            raise Ap2EvidenceError("JWKS response exceeds 1MB cap (refused fail-closed)")
        try:
            jwks = json.loads(raw.decode())
        except Exception as e:  # noqa: BLE001
            raise Ap2EvidenceError(f"JWKS body is not JSON: {type(e).__name__}") from e
        kid = parsed["header"].get("kid")
        keys = jwks.get("keys", [])
        match = [k for k in keys if not kid or k.get("kid") == kid]
        if not match:
            raise Ap2EvidenceError(f"no key in JWKS matches kid={kid!r}")
        return {"jwk": {k: match[0][k] for k in ("kty", "crv", "x", "y", "kid")
                        if k in match[0]},
                "provenance_class": "jwks_fetched",
                "jwks_url": jwks_url, "jwks_sha256": hashlib.sha256(raw).hexdigest(),
                "fetched_utc": _utcnow(),
                "note": "fetched over TLS at build time — a capture witness, "
                        "not proof of issuer control of the key"}
    raise Ap2EvidenceError("no key material: JWT has neither x5c nor jwk header, and no "
                           "supplied key or JWKS URL was given (fail-closed)")


def verify_kb_jwt(parsed: Dict, resolved_claims: Dict) -> Dict:
    """Holder binding (SD-JWT KB-JWT): verified against the holder key in the issuer
    payload's cnf.jwk, plus the sd_hash commitment over the exact presentation
    (<jwt>~<disclosures>*~). Three honest states: absent / verified true-false /
    present-but-unverifiable (no cnf.jwk — declared, never a fake green)."""
    kb = parsed.get("kb_jwt")
    if not kb:
        return {"present": False}
    seg = kb.split(".")
    if len(seg) != 3:
        raise Ap2EvidenceError("kb-jwt must have 3 dot-separated segments")
    try:
        header = _loads_segment(_b64url_decode(seg[0]), "kb-jwt header")
        payload = _loads_segment(_b64url_decode(seg[1]), "kb-jwt payload")
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"kb-jwt header/payload invalid: {e}") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise Ap2EvidenceError("kb-jwt header and payload must be objects")
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"kb-jwt alg {header.get('alg')!r} unsupported (ES256 only)")
    # 1.4.0 (SPEC §9.2): RFC 9901 §4.3 — typ REQUIRED and MUST be kb+jwt (§7.3 step 5.d); iat/aud/nonce/sd_hash REQUIRED with
    # their types. Presence and type, never the values (the sealed scope: aud/nonce/iat are recorded, not validated). Checked
    # whether or not the holder key is known, like the §3.1 segment profile.
    if header.get("typ") != "kb+jwt":
        raise Ap2EvidenceError("kb-jwt typ must be \"kb+jwt\" (RFC 9901 §4.3)")
    ignored = {"kb_jwt_header": _jose_header_ignored(header, "kb-jwt header")}
    for claim, pred, desc in (("iat", lambda v: isinstance(v, int) and not isinstance(v, bool), "an integer"), ("aud", _is_str, "a string"),
                              ("nonce", _is_str, "a string"), ("sd_hash", _is_str, "a string")):
        if claim not in payload:
            raise Ap2EvidenceError(f"kb-jwt payload: missing {claim} (RFC 9901 §4.3)")
        if not pred(payload[claim]):
            raise Ap2EvidenceError(f"kb-jwt payload: {claim} must be {desc} (RFC 9901 §4.3)")
    ignored["kb_jwt_claims"] = _unknown_members(payload, _KB_CLAIMS_REGISTERED)
    # 1.1.0 r2: `cnf` absent or an object, `cnf.jwk` absent or an object (an empty object is a holder key that fails to
    # parse, not "unknown"): present-with-null used to be an AttributeError here and "absent" in JS
    rc = resolved_claims if isinstance(resolved_claims, dict) else {}
    if "cnf" in rc and not isinstance(rc["cnf"], dict):
        raise Ap2EvidenceError("cnf must be an object")
    cnf = rc.get("cnf", {})
    ignored["cnf"] = _unknown_members(cnf, _CNF_REGISTERED)   # RFC 7800 §3.1: not understood -> ignored, here reported
    _b64url_decode(seg[2])   # the §3.1 profile applies to all three segments even when the holder key is unknown: without
    # this, a KB-JWT whose signature segment is non-canonical base64url passed with valid: true, because the branch below
    # returns before the signature is ever decoded (found by probing the six uncovered KB-JWT branches)
    recorded = {k: payload.get(k) for k in ("aud", "nonce", "iat") if k in payload}   # final check: the sealed scope says
    # these are RECORDED whenever a KB-JWT is present — this branch returned before recording them, in both verifiers
    if "jwk" not in cnf:
        return {"present": True, "verified": None, "claims_recorded_not_validated": recorded,
                "note": "no cnf.jwk in issuer payload — holder key unknown (declared)", "_ignored": ignored}
    jwk = cnf["jwk"]
    if not isinstance(jwk, dict):
        raise Ap2EvidenceError("cnf.jwk must be an object")
    ignored["cnf_jwk"] = _unknown_members(jwk, _JWK_REGISTERED)   # RFC 7517 §4
    sig_ok = verify_es256(f"{seg[0]}.{seg[1]}".encode("ascii"),
                          _b64url_decode(seg[2]), jwk)
    presentation = parsed["compact"].rsplit("~", 1)[0] + "~"
    sd_hash_ok = payload.get("sd_hash") == _sha256_b64url(presentation.encode("ascii"))
    return {"present": True, "verified": bool(sig_ok and sd_hash_ok),
            "signature_ok": sig_ok, "sd_hash_ok": sd_hash_ok, "note": None,
            "claims_recorded_not_validated": recorded, "_ignored": ignored}


# ────────────────────────────────────────────────────────── bindings

def find_bindings(artifacts: List[Dict]) -> List[Dict]:
    """Cross-artifact hash commitments, recomputed from the PRIMARY quantity: sha-256 over
    each artifact's exact compact serialization (hex and b64url forms), matched against
    every string claim of the other artifacts. Deterministic; found-or-absent, never guessed."""
    by_value = {}   # r5: inverse index (digest string -> name, encoding) — the per-leaf scan used to be O(artifacts), quadratic
    for a in artifacts:
        raw = a["compact"].encode("ascii")
        by_value.setdefault(hashlib.sha256(raw).hexdigest(), []).append((a["name"], "hex"))
        by_value.setdefault(_sha256_b64url(raw), []).append((a["name"], "b64url"))
    found = []

    def scan(node, path, holder):
        if isinstance(node, dict):
            for k, v in node.items():
                scan(v, f"{path}.{k}" if path else k, holder)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                scan(v, f"{path}[{i}]", holder)
        elif isinstance(node, str):
            for other, enc in by_value.get(node, ()):
                if other == holder:
                    continue
                found.append({"in": holder, "claim": path, "commits_to": other, "encoding": enc})

    for a in artifacts:
        scan(a["resolved_claims"], "", a["name"])
    return found


# ────────────────────────────────────────────────────────── RFC 3161 time anchor

def _rfc3161_stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """OPTIONAL RFC 3161 timestamp via openssl (graceful when absent). Its absence
    never invalidates the evidence — signatures and digests stand on their own."""
    import shutil
    import subprocess
    import tempfile
    from urllib.parse import urlparse
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL scheme not allowed (http/https only)"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    d = tempfile.mkdtemp()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = subprocess.run(
            [exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts-query failed"}
        with open(tsq, "rb") as f:
            req = f.read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(http, timeout=timeout) as rh:
            resp = rh.read()
        # anchored only on a token whose imprint is THIS digest (2026-10-03: any HTTP body — an error page, a rejection, a token
        # for another digest — was recorded as anchored: True)
        try:     # the DER walk reads an imprint even from a non-granted reply carrying a token: both checks are needed
            facts = parse_timestamp_resp(resp)
        except Ap2EvidenceError:
            facts = {}
        if not (facts.get("granted") and facts.get("imprint") == digest_hex.lower()):
            return {"anchored": False, "tsa_url": tsa_url, "note": "TSA reply is not a granted token for this digest"}
        return {"anchored": True, "tsa_url": tsa_url, "tsr_b64": base64.b64encode(resp).decode()}   # 1.4.0: `tsa_url`, the vectors' spelling (`tsa` stays accepted, SPEC §9.1)
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        import shutil as _sh
        _sh.rmtree(d, ignore_errors=True)


def _der_tlv(buf: bytes, off: int) -> Tuple[int, int, int]:
    """(tag, start, end) of the DER element at `off`; raises Ap2EvidenceError on malformation."""
    if off + 2 > len(buf):
        raise Ap2EvidenceError("der: truncated")
    tag, ln, hl = buf[off], buf[off + 1], 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + 2 + n > len(buf):
            raise Ap2EvidenceError("der: bad length")
        ln = int.from_bytes(buf[off + 2:off + 2 + n], "big"); hl = 2 + n
    if off + hl + ln > len(buf):
        raise Ap2EvidenceError("der: overrun")
    return tag, off + hl, off + hl + ln


def _der_children(buf: bytes, start: int, end: int) -> List[Tuple[int, int, int]]:
    out, o = [], start
    while o < end:
        t = _der_tlv(buf, o); out.append(t); o = t[2]
    return out


def parse_timestamp_resp(tsr: bytes, _partial: Optional[Dict] = None) -> Dict:
    """Minimal DER walk of an RFC 3161 TimeStampResp: PKIStatus and the TSTInfo messageImprint hash (hex). No signature
    or certificate processing — the same two facts the JS verifier reads (SPEC §3.2). `_partial` collects what was read
    before any failure, so the caller can report a measured `granted` instead of asserting one (r10)."""
    _partial = {} if _partial is None else _partial
    tag, st, en = _der_tlv(tsr, 0)
    if tag != 0x30:
        raise Ap2EvidenceError("not a TimeStampResp")
    # r10: PKIStatus is read first and carried on the exception, so a truncated token does not make the receipt claim
    # `granted: false` — a fact it never established (the JS verifier reported the status it had actually read)
    kids = _der_children(tsr, st, en)
    if not kids:
        raise Ap2EvidenceError("empty TimeStampResp")
    stag, sst, sen = kids[0]
    sk = _der_children(tsr, sst, sen)
    if not sk or sk[0][0] != 0x02:
        raise Ap2EvidenceError("no PKIStatus")
    status_bytes = tsr[sk[0][1]:sk[0][2]]
    granted = len(status_bytes) == 1 and status_bytes[0] in (0, 1)
    _partial["granted"] = granted
    if len(kids) < 2:
        return {"granted": granted, "imprint": None}
    ci = _der_children(tsr, kids[1][1], kids[1][2])           # ContentInfo: OID, [0] SignedData
    if len(ci) < 2:
        raise Ap2EvidenceError("no SignedData")
    sdl = _der_children(tsr, ci[1][1], ci[1][2])
    if not sdl:
        raise Ap2EvidenceError("empty SignedData")
    sd = sdl[0]
    sdc = _der_children(tsr, sd[1], sd[2])                    # version, digestAlgorithms, encapContentInfo, ...
    if len(sdc) < 3:
        raise Ap2EvidenceError("SignedData too short")
    eci = _der_children(tsr, sdc[2][1], sdc[2][2])
    if len(eci) < 2:
        raise Ap2EvidenceError("no eContent")
    wl = _der_children(tsr, eci[1][1], eci[1][2])
    if not wl:
        raise Ap2EvidenceError("empty eContent")
    wrap = wl[0]
    if wrap[0] != 0x04:
        raise Ap2EvidenceError("eContent is not an OCTET STRING")
    tst = _der_tlv(tsr, wrap[1])
    tstc = _der_children(tsr, tst[1], tst[2])                 # version, policy, messageImprint, serial, genTime, ...
    if len(tstc) < 3:
        raise Ap2EvidenceError("TSTInfo too short")
    mic = _der_children(tsr, tstc[2][1], tstc[2][2])
    if len(mic) < 2 or mic[1][0] != 0x04:
        raise Ap2EvidenceError("no messageImprint hash")
    gen_time = None   # r4: TSTInfo.genTime (GeneralizedTime, UTC) — reported, and the TSA chain is validated AT that time
    if len(tstc) >= 5 and tstc[4][0] == 0x18:
        gt = tsr[tstc[4][1]:tstc[4][2]].decode("ascii", "replace")
        if re.fullmatch(r"[0-9]{14}(\.[0-9]+)?Z", gt):   # r9: ASCII digits, as the JS verifier
            gen_time = gt
    return {"granted": granted, "imprint": tsr[mic[1][1]:mic[1][2]].hex(), "gen_time": gen_time,
            "tst_info": bytes(tsr[wrap[1]:wrap[2]])}   # 1.5.0 (SPEC §3.3): the TSTInfo the TSA signed = the identity of the anchor


def _verify_rfc3161(tsr_b64: str, expected_digest_hex: str, timeout: int = 15, tsa_cert: Optional[str] = None) -> Dict:
    """RFC 3161 token check (SPEC §3.2). `verified` = the token parses, its status is granted and the TSTInfo
    messageImprint equals the recomputed pack digest — BINDING, not TSA authenticity: the TSA signature and certificate
    chain are validated only when the relying party supplies the TSA certificate (`tsa_cert`, PEM), through
    `openssl ts -verify -CAfile`; then `tsa_verified` is True/False (None when not requested or openssl is absent).
    1.1.0 r1: a self-forged TimeStampResp with status 0 and the right imprint used to pass the JS verifier and to
    fail this one only because `openssl ts -reply -text` refused the minimal DER — neither was a check of the TSA."""
    import shutil
    import subprocess
    import tempfile
    try:
        tsr = _sigsuite._unb64(tsr_b64)                       # strict base64 (a space inside the token used to be skipped)
    except (ValueError, TypeError):
        return {"verified": False, "granted": None, "imprint_ok": None, "gen_time": None, "tsa_verified": None, "note": "tsr_b64 is not canonical base64"}   # r11: None = never read, not "it did not match"
    partial: Dict = {}
    try:
        info = parse_timestamp_resp(tsr, partial)
    except Exception as e:  # noqa: BLE001 — any malformed DER is "not parseable" (r2: an empty EXPLICIT [0] was an IndexError traceback)
        return {"verified": False, "granted": partial.get("granted"), "imprint_ok": partial.get("imprint_ok"), "gen_time": None, "tsa_verified": None,
                "note": f"token not parseable: {type(e).__name__}: {str(e)[:80]}"}   # r11: imprint_ok too — None when never read   # r10: the status READ, or None — never an unmeasured False
    # r11: None when the token carried no messageImprint at all — "never read" is not "did not match"
    imprint_ok = None if info.get("imprint") is None else (info["imprint"] == expected_digest_hex.lower())
    partial["imprint_ok"] = imprint_ok
    out = {"verified": bool(info["granted"] and imprint_ok is True), "granted": info["granted"], "imprint_ok": imprint_ok, "gen_time": info.get("gen_time"), "tsa_verified": None}
    if tsa_cert is None:
        return out
    exe = shutil.which("openssl")
    if not exe:
        out["tsa_note"] = "openssl absent — TSA signature/chain NOT verified"; return out
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, "t.tsr")
        with open(path, "wb") as f:
            f.write(tsr)
        cmd = [exe, "ts", "-verify", "-digest", expected_digest_hex, "-sha256", "-in", path, "-CAfile", tsa_cert]
        if info.get("gen_time"):   # r4: validate the chain at the token's own genTime (`-attime`), so a TSA certificate that expired
            # AFTER issuing does not turn `tsa_verified` False years later; revocation is not checked (declared)
            import calendar, time as _t
            cmd += ["-attime", str(calendar.timegm(_t.strptime(info["gen_time"].split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")))]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out["tsa_verified"] = r.returncode == 0 and "Verification: OK" in (r.stdout or "")
        if not out["tsa_verified"]:   # `verified` keeps its §3.2 meaning (binding); the TSA outcome is its own field, in both verifiers
            out["tsa_note"] = (r.stderr or r.stdout).strip()[-160:]
    except Exception as e:  # noqa: BLE001
        out["tsa_verified"] = False; out["tsa_note"] = f"{type(e).__name__}: {str(e)[:80]}"
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return out

def _verify_one(parsed: Dict, key: Dict) -> Dict:
    sig_ok = verify_es256(parsed["signing_input"], parsed["signature"], key["jwk"])
    resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
    return {"signature_ok": sig_ok, "resolved_claims": resolved,
            "disclosures_ok": True}     # resolve_disclosures raised otherwise


def build_evidence(artifacts: List[Dict], out_path: str,
                   keys: Optional[Dict[str, Dict]] = None,
                   jwks_urls: Optional[Dict[str, str]] = None,
                   tsa_url: Optional[str] = None,
                   subject: str = "agentic-payment mandate evidence",
                   extra_tsa_urls: Optional[List[str]] = None) -> Dict:
    """artifacts: [{name, sd_jwt}]. Verifies every artifact NOW, snapshots the key material
    used, records bindings, and writes ONE self-contained evidence file. Any artifact that
    fails to verify aborts the build (an evidence file must never contain a red light
    dressed as evidence — fail-closed at the source)."""
    keys, jwks_urls = keys or {}, jwks_urls or {}
    names = [a["name"] for a in artifacts]
    if any(not isinstance(n, str) or not n for n in names):   # r5: build wrote a pack with name "" that both verifiers then refused
        raise Ap2EvidenceError("artifact name must be a non-empty string (SPEC §2)")
    if len(set(names)) != len(names):
        raise Ap2EvidenceError("duplicate artifact names (bindings would silently "
                               "overwrite each other — refused fail-closed)")
    entries, for_bindings = [], []
    for a in artifacts:
        parsed = parse_sd_jwt(a["sd_jwt"])
        if not isinstance(parsed["header"], dict) or not isinstance(parsed["payload"], dict):
            raise Ap2EvidenceError(f"artifact {a['name']!r}: JWT header and payload must be objects")
        _jose_header_ignored(parsed["header"], "JWT header")   # RFC 7515 §4.1.11 at build: refused at the source, like a bad signature
        key = _snapshot_key(parsed, supplied_jwk=keys.get(a["name"]),
                            jwks_url=jwks_urls.get(a["name"]))
        v = _verify_one(parsed, key)
        if not v["signature_ok"]:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: ES256 signature INVALID "
                                   "(build refused — no evidence file for a red light)")
        kb = verify_kb_jwt(parsed, v["resolved_claims"]); kb.pop("_ignored", None)   # the receipt's report, not part of the sealed copy
        if kb.get("verified") is False:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: KB-JWT holder binding "
                                   "INVALID (build refused — no evidence file for a red light)")
        entries.append({"name": a["name"], "sd_jwt_compact": parsed["compact"],
                        "header": parsed["header"], "key": key,
                        "resolved_claims": v["resolved_claims"],
                        "kb_jwt": kb,
                        "verified_at_build": {"signature_ok": True,
                                              "disclosures_ok": True}})
        for_bindings.append({"name": a["name"], "compact": parsed["compact"],
                             "resolved_claims": v["resolved_claims"]})
    evidence = {
        "evidence_format": EVIDENCE_FORMAT, "subject": subject,
        "created_utc": _utcnow(), "artifacts": entries,
        "bindings": find_bindings(for_bindings),
        "honest_scope": HONEST_SCOPE,
    }
    evidence["evidence_digest_sha256"] = hashlib.sha256(_canon(evidence)).hexdigest()
    evidence["rfc3161_timestamp"] = (
        _rfc3161_stamp(evidence["evidence_digest_sha256"], tsa_url)
        if tsa_url else {"anchored": False, "note": "no TSA provided"})
    # 1.5.0 — SPEC §3.3: every further TSA goes to `anchors` (the first stays in rfc3161_timestamp, so a pack built with one
    # TSA is still read by 1.4.x verifiers); an anchor that could not be obtained is NOT written (an entry is a token or
    # nothing) and is reported in the build result
    added, failed = [], []
    for u in extra_tsa_urls or []:
        st = _rfc3161_stamp(evidence["evidence_digest_sha256"], u)
        if st.get("anchored"):
            added.append({"mechanism": "rfc3161", "tsr_b64": st["tsr_b64"], "tsa_url": u})
        else:
            failed.append({"tsa_url": u, "note": st.get("note")})
    if added:
        evidence["anchors"] = added
    try:   # 1.5.2: a pack that cannot be written is EX_IOERR in the CLI, not a traceback (exit 1, the "not valid" code)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, ensure_ascii=False, indent=1, sort_keys=True)
    except OSError as e:
        raise Ap2WriteError(f"cannot write the pack {out_path!r}: {type(e).__name__}: {e.strerror or e}") from e
    return {"out": out_path, "artifacts": len(entries),
            "bindings": len(evidence["bindings"]),
            "evidence_digest_sha256": evidence["evidence_digest_sha256"],
            "rfc3161_anchored": evidence["rfc3161_timestamp"].get("anchored", False),
            "anchors_added": len(added), **({"anchors_failed": failed} if failed else {})}


def add_anchor(path: str, tsa_url: str) -> Dict:
    """1.5.0 — SPEC §3.3: append one RFC 3161 anchor to an EXISTING pack (a second TSA, or a later token from any TSA).
    The token commits to the pack's digest, not to the anchors already there, so it proves existence from its own time
    only: it is not an RFC 4998 renewal. The token is requested for the digest RECOMPUTED from the sealed content, and
    the pack is refused unchanged when that differs from the declared digest (stamping a pack that does not verify would attest
    nothing). The digest and the producer signatures do not change: `anchors` lies outside them. Written atomically."""
    import tempfile
    path = os.path.realpath(path)   # a symlink is followed: the pack it names is stamped, the link stays a link
    try:
        dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    except OSError as e:
        raise Ap2EvidenceError(f"cannot open the pack's directory: {type(e).__name__}") from e
    try:
        try:   # the read-modify-write under an exclusive lock on the directory: measured on b3edfc8, six concurrent stamps of one
            import fcntl   # pack all reported success and the file kept ONE anchor (the others lost), two raised FileNotFoundError
            fcntl.flock(dfd, fcntl.LOCK_EX)
        except ImportError:   # no fcntl (Windows): no lock — concurrent stamps of one pack are not supported there (declared)
            pass
        ev = read_evidence_file(path)
        if ev.get("evidence_format") != EVIDENCE_FORMAT:
            raise Ap2EvidenceError(f"evidence_format must be {EVIDENCE_FORMAT!r}")
        digest = hashlib.sha256(_canon({k: v for k, v in ev.items() if k not in _DIGEST_EXCLUDED})).hexdigest()
        if digest != ev.get("evidence_digest_sha256"):
            raise Ap2EvidenceError("the declared evidence_digest_sha256 does not match the sealed content: not stamped")
        if "anchors" in ev and not (isinstance(ev["anchors"], list) and ev["anchors"]):
            raise Ap2EvidenceError("anchors must be a non-empty list (SPEC §3.3): not stamped")
        st = _rfc3161_stamp(digest, tsa_url)
        if not st.get("anchored"):
            raise Ap2EvidenceError(f"no anchor obtained: {st.get('note')}")
        ev.setdefault("anchors", []).append({"mechanism": "rfc3161", "tsr_b64": st["tsr_b64"], "tsa_url": tsa_url})
        mode = os.stat(path).st_mode & 0o7777
        tmp = None
        try:   # a fresh, unpredictable name created O_EXCL (a fixed name could be a planted symlink: measured, it overwrote its target)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".ap2-stamp-", suffix=".tmp")
            os.fchmod(fd, mode)   # the pack keeps its permissions (0600 became 0644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(ev, f, ensure_ascii=False, indent=1, sort_keys=True)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, path); tmp = None
        except OSError as e:
            raise Ap2WriteError(f"cannot write the stamped pack: {type(e).__name__}: not stamped") from e
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return {"out": path, "evidence_digest_sha256": digest, "anchors": len(ev["anchors"])}
    finally:
        os.close(dfd)


def sign_evidence(path, identity=None, classical_alg="ed25519"):
    """Add an OMEGA PRODUCER SIGNATURE to an evidence pack: a HYBRID block (a classical
    signature + ML-DSA-65 when available) over evidence_digest_sha256, so the pack's
    integrity/authenticity survives the quantum transition (NIST IR 8547). The signature
    scheme is a DECLARED class per the auditor's request: each signature records
    its sig_alg. Backward-compatible: producer_signatures is excluded from the digest,
    exactly like the RFC 3161 timestamp. Honest scope: this protects THIS pack; it does not
    retro-protect the underlying ES256 mandate signature (still classical) - for that, the
    durable claim rests on the time anchor proving the mandate existed pre-quantum."""
    ev = read_evidence_file(path)
    digest = ev.get("evidence_digest_sha256")
    if not digest:
        raise Ap2EvidenceError("evidence pack has no digest to sign")
    if identity is None:
        identity = _sigsuite.ProducerIdentity.create(classical_alg=classical_alg)
    ev["producer_signatures"] = identity.sign_block(digest.encode("ascii"))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=1, sort_keys=True)
    algs = [x["sig_alg"] for x in ev["producer_signatures"]["signatures"]]
    return {"out": path, "scheme": ev["producer_signatures"]["scheme"], "sig_algs": algs,
            "pq_protected": any(a in _sigsuite.POST_QUANTUM for a in algs),
            "producer_public_keys": identity.public_keys()}


def _chain_verdict(trust_anchor, art_results):
    if trust_anchor is None:
        return None
    attempted = [r["x5c_leaf"] for r in art_results if r.get("x5c_leaf") is not None]
    if not attempted or any(x.get("chain_verified") is None for x in attempted):
        return None          # nothing was attempted, or openssl could not measure one of them
    return all(x.get("chain_verified") is True for x in attempted)


def _anchor_identity(tsr_b64: str) -> bytes:
    """SPEC §3.3: the identity of an anchor is the TSTInfo the TSA signed (eContent of the token), not the bytes around it.
    Called only on a token whose binding verified, i.e. that parsed; the decoded bytes are the fallback for a stubbed check."""
    raw = _sigsuite._unb64(tsr_b64)
    try:
        return b"tst:" + parse_timestamp_resp(raw)["tst_info"]
    except Ap2EvidenceError:
        return b"raw:" + raw


def _gt_key(gt: str):
    """Order key of a GeneralizedTime `YYYYMMDDHHMMSS[.f]Z` (the only shape parse_timestamp_resp reports): whole seconds, then
    the fraction as a number — a string comparison put "…00.5Z" before "…00Z" ('.' < 'Z')."""
    whole, _, frac = gt.rstrip("Z").partition(".")
    return (whole, float("0." + frac) if frac else 0.0)


def verify_evidence(path: str, trusted_producer_keys=None, require_pq: bool = False,
                    require_producer: bool = False, require_anchor: bool = False, tsa_cert: Optional[str] = None,
                    trust_anchor: Optional[str] = None, min_anchors: Optional[int] = None) -> Dict:
    """OFFLINE re-verification from the evidence file alone: digest, every signature with
    the SNAPSHOTTED key, every disclosure, every binding, and the RFC 3161 token's binding
    (status + imprint; the TSA itself only with `tsa_cert`, via openssl). Fail-closed."""
    if min_anchors is not None and (type(min_anchors) is not int or min_anchors < 1):   # SPEC §3.3: an integer >= 1 —
        raise ValueError(f"min_anchors must be an integer >= 1 (got {min_anchors!r})")      # 0, NaN or "2" never weakens the policy in silence
    try:
        ev = read_evidence_file(path)
    except Ap2EvidenceError as e:   # 1.1.0: a hostile or unreadable file is a refusal receipt, never a traceback
        return {"digest_ok": False, "artifacts": [], "producer_signatures": {"present": False, "pq_protected": False, "trusted": None},
                "pq_protected": False, "bindings_ok": False, "rfc3161": {"claimed": False, "verified": None}, "anchors": [], "anchors_verified": 0, "provenance_classes": [],
                "self_asserted_only": True, "chain_verified": None, "policy_ok": False, "valid": False, "honest_scope": None, "refused": str(e)}
    def refusal(msg):
        return {"digest_ok": False, "artifacts": [], "producer_signatures": {"present": False, "pq_protected": False, "trusted": None},
                "pq_protected": False, "bindings_ok": False, "rfc3161": {"claimed": False, "verified": None}, "anchors": [], "anchors_verified": 0, "provenance_classes": [],
                "self_asserted_only": True, "chain_verified": None, "policy_ok": False, "valid": False, "honest_scope": None, "refused": msg}
    # 1.1.0 (review r1): the SHAPE of the top-level fields is checked before anything touches them — `artifacts` a list of
    # objects, `bindings` a list, `rfc3161_timestamp` an object or absent, `producer_signatures` an object or absent. A wrong
    # type used to be a TypeError/AttributeError traceback (the JS verifier answered); `producer_signatures: {}` was "absent".
    if ev.get("evidence_format") != EVIDENCE_FORMAT:   # r5: version confusion — a "…/2.0" pack was verified under the 1.0 rules
        return refusal(f"evidence_format must be {EVIDENCE_FORMAT!r}")
    for f in ("subject", "created_utc", "honest_scope"):   # SPEC §1 MUSTs: present and a string, or the receipt is silently poorer
        if not isinstance(ev.get(f), str):
            return refusal(f"{f} must be a string (SPEC §1)")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", ev["created_utc"]):   # r6: §1 says ISO-8601 UTC, only the type was checked.
        # r9: [0-9], not \d — in Python \d matches every Unicode Nd digit, in JavaScript only [0-9], so "٢٠٢٦-٠٩-٢٢T٠٠:٠٠:٠٠Z"
        # (Arabic-Indic) verified here and was refused by the JS verifier: opposite verdicts on a pack in profile.
        return refusal("created_utc must be ISO-8601 UTC, YYYY-MM-DDTHH:MM:SSZ (SPEC §1)")
    if hashlib.sha256(ev["honest_scope"].encode("utf-8")).hexdigest() != HONEST_SCOPE_SHA256:
        # r8: the receipt used to REPRINT whatever scope the file carried — an author could write "anchored by a QTSP under
        # eIDAS art. 45j" and see it beside `valid: true`. The scope is the format's, not the pack's (SPEC §1).
        return refusal("honest_scope does not match the canonical scope of this evidence_format (SPEC §1)")
    if not isinstance(ev.get("artifacts"), list) or any(not isinstance(a, dict) for a in ev["artifacts"]):
        return refusal("artifacts must be a list of objects")
    names = [a.get("name") for a in ev["artifacts"]]   # r3: the name keys the binding table — a non-string crashed the JS table, "__proto__" vanished from it
    if any(not isinstance(n, str) or not n for n in names):
        return refusal("artifacts[].name must be a non-empty string")
    if len(set(names)) != len(names):
        return refusal("artifacts[].name must be unique within the pack")
    if not isinstance(ev.get("bindings", []), list):
        return refusal("bindings must be a list")
    if "rfc3161_timestamp" in ev and not isinstance(ev["rfc3161_timestamp"], dict):
        return refusal("rfc3161_timestamp must be an object")
    if "rfc3161_timestamp" in ev and not isinstance(ev["rfc3161_timestamp"].get("anchored"), bool):   # r2: [] / {} were "not anchored" here and "anchored, unverified" in JS
        return refusal("rfc3161_timestamp.anchored must be a boolean")
    if "producer_signatures" in ev and not isinstance(ev["producer_signatures"], dict):
        return refusal("producer_signatures must be an object")
    # 1.4.0 — SPEC §9.1: the top-level object, the anchor block, the producer block and every binding entry are CLOSED
    try:
        _check_closed(ev, "top level", _TOP_KEYS)
        if "rfc3161_timestamp" in ev:
            _check_closed(ev["rfc3161_timestamp"], "rfc3161_timestamp", _RFC3161_KEYS)
        if "producer_signatures" in ev:
            _check_closed(ev["producer_signatures"], "producer_signatures", _PRODUCER_KEYS)
        for i, b in enumerate(ev.get("bindings", [])):
            _check_closed(b, f"bindings[{i}]", _BINDING_KEYS)
        for i, an in enumerate(ev.get("anchors", [])):   # 1.5.0 — SPEC §3.3/§9.1: closed entries, the mechanism first
            if not isinstance(an, dict):
                raise Ap2EvidenceError(f"anchors[{i}] must be an object (SPEC §9.1)")
            if "mechanism" not in an:
                raise Ap2EvidenceError(f"anchors[{i}]: missing mechanism (SPEC §9.1)")
            if not isinstance(an["mechanism"], str):
                raise Ap2EvidenceError(f"anchors[{i}]: mechanism must be a string (SPEC §9.1)")
            if an["mechanism"] not in _ANCHOR_MECHANISMS:
                raise Ap2EvidenceError(f"anchors[{i}]: mechanism {_jkey(an['mechanism'])} is not defined by this revision (SPEC §3.3)")
            _check_closed(an, f"anchors[{i}]", _ANCHOR_RFC3161_KEYS)
    except Ap2EvidenceError as e:
        return refusal(str(e))
    e2 = {k: v for k, v in ev.items() if k not in _DIGEST_EXCLUDED}
    recomputed_digest = hashlib.sha256(_canon(e2)).hexdigest()
    digest_ok = recomputed_digest == ev.get("evidence_digest_sha256")

    # r9: the time anchor is checked FIRST, so a TSA-verified genTime can date the x5c chain validation below
    ts = ev.get("rfc3161_timestamp") or {}
    rfc = {"claimed": bool(ts.get("anchored", False)), "verified": None}
    if ts.get("anchored") and isinstance(ts.get("tsr_b64"), str):
        rfc = {"claimed": True, **_verify_rfc3161(ts["tsr_b64"], recomputed_digest, tsa_cert=tsa_cert)}
    elif ts.get("anchored"):
        rfc = {"claimed": True, "verified": False, "note": "anchored claimed but tsr_b64 absent"}
    # 1.5.0 — SPEC §3.3: every `anchors` entry checked like the block above; COUNTING = binding verified (+ TSA-verified when
    # --tsa-cert was given); DISTINCT = a different signed TSTInfo (a copied token is one anchor, however it is wrapped);
    # any failing claim fails the pack
    anchor_results = [{"mechanism": an["mechanism"], "claimed": True, **_verify_rfc3161(an["tsr_b64"], recomputed_digest, tsa_cert=tsa_cert)}
                      for an in ev.get("anchors", [])]
    counted, earliest = set(), None
    for r_, tok in ([(rfc, ts.get("tsr_b64"))] if rfc.get("claimed") else []) + [(r_, an["tsr_b64"]) for r_, an in zip(anchor_results, ev.get("anchors", []))]:
        if r_.get("verified") is True and (tsa_cert is None or r_.get("tsa_verified") is True):
            # the TSTInfo the TSA signed, not the wrapper: the same token re-wrapped (bytes after the TimeStampResp, a status
            # string, a longer length) verified as a second anchor under --tsa-cert --min-anchors 2 (measured on b3edfc8)
            counted.add(_anchor_identity(tok))
            if r_.get("tsa_verified") is True and r_.get("gen_time") and (earliest is None or _gt_key(r_["gen_time"]) < _gt_key(earliest)):
                earliest = r_["gen_time"]
    anchors_verified = len(counted)
    if anchor_results:   # the aggregate of §3.3; without `anchors` the block is exactly what 1.4.x reported
        rfc = dict(rfc, claimed=True, verified=(False if (rfc.get("verified") is False or any(x.get("verified") is not True for x in anchor_results)) else True))
    proven_time = earliest

    art_results, all_ok = [], True
    for_bindings = []
    for a in ev["artifacts"]:
        try:
            _check_closed(a, "artifact", _ARTIFACT_KEYS)   # 1.4.0 — SPEC §9.1: the entry, its key, its KB record and its attestation are CLOSED
            _check_closed(a["key"], "artifact key", _KEY_KEYS)
            _check_closed(a["kb_jwt"], "artifact kb_jwt", _KB_COPY_KEYS)
            _check_closed(a["verified_at_build"], "artifact verified_at_build", _VAB_KEYS)
            compact = a["sd_jwt_compact"]
            if not isinstance(compact, str) or compact != compact.strip() or not compact.isascii():
                raise Ap2EvidenceError("sd_jwt_compact must be the exact ASCII compact serialization (no surrounding whitespace)")
            key = a["key"]
            if not isinstance(key, dict) or not isinstance(key.get("jwk"), dict):
                raise Ap2EvidenceError("artifact key.jwk must be an object")
            pc = key.get("provenance_class")
            if not isinstance(pc, str) or pc not in PROVENANCE_CLASSES:   # r7: absent/null used to mean "no class", which CLEARED self_asserted_only   # r2: a list was a TypeError in sorted(); r5: an out-of-enum value passed as a strong class
                raise Ap2EvidenceError(f"artifact key.provenance_class must be one of {sorted(PROVENANCE_CLASSES)}")
            parsed = parse_sd_jwt(compact)
            if not isinstance(parsed["payload"], dict) or not isinstance(parsed["header"], dict):
                raise Ap2EvidenceError("JWT header and payload must be objects")
            if _canon(a["header"]) != _canon(parsed["header"]):   # 1.4.0 — SPEC §2: the informative copy must say what the signed header says
                raise Ap2EvidenceError("artifact header copy differs from the decoded protected header (SPEC §2)")
            if bool(parsed["kb_jwt"]) != a["kb_jwt"]["present"]:
                raise Ap2EvidenceError("artifact kb_jwt.present contradicts the compact serialization (SPEC §9.1)")
            # SPEC §9.2 — the standards' rule for the unknown: ignored, and REPORTED (crit: RFC 7515 §4.1.11, a rejection)
            ignored = {"header": _jose_header_ignored(parsed["header"], "JWT header"),
                       "header_jwk": _unknown_members(parsed["header"].get("jwk"), _JWK_REGISTERED),
                       "key_jwk": _unknown_members(key["jwk"], _JWK_REGISTERED)}
            self_asserted, leaf_ident = _check_provenance(pc, parsed, key, trust_anchor, at_time=proven_time)   # r5: reconciled, not believed; r7/r8: it decides self_asserted_only; r9: at a proven time, and it names the leaf
            sig_ok = verify_es256(parsed["signing_input"], parsed["signature"], key["jwk"])
            resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
            claims_ok = _canon(resolved) == _canon(a.get("resolved_claims"))
            kb = verify_kb_jwt(parsed, resolved)
            for k in _KB_RECOMPUTED:   # SPEC §9.1 (NEMESIS 2026-10-11): a recorded KB value that says something else is that artifact's error
                if k in a["kb_jwt"] and (k not in kb or _canon(a["kb_jwt"][k]) != _canon(kb[k])):
                    raise Ap2EvidenceError(f"artifact kb_jwt.{k} contradicts the KB-JWT (SPEC §9.1)")
            ignored.update(kb.pop("_ignored", {}))
            art_results.append({"name": a.get("name"), "signature_ok": sig_ok,
                                "claims_match": claims_ok, "kb_jwt": kb,
                                "provenance_class": key.get("provenance_class"),
                                "self_asserted": self_asserted,
                                "ignored": {k: v for k, v in sorted(ignored.items()) if v},   # SPEC §9.2: only the non-empty slots
                                **({"x5c_leaf": leaf_ident} if leaf_ident else {})})
            all_ok = (all_ok and sig_ok and claims_ok
                      and kb.get("verified") is not False)
            for_bindings.append({"name": a.get("name"), "compact": parsed["compact"],
                                 "resolved_claims": resolved})
        except Exception as e:  # noqa: BLE001 — any malformation of an artifact is that artifact's error, never a traceback
            art_results.append({"name": a.get("name") if isinstance(a, dict) else None, "error": f"{type(e).__name__}: {str(e)[:120]}"})
            all_ok = False

    try:   # r4: the binding SET (SPEC §4) — entries compared by sorted canonical form; the scan order of JS Object.keys puts
        # array-index keys ("0", "7") first, so an ordered comparison split the verdict on a pack the reference itself built
        bindings_ok = (sorted(_canon(b) for b in find_bindings(for_bindings)) == sorted(_canon(b) for b in ev.get("bindings", []))) if all_ok else False
    except Exception:  # noqa: BLE001
        bindings_ok = False

    classes = sorted({r.get("provenance_class") for r in art_results
                      if r.get("provenance_class")})

    # OMEGA producer signature(s) over the digest: crypto-agile, hybrid (classical + ML-DSA-65).
    # A claimed-but-invalid signature is tamper -> fail-closed. pq_protected only on a valid PQ sig.
    prod = ev.get("producer_signatures")
    if prod is not None:   # 1.1.0 r1: an EMPTY block is present with zero passing signatures -> not ok (SPEC §5), like the JS verifier
        pv = _sigsuite.verify_producer_block(
            prod, recomputed_digest.encode("ascii"),
            trusted=trusted_producer_keys)
        producer = {"present": True, "scheme": pv["scheme"], "scheme_ok": pv["scheme_ok"], "ok": pv["ok"],
                    "pq_protected": pv["pq_protected"], "trusted": pv["trusted"],
                    "signatures": pv["results"]}
        if not pv["ok"]:
            all_ok = False
        # a pinned trust set that the producer key does NOT match = not authentic
        if trusted_producer_keys is not None and pv["trusted"] is not True:
            all_ok = False
    else:
        producer = {"present": False, "pq_protected": False, "trusted": None,
                    "note": "no producer signature; pack integrity rests on digest + time anchor only. "
                            "Without a pinned producer key a signature would prove consistency, not authenticity."}
    # relying-party policy: enforce PQ / producer so a stripped-signature downgrade is rejected
    policy_ok = True
    if require_producer and not (producer["present"] and producer.get("ok")):
        policy_ok = False
    if require_pq and not (producer.get("pq_protected") and producer.get("trusted") is True):
        policy_ok = False
    # require_anchor: the existed-by claim must be PROVEN, not merely claimed. A missing
    # anchor, an unverifiable one (no openssl -> verified None), or a failing token all
    # reject — fail-closed, "claimed" never upgrades to "proven".
    need = max(1 if require_anchor else 0, min_anchors or 0)   # SPEC §3.3: require_anchor alone is min_anchors = 1
    if need and anchors_verified < need:
        policy_ok = False

    return {"digest_ok": digest_ok, "artifacts": art_results,
            "producer_signatures": producer, "pq_protected": producer.get("pq_protected", False),
            "bindings_ok": bindings_ok, "rfc3161": rfc,
            "anchors": anchor_results, "anchors_verified": anchors_verified,   # 1.5.0 — SPEC §3.3
            "provenance_classes": classes,
            # r7 FAIL-CLOSED, r10 with ANY: the flag warns that a key in this pack is self-asserted, so ONE reconciled
            # artifact must not clear it for the others — measured: a pack whose mandate was `jwk_header` and whose second
            # artifact chained to the anchor reported `self_asserted_only: false`, i.e. "no self-asserted key here", while
            # the mandate-signing key had never been reconciled at all. A label ("supplied", "jwks_fetched") never clears it.
            "self_asserted_only": (not art_results) or any(r.get("self_asserted", True) for r in art_results),   # final check: zero artifacts is not "no self-asserted key", it is nothing measured
            # r8: what the verifier DID about chains — None when no anchor was supplied (so the flag above is fail-closed true)
            # r9: True only if every chain really validated; None when openssl could not measure it. r11: only artifacts that
            # ATTEMPTED a chain count — before, one `jwk_header` artifact anywhere collapsed the field to None even when every
            # x5c chain present had validated, which is the r10 `all()` defect one field over (invisible to the oracle, since
            # the JS verifier always answers null).
            "chain_verified": _chain_verdict(trust_anchor, art_results),
            # un evidence senza artefatti non prova NULLA: mai 'valid' (falso-verde per l'auditor)
            "policy_ok": policy_ok,
            "valid": bool(art_results and digest_ok and all_ok and bindings_ok
                          and rfc.get("verified") is not False and policy_ok),
            "honest_scope": ev.get("honest_scope"),
            # informative, both verifiers (SPEC §6): whether THIS verifier can check ML-DSA-65 at all — without it a
            # producer signature is SKIP, never a pass, and the reader of the receipt should not have to guess why
            "mldsa_backend": bool(_sigsuite.MLDSA_AVAILABLE)}


# ────────────────────────────────────────────────────────── CLI

EX_IOERR = 74   # 1.5.2 — sysexits.h: the outcome was computed but its receipt (or the output file) was not written whole


def _to_devnull(stream) -> None:
    """The bytes still buffered in a stream whose write failed must not fail again at interpreter exit: that exit is 120
    with an "Exception ignored" message, not ours. fd -> /dev/null, so the final flush succeeds and discards them."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, stream.fileno())
        os.close(null)
    except (OSError, ValueError, AttributeError):
        pass


def _text_layer_bytes(stream, buf, text: str) -> bytes:
    """The bytes Python's own text layer over `buf` writes for `text` as the first thing written: its encoding and error
    handler, "\\n" as os.linesep where the platform translates it (not Linux; not measured here), and a byte order mark
    only where that layer puts one: utf-16 / utf-32 only on a stream seekable at offset 0 (a file), utf-8-sig on a pipe
    too, none on a seekable stream past offset 0 (measured on Python 3.9, 3.11 and 3.13, 13/10/2026)."""
    import codecs
    if os.linesep != "\n":
        text = text.replace("\n", os.linesep)
    encoding = stream.encoding or "utf-8"
    enc = codecs.getincrementalencoder(encoding)(stream.errors or "strict")
    try:
        seekable = buf.seekable()
        at_start = seekable and buf.tell() == 0
    except (OSError, ValueError):
        seekable = at_start = False
    if (seekable and not at_start) or (not seekable and codecs.lookup(encoding).name in ("utf-16", "utf-32")):
        enc.setstate(0)   # no byte order mark
    return enc.encode(text, final=True)


def _wait_writable(buf) -> None:
    """The stream is non-blocking and full: wait until it can take more, as a blocking write would (the reader is slow,
    not gone; one that goes away makes the next write EPIPE). `select` sleeps in the kernel and Python retries it after a
    signal (PEP 475). The descriptor is asked for only here: a byte stream with no descriptor (an io.BytesIO under a
    TextIOWrapper, as pytest's capsys) never blocks. POSIX only: on Windows `select` waits on sockets only, so a full
    non-blocking pipe there is reported as 74 (not measured)."""
    import select
    try:
        select.select([], [buf.fileno()], [])
    except (OSError, ValueError) as e:   # no descriptor, or one select cannot wait on
        raise OSError(f"non-blocking and cannot be waited for: {e}")


def _write_all(stream, text: str) -> None:
    """Write the whole text to `stream` (stdout or stderr) and flush it; raise when it did not all get there. The bytes go
    to `stream.buffer` in a loop that checks the count: with -u or PYTHONUNBUFFERED that is a raw FileIO whose write() can
    take part of the data (`ulimit -f`, a disk nearly full) and return the count without raising, or return None (a full
    non-blocking pipe), and the text layer above dropped the rest in silence (measured 13/10/2026 on 1.5.2 before this
    change: exit 0 with 24 bytes of the receipt on a file under `ulimit -f 1`). A non-blocking stream that is full is
    waited for, never given up on (before: 74 with 65 536 bytes in the pipe, or 0 with them under -u). A text stream
    with no bytes below it (io.StringIO) gets the text itself."""
    stream.flush()   # whatever the text layer still holds goes first
    buf = getattr(stream, "buffer", None)
    if buf is None:
        stream.write(text)
        stream.flush()
        return
    data = memoryview(_text_layer_bytes(stream, buf, text))
    while data:
        try:
            n = buf.write(data)
            waited = False
        except BlockingIOError as e:   # buffered stream on a full non-blocking pipe: part of it taken
            n, waited = e.characters_written, True
        if n is None:   # raw stream on a full non-blocking pipe: nothing taken
            n, waited = 0, True
        if n < 0 or n > len(data) or (n == 0 and not waited):
            raise OSError(f"short write: {len(data)} bytes not written")
        data = data[n:]
        if data and waited:
            _wait_writable(buf)
    while True:   # flushed HERE, before the exit code is chosen, not by the interpreter at exit
        try:
            buf.flush()
            return
        except BlockingIOError:
            _wait_writable(buf)


def _emit(text: str) -> Optional[str]:
    """Write the receipt to stdout whole and flushed, before the exit code is chosen. Returns None when every byte was
    handed to the OS, else the reason. Before 1.5.2 the receipt went through print(): on /dev/full or a closed pipe a
    receipt that fit the stream buffer failed at the interpreter's final flush (exit 120, "Exception ignored"), a larger
    one failed inside print() (a traceback, exit 1, also for a valid pack: 84 620 bytes measured), and with stdout closed
    (`>&-`, sys.stdout is None) print() did nothing and the exit was the verdict's 0/1 (measured 2026-10-12 on 1.5.1)."""
    out = sys.stdout
    if out is None:
        return "stdout is closed"
    try:
        _write_all(out, text + "\n")
        return None
    except (OSError, ValueError) as e:   # ENOSPC, EPIPE, EBADF, EFBIG; ValueError: write to a closed file object
        _to_devnull(out)
        return f"{type(e).__name__}: {e}"


def _say(text: str) -> bool:
    """Write `text` to stderr without ever raising, through the same writer as the receipt (a full non-blocking stderr is
    waited for); True when it was written. A stderr that fails is pointed at the null device, so the interpreter's last
    flush cannot fail again and turn the exit code into 120."""
    err = sys.stderr
    if err is None:
        return False
    try:
        _write_all(err, text)
        return True
    except (OSError, ValueError):
        _to_devnull(err)
        return False


def _not_written(reason: str) -> int:
    """One line on stderr, if stderr can take it; the exit is EX_IOERR either way."""
    _say(f"receipt not written: {reason}\n")
    return EX_IOERR


def _refused(msg: str) -> int:
    """A refusal of `build` / `stamp`: one `{"error": ...}` line on stderr, exit 1; never on stdout. When that line cannot
    be written (stderr on /dev/full, or closed) the exit is EX_IOERR, as for a lost receipt (1.5.2 review: before, stderr
    full gave the interpreter's 120 and stderr closed sent the refusal to stdout)."""
    if _say(json.dumps({"error": msg}) + "\n"):
        return 1   # a closed stderr (_ClosedStderr) turns this into EX_IOERR in main()
    return EX_IOERR


class _ClosedStderr:
    """sys.stderr while fd 2 is closed (sys.stderr is None): what would have gone there is counted, never sent to stdout
    (argparse prints its usage to stdout when sys.stderr is None)."""
    lost = False

    def write(self, s):
        if s:
            self.lost = True
        return len(s)

    def flush(self):
        pass


class _Parser(argparse.ArgumentParser):
    """argparse up to 3.12 lets the OSError of a usage message written to a full stderr escape (a traceback, then 120);
    3.13 swallows it. Here the failed write is recorded and the exit becomes EX_IOERR in every version."""
    stderr_lost = False

    def _print_message(self, message, file=None):
        if not message:
            return
        file = sys.stderr if file is None else file
        if file is sys.stderr:
            if not _say(message):
                _Parser.stderr_lost = True
            return
        try:
            file.write(message)
        except (OSError, ValueError):
            _Parser.stderr_lost = True
            _to_devnull(file)


def _stderr_settled(rc: int) -> int:
    """The exit code once stderr is flushed: EX_IOERR when a message meant for stderr (usage, refusal, the "receipt not
    written" line) did not get there, so a full or closed stderr never gives the interpreter's 120 or a traceback."""
    err = sys.stderr
    if getattr(err, "lost", False) or _Parser.stderr_lost:
        return EX_IOERR
    try:
        if err is not None:
            err.flush()
        return rc
    except (OSError, ValueError):
        _to_devnull(err)
        return EX_IOERR


def main(argv: Optional[List[str]] = None) -> int:
    if sys.stderr is None:
        sys.stderr = _ClosedStderr()
    _Parser.stderr_lost = False
    try:
        rc = _main(argv)
    except SystemExit as e:   # argparse usage errors (2)
        if not isinstance(e.code, int):
            raise
        raise SystemExit(_stderr_settled(e.code)) from None
    return _stderr_settled(rc)


def _main(argv: Optional[List[str]] = None) -> int:
    p = _Parser(prog="ap2-evidence-pack", allow_abbrev=False, add_help=False,
                                description="Self-contained, offline-verifiable dispute "
                                            "evidence for agentic-payment SD-JWT mandates")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build", allow_abbrev=False, add_help=False)
    b.add_argument("out")
    b.add_argument("artifacts", nargs="+", metavar="name=path",
                   help="e.g. checkout=checkout.sdjwt payment=payment.sdjwt")
    b.add_argument("--key", action="append", default=[], metavar="name=jwk.json",
                   help="supplied verification JWK for an artifact")
    b.add_argument("--jwks-url", action="append", default=[], metavar="name=https://...",
                   help="fetch the key from a JWKS at build time (TLS witness)")
    b.add_argument("--tsa", action="append", default=[], help="RFC 3161 TSA URL (optional third-party time anchor); may repeat: the first goes to rfc3161_timestamp, the others to anchors (SPEC §3.3)")
    b.add_argument("--subject", default="agentic-payment mandate evidence")
    st = sub.add_parser("stamp", allow_abbrev=False, add_help=False)   # 1.5.0 — SPEC §3.3: add an anchor to an existing pack
    st.add_argument("evidence")
    st.add_argument("--tsa", required=True, action="append", help="RFC 3161 TSA URL: append its token to `anchors` (exactly one per run)")
    v = sub.add_parser("verify", allow_abbrev=False, add_help=False)
    v.add_argument("evidence")
    v.add_argument("--trusted-producer-key", action="append", default=None, metavar="ALG=B64",
                   help="pin a producer public key as <sig_alg>=<base64> (e.g. ed25519=…, ml-dsa-65=…); may repeat. With any pin, an unpinned producer is not authentic")
    v.add_argument("--require-producer", action="store_true", help="policy: a valid producer signature is required")
    v.add_argument("--require-pq", action="store_true", help="policy: a valid, PINNED post-quantum producer signature is required")
    v.add_argument("--require-anchor", action="store_true", help="policy: the RFC 3161 anchor must be present and BOUND to this pack (status granted, messageImprint = digest); with --tsa-cert also TSA-verified")
    v.add_argument("--trust-anchor", help="PEM trust anchor: validate the artifact x5c chain with openssl verify. Without it every key is self-asserted (offline, a certificate proves only that the signer wrote it) — the JS verifier cannot validate chains and reports chain_verified null (declared)")
    v.add_argument("--min-anchors", help="policy: at least N distinct anchors must verify (SPEC §3.3; --require-anchor alone is 1)")
    v.add_argument("--tsa-cert", help="PEM certificate (or chain) of the TSA: verify the token's signature and chain with openssl ts -verify (without it, the TSA is NOT verified — declared)")
    raw = list(sys.argv[1:] if argv is None else argv)
    # 1.1.0: one CLI grammar with the sibling verifiers — "" or a flag as a value, "--", -h/--help, a value on a boolean flag,
    # an abbreviated flag = usage (exit 2, no verdict); the file path itself must not be "" or flag-like
    if "--" in raw or any(x in ("-h", "--help") for x in raw) or any(x.split("=", 1)[0] in ("--require-producer", "--require-pq", "--require-anchor") and "=" in x for x in raw):
        p.error("unexpected argument")
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok in ("--trusted-producer-key", "--key", "--jwks-url", "--tsa", "--subject", "--tsa-cert", "--trust-anchor", "--min-anchors"):
            val = raw[i + 1] if i + 1 < len(raw) else None
            if val is None or val == "" or val.startswith("-"):
                p.error(f"{tok} needs a value (got {val!r})")
            i += 2; continue
        if tok.split("=", 1)[0] in ("--trusted-producer-key", "--key", "--jwks-url", "--tsa", "--subject", "--tsa-cert", "--trust-anchor", "--min-anchors") and "=" in tok:
            val = tok.split("=", 1)[1]
            if val == "" or val.startswith("-"):
                p.error(f"{tok.split('=', 1)[0]} needs a value (got {val!r})")
        i += 1
    a = p.parse_args(raw)
    if a.cmd == "build":
        # r5: every name=path pair is validated as a pair, and a file that cannot be read is a usage error (exit 2),
        # never the FileNotFoundError traceback `--key foo` / a missing artifact file used to produce
        def _pair(flag, spec):
            name, sep, path = spec.partition("=")
            if not sep or not name or not path:
                p.error(f"{flag} expects name=path (got {spec!r})")
            return name, path

        def _read(flag, path, as_json=False):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f) if as_json else f.read()
            except OSError as e:
                p.error(f"{flag}: cannot read {path!r} ({type(e).__name__})")
            except ValueError as e:
                p.error(f"{flag}: {path!r} is not valid JSON ({e})")

        arts = []
        for spec in a.artifacts:
            name, path = _pair("artifact", spec)
            arts.append({"name": name, "sd_jwt": _read("artifact", path)})
        keys = {}
        for spec in a.key:
            name, path = _pair("--key", spec)
            keys[name] = _read("--key", path, as_json=True)
        jwks = dict(_pair("--jwks-url", s) for s in a.jwks_url)
        try:
            res = build_evidence(arts, a.out, keys=keys, jwks_urls=jwks,
                                 tsa_url=(a.tsa[0] if a.tsa else None), subject=a.subject,
                                 extra_tsa_urls=a.tsa[1:])
        except Ap2WriteError as e:
            return _not_written(str(e))
        except Ap2EvidenceError as e:
            return _refused(str(e))
        why = _emit(json.dumps(res, indent=1))
        return 0 if why is None else _not_written(why)
    if a.cmd == "stamp":
        if a.evidence == "" or a.evidence.startswith("-"):
            p.error(f"evidence path needs a value (got {a.evidence!r})")
        if len(a.tsa) != 1:   # measured on b3edfc8: `--tsa A --tsa B` stamped B only, exit 0, A dropped in silence
            p.error(f"stamp takes exactly one --tsa (got {len(a.tsa)}): run it once per TSA")
        try:
            res = add_anchor(a.evidence, a.tsa[0])
        except Ap2WriteError as e:
            return _not_written(str(e))
        except Ap2EvidenceError as e:
            return _refused(str(e))
        why = _emit(json.dumps(res, indent=1))
        return 0 if why is None else _not_written(why)
    if a.cmd == "verify":
        if a.evidence == "" or a.evidence.startswith("-"):
            p.error(f"evidence path needs a value (got {a.evidence!r})")
        min_anchors = None
        if a.min_anchors is not None:
            if not re.fullmatch(r"[1-9][0-9]{0,5}", a.min_anchors):   # ASCII digits, >= 1 (the JS verifier: the same grammar)
                p.error(f"--min-anchors expects an integer >= 1 (got {a.min_anchors!r})")
            min_anchors = int(a.min_anchors)
        trusted = None
        if a.trusted_producer_key:
            trusted = {}
            for spec in a.trusted_producer_key:
                alg, sep, key = spec.partition("=")
                if not sep or not alg or not key:
                    p.error(f"--trusted-producer-key expects ALG=B64 (got {spec!r})")
                trusted.setdefault(alg, []).append(key)
        r = verify_evidence(a.evidence, trusted_producer_keys=trusted, require_pq=a.require_pq,
                            require_producer=a.require_producer, require_anchor=a.require_anchor, tsa_cert=a.tsa_cert,
                            trust_anchor=a.trust_anchor, min_anchors=min_anchors)
        why = _emit(json.dumps(r, indent=1))
        if why is not None:   # 1.5.2: never the verdict's 0/1 when the receipt did not reach stdout whole
            return _not_written(why)
        return 0 if r["valid"] else 1
    p.print_help(sys.stderr)   # r3: usage goes to stderr, no verdict on stdout — as every other usage path and the JS verifier
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
