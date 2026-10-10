#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generative proof of the closed schema (SPEC §9): every object at every level, mutated every way, with the EXPECTED
outcome computed from the SPEC tables — never from a verifier — and both verifiers held to it and to each other.

Why. On 2026-10-10 an outside reader touched the anchor block and the 1.3.0 verifiers accepted, with `valid: true` and
no trace in the receipt, a key nobody had defined — inside rfc3161_timestamp, inside the producer block, inside every
signature entry. Our fuzzers varied the TYPES of known fields; none of them ever added a key. Enumerating attacks one by
one always forgets one; this bench instead derives the mutations from the schema itself: for every object the SPEC
defines (§9.1) and every object a standard defines (§9.2), at every level of every conformance vector and of freshly
signed packs:

  unknown keys       ASCII, non-ASCII, `__proto__`, `constructor`, the empty string, a control character, a case variant
                     of a known key, a dotted/bracketed name — with values of every JSON type and a boundary integer
  wrong types        every known key replaced by each hostile type (null, number, string, list, object, boolean)
  missing keys       every required key deleted; every optional key deleted (must change nothing)
  duplicate keys     the first key of every object spelled twice (textual — a parser must refuse, SPEC §3.1)
  key order          every object with its keys reversed (must change nothing — the digest is canonical)
  spelling           known keys written with \\u escapes (the same key — must change nothing); non-ASCII values
  JOSE / JWT / JWK   unregistered header parameters, JWK members, cnf members and KB-JWT claims (ignored AND reported,
                     RFC 7515 §4 / 7517 §4 / 7800 §3.1 / 7519 §4); `crit` in every malformed and well-formed shape
                     (the JWS is invalid, RFC 7515 §4.1.11); KB-JWT typ and REQUIRED claims (RFC 9901 §4.3)
  out of grammar     trailing data, truncation, comments, single quotes, NaN, Infinity, BOM, leading zero, hex, +sign

Each mutation carries its EXPECTED CLASS from the SPEC tables: REFUSE (a refusal naming the key), ARTERR (that artifact's
error), SIGFAIL (that producer-signature entry FAIL, block not ok), ANCHOR_FALSE (rfc3161_verified false),
CLAIMS_MISMATCH, REPORT (verdict unchanged, name listed in artifacts[i].ignored.<slot>), RECORDED (an unknown issuer
claim is simply part of the resolved claims), UNCHANGED (every compared field identical to the unmutated source). Every
mutation must (1) meet its class in the Python reference, (2) meet it in the JS verifier, (3) give the same compared
fields in both — the differential. The unmutated sources are compared too.

Positive control (the bench must be able to fail): run it against the 1.3.0 verifiers —
    python3 verifiers/schema_mutants.py --py-root <checkout of v1.3.0> --js <its verifiers/js/ap2-verify.mjs>
and the §9.1 mutations pass silently there: valid unchanged, nothing in the receipt. The counts are in CHANGELOG 1.4.0.

    python3 verifiers/schema_mutants.py [--full] [--py-root DIR] [--js FILE] [--json OUT] [--keep]

The corpus is written under TMPDIR in a directory of its own and removed at the end (--keep to inspect it). One process
loads ONE Python reference (the one at --py-root): the positive control is a separate invocation, by design.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
VDIR = os.path.join(ROOT, "spec", "vectors", "ap2")
JS_DEFAULT = os.path.join(HERE, "js", "ap2-verify.mjs")
VERIFY_MANY = os.path.join(HERE, "js", "verify_many.mjs")

REFUSE, ARTERR, SIGFAIL, ANCHOR_FALSE, CLAIMS_MISMATCH, REPORT, RECORDED, UNCHANGED = (
    "REFUSE", "ARTERR", "SIGFAIL", "ANCHOR_FALSE", "CLAIMS_MISMATCH", "REPORT", "RECORDED", "UNCHANGED")
SIGNAL_CLASSES = (REFUSE, ARTERR, SIGFAIL, ANCHOR_FALSE, CLAIMS_MISMATCH)

UNKNOWN_KEYS_FULL = ["x_unknown", "ünïcödé_ключ", "__proto__", "constructor", "", "A\u0000B", "a.b[0]"]
UNKNOWN_VALUES = ["x", 1, True, None, [], {}, 9007199254740991]
HOSTILE_FULL = [None, 0, "", [], {}, True, "x", 1]
HOSTILE_QUICK = [None, "", {}, "x"]

# ── the SPEC §9.1 tables, as data: key -> (python type, required, enum) ─────────────────────────────────────────────
# `enum` marks a string key with a constrained value, so the hostile string "x" is a violation there (a free string is not).
S, B, L, O, ANY = "str", "bool", "list", "obj", "any"
TOP = {"evidence_format": (S, 1, 1), "subject": (S, 1, 0), "created_utc": (S, 1, 1), "artifacts": (L, 1, 0), "bindings": (L, 0, 0),
       "honest_scope": (S, 1, 1), "evidence_digest_sha256": (S, 1, 0), "rfc3161_timestamp": (O, 0, 0), "producer_signatures": (O, 0, 0)}
RFC = {"anchored": (B, 1, 0), "tsr_b64": (S, 0, 0), "tsa_url": (S, 0, 0), "tsa": (S, 0, 0), "note": (S, 0, 0)}
PROD = {"scheme": (S, 1, 1), "over": (S, 1, 1), "signatures": (L, 1, 0)}
ENTRY = {"sig_alg": (S, 1, 0), "public_key_b64": (S, 1, 1), "signature_b64": (S, 1, 1), "post_quantum": (B, 1, 0)}
BIND = {"in": (S, 1, 0), "claim": (S, 1, 0), "commits_to": (S, 1, 0), "encoding": (S, 1, 1)}
ART = {"name": (S, 1, 0), "sd_jwt_compact": (S, 1, 1), "header": (O, 1, 0), "key": (O, 1, 0), "resolved_claims": (ANY, 1, 0), "kb_jwt": (O, 1, 0), "verified_at_build": (O, 1, 0)}
KEY = {"jwk": (O, 1, 0), "provenance_class": (S, 1, 1), "note": (S, 0, 0), "x5c_chain_sha256": (L, 0, 0), "jwks_url": (S, 0, 0), "jwks_sha256": (S, 0, 0), "fetched_utc": (S, 0, 0)}
KBC = {"present": (B, 1, 0), "verified": ("bool_or_null", 0, 0), "signature_ok": (B, 0, 0), "sd_hash_ok": (B, 0, 0), "note": ("str_or_null", 0, 0), "claims_recorded_not_validated": (O, 0, 0)}
VAB = {"signature_ok": ("true", 1, 0), "disclosures_ok": ("true", 1, 0)}
PYTYPE = {S: str, B: bool, L: list, O: dict, ANY: object, "bool_or_null": bool, "str_or_null": str, "true": bool}


def _wrong_type(kind, value):
    if kind == ANY:
        return False
    if kind == "bool_or_null": return not (value is None or isinstance(value, bool))
    if kind == "str_or_null": return not (value is None or isinstance(value, str))
    if kind == "true": return value is not True
    return type(value) is not PYTYPE[kind]


# ── corpus helpers ──────────────────────────────────────────────────────────────────────────────────────────────────
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def rehash(ev: dict) -> dict:
    e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    ev = dict(ev); ev["evidence_digest_sha256"] = hashlib.sha256(canon(e2)).hexdigest(); ev.pop("producer_signatures", None); return ev


UNSEALED_TOP = ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")


def strip(ev: dict) -> dict:
    """The sealed content alone, resealed: no producer block, no anchor block — a source whose verdict rests on the content."""
    ev = rehash(ev); ev.pop("rfc3161_timestamp", None); return ev


def flags_for(policy: dict):
    fl = []
    for alg, keys in (policy.get("trusted_producer_keys") or {}).items():
        for k in ([keys] if isinstance(keys, str) else keys):
            fl += ["--trusted-producer-key", f"{alg}={k}"]
    for name in ("require_producer", "require_pq", "require_anchor"):
        if policy.get(name):
            fl.append("--" + name.replace("_", "-"))
    return fl


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Fresh:
    """Freshly signed packs (own keys): the only way to mutate INSIDE a signed header/payload and still verify the signature."""

    def __init__(self, scope):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.ec = ec; self.scope = scope
        self.sk, self.jwk = self._signer(); self.hsk, self.hjwk = self._signer()

    def _signer(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        sk = ec.generate_private_key(ec.SECP256R1()); n = sk.public_key().public_numbers()
        return sk, {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}

    def sign(self, sk, header_txt: bytes, payload_txt: bytes) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        si = _b64u(header_txt) + "." + _b64u(payload_txt)
        r, s = decode_dss_signature(sk.sign(si.encode("ascii"), self.ec.ECDSA(hashes.SHA256())))
        return si + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def pack(self, header, payload, resolved=None, header_txt=None, payload_txt=None, kb=None, name="intent"):
        """`header`/`payload` as dicts (the artifact copies); the raw texts default to their compact dumps — pass raw bytes to
        sign a duplicate key or any other text a dict cannot hold. `kb` is a complete KB-JWT string or None."""
        ht = header_txt if header_txt is not None else json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()
        pt = payload_txt if payload_txt is not None else json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        compact = self.sign(self.sk, ht, pt) + "~" + (kb or "")
        art = {"name": name, "sd_jwt_compact": compact, "header": header,
               "key": {"jwk": self.jwk, "provenance_class": "jwk_header", "note": "key embedded in the protected header (self-asserted)"},
               "resolved_claims": resolved if resolved is not None else payload, "kb_jwt": {"present": bool(kb)},
               "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}
        return rehash({"evidence_format": "ap2-evidence-pack/1.0", "subject": "schema mutants", "created_utc": "2026-10-10T00:00:00Z",
                       "artifacts": [art], "bindings": [], "honest_scope": self.scope})

    def kb(self, presentation: str, header=None, payload=None, header_txt=None, payload_txt=None) -> str:
        header = header if header is not None else {"alg": "ES256", "typ": "kb+jwt"}
        payload = payload if payload is not None else {"iat": 1760054400, "aud": "merchant", "nonce": "n1", "sd_hash": _b64u(hashlib.sha256(presentation.encode("ascii")).digest())}
        ht = header_txt if header_txt is not None else json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()
        pt = payload_txt if payload_txt is not None else json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        return self.sign(self.hsk, ht, pt)


# ── corpus ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class Corpus:
    def __init__(self, d: str, quick: bool):
        self.d = d; self.quick = quick; self.recs = []; self.n = 0
        self.unknown_keys = UNKNOWN_KEYS_FULL[:4] if quick else UNKNOWN_KEYS_FULL
        self.hostile = HOSTILE_QUICK if quick else HOSTILE_FULL

    def write(self, obj_or_text, suffix=".json") -> str:
        self.n += 1; p = os.path.join(self.d, f"m{self.n:05d}{suffix}")
        data = obj_or_text if isinstance(obj_or_text, (bytes, str)) else json.dumps(obj_or_text, ensure_ascii=False)
        with open(p, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
        return p

    def add(self, name, path, flags, cls, base, idx=None, sig=None, needle=None, slot=None, key=None, obj=None, kind=None):
        self.recs.append({"name": name, "path": path, "flags": list(flags), "cls": cls, "base": base, "idx": idx, "sig": sig,
                          "needle": needle, "slot": slot, "key": key, "obj": obj, "kind": kind})

    # -- objects of a pack: (label, locate(pack) -> (parent, key), table, unknown_cls, sealed, idx, sig) --
    def objects(self, ev):
        out = [("top", lambda e: (None, None), TOP, REFUSE, True, None, None)]
        if isinstance(ev.get("rfc3161_timestamp"), dict):
            out.append(("rfc3161_timestamp", lambda e: (e, "rfc3161_timestamp"), RFC, REFUSE, False, None, None))
        if isinstance(ev.get("producer_signatures"), dict):
            out.append(("producer_signatures", lambda e: (e, "producer_signatures"), PROD, REFUSE, False, None, None))
            for j, s in enumerate(ev["producer_signatures"].get("signatures", [])):
                if isinstance(s, dict):
                    out.append((f"signatures[{j}]", (lambda j: lambda e: (e["producer_signatures"]["signatures"], j))(j), ENTRY, SIGFAIL, False, None, j))
        for k, b in enumerate(ev.get("bindings", [])):
            out.append((f"bindings[{k}]", (lambda k: lambda e: (e["bindings"], k))(k), BIND, REFUSE, True, None, None))
        for i, a in enumerate(ev.get("artifacts", [])):
            out += [(f"artifacts[{i}]", (lambda i: lambda e: (e["artifacts"], i))(i), ART, ARTERR, True, i, None),
                    (f"artifacts[{i}].key", (lambda i: lambda e: (e["artifacts"][i], "key"))(i), KEY, ARTERR, True, i, None),
                    (f"artifacts[{i}].kb_jwt", (lambda i: lambda e: (e["artifacts"][i], "kb_jwt"))(i), KBC, ARTERR, True, i, None),
                    (f"artifacts[{i}].verified_at_build", (lambda i: lambda e: (e["artifacts"][i], "verified_at_build"))(i), VAB, ARTERR, True, i, None),
                    (f"artifacts[{i}].header", (lambda i: lambda e: (e["artifacts"][i], "header"))(i), None, ARTERR, True, i, None),
                    (f"artifacts[{i}].resolved_claims", (lambda i: lambda e: (e["artifacts"][i], "resolved_claims"))(i), None, CLAIMS_MISMATCH, True, i, None),
                    (f"artifacts[{i}].key.jwk", (lambda i: lambda e: (e["artifacts"][i]["key"], "jwk"))(i), None, REPORT, True, i, None)]
        return out

    @staticmethod
    def get(ev, locate):
        parent, key = locate(ev)
        return ev if parent is None else parent[key]

    @staticmethod
    def put(ev, locate, obj):
        parent, key = locate(ev)
        if parent is None:
            ev.clear(); ev.update(obj)
        else:
            parent[key] = obj

    def finish(self, ev, sealed):
        return rehash(ev) if sealed else ev

    def case_variant(self, table, obj):
        for k in (table or obj):
            if isinstance(k, str) and k and k[0].islower():
                v = k[0].upper() + k[1:]
                if v not in (table or {}) and v not in obj:
                    return v
        return None

    def mutate_object_family(self, src_name, src, flags, label, locate, table, unknown_cls, sealed, idx, sig, base):
        """Every mutation of ONE object (unknown keys, hostile types, deletions, duplicate, permutation, escaped spelling)."""
        obj = self.get(src, locate)
        if not isinstance(obj, dict):
            return
        fl = [] if sealed else flags
        # unknown keys, every value type (REPORT for the JWK: ignored and listed under `key_jwk`)
        keys = list(self.unknown_keys); cv = self.case_variant(table, obj)
        if cv: keys.append(cv)
        for n, k in enumerate(keys):
            if k in obj or (table and k in table):
                continue
            vals = UNKNOWN_VALUES if not self.quick else UNKNOWN_VALUES[n % len(UNKNOWN_VALUES):n % len(UNKNOWN_VALUES) + 1]
            for v in vals:
                e = copy.deepcopy(src); o = self.get(e, locate); o[k] = v
                cls = unknown_cls; needle = json.dumps(k, ensure_ascii=False) if cls in (REFUSE, ARTERR) and table else None
                if cls == ARTERR and not table:   # the header copy: it no longer equals the signed header
                    needle = "header copy"
                self.add(f"{src_name}/{label}/unknown-key/{json.dumps(k, ensure_ascii=False)}={json.dumps(v)}", self.write(self.finish(e, sealed)), fl, cls, base,
                         idx=idx, sig=sig, needle=needle, slot="key_jwk" if cls == REPORT else None, key=k, obj=label, kind="unknown-key")
        if table is None:
            # the header copy and resolved_claims: hostile types of the object itself
            for h in self.hostile:
                if type(h) is dict:
                    continue
                e = copy.deepcopy(src); self.put(e, locate, h)
                cls = ARTERR if label.endswith(".header") else (CLAIMS_MISMATCH if label.endswith("resolved_claims") else ARTERR)
                self.add(f"{src_name}/{label}/type/{json.dumps(h)}", self.write(self.finish(e, sealed)), fl, cls, base, idx=idx, obj=label, kind="wrong-type")
            self.textual(src_name, src, fl, label, locate, REFUSE, sealed, base, idx, sig)
            return
        # hostile types and deletions of every known key
        for k, (kind, required, enum) in table.items():
            present = k in obj
            for h in self.hostile:
                if present and not _wrong_type(kind, h) and not (enum and isinstance(h, str)):
                    continue   # the same type (or a free string): not a schema violation — the value's own rule decides, elsewhere
                if not present and (not _wrong_type(kind, h) and not (enum and isinstance(h, str))):
                    continue
                if isinstance(h, str) and h and not enum:
                    continue
                cls = unknown_cls
                if label == "rfc3161_timestamp" and k == "tsr_b64" and isinstance(h, str):
                    cls = ANCHOR_FALSE    # "x" is a string: not a shape violation, a token that does not decode (SPEC §3.2)
                if label.startswith("artifacts[") and table is ART and k == "name":
                    cls = REFUSE          # SPEC §2: a non-string name is a refusal, checked before the artifact loop
                if label.startswith("artifacts[") and table is ART and k == "resolved_claims":
                    continue              # ANY type: compared, not typed — covered by the resolved_claims family
                e = copy.deepcopy(src); o = self.get(e, locate); o[k] = h
                reseal = sealed and not (label == "top" and k in UNSEALED_TOP)   # the three unsealed keys are mutated on the resealed source as they are
                self.add(f"{src_name}/{label}/type/{k}={json.dumps(h)}", self.write(self.finish(e, reseal)), fl, cls, base, idx=idx, sig=sig, obj=label, key=k, kind="wrong-type")
            if present:
                e = copy.deepcopy(src); o = self.get(e, locate); del o[k]
                if label == "top" and k == "bindings" and obj.get("bindings"):
                    continue   # absent reads as []: with recorded bindings that is a bindings mismatch, not a schema case
                if label == "rfc3161_timestamp" and k == "tsr_b64":
                    cls = ANCHOR_FALSE if obj.get("anchored") is True else UNCHANGED   # SPEC §6.4: claimed without a token
                elif required:
                    cls = REFUSE if (table is ART and k == "name") else unknown_cls
                else:
                    cls = UNCHANGED
                reseal = sealed and not (label == "top" and k in UNSEALED_TOP)
                self.add(f"{src_name}/{label}/delete/{k}", self.write(self.finish(e, reseal)), fl, cls, base, idx=idx, sig=sig, obj=label, key=k, kind="delete")
        self.textual(src_name, src, fl, label, locate, REFUSE, sealed, base, idx, sig)

    def textual(self, src_name, src, fl, label, locate, dup_cls, sealed, base, idx, sig):
        """Duplicate first key (textual), reversed key order, escaped spelling of the first key."""
        obj = self.get(src, locate)
        if not isinstance(obj, dict) or not obj:
            return
        first = next(iter(obj)); orig = json.dumps(obj[first], separators=(",", ":"), ensure_ascii=False)
        # duplicate key: a sentinel marks the exact spot, so the replacement is the object's own key and nothing else
        e = copy.deepcopy(src); o = self.get(e, locate); o[first] = "@@DUP-SENTINEL@@"
        txt = json.dumps(e, separators=(",", ":"), ensure_ascii=False)
        tok = json.dumps(first, ensure_ascii=False) + ':"@@DUP-SENTINEL@@"'
        assert txt.count(tok) == 1, (label, first)
        txt = txt.replace(tok, json.dumps(first, ensure_ascii=False) + ":" + orig + "," + json.dumps(first, ensure_ascii=False) + ":" + orig)
        self.add(f"{src_name}/{label}/duplicate-key/{first}", self.write(txt), fl, dup_cls, base, idx=idx, sig=sig, needle="uplicate", obj=label, key=first, kind="duplicate-key")
        # reversed key order: the canonical form (sorted keys) is untouched, so nothing may change — digest included
        e = copy.deepcopy(src); o = self.get(e, locate); self.put(e, locate, dict(reversed(list(o.items()))))
        self.add(f"{src_name}/{label}/reorder", self.write(json.dumps(e, separators=(",", ":"), ensure_ascii=False)), fl, UNCHANGED, base, idx=idx, sig=sig, obj=label, kind="reorder")
        # escaped spelling of the first key ("subject" IS "subject"): nothing may change
        if first and first.isascii() and first.isalpha():
            e = copy.deepcopy(src); o = self.get(e, locate); o[first] = "@@ESC-SENTINEL@@"
            txt = json.dumps(e, separators=(",", ":"), ensure_ascii=False)
            tok = json.dumps(first) + ':"@@ESC-SENTINEL@@"'
            esc = '"' + first[:-1] + "\\u%04x" % ord(first[-1]) + '"'
            txt = txt.replace(tok, esc + ":" + orig)
            self.add(f"{src_name}/{label}/escaped-key/{first}", self.write(txt), fl, UNCHANGED, base, idx=idx, sig=sig, obj=label, key=first, kind="escaped-key")

    def grammar(self, base_name, text, flags):
        """Out-of-grammar files: a refusal, never a verdict read off a lenient parse."""
        cases = {"trailing-data": text + "x", "truncated": text[:-20], "line-comment": text.replace("{", "{// c\n", 1), "single-quotes": text.replace('"subject"', "'subject'", 1),
                 "nan": text.replace('"subject"', '"n":NaN,"subject"', 1), "infinity": text.replace('"subject"', '"n":Infinity,"subject"', 1), "bom": "﻿" + text,
                 "leading-zero": text.replace('"subject"', '"n":01,"subject"', 1), "hex-number": text.replace('"subject"', '"n":0x1,"subject"', 1),
                 "plus-sign": text.replace('"subject"', '"n":+1,"subject"', 1), "float": text.replace('"subject"', '"n":1.0,"subject"', 1), "exponent": text.replace('"subject"', '"n":1e2,"subject"', 1),
                 "int-over-2^53": text.replace('"subject"', '"n":9007199254740992,"subject"', 1), "lone-surrogate": text.replace('"subject"', '"n":"\\ud800","subject"', 1),
                 "control-char-raw": text.replace('"subject"', '"n":"a\tb","subject"', 1), "empty": "", "array": "[" + text + "]", "unquoted-key": text.replace('"subject"', "subject", 1)}
        for nm, t in cases.items():
            self.add(f"{base_name}/grammar/{nm}", self.write(t), flags, REFUSE, base_name, obj="file", kind="grammar")

    def build(self):
        vectors = []
        for exp_path in sorted(f for f in os.listdir(VDIR) if f.endswith(".expected.json")):
            with open(os.path.join(VDIR, exp_path), encoding="utf-8") as f:
                exp = json.load(f)
            name = exp["vector"]
            with open(os.path.join(VDIR, name + ".json"), encoding="utf-8") as f:
                ev = json.load(f)
            vectors.append((name, ev, flags_for(exp.get("policy", {})), exp["normative"]))
        # baselines: every vector under its policy; every DISTINCT sealed content stripped of its anchor/producer blocks, resealed, no policy
        sealed_seen = {}
        for name, ev, flags, norm in vectors:
            self.add(f"base/{name}", os.path.join(VDIR, name + ".json"), flags, None, None, kind="baseline")
            r = strip(ev); dg = r["evidence_digest_sha256"]
            if dg not in sealed_seen:
                sealed_seen[dg] = f"base/{name}~resealed"
                self.add(sealed_seen[dg], self.write(r), [], None, None, kind="baseline")
        # mutations of every object of every vector
        for name, ev, flags, norm in vectors:
            if norm.get("valid") is not True and name not in ("stripped_signature", "unpinned_producer", "anchor_missing", "digest_mismatch"):
                continue   # a source whose baseline is already a refusal / an artifact error cannot attribute a new signal
            r = strip(ev); sealed_base = sealed_seen[r["evidence_digest_sha256"]]
            for label, locate, table, unknown_cls, sealed, idx, sig in self.objects(ev):
                if sealed:
                    self.mutate_object_family(name, r, [], label, locate, table, unknown_cls, True, idx, sig, sealed_base)
                else:
                    if unknown_cls == SIGFAIL and name in ("digest_mismatch",):
                        continue   # the producer signatures FAIL there already (recomputed digest): a FAIL entry is not attributable
                    self.mutate_object_family(name, ev, flags, label, locate, table, unknown_cls, False, idx, sig, f"base/{name}")
        base = next(ev for n, ev, _, _ in vectors if n == "valid_signed")
        self.grammar("base/valid_signed", json.dumps(base, separators=(",", ":"), ensure_ascii=False), flags_for({}))
        self.fresh(base["honest_scope"])

    def fresh(self, scope):
        """Inside the signature: JOSE header, header JWK, payload, cnf, KB-JWT — the standards' rules (SPEC §9.2)."""
        F = Fresh(scope); H = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": F.jwk}; P = {"iss": "user-wallet", "mandate_type": "intent", "max_amount": "150.00 EUR"}
        plain = F.pack(H, P); bp = self.write(plain); self.add("base/fresh-plain", bp, [], None, None, kind="baseline")
        keys = self.unknown_keys
        for k in keys:
            if k in H: continue
            h = dict(H); h[k] = "x"
            self.add(f"fresh/header/unknown-param/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(h, P)), [], REPORT, "base/fresh-plain", idx=0, slot="header", key=k, obj="jose-header", kind="unknown-key")
            j = dict(F.jwk); j[k] = "x"; h = dict(H, jwk=j)
            self.add(f"fresh/header.jwk/unknown-member/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(h, P)), [], REPORT, "base/fresh-plain", idx=0, slot="header_jwk", key=k, obj="jose-header-jwk", kind="unknown-key")
            p = dict(P); p[k] = "x"
            self.add(f"fresh/payload/unknown-claim/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(H, p)), [], RECORDED, "base/fresh-plain", idx=0, key=k, obj="jwt-payload", kind="unknown-key")
        # crit (RFC 7515 §4.1.11): well-formed = an extension we do not understand = invalid; malformed = invalid
        for nm, h in (("well-formed", dict(H, ap2_ext="x", crit=["ap2_ext"])), ("empty-list", dict(H, crit=[])), ("registered-name", dict(H, crit=["alg"])),
                      ("absent-name", dict(H, crit=["nothere"])), ("duplicate-name", dict(H, ap2_ext="x", crit=["ap2_ext", "ap2_ext"])), ("not-a-list", dict(H, crit="ap2_ext")),
                      ("list-of-int", dict(H, crit=[1])), ("null", dict(H, crit=None))):
            self.add(f"fresh/header/crit/{nm}", self.write(F.pack(h, P)), [], ARTERR, "base/fresh-plain", idx=0, needle="crit", obj="jose-header", key="crit", kind="crit")
        # duplicate keys INSIDE the signed segments (SPEC §3.1: the profile applies inside the SD-JWT)
        ht = json.dumps(H, separators=(",", ":")).encode(); pt = json.dumps(P, separators=(",", ":")).encode()
        self.add("fresh/header/duplicate-key", self.write(F.pack(H, P, header_txt=ht[:-1] + b',"typ":"x"}')), [], ARTERR, "base/fresh-plain", idx=0, needle="uplicate", obj="jose-header", kind="duplicate-key")
        self.add("fresh/payload/duplicate-key", self.write(F.pack(H, P, payload_txt=pt[:-1] + b',"iss":"other"}')), [], ARTERR, "base/fresh-plain", idx=0, needle="uplicate", obj="jwt-payload", kind="duplicate-key")
        # KB-JWT: cnf, cnf.jwk, KB header, KB payload
        PK = dict(P, cnf={"jwk": F.hjwk}); presentation = F.sign(F.sk, json.dumps(H, separators=(",", ":")).encode(), json.dumps(PK, separators=(",", ":")).encode()) + "~"
        kb_pack = F.pack(H, PK, kb=F.kb(presentation)); self.add("base/fresh-kb", self.write(kb_pack), [], None, None, kind="baseline")
        for k in keys:
            if k in ("jwk",): continue
            pk = copy.deepcopy(PK); pk["cnf"][k] = "x"; pres = F.sign(F.sk, ht, json.dumps(pk, separators=(",", ":"), ensure_ascii=False).encode()) + "~"
            self.add(f"fresh/cnf/unknown-member/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(H, pk, kb=F.kb(pres))), [], REPORT, "base/fresh-kb", idx=0, slot="cnf", key=k, obj="cnf", kind="unknown-key")
            pk = copy.deepcopy(PK); pk["cnf"]["jwk"][k] = "x"; pres = F.sign(F.sk, ht, json.dumps(pk, separators=(",", ":"), ensure_ascii=False).encode()) + "~"
            self.add(f"fresh/cnf.jwk/unknown-member/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(H, pk, kb=F.kb(pres))), [], REPORT, "base/fresh-kb", idx=0, slot="cnf_jwk", key=k, obj="cnf-jwk", kind="unknown-key")
            kh = {"alg": "ES256", "typ": "kb+jwt", k: "x"}
            self.add(f"fresh/kb-header/unknown-param/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(H, PK, kb=F.kb(presentation, header=kh))), [], REPORT, "base/fresh-kb", idx=0, slot="kb_jwt_header", key=k, obj="kb-header", kind="unknown-key")
            kp = {"iat": 1760054400, "aud": "merchant", "nonce": "n1", "sd_hash": _b64u(hashlib.sha256(presentation.encode("ascii")).digest()), k: "x"}
            self.add(f"fresh/kb-payload/unknown-claim/{json.dumps(k, ensure_ascii=False)}", self.write(F.pack(H, PK, kb=F.kb(presentation, payload=kp))), [], REPORT, "base/fresh-kb", idx=0, slot="kb_jwt_claims", key=k, obj="kb-payload", kind="unknown-key")
        sdh = _b64u(hashlib.sha256(presentation.encode("ascii")).digest()); KP = {"iat": 1760054400, "aud": "merchant", "nonce": "n1", "sd_hash": sdh}
        for nm, kh in (("typ-missing", {"alg": "ES256"}), ("typ-wrong", {"alg": "ES256", "typ": "JWT"}), ("typ-case", {"alg": "ES256", "typ": "KB+JWT"}), ("crit-well-formed", {"alg": "ES256", "typ": "kb+jwt", "ap2_ext": "x", "crit": ["ap2_ext"]}),
                       ("crit-empty", {"alg": "ES256", "typ": "kb+jwt", "crit": []}), ("alg-none", {"alg": "none", "typ": "kb+jwt"})):
            self.add(f"fresh/kb-header/{nm}", self.write(F.pack(H, PK, kb=F.kb(presentation, header=kh))), [], ARTERR, "base/fresh-kb", idx=0, needle="kb-jwt", obj="kb-header", kind=nm)
        for k in ("iat", "aud", "nonce", "sd_hash"):
            kp = dict(KP); del kp[k]
            self.add(f"fresh/kb-payload/missing/{k}", self.write(F.pack(H, PK, kb=F.kb(presentation, payload=kp))), [], ARTERR, "base/fresh-kb", idx=0, needle=k, obj="kb-payload", key=k, kind="delete")
            for h in self.hostile:
                if (k == "iat" and type(h) is int) or (k != "iat" and type(h) is str):
                    continue
                kp = dict(KP); kp[k] = h
                self.add(f"fresh/kb-payload/type/{k}={json.dumps(h)}", self.write(F.pack(H, PK, kb=F.kb(presentation, payload=kp))), [], ARTERR, "base/fresh-kb", idx=0, needle=k, obj="kb-payload", key=k, kind="wrong-type")
        kht = b'{"alg":"ES256","typ":"kb+jwt"'; kpt = json.dumps(KP, separators=(",", ":")).encode()
        self.add("fresh/kb-header/duplicate-key", self.write(F.pack(H, PK, kb=F.kb(presentation, header_txt=kht + b',"typ":"kb+jwt"}'))), [], ARTERR, "base/fresh-kb", idx=0, needle="uplicate", obj="kb-header", kind="duplicate-key")
        self.add("fresh/kb-payload/duplicate-key", self.write(F.pack(H, PK, kb=F.kb(presentation, payload_txt=kpt[:-1] + b',"nonce":"n2"}'))), [], ARTERR, "base/fresh-kb", idx=0, needle="uplicate", obj="kb-payload", kind="duplicate-key")


# ── running the two verifiers ───────────────────────────────────────────────────────────────────────────────────────
def kwargs_for(flags):
    kw = {"trusted_producer_keys": None}; i = 0
    while i < len(flags):
        f = flags[i]
        if f == "--trusted-producer-key":
            alg, _, key = flags[i + 1].partition("="); kw["trusted_producer_keys"] = kw["trusted_producer_keys"] or {}; kw["trusted_producer_keys"].setdefault(alg, []).append(key); i += 2
        elif f == "--require-producer": kw["require_producer"] = True; i += 1
        elif f == "--require-pq": kw["require_pq"] = True; i += 1
        elif f == "--require-anchor": kw["require_anchor"] = True; i += 1
        else: raise ValueError(f)
    return kw


def run_python(py_root, recs):
    sys.path.insert(0, py_root)
    import ap2_evidence as ap2  # noqa: E402
    assert os.path.realpath(os.path.dirname(ap2.__file__)) == os.path.realpath(py_root), (ap2.__file__, py_root)
    out = {}
    for r in recs:
        try:
            out[r["name"]] = ap2.verify_evidence(r["path"], **kwargs_for(r["flags"]))
        except Exception as e:  # noqa: BLE001 — a traceback is a finding of its own
            out[r["name"]] = {"crash": f"{type(e).__name__}: {e}"}
    return out


def run_js(js_path, recs, d):
    manifest = os.path.join(d, "manifest.json")
    with open(manifest, "w", encoding="utf-8") as f:
        json.dump([{"name": r["name"], "path": r["path"], "flags": r["flags"]} for r in recs], f)
    p = subprocess.run(["node", VERIFY_MANY, js_path, manifest], capture_output=True, text=True, timeout=1800)
    if p.returncode != 0:
        raise RuntimeError("verify_many failed: " + p.stderr[-800:])
    return json.loads(p.stdout)


# ── judging ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def norm(r):
    """The compared fields: the oracle's seventeen plus the per-artifact signals and the §9.2 report."""
    if not isinstance(r, dict) or "crash" in r:
        return ("CRASH", str(r))
    prod = r.get("producer_signatures") or {}; ts = r.get("rfc3161") or {}
    arts = tuple((("error" in a), a.get("claims_match"), a.get("signature_ok"), (a.get("kb_jwt") or {}).get("present"), (a.get("kb_jwt") or {}).get("verified"),
                  json.dumps(a.get("ignored"), sort_keys=True) if "ignored" in a else None) for a in (r.get("artifacts") or []))
    sigs = tuple((s.get("sig_alg"), s.get("status"), s.get("key_trusted")) for s in (prod.get("signatures") or []))
    return (r.get("valid"), r.get("digest_ok"), r.get("bindings_ok"), prod.get("present"), prod.get("ok"), prod.get("trusted"), r.get("pq_protected"),
            ts.get("claimed"), ts.get("verified"), ts.get("granted"), ts.get("imprint_ok"), ts.get("gen_time"), r.get("policy_ok"), r.get("self_asserted_only"),
            r.get("chain_verified"), tuple(r.get("provenance_classes") or ()), r.get("refused") is None, arts, sigs)


def judge(rec, r, base):
    """Does receipt `r` meet the class the SPEC prescribes for this mutation? Returns (met, why)."""
    if not isinstance(r, dict) or "crash" in r:
        return False, "crash"
    cls = rec["cls"]; arts = r.get("artifacts") or []; prod = r.get("producer_signatures") or {}
    a = arts[rec["idx"]] if rec["idx"] is not None and rec["idx"] < len(arts) else {}
    if cls == REFUSE:
        ok = r.get("valid") is False and isinstance(r.get("refused"), str) and (rec["needle"] is None or rec["needle"] in r["refused"])
        return ok, f"refused={r.get('refused')!r} valid={r.get('valid')}"
    if cls == ARTERR:
        ok = r.get("valid") is False and "error" in a and (rec["needle"] is None or rec["needle"] in a["error"])
        return ok, f"artifact={a.get('error')!r} valid={r.get('valid')} refused={r.get('refused')!r}"
    if cls == SIGFAIL:
        sigs = prod.get("signatures") or []
        ok = r.get("valid") is False and prod.get("ok") is False and rec["sig"] < len(sigs) and sigs[rec["sig"]].get("status") == "FAIL"
        return ok, f"producer_ok={prod.get('ok')} statuses={[s.get('status') for s in sigs]} valid={r.get('valid')} refused={r.get('refused')!r}"
    if cls == ANCHOR_FALSE:
        ok = r.get("valid") is False and (r.get("rfc3161") or {}).get("verified") is False
        return ok, f"rfc3161={r.get('rfc3161')} valid={r.get('valid')} refused={r.get('refused')!r}"
    if cls == CLAIMS_MISMATCH:
        ok = r.get("valid") is False and a.get("claims_match") is False
        return ok, f"claims_match={a.get('claims_match')} valid={r.get('valid')} error={a.get('error')!r}"
    if cls == REPORT:
        ig = a.get("ignored") or {}
        ok = r.get("valid") == base.get("valid") and "error" not in a and rec["key"] in (ig.get(rec["slot"]) or [])
        return ok, f"valid={r.get('valid')} base={base.get('valid')} ignored={ig} error={a.get('error')!r}"
    if cls == RECORDED:
        ok = r.get("valid") is True and base.get("valid") is True and "error" not in a
        return ok, f"valid={r.get('valid')} error={a.get('error')!r}"
    if cls == UNCHANGED:
        ok = norm(r) == norm(base)
        return ok, "differs from the unmutated source" if not ok else "same"
    raise ValueError(cls)


def silent(rec, r, base):
    """The positive-control measure: a signal class whose receipt shows NO signal and the same `valid` as the source."""
    if rec["cls"] not in SIGNAL_CLASSES or not isinstance(r, dict) or "crash" in r:
        return False
    arts = r.get("artifacts") or []; prod = r.get("producer_signatures") or {}; bsig = [s.get("status") for s in ((base.get("producer_signatures") or {}).get("signatures") or [])]
    new_fail = any(s.get("status") == "FAIL" and (i >= len(bsig) or bsig[i] != "FAIL") for i, s in enumerate(prod.get("signatures") or []))
    return (r.get("valid") == base.get("valid") and r.get("refused") is None and not any("error" in a for a in arts) and not new_fail
            and all(a.get("claims_match") is not False for a in arts) and (r.get("rfc3161") or {}).get("verified") == (base.get("rfc3161") or {}).get("verified"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--full", action="store_true", help="every unknown-key spelling and every hostile type (default: the quick subset)")
    ap.add_argument("--py-root", default=ROOT, help="directory holding the ap2_evidence.py to test (the positive control points at an older checkout)")
    ap.add_argument("--js", default=JS_DEFAULT, help="the ap2-verify.mjs to test")
    ap.add_argument("--no-js", action="store_true", help="skip the JS verifier (no differential)")
    ap.add_argument("--json", help="write every record, receipt pair and verdict here")
    ap.add_argument("--keep", action="store_true", help="keep the corpus directory (printed)")
    a = ap.parse_args(argv)
    res = run(quick=not a.full, py_root=os.path.abspath(a.py_root), js=None if a.no_js else os.path.abspath(a.js), keep=a.keep, out_json=a.json, log=print)
    return 0 if res["ok"] else 1


def run(quick=True, py_root=ROOT, js=JS_DEFAULT, keep=False, out_json=None, log=lambda *a: None):
    d = tempfile.mkdtemp(prefix="ap2-schema-mutants-")
    try:
        c = Corpus(d, quick); c.build()
        recs = c.recs; muts = [r for r in recs if r["cls"]]
        log(f"corpus: {len(muts)} mutations from {sum(1 for r in recs if not r['cls'])} sources ({'quick' if quick else 'full'}), in {d}")
        py = run_python(py_root, recs)
        jsr = run_js(js, recs, d) if js else None
        by_name = {r["name"]: r for r in recs}
        unmet = {"py": [], "js": []}; silent_n = {"py": 0, "js": 0}; diffs = []; per_class = {}
        for r in muts:
            base_py = py[r["base"]]; mp, why_p = judge(r, py[r["name"]], base_py)
            per_class.setdefault(r["cls"], [0, 0]); per_class[r["cls"]][0] += 1
            if not mp: unmet["py"].append((r["name"], why_p))
            if silent(r, py[r["name"]], base_py): silent_n["py"] += 1
            if jsr is not None:
                base_js = jsr[r["base"]]; mj, why_j = judge(r, jsr[r["name"]], base_js)
                if not mj: unmet["js"].append((r["name"], why_j))
                if silent(r, jsr[r["name"]], base_js): silent_n["js"] += 1
                if mp and mj: per_class[r["cls"]][1] += 1
            elif mp:
                per_class[r["cls"]][1] += 1
        if jsr is not None:
            for r in recs:
                if norm(py[r["name"]]) != norm(jsr[r["name"]]):
                    diffs.append((r["name"], norm(py[r["name"]]), norm(jsr[r["name"]])))
        for cls, (n, met) in sorted(per_class.items()):
            log(f"  {cls:16} {met}/{n} met in {'both verifiers' if jsr is not None else 'the Python reference'}")
        for v in ("py", "js") if jsr is not None else ("py",):
            log(f"  {v}: {len(unmet[v])} mutations did not get the class the SPEC prescribes; {silent_n[v]} passed SILENTLY (valid unchanged, no signal)")
            for name, why in unmet[v][:12]:
                log(f"     [{v} UNMET] {name}: {why}")
        if jsr is not None:
            log(f"  differential: {len(diffs)} disagreements on {len(recs)} files (sources included)")
            for name, p_, j_ in diffs[:12]:
                log(f"     [DIFF] {name}\n        py={p_}\n        js={j_}")
        ok = not unmet["py"] and not unmet["js"] and not diffs
        log(("schema mutants: every mutation got its SPEC class in " + ("both verifiers, 0 disagreements" if jsr is not None else "the reference")) if ok else "schema mutants: FAILURES above")
        res = {"ok": ok, "quick": quick, "mutations": len(muts), "sources": len(recs) - len(muts), "per_class": per_class, "unmet": unmet, "silent": silent_n,
               "disagreements": len(diffs), "py_root": py_root, "js": js}
        if out_json:
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump({**res, "records": recs, "receipts": {"py": py, "js": jsr}, "diffs": [(n, list(map(str, p_)), list(map(str, j_))) for n, p_, j_ in diffs]}, f, indent=1, default=str)
        if keep:
            log("corpus kept in", d)
        return res
    finally:
        if not keep:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
