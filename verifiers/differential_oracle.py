#!/usr/bin/env python3
"""Differential oracle over the ap2-evidence-pack verifiers: the Python reference (`ap2_evidence.py verify`) and the
independent Node verifier (`verifiers/js/ap2-verify.mjs`) must give the same (valid, digest_ok, bindings_ok, producer_ok,
pq_protected, rfc3161_verified, policy_ok) on every case: the shipped conformance vectors under their declared policy,
hostile files that a lenient verifier would accept (every one carries a digest recomputed the way that verifier would),
and a CLI-grammar table (usage exit 2, no verdict, in both). Exit 1 on any disagreement. 1.1.0 (2026-09-22): the cases
were measured red on the 1.0.2 reference first (see README)."""
import base64, copy, glob, hashlib, json, os, shutil, subprocess, sys, tempfile
try:
    import resource
except ImportError:   # non-POSIX: the file-object cases then run without a per-child memory bound
    resource = None
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
# positive control: point either verifier at an OLDER checkout (git worktree) — the cases must turn red there
PY = [sys.executable, "-B", os.path.join(os.environ.get("AP2_ORACLE_PY_ROOT", ROOT), "ap2_evidence.py"), "verify"]
JS = ["node", os.environ.get("AP2_ORACLE_JS", os.path.join(HERE, "js", "ap2-verify.mjs"))]
# r5: the ELEVEN normative fields of SPEC §6, not the seven of 1.1.0 r1 — `producer_present`, `producer_trusted`,
# `rfc3161_claimed` and `self_asserted_only` were never compared on the hostile files, and one of them (the sorted
# `provenance_classes` behind self_asserted_only) really did diverge (code point vs UTF-16 code unit).
# r10: `granted`/`imprint_ok` and the x5c leaf identity are compared too — the reference asserted `granted: false` on a
# truncated token whose status it had read as granted, and the two verifiers rendered the same DN in different encodings
# (RFC 4514 vs OpenSSL multi-line) with the JS one missing the validity a §6.7 MUST requires: none of it was visible here.
KEYS = ("valid", "digest_ok", "bindings_ok", "producer_present", "producer_ok", "producer_trusted", "pq_protected",
        "rfc3161_claimed", "rfc3161_verified", "rfc3161_granted", "rfc3161_imprint_ok", "rfc3161_gen_time",
        "policy_ok", "self_asserted_only", "chain_verified", "provenance_classes",
        "anchors_verified", "refused", "anchors", "x5c_leaves")   # 1.5.0: anchors_verified (normative), the refusal text, each anchor's facts


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def rehash(ev, canon_fn=canon):
    e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    ev = dict(ev); ev["evidence_digest_sha256"] = hashlib.sha256(canon_fn(e2)).hexdigest(); ev.pop("producer_signatures", None); return ev


def _der(tag, body):
    n = len(body); lb = bytes([n]) if n < 128 else bytes([0x82, n >> 8, n & 0xFF]); return bytes([tag]) + lb + body


def _forged_tsr(digest, extra_tst=b""):
    tst = _der(0x30, _der(0x02, b"\x01") + _der(0x06, bytes.fromhex("2a03")) + _der(0x30, _der(0x30, _der(0x06, bytes.fromhex("608648016503040201"))) + _der(0x04, digest)) + _der(0x02, b"\x01") + _der(0x18, b"20260922100000Z") + extra_tst)
    eci = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010904")) + _der(0xA0, _der(0x04, tst)))
    sd = _der(0x30, _der(0x02, b"\x03") + _der(0x31, b"") + eci + _der(0x31, b""))
    return _der(0x30, _der(0x30, _der(0x02, b"\x00")) + _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010702")) + _der(0xA0, sd)))


# Declared divergence: TSA signature/chain verification needs openssl (Python only); the JS verifier reports tsa_verified null
# and under --require-anchor --tsa-cert does NOT pass (policy_ok false) — the same verdict, one different field.
# NB: the gen_time below is the probe TSA token's own genTime — regenerating the anchor vectors changes it and this
# declaration must be updated with them (the run then reports the mismatch instead of silently passing).
# the cases that must PASS: they prove the bench can tell green from red (never hostile files)
POSITIVE_CONTROLS = frozenset({"non-ascii-subject-rehashed", "fresh-pack-control-valid", "must-created_utc-ok", "file-exactly-at-the-bound"})
MAX_EVIDENCE_BYTES = 64 << 20
# 25/09/2026 — what a verifier must refuse BEFORE reading it, with a DECLARED reason that both must give: agreement alone is
# not enough (a FIFO blocked both verifiers and a symlink to /dev/zero exhausted memory in both: they "agreed").
# Each row runs with a timeout and, where the OS allows, a per-child RLIMIT_DATA, so a regression is a red row, never a
# hung oracle or a host out of memory.
REFUSALS = {"file-fifo": "not a regular file", "file-devzero-symlink": "not a regular file", "file-directory": "not a regular file",
            "file-one-byte-over-the-bound": "exceeds"}
HAZARD_TIMEOUT, HAZARD_MEM = 20, 1500 << 20

_LEAF_CA = _LEAF_SELF = _LEAF_MIX = None   # the x5c leaves are freshly generated each run: the declaration ignores that one field

DECLARED = {
    # The four declared divergences all have ONE cause: chain and TSA validation run `openssl` and are therefore the
    # reference's alone — the JS verifier reports `chain_verified: null` / `tsa_verified: null` and never clears a flag or
    # passes a policy on their strength. NB the gen_time below is the probe TSA token's own genTime: regenerating the
    # anchor vectors changes it and this declaration must be updated with them (the run then reports the mismatch).
    # 1.5.0: the same cause on `anchors` — two TSA-verified anchors in the reference, none counted in JS under --tsa-cert
    "vector-anchors_two_valid-tsa-cert-bundle": {
        "py": (True, True, True, True, True, None, True, True, True, True, True, "20260922175855Z", True, True, None, ("jwk_header",), 2, None,
               (("rfc3161", True, True, True, "20261011172954Z"),), ()),
        "js": (False, True, True, True, True, None, True, True, True, True, True, "20260922175855Z", False, True, None, ("jwk_header",), 0, None,
               (("rfc3161", True, True, True, "20261011172954Z"),), ())},
    "vector-anchors_two_valid-tsa-cert-one": {
        "py": (False, True, True, True, True, None, True, True, True, True, True, "20260922175855Z", False, True, None, ("jwk_header",), 1, None,
               (("rfc3161", True, True, True, "20261011172954Z"),), ()),
        "js": (False, True, True, True, True, None, True, True, True, True, True, "20260922175855Z", False, True, None, ("jwk_header",), 0, None,
               (("rfc3161", True, True, True, "20261011172954Z"),), ())},
    "vector-anchor_valid-tsa-cert": {
        "py": (True, True, True, True, True, None, True, True, True, True, True, "20260922175855Z", True, True, None, ("jwk_header",), 1, None, (), ()),
        "js": (False, True, True, True, True, None, True, True, True, True, True, "20260922175855Z", False, True, None, ("jwk_header",), 0, None, (), ())},
    "x5c-ca-issued-with-trust-anchor": {
        "py": (True, True, True, False, None, None, False, False, None, None, None, None, True, False, True, ("x5c_header",), 0, None, (), _LEAF_CA),
        "js": (True, True, True, False, None, None, False, False, None, None, None, None, True, True, None, ("x5c_header",), 0, None, (), _LEAF_CA)},
    "mixed-self-asserted-mandate-plus-chained-artifact": {
        "py": (True, True, True, False, None, None, False, False, None, None, None, None, True, True, True, ("jwk_header", "x5c_header"), 0, None, (), _LEAF_MIX),
        "js": (True, True, True, False, None, None, False, False, None, None, None, None, True, True, None, ("jwk_header", "x5c_header"), 0, None, (), _LEAF_MIX)},
    "x5c-self-signed-with-trust-anchor": {
        "py": (True, True, True, False, None, None, False, False, None, None, None, None, True, True, False, ("x5c_header",), 0, None, (), _LEAF_SELF),
        "js": (True, True, True, False, None, None, False, False, None, None, None, None, True, True, None, ("x5c_header",), 0, None, (), _LEAF_SELF)}}


def _matches_declared(name, py, js):
    """A declared divergence matches when every compared field agrees with the declaration, except the freshly generated
    x5c leaf identity (new keys each run) — which must still be IDENTICAL between the two verifiers."""
    d = DECLARED[name]
    if py[-1] != js[-1]:
        return False
    return py[:-1] == d["py"][:-1] and js[:-1] == d["js"][:-1]


def flags_for(policy):
    fl = []
    for alg, keys in (policy.get("trusted_producer_keys") or {}).items():
        for k in ([keys] if isinstance(keys, str) else keys):
            fl += ["--trusted-producer-key", f"{alg}={k}"]
    for name in ("require_producer", "require_pq", "require_anchor"):
        if policy.get(name):
            fl.append("--" + name.replace("_", "-"))
    if "min_anchors" in policy:   # 1.5.0 — SPEC §3.3
        fl += ["--min-anchors", str(policy["min_anchors"])]
    return fl


def _refused_key(text):
    """The refusal text is compared EXACTLY where the SPEC fixes it — the closed-schema refusals of §9.1 and the anchors
    refusals of §3.3 (`<object>: unknown key "x" (SPEC §9.1)` …); elsewhere (profile parse errors: UTF-8, floats, depth)
    the SPEC fixes only that the file is refused, and the two verifiers word it differently (measured 2026-10-11, 9 files,
    same verdict), so only the presence of a refusal is compared."""
    if text is None:
        return None
    return text if ("(SPEC §9.1)" in text or "(SPEC §3.3)" in text) else "<refused>"


def run(cmd, path, flags):
    try:
        out = subprocess.run(list(cmd) + [path] + flags, capture_output=True, text=True, timeout=120)
        r = json.loads(out.stdout); prod = r.get("producer_signatures") or {}; ts = r.get("rfc3161") or {}
        leaves = tuple(tuple((a.get("x5c_leaf") or {}).get(f) for f in ("subject", "issuer", "serial", "not_valid_before", "not_valid_after", "sha256"))
                       for a in (r.get("artifacts") or []) if a.get("x5c_leaf"))   # identity only: chain_verified is the declared divergence, compared at top level
        return (r.get("valid"), r.get("digest_ok"), r.get("bindings_ok"), prod.get("present"), prod.get("ok"), prod.get("trusted"),
                r.get("pq_protected"), ts.get("claimed"), ts.get("verified"), ts.get("granted"), ts.get("imprint_ok"), ts.get("gen_time"),
                r.get("policy_ok"), r.get("self_asserted_only"), r.get("chain_verified"), tuple(r.get("provenance_classes") or ()),
                r.get("anchors_verified"), _refused_key(r.get("refused")),
                tuple((a.get("mechanism"), a.get("verified"), a.get("granted"), a.get("imprint_ok"), a.get("gen_time")) for a in (r.get("anchors") or [])),
                leaves)
    except Exception:  # noqa: BLE001
        return ("NONJSON/CRASH:" + os.path.basename(cmd[-1] if cmd[-1] != "verify" else cmd[-2]),) * len(KEYS)   # distinct per verifier: two crashes never agree


def _limit_memory():
    resource.setrlimit(resource.RLIMIT_DATA, (HAZARD_MEM, HAZARD_MEM))


def refusal_of(cmd, path):
    """The `refused` reason of one verifier on a file-object case: BLOCKED on timeout, CRASH:<exit> without a JSON receipt."""
    try:
        out = subprocess.run(list(cmd) + [path], capture_output=True, text=True, timeout=HAZARD_TIMEOUT,
                             preexec_fn=_limit_memory if resource is not None else None)
    except subprocess.TimeoutExpired:
        return "BLOCKED"
    try:
        r = json.loads(out.stdout)
    except ValueError:
        return f"CRASH:{out.returncode}"
    return "valid" if r.get("valid") else str(r.get("refused"))


def build_cases(d):
    cases = {}
    vdir = os.path.join(ROOT, "spec", "vectors", "ap2")
    for exp_path in sorted(glob.glob(os.path.join(vdir, "*.expected.json"))):
        exp = _load(exp_path); name = exp["vector"]
        cases["vector-" + name] = (os.path.join(vdir, name + ".json"), flags_for(exp.get("policy", {})))
    with open(os.path.join(vdir, "valid_signed.json"), encoding="utf-8") as fh:
        base_text = fh.read()
    base = json.loads(base_text)
    def w(name, data):
        p = os.path.join(d, name + ".json"); _write(p, data if isinstance(data, bytes) else data.encode("utf-8")); return p
    # 1.1.0 profile cases: each hostile file carries the digest a lenient verifier would recompute, so the profile rule decides
    # r2: `__proto__` as an ORDINARY key, digest recomputed with it — a verifier whose parser drops or pollutes it recomputes a
    # different digest (the 1.1.0 r1 case kept the old digest, so every verifier answered digest_ok False and the case could not fail)
    e = {"__proto__": {"evil": 1}}; e.update(base); cases["proto-key-rehashed"] = (w("proto", json.dumps(rehash(e))), [])
    ev = rehash(dict(base, subject="x�")); cases["raw-byte-hashed-as-fffd"] = (w("fffd", json.dumps(ev, ensure_ascii=False).encode("utf-8").replace("�".encode("utf-8"), b"\xff", 1)), [])
    cases["non-ascii-subject-rehashed"] = (w("nonascii", json.dumps(rehash(dict(base, subject="café ≥ 1 😀")), ensure_ascii=False)), [])   # in profile: PASS both
    cases["float-1.0-rehashed"] = (w("float", json.dumps(rehash(dict(base, extra=1.0)))), [])
    cases["int-2^53+1-rehashed"] = (w("bigint", json.dumps(rehash(dict(base, extra=9007199254740993)))), [])
    cases["deep-100000"] = (w("deep", "[" * 100000), [])
    cases["nan-constant"] = (w("nan", base_text.replace('"created_utc"', '"x": NaN, "created_utc"', 1)), [])
    lone = dict(base, subject="\ud800"); e2 = {k: v for k, v in lone.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    lone["evidence_digest_sha256"] = hashlib.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode("utf-8", "surrogatepass")).hexdigest(); lone.pop("producer_signatures", None)
    cases["lone-surrogate-rehashed"] = (w("lone", json.dumps(lone)), [])
    dup = rehash(base); txt = json.dumps(dup); cases["dup-key-same-value"] = (w("dup", txt[:-1] + ',"subject":' + json.dumps(dup["subject"]) + "}"), [])
    cases["digest-uppercase"] = (w("upper", json.dumps(dict(base, evidence_digest_sha256=base["evidence_digest_sha256"].upper()))), [])
    cases["artifacts-empty"] = (w("empty", json.dumps(rehash(dict(base, artifacts=[], bindings=[])))), [])
    cases["bom-prefixed"] = (w("bom", "﻿" + base_text), [])
    cases["not-an-object"] = (w("list", "[1]"), [])
    # SD-JWT segment shapes on the BINDER artifact (`cart`, index 1 — mutating the bound `intent` would flip bindings_ok for
    # every verifier and hide the base64url rule, review r1); digest recomputed so only the artifact layer decides
    binder = next(i for i, a in enumerate(base["artifacts"]) if a["name"] == "cart")
    c = base["artifacts"][binder]["sd_jwt_compact"]; parts = c.split("~"); h, p_, s_ = parts[0].split(".")
    for nm, sig in (("sig-b64url-space", s_[:10] + " " + s_[10:]), ("sig-b64url-padded", s_ + "=="), ("sig-b64url-plus", s_.replace("-", "+", 1) if "-" in s_ else s_[:-1] + "+")):
        e = copy.deepcopy(base); pp = parts[:]; pp[0] = ".".join([h, p_, sig]); e["artifacts"][binder]["sd_jwt_compact"] = "~".join(pp); cases[nm] = (w(nm, json.dumps(rehash(e))), [])
    # review r1: top-level field SHAPES (Python raised TypeError/AttributeError; JS answered), empty producer block, lenient
    # tsr_b64 / JWK coordinates, deep JWT header, non-object payload, trailing NBSP on the compact serialization
    for nm, mut in (("artifacts-null", lambda e: e.__setitem__("artifacts", None)), ("artifacts-string", lambda e: e.__setitem__("artifacts", "x")),
                    ("artifacts-list-of-null", lambda e: e.__setitem__("artifacts", [None])), ("key-null", lambda e: e["artifacts"][0].__setitem__("key", None)),
                    ("jwk-list", lambda e: e["artifacts"][0]["key"].__setitem__("jwk", [1])), ("rfc3161-null", lambda e: e.__setitem__("rfc3161_timestamp", None)),
                    ("rfc3161-string", lambda e: e.__setitem__("rfc3161_timestamp", "x")), ("producer-string", lambda e: e.__setitem__("producer_signatures", "x")),
                    ("producer-empty-object", lambda e: e.__setitem__("producer_signatures", {})), ("producer-list", lambda e: e.__setitem__("producer_signatures", [])),
                    ("producer-signatures-list-of-null", lambda e: e.__setitem__("producer_signatures", {"signatures": [None]}))):
        e = copy.deepcopy(base); mut(e); cases[nm] = (w(nm, json.dumps(e)), [])
    e = copy.deepcopy(base); e["bindings"] = None; cases["bindings-null-rehashed"] = (w("bnull", json.dumps(rehash(e))), [])
    # r6: these two used to swap a segment WITHOUT re-signing, so both verifiers failed on the signature and the shape rule
    # they are named after was never reached (that is how the JS shape check survived round 5 commented out). Now signed.
    sk6, n6 = _fresh_key()
    e = _fresh_pack(base, sk6, n6, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', '["not","an","object"]', ["not", "an", "object"])
    for a in e["artifacts"]: a["key"].pop("provenance_class", None)
    cases["payload-array-signed-rehashed"] = (w("parr", json.dumps(rehash(e))), [])
    e = _fresh_pack(base, sk6, n6, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', '"a string payload"', "a string payload")
    for a in e["artifacts"]: a["key"].pop("provenance_class", None)
    cases["payload-string-signed-rehashed"] = (w("pstr2", json.dumps(rehash(e))), [])
    deep_hdr = "[" * 100000
    e = _fresh_pack(base, sk6, n6, deep_hdr.encode(), '{"iss":"x"}', {"iss": "x"})
    for a in e["artifacts"]: a["key"].pop("provenance_class", None)
    cases["header-deep-signed-rehashed"] = (w("hdeep", json.dumps(rehash(e))), [])
    # r6: the x5c_header branch had NO coverage at all (no vector carries an x5c) — a real self-signed leaf, canonical and
    # non-canonically spelled, plus a leaf whose key differs from the snapshotted jwk
    x5c_built = _x5c_cases(base)
    for nm, ev6 in x5c_built:
        cases["x5c-" + nm] = (w("x5c" + nm, json.dumps(rehash(ev6))), [])
    anchor = os.path.join(d, "probe_ca.pem"); _write(anchor, _x5c_cases.ca_pem)
    # r10: a MIXED pack — the mandate is a self-asserted jwk_header, a second artifact chains to the anchor. With `all()`
    # the reference cleared self_asserted_only, i.e. "no self-asserted key here", while the mandate key was never reconciled.
    mixed = _mixed_pack(base, dict(x5c_built)["ca-issued-leaf"])
    cases["mixed-self-asserted-mandate-plus-chained-artifact"] = (w("mixed", json.dumps(rehash(mixed))), ["--trust-anchor", anchor])
    ca_ev = dict(x5c_built)["ca-issued-leaf"]
    cases["x5c-ca-issued-with-trust-anchor"] = (w("x5canch", json.dumps(rehash(ca_ev))), ["--trust-anchor", anchor])
    cases["x5c-self-signed-with-trust-anchor"] = (w("x5cselfanch", json.dumps(rehash(dict(x5c_built)["canonical"]))), ["--trust-anchor", anchor])
    for nm, v in (("created_utc-arabic-indic-digits", "٢٠٢٦-٠٩-٢٢T٠٠:٠٠:٠٠Z"),   # r9: Python \d matches Unicode Nd, JS \d is [0-9]
                  ("created_utc-fullwidth-digits", "２０２６-０９-２２T００:００:００Z"),
                  ("created_utc-not-iso", "22/09/2026"), ("created_utc-no-Z", "2026-09-22T00:00:00"), ("created_utc-ok", "2026-09-22T00:00:00Z")):
        e = copy.deepcopy(base); e["created_utc"] = v; cases["must-" + nm] = (w("cu" + nm, json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["artifacts"][binder]["sd_jwt_compact"] = c + "\u00a0"; cases["compact-trailing-nbsp-rehashed"] = (w("nbsp", json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["artifacts"][binder]["key"]["jwk"]["x"] = e["artifacts"][binder]["key"]["jwk"]["x"] + "="; cases["jwk-x-padded-rehashed"] = (w("jwkpad", json.dumps(rehash(e))), [])
    av = _load(os.path.join(vdir, "anchor_valid.json")); e = copy.deepcopy(av); t = e["rfc3161_timestamp"]["tsr_b64"]; e["rfc3161_timestamp"]["tsr_b64"] = t[:10] + " " + t[10:]; cases["tsr-b64-space"] = (w("tsrsp", json.dumps(e)), [])
    # a self-forged TimeStampResp (status 0, imprint = digest, no signer): binding holds, TSA does not — declared divergence under --tsa-cert
    forged = _forged_tsr(bytes.fromhex(base["evidence_digest_sha256"]))
    e = dict(base); e["rfc3161_timestamp"] = {"anchored": True, "tsa_url": "forged", "tsr_b64": base64.b64encode(forged).decode()}
    cases["tsr-self-forged-binding-only"] = (w("forged", json.dumps(e)), ["--require-anchor"])
    cases["tsr-self-forged-tsa-cert"] = (w("forged2", json.dumps(e)), ["--require-anchor", "--tsa-cert", os.path.join(vdir, "anchor_probe_tsa.crt")])
    cases["vector-anchor_valid-tsa-cert"] = (os.path.join(vdir, "anchor_valid.json"), ["--require-anchor", "--tsa-cert", os.path.join(vdir, "anchor_probe_tsa.crt")])
    with open(os.path.join(vdir, "anchor_probe_tsa.crt"), "rb") as f1, open(os.path.join(vdir, "anchor_probe_tsa2.crt"), "rb") as f2:   # 1.5.0: a PEM bundle of both TSAs
        bundle = w("tsa_bundle", f1.read() + f2.read())
    cases["vector-anchors_two_valid-tsa-cert-bundle"] = (os.path.join(vdir, "anchors_two_valid.json"), ["--min-anchors", "2", "--tsa-cert", bundle])
    # only the FIRST TSA's certificate: the second anchor binds but is not TSA-verified, so it does not count (SPEC §3.3)
    cases["vector-anchors_two_valid-tsa-cert-one"] = (os.path.join(vdir, "anchors_two_valid.json"), ["--min-anchors", "2", "--tsa-cert", os.path.join(vdir, "anchor_probe_tsa.crt")])
    e = copy.deepcopy(base); e["artifacts"][0]["resolved_claims"]["extra"] = "x"; cases["claims-mismatch-rehashed"] = (w("claims", json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["bindings"] = []; cases["bindings-dropped-rehashed"] = (w("bind", json.dumps(rehash(e))), [])
    # producer block shapes
    e = copy.deepcopy(base); e["producer_signatures"]["signatures"][0]["signature_b64"] = e["producer_signatures"]["signatures"][0]["signature_b64"][:8] + " " + e["producer_signatures"]["signatures"][0]["signature_b64"][8:]; cases["producer-sig-b64-space"] = (w("psp", json.dumps(e)), [])
    e = copy.deepcopy(base); e["producer_signatures"]["signatures"].append({"sig_alg": "rsa-pss", "public_key_b64": "AA==", "signature_b64": "AA==", "post_quantum": False}); cases["producer-unknown-alg"] = (w("punk", json.dumps(e)), [])
    e = copy.deepcopy(base); e["producer_signatures"]["signatures"] = e["producer_signatures"]["signatures"][:1]; cases["producer-pq-stripped-required"] = (w("pstr", json.dumps(e)), ["--require-pq", "--trusted-producer-key", "ed25519=" + e["producer_signatures"]["signatures"][0]["public_key_b64"]])
    # ── review r2 (2026-09-22): shapes INSIDE the signed JWT (present-with-null, non-string digests/names, cnf), JWK coordinate
    # length, sig_alg prototype keys under pins, empty EXPLICIT [0] in the token, provenance_class type, `anchored` type.
    # Each signed case is a fresh single-artifact pack signed by a key generated here: the reference's `dict.get(k, default)`
    # and the JS `??` disagreed on present-with-null, and the reference's `json.loads` on the JWT payload took a duplicate key
    # (last wins) and a BOM that the JS parser refused.
    pin = ["--trusted-producer-key", "ed25519=" + base["producer_signatures"]["signatures"][0]["public_key_b64"]]
    for nm, alg in (("constructor", "constructor"), ("__proto__", "__proto__"), ("list", ["ed25519"]), ("dict", {})):
        e = copy.deepcopy(base); e["producer_signatures"]["signatures"].append({"sig_alg": alg, "public_key_b64": "AA==", "signature_b64": "AA==", "post_quantum": False}); cases[f"producer-sig_alg-{nm}-pinned"] = (w("psa" + nm, json.dumps(e)), pin)
    t1 = _der(0x30, _der(0x30, _der(0x02, b"\x00")) + _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010702")) + _der(0xA0, b"")))
    sd_e = _der(0x30, _der(0x02, b"\x03") + _der(0x31, b"") + _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010904")) + _der(0xA0, b"")) + _der(0x31, b""))
    t2 = _der(0x30, _der(0x30, _der(0x02, b"\x00")) + _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010702")) + _der(0xA0, sd_e)))
    for nm, t in (("empty-signeddata", t1), ("empty-econtent", t2)):
        e = dict(base); e["rfc3161_timestamp"] = {"anchored": True, "tsa_url": "forged", "tsr_b64": base64.b64encode(t).decode()}; cases["tsr-" + nm] = (w("tsr" + nm, json.dumps(e)), [])
    for nm, v in (("list", ["x"]), ("int", 5)):
        e = copy.deepcopy(base); e["artifacts"][0]["key"]["provenance_class"] = v; cases[f"provenance-class-{nm}-rehashed"] = (w("prov" + nm, json.dumps(rehash(e))), [])
    for nm, v in (("list", []), ("dict", {}), ("int-0", 0), ("string", "false")):
        e = dict(base); e["rfc3161_timestamp"] = {"anchored": v}; cases[f"anchored-{nm}"] = (w("anch" + nm, json.dumps(e)), [])
    sk, n = _fresh_key(); H = '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}'
    def P(name, payload_txt, resolved, **kw):
        cases[name] = (w(name, json.dumps(_fresh_pack(base, sk, n, H, payload_txt, resolved, **kw))), [])
    P("jwt-payload-dup-key-rehashed", '{"iss":"x","amount":"1","amount":"999"}', {"iss": "x", "amount": "999"})
    P("jwt-payload-bom-rehashed", b'\xef\xbb\xbf{"iss":"x"}', {"iss": "x"})
    P("sd-null-rehashed", '{"iss":"x","_sd":null}', {"iss": "x"})
    P("sd-object-rehashed", '{"iss":"x","_sd":{}}', {"iss": "x"})
    P("sd-list-of-int-rehashed", '{"iss":"x","_sd":[1]}', {"iss": "x"})
    P("sd_alg-null-rehashed", '{"iss":"x","_sd_alg":null}', {"iss": "x"})
    P("array-dots-list-rehashed", '{"iss":"x","a":[{"...":[1]}]}', {"iss": "x", "a": []})
    disc = base64.urlsafe_b64encode(b'["salt",[1],"v"]').decode().rstrip("="); dig = base64.urlsafe_b64encode(hashlib.sha256(disc.encode()).digest()).decode().rstrip("=")
    P("disclosure-name-list-rehashed", '{"iss":"x","_sd":["%s"]}' % dig, {"iss": "x"}, disclosures=[disc])
    kb = ".".join(base64.urlsafe_b64encode(x).decode().rstrip("=") for x in (b'{"alg":"ES256","typ":"kb+jwt"}', b'{"aud":"a","nonce":"n","iat":1,"sd_hash":"x"}', b"\x00" * 64))
    P("kb-cnf-null-rehashed", '{"iss":"x","cnf":null}', {"iss": "x", "cnf": None}, kb=kb)
    P("kb-cnf-string-rehashed", '{"iss":"x","cnf":"k"}', {"iss": "x", "cnf": "k"}, kb=kb)
    P("kb-cnf-jwk-empty-rehashed", '{"iss":"x","cnf":{"jwk":{}}}', {"iss": "x", "cnf": {"jwk": {}}}, kb=kb)
    P("fresh-pack-control-valid", '{"iss":"x","_sd":[],"_sd_alg":"sha-256"}', {"iss": "x"})   # positive control of the fresh-key builder: both must say valid
    # coverage probe before the release, part 2: the seven `resolve_disclosures` branches were the largest uncovered
    # region of the verify path. Probed and found concordant — these cases keep them that way.
    dg = lambda s: base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).decode().rstrip("=")  # noqa: E731
    _d1 = base64.urlsafe_b64encode(b'["salt","k","v"]').decode().rstrip("=")
    _d2 = base64.urlsafe_b64encode(b'["s2","k","v2"]').decode().rstrip("=")
    for nm, discs, pay, res in (
            ("disclosure-not-base64url", ["!!!"], '{"iss":"x","_sd":["%s"]}' % dg("!!!"), {"iss": "x"}),
            ("disclosure-not-json", [base64.urlsafe_b64encode(b"nope").decode().rstrip("=")], '{"iss":"x","_sd":["%s"]}' % dg(base64.urlsafe_b64encode(b"nope").decode().rstrip("=")), {"iss": "x"}),
            ("disclosure-is-object", [base64.urlsafe_b64encode(b'{"a":1}').decode().rstrip("=")], '{"iss":"x","_sd":["%s"]}' % dg(base64.urlsafe_b64encode(b'{"a":1}').decode().rstrip("=")), {"iss": "x"}),
            ("disclosure-four-elements", [base64.urlsafe_b64encode(b'["s","k","v","x"]').decode().rstrip("=")], '{"iss":"x","_sd":["%s"]}' % dg(base64.urlsafe_b64encode(b'["s","k","v","x"]').decode().rstrip("=")), {"iss": "x"}),
            ("disclosure-duplicate-digest", [_d1, _d1], '{"iss":"x","_sd":["%s"]}' % dg(_d1), {"iss": "x", "k": "v"}),
            ("disclosure-unused", [_d1], '{"iss":"x"}', {"iss": "x"}),
            ("disclosure-name-collides", [_d1, _d2], '{"iss":"x","_sd":["%s","%s"]}' % (dg(_d1), dg(_d2)), {"iss": "x", "k": "v"})):
        cases[nm] = (w(nm, json.dumps(_fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', pay, res, disclosures=discs))), [])
    # coverage probe before the release: the six KB-JWT branches were never exercised by tests or oracle, and one of them
    # accepted a non-canonical base64url signature segment (the branch returns before the signature is decoded)
    kh = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"kb+jwt"}').decode().rstrip("=")
    kp = base64.urlsafe_b64encode(b'{"sd_hash":"x"}').decode().rstrip("=")
    ksig = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")
    for nm, kbv, pay, res in (("kb-two-segments", kh + "." + kp, '{"iss":"x"}', {"iss": "x"}),
                              ("kb-header-not-json", base64.urlsafe_b64encode(b"not json").decode().rstrip("=") + "." + kp + "." + ksig, '{"iss":"x"}', {"iss": "x"}),
                              ("kb-payload-array", kh + "." + base64.urlsafe_b64encode(b"[1,2]").decode().rstrip("=") + "." + ksig, '{"iss":"x"}', {"iss": "x"}),
                              ("kb-alg-rs256", base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=") + "." + kp + "." + ksig, '{"iss":"x"}', {"iss": "x"}),
                              ("kb-cnf-jwk-string", kh + "." + kp + "." + ksig, '{"iss":"x","cnf":{"jwk":"k"}}', {"iss": "x", "cnf": {"jwk": "k"}}),
                              ("kb-sig-padded", kh + "." + kp + "." + ksig + "=", '{"iss":"x"}', {"iss": "x"}),
                              ("kb-sig-space", kh + "." + kp + "." + ksig[:10] + " " + ksig[10:], '{"iss":"x"}', {"iss": "x"})):
        cases[nm] = (w(nm, json.dumps(_fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', pay, res, kb=kbv))), [])
    sk0, n0 = _fresh_key(top_zero=True)
    cases["jwk-x-31-bytes-rehashed"] = (w("jwk31", json.dumps(_fresh_pack(base, sk0, n0, H, '{"iss":"x"}', {"iss": "x"}, jwk_x_bytes=n0.x.to_bytes(31, "big")))), [])
    # ── review r3 (2026-09-22): artifact `name` shapes (the JS binding table was a prototype-bearing object: an absent name was a
    # TypeError crash, an int name was stringified, "__proto__" vanished from it), a 4-byte DER length with the top bit set (JS `<<`
    # is int32: the length went negative, the overrun check passed and a token the reference refuses verified), the bare invocation
    binder = next(i for i, a in enumerate(base["artifacts"]) if a["name"] == "cart"); intent = next(i for i, a in enumerate(base["artifacts"]) if a["name"] == "intent")
    e = copy.deepcopy(base); del e["artifacts"][binder]["name"]; cases["name-absent-rehashed"] = (w("nabs", json.dumps(rehash(e))), [])
    for nm, v in (("int", 1), ("proto", "__proto__"), ("empty", "")):
        e = copy.deepcopy(base); e["artifacts"][intent]["name"] = v
        for b in e["bindings"]:
            for k in ("in", "commits_to"):
                if b[k] == "intent": b[k] = v
        cases[f"name-{nm}-rehashed"] = (w("n" + nm, json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["artifacts"][intent]["name"] = "cart"; cases["name-duplicate-rehashed"] = (w("ndup", json.dumps(rehash(e))), [])
    e = dict(base); e["rfc3161_timestamp"] = {"anchored": True, "tsa_url": "forged", "tsr_b64": base64.b64encode(_forged_tsr(bytes.fromhex(base["evidence_digest_sha256"]), extra_tst=bytes([0x04, 0x84, 0x80, 0, 0, 0]))).decode()}
    cases["tsr-der-len-4byte-negative"] = (w("tsrneg", json.dumps(e)), ["--require-anchor"])
    # ── review r4 (2026-09-22): the binding SET — JS Object.keys enumerates array-index keys first, so a cart whose payload holds
    # two commitments under "intent_hash" and "0" was scanned in another order and an ORDERED comparison failed in JS on a pack the
    # reference built; the recorded list reversed must verify in both; a duplicated entry must fail in both (multiset)
    import ap2_evidence as _ap2
    def two(name_a, name_b, cart_payload):
        intent = _sign_compact(sk, n, '{"iss":"x"}'); H = hashlib.sha256(intent.encode()).hexdigest()
        out = os.path.join(d, f"two_{name_a}_{len(cases)}.json"); _ap2.build_evidence([{"name": name_a, "sd_jwt": intent}, {"name": name_b, "sd_jwt": _sign_compact(sk, n, cart_payload % (H, H))}], out); return out
    cases["bindings-index-key-after-plain"] = (two("intent", "cart", '{"iss":"x","intent_hash":"%s","0":"%s"}'), [])
    cases["bindings-index-keys-reversed"] = (two("intent", "cart", '{"iss":"x","2":"%s","1":"%s"}'), [])
    cases["bindings-artifact-named-0"] = (two("0", "cart", '{"iss":"x","h":"%s","g":"%s"}'), [])
    p = two("intent", "cart", '{"iss":"x","a":"%s","b":"%s"}'); ev2 = _load(p); ev2["bindings"] = list(reversed(ev2["bindings"])); cases["bindings-recorded-reversed-rehashed"] = (w("brev", json.dumps(rehash(ev2))), [])
    ev2 = _load(p); ev2["bindings"] = ev2["bindings"] + ev2["bindings"][:1]; cases["bindings-entry-duplicated-rehashed"] = (w("bdup", json.dumps(rehash(ev2))), [])
    # ── review r5 (2026-09-22): the provenance class is reconciled with the signed header (relabelling jwk_header as x5c_header
    # flipped self_asserted_only with no x5c anywhere), the enum is closed, `evidence_format` and the §1 MUSTs are checked
    for nm, v in (("x5c_header-without-x5c", "x5c_header"), ("out-of-enum", "qualified_eidas_certificate"), ("supplied-unverifiable", "supplied"), ("list", ["jwk_header"])):
        e = copy.deepcopy(base)
        for a in e["artifacts"]: a["key"]["provenance_class"] = v
        cases["provenance-" + nm] = (w("pcl" + nm, json.dumps(rehash(e))), [])
    e = copy.deepcopy(base)
    for a in e["artifacts"]: a["key"].pop("provenance_class", None)
    cases["provenance-absent-rehashed"] = (w("pcnone", json.dumps(rehash(e))), [])
    for nm, mut in (("format-2.0", lambda e: e.__setitem__("evidence_format", "ap2-evidence-pack/2.0")), ("format-absent", lambda e: e.pop("evidence_format", None)),
                    ("subject-absent", lambda e: e.pop("subject", None)), ("subject-int", lambda e: e.__setitem__("subject", 1)),
                    ("created_utc-absent", lambda e: e.pop("created_utc", None)), ("honest_scope-absent", lambda e: e.pop("honest_scope", None))):
        e = copy.deepcopy(base); mut(e); cases["must-" + nm] = (w("must" + nm, json.dumps(rehash(e))), [])
    cases["jwk-x-33-bytes-rehashed"] = (w("jwk33", json.dumps(_fresh_pack(base, sk, n, H, '{"iss":"x"}', {"iss": "x"}, jwk_x_bytes=n.x.to_bytes(33, "big")))), [])
    # ── 25/09/2026: file objects a verifier must not read (REFUSALS) and the bound itself — trailing spaces change no digest
    fifo = os.path.join(d, "fifo.json"); os.mkfifo(fifo); cases["file-fifo"] = (fifo, [])
    z = os.path.join(d, "zero.json"); os.symlink("/dev/zero", z); cases["file-devzero-symlink"] = (z, [])
    dd = os.path.join(d, "dir.json"); os.makedirs(dd); cases["file-directory"] = (dd, [])
    for nm, size in (("file-one-byte-over-the-bound", MAX_EVIDENCE_BYTES + 1), ("file-exactly-at-the-bound", MAX_EVIDENCE_BYTES)):
        raw = base_text.encode("utf-8"); cases[nm] = (w(nm, raw + b" " * (size - len(raw))), [])
    return cases


def _fresh_key(top_zero=False):
    from cryptography.hazmat.primitives.asymmetric import ec
    while True:
        sk = ec.generate_private_key(ec.SECP256R1()); n = sk.public_key().public_numbers()
        if not top_zero or n.x >> 248 == 0:   # a coordinate whose leading byte is zero (about 1 key in 256): the 31-byte spelling
            return sk, n


def _x5c_cases(base):
    """A real self-signed P-256 certificate in the signed header, provenance_class x5c_header: canonical (must verify in both),
    with a space / newline inside the leaf (r6: `base64.b64decode` dropped them in the reference, `b64Strict` refused them in JS),
    and a leaf whose public key is NOT the snapshotted one (the reconciliation must refuse)."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    sk = ec.generate_private_key(ec.SECP256R1()); nums = sk.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oracle probe issuer")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(sk.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1)).sign(sk, hashes.SHA256()))
    leaf = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    other = ec.generate_private_key(ec.SECP256R1()); on = other.public_key().public_numbers()
    # r7: a leaf ISSUED BY SOMEONE ELSE (issuer != subject) is the only shape that clears self_asserted_only — the positive
    # control of that flag, and the only case in the whole suite where it is false
    ca = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oracle probe CA")])
    issued = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oracle probe subject")]))
              .issuer_name(ca_name).public_key(sk.public_key()).serial_number(2)
              .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1)).sign(ca, hashes.SHA256()))
    leaf_issued = base64.b64encode(issued.public_bytes(serialization.Encoding.DER)).decode()
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca.public_key()).serial_number(3)
               .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca, hashes.SHA256()))
    _x5c_cases.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)   # r8: the anchor the relying party would pin
    out = []
    for nm, c, key_jwk in (("canonical", leaf, jwk), ("leaf-with-space", leaf[:20] + " " + leaf[20:], jwk), ("leaf-newline", leaf[:20] + "\n" + leaf[20:], jwk),
                           ("ca-issued-leaf", leaf_issued, jwk),
                           ("leaf-key-mismatch", leaf, {"kty": "EC", "crv": "P-256", "x": b64u(on.x.to_bytes(32, "big")), "y": b64u(on.y.to_bytes(32, "big"))})):
        hdr = json.dumps({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": [c]}, separators=(",", ":"))
        si = b64u(hdr.encode()) + "." + b64u(b'{"iss":"x"}')
        signer = sk if key_jwk is jwk else other
        r, s_ = decode_dss_signature(signer.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        compact = si + "." + b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~"
        out.append((nm, {"evidence_format": base["evidence_format"], "subject": "oracle r6", "created_utc": "2026-09-22T00:00:00Z",
                         "artifacts": [{"name": "intent", "sd_jwt_compact": compact, "header": json.loads(hdr), "key": {"jwk": key_jwk, "provenance_class": "x5c_header"},
                                        "resolved_claims": {"iss": "x"}, "kb_jwt": {"present": False}, "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}],
                         "bindings": [], "honest_scope": base["honest_scope"]}))
    return out


def _mixed_pack(base, x5c_ev):
    """One self-asserted (jwk_header) artifact plus the CA-issued x5c one: the case where `all` and `any` differ."""
    sk, n = _fresh_key()
    solo = _fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', '{"iss":"x"}', {"iss": "x"})
    ev = json.loads(json.dumps(x5c_ev))
    a0 = json.loads(json.dumps(solo["artifacts"][0])); a0["name"] = "mandate"
    ev["artifacts"] = [a0] + ev["artifacts"]
    return ev


def _sign_compact(sk, n, payload_txt):
    """An SD-JWT (no disclosures) with the JWK in the header, signed by `sk` — what the reference's `build` snapshots as jwk_header."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    si = b64u(json.dumps({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk}, separators=(",", ":")).encode()) + "." + b64u(payload_txt.encode())
    r, s_ = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return si + "." + b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~"


def _fresh_pack(base, sk, n, header_txt, payload_txt, resolved, disclosures=(), kb=None, jwk_x_bytes=None):
    """One-artifact pack signed by `sk` over the RAW header/payload text (so duplicate keys, BOM, floats reach the verifiers
    inside a valid ES256 signature), digest recomputed. `resolved` is what a lenient verifier resolves."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    jwk_pub = {"kty": "EC", "crv": "P-256", "x": b64u(jwk_x_bytes if jwk_x_bytes is not None else n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    if isinstance(header_txt, str) and '"jwk"' not in header_txt:   # r5: the snapshotted key is provenance_class jwk_header, so the signed header must carry the SAME jwk (reconciled at verify)
        header_txt = header_txt.rstrip()[:-1] + ',"jwk":' + json.dumps(jwk_pub, separators=(",", ":")) + "}"
    ht = header_txt.encode() if isinstance(header_txt, str) else header_txt; pt = payload_txt.encode() if isinstance(payload_txt, str) else payload_txt
    si = b64u(ht) + "." + b64u(pt); r, s_ = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    compact = si + "." + b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~" + "".join(x + "~" for x in disclosures) + (kb or "")
    jwk = jwk_pub
    ev = {"evidence_format": base["evidence_format"], "subject": "oracle r2", "created_utc": "2026-09-22T00:00:00Z",
          "artifacts": [{"name": "intent", "sd_jwt_compact": compact, "header": json.loads(ht) if isinstance(header_txt, str) else None, "key": {"jwk": jwk, "provenance_class": "jwk_header"},
                         "resolved_claims": resolved, "kb_jwt": {"present": bool(kb)}, "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}],   # 1.4.0: `present` must agree with the compact (SPEC §9.1)
          "bindings": [], "honest_scope": base["honest_scope"]}
    return rehash(ev)


CLI = {"cli-no-path": [], "cli-unknown-flag": ["V", "--no-such"], "cli-two-positionals": ["V", "V"], "cli-empty-path": [""], "cli-help": ["--help"], "cli-h": ["-h"],
       "cli-double-dash": ["--", "V"], "cli-bool-with-value": ["V", "--require-pq=1"], "cli-key-empty": ["V", "--trusted-producer-key", ""], "cli-key-missing-value": ["V", "--trusted-producer-key"],
       "cli-key-flag-as-value": ["V", "--trusted-producer-key", "--require-pq"], "cli-key-no-alg": ["V", "--trusted-producer-key", "abc"], "cli-tsa-cert-empty": ["V", "--tsa-cert", ""], "cli-repeated-key-empty-first": ["V", "--trusted-producer-key", "", "--trusted-producer-key", "ed25519=AA=="],
       "cli-eq-form-verdict": ["V", "--trusted-producer-key=ed25519=AA=="], "cli-bare-no-subcommand": ["BARE"],
       "cli-trust-anchor-empty": ["V", "--trust-anchor", ""], "cli-trust-anchor-eq-empty": ["V", "--trust-anchor="],   # r9: the flag added in r8 was outside the reference's grammar
       "cli-trust-anchor-flag-value": ["V", "--trust-anchor", "--require-pq"]}   # r3: no "verify" prefix at all


def main():
    if not shutil.which("node"):
        print("node absent: the JS verifier cannot be measured"); return 2
    tmp = tempfile.mkdtemp(); diffs = 0; n = 0
    try:
        cases = build_cases(tmp)
        declared = 0
        for name, (path, flags) in cases.items():
            if name in REFUSALS:   # declared reason, checked in each verifier (not only their agreement)
                py, js = refusal_of(PY, path), refusal_of(JS, path); n += 1
                ok = REFUSALS[name] in py and REFUSALS[name] in js and py != "valid" and js != "valid"; diffs += 0 if ok else 1
                print(f"  [{'OK ' if ok else 'DIFF'}] {name:34} declared refusal {REFUSALS[name]!r}: py={py[:70]!r} js={js[:70]!r}")
                continue
            py, js = run(PY, path, flags), run(JS, path, flags); n += 1
            if name in POSITIVE_CONTROLS and py[0] is not True:   # a positive control that does not verify proves nothing
                diffs += 1; print(f"  [DIFF] {name:34} positive control did not verify: py={py[:3]}"); continue
            if name in DECLARED and _matches_declared(name, py, js):
                declared += 1; print(f"  [DECL] {name:34} py={py} js={js}  <- declared: " + ("TSA verification" if "tsa-cert" in name else "chain validation") + " is openssl-only"); continue
            ok = py == js; diffs += 0 if ok else 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:34} py={py} js={js}")
        valid = os.path.join(ROOT, "spec", "vectors", "ap2", "valid_signed.json")
        for name, argv in CLI.items():
            bare = argv == ["BARE"]; args = [] if bare else [valid if a == "V" else a for a in argv]; row = {}
            for k, cmd in (("py", PY[:-1]), ("js", JS)):
                full = list(cmd) + (["verify"] if k == "py" and not bare else []) + args
                try:
                    out = subprocess.run(full, capture_output=True, text=True, timeout=60)
                    try: row[k] = "verdict:" + str(json.loads(out.stdout).get("valid"))
                    except Exception: row[k] = "usage" if out.returncode == 2 and out.stdout == "" else f"exit{out.returncode}{'+stdout' if out.stdout else ''}"   # r3: usage = exit 2 AND nothing on stdout
                except Exception: row[k] = "CRASH"
            want = "verdict:False" if name.endswith("-verdict") else "usage"   # the eq-form pins an unknown key: a verdict (not authentic), not usage
            ok = all(v == want for v in row.values()); diffs += 0 if ok else 1; n += 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:34} expect {want}: {row}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if declared != len(DECLARED):   # r2: a declared divergence that stops appearing (e.g. openssl absent) is reported, not silently counted OK
        print(f"  [WARN] declared divergences observed: {declared}/{len(DECLARED)} — the declaration no longer matches this machine"); diffs += 1
    n_vec = sum(1 for k in cases if k.startswith("vector-")); n_cli = len(CLI)
    n_pos = sum(1 for k in cases if k in POSITIVE_CONTROLS)
    print(f"decomposition: {n_vec} vector runs + {len(cases) - n_vec - n_pos} hostile files + {n_pos} positive controls + {n_cli} CLI cases = {n}")
    print(f"disagreements: {diffs}/{n} (declared: {declared})"); return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
