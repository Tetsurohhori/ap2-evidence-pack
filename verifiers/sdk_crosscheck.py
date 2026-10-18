#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""THIRD verifier, written by other people: Google's AP2 SDK over the `sd-jwt` reference implementation.

The differential oracle compares this repository's two verifiers, and both were written by the same author — so an
error in READING the specification is invisible to it: the same misreading lands in Python and in Node, and they agree.
This script closes that gap for the layer the SDK covers, the SD-JWT mandate itself. For every artifact of a pack it
asks `ap2.sdk.sdjwt.sd_jwt.verify()` (Google's wrapper around `sd_jwt.verifier.SDJWTVerifier`, the reference
implementation of RFC 9901, whose PyPI metadata names Daniel Fett — one of that RFC's three authors — as its author) whether the token verifies under the snapshotted key, and compares two things with what our
reference says about the same artifact:

  1. the VERDICT  — accept / refuse;
  2. the RESOLVED CLAIMS — the payload after disclosure resolution, which is where a misread digest rule would hide:
     a verdict can agree while the two stacks disclose different claims.

What it does NOT compare: the container (digest, bindings, producer signature, RFC 3161, policy, provenance class) —
the SDK has no notion of any of it, and our packs are the only place it exists. Read this as a cross-check of the
mandate layer only: of the six verification steps of SPEC §6, the signature and the disclosure resolution inside
step 2, and nothing else.

Usage:
    AP2_SDK_PATH=/path/to/AP2/code/sdk/python  python3 verifiers/sdk_crosscheck.py [pack.json ...]

Needs `jwcrypto`, `sd-jwt` and `pydantic` (the SDK's dependencies), which this repository does not require: run it in a
venv of its own. Exit 1 on any disagreement.
"""
import base64
import glob
import json
import os
import subprocess
import sys

SDJWT_VERSION = "unknown"   # replaced by _sdk() with the version of the package actually installed
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import ap2_evidence as ap2  # noqa: E402


def _sdk():
    p = os.environ.get("AP2_SDK_PATH")
    if not p or not os.path.isdir(p):
        sys.exit("set AP2_SDK_PATH to the AP2 repository's code/sdk/python (the SDK is not vendored here)")
    sys.path.insert(0, p)
    from ap2.sdk.sdjwt import sd_jwt as sdk_sdjwt   # noqa: PLC0415
    from jwcrypto.jwk import JWK                    # noqa: PLC0415
    try:
        import importlib.metadata as _md            # noqa: PLC0415
        globals()["SDJWT_VERSION"] = _md.version("sd-jwt")
    except Exception:                                # noqa: BLE001
        globals()["SDJWT_VERSION"] = "unknown"
    repo = os.path.abspath(os.path.join(p, "..", "..", ".."))
    r = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True)
    return sdk_sdjwt, JWK, (r.stdout.strip()[:12] or "unknown")


# Why our stack refused an artifact decides what a divergence MEANS. Three of the four buckets below are not
# disagreements about RFC 9901 at all: a layer the third stack does not have, a profile this repository declares
# stricter, or a structural MUST the RFC's own verifier algorithm does not enforce. Only what falls through is a finding — a rule the RFC puts on every verifier that the third stack does not enforce.
# 1.4.0: a refusal marked "(SPEC §9.1)" (a closed object of THIS format: the artifact entry, its key block, the recorded
# KB copy, the build attestation) is NOT a bucket here. Those checks run BEFORE the token's own, so the reason they give
# can stand in front of an RFC 9901 refusal the third stack disagrees with; `token_layer_view` looks underneath first.
CLOSED_MARK = "(SPEC §9.1)"
OURS_ONLY = ("provenance_class", "only EC/P-256")   # the pack's key block, no SD-JWT equivalent. "key.jwk must be
#   an object" does not belong here: such an artifact never reaches this branch, it is counted in `nokey` above.
# Exception types that are a crash inside the library rather than a refusal it meant to make.
UNCAUGHT = ("JSONDecodeError", "AttributeError", "TypeError", "KeyError", "IndexError", "RecursionError")
# A ValueError is ambiguous: the library raises one deliberately ("No holder public key in SD-JWT") and Python raises
# one when a tuple unpack fails, which is a crash. The message separates them.
PROFILE_31 = ("invalid base64url segment", "must be exactly 32 bytes", "exact ASCII compact serialization",
              "duplicate JSON key", "starts with a B", "not valid JSON/base64url")      # SPEC §3.1, declared stricter than RFC
# RFC 9901 puts a MUST on the VERIFIER in §7.1 step 5, and MUSTs on the STRUCTURE in §4.2.4.1 and §4.2.4.2 that its own
# verification algorithm then does not enforce: §7.1 step 3.b collects only well-formed `_sd` arrays and
# `{"...": string}` objects, and step 3.e removes every `_sd` key. So ignoring a malformed one is what the RFC's
# algorithm prescribes; rejecting it is this format's stricter choice. The two are not the same finding.
RFC_VERIFIER_MUST = ("match no digest", "disclosure must be [salt", "duplicate disclosure digest",
                     "disclosed claim name must be a string", "collides", "malformed disclosure",
                     # §7.1 step 2.d: "Check that the _sd_alg claim value is understood and the hash algorithm is
                     # deemed secure according to the Holder or Verifier's policy". That IS a verifier step, so an unsupported _sd_alg does not belong below.
                     "_sd_alg")
RFC_STRUCTURAL = ("_sd must be a list", "array disclosure placeholder")

# A divergence stays here only with its clause and its measurement. Declaring one is not excusing it: a declared
# divergence that STOPS appearing fails this bench too (the declaration would no longer describe the machine), which is
# the rule the differential oracle already applies to its own four.
DECLARED = {
    "disclosure-unused.json:intent":
        'RFC 9901 §7.1 step 5: "If any Disclosure was not referenced by digest value in the Issuer-signed JWT '
        '(directly or recursively via other Disclosures), the SD-JWT MUST be rejected." First measured 2026-09-22 and re-measured on '
        "every run of this bench, against the installed sd-jwt through the AP2 SDK: it accepts the presentation and "
        "returns a payload with the claim dropped. No forged claim passes — the divergence is the verdict, not the "
        "content.",
}

# The direction "we accept, the third stack refuses" is never bucketed by a reason string. It can be DECLARED only per
# case, with the clause that makes it a verifier-policy difference and not a hole, and only while EVERY condition below
# holds on the artifact (`declared_we_accept`): the third stack's own refusal reason, our KB-JWT recorded present and
# `verified: null`, and the issuer payload carrying no `cnf.jwk`. Any other wrong-way divergence — another case, another
# reason, or the same case once our verifier says something else — stays a [DIFF] and the bench red (control 8).
DECLARED_WE_ACCEPT = {
    "holder_key_unknown.json:cart": {
        "third_reason": "ValueError: No holder public key in SD-JWT",
        "why": 'RFC 9901 §7.3 step 1: "Determine if Key Binding is to be checked according to the Verifier\'s policy for '
               'the use case at hand"; step 5 ("If Key Binding is required: a. Determine the public key for the Holder '
               'from the SD-JWT") runs only under that policy, and §9.5: "Verifiers MUST decide whether Key Binding is '
               'required for a particular use case before verifying a credential." This bench hands the third stack the '
               "KB-JWT's aud/nonce, i.e. asks it as a verifier that REQUIRES key binding, where a missing holder key is a "
               "failed step and the presentation MUST be rejected. This format verifies offline, cannot validate aud/nonce/"
               "iat (§7.3 steps 5.e/5.f) and does not require key binding (SPEC §6 step 2): the KB-JWT is recorded "
               "present-but-unverifiable and the receipt states holder_binding not_evaluated/holder_key_unknown — never "
               "verified. A relying party whose policy requires key binding reads that state as not met. First measured "
               "2026-10-18, against sd-jwt 0.10.4 through the AP2 SDK; re-measured on every run.",
    },
}


def _issuer_has_cnf_jwk(compact):
    try:
        cnf = ap2.parse_sd_jwt(compact)["payload"].get("cnf")
    except Exception:   # noqa: BLE001 — unreadable: not the declared case
        return None
    return isinstance(cnf, dict) and "jwk" in cnf


def declared_we_accept(name, note, our_art, compact):
    """The declaration that applies to this wrong-way divergence, or None. All conditions, never the name alone."""
    d = DECLARED_WE_ACCEPT.get(name)
    kb = our_art.get("kb_jwt") if isinstance(our_art.get("kb_jwt"), dict) else {}
    if (d is None or note != d["third_reason"] or kb.get("present") is not True or kb.get("verified") is not None
            or _issuer_has_cnf_jwk(compact) is not False):
        return None
    return d


def classify(err):
    if not err:
        return "unknown", ""
    for k in OURS_ONLY:
        if k in err:
            return "ours_only", "a layer of the pack the third stack has no notion of"
    for k in PROFILE_31:
        if k in err:
            return "profile", "this repository's §3.1 profile, declared stricter than RFC 9901"
    for k in RFC_VERIFIER_MUST:
        if k in err:
            return "finding", "RFC 9901 §7.1 puts this MUST on the verifier; the third stack does not enforce it"
    for k in RFC_STRUCTURAL:
        if k in err:
            return "structural", ("RFC 9901 §4.2.4.1/§4.2.4.2 require the structure of the Issuer, and its verification "
                               "algorithm does not enforce it (§7.1 step 3.b collects only well-formed shapes, step "
                               "3.e removes every _sd key): ignoring the malformed part is what the RFC prescribes, "
                               "rejecting it is this format's stricter choice")
    return "unknown", ""


_ART_SUBS = (("key", "_KEY_KEYS"), ("kb_jwt", "_KB_COPY_KEYS"), ("verified_at_build", "_VAB_KEYS"))


def _strip_unknown_keys(a):
    """Drop only what the 1.6.0 unknown-key rule of SPEC §9.1 looks at: keys of artifacts[i] and of its key, kb_jwt and
    verified_at_build objects that this revision does not define. True when anything was dropped."""
    dropped = False
    for k in [k for k in a if k not in ap2._ARTIFACT_KEYS]:
        del a[k]
        dropped = True
    for sub, keys in _ART_SUBS:
        o = a.get(sub)
        if isinstance(o, dict):
            for k in [k for k in o if k not in getattr(ap2, keys)]:
                del o[k]
                dropped = True
    return dropped


def artifact_layer_view(ev, ours):
    """Our per-artifact verdicts, also when 1.6.0 refused the whole pack for an unknown key inside an artifact.

    1.6.0 (SPEC §9.1, not additive) moved that rule from the artifact's own `error` to a pack refusal of class
    `unknown_member` with `artifacts: []`. Read as a refusal before the mandate layer, every such pack left the
    comparison, and the controls that put `x_unknown` in an entry read "no error" (CI run 39135564764, controls 4 and 7).
    The refusal is still a closed object of this format around a token: each artifact carrying such a key gets the
    refusal as its error (it carries CLOSED_MARK, so the §9.1 path looks underneath), and the others the verdict of the
    same pack with those keys removed. Any other refusal is returned as it is."""
    import copy        # noqa: PLC0415
    msg = ours.get("refused")
    if not (isinstance(msg, str) and ours.get("refusal_class") == "unknown_member" and msg.startswith("artifacts[")
            and isinstance(ev.get("artifacts"), list)):
        return ours
    ev2 = copy.deepcopy(ev)
    flagged = {i for i, a in enumerate(ev2["artifacts"]) if isinstance(a, dict) and _strip_unknown_keys(a)}
    r = _verify_obj(ev2)
    if r.get("refused") or not flagged:
        return ours
    arts = list(r.get("artifacts") or [])
    for i in flagged:
        if i < len(arts) and isinstance(arts[i], dict):
            arts[i] = dict(arts[i], error=(msg if msg.startswith(f"artifacts[{i}]") else
                                           f"artifacts[{i}]: unknown key {CLOSED_MARK}"))
    return dict(r, artifacts=arts, refused=None, refusal_class=None)


def token_layer_view(ev, idx):
    """Our verdict on artifact `idx` with its closed objects (SPEC §9.1) rebuilt as `build` writes them: the `header`
    copy decoded from the token, `kb_jwt` reduced to `present` as the token says, `verified_at_build` the two `true`s,
    keys the key block does not define dropped. Returns (our_art, art). A §9.1 refusal is a layer the third stack has
    no notion of ONLY if what is left underneath still gets the third stack's verdict: without this, a recorded KB copy
    contradicting a KB-JWT whose signature or sd_hash fails hid any third stack that does not check them (measured).
    """
    import copy        # noqa: PLC0415
    ev2 = copy.deepcopy(ev)
    a = ev2["artifacts"][idx]
    compact = a.get("sd_jwt_compact")
    try:
        parsed = ap2.parse_sd_jwt(compact)
        a["header"], kb_present = parsed["header"], bool(parsed["kb_jwt"])
    except Exception:   # noqa: BLE001 — the token's own refusal will come out of verify below
        kb_present = isinstance(a.get("kb_jwt"), dict) and a["kb_jwt"].get("present") is True
    a["kb_jwt"] = {"present": kb_present}
    a["verified_at_build"] = {"signature_ok": True, "disclosures_ok": True}
    if isinstance(a.get("key"), dict):
        a["key"] = {k: v for k, v in a["key"].items() if k in ap2._KEY_KEYS}
    for k in [k for k in a if k not in ap2._ARTIFACT_KEYS]:
        del a[k]
    for other in ev2["artifacts"]:   # 1.6.0: another entry's unknown key refuses the whole pack, not this token
        if isinstance(other, dict) and other is not a:
            _strip_unknown_keys(other)
    arts = _verify_obj(ev2).get("artifacts") or []
    under = arts[idx] if idx < len(arts) and isinstance(arts[idx], dict) else {"error": f"rebuilt pack refused {CLOSED_MARK}"}
    return under, a


def closed_layer_decision(under, under_src, their):
    """What a §9.1 refusal means once the token underneath has been looked at (`token_layer_view`):
    "ours_only"  — underneath, our verdict is the third stack's, or the key block itself is malformed: a layer it lacks;
    "we_accept"  — underneath we accept and the third stack refuses: the direction never bucketed away;
    "underneath" — underneath we refuse and the third stack accepts: judged on that reason, like any other refusal."""
    under_ok, _ = ours_says(under, under_src)
    if under_ok == their or CLOSED_MARK in str(under.get("error", "")):
        return "ours_only"
    if under_ok and not their:
        return "we_accept"
    return "underneath"


def _verify_obj(ev):
    import tempfile    # noqa: PLC0415
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(ev, fh)
        return ap2.verify_evidence(path)
    finally:
        os.unlink(path)


def closed_layer_control(sdk_sdjwt, JWK, base_pack):
    """Controls for the §9.1 handling: each case is a state in which the closed layer must NOT be the end of it, or must."""
    import copy        # noqa: PLC0415
    with open(base_pack, encoding="utf-8") as fh:
        base = json.load(fh)
    out, ok_all = [], True

    def case(label, ev, their, want):
        nonlocal ok_all
        top = (artifact_layer_view(ev, _verify_obj(ev)).get("artifacts") or [{}])[0]
        under, src = token_layer_view(ev, 0)
        got = closed_layer_decision(under, src, their)
        good = CLOSED_MARK in str(top.get("error", "")) and got == want
        ok_all &= good
        out.append(f"  [{'PASS' if good else 'FAIL'}] {label}: {got} (want {want}); ours "
                   f"{top.get('error', 'no error')!r}; underneath {under.get('error', 'no error')!r}")

    # 4: every closed object of the entry broken at once (unknown key in the entry and in its key block, header copy
    # gone, attestation emptied) around a rewritten disclosure the third stack ACCEPTS (RFC 9901 §7.1 step 5).
    ev = copy.deepcopy(base)
    art = ev["artifacts"][0]
    compact = art["sd_jwt_compact"]
    head, _, rest = compact.partition("~")
    d = [x for x in rest.split("~") if x][0]
    raw = json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))
    raw[-1] = "999999.00 EUR" if raw[-1] != "999999.00 EUR" else "1.00 EUR"
    newd = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":")).encode()).decode().rstrip("=")
    art["sd_jwt_compact"] = compact.replace("~" + d + "~", "~" + newd + "~", 1)
    art["x_unknown"] = True
    art["key"]["x_unknown"] = True
    art.pop("header", None)
    art["verified_at_build"] = {}
    their, _, _ = sdk_says(sdk_sdjwt, JWK, art["sd_jwt_compact"], art["key"]["jwk"])
    case("control 4 closed objects broken around a token the third stack accepts and we refuse", ev, their, "underneath")

    # 5: the recorded KB copy `build` writes, around a KB-JWT whose signature no longer verifies. Asked as if the third
    # stack had accepted it (one that skips the key binding): underneath, our refusal must stand.
    with open(os.path.join(ROOT, "spec", "vectors", "ap2", "kb_jwt_valid.json"), encoding="utf-8") as fh:
        ev5 = json.load(fh)
    a5 = ev5["artifacts"][0]
    kb5 = ap2.verify_kb_jwt(ap2.parse_sd_jwt(a5["sd_jwt_compact"]), a5["resolved_claims"])
    kb5.pop("_ignored", None)
    a5["kb_jwt"] = kb5
    c5 = a5["sd_jwt_compact"]
    a5["sd_jwt_compact"] = c5[:-10] + ("A" if c5[-10] != "A" else "B") + c5[-9:]
    case("control 5 a recorded KB copy around a KB-JWT that fails, third stack accepting", ev5, True, "underneath")

    # 6: a known key of the key block with the wrong type is the pack's own layer, whatever the third stack says.
    ev6 = copy.deepcopy(base)
    ev6["artifacts"][0]["key"]["note"] = 5
    case("control 6 a malformed key block stays ours-only", ev6, True, "ours_only")

    # 7: only the closed layer refuses, and the third stack (as if) refuses the token: the direction never bucketed.
    ev7 = copy.deepcopy(base)
    ev7["artifacts"][0]["x_unknown"] = True
    case("control 7 we accept underneath, third stack refusing", ev7, False, "we_accept")

    # 8: a declared wrong-way divergence holds only with every condition; each variant below must stay a [DIFF].
    hk = os.path.join(ROOT, "spec", "vectors", "ap2", "holder_key_unknown.json")
    with open(hk, encoding="utf-8") as fh:
        ev8 = json.load(fh)
    a8 = ev8["artifacts"][0]
    o8 = ap2.verify_evidence(hk)["artifacts"][0]
    name8, note8 = "holder_key_unknown.json:cart", DECLARED_WE_ACCEPT["holder_key_unknown.json:cart"]["third_reason"]
    with open(os.path.join(ROOT, "spec", "vectors", "ap2", "kb_jwt_valid.json"), encoding="utf-8") as fh:
        cnf_compact = json.load(fh)["artifacts"][0]["sd_jwt_compact"]
    variants = [("the declared case", name8, note8, o8, a8["sd_jwt_compact"], True),
                ("another case, same reason", "valid_signed.json:intent", note8, o8, a8["sd_jwt_compact"], False),
                ("same case, another third-stack reason", name8, "InvalidJWSSignature: Verification failed", o8,
                 a8["sd_jwt_compact"], False),
                ("same case, our KB-JWT verified", name8, note8, dict(o8, kb_jwt=dict(o8["kb_jwt"], verified=True)),
                 a8["sd_jwt_compact"], False),
                ("same case, issuer carrying cnf.jwk", name8, note8, o8, cnf_compact, False),
                ("same case, our KB-JWT absent", name8, note8, dict(o8, kb_jwt=dict(o8["kb_jwt"], present=False)),
                 a8["sd_jwt_compact"], False)]
    for label, nm, nt, oa, cp, want in variants:
        got = declared_we_accept(nm, nt, oa, cp) is not None
        good = got == want
        ok_all &= good
        out.append(f"  [{'PASS' if good else 'FAIL'}] control 8 declared wrong-way divergence, {label}: "
                   f"{'declared' if got else 'DIFF'} (want {'declared' if want else 'DIFF'})")

    # 9: the 1.6.0 pack refusal mapped back (artifact_layer_view). Every entry carrying an unknown key gets a §9.1 error
    # and is looked at underneath with the OTHER entries' unknown keys removed; a refusal that survives the removal (here
    # an unknown key in a producer-signature entry) keeps the pack refused, never an admitted pack with no artifacts.
    ev9 = copy.deepcopy(base)
    for a in ev9["artifacts"]:
        a["x_unknown"] = True
    v9 = artifact_layer_view(ev9, _verify_obj(ev9))
    arts9 = v9.get("artifacts") or []
    for i in range(len(ev9["artifacts"])):
        top = arts9[i] if i < len(arts9) and isinstance(arts9[i], dict) else {}
        under, _ = token_layer_view(ev9, i)
        good = (not v9.get("refused") and CLOSED_MARK in str(top.get("error", "")) and "error" not in under
                and under.get("signature_ok") is True)
        ok_all &= good
        out.append(f"  [{'PASS' if good else 'FAIL'}] control 9 unknown key in every entry, artifact {i}: ours "
                   f"{top.get('error', 'no error')!r}; underneath {under.get('error', 'no error')!r}")
    ev9b = copy.deepcopy(base)
    ev9b["artifacts"][0]["x_unknown"] = True
    ev9b["producer_signatures"]["signatures"][0]["x_unknown"] = True
    raw9b = _verify_obj(ev9b)
    v9b = artifact_layer_view(ev9b, raw9b)
    good = bool(raw9b.get("refused")) and v9b.get("refused") == raw9b.get("refused")
    ok_all &= good
    out.append(f"  [{'PASS' if good else 'FAIL'}] control 9 a refusal that survives the removal stays a refusal: "
               f"{str(v9b.get('refused'))[:80]!r}")
    return ok_all, out


def has_kb(compact):
    """A KB-JWT is present when the segment after the last `~` is itself a three-part JWT.

    `sd_jwt.verify` is called without expected_aud/nonce, so the third stack does not validate the KB-JWT at all: on
    such a pack its acceptance carries no opinion, and counting it as agreement OR as a divergence would both be false.
    """
    tail = compact.rsplit("~", 1)[-1].strip()
    # A disclosure is one base64url token with no dot; anything with a dot in that position is a KB-JWT, including a
    # MALFORMED one (r1 of this bench: a two-segment KB slipped through a `== 3` test and was counted as a finding).
    return "." in tail


def kb_expectations(compact):
    """The `aud`/`nonce` a KB-JWT carries, so the third stack can be asked about the key binding at all.

    Feeding the token its OWN aud and nonce does not validate them against anything — offline, neither verifier can:
    this repository records them as present-but-not-validated and says so in its sealed scope. What it does buy is the
    part that IS checkable offline and was otherwise never compared: the KB-JWT signature and its `sd_hash` binding.
    Returns (aud, nonce) or (None, None) when there is no KB-JWT or its payload cannot be read.
    """
    tail = compact.rsplit("~", 1)[-1].strip()
    if "." not in tail:
        return None, None
    parts = tail.split(".")
    if len(parts) != 3:
        return None, None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:   # noqa: BLE001
        return None, None
    if not isinstance(payload, dict):
        return None, None
    aud, nonce = payload.get("aud"), payload.get("nonce")
    return (aud if isinstance(aud, str) else None), (nonce if isinstance(nonce, str) else None)


def sdk_says(sdk_sdjwt, JWK, compact, jwk_dict):
    """(verdict, claims, note): does the third stack accept this token under this key, and what does it disclose?

    verdict None means the third stack could not be asked at all, which is not a disagreement — it is a gap, printed
    as such.
    """
    try:
        key = JWK(**{k: v for k, v in jwk_dict.items() if k in ("kty", "crv", "x", "y")})
    except Exception as e:   # noqa: BLE001
        return None, None, f"key not loadable by jwcrypto: {type(e).__name__}"
    aud, nonce = kb_expectations(compact)
    try:
        return True, sdk_sdjwt.verify(compact, key, expected_aud=aud, expected_nonce=nonce), ""
    except Exception as e:   # noqa: BLE001
        return False, None, f"{type(e).__name__}: {str(e)[:90]}"


def ours_says(our_art, art):
    """(verdict, claims): our reference's opinion on the same artifact, at the same layer.

    The reference does NOT return the claims it resolved: it returns `claims_match`, meaning it re-derived exactly the
    `resolved_claims` written in the pack. So the claims attributable to our stack are the pack's own, and only when
    that flag is true — otherwise our verifier has itself disowned them and there is nothing of ours to compare.
    """
    # The artifact's verdict is not `signature_ok` alone: a pack whose resolved claims do not match what the file
    # records, or whose KB-JWT verifies FALSE, fails here too. Reading only the signature was a proxy for the verdict,
    # and it made `claims-mismatch` print "both accept" over an artifact this verifier rejects.
    kb = our_art.get("kb_jwt") if isinstance(our_art.get("kb_jwt"), dict) else {}
    ok = (our_art.get("signature_ok") is True and "error" not in our_art
          and our_art.get("claims_match") is not False and kb.get("verified") is not False)
    claims = art.get("resolved_claims") if our_art.get("claims_match") is True else None
    return ok, (claims if isinstance(claims, dict) else None)


def positive_controls(sdk_sdjwt, JWK, base_pack):
    """Show this bench can go red before trusting the green it prints (metodo verde: a bench that cannot fail measures nothing).

    Three controls, each one a state in which a real disagreement or a real refusal MUST appear:
      1. a flipped signature byte  — both stacks must refuse;
      2. a rewritten disclosure    — the forged value must never reach the caller (the third stack ACCEPTS the
         presentation and drops the claim; only this repository refuses it, which is the declared divergence below);
      3. a wrong key               — the third stack's own verdict must flip. This asks the third stack alone; that a
         disagreement is REPORTED and turns this bench red is a separate ablation, AP2_XCHECK_SEED_DIVERGENCE=1.
    """
    with open(base_pack, encoding="utf-8") as fh:
        ev = json.load(fh)
    art = ev["artifacts"][0]
    compact, jwk = art["sd_jwt_compact"], art["key"]["jwk"]
    out, ok_all = [], True

    head, _, rest = compact.partition("~")
    h, pl, sig = head.split(".")
    flipped_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    flipped = f"{h}.{pl}.{flipped_sig}~{rest}"
    v, _, note = sdk_says(sdk_sdjwt, JWK, flipped, jwk)
    good = v is False
    ok_all &= good
    out.append(f"  [{'PASS' if good else 'FAIL'}] control 1 flipped signature: third stack "
               f"{'refuses' if v is False else 'ACCEPTS — the bench cannot see a forged signature'} ({note})")

    parts = [x for x in rest.split("~") if x]
    if parts:
        # A disclosure rewritten so that it STILL PARSES: [salt, name, value] with the value changed. Flipping a byte
        # would only break base64 or JSON, which any parser catches; this one is caught solely because the digest in
        # `_sd` no longer matches — the property actually under test.
        d = parts[0]
        raw = json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))
        forged = "999999.00 EUR" if raw[-1] != "999999.00 EUR" else "1.00 EUR"
        raw[-1] = forged
        newd = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":")).encode()).decode().rstrip("=")
        tampered = compact.replace("~" + d + "~", "~" + newd + "~", 1)
        v2, claims2, note2 = sdk_says(sdk_sdjwt, JWK, tampered, jwk)
        # The security property: whatever the verdict, the forged value must never reach the caller.
        leaked = forged in json.dumps(claims2 or {})
        ok_all &= not leaked
        out.append(f"  [{'FAIL' if leaked else 'PASS'}] control 2 rewritten disclosure: the forged value "
                   f"{'IS DISCLOSED — a rewritten claim passes' if leaked else 'never reaches the caller'}"
                   + (f" (third stack refuses: {note2})" if v2 is False else " (third stack accepts, claim dropped)"))
        if v2 is True:
            out.append("  [DECL] control 2, divergence of verdict: the third stack ACCEPTS the presentation and "
                       "silently drops the unreferenced disclosure; this repository refuses it. RFC 9901 §7.1 step 5: "
                       "\"If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or "
                       "recursively via other Disclosures), the SD-JWT MUST be rejected.\" First measured 2026-09-22, "
                       f"re-measured on every run, against sd-jwt {SDJWT_VERSION}; no forged claim passes either "
                       "way, the difference is that a "
                       "presentation the RFC says MUST be rejected is accepted with a reduced payload.")
    else:
        out.append("  [SKIP] control 2 rewritten disclosure: this pack has no disclosure to rewrite")

    wrong = dict(jwk)
    wrong["x"] = ("A" if wrong["x"][0] != "A" else "B") + wrong["x"][1:]
    v3, _, note3 = sdk_says(sdk_sdjwt, JWK, compact, wrong)
    good3 = v3 is False   # `is not True` also passed when the key could not be loaded at all, testing nothing
    ok_all &= good3
    out.append(f"  [{'PASS' if good3 else 'FAIL'}] control 3 the third stack's verdict flips on a wrong key: "
               f"third says {v3} ({note3})")
    out.append("  [NOTE] control 3 checks the third stack alone. That a divergence is REPORTED and turns this bench "
               "red is held by AP2_XCHECK_SEED_DIVERGENCE=1, which corrupts the key handed to the third stack on the "
               "first artifact: the run must then print [DIFF] and exit 1. CI runs it that way as its own step.")
    return ok_all, out



def interop_controls(sdk_sdjwt, JWK, base_pack):
    """Tokens ISSUED by the third stack, verified here — the direction the rest of this bench cannot test.

    Everything else compares opinions about tokens produced in this repository: flat `_sd`, three-element disclosures,
    no decoys. A misreading shared by this repository's two verifiers would survive that, because the corpus itself
    comes from the same reading. Here the third stack mints the token — decoy digests included, and the delegate
    payload lands as an ARRAY-ELEMENT disclosure, a shape no hostile file exercises — and this repository's reference
    is asked to verify it and to resolve the same claims.
    """
    out, ok_all = [], True
    try:
        from pydantic import BaseModel   # noqa: PLC0415
    except Exception:                     # noqa: BLE001
        return True, ["  [SKIP] interop: pydantic absent, the third stack cannot be asked to issue"]

    class _Mandate(BaseModel):
        iss: str
        mandate_type: str
        max_amount: str

    with open(base_pack, encoding="utf-8") as fh:
        base = json.load(fh)
    for decoys in (False, True):
        try:
            key = JWK.generate(kty="EC", crv="P-256")
            pub = {k: v for k, v in json.loads(key.export_public()).items() if k in ("kty", "crv", "x", "y")}
            compact = sdk_sdjwt.create(
                _Mandate(iss="third-party-issuer", mandate_type="checkout", max_amount="42.00 EUR"),
                key, add_decoy_claims=decoys).sd_jwt_issuance
            theirs = sdk_sdjwt.verify(compact, key)
        except Exception as e:   # noqa: BLE001
            out.append(f"  [SKIP] interop (decoys={decoys}): the third stack could not issue ({type(e).__name__})")
            continue
        # 1.4.0 (SPEC §9.1): an artifact entry carries `header`, the decoded protected header of the issuer JWT,
        # exactly as `build` writes it; the verifier checks it equals the signed one.
        hseg = compact.split("~")[0].split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(hseg + "=" * (-len(hseg) % 4)))
        ev = {"evidence_format": base["evidence_format"], "subject": "issued by the third stack",
              "created_utc": "2026-01-01T00:00:00Z",
              "artifacts": [{"name": "checkout", "sd_jwt_compact": compact, "header": header,
                             "key": {"jwk": pub, "provenance_class": "supplied"},
                             "resolved_claims": theirs, "kb_jwt": {"present": False},
                             "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}],
              "bindings": [], "honest_scope": base["honest_scope"]}
        sys.path.insert(0, HERE)
        from differential_oracle import rehash   # noqa: PLC0415
        import tempfile     # noqa: PLC0415
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(rehash(ev), fh)
        try:
            r = ap2.verify_evidence(path)
        finally:
            os.unlink(path)
        art = (r.get("artifacts") or [{}])[0]
        # The sentence "the delegate payload lands as an array-element disclosure" is a claim about what the third
        # stack emitted: asserted here against the signed payload, so it cannot drift away from the token.
        try:
            seg = compact.split("~")[0].split(".")[1]
            payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
            arr_ph = json.dumps(payload).count('"..."')
        except Exception:   # noqa: BLE001
            arr_ph = -1
        good = r.get("valid") is True and art.get("claims_match") is True and arr_ph > 0
        ok_all &= good
        out.append(f"  [{'PASS' if good else 'FAIL'}] interop, token issued by the third stack "
                   f"(decoy digests: {'yes' if decoys else 'no'}, {arr_ph} array-element placeholders in its signed "
                   f"payload): "
                   + ("this repository verifies it and resolves the same claims" if good
                      else f"REFUSED here — {art.get('error') or r.get('refused')}"))
    return ok_all, out


def hostile_packs():
    """The oracle's hostile corpus, built here so the third stack sees the same files our two verifiers see.

    Most of those files attack the container (digest, bindings, producer signature), which the third stack has no
    notion of; the ones that matter here are the mandate-level attacks — the §3.1 profile inside the SD-JWT, base64
    spelling, duplicate keys, lone surrogates. Returns (tempdir, [paths]); the caller removes the directory.
    """
    sys.path.insert(0, HERE)
    import shutil          # noqa: PLC0415
    import tempfile        # noqa: PLC0415
    from differential_oracle import REFUSALS, build_cases   # noqa: PLC0415
    d = tempfile.mkdtemp()
    try:
        cases = build_cases(d)
    except Exception:       # noqa: BLE001
        shutil.rmtree(d, ignore_errors=True)
        raise
    # 26/09/2026: the oracle's file-object cases (a FIFO, a symlink to /dev/zero, a directory) are not files this bench
    # may open — json.load(open()) on /dev/zero read until the CI runner was killed, and a FIFO would block. They test
    # the refusal BEFORE reading, which the third stack has no layer for. Left out, counted and printed.
    not_files = sorted(n for n, why in REFUSALS.items() if why == "not a regular file")
    return d, [path for name, (path, _flags) in sorted(cases.items())
               if not name.startswith("vector-") and name not in not_files], not_files


def main(argv):
    sdk_sdjwt, JWK, sha = _sdk()
    base = os.path.join(ROOT, "spec", "vectors", "ap2", "valid_signed.json")
    args = [a for a in argv[1:] if not a.startswith("--")]
    tmpdir = None
    if "--hostile" in argv:
        tmpdir, extra, not_files = hostile_packs()
    else:
        extra, not_files = [], []
    packs = (args or sorted(p for p in glob.glob(os.path.join(ROOT, "spec", "vectors", "ap2", "*.json"))
                            if not p.endswith(".expected.json"))) + extra
    print(f"third verifier: Google AP2 SDK at commit {sha} over sd-jwt {SDJWT_VERSION}, the reference "
          f"implementation (version read from the installed package, not written here)")
    print("layer compared: the SD-JWT mandate only (signature + disclosure resolution). Not the container.")
    controls_ok, lines = positive_controls(sdk_sdjwt, JWK, base)
    c4_ok, c4_lines = closed_layer_control(sdk_sdjwt, JWK, base)
    controls_ok &= c4_ok
    lines.extend(c4_lines)
    print("positive controls (this bench must be able to go red):")
    for line in lines:
        print(line)
    interop_ok, ilines = interop_controls(sdk_sdjwt, JWK, base)
    controls_ok &= interop_ok
    print("interoperability, the other direction (the third stack issues, this repository verifies):")
    for line in ilines:
        print(line)
    diffs = gaps = n = claims_cmp = earlier = ours_only = profile = kbgap = structural = unreadable = n_vec = 0
    findings = []
    raises_uncaught = raises_meant = nokey = 0
    seen_declared = set()
    for path in packs:
        try:
            with open(path, encoding="utf-8") as fh:
                ev = json.load(fh)
        except Exception:   # noqa: BLE001
            # A hostile file this bench cannot even read (a BOM, a 100000-deep nesting, a raw non-UTF-8 byte). It was
            # being skipped in silence, which quietly shrank the denominator: counted and printed instead.
            unreadable += 1
            continue
        try:
            ours = artifact_layer_view(ev, ap2.verify_evidence(path))
        except Exception as e:   # noqa: BLE001
            print(f"  [SKIP] {os.path.basename(path):44} our reference raised {type(e).__name__}")
            continue
        if ours.get("refused"):
            # Our stack refused the FILE before reaching any artifact (§3.1 profile, evidence_format, sealed scope).
            # The third stack has no such layer, so this is not a disagreement about the mandate — it is a refusal we
            # make and it cannot. Counted apart, never as agreement.
            earlier += 1
            continue
        for idx, (art, our_art) in enumerate(zip(ev.get("artifacts", []) or [], ours.get("artifacts", []) or [])):
            if not isinstance(art, dict) or not isinstance(our_art, dict):
                continue
            compact = art.get("sd_jwt_compact")
            jwk = (art.get("key") or {}).get("jwk") if isinstance(art.get("key"), dict) else None
            if not isinstance(compact, str) or not isinstance(jwk, dict):
                # The key block itself is not a key: there is nothing to hand the third stack, so no opinion of its
                # own exists. Counted and printed — leaving these out of every total is the shrinking-denominator
                # defect this bench already had once with the three unreadable files.
                nokey += 1
                continue
            n += 1
            from_vector = os.path.join("spec", "vectors", "ap2") in path
            n_vec += 1 if from_vector else 0
            name = f"{os.path.basename(path)}:{art.get('name')}"
            seed = os.environ.get("AP2_XCHECK_SEED_DIVERGENCE") == "1" and n == 1
            asked = dict(jwk)
            if seed:
                # Ablation of the comparator itself: hand the third stack a key that cannot verify while our own
                # verdict is unchanged. A bench that cannot report a disagreement proves nothing by reporting none.
                asked["x"] = ("A" if str(asked.get("x", "A"))[0] != "A" else "B") + str(asked.get("x", ""))[1:]
            their, their_claims, note = sdk_says(sdk_sdjwt, JWK, compact, asked)
            our, our_claims = ours_says(our_art, art)
            if their is False and note:
                # "refuse" for the third stack means "raises". Some of those are deliberate refusals carrying a
                # message; others are uncaught internal errors. Both fail closed here, but only the first is a verdict,
                # and a reader of these totals must be able to tell them apart.
                if note.split(":")[0] in UNCAUGHT or "values to unpack" in note:
                    raises_uncaught += 1
                else:
                    raises_meant += 1
            if their is None:
                gaps += 1
                print(f"  [GAP ] {name:46} third stack could not be asked ({note})")
                continue
            if their != our:
                if seed:
                    diffs += 1
                    findings.append((name, "seeded divergence", note))
                    print(f"  [DIFF] {name:46} SEEDED: third stack given a corrupted key — {note}")
                    continue
                if our and not their:
                    # The safety-critical direction: something WE accept and a third implementation refuses. It is never
                    # bucketed away, whatever the reason — that is the shape of a hole in our own verifier. Only a
                    # declaration with its clause and every condition met (`declared_we_accept`, control 8) prints it apart.
                    d = declared_we_accept(name, note, our_art, compact)
                    if d is not None:
                        seen_declared.add(name)
                        print(f"  [DECL] {name:46} ours=ACCEPT third=refuse ({note}) — {d['why']}")
                        continue
                    diffs += 1
                    findings.append((name, "we accept, third refuses", note))
                    print(f"  [DIFF] {name:46} ours=ACCEPT third=refuse — {note}")
                    continue
                if CLOSED_MARK in str(our_art.get("error", "")):
                    # A closed object of this format refused the artifact before its token was looked at. That is a
                    # layer the third stack has no notion of only if the token underneath gets the third stack's verdict.
                    under, under_src = token_layer_view(ev, idx)
                    decision = closed_layer_decision(under, under_src, their)
                    if decision == "ours_only":
                        ours_only += 1
                        continue
                    if decision == "we_accept":
                        diffs += 1
                        findings.append((name, "we accept, third refuses", note))
                        print(f"  [DIFF] {name:46} ours=ACCEPT under the closed layer, third=refuse — {note}")
                        continue
                    our_art = under   # judged on the reason underneath, like any other refusal
                if has_kb(compact) and kb_expectations(compact) == (None, None):
                    # No readable aud/nonce, so the third stack cannot be asked about the key binding at all.
                    kbgap += 1
                    continue
                if our_art.get("claims_match") is False:
                    # `claims_match` compares the resolved claims against the `resolved_claims` RECORDED IN THE PACK —
                    # a container field the third stack has never seen. Its refusal is ours to make and not comparable.
                    ours_only += 1
                    continue
                kind, why = classify(our_art.get("error"))
                if kind == "ours_only":
                    ours_only += 1
                    continue
                if kind == "profile":
                    profile += 1
                    continue
                if kind == "structural":
                    structural += 1
                    print(f"  [SPEC] {name:46} ours=refuse third=accept — {why}")
                    print(f"         our reason: {our_art.get('error', '')}")
                    # What the third stack HANDS BACK matters more than that it accepted: printed, so the sentence
                    # about it in the README and the SPEC is copied from a measurement, not written from memory.
                    print(f"         third stack returns: {json.dumps(their_claims, sort_keys=True)[:150]}")
                    continue
                if name in DECLARED:
                    seen_declared.add(name)
                    print(f"  [DECL] {name:46} ours=refuse third=accept — {DECLARED[name]}")
                    continue
                findings.append((name, our_art.get("error", ""), why))
                diffs += 1
                print(f"  [DIFF] {name:46} ours=refuse third=accept — {why}")
                print(f"         our reason: {our_art.get('error', '')}")
                continue
            if their and our_claims is not None:
                claims_cmp += 1
                theirs = their_claims or {}
                # Key SETS first: comparing only the intersection would hide a claim one stack discloses and the other
                # does not, which is exactly the shape a misread digest rule produces.
                only_ours = sorted(set(our_claims) - set(theirs))
                only_theirs = sorted(set(theirs) - set(our_claims))
                bad = sorted(k for k in set(theirs) & set(our_claims) if our_claims[k] != theirs[k])
                if only_ours or only_theirs or bad:
                    diffs += 1
                    print(f"  [DIFF] {name:46} both accept but disclose differently — "
                          f"only ours {only_ours}, only third {only_theirs}, different values {bad}")
                    continue
                print(f"  [OK  ] {name:46} both accept, same {len(theirs)} claims, same values")
            else:
                print(f"  [OK  ] {name:46} both {'accept' if our else 'refuse'}"
                      + (f" ({note})" if not our else ""))
    missing = sorted((set(DECLARED) | set(DECLARED_WE_ACCEPT)) - seen_declared) if "--hostile" in argv else []
    if missing:
        print(f"  [WARN] declared divergences that did not appear: {missing} — the declaration no longer describes "
              "this machine (a newer third-party release may have fixed it, or the case stopped being built)")
        diffs += len(missing)
    print(f"artifacts from the conformance vectors: {n_vec} | from the hostile corpus: {n - n_vec}")
    print(f"the third stack refuses by RAISING: {raises_meant} deliberate refusals carrying a message, "
          f"{raises_uncaught} uncaught internal errors (fail-closed in effect, but not a verdict)")
    print(f"artifacts whose key block is not a key, so nothing could be handed to the third stack: {nokey}")
    print(f"hostile files this bench cannot even read (BOM, 100000-deep nesting, a non-UTF-8 byte): {unreadable}")
    print(f"file-object cases not handed to this bench (not regular files; refused before reading by our two verifiers, "
          f"see the oracle): {len(not_files)} {not_files}")
    print("not disagreements, counted apart:")
    print(f"  ARTIFACTS refused by us at a layer the third stack has no notion of (key provenance,\n    the `resolved_claims` the file itself records, the closed objects of SPEC §9.1): {ours_only}")
    print(f"  refused by us under the §3.1 profile this repository declares stricter:          {profile}")
    print(f"  KB-JWT whose aud/nonce could not be read, so its binding could not be compared: {kbgap}")
    print(f"  refused by us where the RFC's own verification algorithm ignores the malformed part:  {structural}")
    print(f"packs seen: {len(packs)} | refused by us before the mandate layer (no third-stack opinion "
          f"applies): {earlier}")
    print(f"artifacts compared: {n} | claim-sets compared: {claims_cmp} | not askable: {gaps}")
    print(f"mandate-layer disagreements with the third stack, on a rule the RFC puts on the verifier: {diffs}/{n}")
    wrong_way = [f for f in findings if f[1] in ("we accept, third refuses", "seeded divergence")]
    declared_wrong_way = sorted(set(DECLARED_WE_ACCEPT) & seen_declared)
    print("  (none undeclared in the direction 'we accept, a third implementation refuses')" if not wrong_way
          else f"  INCLUDING {len(wrong_way)} in the direction 'we accept, the third stack refuses': "
               f"{[f[0] for f in wrong_way]}")
    if declared_wrong_way:
        print(f"  declared in that direction (verifier policy, with every condition checked, see [DECL]): "
              f"{len(declared_wrong_way)} {declared_wrong_way}")
    if tmpdir:
        import shutil    # noqa: PLC0415
        shutil.rmtree(tmpdir, ignore_errors=True)
    if not controls_ok:
        print("positive controls FAILED: a green result here would mean nothing")
    return 1 if (diffs or not controls_ok) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
