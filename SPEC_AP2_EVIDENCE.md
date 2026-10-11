<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Roberto Locatelli -->

# ap2-evidence-pack — normative format v1.0 (2026-09-05), specification revision 1.4.1 (2026-10-11)

Status: **proposed format** (no standards body; normative for this repository), defined by the conformance vectors in
`spec/vectors/ap2/` (each `<name>.json` pack + `<name>.expected.json`
policy/verdict). Revision 1.4.0 adds §9, the CLOSED SCHEMA: every object this format defines
has an exhaustive key list, and a key outside it is a refusal with a reason — never silently
accepted; objects defined by a standard (JOSE header, JWT claims, JWK, `cnf`) follow that
standard's rule for the unknown (ignore) and the ignored names are REPORTED in the receipt.
The `evidence_format` string is unchanged: 1.4.0 narrows what is accepted, it does not change
the sealed content or the digest of a conformant pack (every 1.0–1.3 vector still verifies). An independent verifier claims conformance by reproducing every
vector's `normative` block from this text alone — see §7. Reference
implementation: `ap2_evidence.py` (informative, not normative).

Scope (what a valid pack proves): these exact SD-JWT artifacts, with the
snapshotted key material, verified when the pack was built; the pack was not
altered afterwards; and — only when an RFC 3161 token is bound to the pack AND the
relying party has verified the TSA's signature with the TSA's certificate (§3.2) — all
of it existed by that TSA's time. It does NOT prove the issuer authorised a key beyond
the declared provenance class, and never proves the truth of the recorded
transaction.

## 1. Container

One UTF-8 JSON object. A strict parser MUST reject duplicate object keys
(top-level or nested). Top-level fields (the list is EXHAUSTIVE — §9: any other top-level key is a refusal):

| Field | Req | Meaning |
|---|---|---|
| `evidence_format` | MUST | `"ap2-evidence-pack/1.0"` |
| `subject` | MUST | free-text description |
| `created_utc` | MUST | ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `artifacts` | MUST | array of artifact entries (§2), ≥ 1 — an empty pack is never `valid` |
| `bindings` | MUST | array of discovered hash bindings (§4) |
| `honest_scope` | MUST | the canonical scope statement of this format version, verbatim (below), part of the sealed content |

**The scope statement is fixed by the format version, not chosen by the pack.** For
`ap2-evidence-pack/1.0` it is the exact string whose SHA-256 over its UTF-8 bytes is
`a4b12a682847c23c4a136dd399c6aa0dfa69540a5c7200039d506e86ac31dfbf`
(the canonical text is `HONEST_SCOPE` in `ap2_evidence.py` and is reproduced in §8). A verifier
MUST refuse a pack whose `honest_scope` hashes to anything else, whatever else the pack contains —
after the §3.1 profile parse and the `evidence_format` check, which come first: the
receipt reprints the scope beside its verdict, so a pack that could rewrite it could make the
receipt state anything. 1.1.0: the sealed text was corrected three times before release, on five sentences — it claimed the
format never validates x5c chains (false since `--trust-anchor`); it said an RFC 3161 token attests
the TSA's clock without adding that this holds only once the relying party verifies the TSA
signature; it said nothing about a chain is sealed (the x5c bytes are, the validation result is not);
and it described the producer signature and `valid` as covering "the file", when both cover the
SEALED CONTENT — §3 excludes the digest, the anchor block and the signatures, so a removed time
anchor is caught only under `require_anchor`.
| `evidence_digest_sha256` | MUST | hex SHA-256 over the canonical content (§3) |
| `rfc3161_timestamp` | MUST at build (a verifier treats an absent block as `anchored: false`) | `{"anchored": false, "note"?: string}` or `{"anchored": true, "tsr_b64": <b64 DER TimeStampResp>, "tsa_url"?: string, "note"?: string}` — closed (§9.1); `tsa` is accepted as the 1.0–1.3 spelling of `tsa_url` |
| `producer_signatures` | MAY | hybrid producer-signature block (§5), closed (§9.1) |

## 2. Artifact entry

| Field | Meaning |
|---|---|
| `name` | non-empty string, unique within the pack (a non-string, empty or duplicate name is a refusal at verify; duplicate names MUST reject at build) |
| `sd_jwt_compact` | the EXACT compact serialization `issuer-JWT~disclosure*~[kb-jwt]` |
| `header` | the decoded protected header: an informative copy that MUST be canonically equal (§3) to the header the verifier decodes from `sd_jwt_compact` — a copy that says something else is that artifact's error (1.4.0) |
| `key` | `{"jwk": <P-256 JWK>, "provenance_class": <class>, ...}` — the snapshotted verification key |
| `resolved_claims` | payload with every `_sd` digest resolved to its disclosed claim |
| `kb_jwt` | KB-JWT verification record (§6, `kb_verified`): closed object (§9.1) whose `present` MUST equal whether `sd_jwt_compact` carries a KB-JWT |
| `verified_at_build` | build-time attestation: exactly `{"signature_ok": true, "disclosures_ok": true}` (§9.1 — a pack never carries a red light dressed as evidence) |

An artifact entry is a closed object (§9.1): a key outside this table is that artifact's error.

`provenance_class` is one of `x5c_header`, `jwk_header`, `supplied`, `jwks_fetched`
— the format records how the key was captured instead of pretending all captures
are equal. `jwk_header` is self-asserted. Any other value (or a non-string) is a
refusal of that artifact. A verifier MUST RECONCILE the two header-derived classes
with the header it just parsed: `jwk_header` requires the signed header to carry a
`jwk` equal to the snapshotted one on `kty`/`crv`/`x`/`y`; `x5c_header` requires a
signed `x5c` whose leaf public key equals it; `x5c` entries are strict base64 (RFC 4648,
no whitespace) like every other base64 value in the format. `supplied` and `jwks_fetched` are
capture-time assertions that cannot be checked offline — a verifier records them,
and a relying party MUST NOT read them as proof of anything beyond the declaration.
`provenance_class` is REQUIRED on every artifact: absent, `null`, a non-string or an
out-of-enum value is a refusal of that artifact (1.1.0 r7 — before, a missing class
silently CLEARED `self_asserted_only`).
1.1.0 r5: before this rule `provenance_class` was believed, so relabelling
`jwk_header` as `x5c_header` flipped `self_asserted_only` to false with no `x5c`
anywhere in the pack — the one field the honest scope sends the auditor to.

## 3. Canonicalisation and digest (NORMATIVE)

`evidence_digest_sha256 = HEX(SHA-256(canonical_bytes))` where `canonical_bytes`
is the JSON serialisation of the top-level object **excluding** the keys
`evidence_digest_sha256`, `rfc3161_timestamp`, `producer_signatures`, with:

- keys sorted lexicographically, recursively;
- separators `(",", ":")` — no insignificant whitespace;
- ASCII-escaped output (`ensure_ascii`): every non-ASCII character as `\uXXXX`.

(The file's own indentation/escaping on disk is NOT significant — the digest
is over the canonical form, not the file bytes.) The RFC 3161 token and the
producer signatures are outside the digest so they can be attached after
sealing without changing what they attest.

### 3.1 Acceptance profile of the evidence file (NORMATIVE, 1.1.0)

So that every implementation computes the same canonical bytes or refuses the same
file, a verifier MUST refuse (a receipt with `valid: false`, never a crash) an evidence
file that: is not a regular file (a FIFO, a device, a directory — decided on the opened file, which is opened without
blocking and never read past 64 MiB + 1 byte; added 25/09/2026, Unreleased); is not valid UTF-8 or starts with a BOM;
exceeds 64 MiB; is not a JSON object;
contains a duplicate object key at any depth; contains a number with a fraction or an
exponent (floats are not portable — use a string) or an integer outside ±(2^53−1);
contains `NaN`/`Infinity`; nests deeper than 512; contains an unpaired UTF-16 surrogate
escape (`\uD800`–`\uDFFF` not forming a pair). Non-ASCII text is in profile (the
canonical form escapes it). base64url segments of the SD-JWTs (RFC 7515 §2) and base64
values of the producer block (RFC 4648) are strict: alphabet only, no whitespace, no
padding on base64url, canonical trailing bits; a segment spelled any other way is a
verification failure of that artifact/signature, not a re-encoding.

The same profile applies to the JSON INSIDE the SD-JWTs — the issuer JWT header and
payload, every disclosure, the KB-JWT header and payload: strict UTF-8, no BOM, no
duplicate keys, no floats, bounded integers and depth, no lone surrogate. A signed
payload with a duplicate key (`{"amount":"1","amount":"999"}`) is refused, not read
"last wins" by one verifier and "first wins" by another. Shapes are imposed, and a key
present with `null` is NOT the same as an absent key: `_sd` absent or a list of strings;
`_sd_alg` absent or exactly `"sha-256"`; an array placeholder `{"...": d}` with `d` a
string; a disclosed claim name a string; `cnf` absent or an object, `cnf.jwk` absent or an
object (an empty object is a holder key that fails to parse, not an unknown holder);
JWK `x`/`y` exactly 32 bytes each (RFC 7518 §6.2.1); `key.provenance_class` in the §2 enum;
`rfc3161_timestamp.anchored` a boolean; `producer_signatures.signatures[].sig_alg` a
string (any other type is a FAIL entry). A violation inside an artifact is that
artifact's error (the pack is not `valid`); a violation of a top-level shape is a refusal.

### 3.2 RFC 3161 token check (NORMATIVE when `anchored`)

`rfc3161.verified` is `true` iff the token parses as a TimeStampResp, its status is
granted (0 or 1) and the TSTInfo `messageImprint` equals the recomputed
`evidence_digest_sha256`; `false` otherwise (a claimed-but-failing anchor rejects the
pack). `verified` states BINDING, not TSA authenticity: a self-forged TimeStampResp
with the right imprint satisfies it. TSA authenticity is `rfc3161.tsa_verified`: the
reference verifies the token's signature and chain with `openssl ts -verify -CAfile`
when the relying party passes `--tsa-cert <PEM>`; the JS verifier cannot (no openssl)
and reports `null`. Under `--require-anchor --tsa-cert`, `tsa_verified` must be `true`
for `policy_ok` — so the JS verifier never passes that policy (declared divergence).
`tsr_b64` is strict base64 (RFC 4648) like the producer block. Both verifiers report the
TSTInfo `genTime` as `rfc3161.gen_time` (GeneralizedTime, UTC, or `null` when absent or
malformed); the reference validates the TSA chain **at that time** (`openssl ts -verify -attime`)
when the token carries a well-formed `genTime`, so a TSA certificate that expired after
issuing the token does not turn `tsa_verified` false years later; with no usable `genTime`
the chain is validated at the current time instead (an expired certificate then fails).
Revocation is not checked (declared).

## 4. Bindings (NORMATIVE)

A binding records that one artifact commits to another **by value**: artifact
`A` binds `B` iff some string value anywhere in `A`'s resolved claims equals
`HEX(SHA-256(B.sd_jwt_compact))` (lowercase hex) or `BASE64URL(SHA-256(B.sd_jwt_compact))`
(no padding) — the hash of the exact compact serialization (the primary quantity, not a
proxy field). Each binding is the object
`{"in": A.name, "claim": <path>, "commits_to": B.name, "encoding": "hex" | "b64url"}`
where `<path>` locates the matching value in `A`'s resolved claims: object keys joined
with `.`, array positions as `[i]`, no leading separator (`cart.items[0].ref`, `intent_hash`).
An artifact never binds itself. The recorded `bindings` is a **set** (a JSON list whose
order carries no meaning): a verifier MUST recompute every binding and compare the two lists
as multisets of canonical entries (each entry in the §3 canonical form, sorted); any
difference fails the pack. 1.1.0 r4: an ordered comparison split the verdict between two
conformant verifiers on a pack the reference built (JavaScript enumerates array-index keys
such as `"0"` before the other keys, whatever the insertion order).

## 5. Producer signatures (NORMATIVE when present)

```json
{"scheme": "hybrid" | "classical-only",
 "over": "evidence_digest_sha256",
 "signatures": [{"sig_alg": "ed25519" | "ecdsa-p256" | "ml-dsa-65",
                 "public_key_b64": "<base64 raw key>",
                 "signature_b64": "<base64 signature>",
                 "post_quantum": bool}]}
```

Each signature is over the **ASCII bytes of the lowercase hex**
`evidence_digest_sha256` as **recomputed** by the verifier (never the declared
value — recompute-from-content is the rule). Key/signature encodings: `ed25519`
raw 32-byte key / 64-byte signature; `ecdsa-p256` X9.62 uncompressed point
(65 bytes, leading `0x04`) / raw `r||s` (64 bytes), SHA-256; `ml-dsa-65`
FIPS 204 **final** ML-DSA-65, external/pure interface, **empty context** —
raw 1952-byte key / ≈3309-byte signature. (The ML-DSA-65 path is checked
against the NIST ACVP sigVer subset in `pqcrypto/vectors/`, the same vectors
elara-mesh runs — one oracle, both stacks.)

Verification is fail-closed: any present-but-invalid signature makes the block
(and the pack) invalid; an unknown `sig_alg` or a missing PQ backend is a
verification GAP (skip), and a block with any gap or zero passing signatures is
never `ok`. 1.4.0 (§9.1): the block is a closed object — exactly `scheme` (one of the two
values above), `over` (exactly `"evidence_digest_sha256"`) and `signatures` (a list); any other
key, a missing key or a wrong type is a refusal of the file. Each entry is a closed object —
exactly `sig_alg` (string), `public_key_b64` (string), `signature_b64` (string),
`post_quantum` (boolean) — and an entry with any other key, a missing key, a wrong type, or
a `post_quantum` that contradicts `sig_alg` (`true` iff `sig_alg` is `ml-dsa-65`) is a FAIL
entry (the block is not `ok`). `scheme` is reconciled with the entries: `hybrid` requires at
least one entry with a classical `sig_alg` (`ed25519`/`ecdsa-p256`) AND at least one `ml-dsa-65`
entry; `classical-only` requires no `ml-dsa-65` entry; a block whose scheme does not match its
entries is not `ok` (measured 2026-10-10 on 1.3.0: `scheme: "hybrid"` over a lone Ed25519
signature was `producer_ok: true`). **Pinning:** an embedded key proves internal consistency, never
authenticity. When the relying party supplies a pinned trust set
(`{sig_alg: [public_key_b64, ...]}`), `producer_trusted` is `true` only if every
present signature's key is pinned; a valid-but-unpinned signature MUST reject
the pack even with no policy flags set. Without a pinned set `producer_trusted`
is `null` and the pack MUST NOT be treated as authentic. `pq_protected` is true
only on a valid ML-DSA-65 signature whose key is pinned (or no pin set given).

## 6. Verification algorithm and verdict (NORMATIVE)

Inputs: the pack file, an optional pinned producer trust set, and three policy
flags: `require_producer`, `require_pq`, `require_anchor`.

1. Parse under the profile (§3.1; duplicate keys reject). Refuse unless `evidence_format` is
   exactly `"ap2-evidence-pack/1.0"`, unless `honest_scope` matches the canonical scope of that version
   by SHA-256 (§1, §8), and unless `subject`, `created_utc`, `honest_scope` are strings
   (§1 MUSTs — 1.1.0 r5: a `…/2.0` pack used to be verified under the 1.0 rules, and a pack
   with no `honest_scope` produced a receipt with `honest_scope: null`). Recompute the digest (§3) → `digest_ok`.
2. For EVERY artifact: parse `sd_jwt_compact` (its JSON under the §3.1 profile); apply the JOSE rules of §9.2 to the
   protected header (`crit` → RFC 7515 §4.1.11, unknown parameters ignored and reported); verify the ES256 signature with
   the snapshotted JWK over the JWS signing input; resolve disclosures
   fail-closed (unmatched, duplicate, or malformed disclosure → reject — for an UNMATCHED
   disclosure this is RFC 9901 §7.1 step 5 verbatim, "the SD-JWT MUST be rejected"; for an `_sd`
   that is not an array of digest strings and for an array placeholder whose value is not a digest
   string, §4.2.4.1 and §4.2.4.2 address the MUST to the Issuer and §7.1 gives the verifier no rejection
   step of its own — §7.1 step 3.b collects only well-formed shapes and step 3.e removes every `_sd`
   key — so refusing is this format's stricter choice, measured 23/09/2026 against the `sd-jwt` reference
   implementation, which drops a malformed `_sd` (`{}`, `[1]`), keeps `{"...": [1]}` as an ordinary array
   element of its verified payload, and refuses `_sd: null` as this format does); the
   canonical form of the resolved claims MUST equal the recorded
   `resolved_claims`; re-verify the KB-JWT when the issuer payload carries
   `cnf.jwk` (ES256 over `issuer-JWT~disclosure*~`; without `cnf.jwk` a present
   KB-JWT is recorded as unverifiable, never treated as verified-green, and
   never fails the pack by itself — but a KB-JWT that verifies FALSE does, and a §3.1 profile
   violation in any of its three segments is that artifact's failure whether or not the holder
   key is known: the strict segment rule does not depend on being able to check the signature;
   1.4.0, likewise independent of the holder key: the KB-JWT header MUST carry `typ: "kb+jwt"`
   and `alg: "ES256"`, and its payload MUST carry `iat` (integer), `aud` (string), `nonce`
   (string) and `sd_hash` (string) — RFC 9901 §4.3 REQUIRED and §7.3 step 5.d; a KB-JWT missing
   any of them is that artifact's error, whatever `cnf` says). A verifier records the
   KB-JWT `aud`/`nonce`/`iat` as present-but-not-validated, as the sealed scope states: their expected
   values are transaction context an offline verifier cannot know.
3. Recompute bindings (§4), compare → `bindings_ok`.
4. If `rfc3161_timestamp.anchored`: check the token's binding (§3.2) — status
   granted AND messageImprint == the **recomputed** digest → `rfc3161_verified`
   true/false (this needs no tooling: a DER walk). The TSA's signature and chain are
   verified only against a relying-party-supplied TSA certificate (`tsa_verified`
   true/false; `null` = not requested or no tooling, never a pass). A claimed-but-failing token fails
   the pack (tamper, not a warning).
5. Verify the producer block per §5 → `producer_ok`, `producer_trusted`,
   `pq_protected`.
6. Policy: `policy_ok` is false if `require_producer` and no valid producer
   block; if `require_pq` and not (`pq_protected` and `producer_trusted` true);
   if `require_anchor` and `rfc3161_verified` is not true (missing, unverifiable
   and failing all reject — "claimed" never upgrades to "proven").
   The receipt also carries `mldsa_backend` (informative): whether that verifier can check
   ML-DSA-65 at all. Without the backend a post-quantum producer signature is SKIP — never a pass —
   and the reader should not have to infer why.

7. `self_asserted_only` is FAIL-CLOSED: `true` if ANY artifact's key is still self-asserted — it is
   cleared only when EVERY artifact's key was reconciled to an
   `x5c` chain that VALIDATES to a trust anchor the relying party supplies (`--trust-anchor`,
   reported in `chain_verified`: `true`/`false`, or `null` when no anchor was given, the verifier
   cannot validate chains, or the check was not measurable — openssl absent). The chain is validated
   at the `genTime` of a TSA-VERIFIED RFC 3161 token when the pack carries one, and at the current
   time otherwise (1.1.0 r9: a signing certificate lives 1-3 years, so at today's clock a leaf valid
   2020-2021 could never clear the flag — the one mechanism that clears it was unusable in the very
   scenario this format exists for). A cleared flag states that **a CA under YOUR anchor certified
   this key at that time** — never that the key belongs to the mandate's issuer: that binding is
   outside what an offline verifier can establish. For this reason a verifier MUST report the
   validated leaf's identity (`x5c_leaf`: subject and issuer DN, serial, validity, SHA-256 of the
   DER), so an auditor can see whether it says `CN=the-bank` or `CN=someone-else`. Offline and without an anchor, every class is
   self-asserted — `jwk_header`, `x5c_header`, `supplied`, `jwks_fetched` alike — and so is
   every refusal receipt. 1.1.0 r7 had made `supplied`/`jwks_fetched`/absent fail closed but
   still cleared the flag when the leaf's issuer DN differed from its subject DN; r8 measured
   that a leaf SELF-SIGNED with its own key, merely declaring `CN=DigiCert Global Root CA` as
   its issuer, cleared it in both verifiers while the pack stayed `valid`. Two DN strings the
   forger writes are not an issuance: only a validated chain is.
   (flag, not a failure: the verdict names the weakness instead of hiding it).
8. `valid` = artifacts non-empty AND `digest_ok` AND every artifact verifies
   AND `bindings_ok` AND `rfc3161_verified` is not false AND producer block ok
   (when present) and trusted (when pinned) AND `policy_ok`.

The eleven **normative verdict fields** a conformant verifier must reproduce:
`valid`, `digest_ok`, `bindings_ok`, `policy_ok`, `pq_protected`,
`producer_present`, `producer_ok`, `producer_trusted`, `rfc3161_claimed`,
`rfc3161_verified`, `self_asserted_only` (tri-state fields use
true/false/null).

## 7. Conformance (normative)

Run every `spec/vectors/ap2/<name>.json` under the policy in
`<name>.expected.json` and reproduce the `normative` block exactly
(`run_ap2_conformance.py` does this for the reference; exit 0 = conformant).
The set contains five ACCEPTs (`valid_signed` — positive control — and `anchor_valid`,
a real RFC 3161 token from a probe TSA whose certificate ships beside it; since 1.4.0 also
`header_param_ignored`, a signed header with an unregistered parameter that RFC 7515 §4 says to
ignore, `kb_jwt_valid`, a holder-bound mandate whose KB-JWT verifies, and `key_jwk_member_ignored`,
a snapshotted JWK with an unregistered member) and twelve
REJECTs (stripped-signature downgrade, valid-but-unpinned producer, digest mismatch,
anchor required-but-missing, anchor claimed-but-invalid, a real token for another digest; since
1.4.0: an unknown key at the top level, inside `rfc3161_timestamp`, inside an artifact entry and
inside a producer-signature entry, a `crit` header parameter the verifier does not understand, and
a KB-JWT without the `kb+jwt` type). A vector
whose `requires` tooling is absent is reported SKIP, honestly unverified. When an
`<name>.expected.json` carries a `report` block, a conformant verifier also reproduces it: today it
holds `ignored`, the per-artifact list of names ignored under a standard's rule (§9.2), mapped
onto the reference receipt's `artifacts[i].ignored`.
Independent implementations: open a PR to be listed in the README conformance table.


## 8. Canonical scope statement for `ap2-evidence-pack/1.0` (NORMATIVE)

SHA-256 of the UTF-8 bytes of the decoded JSON string value (not of the escaped bytes on disk):
`a4b12a682847c23c4a136dd399c6aa0dfa69540a5c7200039d506e86ac31dfbf`

```text
Proves: these exact SD-JWT artifacts, with the snapshotted key material (see each key's provenance_class), verified at build time; the RFC 3161 token (if present) binds this digest to a TimeStampResp, and attests the TSA's clock only once the relying party has verified the TSA's signature (--tsa-cert): a self-issued token satisfies the binding alone. Does NOT prove the issuer authorised the key beyond what the provenance class states, does NOT confer eIDAS qualified-archive legal presumption, and does NOT by itself validate x5c chains to a trust anchor — that is an act of the relying party at verification time, with `--trust-anchor`, reported in `chain_verified` and in each artifact's `x5c_leaf` (SPEC §6.7): the x5c bytes are sealed inside the signed header, the validation RESULT never is — and never proves the truth of the recorded transaction itself. When a producer signature is present, it protects the SEALED CONTENT (the file minus the digest, the anchor block and the signatures themselves - so a removed or downgraded time anchor is caught only under a require-anchor policy), and authenticity ONLY for a relying party that has PINNED the producer public key out of band (an embedded key alone proves consistency, not authenticity), across the retention window (hybrid: a classical signature + FIPS-204 ML-DSA-65, surviving the quantum transition per NIST IR 8547); it does NOT retro-protect the underlying ES256 mandate signature - for the existed-before-a-quantum-adversary claim you still need a trusted time anchor (RFC 3161 / RFC 4998 renewal). 'valid' means each artifact verifies and the SEALED CONTENT is intact — NOT that the file as a whole is unaltered (the anchor block lies outside the digest), NOT that the mandates form a bound chain (read `bindings`) nor that self-asserted keys prove issuer identity (read `provenance_classes`/`self_asserted_only`). KB-JWT holder binding is verified when the issuer payload carries cnf.jwk; without cnf.jwk it is recorded as present-but-unverifiable, never painted green. KB-JWT aud/nonce/iat are RECORDED for the auditor, not validated — their expected values are transaction context this tool cannot know offline.
```

## 9. Closed schema (NORMATIVE, 1.4.0)

A verifier of this format is a precision instrument: whoever reads its `valid` trusts it. On
2026-10-10 the 1.3.0 verifiers were measured accepting, with `valid: true` and no trace in the
receipt, a key they had never heard of inside `rfc3161_timestamp`, inside `producer_signatures`
and inside every `signatures[i]` entry (an unknown top-level key was caught only because the
digest covers it — a pack SEALED with one verified). Nothing in this text said what to do with
the unknown, so both implementations did the same thing: nothing. This section closes every
object the format defines and states, for every object a standard defines, which rule of that
standard applies. The principle: **a key the verifier does not understand is never silent** —
in a closed object it is a refusal with a reason; in a standard's object it is ignored as the
standard requires AND reported.

### 9.1 Objects of this format — closed, unknown = refusal with a reason

Every key of every object below is listed with its type; a key not in the list, a listed key
of another type, or a listed MUST key that is absent, has the outcome in the last column.
"Refusal" is a receipt with `valid: false` and `refused` naming the object and the key
(`<object>: unknown key "x" (SPEC §9.1)`; with several unknown keys, the first by Unicode code point —
1.4.1); "artifact error" is `artifacts[i].error` for that artifact (the pack is not `valid`); "FAIL
entry" is `status: FAIL` for that producer signature (the block is not `ok`, the pack is not
`valid`), whose `note` names the unknown keys and the missing keys, each list sorted by code point
(1.4.1: in 1.4.0 the note did not name them; an entry that is not an object has no keys and no note). Keys are compared exactly (case-sensitive,
after JSON unescaping — `"subj\u0065ct"` IS `subject`).

| Object | Keys (type) | Unknown / wrong type / missing MUST |
|---|---|---|
| top level | `evidence_format` (string, MUST), `subject` (string, MUST), `created_utc` (string, MUST), `artifacts` (list, MUST), `bindings` (list; absent reads as `[]`), `honest_scope` (string, MUST), `evidence_digest_sha256` (string, MUST), `rfc3161_timestamp` (object), `producer_signatures` (object) | refusal |
| `rfc3161_timestamp` | `anchored` (boolean, MUST), `tsr_b64` (string; when `anchored` is true and it is ABSENT the §6.4 rule applies: `rfc3161_verified: false`, not a refusal), `tsa_url` (string), `tsa` (string, 1.0–1.3 spelling), `note` (string) | refusal |
| `producer_signatures` | `scheme` (`"hybrid"` or `"classical-only"`, MUST), `over` (`"evidence_digest_sha256"`, MUST), `signatures` (list, MUST) | refusal |
| `producer_signatures.signatures[i]` | `sig_alg` (string, MUST), `public_key_b64` (string, MUST), `signature_b64` (string, MUST), `post_quantum` (boolean, MUST, `true` iff `sig_alg == "ml-dsa-65"`); an entry that is not an object | FAIL entry |
| `bindings[i]` | `in` (string), `claim` (string), `commits_to` (string), `encoding` (`"hex"` or `"b64url"`) — all four MUST; an entry that is not an object | refusal |
| `artifacts[i]` | `name` (non-empty string, MUST), `sd_jwt_compact` (string, MUST), `header` (object, MUST, canonically equal to the decoded protected header), `key` (object, MUST), `resolved_claims` (MUST, canonically equal to the recomputed claims), `kb_jwt` (object, MUST), `verified_at_build` (object, MUST) | artifact error (a `name` that is not a non-empty string stays a refusal, §2) |
| `artifacts[i].key` | `jwk` (object, MUST), `provenance_class` (string in the §2 enum, MUST), `note` (string), `x5c_chain_sha256` (list of strings), `jwks_url` (string), `jwks_sha256` (string), `fetched_utc` (string) | artifact error |
| `artifacts[i].kb_jwt` | `present` (boolean, MUST, equal to "the compact serialization ends with a KB-JWT"), `verified` (boolean or null), `signature_ok` (boolean), `sd_hash_ok` (boolean), `note` (string or null), `claims_recorded_not_validated` (object); each of `verified`, `signature_ok`, `sd_hash_ok`, `claims_recorded_not_validated` that is present MUST be canonically equal (§3) to the value the verifier recomputes from the KB-JWT (§6) — a recorded value the KB-JWT does not support, or a key the recomputation does not produce, is that artifact's error, like the `header` copy (added on review, 2026-10-11) | artifact error |
| `artifacts[i].verified_at_build` | `signature_ok` (exactly `true`, MUST), `disclosures_ok` (exactly `true`, MUST) | artifact error |

`resolved_claims` and `bindings` are closed by construction (they MUST equal a recomputation);
the two rows above make the reason explicit instead of leaving a bare `claims_match: false`.

### 9.2 Objects defined by a standard — the standard's rule, and a report

| Object | Standard and its rule for the unknown | What this format does |
|---|---|---|
| issuer JWT protected header | RFC 7515 §4: "all Header Parameters not defined by this specification MUST be ignored when not understood", unless listed in `crit`; §4.1.11: a `crit` naming an extension the recipient does not understand makes the JWS INVALID; `crit` MUST NOT be `[]`, MUST NOT list registered names, duplicates, or names absent from the header | names this format understands: `alg`, `jku`, `jwk`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `typ`, `cty`, `crit` (those defined by RFC 7515 §4.1 and RFC 7519 §5; other names of the IANA JOSE registry are not understood here, so they are ignored and reported like any other). This format understands NO extension: a `crit` that is present and well-formed is therefore always that artifact's error, and a malformed `crit` (not a list of strings, empty, duplicate, registered or absent names) is one too. Every other unregistered name is ignored and reported in `artifacts[i].ignored.header` |
| `jwk` in the header, `key.jwk`, `cnf.jwk` | RFC 7517 §4: "Additional members can be present in the JWK; if not understood by implementations encountering them, they MUST be ignored" | registered members: `kty`, `use`, `key_ops`, `alg`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256` (RFC 7517 §4) and `crv`, `x`, `y`, `d` (RFC 7518 §6.2). Others ignored and reported in `ignored.header_jwk` / `ignored.key_jwk` / `ignored.cnf_jwk` |
| issuer JWT payload | RFC 7519 §4: "all claims that are not understood by implementations MUST be ignored" | every claim is RECORDED: the resolved payload is the pack's content and `resolved_claims` lists it in full, so nothing is reported twice; the SD-JWT shapes of RFC 9901 (`_sd`, `_sd_alg`, `...`) are imposed as in §3.1 |
| `cnf` | RFC 7800 §3.1: "all confirmation members that are not understood by implementations MUST be ignored" | understood: `jwk`, `jwe`, `jku`, `kid` (the members RFC 7800 defines, §3.2–§3.5; other confirmation methods of the IANA registry, e.g. `x5t#S256` of RFC 8705 or `jkt` of RFC 9449, are not understood here). Others ignored and reported in `ignored.cnf` |
| KB-JWT header | RFC 7515 as above; RFC 9901 §4.3: `typ` REQUIRED, MUST be `kb+jwt`; `alg` REQUIRED | `typ` not exactly `"kb+jwt"` is that artifact's error (RFC 9901 §4.3; RFC 9901 §7.3 step 5.d asks a Verifier to check it when Key Binding is required — this format checks every KB-JWT it carries, whether or not the holder key is known); `alg` not `"ES256"` is that artifact's error by this format's profile (§6 step 2: `alg: "ES256"`; RFC 9901 §4.3 only forbids `none`); `crit` as above; other unregistered names ignored and reported in `ignored.kb_jwt_header` |
| KB-JWT payload | RFC 7519 §4 (ignore); RFC 9901 §4.3: `iat`, `aud`, `nonce`, `sd_hash` REQUIRED | the four REQUIRED claims must be present with their RFC 9901 types (`iat` integer, the others strings) — absence or wrong type is that artifact's error; their VALUES are recorded, not validated (sealed scope). Registered names: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` (RFC 7519 §4.1), `nonce`, `sd_hash` (RFC 9901). Others ignored and reported in `ignored.kb_jwt_claims` |

`artifacts[i].ignored` is an object present on every artifact that verified; each slot above is
a list of the ignored names sorted by code point and appears only when non-empty, so an
artifact with nothing ignored carries `ignored: {}`. The report is informative for the verdict
(it never changes `valid`) and normative for conformance when a vector's `expected.json` carries
it (§7): two conformant verifiers report the same names.

### 9.3 Generative proof

`verifiers/schema_mutants.py` derives, from every conformance vector and from freshly signed
packs, mutations at every level of every object listed in §9.1 and §9.2 — unknown keys (ASCII,
Unicode, `__proto__`, `constructor`, empty, case-variants of known keys, escaped spellings),
every known key replaced by each hostile type, duplicate keys, key-order permutations, escaped
spellings of known keys, boundary numbers and out-of-grammar files — and computes each
mutation's EXPECTED class from the two tables above, not from a verifier. Both verifiers must
give that class and must agree with each other on every compared field. Run against the 1.3.0
verifiers the same corpus is the positive control: measured 2026-10-10, of 12 818 mutations (full
corpus) 8 186 passed SILENTLY on 1.3.0 in BOTH verifiers — `valid` unchanged, nothing in the receipt
— and the two verifiers agreed with each other on every one of them (0 differential disagreements):
agreement between two implementations by one author is not correctness. On 1.4.0: 12 818/12 818
met their class, 0 disagreements (details in CHANGELOG 1.4.0).
