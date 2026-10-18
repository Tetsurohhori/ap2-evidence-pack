<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Roberto Locatelli -->

# ap2-evidence-pack — normative format v1.0 (2026-09-05), specification revision 1.6.0 (2026-10-18)

Status: **proposed format** (no standards body; normative for this repository), defined by the conformance vectors in
`spec/vectors/ap2/` (each `<name>.json` pack + `<name>.expected.json`
policy/verdict). Revision 1.6.0 adds to every receipt one closed field per question a relying party asks (§6.9):
`admission` (was the pack evaluated at all, and if not, `refusal_class`), `states` (one state per subject — sealed content,
holder binding, time anchor, producer signature, issuer identity — with its reasons) and `policy` (which requirement of the
relying party is not met); it gives exit 74 a complete receipt when a check could not be run here (§6.10), makes an unknown
key inside an artifact entry or a producer-signature entry a refusal like every other object of §9.1 (NOT additive: the
twelve fields of two vectors change, §9.1), and adds §10, an informative reading of the receipt for a relying party. The
twelve fields of §6 keep their meaning. Revision 1.5.4 writes down two rules both verifiers already followed and the text did not state — the
order of the checks of an `anchors` entry (§3.3) and `bindings_ok` when an artifact fails (§6 step 3) —; changes what
§5 reports on a producer block that is not `ok` (`producer_trusted`, `pq_protected`, and so `policy_ok` under
`require_pq`: field values of packs that were already not `valid`, whose `valid` does not change); and lets an expected
file declare the cryptographic backend its verdict needs (`requires_backend`, §7). Revision 1.5.0 adds §3.3: `anchors`, a closed list of additional time anchors outside the
digest, so one pack can carry more than one commitment to the same digest (a pack with `anchors` needs a 1.5.0 verifier:
1.4.x refuses the unknown top-level key, as §9 requires). Revision 1.4.0 adds §9, the CLOSED SCHEMA: every object this format defines
has an exhaustive key list, and a key outside it is a refusal with a reason — never silently
accepted; objects defined by a standard (JOSE header, JWT claims, JWK, `cnf`) follow that
standard's rule for the unknown (ignore) and the ignored names are REPORTED in the receipt.
The `evidence_format` string is unchanged: 1.4.0 narrows what is accepted, it does not change
the sealed content or the digest of a conformant pack (every 1.1–1.3 vector still verifies; the 1.0.x vectors stopped
verifying in 1.1.0, when `honest_scope` was pinned). An independent verifier claims conformance by reproducing every
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
| `anchors` | MAY (1.5.0) | non-empty list of additional time anchors (§3.3), closed (§9.1) |

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
`evidence_digest_sha256`, `rfc3161_timestamp`, `producer_signatures`, `anchors` (1.5.0; no 1.0–1.4 pack carries it, so
no digest of an earlier pack changes), with:

- keys sorted lexicographically, recursively;
- separators `(",", ":")` — no insignificant whitespace;
- ASCII-escaped output (`ensure_ascii`): every non-ASCII character as `\uXXXX`.

(The file's own indentation/escaping on disk is NOT significant — the digest
is over the canonical form, not the file bytes.) The time anchors and the
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
and reports `null` (1.6.0: and states `time_anchor` `not_evaluated` with `instrument_failure`, §6.9). Under `--require-anchor --tsa-cert`, `tsa_verified` must be `true`
for `policy_ok` — so the JS verifier never passes that policy (declared divergence).
`tsr_b64` is strict base64 (RFC 4648) like the producer block. Both verifiers report the
TSTInfo `genTime` as `rfc3161.gen_time` (GeneralizedTime, UTC, or `null` when absent or
malformed); the reference validates the TSA chain **at that time** (`openssl ts -verify -attime`)
when the token carries a well-formed `genTime`, so a TSA certificate that expired after
issuing the token does not turn `tsa_verified` false years later; with no usable `genTime`
the chain is validated at the current time instead (an expired certificate then fails).
Revocation is not checked (declared).

### 3.3 Additional time anchors: `anchors` (NORMATIVE, 1.5.0)

One RFC 3161 token depends on one TSA key, which ages; mechanisms that fail in different ways (another TSA; in a later
revision another kind of commitment, such as an RFC 4998 renewal) can only add protection if the pack can carry more
than one. Before
1.5.0 it could not: a second token as a new top-level key changes the digest, and inside `rfc3161_timestamp` it is a
refusal (§9.1). `anchors` is the place for them.

- `anchors` is OPTIONAL; when present it is a non-empty list (an empty list, or a non-list, is a refusal).
- Each entry is a closed object (§9.1) with `mechanism` (string, MUST). This revision defines one mechanism:
  `"rfc3161"`, with `tsr_b64` (string, MUST: strict base64 of a DER TimeStampResp), `tsa_url` (string) and `note`
  (string). A `mechanism` this revision does not define is a refusal naming it — never skipped: a verifier that cannot
  check an anchor must not let the pack look as if it had one. A new mechanism is a new revision of this text.
  Order (1.5.4): each entry is checked in list order — not an object, then `mechanism` missing, then not a string, then
  not defined here (the refusal naming it), and only then the §9.1 scan of that mechanism's keys. The keys of an entry
  are listed PER MECHANISM, so for an undefined mechanism there is no list to scan against: an entry with an undefined
  mechanism and a key unknown to `rfc3161` is refused for its mechanism, not for the key (vector
  `anchors_unknown_mechanism`).
- Every `rfc3161` entry is checked exactly as §3.2 checks the `rfc3161_timestamp` token, against the RECOMPUTED digest:
  `verified`, `granted`, `imprint_ok`, `gen_time`, `tsa_verified` (`--tsa-cert` takes a PEM file that may hold the
  certificates of several TSAs). A claimed entry whose binding fails rejects the pack, like a failing
  `rfc3161_timestamp` token: an anchor is never ignored because another one verifies. An entry whose TSA signature does
  not verify under `--tsa-cert` is not counted (below): it does not reject the pack by itself, only through a policy it
  then fails to meet.
- Every `rfc3161` entry commits to the pack's digest, not to the anchors already present: a token added later proves
  existence from its own time only. It is not a renewal in the sense of RFC 4998 (which re-stamps the earlier evidence).
- The receipt lists one result per entry in `anchors` (same order), each carrying `mechanism`.
- **Counting.** An anchor COUNTS when its binding is verified and, when the relying party passed `--tsa-cert`, its TSA
  signature is verified too. `anchors_verified` (normative, an integer) is the number of DISTINCT counting anchors
  among the `rfc3161_timestamp` token and the `anchors` entries; two entries are the same anchor when the TSTInfo they
  carry — the eContent the TSA signed (RFC 3161 §2.4.2) — is byte-for-byte equal: a copied token is one anchor however it
  is re-wrapped (bytes after the TimeStampResp, a status string, a longer length encoding leave the signature valid).
  Distinct tokens from the same TSA share that TSA's key: this
  count does not establish that they fail independently — a relying party that needs that reads `gen_time` and the TSA
  of each entry (declared).
- `rfc3161_claimed` is true when the `rfc3161_timestamp` block is anchored OR `anchors` holds an `rfc3161` entry;
  `rfc3161_verified` is `null` when nothing is claimed, `false` when ANY claimed RFC 3161 token fails its binding, and
  `true` otherwise. On a pack without `anchors` both fields are what 1.4.x reports.
- **Policy.** `min_anchors` (a verifier input, integer ≥ 1; any other value is an error of the caller, never a weaker
  policy): `policy_ok` is false when `anchors_verified` < `min_anchors`.
  `require_anchor` is `min_anchors = 1` when no larger value is given. How many anchors a relying party requires is its
  decision; the pack never states it.
- The time at which §6 step 7 validates x5c chains is the EARLIEST `gen_time` among the counting anchors that are
  TSA-verified (the strongest existence bound the pack proves); with none, the current time, as before.

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
1.5.4: both are statements about a block that verified. When the block is not `ok`, `producer_trusted` is `null`
(pinned set given or not) and `pq_protected` is `false` (a valid pinned ML-DSA-65 entry beside a failing entry
included); so `require_pq` (§6 step 6) is never met by a block that is not `ok`. Such a pack is not `valid` (§6 step
8, unchanged): 1.5.3 (measured on `f03abbc`) reported `producer_trusted` `true` when every key was pinned and the block
failed through an entry or its `scheme`, `false` when the block held a SKIP entry or no entry, `pq_protected` `true` on
any block holding a valid ML-DSA-65 entry whose key was pinned (or no pinned set), and so, under `require_pq`, `policy_ok`
`true` where both were `true` (vectors
`producer_mldsa_fails_pinned`,
`producer_classical_fails_pinned`, `producer_classical_fails_unpinned`).

## 6. Verification algorithm and verdict (NORMATIVE)

Inputs: the pack file, an optional pinned producer trust set, three policy
flags: `require_producer`, `require_pq`, `require_anchor`, and `min_anchors` (1.5.0, §3.3).

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
   `cnf.jwk` (its ES256 signature under `cnf.jwk`, AND its `sd_hash` equal to BASE64URL(SHA-256) of
   `issuer-JWT~disclosure*~` — RFC 9901 §7.3 step 5.c and 5.g; a KB-JWT that fails either verifies FALSE; without `cnf.jwk` a present
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
3. Recompute bindings (§4), compare → `bindings_ok`. 1.5.4: `bindings_ok` is `false` when ANY artifact fails step 2
   (an artifact error or a refusal), whatever `bindings` holds, `[]` included — the recomputation needs every
   artifact's verified claims, and an artifact that did not verify has none (vectors `header_crit_unknown`,
   `kb_jwt_typ_missing`: `bindings: []`, `bindings_ok: false`).
4. If `rfc3161_timestamp.anchored`: check the token's binding (§3.2) — status
   granted AND messageImprint == the **recomputed** digest → `rfc3161_verified`
   true/false (this needs no tooling: a DER walk). The TSA's signature and chain are
   verified only against a relying-party-supplied TSA certificate (`tsa_verified`
   true/false; `null` = not requested or no tooling, never a pass). A claimed token whose binding fails
   fails the pack (tamper, not a warning); one whose TSA signature does not verify is not counted (§3.3). 1.5.0: the same check for every `anchors` entry, and `anchors_verified` (§3.3).
5. Verify the producer block per §5 → `producer_ok`, `producer_trusted`,
   `pq_protected`.
6. Policy: `policy_ok` is false if `require_producer` and no valid producer
   block; if `require_pq` and not (`pq_protected` and `producer_trusted` true);
   if `anchors_verified` < `min_anchors` (§3.3; `require_anchor` alone is `min_anchors = 1`, so missing,
   unverifiable and failing anchors all reject — "claimed" never upgrades to "proven").
   The receipt also carries `mldsa_backend` (informative): whether that verifier can check
   ML-DSA-65 at all. Without the backend a post-quantum producer signature is SKIP — never a pass —
   and the reader should not have to infer why.

7. `self_asserted_only` is FAIL-CLOSED: `true` if ANY artifact's key is still self-asserted — it is
   cleared only when EVERY artifact's key was reconciled to an
   `x5c` chain that VALIDATES to a trust anchor the relying party supplies (`--trust-anchor`,
   reported in `chain_verified`: `true`/`false`, or `null` when no anchor was given, the verifier
   cannot validate chains, or the check was not measurable — openssl absent). 1.6.0: a verifier that cannot validate
   chains refuses `--trust-anchor` as a usage error instead of accepting a flag that does nothing (the JS verifier). The chain is validated
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

The twelve **normative verdict fields** a conformant verifier must reproduce:
`valid`, `digest_ok`, `bindings_ok`, `policy_ok`, `pq_protected`,
`producer_present`, `producer_ok`, `producer_trusted`, `rfc3161_claimed`,
`rfc3161_verified`, `self_asserted_only` (tri-state fields use
true/false/null), and since 1.5.0 `anchors_verified` (an integer, §3.3).

### 6.9 The receipt: admission, states, policy (NORMATIVE, 1.6.0)

The twelve fields above keep their meaning (§9.1 changes the values of two vectors, not a meaning). Since 1.6.0 every
receipt of both verifiers also carries:

- `admission`: `"admitted"` or `"refused"`. Every refusal of this text (§1, §3.1, §3.3, §6 step 1, §9.1) is `"refused"`
  and carries `refusal_class`, one of:
  - `format_unsupported` — the pack names a revision or a mechanism this verifier does not implement: an
    `evidence_format` other than `"ap2-evidence-pack/1.0"` (also absent or not a string), an `honest_scope` that is not the canonical scope of that
    format (the scope is fixed by the format version, §1), an `anchors` mechanism this revision does not define (§3.3);
  - `unknown_member` — a key outside the closed list of an object of §9.1;
  - `malformed` — every other refusal (the §3.1 profile, a missing or mistyped MUST, a name that is not a non-empty
    unique string, …).

  `refusal_class` is `null` on an admitted pack. This use of admissibility for a format or revision mismatch is this
  format's own; the nearest rule of draft-krausz-verification-state-03 (work in progress) is §5.4.1(h), which treats a
  version the verifier does not implement as a limitation of the verifier, not a defect of the input. A refused pack was
  not evaluated: `states` and `policy` are `null`, and its twelve fields keep the values of a refusal (`digest_ok`,
  `bindings_ok`, `policy_ok`, `valid` false) BY CONSTRUCTION, not by measurement — a reader of those fields alone sees an
  altered pack; it must read `admission` (§10).
- `states_vocabulary`: `"ap2-evidence-pack/states-1"`, the identifier of the vocabulary below, which this text defines.
  An identifier never changes meaning: a revision that changes a state or a reason defines a new one. The vocabulary is
  aligned with draft-krausz-verification-state-03 §3.1, §3.3 and §5.4.2 (an individual Internet-Draft, work in progress);
  the draft is not the identifier, and a later draft does not change this one.
- `states` (admitted packs): a closed object with exactly the five subjects of the table below. Each is
  `{"state": S, "reasons": [R, ...]}` with an optional `detail` (free text, informative, never compared). S is one of
  `verified`, `contradicted`, `indeterminate`, `not_evaluated` (krausz §3.1). `indeterminate` (reasons `divergence`,
  `absence`) is reserved: no check of this revision produces it.
- `policy` (admitted packs): `{"met": bool, "unmet": [...]}`. `unmet` names, in this order, each requirement of the
  relying party the pack does not meet: `require_producer`, `require_pq`, `require_anchor`, `min_anchors` (§6 step 6),
  `trusted_producer_keys` (a pinned set is given and a present producer block is not `trusted`, §5) and
  `trust_set_complete` (below). `met` is true iff `unmet` is empty. `policy_ok` keeps its §6 step 6 meaning: it is false
  exactly when one of the first four is unmet. A policy is a disposition of the relying party, not a state of the pack.

**Elements and precedence.** Each subject is stated from its ELEMENTS — one per thing it covers (an artifact, a token, a
signature entry) — and takes the state of its highest element under: `contradicted` > `not_evaluated` with reason
`instrument_failure` > any other `not_evaluated` > `verified` (cf. krausz §5.4.1(j): malformed outranks unknown). The two `not_evaluated` ranks give the same
state; an `instrument_failure` element is never hidden by the rank, because `reasons` lists every element that is not
`verified`. A subject
is `verified` only when every element is. `reasons` lists one reason per element that is not `verified`, in element order;
on a `verified` subject it lists the qualifiers of its elements (in this revision only `ca_certified`). A subject with no
element is `not_evaluated` with `not_present`.

| subject | elements | `verified` | `contradicted` (reason) | `not_evaluated` (reason) |
|---|---|---|---|---|
| `sealed_content` | the digest (§3); each artifact (§6 step 2: issuer signature and claims); the binding set (§4), recomputed for this subject whenever every artifact's signature and claims verified — also when a KB-JWT failed, where `bindings_ok` is false by §6 step 3 | every element | `digest_mismatch`; `artifact_invalid` (an artifact error, a signature or claims that do not verify, or no artifact); `binding_mismatch` | — |
| `holder_binding` | each artifact that is not an error and carries a KB-JWT | its KB-JWT verifies under `cnf.jwk` | `kb_signature_invalid` (the signature does not verify, whatever `sd_hash`); `sd_hash_mismatch` (the signature verifies, `sd_hash` does not) | `holder_key_unknown` (no `cnf.jwk`: recorded, never fails the pack, §6 step 2); `not_present` |
| `time_anchor` | the `rfc3161_timestamp` token when `anchored`; each `anchors` entry | binding verified (§3.2) AND, under `--tsa-cert`, the TSA signature verified | `binding_mismatch` (an imprint was read and is another digest, whatever else fails); `token_invalid` (otherwise: not a parseable, granted token); `token_missing` (`anchored` with no `tsr_b64`, §6 step 4) | `tsa_not_checked` (binding verified, no TSA certificate given: a self-issued token satisfies the binding, §3.2); `tsa_invalid` (the TSA signature does not verify under the certificate given: not counted, §3.3); `instrument_failure`; `not_present` |
| `producer_signature` | each signature entry; the block itself | `PASS` with a key in the pinned set | `signature_invalid` (a `FAIL` entry; also a block with no entry, or whose `scheme` does not match its entries, §5, with a `detail`) | `self_asserted` (`PASS`, no pinned set: the key is carried by the pack — `valid` can be true without pins, a policy of this format, never a trust statement; krausz §5.4.2(a) has no resolved result without the relying party's trust material); `key_unresolved` (`PASS`, a pinned set that does not hold the key — not a failed signature); `backend_missing` (`SKIP`: no ML-DSA-65 backend, or a `sig_alg` this format does not define); `not_present` |
| `issuer_identity` | the key of each artifact that is not an error | an `x5c_header` key whose chain validates to the relying party's trust anchor (§6 step 7) — qualifier `ca_certified`: a CA under YOUR anchor certified the key, never "this is the issuer" | `chain_broken` (openssl reports a certificate signature failure inside the chain, or an `x5c` entry is not strict base64) | `self_asserted` (`jwk_header`, `supplied`, `jwks_fetched`); `no_trust_anchor` (`x5c_header`, no anchor given); `chain_unresolved` (the chain does not reach the anchor given: not resolved in the relying party's material, not a defect of the input); `instrument_failure`; `not_present` |

An artifact that is an error is stated once, in `sealed_content` (`artifact_invalid`); `holder_binding` and
`issuer_identity` are stated over the artifacts that are not errors, and say `not_present` with a `detail` when none is.

`instrument_failure` (krausz §3.1: the verifier's instrument failed; never a result about the input): openssl absent,
openssl that cannot be started, is killed by a signal or does not answer, a temporary file openssl needs that cannot be
written, a verifier that
cannot make the check at all (the JS verifier under `--tsa-cert`). The `detail` names which. No producer check calls an
outside tool, so this revision never states it on `producer_signature`.

**The tokens of krausz §5.4.2.** This text reuses `key_unresolved`, `signature_invalid` and the trust-set completeness
input of krausz §5.4.2 as reason codes under the §3.1 states; krausz does not — it reports them as the receipt step's own
tokens. Here the cryptographic check against the key the pack carries RAN; `key_unresolved` means the key is not
resolved in the pinned set.

**`trust_set_complete`** (a verifier input, `--trust-set-complete`, default false — krausz §5.4.2 "Completeness input",
which credits the split between the keys a relying party holds and a list it declares complete to x402 TSC issue #4,
2026-09-24): the relying party declares its pinned set complete. An entry that is
`key_unresolved` then also puts `trust_set_complete` in `policy.unmet`. It never turns `key_unresolved` into
`signature_invalid`, and `valid` does not change (a pinned set that does not hold a key already makes the pack not
valid, §5).

**`valid` and the states.** `valid` keeps its §6 step 8 definition. On every admitted receipt it equals: no subject but
`issuer_identity` is `contradicted`, AND no producer entry is `SKIP` (`backend_missing`), AND `policy.met`. Two terms are
not those of the equation the design of this revision pre-registered (every subject; no `SKIP` term), and both come from
rules of earlier revisions this one does not change: an x5c chain never decided `valid` (§6 step 7: a flag, not a failure
— vector `issuer_x5c_chain_broken` is valid with `issuer_identity` contradicted), and §5 makes a block with a `SKIP` entry
not `ok` although no check failed (`producer_backend_missing`). Measured on 18/10/2026 by `verifiers/states_controls.py`
(the schema-mutant corpus plus the vectors under four pinned-set inputs, 22 967 receipts): the equation above holds on
every receipt; the pre-registered one fails on 7, all of them receipts of those two packs.

**What no state can say.** A producer block that was removed and one that was never added give the same digest and
the same states (`producer_signature: not_evaluated`, `not_present`): only the SHA-256 of the whole file, or
`require_producer`, tells them apart (§10).

### 6.10 Exit codes and the receipt (NORMATIVE, 1.6.0)

`0`: `valid`. `1`: not `valid`, OR refused — read `admission`. `2`: a usage error (no receipt; 1.6.0: also a `--tsa-cert` or `--trust-anchor` that is not a readable regular
file). `74`: one of two cases,
told apart by what is on stdout:

- a check the caller asked for could not be RUN on this machine (openssl that cannot be started, is killed by a signal or
  does not answer, a
  temporary file openssl needs that cannot be written): the COMPLETE receipt on stdout — that subject `not_evaluated` with
  `instrument_failure` and a `detail` beginning `check not run here`, every other subject evaluated — and one line on
  stderr beginning `check not run here:`. 1.5.2–1.5.4 gave 74 with no receipt here. The library raises `Ap2WriteError`
  whose `receipt` is that complete receipt;
- the receipt itself could not be written whole (a full disk, a file size limit, a reader that closed the pipe): nothing,
  or a cut JSON, on stdout and one line `receipt not written: …` on stderr.

openssl ABSENT is neither: as in 1.5.x the field is `null` (`tsa_verified`, `chain_verified`), the subject is
`not_evaluated` with `instrument_failure` (`detail`: openssl absent) and the exit follows `valid`. The JS verifier accepts
`--trust-set-complete` and refuses `--trust-anchor` (exit 2, §6 step 7).

## 7. Conformance (normative)

Run every `spec/vectors/ap2/<name>.json` under the policy in
`<name>.expected.json` and reproduce the `normative` block exactly
(`run_ap2_conformance.py` does this for the reference; exit 0 = conformant).
The set contains forty-two vectors (1.6.0: + 13, one for each cell of the §6.9 table the earlier vectors did not reach:
`holder_kb_signature_invalid`, `holder_sd_hash_mismatch`, `holder_key_unknown` — valid —, `sealed_binding_mismatch`,
`time_token_missing`, `time_tsa_verified` and `time_tsa_invalid` — anchor_valid's bytes under `tsa_cert` —,
`producer_backend_missing`, `producer_trust_set_complete`, `issuer_x5c_no_anchor` — valid —, `issuer_x5c_ca_certified`,
`issuer_x5c_chain_unresolved` and `issuer_x5c_chain_broken` — all three valid, under `trust_anchor`). Of the twenty-nine
earlier vectors: seven ACCEPTs (`valid_signed` — positive control — and `anchor_valid`,
a real RFC 3161 token from a probe TSA whose certificate ships beside it; since 1.4.0 also
`header_param_ignored`, a signed header with an unregistered parameter that RFC 7515 §4 says to
ignore, `kb_jwt_valid`, a holder-bound mandate whose KB-JWT verifies, and `key_jwk_member_ignored`,
a snapshotted JWK with an unregistered member; since 1.5.0 `anchors_two_valid`, two distinct anchors
under `min_anchors` 2, and `anchors_only`, an anchor carried only in `anchors`) and twenty-two
REJECTs (stripped-signature downgrade, valid-but-unpinned producer, digest mismatch,
anchor required-but-missing, anchor claimed-but-invalid, a real token for another digest; since
1.4.0: an unknown key at the top level, inside `rfc3161_timestamp`, inside an artifact entry and
inside a producer-signature entry — since 1.6.0 both refusals of class `unknown_member` —, a `crit` header parameter the verifier does not understand, and
a KB-JWT without the `kb+jwt` type; since 1.5.0 (§3.3): a copied token counted once, one anchor under
`min_anchors` 2, an `anchors` entry whose token is not a TimeStampResp, a real token for another
digest in `anchors`, an unknown mechanism, an unknown key in an entry, an empty `anchors`; since 1.5.4 (§5) a pinned
block whose ML-DSA-65 signature fails, a pinned block whose classical signature fails under `require_pq`, and the same
bytes with no pinned set). A vector
whose `requires` tooling is absent is reported SKIP, honestly unverified. 1.5.4: `requires_backend` lists the
cryptographic backends without which a verifier cannot reproduce the vector's `normative` block; this revision defines
one, `"ml-dsa-65"` (a verifier that can check FIPS 204 ML-DSA-65 — the receipt's `mldsa_backend`, §6 step 6). A verifier
without that backend reports such a vector SKIP — not a disagreement and never a pass — and does not claim conformance on
it. Twenty-one vectors carry it (1.5.4: twelve; 1.6.0: also `digest_mismatch` and the three
`producer_*_fails_*` vectors, whose `states` block depends on the backend, and five of the thirteen new vectors); which
ones is MEASURED, not chosen: the reference verifier is run on every vector with and
without its ML-DSA-65 backend, and the vectors it reproduces only with the backend are the ones marked
(`make_vectors_154.py --declare-backend`; the test suite repeats the measurement). The expected files are a closed
format: keys `vector`, `description`, `policy`, `normative` (all twelve fields), `report` (`ignored`, `refused`),
`requires`, `requires_backend` (`"ml-dsa-65"`), and since 1.6.0 `states` (REQUIRED: `admission`, `refusal_class`,
`subjects` — each of the five subjects with its `state` and `reasons`, `detail` excluded — and `policy`, `null` both on a
refusal; a conformant verifier reproduces it exactly); `policy` keys `trusted_producer_keys`, `require_pq`,
`require_producer`, `require_anchor`, `min_anchors`, with the types of §6 (`require_*` booleans, `min_anchors` a positive
integer, `trusted_producer_keys` null or an object mapping a `sig_alg` to a key or a non-empty list of keys), and since
1.6.0 `trust_set_complete` (boolean), `tsa_cert` and `trust_anchor` (the name of a file of the vector set, passed as
`--tsa-cert` / `--trust-anchor`). The five vectors that pass `tsa_cert` or `trust_anchor` list `"openssl"` in `requires`: a
verifier that cannot call openssl (the JS verifier) reports them SKIP. A runner that meets
any other key, backend name or policy type, a file that is not UTF-8 JSON or repeats a key, or a pack without its
expected file (or the reverse) stops with an error of the vector set, never ignoring it (`run_ap2_conformance.py`:
exit 2). When an
`<name>.expected.json` carries a `report` block, a conformant verifier also reproduces it: today it
holds `ignored`, the per-artifact list of names ignored under a standard's rule (§9.2), mapped
onto the reference receipt's `artifacts[i].ignored`; since 1.5.0 it may also hold `refused`, the EXACT
refusal text (§9.1/§3.3 fix its form), so a verifier that refuses for another reason does not pass.
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
"Refusal" is a receipt with `valid: false`, `admission: "refused"` (1.6.0, §6.9: `refusal_class` `unknown_member` for an
unknown key, `malformed` for a wrong type or a missing key) and `refused` naming the object and the key
(`<object>: unknown key "x" (SPEC §9.1)`; with several unknown keys, the first by Unicode code point —
1.4.1); "artifact error" is `artifacts[i].error` for that artifact (the pack is not `valid`); "FAIL
entry" is `status: FAIL` for that producer signature (the block is not `ok`, the pack is not
`valid`), whose `note` names the unknown keys and the missing keys, each list sorted by code point
(1.4.1: in 1.4.0 the note did not name them; an entry that is not an object has no keys and no note). Keys are compared exactly (case-sensitive,
after JSON unescaping — `"subj\u0065ct"` IS `subject`).

| Object | Keys (type) | Unknown / wrong type / missing MUST |
|---|---|---|
| top level | `evidence_format` (string, MUST), `subject` (string, MUST), `created_utc` (string, MUST), `artifacts` (list, MUST), `bindings` (list; absent reads as `[]`), `honest_scope` (string, MUST), `evidence_digest_sha256` (string, MUST), `rfc3161_timestamp` (object), `producer_signatures` (object), `anchors` (non-empty list, 1.5.0) | refusal |
| `anchors[i]` (1.5.0) | `mechanism` (string, MUST, one of the mechanisms of §3.3: `"rfc3161"`); for `rfc3161`: `tsr_b64` (string, MUST), `tsa_url` (string), `note` (string); an entry that is not an object | refusal (an unknown `mechanism` is named: `anchors[i]: mechanism "x" is not defined by this revision (SPEC §3.3)`) |
| `rfc3161_timestamp` | `anchored` (boolean, MUST), `tsr_b64` (string; when `anchored` is true and it is ABSENT the §6.4 rule applies: `rfc3161_verified: false`, not a refusal), `tsa_url` (string), `tsa` (string, 1.0–1.3 spelling), `note` (string) | refusal |
| `producer_signatures` | `scheme` (`"hybrid"` or `"classical-only"`, MUST), `over` (`"evidence_digest_sha256"`, MUST), `signatures` (list, MUST) | refusal |
| `producer_signatures.signatures[i]` | `sig_alg` (string, MUST), `public_key_b64` (string, MUST), `signature_b64` (string, MUST), `post_quantum` (boolean, MUST, `true` iff `sig_alg == "ml-dsa-65"`); an entry that is not an object | FAIL entry; an UNKNOWN key: refusal (1.6.0, below) |
| `bindings[i]` | `in` (string), `claim` (string), `commits_to` (string), `encoding` (`"hex"` or `"b64url"`) — all four MUST; an entry that is not an object | refusal |
| `artifacts[i]` | `name` (non-empty string, MUST), `sd_jwt_compact` (string, MUST), `header` (object, MUST, canonically equal to the decoded protected header), `key` (object, MUST), `resolved_claims` (MUST, canonically equal to the recomputed claims), `kb_jwt` (object, MUST), `verified_at_build` (object, MUST) | artifact error (a `name` that is not a non-empty string stays a refusal, §2); an UNKNOWN key: refusal (1.6.0, below) |
| `artifacts[i].key` | `jwk` (object, MUST), `provenance_class` (string in the §2 enum, MUST), `note` (string), `x5c_chain_sha256` (list of strings), `jwks_url` (string), `jwks_sha256` (string), `fetched_utc` (string) | artifact error; an UNKNOWN key: refusal (1.6.0) |
| `artifacts[i].kb_jwt` | `present` (boolean, MUST, equal to "the compact serialization ends with a KB-JWT"), `verified` (boolean or null), `signature_ok` (boolean), `sd_hash_ok` (boolean), `note` (string or null), `claims_recorded_not_validated` (object); each of `verified`, `signature_ok`, `sd_hash_ok`, `claims_recorded_not_validated` that is present MUST be canonically equal (§3) to the value the verifier recomputes from the KB-JWT (§6) — a recorded value the KB-JWT does not support, or a key the recomputation does not produce, is that artifact's error, like the `header` copy (added on review, 2026-10-11) | artifact error; an UNKNOWN key: refusal (1.6.0) |
| `artifacts[i].verified_at_build` | `signature_ok` (exactly `true`, MUST), `disclosures_ok` (exactly `true`, MUST) | artifact error; an UNKNOWN key: refusal (1.6.0) |

`resolved_claims` and `bindings` are closed by construction (they MUST equal a recomputation);
the two rows above make the reason explicit instead of leaving a bare `claims_match: false`.

**1.6.0 — an unknown key is a refusal in every object of this section (NOT additive).** 1.4.0–1.5.4 made an unknown key
inside `artifacts[i]`, `artifacts[i].key`, `artifacts[i].kb_jwt`, `artifacts[i].verified_at_build` an artifact error and
inside `producer_signatures.signatures[i]` a FAIL entry. A reader of the twelve fields then saw an altered artifact or a
failed signature where the verifier had met a key it did not know — which a later revision of this format may define.
Since 1.6.0 such a key is a refusal of class `unknown_member` (§6.9), with the text
`artifacts[i]: unknown key "x" (SPEC §9.1)` (`artifacts[i].key`, `artifacts[i].kb_jwt`, `artifacts[i].verified_at_build`,
`producer_signatures.signatures[i]` likewise; the first unknown key by code point). The scan runs after the closed checks
of the top level, `rfc3161_timestamp`, `producer_signatures`, `bindings[i]` and `anchors[i]`, artifacts in list order
(each entry, then its `key`, `kb_jwt`, `verified_at_build`), then the signature entries. Only the unknown-key rule moves:
a wrong type or a missing key in these objects stays an artifact error or a FAIL entry (a FAIL entry's `note` names its
missing keys). This changes the twelve fields of two vectors: `unknown_key_artifact` (`digest_ok` and `policy_ok`
true → false) and `unknown_key_producer_entry` (`digest_ok`, `bindings_ok`, `policy_ok` true → false, `producer_present`
true → false, `producer_ok` false → null). `valid` does not change on any pack: a pack with such a key was never valid. The exit code
(1) changes in one branch: under `--tsa-cert` or `--trust-anchor` where openssl cannot run, 1.5.x reached that check
first (exit 74, no receipt); 1.6.0 refuses before any check runs (exit 1). A verifier conformant to the 1.5.x vectors is therefore not conformant to 1.6.0 on these two. The rule
applies to the objects of THIS section only: the objects of §9.2 keep their standard's rule (an unknown header parameter
or JWK member is ignored and reported — `header_param_ignored`, `key_jwk_member_ignored` stay valid — and an unknown
`crit` extension stays the artifact's error, RFC 7515 §4.1.11).

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
met their class, 0 disagreements (details in CHANGELOG 1.4.0). 1.5.0 adds `anchors` (the top-level key and every
entry): measured 2026-10-11, 16 503 mutations from 37 sources, each met its class in both verifiers, 0 disagreements on
16 540 files. Against the 1.4.1 verifiers the same corpus leaves 788 (Python) and 689 (JS) mutations without their
class, all from the two accepting `anchors` sources: 1.4.1 refuses the `anchors` key (as its §9 requires) and, in Python,
444 runs of `anchors_two_valid` stop at a `TypeError` (the 1.4.1 API has no `min_anchors`) — a check that the bench reaches
these sources, not a measure of the §3.3 rules; the mutants of the new code are that measure (CHANGELOG 1.5.0). 1.6.0 moves the
unknown keys of `artifacts[i]` (and its `key`, `kb_jwt`, `verified_at_build`) and of `signatures[i]` to the refusal class,
and checks `refusal_class: unknown_member` on every unknown-key mutation: measured 2026-10-18, 23 486 mutations from 59
sources, each met its class in both verifiers, 0 disagreements on 23 545 files; with the 1.6.0 refusal of `artifacts[i]`
and `signatures[i]` removed from a copy of the reference, 2 520 of them do not.

## 10. Reading a receipt as a relying party (INFORMATIVE)

This section changes no rule of §1–§9. It says, for a party that decides something on the strength of a pack (a dispute
provider, an auditor, an issuer years later), what each field of the receipt establishes and what it leaves to that
party, so that a dispute specification can cite it instead of restating it.

**What to record.** Record the fields, not the names of the conformance vectors: the vectors are examples, the verifier
does not emit their names. Since 1.6.0 the receipt states its verdict in four fields — `admission` (with
`refusal_class`), `states_vocabulary`, `states` and `policy` (§6.9) — beside the twelve fields of §6; in both verifiers
`producer_present`, `producer_ok` and `producer_trusted` are `producer_signatures.present`, `.ok` (always present since
1.6.0, `null` when there is no producer block) and `.trusted`, and `rfc3161_claimed` and `rfc3161_verified` are
`rfc3161.claimed` and `.verified`. A reference to a pack by `evidence_digest_sha256` alone does not identify one file: the
digest covers the sealed content (§3), not `rfc3161_timestamp`, `producer_signatures` or `anchors`, so a copy with a
signature or an anchor removed, or re-signed, has the same digest (and a copy with its producer block removed has the
states of a pack that never had one, §6.9). Record the SHA-256 of
the whole file, or verify with pinned producer keys and `require_producer`, plus `require_anchor` or `min_anchors` when
a ground rests on the pack's time.

**First, was the pack evaluated at all: `admission`.** `refused` means the verifier did not evaluate the pack; its
`digest_ok`, `bindings_ok`, `policy_ok` and `valid` are `false` by construction, not measured, and a reader of those
fields alone sees tampering that nobody measured. `refusal_class` says why: `format_unsupported` (a revision or an anchor
mechanism this verifier does not implement — a verifier of that revision may accept the pack), `unknown_member` (a key
outside a closed list: it can come from a later revision as well as from an injection, and the receipt cannot tell which),
`malformed`. A refusal is not evidence of tampering and not evidence against the submitting party.

**Exit codes.** `1` is both "not valid" and "refused"; `2` is a usage error. `74` with a complete JSON receipt on stdout
means a check asked for could not be run on this machine (the subject says `instrument_failure`): verify again where it can
run. `74` with nothing or a cut JSON means the receipt was not written. Read the receipt, not the exit code (§6.10).

**Then the states** (an admitted pack, §6.9).

| state | what it establishes | what the relying party does |
|---|---|---|
| `contradicted` on `sealed_content`, `holder_binding`, `time_anchor` or `producer_signature` | a check ran and failed: the sealed content is not what was sealed, an artifact or a KB-JWT does not verify, a claimed anchor does not bind this digest, a producer signature fails; `valid` is `false` whatever the policy | do not rely on the pack; the submitting party may supply a conformant one |
| `contradicted` on `issuer_identity` (`chain_broken`) | a certificate signature inside an x5c chain fails; `valid` is unchanged (a chain never decides `valid`, §6 step 7) | do not rely on that key's certificate for the issuer's identity |
| `not_evaluated` | the property was not established HERE — never a pass, never tampering | supply what the reason names and verify again: `instrument_failure` — a verifier and machine that can run the check; `backend_missing` — a verifier with ML-DSA-65; `self_asserted` or `key_unresolved` on the producer — the producer's key, obtained out of band and pinned; `tsa_not_checked` or `tsa_invalid` — the certificate of a TSA you trust (`--tsa-cert`); `no_trust_anchor`, `chain_unresolved` or `self_asserted` on the issuer — your trust anchor, or the out-of-band key comparison below; `holder_key_unknown` — the holder binding is not established by this pack; `not_present` — the pack carries no such element |
| `verified` | the check ran and passed, within its scope: `producer_signature` — signed by a key YOU pinned; `time_anchor` — every token binds this digest and is signed by a TSA whose certificate you gave, at its `gen_time`; `issuer_identity` (`ca_certified`) — a CA under your anchor certified each key, never that the key is the issuer's: `x5c_leaf` names the certificate holder, which you match to the issuer | rely on that property, in that scope |

`policy.unmet` names what the pack lacks for THIS relying party (`require_producer`, `require_pq`, `require_anchor`,
`min_anchors`, `trusted_producer_keys`, `trust_set_complete`): the content may be intact; ask for the missing element or
decide without the ground that needed it. `valid` is `true` without pinned keys (`producer_signature: self_asserted`): that
is a policy of this format, not a trust statement.

**Signatures and identity.** `self_asserted_only: true` (and `issuer_identity` other than `verified`) means the mandate
signatures were checked against key material carried in the pack: they prove the artifacts are consistent with those
keys, not who the issuer is — for a valid pack too. For keys embedded in the signed headers (`jwk_header`) the relying
party compares them with the issuer's published keys out of band and records that it did. With the JS verifier,
`--tsa-cert` gives `time_anchor: not_evaluated/instrument_failure` and counts no anchor, and `--trust-anchor` is a usage
error: both checks need the reference verifier (openssl).

**Time.** `time_anchor: not_present` means the pack claims no anchor (a token under `anchored: false` is not checked).
`anchors_verified` counts the distinct anchors whose token binds this digest; with `--tsa-cert` only those whose TSA
signature also verifies (§3.3). `tsa_not_checked` is a binding a self-issued token satisfies (§3.2): it says nothing about
a TSA's clock. A time-based ground needs `time_anchor: verified` under the certificate of a TSA the relying party trusts,
read with its `gen_time`, or an independent timestamp.

**ACP SEP #303 §7.4a.** The Agentic Commerce Protocol dispute RFC (agentic-commerce-protocol/agentic-commerce-protocol
PR #316, `rfcs/rfc.dispute_resolution.md` at commit 6710a3a, 2026-10-17, a proposal under review) maps nine of the twelve fields (`bindings_ok`,
`pq_protected` and `policy_ok` are not named in §7.4a) and the `anchors` binding to admissibility. Its rows, and the 1.6.0 fields that carry the same condition:

| §7.4a at 6710a3a | 1.6.0 fields |
|---|---|
| `valid: true` under the provider's policy → Admissible, apply 7.4 normally | `admission: admitted`, `valid: true`, `policy.met: true` — and `producer_signature` read as below: without pinned keys it is `self_asserted`, which the table's rows do not distinguish from a pinned producer |
| `digest_ok: false`, or `rfc3161_verified: false` / a failed `anchors` binding → Not admissible (tamper) | `sealed_content: contradicted` (`digest_mismatch`); `time_anchor: contradicted` (`binding_mismatch`, `token_invalid`, `token_missing`) |
| `producer_present: false` → only facts the mandate's own signature proves | `producer_signature: not_evaluated` (`not_present`) |
| `producer_ok: true`, `producer_trusted: false` → Consistency-only, MUST NOT be the sole basis for an `overturn` | `producer_signature: not_evaluated` (`key_unresolved`); the same standing applies to `self_asserted` (no keys pinned: `producer_trusted` is `null`, in no row) |
| `anchors_verified: 0` with `rfc3161_claimed: false` → a time-based ground needs an independent timestamp | `time_anchor: not_evaluated` (`not_present`); `tsa_not_checked` and `tsa_invalid` likewise prove no TSA time |
| policy 3: "A verifier result meaning "no check ran" is not tamper. `key_unresolved` (…) **MUST NOT** be treated as `signature_invalid`" | every `not_evaluated` reason; `key_unresolved` is never `contradicted`, and `--trust-set-complete` records the relying party's disposition in `policy.unmet`, never as a failed signature (§6.9) |
| policy 3: "A missing counterparty record (`no_record`) maps to `not_responded`; silence **MUST NOT** be treated as acceptance" | outside this format: the receipt holds no counterparty record and no field stands for a response; an absent pack is not a pack that verified |
| — (no row) | `admission: refused` (any `refusal_class`): not evaluated — not tamper; the pack is not used as submitted, the submitting party may resubmit in a format the provider's verifier implements; record `refused` and `refusal_class` |
| — (no row) | any subject `not_evaluated` with `instrument_failure` (or exit 74 with a receipt): no result about the pack; re-run in a working environment before relying on the absence of that property |

The RFC's requirement that "the determination **MUST** record the verifier output fields for each pack" is met, for a
1.6.0 receipt, by recording `admission`, `refusal_class`, `states_vocabulary`, `states` and `policy` with the twelve fields.

**draft-xg-payment-dispute-profile-01 (informative mapping).** That Internet-Draft (16 October 2026, Independent
Submission, Informational, "a vendor profile documenting one implementation", no IETF consensus) carries agent-native
facts in an `agent_anchors` block — "AP2 mandate_hash, TAP agent_id, approval event hash, receipt signature" (§4.2) —
and a `scope_conformance` field, "one of in_scope, BREACH:<field>, or not_evaluated", which "MUST be re-derived by the
verifier from recorded inputs, never asserted without re-derivation" (§4.2). Read against an ap2-evidence-pack receipt:

- `mandate_hash`: -01 does not define its preimage. Where a profile takes it as the SHA-256 of a mandate's compact
  serialization, that is the value §4 of this format computes for that artifact (lowercase hex), and
  `sealed_content: verified` states that the artifact verified with that exact serialization.
- `scope_conformance`: no field of this receipt re-derives the intent scope against an executed action. A receipt of this
  format establishes which mandates were signed, bound and sealed — not whether an action stayed within them — so a
  profile that fills `scope_conformance` from it alone can state only `not_evaluated`, and none of this format's
  `not_evaluated` reasons may become `in_scope`.
- `settlement_anchor` (§4.3): outside this format; a pack carries no settlement artifact.
- Keys: -01 §3 requires keys to be "resolved out of band"; that is this format's `self_asserted` / `key_unresolved` →
  pinned-key rule, for the producer and for the issuer.
