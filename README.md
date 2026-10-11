# ap2-evidence-pack

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539659.svg)](https://doi.org/10.5281/zenodo.22539659)

**Self-contained, offline-verifiable dispute evidence for agentic-payment SD-JWT mandates
(AP2 Checkout and Payment Mandates, and the delegation chains between them).**

Measured against the AP2 specification as published in `google-agentic-commerce/AP2` on 2026-09-22, whose mandates are
the **Checkout Mandate** and the **Payment Mandate** (the earlier Intent/Cart naming is gone from the spec; this README
used it until today). A delegation chain from that spec — `delegate_payload` carrying an array disclosure — parses and
resolves here unchanged: `python3 -c` on the encoded token in `docs/ap2/checkout_mandate.md` returns the delegate with
its `vct`, `constraints` and `cnf`. What this package does NOT yet do is validate the `vct` against the mandate type,
which the reference SDK does.

The [AP2 spec](https://ap2-protocol.org/ap2/specification/) tells implementers *what* to
keep for dispute resolution — the SD-JWTs with their disclosures, in compact serialization —
and deliberately leaves retrieval/retention mechanics out of scope. But financial
dispute/retention windows run to 5–7 years, and an ES256 mandate is re-verifiable at
dispute time only if the issuer's key material is still resolvable. Years later, JWKS
endpoints are gone and keys have rotated.

This tool turns a set of SD-JWT mandates into **one evidence file** that verifies
**offline, years later**:

- parses SD-JWT compact serialization and resolves selective disclosures **fail-closed**
  (unmatched, duplicate, or malformed disclosures are rejected, never ignored);
- verifies each **ES256** signature at build time and **snapshots the key material used**,
  tagged with an explicit provenance class — `supplied` (caller vouches; always wins over
  self-asserted header material), `x5c_header`, `jwk_header`, `jwks_fetched` (TLS witness
  at capture) — declared rather than flattened;
- verifies **KB-JWT holder binding** against the issuer payload's `cnf.jwk` (three honest
  states: verified / invalid → build refused / present-but-unverifiable, never painted green);
- recomputes **cross-mandate hash bindings** from the exact compact serializations
  (hex and base64url SHA-256);
- seals everything under a canonical SHA-256 digest with an **optional RFC 3161
  timestamp**, so "this key material existed and verified at time T" is attested by a
  third-party clock — re-checked offline for binding (status + imprint) by both verifiers,
  and for TSA authenticity by the reference when the TSA certificate is supplied (`--tsa-cert`).

## Usage

```bash
pip install ap2-evidence-pack   # cryptography >= 48 comes with it (declared since 1.1.1; >= 48 since 1.3.0)

python3 examples/make_samples.py     # generates sample checkout.sdjwt + payment.sdjwt
python3 ap2_evidence.py build evidence.json checkout=checkout.sdjwt payment=payment.sdjwt \
        [--key name=jwk.json] [--jwks-url name=https://...] [--tsa http://tsa.example]

python3 ap2_evidence.py verify evidence.json     # offline, fail-closed; exit 0/1
python3 ap2_evidence.py verify evidence.json --trusted-producer-key ed25519=<b64> --trusted-producer-key ml-dsa-65=<b64> --require-pq --require-anchor   # relying-party policy (1.1.0)
node verifiers/js/ap2-verify.mjs evidence.json   # the independent verifier, same flags
```

Or as a library: `build_evidence(...)` / `verify_evidence(...)`.

## Honest scope

This file proves *what verified against which key material at capture time* — nothing
more. It does **not** prove issuer key authorization beyond what each provenance class
states, does **not** confer qualified-archive legal presumption (in the EU that is a
QTSP service under eIDAS art. 45j), and validates x5c chains only when you supply a trust anchor
(`--trust-anchor`, SPEC §6.7) — nothing about a chain is sealed in the file itself. ES256 only, by design; other algorithms are rejected loudly, never half-verified.
`valid: true` means every artifact verifies and the file is intact — read `bindings` for
chain linkage and `provenance_classes` / `self_asserted_only` for capture strength.
`self_asserted_only` is fail-closed (SPEC §6.7): offline **nothing** clears it — not a label
(`supplied`, `jwks_fetched`), not a certificate that names a famous CA as its issuer. Only an
`x5c` chain that validates to a trust anchor YOU supply does (`--trust-anchor <PEM>`, reported in
`chain_verified`, validated at the `genTime` of a TSA-verified token when the pack has one, so an
expired signing certificate still counts years later); the Node verifier cannot validate chains and
reports `chain_verified: null`. A cleared flag says a CA under your anchor certified that key — not
that the key belongs to the mandate's issuer; read `artifacts[].x5c_leaf` for the subject and issuer
DN of the certificate that was validated.

## Producer signatures (post-quantum hybrid)

`sign_evidence(...)` adds a **hybrid producer signature** over the pack digest — a
classical signature (ed25519 or ecdsa-p256) plus **FIPS 204 ML-DSA-65** — so the pack's
integrity/authenticity survives the quantum transition (NIST IR 8547). Verification is
fail-closed; authenticity requires the relying party to **pin** the producer public keys
out of band (an embedded key proves consistency, never authenticity). Policy flags on
`verify_evidence`: `require_producer`, `require_pq`, `require_anchor`. The ML-DSA-65
path is checked against a NIST ACVP sigVer subset (`pqcrypto/vectors/`) — the same nine
cases the elara-mesh verifier runs, so both stacks answer to one set of NIST-published ACVP vectors — a local check
against public test data, not a NIST validation.

## Conformance (normative)

The format is defined by `SPEC_AP2_EVIDENCE.md` plus the test vectors in
`spec/vectors/ap2/` — five ACCEPTs (`valid_signed`, the positive control; `anchor_valid`,
a real RFC 3161 token from a probe TSA whose certificate ships beside it; and, since 1.4.0,
`header_param_ignored`, `kb_jwt_valid`, `key_jwk_member_ignored`) and twelve REJECTs
(stripped-signature downgrade, valid-but-unpinned producer key, digest mismatch, time
anchor required-but-missing, time anchor claimed-but-invalid, a real token issued for
another digest; since 1.4.0 an unknown key at the top level / inside the anchor block / inside
an artifact entry / inside a producer-signature entry, a `crit` nobody understands, and a
KB-JWT without `typ: kb+jwt`). An independent verifier
claims conformance by reproducing each vector's `normative` block under its declared
policy, from the spec text alone:

```bash
python3 spec/vectors/ap2/run_ap2_conformance.py   # exit 0 = conformant
```

| Implementation | Runtime / deps | Status |
|---|---|---|
| `ap2_evidence.py` | Python 3 + `cryptography` | reference — conformant 17/17; ACVP ML-DSA-65 sigVer 9/9 |
| `verifiers/js/ap2-verify.mjs` | Node with OpenSSL ≥ 3.5 for ML-DSA-65 (measured: Node 22.23.2 / OpenSSL 3.5.7 locally, Node 24 in CI), `node:crypto` only; on an older build ML-DSA-65 is SKIP = incomplete, never a pass, and the ML-DSA vectors are not measured (the JS conformance test skips, it does not pass); no TSA signature check — `tsa_verified` null | independent — conformant 17/17 on every normative field (and the `report` block) through `run_ap2_conformance.run(verify_fn=…)` (`test_ap2_conformance.py`) |

**Closed schema (1.4.0, SPEC §9; 1.4.1).** Measured on 1.3.0 on 2026-10-10: a key nobody had defined, written inside
`rfc3161_timestamp`, `producer_signatures` or a `signatures[i]` entry, was `valid: true` in both verifiers with nothing in
the receipt. Every object this format defines is now an exhaustive key list — unknown key, wrong type or missing MUST is a
refusal / artifact error / FAIL entry that names the key (a signature entry's FAIL names it since 1.4.1) — and every object a standard defines (JOSE header, JWK, `cnf`,
KB-JWT) follows that standard's rule for the unknown (ignored) and REPORTS the ignored names in `artifacts[i].ignored`;
`crit` makes the JWS invalid (RFC 7515 §4.1.11). The proof is generative: `verifiers/schema_mutants.py` derives from every
vector and from freshly signed packs 12 818 mutations at every level of every object (unknown keys in eight spellings and
every value type, every known key of every hostile type and deleted, duplicate keys, key order, escaped spellings, `crit`,
KB-JWT claims, out-of-grammar files), computes each one's expected class from the SPEC tables and holds both verifiers to
it and to each other: 12 818/12 818, 0 disagreements on 1.4.0; on the 1.3.0 verifiers the same corpus passed SILENTLY
8 186 times in both, with the two agreeing on every one (CHANGELOG 1.4.0). The quick subset (3 085) runs in CI.

**Differential oracle** (`verifiers/differential_oracle.py`, 22/09/2026): the two verifiers must
give the same `(valid, digest_ok, bindings_ok, producer_ok, pq_protected, rfc3161_verified,
policy_ok, producer_present, producer_trusted, rfc3161_claimed/granted/imprint_ok/gen_time, chain_verified,
self_asserted_only, provenance_classes, and the `x5c_leaf` identity of every artifact)`
— the eleven normative fields of SPEC §6 plus `rfc3161.granted`, `rfc3161.imprint_ok`, `rfc3161.gen_time`,
`chain_verified`, `provenance_classes` and the `x5c_leaf` identity — on the 17 vectors under their declared policy (plus `anchor_valid` under
`--require-anchor --tsa-cert`, and the CA-issued `x5c` leaf under `--trust-anchor`), 117 hostile files that carry the digest a lenient verifier would
recompute or a wrong JSON shape (`__proto__` key with the digest recomputed over it, non-UTF-8, float `1.0`, 2^53+1, 100000-deep,
`NaN`, lone surrogate, duplicate key, BOM, non-object, `artifacts`/`key`/`jwk`/`rfc3161_timestamp`/
`producer_signatures` of the wrong type, an empty producer block, base64url with a space /
padding / `+` on the binding artifact, a padded JWK coordinate, a deep JWT header, a non-object
payload, a trailing NBSP on the compact serialization, a space inside `tsr_b64`, claims and
bindings mismatch, producer base64 with a space, unknown producer algorithm, PQ signature
stripped under `--require-pq`, a self-forged TimeStampResp with the right imprint, a
TimeStampResp with an empty SignedData / eContent, `sig_alg` `"constructor"` / `"__proto__"` /
a list / an object under a pinned key, `provenance_class` a list or an int, `anchored` a list /
an object / `0` / `"false"`, and — inside a freshly ES256-signed payload, digest recomputed —
a duplicate key, a BOM, `_sd` `null` / `{}` / `[1]`, `_sd_alg: null`, `{"...": [1]}`, a
disclosure whose name is a list, `cnf` `null` / a string, `cnf.jwk` `{}`, JWK `x` of 31 and of 33
bytes; an artifact `name` absent / an int / `"__proto__"` / empty / duplicate; a DER element with a
4-byte length whose top bit is set inside the TSTInfo; and — built by the reference itself — packs whose
bindings sit under array-index claim keys, whose recorded binding list is reversed, or which carry a
duplicated binding entry; `provenance_class` `x5c_header` with no `x5c` in the signed header, out of
enum, a list or absent; `evidence_format` `…/2.0` or absent; `subject`/`created_utc`/`honest_scope`
absent or the wrong type, `created_utc` not ISO-8601; a SIGNED payload that is an array or a string,
a signed 100000-deep header; seven KB-JWT branches (two segments, a header that is not JSON, an array payload, `alg` RS256, `cnf.jwk` a string, and a
signature segment with padding or with a space) and seven `resolve_disclosures` branches (a disclosure that is not
base64url, not JSON, an object, four elements, a duplicate digest, one matching nothing, and a colliding claim name);
a FIFO, a symlink to `/dev/zero`, a directory and a file one byte over 64 MiB in place of the evidence file (each with a
DECLARED refusal reason both verifiers must give, since 25/09/2026 — a FIFO had blocked both and `/dev/zero` had exhausted
memory in both, which a comparison of the two alone records as agreement);
a real self-signed `x5c` leaf — canonical, with a space, with a newline,
one whose key differs from the snapshotted JWK, and one issued by a CA rather than self-signed;
`provenance_class` `supplied`, out of enum, a list or absent; `honest_scope` absent; a pack whose mandate is
self-asserted while a second artifact chains to the anchor) and 19 command-line grammar cases
(18 usage exit 2,
nothing on stdout, in both — the bare invocation without a subcommand included — and one
`--flag=value` form that must produce a verdict, not usage), plus four positive
controls, named here from `POSITIVE_CONTROLS` in the oracle rather than from memory (`non-ascii-subject-rehashed`,
`fresh-pack-control-valid`, `must-created_utc-ok` and, since 25/09/2026, `file-exactly-at-the-bound` — the valid vector
padded with spaces to exactly 64 MiB — each one a pack that must be `valid` in both verifiers, so a suite that answers
REJECT to everything is caught; through 1.2.0 this sentence said more than the oracle did: it only COUNTED the positive
controls, and two verifiers refusing one alike were an agreement — measured by ablation on 25/09/2026, see CHANGELOG). The CA-issued `x5c` leaf under `--trust-anchor`, the only case
where `self_asserted_only` is false, is one of the hostile files, not one of those three — this sentence said
otherwise through 1.1.2:
**158 cases, 0 disagreements, of which 4 are declared divergences** (measured 2026-10-10 on 1.4.0; the run prints its own
decomposition — `18 vector runs + 117 hostile files + 4 positive controls + 19 CLI cases = 158` — so these numbers are
copied from that line rather than counted by hand, which is how several of them went stale during the
review rounds; this very sentence had gone stale once more, and was caught by the final check) — the real token under `--tsa-cert`, where the
reference proves the TSA with openssl and the JS verifier reports `tsa_verified: null` and does
not pass the policy; and the three packs under `--trust-anchor` — the CA-issued leaf, the self-signed leaf and the mixed
mandate-plus-chained pack — whose chains the reference validates with `openssl verify` (clearing `self_asserted_only` for
the CA-issued one) while the JS verifier cannot and reports `chain_verified: null`. A crash counts as a disagreement, and a declared divergence that stops
appearing is reported. Positive controls (`AP2_ORACLE_PY_ROOT` / `AP2_ORACLE_JS` point the oracle
at another checkout), measured 22/09/2026 with the 124-case oracle: against the 1.0.2 reference it is red on 97
(the CLI had no policy flags; float / 2^53+1 / lone surrogate / a space inside a producer
signature or inside `tsr_b64` accepted; `producer_signatures: {}` and `producer_signatures: []`
treated as absent, `valid: true`; tracebacks on non-UTF-8, 100000-deep, BOM, a missing path and
on wrong-typed `artifacts`/`key`/`jwk`/`rfc3161_timestamp`; `--help` exit 0, `--` a verdict);
against the states after rounds 10 and 11 it is red on **0**, and that is not a clean bill: pointing the oracle at an older
checkout makes BOTH verifiers old, so they agree with each other and the run only reports that the declared divergences no
longer appear. The defects the last two rounds fixed were shared by the two verifiers, which is exactly what a differential
oracle cannot see — they are held by unit tests measured red against those commits instead. Against round 9 the oracle was
red on 10 with that round's 130-case set, against the state after round 7 on 3 — the two `--trust-anchor` cases, which that reference
does not know (it exits 2 on the flag), plus the declared divergence that stops appearing there and is reported as
a disagreement — against the state after round 6 on 0 — the round-7
findings were defects the two verifiers SHARED, held instead by two unit tests measured red against the round-6 code
(`test_provenance_class_is_reconciled_and_format_is_pinned`, `test_build_side_x5c_and_jwks_errors_are_receipts`) —
against the state after round 5 on 3 (a signed array payload verified in the JS
verifier, whose shape check had spent a round inside an unterminated line comment; an `x5c` leaf spelled
with a space or a newline was accepted by the reference's lenient `base64.b64decode` and refused by the
JS verifier), against the state after round 4 on 0: the round-5 findings are defects the two
verifiers SHARED (a differential oracle measures agreement, not correctness), and they are held instead
by two unit tests that go red against the round-4 reference —
`test_provenance_class_is_reconciled_and_format_is_pinned` and `test_build_refuses_what_verify_refuses`
(measured 22/09/2026). Against the state after round 3 the oracle is red on 2 (the binding-set cases above),
against the state after round 2 on 5 (the round-3 cases: an absent artifact `name`
crashed the JS binding table, an int name was stringified by it and `"__proto__"` vanished from it; a
4-byte DER length went negative in the JS `<<` and a token the reference refuses verified there; the bare
invocation printed the reference's help on stdout) and against the state after round 1 on 26 (the round-2 cases: the reference read
the signed payload with `json.loads` — duplicate key last-wins, BOM skipped — while the JS parser
refused; present-with-`null` was "absent" in JS and a `TypeError` in the reference; 31/33-byte JWK
coordinates verified in the reference; `anchored: []` was not anchored in the reference and
anchored-unverified in JS; `sig_alg: "constructor"` under a pin crashed the JS verifier;
an empty EXPLICIT `[0]` in the token was an `IndexError` in the reference). Round 4 added the binding
cases: `bindings` is a SET (SPEC §4) in both, because JavaScript enumerates array-index object keys
first — an ordered comparison split the verdict on a pack the reference itself had built.
Ablation (`verifiers/lax_python_ablation.sh`, measured 22/09/2026): each strict layer of the reference
removed **alone** from a copy — file-level strict JSON, JWT-level strict JSON, strict base64url, the JWK
coordinate length — must turn `test_ap2_conformance.py` red by itself, and each does (1 error + 1
failure for the file-level layer, then 1 failure each). Measured on 22/09 before that split: ablating base64url alone left the
suite green, so that layer was not measured by the unit suite; three unit cases were added for it.

**Why not an ETSI container?** For the long-term preservation of *signed documents* the standard answer is an ASiC
container (ETSI EN 319 162) or PAdES/XAdES LTV, which already embed certificates, revocation data and timestamps, and
which any eIDAS validator can read. If your artifacts are documents and your counterparties run eIDAS tooling, use those:
this format is not a replacement and does not try to be one. It exists for a narrower case those containers do not cover —
SD-JWT mandates with selective disclosure, where what has to survive is the resolution of the disclosures, the
cross-mandate hash bindings and the key material *as captured*, verifiable by a single self-contained file with no
trust-list infrastructure. The cost of that choice is explicit: this is not a standardised container, and a relying party
years from now has to run this verifier (or the format's SPEC, which is written to be re-implementable) rather than an
off-the-shelf eIDAS validator.

**Third verifier, written by other people** (`verifiers/sdk_crosscheck.py`, measured 23/09/2026). The oracle above
compares two verifiers written by one author, so a MISREADING of the specification is invisible to it: the same
misreading lands in Python and in Node, and they agree. This bench asks the same questions of a stack nobody here
wrote — Google's AP2 SDK at commit `e1ea56db72a6`, the head of that repository's `main` when this was measured, over
`sd-jwt` 0.10.4 — measured 23/09/2026 as the latest release on PyPI, whose own summary there reads "The reference
implementation of the IETF SD-JWT specification" and whose author field names Daniel Fett, one of RFC 9901's three
authors. The bench compares two things per artifact: the verdict, and the claims left after disclosure resolution, and
it prints the SDK commit and the `sd-jwt` version it actually loaded rather than repeating them from here.

```bash
AP2_SDK_PATH=/path/to/AP2/code/sdk/python python3 verifiers/sdk_crosscheck.py --hostile
```

Re-measured 2026-10-11 on 1.4.0 (AP2 SDK `e1ea56db72a6`, `sd-jwt` 0.10.4). On the seventeen vectors alone: **26
artifacts compared, 23 claim-sets compared, 0 disagreements** (two packs are refused before the mandate layer and one
artifact at a closed object of SPEC §9.1, which the third stack never sees). Vectors plus the hostile corpus together:
**142 artifacts compared (26 from the vectors, 116 hostile), 90 claim-sets compared, 0 undeclared disagreements**. The three file-object cases of the oracle (a FIFO, a symlink to
`/dev/zero`, a directory) are not handed to this bench, which counts and prints them apart. And **none in the direction
that would matter most — nothing this repository accepts and the third stack refuses**. One word needs care in that sentence: "refuses", for the third stack, means "raises". Of
its 19 refusals here, 8 are deliberate and carry a message, and 11 are uncaught internal errors (`JSONDecodeError`,
`'str' object has no attribute 'get'`, a failed tuple unpack). Fail-closed in effect, but not a verdict, and the bench
prints that split rather than hiding it inside a total. The buckets that decide what counts as a disagreement at all
are this repository's own; the one direction never bucketed away is "we accept, the third stack refuses".

**The other direction, which comparing opinions cannot reach.** Every pack above is produced here, so a reading shared
by both of this repository's verifiers would also shape the corpus they are tested on. So the third stack also ISSUES:
it mints tokens — with and without decoy digests — and this repository's Python reference verifies them and resolves
the same claims. Both cases pass, and the bench asserts the shape rather than asserting it in prose: each issued token
carries one `{"...": <digest>}` array-element placeholder in its signed payload, a shape no hostile file here
exercises. The Node verifier is not run on them. What is still NOT cross-checked, stated plainly: nested and recursive disclosures, and delegation chains.

**Positive controls, because a bench that cannot go red measures nothing.** A flipped signature must be refused; a
rewritten disclosure's forged value must never be disclosed (the presentation itself is ACCEPTED by the third stack —
that is the declared divergence below); a wrong key must flip the third stack's verdict. That a disagreement is
actually REPORTED and turns the bench red is held by its own ablation: `AP2_XCHECK_SEED_DIVERGENCE=1` corrupts the key
handed to the third stack, and the run must both print the seeded `[DIFF]` and exit non-zero. The workflow carries
the bench and that ablation as their own steps; whether they are green is a fact about a run, and belongs in the
release notes with the run behind it. Since 1.4.0 a refusal at a closed object of SPEC §9.1 is checked underneath before it
is set aside: the bench rebuilds those objects as `build` writes them and compares the verdict that is left, and four
more controls hold that step: closed objects broken around a token we refuse and the third stack accepts (asked for real);
a recorded KB copy around a KB-JWT that fails, and an artifact only the closed layer refuses (the third stack's verdict
supplied by the control, accept and refuse respectively, since no real case of either exists); a malformed key block,
which stays this repository's own.

**Every malformed input gets a verdict, never a traceback** (`verifiers/type_fuzz.py`). The count above — 11 of the
third stack's 19 refusals being uncaught internal errors — raises the same question about this repository, and it is
the one question here that is this repository's business to answer. `test_hostile_files_are_refusal_receipts_never_tracebacks`
already held it for ten hand-picked FILE-level shapes (eight malformed files, a missing path, a directory) against the
Python reference called as a library, and the differential oracle already runs BOTH verifiers as subprocesses on the
113 hostile files, turning a non-JSON answer into a crash marker that never agrees. What this adds is the fields one at
a time instead of hand-picked files, and a positive control for the crash detector itself. Measured 23/09/2026: every field of a valid pack
(88 of them) replaced by each of eight hostile types — `null`, a number, `""`, `[]`, `{}`, a boolean, a float where an
integer belongs, a lone surrogate — is **695 hostile mutations, answered with a verdict 1390 out of 1390 times** across
the two verifiers (nine substitutions left the pack byte-identical to the valid one — a `true` replaced by `True` — and
are counted apart rather than inflating the denominator). An answer means stdout parses to an object with a boolean
`valid` AND stderr is empty: a receipt printed before a traceback does not count. The harness ships its own crashing verifier and must catch it
first: it does, on 7 of the 8 mutations of the field that verifier mishandles (the eighth is `{}`, which really does
have the method it calls), and the gate is that exact number, not "at least one" — a detector degraded to seeing a
single crash out of eight would pass a laxer test. Below that, it exits 2 without measuring anything.

**What the numbers do NOT cover,** stated so nobody reads them as more than they are. The third stack has no notion of
the container (digest, bindings, producer signature, RFC 3161, policy, key provenance, and the `resolved_claims` the
file records), so **38 packs** this repository refuses at the file level and **16 artifacts** it refuses at a layer
the third stack has no notion of (key provenance, the `resolved_claims` the file itself records, and since 1.4.0 the
closed objects of SPEC §9.1) have no
third-stack opinion at all; **2 more artifacts** carry a key block that is not a key (`null`, or a `jwk` that is a
list), so there was nothing to hand over and they are counted on their own line rather than vanishing from the
denominator; **6 artifacts** are refused under the §3.1 profile this repository
declares stricter than the RFC; on **7 packs** the KB-JWT's `aud`/`nonce` cannot be read, so its binding could not be
compared (where they can be read they are passed through, so the third stack checks the key-binding signature and its
`sd_hash` too — feeding a token its own `aud`/`nonce` validates them against nothing, which is what the sealed scope
already says); and **3 hostile files** this bench cannot even read (a BOM, a 100000-deep nesting, a raw non-UTF-8
byte). Of the six verification steps of SPEC §6, this bench covers the signature and the disclosure resolution inside
step 2 — not the §3.1 profile, not `claims_match`, not the KB-JWT expectations, not the provenance reconciliation.

**One declared divergence, with its clause.** On a presentation carrying a disclosure that matches no digest, this
repository refuses and the third stack accepts, returning a payload with the claim dropped. RFC 9901 §7.1 step 5: *"If
any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other
Disclosures), the SD-JWT MUST be rejected."* No forged claim passes either way — the divergence is the verdict, not the
content. Three further cases are not a defect of anyone: they are where the RFC's own verification algorithm ignores what its
structural MUSTs require. `_sd` that is not an array of strings (§4.2.4.1: *"The _sd key MUST refer to an array of
strings"*) and an array placeholder whose value is not a digest string (§4.2.4.2: *"The value MUST be the digest of the
Disclosure"*) are MUSTs addressed to the Issuer — and §7.1 step 3.b collects only well-formed `_sd` arrays and
`{"...": string}` objects, then step 3.e removes every `_sd` key, so ignoring the malformed part is exactly what the
RFC prescribes to a verifier. This repository rejects instead: a stricter choice of this format, not a third-party
defect. Measured, with the third stack's own returned payload printed by the bench: a malformed `_sd` (`{}`, `[1]`)
leaves `{"iss": "x"}`, while `{"...": [1]}` comes back inside the verified payload as `{"a": [{"...": [1]}], "iss":
"x"}` — an ordinary array element, per §7.1 step 3.b.ii, and issuer-signed content, so not an unauthenticated
injection. `_sd: null` is refused by BOTH.

Independent implementations (any language): open a PR to be listed here.

## Tests

```bash
python3 test_ap2_evidence.py      # negative controls first — the bench can fail
python3 test_ap2_conformance.py   # conformance vectors + ACVP ML-DSA-65 + signature suite + acceptance profile + CLI grammar + JS agreement
python3 test_ap2_schema_mutants.py     # closed schema (SPEC §9) under generative mutation, both verifiers, quick subset
python3 test_ap2_closed_schema_gaps.py # closed schema: the cases the generative bench does not derive (optional keys, present, KB record, report order)
python3 verifiers/schema_mutants.py --full   # the release measurement (12 818 mutations); --py-root/--js point it at an older checkout = positive control
python3 verifiers/differential_oracle.py   # Python vs Node on every vector, hostile file and CLI case (needs node)
verifiers/lax_python_ablation.sh           # the strict layers removed from a copy of the reference -> the suite must be red
AP2_SDK_PATH=... python3 verifiers/sdk_crosscheck.py --hostile   # a third stack, written by other people, on the same tokens
```


## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/ap2-evidence-pack/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with payment networks, PSPs and wallets that need offline dispute evidence for AP2 mandates. Write with the use case; the answer says what is measured and what is not.
- **Licence**: Apache-2.0: use it freely, also in closed products. If you build on it, a note in Discussions helps the roadmap (and tells the author the work is used).
- **Citation**: DOI [10.5281/zenodo.22539659](https://doi.org/10.5281/zenodo.22539659) (Zenodo, concept DOI: always the latest version).
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## License

Apache-2.0 — © 2026 Roberto Locatelli. Built to be contributed to / aligned with the
AP2 ecosystem; feedback and adaptation requests welcome.

## Disclaimer

This is an independent, third-party tool. It is **not affiliated with, endorsed by, or
sponsored by Google** or the AP2 / Agent Payments Protocol project; "AP2" is used solely
to describe the protocol this tool interoperates with. The software is provided **"AS IS"**,
without warranties or conditions of any kind, and with no acceptance of liability, as per
the Apache-2.0 license (§7–8). Nothing in this repository is legal advice, and no
representation is made that any output constitutes admissible or sufficient evidence in
any legal or regulatory proceeding.

## Versioning

Within 1.x these do not change: `build_evidence(artifacts, out_path)`, `verify_evidence(path)` → dict with `valid` and,
when false, `refused`; the CLI `ap2-evidence build|verify` and its exit codes (0 valid, 1 otherwise). Wheel layout,
dependency floors and new refusals may change in a minor release and the changelog says so. A change to the three above
is 2.0.

cryptovalid-opencore >= 0.18.0 depends on this package (its `ap2` extra) and ships no copy of it; the
`downstream-cryptovalid` CI job runs its AP2 suites against the wheel built from every change here (first run green on
2026-10-05, run 37287815388).

## Install (pip)

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ ap2-evidence-pack
```

Installed beside PyPI's `pqcrypto` package? Fine since 1.3.0: this wheel ships its signature suite as `ap2_pqcrypto/`
(the clone keeps `pqcrypto/`). 1.2.2 and earlier overwrote that package's `__init__.py`. Requires `cryptography >= 48`
(ML-DSA-65).

Release artifacts are attached to GitHub Releases; the index links carry `#sha256=` fragments verified by pip. All documented `python3 <file>.py` commands keep working unchanged from a clone.
