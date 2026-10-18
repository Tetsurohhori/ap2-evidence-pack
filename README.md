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
        [--key name=jwk.json] [--jwks-url name=https://...] [--tsa http://tsa.example]...   # 1.5.0: --tsa may repeat
python3 ap2_evidence.py stamp evidence.json --tsa http://tsa2.example   # 1.5.0: add one more time anchor to an existing pack

python3 ap2_evidence.py verify evidence.json     # offline, fail-closed; exit 0/1 (74: a check not run here, with the receipt, or the receipt not written)
python3 ap2_evidence.py verify evidence.json --trusted-producer-key ed25519=<b64> --trusted-producer-key ml-dsa-65=<b64> --require-pq --require-anchor   # relying-party policy (1.1.0)
python3 ap2_evidence.py verify evidence.json --min-anchors 2 --tsa-cert tsa-bundle.pem   # 1.5.0: two distinct anchors, each TSA-verified
python3 ap2_evidence.py verify evidence.json --trusted-producer-key ed25519=<b64> --trust-set-complete   # 1.6.0: the pinned set is complete
node verifiers/js/ap2-verify.mjs evidence.json   # the independent verifier, same flags and exit codes (limits below)
```

**Reading the verdict (1.6.0, SPEC §6.9).** Beside the twelve fields of §6 every receipt states `admission`
(`admitted`, or `refused` with a `refusal_class`: `format_unsupported`, `unknown_member`, `malformed`), and for an admitted
pack `states` — one state per subject (`sealed_content`, `holder_binding`, `time_anchor`, `producer_signature`,
`issuer_identity`), each `verified`, `contradicted` or `not_evaluated` with its `reasons` (vocabulary
`ap2-evidence-pack/states-1`, aligned with draft-krausz-verification-state-03, work in progress) — and `policy`
(`met`, and the requirements `unmet`). `not_evaluated` is never a pass and never tampering: `key_unresolved` (a producer
key outside your pinned set) is not `signature_invalid`, `tsa_not_checked` is a binding a self-issued token satisfies,
`instrument_failure` is this machine, not the pack. A refused pack carries `digest_ok: false` by construction: read
`admission` first. SPEC §10 is the reading for a relying party (with the mapping to ACP SEP #303 §7.4a).

Exit 74 (1.5.2): when the receipt cannot be written whole to stdout (`/dev/full`, a file that cannot grow under
`ulimit -f`, a reader that closed the pipe before the receipt was in it, stdout closed with `>&-`), `build`, `stamp` and
`verify` exit 74 whatever the outcome, with one line `receipt not written: <reason>` on stderr; `build` and `stamp` do the
same when they cannot write the pack itself. The same holds with `-u` or `PYTHONUNBUFFERED=1`. Bytes the pipe has taken
count as written: a reader that closes later (`| head -c 100` on a small receipt) is not seen. A stdout or stderr that is
a non-blocking pipe and full is waited for, as a blocking one would be, never reported as lost; in process, text the
caller left in `sys.stdout`'s buffer goes first and is waited for too. A refusal (1) or a usage message (2) that stderr
does not take (`2>/dev/full`, `2>&-`) is 74 too, and nothing goes to stdout. After a `stamp` that exits 74, the stderr
line says which: a reason ending `not stamped` (the pack could not be written, or, since 1.5.3, openssl could not be
started or did not answer for the query) leaves the pack unchanged, any other reason means the pack
holds the new anchor and only the receipt was lost (verify the pack before stamping again).
`build` writes the pack to a new file with an unpredictable name, created exclusively in the same directory, and renames
it onto the path only when it is whole, so a failed `build` leaves an earlier pack at that path as it was; a path that is
not a regular file (`/dev/stdout`, a FIFO) is written directly, and an existing pack in a directory this process cannot
write is now 74 (1.5.1 rewrote it in place). `pqcrypto.sigsuite.ProducerIdentity.save` writes the key file the same way,
mode 0600; a key file this process may not write (`chmod 400`) is refused with `PermissionError` and left as it was, as
in 1.5.1. A check asked for that cannot be run on this machine is 74, never a verdict: `verify --tsa-cert` and
`--trust-anchor` when the files openssl reads cannot be written (`cannot write a temporary file for openssl`), or when
openssl cannot be started, is killed by a signal (1.6.0) or gives no answer within its time limit (`cannot run openssl
here`). Since 1.6.0 that 74
comes WITH the complete receipt on stdout — the subject of that check `not_evaluated/instrument_failure`, the others
evaluated — and one line `check not run here: <reason>` on stderr (1.5.2–1.5.4: no receipt); the library raises
`Ap2WriteError` carrying that receipt in `.receipt`. A complete JSON on stdout is this case; nothing or a cut JSON is a
receipt not written (SPEC §6.10). openssl absent is not this case and is unchanged: the field is `null` (not measured),
the subject `not_evaluated/instrument_failure`, and `--require-anchor` / `--min-anchors` do not count that anchor (exit 1
when the policy needs it).
What the JS verifier cannot see: with stdout or stderr closed (`>&-`, `2>&-`) Node reopens the descriptor on `/dev/null`
and the write succeeds, so the exit is the verdict's 0/1 (2 for usage); the Python CLI exits 74 there. In process, after
text the caller wrote to a `utf-8-sig` pipe, the receipt carries a second byte order mark (the command line never does).
Measured on Linux only; Windows and macOS are not measured (on Windows Python's `select` waits on sockets only, so a full
non-blocking pipe there would be 74).

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
expired signing certificate still counts years later); the Node verifier cannot validate chains and,
since 1.6.0, refuses `--trust-anchor` as a usage error (exit 2) instead of accepting it and reporting `chain_verified: null`. A cleared flag says a CA under your anchor certified that key — not
that the key belongs to the mandate's issuer; read `artifacts[].x5c_leaf` for the subject and issuer
DN of the certificate that was validated.

## Producer signatures (post-quantum hybrid)

`sign_evidence(...)` adds a **hybrid producer signature** over the pack digest — a
classical signature (ed25519 or ecdsa-p256) plus **FIPS 204 ML-DSA-65** — so the pack's
integrity/authenticity survives the quantum transition (NIST IR 8547). Verification is
fail-closed; authenticity requires the relying party to **pin** the producer public keys
out of band (an embedded key proves consistency, never authenticity). Policy flags on
`verify_evidence`: `require_producer`, `require_pq`, `require_anchor`, and since 1.5.0 `min_anchors`. The ML-DSA-65
path is checked against a NIST ACVP sigVer subset (`pqcrypto/vectors/`) — the same nine
cases the elara-mesh verifier runs, so both stacks answer to one set of NIST-published ACVP vectors — a local check
against public test data, not a NIST validation.

## More than one time anchor: `anchors` (1.5.0, SPEC §3.3)

One RFC 3161 token depends on one TSA key, which ages. Until 1.4.x a pack could not carry a second one: a new top-level
key changed the digest, and inside `rfc3161_timestamp` it was refused (1.4.0) or, before that, ignored. Since 1.5.0 a pack
may carry `anchors`, a non-empty list OUTSIDE the digest; each entry names its `mechanism` (this revision defines
`rfc3161`: `tsr_b64`, optional `tsa_url`, `note`) and is a closed object. What the verifiers do with it:

- every entry is checked like the `rfc3161_timestamp` token against the recomputed digest; a claimed anchor whose BINDING
  fails rejects the pack (an anchor is never ignored because another one verifies); under `--tsa-cert`, an anchor whose
  TSA signature does not verify is not counted (the same rule as the `rfc3161_timestamp` token): it does not reject the
  pack by itself, only through a `--min-anchors` / `--require-anchor` policy it then fails to meet;
- a `mechanism` this revision does not define, an unknown key, an empty list: a refusal that names it;
- `anchors_verified` (a new normative field) counts the DISTINCT anchors that verify — the token in
  `rfc3161_timestamp` included; two anchors are the same when the TSTInfo the TSA signed is the same, so a copied token
  is one anchor however it is re-wrapped; under `--tsa-cert` (a PEM file may hold several TSAs)
  only TSA-verified anchors count; `--min-anchors N` is the relying party's policy (`--require-anchor` alone is 1);
- distinct tokens of the SAME TSA count as two: they share that TSA's key, so the count does not establish that they
  fail independently — a relying party that needs that reads each entry's TSA and `gen_time` (declared).

`ap2_evidence.py build … --tsa A --tsa B` puts A's token in `rfc3161_timestamp` (so a pack with one TSA is still read by
1.4.x) and the others in `anchors`; `ap2_evidence.py stamp pack.json --tsa C` (one `--tsa` per run) adds one to an existing pack — from a second TSA,
or a later token from any TSA — after checking that the sealed content still matches its digest;
the digest and the producer signatures do not change. Only RFC 3161 is defined here; another mechanism (an OpenTimestamps
proof, a renewal chain in RFC 4998 form) would be a new revision of the SPEC, not something a verifier skips. A pack that
carries `anchors` needs a 1.5.0 verifier: 1.4.x refuses the unknown top-level key, as its own SPEC §9 requires. Each
token commits to the pack's digest, not to the anchors already there, so a token added later proves existence from its
own time only: it is not an RFC 4998 renewal (corrected after the 1.5.0 release, see CHANGELOG).

## Conformance (normative)

The format is defined by `SPEC_AP2_EVIDENCE.md` plus the test vectors in
`spec/vectors/ap2/` — seven ACCEPTs (`valid_signed`, the positive control; `anchor_valid`,
a real RFC 3161 token from a probe TSA whose certificate ships beside it; and, since 1.4.0,
`header_param_ignored`, `kb_jwt_valid`, `key_jwk_member_ignored`; since 1.5.0 `anchors_two_valid` and `anchors_only`)
and twenty-two REJECTs
(stripped-signature downgrade, valid-but-unpinned producer key, digest mismatch, time
anchor required-but-missing, time anchor claimed-but-invalid, a real token issued for
another digest; since 1.4.0 an unknown key at the top level / inside the anchor block / inside
an artifact entry / inside a producer-signature entry, a `crit` nobody understands, and a
KB-JWT without `typ: kb+jwt`; since 1.5.0 seven `anchors` cases of SPEC §3.3, the three refusals pinned to their exact
text; since 1.5.4 three producer blocks that do not verify, SPEC §5); since 1.6.0 thirteen more, one for each cell of
the SPEC §6.9 states table the others did not reach (`holder_*`, `sealed_binding_mismatch`, `time_*`, `producer_*`,
`issuer_x5c_*`; five of them under `--tsa-cert` or `--trust-anchor`, which need openssl), and every expected file carries
the `states` block a verifier must reproduce. 1.6.0 changes the twelve fields of two vectors (an unknown key inside an
artifact entry or a producer-signature entry is now a refusal, SPEC §9.1): a verifier conformant to 1.5.x is not
conformant to 1.6.0 on those two. An independent verifier
claims conformance by reproducing each vector's `normative` block under its declared
policy, from the spec text alone. Since 1.5.4 the vectors whose verdict needs an ML-DSA-65 backend say so
(`"requires_backend": ["ml-dsa-65"]` in their `.expected.json`, SPEC §7; twelve in 1.5.4, twenty-one in 1.6.0): a verifier
without that backend reports them SKIP, not as disagreements, and does not claim them. Which ones is measured — the reference run with and without its
backend — and the test suite repeats the measurement:

```bash
python3 spec/vectors/ap2/run_ap2_conformance.py   # exit 0 = conformant
```

| Implementation | Runtime / deps | Status |
|---|---|---|
| `ap2_evidence.py` | Python 3 + `cryptography`; `openssl` for `--tsa-cert` / `--trust-anchor` | reference — conformant 42/42 (1.6.0); ACVP ML-DSA-65 sigVer 9/9 |
| `verifiers/js/ap2-verify.mjs` | Node with OpenSSL ≥ 3.5 for ML-DSA-65 (measured: Node 22.23.2 / OpenSSL 3.5.7 locally, Node 24 in CI), `node:crypto` only; on an older build ML-DSA-65 is SKIP = incomplete, never a pass, and the ML-DSA vectors are not measured (the JS conformance test skips, it does not pass); no TSA signature check — `tsa_verified` null, `time_anchor` `instrument_failure`; no x5c chain validation — `--trust-anchor` is a usage error (1.6.0) | independent — conformant on 36/42 on every normative field, the `report` and the `states` block, through `run_ap2_conformance.run(verify_fn=…)` (`test_ap2_conformance.py`); the 6 vectors whose `requires` lists openssl are SKIP (1.6.0: the five under `tsa_cert` / `trust_anchor`, and `anchor_invalid`, which the differential oracle runs in both verifiers) |

**Closed schema (1.4.0, SPEC §9; 1.4.1).** Measured on 1.3.0 on 2026-10-10: a key nobody had defined, written inside
`rfc3161_timestamp`, `producer_signatures` or a `signatures[i]` entry, was `valid: true` in both verifiers with nothing in
the receipt. Every object this format defines is now an exhaustive key list — unknown key, wrong type or missing MUST is a
refusal / artifact error / FAIL entry that names the key (a signature entry's FAIL names it since 1.4.1; since 1.6.0 an
unknown key is a refusal in every one of these objects, `refusal_class: unknown_member`) — and every object a standard defines (JOSE header, JWK, `cnf`,
KB-JWT) follows that standard's rule for the unknown (ignored) and REPORTS the ignored names in `artifacts[i].ignored`;
`crit` makes the JWS invalid (RFC 7515 §4.1.11). The proof is generative: `verifiers/schema_mutants.py` derives from every
vector and from freshly signed packs 12 818 mutations at every level of every object (unknown keys in eight spellings and
every value type, every known key of every hostile type and deleted, duplicate keys, key order, escaped spellings, `crit`,
KB-JWT claims, out-of-grammar files), computes each one's expected class from the SPEC tables and holds both verifiers to
it and to each other: 12 818/12 818, 0 disagreements on 1.4.0; on the 1.3.0 verifiers the same corpus passed SILENTLY
8 186 times in both, with the two agreeing on every one (CHANGELOG 1.4.0). 1.5.0 adds `anchors` to the tables: 16 503
mutations from 37 sources, each with its class in both verifiers, 0 disagreements on 16 540 files (measured 2026-10-11).
1.6.0 (an unknown key in an artifact entry or a signature entry is a refusal, `refusal_class: unknown_member`): 23 486
mutations from 59 sources, each with its class in both verifiers, 0 disagreements on 23 545 files; with that refusal removed
from a copy of the reference, 2 520 miss their class (measured 2026-10-18). The quick subset (5 660) runs in CI.
`verifiers/states_controls.py` (1.6.0) runs the same corpus through the controls of the states (SPEC §6.9): no
`contradicted` without a check that ran and failed, no `verified` over a check that did not run, the `valid` equation,
pinned sets that never create a contradiction — 22 967 receipts, 0 violations; each of six deliberately broken rules of
the derivation turns it red.

**Differential oracle** (`verifiers/differential_oracle.py`, 22/09/2026): the two verifiers must
give the same `(valid, digest_ok, bindings_ok, producer_ok, pq_protected, rfc3161_verified,
policy_ok, producer_present, producer_trusted, rfc3161_claimed/granted/imprint_ok/gen_time, chain_verified,
self_asserted_only, provenance_classes, and the `x5c_leaf` identity of every artifact)`
— the normative fields of SPEC §6 (twelve since 1.5.0: `anchors_verified`) plus `rfc3161.granted`, `rfc3161.imprint_ok`, `rfc3161.gen_time`,
`chain_verified`, `provenance_classes`, the `x5c_leaf` identity and, since 1.5.0, each `anchors` entry and the refusal
text where SPEC §9.1/§3.3 fix it — on the vectors under their declared policy (29 up to 1.5.4, 42 since 1.6.0; plus `anchor_valid` under
`--require-anchor --tsa-cert`, `anchors_two_valid` under `--min-anchors 2` with a bundle of both probe TSAs and with
the first TSA alone, and the CA-issued `x5c` leaf under `--trust-anchor`), 117 hostile files that carry the digest a lenient verifier would
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
Re-measured 2026-10-18 on 1.6.0, which also compares `admission`, `refusal_class`, the state and reasons of every subject
and `policy`, and passes the vectors' `tsa_cert` / `trust_anchor` / `trust_set_complete`: **185 cases, 0 disagreements, of
which 12 are declared divergences** (`45 vector runs + 117 hostile files + 4 positive controls + 19 CLI cases = 185`; the
six new declared ones have the one cause of the others — TSA and chain checks are openssl-only: the five 1.6.0 vectors
under `--tsa-cert` / `--trust-anchor`, where JS states `instrument_failure` or gives a usage error, and the self-forged
token under `--tsa-cert`, now `tsa_invalid` in the reference and `instrument_failure` in JS); a copy of the JS verifier with
one reason renamed (`tsa_not_checked`) gives 8 disagreements on the same run.
Re-measured 2026-10-18 on 1.5.4: **172 cases, 0 disagreements, of which 6 are declared divergences**
(`32 vector runs + 117 hostile files + 4 positive controls + 19 CLI cases = 172`: the three 1.5.4 vectors); against the
1.5.3 JS verifier the same run reports 10 disagreements, the three new vectors and seven hostile producer blocks whose
`producer_trusted` or `pq_protected` 1.5.4 changes. Re-measured 2026-10-11 on 1.5.0: **169 cases, 0 disagreements, of which 6 are declared divergences**
(`29 vector runs + 117 hostile files + 4 positive controls + 19 CLI cases = 169`; the two new declared ones are the same
cause — `anchors_two_valid` under `--tsa-cert`, which only the reference can check). On 1.4.0:
**158 cases, 0 disagreements, of which 4 are declared divergences** (measured 2026-10-10 on 1.4.0; the run prints its own
decomposition — `18 vector runs + 117 hostile files + 4 positive controls + 19 CLI cases = 158` — so these numbers are
copied from that line rather than counted by hand, which is how several of them went stale during the
review rounds; this very sentence had gone stale once more, and was caught by the final check) — the real token under `--tsa-cert`, where the
reference proves the TSA with openssl and the JS verifier reports `tsa_verified: null` and does
not pass the policy; and the three packs under `--trust-anchor` — the CA-issued leaf, the self-signed leaf and the mixed
mandate-plus-chained pack — whose chains the reference validates with `openssl verify` (clearing `self_asserted_only` for
the CA-issued one) while the JS verifier cannot: it reported `chain_verified: null` up to 1.5.4 and since 1.6.0 refuses
`--trust-anchor` as a usage error, which is what the oracle now declares. A crash counts as a disagreement, and a declared divergence that stops
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

Re-measured 2026-10-18 on 1.6.0 (same SDK commit, `sd-jwt` 0.10.4, Python 3.11), vectors plus the hostile corpus: 160 packs
seen, 42 refused before the mandate layer, **177 artifacts compared, 122 claim-sets compared, 0 undeclared
disagreements**, and **one declared divergence in the direction "we accept, the third stack refuses"**:
`holder_key_unknown` (below, with its clause). The first CI run of 1.6.0 (run 39135564764) was red on the bench itself:
1.6.0 turned an unknown key in `artifacts[i]` into a refusal of the whole pack, the bench still read it from the
artifact's own `error`, and two of its positive controls (4 and 7) could no longer see it; the bench now maps that
refusal back onto the artifact before comparing (CHANGELOG 1.6.0). Re-measured 2026-10-11 on 1.5.0, vectors plus the hostile corpus: 144 packs seen, 41 refused before the mandate layer,
**154 artifacts compared, 102 claim-sets compared, 0 disagreements** on a rule the RFC puts on the verifier, none in the
direction "we accept, a third implementation refuses" on 1.5.0 (AP2 SDK `e1ea56db72a6`, `sd-jwt` 0.10.4). Earlier the same day on 1.4.0
(same SDK, `sd-jwt` 0.10.4), on the seventeen vectors alone: **26
artifacts compared, 23 claim-sets compared, 0 disagreements** (two packs are refused before the mandate layer and one
artifact at a closed object of SPEC §9.1, which the third stack never sees). Vectors plus the hostile corpus together:
**142 artifacts compared (26 from the vectors, 116 hostile), 90 claim-sets compared, 0 undeclared disagreements**. The three file-object cases of the oracle (a FIFO, a symlink to
`/dev/zero`, a directory) are not handed to this bench, which counts and prints them apart. And, on 1.4.0, **none in the direction
that would matter most — nothing this repository accepts and the third stack refuses** (on 1.6.0 there is one, declared:
`holder_key_unknown`, above). One word needs care in that sentence: "refuses", for the third stack, means "raises". Of
its 19 refusals on 1.4.0 (22 on 1.6.0: 11 and 11), 8 are deliberate and carry a message, and 11 are uncaught internal errors (`JSONDecodeError`,
`'str' object has no attribute 'get'`, a failed tuple unpack). Fail-closed in effect, but not a verdict, and the bench
prints that split rather than hiding it inside a total. The buckets that decide what counts as a disagreement at all
are this repository's own; the one direction never bucketed away by a reason is "we accept, the third stack refuses" —
since 1.6.0 a divergence there can only be declared case by case, with its clause and conditions (control 8).

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
which stays this repository's own. Since 1.6.0 a fifth (control 8) holds the declaration of a divergence in the direction
"we accept, the third stack refuses": the declared case must be printed apart, and five variants of it — another case
with the same reason, the same case with another third-stack reason, our KB-JWT verified, our KB-JWT absent, an issuer
carrying `cnf.jwk` — must each stay a disagreement. A control 9 holds the mapping of the 1.6.0 pack
refusal: with an unknown key in every entry, each entry carries the §9.1 error and verifies underneath once the others'
unknown keys are removed; a refusal that survives the removal (an unknown key in a producer-signature entry) stays a
refusal. The summary line counts the declared case apart from the undeclared ones.

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
file records), so **42 packs** (1.6.0, 2026-10-18) this repository refuses at the file level and **16 artifacts** it refuses at a layer
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

**Two declared divergences, each with its clause.** On a presentation carrying a disclosure that matches no digest, this
repository refuses and the third stack accepts, returning a payload with the claim dropped. RFC 9901 §7.1 step 5: *"If
any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other
Disclosures), the SD-JWT MUST be rejected."* No forged claim passes either way — the divergence is the verdict, not the
content. The second goes the other way. `holder_key_unknown` carries a KB-JWT while the issuer payload has no `cnf.jwk`:
this repository accepts the pack and states `holder_binding` `not_evaluated`/`holder_key_unknown` (SPEC §6 step 2: the
KB-JWT is recorded as unverifiable and never fails the pack by itself); the third stack, which this bench asks with the
KB-JWT's own `aud`/`nonce` — i.e. as a verifier that requires key binding — raises *"No holder public key in SD-JWT"*.
RFC 9901 §7.3 makes that a verifier-policy question, not a rule: step 1, *"Determine if Key Binding is to be checked
according to the Verifier's policy for the use case at hand"*; step 5 (*"If Key Binding is required: a. Determine the
public key for the Holder from the SD-JWT"*) and the abort that follows a failed step apply only under that policy; and
§9.5, *"Verifiers MUST decide whether Key Binding is required for a particular use case before verifying a credential."*
This format verifies offline, cannot validate `aud`/`nonce`/`iat` (§7.3 steps 5.e/5.f) and does not require key binding;
a relying party whose policy does reads `not_evaluated` as not met. The bench declares it with every condition checked
on the artifact, so any other divergence in that direction still turns it red. Three further cases are not a defect of anyone: they are where the RFC's own verification algorithm ignores what its
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

- [`aos-standard/catalog` `docs/runs/ap2-evidence-pack-cold/`](https://github.com/aos-standard/catalog/tree/main/docs/runs/ap2-evidence-pack-cold) — Python, written from `SPEC_AP2_EVIDENCE.md` only (reference and JS verifiers not opened); `cryptography` for ES256/Ed25519/P-256, the `openssl` 3.6 binary for ML-DSA-65. Verifier `ap2_cold_verifier.py` sha256 `638bb3b7…a9beb5`, run at catalog `556b982` against vectors `f03abbc` (1.5.3): 26/26 (first scored run 25/26, one check reordered); unchanged, against `c08128e` (1.5.4): 29/29, 0 SKIP (`ADDENDUM-c08128e.md`, catalog `1ddaa1c`). Does not read `requires_backend`: on a host without ML-DSA-65 it reports the twelve marked vectors as disagreements, not SKIP.

## Tests

```bash
python3 test_ap2_evidence.py      # negative controls first — the bench can fail
python3 test_ap2_conformance.py   # conformance vectors + ACVP ML-DSA-65 + signature suite + acceptance profile + CLI grammar + JS agreement
python3 test_ap2_schema_mutants.py     # closed schema (SPEC §9) under generative mutation, both verifiers, quick subset
python3 test_ap2_closed_schema_gaps.py # closed schema: the cases the generative bench does not derive (optional keys, present, KB record, report order)
python3 test_ap2_anchors.py            # 1.5.0: stamp / build --tsa repeated with a real local TSA, anchor identity, the earliest gen_time, --min-anchors in both verifiers
python3 verifiers/schema_mutants.py --full   # the release measurement (16 503 mutations in 1.5.0); --py-root/--js point it at an older checkout = positive control
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
when false, `refused`; the CLI `ap2-evidence build|verify` (1.5.0 adds `stamp`) and its exit codes (0 valid or done, 1 not valid or refused, 2 a usage error). Wheel layout,
dependency floors and new refusals may change in a minor release and the changelog says so. A change to the three above
is 2.0, with one exception, made in 1.5.2 and extended in 1.5.3 to one case: exit 74 when the receipt, the pack, a refusal or a usage
message could not be written whole, or when `--tsa-cert` or `--trust-anchor` could not write the temporary files openssl
reads, could not start openssl or had no answer from it in time (`verify_evidence` then raises `Ap2WriteError`); in 1.5.3,
when `stamp` could not start the openssl that makes its query or had no answer from it in time (`add_anchor` raises
`Ap2WriteError`; 1.5.2 refused it, exit 1). 1.5.1
exited there with 120, with 1 and a traceback (a valid pack included), with 1 as a refusal (`stamp`) or as "not valid"
(`--tsa-cert`, `--trust-anchor`), with 0 and `"tsa_verified": false` or `"chain_verified": false` for a check never
completed (`--tsa-cert` with no anchor policy, `--trust-anchor`; openssl not started or too slow), or with the verdict's
0/1 or the usage 2 while the output was lost or went to stdout.

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
