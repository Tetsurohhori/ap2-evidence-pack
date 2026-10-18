# Changelog

## 1.6.0 — 2026-10-18 — one closed field per question: admission, states, policy

A relying party (a dispute provider, an auditor) used to read the verdict off twelve booleans and their combinations, and
several combinations meant two things: a refusal had `digest_ok: false` like a tampered pack; a producer signature that
could not be checked (`SKIP`) looked like one that failed; `null` meant "nothing claimed" in one field and "not checked
here" in another; exit 74 meant both "a check could not run here" and "the receipt was not written". 1.6.0 adds, in both
verifiers, one closed field per question (SPEC §6.9), defined in this SPEC with the immutable identifier
`ap2-evidence-pack/states-1` and aligned with draft-krausz-verification-state-03 §3.1, §3.3, §5.4.2 (work in progress).
The twelve fields of §6 keep their meaning.

**Not additive** (a verifier, a reader or a runner of 1.5.x sees these differences):

1. **An unknown key inside `artifacts[i]`, its `key`, `kb_jwt` or `verified_at_build`, or inside a
   `producer_signatures.signatures[i]` entry is a refusal** (`refusal_class: unknown_member`, SPEC §9.1), as in every other
   object of §9.1. 1.4.0–1.5.4 made it an artifact error or a FAIL entry, which the twelve fields showed as an altered
   artifact or a failed signature. The twelve fields of two vectors change (measured on the reference, 2026-10-18):
   `unknown_key_artifact` — `digest_ok` and `policy_ok` true → false; `unknown_key_producer_entry` — `digest_ok`,
   `bindings_ok`, `policy_ok` true → false, `producer_present` true → false, `producer_ok` false → null. (The design of
   this release listed the other changes but not `policy_ok`: a refusal receipt has `policy_ok: false`.) `valid` and the
   exit code (1) change on no pack: such a pack was never valid. A 29/29 conformance to 1.5.x is not conformance to 1.6.0.
   Only the unknown-key rule moves; a wrong type or a missing key stays an artifact error / FAIL entry, and the objects
   of §9.2 keep their standard's rule (`header_param_ignored`, `key_jwk_member_ignored` stay valid; an unknown `crit`
   stays the artifact's error).
2. **Exit 74 for a check that could not be run here comes with the complete receipt** (SPEC §6.10): openssl that cannot be
   started or does not answer, or temporary files openssl needs that cannot be written, under `--tsa-cert` or
   `--trust-anchor`. 1.5.2–1.5.4 wrote no receipt; now stdout holds the receipt (that subject
   `not_evaluated/instrument_failure`, the others evaluated) and stderr one line `check not run here: …`. A receipt that
   cannot be written stays 74 with `receipt not written: …` and no complete JSON: the reader tells the two apart by the
   receipt. The library still raises `Ap2WriteError`, now carrying the receipt in `.receipt`. openssl ABSENT is unchanged
   (exit by `valid`, the field `null`; the subject says `instrument_failure`).
3. **The JS verifier refuses `--trust-anchor`** (exit 2, usage): it cannot validate x5c chains, and 1.1.0–1.5.4 accepted the
   flag and did nothing with it (`chain_verified: null`). Under `--tsa-cert` it states `time_anchor`
   `not_evaluated/instrument_failure` (it counted no anchor before too: fail-closed, now named).
4. **The expected files** carry a required `states` block and may carry the policy keys `trust_set_complete`, `tsa_cert`,
   `trust_anchor` (SPEC §7); a 1.5.x runner stops on them (closed format, exit 2). `requires_backend` is on 21 vectors (12
   in 1.5.4): `digest_mismatch` and the three `producer_*_fails_*` vectors, whose `states` block depends on the ML-DSA-65
   backend, and five of the new vectors — measured with `make_vectors_154.py --declare-backend`.

**Added:**

- `admission` (`admitted` / `refused`) with `refusal_class` (`format_unsupported`, `unknown_member`, `malformed`);
  `states_vocabulary`; `states` — five subjects (`sealed_content`, `holder_binding`, `time_anchor`, `producer_signature`,
  `issuer_identity`), each `{state, reasons, detail?}` with the precedence contradicted > not_evaluated/instrument_failure
  > other not_evaluated > verified; `policy` — `{met, unmet}`. A refused pack has `states` and `policy` `null`.
- `producer_signatures.ok` is always present (`null` without a producer block, and on every refusal): the 1.5.4 reference
  wrote no such key on 12 of the 29 vectors (measured 2026-10-18, no policy flags).
- `--trust-set-complete` / `trust_set_complete=True` (both verifiers): the pinned set is declared complete; a
  `key_unresolved` producer key then also puts `trust_set_complete` in `policy.unmet`. Never a failed signature; `valid`
  unchanged.
- 13 vectors, one per cell of the §6.9 table the others did not reach (`make_vectors_160.py`, whose `states` blocks are
  written by hand from the table and checked against the reference with `--check`: 0 differences), and the `states`
  block of the 29 earlier vectors (`--states`, from the reference, reviewed one by one in the release report).
- `verifiers/states_controls.py` and `test_ap2_states.py`: the pre-registered controls of the design, generative over the
  schema-mutant corpus under four pinned-set inputs — no `contradicted` without a check that ran and failed, no `verified`
  over a check that did not run, the `valid` equation of §6.9, pinned sets that never create or remove a contradiction —
  22 967 receipts, 0 violations; each of six deliberately broken rules turns it red. On the same 22 967 inputs `valid`
  equals the 1.5.4 verifier's on every one (`--old`; `trust_set_complete` is not passed to 1.5.4, and no input of the
  bench sets it).
- SPEC §10 (informative): reading a receipt as a relying party, with the mapping of the 1.6.0 fields to ACP SEP #303
  §7.4a at commit 6710a3a and an informative mapping to draft-xg-payment-dispute-profile-01.

**Found by the bench before release:** the first draft of the derivation stated `sealed_content: verified` on packs whose
KB-JWT failed, where §6 step 3 sets `bindings_ok: false` without recomputing the binding set — `verified` over a check that
had not run (89 receipts). The binding set is now recomputed for the state whenever every artifact's signature and claims
verified. The pre-registered equation for `valid` (every subject, no `SKIP` term) does not hold on two vectors and is
corrected in SPEC §6.9: `issuer_x5c_chain_broken` (a chain never decided `valid`) and `producer_backend_missing` (a `SKIP`
entry makes the block not `ok` with no check failed).

Measured on 2026-10-18 (Python 3.11.2, cryptography 50.0.1, OpenSSL 3.0.22, Node 22.23.2): conformance 42/42 (reference),
37/42 + 5 SKIP (JS: the vectors that need openssl); differential oracle 185 cases, 0 disagreements, 12 declared; schema
mutants (full) 23 486 mutations, 0 unmet, 0 disagreements on 23 545 files.

## 1.5.4 — 2026-10-18 — a producer block that does not verify states no trust and no post-quantum protection

Points 2–5 below come from an independent clean-room verifier by @Tetsurohhori (aos-standard/catalog 556b982), written
from the SPEC text, which agreed with the 26 vectors of 1.5.3 and named the choices the text had left to its reader —
points 2, 3 and 4 are three of them; point 5 is what that verifier does with `pq_protected` (read in its code, not named
by it); point 1 from the measurement of the same verifier on a host whose OpenSSL has no ML-DSA-65.

1. **`requires_backend` (SPEC §7).** On a host with OpenSSL 3.0.22 that verifier agreed on 14 of the 26 vectors of 1.5.3
   (measured 2026-10-18): the other 12 are exactly the vectors whose verdict needs an ML-DSA-65 signature checked, and
   nothing in their `.expected.json` said so, so a verifier without the backend saw disagreements where the SPEC
   (§6 step 6) asks for SKIP. Those 12 now carry `"requires_backend": ["ml-dsa-65"]`. Which 12 is measured, not chosen:
   the reference run on every vector with and without its backend (`make_vectors_154.py --declare-backend`;
   `test_requires_backend_is_the_measured_dependence` repeats it). `run_ap2_conformance.py` counts them SKIP when the
   backend is absent (without it: 17 PASS, 12 SKIP, conformant) and reads the expected files as a closed format: an
   unknown key, policy key, report key or backend name, a policy value of the wrong type, a file that is not UTF-8 JSON
   or repeats a key, and a pack without its expected file (or the reverse) are errors of the vector set, exit 2, never
   ignored and never a verifier's FAIL. The key is
   new rather than a value of `requires`, which runners — ours and that verifier's — read as names of executables: a
   1.5.3 runner ignores `requires_backend`, and the same verifier's runner, unchanged, gives 17/29 on the OpenSSL 3.0
   host (12 disagreements, as before) and, with a two-line backend clause, 17 agree and 12 SKIP.
2. **Order in an `anchors` entry (SPEC §3.3).** For an entry with an undefined mechanism, the refusal naming the
   mechanism comes before the §9.1 scan of that mechanism's keys (there is no key list for an undefined mechanism).
   Both verifiers already did this; the vector `anchors_unknown_mechanism` pins it (with the two checks swapped in a
   copy of the 1.5.3 reference, it is the one vector that fails). Text only.
3. **`bindings_ok` (SPEC §6 step 3)** is `false` when any artifact fails, whatever `bindings` holds, `[]` included.
   Both verifiers already did this; `header_crit_unknown` and `kb_jwt_typ_missing` (`bindings: []`) pin it (with the
   rule removed from a copy of the 1.5.3 Python and JS verifiers, both vectors fail in each). Text only.
4. **`producer_trusted` on a block that is not `ok` (SPEC §5)** is `null`, pinned set given or not: a block that did not
   verify carries no trust statement. 1.5.3 (measured on the reference) reported `true` when every key was pinned and
   the block was not `ok` because an entry failed or `scheme` did not match the entries; `false` when a key was not
   pinned, when an entry was SKIP (an unknown `sig_alg`, or the ML-DSA-65 entry on a verifier without that backend, where
   1.5.4 turns `false` into `null` on every pinned hybrid pack, `valid_signed` included, `valid` `false` in both) or when the
   block held no entry. Vector `producer_mldsa_fails_pinned`.
5. **`pq_protected` on a block that is not `ok` (SPEC §5)** is `false`. 1.5.3 reported `true` whenever the block held a
   valid ML-DSA-65 signature whose key was pinned (or no pinned set was given), whatever made the block not `ok` — a failing classical entry, a `scheme` that did
   not match the entries, a SKIP entry (measured on the reference); and where `producer_trusted` was also `true` (every key
   pinned, the block failing through an entry or its `scheme`) `require_pq` was met and `policy_ok` was `true`.
   Vectors `producer_classical_fails_pinned` (pinned, `require_pq`) and `producer_classical_fails_unpinned`.

**Points 4 and 5 change field values only on packs that were already not `valid`**: a producer block that is not `ok`
makes the pack not `valid` (§6 step 8) in 1.5.3 as in 1.5.4, and `valid` is unchanged on every case measured. The
fields that change are `producer_trusted`, `pq_protected` and, under `require_pq`, `policy_ok`. Measured: with an ML-DSA-65
backend the 1.5.3 verifiers (Python and JS) disagree with the three new vectors (0/3 each; the 1.5.3 reference without
the backend agrees with `producer_classical_fails_unpinned` and reports `false`, not `true`, on the other two); the differential oracle with the 1.5.3 JS
verifier against the 1.5.4 reference reports 10 of 172 cases — the three vectors and seven hostile producer blocks — and
`valid` is `false` in both on all ten. `verify_producer_block` (`pqcrypto/sigsuite.py`, shipped as `ap2_pqcrypto/sigsuite.py`) returns the same keys;
callers that read its `trusted`/`pq_protected` on a block that is not `ok` see `None`/`False`.

Vector set: 29 (7 ACCEPT, 22 REJECT). The three new vectors are derived from `valid_signed.json` by changing one byte
of one producer signature and regenerate byte for byte (`make_vectors_154.py`); none of them needs an ML-DSA-65
backend under 1.5.4 (measured: they pass with and without it).

## 1.5.3 — 2026-10-17 — `stamp` that cannot start openssl is exit 74

- `stamp` asks openssl for the RFC 3161 query before it contacts the TSA. Measured on 1.5.2 (`9a85db5`, Python 3.11.2)
  under `RLIMIT_NPROC` 1, where `fork` is refused: `stamp` exited 1, the code of a refusal, with
  `{"error": "no anchor obtained: BlockingIOError: [Errno 11] Resource temporarily unavailable"}`; the pack was left
  unchanged. Nothing was decided about the pack or the TSA: the query was never made here. In 1.5.3 that openssl, and one
  that gives no answer within the timeout, go through the same path as the checks of `verify` (1.5.2): exit 74, one
  line on stderr, `receipt not written: cannot run openssl here: BlockingIOError: Resource temporarily unavailable: not
  stamped`, nothing on stdout, the pack unchanged. A TSA that answers with no token for this digest, or that cannot be
  reached, is still a refusal, exit 1, as are an openssl absent from the PATH and one that exits with an error for the
  query (as in 1.5.2). `build` with `--tsa` is unchanged: it writes the pack and records the reason as the unanchored
  note, whose text is now `Ap2WriteError: cannot run openssl here: …`, as is the note of a further `--tsa` in
  `anchors_failed`. The README's Versioning section reserves a change of exit codes for 2.0, with the one exception made
  in 1.5.2 and declared limited to it; 1.5.3 extends that exception to this case, and the section now says so. Test:
  `test_stamp_whose_openssl_cannot_be_started_is_74_and_the_pack_is_unchanged`, which fails on 1.5.2 (exit 1), with
  `build` given two `--tsa` and a TSA that cannot be reached in it.

### Known limitations

- A run under a file size limit can leave Python's own bytecode cache cut (measured 2026-10-13 on 1.5.2,
  `9a85db5`). CPython 3.9 and 3.11 write each `.pyc` with one raw write: from a copy without `__pycache__`, one run
  under a limit smaller than a `.pyc` left it cut — `python3 ap2_evidence.py verify` cut `pqcrypto/sigsuite`'s
  (13 628 bytes on 3.9.25, cut under limits of 1 to 4 KiB, whole under 16 KiB; 25 347 bytes on 3.11.2, cut under
  16 KiB too), and `python -m ap2_evidence` also cut `ap2_evidence`'s own (81 795 and 144 498 bytes) — and every
  later run exited 1 with `EOFError: marshal data too short`. The failure is loud — no verdict and no exit code of
  a verdict comes from a cut file — and lasts until `__pycache__` (and `pqcrypto/__pycache__`) is removed, or is
  avoided with `python -B` or `PYTHONDONTWRITEBYTECODE=1`. Python 3.13.15 wrote no cut file in the same runs; a cut
  file put there stops it as well. A wheel installed with pip's default settings has its `.pyc` compiled at install
  time.

## 1.5.2 — 2026-10-13 — a receipt that was not written is exit 74

Both CLIs computed the outcome, wrote the receipt to stdout and exited with the verdict's code without checking that the
write had succeeded. Measured on 1.5.1 with real processes (Linux; Python 3.11.2, and 3.9.25 / 3.13.15 where named; Node
22.23.2), `verify` on `anchor_valid.json`, `digest_mismatch.json` and a valid pack whose receipt is 84 620 bytes (84 432
from the JS verifier):
- stdout on `/dev/full` or on a pipe whose reader has gone: the JS verifier exited 0 or 1 with nothing on stderr; the
  Python CLI exited 120 for the two small receipts (the interpreter's own final flush, "Exception ignored", a code no
  contract names) and 1 with a traceback for the large one, a valid pack.
- stdout closed (`>&-`): the Python CLI exited 0 or 1 with nothing on stderr, and `build` and `stamp` exited 0.
- stdout on a regular file that stops growing (`ulimit -f 4`): with the large receipt the JS verifier wrote 4 096 bytes
  of the 84 432 and exited 0, the Python CLI exited 1 with a traceback. Appended to a file already holding 1 000 bytes
  under a 1 024-byte limit, both took 24 bytes: JS exited with the verdict's 0 or 1; Python exited 120 for the small
  receipts, and 1 with a traceback for the large one and for all three under `-u`.
- stdout a non-blocking pipe read 1 s late: the Python CLI exited 1 with a traceback for the large receipt, and under
  `-u` / `PYTHONUNBUFFERED=1` exited 0 with 65 536 bytes of the 84 620 in the pipe; the same pipe already full at start:
  120 for the small receipts, and under `-u` the verdict's 0 or 1 with nothing written.
- stderr on `/dev/full`, or a non-blocking pipe that is full: a usage error and a refusal of `build` or `stamp` exited
  120 in the Python CLI; the JS usage line was lost with exit 2. stderr closed (`2>&-`): the Python usage and refusal
  text went to stdout: usage exited 1 on Python 3.9 and 3.11, 2 on 3.13; a refusal exited 1 (3.11).
- `build` into a path it could not write: a traceback, exit 1 (the "not valid" code). `build` over an existing pack
  under `ulimit -f 2`: the 5 891-byte pack was left at 2 048 bytes and no longer verified. `stamp` into a directory it
  could not write: exit 1 with its refusal.
- with no writable temporary file (`ulimit -f 0`): `verify --tsa-cert` on a valid pack and `stamp` raised a traceback
  (exit 1); `verify --trust-anchor` reported a valid pack "not valid", exit 1. With the file
  openssl reads cut at 100 bytes, `verify --tsa-cert --require-anchor` exited 1, "not valid".
- with openssl unable to start (`fork` refused under `RLIMIT_NPROC` 1): `verify --tsa-cert --require-anchor` on a
  valid pack gave `"tsa_verified": false`, `"valid": false`, exit 1; `--tsa-cert` alone exit 0 with `"tsa_verified":
  false`; `--trust-anchor` exit 0 with `"chain_verified": false`. With an openssl that answers after 20 s (the limit is
  15 s) `--tsa-cert` and `--trust-anchor` gave the same two `false` fields, exit 0.
- `main()` called in process after the caller wrote text that was still in `sys.stdout`'s buffer, stdout a full
  non-blocking pipe: exit 120.

Now:
- The receipt is written and flushed before the exit code is chosen. Python writes the bytes its stdout text layer
  would write (its encoding and error handler, a byte order mark only where that layer writes one as the first thing
  written) to the byte stream below it, in a loop that checks every count, so a short write under `-u` continues and
  the next failure is seen; text the caller left in the buffer goes first. Node sets the code in the write's callback
  and `error` event, and writes to a regular file synchronously in a loop to the last byte.
- A receipt that does not reach stdout whole exits 74 (EX_IOERR in sysexits.h) whatever the outcome, with one line
  `receipt not written: <reason>` on stderr; if stderr fails too, the exit is still 74. Bytes a pipe has taken count as
  written: a reader that closes after that (`| head -c 100` on a small receipt) is not seen.
- A stdout or stderr that is a non-blocking pipe and full is waited for, as a blocking write waits (Python in `select`;
  Node retries `EAGAIN` after a pause of 1 to 50 ms), never reported as lost.
- A refusal (1) or a usage message (2) that stderr does not take is 74, and stdout stays empty; with a working stderr
  they keep 1 and 2 in every stdout mode.
- `build` and `sign_evidence` write the pack, and `pqcrypto.sigsuite.ProducerIdentity.save` the key file, to a new file
  in the same directory with an unpredictable name created exclusively (`O_EXCL`: a file, FIFO or symlink already at
  that name is neither written, followed nor waited on), flushed, fsync'd and closed, then renamed onto the path; on a
  failure the temporary file is removed and what was at the path stays as it was. The pack keeps the mode of the pack it
  replaces (0666 less the umask for a new one); the key file is 0600, also when it replaces one (1.5.1 kept an existing
  file's mode, 0644 included, and a failed save left a 223-byte key file at 100 bytes, no longer loadable); a key file
  this process may not write (mode 0400) is refused with `PermissionError` and left as it was, as in 1.5.1. A symlink is
  followed and stays a link; a path that is not a regular file (`/dev/stdout`, a FIFO) is written directly, as before.
  One change of behaviour: an existing, writable pack in a directory this process cannot write was rewritten in place
  (exit 0) and is now 74, since no temporary file can be made there. A directory as the pack path is refused before any
  TSA is asked. `build` or `stamp` that cannot write the pack exits 74; after a `stamp` that exits 74, `cannot write the
  stamped pack … not stamped` leaves the pack unchanged, any other reason means the pack holds the new anchor and only
  the receipt was lost.
- A check asked for that cannot be run on this machine is 74, never a verdict: `verify --tsa-cert` and `--trust-anchor`
  when the files openssl reads cannot be written (`cannot write a temporary file for openssl: <reason>`), or openssl
  cannot be started or gives no answer within its time limit (`cannot run openssl here: <reason>`); `verify_evidence`
  raises `Ap2WriteError` there. openssl absent is unchanged: the field is `null` (not measured) and `--require-anchor` /
  `--min-anchors` do not count that anchor (exit 1 when the policy needs it). The TSA query of `build --tsa` and
  `stamp` is read from openssl's stdout, with no temporary file.

Exit codes 0, 1 and 2 keep their meaning; the 1.5.1 entry below says "the exit codes are unchanged" about 1.5.1. The
versioning rule reserves a change of exit codes for 2.0: 74 is the one exception, made here and named in the README's
Versioning section. Receipts written to a regular file are byte for byte those of 1.5.1: `verify` on the 52 JSON files
under the 1.5.1 tree's `spec/` and on a valid pack with an 84 620-byte receipt, Python buffered and unbuffered and Node
22, gave the same exit code, stdout and stderr in 159 of 159 runs.

Limits, declared: with stdout or stderr closed (`>&-`, `2>&-`) Node reopens the descriptor on `/dev/null`, so the JS
verifier's write succeeds and it exits with the verdict's 0/1 (2 for usage); the Python CLI exits 74 there. In process,
after text the caller wrote to a `utf-8-sig` pipe, the receipt carries a second byte order mark (the command line never
does: one receipt per process; measured on Python 3.9, 3.11 and 3.13). All of this is measured on Linux only: on Windows
Python's `select` waits on sockets only, so a full non-blocking pipe there would be 74; Windows and macOS are not
measured.

`test_receipt_not_written.py` (54 tests) runs both CLIs in child processes with real descriptors: a regular file (the
control), `/dev/full`, a pipe whose reader has gone, fd 1 or 2 closed before exec, `RLIMIT_FSIZE`, a non-blocking pipe
already full at start (on stdout and on stderr, with a CPU window a spin cannot pass), `-u`, six encodings against
Python's own text layer, a pack path that cannot be written, an earlier pack and key file left intact, the temporary
name drawn onto a planted file, FIFO and symlink, `RLIMIT_FSIZE` and `RLIMIT_NPROC` under the openssl checks, openssl
gone since `which` and openssl without an answer, a write that takes 0 bytes and an fsync that fails (an `LD_PRELOAD`
shim, skipped without a C compiler), a read-only key file, and `main()` in process. One existing test changes with the
code: `test_ap2_anchors.py` expected exit 1 for `stamp` into a directory it cannot write and now expects 74 (still "not
stamped" on stderr, no traceback). Verdicts, vectors and digests are unchanged. `Ap2WriteError`, raised by
`build_evidence`, `add_anchor` and `verify_evidence` as above, is both an `Ap2EvidenceError` and an `OSError`
(`build_evidence` raised an `OSError` there before; `add_anchor` an `Ap2EvidenceError`). Against the 1.5.1 files the
test file reports 79 failures and errors (subtests included) in 38 of its 54 tests; on 1.5.2 none, on Python 3.9.25,
3.11.2 and 3.13.15. Of 75 mutants of the lines this release adds or changes, it kills 74 (Python 3.11.2, Node 22).
Alive: the JS write without its callback but with its `error` listener, equivalent here: Node reports the failed write
through the event too, and the two gave the same exit code, stdout and stderr in 42 runs (3 packs × 7 stdout modes × 2
stderr modes), where the write without callback and without listener differed in 12.

## 1.5.1 — 2026-10-12 — the JS receipt reaches a pipe whole

The JS verifier called `process.exit()` right after printing the receipt. On a pipe, Node drops what it has not yet
written: an evidence file with a 100 000-character unknown key gave 65 536 bytes of broken JSON on `node ap2-verify.mjs
… | cat` (measured on 1.5.0, Linux, whose pipe buffer is 64 KiB; the receipt is 100 477 bytes), and a valid pack whose
receipt passed 64 KiB exited 0 with a receipt cut the same way. It now sets `process.exitCode` and returns, so the receipt
is written whole; the exit codes are unchanged (0 valid, 1 not valid, 2 usage). `test_js_receipt_pipe.py` writes the
receipt into a real pipe whose reader starts late and reads the verifier's own exit code: an invalid and a valid receipt
over 64 KiB, two small ones and two usage errors. It fails on 1.5.0, and on each of eight mutants of the changed line (the
exit code left at 0, forced to 0 or 1, inverted; `process.exit()` restored, or called after the assignment, on the next
tick or on `setImmediate`). Verdicts, vectors and digests are unchanged; the Python reference was not affected. The JS
verifier is not in the wheel or the sdist: the Python code they ship differs from 1.5.0 only in the `add_anchor`
docstring corrected after the 1.5.0 release.

**Text corrected.** The README's versioning paragraph gave the CLI exit codes as "0 valid, 1 otherwise"; a usage error
exits 2, in both verifiers (the Python CLI already did in 1.0.0).

## 1.5.0 — 2026-10-11 — more than one time anchor: `anchors` (SPEC §3.3)

**Text corrected after the release (2026-10-11, no code change).** The README and the `add_anchor` docstring said `stamp` adds "a
renewal before the first TSA's certificate ages out", and the SPEC §3.3 introduction listed "a renewal token" among the
mechanisms a pack can carry. Neither holds: each token commits to the pack's digest, not to the anchors already there, so
a token added later proves existence from its own time only — not a renewal in the sense of RFC 4998. And "a failing one
fails the pack" (this entry) and "a claimed anchor that fails rejects the pack" (README) were true for a token whose
binding fails, not for one whose TSA signature does not verify under `--tsa-cert`: that one is not counted, which can
fail the pack only through a `--min-anchors` / `require_anchor` policy. Behaviour, vectors and digests are unchanged.

**Why.** One RFC 3161 token depends on one TSA key, which ages. Measured on 1.3.0 and stated in the AP2 #338 discussion:
the format could not carry a second commitment to the same digest — a new top-level key changes the digest, and inside
`rfc3161_timestamp` it was silently ignored (1.3.0) or refused (1.4.x).

**The rule, written first (SPEC §3.3, §9.1, revision 1.5.0).** `anchors` is an optional, non-empty top-level list OUTSIDE the
digest (§3 now excludes four keys; no 1.0–1.4 pack carries it, so no earlier digest changes). Each entry is a closed object
naming its `mechanism`; this revision defines `rfc3161` (`tsr_b64`, `tsa_url`, `note`). An undefined mechanism, an unknown
key or an empty list is a refusal that names it. Every entry is checked like the `rfc3161_timestamp` token; one whose
binding fails fails the pack (one whose TSA signature does not verify under `--tsa-cert` is not counted, as for the
block). `anchors_verified` — the number of DISTINCT anchors (a different signed TSTInfo) that verify (and, under
`--tsa-cert`, are TSA-verified), the block's token included — is a twelfth normative field; `min_anchors` / `--min-anchors N` is the
relying party's policy (`require_anchor` alone is 1). `rfc3161_claimed`/`rfc3161_verified` aggregate over the block and the
entries; on a pack without `anchors` both are what 1.4.x reports. The x5c chain is validated at the EARLIEST `gen_time`
among the TSA-verified anchors. Declared: two tokens of the same TSA count as two anchors (they share its key).

**Both verifiers** (`ap2_evidence.py`, `verifiers/js/ap2-verify.mjs`): the rule above, the same refusal texts, `anchors`
(one result per entry) and `anchors_verified` in the receipt, `--min-anchors` with one grammar (ASCII digits, 1 to 999999,
no leading zero); `min_anchors` / `minAnchors` at the API is an integer ≥ 1 or an error, never a weaker policy.
The JS verifier cannot verify a TSA signature (no openssl), so under `--tsa-cert` it counts no anchor — declared, as for
`rfc3161_timestamp` since 1.1.0.

**Builder.** `build --tsa` may repeat (the first TSA stays in `rfc3161_timestamp`, so a pack built with one TSA is still read
by 1.4.x; the others go to `anchors`; a further TSA that gives no token is listed in the result, `anchors_failed`, and not
written; when the first one gives none, `rfc3161_timestamp` is `anchored: false` with its note, as in 1.4.x).
`stamp <pack> --tsa URL` (one `--tsa` per run) / `add_anchor()` adds an anchor to an existing pack after checking that the
sealed content matches its digest; the digest and the producer signatures do not change; the file is written through a
fresh temporary file in the same directory and renamed, keeping its mode, under a lock on that directory (POSIX), so
concurrent stamps of one pack keep every anchor; a failure leaves the pack as it was.

**Vectors** (`make_vectors_anchors.py`, a second probe TSA whose certificate ships as `anchor_probe_tsa2.crt`): two ACCEPTs
(`anchors_two_valid`, `anchors_only`) and seven REJECTs (`anchors_copied_token`, `anchors_min_not_met`,
`anchors_entry_garbage`, `anchors_entry_wrong_digest`, `anchors_unknown_mechanism`, `anchors_unknown_key`,
`anchors_empty`); 26 vectors, conformant 26/26 in both verifiers. Every `expected.json` carries `anchors_verified`. The
three refusals carry `report.refused`, the exact text: the 1.4.1 verifiers refuse these packs too, for another reason
(`top level: unknown key "anchors"`), and a normative block of `valid: false` alone would have let that pass.

**Measured 2026-10-11.** Differential oracle 169 cases, 0 disagreements, 6 declared (the two new ones: `anchors_two_valid`
under `--tsa-cert`, which only the reference checks); it now also compares `anchors_verified`, each anchor's facts and the
refusal text where §9.1/§3.3 fix it (elsewhere the two verifiers word parse refusals differently, same verdict — 9 files).
`schema_mutants.py --full`: 16 503 mutations from 37 sources, each with its SPEC class in both verifiers, 0 disagreements on
16 540 files; against the 1.4.1 verifiers the same corpus leaves 788 (Python) and 689 (JS) mutations without their class —
all from `anchors_only` and `anchors_two_valid`: 1.4.1 refuses the `anchors` key, and 444 Python runs stop at a `TypeError`
(no `min_anchors` in the 1.4.1 API); that shows the bench reaches the new sources, not that it judges the §3.3 rules.
Nine mutants of the new code (a copied token counted twice, a failing anchor ignored, an unknown mechanism skipped,
`anchors` inside the digest, `min_anchors` ignored, an empty list accepted, an unknown entry key accepted, the block's token
not counted, `--tsa-cert` ignored in the count): 9/9 killed. `sdk_crosscheck.py --hostile` against the AP2 SDK at
`e1ea56db72a6`: 154 artifacts, 0 disagreements. `test_ap2_anchors.py` runs `stamp` and `build --tsa` against a
real local TSA (openssl `ts -reply`) and the `--min-anchors` grammar in both verifiers.

**Review (before release).** A copied token re-wrapped — a byte after the TimeStampResp, a status string, a longer length —
still verified under `--tsa-cert` (openssl accepts the wrapper) and counted as a SECOND anchor: `--min-anchors 2 --tsa-cert`
passed on one timestamp. The identity of an anchor is now the TSTInfo the TSA signed (SPEC §3.3), in both verifiers.
`stamp` wrote through a fixed temporary name (a symlink planted there was written through), reset the pack's mode to
the umask (0600 became 0644), lost anchors under concurrent stamps while reporting success, and dropped the first of two
`--tsa` in silence; `min_anchors` at the API accepted 0, NaN or a string. Tests pin each one, and the cases the suite
did not reach: an aggregate with a failing entry beside a good one, the earliest-`gen_time` rule (a leaf that expires
between two real tokens), the exact texts of the entry refusals. `test_ap2_anchors.py`: 25 tests.

**Fixed on the way.** `schema_mutants.py` and the oracle recomputed the digest over a hard-coded list of three excluded keys
(now the SPEC's four); the JS conformance test passed its options through `**_`, which would have swallowed `min_anchors`
silently (now explicit); `run_ap2_conformance.py` read `report.ignored` without checking that it was there.

**Not covered.** Only `rfc3161` is defined: an OpenTimestamps proof or an RFC 4998 renewal chain would be a new revision.
The "earliest TSA-verified `gen_time`" rule for x5c validation is not pinned by a vector (it needs a chained x5c and two
TSAs); `test_ap2_anchors.py` pins it with two local TSAs. A pack that carries `anchors` is refused by every 1.4.x verifier.

## 1.4.1 — 2026-10-11 — a signature entry's FAIL names the key; the same key named in both verifiers

**What 1.4.0 said and did not do (measured 2026-10-11 on the 1.4.0 release).** The 1.4.0 entry below said that a key
outside a closed object is "a refusal, an artifact error or a FAIL entry that names the key". For a `signatures[i]` entry
that was not true: the entry was `status: FAIL` and the pack not valid, but its `note` read only "entry is not the closed
shape of SPEC §9.1", in both verifiers, without the key. The key was named in the anchor block, the producer block, the
binding entries, the top level and the artifact objects. And with several unknown keys in one object, one of them an
array index such as `"1"`, the two verifiers could name different keys: Python the first in file order, JS the first of
`Object.keys`, which puts array-index keys first. An entry whose `sig_alg` was absent or not a string was a FAIL entry
with no note at all, in both.

**Now, identically in `pqcrypto/sigsuite.py` and `verifiers/js/ap2-verify.mjs`:** the FAIL entry's `note` names the
unknown keys and the missing keys, each list sorted by Unicode code point (`…; unknown key(s) ["x"]; missing ["y"]`),
also when `sig_alg` is absent or not a string (an entry that is not an object has no keys and no note); and every
closed-object refusal names the first unknown key by code point (`ap2_evidence.py` and the JS verifier). SPEC §9.1 says
both (revision 1.4.1). Tests (`test_ap2_conformance.py`, class `TestSignatureEntryNamesTheKey`, four tests, all failing
on 1.4.0): a FAIL entry with an integer-like key, a non-BMP and a BMP key and a missing key gets the same note in both;
three missing keys are listed by code point in both, and in Python under six hash seeds; an entry without a string
`sig_alg` names its keys in both; an anchor block with several unknown keys is refused naming the same key in both, on
three key sets that together tell code-point order apart from file order, `Object.keys` order and UTF-16 order. Verdicts do not change:
every pack 1.4.0 refused or accepted, 1.4.1 refuses or accepts; only the text that names the key changes.

**Completing the 1.4.0 list of behaviour that moves for packs already in the field** (measured 2026-10-11 by building packs
with the 1.0.0–1.3.0 builders across their branches): besides what that entry lists, a KB-JWT whose `typ` is present
but not exactly `kb+jwt` (`"JWT"`, `"KB+JWT"`), a KB-JWT whose `iat`, `aud`, `nonce` or `sd_hash` has the wrong type
(`sd_hash` only without `cnf`: with `cnf` the builders already refused it), and a mandate or KB-JWT header carrying
`crit`, well-formed or not (RFC 7515 §4.1.11), make the artifact fail under 1.4.x. Packs built with 1.0.x stopped verifying already in 1.1.0, when `honest_scope` was pinned to the
canonical scope of the format (`honest_scope does not match`).

## 1.4.0 — 2026-10-11 — closed schema: a key the verifier does not understand is never silent

**The finding (2026-10-10, measured on 1.3.0 = `6b2c7cf`).** Following an outside reader's remark on the anchor block
(AP2 discussion #338), the two verifiers were given `valid_signed.json` with one key nobody had defined,
`additional_anchors`, written inside `rfc3161_timestamp`: both answered `valid: true` with nothing in the receipt. The
same silence held for a key inside `producer_signatures`, inside every `signatures[i]` entry, and — once sealed into the
digest — at the top level and inside an artifact entry; a KB-JWT without `typ: kb+jwt` and a signed header with a `crit`
naming an extension nobody understands were `valid: true` too (the six 1.4.0 REJECT vectors below, each `valid: true`
on 1.3.0, re-measured on the release commit). Every fuzzer of this repository varied the TYPES of known fields; none
ever added a key. Nothing in the specification said what to do with the unknown, so both implementations did the same
thing: nothing — and the differential oracle, which compares them with each other, had no way to see it.

**The rule, written first (SPEC §9).** Every object this format defines is a CLOSED schema — an exhaustive key list with
types — and a key outside it is a refusal, an artifact error or a FAIL entry that names the key (§9.1) [corrected in 1.4.1: in 1.4.0 a
signature entry's FAIL did not name the key; see 1.4.1]. Every object a
standard defines follows that standard's rule for the unknown and REPORTS what it ignored (§9.2): JOSE header parameters
(RFC 7515 §4, ignored; `crit`, RFC 7515 §4.1.11, the JWS is invalid — this format understands no extension), JWK members
(RFC 7517 §4), `cnf` members (RFC 7800 §3.1), KB-JWT claims (RFC 7519 §4; `typ: kb+jwt` and `iat`/`aud`/`nonce`/`sd_hash`
REQUIRED, RFC 9901 §4.3). The report is `artifacts[i].ignored`, one sorted list per slot, present only when non-empty.
The `evidence_format` string, the digest and the sealed scope are unchanged: 1.4.0 narrows what is accepted; every 1.0–1.3
conformance vector still verifies with the same normative block.

**What changed in both verifiers, identically** (`ap2_evidence.py`, `pqcrypto/sigsuite.py`, `verifiers/js/ap2-verify.mjs`):
- closed objects with the same three messages (`<object>: unknown key "x" (SPEC §9.1)`, `… must be <type> (SPEC §9.1)`,
  `…: missing <key> (SPEC §9.1)`): top level, `rfc3161_timestamp`, `producer_signatures`, `bindings[i]` (refusals);
  artifact entry, `key`, `kb_jwt`, `verified_at_build` (artifact error); `signatures[i]` (FAIL entry);
- the artifact's `header` copy must canonically equal the decoded protected header; `kb_jwt.present` must agree with the
  compact serialization; `verified_at_build` is exactly `{signature_ok: true, disclosures_ok: true}`;
- (review of 2026-10-11) the recorded KB values `verified`, `signature_ok`, `sd_hash_ok` and `claims_recorded_not_validated`,
  when present, must canonically equal what the verifier recomputes from the KB-JWT: on the first 1.4.0 build a key nobody
  defined inside `claims_recorded_not_validated`, or a recorded `aud`/`verified` the KB-JWT contradicts, still verified
  `valid: true` in both verifiers with nothing in the receipt (`test_ap2_closed_schema_gaps.py`);
- producer entries: `post_quantum` must be `true` iff `sig_alg` is `ml-dsa-65`; `scheme` is reconciled with the entries
  (`hybrid` = a classical AND an `ml-dsa-65` entry, `classical-only` = no `ml-dsa-65`) — measured on 1.3.0: `scheme:
  "hybrid"` over a lone Ed25519 signature was `producer_ok: true`; the receipt gains `producer_signatures.scheme_ok`;
- `crit` handling and the ignored-name report for the issuer header, its `jwk`, the snapshotted `key.jwk`, `cnf`,
  `cnf.jwk`, the KB-JWT header and payload; KB-JWT `typ` and the four REQUIRED claims checked (presence and type — the
  values stay recorded, not validated, as the sealed scope says);
- `build` refuses a header whose `crit` it does not understand (at the source, like a bad signature) and writes the
  anchor block's TSA as `tsa_url` (the vectors' spelling; `tsa` stays accepted as the 1.0–1.3 spelling, §9.1).
Behaviour that moves for packs already in the field: an anchor block, producer block or binding entry with a key outside
§9.1 is now refused; an empty producer block `{}` or one without `scheme`/`over`/`signatures` is a refusal (1.1.0 r1 made
it "present, not ok"); a KB-JWT without `typ`/`iat`/`aud`/`nonce`/`sd_hash` makes its artifact fail (the three KB-JWT test
fixtures of this repository lacked `iat` and were completed) [completed in 1.4.1: also a KB-JWT whose `typ` is not exactly
`kb+jwt` or whose `iat`, `aud`, `nonce` or `sd_hash` has the wrong type, and a mandate or KB-JWT header carrying `crit`; see
1.4.1].

**Conformance vectors 8 → 17** (`spec/vectors/ap2/`, generator `make_vectors_closed_schema.py`; the five derived from
`valid_signed` regenerate byte for byte, the four signed with fresh keys are frozen). ACCEPT: `header_param_ignored`,
`kb_jwt_valid` (the first KB-JWT vector of the set), `key_jwk_member_ignored` — each with a `report` block the runner
now compares. REJECT: `unknown_key_top_level`, `unknown_key_anchor_block` (the measured mutation), `unknown_key_producer_entry`,
`unknown_key_artifact`, `header_crit_unknown`, `kb_jwt_typ_missing`. Positive control on the 1.3.0 reference: exactly
those six are `valid: true` there; the eleven others give the same `valid` on both versions. Both verifiers: 17/17.

**Generative proof (`verifiers/schema_mutants.py`, CI: `test_ap2_schema_mutants.py`).** From every vector and from
freshly signed packs, every object of §9.1 and §9.2 is mutated at every level — unknown keys in eight spellings (ASCII,
non-ASCII, `__proto__`, `constructor`, empty, a control character, a case variant of a known key, a dotted name) with
values of every JSON type, every known key replaced by each hostile type and deleted, duplicate keys (textual), reversed
key order, `\u`-escaped key spellings, `crit` in eight shapes, KB-JWT `typ`/required claims, duplicate keys inside the
signed segments, eighteen out-of-grammar files — and each mutation's EXPECTED class is computed from the SPEC tables, never
from a verifier. Measured 2026-10-10: full corpus 12 818 mutations from 28 sources (quick subset in CI: 3 085) — on 1.4.0
every mutation got its class in both verifiers, 0 differential disagreements on 12 846 files; on the 1.3.0 verifiers, same
corpus, 9 825 (Python) / 9 827 (JS) mutations did NOT get their class and **8 186 passed silently in both** (`valid`
unchanged, nothing in the receipt), with 0 disagreements between the two — they agreed on every silent acceptance. The CI
test also keeps a built-in control: a copy of the reference with the top-level closure removed turns the bench red.
Positive control of the bench kept apart by design: one process loads one reference (`--py-root`/`--js`).

**Tests on the release commit** (Python 3.11.2, Node 22.23.2 / OpenSSL 3.5.7): `test_ap2_evidence.py` 30, `test_ap2_conformance.py`
27, `test_ap2_schema_mutants.py` 2 (new), `test_packaging.py` 6, `test_stamp_tsa_locale.py` 2, `pqcrypto/test_pqsig.py` 13
(one extended: scheme reconciliation and the closed entry), `pqcrypto/test_acvp_mldsa65.py` 1, `test_ap2_closed_schema_gaps.py` 5 (new on review:
listed optional keys with valid values change nothing, `present` flipped, a non-string in a list of strings, recorded KB values,
report order by code point — the cases the generative bench does not derive) — all OK; differential
oracle, ablation and type-fuzz figures in the README. The new tests remove their own temporary directories.

**Third-verifier bench (`verifiers/sdk_crosscheck.py`), adjusted to the closed schema.** Its interop control builds a
pack by hand around tokens the third stack issues; without the `header` copy §9.1 now requires, both interop cases were
refused (`artifact: missing header`), so the bench was red for a reason in the bench. It now writes the decoded protected
header, as `build` does. A refusal marked `(SPEC §9.1)` is not the end of the comparison: those checks run before the
token's own, so the bench rebuilds the artifact's closed objects as `build` writes them (`header` decoded from the token,
`kb_jwt` reduced to `present`, `verified_at_build` the two `true`s, undefined keys dropped) and verifies again. The refusal
is counted with the layers the third stack has no notion of only when the verdict underneath is the third stack's, or the
key block itself is malformed; otherwise the reason underneath is judged like any other refusal, and "we accept
underneath, the third stack refuses" is a disagreement. Without the first part, the new `unknown_key_artifact` vector was
reported as a disagreement about RFC 9901; a plain `(SPEC §9.1)` bucket, tried first, would have hidden behind the KB
copy `build` records a third stack that skips the KB-JWT signature (measured on a copy of the bench). Positive controls:
the seeded divergence still turns the bench red, so does a copy without the §9.1 handling, and four built-in controls
(4–7) hold the rebuilt view and its three outcomes (4 asks the third stack for real; 5 and 7 supply its verdict). Re-measured 2026-10-11: 142 artifacts compared, 90 claim-sets,
0 undeclared disagreements (README).

**Not changed, declared.** The issuer JWT payload is not "closed": every claim is the pack's content and is recorded in
`resolved_claims` in full (RFC 7519 §4). The §9.2 report never changes `valid`. `sig_alg` values outside the three
algorithms stay a SKIP (verification gap), as before.

## 1.3.0 — 2026-10-05 — the wheel no longer shares a directory with PyPI's pqcrypto; cryptography >= 48

- **The wheel installs the signature suite as `ap2_pqcrypto/`, not `pqcrypto/`.** PyPI's `pqcrypto` (1.0.0, a PQClean
  binding) owns `pqcrypto/` in site-packages. Measured 2026-10-05: installing 1.2.2 on top of it replaced its
  `__init__.py` with our empty one (the public names `dir(pqcrypto)` lists went from 42 to 0; `pip check` said nothing)
  and uninstalling 1.2.2 removed that file for good. The clone keeps `pqcrypto/` (every documented `python3 <file>.py`
  command is unchanged); setuptools maps it to `ap2_pqcrypto` in the wheel, and `ap2_evidence` looks for `sigsuite.py`
  in `pqcrypto/` first, then `ap2_pqcrypto/` — the file, not the directory, because PyPI's `pqcrypto/` may sit beside
  the installed module. `test_packaging.py` (6 tests) checks the pyproject mapping and the import hook beside a foreign
  `pqcrypto/`, each with its positive control (the 1.2.2 layout fails the first; a foreign `pqcrypto/` without
  `ap2_pqcrypto/` fails to import), the declared floor, and that a wheel built from a clean copy carries
  `ap2_pqcrypto/sigsuite.py` and no `pqcrypto/` entry; the CI checks the built wheel the same way, and its install step
  now imports from the venv with `-I` and asserts the origin (until now it imported the checkout, not the wheel). Measured with 1.3.0 installed beside pqcrypto
  1.0.0: 42 names before, with it installed and after `pip uninstall ap2-evidence-pack`; `ap2-evidence build` and
  `verify` work from the install; a tampered pack is refused (exit 1).
- **`cryptography >= 48`** (was >= 42). ML-DSA-65 (the hybrid producer signature) works from 48.0.0; 47.0.0 ships the
  `mldsa` module but raises `UnsupportedAlgorithm`. A new CI job runs every suite with 48.0.0.
- The next cryptovalid-opencore (0.18.0, prepared beside this release) is to depend on this package (its `ap2` extra)
  instead of shipping its own copy of `ap2_evidence.py` and `pqcrypto/` (the two wheels installed the same paths and
  overwrote each other).

Measured before the tag: every `test_*.py` and `pqcrypto/test_*.py` (6 files, 79 tests) on Python 3.9.25, 3.11.2 and
3.13.15, each with cryptography 48.0.0 and 50.0.2.

## 1.2.2 — 2026-10-04 — an RFC 3161 mark only for a granted token for this digest

- **`_rfc3161_stamp` recorded any HTTP body as `anchored: true`** — an error page, a rejection, a genuine token for
  another digest — with those bytes as `tsr_b64`. It now reads the reply with `parse_timestamp_resp` (the DER walk the
  verifier already uses) and requires both: a granted status (0 or 1, both carry a token) and the token's imprint equal
  to the digest. The granted check is needed: the DER walk reads an imprint even from a rejection that carries a token.
  `verify` was not affected: it reads the token itself (measured: a pack whose `rfc3161_timestamp` says `anchored: true`
  over an HTML page is `valid: false`, exit 1).
  `test_stamp_tsa_locale.py` builds a local TSA with openssl behind a local HTTP server; on 1.2.1 its four wrong replies
  (another digest, a rejection, an HTML page, a rejection carrying a valid token) are anchored, here none is, while the
  genuine token and a status-1 token are. Without openssl the test is skipped and says that the stamp is not measured.
- The HTTP response of the stamp, and the files the example builder, the Elara reader and three tools under `verifiers/`
  read or write, are closed (`with`).
- `dist/` held the 1.0.2 wheel and sdist; it is no longer tracked (the packages are the release assets).

Measured: every `test_*.py` and `pqcrypto/test_*.py` on Python 3.9.25, 3.11.2 and 3.13.15 (73 tests, the same count as
script and as module); the sample gate (tampered pack refused); `differential_oracle.py` 0 disagreements of 149 (4
declared); the strict-layer ablation; `type_fuzz.py` 1390 of 1390 inputs answered with a verdict; the wheel installs and
verifies on its own; the third stack (AP2 SDK at `e1ea56d`) 0 disagreements of 138, and a seeded one is reported.

## Corrections (2026-09-26)

- Small-order keys allow a forgery on any message, not on "a share of messages" (correction to the 1.2.1 notes). The
  1.2.1 note said that, for the small-order points other than the identity, a forgery holds only "on a share of
  messages". By the verification equation, that is true of one fixed construction (R = identity, S = 0), but it
  understated the risk: with any small-order public key A, of order n = 2, 4 or 8, anyone can produce a signature on any
  message. Pick S and a guess g for k mod n, set R = [S]B − [g]A, compute k = H(R ‖ A ‖ M) mod L as the verifier does,
  and retry until k ≡ g (mod n); each try succeeds with probability about 1/n. Measured on 2026-09-26 with curve
  arithmetic written for the measurement, not this repository's code: for each of the 8 small-order public keys, a
  signature on one message chosen in advance verified under OpenSSL, through Python `cryptography` (1 to 16 tries) and
  through Node 22 `crypto` (1 to 17 tries) — the same backend, so one measurement, not two independent ones. In the
  Python probe, the same construction against an ordinary key verified 0 times in 2000 (null control). The refusal of
  these keys added in 1.2.1 is unchanged; this corrects only the description of what it prevents. The source comments
  that repeated the wording are corrected too.

## 1.2.1 — 2026-09-26 — small-order keys refused; the evidence file must be a regular file

Numbers dated 25/09 in this note come from the author's measurement records, which are not part of this repository,
and were not re-measured for 1.2.1 except where a 26/09 figure is given; the tests and oracle cases for each rule are
in the repository. Found by the 25/09/2026 malformed-input review (four independent reviewers).

- **Small-order Ed25519 keys refused (25/09/2026).** With the identity key as public key, R=identity, S=0 is a valid
  signature on every message. For the other small-order points, under the cofactorless equation that both verifiers
  use, such a forgery holds on a share of messages (the hash depends on R, so not on every one; not measured here);
  under cofactored verification it would hold on every message. A non-canonical encoding (y >= p) is refused because
  the key has no unique encoding. Measured with the identity key in both verifiers, the Python reference
  (`cryptography`) and the JS verifier (Node) — both OpenSSL-backed, so this is one measurement of one backend, not
  two independent ones: a forged producer signature made that way, with that key pinned by the relying party, was
  PASS; after the change both refuse it. Both verifiers now refuse those keys with the same list (8 small-order
  encodings, 2 with the sign bit on x = 0, every y >= p; checked against curve arithmetic on 25/09: 0 disagreements
  on 48 special and 200 000 random keys).
- **The evidence file must be a regular file.** Re-measured on 25/09 on 1.2.0 (`040a1fa`) before any change, under
  an RLIMIT_DATA of 1500 MiB: a FIFO in place of the evidence file blocked both verifiers (no receipt after 30 s); a
  symlink to `/dev/zero` passed the 64 MiB check — a device reports size 0 — and was read until memory ran out
  (Python `MemoryError` traceback exit 1, Node abort `std::bad_alloc`); a directory was refused with an OS error name
  (`IsADirectoryError` / `EISDIR`). Both verifiers now open the file without blocking (`O_NONBLOCK | O_NOCTTY`), keep
  it only if the OPEN descriptor is a regular file (`fstat`), and read at most 64 MiB + 1 byte: a FIFO, a device or a
  directory is the refusal `unreadable evidence file: not a regular file`; a file above the bound stays `exceeds`, and
  by construction also when it grows while being read (no oracle case exercises a growing file). SPEC §3.1 states
  the rule. Measured 26/09 on the release commit (peak RSS of the child, `getrusage`): a file of 64 MiB + 1 byte and
  a symlink to `/dev/zero` are refused at 37 MiB (Python) / 49 MiB (Node), the same peak as a usage error — the
  interpreter's baseline, not a cost of the refusal.
- **Not fixed: the 64 MiB bound limits what is read, not what parsing costs** (measured 25/09/2026): under an
  RLIMIT_DATA of 1500 MiB a 64 MiB file of tiny values (`[{},…]`, `[[],…]`) ends in a Python `MemoryError` traceback
  with no receipt and a Node abort, and Node aborts on a single 64 MiB string too (its strict parser). Closing it
  needs a smaller size bound or a bound on the number of values: a change to SPEC §3.1, left to the author.
- **Oracle.** Four cases with a FIXED refusal reason that both verifiers must give — `file-fifo`,
  `file-devzero-symlink`, `file-directory`, `file-one-byte-over-the-bound` — run with a 20 s timeout and an
  RLIMIT_DATA of 1500 MiB per child, and a positive control `file-exactly-at-the-bound` (the valid vector padded with
  spaces to exactly 64 MiB, which changes no digest). Positive controls must now PASS: through 1.2.0 the oracle only
  counted them, so two verifiers that refused a positive control alike were an agreement (ablation: both verifiers
  made to refuse a file of exactly 64 MiB → 0 disagreements with that check removed, 1 with it). Measured 25/09: 144
  cases / 0 disagreements on 1.2.0 with its own oracle; the new oracle, 149 cases: 0 disagreements after the change,
  3 on 1.2.0 (`file-fifo` BLOCKED in both, `file-devzero-symlink` no receipt in both, `file-directory` with the OS
  reason). In both oracles, 4 known divergences are declared and matched field by field, except the freshly
  generated x5c leaf (`openssl`-dependent chain and TSA checks, the same four since 1.1.0); they are not counted as
  disagreements.
- **Ablation (25/09),** each control removed alone in each verifier: the regular-file check is deliberately
  redundant — a `stat` before `open` and an `fstat` on the descriptor back each other up, so removing either alone
  turns nothing red, and removing both turns the 3 file-object cases red; `O_NONBLOCK` removed with the `stat` →
  `file-fifo`; the `bound + 1` read cap is covered by the `fstat` size check (it guards only a file that grows while
  read). The separate `lax_python_ablation.sh` ("every strict layer RED alone") covers the parsing layers, not these
  file checks.
- **Tests:** `test_ap2_evidence.py` 27 → 29 on 25/09 (the FIFO/`/dev/zero`/directory test red on 1.2.0; the bound
  test green there too — a valid file at exactly the bound must pass, before and after).

- **The third-verifier bench (`verifiers/sdk_crosscheck.py --hostile`) opened the new file-object cases.** It reuses
  the oracle's hostile corpus and used to read each file with a plain `json.load(open())`. Measured 2026-09-26 locally:
  on the symlink to `/dev/zero` it read until the process was killed (SIGKILL, sender not identified) after 14.1 s at a
  peak of 5165 MiB. The CI runner of the first 1.2.1 push (run 36258094086, commit `bfe6827`) received a shutdown
  signal 10 s into that same step; the runner's own reason is not visible in the log, and the local measurement is
  what ties the two. A FIFO would have blocked the bench (by the semantics of `open()`; not run). The FIFO,
  `/dev/zero` and directory cases are now left out of that bench, counted and printed: they test a refusal before
  reading, and this bench hands the third stack already-parsed objects, so there is nothing on that side to compare.
  After the fix: 7.9 s, peak 237 MiB; 138 artifacts compared (16 from the vectors, 122 hostile), 89 claim-sets,
  0 undeclared disagreements. 1.2.0 had 136 and 87: the two added artifacts and claim-sets are the valid pack padded
  to exactly the bound (removing that case reproduces 136 / 87).
- **Release assets: the SBOM license was wrong.** The CycloneDX SBOM attached to the 1.1.0, 1.1.1 and 1.2.0
  releases declares `AGPL-3.0-or-later`; the package is `Apache-2.0` (LICENSE, `pyproject.toml`). The release script
  had the license hard-coded; from 1.2.1 it reads it from `pyproject.toml`, and fails (exit 2) if `pyproject.toml`
  carries no license. The earlier assets are left as published: replacing a published asset would silently change
  what users already downloaded. This entry is the correction. `SHA256SUMS` now lists every file in the release
  directory (itself excluded), not only the wheel and the sdist.

Re-run on 26/09/2026 on the release commit: `test_ap2_evidence.py` 30 tests (the 29 above plus the small-order key
test), oracle 149 cases / 0 disagreements (4 declared divergences), `type_fuzz.py` 1390/1390 inputs answered with a
verdict instead of a crash (695 mutations × 2 verifiers; it substitutes field types, not files).

## 1.2.0 — 2026-09-23 — a third verifier, written by other people

Every measurement in this repository until now came from two verifiers written by one author. Both reviewers of 1.1.2
named the same limit independently — a misreading of the specification lands identically in Python and in Node, and the
oracle records it as perfect agreement. `verifiers/sdk_crosscheck.py` closes it for the layer it can reach: it runs
Google's AP2 SDK (commit `e1ea56db72a6`, the head of its `main` on 23/09/2026) over `sd-jwt` 0.10.4, the reference
implementation whose PyPI metadata names Daniel Fett — one of RFC 9901's three authors — and the latest release on PyPI, against the same tokens, and
compares the verdict AND the claims each stack resolves.

- **Measured 23/09/2026:** eight vectors alone, 16 artifacts, same verdict and same claim names and values on all of
  them. Vectors plus hostile corpus: 136 artifacts compared (16 of them from the vectors), 87 claim-sets compared,
  **0 undeclared disagreements**, and none in the direction that would signal a hole here — nothing this repository
  accepts and the third stack refuses.
- **The third stack also ISSUES.** Comparing opinions about tokens produced here cannot see a reading shared by both
  local verifiers, because the corpus comes from that same reading. So the SDK mints tokens — with and without decoy
  digests — and this repository's PYTHON reference verifies them and resolves the same claims (the Node verifier is
  not run on them). Both pass, and the bench asserts the emitted shape instead of describing it: one
  `{"...": <digest>}` array-element placeholder per issued token, a shape no hostile file exercises. Nested and recursive disclosures and delegation
  chains are still not cross-checked, and the README says so.
- **One declared divergence, with its clause.** A presentation carrying a disclosure that matches no digest: this
  repository refuses it, the third stack accepts it and returns the payload with that claim dropped. RFC 9901 §7.1
  step 5 requires rejection. No forged claim passes either way; the divergence is the verdict, not the content.
- **Three cases that are nobody's defect,** and an earlier draft of this entry got the reason wrong by calling the RFC
  "silent". It is not: `_sd` that is not an array of digest strings and an array placeholder whose value is not a
  digest string are MUSTs of §4.2.4.1 and §4.2.4.2 addressed to the Issuer, and §7.1 step 3.b collects only well-formed
  shapes while step 3.e removes every `_sd` key — so ignoring the malformed part is what the RFC's verification
  algorithm prescribes. This format rejects instead, a stricter choice. The bench now prints the payload the third
  stack returns, so that sentence is copied from a measurement: `{"...": [1]}` comes back as an ordinary array element
  inside the verified payload, a malformed `_sd` simply disappears, and `_sd: null` is refused by BOTH. SPEC §6 step 2
  says which of these rules come from the RFC and which are this format's choice.
- **Positive controls and their own ablation,** because a bench that cannot go red measures nothing: a flipped
  signature must be refused, a rewritten disclosure's forged value must never be disclosed, a wrong key must flip the
  third stack's verdict — and `AP2_XCHECK_SEED_DIVERGENCE=1` corrupts the key handed to the third stack so that a
  disagreement is actually reported and the run exits 1.
- **Six defects in this bench, found by two review passes and re-measured before fixing.** Its verdict for our side
  read `signature_ok` alone, a proxy for the artifact's verdict: on `claims-mismatch` it printed "both accept" over an
  artifact this verifier rejects. Three hostile files it cannot even read (a BOM, a 100000-deep nesting, a raw
  non-UTF-8 byte) were skipped in silence, quietly shrinking the denominator. The wrong-key control passed when the
  key could not be loaded at all, testing nothing. The seeded-divergence run printed "none in the direction 'we accept,
  a third implementation refuses'" while the seeded divergence was in precisely that direction. The CI ablation checked
  only a non-zero exit, which a crash also produces, and now requires the seeded `[DIFF]` in the output. And the
  citation for `_sd_alg` said §7.1 step 3.d; it is step 2.d.
- **A false sentence shipped in 1.1.2 and earlier,** found by the same review: the README named the oracle's three
  positive controls as non-ASCII, a fresh-key pack and "the CA-issued `x5c` leaf under `--trust-anchor`". Measured
  against `POSITIVE_CONTROLS` in the oracle, the third is `must-created_utc-ok`; the `x5c` leaf is one of the 113
  hostile files. The README now names them from that set and says the sentence was wrong.
- **What it does not cover, with the counts:** 32 packs refused here at the file level and 15 artifacts refused at a
  layer the third stack has no notion of (key provenance, and the `resolved_claims` the file records) get no
  third-stack opinion; 2 more carry a key block that is not a key, so nothing could be handed over; 6 artifacts are refused under the §3.1 profile this format declares
  stricter; on 7 packs the KB-JWT's `aud`/`nonce` cannot be read, so its binding could not be compared (where they can
  be read they are passed through, so the key-binding signature and its `sd_hash` are checked too); 3 hostile files are
  unreadable by the bench. Of the six verification steps of SPEC §6 it covers the signature and the disclosure
  resolution inside step 2, nothing else.
- **`verifiers/type_fuzz.py`, which the cross-check's own result asked for.** Finding that 10 of the third stack's 17
  refusals are uncaught internal errors raises the same question here, and that one is this repository's to answer:
  every field of a valid pack (88) replaced by each of eight hostile types is 695 hostile mutations, answered with a
  verdict 1390/1390 times by the two verifiers (nine substitutions leave the pack identical to the valid one and are
  counted apart), where an answer means an object with a boolean `valid` on stdout and nothing on stderr.
  `test_hostile_files_…_never_tracebacks` already covered ten hand-picked file-level shapes against the Python
  reference as a library, and the differential oracle already ran both verifiers as subprocesses on the 113 hostile
  files with a non-JSON answer as a crash marker; what this adds is the fields one at a time and a positive control
  for the crash detector itself, gated on the exact number of crashes that control must produce. The harness ships a deliberately
  crashing verifier and refuses to measure anything unless it catches it first.
- **Two more defects of the same shrinking-denominator shape, found by the third review pass.** Two artifacts whose
  key block is not a key were skipped with no counter at all — in no total, while a bucket label named their case —
  and the declared divergence printed the `sd-jwt` version as a hand-written `0.10.4` inside a line the bench emits as
  a measurement, which would have printed that string whatever version CI resolved. The version is now read from the
  installed package, and those two artifacts have their own line.
- The workflow gains a job for the cross-check and a step that ablates it, plus a step for the no-crash property. The outcome of the run belongs in the
  release notes, measured, not here.

## 1.1.2 — 2026-09-22 — the vocabulary matches the specification (committed, never tagged: it ships inside 1.2.0)

**Independent competitive analysis by two separate AI reviewers, run in parallel after publication.** One of them went
outside the repository, read the current AP2 specification and the projects competing with this one, and found the thing
eleven review rounds could not: the public vocabulary was a version behind. Measured in `google-agentic-commerce/AP2` on
2026-09-22: "Intent Mandate" and "Cart Mandate" occur **zero** times in `docs/ap2/`, while Checkout Mandate occurs 63
times and Payment Mandate 84. The README opened with "AP2-style Intent / Cart / Payment mandate chains", the sample
generator wrote `intent.sdjwt` and `cart.sdjwt`, and the CI gate built from them.

- README, samples, CLI help, tests and the CI gate now use **Checkout** and **Payment** mandates, with the `vct` values
  of the current spec (`mandate.checkout.open.1`, `mandate.payment.1`).
- The README states what was measured against that spec today: a delegation chain from `docs/ap2/checkout_mandate.md` —
  `delegate_payload` carrying an array disclosure — parses and resolves here unchanged, returning the delegate with its
  `vct`, `constraints` and `cnf`; and it states what this package does NOT do, which the reference SDK does: validate
  the `vct` against the mandate type.

Both analyses also listed what no competitor has (measured by them as zero occurrences in the repositories of
MandateBound, Verifiable Intent and the AP2 SDK): the hybrid ML-DSA-65 producer signature, the offline-verified RFC 3161
anchor, a second independent verifier with a differential oracle and declared divergences, and normative vectors with
expected verdicts. Those claims are recorded here, not in the README, until they are measured in this repository by a
script anyone can run.

## 1.1.1 — 2026-09-22 — the dependency is declared, and CI tests the distributed package

**Independent AI review, after publication** (the review attacked the framing, not the code, which is what
three passes of a same-family reviewer could not do). Two findings were measured and acted on here; a third is recorded
below because it cannot be fixed without changing the sealed scope.

- **CI tested the repository, never the package.** Every step ran `python test_*.py` inside the checkout with
  `cryptography` installed by the workflow — which is exactly why a missing dependency declaration survived four releases.
  CI now builds the wheel, installs it ALONE in a clean venv, imports it and verifies a vector from there.
- **The README did not name the standards that solve the neighbouring problem.** ASiC (ETSI EN 319 162) and PAdES/XAdES
  LTV already embed certificates, revocation data and timestamps for long-term preservation of signed documents, and any
  eIDAS validator reads them. The README now says so, says when to use those instead, and states the cost of not being a
  standardised container.
- **Recorded, not fixed:** the sealed scope says that for the "existed before a quantum adversary" claim you still need a
  trusted time anchor. Measured: the probe TSA — like essentially every TSA in service — signs with `ecdsa-with-SHA256`.
  An adversary able to forge the ES256 mandate signature can forge that timestamp too, so the anchor does not carry the
  claim unless the TSA itself is post-quantum or the token is renewed under RFC 4998 before the algorithm falls. The
  sentence is not false as written ("you still need") but it is incomplete, and correcting it changes the pinned scope
  hash and therefore rejects every existing pack: it belongs to the next format version, not to a patch release.



`cryptography` was never listed in `[project].dependencies`, in any release: installing from the index produced a package
whose first import failed with `ModuleNotFoundError: No module named 'cryptography'`. The README said to install it by
hand, which is a documented workaround, not a working install — measured in a clean venv right after publishing 1.1.0,
which is what the clean-install step of the release procedure is for. No change to the format, the verifiers, the vectors
or the sealed scope: `ap2-evidence-pack/1.0` packs verify exactly as under 1.1.0.

## 1.1.0 — 2026-09-22 — acceptance profile, one CLI grammar, an independent verifier and a differential oracle

Propagation of the verifier-hygiene classes found in the cra-evidence / omega-evidence / cryptovalid reviews (21/09/2026),
the hygiene classes of the first four bullets were measured on the 1.0.2 verifier first: that day's oracle was red on 97
of its 124 cases there. Later rounds found defects 1.0.2 could not exhibit at all, having neither a second verifier nor
the policy flags.

- **Acceptance profile of the evidence file** (SPEC §3.1): non-UTF-8, BOM, >64 MiB, non-object, duplicate keys, floats,
  integers beyond ±(2^53−1), `NaN`/`Infinity`, nesting >512, lone surrogate escapes are refused with a receipt
  (`valid: false`, `refused: <reason>`) — never a traceback. 1.0.2 crashed on non-UTF-8 (`UnicodeDecodeError`),
  100000-deep (`RecursionError`), a missing path or a directory, and accepted a float, 2^53+1 or a lone surrogate with a
  recomputed digest.
- **Strict base64url / base64**: SD-JWT segments and producer-block values must be canonical (alphabet, length, padding,
  trailing bits). 1.0.2 stripped whitespace and added padding silently, and a space inside a producer signature still
  verified (`sigsuite._unb64` was `b64decode`).
- **One CLI grammar** with the sibling verifiers: `--help`/`-h` (exit 0 before), `--`, an empty or flag-like value at any
  occurrence, an abbreviated flag, a value on a boolean flag, a second positional = usage (exit 2, no verdict); `--flag=value`
  accepted. The relying-party policy is now on the CLI: `--trusted-producer-key ALG=B64` (repeatable), `--require-producer`,
  `--require-pq`, `--require-anchor` (they existed in the API only).
- **Independent verifier** `verifiers/js/ap2-verify.mjs` (Node, `node:crypto` only): ES256, SD-JWT disclosures, KB-JWT,
  bindings, producer Ed25519 / ECDSA P-256 / ML-DSA-65 (OpenSSL ≥ 3.5, else SKIP = incomplete), RFC 3161 status +
  messageImprint (SPEC §3.2), the same profile and CLI grammar.
- **Differential oracle** `verifiers/differential_oracle.py`: 8 vectors (+1 under `--tsa-cert`) + 39 hostile files + 15 CLI cases
  + 1 positive control = 64, 0 disagreements, 1 declared (TSA proof is openssl-only); 43 red against 1.0.2; a crash counts as
  a disagreement. Review round 1 added the wrong-JSON-shape class (tracebacks in the reference), the
  empty producer block, lenient `tsr_b64` and JWK coordinates, the binder-side base64url mutations and the forged TimeStampResp. Two new vectors with a **real RFC 3161 token** from a probe TSA (certificate shipped):
  `anchor_valid` (ACCEPT) and `anchor_wrong_digest` (a real token for another digest: REJECT) — before, the only anchor
  vector was garbage bytes, so a verifier that never parsed the token passed it.
- RFC 3161: `verified` = status granted + messageImprint equals the digest (BINDING), in both verifiers by a DER walk — a
  self-forged TimeStampResp with the right imprint satisfies it, so it never meant TSA authenticity (1.0.x said
  "cryptographically verify": it ran `openssl ts -reply -text`, which verifies nothing). New `--tsa-cert <PEM>`: the
  reference verifies the token's signature and chain with `openssl ts -verify -CAfile` (`tsa_verified`), required by
  `--require-anchor --tsa-cert`; the JS verifier cannot and does not pass that policy (declared).

- **Review round 2** (22/09/2026): the §3.1 profile now applies INSIDE the SD-JWT (issuer header/payload,
  disclosures, KB-JWT) — the reference read the signed payload with `json.loads` (a duplicate key read last-wins, a BOM
  skipped) while the JS parser refused, so one verifier certified `{"amount":"1","amount":"999"}` as `"999"` and the other
  refused it; present-with-`null` is not absent (`dict.get` vs `??`): `_sd`, `_sd_alg`, `{"...": d}`, disclosure names,
  `cnf`, `cnf.jwk` have imposed shapes; JWK `x`/`y` must be 32 bytes (RFC 7518 §6.2.1 — 31/33 bytes verified in the
  reference, refused in JS); `provenance_class` a string (a list was a `TypeError` in `sorted`); `anchored` a boolean
  (`[]` was "not anchored" in the reference and "anchored, unverified" in JS); `sig_alg` a string (`"constructor"` under a
  pinned key crashed the JS verifier on its prototype-bearing table, now `Object.create(null)`; a list was a `TypeError`
  in the reference); an empty EXPLICIT `[0]` in the TimeStampResp was an `IndexError` traceback. Oracle: 90 cases,
  0 disagreements, 1 declared; `proto-key` case rehashed so that it
  can fail; a declared divergence that stops appearing is reported. README: the Node requirement is OpenSSL ≥ 3.5 for
  ML-DSA-65 (not "Node ≥ 20"); the JS conformance test SKIPS on a build without ML-DSA instead of failing.
- **Review round 3** (22/09/2026): `artifacts[].name` must be a non-empty unique string (refusal) — the
  JS binding table was a prototype-bearing object: an absent name was a `TypeError` crash, an int name was stringified
  (`bindings_ok` false against the reference's `true`), `"__proto__"` set the prototype and vanished (valid in the
  reference, not in JS); the JS DER length used `<<` (int32): a 4-byte length `84 80 00 00 00` went negative, passed the
  overrun check and a TimeStampResp the reference refuses verified in JS; the bare invocation of the reference printed its
  help on stdout with exit 2 (now stderr, like every usage path and the JS verifier); the oracle's usage rule is exit 2 AND
  nothing on stdout. Oracle: 97 cases, 0 disagreements, 1 declared; positive controls 5 red on the round-2 state, 26 on the
  round-1 state, 71 on 1.0.2.
- **Review round 4** (22/09/2026): `bindings` is compared as a SET in both verifiers (SPEC §4 now defines
  the entry schema, the claim-path grammar and both encodings) — JavaScript's `Object.keys` enumerates array-index keys
  (`"0"`, `"2"`) before the others, so a cart committing under `intent_hash` and `"0"` was scanned in a different order and
  the ORDERED comparison gave `valid: true` in the reference and `false` in the JS verifier on a pack `build` had produced.
  The ablation is now one layer at a time (ablating strict base64url alone had left the unit suite green — that layer was
  not measured; three base64url cases added). The probe TSA certificate is re-issued for 20 years and the two anchor tokens
  with it (it expired in 2 days, so `tsa_verified` would have gone false in 48 hours); the reference validates the chain at
  the token's own `genTime` (`openssl ts -verify -attime`), both verifiers report `rfc3161.gen_time`; the stale
  `requires: ["openssl"]` is off the anchor vectors (the binding check needs no openssl). Oracle: 102 cases,
  0 disagreements, 1 declared; positive control 2 red on the round-3 state.
- **Review round 5** (22/09/2026): `provenance_class` is RECONCILED with the signed header instead of
  believed — relabelling `jwk_header` as `x5c_header` made `self_asserted_only` false with no `x5c` anywhere (the one
  field the honest scope sends the auditor to), and out-of-enum values passed as strong classes; the enum is closed in
  both verifiers. `evidence_format` and the §1 MUSTs (`subject`, `created_utc`, `honest_scope`) are checked: a
  `ap2-evidence-pack/2.0` pack used to be verified under the 1.0 rules (version confusion) and a pack with no
  `honest_scope` produced a receipt with `honest_scope: null`. The binding scan uses an inverse index instead of a
  per-leaf loop over the artifacts — the cost was quadratic (measured: 0.70 s at 2 000 artifacts, 5.04 s at 4 000;
  after: 0.009 s and 0.015 s, 0.071 s at 16 000); the set of bindings is unchanged. `build` refuses an empty artifact
  name (it used to write a pack, exit 0, that both verifiers then refused) and its CLI validates `name=path` pairs and
  reports unreadable files as usage (exit 2) instead of a `FileNotFoundError` traceback. The oracle now compares the
  eleven normative fields of SPEC §6 plus `provenance_classes` (it compared seven; `provenance_classes` really did diverge, sorted by code point
  in the reference and by UTF-16 code unit in JS — the JS side now uses the same comparator) and runs 113 cases,
  0 disagreements, 1 declared; the file-level ablation is applied at its use site (patching `loads_strict` also ablated
  the JWT level, since `_loads_segment` delegates to it); two tests that claimed "in both verifiers" now skip instead of
  passing when node is absent, and the bare-invocation loop really runs the JS CLI. Three vector descriptions realigned
  with the code (they still said "neither verifier validates the TSA chain", "cryptographic token verification" and
  "the one ACCEPT of the set").
- **Review round 6** (22/09/2026): the JS "JWT header and payload must be objects" check had ended up
  INSIDE an unterminated line comment in round 5 — a signed payload that is a JSON array verified there and failed in the
  reference; it is code again, and the oracle case that was supposed to cover it (`payload-list-rehashed`) turned out to
  swap the segment without re-signing, so both verifiers failed on the signature and the shape rule was never reached:
  the payload/header shape cases are now built as freshly SIGNED packs. The `x5c` leaf is decoded with the strict base64
  decoder in the reference (`base64.b64decode` dropped a space or newline, the JS verifier refused the same bytes) and the
  `x5c_header` branch, which had no coverage at all, gets four oracle cases with a real self-signed leaf. A stray
  `unittest.main()` in the middle of `test_ap2_evidence.py` meant 13 of its 27 tests never ran in CI (holder binding,
  producer content binding, x5c chain limits): removed, and CI now fails if a module collects fewer tests as a script than
  as a module. `created_utc` is imposed as ISO-8601 UTC in both verifiers (SPEC §1 said MUST, only the type was checked).
  Oracle: 121 cases, 0 disagreements, 1 declared; positive control 3 red on the round-5 state.
- **Review round 7** (22/09/2026): `self_asserted_only` is FAIL-CLOSED (SPEC §6.7). Round 5 reconciled
  two of the six spellings of `provenance_class`; the other four still cleared the flag with no evidence at all —
  measured: `"supplied"` and `"jwks_fetched"` cleared it on the strength of the label, and `null` or a DELETED field
  cleared it by making the class set empty. Since `producer_signatures` sits outside the digest, an unsigned pack is
  freely editable, so the one field the honest scope sends the auditor to was the pack author's to choose. Now the class
  is REQUIRED and in the enum (absent/null/other = refusal of that artifact), and the flag is true unless every key was
  reconciled to a certificate leaf that someone else issued — a self-signed `x5c` leaf is still self-asserted. `build`
  no longer tracebacks on an `x5c` leaf wrapped at 76 columns, a non-certificate, a non-string entry or an unreachable
  JWKS (bare `ValueError`/`URLError` escaped `except Ap2EvidenceError`): they are `{"error": …}` receipts, exit 1. The
  oracle compares `rfc3161.gen_time` too and gets a CA-issued `x5c` leaf as the positive control of the honesty flag
  (122 cases, 0 disagreements, 1 declared); an unparseable token returns the same receipt shape in both verifiers; the
  ablation checks the patched module still imports, so a botched patch cannot masquerade as a red ablation.
- **Review round 8** (22/09/2026): round 7 had moved the author's freedom one field along — it cleared
  `self_asserted_only` when the leaf's issuer DN differed from its subject DN, and **measured**: a certificate SELF-SIGNED
  with its own key, declaring `CN=DigiCert Global Root CA` as issuer, cleared the flag in both verifiers on a `valid` pack.
  Offline, "issued by someone else" is not establishable, so nothing clears the flag any more except an `x5c` chain that
  validates to a trust anchor the relying party supplies: new `--trust-anchor <PEM>` (`openssl verify` in the reference,
  `chain_verified` true/false; the JS verifier cannot validate chains and reports `null` — the second declared divergence,
  like `--tsa-cert`). A refusal receipt now carries `self_asserted_only: true` as well (it printed the green value, `false`,
  on a file the verifier had refused to read). `honest_scope` is pinned by SHA-256 to the canonical scope of the declared
  `evidence_format` in both verifiers: the receipt used to REPRINT whatever scope the file carried, so an author could write
  "anchored by a QTSP under eIDAS art. 45j" and see it beside `valid: true`. Oracle: 124 cases, 0 disagreements,
  2 declared.
- **Review round 9** (22/09/2026): `created_utc` was validated with `\d`, which in Python matches every
  Unicode Nd digit and in JavaScript only `[0-9]` — measured: `"٢٠٢٦-٠٩-٢٢T٠٠:٠٠:٠٠Z"` verified in the reference and was
  refused by the JS verifier, opposite verdicts on a pack in profile (non-ASCII text is in profile by §3.1). `--trust-anchor`,
  added in r8, was outside the reference's CLI grammar: `--trust-anchor ""` gave a verdict on stdout there and usage exit 2
  in JS. The x5c chain was validated at the CURRENT clock, so a leaf valid 2020-2021 — the ordinary case for a format whose
  claim is "verifies offline years later" — could never clear `self_asserted_only`; it is now validated at the `genTime` of a
  TSA-verified token when the pack carries one, like the TSA chain since r4. `chain_verified` is tri-state (`null` when
  openssl is absent: unmeasurable is not failed) and present in refusal receipts, which lacked it while the JS ones had it.
  Both verifiers now report `artifacts[].x5c_leaf` (subject and issuer DN, serial, validity, SHA-256): a cleared flag means
  a CA under the relying party's anchor certified that key, never that the key belongs to the mandate's issuer — without the
  DN an auditor cannot tell `CN=the-bank` from `CN=attacker`. Oracle: 129 cases, 0 disagreements, 2 declared; positive
  control 4 red on the round-8 state, plus a unit test for the expired leaf measured red there.
- **Review round 10** (22/09/2026): `self_asserted_only` was computed with `all()` over the per-artifact
  flags, so ONE reconciled artifact cleared it for the whole pack — measured: a pack whose mandate carried a self-asserted
  `jwk_header` key and whose second artifact chained to the relying party's anchor reported `self_asserted_only: false`,
  i.e. "no self-asserted key here", while the mandate-signing key had never been reconciled at all (and the JS verifier
  said `true`: an undeclared divergence the oracle could not see). It is `any()` in both now. The reference asserted
  `granted: false` on a truncated token whose PKIStatus it had already read as granted; both verifiers now carry the status
  that was actually read into the failure path, or `null`. The JS receipt did not carry the leaf validity that SPEC §6.7
  requires, and rendered DNs in OpenSSL multi-line form while the reference used RFC 4514 — the same certificate produced
  two different receipts in the field §6.7 asks for precisely to tell `CN=the-bank` from `CN=attacker`; RFC 4514 in both.
  The oracle now compares `rfc3161.granted`, `rfc3161.imprint_ok`, `chain_verified` and the `x5c_leaf` identity: 130 cases,
  0 disagreements, 3 declared, and **10 red** against the round-9 state. README: 19 CLI cases, not 16.
- **Self-audit before release** (22/09/2026, on the error classes committed during these rounds): the README's "hostile
  files" count had gone stale a third time (97 against 99 measured), so the oracle now PRINTS its own decomposition
  (`9 vector runs + 99 hostile files + 3 positive controls + 19 CLI cases = 130`) and the public numbers are copied from a
  measurement instead of counted by hand. A trailing `//` comment swallowed the rest of its line twice in one day — a shape
  check, then `policy_ok` — so `test_both_receipts_carry_the_same_field_names` now compares the KEY SETS of the two
  receipts (top level, per artifact, `rfc3161`, and on a refusal), measured red against the previous commit; it caught
  `mldsa_backend`, emitted by the JS verifier alone and documented nowhere, which is now in both receipts and in SPEC §6.
  Last of the "asserted but not measured" class: `granted` is `null`, not `false`, when `tsr_b64` never decoded and no
  PKIStatus was ever read. Checked and clean: no hostile oracle case shares the intact vector's verdict tuple.
- **Review round 11** (22/09/2026), the last before the release: the sealed `honest_scope` said the
  format "does NOT validate x5c chains to a trust anchor", which round 8 had made false — so a `verify --trust-anchor`
  printed `chain_verified: true` in the same JSON object as a scope denying that chains are ever validated. The scope is
  pinned by SHA-256, so correcting it invalidates every existing pack: it was done now, before the tag, and the whole
  vector set was regenerated with fresh keys and two re-issued RFC 3161 tokens (the declared genTime in the oracle moved
  with them — the run reported the mismatch instead of passing silently, which is what that guard is for).
  `chain_verified` no longer collapses to `null` because a pack also contains a non-x5c artifact: only artifacts that
  attempted a chain count, so a mandate/cart pack mixing `jwk_header` and `x5c_header` now reports what was measured —
  the round-10 `all()` defect one field over, and invisible to the oracle because the JS verifier always answers `null`.
  `imprint_ok` is `null` wherever no messageImprint was read (it asserted `false`, the same accusation round 10 made of
  `granted`, applied to half the object), and the two early `return`s of the JS token walk carry the same fields as every
  other branch. The reference emits `x5c_leaf.chain_verified` always, as the JS receipt did: the same certificate was
  producing a six-field receipt on one side and a seven-field one on the other. Oracle: 130 cases, 0 disagreements,
  4 declared.

- **Final check before the tag** (22/09/2026): three public sentences were false of the measurements and one
  rule the verifiers enforce was missing from the SPEC. `self_asserted_only` printed its GREEN value on a pack with zero
  artifacts (`any()` over an empty list) — the honesty flag is fail-closed there too now, in both verifiers, held by
  `test_honesty_flag_and_scope_are_fail_closed` measured red against the previous commit. Both verifiers refused a
  rewritten `honest_scope` citing "SPEC §1", but the SPEC carried neither the canonical text nor its hash: §1 now pins it
  by SHA-256 and §8 reproduces it verbatim, so an independent implementation can enforce the rule from the text alone.
  The sealed scope itself said "nothing about a chain is sealed in this file" (the x5c bytes are sealed; the validation
  RESULT is not) and that an RFC 3161 token attests the TSA's clock without adding that this holds only once the relying
  party verifies the TSA signature — both corrected, which changed the pinned hash a second time and regenerated the
  vectors again. Stale numbers fixed: the ablation is 1 error + 1 failure on the first layer, the declared divergences are
  three `--trust-anchor` packs plus the `--tsa-cert` one, and the hostile-file list named three cases that do not exist.

- **After the second final pass** (22/09/2026): the sealed scope promises the KB-JWT `aud`/`nonce`/`iat` are RECORDED
  whenever a KB-JWT is present. Measured: neither verifier recorded them on the branch where the KB-JWT carries no
  `cnf.jwk` — the reference returned early with a `note`, the JS verifier without one, so the two receipts differed in
  shape there as well. Both record them on every branch now, with identical fields, and the receipt-shape test covers a
  pack that carries a KB-JWT (red against the previous commit). Found by checking the branch the tests did not reach.
  That prompted a coverage measurement of the whole reference under the tests AND the oracle — 79% of its lines — which
  named `verify_kb_jwt` as the least exercised path. Probing its six uncovered branches found another defect, shared by
  both verifiers: a KB-JWT whose signature segment is non-canonical base64url verified with `valid: true`, because the
  branch for an unknown holder key returns before the signature is ever decoded, so the §3.1 profile never reached it.
  Both verifiers now apply the profile to all three KB-JWT segments; measured on the previous commit, that pack was
  `valid: true` in both. The same measurement was then redone counting the subprocesses the oracle spawns (85%, not 79%:
  the first figure missed every case the oracle runs out of process — a measuring instrument reading the wrong quantity,
  which is the class this release kept finding). The next largest uncovered region, the seven `resolve_disclosures`
  branches, was probed the same way and found CONCORDANT and correct in both verifiers — no defect there. Both sets are
  oracle cases now: 144 cases, 0 disagreements, 4 declared.

**Breaking: 1.1.0 refuses every pack built by 1.0.x.** The scope statement is sealed and pinned by SHA-256 (SPEC §1/§8),
and it was corrected during the review rounds, so a 1.0.x pack is refused with `honest_scope does not match the canonical
scope of this evidence_format` — measured on a pack built with the `v1.0.2` tree and verified with this one, in both
verifiers. Re-build with 1.1.0: a pack built by this tree is ACCEPT in both verifiers and the
conformance runner exits 0 on all eight vectors.
