#!/usr/bin/env node
// verify_many — test harness, not a verifier: loads the JS verifier at <ap2-verify.mjs> (any revision that exports
// verifyEvidence — the 1.3.0 one too, for the positive control of verifiers/schema_mutants.py) and runs it in-process on
// every entry of a manifest, so a corpus of thousands of mutants costs one Node start instead of thousands.
// Usage: node verify_many.mjs <ap2-verify.mjs> <manifest.json>
//   manifest: [{"name": ..., "path": ..., "flags": ["--trusted-producer-key", "ALG=B64", "--require-pq", ...]}, ...]
//   stdout:   {"<name>": <receipt or {"crash": "<message>"}>, ...}
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function opts(flags) {
  const o = { trusted: null };
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i];
    if (f === "--trusted-producer-key") { const v = flags[++i]; const k = v.indexOf("="); o.trusted = o.trusted ?? Object.create(null); (o.trusted[v.slice(0, k)] ??= []).push(v.slice(k + 1)); }
    else if (f === "--require-producer") o.requireProducer = true;
    else if (f === "--require-pq") o.requirePq = true;
    else if (f === "--require-anchor") o.requireAnchor = true;
    else if (f === "--tsa-cert") o.tsaCert = flags[++i];
    else if (f === "--trust-anchor") flags[++i];
    else throw new Error("unknown flag " + f);
  }
  return o;
}

const [, , verifierPath, manifestPath] = process.argv;
if (!verifierPath || !manifestPath) { console.error("usage: verify_many.mjs <ap2-verify.mjs> <manifest.json>"); process.exit(2); }
const { verifyEvidence } = await import(pathToFileURL(verifierPath).href);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const out = {};
for (const m of manifest) {
  try { out[m.name] = verifyEvidence(m.path, opts(m.flags ?? [])); }
  catch (e) { out[m.name] = { crash: String(e?.message ?? e) }; }   // a crash is a finding, never a silent omission
}
process.stdout.write(JSON.stringify(out));
