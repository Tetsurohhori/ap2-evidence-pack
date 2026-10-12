#!/usr/bin/env node
// ap2-verify — independent JavaScript verifier of ap2-evidence-pack evidence files (SPEC_AP2_EVIDENCE.md), Node with OpenSSL >= 3.5 for ML-DSA-65,
// node:crypto only (no ap2_evidence code, no dependency). Same normative facts as ap2_evidence.verify_evidence:
// digest_ok, per-artifact ES256 signature / disclosures / KB-JWT, bindings, producer signatures (ed25519, ecdsa-p256;
// ml-dsa-65 through the Node build's OpenSSL >= 3.5, else SKIP = incomplete, never a pass), policy flags, valid.
// Acceptance profile of the file (SPEC §3.1): strict UTF-8, no BOM, no duplicate keys, no floats, integers within
// +/-(2^53-1), nesting <= 512, no lone surrogate escape, 64 MiB bound. A refused file is a receipt with valid=false.
// Usage: ap2-verify.mjs <evidence.json> [--trusted-producer-key ALG=B64]... [--require-producer] [--require-pq] [--require-anchor] [--min-anchors N] [--tsa-cert PEM] [--trust-anchor PEM]
import { statSync, openSync, fstatSync, readSync, closeSync, constants as FS } from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify, X509Certificate } from "node:crypto";

const MAX_DEPTH = 512, MAX_BYTES = 64 * 1024 * 1024, SAFE = 2 ** 53 - 1;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
class Refused extends Error {}

// ---- strict JSON parser (keeps number lexemes; refuses what the profile refuses) ----
function parseStrict(text) {
  let i = 0, depth = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const err = (m) => { throw new Refused(m + " at " + i); };
  function str() {
    i++; let out = "";
    for (;;) { if (i >= text.length) err("eof in string"); const c = text[i++];
      if (c === '"') return out;
      if (c === "\\") { const e = text[i++];
        if (e === "u") { const h = text.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) err("bad \\u"); i += 4; let cp = parseInt(h, 16);
          if (cp >= 0xd800 && cp <= 0xdbff) { if (text[i] === "\\" && text[i + 1] === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { const lo = parseInt(text.slice(i + 2, i + 6), 16); if (lo >= 0xdc00 && lo <= 0xdfff) { i += 6; cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); } else err("lone surrogate"); } else err("lone surrogate"); }
          else if (cp >= 0xdc00 && cp <= 0xdfff) err("lone surrogate");
          out += String.fromCodePoint(cp); }
        else { const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }; if (!(e in map)) err("bad escape"); out += map[e]; } }
      else { if (c.charCodeAt(0) < 0x20) err("control character in string"); out += c; } }
  }
  function value() {
    ws(); const c = text[i];
    if (c === "{") { if (++depth > MAX_DEPTH) err("too deep"); i++; const o = Object.create(null); ws(); if (text[i] === "}") { i++; depth--; return o; }
      for (;;) { ws(); if (text[i] !== '"') err("key"); const k = str(); ws(); if (text[i] !== ":") err("colon"); i++; if (k in o) err("duplicate key " + k); o[k] = value(); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "}") { i++; depth--; return o; } err("object"); } }
    if (c === "[") { if (++depth > MAX_DEPTH) err("too deep"); i++; const a = []; ws(); if (text[i] === "]") { i++; depth--; return a; }
      for (;;) { a.push(value()); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "]") { i++; depth--; return a; } err("array"); } }
    if (c === '"') return str();
    if (text.startsWith("true", i)) { i += 4; return true; } if (text.startsWith("false", i)) { i += 5; return false; } if (text.startsWith("null", i)) { i += 4; return null; }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i)); if (!m) err("value");
    if (m[2] || m[3]) err("float " + m[0]); const n = Number(m[0]); if (!Number.isSafeInteger(n) || Math.abs(n) > SAFE) err("integer out of range"); i += m[0].length; return n;
  }
  const v = value(); ws(); if (i !== text.length) err("trailing data"); return v;
}
// ---- canonical form (SPEC §3): sorted keys, "," ":" separators, ensure_ascii (non-ASCII -> \uXXXX, lowercase hex, surrogate pairs) ----
function esc(s) { let o = '"'; for (const ch of s) { const cp = ch.codePointAt(0);
  if (ch === '"') o += '\\"'; else if (ch === "\\") o += "\\\\"; else if (ch === "\n") o += "\\n"; else if (ch === "\r") o += "\\r"; else if (ch === "\t") o += "\\t"; else if (ch === "\b") o += "\\b"; else if (ch === "\f") o += "\\f";
  else if (cp < 0x20 || cp === 0x7f) o += "\\u" + cp.toString(16).padStart(4, "0");
  else if (cp > 0x7f) { if (cp > 0xffff) { const v = cp - 0x10000; o += "\\u" + (0xd800 + (v >> 10)).toString(16).padStart(4, "0") + "\\u" + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0"); } else o += "\\u" + cp.toString(16).padStart(4, "0"); }
  else o += ch; } return o + '"'; }
const cmp = (a, b) => { const A = Array.from(a, (c) => c.codePointAt(0)), B = Array.from(b, (c) => c.codePointAt(0)); for (let k = 0; k < Math.min(A.length, B.length); k++) if (A[k] !== B[k]) return A[k] - B[k]; return A.length - B.length; };
function canon(v) { if (v === null) return "null"; if (v === true) return "true"; if (v === false) return "false"; if (typeof v === "number") return String(v); if (typeof v === "string") return esc(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]"; return "{" + Object.keys(v).sort(cmp).map((k) => esc(k) + ":" + canon(v[k])).join(",") + "}"; }
const sha256 = (b) => createHash("sha256").update(b).digest();
const b64u = (b) => Buffer.from(b).toString("base64url");
const EVIDENCE_FORMAT = "ap2-evidence-pack/1.0";
const HONEST_SCOPE_SHA256 = "a4b12a682847c23c4a136dd399c6aa0dfa69540a5c7200039d506e86ac31dfbf";   // SPEC §1: sha256 of the canonical honest scope of this format version
const B64URL = /^[A-Za-z0-9_-]+$/;
function b64uDecode(s) { if (typeof s !== "string" || !s || !B64URL.test(s) || s.length % 4 === 1) throw new Refused("invalid base64url segment"); const raw = Buffer.from(s, "base64url"); if (b64u(raw) !== s) throw new Refused("non-canonical base64url"); return raw; }
const b64Strict = (s) => { if (typeof s !== "string" || !s || s.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null; const raw = Buffer.from(s, "base64"); return raw.toString("base64") === s ? raw : null; };
function jsonOf(buf) { const t = UTF8.decode(buf); return parseStrict(t); }

// ---- SD-JWT ----
function parseSdJwt(compact) {
  if (typeof compact !== "string") throw new Refused("sd_jwt_compact not a string");
  compact = compact.trim(); let jwt, middle, kb;
  if (compact.includes("~")) { const parts = compact.split("~"); jwt = parts[0]; middle = parts.slice(1, -1); kb = parts[parts.length - 1] || null; } else { jwt = compact; middle = []; kb = null; }
  const seg = jwt.split("."); if (seg.length !== 3) throw new Refused("issuer JWT must have 3 dot-separated segments");
  let header, payload; try { header = jsonOf(b64uDecode(seg[0])); payload = jsonOf(b64uDecode(seg[1])); } catch (e) { throw new Refused("JWT header/payload not valid JSON/base64url: " + e.message); }
  return { compact, jwt, header, payload, signature: b64uDecode(seg[2]), signingInput: Buffer.from(seg[0] + "." + seg[1], "ascii"), disclosures: middle.filter((d) => d), kbJwt: kb };
}
function resolveDisclosures(payload, disclosures) {
  // r2: SHAPES imposed, present-with-null is not absent (`??` said it was; the reference's dict.get did not): _sd_alg absent or "sha-256",
  // _sd absent or a list of strings, {"...": x} with x a string, a disclosed claim name a string
  if ("_sd_alg" in payload && payload._sd_alg !== "sha-256") throw new Refused("_sd_alg unsupported");
  const byDigest = new Map();
  for (const d of disclosures) { let arr; try { arr = jsonOf(b64uDecode(d)); } catch (e) { throw new Refused("malformed disclosure: " + e.message); }
    if (!Array.isArray(arr) || ![2, 3].includes(arr.length)) throw new Refused("disclosure must be [salt,name,value] or [salt,value]");
    const dig = b64u(sha256(Buffer.from(d, "ascii"))); if (byDigest.has(dig)) throw new Refused("duplicate disclosure digest"); byDigest.set(dig, arr); }
  const used = new Set();
  function walk(node) {
    if (node !== null && typeof node === "object" && !Array.isArray(node)) { const out = Object.create(null);
      for (const k of Object.keys(node)) { if (k === "_sd" || k === "_sd_alg") continue; out[k] = walk(node[k]); }
      const sd = "_sd" in node ? node._sd : []; if (!Array.isArray(sd) || sd.some((x) => typeof x !== "string")) throw new Refused("_sd must be a list of digest strings");
      for (const dig of sd) { if (byDigest.has(dig)) { const arr = byDigest.get(dig); if (arr.length !== 3) throw new Refused("object disclosure must be [salt,name,value]"); if (typeof arr[1] !== "string") throw new Refused("disclosed claim name must be a string"); if (arr[1] in out) throw new Refused("disclosed claim collides"); out[arr[1]] = walk(arr[2]); used.add(dig); } }
      return out; }
    if (Array.isArray(node)) { const out = []; for (const item of node) { if (item !== null && typeof item === "object" && !Array.isArray(item) && Object.keys(item).length === 1 && "..." in item) { const dig = item["..."]; if (typeof dig !== "string") throw new Refused("array disclosure placeholder must be a digest string"); if (byDigest.has(dig)) { const arr = byDigest.get(dig); if (arr.length !== 2) throw new Refused("array disclosure must be [salt,value]"); out.push(walk(arr[1])); used.add(dig); } } else out.push(walk(item)); } return out; }
    return node;
  }
  const resolved = walk(payload); for (const dig of byDigest.keys()) if (!used.has(dig)) throw new Refused("disclosure(s) match no digest");
  return resolved;
}
function es256Verify(signingInput, signature, jwk) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk) || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Refused("jwk is not EC P-256");
  const x = b64uDecode(jwk.x), y = b64uDecode(jwk.y);   // r1: Node's JWK import decodes leniently (padding, +/); the reference is strict — decode strictly first
  if (x.length !== 32 || y.length !== 32) throw new Refused("jwk coordinates must be 32 bytes");
  if (signature.length !== 64) throw new Refused("ES256 signature must be 64 bytes");
  const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(x), y: b64u(y) }, format: "jwk" });
  try { return cryptoVerify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature); } catch { return false; }
}
function verifyKbJwt(parsed, resolved) {
  const kb = parsed.kbJwt; if (!kb) return { present: false };
  const seg = kb.split("."); if (seg.length !== 3) throw new Refused("kb-jwt must have 3 dot-separated segments");
  let header, payload; try { header = jsonOf(b64uDecode(seg[0])); payload = jsonOf(b64uDecode(seg[1])); } catch (e) { throw new Refused("kb-jwt header/payload invalid: " + e.message); }   // 1.4.0: the inner reason, as the reference
  if (header.alg !== "ES256") throw new Refused("kb-jwt alg unsupported");
  if (typeof header !== "object" || header === null || Array.isArray(header) || typeof payload !== "object" || payload === null || Array.isArray(payload)) throw new Refused("kb-jwt header and payload must be objects");
  // 1.4.0 (SPEC §9.2): RFC 9901 §4.3 — typ REQUIRED, MUST be kb+jwt (§7.3 step 5.d); iat/aud/nonce/sd_hash REQUIRED with their types.
  // Presence and type, never the values (sealed scope: recorded, not validated). Checked whether or not the holder key is known.
  if (header.typ !== "kb+jwt") throw new Refused('kb-jwt typ must be "kb+jwt" (RFC 9901 §4.3)');
  const ignored = { kb_jwt_header: joseHeaderIgnored(header, "kb-jwt header") };
  for (const [claim, pred, desc] of [["iat", (v) => Number.isInteger(v), "an integer"], ["aud", isStr, "a string"], ["nonce", isStr, "a string"], ["sd_hash", isStr, "a string"]]) {
    if (!(claim in payload)) throw new Refused("kb-jwt payload: missing " + claim + " (RFC 9901 §4.3)");
    if (!pred(payload[claim])) throw new Refused("kb-jwt payload: " + claim + " must be " + desc + " (RFC 9901 §4.3)"); }
  ignored.kb_jwt_claims = unknownMembers(payload, KB_CLAIMS_REGISTERED);
  const cnf = resolved !== null && typeof resolved === "object" && "cnf" in resolved ? resolved.cnf : undefined;   // r2: cnf absent or object; cnf.jwk absent or object
  if (cnf !== undefined && (cnf === null || typeof cnf !== "object" || Array.isArray(cnf))) throw new Refused("cnf must be an object");
  ignored.cnf = unknownMembers(cnf, CNF_REGISTERED);   // RFC 7800 §3.1: not understood -> ignored, here reported
  b64uDecode(seg[2]);   // §3.1 applies to all three segments even when the holder key is unknown (see the reference)
  const recorded = {}; for (const k of ["aud", "nonce", "iat"]) if (k in payload) recorded[k] = payload[k];   // the sealed scope says these are RECORDED whenever a KB-JWT is present
  const jwk = cnf !== undefined && "jwk" in cnf ? cnf.jwk : undefined;
  if (jwk === undefined) return { present: true, verified: null, claims_recorded_not_validated: recorded, note: "no cnf.jwk in issuer payload — holder key unknown (declared)", _ignored: ignored };
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) throw new Refused("cnf.jwk must be an object");
  ignored.cnf_jwk = unknownMembers(jwk, JWK_REGISTERED);   // RFC 7517 §4
  const sigOk = es256Verify(Buffer.from(seg[0] + "." + seg[1], "ascii"), b64uDecode(seg[2]), jwk);
  const presentation = parsed.compact.slice(0, parsed.compact.lastIndexOf("~")) + "~";
  const sdHashOk = payload.sd_hash === b64u(sha256(Buffer.from(presentation, "ascii")));
  return { present: true, verified: Boolean(sigOk && sdHashOk), signature_ok: sigOk, sd_hash_ok: sdHashOk, note: null, claims_recorded_not_validated: recorded, _ignored: ignored };   // final check: the sealed scope says these are RECORDED — the reference did it, this verifier did not
}
const PROVENANCE_CLASSES = new Set(["supplied", "x5c_header", "jwk_header", "jwks_fetched"]);
// ---- closed schema (SPEC §9, 1.4.0): every object this format defines is an exhaustive key list (unknown = refusal / artifact
// error / FAIL entry, the key named); every object a standard defines follows that standard's rule for the unknown (ignored AND
// reported). Measured 2026-10-10 on 1.3.0: a key nobody defined inside rfc3161_timestamp, the producer block or a signature entry
// was accepted with valid: true and no trace in the receipt. Same lists, same three messages as the reference.
const JOSE_HEADER_REGISTERED = new Set(["alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"]);   // RFC 7515 §4.1, RFC 7519 §5
const JWK_REGISTERED = new Set(["kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "d"]);   // RFC 7517 §4, RFC 7518 §6.2
const CNF_REGISTERED = new Set(["jwk", "jwe", "jku", "kid"]);                                                                     // RFC 7800 §3.1
const KB_CLAIMS_REGISTERED = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "sd_hash"]);                      // RFC 7519 §4.1, RFC 9901 §4.3
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v) => typeof v === "string", isBool = (v) => typeof v === "boolean", isList = Array.isArray;
const T = {
  str: [isStr, "a string"], bool: [isBool, "a boolean"], obj: [isObj, "an object"], list: [isList, "a list"], any: [() => true, ""],
  strOrNull: [(v) => v === null || isStr(v), "a string or null"], boolOrNull: [(v) => v === null || isBool(v), "a boolean or null"],
  isTrue: [(v) => v === true, "true"], listOfStr: [(v) => isList(v) && v.every(isStr), "a list of strings"],
  scheme: [(v) => v === "hybrid" || v === "classical-only", '"hybrid" or "classical-only"'], over: [(v) => v === "evidence_digest_sha256", '"evidence_digest_sha256"'],
  enc: [(v) => v === "hex" || v === "b64url", '"hex" or "b64url"'] };
// [type, required]
const TOP_KEYS = { evidence_format: [T.str, 1], subject: [T.str, 1], created_utc: [T.str, 1], artifacts: [T.list, 1], bindings: [T.list, 0], honest_scope: [T.str, 1],
                   evidence_digest_sha256: [T.str, 1], rfc3161_timestamp: [T.obj, 0], producer_signatures: [T.obj, 0],
                   anchors: [[(v) => isList(v) && v.length > 0, "a non-empty list"], 0] };   // 1.5.0 — SPEC §3.3
const ANCHOR_MECHANISMS = ["rfc3161"];   // SPEC §3.3: the mechanisms this revision defines; any other is a refusal naming it
const ANCHOR_RFC3161_KEYS = { mechanism: [[(v) => v === "rfc3161", '"rfc3161"'], 1], tsr_b64: [T.str, 1], tsa_url: [T.str, 0], note: [T.str, 0] };
const DIGEST_EXCLUDED = ["evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures", "anchors"];   // SPEC §3 (1.5.0: + anchors)
const RFC3161_KEYS = { anchored: [T.bool, 1], tsr_b64: [T.str, 0], tsa_url: [T.str, 0], tsa: [T.str, 0], note: [T.str, 0] };   // tsr_b64 ABSENT under anchored: §6.4, rfc3161_verified false
const PRODUCER_KEYS = { scheme: [T.scheme, 1], over: [T.over, 1], signatures: [T.list, 1] };
const BINDING_KEYS = { in: [T.str, 1], claim: [T.str, 1], commits_to: [T.str, 1], encoding: [T.enc, 1] };
const ARTIFACT_KEYS = { name: [T.str, 1], sd_jwt_compact: [T.str, 1], header: [T.obj, 1], key: [T.obj, 1], resolved_claims: [T.any, 1], kb_jwt: [T.obj, 1], verified_at_build: [T.obj, 1] };
const KEY_KEYS = { jwk: [T.obj, 1], provenance_class: [T.str, 1], note: [T.str, 0], x5c_chain_sha256: [T.listOfStr, 0], jwks_url: [T.str, 0], jwks_sha256: [T.str, 0], fetched_utc: [T.str, 0] };
const KB_COPY_KEYS = { present: [T.bool, 1], verified: [T.boolOrNull, 0], signature_ok: [T.bool, 0], sd_hash_ok: [T.bool, 0], note: [T.strOrNull, 0], claims_recorded_not_validated: [T.obj, 0] };
const VAB_KEYS = { signature_ok: [T.isTrue, 1], disclosures_ok: [T.isTrue, 1] };
const ENTRY_KEYS = new Set(["sig_alg", "public_key_b64", "signature_b64", "post_quantum"]);
const byCodePoint = (a, b) => { const x = Array.from(a), y = Array.from(b); for (let i = 0; i < Math.min(x.length, y.length); i++) { const d = x[i].codePointAt(0) - y[i].codePointAt(0); if (d) return d; } return x.length - y.length; };
function entryShapeNote(entry) {   // SPEC §9.1 FAIL entry: the same note as the reference's _entry_shape_note (unknown keys by code point, then missing)
  const own = isObj(entry) ? Object.keys(entry) : [];
  const unknown = own.filter((k) => !ENTRY_KEYS.has(k)).sort(byCodePoint), missing = [...ENTRY_KEYS].filter((k) => !own.includes(k)).sort(byCodePoint);
  let note = "entry is not the closed shape of SPEC §9.1";
  if (unknown.length) note += "; unknown key(s) " + JSON.stringify(unknown);
  if (missing.length) note += "; missing " + JSON.stringify(missing);
  return note;
}
function checkClosed(obj, what, allowed) {   // SPEC §9.1 — the same three messages as the reference's _check_closed
  if (!isObj(obj)) throw new Refused(what + " must be an object (SPEC §9.1)");
  const unknown = Object.keys(obj).filter((k) => !Object.hasOwn(allowed, k)).sort(byCodePoint);   // 1.4.1: the first by code point, as the reference
  if (unknown.length) throw new Refused(what + ": unknown key " + JSON.stringify(unknown[0]) + " (SPEC §9.1)");
  for (const [k, [[pred, desc], required]] of Object.entries(allowed)) {
    if (k in obj) { if (!pred(obj[k])) throw new Refused(what + ": " + k + " must be " + desc + " (SPEC §9.1)"); }
    else if (required) throw new Refused(what + ": missing " + k + " (SPEC §9.1)"); }
}
function joseHeaderIgnored(header, what) {   // RFC 7515 §4 (ignore when not understood) and §4.1.11 (crit: an extension not understood = the JWS is invalid)
  if ("crit" in header) { const c = header.crit;
    if (!isList(c) || !c.length || c.some((x) => !isStr(x)) || new Set(c).size !== c.length || c.some((x) => JOSE_HEADER_REGISTERED.has(x) || !(x in header))) throw new Refused(what + ": malformed crit (RFC 7515 §4.1.11)");
    throw new Refused(what + ": crit names extension(s) this verifier does not understand (RFC 7515 §4.1.11: the JWS is invalid)"); }
  return Object.keys(header).filter((k) => !JOSE_HEADER_REGISTERED.has(k)).sort(cmp);
}
const unknownMembers = (obj, registered) => isObj(obj) ? Object.keys(obj).filter((k) => !registered.has(k)).sort(cmp) : [];
function checkProvenance(pc, parsed, key) {   // returns: is this key SELF-ASSERTED as far as an offline verifier can tell? (r7, fail-closed)
  // r5: `jwk_header`/`x5c_header` are RECONCILED with the header the verifier just parsed (relabelling jwk_header as
  // x5c_header used to flip self_asserted_only to false with no x5c anywhere); `supplied`/`jwks_fetched` are capture-time
  // assertions that cannot be checked offline (SPEC §2).
  if (pc !== "jwk_header" && pc !== "x5c_header") return { selfAsserted: true, ident: null };   // supplied / jwks_fetched: capture-time labels, not checkable here
  const header = parsed.header && typeof parsed.header === "object" ? parsed.header : {};
  const jwk = key.jwk ?? {};
  if (pc === "jwk_header") {
    const hj = header.jwk;
    if (!hj || typeof hj !== "object" || Array.isArray(hj) || ["kty", "crv", "x", "y"].some((f) => hj[f] !== jwk[f])) throw new Refused("provenance_class jwk_header but the signed header carries no matching jwk");
    return { selfAsserted: true, ident: null };
  }
  const x5c = header.x5c;
  if (!Array.isArray(x5c) || !x5c.length || typeof x5c[0] !== "string") throw new Refused("provenance_class x5c_header but the signed header carries no x5c");
  let leaf, ident;
  try {
    const der = b64Strict(x5c[0]); if (!der) throw new Error("leaf not base64");
    const cert = new X509Certificate(der);
    leaf = createPublicKey({ key: cert.publicKey.export({ format: "jwk" }), format: "jwk" }).export({ format: "jwk" });
    // r9: the receipt names WHO the certificate was issued to — a cleared flag means "a CA under your anchor certified this key",
    // never "the key belongs to the mandate's issuer", and an auditor cannot tell CN=the-bank from CN=attacker without this
    // r10: RFC 4514 (most specific RDN first, comma-separated) in both verifiers — Node renders a DN as OpenSSL multi-line
    // in the opposite order, so the same certificate produced two different receipts in the field §6.7 asks for precisely
    // to tell CN=the-bank from CN=attacker. Validity too: it is a MUST of §6.7 and it was missing here.
    const rfc4514 = (dn) => String(dn).split("\n").filter(Boolean).reverse().join(",");
    const isoZ = (t) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
    ident = { subject: rfc4514(cert.subject), issuer: rfc4514(cert.issuer), serial: cert.serialNumber.toLowerCase().replace(/^0+/, ""),
              not_valid_before: isoZ(cert.validFrom), not_valid_after: isoZ(cert.validTo),
              sha256: createHash("sha256").update(der).digest("hex"), chain_verified: null };
  } catch (e) { throw new Refused("provenance_class x5c_header but the x5c leaf is unusable"); }
  if (["kty", "crv", "x", "y"].some((f) => leaf[f] !== jwk[f])) throw new Refused("provenance_class x5c_header but the x5c leaf key differs from the snapshotted jwk");
  // r8: r7 read "issued by someone else" off `subject !== issuer` — two DN strings the forger writes himself (a leaf
  // self-signed with its own key, declaring CN=DigiCert Global Root CA, cleared the flag). Offline that is not
  // establishable; only a chain validated to a relying-party trust anchor clears it, and this verifier cannot validate
  // chains, so it always reports the key as self-asserted and `chain_verified: null` (declared, like tsa_verified).
  return { selfAsserted: true, ident };   // this verifier cannot validate chains: always self-asserted (declared)
}
function findBindings(arts) {
  const byValue = new Map();   // r5: inverse index (digest string -> [name, encoding]) — the per-leaf scan was O(artifacts), quadratic
  for (const a of arts) { const raw = Buffer.from(a.compact, "ascii"); const h = sha256(raw); for (const [v, enc] of [[h.toString("hex"), "hex"], [b64u(h), "b64url"]]) { if (!byValue.has(v)) byValue.set(v, []); byValue.get(v).push([a.name, enc]); } }
  const found = [];
  function scan(node, path, holder) { if (node !== null && typeof node === "object" && !Array.isArray(node)) { for (const k of Object.keys(node)) scan(node[k], path ? path + "." + k : k, holder); }
    else if (Array.isArray(node)) node.forEach((v, i) => scan(v, path + "[" + i + "]", holder));
    else if (typeof node === "string") { for (const [other, enc] of byValue.get(node) ?? []) { if (other === holder) continue; found.push({ in: holder, claim: path, commits_to: other, encoding: enc }); } } }
  for (const a of arts) scan(a.resolved, "", a.name); return found;
}
// ---- producer signatures ----
const MLDSA65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");   // SEQ{ SEQ{OID 2.16.840.1.101.3.4.3.18}, BIT STRING(0x00||1952 bytes) } — the wrapping measured in omega-evidence
// small-order / non-canonical Ed25519 keys: with the identity key R=identity, S=0 verifies on every message and OpenSSL accepts it (measured 25/09/2026); with any small-order key a signature on any message can be built by choosing R, measured 26/09/2026; same list in verifiers/js/ap2-verify.mjs
const WEAK_ED25519 = new Set(["0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000080", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]);
function weakEd25519(pk) {
  if (WEAK_ED25519.has(pk.toString("hex"))) return true;
  if ((pk[31] & 0x7f) !== 0x7f || pk[0] < 0xed) return false;
  for (let i = 1; i < 31; i++) if (pk[i] !== 0xff) return false;
  return true;
}
const HAVE_MLDSA = (() => { try { createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.alloc(1952)]), format: "der", type: "spki" }); return true; } catch { return false; } })();
function verifyProducer(alg, pubB64, sigB64, message) {
  const pk = b64Strict(pubB64), sig = b64Strict(sigB64); if (!pk || !sig) return false;
  try {
    if (alg === "ed25519") { if (pk.length !== 32 || sig.length !== 64 || weakEd25519(pk)) return false; const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pk]), format: "der", type: "spki" }); return cryptoVerify(null, message, key, sig); }
    if (alg === "ecdsa-p256") { if (sig.length !== 64 || pk.length !== 65 || pk[0] !== 4) return false; const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: pk.subarray(1, 33).toString("base64url"), y: pk.subarray(33).toString("base64url") }, format: "jwk" }); return cryptoVerify("sha256", message, { key, dsaEncoding: "ieee-p1363" }, sig); }
    if (alg === "ml-dsa-65") { if (!HAVE_MLDSA) return null; if (pk.length !== 1952 || sig.length !== 3309) return false;
      const key = createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, pk]), format: "der", type: "spki" }); return cryptoVerify(null, message, key, sig); }
  } catch { return false; }
  return null;   // unknown alg = verification gap, never a pass
}
function verifyProducerBlock(block, message, trusted) {
  const results = []; let pq = false, allPinned = trusted !== null, nPass = 0, nFail = 0, nSkip = 0;
  for (const s of Array.isArray(block?.signatures) ? block.signatures : []) {
    const alg = s?.sig_alg, pub = s?.public_key_b64 ?? "";
    if (typeof alg !== "string") { nFail++; const r = { sig_alg: null, status: "FAIL", post_quantum: false, key_trusted: null }; if (isObj(s)) r.note = entryShapeNote(s); results.push(r); allPinned = false; continue; }   // 1.4.1: an object entry without a string sig_alg names its unknown and missing keys too   // r2: "constructor"/"__proto__" as sig_alg crashed the pin lookup on a prototype-bearing table
    // 1.4.0 — SPEC §9.1: the entry is a CLOSED object (exactly four keys, these types, post_quantum iff ml-dsa-65): otherwise a FAIL entry, never a pass
    const keys = Object.keys(s); if (!isObj(s) || keys.length !== 4 || keys.some((k) => !ENTRY_KEYS.has(k)) || !isStr(s.public_key_b64) || !isStr(s.signature_b64) || !isBool(s.post_quantum) || s.post_quantum !== (alg === "ml-dsa-65")) {
      nFail++; results.push({ sig_alg: alg, status: "FAIL", post_quantum: alg === "ml-dsa-65", key_trusted: null, note: entryShapeNote(s) }); allPinned = false; continue; }
    const v = verifyProducer(alg, pub, s.signature_b64, message);
    const status = v === true ? "PASS" : v === null ? "SKIP" : "FAIL"; if (v === true) nPass++; else if (v === false) nFail++; else nSkip++;
    let keyTrusted = null; if (trusted !== null) { const allowed = Object.hasOwn(trusted, alg) ? trusted[alg] : []; keyTrusted = allowed.includes(pub); if (!keyTrusted) allPinned = false; }
    if (v === true && alg === "ml-dsa-65" && (trusted === null || keyTrusted)) pq = true;
    results.push({ sig_alg: alg, status, post_quantum: alg === "ml-dsa-65", key_trusted: keyTrusted });
  }
  // 1.4.0 — SPEC §5/§9.1: `scheme` reconciled with the entries ("hybrid" = a classical AND an ml-dsa-65 entry; "classical-only" = no ml-dsa-65)
  const algs = results.map((r) => r.sig_alg); const hasPq = algs.includes("ml-dsa-65"), hasClassical = algs.some((a) => a === "ed25519" || a === "ecdsa-p256");
  const schemeOk = (block?.scheme === "hybrid" && hasPq && hasClassical) || (block?.scheme === "classical-only" && !hasPq);
  const ok = nPass >= 1 && nFail === 0 && nSkip === 0 && schemeOk; const trustedOk = trusted === null ? null : (results.length > 0 && allPinned && nSkip === 0);
  return { ok, incomplete: nSkip > 0 && nFail === 0, pq_protected: pq, trusted: trustedOk, results, scheme_ok: schemeOk };
}
// ---- RFC 3161 token: minimal DER walk — TimeStampResp{ status PKIStatusInfo{ INTEGER }, timeStampToken ContentInfo{ OID, [0] SignedData{ ..., encapContentInfo{ OID id-ct-TSTInfo, [0] OCTET STRING TSTInfo } } } }
// TSTInfo{ version, policy OID, messageImprint{ AlgorithmIdentifier, OCTET STRING hash } ... }. Same two facts the reference checks
// (SPEC §3.2). TSA signature/chain: only the reference, with `--tsa-cert` through `openssl ts -verify`; here `tsa_verified` is null (declared).
function derTLV(buf, off) { if (off + 2 > buf.length) throw new Refused("der"); const tag = buf[off]; let len = buf[off + 1], hl = 2;
  if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4 || off + 2 + n > buf.length) throw new Refused("der len"); len = 0; for (let k = 0; k < n; k++) len = len * 256 + buf[off + 2 + k]; hl = 2 + n; }   // r3: `<<` is int32 — 0x84 80 00 00 00 went negative and passed the overrun check
  if (off + hl + len > buf.length) throw new Refused("der overrun"); return { tag, start: off + hl, end: off + hl + len, next: off + hl + len }; }
function derChildren(buf, tlv) { const out = []; let o = tlv.start; while (o < tlv.end) { const c = derTLV(buf, o); out.push(c); o = c.next; } return out; }
function verifyRfc3161(tsrB64, expectedDigestHex) {
  // r11: granted null = no status was read (the bytes never decoded), not "the TSA refused" — a value the receipt never measured
  const raw = b64Strict(tsrB64); if (!raw) return { verified: false, granted: null, imprint_ok: null, gen_time: null, note: "tsr_b64 is not canonical base64" };   // r11: null = never read
  let grantedRead = null;   // r10: the status read before any later failure, so the receipt reports a measured granted, never an assumed one
  try {
    const resp = derTLV(raw, 0); if (resp.tag !== 0x30) return { verified: false, granted: null, imprint_ok: null, gen_time: null, note: "not a TimeStampResp" };   // r11: same receipt shape as every other branch
    const [status, token] = derChildren(raw, resp); const st = derChildren(raw, status)[0]; if (!st || st.tag !== 0x02) return { verified: false, granted: null, imprint_ok: null, gen_time: null, note: "no status" };   // r11
    const granted = st.end - st.start === 1 && (raw[st.start] === 0 || raw[st.start] === 1); grantedRead = granted;   // granted (0) / grantedWithMods (1)
    if (!token) return { verified: false, granted, imprint_ok: null, gen_time: null };   // r11: no token, so no imprint was read
    const ci = derChildren(raw, token); const sd = ci[1] && derChildren(raw, ci[1])[0]; if (!sd) return { verified: false, granted, imprint_ok: null, gen_time: null };
    const sdc = derChildren(raw, sd);           // version, digestAlgorithms, encapContentInfo, [certs], [crls], signerInfos
    const eci = sdc[2]; const ecic = derChildren(raw, eci); const wrap = ecic[1] && derChildren(raw, ecic[1])[0]; if (!wrap || wrap.tag !== 0x04) return { verified: false, granted, imprint_ok: null, gen_time: null };
    const tst = derTLV(raw, wrap.start); const tstc = derChildren(raw, tst);   // version, policy, messageImprint, serial, genTime, ...
    const mi = tstc[2]; const mic = derChildren(raw, mi); const hash = mic[1]; if (!hash || hash.tag !== 0x04) return { verified: false, granted, imprint_ok: null, gen_time: null };
    const imprint = raw.subarray(hash.start, hash.end).toString("hex"); const imprintOk = imprint === expectedDigestHex.toLowerCase();
    let genTime = null; const gt = tstc[4]; if (gt && gt.tag === 0x18) { const s = raw.subarray(gt.start, gt.end).toString("latin1"); if (/^\d{14}(\.\d+)?Z$/.test(s)) genTime = s; }   // r4: TSTInfo.genTime, reported as in the reference
    return { verified: Boolean(granted && imprintOk), granted, imprint_ok: imprintOk, gen_time: genTime };
  } catch (e) { return { verified: false, granted: grantedRead, imprint_ok: null, gen_time: null, note: "token not parseable: " + (e.message ?? e) }; }   // r10: same shape and same measured status as the reference
}
// 1.5.0 — SPEC §3.3: the identity of an anchor is the TSTInfo the TSA signed (eContent of the token), not the bytes around
// it. Called only on a token whose binding verified, so the walk below already succeeded once in verifyRfc3161.
function tstInfoHex(tsrB64) {
  const raw = b64Strict(tsrB64);
  try {
    const resp = derTLV(raw, 0); const token = derChildren(raw, resp)[1];
    const ci = derChildren(raw, token); const sd = derChildren(raw, ci[1])[0]; const sdc = derChildren(raw, sd);
    const wrap = derChildren(raw, derChildren(raw, sdc[2])[1])[0];
    return "tst:" + raw.subarray(wrap.start, wrap.end).toString("hex");
  } catch { return "raw:" + raw.toString("hex"); }
}
// ---- evidence ----
// The file is opened WITHOUT blocking and read only if the OPEN descriptor is a regular file, at most MAX_BYTES bytes: a FIFO
// must not hang the verifier, a symlink to /dev/zero (a device reports size 0) must not be read until memory runs out.
// null = above the bound; a FIFO / device / directory throws "unreadable evidence file: not a regular file".
function readEvidenceBytes(path) {
  if (!statSync(path).isFile()) throw new Refused("unreadable evidence file: not a regular file");   // refused BEFORE it is opened (opening a device can act on it)
  const fd = openSync(path, FS.O_RDONLY | (FS.O_NONBLOCK ?? 0) | (FS.O_NOCTTY ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Refused("unreadable evidence file: not a regular file");
    if (st.size > MAX_BYTES) return null;
    const chunks = [], chunk = Buffer.allocUnsafe(1 << 20); let total = 0;
    for (;;) { const got = readSync(fd, chunk, 0, chunk.length, null); if (got === 0) break; total += got; if (total > MAX_BYTES) return null; chunks.push(Buffer.from(chunk.subarray(0, got))); }
    return Buffer.concat(chunks, total);
  } finally { closeSync(fd); }
}
export function verifyEvidence(path, opts = {}) {
  if (opts.minAnchors !== undefined && opts.minAnchors !== null && !(Number.isSafeInteger(opts.minAnchors) && opts.minAnchors >= 1))   // SPEC §3.3: an integer >= 1 —
    throw new TypeError("minAnchors must be an integer >= 1 (got " + String(opts.minAnchors) + ")");   // NaN once disabled the policy in silence
  const refuse = (m) => ({ digest_ok: false, artifacts: [], producer_signatures: { present: false, pq_protected: false, trusted: null }, pq_protected: false, bindings_ok: false, rfc3161: { claimed: false, verified: null }, anchors: [], anchors_verified: 0, provenance_classes: [], self_asserted_only: true, chain_verified: null, policy_ok: false, valid: false, honest_scope: null, refused: m });   // r8: the honesty flag is fail-closed inside a refusal too
  let ev; try { const raw = readEvidenceBytes(path); if (raw === null) return refuse("evidence file exceeds bound"); const text = UTF8.decode(raw); if (text.startsWith("﻿")) return refuse("BOM"); ev = parseStrict(text); } catch (e) { return refuse(String(e.message ?? e)); }
  if (ev === null || typeof ev !== "object" || Array.isArray(ev)) return refuse("not a JSON object");
  // shape of the top-level fields (SPEC §1), the same refusals as the reference
  if (ev.evidence_format !== EVIDENCE_FORMAT) return refuse("evidence_format must be " + JSON.stringify(EVIDENCE_FORMAT));   // r5: a "…/2.0" pack was verified under the 1.0 rules
  for (const f of ["subject", "created_utc", "honest_scope"]) if (typeof ev[f] !== "string") return refuse(f + " must be a string (SPEC §1)");
  if (createHash("sha256").update(Buffer.from(ev.honest_scope, "utf8")).digest("hex") !== HONEST_SCOPE_SHA256) return refuse("honest_scope does not match the canonical scope of this evidence_format (SPEC §1)");   // r8: the receipt used to reprint any scope the file carried
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(ev.created_utc)) return refuse("created_utc must be ISO-8601 UTC, YYYY-MM-DDTHH:MM:SSZ (SPEC §1)");   // r6
  if (!Array.isArray(ev.artifacts) || ev.artifacts.some((a) => a === null || typeof a !== "object" || Array.isArray(a))) return refuse("artifacts must be a list of objects");
  const names = ev.artifacts.map((a) => a.name); if (names.some((n) => typeof n !== "string" || !n)) return refuse("artifacts[].name must be a non-empty string");   // r3
  if (new Set(names).size !== names.length) return refuse("artifacts[].name must be unique within the pack");
  if ("bindings" in ev && !Array.isArray(ev.bindings)) return refuse("bindings must be a list");
  if ("rfc3161_timestamp" in ev && (ev.rfc3161_timestamp === null || typeof ev.rfc3161_timestamp !== "object" || Array.isArray(ev.rfc3161_timestamp))) return refuse("rfc3161_timestamp must be an object");
  if ("rfc3161_timestamp" in ev && typeof ev.rfc3161_timestamp.anchored !== "boolean") return refuse("rfc3161_timestamp.anchored must be a boolean");   // r2: [] / {} were "anchored, unverified" here and "not anchored" in the reference
  if ("producer_signatures" in ev && (ev.producer_signatures === null || typeof ev.producer_signatures !== "object" || Array.isArray(ev.producer_signatures))) return refuse("producer_signatures must be an object");
  try {   // 1.4.0 — SPEC §9.1: the top-level object, the anchor block, the producer block and every binding entry are CLOSED
    checkClosed(ev, "top level", TOP_KEYS);
    if ("rfc3161_timestamp" in ev) checkClosed(ev.rfc3161_timestamp, "rfc3161_timestamp", RFC3161_KEYS);
    if ("producer_signatures" in ev) checkClosed(ev.producer_signatures, "producer_signatures", PRODUCER_KEYS);
    (ev.bindings ?? []).forEach((b, i) => checkClosed(b, "bindings[" + i + "]", BINDING_KEYS));
    (ev.anchors ?? []).forEach((an, i) => {   // 1.5.0 — SPEC §3.3/§9.1: closed entries, the mechanism first (the reference's order)
      if (!isObj(an)) throw new Refused("anchors[" + i + "] must be an object (SPEC §9.1)");
      if (!Object.hasOwn(an, "mechanism")) throw new Refused("anchors[" + i + "]: missing mechanism (SPEC §9.1)");
      if (typeof an.mechanism !== "string") throw new Refused("anchors[" + i + "]: mechanism must be a string (SPEC §9.1)");
      if (!ANCHOR_MECHANISMS.includes(an.mechanism)) throw new Refused("anchors[" + i + "]: mechanism " + JSON.stringify(an.mechanism) + " is not defined by this revision (SPEC §3.3)");
      checkClosed(an, "anchors[" + i + "]", ANCHOR_RFC3161_KEYS); });
  } catch (e) { return refuse(String(e.message ?? e)); }
  const e2 = Object.create(null); for (const k of Object.keys(ev)) if (!DIGEST_EXCLUDED.includes(k)) e2[k] = ev[k];
  const recomputed = sha256(Buffer.from(canon(e2), "utf-8")).toString("hex"); const digestOk = recomputed === ev.evidence_digest_sha256;
  const artResults = []; let allOk = true; const forBindings = [];
  for (const a of ev.artifacts) {
    try { checkClosed(a, "artifact", ARTIFACT_KEYS); checkClosed(a.key, "artifact key", KEY_KEYS); checkClosed(a.kb_jwt, "artifact kb_jwt", KB_COPY_KEYS); checkClosed(a.verified_at_build, "artifact verified_at_build", VAB_KEYS);   // 1.4.0 — SPEC §9.1
      const compact = a.sd_jwt_compact; if (typeof compact !== "string" || compact !== compact.trim() || !/^[\x00-\x7f]*$/.test(compact)) throw new Refused("sd_jwt_compact must be the exact ASCII compact serialization");
      if (!a.key || typeof a.key !== "object" || Array.isArray(a.key)) throw new Refused("artifact key.jwk must be an object");
      const pc = a.key.provenance_class;   // r2: a list was sorted here; r5: out-of-enum passed as a strong class; r7: absent/null used to CLEAR self_asserted_only
      if (typeof pc !== "string" || !PROVENANCE_CLASSES.has(pc)) throw new Refused("artifact key.provenance_class must be one of " + [...PROVENANCE_CLASSES].sort().join(", "));
      const parsed = parseSdJwt(compact);
      // r6: this shape check spent round 5 INSIDE an unterminated line comment — a signed payload that is a JSON array
      // verified in this verifier and failed in the reference. It runs before checkProvenance, which reads the header.
      if (parsed.payload === null || typeof parsed.payload !== "object" || Array.isArray(parsed.payload) || parsed.header === null || typeof parsed.header !== "object" || Array.isArray(parsed.header)) throw new Refused("JWT header and payload must be objects");
      if (canon(a.header) !== canon(parsed.header)) throw new Refused("artifact header copy differs from the decoded protected header (SPEC §2)");   // 1.4.0: the informative copy must say what the signed header says
      if (Boolean(parsed.kbJwt) !== a.kb_jwt.present) throw new Refused("artifact kb_jwt.present contradicts the compact serialization (SPEC §9.1)");
      // SPEC §9.2 — the standards' rule for the unknown: ignored, and REPORTED (crit: RFC 7515 §4.1.11, a rejection)
      const ignored = { header: joseHeaderIgnored(parsed.header, "JWT header"), header_jwk: unknownMembers(parsed.header.jwk, JWK_REGISTERED), key_jwk: unknownMembers(a.key.jwk, JWK_REGISTERED) };
      const prov = checkProvenance(pc, parsed, a.key); const selfAsserted = prov.selfAsserted;   // r5: reconciled with the signed header; r7: decides self_asserted_only
      const sigOk = es256Verify(parsed.signingInput, parsed.signature, a.key.jwk); const resolved = resolveDisclosures(parsed.payload, parsed.disclosures);
      const claimsOk = canon(resolved) === canon(a.resolved_claims ?? null); const kb = verifyKbJwt(parsed, resolved);
      for (const k of ["verified", "signature_ok", "sd_hash_ok", "claims_recorded_not_validated"]) if (Object.hasOwn(a.kb_jwt, k) && (!Object.hasOwn(kb, k) || canon(a.kb_jwt[k]) !== canon(kb[k]))) throw new Refused("artifact kb_jwt." + k + " contradicts the KB-JWT (SPEC §9.1)");   // SPEC §9.1 (NEMESIS 2026-10-11)
      Object.assign(ignored, kb._ignored ?? {}); delete kb._ignored; const ign = {}; for (const k of Object.keys(ignored).sort(cmp)) if (ignored[k].length) ign[k] = ignored[k];   // SPEC §9.2: only the non-empty slots
      artResults.push({ name: a.name, signature_ok: sigOk, claims_match: claimsOk, kb_jwt: kb, provenance_class: a.key?.provenance_class, self_asserted: selfAsserted, ignored: ign, ...(prov.ident ? { x5c_leaf: prov.ident } : {}) });
      allOk = allOk && sigOk && claimsOk && kb.verified !== false; forBindings.push({ name: a.name, compact: parsed.compact, resolved });
    } catch (e) { artResults.push({ name: a?.name, error: String(e.message ?? e) }); allOk = false; }
  }
  const asSet = (l) => l.map((b) => canon(b)).sort().join("\n");   // r4: binding SET (SPEC §4) — Object.keys enumerates index keys first, so the scan order is not the reference's
  const bindingsOk = allOk ? asSet(findBindings(forBindings)) === asSet(ev.bindings ?? []) : false;   // `bindings` absent = [] in both; null is refused above
  const ts = ev.rfc3161_timestamp ?? {}; let rfc = { claimed: Boolean(ts.anchored), verified: null };   // `anchored` is a boolean by the shape check above
  if (ts.anchored && typeof ts.tsr_b64 === "string") rfc = { claimed: true, ...verifyRfc3161(ts.tsr_b64, recomputed), tsa_verified: null };   // BINDING only (status granted + messageImprint == digest, SPEC §3.2); TSA signature/chain: this verifier cannot (no openssl) -> tsa_verified null = incomplete under --tsa-cert
  else if (ts.anchored) rfc = { claimed: true, verified: false, note: "anchored claimed but tsr_b64 absent" };
  // 1.5.0 — SPEC §3.3: each `anchors` entry checked like the block; COUNTING = binding verified (+ TSA-verified when --tsa-cert:
  // never here, no openssl -> 0 under --tsa-cert, declared); DISTINCT = a different signed TSTInfo (a copied token is one anchor,
  // however it is wrapped); any failing claim fails the pack
  const anchorResults = (ev.anchors ?? []).map((an) => ({ mechanism: an.mechanism, claimed: true, ...verifyRfc3161(an.tsr_b64, recomputed), tsa_verified: null }));
  const counted = new Set();
  const pairs = (rfc.claimed ? [[rfc, ts.tsr_b64]] : []).concat(anchorResults.map((r, i) => [r, ev.anchors[i].tsr_b64]));
  for (const [r, tok] of pairs) if (r.verified === true && (!opts.tsaCert || r.tsa_verified === true)) counted.add(tstInfoHex(tok));
  const anchorsVerified = counted.size;
  if (anchorResults.length) rfc = { ...rfc, claimed: true, verified: (rfc.verified === false || anchorResults.some((x) => x.verified !== true)) ? false : true };
  const classes = [...new Set(artResults.map((r) => r.provenance_class).filter(Boolean))].sort(cmp);   // r5: by code point, as the reference (default sort is by UTF-16 code unit)
  let producer; const prod = ev.producer_signatures;
  if (prod) { const pv = verifyProducerBlock(prod, Buffer.from(recomputed, "ascii"), opts.trusted ?? null); producer = { present: true, scheme: prod.scheme, scheme_ok: pv.scheme_ok, ok: pv.ok, incomplete: pv.incomplete, pq_protected: pv.pq_protected, trusted: pv.trusted, signatures: pv.results };
    if (!pv.ok) allOk = false; if ((opts.trusted ?? null) !== null && pv.trusted !== true) allOk = false; }
  else producer = { present: false, pq_protected: false, trusted: null };
  let policyOk = true; if (opts.requireProducer && !(producer.present && producer.ok)) policyOk = false;
  if (opts.requirePq && !(producer.pq_protected && producer.trusted === true)) policyOk = false;
  const need = Math.max(opts.requireAnchor ? 1 : 0, opts.minAnchors ?? 0);   // SPEC §3.3: require_anchor alone is min_anchors = 1
  if (need && anchorsVerified < need) policyOk = false;   // under --tsa-cert nothing counts here (no openssl): not a pass (declared)
  return { digest_ok: digestOk, artifacts: artResults, producer_signatures: producer, pq_protected: producer.pq_protected ?? false, bindings_ok: bindingsOk, rfc3161: rfc, anchors: anchorResults, anchors_verified: anchorsVerified, provenance_classes: classes,
    // r10: ANY — one reconciled artifact must not clear the flag for the others; r7: a label alone never clears it,
    // a missing class is a refusal; r8: this verifier cannot validate x5c chains, so chain_verified is always null (declared)
    self_asserted_only: artResults.length === 0 || artResults.some((r) => r.self_asserted !== false), chain_verified: null, policy_ok: policyOk,
    valid: Boolean(artResults.length && digestOk && allOk && bindingsOk && rfc.verified !== false && policyOk), honest_scope: ev.honest_scope ?? null, mldsa_backend: HAVE_MLDSA };
}
function main(argv) {
  const usage = () => { console.error("usage: ap2-verify.mjs <evidence.json> [--trusted-producer-key ALG=B64]... [--require-producer] [--require-pq] [--require-anchor] [--min-anchors N] [--tsa-cert PEM] [--trust-anchor PEM]"); process.exit(2); };
  const a = argv.slice(2); const opts = { trusted: null }; let path = null;
  for (let i = 0; i < a.length; i++) { let tok = a[i], eqv = null; const eq = tok.indexOf("="); if (eq > 0 && tok.startsWith("--")) { eqv = tok.slice(eq + 1); tok = tok.slice(0, eq); }
    const nx = () => { const v = eqv !== null ? eqv : a[++i]; if (v === undefined || v === "" || v.startsWith("-")) usage(); return v; };
    if (tok === "--trusted-producer-key") { const v = nx(); const k = v.indexOf("="); if (k <= 0 || k === v.length - 1) usage(); opts.trusted = opts.trusted ?? Object.create(null); (opts.trusted[v.slice(0, k)] ??= []).push(v.slice(k + 1)); }   // r2: a null-prototype table, so "constructor=…" is a pin like any other
    else if (tok === "--tsa-cert") opts.tsaCert = nx();
    else if (tok === "--min-anchors") { const v = nx(); if (!/^[1-9][0-9]{0,5}$/.test(v)) usage(); opts.minAnchors = Number(v); }   // 1.5.0 — the reference's grammar
    else if (tok === "--trust-anchor") { nx(); }   // r8: accepted for one CLI grammar; this verifier cannot validate x5c chains -> chain_verified stays null (declared)
    else if (tok === "--require-producer" && eqv === null) opts.requireProducer = true; else if (tok === "--require-pq" && eqv === null) opts.requirePq = true; else if (tok === "--require-anchor" && eqv === null) opts.requireAnchor = true;
    else if (tok.startsWith("-") || path !== null) usage(); else path = tok; }
  if (!path) usage();
  const r = verifyEvidence(path, opts); console.log(JSON.stringify(r, null, 1)); return r.valid ? 0 : 1;
}
// exitCode, not process.exit(): exit() right after console.log to a PIPE drops every byte past 64 KiB of the receipt
// (measured 12/10/2026: an evidence file with a 100 000-character unknown key gave 65 536 bytes of broken JSON on `| cat`)
if (process.argv[1] && /ap2-verify\.mjs$/.test(process.argv[1])) process.exitCode = main(process.argv);
