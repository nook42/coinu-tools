import { createHash } from 'node:crypto';

// Public source is untrusted. This module reads only named, literal Rust constants;
// it deliberately does not evaluate Rust or follow arbitrary source paths.

export const WIRE_GUESTS = Object.freeze([
  { id: 'CHUNK', crate: 'stage4-chunk-guest', elf: 'bitcoinu-stage4-chunk-guest' },
  { id: 'NODE', crate: 'stage4-node-guest', elf: 'bitcoinu-stage4-node-guest' },
  { id: 'ROOT', crate: 'stage4-root-guest', elf: 'bitcoinu-stage4-root-guest' },
  { id: 'EVIDENCE_SEGMENT', crate: 'evidence-segment-wire-guest', elf: 'evidence-segment-wire-guest' },
  { id: 'BIND', crate: 'bind-wire-guest', elf: 'bind-wire-guest' },
  { id: 'BIND_CHILD', crate: 'bind-child-wire-guest', elf: 'bind-child-wire-guest' },
  { id: 'GROUP', crate: 'group-wire-guest', elf: 'group-wire-guest' },
  ...[0, 1, 2, 3].map((level) => ({
    id: `L${level}`, crate: 'agg-wire-guest', elf: `agg-wire-l${level}`,
    bin: `agg-wire-l${level}`, feature: `level${level}`,
  })),
  { id: 'FINAL', crate: 'final-wire-guest', elf: 'final-wire-guest' },
]);

// The eleven production child-key constants. NODE receives its child key in private input.
export const WIRE_VKEY_EDGES = Object.freeze([
  { parent: 'ROOT', child: 'CHUNK', file: 'stage4-root-guest/src/main.rs', name: 'CHUNK_VKEY' },
  { parent: 'ROOT', child: 'NODE', file: 'stage4-root-guest/src/main.rs', name: 'NODE_VKEY' },
  { parent: 'BIND', child: 'ROOT', file: 'bind-wire-guest/src/main.rs', name: 'ROOT_VKEY' },
  { parent: 'BIND', child: 'EVIDENCE_SEGMENT', file: 'bind-wire-guest/src/main.rs', name: 'EVIDENCE_SEGMENT_VKEY' },
  { parent: 'BIND', child: 'BIND_CHILD', file: 'bind-wire-guest/src/main.rs', name: 'BIND_CHILD_VKEY' },
  ...[0, 1, 2, 3].map((level) => ({
    parent: `L${level}`, child: level === 0 ? 'GROUP' : `L${level - 1}`,
    file: `agg-wire-guest/src/bin/level${level}.rs`, name: 'CHILD_VKEY',
  })),
  { parent: 'FINAL', child: 'BIND', file: 'final-wire-guest/src/main.rs', name: 'BIND_VKEY' },
  { parent: 'FINAL', child: 'L3', file: 'final-wire-guest/src/main.rs', name: 'AGG_L3_VKEY' },
]);

export function vkDigestBytes32(words) {
  if (!Array.isArray(words) || words.length !== 8) throw new Error('vkey needs eight words');
  let value = 0n;
  for (const word of words) {
    if (!Number.isSafeInteger(word) || word < 0 || word >= 2 ** 31) {
      throw new Error(`KoalaBear word out of range: ${word}`);
    }
    value = (value << 31n) + BigInt(word);
  }
  return `0x${value.toString(16).padStart(64, '0')}`;
}

// Tokenize the whole file before deciding which identifier a Rust item binds.
// Non-ASCII comments are harmless, but invisible/bidirectional code points are
// rejected even there: a reviewer must see the same source that is checked.
export function rustTokens(source) {
  const s = String(source);
  if (/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u.test(s)) {
    throw new Error('invisible or bidirectional Rust source');
  }
  const out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }
    if (s.startsWith('//', i)) { i = s.indexOf('\n', i); if (i < 0) break; continue; }
    if (s.startsWith('/*', i)) {
      let depth = 1; i += 2;
      while (i < s.length && depth) {
        if (s.startsWith('/*', i)) { depth++; i += 2; }
        else if (s.startsWith('*/', i)) { depth--; i += 2; }
        else i++;
      }
      if (depth) throw new Error('unterminated Rust block comment');
      continue;
    }
    if (c.charCodeAt(0) > 127) throw new Error('non-ASCII Rust source outside comment');
    if (s.startsWith('r#', i) || s.startsWith('r"', i)) throw new Error('raw Rust identifier/string');
    if (s.startsWith('b"', i) || s.startsWith("b'", i)
        || s.startsWith('br"', i) || s.startsWith('br#', i)) {
      throw new Error('byte Rust literal');
    }
    if (c === '"' || c === "'") {
      if (c === "'" && /[A-Za-z_]/.test(s[i + 1] || '')
          && s[i + 2] !== "'" && !/^[A-Za-z_][A-Za-z0-9_]*'/.test(s.slice(i + 1))) {
        const m = /^'[A-Za-z_][A-Za-z0-9_]*/.exec(s.slice(i));
        out.push({ kind: 'lifetime', value: m[0] }); i += m[0].length; continue;
      }
      const start = i++;
      let closed = false;
      while (i < s.length) {
        if (s[i] === '\\') { i += 2; continue; }
        if (s[i++] === c) { closed = true; break; }
      }
      if (!closed) throw new Error('unterminated Rust string/char');
      const literal = s.slice(start, i);
      if (/[^\x00-\x7f]/.test(literal)) throw new Error('non-ASCII Rust source outside comment');
      out.push({ kind: c === '"' ? 'string' : 'char', value: literal });
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(s.slice(i))[0];
      // Rust 2021 reserves identifier-adjacent literal prefixes, including cr"...".
      // Split lifetime/char above before applying this boundary rule.
      if ('"\'#'.includes(s[i + m.length] || '')) throw new Error('reserved Rust literal prefix');
      out.push({ kind: 'id', value: m }); i += m.length; continue;
    }
    if (/[0-9]/.test(c)) {
      const m = /^(?:0x[0-9a-fA-F_]+|[0-9][0-9_]*)(?:u32)?/.exec(s.slice(i))[0];
      out.push({ kind: 'number', value: m }); i += m.length; continue;
    }
    if (!'#[]{}();:,=!.&*+<>-|?/%^~@$'.includes(c)) {
      throw new Error(`unknown Rust token U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    }
    out.push({ kind: 'symbol', value: c }); i++;
  }
  return out;
}

const AGG_LEVEL_CFG = 'cfg(any(all(feature="level0",feature="level1"),all(feature="level0",feature="level2"),all(feature="level0",feature="level3"),all(feature="level1",feature="level2"),all(feature="level1",feature="level3"),all(feature="level2",feature="level3")))';
const ATTRIBUTES = new Set([
  '!no_main', 'cfg(feature="measurement-only")',
  'cfg(not(feature="measurement-only"))', AGG_LEVEL_CFG,
]);
const MACROS = new Set(['assert', 'assert_eq', 'assert_ne', 'panic', 'compile_error']);

// Positive grammar from HEAD crates/{stage4-root-guest,bind-wire-guest,
// final-wire-guest}/src/main.rs and agg-wire-guest/src/{bin/level0..3.rs,common.rs}.
// The per-file token signatures below also pin the positions of these forms.
const RUST_LEXICAL_KINDS = new Set(['id', 'number', 'string', 'symbol']);
const RUST_TOP_ITEMS = new Set(['fn', 'const', 'use', 'mod']);
const RUST_BODY_BINDING = new Set(['let']);
const RUST_ITEM_KEYWORDS = new Set(['fn', 'const', 'use', 'mod', 'struct', 'enum', 'union',
  'trait', 'impl', 'type', 'extern', 'static', 'macro_rules']);
export const RUST_USE_PATHS = new Set([
  'agg_wire::aggregate', 'sha2::{Digest,Sha256}', 'sp1_lib::verify::verify_sp1_proof',
  'stage4_wire::{run_root,RootInput}',
  'wire_schema::{pv::{Kind,PublicValues},sha256,}',
  'bind_wire::{BindDeploymentWords,PrivateDeploymentWords,SegmentWitness}',
  'stage5_mpt::{DepositProof,ProofPath,U256}',
  'wire_schema::digest::{Candidate,Invalid,InvalidReason}',
  'final_wire::{validate,Input}', 'wire_schema::DeploymentParams',
]);
const COMMON_ARGUMENTS = new Set(['level', 'child_vkey', 'child_vkey_unset', 'measurement_vkey']);
export const WIRE_RUST_ALLOWLIST = Object.freeze({
  lexicalKinds: Object.freeze([...RUST_LEXICAL_KINDS]),
  topItems: Object.freeze([...RUST_TOP_ITEMS]),
  bodyBindings: Object.freeze([...RUST_BODY_BINDING]),
  usePaths: Object.freeze([...RUST_USE_PATHS]),
  macros: Object.freeze(['sp1_zkvm::entrypoint', ...MACROS]),
  attributes: Object.freeze([...ATTRIBUTES, 'path="../common.rs"']),
});

// HEAD token structures are the position-sensitive part of the allowlist. Only
// the production vkey initializers vary after baking. These hashes are of token
// sequences, not bytes: whitespace/comments and numeric spelling may vary.
export const RUST_SOURCE_SHAPES = Object.freeze({
  'stage4-root-guest/src/main.rs': 'e28a5c595fc51a574a21ce1da0e820ccbda87558e3046f185dbfd3a15cfa1014',
  'bind-wire-guest/src/main.rs': '3c619e55a707b233e9a888f4738c445cf1f4e38f330db21a883cd39e4ecba4a4',
  'agg-wire-guest/src/bin/level0.rs': 'c22fa9416182e61d7100ff18dca011c20a10571bbc08cad27b44f2c53900cdf9',
  'agg-wire-guest/src/bin/level1.rs': '81186c578c8fab53fd3f39527209e841bb6693f2c1194ae2cd18ddafe00aa778',
  'agg-wire-guest/src/bin/level2.rs': '3725aa51c49d21ac7b45306e6050b236c94702bb4e2232b0a8c7cdbbebad913a',
  'agg-wire-guest/src/bin/level3.rs': '4ef9c43fe03ca001c12ec8f2002e65a1a17d1685b9e72fa4c147081105247421',
  'final-wire-guest/src/main.rs': 'acc0d1e0b066fb8ae0623c442e59072fdad41c4b9b67231b80aaab0a6d7fbc3d',
  'agg-wire-guest/src/common.rs': 'cd477e9ad43c0058e84e12edbe38b441c401fd12d2f4300f56b6cc6c1df6fb14',
});

export function wireSourceShape(source, tableNames = []) {
  const tokens = rustTokens(source);
  const names = new Set(tableNames);
  const values = [];
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].value;
    if (t === '{') depth++;
    if (t === '}') depth--;
    values.push(`${tokens[i].kind}:${t}`);
    if (depth === 0 && t === 'const' && names.has(tokens[i + 1]?.value)) {
      // Keep the declaration and replace only its initializer. The reader
      // independently demands the exact eight-word literal grammar.
      let eq = i + 1;
      let typeBrackets = 0;
      while (eq < tokens.length) {
        if (tokens[eq].value === '[') typeBrackets++;
        if (tokens[eq].value === ']') typeBrackets--;
        if (typeBrackets === 0 && (tokens[eq].value === '=' || tokens[eq].value === ';')) break;
        eq++;
      }
      if (tokens[eq]?.value !== '=') throw new Error('table initializer missing');
      for (let k = i + 1; k <= eq; k++) values.push(`${tokens[k].kind}:${tokens[k].value}`);
      values.push('table-initializer');
      let end = eq + 1;
      let brackets = 0;
      for (; end < tokens.length; end++) {
        if (tokens[end].value === '[') brackets++;
        if (tokens[end].value === ']') brackets--;
        if (tokens[end].value === ';' && brackets === 0) break;
      }
      if (end === tokens.length) throw new Error('table initializer unterminated');
      i = end - 1;
    }
  }
  return createHash('sha256').update(values.join('\0')).digest('hex');
}

function checkRustSourceShape(file, source) {
  const expected = RUST_SOURCE_SHAPES[file];
  if (!expected) throw new Error(`${file}: no audited Rust shape`);
  const names = WIRE_VKEY_EDGES.filter((edge) => edge.file === file).map((edge) => edge.name);
  if (wireSourceShape(source, names) !== expected) throw new Error(`${file}: Rust item/position structure differs from HEAD`);
}

function inspectRust(tokens, name, { common = false, agg = false } = {}) {
  const value = (i) => tokens[i]?.value;
  const attributesByEnd = new Map();
  let modCount = 0;
  let depth = 0;
  let found = null;
  for (let i = 0; i < tokens.length; i++) {
    const t = value(i);
    if (!RUST_LEXICAL_KINDS.has(tokens[i].kind)) throw new Error('unsupported Rust lexical kind');
    if (tokens[i].kind === 'id' && RUST_ITEM_KEYWORDS.has(t)) {
      if (depth === 0 && !RUST_TOP_ITEMS.has(t)) throw new Error(`unsupported Rust item: ${t}`);
      if (depth > 0) throw new Error(`nested Rust item: ${t}`);
    }
    if (t === 'let') {
      if (depth === 0 || !RUST_BODY_BINDING.has(t)) throw new Error('unsupported Rust let position');
    }
    if (tokens[i].kind === 'char' || tokens[i].kind === 'lifetime') {
      throw new Error('unsupported Rust character/lifetime');
    }
    if (t === '#') {
      let j = i + 1;
      const inner = value(j) === '!' ? (j++, true) : false;
      if (value(j++) !== '[') throw new Error('unsupported Rust attribute');
      let brackets = 1;
      const body = [];
      for (; j < tokens.length && brackets; j++) {
        if (value(j) === '[') brackets++;
        if (value(j) === ']') brackets--;
        if (brackets) body.push(value(j));
      }
      if (brackets) throw new Error('unterminated Rust attribute');
      const attr = `${inner ? '!' : ''}${body.join('')}`;
      if (attr !== 'path="../common.rs"' && !ATTRIBUTES.has(attr)) throw new Error(`unsupported Rust attribute: ${attr}`);
      if (attr === 'path="../common.rs"' && !agg) throw new Error('unexpected AGG path');
      attributesByEnd.set(j - 1, { start: i, attr });
      i = j - 1; continue;
    }
    if (t === '{') depth++;
    if (t === '}') { if (--depth < 0) throw new Error('unbalanced Rust braces'); }
    if (t === 'mod') {
      const pathAttribute = attributesByEnd.get(i - 1);
      if (!agg || modCount++ || depth !== 0 || value(i + 1) !== 'common' || value(i + 2) !== ';'
          || pathAttribute?.attr !== 'path="../common.rs"'
          || ![undefined, ';', '}'].includes(value(pathAttribute.start - 1))) {
        throw new Error('external Rust module');
      }
    }
    if (tokens[i].kind === 'id' && value(i + 1) === '!'
        && (['(', '{', '['].includes(value(i + 2)) || t === 'macro_rules')) {
      let start = i;
      while (start >= 3 && value(start - 1) === ':' && value(start - 2) === ':'
          && tokens[start - 3]?.kind === 'id') start -= 3;
      if (start >= 2 && value(start - 1) === ':' && value(start - 2) === ':') start -= 2;
      const macro = tokens.slice(start, i + 1).map((x) => x.value).join('');
      if (!(macro === 'sp1_zkvm::entrypoint' || (MACROS.has(macro) && (macro !== 'compile_error' || common)))) {
        throw new Error(`unsupported Rust macro: ${macro}`);
      }
    }
    if (t === 'use') {
      if (depth !== 0) throw new Error('nested Rust use');
      let j = i + 1;
      while (j < tokens.length && value(j) !== ';') j++;
      if (j === tokens.length) throw new Error('unterminated Rust use');
      const usePath = tokens.slice(i + 1, j).map((x) => x.value).join('');
      if (!RUST_USE_PATHS.has(usePath)) throw new Error(`unsupported Rust use path: ${usePath}`);
      if (common && tokens.slice(i + 1, j).some((x) => x.value === 'as')) throw new Error('AGG common use alias');
      if (tokens.slice(i + 1, j).some((x) => x.value === name)) throw new Error(`${name}: use binding`);
    }
    if (common && (t === 'const' || t === 'static')) throw new Error('AGG common constant');
    if (t === 'let') {
      let j = i + 1;
      while (j < tokens.length && value(j) !== '=' && value(j) !== ';') j++;
      if (tokens.slice(i + 1, j).some((x) => x.value === name || (common && COMMON_ARGUMENTS.has(x.value)))) {
        throw new Error(`${name}: let binding`);
      }
      if (common && tokens.slice(i + 1, j).some((x, k, a) => x.value === '[' && a[k + 1]?.value === 'u32')) {
        throw new Error('AGG common word-array binding');
      }
    }
    if ((t === 'const' && value(i + 1) === name)
        || (t === 'static' && (value(i + 1) === name
          || (value(i + 1) === 'mut' && value(i + 2) === name)))) {
      if (common || t !== 'const' || depth !== 0) throw new Error(`${name}: non-item binding`);
      let preceding = value(i - 1) === 'pub' ? i - 2 : i - 1;
      const itemAttributes = [];
      while (attributesByEnd.has(preceding)) {
        const entry = attributesByEnd.get(preceding);
        itemAttributes.unshift(entry.attr);
        preceding = entry.start - 1;
      }
      // Rust accepts other visibility forms, but the audited table grammar
      // accepts only `const` or `pub const` with at most one cfg attribute.
      if (value(preceding) === 'pub' || ![undefined, ';', '}'].includes(value(preceding))
          || itemAttributes.length > 1) throw new Error(`${name}: unsupported item prefix`);
      const attr = itemAttributes[0];
      if (attr && attr !== 'cfg(feature="measurement-only")') throw new Error(`${name}: attribute on vkey`);
      if (attr === 'cfg(feature="measurement-only")') continue;
      if (found) throw new Error(`${name}: duplicate definition`);
      let j = i + 2;
      const expect = (x) => { if (value(j++) !== x) throw new Error(`${name}: not a baked literal array`); };
      for (const x of [':', '[', 'u32', ';', '8', ']', '=', '[']) expect(x);
      const words = [];
      for (let n = 0; n < 8; n++) {
        const word = tokens[j++];
        if (word?.kind !== 'number' || !/^(?:0x[0-9a-fA-F_]+|[0-9][0-9_]*)(?:u32)?$/.test(word.value)) {
          throw new Error(`${name}: nonliteral word`);
        }
        const value = Number(BigInt(word.value.replace(/u32$/, '').replaceAll('_', '')));
        if (!Number.isSafeInteger(value) || value < 0 || value >= 2 ** 31) throw new Error(`${name}: word out of range`);
        words.push(value);
        if (n < 7) expect(',');
      }
      if (value(j) === ',') j++;
      expect(']'); expect(';');
      found = words;
    }
  }
  if (depth !== 0) throw new Error('unbalanced Rust braces');
  if (agg && modCount !== 1) throw new Error('missing AGG common module');
  if (!common && !found) throw new Error(`${name}: expected exactly one production definition`);
  return found;
}

export function readBakedVkey(source, name, { aggCommon = null } = {}) {
  const words = inspectRust(rustTokens(source), name, { agg: aggCommon != null });
  if (aggCommon != null) inspectRust(rustTokens(aggCommon), name, { common: true });
  return words;
}

// Build-input allowlist from the 23 HEAD crates in crates/pack-guest-source.mjs.
// Every manifest, lockfile, and toolchain file is pinned; no other Cargo input
// path or crate is accepted. The unit test regenerates this map from HEAD.
export const WIRE_SOURCE_CRATES = Object.freeze([
  'stage4-chunk-guest',
  'stage4-node-guest',
  'stage4-root-guest',
  'stage4-wire',
  'stage4-core',
  'wire-schema',
  'evidence-segment-wire',
  'evidence-segment-wire-guest',
  'stage5-evidence',
  'stage5-compact',
  'stage5-timebind',
  'stage5-mpt',
  'bind-wire',
  'bind-wire-guest',
  'bind-child-wire-guest',
  'group-wire',
  'group-wire-guest',
  'agg-wire',
  'agg-wire-guest',
  'final-wire',
  'final-wire-guest',
  'group-guest',
  'scoring-core',
]);
export const WIRE_BUILD_INPUT_SHA256 = Object.freeze({
  'agg-wire-guest/Cargo.lock': '985398fcc4c65ae70bf007117d4fea5545a0a458abed9fdfb87bc7dfc670dba7',
  'agg-wire-guest/Cargo.toml': '5e7285c9c379aad3721884dd410fa4878ce548008e674886a8e6832824598ea4',
  'agg-wire-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'agg-wire/Cargo.lock': '37c2dc55ccb2b181aaec4d5ab3901edadc2d7878dfc273fb3001d9b7ce6fa043',
  'agg-wire/Cargo.toml': '076a90f6bf53a80775f5806436ec3f533dc8201dce540bea3a3ba995fb7a202e',
  'agg-wire/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'bind-wire-guest/Cargo.lock': '1a8b3739c1b010cfbdfcf19af7cfaf5c97492fbd1f6abf9041c3f4e5f4c421fb',
  'bind-wire-guest/Cargo.toml': '2c44bd76e71057c5cb0cc9d579907b18d2c0dfd5ab45f8c666b3679055ea75d7',
  'bind-wire-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'bind-child-wire-guest/Cargo.lock': '6990c9c243340b175b74bde12839ddee4706ff88ca33b129bbf025625f72b3e5',
  'bind-child-wire-guest/Cargo.toml': '77a6ba4b038e7bb32476292e163c6d96351e46d5a2c20badad6ac563d4ae51be',
  'bind-child-wire-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'bind-wire/Cargo.lock': '682827fac127308e8bf13bdbe449c54d87f5d5ba4b9a443bd807c61b6d6bac68',
  'bind-wire/Cargo.toml': 'b5cbaa3b710401b6b77520fb0427c17a471d8e8000192c2fa397f31039ad2ff8',
  'bind-wire/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'evidence-segment-wire-guest/Cargo.lock': '5dacf9af14cf4c7946617b7c0cdbd51710983f3996a3a75d7151a0ee757c825c',
  'evidence-segment-wire-guest/Cargo.toml': '9a4d2b7cde79b81c1c0b1b4c06948904266de6fd2e3f845fc3e3dc59b55655f1',
  'evidence-segment-wire-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'evidence-segment-wire/Cargo.lock': 'face5509cab454f80b4669fad18236163034df7d388663f3d7d02f55d39d11d2',
  'evidence-segment-wire/Cargo.toml': 'a0ba202e36f766db8da68b03957457cb0ce6e6fd306b509934a77e11b9da407b',
  'evidence-segment-wire/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'final-wire-guest/Cargo.lock': 'e2f3e1dd18e06388b1f7ca733b579779548925cbde3b9c11b7fa6115b16d3b8a',
  'final-wire-guest/Cargo.toml': '1f16c2f499ca9a76c37462ad7bc89b0e74975dc450d85fd20642d23f6cf278e0',
  'final-wire-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'final-wire/Cargo.lock': 'f2cbdc760d17dedae4f1f7da050c262f6bbad29c673c4592c9c03b19438ef259',
  'final-wire/Cargo.toml': '0f43ea7dcd6a7945e7a6042f4db88526bc7ac97e99934d9d25c5d3aa3bb4e340',
  'final-wire/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'group-guest/Cargo.lock': 'bf912d3a340439112f768feec199ae9b978288edf22381f939b6f84b0638f649',
  'group-guest/Cargo.toml': '13791c529bf5c5f49221437fa10df274a48ae709db6166fa3ad889239aef6661',
  'group-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'group-wire-guest/Cargo.lock': '667a4a8568b5f83e0c2c7e404f0a8ee14fa54d4cdb309c29036cd86466fbf478',
  'group-wire-guest/Cargo.toml': 'ee648243f210339eac22dd2b6c7295880fa5ee4088d38124b0ca8a493a3cb968',
  'group-wire-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'group-wire/Cargo.lock': '453348e73bf0dab6aad07005d905f437b4d4d6f5f215cce5ac9ca33f49299a72',
  'group-wire/Cargo.toml': 'f680c74b11ca69c3d9a243c7964558b2f215d43f2e25073396a5d1ea0a6f4a13',
  'group-wire/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'scoring-core/Cargo.lock': 'c5187b27bf05ebef578e68735243c1e9c191c9029b2322b6bf7abd2c455d7156',
  'scoring-core/Cargo.toml': 'e497010d040d8072dde3b88cca3813d53fbef66675ec4919ccadd3d33eb0c9f9',
  'stage4-chunk-guest/Cargo.lock': 'e48538ed9c801793dc00add3addece4643785f1c4736ac26451d45190dd3e7c5',
  'stage4-chunk-guest/Cargo.toml': '8941cb02e91f4b65ae4f9a4d6238d8d6041f6c635a0bc0a1ed601435a48ce122',
  'stage4-chunk-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'stage4-core/Cargo.lock': 'd5991ab74308b58a577d1dfe6b5b3ec199f62e90df559346aac101cdc5501b28',
  'stage4-core/Cargo.toml': '263566ef3f52f1a036b484c78e17975ceebcb6e71f2ae7ad54eb0cd0e6033b27',
  'stage4-node-guest/Cargo.lock': '86a900a7d77b3e7b476c641eab4d9e40f2255d5bf9f6226c27dd6e61f178357e',
  'stage4-node-guest/Cargo.toml': '9625d8699a1aa86660f9ce0fa52cbd7d6a3e4737dbf963118f46d37d9fe01a26',
  'stage4-node-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'stage4-root-guest/Cargo.lock': '1c0cedbb866b0a220c01d3e4bf2df9697389c891f22c4af7e3c3db7174951097',
  'stage4-root-guest/Cargo.toml': 'ffc40a3907ab3a2f7512862aa954ab14985de4371fbf37225252492e41458118',
  'stage4-root-guest/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'stage4-wire/Cargo.lock': 'af3a2214db5008a6ee6b318dfa45f5df9bdfcff3e8c3bd15164d697b6d3b45d7',
  'stage4-wire/Cargo.toml': '80a082a92547d28db490015aa38e0cb0407854e39772981305bdac316103a213',
  'stage4-wire/rust-toolchain.toml': '542cd3f3a25fbc2c176ba4481d3c6d9d30918d13af2da933bbc41f0c1f0c25f3',
  'stage5-compact/Cargo.lock': '0b925b1d04ce43c03bed87a17adc5794f8a096c91fccb34c887f5039cb39aa4c',
  'stage5-compact/Cargo.toml': '50b1e58192b4014be18ebbccf1f00ae48b9dadd6ee0c032d722427d2d9799ef5',
  'stage5-evidence/Cargo.lock': '2f4ba7158caad2b310365c4f4a26fdb3d83231f6d68f01686862eb91f5168a9b',
  'stage5-evidence/Cargo.toml': '06a8232fec0f13e4ef6d0e50aa6960e4e984eeaf6e5b700872faeec08e6542df',
  'stage5-mpt/Cargo.lock': 'bef8c2507e3e35ec5f72e554175f6d5b77910deb099b400007fb09b53f98a8a4',
  'stage5-mpt/Cargo.toml': 'a3a93e1d8cc7b7b9d7fb0b563346cae08262ec6ac49437b8232fe137aa0872ee',
  'stage5-timebind/Cargo.lock': '3afbdc04d85275476a7ea71290ca5e71b78a2082c1117e20437f20fbc27f95ac',
  'stage5-timebind/Cargo.toml': '4cec1c4301c8c8e1bc75c883fd512ac0071302a0e95ef28481014f657dd62958',
  'wire-schema/Cargo.lock': '81f2c6a74faf16665c51dcba04d5b1c3816c0f4ec700ed0edd6d613805cad3f0',
  'wire-schema/Cargo.toml': '49d023ba389e80e81ae178c109bfbef412924f3ebf85031010a222eb7a931e90',
});
const WIRE_GUEST_BINS = Object.freeze({
  'agg-wire-guest': Object.freeze(['level0.rs', 'level1.rs', 'level2.rs', 'level3.rs']),
});
const BUILD_INPUT_NAME = /^(?:Cargo\.toml|Cargo\.lock|rust-toolchain(?:\.toml)?)$/;
const sha256 = (bytes) => createHash('sha256').update(Buffer.from(bytes)).digest('hex');
const ASCII_SOURCE_SEGMENT = /^(?:[a-z0-9_-][a-z0-9._-]*|Cargo\.toml|Cargo\.lock)$/;
const FOLDED_BUILD_INPUT_NAMES = new Set(['cargo.toml', 'cargo.lock', 'rust-toolchain', 'rust-toolchain.toml']);

export function visibleTerminalText(value) {
  return JSON.stringify(String(value)).slice(1, -1).replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, (char) =>
    Array.from({ length: char.length }, (_, index) =>
      `\\u${char.charCodeAt(index).toString(16).padStart(4, '0')}`).join(''));
}

export function quotedSourcePath(sourcePath) {
  return `"${visibleTerminalText(sourcePath)}"`;
}

export function checkGuestSourceNames(files, guestCrates = [...new Set(WIRE_GUESTS.map((guest) => guest.crate))]) {
  const paths = files instanceof Map ? [...files.keys()] : files.map((file) => file.path);
  if (new Set(paths).size !== paths.length) throw new Error('duplicate source path');
  const foldedPaths = new Map();
  const filePaths = new Set(paths);
  for (const p of paths) {
    const parts = p.split('/');
    if (parts.some((part) => !ASCII_SOURCE_SEGMENT.test(part) || part.endsWith('.'))) {
      throw new Error(`${quotedSourcePath(p)}: source path segment outside audited spelling`);
    }
    for (let i = 1; i <= parts.length; i++) {
      const prefix = parts.slice(0, i).join('/');
      const folded = prefix.toLowerCase();
      const prior = foldedPaths.get(folded);
      if (prior && prior !== prefix) throw new Error(`${quotedSourcePath(p)}: case-folded path collision with ${quotedSourcePath(prior)}`);
      foldedPaths.set(folded, prefix);
      if (i < parts.length && filePaths.has(prefix)) throw new Error(`${quotedSourcePath(p)}: file/directory path collision`);
    }
    const foldedParts = parts.map((part) => part.toLowerCase());
    if (foldedParts.includes('.cargo') || foldedParts.at(-1) === 'build.rs') {
      throw new Error(`${quotedSourcePath(p)}: Cargo executable input outside audited names`);
    }
    if (FOLDED_BUILD_INPUT_NAMES.has(foldedParts.at(-1)) && !BUILD_INPUT_NAME.test(parts.at(-1))) {
      throw new Error(`${quotedSourcePath(p)}: Cargo input spelling differs from canonical name`);
    }
    for (const crate of guestCrates) {
      const prefix = `${crate}/target`;
      const foldedPath = p.toLowerCase();
      if (foldedPath === prefix.toLowerCase() || foldedPath.startsWith(`${prefix.toLowerCase()}/`)) {
        throw new Error(`${quotedSourcePath(p)}: guest target must be empty in source`);
      }
    }
  }
  return true;
}

export function checkWireBuildInputs(files) {
  const byPath = files instanceof Map ? files : new Map(files.map((file) => [file.path, file.bytes]));
  const paths = [...byPath.keys()];
  const sourceCrates = new Set(paths.map((p) => p.split('/')[0]));
  if (sourceCrates.size !== WIRE_SOURCE_CRATES.length
    || WIRE_SOURCE_CRATES.some((crate) => !sourceCrates.has(crate))) {
    throw new Error(`not a wiring ${WIRE_SOURCE_CRATES.length}-crate source bundle (Stage 3 bundles are not supported by menu 2)`);
  }
  checkGuestSourceNames(files);
  const crates = new Set();
  for (const p of paths) {
    const parts = p.split('/');
    if (parts.length < 2 || !WIRE_SOURCE_CRATES.includes(parts[0])) throw new Error(`${quotedSourcePath(p)}: crate outside audited closure`);
    crates.add(parts[0]);
    if (FOLDED_BUILD_INPUT_NAMES.has(parts.at(-1).toLowerCase())) {
      const expected = WIRE_BUILD_INPUT_SHA256[p];
      if (!expected || sha256(byPath.get(p)) !== expected) throw new Error(`${quotedSourcePath(p)}: Cargo build input differs from HEAD`);
    }
  }
  if (crates.size !== WIRE_SOURCE_CRATES.length || WIRE_SOURCE_CRATES.some((crate) => !crates.has(crate))) {
    throw new Error('source crate closure differs from HEAD');
  }
  for (const p of Object.keys(WIRE_BUILD_INPUT_SHA256)) {
    if (!byPath.has(p)) throw new Error(`${quotedSourcePath(p)}: canonical Cargo input missing`);
  }
  for (const guest of WIRE_GUESTS) {
    const prefix = `${guest.crate}/src/bin/`;
    const actual = paths.filter((p) => p.toLowerCase().startsWith(prefix.toLowerCase()))
      .map((p) => p.slice(prefix.length)).sort();
    const expected = WIRE_GUEST_BINS[guest.crate] || [];
    if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${guest.crate}: bin source set differs from HEAD`);
  }
  return true;
}

export function verifyWireVkeys(files, vkeys, epochVkey) {
  const byPath = files instanceof Map ? files : new Map(files.map((file) => [file.path, file.bytes]));
  const decodeRust = (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(bytes));
  const results = [];
  try { checkWireBuildInputs(byPath); }
  catch (error) {
    return [...WIRE_VKEY_EDGES.map((edge) => ({ ...edge, status: 'unavailable', reason: error.message })),
      { parent: 'CHAIN', child: 'FINAL', status: 'unavailable', reason: error.message }];
  }
  for (const edge of WIRE_VKEY_EDGES) {
    const parent = byPath.get(edge.file);
    const child = WIRE_GUESTS.find((guest) => guest.id === edge.child);
    if (!parent || !byPath.has(`${child.crate}/Cargo.toml`) || !vkeys[edge.child]) {
      results.push({ ...edge, status: 'unavailable', reason: 'parent source, child crate, or child ELF missing' });
      continue;
    }
    try {
      const aggCommon = edge.parent.startsWith('L') ? byPath.get('agg-wire-guest/src/common.rs') : null;
      if (edge.parent.startsWith('L') && !aggCommon) throw new Error('AGG common source missing');
      const source = decodeRust(parent);
      const commonSource = aggCommon == null ? null : decodeRust(aggCommon);
      checkRustSourceShape(edge.file, source);
      if (commonSource != null) checkRustSourceShape('agg-wire-guest/src/common.rs', commonSource);
      const baked = vkDigestBytes32(readBakedVkey(source, edge.name, {
        aggCommon: commonSource,
      }));
      results.push({ ...edge, baked, derived: vkeys[edge.child], status: baked.toLowerCase() === String(vkeys[edge.child]).toLowerCase() ? 'pass' : 'fail' });
    } catch (error) {
      results.push({ ...edge, status: 'unavailable', reason: String(error.message || error) });
    }
  }
  results.push({ parent: 'CHAIN', child: 'FINAL', status: !vkeys.FINAL ? 'unavailable'
    : String(vkeys.FINAL).toLowerCase() === String(epochVkey).toLowerCase() ? 'pass' : 'fail',
  derived: vkeys.FINAL, expected: epochVkey });
  return results;
}
