import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { execFileSync, spawnSync, spawn as realSpawn } from 'node:child_process';
import { WIRE_GUESTS, WIRE_VKEY_EDGES, WIRE_SOURCE_CRATES, WIRE_BUILD_INPUT_SHA256, RUST_SOURCE_SHAPES, RUST_USE_PATHS, WIRE_RUST_ALLOWLIST, checkGuestSourceNames, checkWireBuildInputs, readBakedVkey, rustTokens, verifyWireVkeys, vkDigestBytes32, wireSourceShape, visibleTerminalText } from '../src/wiring-vkeys.js';
import { ZKP_EXPECTED } from '../vendor/workers/game_workers/lib/zkp-protocol.js';
import { getAddress } from 'viem';
const mutation = process.argv.find((arg) => arg.startsWith('--stage3-mutation='))?.split('=')[1];
const mutations = {
  v3: ["  if (verifierMismatch) {\n    ui.println(ui.t(isPending", "  if (false) {\n    ui.println(ui.t(isPending"],
  v4: ["{ pinMismatch, verifierMismatch, scanIncomplete: isPending", "{ pinMismatch, scanIncomplete: isPending"],
  v7: ["String(epoch.verifier).toLowerCase() !== ZKP_EXPECTED.verifier.toLowerCase()", "String(epoch.verifier) !== ZKP_EXPECTED.verifier"],
  z1: ["if (confirmed) {", "if (true) {"],
  z2: ["await runQuietProcess(command.argv, spawnProcess);", "ui.println(command.build); await runQuietProcess(command.argv, spawnProcess);"],
  z4: ["await runQuietProcess(command.argv, spawnProcess);", "try { await runQuietProcess(command.argv, spawnProcess); } catch {}"],
  z5: ["let done = 0;", "ui.println(ui.t('zk.stage3InstallHint')); let done = 0;"],
  z6: ["{ shell: false, stdio: ['ignore', 'pipe', 'pipe'] }", "{ shell: true, stdio: ['ignore', 'pipe', 'pipe'] }"],
  z7: ["for (let suffix = 1; ; suffix++) {", "fs.rmSync(path.join(cfg.dataDir, outputName), { recursive: true, force: true }); for (let suffix = 1; ; suffix++) {"],
  z9: ["} catch { signal.throwIfAborted(); }", "} catch { break; }"],
  z10: ["wireResults.some((edge) => edge.status === 'fail') || failed.size === 0", "failed.size === 0"],
  z11: ["notVerified = true; break;", "wireResults = null; break;"],
  z12: ["commands.filter((command) => failed.has(command.id))", "commands"],
  z13: ["  if (sourceError) {", "  if (false && sourceError) {"],
  z14: ["platform !== 'win32' && installCommands.length > 0", "installCommands.length > 0"],
  z15: ["child.kill(signal)", "false"],
  z16: ["    running();\n    try {\n      await runQuietProcess(command.argv, spawnProcess);", "    try {\n      await runQuietProcess(command.argv, spawnProcess);\n      running();"],
  z17: ["    child.stdout.resume();\n    child.stderr.resume();", "    // 出力を読まない"],
  z18: ["{ shell: false, stdio: ['ignore', 'pipe', 'pipe'] }", "{ shell: false, stdio: argv[1] === 'version' ? 'inherit' : ['ignore', 'pipe', 'pipe'] }"],
  z19: ["wireResults.some((result) => result.status === 'unavailable') ? 'unavailable' : 'pass'", "false ? 'unavailable' : 'pass'"],
  z20: ["failed.has(edge.child) || (failed.has(edge.parent) && edge.status !== 'fail')",
    "failed.has(edge.parent) || failed.has(edge.child)"],
  z21: ["await runQuietProcess(['docker', 'version', '--format', '{{.Server.Version}}'], interrupted.spawn);",
    "await runQuietProcess(['docker', 'version', '--format', '{{.Server.Version}}'], spawnProcess);"],
  z22: ["terminate = setTimeout(() => kill('SIGTERM'), 300);", "// SIGTERM の段を外す"],
  z23: ["force = setTimeout(() => kill('SIGKILL'), 1300);", "// SIGKILL の段を外す"],
  z24: ["ui.t('zk.conclusionSourceMatches', { path: visibleTerminalText(outDir) })",
    "ui.t('zk.conclusionProof', { range: formatRanges(blocks) })"],
  z25: ["    sourceError = error;", "    fs.mkdirSync(path.join(cfg.dataDir, 'UNSAFE-SOURCE')); fs.writeFileSync(path.join(cfg.dataDir, 'UNSAFE-SOURCE/source.rs'), unpacked?.files[0]?.bytes || 'UNSAFE'); sourceError = error;"],
  z27: ["ui.t('zk.conclusionSourceMatches', { path: visibleTerminalText(outDir) })",
    "ui.t('zk.conclusionSourceMatches', { path: visibleTerminalText(outDir + '-wrong') })"],
  z28: ["  } else if (isPending) {\n    ui.println(ui.t(`zk.conclusionPending.${wireState}`));",
    "  } else if (isPending && wireState !== 'pass') {\n    ui.println(ui.t(`zk.conclusionPending.${wireState}`));"],
  z30: ["          // The formatter cleans up its env-files; keep the source saved in Stage1.",
    "          fs.rmSync(outDir, { recursive: true, force: true });"],
  z31: ["      writeError = error;", "      sourceError = error;"],
  z32: ["      writeError = error;", "      writeError = error; ui.println(ui.t('zk.sourceSaved', { path: visibleTerminalText(outDir) }));"],
  z8: ["ui.println(ui.t('zk.stage1'));\n  ui.println(ui.t('zk.fetching'));\n  const published = await collectGuestSource(chain, epoch.guestSourceHash);",
    "ui.println(ui.t('zk.fetching'));\n  const published = await collectGuestSource(chain, epoch.guestSourceHash);\n  ui.println(ui.t('zk.stage1'));"],
};
function mutated(source, pair) {
  assert(source.includes(pair[0]), '変異の対象がある');
  return source.replace(pair[0], pair[1]);
}
let zkpSource = fs.readFileSync(new URL('../src/zkp.js', import.meta.url), 'utf8');
if (mutation && !['z3', 'z26', 'z29', 'w3'].includes(mutation)) zkpSource = mutated(zkpSource, mutations[mutation]);
if (mutation === 'z13') zkpSource = mutated(zkpSource,
  ["  if (confirmed) {", "  if (confirmed) { unpacked = unpackGuestSource(published.source); checkWireBuildInputs(unpacked.files);"]);
if (mutation === 'z26') {
  const start = zkpSource.indexOf('      const outputName = isPending');
  const end = zkpSource.indexOf('    } catch (error) {\n      // Local write failures', start);
  assert(start >= 0 && end > start, 'z26: Stage1 の保存処理がある');
  const save = zkpSource.slice(start, end);
  zkpSource = zkpSource.slice(0, start) + zkpSource.slice(end);
  zkpSource = mutated(zkpSource, ['  if (confirmed) {', '  if (confirmed) {\n' + save]);
}
if (mutation === 'z29') {
  // FIX3 の形: 準備も Stage1 へ移し、準備失敗では今書いた木を消す。
  const start = zkpSource.indexOf('        let commands;\n        try {\n          if (writeError) throw writeError;\n          commands = formatWireGuestRebuildCommands');
  const end = zkpSource.indexOf('        const vkeys = {};', start);
  assert(start >= 0 && end > start, 'z29: Stage3 の準備処理がある');
  zkpSource = zkpSource.slice(0, start) + zkpSource.slice(end);
  zkpSource = mutated(zkpSource, ['let unpacked, outDir, sourceError, writeError;', 'let unpacked, outDir, commands, sourceError, writeError;']);
  zkpSource = mutated(zkpSource, ["      ui.println(ui.t('zk.sourceSaved', {", `      try {
        commands = formatWireGuestRebuildCommands(outDir, unpacked.sp1Image, unpacked.files,
          { replaceExistingEnv: true });
      } catch (error) {
        fs.rmSync(outDir, { recursive: true, force: true });
        sourceError = error;
        throw error;
      }
      ui.println(ui.t('zk.sourceSaved', {`]);
}
if (mutation === 'z21') zkpSource = mutated(zkpSource,
  ["await readVersion(interrupted.spawn);", "await readVersion(spawnProcess);"]);

// native fs.constants は書換不可。継承した fs の定数だけを試験内で差し替える。
zkpSource = mutated(zkpSource, ["import fs from 'node:fs';", `import nativeFs from 'node:fs';
const fs = Object.create(nativeFs, { constants: { value: { ...nativeFs.constants }, writable: true } });
export { fs as stage3Fs };`]);
zkpSource = zkpSource.replace(/from '([^']+)'/g, (_, p) =>
  `from '${p.startsWith('.') ? new URL(p, new URL('../src/zkp.js', import.meta.url)).href : import.meta.resolve(p)}'`);
const { buildExpectedPublicValues, cargoProveVersion, cargoProveVkey, formatWireGuestRebuildCommands, guestSourceChainHash,
  runZkpMode, unpackGuestSource, writeGuestSourceSafely, inspectWireGuestVkeys, wireVkeyExitCode, stage3Fs }
  = await import(`data:text/javascript;base64,${Buffer.from(zkpSource).toString('base64')}`);
if (mutation && mutation !== 'w3') console.log(`MUTATION_APPLIED ${mutation}`);

// Docker/cargo-prove の代役。外部プログラムを一切起動しない。
const matchingVersionText = 'cargo-prove sp1 (8252c29 2026-06-25T11:48:19Z)';
function fakeStage3Spawn({ calls = [], events = [], dockerError, versionError, dockerExit = 0, versionExit = 0, version = matchingVersionText,
  failBuild = 0, failVkey = 0, key = () => vkey, omitElf = false } = {}) {
  let builds = 0, keys = 0, buildStarts = 0, keyStarts = 0;
  const fails = (setting, n, guest) => typeof setting === 'function' ? setting(n, guest)
    : Array.isArray(setting) ? setting.includes(n) : n === setting;
  return (command, args, options) => {
    calls.push({ command, args, options });
    if (command === 'docker' && args[0] === 'run') events.push(`spawn-build-${++buildStarts}`);
    if (command === 'cargo-prove' && args[1] === 'vkey') events.push(`spawn-vkey-${++keyStarts}`);
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    queueMicrotask(() => {
      let error, code = 0, output = '';
      if (command === 'docker' && args[0] === 'version') {
        events.push('docker-version'); error = dockerError; code = dockerExit;
      } else if (command === 'cargo-prove' && args[1] === '--version') {
        events.push('prove-version'); error = versionError; output = version; code = versionExit;
      } else if (command === 'docker' && args[0] === 'run') {
        events.push(`build-${++builds}`);
        const source = args[args.indexOf('-v') + 1].slice(0, -':/root/program:ro'.length);
        const crate = args[args.indexOf('-w') + 1].split('/').at(-1);
        const bin = args.includes('--bin') ? args[args.indexOf('--bin') + 1] : null;
        const guest = WIRE_GUESTS.find((g) => g.crate === crate && (g.bin || null) === bin);
        assert(guest, '組み直すゲストは既存の12本');
        // A failed process may still leave an ELF; pass must depend on its exit too.
        if (!(typeof omitElf === 'function' ? omitElf(builds, guest) : omitElf)) {
          const elf = path.join(source, crate, 'target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release', guest.elf);
          fs.mkdirSync(path.dirname(elf), { recursive: true }); fs.writeFileSync(elf, 'FAKE ELF');
        }
        if (fails(failBuild, builds, guest)) code = 7;
      } else if (command === 'cargo-prove' && args[1] === 'vkey') {
        events.push(`vkey-${++keys}`);
        const guest = WIRE_GUESTS.find((g) => args.at(-1).endsWith('/' + g.elf));
        output = key(guest);
        if (fails(failVkey, keys, guest)) error = new Error('INTERNAL_FAILURE /secret/path docker run --env-file secret exited 9');
      } else assert.fail('想定外の外部プログラム');
      // Commands and diagnostics on both pipes must never reach stdout/stderr.
      child.stdout.write(output + '\n');
      child.stderr.write('INTERNAL_FAILURE docker run ' + SP1_IMAGE + ' /secret/path exited 7\n');
      if (error) child.emit('error', error);
      child.emit('close', code);
    });
    return child;
  };
}

import { SP1_IMAGE, collectFiles, packGuestSource, PUBLIC_SOURCE_CRATES,
  compressGuestSourceV2, splitGuestSource } from '../../crates/pack-guest-source.mjs';
import { futureAnchorsHash, compareFutureAnchorRuntime } from '../src/future-anchor.js';
import { checkProofFutureAnchor, auditFutureAnchorProviders } from '../src/future-anchor.js';
import { assessEvidenceSegmentBoundaries, deriveGroupingUpperBound,
  resolveProofProviderLabels } from '../src/stages/results.js';
import { evidenceSegmentArtifact } from '../vendor/workers/game_workers/lib/evidence-segment-plan.js';
import { encodeClaimData } from '../vendor/workers/game_workers/lib/claim-data-codec.js';
let reportSource = fs.readFileSync(new URL('../src/report.js', import.meta.url), 'utf8');
if (mutation === 'w3') reportSource = mutated(reportSource, [
  "} else if (ctx.data?.zkInfo?.kind === 'proof'\n          && (st('check.stageC.merkleRoot') === 'fail'\n            || st('check.stageC.evidenceReportMatch') === 'fail')) {",
  '} else if (false) {',
]);
reportSource = reportSource.replace(/from '(\.\.?\/[^']+)'/g, (_, p) =>
  `from '${new URL(p, new URL('../src/report.js', import.meta.url)).href}'`);
const { createReport } = await import(`data:text/javascript;base64,${Buffer.from(reportSource).toString('base64')}`);
if (mutation === 'w3') console.log(`MUTATION_APPLIED ${mutation}`);
import { t } from '../src/i18n.js';
import { checkFutureAnchorRuntimeJson } from '../scripts/future-anchor-runtime.mjs';
import { futureAnchorsHash as collectorHash } from '../../Hardhat/bitcoinu/scripts/lib/collect-wire-lanes.mjs';

// FIX2 G4: Stage3 だけの変異起動でも③自体を必ず照合する。
{
const providerA = `0x${'cc'.repeat(20)}`;
for (const k13 of ['pass', 'fail']) {
  const report = createReport();
  report.check('check.stageC.rootSubmitted', 'pass');
  report.check('check.stageC.merkleRoot', 'fail');
  report.check('check.stageC.futureAnchorsHash', k13);
  const lines = [];
  report.renderSummary({ t: t('ja'), println: (line) => lines.push(String(line)) }, {
    blockNum: 17, data: { zkInfo: { kind: 'proof' }, futureAnchorCheck: { provider: providerA } },
    r2: { baseDir: '/tmp/block17' },
  });
  const resultLines = lines.filter((line) => line.startsWith('  ③ '));
  const reason = t('ja')(k13 === 'fail' ? 'reason.proofRootProviderMismatch' : 'reason.proofRootMismatch', { provider: providerA });
  assert.deepEqual(resultLines, ['  ' + t('ja')('notVerified.results', { reason })], 'FIX2 G4: ③自体が証明つきroot不一致の理由を出す');
  assert(!resultLines[0].includes('実装乖離'));
  assert(resultLines[0].includes(k13 === 'fail' ? `供給元 ${providerA}` : '子の鍵は未照合'));
  // この疎な盤では公開値は未検証。G1 の後も⓪は旧文＋③と同じ理由になる。
  assert.deepEqual(lines.filter((line) => line.startsWith('  ⓪ ')),
    ['  ' + t('ja')('notVerified.zkProof', { reason })], 'FIX2 G4: ⓪は公開値保証なしの文と③と同じ理由');
}
}

function replaceWireInitializer(source, name, literal) {
  const pattern = new RegExp(`(const ${name}: \\[u32; 8\\] = )(?:${name}_UNSET|\\[[^\\]]+\\]);`, 'g');
  const matches = [...String(source).matchAll(pattern)];
  assert.equal(matches.length, 1, `${name} の初期化は1か所`);
  return String(source).replace(pattern, (_match, prefix) => `${prefix}${literal};`);
}

const words = [0x46995ee0, 0x693e2d06, 0x744471e2, 0x1ee9a481,
  0x3146aeb1, 0x01469cbf, 0x43721db9, 0x163137e7];
const other = [1, 2, 3, 4, 5, 6, 7, 8];
const vkey = vkDigestBytes32(words);
assert.equal(vkey, '0x008d32bdc1a4f8b41ba2238f11ee9a481628d5d62051a72fe1b90edc963137e7');
const literal = `[${words.map((word) => `0x${word.toString(16)}u32`).join(', ')}]`;
const files = new Map(collectFiles().map((p) => [p,
  fs.readFileSync(new URL(`../../crates/${p}`, import.meta.url))]));
const headFiles = new Map(files);
for (const edge of WIRE_VKEY_EDGES) {
  const previous = String(files.get(edge.file));
  files.set(edge.file, replaceWireInitializer(previous, edge.name, literal));
}
if (!mutation && !process.argv.includes('--stage3-only')) {
// 焼いた HEAD の11辺と FINAL は WR-BAKE record.json の値でそのまま pass する。
const recordedVkeys = Object.freeze({
  CHUNK: '0x00c9d8b432b5488fcb4d13fad63b6dffd7a53ff91c6a607a3e95db65a23d4b89',
  NODE: '0x00354a25571073e3963eea6c6b03d59baaa0c5d9a50b98209d38eed103dafad5',
  EVIDENCE_SEGMENT: '0x00676d4517f404fb1c9253e925fac438969ec7dbf93f9df04e87e7af432b77f3',
  BIND_CHILD: '0x005ef2afcf87ceff945f1fa7a8ab6382b5bcd7e8cb9b87db331d398edb89895d',
  GROUP: '0x00b0719feb2714f1035a133b409338e625e86f64867c4d61beb9ec8bb8c7a8ec',
  ROOT: '0x0015187608fc1fc4b064b3d287863d27afd5fff34e8b15ac860a09a5116ed9f8',
  L0: '0x006fe2e9806b1a169c2409bc3c002579eb289e4df7ffe68adec18170f0272a1f',
  BIND: '0x00eef3ad4c99478cb3aaa1cf393efd4bcebe0b6c2e196cc8d4cdcbf30a8b929f',
  L1: '0x001066aeb47241e1523045b7d835f2b0b9f1d06912b2a05220c38ee5d9185698',
  L2: '0x00249bfa5ef2812d2433d06411142f58f9517bfdf0062d0f30cf9973ce0f8c75',
  L3: '0x00ba528c572303c839803e3263b8578b33cfdc59e7dcf9fc443719ed965f965c',
  FINAL: '0x00382340c4efdab8b43e1574f19fe2c6a1062723cc15b9f8676cca50b0394801',
});
assert.deepEqual(verifyWireVkeys(headFiles, recordedVkeys, recordedVkeys.FINAL)
  .map(({ status }) => status), Array(12).fill('pass'));

const vkeys = Object.fromEntries(WIRE_GUESTS.map((guest) => [guest.id, vkey]));
const evaluate = (source = files, keys = vkeys, top = vkey) => verifyWireVkeys(source, keys, top);
assert.equal(evaluate().length, 12);
assert(evaluate().every((result) => result.status === 'pass'));
for (const [index, edge] of WIRE_VKEY_EDGES.entries()) {
  const changed = new Map(files);
  changed.set(edge.file, changed.get(edge.file).replace(
    new RegExp(`(const ${edge.name}: \\[u32; 8\\] = )\\[[^\\]]+\\]`),
    `$1[${other.join(', ')}]`,
  ));
  const result = evaluate(changed);
  assert.equal(result.filter((row) => row.status === 'fail').length, 1, `edge ${index}`);
  assert.equal(result[index].status, 'fail', `${edge.parent}->${edge.child}`);
  assert.equal(result.at(-1).status, 'pass');
}
assert.equal(evaluate(files, vkeys, vkDigestBytes32(other)).filter((row) => row.status === 'fail').length, 1);
assert.equal(wireVkeyExitCode(evaluate()), 0);
assert.equal(wireVkeyExitCode(null), 0);
assert.equal(wireVkeyExitCode(evaluate(files, vkeys, vkDigestBytes32(other))), 2);
assert.equal(wireVkeyExitCode([{ status: 'unavailable' }]), 2);
assert.equal(wireVkeyExitCode(null, { pinMismatch: true }), 2);
for (const caseName of [
  'A_char_literal', 'B_raw_string', 'C_use_alias_plus_local', 'D_lrm_whitespace',
  'E_raw_ident', 'F_pub_hides_cfg', 'G_macro_rules_space', 'H_include_space',
  'I_raw_ident_external_mod',
]) {
  const attack = fs.readFileSync(new URL(`./fixtures/wr15-fix1/${caseName}.rs`, import.meta.url), 'utf8');
  const changed = new Map(files);
  changed.set('final-wire-guest/src/main.rs', `${attack}\nconst AGG_L3_VKEY: [u32; 8] = ${literal};`);
  const result = evaluate(changed);
  assert.equal(result.find((row) => row.parent === 'FINAL' && row.child === 'BIND').status, 'unavailable', caseName);
  assert.equal(wireVkeyExitCode(result), 2, caseName);
}
const invalidUtf8 = new Map(files);
invalidUtf8.set('final-wire-guest/src/main.rs', Buffer.concat([
  Buffer.from(`// comment `), Buffer.from([0xff]),
  Buffer.from(`\nconst BIND_VKEY: [u32; 8] = ${literal};\nconst AGG_L3_VKEY: [u32; 8] = ${literal};`),
]));
assert.equal(evaluate(invalidUtf8).find((row) => row.parent === 'FINAL' && row.child === 'BIND').status, 'unavailable');
// The real HEAD guest sources are unbaked. Bake only the eleven named production
// definitions in a copy, then check all edges in both matching and mismatch directions.
const actualGuestFiles = new Map(files);
for (const edge of WIRE_VKEY_EDGES) {
  assert(actualGuestFiles.has(edge.file));
}
assert.deepEqual(evaluate(actualGuestFiles).map((row) => row.status), Array(12).fill('pass'));
for (const [index, edge] of WIRE_VKEY_EDGES.entries()) {
  const changed = new Map(actualGuestFiles);
  changed.set(edge.file, String(changed.get(edge.file)).replace(
    new RegExp(`(const ${edge.name}: \\[u32; 8\\] = )\\[[^\\]]+\\]`),
    `$1[${other.join(', ')}]`,
  ));
  const result = evaluate(changed);
  assert.equal(result[index].status, 'fail', `${edge.parent}->${edge.child}`);
  assert.equal(wireVkeyExitCode(result), 2);
}
for (const [caseName, mutate] of [
  ['redirect', (m) => m.set('final-wire-guest/Cargo.toml',
    `${m.get('final-wire-guest/Cargo.toml')}\n[[bin]]\nname = "final-wire-guest"\npath = "src/real.rs"\n`)],
  ['deffeat', (m) => m.set('final-wire-guest/Cargo.toml',
    `${m.get('final-wire-guest/Cargo.toml')}\n[features]\ndefault = ["measurement-only"]\n`)],
  ['buildrs', (m) => m.set('final-wire-guest/build.rs', 'fn main() { println!("cargo:rustc-cfg=feature=\\"measurement-only\\""); }')],
  ['cargo-alias', (m) => m.set('final-wire-guest/.cargo/config.toml', '[alias]\nprove = "evil"\n')],
]) {
  const changed = new Map(files);
  mutate(changed);
  const result = evaluate(changed);
  assert(result.every((row) => row.status === 'unavailable'), caseName);
  assert.equal(wireVkeyExitCode(result), 2, caseName);
}
for (const lang of ['en', 'ja', 'zh']) {
  for (const status of ['pass', 'fail', 'unavailable', 'unperformed']) {
    assert.notEqual(t(lang)(`zk.wireStatus.${status}`), `zk.wireStatus.${status}`);
  }
}

const parses = (source) => readBakedVkey(source, 'CHILD_VKEY');
const honestZ = fs.readFileSync(new URL('./fixtures/wr15-fix1/Z_honest_rustfmt.rs', import.meta.url), 'utf8');
assert.deepEqual(readBakedVkey(honestZ, 'BIND_VKEY'), other);
assert.deepEqual(parses(`pub const CHILD_VKEY:\n [u32; 8] = [${words.join(',\n')}];`), words);
assert.throws(() => parses(`const CHILD_VKEY: [u32; 8] = [2147483648, 0, 0, 0, 0, 0, 0, 0];`), /out of range/);
assert.deepEqual(parses(`/* const CHILD_VKEY: [u32;8] = [0;8]; /* nested */ */\nconst CHILD_VKEY: [u32; 8] = ${literal};`), words);
assert.deepEqual(parses(`// L0–L3 shared comment\n/* 任意 /* nested – */ */ const CHILD_VKEY: [u32; 8] = ${literal};`), words);
for (const source of [
  `// \u200e invisible\nconst CHILD_VKEY: [u32; 8] = ${literal};`,
  `/* \u202e bidi */ const CHILD_VKEY: [u32; 8] = ${literal};`,
  `const CHILD_VKEY: [u32; 8] = ${literal}; let _ = "é";`,
]) assert.throws(() => parses(source));
for (const source of [
  'const CHILD_VKEY: [u32; 8] = [0; 8];',
  'const CHILD_VKEY_UNSET: [u32; 8] = [0u32; 8]; const CHILD_VKEY: [u32; 8] = CHILD_VKEY_UNSET;',
  `#[cfg(feature = "measurement-only")] const CHILD_VKEY: [u32; 8] = ${literal};`,
  `const CHILD_VKEY: [u32; 8] = ${literal}; static CHILD_VKEY: [u32; 8] = ${literal};`,
  `#[inline] const CHILD_VKEY: [u32; 8] = ${literal};`,
  `static mut CHILD_VKEY: [u32; 8] = ${literal};`,
  `pub(crate) const CHILD_VKEY: [u32; 8] = ${literal};`,
  `#[cfg(feature = "measurement-only")] #[cfg(not(feature = "measurement-only"))] const CHILD_VKEY: [u32; 8] = ${literal};`,
  `include!("elsewhere.rs"); const CHILD_VKEY: [u32; 8] = ${literal};`,
  `macro_rules! make { () => {} } const CHILD_VKEY: [u32; 8] = ${literal};`,
  `mod other; const CHILD_VKEY: [u32; 8] = ${literal};`,
]) assert.throws(() => parses(source));
assert.deepEqual(parses(`#[cfg(feature = "measurement-only")] const CHILD_VKEY: [u32; 8] = [0; 8];\nconst CHILD_VKEY: [u32; 8] = ${literal};`), words);
const agg = `#[path = "../common.rs"] mod common; const CHILD_VKEY: [u32; 8] = ${literal};`;
assert.deepEqual(readBakedVkey(agg, 'CHILD_VKEY', { aggCommon: 'pub fn main() {}' }), words);
assert.throws(() => readBakedVkey(agg, 'CHILD_VKEY', { aggCommon: 'const X: [u32; 8] = [0; 8];' }));
for (const common of [
  'pub const K: [u32; 4 + 4] = [9; 8];',
  'pub fn run() { let k: [u32; 8] = [9; 8]; }',
  'mod r#more; pub fn run() {}',
]) assert.throws(() => readBakedVkey(agg, 'CHILD_VKEY', { aggCommon: common }));
assert.throws(() => readBakedVkey(agg.replace('../common.rs', '../other.rs'), 'CHILD_VKEY', { aggCommon: '' }));
const absent = new Map(files); absent.delete('group-wire-guest/Cargo.toml');
assert.equal(evaluate(absent).find((row) => row.child === 'GROUP').status, 'unavailable');

const commandRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wr15-command-'));
const commandSource = path.join(commandRoot, 'source');
const commands = formatWireGuestRebuildCommands(commandSource, SP1_IMAGE, [...files].map(([p, bytes]) => ({ path: p, bytes })));
assert.equal(commands.length, 12);
assert.equal(new Set(commands.map((row) => row.elfPath)).size, 12);
assert(commands.every((row) => row.build.startsWith('docker run --rm --platform linux/amd64')));
assert(commands.every((row) => row.build.includes('/root/program:ro')));
assert(commands.every((row) => !row.build.includes(`cd ${commandSource}`) && !row.build.includes('sp1-cargo-registry')));
assert(commands.filter((row) => row.bin).every((row) => row.build.includes(`--bin ${row.bin} --features ${row.feature}`)));
assert(commands.every((row) => !/[\x00-\x1f]/.test(row.build)));
// sp1-build 6.3.1 command/docker.rs/build_docker_args, command/utils.rs/
// get_program_build_args and get_rust_compiler_flags, src/lib.rs/DEFAULT_TARGET.
const expectedFlags = ['-C', 'passes=lower-atomic', '-C', 'link-arg=--image-base=2013265920',
  '-C', 'panic=abort', '--cfg', 'getrandom_backend="custom"',
  '-C', 'llvm-args=-misched-prera-direction=bottomup',
  '-C', 'llvm-args=-misched-postra-direction=bottomup'].join('\x1f');
for (const row of commands) {
  const envFile = fs.readFileSync(row.envPath, 'utf8');
  assert(envFile.includes(`CARGO_TARGET_DIR=/root/program/${row.crate}/target/elf-compilation/docker\n`));
  assert(envFile.includes(`CARGO_ENCODED_RUSTFLAGS=${expectedFlags}\n`));
  assert(envFile.includes('RUSTUP_TOOLCHAIN=succinct\nRUSTC_BOOTSTRAP=1\n'));
  assert(envFile.includes('RUSTC=/root/.sp1/toolchains/g7wv95WZT7/bin/rustc\n'));
  assert(envFile.includes('CFLAGS_riscv32im_succinct_zkvm_elf=-D__ILP32__\n'));
  assert(row.build.includes(`-v ${commandSource}:/root/program:ro`));
  assert(row.build.includes(`-w /root/program/${row.crate} --env-file ${row.envPath}`));
  assert(row.build.includes(`--entrypoint '' ${SP1_IMAGE} cargo build --release --target riscv64im-succinct-zkvm-elf`));
  assert(row.build.endsWith('--locked') || row.build.includes('--locked'));
}
fs.rmSync(commandRoot, { recursive: true, force: true });
let invoked;
assert.equal(await cargoProveVkey('/tmp/source/elf/final-wire-guest', (command, args, options) => {
  invoked = { command, args, options, emptyCwd: fs.readdirSync(options.cwd).length === 0 };
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  queueMicrotask(() => {
    child.stdout.emit('data', `${vkey}\n`);
    child.emit('close', 0);
  });
  return child;
}), vkey);
assert.equal(invoked.command, 'cargo-prove');
assert.deepEqual(invoked.args, ['prove', 'vkey', '--elf', '/tmp/source/elf/final-wire-guest']);
assert.equal(invoked.options.shell, false);
assert.equal(invoked.emptyCwd, true);
assert(invoked.options.cwd.startsWith(os.tmpdir()));
assert(!invoked.options.cwd.startsWith('/tmp/source'));
assert(!fs.existsSync(invoked.options.cwd));
const versionCalls = [];
assert.match(await cargoProveVersion((command, args, options) => {
  versionCalls.push({ command, args, options, emptyCwd: fs.readdirSync(options.cwd).length === 0 });
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  queueMicrotask(() => {
    child.stdout.emit('data', 'cargo-prove sp1 (8252c29 2026-06-25T11:48:19Z)\n');
    child.emit('close', 0);
  });
  return child;
}), /8252c29/);
assert.deepEqual(versionCalls[0].args, ['prove', '--version']);
assert.equal(versionCalls[0].command, 'cargo-prove');
assert.equal(versionCalls[0].options.shell, false);
assert.equal(versionCalls[0].emptyCwd, true);
assert(!fs.existsSync(versionCalls[0].options.cwd));
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wr15-elf-test-'));
try {
  for (const guest of WIRE_GUESTS) {
    const elf = path.join(dir, guest.crate, 'target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release', guest.elf);
    fs.mkdirSync(path.dirname(elf), { recursive: true });
    fs.writeFileSync(elf, 'synthetic');
  }
  const source = { sp1Image: SP1_IMAGE, files: [...files].map(([name, bytes]) => ({ path: name, bytes })) };
  let derived = 0;
  const matchingVersion = async () => 'cargo-prove sp1 (8252c29 2026-06-25T11:48:19Z)';
  const wrongVersion = await inspectWireGuestVkeys(source, vkey, dir,
    async () => { derived++; return vkDigestBytes32(other); }, async () => 'cargo-prove sp1 (deadbee 2026-01-01)');
  assert.equal(derived, 0, 'version mismatch must stop derivation');
  assert.equal(wrongVersion.length, 12);
  assert(wrongVersion.every((row) => row.status === 'unavailable' && /cargo-prove version mismatch/.test(row.reason)));
  assert.equal(wireVkeyExitCode(wrongVersion), 2);
  const result = await inspectWireGuestVkeys(source,
    vkey, dir, async () => { derived++; return vkey; }, matchingVersion);
  assert.equal(derived, 12);
  assert(result.every((row) => row.status === 'pass'));
  fs.rmSync(path.join(dir, 'agg-wire-guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/agg-wire-l0'));
  assert.equal((await inspectWireGuestVkeys(source,
    vkey, dir, async () => vkey, matchingVersion)).find((row) => row.child === 'L0').status, 'unavailable');
  const outside = path.join(dir, 'outside-elf');
  fs.writeFileSync(outside, 'synthetic');
  fs.symlinkSync(outside, path.join(dir, 'agg-wire-guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/agg-wire-l0'));
  assert.equal((await inspectWireGuestVkeys(source,
    vkey, dir, async () => vkey, matchingVersion)).find((row) => row.child === 'L0').status, 'unavailable');
} finally { fs.rmSync(dir, { recursive: true, force: true }); }

assert.equal(futureAnchorsHash(0, 200), collectorHash(0, 200));
assert.equal(futureAnchorsHash(17, 86400), collectorHash(17, 86400));
// crates/stage5-timebind/src/lib.rs::future_anchor_hash_matches_solidity_provider_vectors
for (const [n, hash] of [
  [0n, 'cc507474bae6ff2e3c31f3c7fd8b4f911e9940a9a4dd1003685c9fc2a182699c'],
  [1n, '00f3e6e88f453de37f767da22b42b4967fb87357d775c97ab16d9cbcd1ee8431'],
  [7n, '2203037d82c7e7dcfe58d89c379d1049ca76fb3e0c7e019c4f3a3e31cbf14432'],
  [1n << 32n, '80ae6b438227b8c78578fc8c44248a34caf5e1d0ce9ea3cfa13811b74c017ae1'],
]) assert.equal(futureAnchorsHash(n, 200), `0x${hash}`);
const runtimePath = new URL('../src/future-anchor-runtime.json', import.meta.url);
function checkSavedRuntime(p = runtimePath, projectRoot = new URL('../../', import.meta.url)) {
  const saved = JSON.parse(fs.readFileSync(p, 'utf8'));
  const source = fs.readFileSync(new URL('Hardhat/bitcoinu/contracts/FutureAnchorProvider.sol', projectRoot));
  const config = fs.readFileSync(new URL('Hardhat/bitcoinu/hardhat.config.js', projectRoot), 'utf8');
  const compiler = config.match(/version:\s*["']0\.8\.24["'][\s\S]*?settings:\s*\{([\s\S]*?)\n\s*\},/);
  assert(compiler, 'Hardhat 0.8.24 settings missing');
  const stale = saved.sourceSha256 !== crypto.createHash('sha256').update(source).digest('hex')
    || saved.solcVersion !== '0.8.24'
    || JSON.stringify(saved.settings) !== JSON.stringify({ optimizer: { enabled: true, runs: 1 }, evmVersion: 'cancun' })
    || !/optimizer:\s*\{\s*enabled:\s*true,\s*runs:\s*1\s*\}/.test(compiler[1])
    || !/evmVersion:\s*["']cancun["']/.test(compiler[1]);
  if (stale) throw new Error('FutureAnchorProvider runtime JSON is stale');
  return saved;
}
const runtime = checkSavedRuntime();
const freshRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wr15-runtime-fresh-'));
try {
  for (const rel of [
    'block-verifier/src/future-anchor-runtime.json',
    'Hardhat/bitcoinu/contracts/FutureAnchorProvider.sol',
    'Hardhat/bitcoinu/hardhat.config.js',
  ]) {
    const target = path.join(freshRoot, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(new URL(`../../${rel}`, import.meta.url), target);
  }
  const rootUrl = pathToFileURL(`${freshRoot}/`);
  assert.deepEqual(checkSavedRuntime(new URL('block-verifier/src/future-anchor-runtime.json', rootUrl), rootUrl), runtime);
} finally { fs.rmSync(freshRoot, { recursive: true, force: true }); }
const debugPath = new URL('../../Hardhat/bitcoinu/artifacts/contracts/FutureAnchorProvider.sol/FutureAnchorProvider.dbg.json', import.meta.url);
if (fs.existsSync(debugPath)) checkFutureAnchorRuntimeJson();
const staleDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wr15-runtime-test-'));
try {
  const stalePath = path.join(staleDir, 'runtime.json');
  fs.writeFileSync(stalePath, JSON.stringify({ ...runtime, sourceSha256: '0'.repeat(64) }));
  assert.throws(() => checkSavedRuntime(stalePath), /stale/);
  if (fs.existsSync(debugPath)) assert.throws(() => checkFutureAnchorRuntimeJson(stalePath), /stale/);
} finally { fs.rmSync(staleDir, { recursive: true, force: true }); }
const evidence = `0x${'12'.repeat(20)}`;
let code = runtime.object.toLowerCase().replace(/^0x/, '');
for (const ref of runtime.immutableReferences) {
  code = code.slice(0, ref.start * 2) + '0'.repeat(24) + evidence.slice(2) + code.slice((ref.start + 32) * 2);
}
assert.equal(compareFutureAnchorRuntime(`0x${code}`, runtime, evidence).ok, true);
assert.equal(compareFutureAnchorRuntime(`0x${code.slice(0, -1)}0`, runtime, evidence).ok, false);
assert.equal(compareFutureAnchorRuntime(`0x${code}`, runtime, `0x${'34'.repeat(20)}`).ok, false);

const tm = `0x${'aa'.repeat(20)}`;
const ev = evidence;
const providerA = `0x${'cc'.repeat(20)}`;
const providerB = `0x${'dd'.repeat(20)}`;
const zero = `0x${'00'.repeat(20)}`;
const blockNum = 17;
const formula = futureAnchorsHash(blockNum, 86400);
const proofEvent = { evtBlock: 10n, logIndex: 5n };
function anchorChain({ current = providerA, pending = zero, eta = 0n, before = null,
  logs = [], timestamp = 100n, badEvidence = false, badHash = false,
  badCode = false, failHistoric = false } = {}) {
  const stateAt = (height) => height === 9n && before ? before : { current, pending, eta };
  const chain = {
    contracts: { tokenMining: tm },
    client: {
      getBlock: async () => ({ timestamp }),
      getBlockNumber: async () => 10n,
      getCode: async () => badCode ? '0x00' : `0x${code}`,
      readContract: async ({ address, functionName, blockNumber, args }) => {
        if (failHistoric && blockNumber != null && ['anchorProvider', 'pendingAnchorProvider', 'pendingVkeyEta'].includes(functionName)) {
          throw new Error('archive unavailable');
        }
        if (functionName === 'evidence') return badEvidence && address !== tm ? providerB : ev;
        if (functionName === 'GAME_PERIOD') return 86400n;
        const state = stateAt(blockNumber);
        if (functionName === 'anchorProvider') return state.current;
        if (functionName === 'pendingAnchorProvider') return state.pending;
        if (functionName === 'pendingVkeyEta') return state.eta;
        if (functionName === 'anchorsHash') return badHash ? `0x${'ab'.repeat(32)}`
          : futureAnchorsHash(args[0], 86400);
        throw new Error(`unexpected ${functionName}`);
      },
    },
    getLogsChunked: async ({ event }) => logs.filter((log) => log.eventName === event.name),
  };
  return chain;
}
for (const badProvider of [providerA, providerB, `0x${'11'.repeat(20)}`, `0x${'22'.repeat(20)}`, `0x${'33'.repeat(20)}`]) {
  const result = await checkProofFutureAnchor(anchorChain({ current: badProvider }), blockNum,
    proofEvent, `0x${'01'.repeat(32)}`);
  assert.equal(result.status, 'fail');
  assert.equal(result.provider.toLowerCase(), badProvider.toLowerCase());
}
assert.equal((await checkProofFutureAnchor(anchorChain(), blockNum, proofEvent, formula)).status, 'pass');
assert.equal((await checkProofFutureAnchor(anchorChain({ current: zero }), blockNum, proofEvent,
  `0x${'00'.repeat(32)}`)).status, 'pass');
assert.equal((await checkProofFutureAnchor(anchorChain({ pending: providerB, eta: 50n }), blockNum,
  proofEvent, formula)).source, 'pending');
const laterApply = [{ eventName: 'VerifierAndVkeyApplied', logIndex: 8n }];
assert.equal((await checkProofFutureAnchor(anchorChain({ current: providerB, before: {
  current: providerA, pending: providerB, eta: 50n,
}, logs: laterApply }), blockNum, proofEvent, formula)).provider, 'unavailable');
const laterCancel = [{ eventName: 'VerifierAndVkeyCancelled', logIndex: 8n }];
assert.equal((await checkProofFutureAnchor(anchorChain({ current: providerA, before: {
  current: providerA, pending: providerB, eta: 50n,
}, logs: laterCancel }), blockNum, proofEvent, formula)).provider, providerB);
const earlierApplyAndLaterCancel = [
  { eventName: 'VerifierAndVkeyProposed', logIndex: 2n },
  { eventName: 'VerifierAndVkeyApplied', logIndex: 3n },
  { eventName: 'VerifierAndVkeyCancelled', logIndex: 8n },
];
assert.equal((await checkProofFutureAnchor(anchorChain({ current: providerB, before: {
  current: providerA, pending: providerB, eta: 50n,
}, logs: earlierApplyAndLaterCancel }), blockNum, proofEvent, formula)).provider, providerB);
const unreadable = await checkProofFutureAnchor(anchorChain({ failHistoric: true }), blockNum, proofEvent, formula);
assert.equal(unreadable.status, 'pass');
assert.equal(unreadable.provider, 'unavailable');
const unreadableZero = await checkProofFutureAnchor(anchorChain({ failHistoric: true }), blockNum,
  proofEvent, `0x${'00'.repeat(32)}`);
assert.equal(unreadableZero.status, 'skip');
assert.equal(unreadableZero.reason, 'provider_unavailable');
assert.equal((await checkProofFutureAnchor(anchorChain({ failHistoric: true }), blockNum,
  proofEvent, `0x${'01'.repeat(32)}`)).status, 'fail');
const shadowAndLaterChange = [
  { eventName: 'VerifierAndVkeyApplied', logIndex: 3n },
  { eventName: 'VerifierAndVkeyApplied', logIndex: 8n },
];
const shadow = await checkProofFutureAnchor(anchorChain({ current: providerB, before: {
  current: zero, pending: zero, eta: 0n,
}, logs: shadowAndLaterChange }), blockNum, proofEvent, formula);
assert.equal(shadow.provider, 'unavailable');
assert.equal(shadow.status, 'pass');
assert.equal((await checkProofFutureAnchor(anchorChain({ current: providerB, before: {
  current: zero, pending: zero, eta: 0n,
}, logs: shadowAndLaterChange }), blockNum, proofEvent, `0x${'00'.repeat(32)}`)).status, 'skip');
assert.equal((await checkProofFutureAnchor(anchorChain({ current: providerB, before: {
  current: zero, pending: zero, eta: 0n,
}, logs: shadowAndLaterChange }), blockNum, proofEvent, `0x${'01'.repeat(32)}`)).status, 'fail');
const shadowThenProposed = [
  { eventName: 'VerifierAndVkeyApplied', logIndex: 3n },
  { eventName: 'VerifierAndVkeyProposed', logIndex: 8n },
];
assert.equal((await checkProofFutureAnchor(anchorChain({ current: providerB, before: {
  current: zero, pending: zero, eta: 0n,
}, logs: shadowThenProposed }), blockNum, proofEvent, formula)).provider, 'unavailable');
const lateReport = createReport();
lateReport.check('check.stageC.evidenceReportMatch', 'fail', {
  provider: 'unavailable', childKeys: 'unperformed_in_menu1',
});
const lateStage = { futureAnchorCheck: { provider: providerA },
  anomalies: ['proof root provider unavailable'],
  proofProviderAnomalies: [{ index: 0, key: 'proofRoot' }] };
resolveProofProviderLabels({ report: lateReport,
  ui: { t: (_, { provider }) => `proof root provider ${provider}` } }, lateStage);
assert.equal(lateReport.get('check.stageC.evidenceReportMatch').params.provider, providerA);
assert.equal(lateStage.anomalies[0], `proof root provider ${providerA}`);
assert.equal((await auditFutureAnchorProviders(anchorChain(), runtime)).current.status, 'pass');
assert.equal((await auditFutureAnchorProviders(anchorChain({ current: zero }), runtime)).current.status, 'unwired');
assert.equal((await auditFutureAnchorProviders(anchorChain({ pending: zero, eta: 200n }), runtime)).pending.status, 'unwired');
for (const bad of [{ badEvidence: true }, { badCode: true }, { badHash: true }]) {
  assert.equal((await auditFutureAnchorProviders(anchorChain(bad), runtime)).current.status, 'fail');
}
assert.equal((await auditFutureAnchorProviders(anchorChain({ pending: providerB, eta: 200n,
  badHash: true }), runtime)).pending.status, 'fail');

const frames = [{ seq: 1, rawBytes: 10 }, { seq: 2, rawBytes: 20 }];
const artifact = evidenceSegmentArtifact(frames);
assert.equal(assessEvidenceSegmentBoundaries(frames, artifact).status, 'pass');
assert.equal(assessEvidenceSegmentBoundaries(frames, { ...artifact, segments: [] }).status, 'warn');
assert.equal(assessEvidenceSegmentBoundaries(frames, { ...artifact,
  pinVersion: 'unknown' }).status, 'warn');
assert.equal(assessEvidenceSegmentBoundaries(frames, { ...artifact, budget: {} }).status, 'warn');
assert.equal(assessEvidenceSegmentBoundaries([], evidenceSegmentArtifact([])).status, 'pass');
const emptyClaim = encodeClaimData(17, { groups: [] });
assert.equal(buildExpectedPublicValues({ input: { blockNum: 17,
  chunksHex: [`0x${Buffer.from(emptyClaim.bytes).toString('hex')}`],
  applicantHashUpdatedBlock: 0, evidenceGraceSec: 0, randaoEthBlockNumber: 0,
} }).blockNum, 17n);
assert.throws(() => buildExpectedPublicValues({ input: { blockNum: 18,
  chunksHex: [`0x${Buffer.from(emptyClaim.bytes).toString('hex')}`],
} }), /blob blockNum/);

const rosterChain = {
  getTimingConstants: async () => ({ startTimeEntryMs: 1_000_000, blockTimeMs: 100_000 }),
  currentGrace: async () => 50,
  otherRegistrationCount: async () => 1,
  otherRegistrationAt: async () => ({ hash: `0x${'00'.repeat(32)}`,
    registeredAt: 1050, registeredBlock: 9 }),
};
const zeroRoster = await deriveGroupingUpperBound(rosterChain, 1, undefined, `0x${'00'.repeat(32)}`);
assert.equal(zeroRoster.source, 'chattingStart_fallback');
assert.equal((await deriveGroupingUpperBound(rosterChain, 1)).source, 'chattingStart_fallback');
// WR-15-FIX2: regenerate both structural and Cargo allowlists; exercise gates (a)/(c).
{
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
// Other work may add untracked files to crates/ while this unit runs. The
// allowlist is deliberately regenerated from the committed HEAD tree.
const repo = new URL('../../', import.meta.url);
const paths = execFileSync('git', ['ls-files', 'crates'], { cwd: repo, encoding: 'utf8' })
  .trim().split('\n').filter((p) => p.startsWith('crates/')
    && PUBLIC_SOURCE_CRATES.includes(p.split('/')[1])
    && /\.(?:rs|toml|lock)$/.test(p)
    && !p.split('/').some((part) => part === 'fixtures' || part === 'target'))
  .map((p) => p.slice('crates/'.length)).sort();
assert.equal(paths.length, 204); // WR-10x-e: bind-child-wire-guest の4ファイルを追加
assert.deepEqual([...WIRE_SOURCE_CRATES], [...PUBLIC_SOURCE_CRATES]);
const full = new Map(paths.map((p) => [p,
  execFileSync('git', ['show', `08f7ef70556b7aca19aa4fdab25a4c127fbf47f7:crates/${p}`], { cwd: repo })]));
const canonicalRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wr15-fix2-head-'));
for (const [p, bytes] of full) {
  const target = path.join(canonicalRoot, p);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
}
const inputs = Object.fromEntries(paths.filter((p) => /(?:^|\/)(?:Cargo\.(?:toml|lock)|rust-toolchain(?:\.toml)?)$/.test(p))
  .map((p) => [p, sha(full.get(p))]));
assert.deepEqual(inputs, WIRE_BUILD_INPUT_SHA256);
assert.equal(checkWireBuildInputs(full), true);
const rustFiles = [...new Set(WIRE_VKEY_EDGES.map((e) => e.file)), 'agg-wire-guest/src/common.rs'];
assert.deepEqual(Object.keys(RUST_SOURCE_SHAPES).sort(), [...rustFiles].sort());
for (const p of rustFiles) {
  const names = WIRE_VKEY_EDGES.filter((e) => e.file === p).map((e) => e.name);
  assert.equal(wireSourceShape(String(full.get(p)), names), RUST_SOURCE_SHAPES[p], p);
}
const observed = { lexicalKinds: new Set(), topItems: new Set(), bodyBindings: new Set(),
  macros: new Set(), attributes: new Set() };
for (const p of rustFiles) {
  const ts = rustTokens(String(full.get(p)));
  const at = (i) => ts[i]?.value;
  let depth = 0;
  for (let i = 0; i < ts.length; i++) {
    const t = at(i);
    observed.lexicalKinds.add(ts[i].kind);
    if (depth === 0 && ['fn', 'const', 'use', 'mod'].includes(t)) observed.topItems.add(t);
    if (depth > 0 && t === 'let') observed.bodyBindings.add(t);
    if (t === '#') {
      let j = i + 1;
      const inner = at(j) === '!' ? (j++, true) : false;
      assert.equal(at(j++), '[');
      let n = 1; const parts = [];
      for (; j < ts.length && n; j++) {
        if (at(j) === '[') n++;
        if (at(j) === ']') n--;
        if (n) parts.push(at(j));
      }
      observed.attributes.add(`${inner ? '!' : ''}${parts.join('')}`);
    }
    if (ts[i].kind === 'id' && at(i + 1) === '!' && ['(', '{', '['].includes(at(i + 2))) {
      let start = i;
      while (start >= 3 && at(start - 1) === ':' && at(start - 2) === ':' && ts[start - 3].kind === 'id') start -= 3;
      observed.macros.add(ts.slice(start, i + 1).map((x) => x.value).join(''));
    }
    if (t === '{') depth++;
    if (t === '}') depth--;
  }
}
for (const key of ['lexicalKinds', 'topItems', 'bodyBindings', 'macros', 'attributes']) {
  assert.deepEqual([...observed[key]].sort(), [...WIRE_RUST_ALLOWLIST[key]].sort(), key);
}
const usePaths = new Set(rustFiles.flatMap((p) => [...String(full.get(p)).matchAll(/^use\s+([\s\S]*?);/gm)]
  .map((m) => m[1].replace(/\s+/g, ''))));
assert.deepEqual([...RUST_USE_PATHS].sort(), [...usePaths].sort());

const words = [0x46995ee0, 0x693e2d06, 0x744471e2, 0x1ee9a481,
  0x3146aeb1, 0x01469cbf, 0x43721db9, 0x163137e7];
const literal = `[\n${words.map((w) => `0x${w.toString(16)}u32`).join(',\n')},\n]`;
const baked = new Map(full);
for (const edge of WIRE_VKEY_EDGES) {
  const p = edge.file;
  const old = String(baked.get(p));
  baked.set(p, Buffer.from(replaceWireInitializer(old, edge.name, literal)));
}
const vkey = vkDigestBytes32(words);
const vkeys = Object.fromEntries(WIRE_GUESTS.map((guest) => [guest.id, vkey]));
const evaluate = (files) => verifyWireVkeys(files, vkeys, vkey);
assert.deepEqual(evaluate(baked).map((r) => r.status), Array(12).fill('pass'));
assert.equal(wireVkeyExitCode(evaluate(baked)), 0);
const finalPath = 'final-wire-guest/src/main.rs';
const commonPath = 'agg-wire-guest/src/common.rs';
const edit = (p, fn) => { const copy = new Map(baked); copy.set(p, Buffer.from(fn(String(copy.get(p))))); return copy; };
const block = '        verify_child(&BIND_VKEY, &binder_pv);';
const variants = {
  V1: edit(finalPath, (s) => s.replace(`const BIND_VKEY: [u32; 8] = ${literal};`,
    `const NOTE: &core::ffi::CStr = cr"\\";\nconst BIND_VKEY: [u32; 8] = [9, 9, 9, 9, 9, 9, 9, 9];\nconst DOC: &str = "\n; const BIND_VKEY: [u32; 8] = ${literal}; const DOC2: &str = \n";\n// ";`)),
  V2: edit(finalPath, (s) => s.replace(block,
    `        struct BIND_VKEY;\n        impl core::ops::Deref for BIND_VKEY {\n            type Target = [u32; 8];\n            fn deref(&self) -> &[u32; 8] { &[9; 8] }\n        }\n${block}`)),
  V3: edit(finalPath, (s) => s.replace(block, `        use final_wire::*;\n${block}`)),
  V4a: edit(commonPath, (s) => s.replace('    let block_num', '    let child_vkey = [9u32; 8];\n    let block_num')),
  V4b: edit(commonPath, (s) => s.replace('    let block_num', '    let child_vkey: [_; 8] = [9; 8];\n    let block_num')),
};
for (const [name, files] of Object.entries(variants)) {
  const result = evaluate(files);
  assert.equal(wireVkeyExitCode(result), 2, name);
  assert(result.some((r) => r.status === 'unavailable'), name);
}
const probeDir = new URL('./fixtures/wr15-fix2/rust/', import.meta.url);
for (const n of ['P1_raw_cstr', 'P2_block_unit_struct', 'P3_block_glob']) {
  assert.throws(() => readBakedVkey(fs.readFileSync(new URL(`${n}.rs`, probeDir), 'utf8'), 'BIND_VKEY'), undefined, n);
}
assert.match(fs.readFileSync(new URL('./fixtures/wr15-fix2/lib/final_wire.rs', import.meta.url), 'utf8'),
  /pub const BIND_VKEY: \[u32; 8\] = \[9; 8\];/);
const consistent = new Set(['N5_underscore_suffix', 'N6_hex_leading_underscore',
  'N7_leading_zero_decimal', 'A4_measurement_plus_production', 'A5_doc_comment',
  'C1_string_with_comment_open', 'C2_line_comment_with_block_marks',
  'C3_block_comment_with_quote', 'C4_nested_block', 'C5_slash_star_slash',
  'C6_escaped_quote_and_continuation', 'C9_crlf_honest',
  'C12_u2028_in_line_comment', 'M2_spaced_assert']);
const consistencyDir = new URL('./fixtures/wr15-fix2/', import.meta.url);
const consistencyFiles = fs.readdirSync(consistencyDir).filter((p) => p.endsWith('.rs'));
assert.equal(consistencyFiles.length, 34);
for (const file of consistencyFiles) {
  const source = fs.readFileSync(new URL(file, consistencyDir), 'utf8');
  const name = file.slice(0, -3);
  if (consistent.has(name)) {
    const expected = name === 'N7_leading_zero_decimal' ? [10, 2, 3, 4, 5, 6, 7, 8]
      : [1, 2, 3, 4, 5, 6, 7, 8];
    assert.deepEqual(readBakedVkey(source, 'BIND_VKEY'), expected, name);
  } else assert.throws(() => readBakedVkey(source, 'BIND_VKEY'), undefined, name);
}
const agg = `#[path = "../common.rs"] mod common; const CHILD_VKEY: [u32; 8] = ${literal};`;
assert.throws(() => readBakedVkey(agg, 'CHILD_VKEY', {
  aggCommon: fs.readFileSync(new URL('P4_common_untyped_let.rs', probeDir), 'utf8'),
}));
assert.throws(() => readBakedVkey(agg, 'CHILD_VKEY', {
  aggCommon: 'use final_wire::*; pub fn main() {}',
}));

// メニューの自動照合にも使えるよう、試験用の11定数を焼いた木を梱包する。
for (const [p, bytes] of baked) fs.writeFileSync(path.join(canonicalRoot, p), bytes);
const packed = packGuestSource(canonicalRoot);
const packageSource = unpackGuestSource(packed.bytes);
assert.equal(packageSource.files.length, 204); // WR-10x-e: bind-child-wire-guest の4ファイルを追加
const target = fs.mkdtempSync(path.join(os.tmpdir(), 'wr15-fix2-gate-'));
const asFiles = (m) => [...m].map(([p, bytes]) => ({ path: p, bytes }));
try {
  const honestDir = writeGuestSourceSafely(packageSource, target, 'honest');
  const commands = formatWireGuestRebuildCommands(honestDir, SP1_IMAGE, packageSource.files);
  assert.equal(commands.length, 12);
  assert(commands.every((c) => c.build.startsWith('docker run ')));
  const bad = {
    rootCargoAlias: (m) => m.set('.cargo/config.toml', '[alias]\nprove = "evil"\n'),
    crateBuildRs: (m) => m.set('final-wire-guest/build.rs', 'fn main() {}'),
    manifestBuild: (m) => m.set('final-wire-guest/Cargo.toml',
      String(m.get('final-wire-guest/Cargo.toml')).replace('edition = "2021"', 'edition = "2021"\nbuild = "build.rs"')),
    procMacro: (m) => m.set('final-wire-guest/Cargo.toml', Buffer.concat([m.get('final-wire-guest/Cargo.toml'), Buffer.from('\n[lib]\nproc-macro = true\n')])),
    lockChange: (m) => m.set('final-wire-guest/Cargo.lock',
      String(m.get('final-wire-guest/Cargo.lock')).replace('version = 4', 'version = 3')),
    toolchainChange: (m) => m.set('final-wire-guest/rust-toolchain.toml', '[toolchain]\nchannel = "stable"\n'),
    extraCrate: (m) => m.set('evil-crate/Cargo.toml', '[package]\nname = "evil"\n'),
    workspacePatch: (m) => m.set('Cargo.toml', '[workspace]\n[patch.crates-io]\n'),
    extraBin: (m) => m.set('agg-wire-guest/src/bin/level4.rs', 'fn main() {}'),
    upperCargo: (m) => m.set('final-wire-guest/.Cargo/config.toml', 'x'),
    upperCargoAll: (m) => m.set('final-wire-guest/.CARGO/config', 'x'),
    upperBuild: (m) => m.set('final-wire-guest/Build.rs', 'x'),
    upperBuildAll: (m) => m.set('final-wire-guest/BUILD.RS', 'x'),
    upperBin: (m) => m.set('agg-wire-guest/src/BIN/level9.rs', 'x'),
    extraBinText: (m) => m.set('agg-wire-guest/src/bin/extra.txt', 'x'),
    upperToolchain: (m) => m.set('scoring-core/RUST-TOOLCHAIN.toml', 'x'),
    upperLock: (m) => m.set('final-wire-guest/CARGO.LOCK', 'x'),
    fullwidth: (m) => m.set('final-wire-guest/ｂuild.rs', 'x'),
    cyrillic: (m) => m.set('final-wire-guest/.cargо/config', 'x'),
    trailingDot: (m) => m.set('final-wire-guest/extra./x.rs', 'x'),
    fileCollision: (m) => { m.set('final-wire-guest/Foo', 'x'); m.set('final-wire-guest/foo', 'y'); },
    dirCollision: (m) => { m.set('final-wire-guest/Foo/x', 'x'); m.set('final-wire-guest/foo/y', 'y'); },
    fileDirCollision: (m) => { m.set('final-wire-guest/Foo', 'x'); m.set('final-wire-guest/foo/y', 'y'); },
    targetSource: (m) => m.set('final-wire-guest/Target/x', 'x'),
  };
  for (const [name, mutate] of Object.entries(bad)) {
    const modified = new Map(full); mutate(modified);
    const unpacked = { ...packageSource, files: asFiles(modified) };
    const forbidden = path.join(target, name);
    assert.throws(() => writeGuestSourceSafely(unpacked, target, name), undefined, `${name}: gate a`);
    assert(!fs.existsSync(forbidden), `${name}: wrote a source tree`);
    assert.throws(() => formatWireGuestRebuildCommands(forbidden, SP1_IMAGE, unpacked.files), undefined, `${name}: gate c`);
    const result = evaluate(modified);
    assert.equal(wireVkeyExitCode(result), 2, `${name}: exit`);
    assert(result.every((row) => row.status === 'unavailable'), `${name}: unavailable`);
  }
  const plantedElf = 'final-wire-guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/final-wire-guest';
  const withPlantedElf = new Map(full); withPlantedElf.set(plantedElf, Buffer.from('PLANTED'));
  const plantedFiles = asFiles(withPlantedElf);
  assert.throws(() => checkGuestSourceNames(withPlantedElf), /guest target must be empty in source/);
  assert.throws(() => writeGuestSourceSafely({ ...packageSource, files: plantedFiles }, target, 'planted-elf'),
    /guest target must be empty in source/);
  assert(!fs.existsSync(path.join(target, 'planted-elf')));
  assert.throws(() => formatWireGuestRebuildCommands(path.join(target, 'planted-elf'), SP1_IMAGE, plantedFiles),
    /guest target must be empty in source/);
  // The writer's second target check must still catch a source introduced after its input gate.
  let fileReads = 0;
  const latePlanted = { get files() { return ++fileReads === 1 ? packageSource.files : plantedFiles; } };
  assert.throws(() => writeGuestSourceSafely(latePlanted, target, 'late-planted-elf'),
    /source overlaps writable target/);
  assert(!fs.existsSync(path.join(target, 'late-planted-elf')));
  const foldedCargo = new Map(full);
  foldedCargo.set('scoring-core/src/Cargo.toml/a.rs', Buffer.from('x'));
  foldedCargo.set('scoring-core/src/cargo.toml/b.rs', Buffer.from('x'));
  assert.throws(() => checkGuestSourceNames(foldedCargo), /case-folded path collision/);
  assert.throws(() => checkWireBuildInputs(foldedCargo), /case-folded path collision/);
  const lowerCargoLock = new Map(full); lowerCargoLock.set('scoring-core/src/cargo.lock', Buffer.from('x'));
  assert.throws(() => checkGuestSourceNames(lowerCargoLock), /Cargo input spelling differs from canonical name/);
  assert.throws(() => checkWireBuildInputs(lowerCargoLock), /Cargo input spelling differs from canonical name/);
  for (const unsafe of ['final-wire-guest/.git/config', 'final-wire-guest/.envrc',
    'final-wire-guest/.vscode/settings.json', 'agg-wire-guest/src/BIN/level0.rs']) {
    const modified = new Map(full); modified.set(unsafe, Buffer.from('x'));
    assert.throws(() => checkGuestSourceNames(modified), /outside audited spelling/, unsafe);
    assert.throws(() => writeGuestSourceSafely({ ...packageSource, files: asFiles(modified) }, target, 'bad-segment'),
      /outside audited spelling/, unsafe);
    assert(!fs.existsSync(path.join(target, 'bad-segment')));
  }
  const oldRev = '6b9da7f61~1';
  const oldCrates = new Set(['scoring-core', 'stage3-aggregation', 'group-guest', 'agg-guest', 'zkp-guest']);
  const oldPaths = execFileSync('git', ['ls-tree', '-r', '--name-only', oldRev, '--', 'crates'],
    { cwd: repo, encoding: 'utf8' }).trim().split('\n')
    .filter((p) => oldCrates.has(p.split('/')[1]) && /\.(rs|toml|lock)$/.test(p)
      && !p.includes('/target/') && !p.includes('/fixtures/'));
  assert.equal(oldPaths.length, 75);
  const oldFiles = oldPaths.map((p) => ({ path: p.slice('crates/'.length),
    bytes: execFileSync('git', ['show', `${oldRev}:${p}`], { cwd: repo }) }));
  assert.throws(() => checkWireBuildInputs(oldFiles), /not a wiring 23-crate source bundle/);
  assert.throws(() => writeGuestSourceSafely({ files: oldFiles }, target, 'legacy-honest'),
    /not a wiring 23-crate source bundle/);
  assert(!fs.existsSync(path.join(target, 'legacy-honest')));
  // Exercise menu 2's exit and printed output without running a build.
  const added = Buffer.from('[alias]\nprove = "evil"\n');
  const badRaw = Buffer.concat([packed.uncompressedBytes,
    Buffer.from(`file\t.cargo/config.toml\t${added.length}\n`), added, Buffer.from('\n')]);
  const maliciousPackage = compressGuestSourceV2(badRaw);
  const sourceOutput = path.join(target, `zkp-guest-source-${vkey.slice(2, 14)}`);
  const runPackage = async (bytes, dataDir = target, config = {}, interaction = null) => {
    const chunks = splitGuestSource(bytes).map((chunk) => `0x${chunk.toString('hex')}`);
    const hash = guestSourceChainHash(chunks);
    const logs = chunks.map((data, index) => ({ blockNumber: 500n, logIndex: index,
      args: { guestSourceHash: hash, chunkIndex: index, totalChunks: chunks.length,
        runningHash: guestSourceChainHash(chunks.slice(0, index + 1)), data } }));
    const output = [];
    const chain = {
      contracts: { tokenMining: `0x${'11'.repeat(20)}` },
      vkeyEpochs: async () => [{ index: 0, vkey, verifier: ZKP_EXPECTED.verifier, guestSourceHash: hash, activatedAt: 0 }],
      pendingVkeyProposal: async () => ({ pending: false }),
      proofRequired: async () => false,
      blockStates: async () => ({ root: `0x${'00'.repeat(32)}`, zkEpochPlusOne: 0 }),
      client: { readContract: async ({ functionName }) => functionName === 'guestSourceOf'
        ? [hash, chunks.length, chunks.length] : 500n },
      getLogsChunked: async () => logs,
    };
    const code = await runZkpMode({ zkScanMaxBlock: 0, dataDir, ...config }, chain,
      { println: (line) => output.push(String(line)), warn: (line) => output.push(String(line)),
        t: (key, params) => params ? `${key} ${JSON.stringify(params)}` : key },
      { isInteractive: true, yesNo: async () => true },
      { spawnProcess: fakeStage3Spawn(), runVkey: interaction?.runVkey || (async () => vkey),
        readVersion: async () => matchingVersionText });
    return { code, output: output.join('\n') };
  };
  const blocked = await runPackage(maliciousPackage);
  assert.equal(blocked.code, 2);
  assert.match(blocked.output, /zk\.wireUnsafeSource/);
  assert(!blocked.output.includes('docker run '));
  assert(!fs.existsSync(sourceOutput));
  const legacyBytes = (entries) => compressGuestSourceV2(Buffer.concat([
    Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`),
    ...entries.flatMap((file) => [Buffer.from(`file\t${file.path}\t${file.bytes.length}\n`),
      Buffer.from(file.bytes), Buffer.from('\n')]),
  ]));
  const oldBlocked = await runPackage(legacyBytes([...oldFiles,
    { path: 'zkp-guest/.Cargo/config.toml', bytes: Buffer.from('x') }]));
  assert.equal(oldBlocked.code, 2);
  assert.match(oldBlocked.output, /zk\.wireUnsafeSource/);
  assert(!oldBlocked.output.includes('docker run '));
  assert(!fs.existsSync(sourceOutput));
  const oldHonest = await runPackage(legacyBytes(oldFiles));
  assert.equal(oldHonest.code, 2);
  assert.match(oldHonest.output, /zk\.wireUnsafeSource/);
  assert(!oldHonest.output.includes('docker run '));
  assert(!fs.existsSync(sourceOutput));
  const spoofPath = 'scoring-core/guest source output already exists: (previous run)/x.rs';
  const spoofed = new Map(full); spoofed.set(spoofPath, Buffer.from('x'));
  const spoofResult = await runPackage(legacyBytes(asFiles(spoofed)));
  assert.equal(spoofResult.code, 2);
  assert.match(spoofResult.output, /zk\.wireUnsafeSource/);
  assert(!spoofResult.output.includes('zk.sourceAlreadyExists'));
  assert(!spoofResult.output.includes('docker run '));
  assert(!fs.existsSync(sourceOutput));
  const bidiPath = 'scoring-core/\u202e\u2066\u009bgnp.exe/x';
  const bidi = new Map(full); bidi.set(bidiPath, Buffer.from('x'));
  const bidiResult = await runPackage(legacyBytes(asFiles(bidi)));
  assert.equal(bidiResult.code, 2);
  assert.match(bidiResult.output, /zk\.wireUnsafeSource/);
  assert(!bidiResult.output.includes('\u202e'));
  assert(!bidiResult.output.includes('\u2066'));
  assert(!bidiResult.output.includes('\u009b'));
  assert(!bidiResult.output.includes('docker run '));
  assert(!fs.existsSync(sourceOutput));
  const forgedHeader = `file\t\u001b[2JALL 12 EDGES PASS\u001b[8m\u202e\u009b\u0007\tX\tY\n`;
  const malformed = await runPackage(compressGuestSourceV2(Buffer.concat([
    packed.uncompressedBytes, Buffer.from(forgedHeader),
  ])));
  assert.equal(malformed.code, 2);
  assert.match(malformed.output, /zk\.wireUnsafeSource/);
  for (const cp of ['001b', '202e', '009b', '0007']) {
    assert(malformed.output.includes(`\\u${cp}`), `門の理由は可視化 U+${cp}`);
  }
  assert(!/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(malformed.output.replaceAll('\n', '')));
  assert(!malformed.output.includes('docker run '));
  assert(!fs.existsSync(sourceOutput));
  const fatal = spawnSync(process.execPath, [fileURLToPath(new URL('../src/index.js', import.meta.url)),
    '--config', `missing-\u001b[2J\u0007\u202e.json`], { cwd: target, encoding: 'utf8' });
  assert.equal(fatal.status, 3);
  for (const cp of ['001b', '0007', '202e']) assert(fatal.stderr.includes(`\\u${cp}`));
  assert(!/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(fatal.stderr.replaceAll('\n', '')));
  assert.equal(visibleTerminalText('\ud800x\udfff\u2028\u2029'), '\\ud800x\\udfff\\u2028\\u2029',
    'U+2028/2029 escape');
  for (const cp of ['2028', '2029']) {
    const linePath = `scoring-core/a${String.fromCharCode(parseInt(cp, 16))}b.rs`;
    const lineFiles = new Map(full); lineFiles.set(linePath, Buffer.from('x'));
    const lineResult = await runPackage(legacyBytes(asFiles(lineFiles)));
    assert.equal(lineResult.code, 2);
    assert.match(lineResult.output, /zk\.wireUnsafeSource/);
    assert(lineResult.output.includes(`\\u${cp}`), `門の理由は可視化 U+${cp}`);
    assert(!lineResult.output.includes(String.fromCharCode(parseInt(cp, 16))));
    assert(!lineResult.output.includes('docker run '));
    assert(!fs.existsSync(sourceOutput));
  }
  const guestCrates = new Set(WIRE_GUESTS.map((guest) => guest.crate));
  const disguised = [...baked].flatMap(([p, bytes]) => {
    const crate = p.split('/')[0];
    if (crate === 'final-wire-guest') return [{ path: `zkp-guest/${p.slice(crate.length + 1)}`, bytes }];
    return guestCrates.has(crate) ? [] : [{ path: p, bytes }];
  });
  for (const variant of [false, true]) {
    const entries = disguised.map((file) => ({ ...file }));
    if (variant) {
      const manifest = entries.find((file) => file.path === 'zkp-guest/Cargo.toml');
      manifest.bytes = Buffer.from(String(manifest.bytes).replace('[package]\n', '[package]\nbuild = "src/gen.rs"\n'));
      entries.push({ path: 'zkp-guest/src/gen.rs', bytes: Buffer.from('fn main() {}\n') });
    }
    const result = await runPackage(legacyBytes(entries));
    assert.equal(result.code, 2, `disguised ${variant}`);
    assert.match(result.output, /zk\.wireUnsafeSource/);
    assert(!result.output.includes('docker run '));
    assert(!fs.existsSync(sourceOutput));
  }
  for (const unsafe of ['final-wire-guest/.git/config', 'final-wire-guest/.envrc',
    'final-wire-guest/.vscode/settings.json', 'agg-wire-guest/src/BIN/level0.rs']) {
    const modified = new Map(full); modified.set(unsafe, Buffer.from('x'));
    const result = await runPackage(legacyBytes(asFiles(modified)));
    assert.equal(result.code, 2, unsafe);
    assert.match(result.output, /zk\.wireUnsafeSource/);
    assert(!result.output.includes('docker run '));
    assert(!fs.existsSync(sourceOutput));
  }
  const allowed = await runPackage(packed.bytes);
  assert.equal(allowed.code, 0);
  assert.equal((allowed.output.match(/docker run /g) || []).length, 0);
  assert(fs.existsSync(sourceOutput));
  const rerun = await runPackage(packed.bytes);
  assert.equal(rerun.code, 0);
  assert(fs.existsSync(sourceOutput + '-2'));
  assert(!rerun.output.includes('zk.wireUnsafeSource'));
  assert(fs.existsSync(sourceOutput));
  assert(fs.existsSync(`${sourceOutput}.stage4-root-guest.docker.env`));
  // A competing writer creates the destination after the first check and before the second.
  const raceDir = path.join(target, 'race'); fs.mkdirSync(raceDir);
  const raceOutput = path.join(fs.realpathSync(raceDir), path.basename(sourceOutput));
  const realLstat = fs.lstatSync;
  let outputChecks = 0;
  fs.lstatSync = (candidate, ...args) => {
    if (candidate === raceOutput && ++outputChecks === 2) {
      fs.mkdirSync(raceOutput);
      fs.writeFileSync(path.join(raceOutput, 'other-writer'), 'KEEP');
    }
    return realLstat(candidate, ...args);
  };
  let raceResult;
  try { raceResult = await runPackage(packed.bytes, raceDir); }
  finally { fs.lstatSync = realLstat; }
  assert.equal(outputChecks, 2);
  assert.equal(raceResult.code, 0);
  assert(fs.existsSync(raceOutput + '-2'), '競合した出力先も連番へ退避');
  assert(!raceResult.output.includes('docker run '));
  assert.deepEqual(fs.readdirSync(raceOutput), ['other-writer']);
  assert.equal(fs.readFileSync(path.join(raceOutput, 'other-writer'), 'utf8'), 'KEEP');
  for (const [name, token] of [['esc', '\u001b'], ['so', '\u000e']]) {
    const edgeFiles = new Map(baked);
    const edgeFile = 'agg-wire-guest/src/bin/level0.rs';
    edgeFiles.set(edgeFile, Buffer.from(String(edgeFiles.get(edgeFile)).replace(
      'const CHILD_VKEY_UNSET', `${token} const CHILD_VKEY_UNSET`)));
    const edgeDir = path.join(target, `edge-${name}`); fs.mkdirSync(edgeDir);
    const edgeResult = await runPackage(legacyBytes(asFiles(edgeFiles)), edgeDir, {}, {
      runVkey: async () => vkey,
    });
    const row = edgeResult.output.split('\n').find((line) => line.includes('L0') && line.includes('GROUP'));
    assert.equal(edgeResult.code, 2);
    assert.equal((edgeResult.output.match(/docker run /g) || []).length, 0);
    assert(row, `edge row ${name}`);
    assert(!row.includes('U+'), '内部の字句解析理由を出さない');
    assert(!row.includes(token), `raw token ${name}`);
  }
  const staleDir = path.join(target, 'stale-env'); fs.mkdirSync(staleDir);
  const staleName = `zkp-guest-source-${vkey.slice(2, 14)}.stage4-root-guest.docker.env`;
  const staleEnv = path.join(staleDir, staleName);
  fs.writeFileSync(staleEnv, 'OLD=1\n');
  const staleRun = await runPackage(packed.bytes, staleDir);
  assert.equal(staleRun.code, 0);
  assert.equal((staleRun.output.match(/docker run /g) || []).length, 0);
  assert(!fs.readFileSync(staleEnv, 'utf8').includes('OLD=1'));
  const symlinkDir = path.join(target, 'symlink-env'); fs.mkdirSync(symlinkDir);
  const symlinkTarget = path.join(symlinkDir, 'outside'); fs.writeFileSync(symlinkTarget, 'KEEP');
  fs.symlinkSync(symlinkTarget, path.join(symlinkDir, staleName));
  const symlinkRun = await runPackage(packed.bytes, symlinkDir);
  assert.equal(symlinkRun.code, 2);
  assert.match(symlinkRun.output, /zk\.wireUnsafeSource/);
  assert.match(symlinkRun.output, /zk\.sourceSaved/);
  assert(!symlinkRun.output.includes('docker run '));
  assert(fs.existsSync(path.join(symlinkDir, path.basename(sourceOutput), 'final-wire-guest/src/main.rs')),
    '準備に失敗してもStage1のソースを残す');
  assert.equal(fs.readFileSync(symlinkTarget, 'utf8'), 'KEEP');
  assert.deepEqual(fs.readdirSync(symlinkDir).sort(), [staleName, 'outside', path.basename(sourceOutput)].sort(),
    '準備で先に作ったenv-fileだけを消し、既存のsymlinkと保存した木を残す');
  const directoryEnvDir = path.join(target, 'directory-env'); fs.mkdirSync(directoryEnvDir);
  fs.mkdirSync(path.join(directoryEnvDir, staleName));
  const directoryEnvRun = await runPackage(packed.bytes, directoryEnvDir);
  assert.equal(directoryEnvRun.code, 2);
  assert.match(directoryEnvRun.output, /zk\.wireUnsafeSource/);
  assert.match(directoryEnvRun.output, /zk\.sourceSaved/);
  assert(!directoryEnvRun.output.includes('docker run '));
  assert(fs.existsSync(path.join(directoryEnvDir, path.basename(sourceOutput), 'final-wire-guest/src/main.rs')));
  assert.deepEqual(fs.readdirSync(directoryEnvDir).sort(), [staleName, path.basename(sourceOutput)].sort(),
    '準備で先に作ったenv-fileだけを消し、既存のディレクトリと保存した木を残す');
  const pinDir = path.join(target, 'pin-diff'); fs.mkdirSync(pinDir);
  const pinResult = await runPackage(packed.bytes, pinDir, { zkVkey: `0x${'ff'.repeat(32)}` });
  assert.equal(pinResult.code, 2);
  assert.match(pinResult.output, /zk\.pinDiff/);
  assert.equal((pinResult.output.match(/docker run /g) || []).length, 0);
} finally {
  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(canonicalRoot, { recursive: true, force: true });
}
}

// WR-REVIEW-BV: public pending proposal and local cargo-prove version.
{
const appliedPackage = packGuestSource();
const original = unpackGuestSource(appliedPackage.bytes);
const words = [0x46995ee0, 0x693e2d06, 0x744471e2, 0x1ee9a481,
  0x3146aeb1, 0x01469cbf, 0x43721db9, 0x163137e7];
const literal = `[${words.map((word) => `0x${word.toString(16)}u32`).join(', ')}]`;
const proposedVkey = vkDigestBytes32(words);
const baked = new Map(original.files.map((file) => [file.path, Buffer.from(file.bytes)]));
for (const edge of WIRE_VKEY_EDGES) {
  const old = String(baked.get(edge.file));
  baked.set(edge.file, Buffer.from(replaceWireInitializer(old, edge.name, literal)));
}

function packageBytes(files) {
  const inner = Buffer.concat([
    Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${original.sp1Image}\n`),
    ...[...files].flatMap(([file, bytes]) => [Buffer.from(`file\t${file}\t${bytes.length}\n`),
      bytes, Buffer.from('\n')]),
  ]);
  return compressGuestSourceV2(inner);
}

async function inspectProposal(proposalBytes, version, { scanUnavailable = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wr-review-bv-'));
  try {
    const chunks = splitGuestSource(proposalBytes).map((part) => `0x${part.toString('hex')}`);
    const hash = guestSourceChainHash(chunks);
    const appliedHash = appliedPackage.guestSourceHash;
    const requested = [];
    let derived = 0;
    let proposalRead = 0;
    let chosen = 0;
    const lines = [];
    const chain = {
      contracts: { tokenMining: `0x${'11'.repeat(20)}` },
      vkeyEpochs: async () => [{ index: 0, verifier: ZKP_EXPECTED.verifier, vkey: `0x${'11'.repeat(32)}`,
        guestSourceHash: appliedHash, activatedAt: 1 }],
      pendingVkeyProposal: async () => {
        proposalRead++;
        return { pending: true, vkey: proposedVkey, guestSourceHash: hash,
          verifier: ZKP_EXPECTED.verifier, proposedAt: 1, eta: Math.floor(Date.now() / 1000) + 14 * 86400 };
      },
      proofRequired: async () => true,
      blockStates: async () => {
        if (scanUnavailable) throw new Error('unrelated applied block state unavailable');
        return { root: `0x${'00'.repeat(32)}`, zkEpochPlusOne: 0 };
      },
      client: { readContract: async ({ functionName, args }) => {
        if (functionName === 'guestSourceOf') {
          requested.push(args[0]);
          assert.equal(args[0], hash);
          return [hash, chunks.length, chunks.length];
        }
        if (functionName === 'guestSourceBlocks') return BigInt(100 + Number(args[1]));
        throw new Error(`unexpected view: ${functionName}`);
      } },
      getLogsChunked: async ({ args, fromBlock }) => {
        assert.equal(args.guestSourceHash, hash);
        const i = Number(fromBlock) - 100;
        return [{ blockNumber: fromBlock, logIndex: 0,
          args: { guestSourceHash: hash, chunkIndex: i, totalChunks: chunks.length,
            data: chunks[i], runningHash: guestSourceChainHash(chunks.slice(0, i + 1)) } }];
      },
    };
    const code = await runZkpMode({ zkScanMaxBlock: 0, dataDir: root, zkVkey: `0x${'11'.repeat(32)}` }, chain,
      { println: (line) => lines.push(String(line)), warn: (line) => lines.push(String(line)), t: t('ja') },
      { isInteractive: true,
        choice: async (_, items, opts) => {
          assert.equal(items.length, 2);
          assert(items[1].includes('公示中の提案'));
          assert.equal(opts.defaultIndex, 0);
          chosen++;
          return 1;
        },
        yesNo: async () => true },
      { spawnProcess: fakeStage3Spawn(), readVersion: async () => version,
        runVkey: async () => { derived++; return proposedVkey; } });
    return { code, output: lines.join('\n'), derived, proposalRead, chosen, requested, hash };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

const honestBytes = packageBytes(baked);
const matching = 'cargo-prove sp1 (8252c29 2026-06-25T11:48:19Z)';
for (const lang of ['en', 'ja', 'zh']) {
  const translate = t(lang);
  const notice = translate('fact.system.pendingVkey', { vkey: proposedVkey,
    guestSourceHash: appliedPackage.guestSourceHash, eta: 'ETA', daysLeft: 14 });
  assert(notice.includes(appliedPackage.guestSourceHash), `${lang}: pending source in menu 1`);
  assert(notice.includes('12'), `${lang}: rebuild instructions in menu 1`);
  for (const state of ['pass', 'failed', 'unavailable', 'unperformed']) {
    assert.notEqual(translate(`zk.conclusionPending.${state}`), `zk.conclusionPending.${state}`);
  }
}
const honest = await inspectProposal(honestBytes, matching);
assert.equal(honest.code, 0);
assert.equal(honest.derived, 12);
assert.equal(honest.proposalRead, 1);
assert.equal(honest.chosen, 1);
assert.deepEqual(honest.requested, [honest.hash]);
assert.equal((honest.output.match(/docker run /g) || []).length, 0);
assert.equal((honest.output.match(/→.*: 一致（/g) || []).length, 12);
assert(honest.output.includes('公示中の提案: 未発効。子の11辺と提案の最上段vkeyはすべて'));
assert(!honest.output.includes('結論: ブロック'));
const incompleteAppliedScan = await inspectProposal(honestBytes, matching, { scanUnavailable: true });
assert.equal(incompleteAppliedScan.code, 0, 'pending source result is separate from applied block scan');
assert.match(incompleteAppliedScan.output, /公示中の提案: 未発効。子の11辺/);

const changed = new Map(baked);
const bind = 'bind-wire-guest/src/main.rs';
changed.set(bind, Buffer.from(String(changed.get(bind)).replace(
  `const BIND_CHILD_VKEY: [u32; 8] = ${literal};`,
  'const BIND_CHILD_VKEY: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];')));
const mismatched = await inspectProposal(packageBytes(changed), matching);
assert.equal(mismatched.code, 2);
assert.equal(mismatched.derived, 12);
assert.equal((mismatched.output.match(/→.*: 不一致（/g) || []).length, 1);
assert.match(mismatched.output, /BIND → BIND_CHILD: 不一致/);
assert.match(mismatched.output, /公示中の提案: 未発効。子の辺または提案の最上段vkeyに不一致/);

const wrongVersion = await inspectProposal(honestBytes, 'cargo-prove sp1 (deadbee 2026-01-01)');
assert.equal(wrongVersion.code, 0);
assert.equal(wrongVersion.derived, 0);
assert.equal((wrongVersion.output.match(/→.*: 未実施（/g) || []).length, 12);
assert(!wrongVersion.output.includes('→ BIND_CHILD: 不一致'));
assert(wrongVersion.output.includes(t('ja')('zk.stage3Failed')));
assert(!wrongVersion.output.includes('cargo-prove version mismatch'));
assert.match(wrongVersion.output, /公示中の提案: 未発効。子の鍵の照合は未実施/);
console.log('wr-review-bv-unit: pending pass, one changed edge, and version mismatch passed');

}

}

// WR-UI-VERIFIER-ZKP-STAGE3RUN-FIX3〜FIX5: Z1〜Z10 と保存・準備の失敗。実物の道具・RPC は使わない。
const stage3Examples = {};
const stage3Source = compressGuestSourceV2(Buffer.concat([
  Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`),
  ...[...files].flatMap(([p, bytes]) => [Buffer.from(`file\t${p}\t${Buffer.byteLength(bytes)}\n`),
    Buffer.from(bytes), Buffer.from('\n')]),
]));
// FIX3 §3: 実装から生成せず、ユーザー指定の3言語を全文で固定する。
const fix3Texts = {
  ja: [
    'オンチェーンに公開されている証明プログラムのソースコードを取得し、構成して/PATHに保存しました。',
    '結論: オンチェーンで公開されている証明プログラムのソースコードは、検証コントラクトで検証されている証明内容と一致していることが確認されました。このソースコードは/PATHに保存されています。',
  ],
  en: [
    'Fetched the proof program source code published on-chain, assembled it, and saved it to /PATH.',
    'Conclusion: It was confirmed that the proof program source code published on-chain matches what the verifier contract verifies. This source code is saved at /PATH.',
  ],
  zh: [
    '已获取链上公开的证明程序源代码，组装后保存到 /PATH。',
    '结论: 已确认链上公开的证明程序源代码与验证合约所验证的证明内容一致。该源代码保存在 /PATH。',
  ],
};
for (const [lang, texts] of Object.entries(fix3Texts)) {
  assert.deepEqual(['zk.sourceSaved', 'zk.conclusionSourceMatches'].map((key) => t(lang)(key, { path: '/PATH' })), texts);
}
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function until(test, label) {
  const deadline = Date.now() + 2000;
  while (!test()) { assert(Date.now() < deadline, label); await tick(); }
}
async function stage3Run({ answer = false, interactive = true, lang = 'ja', platform = 'darwin',
  existing = false, pending = false, noBlocks = false, shadowBlock = false, fake = {}, promptFixture, drive, retryAnswers = [],
  verifier = ZKP_EXPECTED.verifier, pendingVerifier = verifier, pinned = vkey,
  sourceBytes = stage3Source, spawnOverride, exitProcess = () => {}, dataPathSegment = '', sourceWriteFailure } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'stage3run-'));
  const dataDir = path.join(root, dataPathSegment);
  fs.mkdirSync(dataDir, { recursive: true });
  const source = path.join(dataDir, `zkp-guest-source-${vkey.slice(2, 14)}`);
  if (existing) { fs.mkdirSync(source); fs.writeFileSync(path.join(source, 'KEEP'), 'original'); }
  const chunks = splitGuestSource(sourceBytes).map((p) => `0x${p.toString('hex')}`);
  const hash = guestSourceChainHash(chunks);
  const events = [], calls = [], lines = [], raw = [], asked = [], renderedKeys = [], warnings = [];
  const sourceTempPrefix = path.join(fs.realpathSync(dataDir), '.zkp-guest-source-tmp-');
  const writeFailureReason = sourceWriteFailure === 'EACCES'
    ? `EACCES: permission denied, mkdtemp '${sourceTempPrefix}XXXXXX'`
    : sourceWriteFailure === 'O_NOFOLLOW' ? 'this platform cannot enforce O_NOFOLLOW' : undefined;
  const translate = t(lang);
  const output = (line) => { lines.push(String(line)); events.push(String(line));
    promptFixture?.output.write(String(line) + '\n'); };
  const chain = {
    contracts: { tokenMining: `0x${'11'.repeat(20)}` },
    vkeyEpochs: async () => pending && !interactive ? []
      : [{ index: 0, vkey, verifier, guestSourceHash: hash, activatedAt: 0 }],
    proofRequired: async () => !noBlocks,
    pendingVkeyProposal: async () => ({ pending, vkey, verifier: pendingVerifier, guestSourceHash: hash, eta: 0 }),
    blockStates: async () => ({ root: noBlocks && !shadowBlock ? `0x${'00'.repeat(32)}` : `0x${'22'.repeat(32)}`, zkEpochPlusOne: noBlocks ? 0 : 1 }),
    client: { readContract: async ({ functionName }) => {
      events.push('read-source');
      return functionName === 'guestSourceOf' ? [hash, chunks.length, chunks.length] : 500n;
    } },
    getLogsChunked: async () => chunks.map((data, i) => ({ blockNumber: 500n, logIndex: i,
      args: { guestSourceHash: hash, data, chunkIndex: i, totalChunks: chunks.length,
        runningHash: guestSourceChainHash(chunks.slice(0, i + 1)) } })),
  };
  let writes = 0, questions = 0, saveAttempts = 0;
  const rename = fs.renameSync, writeFile = fs.writeFileSync, stdout = process.stdout.write, stderr = process.stderr.write;
  const mkdtemp = fs.mkdtempSync, constants = stage3Fs.constants;
  if (sourceWriteFailure === 'O_NOFOLLOW') stage3Fs.constants = { ...constants, O_NOFOLLOW: undefined };
  fs.mkdtempSync = (prefix, ...args) => {
    if (prefix === sourceTempPrefix) {
      saveAttempts++; events.push('save-attempt');
      if (sourceWriteFailure === 'EACCES') throw Object.assign(new Error(writeFailureReason), { code: 'EACCES' });
    }
    return mkdtemp(prefix, ...args);
  };
  fs.renameSync = (...args) => { writes++; events.push('write-source'); return rename(...args); };
  fs.writeFileSync = (target, ...args) => {
    if (String(target).endsWith('.docker.env')) events.push('write-env');
    return writeFile(target, ...args);
  };
  process.stdout.write = process.stderr.write = (data) => { raw.push(String(data)); return true; };
  try {
    const operation = runZkpMode({ zkScanMaxBlock: 0, dataDir, zkVkey: pinned }, chain,
      { t: (key, args) => { renderedKeys.push(key); return translate(key, args); }, println: output, warn: (line) => { warnings.push(line); output(line); } },
      { isInteractive: interactive, choice: async () => 1, yesNo: async (message, options) => {
        questions++; events.push('confirm'); asked.push(message);
        assert.deepEqual(options, { defaultValue: null });
        if (promptFixture) return promptFixture.prompts.yesNo(message, options);
        const reply = questions === 1 ? answer : retryAnswers.shift() ?? false;
        output(`${message} [y/n] ${reply ? 'y' : 'n'}`);
        return reply;
      }, onInterrupt: promptFixture?.prompts.onInterrupt, close: promptFixture?.prompts.close },
      { platform, exitProcess, spawnProcess: spawnOverride
        ? spawnOverride({ calls, events }) : fakeStage3Spawn({ calls, events, ...fake }) });
    if (drive) await drive({ calls, events, get writes() { return writes; }, get questions() { return questions; } });
    const code = await operation;
    fs.writeFileSync = writeFile; // 以下の期待argvのformatter呼出しは実行中の準備に数えない。
    const screen = lines.join('\n') + raw.join('') + (promptFixture?.screen() || '');
    assert(!/docker run|INTERNAL_FAILURE|\/secret\/path|exited 7|exited 9|--env-file|--entrypoint/.test(screen), 'Z2: argv と内部エラーは両出力に出ない');
    assert(!screen.includes(translate('zk.stage3InstallHint')) || fake.dockerError?.code === 'ENOENT'
      || fake.versionError?.code === 'ENOENT' || (Object.hasOwn(fake, 'version') && fake.version !== matchingVersionText),
    '道具がそろえばインストール案内を出さない');
    if (existing) {
      assert(fs.existsSync(path.join(source, 'KEEP')), 'Z5: 既存フォルダを削除してはならない');
      assert.equal(fs.readFileSync(path.join(source, 'KEEP'), 'utf8'), 'original', 'Z5: 既存フォルダを消さない');
      assert.deepEqual(fs.readdirSync(source), ['KEEP'], 'Z5: 既存の中身を変えない');
    }
    const savedName = pending ? `zkp-pending-source-${vkey.slice(2, 14)}-${hash.slice(2, 14)}` : path.basename(source);
    const saved = path.join(fs.realpathSync(dataDir), savedName) + (existing ? '-2' : '');
    if (fs.existsSync(saved)) {
      assert.equal(writes, 1, 'Z5: 保存は1回だけ');
      const savedLine = translate('zk.sourceSaved', { path: saved });
      assert.equal(lines.filter((line) => line === savedLine).length, 1, 'Stage1: 新しい保存先つきの文を1回出す');
      const savedAt = events.indexOf(savedLine);
      assert(events.indexOf(translate('zk.sourceHashOk', { hash })) < events.indexOf('write-source'));
      assert(events.indexOf('write-source') < savedAt && savedAt < events.indexOf(translate('zk.stage2')),
        'Z1/Z5: Stage1 の整合確認の後、Stage2 より前に保存と文を出す');
      assert(!events.includes('confirm') || savedAt < events.indexOf('confirm'), 'Z1: 確認より前に保存する');
      assert(lines.includes(`  SP1 image: ${SP1_IMAGE}`));
    }
    if (calls.some((c) => c.args[0] === 'run')) {
      const expected = formatWireGuestRebuildCommands(saved, SP1_IMAGE, unpackGuestSource(sourceBytes).files);
      const actual = calls.filter((c) => c.args[0] === 'run');
      actual.forEach((c) => {
        assert.deepEqual([c.command, ...c.args], expected.find((e) => e.argv.join('\0') === [c.command, ...c.args].join('\0'))?.argv, 'Z5: formatter と同じ argv');
        assert.equal(c.options.shell, false, 'Z5: shell は false');
        assert.deepEqual(c.options.stdio, ['ignore', 'pipe', 'pipe']);
      });
    }
    calls.forEach((c) => {
      assert.equal(c.options.shell, false);
      if (c.command === 'docker') assert.deepEqual(c.options.stdio, ['ignore', 'pipe', 'pipe'],
        '道具の確かめも画面へ継承しない');
    });
    return { code, screen, lines, events, calls, writes, questions, asked, saved, hash,
      saveAttempts, writeFailureReason, renderedKeys, warnings,
      entries: fs.readdirSync(dataDir), savedBytes: fs.existsSync(path.join(saved, 'final-wire-guest/src/main.rs'))
        ? fs.readFileSync(path.join(saved, 'final-wire-guest/src/main.rs')) : null };
  } finally {
    fs.mkdtempSync = mkdtemp; stage3Fs.constants = constants;
    fs.renameSync = rename; fs.writeFileSync = writeFile; process.stdout.write = stdout; process.stderr.write = stderr;
    fs.rmSync(root, { recursive: true, force: true });
  }
}
// SUMMARY-ZKP-FIX1: verifier照合はStage2で行い、Stage3の確認・処理を維持する。
const verifierExamples = {};
for (const lang of ['ja', 'en', 'zh']) {
  const verifier = getAddress(ZKP_EXPECTED.verifier);
  const r = await stage3Run({ lang, verifier });
  const okLine = t(lang)('zk.verifierOk', { verifier });
  assert(r.lines.includes(okLine), `${lang}: 本物のチェックサム表記は一致`);
  assert(r.lines.indexOf(t(lang)('zk.pinOk', { vkey })) < r.lines.indexOf(okLine));
  assert(r.lines.indexOf(okLine) < r.lines.indexOf(t(lang)('zk.stage3')));
  assert(!r.warnings.includes(okLine), '一致はprintln');
  assert.equal(r.code, 0, '本物のverifierなら従来の終了コード');
}
const otherVerifier = `0x${'33'.repeat(20)}`;
for (const pending of [false, true]) for (const state of [
  { name: 'yes', answer: true }, { name: 'no', answer: false },
  { name: 'noninteractive', interactive: false },
  { name: 'toolsMissing', answer: true, fake: { dockerError: Object.assign(new Error('missing'), { code: 'ENOENT' }) } },
  { name: 'notVerified', answer: true, fake: { failBuild: 1 } },
  { name: 'wireFailed', answer: true, fake: { key: () => vkDigestBytes32(other) } },
  { name: 'shadow', noBlocks: true, shadowBlock: true },
  { name: 'pinMismatch', pinned: `0x${'44'.repeat(32)}` },
]) {
  const r = await stage3Run({ ...state, pending,
    verifier: pending ? ZKP_EXPECTED.verifier : otherVerifier, pendingVerifier: otherVerifier });
  const diffLine = t('ja')('zk.verifierDiff', { onchain: otherVerifier, expected: ZKP_EXPECTED.verifier });
  assert(r.warnings.includes(diffLine), `FIX1: 不一致はwarnで指定の全文/${pending}/${state.name}`);
  assert(r.lines.indexOf(t('ja')('zk.stage2')) < r.lines.indexOf(diffLine));
  assert(r.lines.indexOf(diffLine) < r.lines.indexOf(t('ja')('zk.stage3')), 'FIX1: Stage2で警告');
  assert.equal(r.questions, state.interactive === false ? 0 : state.name === 'notVerified' ? 2 : 1,
    'FIX1: 不一致でもStage3の確認と再試行の確認を維持');
  if (state.answer && !state.fake) assert(r.calls.some((call) => call.args[0] === 'run'), 'FIX1: はいなら再現処理へ進む（模擬）');
  const key = pending ? 'zk.conclusionPendingVerifierMismatch' : 'zk.conclusionVerifierMismatch';
  assert.deepEqual(r.renderedKeys.filter((item) => item.startsWith('zk.conclusion') || item === 'zk.stage3NotVerified'), [key],
    'FIX1: verifier不一致の結論だけを優先');
  assert(r.lines.includes(t('ja')(key)), 'FIX1: 指定の結論の全文');
  assert.equal(r.code, 2, `FIX1: verifier不一致/${pending}/${state.name}は終了コード2`);
  if (state.name === 'no') verifierExamples[pending ? 'pending' : 'applied'] = r.lines;
}
// 公示中に正常なverifierを選んだとき、適用済みの別verifierを比較しない。
{
  const r = await stage3Run({ pending: true, verifier: otherVerifier, pendingVerifier: ZKP_EXPECTED.verifier });
  assert(r.renderedKeys.includes('zk.verifierOk'));
  assert(r.renderedKeys.includes('zk.conclusionPending.unperformed'));
  assert.equal(r.code, 0);
}
console.log('SUMMARY-ZKP-FIX1 verifier: applied/pending, yes/no/noninteractive, priority, checksum, exit: PASS');
assert.equal(t('zh')('zk.conclusionPendingVerifierMismatch'),
  '公示中的提案：尚未生效。提案的验证合约不是 Succinct 的 SP1 Groth16 verifier v6.1.0。请在生效前调查。',
  'FIX2 G5: zh の公示中の見出しと全文');
if (process.argv.includes('--stage3-examples')) console.log('VERIFIER_EXAMPLES ' + JSON.stringify(verifierExamples));
function unperformed(result, label) {
  assert.equal(result.code, 0, label);
  assert.equal(result.lines.filter((line) => line.includes(': 未実施（')).length, 12, label);
  assert(result.screen.includes(t('ja')('zk.wireUnperformed')), label);
  assert(result.screen.includes(t('ja')('zk.conclusionWire.unperformed', { range: '0' })), label);
  assert(!result.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: result.saved })), label);
}
for (const lang of ['ja', 'en', 'zh']) {
  const r = await stage3Run({ lang });
  const tr = t(lang);
  const headings = ['zk.stage1', 'zk.stage2', 'zk.stage3'].map((key) => r.lines.indexOf(tr(key)));
  assert(headings[0] < headings[1] && headings[1] < headings[2], `${lang}: Stage1 → Stage2 → Stage3 の順`);
  for (const [stage, next] of [['zk.stage1', tr('zk.fetching')], ['zk.stage2', tr('zk.pinOk', { vkey })],
    ['zk.stage3', `${tr('zk.stage3Confirm')} [y/n] n`]]) {
    const i = r.lines.indexOf(tr(stage));
    assert(i >= 1 && r.lines[i - 1] === '', `${lang}: 各見出しの前に空行1つ`);
    assert(i < r.lines.indexOf(next), `${lang}: Z6 段の処理より前の見出し`);
  }
  assert(r.events.indexOf(tr('zk.stage1')) < r.events.indexOf('read-source'), `${lang}: Stage1 は読みの前`);
  assert.equal(r.calls.length, 0, 'Z1: いいえでは起動0');
  assert(!r.events.includes('write-env'), 'FIX4: いいえでは組み直し準備をしない');
  assert(!r.entries.some((name) => name.endsWith('.docker.env')));
  assert.equal(r.writes, 1, 'Z1: いいえでもStage1で書き出し1回');
  assert(r.entries.includes(path.basename(r.saved)));
  if (lang === 'ja') { unperformed(r, 'いいえ'); stage3Examples.no = r.screen; }
}
const nonInteractive = await stage3Run({ interactive: false, answer: true });
assert.equal(nonInteractive.questions, 0); assert.equal(nonInteractive.calls.length, 0);
assert.equal(nonInteractive.writes, 1); unperformed(nonInteractive, '非対話');
assert(!nonInteractive.events.includes('write-env'), 'FIX4: 非対話では組み直し準備をしない');
assert(!nonInteractive.entries.some((name) => name.endsWith('.docker.env')));
const passed = await stage3Run({ answer: true });
assert.equal(passed.code, 0);
assert.equal(passed.writes, 1);
assert.equal(passed.calls.length, 26, 'Docker版1・cargo版1・build12・鍵12');
assert.deepEqual(passed.calls[0].args, ['version', '--format', '{{.Server.Version}}']);
assert.deepEqual(passed.calls[1].args, ['prove', '--version']);
assert(passed.events.indexOf('confirm') < passed.events.indexOf('docker-version'));
assert(passed.events.indexOf('write-source') < passed.events.indexOf('confirm'));
assert(passed.events.indexOf('write-source') < passed.events.indexOf('build-1'));
assert(passed.events.indexOf('prove-version') < passed.events.indexOf('write-env'), 'FIX4: 道具の確認後に準備');
assert(passed.events.indexOf('write-env') < passed.events.indexOf('spawn-build-1'));
assert(passed.events.indexOf('build-12') < passed.events.indexOf('vkey-1'));
assert.deepEqual(passed.lines.filter((line) => line.startsWith('実行中...')),
  Array.from({ length: 24 }, (_, i) => `実行中...（${i + 1}/24）`));
assert.equal(passed.lines.filter((line) => line.includes(': 一致（')).length, 12);
assert(passed.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: passed.saved })));
assert(passed.savedBytes.equals(Buffer.from(files.get('final-wire-guest/src/main.rs'))), 'Z5: Stage1のソースをbyte-exactで書く');
stage3Examples.yes = passed.screen;
// Z9: 適用済みのpassだけ新しい結論。確定ブロックが無くても同じ文になる。
for (const lang of ['ja', 'en', 'zh']) for (const state of [{}, { noBlocks: true }, { noBlocks: true, shadowBlock: true }]) {
  const r = await stage3Run({ answer: true, lang, ...state });
  const tr = t(lang);
  assert.equal(r.code, 0);
  assert.equal(r.lines.filter((line) => line === tr('zk.conclusionSourceMatches', { path: r.saved })).length, 1,
    'Z9: 保存先と一致するpassの結論を1回出す');
  assert(r.lines.includes(tr('zk.sourceSaved', { path: r.saved })));
  assert(!r.screen.includes(tr('zk.conclusionShadow', { range: state.shadowBlock ? '0' : '-' })));
}
for (const answer of [false, true]) {
  const r = await stage3Run({ answer, pending: true });
  assert.equal(r.code, 0);
  assert.equal(r.writes, 1, '公示中の提案もStage1で保存');
  assert(r.screen.includes(t('ja')(`zk.conclusionPending.${answer ? 'pass' : 'unperformed'}`)));
  assert(!r.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: r.saved })), 'Z9: 公示中の提案には新しい結論を出さない');
}
const shadowUnperformed = await stage3Run({ noBlocks: true, shadowBlock: true });
assert(shadowUnperformed.screen.includes(t('ja')('zk.conclusionShadow', { range: '0' })));
assert(shadowUnperformed.screen.includes(t('ja')('zk.conclusionWire.unperformed', { range: '-' })));
assert(!shadowUnperformed.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: shadowUnperformed.saved })));
console.log('FIX3: exact ja/en/zh texts; Stage1 save once for yes/no/noninteractive; applied/no-block pass path; pending + non-pass unchanged: PASS');

// FIX4 L-3: Dockerのマウントで曖昧になる保存先も、ソースの保存と確認までは通る。
for (const delimiter of [':', ',']) {
  const dataPathSegment = `data${delimiter}source`;
  const sourceKept = (r) => {
    assert.equal(r.writes, 1, 'L-3: Stage1の保存は1回');
    assert(r.entries.includes(path.basename(r.saved)), 'L-3: Stage1の木を残す');
    assert(r.savedBytes?.equals(Buffer.from(files.get('final-wire-guest/src/main.rs'))), 'L-3: ソースの内容も保つ');
    assert(!r.entries.some((name) => name.endsWith('.docker.env')), 'L-3: env-fileを残さない');
  };
  for (const mode of [{ answer: false }, { interactive: false, answer: true }]) {
    const r = await stage3Run({ dataPathSegment, ...mode });
    unperformed(r, `L-3 ${delimiter}: いいえ・非対話`);
    assert.equal(r.questions, mode.interactive === false ? 0 : 1, 'L-3: いいえは質問まで到達する');
    assert.equal(r.calls.length, 0);
    assert(!r.events.includes('write-env'));
    assert(!r.screen.includes('source output path cannot be mounted unambiguously'));
    sourceKept(r);
    if (delimiter === ':' && mode.answer === false) stage3Examples.colonNo = r.screen;
  }
  const r = await stage3Run({ dataPathSegment, answer: true });
  const unsafe = t('ja')('zk.wireUnsafeSource', { reason: 'source output path cannot be mounted unambiguously' });
  assert.equal(r.code, 2, 'L-3: 準備の失敗は終了コード2');
  assert.equal(r.questions, 1);
  assert.deepEqual(r.calls.map((c) => [c.command, ...c.args]), [
    ['docker', 'version', '--format', '{{.Server.Version}}'], ['cargo-prove', 'prove', '--version'],
  ], 'L-3: 両方の道具の確かめだけを行い、組み直し・算出は始めない');
  assert(r.events.indexOf('confirm') < r.events.indexOf('docker-version'));
  assert(r.events.indexOf('docker-version') < r.events.indexOf('prove-version'));
  assert(r.events.indexOf('prove-version') < r.events.indexOf(unsafe), 'L-3: 道具の確かめが通った後に準備で失敗');
  assert.equal(r.lines.at(-1), unsafe, 'L-3: 従来の照合不能の文で止まる');
  assert(!r.screen.includes(t('ja')('zk.stage3Failed')));
  assert(!r.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: r.saved })));
  sourceKept(r);
  if (delimiter === ':') stage3Examples.colonYes = r.screen;
  for (const fake of [{ dockerExit: 1 }, { version: 'wrong version' }]) {
    const unavailable = await stage3Run({ dataPathSegment, answer: true, fake });
    unperformed(unavailable, `L-3 ${delimiter}: 道具の確認失敗では準備しない`);
    assert.equal(unavailable.calls.length, 2);
    assert(unavailable.screen.includes(t('ja')('zk.stage3Failed')));
    assert(!unavailable.screen.includes('source output path cannot be mounted unambiguously'));
    assert(!unavailable.events.includes('write-env'));
    sourceKept(unavailable);
  }
}
console.log('FIX4 L-3: colon/comma no + noninteractive = 0; yes after tool checks = 2; source kept + no env-files; ordinary path unchanged: PASS');

// FIX5: 門を通った後の保存失敗は、確認前の拒否にしない。
for (const sourceWriteFailure of ['EACCES', 'O_NOFOLLOW']) {
  const options = { sourceWriteFailure, platform: sourceWriteFailure === 'O_NOFOLLOW' ? 'win32' : 'darwin' };
  const notSaved = (r) => {
    assert.equal(r.saveAttempts, 1, 'FIX5: Stage1で保存を1回試みる');
    assert.equal(r.writes, 0, 'FIX5: 最終出力先は作られない');
    assert.deepEqual(r.entries, [], 'FIX5: ソースも一時木もenv-fileも残らない');
    assert(!r.renderedKeys.includes('zk.sourceSaved'), 'FIX5: 保存失敗で保存の文を出さない');
    assert(!r.renderedKeys.includes('zk.conclusionSourceMatches'), 'FIX5: 保存失敗をpassにしない');
    assert(!r.events.includes('write-env'), 'FIX5: 保存失敗では組み直し準備をしない');
    assert(!r.calls.some((c) => c.args[0] === 'run' || c.args[1] === 'vkey'), 'FIX5: 組み直し・鍵の算出は起動0');
    assert(r.events.indexOf(t('ja')('zk.sourceHashOk', { hash: r.hash })) < r.events.indexOf('save-attempt'));
    assert(r.events.indexOf('save-attempt') < r.events.indexOf(t('ja')('zk.stage2')));
    assert(r.lines.indexOf(t('ja')('zk.pinOk', { vkey })) < r.lines.indexOf(t('ja')('zk.stage3')),
      'FIX5: 保存失敗でもStage2を出してStage3へ進む');
  };
  for (const mode of [{ answer: false }, { interactive: false, answer: true }]) {
    const r = await stage3Run({ ...options, ...mode });
    unperformed(r, `FIX5 ${sourceWriteFailure}: いいえ・非対話`);
    assert.equal(r.questions, mode.interactive === false ? 0 : 1, 'FIX5: いいえは質問まで到達する');
    assert.equal(r.calls.length, 0, 'FIX5: いいえ・非対話はspawn 0');
    assert(!r.renderedKeys.includes('zk.wireUnsafeSource'), 'FIX5: いいえ・非対話では保存エラーを表示しない');
    assert(!r.screen.includes(r.writeFailureReason));
    notSaved(r);
    if (sourceWriteFailure === 'EACCES' && mode.answer === false) stage3Examples.writeNo = r.screen;
  }
  const r = await stage3Run({ ...options, answer: true });
  const unsafe = t('ja')('zk.wireUnsafeSource', { reason: r.writeFailureReason });
  assert.equal(r.code, 2, 'FIX5: はいの保存失敗は準備失敗と同じ2');
  assert.equal(r.questions, 1);
  assert.deepEqual(r.calls.map((c) => [c.command, ...c.args]), [
    ['docker', 'version', '--format', '{{.Server.Version}}'], ['cargo-prove', 'prove', '--version'],
  ], 'FIX5: 両方の道具の確認だけを行う');
  assert(r.events.indexOf('confirm') < r.events.indexOf('docker-version'));
  assert(r.events.indexOf('docker-version') < r.events.indexOf('prove-version'));
  assert(r.events.indexOf('prove-version') < r.events.indexOf(unsafe), 'FIX5: 道具の確認後に保存失敗の理由を出す');
  assert.equal(r.lines.at(-1), unsafe, 'FIX5: 元の理由と既存の文で止まる');
  assert(!r.renderedKeys.includes('zk.stage3Failed'));
  notSaved(r);
  if (sourceWriteFailure === 'EACCES') stage3Examples.writeYes = r.screen;
  for (const fake of [{ dockerExit: 1 }, { version: 'wrong version' }]) {
    const unavailable = await stage3Run({ ...options, answer: true, fake });
    unperformed(unavailable, `FIX5 ${sourceWriteFailure}: 道具の確認失敗`);
    assert.equal(unavailable.questions, 1); assert.equal(unavailable.calls.length, 2);
    assert(unavailable.renderedKeys.includes('zk.stage3Failed'));
    assert(!unavailable.renderedKeys.includes('zk.wireUnsafeSource'), 'FIX5: 道具の確認失敗を先に扱う');
    notSaved(unavailable);
  }
}
console.log('FIX5: EACCES + no O_NOFOLLOW; no/noninteractive = unperformed 0, no saved text/spawn; yes after tools = unsafe 2, no rebuild; tool failure unchanged: PASS');

const duplicate = await stage3Run({ answer: true, existing: true });
assert.equal(duplicate.code, 0);
assert(duplicate.entries.includes(`zkp-guest-source-${vkey.slice(2, 14)}-2`));
const missing = () => Object.assign(new Error('INTERNAL_FAILURE docker run /secret/path'), { code: 'ENOENT' });
const sp1Install = ['curl -fsSL https://sp1up.succinct.xyz | bash', '~/.sp1/bin/sp1up -v 6.3.1'];
const dockerInstalls = { darwin: 'brew install --cask docker', linux: 'curl -fsSL https://get.docker.com | sh' };
for (const platform of ['darwin', 'linux', 'win32', 'freebsd']) {
  const r = await stage3Run({ answer: true, platform, fake: { dockerError: missing() } });
  unperformed(r, `Dockerなし ${platform}`);
  assert.equal(r.writes, 1); assert.equal(r.calls.length, 2);
  const install = dockerInstalls[platform];
  for (const command of [...Object.values(dockerInstalls), ...sp1Install]) assert.equal(r.lines.includes(command), command === install);
  assert.equal(r.lines.includes(t('ja')('zk.stage3InstallHint')), Boolean(install));
  if (platform === 'darwin') stage3Examples.missing = r.screen;
}
for (const fake of [{ versionError: missing() }, { version: 'cargo-prove sp1 (deadbee 2026-01-01)' },
  { version: '' }, { version: 'cargo-prove sp1 6.3.2 (8252c29)' },
  { dockerError: missing(), versionError: missing() }]) {
  const r = await stage3Run({ answer: true, fake });
  unperformed(r, 'cargoなし/版違い/両方なし');
  assert.equal(r.writes, 1); assert.equal(r.calls.length, 2);
  const hintIndex = r.lines.indexOf(t('ja')('zk.stage3InstallHint'));
  assert.deepEqual(r.lines.slice(hintIndex + 1, hintIndex + 1 + sp1Install.length + (fake.dockerError ? 1 : 0)),
    [...(fake.dockerError ? [dockerInstalls.darwin] : []), ...sp1Install]);
}
for (const fake of [{ dockerError: new Error('INTERNAL_FAILURE /secret/path') },
  { versionError: new Error('INTERNAL_FAILURE exited 9') }, { dockerExit: 1 }, { versionExit: 1 }]) {
  const r = await stage3Run({ answer: true, fake });
  unperformed(r, '処理失敗');
  assert(r.screen.includes(t('ja')('zk.stage3Failed')));
  assert(!r.screen.includes(t('ja')('zk.stage3InstallHint')));
  assert(!sp1Install.some((line) => r.screen.includes(line)));
  assert.equal(r.writes, 1);
}
const mismatch = await stage3Run({ answer: true, fake: { key: (g) => g.id === 'FINAL' ? vkDigestBytes32(other) : vkey } });
assert.equal(mismatch.code, 2);
assert.equal(mismatch.lines.filter((line) => line.startsWith('実行中...')).length, 24);
assert(mismatch.screen.includes('CHAIN → FINAL: 不一致'));
assert(mismatch.screen.includes(t('ja')('zk.conclusionWire.failed', { range: '0' })));
assert(!mismatch.screen.includes(t('ja')('zk.stage3Failed')));

// FIX1 R-1: 展開・名前・Cargo の門は回答予定の値や非対話に依存しない。
function sourcePackage(entries) {
  return compressGuestSourceV2(Buffer.concat([
    Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`),
    ...[...entries].flatMap(([p, bytes]) => [Buffer.from(`file\t${p}\t${Buffer.byteLength(bytes)}\n`),
      Buffer.from(bytes), Buffer.from('\n')]),
  ]));
}
const cargoBad = new Map(files);
cargoBad.set('final-wire-guest/Cargo.toml', Buffer.concat([cargoBad.get('final-wire-guest/Cargo.toml'), Buffer.from('\n# changed\n')]));
const nameBad = new Map(files); nameBad.set('final-wire-guest/.git/config', Buffer.from('x'));
const legacyOnly = new Map([['zkp-guest/src/main.rs', Buffer.from('fn main() {}')]]);
for (const bytes of [sourcePackage(cargoBad), sourcePackage(nameBad), sourcePackage(legacyOnly),
  compressGuestSourceV2(Buffer.from('malformed'))]) {
  for (const mode of [{ answer: false }, { answer: true }, { interactive: false }]) {
    const r = await stage3Run({ ...mode, sourceBytes: bytes });
    assert.equal(r.code, 2, 'R-1: 門に落ちたら2');
    assert.equal(r.questions, 0, 'R-1: 確認の前に止める');
    assert.equal(r.saveAttempts, 0, 'FIX5: 門の失敗では保存を試みない');
    assert.equal(r.writes, 0); assert.equal(r.calls.length, 0); assert.deepEqual(r.entries, []);
    assert(r.screen.includes('照合不能（'));
    assert(!r.screen.includes(t('ja')('zk.stage3Failed')));
    const stage2 = r.lines.indexOf(t('ja')('zk.stage2'));
    const stage3 = r.lines.indexOf(t('ja')('zk.stage3'));
    assert(stage2 >= 0 && stage2 < r.lines.indexOf(t('ja')('zk.pinOk', { vkey })));
    assert(r.lines.indexOf(t('ja')('zk.pinOk', { vkey })) < stage3, 'Z10: 門に落ちてもStage2を出す');
    let reason;
    try { const unpacked = unpackGuestSource(bytes); checkWireBuildInputs(unpacked.files); }
    catch (error) { reason = visibleTerminalText(error.message || String(error)); }
    assert(reason);
    assert.equal(r.lines[stage3 + 1], t('ja')('zk.wireUnsafeSource', { reason }), 'Z10: Stage3見出し直後に従来と同じ引数と文');
    assert(!r.screen.includes(t('ja')('zk.sourceSaved', { path: r.saved })));
    assert(!r.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: r.saved })));

    stage3Examples.gate ??= r.screen;
  }
}
// 各 running は非同期の完了より前だけでなく、spawn の呼出より前。
for (let n = 1; n <= 12; n++) {
  for (const [kind, done] of [['build', n], ['vkey', n + 12]]) {
    const event = passed.events.indexOf(`spawn-${kind}-${n}`);
    assert.equal(passed.events[event - 1], `実行中...（${done}/24）`, 'R-5: 起動の前に進捗');
  }
}
const failingTwo = { failBuild: 4, failVkey: 2 }; // EVIDENCE_SEGMENT と NODE。
const declined = await stage3Run({ answer: true, fake: failingTwo });
assert.equal(declined.code, 2);
assert.equal(declined.questions, 2);
assert(declined.asked[1].includes('この2個'));
assert.equal(declined.calls.filter((c) => c.args[0] === 'run').length, 12, 'R-2: build失敗後も全部試す');
assert.equal(declined.calls.filter((c) => c.args[1] === 'vkey').length, 11, 'R-2: 失敗したbuildの算出だけ飛ばす');
assert(declined.screen.includes('検証できませんでした。'));
assert(!declined.screen.includes(t('ja')('zk.stage3Failed')));
assert(!declined.screen.includes(t('ja')('zk.wireUnperformed')));
assert(!declined.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: declined.saved })));
for (const edge of WIRE_VKEY_EDGES) {
  if (['NODE', 'EVIDENCE_SEGMENT'].includes(edge.parent) || ['NODE', 'EVIDENCE_SEGMENT'].includes(edge.child)) {
    assert(declined.lines.includes(`  ${edge.parent} → ${edge.child}: 照合不能（-）`));
  }
}
assert.equal(declined.lines.filter((l) => l.startsWith('実行中...')).length, 23);
stage3Examples.declined = declined.screen;
const retried = await stage3Run({ answer: true, fake: failingTwo, retryAnswers: [true] });
assert.equal(retried.code, 0); assert.equal(retried.questions, 2);
assert(retried.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: retried.saved })));
const rebuilds = retried.calls.filter((c) => c.args[0] === 'run');
assert.equal(rebuilds.length, 14, 'Z7: 失敗した2本だけリトライ');
assert.deepEqual(rebuilds.slice(12).map((c) => c.args[c.args.indexOf('-w') + 1]),
  ['/root/program/stage4-node-guest', '/root/program/evidence-segment-wire-guest']);
assert.deepEqual(retried.lines.filter((l) => /実行中.*\/4）/.test(l)),
  ['実行中...（1/4）', '実行中...（2/4）', '実行中...（3/4）', '実行中...（4/4）']);
stage3Examples.retried = retried.screen;
// 算出だけの失敗・ELFの欠けも全体を捨てず、次の試行は組み直しから。
for (const fake of [{ failVkey: [1, 12] }, { omitElf: (n) => n === 1 || n === 12 },
  { failBuild: [1, 12] }]) {
  const r = await stage3Run({ answer: true, fake, retryAnswers: [true] });
  assert.equal(r.code, 0); assert(r.asked[1].includes('この2個'));
  assert.equal(r.calls.filter((c) => c.args[0] === 'run').length, 14);
}
const persistent = await stage3Run({ answer: true, fake: { failBuild: (_n, g) => g.id === 'GROUP' },
  retryAnswers: [true, true, false] });
assert.equal(persistent.code, 2); assert.equal(persistent.questions, 4);
assert.equal(persistent.calls.filter((c) => c.args[0] === 'run').length, 14);
assert(persistent.screen.includes('検証できませんでした。'));
const shrinking = await stage3Run({ answer: true, retryAnswers: [true, true],
  fake: { failBuild: (n, g) => (n <= 12 && ['NODE', 'EVIDENCE_SEGMENT'].includes(g.id)) || n === 14 } });
assert.equal(shrinking.code, 0); assert.equal(shrinking.questions, 3);
assert(shrinking.asked[1].includes('この2個')); assert(shrinking.asked[2].includes('この1個'));
assert.deepEqual(shrinking.calls.filter((c) => c.args[0] === 'run').slice(12)
  .map((c) => c.args[c.args.indexOf('-w') + 1]),
['/root/program/stage4-node-guest', '/root/program/evidence-segment-wire-guest', '/root/program/evidence-segment-wire-guest']);
const allBuildsFailed = await stage3Run({ answer: true, fake: { failBuild: () => true } });
assert.equal(allBuildsFailed.code, 2); assert(allBuildsFailed.asked[1].includes('この12個'));
assert.equal(allBuildsFailed.calls.filter((c) => c.args[0] === 'run').length, 12);
assert.equal(allBuildsFailed.calls.filter((c) => c.args[1] === 'vkey').length, 0);
assert.equal(allBuildsFailed.lines.filter((l) => l.startsWith('実行中...')).length, 12);
const mixed = await stage3Run({ answer: true, fake: { ...failingTwo,
  key: (g) => g.id === 'FINAL' ? vkDigestBytes32(other) : vkey } });
assert.equal(mixed.code, 2); assert.equal(mixed.questions, 1, 'R-2: 不一致ならリトライを聞かない');
assert(mixed.screen.includes('CHAIN → FINAL: 不一致'));
assert(mixed.screen.includes('ROOT → NODE: 照合不能（-）'));
assert(mixed.screen.includes(t('ja')('zk.conclusionWire.failed', { range: '0' })));
assert(!mixed.screen.includes('検証できませんでした。'));
assert.equal(mixed.calls.filter((c) => c.args[0] === 'run').length, 12);
assert.equal(mixed.calls.filter((c) => c.args[1] === 'vkey').length, 11);
stage3Examples.mixed = mixed.screen;
// 親の鍵が算出不能で、子の鍵が一致なら、その親から出る辺も照合不能。
const parentFailed = await stage3Run({ answer: true, fake: { failVkey: 3 } });
for (const child of ['CHUNK', 'NODE']) assert(parentFailed.screen.includes(`ROOT → ${child}: 照合不能（-）`));
// FIX2 A: 親の組み直し／算出失敗でも、ソースの定数と子の鍵の不一致は確定できる。
for (const [parent, child] of [['ROOT', 'CHUNK'], ['L2', 'L1']]) {
  for (const failure of ['failBuild', 'failVkey']) {
    const r = await stage3Run({ answer: true, fake: {
      [failure]: (_n, g) => g.id === parent,
      key: (g) => g.id === child ? vkDigestBytes32(other) : vkey,
    } });
    assert.equal(r.code, 2, 'A: 親が失敗しても不一致は2');
    assert.equal(r.questions, 1, 'A: 不一致があればリトライを聞かない');
    assert(r.screen.includes(`${parent} → ${child}: 不一致`), 'A: 計算できた不一致を保持する');
    assert.equal(r.lines.filter((line) => line.includes(': 不一致（')).length, 1);
    assert(r.screen.includes(t('ja')('zk.conclusionWire.failed', { range: '0' })));
    assert(!r.screen.includes('検証できませんでした。'));
    assert(!r.screen.includes('PCの不調'));
    assert.equal(r.calls.filter((c) => c.args[0] === 'run').length, 12);
    const incoming = WIRE_VKEY_EDGES.find((edge) => edge.child === parent);
    assert(r.screen.includes(`${incoming.parent} → ${parent}: 照合不能（-）`),
      'A: 失敗した親も別の辺では子なので、その辺は照合不能');
  }
}
// 12部品を1つずつ失敗させても、必ずその部品が子である辺が照合不能で、pass にならない。
for (const guest of WIRE_GUESTS) for (const failure of ['failBuild', 'failVkey']) {
  const r = await stage3Run({ answer: true, fake: { [failure]: (_n, g) => g.id === guest.id } });
  const incoming = [...WIRE_VKEY_EDGES, { parent: 'CHAIN', child: 'FINAL' }]
    .find((edge) => edge.child === guest.id);
  assert(incoming, `${guest.id}: 12部品はすべてどこかの辺の子`);
  assert.equal(r.code, 2, `${guest.id}: 子の失敗をpassにしない`);
  assert.equal(r.questions, 2);
  assert(r.lines.includes(`  ${incoming.parent} → ${guest.id}: 照合不能（-）`));
  assert(r.screen.includes('検証できませんでした。'));
  assert(!r.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: r.saved })));
}
console.log('FIX2 A: parent failure preserves ROOT/CHUNK + L2/L1 mismatches; all 12 failed children unavailable: PASS');
// 算出が全部成功しても、定数を読めない辺が残れば pass にしない。
const unreadable = new Map(files);
unreadable.set('agg-wire-guest/src/bin/level0.rs', Buffer.concat([
  Buffer.from('\x1b'), Buffer.from(unreadable.get('agg-wire-guest/src/bin/level0.rs'))]));
const unavailableEdge = await stage3Run({ answer: true, sourceBytes: sourcePackage(unreadable) });
assert.equal(unavailableEdge.code, 2); assert.equal(unavailableEdge.questions, 1);
assert(unavailableEdge.screen.includes('L0 → GROUP: 照合不能（-）'));
assert(unavailableEdge.screen.includes(t('ja')('zk.conclusionWire.unavailable', { range: '0' })));
assert(!unavailableEdge.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: unavailableEdge.saved })));
for (const fake of [{ versionError: missing() }, { version: '' },
  { dockerError: missing(), versionError: missing() }]) {
  const r = await stage3Run({ answer: true, platform: 'win32', fake });
  unperformed(r, 'R-3: Windows');
  assert(!r.screen.includes(t('ja')('zk.stage3InstallHint')));
  for (const line of [...sp1Install, ...Object.values(dockerInstalls), 'winget install Docker.DockerDesktop']) {
    assert(!r.screen.includes(line), 'R-3: Windows はインストール命令を出さない');
  }
}

// 実 yesNo とメニューをつなぎ、Stage1保存後は空・不正入力の間も追加の保存・起動なしで待つ。
let promptSeq = 0;
async function promptFixture({ nonInteractive = false, terminal = false } = {}) {
  const input = new PassThrough(), output = new PassThrough();
  input.isTTY = output.isTTY = terminal;
  input.setRawMode = (raw) => { input.isRaw = raw; };
  const lines = []; output.on('data', (data) => lines.push(data.toString()));
  globalThis.__STAGE3_PROMPTS = { input, output };
  let code = fs.readFileSync(new URL('../src/prompts.js', import.meta.url), 'utf8')
    .replace("import { stdin as input, stdout as output } from 'node:process';", 'const { input, output } = globalThis.__STAGE3_PROMPTS;');
  if (mutation === 'z3') code = mutated(code,
    ["if (answer === '' && defaultValue !== null) return defaultValue;", "if (answer === '') return defaultValue ?? false;"]);
  const { createPrompts } = await import(`data:text/javascript;base64,${Buffer.from(code + `\n// ${promptSeq++}`).toString('base64')}`);
  const prompts = createPrompts({ nonInteractive });
  return { input, output, prompts, screen: () => lines.join(''), close: () => {
    prompts.close(); input.destroy(); output.destroy(); delete globalThis.__STAGE3_PROMPTS;
  } };
}
for (const finalAnswer of ['y', 'YES', 'n', 'NO']) {
  const f = await promptFixture();
  try {
    const r = await stage3Run({ promptFixture: f, drive: async (state) => {
      await tick();
      assert(f.screen().includes('[y/n]'));
      for (const answer of ['', ' ', 'maybe']) {
        const count = f.screen().split('[y/n]').length;
        f.input.write(answer + '\n'); await tick();
        assert.equal(f.screen().split('[y/n]').length, count + 1, 'Z1: 空/不正入力は同じ質問で待ち続ける');
        assert.equal(state.calls.length, 0); assert.equal(state.writes, 1);
      }
      f.input.write(finalAnswer + '\n');
    } });
    assert.equal(r.calls.length, ['y', 'YES'].includes(finalAnswer) ? 26 : 0);
  } finally { f.close(); }
}
for (const defaultValue of [true, false, null]) {
  const f = await promptFixture({ nonInteractive: true });
  try { assert.equal(await f.prompts.yesNo('確認', { defaultValue }), defaultValue ?? false);
    assert.equal(f.input.listenerCount('data'), 0); assert.equal(f.screen(), '');
  } finally { f.close(); }
}
for (const defaultValue of [true, false]) {
  const f = await promptFixture();
  try {
    const result = f.prompts.yesNo('確認', { defaultValue });
    assert(f.screen().includes(defaultValue ? '[Y/n]' : '[y/N]'));
    f.input.write('\n'); assert.equal(await result, defaultValue, '既定ありの挙動を維持');
  } finally { f.close(); }
}
// リトライも実 yesNo を通し、空Enterで副作用を起こさず、説明後は1行空ける。
for (const answer of ['y', 'n']) {
  const f = await promptFixture();
  try {
    const r = await stage3Run({ promptFixture: f, fake: failingTwo, drive: async (state) => {
      await tick(); f.input.write('y\n');
      await until(() => state.questions >= 2, 'リトライの質問に到達する');
      assert(f.screen().includes(t('ja')('zk.stage3RetryExplain', { n: 2 }) + '\n\n'
        + t('ja')('zk.stage3RetryPrompt', { n: 2 }) + ' [y/n] '), '質問前に空行1つ');
      const calls = state.calls.length, writes = state.writes;
      for (const blank of ['', ' ', 'maybe']) {
        const count = f.screen().split('[y/n]').length;
        f.input.write(blank + '\n'); await tick();
        assert.equal(f.screen().split('[y/n]').length, count + 1);
        assert.equal(state.calls.length, calls); assert.equal(state.writes, writes);
      }
      f.input.write(answer + '\n');
    } });
    assert.equal(r.code, answer === 'y' ? 0 : 2);
  } finally { f.close(); }
}

// runQuietProcess の両pipeを実際に満たす。pipeの読み捨てを消すとwatchdogで子を
// 片付けてからassertionで赤にする（テスト全体のtimeoutを検出に数えない）。
const realChildren = [];
function nodeChild(code, options, lifetime = 3000, onWatchdog = () => {}) {
  const child = realSpawn(process.execPath, ['-e', code], options);
  realChildren.push(child);
  const timer = setTimeout(() => { onWatchdog(); child.kill('SIGKILL'); }, lifetime);
  child.once('close', () => clearTimeout(timer));
  return child;
}
const quiet = await stage3Run({ answer: true, spawnOverride: ({ calls, events }) => {
  const fakeSpawn = fakeStage3Spawn({ calls, events });
  return (command, args, options) => {
    if (command !== 'docker') return fakeSpawn(command, args, options);
    calls.push({ command, args, options });
    if (args[0] === 'run') {
      const source = args[args.indexOf('-v') + 1].slice(0, -':/root/program:ro'.length);
      const crate = args[args.indexOf('-w') + 1].split('/').at(-1);
      const guest = WIRE_GUESTS.find((g) => g.crate === crate
        && (g.bin || null) === (args.includes('--bin') ? args[args.indexOf('--bin') + 1] : null));
      const elf = path.join(source, crate, 'target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release', guest.elf);
      fs.mkdirSync(path.dirname(elf), { recursive: true }); fs.writeFileSync(elf, 'FAKE ELF');
    }
    return nodeChild("process.stdout.write('QUIET_CHILD_OUTPUT' + 'x'.repeat(512 * 1024));"
      + "process.stderr.write('QUIET_CHILD_OUTPUT' + 'y'.repeat(512 * 1024));", options, 1200);
  };
} });
assert.equal(quiet.code, 0, 'R-5: stdout/stderr が64KBを大幅に超えても詰まらない');
assert(!quiet.screen.includes('QUIET_CHILD_OUTPUT'), 'R-5: 実子の出力は画面に出ない');
assert(realChildren.every((c) => c.exitCode === 0));
console.log('FIX1 quiet real children: 13 x stdout 512KiB + stderr 512KiB, hidden: PASS');

// SIGINT/readline SIGINT/close × 道具の版確認/build/算出。raw mode の最初の Ctrl+C も渡す。
for (const phase of ['docker-version', 'prove-version', 'build', 'vkey']) for (const origin of ['signal', 'readline-sigint', 'readline-close']) {
  const f = await promptFixture({ terminal: true });
  let active, closed, exitCalled, started = 0;
  const signalsBefore = process.listenerCount('SIGINT');
  try {
    const r = await stage3Run({ promptFixture: f, exitProcess: (code) => { exitCalled = code; },
      spawnOverride: ({ calls, events }) => {
        const fakeSpawn = fakeStage3Spawn({ calls, events });
        return (command, args, options) => {
          if (!((phase === 'docker-version' && command === 'docker' && args[0] === 'version')
            || (phase === 'prove-version' && command === 'cargo-prove' && args[1] === '--version')
            || (phase === 'build' && command === 'docker' && args[0] === 'run')
            || (phase === 'vkey' && command === 'cargo-prove' && args[1] === 'vkey'))) {
            return fakeSpawn(command, args, options);
          }
          calls.push({ command, args, options }); started++;
          active = nodeChild('setTimeout(() => {}, 900);', options, 2000);
          active.once('close', (code, signal) => { closed = { code, signal }; });
          return active;
        };
      }, drive: async () => {
        await tick(); f.input.write('y\n');
        await until(() => active, '停止対象の子を起動する');
        if (origin === 'signal') process.emit('SIGINT');
        else if (origin === 'readline-sigint') f.input.write('\x03');
        else f.input.end();
      } });
    assert.equal(r.code, 130); assert.equal(exitCalled, 130, 'CLI を130で終了する');
    assert.equal(started, 1, 'Z8: 残りを起動しない');
    assert(closed?.signal === 'SIGINT' || closed?.signal === 'SIGTERM' || closed?.signal === 'SIGKILL',
      'Z8: 子へ停止signalを送ってcloseを待つ');
    assert.throws(() => process.kill(active.pid, 0), { code: 'ESRCH' }, 'B/Z8: 子のpidが残らない');
    if (phase.endsWith('-version')) {
      assert.equal(r.writes, 1, 'B: 道具確認中の中断でもStage1の保存を保つ');
      assert(r.entries.includes(path.basename(r.saved)));
      assert.equal(r.calls.filter((c) => c.args[0] === 'run').length, 0, 'B: 組み直しの起動0回');
      assert.equal(r.calls.length, phase === 'docker-version' ? 1 : 2, 'B: 次の道具を起動しない');
      assert.equal(r.questions, 1);
      assert(!r.screen.includes(t('ja')('zk.wireUnperformed')));
    }
    assert(!r.screen.includes(t('ja')('zk.stage3Failed')));
    assert(!r.screen.includes('検証できませんでした。'));
    assert(!r.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: r.saved })));
    for (const c of r.calls.filter((c) => c.command === 'cargo-prove')) {
      assert(!fs.existsSync(c.options.cwd), 'Z8: cargo-prove の一時ディレクトリを消す');
    }
    assert.equal(process.listenerCount('SIGINT'), signalsBefore, '一時listenerを外す');
  } finally {
    if (active && active.exitCode === null && active.signalCode === null) active.kill('SIGKILL');
    f.close();
  }
}
console.log('FIX2 B: first Ctrl+C during docker/cargo-prove version, 130 + Stage1 source kept + no build/remaining child: PASS');

// FIX2 C: ハンドラ準備後にCtrl+C。SIGINT/SIGTERMを無視する実子を段階的に止める。
// watchdog は変異で残った子の後始末専用。発火したら試験は必ずassertionで赤。
for (const phase of ['build', 'vkey']) {
  const f = await promptFixture({ terminal: true });
  let active, closed, exitCalled, watchdogFired = false, output = '';
  const sent = [], signalsBefore = process.listenerCount('SIGINT');
  try {
    const r = await stage3Run({ promptFixture: f, exitProcess: (code) => { exitCalled = code; },
      spawnOverride: ({ calls, events }) => {
        const fakeSpawn = fakeStage3Spawn({ calls, events });
        return (command, args, options) => {
          if (!((phase === 'build' && command === 'docker' && args[0] === 'run')
            || (phase === 'vkey' && command === 'cargo-prove' && args[1] === 'vkey'))) {
            return fakeSpawn(command, args, options);
          }
          calls.push({ command, args, options });
          active = nodeChild("process.on('SIGINT', () => process.stdout.write('SEEN_SIGINT\\n'));"
            + "process.on('SIGTERM', () => process.stdout.write('SEEN_SIGTERM\\n'));"
            + "process.stdout.write('READY\\n'); setInterval(() => {}, 1000);",
          options, 4500, () => { watchdogFired = true; });
          const kill = active.kill.bind(active);
          active.kill = (signal) => { sent.push(signal); return kill(signal); };
          active.stdout.on('data', (bytes) => { output += bytes.toString(); });
          active.once('close', (code, signal) => { closed = { code, signal }; });
          return active;
        };
      }, drive: async () => {
        await tick(); f.input.write('y\n');
        await until(() => output.includes('READY\n'), 'C: 実子の無視ハンドラが準備できる');
        f.input.write('\x03');
      } });
    assert.equal(r.code, 130); assert.equal(exitCalled, 130);
    assert.equal(watchdogFired, false, 'C: watchdogの後始末を正常な停止に数えない');
    assert.deepEqual(sent, ['SIGINT', 'SIGTERM', 'SIGKILL'], 'C: 3段すべてを順番に送る');
    assert(output.includes('SEEN_SIGINT\n') && output.includes('SEEN_SIGTERM\n'), 'C: 実子も両信号を受けて無視した');
    assert.equal(closed?.signal, 'SIGKILL', 'C: 最後の段でcloseする');
    assert.throws(() => process.kill(active.pid, 0), { code: 'ESRCH' }, 'C: 実子のpidが残らない');
    assert.equal(r.calls.filter((c) => phase === 'build' ? c.args[0] === 'run' : c.args[1] === 'vkey').length, 1,
      'C: 中断後に残りを起動しない');
    for (const c of r.calls.filter((c) => c.command === 'cargo-prove')) {
      assert(!fs.existsSync(c.options.cwd), 'C: 一時ディレクトリを消す');
    }
    assert.equal(process.listenerCount('SIGINT'), signalsBefore, 'C: 一時listenerを外す');
    assert(!r.screen.includes('SEEN_SIG'));
    assert(!r.screen.includes(t('ja')('zk.conclusionSourceMatches', { path: r.saved })));
  } finally {
    if (active && active.exitCode === null && active.signalCode === null) active.kill('SIGKILL');
    f.close();
  }
}
console.log('FIX2 C: real children ignore SIGINT/SIGTERM, ordered escalation + SIGKILL + no remaining pid: PASS');
// リトライ待ちにも処理用のSIGINT購読が残るので、質問のPromiseも中断する。
{
  const f = await promptFixture({ terminal: true });
  let exitCalled;
  try {
    const r = await stage3Run({ promptFixture: f, fake: failingTwo,
      exitProcess: (code) => { exitCalled = code; }, drive: async (state) => {
        await tick(); f.input.write('y\n');
        await until(() => state.questions >= 2, '中断するリトライの質問に到達する');
        f.input.write('\x03');
      } });
    assert.equal(r.code, 130); assert.equal(exitCalled, 130);
    assert.equal(r.calls.filter((c) => c.args[0] === 'run').length, 12);
    assert.equal(r.questions, 2);
    assert(!r.screen.includes('検証できませんでした。'));
  } finally { f.close(); }
}
console.log('FIX1 cancellation: first SIGINT/readline SIGINT/close, build/vkey, child close + tmp cleanup: PASS');

console.log('STAGE3RUN FIX5: Z1-Z10, L-3, write failure, gate, retry, partial mismatch, progress-before-spawn, Windows: PASS');
if (process.argv.includes('--stage3-examples')) console.log('STAGE3_EXAMPLES ' + JSON.stringify(stage3Examples));
if (!mutation) for (const name of ['w3', 'v3', 'v4', 'v7', 'z1', 'z2', 'z3', 'z4', 'z5', 'z6', 'z7', 'z8', 'z9', 'z10', 'z11', 'z12', 'z13', 'z14', 'z15', 'z16', 'z17', 'z18', 'z19', 'z20', 'z21', 'z22', 'z23', 'z24', 'z25', 'z26', 'z27', 'z28', 'z29', 'z30', 'z31', 'z32']) {
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--stage3-mutation=' + name],
    { encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024 });
  assert(child.stdout.includes('MUTATION_APPLIED ' + name), `${name}: 変異を適用した`);
  assert.notEqual(child.status, 0, `${name}: 変異は赤になる`);
  assert(child.stderr.includes('AssertionError'), `${name}: 起動失敗を検出に数えない`);
  console.log(`STAGE3RUN mutation ${name}: rejected (assertion, exit ${child.status})`);
}
console.log('WR15 wiring unit: PASS');
