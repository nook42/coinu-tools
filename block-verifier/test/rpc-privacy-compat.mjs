// HEAD と現在の src に同じ秘密なし Q24 fixture を渡し、出力全バイトを比較する。
// 日時・乱数・fixture パスを固定。R2 は in-memory fetch、ソケットも実fetchも禁止。
// 実makeUiの画面・c8 U1の長い公開値・短い保存値も比較する。証跡は実行ごとに別ディレクトリ。
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, readFileSync, writeFileSync, readdirSync, symlinkSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, relative } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const repo = resolve(import.meta.dirname, '../..');
const retainEvidence = Boolean(process.env.RPC_PRIVACY_EVIDENCE_DIR);
const taskRoot = retainEvidence ? resolve(process.env.RPC_PRIVACY_EVIDENCE_DIR) : tmpdir();
mkdirSync(taskRoot, { recursive: true });
const task = mkdtempSync(join(taskRoot, 'rpc-privacy-compat-'));
try {
const trees = join(task, 'trees');
mkdirSync(trees);
console.log(`Evidence: ${task}`);
const fixed = join(task, 'fixed.mjs');
writeFileSync(fixed, `import net from 'node:net';
net.Socket.prototype.connect = net.Server.prototype.listen = function () { throw new Error('FIX1A network forbidden'); };
globalThis.fetch = async () => { throw new Error('FIX1A real fetch forbidden'); };
const RealDate = Date, now = 1794355200000;
globalThis.Date = class extends RealDate { constructor(...args) { super(...(args.length ? args : [now])); } static now() { return now; } };
let seed = 12345; Math.random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
`);
const tracked = execFileSync('git', ['ls-tree', '-r', '--name-only', 'HEAD', '--', 'block-verifier/src'], { cwd: repo, encoding: 'utf8' }).trim().split('\n');
let fixture = execFileSync('git', ['show', '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7:block-verifier/test/q24-emergency-unit.mjs'], { cwd: repo, encoding: 'utf8' });
fixture = fixture.replaceAll('process.pid', '424242');
// 最初の掃除は残す。最後の掃除を省いて、書き出された実ファイルを比較する。
fixture = fixture.replace(/await fs.rm\(taskTmp, \{ recursive: true, force: true \}\);(?=\nawait fs.rm\(p6EmergencyDir)/, '// compatibility: retain result bytes');
const fixtureRoot = join(task, 'fixtures');
const snapshots = new Map();
const screens = new Map();
const c8 = readFileSync(join(import.meta.dirname, 'c8-hostile-public-data-unit.mjs'), 'utf8');
const c8Marker = c8.indexOf('// U1: 正常系');
assert.ok(c8Marker > 0, 'real c8 U1 helpers must exist');
const screenFixture = c8.slice(0, c8Marker) + '\n' + readFileSync(join(import.meta.dirname, 'rpc-privacy-screen-fixture.mjs'), 'utf8');
function allFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const p = join(dir, entry.name); return entry.isDirectory() ? allFiles(p) : [p];
  });
}
const scenarios = ['', '1', 'e', 'l', '123456789012345'];
for (const typo of scenarios) for (const version of ['head', 'current']) {
  const label = `${version}-${typo || 'none'}`;
  const tree = join(trees, label), bv = join(tree, 'block-verifier');
  mkdirSync(join(bv, 'test'), { recursive: true });
  for (const name of ['Hardhat', 'tools', 'crates', 'node_modules']) symlinkSync(join(repo, name), join(tree, name));
  symlinkSync(join(repo, 'block-verifier/vendor'), join(bv, 'vendor'));
  symlinkSync(join(repo, 'block-verifier/scripts'), join(bv, 'scripts'));
  for (const name of ['players.mjs', 'r2-server.mjs']) symlinkSync(join(import.meta.dirname, name), join(bv, 'test', name));
  writeFileSync(join(tree, 'package.json'), '{"type":"module"}');
  if (version === 'head') {
    for (const name of tracked) {
      const file = join(tree, name); mkdirSync(resolve(file, '..'), { recursive: true });
      writeFileSync(file, execFileSync('git', ['show', `08f7ef70556b7aca19aa4fdab25a4c127fbf47f7:${name}`], { cwd: repo }));
    }
  } else cpSync(join(repo, 'block-verifier/src'), join(bv, 'src'), { recursive: true });
  if (version === 'head') {
    const file = join(bv, 'src/index.js');
    const original = readFileSync(file, 'utf8');
    assert.ok(original.includes('function makeUi('), 'HEAD real makeUi must exist');
    writeFileSync(file, original.replace('function makeUi(', 'export function makeUi('));
  }
  writeFileSync(join(bv, 'test/q24-emergency-unit.mjs'), fixture);
  const returned = join(task, `${label}-returned.jsonl`);
  rmSync(returned, { force: true });
  const instrumentedFixture = fixture.replace('selectEmergencyServerSubmissions, writeEmergencyResultSet,', 'selectEmergencyServerSubmissions, writeEmergencyResultSet: baseWriteEmergencyResultSet,').replace('} = emergencyModule;', `} = emergencyModule;\nasync function writeEmergencyResultSet(options) { const saved = loadConfig(['--rpc', 'https://ethereum-rpc.publicnode.com']); options = { ...options, ctx: { ...options.ctx, cfg: { ...options.ctx.cfg, customRpcs: saved.customRpcs } } }; const result = await baseWriteEmergencyResultSet(options); await fs.appendFile(${JSON.stringify(returned)}, JSON.stringify({ differences: result.differences, diffs: result.diffs, nonResultDifferences: result.nonResultDifferences }) + '\\n'); return result; }`);
  assert.notEqual(instrumentedFixture, fixture, 'capture returned differences');
  writeFileSync(join(bv, 'test/q24-emergency-unit.mjs'), instrumentedFixture);
  const workDir = join(task, `work-${label}`); mkdirSync(workDir);
  writeFileSync(join(workDir, 'verifier-config.json'), JSON.stringify({ customRpcs: typo ? [typo] : [] }));
  const result = spawnSync(process.execPath, [join(bv, 'test/q24-emergency-unit.mjs')], {
    cwd: workDir, env: { ...process.env, NODE_OPTIONS: `--import ${fixed}`, R2_FIXTURE_IN_MEMORY: '1', M14D_TEST_TMP_ROOT: fixtureRoot },
    encoding: 'utf8', timeout: 180000, maxBuffer: 16 * 1024 * 1024,
  });
  writeFileSync(join(task, `${label}.log`), result.stdout + result.stderr);
  assert.equal(result.status, 0, `${version}: ${result.stderr.slice(-2000)}`);
  const root = join(fixtureRoot, 'q24-block-verifier-unit-424242');
  const indexFiles = allFiles(root).filter((p) => p.endsWith('/_emergency/bundle-index.json'));
  const files = new Map();
  for (const index of indexFiles) {
    const out = resolve(index, '../..');
    for (const file of allFiles(out)) files.set(relative(root, file), readFileSync(file));
  }
  assert.ok(indexFiles.length > 10 && files.size > 100, 'must compare real emergency exports');
  // 計時以外の人向けログも比較する。module-type 警告のPID/パスは診断ではないため除く。
  const log = result.stdout.replace(/\b(elapsedMs|baselineElapsedMs|totalElapsedMs|elapsedFactor)=[\d.]+/g, '$1=<timing>');
  files.set('_returned-differences.jsonl', readFileSync(returned));
  for (const [name, bytes] of files) {
    if (/\/_emergency\/(public-differences|submission-selection|writer-provenance|differences)\.json$/.test(name)) JSON.parse(bytes);
  }
  snapshots.set(label, { files, log });
  console.log(`${label}: ${indexFiles.length} emergency bundles; ${files.size} files; fixture PASS`);
  writeFileSync(join(bv, 'test/rpc-screen.mjs'), screenFixture);
  for (const length of (typo ? [0] : [0, 320_000, 2_000_000, 8 * 1024 * 1024])) {
    const output = join(task, `screen-${label}-${length}.txt`);
    const screenResult = spawnSync(process.execPath, [join(bv, 'test/rpc-screen.mjs')], {
      cwd: workDir, env: { ...process.env, NODE_OPTIONS: `--import ${fixed}`,
        RPC_SCREEN_TYPO: typo, RPC_SCREEN_LENGTH: String(length), RPC_SCREEN_FILE: output },
      encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024,
    });
    assert.equal(screenResult.status, 0, `real makeUi screen ${label}/${length}: ${screenResult.stderr}`);
    const measurement = JSON.parse(screenResult.stdout.trim().split('\n').at(-1));
    assert.equal(measurement.consistent, 'fail');
    assert.notEqual(measurement.laterMerkle, 'absent');
    assert.ok(measurement.renderMs < 1000, 'real renderSummary must finish under 1s');
    screens.set(`${label}-${length}`, measurement);
    console.log(`real makeUi ${label}: ${JSON.stringify(measurement)}`);
  }
}
for (const typo of scenarios) {
const head = snapshots.get(`head-${typo || 'none'}`), current = snapshots.get(`current-${typo || 'none'}`);
assert.deepEqual([...current.files.keys()].sort(), [...head.files.keys()].sort());
for (const [name, bytes] of head.files) assert.deepEqual(current.files.get(name), bytes, `HEAD byte mismatch: ${typo || 'none'} ${name}`);
assert.equal(current.log, head.log, 'HEAD screen/log byte mismatch (except measured timings)');
const hashes = [...current.files].map(([name, bytes]) => ({ name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }));
writeFileSync(join(task, `byte-parity-${typo || 'none'}.json`), JSON.stringify({ bundles: hashes.filter(({ name }) => name.endsWith('/bundle-index.json')).length, files: hashes }, null, 2) + '\n');
console.log(`HEAD byte parity ${typo || 'none'}: PASS (${hashes.length} files, including diagnostics, canonical output and public originals; returned differences compared as JSON bytes; screen/logs equal)`);
for (const length of (typo ? [0] : [0, 320_000, 2_000_000, 8 * 1024 * 1024])) {
  const headScreen = screens.get(`head-${typo || 'none'}-${length}`);
  const currentScreen = screens.get(`current-${typo || 'none'}-${length}`);
  assert.equal(currentScreen.sha256, headScreen.sha256, 'real makeUi screen bytes must equal HEAD');
  assert.equal(currentScreen.bytes, headScreen.bytes);
  assert.ok(currentScreen.renderMs < headScreen.renderMs * 8 + 50, 'same order of render time as HEAD');
  if (!length) assert.deepEqual(readFileSync(join(task, `screen-current-${typo || 'none'}-0.txt`)),
    readFileSync(join(task, `screen-head-${typo || 'none'}-0.txt`)), 'full real makeUi screen byte parity');
}
}
writeFileSync(join(task, 'screen-timings.json'), JSON.stringify([...screens].map(([scenario, row]) => ({ scenario, ...row })), null, 2) + '\n');
// RB-03: HEADと同じ盤に深いrules.protocolのcheckを足し、実ファイルとexit 4を比較する。
for (const depth of [3000, 4000, 6000]) {
  const results = new Map();
  for (const version of ['head', 'current']) {
    const bv = join(trees, `${version}-none/block-verifier`);
    let deepFixture = fixture.replace('const w1OutputDir =', `const rb3Params = { protocol: JSON.parse('['.repeat(${depth}) + ']'.repeat(${depth})), blockRewardWei: '1', expected: '2' };
const rb3Report = { ...report, list: () => [...report.list(), { id: 'check.stageC.rulesReward', status: 'fail', params: rb3Params }] };
const w1OutputDir =`);
    const marker = deepFixture.indexOf('const w1OutputDir =');
    const tail = deepFixture.slice(marker).replace('blockNum: 4, report, cfg: DEFAULTS,',
      'blockNum: 4, report: rb3Report, cfg: { ...DEFAULTS, rpcUrls: [], customRpcs: [], rpcPresets: [] },');
    deepFixture = deepFixture.slice(0, marker) + tail;
    deepFixture = deepFixture.replace('const readIfWritten =', `if (w1WriteError) console.error('RB-03 export failed: ' + w1WriteError);
process.exit(w1Written ? EXIT_CODE_OF[categorizeEmergencyWrite(w1Written, null)] : 3);
const readIfWritten =`);
    const entry = join(bv, 'test/rpc-deep.mjs'); writeFileSync(entry, deepFixture);
    const run = spawnSync(process.execPath, [entry], { cwd: join(task, `work-${version}-none`),
      env: { ...process.env, NODE_OPTIONS: `--import ${fixed}`, R2_FIXTURE_IN_MEMORY: '1', M14D_TEST_TMP_ROOT: fixtureRoot },
      encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1024 * 1024 });
    writeFileSync(join(task, `deep-${version}-${depth}.log`), run.stdout + run.stderr);
    assert.equal(run.status, 4, `RB-03 depth ${depth} ${version} must write and exit 4: ${run.stderr.slice(-1000)}`);
    const out = join(fixtureRoot, 'q24-block-verifier-unit-424242/w1-groupgame-export');
    const files = new Map(allFiles(out).map((file) => [relative(out, file), readFileSync(file)]));
    const diagnostic = JSON.parse(files.get('_emergency/public-differences.json'));
    assert.ok(diagnostic.checkDifferences.some((row) => Array.isArray(row.params?.protocol)));
    results.set(version, files);
  }
  const head = results.get('head'), current = results.get('current');
  assert.deepEqual([...current.keys()].sort(), [...head.keys()].sort());
  for (const [name, bytes] of head) assert.deepEqual(current.get(name), bytes, `RB-03 HEAD depth ${depth} bytes: ${name}`);
  console.log(`RB-03 HEAD parity depth=${depth}: PASS (${head.size} files; both exit 4)`);
}

} finally {
  if (!retainEvidence) rmSync(task, { recursive: true, force: true });
}
