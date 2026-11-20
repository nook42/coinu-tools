// rpc-privacy-compatがc8の本物のU1ヘルパの後ろへ連結する。単独では起動しない。
// HEADのmakeUiもexportを足しただけの同じ関数を呼ぶ。
const cli = await import('../src/index.js');
const { loadConfig: loadScreenConfig, saveConfig: saveScreenConfig } = await import('../src/config.js');
const { createHash: screenHash } = await import('node:crypto');
const screenTypo = process.env.RPC_SCREEN_TYPO || '';
saveScreenConfig({ customRpcs: screenTypo ? [screenTypo] : [] });
const screenCfg = loadScreenConfig(['--rpc', 'https://ethereum-rpc.publicnode.com', '--lang', 'en', '--non-interactive']);
const screenLength = Number(process.env.RPC_SCREEN_LENGTH || 0);
const screenPublished = screenLength ? 'a'.repeat(screenLength) : 'https://user@mirror.example.org/archive';
const screenCtx = makeCtx({
  lang: 'en',
  chain: makeChainStub({ depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds: [] }),
  players: [player('20000001', depIdsJson(ETH(1.0), ['1']), 0)],
  files: makeFiles({ summary: { blockNum: N, autoDistributed: screenPublished, groups: [] } }),
});
const screenRun = await callRun(screenCtx);
if (screenRun.threw) throw screenRun.error;
const screenChunks = [];
const screenOut = process.stdout.write, screenErr = process.stderr.write;
process.stdout.write = (s) => { screenChunks.push(String(s)); return true; };
process.stderr.write = (s) => { screenChunks.push(String(s)); return true; };
const screenUi = cli.makeUi(makeTranslator('en'), {}, screenCfg);
let screenMs;
try {
  const start = performance.now();
  screenCtx.report.renderSummary(screenUi, screenCtx);
  screenMs = performance.now() - start;
  screenUi.println('Emergency Merkle root: 0x1111aaaa' + '01'.repeat(28));
  screenUi.warn('Error: public R2 failure\n    at public-fixture.js:11:12');
  const written = { differences: [{ checkId: 'emergency.publicArtifactBytes',
    what: 'public artifact bytes differ: games/block12/group1.json',
    chain: { publicSha256: '1f'.repeat(32) }, rebuilt: { sha256: 'a1'.repeat(32) } }], nonResultDifferences: [] };
  cli.emitEmergencyDifferenceMarkers(screenUi, written);
  cli.emitNonInteractiveOutcome(screenUi, { report: screenCtx.report, stopped: false, fatal: false }, written);
} finally { process.stdout.write = screenOut; process.stderr.write = screenErr; }
const screenBytes = screenChunks.join('');
if (!screenLength) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(process.env.RPC_SCREEN_FILE, screenBytes);
}
console.log(JSON.stringify({ length: screenLength, typo: screenTypo, renderMs: screenMs,
  consistent: statusOf(screenCtx, 'check.stageC.autoDistributeConsistent'),
  laterMerkle: statusOf(screenCtx, 'check.stageC.merkleRoot'),
  bytes: Buffer.byteLength(screenBytes), sha256: screenHash('sha256').update(screenBytes).digest('hex') }));
