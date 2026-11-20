// FIX2: 実publicnode応答を固定し、分類・表示・網羅を実装の入口で検査する。外部接続なし。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { custom, HttpRequestError, encodeAbiParameters, parseAbiParameters } from 'viem';
import * as archive from '../src/archive.js';
import * as reports from '../src/report.js';
import * as index from '../src/index.js';
import { createChain } from '../src/chain.js';
import { VERIFICATION_AREAS, publicnodeExplanation } from '../src/verification-areas.js';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { checkProofFutureAnchor } from '../src/future-anchor.js';
import { describeZkpCollectionFailure } from '../src/zkp.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';

// 統括の2026-11-16の測定値そのもの。短い代役文へ置き換えない。
export const PUBLICNODE_BODY = '{"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1}';
export const PUBLICNODE_DETAILS = '{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"}';
const PUBLICNODE_URL = 'https://ethereum-rpc.publicnode.com';
const rpcFailure = () => new HttpRequestError({ status: 403, url: PUBLICNODE_URL,
  body: { method: 'eth_getCode', params: ['0x' + '11'.repeat(20), '0xc99df8'] }, details: PUBLICNODE_DETAILS });
const mutation = process.argv.find((a) => a.startsWith('--mutation='))?.split('=')[1];
async function load(file, edit = (s) => s, extra = '') {
  const url = new URL(file, import.meta.url);
  const source = edit(readFileSync(url, 'utf8')).replace(/from '([^']+)'/g,
    (_, p) => `from '${p.startsWith('.') ? new URL(p, url).href : import.meta.resolve(p)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source + '\n' + extra).toString('base64')}`);
}
let { historicalStateFailure, archiveProbe } = archive;
let { createReport, verificationCoverage } = reports;
let { makeUi, categorize } = index;
let chainFactory = createChain;
if (mutation === 'stale_probe_head') ({ createChain: chainFactory } = await load('../src/chain.js',
  (s) => s.replace('const historical = request.blockNumber != null;',
    'const historical = request.blockNumber != null && (archiveCapability.head == null || BigInt(request.blockNumber) < archiveCapability.head);')));
if (mutation === 'real_message') ({ historicalStateFailure } = await load('../src/archive.js',
  (s) => s.replaceAll('personal token(?:\\.|!|$)', 'personal token[.!]?$')));
if (mutation === 'probe_getCode') ({ archiveProbe } = await load('../src/archive.js',
  (s) => s.replace("method: 'eth_call'", "method: 'eth_getCode'")));
if (['projection', 'labelled_projection', 'coverage_domains', 'coverage_archive', 'not_applicable'].includes(mutation)) {
  const mod = await load('../src/report.js', (s) => {
    if (mutation === 'projection') return s.replace('  if (!params ||', '  return params;\n  if (!params ||');
    if (mutation === 'labelled_projection') return s.replace('conciseRpcText(value, translate)',
      "(/^(?:TokenMining|Evidence|HashStorage):/.test(String(value)) ? value : conciseRpcText(value, translate))");
    if (mutation === 'coverage_domains') return s.replace("entries.some((e) => e.status === 'fail')", 'false');
    if (mutation === 'coverage_archive') return s.replace("entries.some((e) => e.reason === 'archive_unavailable')", 'false');
    return s.replace('const notApplicable = !failed', 'const notApplicable = false && !failed');
  });
  ({ createReport, verificationCoverage } = mod);
}
if (mutation === 'whole_line') ({ makeUi } = await load('../src/index.js',
  (s) => s.replace('redactRpcText(value, configRpcUrls(cfg))', 'redactRpcText(conciseRpcText(value, translate), configRpcUrls(cfg))')));
if (mutation === 'full_on_skip') ({ categorize } = await load('../src/index.js',
  (s) => s.replace("  if (outcome.report.list().some((e) => e.reason === 'archive_unavailable')) return 'partial';", '')));
const resultModule = await load('../src/stages/results.js', (s) => mutation === 'invalid_cause'
  ? s.replace("if (!invalidEmergencyCause && !knownFinalityMismatch) report.unverified('check.stageC.timelineNoGameFinality', error, { reason: 'archive_unavailable' });",
    "report.unverified('check.stageC.timelineNoGameFinality', error, { reason: 'archive_unavailable' }); return false;") : s,
  'export { reproduceEvidence, runAutoWithAvailableState };');
const verdictModule = await load('../src/index.js', (s) => mutation === 'stage_projection'
  ? s.replaceAll(/displayParams\((firstFail|firstWarn|firstSkip)\.params, t\)/g, '$1.params') : s,
  'export { printStageVerdict };');
const { ArchiveUnavailableError } = archive;
const tr = t('ja');
const address = '0x' + '11'.repeat(20);
let assertions = 0;
function eq(a, b, message) { assert.deepEqual(a, b, message); assertions++; }
function ok(value, message) { assert.ok(value, message); assertions++; }
function complete() { const report = createReport(); for (const id of CHECK_INVENTORY) report.check(id, 'pass'); return report; }
function render(report, translate = tr) {
  const lines = []; report.renderSummary({ t: translate, println: (s) => lines.push(s) }, { blockNum: 8, data: {} });
  return lines.join('\n');
}
function noRaw(text, message) { for (const word of ['Status:', 'URL:', 'Request body:', 'Details:', 'Version:']) ok(!text.includes(word), `${message}: ${word}`); }

// §1: 生JSON-RPC error / viem status+detailsの双方。同じ語が要求側にあるだけでは当たらない。
eq(JSON.stringify(JSON.parse(PUBLICNODE_BODY).error), PUBLICNODE_DETAILS, '実応答のerrorを文字どおり固定');
for (const error of [JSON.parse(PUBLICNODE_BODY).error, rpcFailure(),
  { name: 'ContractFunctionExecutionError', message: '表示用', cause: rpcFailure() }]) {
  eq(historicalStateFailure(error), 'archive_unavailable', '追記された実応答を分類');
}
for (const error of [{ code: -32602, message: 'Invalid params' }, { status: 403 },
  { code: -32602, message: 'Archive requests require a personal tokenish string' },
  new HttpRequestError({ status: 403, url: PUBLICNODE_URL, details: '{"code":-32602,"message":"Invalid params"}', body: PUBLICNODE_DETAILS }),
  new HttpRequestError({ status: 503, url: PUBLICNODE_URL, details: PUBLICNODE_DETAILS }),
  { name: 'ContractFunctionExecutionError', message: PUBLICNODE_DETAILS, url: PUBLICNODE_URL, body: PUBLICNODE_DETAILS }]) {
  eq(historicalStateFailure(error), 'rpc_unavailable', 'code・status・要求・表示文だけでは分類しない');
}
// F-11: getCodeを読めるノードでもeth_callを拒まれたら読めると案内しない。再試行は1回だけ。
const probeRequests = [];
const probe = archiveProbe({ getBlockNumber: async () => 20000n, request: async (request) => {
  probeRequests.push(request); if (request.method === 'eth_call') throw rpcFailure(); return '0x6000';
} }, { chainIdExpected: 1 });
eq((await probe()).status, 'unavailable', 'F-11: getCode成功で代用しない'); await probe();
eq(probeRequests, [{ method: 'eth_call', params: [{ to: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', data: '0x18160ddd' }, '0x2710'] }], '実際の履歴eth_callを1回');

// §2: RPCのerror欄だけを投影。FAIL/WARN/SKIP・段の判定行・まとめを実装から描画する。
for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang), report = createReport();
  const raw = rpcFailure().message;
  for (const [id, status, error] of [
    ['fact.system.adminRotationUnavailable', 'warn', `TokenMining: ${raw}; Evidence: ${raw}`],
    ['check.stageC.onchainClaimData', 'fail', raw],
    ['check.stageC.summaryMatch', 'skip', raw],
  ]) {
    const params = { error, sentinel: '検証材料のまま' };
    if (status === 'skip') report.unverified(id, new ArchiveUnavailableError(rpcFailure()), params);
    else report.check(id, status, params);
    assert.equal(report.get(id).params, params); assertions++;
    eq(params.error, error, 'paramsは生の値と参照を保存');
    const single = createReport();
    if (status === 'skip') single.unverified(id, new ArchiveUnavailableError(rpcFailure()), params);
    else single.check(id, status, params);
    const stage = [];
    verdictModule.printStageVerdict({ t: translate, println: (s) => stage.push(s) }, single, { data: {} }, 'C', 0, {});
    noRaw(stage.join('\n'), `${lang}/${status}: 段の判定`);
  }
  const originalChecks = structuredClone(report.list());
  noRaw(render(report, translate), `${lang}: 警告・FAIL・SKIPのまとめ`);
  eq(report.list(), originalChecks, '表示後もparams・判定を保存');
  const machine = []; index.emitNonInteractiveOutcome({ println: (s) => machine.push(s) }, { report, fatal: false, stopped: false }, null);
  eq(machine, [...originalChecks.map((e) => `##CHECK ${e.id} ${e.status}`), '##RESULT fail'], '実機械行は表示の投影で変わらない');
  const typed = createReport();
  typed.check('fact.system.adminRotationUnavailable', 'warn', { error: 'TokenMining: archive_unavailable; Evidence: archive_unavailable' });
  ok(render(typed, translate).includes(translate('reason.archiveUnavailable')), '型付き履歴失敗の警告理由');
  noRaw(JSON.stringify(reports.displayParams({ details: { current: { error: raw } } }, translate)), '入れ子のerror欄');
}

// F-08: error欄を持つ検査でも、機械行と比較材料の表示はそのまま。
const markers = ['##CHECK check.stageC.summaryMatch skip', '##RESULT partial',
  '##COMPARISON check.stageC.summaryMatch fail archive_unavailable',
  '##EMERGENCY_DIFFERENCE {"value":"HTTP request failed. Status: 403 URL: public-data"}',
  '##PREV_ANCHOR_TARGET {"value":"Request body: public-data Details: public-data Version: public-data"}'];
const publicLine = 'HTTP request failed. summaryMatch 不一致 {"diffs":"Status: field vs URL: field"}';
let stdout = ''; const write = process.stdout.write;
process.stdout.write = (s) => { stdout += s; return true; };
try { const ui = makeUi(tr, { isInteractive: false }, {}); for (const line of [...markers, publicLine]) ui.println(line); }
finally { process.stdout.write = write; }
eq(stdout, [...markers, publicLine, ''].join('\n'), 'F-08: 行全体を投影しない');

// F-09: inventoryの全領域の全検査にFAILを注入。必須ID以外の不合格も網羅へ反映する。
for (const id of CHECK_INVENTORY.filter((id) => /^check\.stage/.test(id))) {
  const domains = VERIFICATION_AREAS.filter((area) => area.matches.test(id));
  ok(domains.length, `${id}: 全検査に領域がある`);
  const report = complete(); report.check(id, 'fail');
  for (const domain of domains) {
    const row = verificationCoverage(report).find((row) => row.area === domain.area);
    eq([row.verified, row.notApplicable, row.reason], [false, false, 'failed'], `F-09: ${domain.area}/${id}`);
  }
}
// 必須IDがpassでも、同領域の別の読取が未検証なら領域を合格としない。
const optionalSkip = complete();
optionalSkip.unverified('check.stageC.zkPrevRegistrationWitness', new ArchiveUnavailableError());
eq(verificationCoverage(optionalSkip).find((row) => row.area === 'proofHistory').verified, false, 'F-10: 同領域の未検証も拾う');

// F-07: 配布方式のfactと実際に実行された検査の両方を見る。失敗は対象なしへ隠さない。
for (const mode of ['noGame', 'autoDistributed']) {
  const report = createReport();
  for (const id of CHECK_INVENTORY.filter((id) => !VERIFICATION_AREAS.find((a) => a.area === 'evidence').matches.test(id))) report.check(id, 'pass');
  report.fact(`stageC.${mode}`, true);
  report.check('check.stageC.timelineWindows', 'skip', { reason: 'no_evidence_windows' });
  eq(verificationCoverage(report).find((r) => r.area === 'evidence').notApplicable, true, `F-07: ${mode}/evidence`);
  eq(verificationCoverage(report).find((r) => r.area === 'timeline').notApplicable, false, `R-4: ${mode}/timelineは履歴検査が実行済み`);
  for (const id of ['check.stageC.evidenceReportMatch', 'check.stageC.timelineMatch']) report.check(id, 'fail');
  for (const area of ['evidence', 'timeline']) eq(verificationCoverage(report).find((r) => r.area === area).notApplicable, false, '実際の失敗は対象なしにしない');
}
const timeline = complete(); timeline.fact('stageC.noGame', true); timeline.fact('stageC.timelineNoGame', true);
eq(verificationCoverage(timeline).find((r) => r.area === 'evidence').notApplicable, false, 'timeline no-gameはEvidenceを実行する');

// 安全高の取得→最初のeth_callを計測。仮想経過だけを進め、待機や再ピン留めはしない。
let latestHead = 20000n;
const transport = custom({ request: async ({ method, params }) => {
  if (method === 'eth_blockNumber') return '0x4e20';
  if (method === 'eth_call' && latestHead - BigInt(params[1]) > 100n) throw rpcFailure();
  return encodeAbiParameters(parseAbiParameters('uint256'), [0n]);
} }, { retryCount: 0 });
const chain = chainFactory({ chainIdExpected: 31337, contracts: { tokenMining: address }, rpcUrls: ['http://127.0.0.1:1'] }, null, transport);
await chain.probeArchive();
let typedError;
try { await chain.client.readContract({ address, blockNumber: 10000n, abi: [{ type: 'function', name: 'value', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] }], functionName: 'value' }); }
catch (error) { typedError = error; }
ok(typedError instanceof ArchiveUnavailableError, '本物details→chainの型付き失敗');
// Stage A/B中にheadが進むと、新たに選ぶ安全高は接続時のheadを越えることがある。
latestHead = 30100n;
await assert.rejects(chain.client.readContract({address,blockNumber:29936n,
  abi:[{type:'function',name:'value',stateMutability:'view',inputs:[],outputs:[{type:'uint256'}]}],functionName:'value'}),
ArchiveUnavailableError, '接続時head=20000より新しい安全高でも型付き失敗'); assertions++;
latestHead = 20000n;
// K11の実getLockも、getCodeが読めるかに依らず同じ型で失敗する。
const gm = new GameMasterDO({ storage: {} }, { START_TIME: '1000000', BLOCK_TIME: '1000', ETH_LOCK_CONTRACT_ADDRESS: address });
gm.readDepositSelectionK11 = async () => 10000n;
gm.createReadOnlyClient = () => chain.client;
await assert.rejects(resultModule.verifyDepositsOnChainInUnits(gm, 0, { '1': ['1'] }), ArchiveUnavailableError); assertions++;
const dep = {id:'1', idFrom:'1', amount:'1000000000000000000', depositerAddress:address, unlockTime:2000000};
const autoReport = createReport();
const autoCtx = {blockNum:0, report:autoReport, cfg:{lang:'ja'}, data:{gameSelection:{players:[{globalIndex:0,
  data:{uid:'1',addr:address,lang:'ja',depIds:JSON.stringify({deposit:dep.amount,ids:['1'],deposits:[dep]})}}]}},
  ui:{t:tr,println(){},warn(){}}};
const seedGm = Object.create(gm);
seedGm.createReadOnlyClient = () => ({readContract:async()=>({...dep,idTo:'1',lockOwnerAddress:address,unlocked:false})});
const seedState = {files:{summary:{data:{}}},anomalies:[]};
await resultModule.runAutoWithAvailableState({...autoCtx,report:createReport()}, seedState, seedGm, {});
const autoState = {files:{summary:{data:{...seedState.rebuiltSummary,extraField:'comparison mismatch'}}},anomalies:[]};
eq(await resultModule.runAutoWithAvailableState(autoCtx, autoState, gm, {}), true, '実応答でも正典の仮計算・照合を続行');
eq(autoReport.get('check.stageC.depositVerification').reason, 'archive_unavailable', '実getLockの失敗を呼出元が受ける');
eq(autoReport.get('check.stageC.summaryMatch').comparisonStatus, 'fail', '前提未検証の照合不一致も保存');
eq(categorize({report:autoReport,fatal:false,stopped:false}), 'partial', '仮計算の結果をfullにしない');
noRaw(autoState.anomalies.join('\n'), '実応答で続行したStage Cの警告');
for (const delayed of [false, 'first', 'acc']) {
  latestHead = 20000n;
  let virtualMs = 0, selectedAt, elapsedReal, observedHeight;
  const report = createReport();
  const read = (value, name) => async (_n, opts) => {
    if (delayed === 'acc' && name === 'acc') { virtualMs += 492000; latestHead += 41n; }
    observedHeight = opts.blockNumber; elapsedReal ??= performance.now() - selectedAt;
    await chain.client.readContract({ address, blockNumber: opts.blockNumber,
      abi: [{ type: 'function', name: 'value', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] }], functionName: 'value' });
    return value;
  };
  const ctx = { blockNum: 0, report, data: {}, cfg: { contracts: { evidence: address }, pins: { confirmationBlocks: 64, clockSkewAllowMs: 0 } },
    ui: { t: tr, println() {} }, chain: {
      evidenceAddress: async () => address,
      latest: async () => { selectedAt = performance.now(); return { number: 20000n }; },
      getBlock: async () => { if (delayed === 'first') { virtualMs += 492000; latestHead += 41n; } return { timestamp: 1000n }; },
      resultWindow: read({ openAt: 800, closeAt: 900 }), chatWindow: read({ chatOpenAt: 600, chatCloseAt: 700 }),
      resultCount: read(0), evidenceAcc: read('0x' + '00'.repeat(32), 'acc'),
    } };
  await resultModule.reproduceEvidence(ctx, { files: { manifest: { data: { rules: { evidence: { chatWindowMs: { startMs: 600000, endMs: 700000 } } } } } }, groupIds: [], groupDataList: [], anomalies: [] });
  eq(observedHeight, 19936n, '遅延後も安全高の意味を変えない');
  eq(report.get('check.stageC.evidenceFinality').status, delayed === 'first' ? 'skip' : 'pass', '読めなくなった実際の読みだけ未検証');
  if (delayed) {
    eq(report.get(delayed === 'first' ? 'check.stageC.evidenceFinality' : 'check.stageC.evidenceAcc').reason, 'archive_unavailable', '失敗の型が到達');
    if (delayed === 'acc') eq(report.get('check.stageC.evidenceCompleteness').status, 'pass', '後半のaccが読めなくても完全性を巻き戻さない');
    eq(categorize({ report, fatal: false, stopped: false }), 'partial', 'F-12: SKIPだけでもpartial');
  }
  console.log(`SAFE-READ delayed=${delayed} height=${observedHeight} elapsedRealMs=${elapsedReal.toFixed(3)} simulatedElapsedMs=${virtualMs}`);
}

// F-06: FIX1で直っていたEvidence未配線は、既に履歴失敗のfactがあっても6件ともFAIL。
const unwired = createReport(); unwired.fact('stageC.lockStateError', typedError); unwired.fact('stageC.resultStateError', typedError);
await resultModule.reproduceEvidence({ blockNum: 0, report: unwired, data: {}, cfg: { pins: { confirmationBlocks: 64 } }, ui: { t: tr },
  chain: { evidenceAddress: async () => null, latest: async () => ({ number: 20000n }), getBlock: async () => ({ timestamp: 1000n }) } }, { files: {}, anomalies: [] });
eq(unwired.list().length, 6, 'Evidence未配線の全6件');
ok(unwired.list().every((e) => e.status === 'fail'), 'F-06: 過去状態と独立した配線の不正');
eq(categorize({ report: unwired, fatal: false, stopped: false }), 'fail', 'F-06: 独立のFAILはexit2');
// 未配線の他、no-gameの独立したshape不正をfactだけでSKIPに変えない。
unwired.check('check.stageC.noGameSummary', 'fail');
eq(unwired.get('check.stageC.noGameSummary').status, 'fail', 'no-game shapeの独立した不正');
const invalid = createReport();
await resultModule.verifyTimelineNoGameFinality({ blockNum: 0, report: invalid,
  data: { emergencySource: {}, gameSelection: { players: [1, 2, 3] } }, cfg: { pins: { confirmationBlocks: 64 } }, ui: { t: tr, println() {} },
  chain: { latest: async () => ({ number: 20000n }), findBlockByTimestamp: async () => 9000, getBlock: async () => ({ timestamp: 1000n }),
    resultWindow: async () => { throw typedError; }, resultCount: async () => 0, evidenceAddress: async () => address } },
{ files: { summary: { data: { noGameCause: 'malicious_unknown_cause', noGameFinality: { schemaVersion: 1, safeBlockNumber: '10000' } } } }, anomalies: [] });
eq(invalid.get('check.stageC.timelineNoGameFinality').status, 'fail', 'F-06: 読取不能でも緊急noGameCause不正はFAIL');
eq(invalid.get('check.stageC.timelineNoGameFinality').params.reason, 'invalid_no_game_cause', '不正の理由も残す');

// F-10: 実際のZKP収集・provider読取の型を網羅へ運ぶ。
const proofReport = complete();
resultModule.recordZkpPublicValuesCheck({ report: proofReport, data: {} }, describeZkpCollectionFailure(typedError, 10000));
const proofChain = { contracts: { tokenMining: address }, getLogsChunked: async () => [], client: {
  getBlock: async () => ({ timestamp: 1000n }), readContract: async ({ functionName }) => {
    if (functionName === 'evidence') return address;
    if (functionName === 'GAME_PERIOD') return 86400n;
    throw typedError;
  },
} };
const checked = await checkProofFutureAnchor(proofChain, 8, { evtBlock: 10000, logIndex: 0 }, '0x' + '00'.repeat(32));
ok(checked.unavailableError instanceof ArchiveUnavailableError, 'futureAnchorsHashの読取失敗も型付き');
proofReport.unverified('check.stageC.futureAnchorsHash', checked.unavailableError, { reason: checked.reason });
eq(verificationCoverage(proofReport).find((r) => r.area === 'proofHistory').reason, 'archiveUnavailable', 'F-10: 証明の行で未検証');
ok(render(proofReport).includes(`${tr('summary.area.proofHistory')}: ${tr('summary.areaUnverified', { reason: tr('reason.archiveUnavailable') })}`), '証明の状態をまとめに表示');

// ZKP収集失敗のアノマリーも、RPCから文を組む場所で投影する。
// 証明収集の返値だけを差し込み、暗号処理と前ブロック証跡の別検査をこの表示試験から分ける。
const unavailableProofModule = await load('../src/stages/results.js', (s) => {
  s = s.replace('  inspectProofSubmission,', '  inspectProofSubmission as actualInspectProofSubmission,')
    .replace('  await verifyPrevRegistrationWitness(ctx, S, lastEvent, inspected.resolvedSubmission);', '');
  if (mutation === 'anomaly_projection') s = s.replace('conciseRpcText(inspected.publicValues.error, ctx.ui?.t)', 'inspected.publicValues.error');
  return s;
}, `const inspectProofSubmission = async () => ({
  format: {status: 'unavailable', error: ${JSON.stringify(rpcFailure().message)}},
  publicValues: {status: 'unavailable', cause: 'rpc_unavailable', error: ${JSON.stringify(rpcFailure().message)}},
});`);
const unavailableProofReport = createReport();
const unavailableProofState = { files: {summary: {raw:'{}'}, manifest: {data:{files:{}}}}, blockState:{root:'0x'+'11'.repeat(32)},
  zkInfo: {kind:'proof', epoch:{index:0}}, anomalies:[] };
await unavailableProofModule.verifyZkpSubmission({ blockNum:8, report:unavailableProofReport, data:{}, cfg:{pins:{}}, ui:{t:tr} }, unavailableProofState, {});
noRaw(unavailableProofState.anomalies.join('\n'), 'ZKP収集の警告文');
noRaw(render(unavailableProofReport), 'ZKP収集のFAIL詳細');
const headlessState = {...unavailableProofState, anomalies:[]};
await unavailableProofModule.verifyZkpSubmission({ blockNum:8, report:createReport(), data:{}, cfg:{pins:{}} }, headlessState, {});
noRaw(headlessState.anomalies.join('\n'), 'UIを省略した直接呼出も維持');

// §4: 説明画面とまとめの行名は単一の定義だけから出す。余計な文は入れない。
for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang), lines = publicnodeExplanation(translate);
  const expected = [translate('main.publicnodeIntro')];
  for (const historical of [false, true]) {
    expected.push(translate(historical ? 'main.publicnodeCannot' : 'main.publicnodeCan'));
    expected.push(...VERIFICATION_AREAS.filter((r) => r.historical === historical).map((r) => `  ・${translate(`summary.area.${r.area}`)}`));
  }
  eq(lines, expected, `${lang}: 同じ行名・指定の構成だけ`);
  ok(lines.indexOf(`  ・${translate('summary.area.evidence')}`) < lines.indexOf(translate('main.publicnodeCannot')), 'Evidenceは検証できることに入る');
}
if (!mutation) for (const name of ['real_message', 'probe_getCode', 'projection', 'labelled_projection', 'stage_projection', 'whole_line', 'coverage_domains', 'coverage_archive', 'not_applicable', 'invalid_cause', 'full_on_skip', 'anomaly_projection', 'stale_probe_head']) {
  const child = spawnSync(process.execPath, [new URL(import.meta.url).pathname, `--mutation=${name}`], { encoding: 'utf8', timeout: 30000 });
  eq(child.status, 1, `${name}: 変異を検出`);
  ok(child.stderr.includes('AssertionError'), `${name}: import失敗ではなくassertで赤`);
}
console.log(`fix2-archive-unit: PASS (${assertions} assertions; 13 mutants killed)`);
