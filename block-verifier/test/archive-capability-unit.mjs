// FIX1: p1〜p3 の反証を、実装を通す歯と7件の変異にする。通信はcustom transportのみ。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { custom, HttpRequestError, encodeAbiParameters, parseAbiParameters } from 'viem';
import * as archive from '../src/archive.js';
import * as reports from '../src/report.js';
import * as index from '../src/index.js';
import { createChain as originalChain } from '../src/chain.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';

const mutation = process.argv.find((a) => a.startsWith('--mutation='))?.split('=')[1];
async function load(file, edit = (s) => s, extra = '') {
  const url = new URL(file, import.meta.url);
  const source = edit(readFileSync(url, 'utf8'))
    .replace(/from '([^']+)'/g, (_, p) => `from '${p.startsWith('.') ? new URL(p, url).href : import.meta.resolve(p)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source + '\n' + extra).toString('base64')}`);
}
let { historicalStateFailure, archiveProbe, ArchiveUnavailableError } = archive;
let { createReport, verificationCoverage } = reports;
let { categorize, emitNonInteractiveOutcome, makeUi } = index;
let createChain = originalChain;
if (mutation === 'S1') ({ createReport } = await load('../src/report.js', (s) => s.replace('    const error = facts.get', "    if (/header not found/.test(params.error || '')) status = 'skip';\n    const error = facts.get")));
if (mutation === 'S2') ({ categorize } = await load('../src/index.js', (s) => s.replace("  if (outcome.report.list().some((e) => e.reason === 'archive_unavailable')) return 'partial';", '')));
if (mutation === 'S3') ({ createChain } = await load('../src/chain.js', (s) => s.replace('      try { return await original(request); }', "      if (historical && archiveCapability.status === 'unavailable') throw new ArchiveUnavailableError();\n      try { return await original(request); }")));
if (mutation === 'F1') ({ historicalStateFailure } = await load('../src/archive.js', (s) => s.replace('  const seen = new Set();', "  if (error?.code === -32602) return ARCHIVE_UNAVAILABLE;\n  const seen = new Set();")));
if (mutation === 'F2') ({ verificationCoverage } = await load('../src/report.js', (s) => s.replace("&& e.id !== 'check.system.productionParams'", "&& false")));
if (mutation === 'F4') ({ makeUi } = await load('../src/index.js', (s) => s.replace('redactRpcText(value, configRpcUrls(cfg))', 'redactRpcText(conciseRpcText(value, translate), configRpcUrls(cfg))')));
if (mutation === 'probe_available' || mutation === 'probe_unavailable') ({ archiveProbe } = await load('../src/archive.js', (s) => mutation === 'probe_available'
  ? s.replace("status: reason === ARCHIVE_UNAVAILABLE ? 'unavailable' : 'unknown'", "status: 'available'")
  : s.replace("status: /^0x[0-9a-f]+$/i.test(code ?? '') ? 'available' : 'unknown'", "status: 'unavailable'")));
const resultModule = await load('../src/stages/results.js', (s) => mutation === 'F3'
  ? s.replace('  return provisionalDepositInputs(ctx, gm);', '  try { return provisionalDepositInputs(ctx, gm); } catch { return null; }') : s,
'export { runAutoWithAvailableState as runAutoDistribute, reproduceEvidence, skipHistoricalDeposits };');
const { runAutoDistribute, reproduceEvidence, skipHistoricalDeposits } = resultModule;
let assertions = 0;
function eq(a, b, msg) { assert.deepEqual(a, b, msg); assertions++; }
const tr = t('ja');

// S1 / p1: 運営が制御する検証材料の語句を、能力判定にもSKIPにも使わない。
const report = createReport();
for (const params of [
  { error: 'decode: [claimdata] non-canonical uid: "header not found"' },
  { error: 'HTTP request failed. Status: 403 URL: https://x Request body: {}' },
  { field: 'name', published: 'archive requests are fun', rebuilt: 'Alice' },
  { error: 'archive_unavailable' },
]) {
  report.check('check.stageC.onchainClaimData', 'fail', params);
  eq(report.get('check.stageC.onchainClaimData').status, 'fail', 'S1: 検証データの文言でFAILを消さない');
  assert.equal(report.get('check.stageC.onchainClaimData').params, params); assertions++;
}
const dataError={error:'decode: non-canonical uid: "HTTP request failed. header not found"'};
eq(reports.displayParams(dataError,tr),dataError,'F4: decodeの検証エラーをRPC表示に置き換えない');
eq(resultModule.classifyDepositVerificationError({code:'archive_unavailable'}),'mismatch','S1: 符号だけの偽エラーは型付き失敗ではない');
// F1: code×応答本文の総当たり。引数/URL/要求body/ラッパーmessageは使わない。
for (const code of [-32000, -32001, -32002, -32602, -32603, 3, undefined]) {
  for (const message of ['missing trie node 0xbeef', 'state not available', 'no state available for block 1',
    'world state unavailable', 'state at block 1 pruned', 'history has been pruned', 'historical state unavailable',
    'pruned state', 'archive node required', 'Archive requests require a personal token',
    'header not found', 'Invalid params', 'execution reverted', 'request args: 403 archive node']) {
    const expected = [-32000, -32001, -32002, -32602].includes(code)
      && !['header not found', 'Invalid params', 'execution reverted', 'request args: 403 archive node'].includes(message);
    eq(historicalStateFailure({ code, message }), expected ? 'archive_unavailable' : 'rpc_unavailable', `F1: ${code}/${message}`);
  }
}
for (const error of [
  new Error('missing trie node'), new Error('timeout header not found'),
  Object.assign(new Error('contract reverted URL: https://archive.example'), { cause: { code: 3, message: 'execution reverted' } }),
  new Error('Contract Call args: (403)'), { status: 403 },
  { message: 'fetch failed', cause: { status: 403 } },
  { status: 500, cause: { code: -32000, message: 'missing trie node' } },
  { name: 'ContractFunctionExecutionError', shortMessage: 'missing trie node', url: 'archive', body: { code: -32000, message: 'missing trie node' } },
]) eq(historicalStateFailure(error), 'rpc_unavailable', 'F1: 要求や一般文から推測しない');
for (const details of ['"Archive requests require a personal token"', '{"code":-32602,"message":"Archive requests require a personal token"}']) {
  const error = new HttpRequestError({ status: 403, details, url: 'https://x/key', body: { args: 'header not found' } });
  eq(historicalStateFailure(error), 'archive_unavailable', 'F1: viemの応答欄のみ');
}
const denied = { code: -32602, message: 'Archive requests require a personal token' };
let probeCalls = 0;
const probe = archiveProbe({ getBlockNumber: async () => 20000n, request: async () => { probeCalls++; throw denied; } }, { chainIdExpected: 1 });
eq((await probe()).status, 'unavailable', '能力試験'); await probe(); eq(probeCalls, 1, '接続ごとに一回');
for (const response of [{ code: -32602, message: 'Invalid params' }, { code: -32000, message: 'header not found' }, { status: 503 }]) {
  eq((await archiveProbe({ getBlockNumber: async () => 20000n, request: async () => { throw response; } }, { chainIdExpected: 1 })()).status, 'unknown', '一般失敗を能力不足と断定しない');
}
eq((await archiveProbe({ getBlockNumber: async () => 20000n, request: async () => '0x6000' }, {chainIdExpected:1})()).status, 'available', '読める能力試験');

// S3: probeが拒否されても、安全高のgetCode/eth_callは実際にtransportへ届く。
let safeReads = 0, historicalReads = 0;
const address = '0x'+'11'.repeat(20);
const chain = createChain({ chainIdExpected: 31337, rpcUrls: ['http://127.0.0.1:1'], contracts: { tokenMining: address } }, null,
  custom({ request: async ({method, params}) => {
    if (method === 'eth_blockNumber') return '0x4e20';
    const height = method === 'eth_getCode' ? params[1] : params[1];
    if (height === '0x4de0') { safeReads++; return method === 'eth_call' ? encodeAbiParameters(parseAbiParameters('uint256'), [42n]) : '0x6000'; }
    historicalReads++; throw denied;
  } }, { retryCount: 0 }));
await chain.probeArchive();
await assert.doesNotReject(async () => eq(await chain.client.getCode({ address, blockNumber: 19936n }), '0x6000', 'S3: safe codeは読む')); assertions++;
eq(await chain.client.readContract({address,blockNumber:19936n,abi:[{type:'function',name:'value',stateMutability:'view',inputs:[],outputs:[{type:'uint256'}]}],functionName:'value'}),42n,'S3: safe eth_callは読む');
await assert.rejects(chain.client.getCode({ address, blockNumber: 100n }), ArchiveUnavailableError); assertions++;
eq([safeReads,historicalReads],[2,2],'拒否された読みだけ型付きエラー');
const evidenceReport = createReport(); let evReads = 0;
const evRead = (value) => async (_n, opts) => { eq(opts,{blockNumber:19936n},'S3: atSafeを保持'); evReads++; return value; };
const evCtx = { blockNum:0,report:evidenceReport,data:{},cfg:{contracts:{evidence:address},pins:{confirmationBlocks:64,clockSkewAllowMs:0}},ui:{t:tr,println(){}},
  chain:{archiveCapability:{status:'unavailable'},evidenceAddress:async()=>address,latest:async()=>({number:20000n}),getBlock:async()=>({timestamp:1000n}),resultWindow:evRead({openAt:800,closeAt:900}),chatWindow:evRead({chatOpenAt:600,chatCloseAt:700}),resultCount:evRead(0),evidenceAcc:evRead('0x'+'00'.repeat(32))}};
await reproduceEvidence(evCtx,{files:{manifest:{data:{rules:{evidence:{chatWindowMs:{startMs:600000,endMs:700000}}}}}},groupIds:[],groupDataList:[],anomalies:[]});
eq(evReads,4,'S3: 旧probeと無関係にEvidenceを再現');
eq(evidenceReport.get('check.stageC.evidenceCompleteness').status,'pass','S3: 読めた完全性は従来のpass');
eq(evidenceReport.getFact('stageC.safeStateUnchecked'),undefined,'S3: latestによる代用なし');
// 読めないgetterだけ未検証。accの失敗で読めた完全性の検査を巻き戻さない。
const isolated = createReport();
const isolatedCtx = { ...evCtx, report: isolated, chain: { ...evCtx.chain,
  evidenceAcc: async () => { throw new ArchiveUnavailableError(); } } };
await reproduceEvidence(isolatedCtx,{files:{manifest:{data:{rules:{evidence:{chatWindowMs:{startMs:600000,endMs:700000}}}}}},groupIds:[],groupDataList:[],anomalies:[]});
eq(isolated.get('check.stageC.evidenceCompleteness').status,'pass','S3: 読めた検査を保持');
eq(isolated.get('check.stageC.evidenceAcc').status,'skip','S3: 実際に拒否されたgetterだけ未検証');
eq(categorize({report:isolated,fatal:false,stopped:false}),'partial','S3: acc読取不能はpartial');


// S2 / p2: 長いdiffでも比較の不一致と前提不足を両方保持。exit 1。
const partial = createReport();
partial.fact('stageC.lockStateError', new ArchiveUnavailableError()); partial.fact('stageC.lockStateUnchecked',true);
partial.unverified('check.stageC.depositVerification', new ArchiveUnavailableError(), {reason:'archive_unavailable'});
const longParams={ mode:'neutralized', diffs:'groups[0].members[0].name: "header not found" '.repeat(30), diffCount:20 };
partial.check('check.stageC.summaryMatch','fail',longParams);
eq(partial.get('check.stageC.summaryMatch').params,longParams,'S2: 比較データはそのまま');
eq(categorize({fatal:false,stopped:false,report:partial}),'partial','S2: 前提不明はfullではない');
const lines=[]; partial.renderSummary({t:tr,println:s=>lines.push(s),redactText:String},{blockNum:8,data:{}});
const output=lines.join('\n');
assert.ok(output.indexOf(tr('summary.comparisonMismatch',{checks:'check.stageC.summaryMatch'}))<output.indexOf(tr('summary.coverageVerified'))); assertions++;
eq(partial.get('check.stageC.summaryMatch').comparisonStatus,'fail','S2: SKIP詳細を省いても比較結果は記録に保持');
assert.ok(output.includes(tr('summary.area.scoring') + ': ' + tr('summary.areaUnverified',{reason:tr('reason.archiveUnavailable')}))); assertions++;
const markers=[];
eq(emitNonInteractiveOutcome({println:s=>markers.push(s)},{fatal:false,stopped:false,report:partial},null).exitCode,1,'S2: partial exit1');
assert.ok(markers.includes('##COMPARISON check.stageC.summaryMatch fail archive_unavailable')); assertions++;
// F2: productionParamsだけを除外。配線の破損は全領域を未検証にする。
for (const lang of SUPPORTED_LANGS) {
  const r=createReport();
  for(const id of ['check.stageA.rootMatch','check.stageA.earlyFreeze','check.stageB.playersMatch','check.stageB.randao','check.stageB.groupsMatch']) r.check(id,'pass');
  r.check('check.system.productionParams','fail');
  eq(verificationCoverage(r).find(x=>x.area==='entries').verified,true,'F2: 期間不一致は別掲');
  r.check('check.system.evidenceWiring','fail');
  eq(verificationCoverage(r).find(x=>x.area==='entries').verified,false,'F2: 配線FAILを見る');
  const text=[];r.renderSummary({t:t(lang),println:s=>text.push(s)},{blockNum:8,data:{}});
  assert.ok(!text.join('\n').includes(t(lang)('conclusion.entries',{block:8}))); assertions++;
}
// F3 / p3: provisional入力の上限違反は握り潰さず、元の失敗として残す。
const badGm={calcCollectDepositIds(){throw new Error('deposit ID limit exceeded');}};
assert.throws(()=>skipHistoricalDeposits({blockNum:0,data:{gameSelection:{players:[]}},report:createReport(),ui:{t:tr,warn(){}}},{},badGm,new ArchiveUnavailableError()),/limit exceeded/); assertions++;
assert.throws(()=>skipHistoricalDeposits({}, {}, {},new Error('header not found')),/header not found/);assertions++;
// F4 / p3: 自由な検証材料を含む行は表示でも失わない。
let shown='';const write=process.stdout.write;process.stdout.write=(s)=>{shown+=s;return true;};
try {
  const ui = makeUi(tr,{isInteractive:false},{});
  ui.println('summaryMatch 不一致 {"diffs":"header not found vs Alice"}');
  ui.println('HTTP request failed. summaryMatch 不一致 {"diffs":"header not found vs Alice"}');
  ui.println('##CHECK check.stageC.summaryMatch fail');
}
finally {process.stdout.write=write;}
assert.ok(shown.includes('HTTP request failed. summaryMatch 不一致') && shown.includes('##CHECK check.stageC.summaryMatch fail'),'F4: println全体を短文化しない');assertions++;

// 本物のauto経路: typed読取失敗でだけ仮計算へ進み、独立した入力破損はFAIL。
const dep={id:'1',idFrom:'1',amount:'1000000000000000000',depositerAddress:address,unlockTime:2000000};
const player={globalIndex:0,data:{uid:'1',addr:address,lang:'ja',depIds:JSON.stringify({deposit:dep.amount,ids:['1'],deposits:[dep]})}};
function sample(unavailable, summary={}) {
  let reads=0;
  const gm=new GameMasterDO({storage:{}},{START_TIME:'1000000',BLOCK_TIME:'1000',ETH_LOCK_CONTRACT_ADDRESS:address});
  gm.readDepositSelectionK11=async()=>100n;
  gm.createReadOnlyClient=()=>({readContract:async()=>{reads++;if(unavailable)throw new ArchiveUnavailableError();return {...dep,idTo:'1',lockOwnerAddress:address,unlocked:false};}});
  const ctx={blockNum:0,report:createReport(),cfg:{lang:'ja'},chain:{archiveCapability:{status:unavailable?'unavailable':'available'}},data:{gameSelection:{players:[player]}},ui:{t:tr,println(){},warn(){}}};
  return {ctx,gm,S:{files:{summary:{data:summary}},anomalies:[]},reads:()=>reads};
}
const seed=sample(false);await runAutoDistribute(seed.ctx,seed.S,seed.gm,{});assert.ok(seed.S.rebuiltSummary);assertions++;
for(const unavailable of [false,true]) {
  const s=sample(unavailable,seed.S.rebuiltSummary);eq(await runAutoDistribute(s.ctx,s.S,s.gm,{}),true,'autoは最後まで計算');
  eq(s.reads(),1,'能力の先回り省略なし');
  eq(s.ctx.report.get('check.stageC.summaryMatch').status,unavailable?'skip':'pass','前提未検証なら合格にしない');
  eq(categorize({report:s.ctx.report,fatal:false,stopped:false}),unavailable?'partial':'full','型付き失敗の終了状態');
}
const badAuto=sample(true,seed.S.rebuiltSummary);
const collect=badAuto.gm.calcCollectDepositIds.bind(badAuto.gm);let collectCalls=0;
badAuto.gm.calcCollectDepositIds=(...args)=>{if(++collectCalls>1)throw new Error('deposit ID limit exceeded');return collect(...args);};
eq(await runAutoDistribute(badAuto.ctx,badAuto.S,badAuto.gm,{}),false,'F3: 仮計算の上限超過は中断');
eq(badAuto.ctx.report.get('check.stageC.depositVerification').status,'fail','F3: 上限超過をSKIPへ変換しない');
eq(categorize({report:badAuto.ctx.report,fatal:false,stopped:false}),'fail','F3: 上限超過はexit2');
if(!mutation) for(const id of ['S1','S2','S3','F1','F2','F3','F4','probe_available','probe_unavailable']) {
  const child=spawnSync(process.execPath,[new URL(import.meta.url).pathname,`--mutation=${id}`],{encoding:'utf8',timeout:20000});
  eq(child.status,1,`${id}: 変異は歯で検出`);
  assert.ok(child.stderr.includes('AssertionError'),`${id}はimport失敗でなくassertで赤`);assertions++;
}
console.log(`archive-capability-unit: PASS (${assertions} assertions; S1–S3/F1–F4 + two probe mutants killed)`);
