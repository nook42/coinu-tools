// FIX3: 実装の入口とRPC代役で、履歴不能と独立不正を分ける。通信なし。
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { custom } from 'viem';
import { ArchiveUnavailableError } from '../src/archive.js';
import { createReport, verificationCoverage } from '../src/report.js';
import { categorize, EXIT_CODE_OF } from '../src/index.js';
import { publicnodeExplanation } from '../src/verification-areas.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { TIMELINE_NO_GAME_CAUSES } from '../vendor/workers/game_workers/lib/timeline-check.js';
import { foldEvidenceAcc } from '../src/zkp.js';
import { hashLikeBackend } from '../src/json-utils.js';

const BASE = '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7';
const mutation = process.argv.find((a) => a.startsWith('--mutation='))?.split('=')[1];
let assertions = 0;
const eq = (a,b,m) => { assert.deepEqual(a,b,m); assertions++; };
const ok = (a,m) => { assert.ok(a,m); assertions++; };
const address = '0x' + '11'.repeat(20), zero = '0x' + '00'.repeat(32);
const tr = t('ja'), ui = { t: tr, println() {}, warn() {} };
const error = () => new ArchiveUnavailableError();
async function load(file, edit = s => s, extra = '', supplied = null) {
  const url = new URL(file, import.meta.url);
  const original = supplied ?? readFileSync(url, 'utf8');
  const edited = edit(original);
  if (mutation && edited !== original) ok(true, `${mutation}: 変異適用`);
  const source = edited.replace(/from '([^']+)'/g,
    (_,p) => `from '${p.startsWith('.') ? new URL(p,url).href : import.meta.resolve(p)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source + '\n' + extra).toString('base64')}`);
}
const result = await load('../src/stages/results.js', s => {
  if (mutation === 'finality_return') return s.replace("if (!invalidEmergencyCause && !knownFinalityMismatch) report.unverified('check.stageC.timelineNoGameFinality', error, { reason: 'archive_unavailable' });",
    "if (!invalidEmergencyCause && !knownFinalityMismatch) { report.unverified('check.stageC.timelineNoGameFinality', error, { reason: 'archive_unavailable' }); return false; }");
  if (mutation === 'merkle_relax') return s.replace("const unchecked = report.getFact('stageC.lockStateError') instanceof ArchiveUnavailableError;",
    "const unchecked = report.getFact('stageC.lockStateError') instanceof ArchiveUnavailableError || report.getFact('stageC.resultStateError') instanceof ArchiveUnavailableError;");
  if (mutation === 'acc_late') return s.replace('try { onchainEvidenceAcc = await ctx.chain.evidenceAcc(N, atSafe); }', 'try { /* moved below scan */ }')
    .replace('const onchain = onchainEvidenceAcc;', 'const onchain = await ctx.chain.evidenceAcc(N, atSafe);');
  if (mutation === 'dep_parse') return s.replace('    perUid[String(uid)] = parseEntryDepositIds(p.data.depIds);',
    "    JSON.parse(p.data.depIds);\n    perUid[String(uid)] = parseEntryDepositIds(p.data.depIds);");
  return s;
}, 'export { reproduceEvidence, runAutoDistribute, runAutoWithAvailableState };');
const { createChain } = await load('../src/chain.js', s => mutation === 'deployment_genesis'
  ? s.replace('const code = await client.getCode({ address, blockNumber: mid });',
    'let code; try { code = await client.getCode({ address, blockNumber: mid }); } catch (e) { if (e instanceof ArchiveUnavailableError) return 0n; throw e; }') : s);
const { createChain: baseChain } = await load('../src/chain.js', s=>s, '',
  execFileSync('git',['show',`${BASE}:block-verifier/src/chain.js`],{encoding:'utf8'}));
const membership = await load('../src/entry-membership.js', s => mutation === 'membership_list'
  ? s.replace('if (verified && !canonicalEqual({ entries: infos.map', 'if (false && verified && !canonicalEqual({ entries: infos.map')
  : mutation === 'membership_cache' ? s.replaceAll(', cacheOnly: true', '').replaceAll(', cacheOnly: verified', '') : s);
const coverageModule = await load('../src/report.js', s => mutation === 'timeline_na'
  ? s.replace('&& areaNotApplicable(report, entries)', '&& true') : s);

// 26,400,000高のRPC代役。拒否時はgenesisへ戻らず、その呼出元に型が到達する。
for (const unavailable of [true, false]) {
  const ranges = [], codeHeights = [], requests=[], head = 26400000n, deployment = head - 4000n;
  const chain = createChain({ chainIdExpected: 1, contracts: {}, rpcUrls: ['http://127.0.0.1:1'] }, ui,
    custom({ request: async ({method,params}) => {
      requests.push({method,params});
      if (method === 'eth_blockNumber') return '0x' + head.toString(16);
      if (method === 'eth_getCode') {
        const n = BigInt(params[1]); codeHeights.push(n);
        if (unavailable && n < head - 100n) throw { code: -32602, message: 'Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode' };
        return n < deployment ? '0x' : '0x6000';
      }
      if (method === 'eth_getLogs') { ranges.push(params[0]); return []; }
      throw new Error(`unexpected RPC ${method}`);
    } }, { retryCount: 0 }));
  let caught;
  try {
    const fromBlock = await chain.findContractDeploymentBlock(address);
    await chain.getLogsChunked({address,event:{type:'event',name:'Changed',inputs:[]},args:{},fromBlock,toBlock:head});
  } catch (e) { caught = e; }
  if (unavailable) {
    eq(ranges.length, 0, '履歴code不能ではgenesisのgetLogsを1回も呼ばない');
    ok(caught instanceof ArchiveUnavailableError, '生成高の型付き失敗を呼出元へ渡す');
    eq(codeHeights, [head, head / 2n], '最新と二分探索の最初だけで打ち切る');
  } else {
    eq(await chain.findContractDeploymentBlock(address), deployment, '読めるノードの二分探索の結果');
    eq(BigInt(ranges[0].fromBlock), deployment, 'ログは二分探索結果から読む');
    ok(codeHeights.length > 20 && codeHeights.length < 30, '二分探索を維持');
    const baseRequests=[];
    const reference=baseChain({chainIdExpected:1,contracts:{},rpcUrls:['http://127.0.0.1:1']},ui,custom({request:async({method,params})=>{
      baseRequests.push({method,params});
      if(method==='eth_blockNumber')return '0x'+head.toString(16);
      if(method==='eth_getCode')return BigInt(params[1])<deployment?'0x':'0x6000';
      if(method==='eth_getLogs')return [];
      throw new Error(method);
    }},{retryCount:0}));
    const fromBlock=await reference.findContractDeploymentBlock(address);
    await reference.getLogsChunked({address,event:{type:'event',name:'Changed',inputs:[]},args:{},fromBlock,toBlock:head});
    eq(requests,baseRequests,'読める場合は固定起点の二分探索とログRPCの全要求が一致');
  }
}

// FIX4: 配備高の失敗後もunlock起点の有限窓でrootの欠落を検出する。
{
  const report=createReport(), ranges=[];
  const ctx={blockNum:8,report,ui,cfg:{contracts:{tokenMining:address},pins:{}},data:{},chain:{
    latest:async()=>({number:26400000n}),findBlockByTimestamp:async()=>26399000,
    findContractDeploymentBlock:async()=>{throw error();},
    merkleRootEvents:async(_n,range)=>{ranges.push(range);return [];},
    verificationPeriod:async()=>100,claimPeriod:async()=>100,
    resultWindow:async()=>({closeAt:1000}),getBlockLifecycle:async()=>({mode:0,merkleRoot:zero,verificationStartedAt:0,verificationEndsAt:0,claimEndsAt:0,stage:1}),}};
  const S={groupIds:[],noGame:true,blockState:{root:zero},files:{summary:{data:{}}},anomalies:[],zkInfo:{kind:'shadow'}};
  await result.verifyTimeline(ctx,S,{startTimeEntryMs:0,blockTimeMs:1000,gamePeriodMs:1000,submitPeriodMs:1000});
  eq(ranges,[{fromBlock:26397000n,toBlock:26400000n}],'genesisではなく時刻の有限窓を走査する');
  eq(report.get('check.stageC.rootSubmissionRules').status,'fail','rootイベント0件はFAIL');
  eq(report.get('check.stageC.lifecycleReplayCurrent').status,'fail','FIX6: 現在getterの期間不正は履歴不足でもFAIL');
  ctx.chain.findContractDeploymentBlock=async()=>{throw new Error('ordinary deployment read error');};
  await assert.rejects(()=>result.verifyTimeline(ctx,S,{startTimeEntryMs:0,blockTimeMs:1000}),/ordinary deployment read error/);assertions++;
}

// T-1: no-gameの形に配分を混入。finalityの古い状態を読めなくても形とsummaryはFAIL。
const finality = { schemaVersion:1, evidenceContract:address, safeBlockNumber:'10000', safeTimestamp:1000,
  resultOpenAt:800, resultCloseAt:900, resultCount:0 };
const canonical = { schemaVersion:3, blockNum:8, blockReward:getBlockRewardWei(8).toString(), totalPlayers:3,
  totalGroups:0, noGame:true, majorLangs:[], groups:[], claimStatusKey:'games/block8/claim-status.json',
  claimLayout:'group-overlays-v1', noGameReason:'timeline_unverified', noGameCause:TIMELINE_NO_GAME_CAUSES[0], noGameFinality:finality };
const payout = {group_id:0, members:[{userId:'1',address,full_btcu_reward:'100'}]};
const gm = new GameMasterDO({ storage:{} }, {});
for (const unavailable of [true, false]) {
  const report = createReport(), published = {...canonical,totalGroups:1,groups:[payout]};
  const ctx = {blockNum:8,report,data:{gameSelection:{players:[{},{},{}]}},cfg:{pins:{confirmationBlocks:64}},ui,
    chain:{latest:async()=>({number:20000n}),findBlockByTimestamp:async()=>9000,getBlock:async()=>({timestamp:1000n}),
      resultWindow:async()=>{throw unavailable ? error() : new Error('ordinary RPC failure');},
      resultCount:async()=>0,evidenceAddress:async()=>address}};
  const S = {files:{summary:{data:published}},anomalies:[]};
  await result.verifyTimelineNoGameFinality(ctx,S);
  eq(report.get('check.stageC.timelineNoGameFinality')?.status, unavailable ? 'skip' : 'fail', 'finalityだけ型付き未検証/普通のエラーはFAIL');
  for (const id of ['timelineNoGameSummary','summaryMatch']) eq(report.get(`check.stageC.${id}`)?.status,'fail',`${id}: 配分混入はFAIL`);
  eq(EXIT_CODE_OF[categorize({report,fatal:false,stopped:false})],2,'配分混入はexit 2');
  ok(S.rebuiltSummary && S.rebuiltSummary.groups.length === 0,'0配分を独立再構築');
  const tree = gm.buildMerkleTree(8,gm.collectClaimEntriesFromSummary(8,published));
  ok(tree.leafCount > 0, '反証には実際に請求できる配分を載せる');
  S.files.merkle = {data:tree}; S.files.manifest = {data:{rules:{claimDataFormat:'wrong-format'}}}; S.blockState = {root:tree.root};
  ctx.cfg.pins.claimDataFormat = 'canonical-format';
  await result.verifyMerkle(ctx,S,gm);
  eq(report.get('check.stageC.merkleRoot')?.status,'fail','混入した配分のrootは合格にしない');
  // Evidence状態の失敗だけでroot照合を緩めない（別の読取失敗の再現）。
  report.fact('stageC.resultStateError', error());
  await result.verifyMerkle(ctx,S,gm);
  eq(report.get('check.stageC.merkleRoot')?.status,'fail','resultStateErrorでも独立再計算rootと照合する');
}
const honestReport=createReport(), honest={files:{summary:{data:canonical}},anomalies:[]};
await result.verifyTimelineNoGameFinality({blockNum:8,report:honestReport,data:{gameSelection:{players:[{},{},{}]}},cfg:{pins:{confirmationBlocks:64}},ui,
  chain:{latest:async()=>({number:20000n}),findBlockByTimestamp:async()=>9000,getBlock:async()=>({timestamp:1000n}),resultWindow:async()=>{throw error();},resultCount:async()=>0,evidenceAddress:async()=>address}},honest);
eq(honestReport.get('check.stageC.timelineNoGameSummary').status,'pass','正しいno-gameの形は履歴不能だけではFAILにしない');
eq(EXIT_CODE_OF[categorize({report:honestReport,fatal:false,stopped:false})],1,'finality未検証はpartial');

// N-1: 走査だけで41ブロック進む代役。accはcount直後、同じsafeNumberを読む。
const task=mkdtempSync(join(tmpdir(),'fix3-unit-'));
try {
  const order=[], report=createReport(); let elapsedBlocks=0n;
  const acc=foldEvidenceAcc(zero,address,'0x');
  const ctx={blockNum:0,report,data:{},cfg:{contracts:{evidence:address},pins:{confirmationBlocks:64,clockSkewAllowMs:0}},ui,
    r2:{baseDir:task},chain:{evidenceAddress:async()=>address,latest:async()=>({number:20000n}),getBlock:async()=>({timestamp:1000n}),
      resultWindow:async()=>({openAt:800,closeAt:900}),chatWindow:async()=>({chatOpenAt:600,chatCloseAt:700}),
      resultCount:async(_n,opts)=>{order.push(['count',opts.blockNumber]);return 1;},
      evidenceAcc:async(_n,opts)=>{order.push(['acc',opts.blockNumber]);if (elapsedBlocks>36n) throw error();return acc;},
      client:{getLogs:async({fromBlock,toBlock})=>{order.push(['logs']);elapsedBlocks=41n;return fromBlock<=19900n && toBlock>=19900n
        ? [{args:{blockNum:0n,seq:1n,sender:address,data:'0x',timestamp:850n},blockNumber:19900n,transactionHash:zero}] : [];}}}};
  const S={files:{manifest:{data:{rules:{evidence:{chatWindowMs:{startMs:600000,endMs:700000}}}}}},groupIds:[],groupDataList:[],anomalies:[]};
  await result.reproduceEvidence(ctx,S);
  eq(order.slice(0,2),[['count',19936n],['acc',19936n]],'count直後の同じ安全高でaccを確保');
  eq(report.get('check.stageC.evidenceAcc').status,'pass','7分相当の走査後も確保済みaccと比較する');
} finally {rmSync(task,{recursive:true,force:true});}

// N-2: 起点の実関数とも比較。壊れたdepIdsは[]、別の有効IDの履歴失敗で仮計算へ入る。
const baseSource=execFileSync('git',['show',`${BASE}:block-verifier/src/stages/results.js`],{encoding:'utf8'});
const baseline=await load('../src/stages/results.js',s=>s,'export { runAutoDistribute };',baseSource);
const dep={id:'1',idFrom:'1',amount:'1000000000000000000',depositerAddress:address,unlockTime:2000000};
const players=[{globalIndex:0,data:{uid:'1',addr:address,lang:'ja',depIds:JSON.stringify({deposit:dep.amount,ids:['1'],deposits:[dep]})}},
  {globalIndex:1,data:{uid:'2',addr:address,lang:'ja',depIds:'{broken'}}];
function sample(unavailable) {
  const gm=new GameMasterDO({storage:{}},{START_TIME:'1000000',BLOCK_TIME:'1000',ETH_LOCK_CONTRACT_ADDRESS:address});
  gm.readDepositSelectionK11=async()=>100n;
  gm.createReadOnlyClient=()=>({readContract:async()=>{if(unavailable)throw error();return {...dep,idTo:'1',lockOwnerAddress:address,unlocked:false};}});
  const ctx={blockNum:0,report:createReport(),cfg:{lang:'ja'},chain:{},data:{gameSelection:{players}},ui};
  return {ctx,gm,S:{files:{summary:{data:{}}},anomalies:[]}};
}
const baseSample=sample(false);await baseline.runAutoDistribute(baseSample.ctx,baseSample.S,baseSample.gm,{});
eq(baseSample.ctx.report.get('check.stageC.depositVerification').status,'pass','起点は壊れたdepIdsを空IDで継続');
for (const unavailable of [false,true]) {
  const s=sample(unavailable);await result.runAutoWithAvailableState(s.ctx,s.S,s.gm,{});
  eq(s.ctx.report.get('check.stageC.depositVerification').status,unavailable?'skip':'pass','壊れたdepIdsだけを理由に運営側FAILへ変えない');
  if(!unavailable) eq(s.ctx.report.get('check.stageC.depositVerification'),baseSample.ctx.report.get('check.stageC.depositVerification'),'読める場合は起点と状態/paramsが一致');
}

// R-3: Stage A直後に一覧が欠ける/差し替わる/キャッシュが欠ける。R2取り直しは禁じる。
for (const kind of ['missing','replaced','entry-missing']) {
  const report=createReport(), output=[], calls=[], infos=Array.from({length:100},()=>({entries:[]}));
  infos[0]={entries:[{filename:'00_0',number:1}]};
  const rows=[{uid:'1234'}];
  const ctx={blockNum:0,report,cfg:{contracts:{hashStorage:address}},chain:{hashStorageAddress:async()=>address},data:{infos,entryFileHashes:new Map([['00_0',hashLikeBackend(rows)]])},
    r2:{fetchJson:async(key,opts)=>{
      calls.push({key,opts});
      if (!opts?.cacheOnly) return {data:{entries:[]}}; // 欠落時のR2代役は抜かれた一覧を返す
      if(key.endsWith('/00_info.json'))return kind==='missing'?null:kind==='replaced'?{data:{entries:[]}}:{data:infos[0]};
      if(key.endsWith('/00_0.json'))return null;
      return {data:{entries:[]}};
    }}};
  const found=await membership.findEntry(ctx,'1234',true);
  eq(found.complete,false,`${kind}: 検証済み不在と断定できない`);
  ok(calls.every(c=>c.opts?.cacheOnly===true),`${kind}: R2から取り直さない`);
  // verifyOwnEntryのYes経路に、Stage Aの直後の上記状態を差し込んで表示まで確認する。
  const mod=await load('../src/entry-membership.js',s=>s.replace("import { run as runEntries } from './stages/entries.js';",'const runEntries = async () => ({stop:false});')
    .replaceAll('stageAVerified = verificationCoverage(ctx.report).find((row) => row.area === \'entries\').verified;', 'stageAVerified = true;'));
  ctx.ui={t:tr,section(){},askYesNo:async()=>true,println:s=>output.push(s)};
  await mod.verifyOwnEntry(ctx,'1234',null);
  ok(output.at(-1)===tr('entry.verifyFailed')&&!output.includes(tr('entry.onchainAbsent'))&&!output.includes(tr('entry.onchainIncluded')),`${kind}: 最初の未検証の表示の後、写しの欠落は失敗の結論を出す`);
}

// R-4: 期間行に走った検査があれば、配布方式にかかわらず対象なしにしない。
for(const mode of ['noGame','autoDistributed']) {
  const report=createReport();report.fact(`stageC.${mode}`,true);
  report.check('check.stageC.timelineWindows','skip',{reason:'no_evidence_windows'});
  eq(coverageModule.verificationCoverage(report).find(r=>r.area==='timeline').notApplicable,true,'期間行が全てskipなら対象なし');
  for(const id of ['rootSubmitted','rootSubmissionRules','lifecycleReplayCurrent']) report.check(`check.stageC.${id}`,'pass');
  eq(coverageModule.verificationCoverage(report).find(r=>r.area==='timeline').notApplicable,false,`${mode}: 実施した期間行は対象なしにしない`);
}
for(const lang of SUPPORTED_LANGS) {
  const translate=t(lang), lines=publicnodeExplanation(translate);
  ok(lines.indexOf('  ・'+translate('summary.area.adminHistory'))>lines.indexOf(translate('main.publicnodeCannot')),'管理者履歴を同じ共通定義で検証できないことへ表示');
  ok(lines.indexOf('  ・'+translate('summary.area.timeline'))>lines.indexOf(translate('main.publicnodeCannot')),'配備高を要する期間履歴も検証できないことへ表示');
}
if(!mutation) for(const name of ['deployment_genesis','finality_return','merkle_relax','acc_late','dep_parse','membership_list','membership_cache','timeline_na']) {
  const child=spawnSync(process.execPath,[new URL(import.meta.url).pathname,`--mutation=${name}`],{encoding:'utf8',timeout:30000});
  eq(child.status,1,`${name}: 変異で赤`);ok(child.stderr.includes('AssertionError'),`${name}: 起動失敗ではなく歯で検出`);
}
console.log(`fix3-verifier-unit: PASS (${assertions} assertions; 8 mutants killed)`);
