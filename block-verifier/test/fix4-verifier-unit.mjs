// FIX4: 履歴stateの失敗で独立した違反を消さない。実関数＋RPC代役、外部通信なし。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { custom, HttpRequestError } from 'viem';
import { ArchiveUnavailableError } from '../src/archive.js';
import { createReport, verificationCoverage } from '../src/report.js';
import { categorize, EXIT_CODE_OF } from '../src/index.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { adminCommitRootSubmissionDeadline } from '../vendor/workers/game_workers/lib/block-lifecycle.js';
const BASE='08f7ef70556b7aca19aa4fdab25a4c127fbf47f7';
const mutation=process.argv.find(a=>a.startsWith('--mutation='))?.split('=')[1];
let assertions=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);assertions++;};const ok=(a,m)=>{assert.ok(a,m);assertions++;};
async function load(file,edit=s=>s,supplied) {
 const url=new URL(file,import.meta.url), original=supplied??readFileSync(url,'utf8'), source=edit(original);
 if(mutation && source!==original) ok(true,`${mutation}: 変異適用`);
 return import(`data:text/javascript;base64,${Buffer.from(source.replace(/from '([^']+)'/g,(_,p)=>`from '${p.startsWith('.')?new URL(p,url).href:import.meta.resolve(p)}'`)).toString('base64')}`);
}
const address='0x'+'11'.repeat(20), other='0x'+'22'.repeat(20), root='0x'+'33'.repeat(32), hash='0x'+'44'.repeat(32);
const denied=()=>new ArchiveUnavailableError();const ui={t:t('ja'),println(){},warn(){}};
const results=await load('../src/stages/results.js',s=>{
 if(mutation==='timeline_return')return s.replace('      historyError = error;','      historyError = error; return;');
 if(mutation==='omission_return')return s.replace('  if (finalityUnchecked) {','  if (finalityUnchecked) { return {stop:true};');
 if(mutation==='finality_known')return s.replace('  } : finality;','  } : finality; /* mutation */').replace('...observedFinality','/* observed removed */');
 return s.replace('export function resolveProofProviderLabels(ctx, S) {', "export function resolveProofProviderLabels(ctx, S) { ctx.report.fact('fix4.labelsResolved', true);");
});
const {historicalStateFailure}=await load('../src/archive.js',s=>mutation==='code4444'?s.replace('if (response?.code === 4444)', 'if (false)'):s);
const {createChain}=await load('../src/chain.js',s=>{
 if(mutation!=='timestamp_genesis')return s;
 const a=s.indexOf('    let hi = latestBlock.number;',s.indexOf('  async function findBlockByTimestamp'));
 const b=s.indexOf('    while (lo < hi)',a);
 return s.slice(0,a)+'    let lo = 0n; let hi = latestBlock.number;\n'+s.slice(b);
});
const pruned={jsonrpc:'2.0',id:1,error:{code:4444,message:'pruned history unavailable: requested 13213332, earliest available 15500000'}};
for(const response of [pruned,pruned.error,new HttpRequestError({status:200,details:JSON.stringify(pruned.error),url:'http://127.0.0.1:1',body:{}})]) {
 eq(historicalStateFailure(response),'archive_unavailable','HTTP200の実publicnode応答を構造で判定');
}
eq(historicalStateFailure({code:4444,message:'history unavailable'}),'archive_unavailable','EIP-4444は本文に依らずcodeで判定');
eq(historicalStateFailure({...pruned.error,code:-32602}),'archive_unavailable','FIX10: pruned history unavailableの先頭を構造で判定');
for(const response of [new Error(pruned.error.message),{message:pruned.error.message},{message:'URL 4444',body:pruned}])eq(historicalStateFailure(response),'rpc_unavailable','表示文・要求本文で判定しない');
// 総当たり。重複timestamp・genesis・head・未来も従来のlower_boundと同じ。
const head=26400000n, earliest=15500000n, reads=[];
const chain=createChain({chainIdExpected:31337,contracts:{tokenMining:address},rpcUrls:['http://127.0.0.1:1']},ui,custom({request:async({method,params})=>{
 if(method==='eth_getBlockByNumber') {
  const n=params[0]==='latest'?head:BigInt(params[0]);reads.push(n);
  if(n<earliest)throw pruned.error;
  return {number:'0x'+n.toString(16),timestamp:'0x'+(n*12n).toString(16),hash:root};
 }
 throw new Error(method);
}},{retryCount:0}));
let found;try { found=await chain.findBlockByTimestamp(Number((head-2000n)*12n)); } catch(error) { found=error.name; }
eq(found,Number(head-2000n),'本番相当headで最近の対象を検索');
ok(reads.every(n=>n>=earliest),'倍々探索は最近の対象で保持範囲外を読まない');
await assert.rejects(()=>chain.getBlock(13213332),ArchiveUnavailableError);assertions++;
await assert.rejects(()=>chain.client.getBlock({blockNumber:13213332n}),ArchiveUnavailableError);assertions++;
for(let size=0;size<24;size++) {
 const stamps=Array.from({length:size+1},(_,i)=>Math.floor(i/2)*3);
 const tiny=createChain({chainIdExpected:31337,contracts:{},rpcUrls:['http://127.0.0.1:1']},ui,custom({request:async({params})=>{const n=params[0]==='latest'?size:Number(BigInt(params[0]));return {number:'0x'+n.toString(16),timestamp:'0x'+stamps[n].toString(16)};}},{retryCount:0}));
 for(let ts=-1;ts<=stamps.at(-1)+1;ts++)eq(await tiny.findBlockByTimestamp(ts),ts>stamps.at(-1)?size:stamps.findIndex(n=>n>=ts),'timestamp lower_bound総当たり');
}
function timeline({stamp=1000,empty=false,proof=false,unreadHeader=false}={}) {
 const report=createReport(),ranges=[];
 const event={root,timestamp:stamp,evtBlock:26399010,txHash:hash,transactionIndex:0,logIndex:0};
 const ctx={blockNum:8,report,ui,cfg:{contracts:{tokenMining:address},pins:{confirmationBlocks:64}},data:{},chain:{
  latest:async()=>({number:head}),findBlockByTimestamp:async()=>{if(unreadHeader)throw denied();return 26399000;},
  findContractDeploymentBlock:async()=>{throw denied();},merkleRootEvents:async(_n,r)=>{ranges.push(r);return empty?[]:[event];},
  verificationExtendedEvents:async()=>[],merkleRootInvalidatedEvents:async()=>[],merkleRootProofAttachedEvents:async()=>proof?[{...event,epochIndex:1,logIndex:1}]:[],
  verificationPeriod:async()=>100,claimPeriod:async()=>100,resultWindow:async()=>({closeAt:1000}),
  getBlockLifecycle:async()=>({mode:0,merkleRoot:root,verificationStartedAt:stamp,verificationEndsAt:stamp+100,claimEndsAt:stamp+200,stage:3}),
  client:{getTransaction:async()=>({to:address,input:'0xdeadbeef',hash,blockNumber:26399010n})},contracts:{tokenMining:address},
 }};
 const S={groupIds:[],noGame:true,files:{summary:{data:{}}},anomalies:[],blockState:{root,verificationStartedAt:stamp,proofAttachedAt:proof?stamp:0},zkInfo:{kind:proof?'proof':'shadow',epoch:{index:1,verifier:address,vkey:root}}};
 return {ctx,S,ranges};
}
const timing={startTimeEntryMs:0,blockTimeMs:100000,gamePeriodMs:100000,submitPeriodMs:100000};
for(const options of [{stamp:900},{stamp:799},{empty:true},{proof:true},{}]) {
 const {ctx,S,ranges}=timeline(options);await results.verifyTimeline(ctx,S,timing);
 eq(ranges,[{fromBlock:26397000n,toBlock:head}],'配備高不能でもunlock−2000の有限窓を走査');
 if(options.empty)eq(ctx.report.get('check.stageC.lifecycleReplayCurrent').status,'fail','FIX6: 現在rootと読めた空ログの矛盾はFAIL');
 else eq(ctx.report.get('check.stageC.lifecycleReplayCurrent').reason,'archive_unavailable','全履歴の再現だけ未検証');
 if(options.empty)eq(ctx.report.get('check.stageC.rootResubmitted').status,'fail','rootイベント0件はFAIL');
 if(options.stamp<1000||options.empty)eq(ctx.report.get('check.stageC.rootSubmissionRules').status,'fail','窓終了前/unlock前/欠落はFAIL');
 if(options.proof){eq(ctx.report.get('check.stageC.proofAttachmentEvent').status,'pass','proof付与イベントの検査へ到達');eq(ctx.report.get('check.stageC.zkProofFormat').status,'fail','calldataの不正をFAIL');}
 ok(ctx.report.getFact('stageC.claimWindow'),'現在getterの請求窓のfactを保持');
 ok(ctx.report.getFact('fix4.labelsResolved'),'providerラベルへ到達');
}
// ヘッダも配備高も読めなくても現在getterのfactsへ到達する。
{const {ctx,S}=timeline({unreadHeader:true,proof:true});await results.verifyTimeline(ctx,S,timing);eq(ctx.report.get('check.stageC.rootResubmitted').reason,'archive_unavailable','探索範囲も取得不能ならイベント数は未検証');ok(ctx.report.getFact('stageC.claimWindow'),'古いヘッダ不能で現在窓を捨てない');eq(ctx.report.get('check.stageC.zkProofFormat').reason,'archive_unavailable','proofの在処が分からない場合だけcalldata照合も未検証');}
// 延長のヘッダが無くてもログ上のcap超過は独立にFAIL。
{
 const {ctx,S}=timeline();ctx.chain.verificationExtendedEvents=async()=>[{timestampError:new ArchiveUnavailableError(),timestamp:null,newEndFloor:999999999,evtBlock:26399020,transactionIndex:0,logIndex:0}];
 await results.verifyTimeline(ctx,S,timing);
 eq(ctx.report.get('check.stageC.rootSubmissionRules').status,'fail','古い延長ヘッダ不能でもcap超過を隠さない');
 eq(ctx.report.get('check.stageC.lifecycleReplayCurrent').reason,'archive_unavailable','延長時刻だけが必要な全履歴照合は未検証');
}
{
 const {fetchClaimDataFromChain}=await import('../src/claim-data.js');
 const fetched=await fetchClaimDataFromChain({contracts:{tokenMining:address},client:{
  readContract:async({functionName})=>functionName==='claimDataOf'?[root,1n,1n]:[100n],
  getLogs:async()=>[],getBlock:async()=>{throw new ArchiveUnavailableError();},
 }},null,8);
 ok(fetched.unavailableError instanceof ArchiveUnavailableError,'請求データのブロック本体の拒否も型を保持');
 const anchor=await results.inspectResultManifestAnchor({getBlock:async()=>{throw new ArchiveUnavailableError();}},{hash:root,updated:100},root,1000);
 ok(anchor.unavailableError instanceof ArchiveUnavailableError,'manifest登録時刻の拒否も型を保持');
 const mismatch=await results.inspectResultManifestAnchor({getBlock:async()=>{throw new ArchiveUnavailableError();}},{hash:root,updated:100},'0x'+'22'.repeat(32),1000);
 eq(mismatch.status,'fail','manifest hashの不一致はヘッダの取得前にFAIL');
}
{
 const {checkProofFutureAnchor,futureAnchorsHash}=await import('../src/future-anchor.js');
 const futureChain={contracts:{tokenMining:address},client:{getBlock:async()=>({timestamp:1000n}),readContract:async({functionName,blockNumber})=>{
  if(blockNumber!=null)throw new ArchiveUnavailableError();return functionName==='evidence'?address:100n;
 }},getLogsChunked:async()=>[]};
 for(const claimed of ['0x'+'00'.repeat(32),futureAnchorsHash(8,100),root]){
  const checked=await checkProofFutureAnchor(futureChain,8,{evtBlock:100,logIndex:0},claimed);
  eq(checked.status,claimed===root?'fail':'skip','provider不明でも式と0のどちらでもないK13はFAIL');
 }
 const invalidRootTime=await results.inspectResultManifestAnchor({getBlock:async()=>{throw new ArchiveUnavailableError();}},{hash:root,updated:100},root,0);
 eq(invalidRootTime.status,'fail','登録ヘッダ不能でも現在のroot提出時刻の不正はFAIL');
}
const finality={schemaVersion:1,evidenceContract:address,safeBlockNumber:'10000',safeTimestamp:1000,resultOpenAt:800,resultCloseAt:900,resultCount:0};
const summary={schemaVersion:3,blockNum:8,blockReward:getBlockRewardWei(8).toString(),totalPlayers:3,totalGroups:0,noGame:true,majorLangs:[],groups:[],claimStatusKey:'games/block8/claim-status.json',claimLayout:'group-overlays-v1',noGameReason:'timeline_unverified',noGameCause:'chain_unreadable',noGameFinality:finality};
function noGame({count=0,readable=false,changed={}}={}) {
 const published={...summary,noGameFinality:{...finality,...changed}}, calls=[];
 const ctx={blockNum:8,report:createReport(),ui,cfg:{pins:{confirmationBlocks:64}},data:{gameSelection:{players:[{},{},{}]}},r2:{fetchJson:async key=>key.endsWith('/summary.json')?{data:published}:null},chain:{
  latest:async()=>({number:20000n,timestamp:BigInt(adminCommitRootSubmissionDeadline(900,100)+1)}),findBlockByTimestamp:async()=>9000,getBlock:async()=>({timestamp:1000n}),
  resultWindow:async(_n,opts)=>{calls.push(['window',opts.blockNumber]);if(!readable&&opts.blockNumber===10000n)throw denied();return {openAt:800,closeAt:900};},
  resultCount:async(_n,opts)=>{calls.push(['count',opts.blockNumber]);if(!readable&&opts.blockNumber===10000n)throw denied();return count;},
  evidenceAddress:async()=>address,verificationPeriod:async()=>100,
 }};return {ctx,S:{anomalies:[],zkInfo:{currentProofRequired:true}},calls};
}
for(const count of [1,0]) {
 const {ctx,S,calls}=noGame({count});await results.verifyTimelineNoGameRootOmission(ctx,S);
 ok(calls.some(([kind,height])=>kind==='count'&&height===19936n),'古いfinalityとは別に今の安全高を読む');
 eq(ctx.report.get('check.stageC.timelineNoGameEvidenceEmpty').status,count?'fail':'pass','現在のEvidence提出を見逃さない');
 eq(ctx.report.get('check.stageC.rootSubmitted').status,count?'fail':'skip','提出があればroot省略FAIL、0件でも古いfinalityは未検証');
 eq(ctx.report.get('check.stageC.timelineNoGameFinality').reason,'archive_unavailable','古いfinalityは合格にしない');
 eq(EXIT_CODE_OF[categorize({report:ctx.report,fatal:false,stopped:true})],count?2:1,'検閲FAIL/正当partialの終了コード');
 if(!count)ok(Number.isFinite(ctx.report.get('check.stageC.rootSubmitted').params.deadline),'未検証でも現在の窓から期限を計算');
}
for(const changed of [{evidenceContract:other},{safeTimestamp:999}]){
 const {ctx,S}=noGame({changed});S.files={summary:{data:{...summary,noGameFinality:{...finality,...changed}}}};
 await results.verifyTimelineNoGameFinality(ctx,S);
 for(const id of ['timelineNoGameFinality','timelineNoGameSummary','summaryMatch'])eq(ctx.report.get(`check.stageC.${id}`).status,'fail',`${Object.keys(changed)}の偽装は${id} FAIL`);
}
// 新しい経路も固定起点の実関数と比較（全レコード・params・category）。
const base=await load('../src/stages/results.js',s=>s,execFileSync('git',['show',`${BASE}:block-verifier/src/stages/results.js`],{encoding:'utf8'}));
for(const fn of ['verifyTimelineNoGameRootOmission','verifyTimelineNoGameFinality']){
 const records=[];for(const mod of [base,results]){const {ctx,S}=noGame({readable:true});S.files={summary:{data:summary}};await mod[fn](ctx,S);records.push({checks:ctx.report.list(),category:categorize({report:ctx.report,fatal:false,stopped:false})});}eq(records[1],records[0],`${fn}: 読める場合は固定起点と同じ`);
}
const {verifyOwnEntry}=await load('../src/entry-membership.js',s=>{
 s=s.replace("import { run as runEntries } from './stages/entries.js';",`const runEntries=async(ctx)=>{for(const id of ['rootMatch','earlyFreeze'])ctx.report.check('check.stageA.'+id,'pass');ctx.data.infos=Array.from({length:100},()=>({entries:[]}));ctx.data.entryFileHashes=new Map();return {stop:false};};`);
 if(mutation==='no_cache')s=s.replaceAll('cacheOnly: verified','cacheOnly: true');
 if(mutation==='wiring')s=s.replace("verified = typeof onchain === 'string'", "verified = true || typeof onchain === 'string'");
 return s;
});
for(const lang of SUPPORTED_LANGS)for(const yes of [false,true])for(const wired of [false,true]){
 let fetched=0,wiringCalls=0;const lines=[];
 const ctx={blockNum:8,report:createReport(),cfg:{contracts:{hashStorage:address}},data:{},chain:{hashStorageAddress:async()=>{wiringCalls++;return wired?address:other;}},ui:{t:t(lang),section(){},println:s=>lines.push(s),askYesNo:async()=>yes},r2:{baseDir:'/empty-fixture',fetchJson:async(_key,opts)=>{if(opts.cacheOnly&&!yes)return null;fetched++;return {data:{entries:[]}};}}};
 const found=await verifyOwnEntry(ctx,'123',null);
 eq(found.complete,true,'Noでも空保存から公開データを取得');ok(fetched===(yes?101:1),'自動確認の一覧1個に加え、Yesは検証済み一覧100個を読む');eq(wiringCalls,yes?1:0,'Yesのオンチェーン断定前に現在配線を1回読む');
 eq(found.verified,yes&&wired,'配線不一致では未確認');ok(!lines.includes(ctx.ui.t('entry.unknown')),'Noで運営データの欠落と表示しない');
 ok(lines.includes(ctx.ui.t('entry.onchainUnchecked')),'最初の自動確認は常に未検証');
 if(yes)eq(lines.at(-1),ctx.ui.t(wired?'entry.onchainAbsent':'entry.verifyFailed'),'配線を確認できた場合だけオンチェーン断定');
 else ok(!lines.includes(ctx.ui.t('entry.onchainIncluded'))&&!lines.includes(ctx.ui.t('entry.verifyFailed')),'Noは保証も検証失敗の結論も出さない');
}
for(const lang of SUPPORTED_LANGS){
 const report=createReport();for(const id of ['check.stageA.rootMatch','check.stageA.earlyFreeze','check.stageB.playersMatch','check.stageB.randao','check.stageB.groupsMatch'])report.check(id,'pass');
 report.check('check.main.fatal','fail',{error:'boom'});const rows=verificationCoverage(report);
 for(const area of ['entries','selection','grouping'])eq(rows.find(r=>r.area===area).verified,true,'中断前に記録が揃った行は合格を保持');
 eq(rows.find(r=>r.area==='scoring').reason,'stopped','未到達は既存のstopped');eq(EXIT_CODE_OF[categorize({report,fatal:true,stopped:false})],3,'fatal終了コード3を保持');
 report.fact('system.audit',{adminHistoryChecked:true,adminChangeError:'ordinary RPC error'});report.check('fact.system.adminRotationUnavailable','warn',{error:'ordinary RPC error'});
 eq(verificationCoverage(report).find(r=>r.area==='adminHistory').reason,'rpcRequestFailed','管理者履歴の警告を未到達としない');
 report.check('fact.system.adminRotationUnavailable','fail');eq(verificationCoverage(report).find(r=>r.area==='adminHistory').reason,'failed','管理者履歴FAILを未到達としない');
 report.check('check.system.hashStorageWiring','fail');ok(verificationCoverage(report).every(r=>!r.verified&&r.reason==='failed'),'system FAILは全行を止める');
}
if(!mutation)for(const name of ['code4444','timestamp_genesis','timeline_return','omission_return','finality_known','no_cache','wiring']){
 const child=spawnSync(process.execPath,[new URL(import.meta.url).pathname,`--mutation=${name}`],{encoding:'utf8',timeout:30000});eq(child.status,1,`${name}: 変異で赤`);ok(child.stderr.includes('AssertionError'),`${name}: 実際の歯で検出`);
}
console.log(`fix4-verifier-unit: PASS (${assertions} assertions; 7 mutants killed)`);
