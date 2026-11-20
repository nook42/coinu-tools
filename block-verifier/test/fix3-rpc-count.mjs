// 本番サイズのhead・直近100高だけ状態が読めるRPCを、プロセス内Hardhatで再現する。
// FIX2_RESULT §6のoffline guard / Hardhat config / memory R2を必須にする。
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { custom } from 'viem';
import { generateFixture } from './gen-fixture.mjs';
import { rpc, startNode } from './chain-setup.mjs';
import { loadConfig } from '../src/config.js';
import { createChain } from '../src/chain.js';
import { verifyOneBlock, categorize } from '../src/index.js';
import { verificationCoverage } from '../src/report.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { t } from '../src/i18n.js';

assert.equal(process.env.E2E_IN_PROCESS,'1');
assert.equal(process.env.R2_FIXTURE_IN_MEMORY,'1');
assert.ok(process.env.NODE_OPTIONS?.includes('fix1-offline-guard.cjs'));
const dir=mkdtempSync(join(tmpdir(),'fix3-rpc-count-'));let fx;
try {
  const node=await startNode();
  // fixture自体も保持範囲内へ置く。配備高探索のhead/2は実publicnode同様に古い。
  await rpc(node.rpcUrl,'hardhat_mine',['0x'+(26396000n).toString(16),'0x0']);
  fx=await generateFixture({outDir:dir,node});
  const current=BigInt(await rpc(fx.chainInfo.rpcUrl,'eth_blockNumber'));
  const head=26400000n;
  await rpc(fx.chainInfo.rpcUrl,'hardhat_mine',['0x'+(head-current-128n).toString(16),'0xc']);
  // EDRの一括採掘の中間ヘッダにはblob gas欄が無い。直近のstateを読む128高は実採掘する。
  for(let i=0;i<128;i++) await rpc(fx.chainInfo.rpcUrl,'evm_mine');
  const actualFetch=globalThis.fetch, counts={}, refused={}, ranges=[], oldCodeRequests=[];
  const request=async({method,params=[]})=>{
    counts[method]=(counts[method]||0)+1;
    if (method==='eth_chainId') return '0x1'; // fixtureの契約値はそのまま、mainnetの監査分岐を通す
    if (method==='eth_getLogs') ranges.push(params[0]);
    if (method==='eth_getBlockByNumber' && params[0]!=='latest' && BigInt(params[0])<15500000n) {
      refused[method]=(refused[method]||0)+1;
      throw {code:4444,message:`pruned history unavailable: requested ${BigInt(params[0])}, earliest available 15500000`};
    }
    if (['eth_call','eth_getCode'].includes(method) && /^0x[0-9a-f]+$/i.test(params[1]||'') && BigInt(params[1]) < head-100n) {
      refused[method]=(refused[method]||0)+1;
      if(method==='eth_getCode')oldCodeRequests.push({address:params[0],height:params[1]});
      throw {code:-32602,message:'Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode'};
    }
    const response=await actualFetch(fx.chainInfo.rpcUrl,{method:'POST',body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
    const body=await response.json();if(body.error)throw body.error;return body.result;
  };
  const cfgFile=join(dir,'config.json');
  // donateはSuperAdminChanged/AdminChangedログだけを使うため、fixtureの任意の配備済み契約で代役。
  writeFileSync(cfgFile,JSON.stringify({chainIdExpected:1,rpcUrls:[fx.chainInfo.rpcUrl],contracts:{...fx.chainInfo.contracts,donate:fx.chainInfo.contracts.ethLock},dataDir:join(dir,'data')}));
  const cfg=loadConfig(['--config',cfgFile,'--non-interactive','--lang','ja','--block','0','--artifact-dir',fx.r2Dir]);
  const lines=[];const ui={t:t('ja'),println:(s='')=>lines.push(s),warn:(s='')=>lines.push(s),askYesNo:async()=>true,isInteractive:false};
  const chain=createChain(cfg,ui,custom({request},{retryCount:0}));
  await chain.probeArchive();
  await assert.rejects(()=>chain.getBlock(13213332),ArchiveUnavailableError);
  const outcome=await verifyOneBlock(cfg,chain,ui,0);
  assert.ok(!outcome.fatal,'1ブロックの検証が完了する');
  for(const id of ['fact.system.adminRotationUnavailable','fact.system.donateEventUnavailable']) {
    assert.equal(outcome.report.get(id)?.status,'warn',id);
    assert.equal(outcome.report.get(id)?.reason,'archive_unavailable',id);
    assert.ok(outcome.report.get(id)?.params?.error.includes('archive_unavailable'),id);
  }
  const audit=outcome.report.getFact('system.audit');
  assert.deepEqual([audit.superAdminChanges,audit.donateAdminChanges,audit.donateChecked],[[],[],true],
    'V7: 配備高を読めなくてもDonate走査を試みた事実と新欄を保持');
  assert.equal(audit.adminChangeArchiveErrors.length,3);
  assert.ok(audit.adminChangeArchiveErrors.every(e=>e instanceof ArchiveUnavailableError));
  assert.ok(audit.donateEventArchiveError instanceof ArchiveUnavailableError);
  const row=verificationCoverage(outcome.report).find(r=>r.area==='adminHistory');
  assert.deepEqual([row.verified,row.reason],[false,'archiveUnavailable']);
  assert.equal(outcome.report.get('check.stageC.lifecycleReplayCurrent')?.reason,'archive_unavailable');
  assert.equal(outcome.report.get('check.stageC.evidenceCompleteness')?.status,'pass');
  assert.equal(outcome.report.get('check.stageC.evidenceAcc')?.status,'pass');
  assert.equal(outcome.report.get('check.stageC.rootResubmitted')?.status,'skip');
  assert.equal(outcome.report.get('check.stageC.rootResubmitted')?.reason,'archive_unavailable');
  assert.equal(outcome.report.get('check.stageC.rootSubmissionRules')?.reason,'archive_unavailable');
  assert.ok(outcome.report.getFact('stageC.claimWindow'));
  assert.equal(refused.eth_getBlockByNumber,1,'明示した古いヘッダ以外、最近の窓の探索は保持範囲内');
  // fixtureのEvidence提出は低い高さにあるため、固定の小さな窓が0から始まるのは正当。
  assert.ok(ranges.every(r=>BigInt(r.fromBlock)>0n || BigInt(r.toBlock)<10000n),'genesisからheadへ向かう全履歴走査はゼロ');
  assert.ok((counts.eth_getLogs||0)<100,'呼出回数がhead比例で増えない');
  const expectedOldCodeAddresses=new Set([cfg.contracts.tokenMining,cfg.contracts.evidence,cfg.contracts.hashStorage,cfg.contracts.donate].map(s=>s.toLowerCase()));
  assert.equal(oldCodeRequests.length,5,'システム4契約＋結果履歴1回の二分探索だけ');
  assert.ok(oldCodeRequests.every(r=>expectedOldCodeAddresses.has(r.address.toLowerCase())&&BigInt(r.height)===head/2n));
  const unexpected=outcome.report.list().filter(e=>e.status==='fail'&&e.id!=='check.system.productionParams');
  assert.deepEqual(unexpected,[],'本番期間差以外の独立不正は無い');
  console.log('FIX3_RPC_COUNT '+JSON.stringify({head:String(head),players:8,checks:outcome.report.list().length,category:categorize(outcome),counts,refused,
    getLogsRanges:ranges.map(r=>({from:String(BigInt(r.fromBlock)),to:String(BigInt(r.toBlock))})),oldCodeRequests}));
  outcome.report.renderSummary(ui,{blockNum:0,cfg,r2:{baseDir:fx.r2Dir},data:{}});
  // FIX13: 同じpublicnode代役の実レコードを、実際の対話UIで採取できる。
  const summaryOut=process.argv.find(arg=>arg.startsWith('--summary-out='))?.slice(14);
  if(summaryOut) {
    const {makeUi}=await import('../src/index.js');
    const chunks=[],original=process.stdout.write,records=structuredClone(outcome.report.list());
    process.stdout.write=chunk=>{chunks.push(String(chunk));return true;};
    try {
      outcome.report.renderSummary(makeUi(t('ja'),{isInteractive:true},{...cfg,nonInteractive:false}),
        {blockNum:0,cfg,r2:{baseDir:fx.r2Dir},data:{}});
    } finally {process.stdout.write=original;}
    assert.deepEqual(outcome.report.list(),records,'実UIの描画も検査レコードを変えない');
    const summary=chunks.join('');
    assert.ok(summary.includes('='.repeat(60)+'\n'+t('ja')('summary.title',{block:0})));
    assert.ok(!summary.includes('--------'));
    writeFileSync(summaryOut,summary);
  }
  console.log(lines.filter(s=>s.includes('管理者の交代')||s.includes('履歴を取得')||s.includes('SuperAdminChanged')).join('\n'));
  console.log('fix3-rpc-count: PASS');
} finally {fx?.stop();rmSync(dir,{recursive:true,force:true});}
