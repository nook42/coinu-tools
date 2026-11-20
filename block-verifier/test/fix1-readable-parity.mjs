// 固定起点の実物と現在の実物を、同じ応答表を返すHardhat代役で比較する。
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, cpSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { custom } from 'viem';
import { generateFixture } from './gen-fixture.mjs';
import { verificationCoverage } from '../src/report.js';
const BASE='08f7ef70556b7aca19aa4fdab25a4c127fbf47f7';
const V7_START='c97eec70f38e3d6fbb81806a8d15421b49dbf8f6';
const repo=resolve(import.meta.dirname,'../..');
const task=mkdtempSync(join(tmpdir(),'fix1-readable-parity-'));

// V7 I1: 08f7ef705 との351レコード比較は一切緩めない。
// 追加でV7開始時の実物とも比較し、許す差を次の3つの名前に限定する。
// (a) summary.guarantee.adminHistory の本文（Donate未走査なら既存の短文）、
// (b) system.audit の superAdminChanges / donateAdminChanges / donateChecked、
// (c) 管理者履歴の eth_getLogs の topics[0] を2つのtopic0のORへ変更すること。
// この4場面は31337なので履歴走査は対象外。(c)を使った応答表の共用・正規化はせず、
// RPCはeth_blockNumberだけを除き、順序・引数まで完全一致させる。
// viem 2.42.0 の getBlockNumber は client.cacheTime（既定4,000ms）の間だけ
// 応答を使い回すため、この要求の件数は実行時刻に依る。ほかの要求は除外しない。
// mainnet分岐の(c)はv7-superadmin-audit-unitが実viemで縛る。
function checkV7Requests(current, start, label) {
  const withoutBlockNumber = (requests) => requests.filter((request) => request.method !== 'eth_blockNumber');
  assert.deepEqual(withoutBlockNumber(current), withoutBlockNumber(start),
    `${label}: (c)の対象外のRPCはeth_blockNumber以外の全要求・順序・引数が同一`);
}
function v7Snapshot(outcome, mod, requests) {
  const summaries = {};
  for (const lang of ['ja', 'en', 'zh']) {
    const lines = [];
    outcome.report.renderSummary({ t: mod.i18n.t(lang), println: (line) => lines.push(line) }, { blockNum: 0, data: {} });
    summaries[lang] = lines;
  }
  return { audit: outcome.report.getFact('system.audit'), summaries, requests };
}
function checkV7Parity(current, start, currentMod, startMod, label) {
  const { superAdminChanges, donateAdminChanges, donateChecked, ...existingAudit } = current.audit;
  assert.deepEqual([superAdminChanges, donateAdminChanges, donateChecked], [[], [], false], `${label}: I1(b)の3追加欄だけ`);
  assert.deepEqual(existingAudit, start.audit, `${label}: 既存audit欄を保持`);
  checkV7Requests(current.requests, start.requests, label);
  for (const lang of ['ja', 'en', 'zh']) {
    const before = startMod.i18n.t(lang), after = currentMod.i18n.t(lang);
    const prefix = `  ${before('summary.area.adminHistory')}: `;
    const oldRow = prefix + before('summary.guarantee.adminHistory');
    const newRow = prefix + after(donateChecked ? 'summary.guarantee.adminHistory' : 'summary.areaVerified');
    assert.deepEqual(current.summaries[lang], start.summaries[lang].map((line) => line === oldRow ? newRow : line),
      `${label}/${lang}: I1(a)の名指した1本文だけを許す`);
  }
}

// FIX5: 正典で作った自動配布・応募0件の実レコードから、期間行の表示も確かめる。
function checkNonGameTimeline(outcome, mod, label) {
  const report = outcome.report, translate = mod.i18n.t('ja');
  const records = structuredClone(report.list());
  const id = 'check.stageC.rootSubmitted', original = report.get(id);
  assert.equal(original.status, 'pass', `${label}: root提出の検査は実行済み`);
  assert.equal(report.get('check.stageC.timelineWindows').status, 'skip');
  assert.equal(report.get('check.stageC.timelineWindows').params.reason, 'no_evidence_windows');
  function expectRow(verified, reason) {
    const row = verificationCoverage(report).find((entry) => entry.area === 'timeline');
    assert.equal(row.verified, verified, `${label}: 期間行の表示判定`);
    assert.equal(row.notApplicable, false, `${label}: 実行済みの期間検査を対象なしにしない`);
    if (!verified) assert.equal(row.reason, reason);
    const lines = [];
    report.renderSummary({ t: translate, println: (line) => lines.push(line) }, { blockNum: 0, data: {} });
    const expected = `  ${translate('summary.area.timeline')}: ${translate(
      verified ? 'summary.areaVerified' : 'summary.areaUnverified', verified ? {} : { reason: translate(`reason.${reason}`) })}`;
    assert.ok(lines.includes(expected), `${label}: ${expected}`);
  }
  expectRow(true);
  try {
    report.check(id, 'fail', original.params);
    expectRow(false, 'failed');
    assert.equal(mod.index.EXIT_CODE_OF[mod.index.categorize(outcome)], 2);
    report.unverified(id, new mod.archive.ArchiveUnavailableError(), original.params);
    expectRow(false, 'archiveUnavailable');
    assert.equal(mod.index.EXIT_CODE_OF[mod.index.categorize(outcome)], 1);
  } finally {
    report.check(id, original.status, original.params);
    Object.assign(report.get(id), original);
  }
  assert.deepEqual(report.list(), records, `${label}: 注入後も全レコードを元に戻して固定起点と比較`);
  console.log(`COVERAGE ${label}: 期間行は検証できた; FAILは不合格; 型付き未検証は未検証`);
}

try {
  // cacheTimeの境界を待たず、要求列だけで除外の範囲を確かめる。
  const requests = [
    { method: 'eth_getCode', params: ['0x0000000000000000000000000000000000000001', '0x170'] },
    { method: 'eth_getLogs', params: [{ address: '0x0000000000000000000000000000000000000001', fromBlock: '0x1', toBlock: '0x170' }] },
  ];
  const blockNumber = { method: 'eth_blockNumber', params: [] };
  const cached = [blockNumber, ...requests];
  const expired = [blockNumber, requests[0], blockNumber, requests[1], blockNumber];
  assert.doesNotThrow(() => checkV7Requests(cached, expired, 'cacheTime境界'));
  assert.doesNotThrow(() => checkV7Requests(requests, expired, 'eth_blockNumberなし'));
  const changed = structuredClone(expired);
  changed[1].params[1] = '0x171';
  for (const different of [changed, expired.filter((r) => r.method !== 'eth_getLogs'),
    [...expired, { method: 'eth_chainId', params: [] }], [...expired].reverse()]) {
    assert.throws(() => checkV7Requests(different, cached, 'ほかのRPCの差'), { code: 'ERR_ASSERTION' });
  }
  console.log('RPC PARITY: eth_blockNumberの件数差だけを許容; 他RPCの引数・欠落・追加・順序の差は検出');
  const modules=[];
  for(const version of ['base','current','v7-start']) {
    const root=join(task,version), bv=join(root,'block-verifier');mkdirSync(bv,{recursive:true});
    for(const name of ['Hardhat','tools','crates','node_modules'])symlinkSync(join(repo,name),join(root,name));
    for(const name of ['vendor','scripts'])symlinkSync(join(repo,'block-verifier',name),join(bv,name));
    writeFileSync(join(root,'package.json'),'{"type":"module"}');
    if(version!=='current') {
      const hash=version==='base'?BASE:V7_START;
      const files=execFileSync('git',['ls-tree','-r','--name-only',hash,'--','block-verifier/src'],{cwd:repo,encoding:'utf8'}).trim().split('\n');
      for(const file of files){const dest=join(root,file);mkdirSync(dirname(dest),{recursive:true});writeFileSync(dest,execFileSync('git',['show',`${hash}:${file}`],{cwd:repo}));}
    } else cpSync(join(repo,'block-verifier/src'),join(bv,'src'),{recursive:true});
    const archive = version === 'current' ? await import(pathToFileURL(join(bv,'src/archive.js'))) : null;
    modules.push({version,archive,index:await import(pathToFileURL(join(bv,'src/index.js'))),chain:await import(pathToFileURL(join(bv,'src/chain.js'))),config:await import(pathToFileURL(join(bv,'src/config.js'))),i18n:await import(pathToFileURL(join(bv,'src/i18n.js')))});
  }
  for(const scenario of [null,{name:'FIX1-auto',players:[{uid:'20000001',lang:'ja',eth:'1.0'}],externalDepositors:[]},{name:'FIX1-no-game',players:[],externalDepositors:[]}]) {
    const label=scenario?.name||'FIX1-game';let fx;
    try {
      fx=await generateFixture({outDir:join(task,label),scenario});
      const cfgFile=join(task,'config.json');writeFileSync(cfgFile,JSON.stringify({chainIdExpected:31337,rpcUrls:[fx.chainInfo.rpcUrl],contracts:fx.chainInfo.contracts,dataDir:join(task,'data'),r2Base:'http://127.0.0.1:1'}));
      const table=new Map();const actualFetch=globalThis.fetch;let observed=[];
      const answer=async({method,params=[]})=>{
        observed.push(structuredClone({method,params}));
        const key=JSON.stringify({method,params});
        if(!table.has(key)) {
          const res=await actualFetch(fx.chainInfo.rpcUrl,{method:'POST',body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
          table.set(key,await res.json());
        }
        const row=structuredClone(table.get(key));if(row.error)throw row.error;return row.result;
      };
      const outcomes=[], v7=[];
      for(const mod of modules) {
        observed=[];
        const cfg=mod.config.loadConfig(['--config',cfgFile,'--non-interactive','--lang','en','--block','0','--artifact-dir',fx.r2Dir]);
        const ui={t:mod.i18n.t('en'),println(){},warn(){},askYesNo:async()=>true,isInteractive:false};
        const chain=mod.chain.createChain(cfg,ui,custom({request:answer},{retryCount:0}));
        if(chain.probeArchive)await chain.probeArchive();
        const outcome=await mod.index.verifyOneBlock(cfg,chain,ui,0);
        if (mod.version === 'current' && scenario) {
          const coverage = verificationCoverage(outcome.report);
          assert.equal(coverage.find((row) => row.area === 'evidence').notApplicable, true,
            `${label}: Evidenceは対象なし`);
          assert.equal(coverage.find((row) => row.area === 'timeline').notApplicable, false,
            `${label}: root履歴と期間の検査を実行した行は対象なしにしない`);
          assert.equal(outcome.report.get('check.stageC.lifecycleReplayCurrent').status, 'pass');
          checkNonGameTimeline(outcome, mod, label);
        }
        outcomes.push({checks:outcome.report.list(),category:mod.index.categorize(outcome),code:mod.index.EXIT_CODE_OF[mod.index.categorize(outcome)]});
        v7.push(v7Snapshot(outcome,mod,observed));
      }
      assert.deepEqual(outcomes[1],outcomes[0],`${label}: 全検査の状態・params・終了コードを固定起点と比較`);
      assert.deepEqual(outcomes[1],outcomes[2],`${label}: V7開始時とも全レコード同一`);
      checkV7Parity(v7[1],v7[2],modules[1],modules[2],label);
      assert.equal(outcomes[0].category,'full',`${label}: 元の正常系を合格に維持`);
      console.log(`PARITY ${label}: ${outcomes[0].checks.length} checks; all statuses/params equal; exit ${outcomes[0].code}; ${table.size} shared RPC answers; base=${BASE}`);
      if (!scenario) {
        const file=join(fx.r2Dir,'merkle/block_0.json');const original=readFileSync(file,'utf8');
        const value=JSON.parse(original);value.root='0x'+'11'.repeat(32);writeFileSync(file,JSON.stringify(value));
        const failures=[], v7Failures=[];
        for(const mod of modules) {
          observed=[];
          const cfg=mod.config.loadConfig(['--config',cfgFile,'--non-interactive','--lang','en','--block','0','--artifact-dir',fx.r2Dir]);
          const ui={t:mod.i18n.t('en'),println(){},warn(){},askYesNo:async()=>true,isInteractive:false};
          const chain=mod.chain.createChain(cfg,ui,custom({request:answer},{retryCount:0}));
          const result=await mod.index.verifyOneBlock(cfg,chain,ui,0);
          failures.push({checks:result.report.list(),category:mod.index.categorize(result),code:mod.index.EXIT_CODE_OF[mod.index.categorize(result)]});
          v7Failures.push(v7Snapshot(result,mod,observed));
        }
        assert.deepEqual(failures[1],failures[0],'readable node negative parity');assert.equal(failures[0].code,2);
        assert.deepEqual(failures[1],failures[2],'V7開始時とのnegative parity');
        checkV7Parity(v7Failures[1],v7Failures[2],modules[1],modules[2],'FIX1-readable-mismatch');
        writeFileSync(file,original);
        console.log(`PARITY FIX1-readable-mismatch: ${failures[0].checks.length} checks; all statuses/params equal; exit 2; base=${BASE}`);
      }

    } finally {fx?.stop();}
  }
} finally {rmSync(task,{recursive:true,force:true});}
