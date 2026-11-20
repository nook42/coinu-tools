import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {run as runResults} from '../src/stages/results.js';
import {createReport} from '../src/report.js';
import {DEFAULTS} from '../src/config.js';
import {GameMasterDO} from '../vendor/workers/game_workers/game-master-DO.js';
import {sha256HexOfString} from '../src/json-utils.js';
import {calculateGroupResults} from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import {computeDeclaredTimesMs} from '../vendor/workers/game_workers/lib/timeline-check.js';
import {buildRosterMemberCommitment} from '../vendor/workers/game_workers/lib/roster-member-root.js';
import {canonicalRosterText} from '../vendor/workers/game_workers/lib/roster-canonical.js';
import {makeWireG6Boards} from '../../Hardhat/bitcoinu/scripts/lib/make-wire-g6-boards.mjs';
import {compactBytesToPayload} from '../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import {hexToBytes} from 'viem';
const scratch=mkdtempSync(path.join(tmpdir(),'wr17e-level2-'));
const fixturePath=path.join(scratch,'d41.json');
const generator=fileURLToPath(new URL('./fixtures/d41/gen-band.mjs',import.meta.url));
const generated=spawnSync(process.env.NODE || process.execPath,[generator,fixturePath],{encoding:'utf8'});
assert.equal(generated.status,0,generated.stderr || generated.stdout);
const fx=JSON.parse(readFileSync(fixturePath,'utf8'));
const N=fx.blockNum, EVIDENCE='0x'+'22'.repeat(20),ETH_LOCK='0x'+'11'.repeat(20),HASH_STORAGE='0x'+'33'.repeat(20);
const open=(fx.windows.real.startMs+120000)/1000,close=(fx.windows.real.endMs-120000)/1000;
const resultOpen=close,resultClose=close+1000;
const addr=fx.frames[0].sender;
const members=fx.groups[0].members.map((m,i)=>({uid:m.uid,addr,bAddr:JSON.stringify({address:addr}),lang:'ja',depIds:'{"deposit":"0","ids":[]}',globalIndex:i,name:null,img:null,verified:false}));
const players=members.map((m,i)=>({globalIndex:i,localIndex:i,file:'00_0',data:m}));
const groupsDerived=[{groupId:0,lang:'ja',mixed:false,members:players}];
const rosterIndexText=JSON.stringify(new GameMasterDO({storage:{}},{}).buildRosterIndex([{group_id:0,members}]));
const rosterGroupText=canonicalRosterText(N,0,members);
const rosterManifestText=JSON.stringify({blockNum:N,indexSha256:sha256HexOfString(rosterIndexText),
 groups:[{groupId:0,sha256:sha256HexOfString(rosterGroupText)}]});
const roster={indexText:rosterIndexText,manifestText:rosterManifestText,groupTexts:new Map([[0,rosterGroupText]])};
const rosterHash = buildRosterMemberCommitment({blockNum:N,manifestText:roster.manifestText,groupTexts:roster.groupTexts}).C;
const d1Group = {block_num:N,group_id:0,members:JSON.stringify(members)};
const pinsBoard = (await makeWireG6Boards(path.join(scratch,'pins'),{boards:['zero-entries']}))[0];
const pinRules = JSON.parse(pinsBoard.r2Data.get('verification/block0/manifest.json')).rules;
const summary={schemaVersion:3,blockNum:N,majorLangs:[],timeline:null,groups:[{group_id:0,member_count:3,status:'completed',total_points:0,detailKey:`games/block${N}/group0.json`,claimOverlayKey:`games/block${N}/claim-status/group0.json`,members:members.map(m=>({userId:m.uid,address:addr,lang:'ja',total_points:0,is_disqualified:1,full_btcu_reward:'0'})),depositor_results:[]}],blockReward:'115384615384615000000000',resultLayout:'group-artifacts-v1',claimStatusKey:`games/block${N}/claim-status.json`,claimLayout:'group-overlays-v1'};
const gm=new GameMasterDO({storage:{}},{});
const root=gm.buildMerkleTree(N,gm.collectClaimEntriesFromSummary(N,summary)).root;
const declared=computeDeclaredTimesMs({startTimeMs:Number(fx.board.startTimeSec)*1000,
 blockTimeMs:Number(fx.board.blockIntervalSec)*1000,gamePeriodMs:Number(fx.board.gamePeriodSec)*1000,
 submitPeriodMs:1000_000,confirmations:DEFAULTS.pins.confirmationBlocks},N,Number(fx.board.evidenceGraceSec));
summary.timeline=gm.buildSummaryTimeline(declared,Number(fx.board.evidenceGraceSec));
const tx=i=>'0x'+i.toString(16).padStart(64,'0');
const events=fx.frames.map((f,i)=>({args:{blockNum:BigInt(N),seq:BigInt(i+1),sender:addr,data:f.data,timestamp:BigInt(close+100)},blockNumber:900n,transactionHash:tx(i+1)}));
const formatReport=(name)=>({contractAddress:EVIDENCE,blockNum:N,resultCount:3,window:{openAt:resultOpen,closeAt:resultClose},chatWindow:{chatOpenAt:open,chatCloseAt:close,clockSkewAllowMs:120000},safeBlock:'936',confirmations:64,adopted:fx.frames.flatMap((f,i)=>fx.js[`${i+1}.${name}`]==='accepted'?[{uid:f.uid,groupId:0,seq:i+1,txHash:tx(i+1),serverState:fx.js[`${i+1}.real`]==='accepted'?'identical':'missing'}]:[]),invalid:fx.frames.flatMap((f,i)=>fx.js[`${i+1}.${name}`]==='accepted'?[]:[{seq:i+1,txHash:tx(i+1),reason:'invalid_signature'}])});
function assertBlockZkp(files){
 const segments=files[`games/block${N}/zkp/evidence-segments.json`];
 const stage3=files[`verification/block${N}/stage3/manifest.json`];
 assert.equal(segments.schemaVersion,1);
 assert.equal(segments.segments.reduce((count,s)=>count+Number(s.frameCount),0),fx.frames.length);
 assert.equal(stage3.blockNum,N);
 assert.equal(stage3.groupCount,1);
 assert.deepEqual(stage3.groups.map(g=>[g.groupId,g.object]),[[0,`verification/block${N}/stage3/group-0.json`]]);
 assert.equal(stage3.groups[0].sha256,
  sha256HexOfString(JSON.stringify(files[`verification/block${N}/stage3/group-0.json`])));
}
async function run(name,damageZkp=null){
 const archive={meta:{blockNum:N,groupId:0},members,submissions:{},
  submissionsRaw:Object.fromEntries(fx.frames.filter((_,i)=>fx.js[`${i+1}.real`]==='accepted')
   .map(f=>[f.uid,compactBytesToPayload(hexToBytes(f.data))]))};
 gm.deriveSubmissionsFromRaw(archive,0);
 const scored=await calculateGroupResults({...structuredClone(archive),
  verifiedDepositWei:Object.fromEntries(members.map(m=>[m.uid,'0']))},
  DEFAULTS.pins.minChars,DEFAULTS.pins.minMessages,DEFAULTS.pins.chatCaps,fx.windows.real);
 const groupResult={groupId:0,members:scored.results,resolvedTaboos:scored.resolvedTaboos||{},
  canonicalTimeline:scored.canonicalTimeline};
 for(const member of groupResult.members){member.btcuReward='0';member.fullReward='0';member.playerShare='0';}
 archive.canonicalTimeline=scored.canonicalTimeline;
 gm.mutateR2ObjectWithCAS=async (_key,mutate)=>{mutate(archive);return {ok:true}};
 await gm.appendGameResultsToR2Groups(N,[groupResult],[],[d1Group]);
 const zkpWritten=new Map();
 gm.storage.get=async()=>null;
 gm.storage.put=async()=>{};
 gm.getR2Text=async (key)=>zkpWritten.has(key)?JSON.stringify(zkpWritten.get(key)):null;
 gm.putR2ObjectOrThrow=async (key,value)=>{zkpWritten.set(key,structuredClone(value));};
 await gm.publishEvidenceSegmentArtifact(N,fx.frames.map((f,i)=>({seq:i+1,rawBytes:(f.data.length-2)/2})));
 const stage3Pin=await gm.publishStage3GroupWitness({blockNum:N,groupRow:d1Group,groupData:archive,
  verifiedDepositWei:Object.fromEntries(members.map(m=>[m.uid,'0'])),chatWindow:fx.windows.real});
 gm.storage.list=async()=>new Map([[gm.calcKey(N,'score',0),{groupId:0,stage3:stage3Pin}]]);
 await gm.publishStage3InputManifest(N,[0]);
 const files={
  [`entries/block${N}/game_selection.json`]:{blockNum:N,players},
  [`entries/block${N}/game_groups.json`]:{blockNum:N,groups:[{groupId:0,memberIds:members.map(x=>x.uid)}]},
  [`games/block${N}/summary.json`]:summary,
  [`merkle/block_${N}.json`]:{blockNum:N,root,leafCount:0,totalAmount:'0',proofDepth:0,format:'v2'},
  [`verification/block${N}/evidence-report.json`]:formatReport(name),
  [`games/block${N}/zkp/evidence-segments.json`]:zkpWritten.get(`games/block${N}/zkp/evidence-segments.json`),
  [`verification/block${N}/stage3/manifest.json`]:zkpWritten.get(`verification/block${N}/stage3/manifest.json`),
  [`verification/block${N}/stage3/group-0.json`]:zkpWritten.get(`verification/block${N}/stage3/group-0.json`),
  [`games/block${N}/group0.json`]:archive,
  [`games/block${N}/roster/index.json`]:JSON.parse(roster.indexText),
  [`games/block${N}/roster/group0.json`]:JSON.parse(roster.groupTexts.get(0)),
 };
 files[`games/block${N}/roster/manifest.json`]=JSON.parse(roster.manifestText);
 assertBlockZkp(files);
 for(const damaged of ['segments','stage3']){
  const bad=structuredClone(files);
  if(damaged==='segments')bad[`games/block${N}/zkp/evidence-segments.json`].segments=[{garbage:true}];
  else bad[`verification/block${N}/stage3/manifest.json`].blockNum=999;
  assert.throws(()=>assertBlockZkp(bad),`${damaged}: invalid even if rehashed`);
 }
 const rules={...pinRules,startTime:Number(fx.board.startTimeSec)*1000,
  blockTime:Number(fx.board.blockIntervalSec)*1000,
  periodDurations:{gamePeriod:Number(fx.board.gamePeriodSec)*1000,submitPeriod:1000_000},
  evidence:{resultCount:3,adoptedCount:formatReport(name).adopted.length,chatWindowMs:fx.windows[name]}};
 const manifest={blockNum:N,algorithm:'sha256',rules,files:{}};
 for(const [key,v] of Object.entries(files)) manifest.files[key]=sha256HexOfString(JSON.stringify(v));
 delete manifest.files[`games/block${N}/roster/manifest.json`];
 delete manifest.files[`verification/block${N}/stage3/group-0.json`];
 manifest.manifestHash='0x'+sha256HexOfString(JSON.stringify({blockNum:N,algorithm:'sha256',rules:manifest.rules,files:manifest.files}));
 files[`verification/block${N}/manifest.json`]=manifest;
 if(damageZkp){
  const key=damageZkp==='segments'?`games/block${N}/zkp/evidence-segments.json`:`verification/block${N}/stage3/manifest.json`;
  files[key]={...files[key],blockNum:999,groupCount:42,segments:[{garbage:true}]};
 }
 const r2={baseDir:path.join(scratch,'cache'),async fetchJson(k){if(!(k in files))return null;
  const data=structuredClone(files[k]),raw=JSON.stringify(data),file=path.join(this.baseDir,k);
  mkdirSync(path.dirname(file),{recursive:true});writeFileSync(file,raw);
  return {data,raw,path:file}},async refetch(k){return this.fetchJson(k)},release(){},releaseRaw(){},async exists(k){return k in files}};
 mkdirSync(r2.baseDir,{recursive:true});
 const chain={
  client:{async getLogs({fromBlock,toBlock}){return events.filter(e=>e.blockNumber>=fromBlock&&e.blockNumber<=toBlock)} ,async readContract({functionName}){if(functionName==='getLock')return {amount:0n,idFrom:'0',idTo:'0',unlockTime:0n,lockOwnerAddress:addr,unlocked:false};throw Error('readContract '+functionName)}},
  blockStates:async()=>({root,verificationStartedAt:resultClose+100,zkEpochPlusOne:0,proofAttachedAt:0}),proofRequired:async()=>false,
  ethLockAddress:async()=>ETH_LOCK,evidenceAddress:async()=>EVIDENCE,
  getTimingConstants:async()=>({startTimeEntryMs:Number(fx.board.startTimeSec)*1000,blockTimeMs:Number(fx.board.blockIntervalSec)*1000,gamePeriodMs:Number(fx.board.gamePeriodSec)*1000,submitPeriodMs:1000_000,invariantOk:true}),
  getResultHash:async()=>({hash:manifest.manifestHash,updated:10}),resultRegistrationCount:async()=>1,
  getBlock:async(number)=>({timestamp:BigInt(Number(number)===10?resultOpen-1000:Number(number)===11?open+1:resultClose+10000),number:BigInt(number),hash:'0x'+'44'.repeat(32),mixHash:'0x'+'55'.repeat(32)}),
  latest:async()=>({number:1000n}),resultWindow:async()=>({openAt:resultOpen,closeAt:resultClose}),chatWindow:async()=>({chatOpenAt:open,chatCloseAt:close}),
  currentGrace:async()=>Number(fx.board.evidenceGraceSec),otherRegistrationCount:async()=>1,otherRegistrationAt:async()=>({hash:rosterHash,registeredBlock:11,registeredAt:open+10}),
  resultCount:async()=>3,evidenceAcc:async()=>fx.expectedAcc,
  findBlockByTimestamp:async()=>900n,merkleRootEvents:async()=>[{root,timestamp:resultClose+100,
   blockNumber:901n,transactionIndex:0,logIndex:0,transactionHash:tx(10)}],
  getBlockLifecycle:async()=>({mode:0,merkleRoot:root,verificationStartedAt:resultClose+100,
   verificationEndsAt:resultClose+700,claimEndsAt:resultClose+11500,stage:1}),
  verificationPeriod:async()=>600,claimPeriod:async()=>10800,
 };
 const report=createReport();const ctx={cfg:{lang:'ja',pins:DEFAULTS.pins,contracts:{ethLock:ETH_LOCK,evidence:EVIDENCE,hashStorage:HASH_STORAGE}},chain,r2,ui:{println(){},warn(){},t:k=>k},report,blockNum:N,data:{autoDistribute:false,noGame:false,groupsDerived,gameSelection:{players,targetBlockNum:164},reuseFiles:false,majorLangs:[]}};
 await runResults(ctx);
 return {report,stopReason:ctx.data.stopReason};
}
try {
 const expectedNegative=['check.stageC.chatWindowDeclared','check.stageC.evidenceReportMatch'];
 for(const name of ['real','short','long']){
  const {report,stopReason}=await run(name);
  assert.equal(stopReason,undefined,`${name}: ${stopReason}`);
  const failures=report.list().filter(x=>x.id.startsWith('check.stageC.')&&x.status==='fail');
  assert.deepEqual(failures.map(x=>x.id),name==='real'?[]:expectedNegative,
   `${name}: complete Stage C failure set ${JSON.stringify(failures)}`);
  for(const id of ['downloads','manifestSelfConsistent','manifestAnchor','evidenceCompleteness','scoring','summaryMatch','merkleRoot']){
   assert.equal(report.get(`check.stageC.${id}`)?.status,'pass',`${name} ${id}: ${JSON.stringify(report.get(`check.stageC.${id}`))}`);
  }
  assert.equal(report.get('check.stageC.chatWindowDeclared')?.status,
   name==='real'?'pass':'fail',`${name}: declared window`);
  const check=report.get('check.stageC.evidenceReportMatch');
  assert.equal(check?.status,name==='real'?'pass':'fail',`${name} evidenceReportMatch: ${JSON.stringify(check)}`);
  if(name==='real')assert.equal(check?.params?.notes,'-',`real evidence notes: ${JSON.stringify(check)}`);
  else {
   assert.match(check?.params?.notes ?? '',/adopted set differs/);
   assert.match(check?.params?.notes ?? '',/invalid list differs/);
  }
 }
 for(const damaged of ['segments','stage3']){
  const {report}=await run('real',damaged);
  assert.equal(report.get('check.stageC.manifestFiles')?.status,'fail',`${damaged} damaged public bytes`);
  console.log(`WR17E_LEVEL2_ZKP_REJECTED ${damaged} manifestFiles=fail`);
 }
 console.log('WR17E_LEVEL2_OK control=pass short=fail long=fail');
} finally {
 rmSync(scratch,{recursive:true,force:true});
}
