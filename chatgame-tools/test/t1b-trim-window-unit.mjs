import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { makeMaxAggregateFixture, makeServerLimitBoundaryFixture } from '../../workers/game_workers/script/test-calculator/_max-submission-fixture.mjs';
import { EVIDENCE_MAX_DATA_BYTES, EVIDENCE_TRIM_ORDER } from '../../workers/game_workers/lib/evidence-trim.js';
import { planOnChainTrim } from '../../src/utils/evidence.js';
import { planOnChainTrim as planRecovery } from '../src/recovery/submit.js';
import { buildSubmissionBundle } from '../src/recovery/bundle.js';
import { encodeEvidenceCompactV1, compactBytesToPayload } from '../../workers/game_workers/lib/evidence-compact-v1.js';
import { clientWindowedReceipts } from '../../workers/game_workers/lib/protocol-v2.js';
import { loadConfirmedChatWindow, saveConfirmedChatWindow } from '../../src/utils/relay.js';
import { buildScenario } from './scenario.mjs';

const expected = ['H','G','F','E','C','D','R','A','B','V'];
const order = process.env.T1B_MUTATION === 'old_trim'
  ? ['H','G','F','E','D','A','C','B'] : EVIDENCE_TRIM_ORDER;
assert.deepEqual(order, expected, 'P6-1: 密告→安全余裕→自己集約→下限チャット→投票');
const fixture = await makeMaxAggregateFixture();
const [official, recovery] = await Promise.all([
  planOnChainTrim(fixture.payload, fixture.submitter.uid),
  planRecovery(fixture.payload, fixture.submitter.uid),
]);
assert(official.beforeBytes >= EVIDENCE_MAX_DATA_BYTES && official.afterBytes < EVIDENCE_MAX_DATA_BYTES,
  'P6-1: 実際に130,000バイトへ収める');
assert.equal(official.protectedV, 1, '投票受領証明が独立級');
assert.equal(official.droppedV, 0, '投票受領証明を最後まで残す');
assert.deepEqual(recovery.classCounts, official.classCounts, '復元と公式の分類は同一');
assert.deepEqual(recovery.trimmedBundle.encryptedActions.observed.receipts,
  official.trimmedBundle.encryptedActions.observed.receipts, '復元と公式の保持集合は同一');
const pressure = await makeServerLimitBoundaryFixture();
const pressurePlan = await planOnChainTrim(compactBytesToPayload(pressure.compactBytes), pressure.uid);
assert(pressurePlan.beforeBytes >= EVIDENCE_MAX_DATA_BYTES
  && pressurePlan.afterBytes < EVIDENCE_MAX_DATA_BYTES,
  'P6-1: すべての級に圧力を掛けて130,000バイト未満に収める');
assert(pressurePlan.droppedR > 0 && pressurePlan.droppedB > 0
  && pressurePlan.droppedV === 0,
  'P6-1: 密告の対を合否チャット級より先に削り、投票を保持する');
const underLimit = compactBytesToPayload(encodeEvidenceCompactV1(
  official.trimmedBundle, official.compactContext));
assert.equal(await planOnChainTrim(underLimit, fixture.submitter.uid), null,
  'P6-2: トリム不要のバイト列はそのまま返す');
const honest = await buildScenario();
const honestPayload = (await honest.makeP2Recovery({})).payload;
assert.equal(await planOnChainTrim(honestPayload, honest.players[1].uid), null,
  'P6-2: トリム不要の正直な署名済み提出物は不変');

const storageMap = new Map();
const storage = {getItem:k=>storageMap.get(k)||null,setItem:(k,v)=>storageMap.set(k,v)};
const window = {startMs:100,endMs:200};
assert(saveConfirmedChatWindow(storage, 1, 2, 'roster-a', 110, window));
assert.deepEqual(loadConfirmedChatWindow(storage, 1, 2, 'roster-a', 110), window,
  'U-12: 開始時に確定した窓を再読み込みで再利用');
assert.equal(loadConfirmedChatWindow(storage, 1, 2, 'roster-b', 110), null,
  'U-12: 別名簿の窓は再利用しない');
const X={receiverUid:'H',senderUid:'V',msgRefs:['x'],timestamp:200,signature:'x'};
const Y={receiverUid:'H',senderUid:'V',msgRefs:['x','y'],timestamp:201,signature:'y'};
assert.deepEqual(clientWindowedReceipts([X,Y],window,'V'),[X],
  'U-12: 保存窓で期限外の真の上位集合Yを除きXを残す');
const signer=privateKeyToAccount('0x'+'11'.repeat(32));
const build = requireConfirmedWindow => buildSubmissionBundle({
  blockNum:1,groupId:1,myUid:'a',encryptKey:'0x'+'22'.repeat(32),
  members:[{uid:'a'},{uid:'b'},{uid:'c'}],messages:[],myDepositIds:[],receipts:[],
  chatWindow:null,requireConfirmedWindow,signWallet:message=>signer.signMessage({message}),
});
const fallback = await build(false);
assert(fallback.payload.length > 0, 'U-12: 窓とチェーンが読めなくても提出物を組める');
assert.deepEqual(clientWindowedReceipts([X,Y],null,'V'),[X,Y],
  'U-12: 窓なしでは既読を捨てない');
const officialSource=readFileSync(new URL('../../src/components/game/SubmissionPhase.js',import.meta.url),'utf8');
const recoverySource=readFileSync(new URL('../src/recovery/app.js',import.meta.url),'utf8');
assert(officialSource.includes('提出は続けられますが、窓による既読・行動受領証明の除外はしていません'));
assert(recoverySource.includes('窓による受領証明の除外をせずに提出します'));
assert(recoverySource.includes('requireConfirmedWindow: false'));
console.log('T1b trim/window: ALL PASSED');
