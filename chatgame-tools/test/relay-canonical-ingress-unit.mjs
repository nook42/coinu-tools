// C25-01 / V25-03: 復元クライアントの Nostr chat ingress が
// 正典ブラウザと同じ canonical signature/uid/text/timestamp 集合だけを受理する。

import assert from 'node:assert/strict';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { chatSignStringV2, receiptSignString, readReceiptSignString, compareHexAsc } from '../vendor/src/utils/protocol.js';
import { ReceiptAdmissionQueue, GameRelayChannel, receiptIdentityDigest } from '../vendor/src/utils/relay.js';
import { makeVerifyRelayInner } from '../src/recovery/relay-verify.js';
import { deriveBlockAddress } from '../vendor/src/utils/walletTools.js';

const BLOCK = 25;
const GROUP = 2;
const UID = '12345';
const key = generatePrivateKey();
const account = privateKeyToAccount(key);
const bAddr = JSON.parse(deriveBlockAddress(key, BLOCK).blockAddress);
const relay = new RecoveryRelay({
  signKey: key,
  blockNum: BLOCK,
  groupId: GROUP,
  uid: UID,
  members: [{ uid: UID, bAddr }],
});

async function signed(uid, text, timestamp) {
  const signature = await account.signMessage({
    message: chatSignStringV2(BLOCK, GROUP, uid, text, timestamp),
  });
  return { uid, text, timestamp, signature };
}

let passed = 0;
let failed = 0;
async function check(name, value, expected) {
  const got = await relay._verifyChat(value);
  if (got === expected) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name} — got=${got} expected=${expected}`); }
}

const valid = await signed(UID, 'canonical chat', 1_750_000_000_000);
await check('正準 chat を受理', valid, true);

// R13-06 案Y: +2分の既存受理窓内は破棄せず、app.js が timestamp 到来まで表示を保留する。
// _verifyChat でこれを拒否すると、時刻到来後に表示できる原データ自体が消える。
await check('+2分窓内の未来 chat を保留用に受理', await signed(
  UID,
  'held future chat',
  Date.now() + 60_000,
), true);
await check('+2分窓を超える未来 chat を既存ゲートで拒否', await signed(
  UID,
  'too-far future chat',
  Date.now() + 121_000,
), false);

{
  const realNow = Date.now;
  const baseNow = realNow();
  let clockNow = baseNow;
  const heldRelay = new RecoveryRelay({ signKey: key, blockNum: BLOCK, groupId: GROUP,
    uid: UID, members: [{ uid: UID, bAddr }],
    getChatWindow: () => ({ startMs: baseNow - 1000, endMs: baseNow + 240_000 }) });
  const held = await signed(UID, 'clock-skew one second', baseNow + 120_001);
  try {
    Date.now = () => clockNow;
    await heldRelay._ingestChat(held);
    assert.equal(heldRelay.getMessages().length, 0, 'U-13: future message remains outside display and bundle');
    clockNow += 1;
    await heldRelay._ingestChat(held);
    assert.equal(heldRelay.getMessages().length, 0, 'Q18: elapsed time does not accept a marked message');
    console.log('  ok: +2分を1秒超える発言を捨てて同じページでは取り込まない');
  } finally { Date.now = realNow; heldRelay.stop(); }
}

await check('大文字hex署名を拒否', {
  ...valid,
  signature: `0x${valid.signature.slice(2).toUpperCase()}`,
}, false);
await check('非ASCII uidを拒否', await signed('利用者', 'canonical chat', 1_750_000_000_000), false);
await check('非文字列 textを拒否', await signed(UID, 7, 1_750_000_000_000), false);
await check('小数 timestampを拒否', await signed(UID, 'canonical chat', 1_750_000_000_000.5), false);
await check('可視内容ゼロを拒否', await signed(UID, '\u200b\u200c', 1_750_000_000_000), false);

const receipt = { receiverUid: UID, actionHash: `0x${'12'.repeat(32)}`,
  timestamp: 1_750_000_000_000, signature: `0x${'34'.repeat(32)}${'00'.repeat(31)}011b` };
const changedReceipt = { ...receipt, timestamp: receipt.timestamp + 1 };
await relay._ingestReceiptArrivals([changedReceipt], { fromLive: true });
await relay._ingestReceiptArrivals([receipt]);
assert.equal(relay.getReceipts().length, 2, '同じ署名の改変写しと本物は別 digest で保持');
relay.clearLiveSnapshot();
assert.deepEqual(relay.getReceipts().map((row) => row.timestamp), [receipt.timestamp],
  'live 写しの後始末で本物を消さない');
console.log('  ok: 復元クライアントの受領証明 digest と live 後始末');

// T5 A: 形式が違う WS 写しは検証前に捨て、本物の既出枠と P2P 控えを奪えない。
{
  const now = Date.now();
  const actionHash = `0x${'12'.repeat(32)}`;
  const action = { receiverUid: UID, actionHash, timestamp: now,
    signature: await account.signMessage({ message: receiptSignString(BLOCK, GROUP, UID, actionHash, now) }) };
  const refs = [`0x${'01'.repeat(16)}`, `0x${'02'.repeat(16)}`].sort(compareHexAsc);
  const read = { receiverUid: UID, senderUid: 'sender', msgRefs: refs, timestamp: now,
    signature: await account.signMessage({ message: readReceiptSignString(BLOCK, GROUP, UID, 'sender', refs, now) }) };
  const verify = makeVerifyRelayInner(() => [{ uid: UID, bAddr }, { uid: 'sender', bAddr }], BLOCK, GROUP);
  assert.equal(await verify('receipt', action), true);
  assert.equal(await verify('receipt', read), true);
  assert.equal(receiptIdentityDigest({ ...read, _seq: 9 }), receiptIdentityDigest(read));
  assert.notEqual(receiptIdentityDigest({ ...read, timestamp: now + 1 }), receiptIdentityDigest(read));
  const malformed = [
    [{ ...action, signature: `0x${action.signature.slice(2).toUpperCase()}` }, action],
    [{ ...action, signature: `0X${action.signature.slice(2)}` }, action],
    [{ ...action, signature: `${action.signature}0` }, action],
    [{ ...read, msgRefs: [...refs].reverse() }, read],
  ];
  for (const [copy, genuine] of malformed) {
    const cache = Object.create(GameRelayChannel.prototype);
    cache.relayReceipts = {};
    cache._receiptsStoreKey = () => 'unit';
    cache._saveJson = () => true;
    cache.onReceiptsChange = () => {};
    cache._ingestReceipt(genuine, { verified: true });
    let checks = 0;
    const accepted = [];
    const queue = new ReceiptAdmissionQueue({
      getRosterUids: () => [UID, 'sender'], isRosterVerified: () => true,
      verifyReceipt: async (rc) => { checks++; return verify('receipt', rc); },
      resolveReceipt: () => ({ state: 'covered', facts: ['valid'], priority: 'F' }),
      onAccept: (rc) => accepted.push(rc),
      onDiscard: (_rc, _reason, digest) => cache.forgetReceipt(digest),
    });
    assert.equal(receiptIdentityDigest(copy), null, '非正準の写しは digest を持たない');
    assert.equal(await queue.offer(copy), false);
    assert.equal(queue.seenDigests.size, 0, '非正準の写しは既出に残らない');
    assert.equal(checks, 0, '非正準の写しは署名検証に届かない');
    assert.equal(await queue.offer(genuine), true);
    assert.deepEqual(accepted, [genuine]);
    assert.equal(cache.getRelayReceipts().length, 1, '本物の P2P 控えが残る');
    assert.equal(await queue.offer(genuine), false);
    assert.equal(checks, 1, '同じバイト列の再送は検証前に落ちる');
    queue.dispose();
  }
  console.log('  ok: 非正準 WS 写しの後も本物と控えを受理');
}

console.log('');
if (failed) {
  console.error(`relay-canonical-ingress-unit: ${failed} FAILED (${passed} passed)`);
  process.exit(1);
}
console.log(`relay-canonical-ingress-unit: ALL PASSED (${passed} checks)`);
