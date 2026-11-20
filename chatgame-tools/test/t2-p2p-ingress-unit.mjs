import assert from 'node:assert/strict';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
const { GameRelayChannel, isClientChatWithinLimit, verifyLiveSnapshotEntries } = await import(
  process.env.T2_RELAY_OVERRIDE || new URL('../vendor/src/utils/relay.js', import.meta.url));
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { chatSignStringV2 } from '../vendor/src/utils/protocol.js';
import { applyChatCaps, countHalfWidthChars, GUEST_PINNED_RULES } from '../vendor/workers/game_workers/lib/char-counter.js';

const boundary = [
  ['ascii', 'a'.repeat(1000), 'a'.repeat(1001)],
  ['全角', '界'.repeat(500), '界'.repeat(500) + 'a'],
  ['surrogate', '😀'.repeat(250), '😀'.repeat(250) + 'a'],
  ['結合', ('e\u0301').repeat(333) + 'a', ('e\u0301').repeat(333) + 'aa'],
];
for (const [name, accepted, discarded] of boundary) {
  assert.equal(countHalfWidthChars(accepted), 1000, `${name}: lower edge`);
  assert.equal(countHalfWidthChars(discarded), 1001, `${name}: upper edge`);
  assert.equal(isClientChatWithinLimit(accepted), true, `${name}: accepted`);
  assert.equal(isClientChatWithinLimit(discarded), false, `${name}: discarded`);
  const messages = [accepted, discarded].map((text, id) => ({ uid: '1', text, id }));
  assert.deepEqual(applyChatCaps(messages, GUEST_PINNED_RULES), [messages[0]], `${name}: scoring parity`);
}
// 到着順の累積上限は入口で使わない。1件の境界を越えない限り各メッセージは通す。
assert.equal(isClientChatWithinLimit('a'.repeat(900)), true);

const signKey = generatePrivateKey();
const account = privateKeyToAccount(signKey);
const now = Date.now();
const member = { uid: '1', bAddr: { address: account.address } };
const recovery = new RecoveryRelay({ signKey, blockNum: 1, groupId: 2, uid: '1', members: [member] });
const signed = async (text) => ({ uid: '1', text, timestamp: now,
  signature: await account.signMessage({ message: chatSignStringV2(1, 2, '1', text, now) }) });
assert.equal(await recovery._verifyChat(await signed('a'.repeat(1000))), true);
assert.equal(await recovery._verifyChat(await signed('a'.repeat(1001))), false);

let verified = 0;
const live = await verifyLiveSnapshotEntries({ blockNum: 1, groupId: 2, messages: [
  { ...await signed('a'.repeat(1001)) }, { ...await signed('a'.repeat(1000)) },
] }, { blockNum: 1, groupId: 2, members: [member], verifyChat: async () => { verified++; return true; } });
assert.equal(verified, 1, 'live の長文は署名検証前に除外');
assert.equal(live.messages.length, 1);

const got = [];
const channel = new GameRelayChannel({ signKey, blockNum: 1, groupId: 2, uid: '2', members: [member],
  verifyInnerSignature: async () => { verified++; return true; }, onChat: (inner) => got.push(inner) });
channel.validNostrByUid.set('1', 'pubkey');
for (const text of ['a'.repeat(1001), 'a'.repeat(1000)]) {
  await channel._handleEvent({ pubkey: 'pubkey', content: JSON.stringify({
    type: 'chat', blockNum: 1, groupId: 2, uid: '1', text, timestamp: now, signature: 'sig',
  }) });
}
assert.equal(got.length, 1, 'P2P chat は署名検証前に長文を除外');
assert.equal(verified, 2);
for (let i = 0; i < 12; i++) await channel._handleEvent({ pubkey: 'pubkey', content: JSON.stringify({
  type: 'chat', blockNum: 1, groupId: 2, uid: '1', text: 'a'.repeat(900),
  timestamp: now + i + 1, signature: `sig${i}`,
}) });
assert.equal(got.length, 13, '累積1万字を超えても入口で捨てない');
assert.equal(isClientChatWithinLimit('a'.repeat(1200), 1200), true, 'DO の同じ1件上限値を使える');
console.log('T2 P2P ingress: ALL PASSED');

// T1e: 運営申告の上下限によらず、全入口が採点 pin を使う。
{
const { readFileSync } = await import('node:fs');

const hook = readFileSync(process.env.T1E_HOOK_SOURCE
  || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const entrances = [
  /isClientChatWithinLimit\(msg\.text, GUEST_PINNED_RULES\.maxMsgChars\)/,
  /isClientChatWithinLimit\(inner\?\.text, GUEST_PINNED_RULES\.maxMsgChars\)/,
  /verifyLiveSnapshotEntries\(snapshot, \{[\s\S]*?maxMsgChars: GUEST_PINNED_RULES\.maxMsgChars/,
  /getMaxMsgChars: \(\) => GUEST_PINNED_RULES\.maxMsgChars/,
];
for (const [index, pattern] of entrances.entries()) {
  assert.match(hook, pattern, `official ingress ${index + 1} must use scoring pin`);
}
for (const operatorValue of [25, Number.MAX_SAFE_INTEGER]) {
  assert.equal(isClientChatWithinLimit('a'.repeat(58), GUEST_PINNED_RULES.maxMsgChars), true,
    `58 chars survive operator ${operatorValue}`);
  assert.equal(isClientChatWithinLimit('a'.repeat(1001), GUEST_PINNED_RULES.maxMsgChars), false,
    `1001 chars fail operator ${operatorValue}`);
}
console.log('T1e ingress: ALL PASSED (4 pin entrances, operator low/high)');
}
