import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RecoveryRelay, priorRecoveryStorageBlocks,
  clearFinalizedRecoveryBlockKeys } from '../src/recovery/relay-client.js';
import { GameRelayChannel } from '../vendor/src/utils/relay.js';

class QuotaStorage {
  constructor(limit) { this.limit = limit; this.map = new Map(); }
  get length() { return this.map.size; }
  key(index) { return [...this.map.keys()][index] ?? null; }
  getItem(key) { return this.map.get(key) ?? null; }
  removeItem(key) { this.map.delete(key); }
  setItem(key, value) {
    const next = new Map(this.map);
    next.set(key, String(value));
    const used = [...next].reduce((sum, [k, v]) => sum + k.length + v.length, 0);
    if (used > this.limit) throw new Error('QuotaExceededError');
    this.map = next;
  }
}
globalThis.localStorage = new QuotaStorage(5 * 1024 * 1024);
const failures = [];
const uid = '12345';
const members = [{ uid }, { uid: '67890' }];
const args = { signKey: `0x${'1'.repeat(64)}`, blockNum: 9, groupId: 0, uid, members,
  onPersistenceError: ({ key }) => failures.push(key) };
const recovery = new RecoveryRelay(args);
const channel = new GameRelayChannel({ ...args, verifyInnerSignature: async () => true });
const fake = Array.from({ length: 700 }, (_, i) => ({ receiverUid: '67890', senderUid: uid,
  msgRefs: Array.from({ length: 100 }, (_, j) => `0x${(i * 100 + j).toString(16).padStart(32, '0')}`),
  timestamp: 1000 + i, signature: `fake-${i}`, _seq: i + 1 }));
for (const receipt of fake) channel.relayReceipts[receipt.signature] = receipt;
channel._saveReceiptCache();
recovery._receipts = Object.fromEntries(fake.map((receipt) => [receipt.signature, receipt]));
recovery._saveReceiptArrivals();
const action = { receiverUid: '67890', actionHash: `0x${'a'.repeat(64)}`,
  timestamp: 2000, signature: 'honest-action', _seq: 701, _chainSeenAt: 1900 };
recovery._receipts[action.signature] = action;
recovery._saveReceiptArrivals();
const persisted = JSON.parse(localStorage.getItem(recovery._receiptArrivalsStoreKey()));
assert.equal(Object.keys(persisted).length, 1);
assert.equal(persisted[action.signature]._chainSeenAt, 1900);
assert([...localStorage.map].reduce((n, [k, v]) => n + k.length + v.length, 0) < 1024 * 1024);
assert.deepEqual(failures, []);

// When a preexisting channel cache has consumed the remaining quota, the
// arrival store evicts that duplicate and retries the protected write.
globalThis.localStorage = new QuotaStorage(700);
const retry = new RecoveryRelay(args);
localStorage.setItem(`p2pRelayReceipts_9_group0_user${uid}`, 'x'.repeat(500));
retry._receipts[action.signature] = action;
retry._saveReceiptArrivals();
assert(JSON.parse(localStorage.getItem(retry._receiptArrivalsStoreKey()))[action.signature]);
assert.equal(localStorage.getItem(`p2pRelayReceipts_9_group0_user${uid}`), null);

// Old finalized block keys are removed before the next block needs durable
// arrival marks. Failed writes shrink to action receipts before warning.
// RPC1-B: the recovery node trust key is a finalized-block key too (own small storage so the
// quota-sized block below keeps its original budget).
globalThis.localStorage = new QuotaStorage(640);
localStorage.setItem(`recoveryRpcNodeTrust_v1_8_user${uid}`, '{}');
localStorage.setItem(`myReportGrounds_8_user${uid}`, '{}');
assert.deepEqual(priorRecoveryStorageBlocks(localStorage, 9), [8]);
assert(clearFinalizedRecoveryBlockKeys(localStorage, 8));
assert.equal(localStorage.getItem(`recoveryRpcNodeTrust_v1_8_user${uid}`), null);
assert.equal(localStorage.getItem(`myReportGrounds_8_user${uid}`), null);

globalThis.localStorage = new QuotaStorage(640);
localStorage.setItem(`p2pRelayReceipts_8_group0_user${uid}`, 'x'.repeat(480));
localStorage.setItem(`p2pSelfActions_8_group0_user${uid}`, '{}');
localStorage.setItem(`priorityShownSeparators_8_0_${uid}`, '{}');
localStorage.setItem(`priorityShownSeparators_9_0_${uid}`, '{}');
assert.deepEqual(priorRecoveryStorageBlocks(localStorage, 9), [8]);
assert(clearFinalizedRecoveryBlockKeys(localStorage, 8));
assert.equal(localStorage.getItem(`p2pSelfActions_8_group0_user${uid}`), null);
assert.equal(localStorage.getItem(`priorityShownSeparators_8_0_${uid}`), null);
assert.equal(localStorage.getItem(`priorityShownSeparators_9_0_${uid}`), '{}');
const carry = new RecoveryRelay(args);
const message = { uid, text: 'honest message', timestamp: 1000, signature: 'known',
  blockNum: 9, groupId: 0 };
carry.messages = [message];
const knownRef = (await import('../vendor/workers/game_workers/lib/protocol-v2.js'))
  .msgRefOf(carry.getMsgKey(message));
carry._receipts = { [action.signature]: action,
  read: { receiverUid: '67890', senderUid: uid, msgRefs: [knownRef], timestamp: 2000,
    signature: 'read', _seq: 702, padding: 'x'.repeat(600) } };
carry._saveReceiptArrivals();
assert(JSON.parse(localStorage.getItem(carry._receiptArrivalsStoreKey()))[action.signature]);
assert.equal(JSON.parse(localStorage.getItem(carry._receiptArrivalsStoreKey())).read, undefined);

// Self-action persistence failures must reach the visible warning callback.
globalThis.localStorage = new QuotaStorage(8);
const actionChannel = new GameRelayChannel({ ...args, verifyInnerSignature: async () => true });
actionChannel.relayActions[uid] = { vote: { signature: 'vote', timestamp: 2000 }, reports: [] };
actionChannel._saveOwnActions();
assert(failures.some((key) => key.startsWith('p2pSelfActions_9_')));

// If even the small protected write cannot fit, the caller receives a warning.
globalThis.localStorage = new QuotaStorage(8);
const blocked = new RecoveryRelay({ ...args, onPersistenceError: ({ key }) => failures.push(key) });
blocked._receipts[action.signature] = action;
blocked._saveReceiptArrivals();
assert(failures.includes(blocked._receiptArrivalsStoreKey()));
const app = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
assert.match(app, /onPersistenceError: \(\{ key \} = \{\}\) => showPersistenceWarning/);
console.log('t2-storage-priority-unit: ALL PASSED (cross-block cleanup, action-only fallback, two warnings)');
