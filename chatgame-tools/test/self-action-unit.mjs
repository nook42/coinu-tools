// test/self-action-unit.mjs — 相互ロックの核（自己アクションの P2P 観測）の決定論ユニットテスト（v3.2）。
//
// 別クライアント（同一signKey・例: game.js）が P2P に発行した自己投票/密告/受領証明/チャットを、
// リカバリーツールの RecoveryRelay._handleSelfAction が signKey署名検証の上で正しく振り分けることを
// ネットワーク無しで検証する。relay.js の _observeSelfAction→onSelfAction 追加経路の消費側テスト。
//
// 実行: node test/self-action-unit.mjs

import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { makeVerifyRelayInner } from '../src/recovery/relay-verify.js';
import { GameRelayChannel, buildEvent, deriveNostrKey, groupTag } from '../vendor/src/utils/relay.js';
import { actionSignStringV2, actionHashV2, chatSignStringV2, receiptSignString } from '../vendor/src/utils/protocol.js';
import { deriveBlockAddress } from '../vendor/src/utils/walletTools.js';
import { encryptAction } from '../vendor/src/utils/ecies.js';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

const checks = [];
function check(id, cond) { checks.push({ id, ok: !!cond }); console.log(`  ${cond ? 'ok' : 'NG'}: ${id}`); }
const storage = new Map();
globalThis.localStorage = { getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, String(value)), removeItem: (key) => storage.delete(key) };

const BLOCK = 5, GROUP = 0;

async function main() {
  const meSignKey = generatePrivateKey();
  const meEncryptKey = generatePrivateKey(); // 自己暗号化専用（signKeyと独立でも観測経路の検証には十分）
  const otherSignKey = generatePrivateKey();
  const meAddr = JSON.parse(deriveBlockAddress(meSignKey, BLOCK).blockAddress);   // {address, pubKey, nostrPubkey}
  const otherAddr = JSON.parse(deriveBlockAddress(otherSignKey, BLOCK).blockAddress);
  const meUid = '1000', otherUid = '2000';
  const members = [
    { uid: meUid, bAddr: meAddr },
    { uid: otherUid, bAddr: otherAddr },
  ];
  const meAccount = privateKeyToAccount(meSignKey);

  // RecoveryRelay を start() せず（＝ネットワーク不要）、観測消費経路だけを検証する。
  const selfActions = [];
  const rel = new RecoveryRelay({
    signKey: meSignKey, blockNum: BLOCK, groupId: GROUP, uid: meUid, members,
    onUpdate: null,
    onSelfAction: (type, inner) => selfActions.push({ type, inner }),
  });
  rel._verifyInner = makeVerifyRelayInner(() => members, BLOCK, GROUP); // 通常は start() で確定

  // ① 自己投票観測（encrypted は encryptKey 自己暗号化・signKey 署名）
  {
    const ts = 1000;
    const encrypted = encryptAction({ targetUid: otherUid }, meEncryptKey);
    const signature = await meAccount.signMessage({ message: actionSignStringV2('vote', BLOCK, GROUP, meUid, encrypted, ts) });
    await rel._handleSelfAction('action', { type: 'action', actionType: 'vote', blockNum: BLOCK, groupId: GROUP, uid: meUid, encrypted, timestamp: ts, signature });
  }
  // ② 自己密告観測
  {
    const ts = 2000;
    const encrypted = encryptAction({ targetUid: otherUid, reason: 'suspected_bot' }, meEncryptKey);
    const signature = await meAccount.signMessage({ message: actionSignStringV2('report', BLOCK, GROUP, meUid, encrypted, ts) });
    await rel._handleSelfAction('action', { type: 'action', actionType: 'report', blockNum: BLOCK, groupId: GROUP, uid: meUid, encrypted, timestamp: ts, signature });
  }
  // ③ 自己チャット観測（別クライアントの自己発言 → canon へマージ）
  {
    const ts = 3000;
    const text = 'hi from other client';
    const signature = await meAccount.signMessage({ message: chatSignStringV2(BLOCK, GROUP, meUid, text, ts) });
    await rel._handleSelfAction('chat', { type: 'chat', blockNum: BLOCK, groupId: GROUP, uid: meUid, text, timestamp: ts, signature });
  }
  // ④ 自己受領証明観測（別クライアントが発行した action 受領証明）
  {
    const ts = 4000;
    const actionHash = actionHashV2('vote', BLOCK, GROUP, otherUid, 'deadbeef', 999);
    const signature = await meAccount.signMessage({ message: receiptSignString(BLOCK, GROUP, meUid, actionHash, ts) });
    await rel._handleSelfAction('receipt', { type: 'receipt', blockNum: BLOCK, groupId: GROUP, receiverUid: meUid, actionHash, timestamp: ts, signature });
  }
  // ⑤ 改ざん（署名不一致）は振り分けられない
  {
    const ts = 5000;
    const encrypted = encryptAction({ targetUid: otherUid }, meEncryptKey);
    const badSig = '0x' + '11'.repeat(65);
    await rel._handleSelfAction('action', { type: 'action', actionType: 'vote', blockNum: BLOCK, groupId: GROUP, uid: meUid, encrypted, timestamp: ts, signature: badSig });
  }

  const votes = selfActions.filter((a) => a.type === 'action' && a.inner.actionType === 'vote');
  const reports = selfActions.filter((a) => a.type === 'action' && a.inner.actionType === 'report');
  const receipts = selfActions.filter((a) => a.type === 'receipt');
  check('self vote → onSelfAction(action, actionType=vote)', votes.length === 1 && !!votes[0].inner.encrypted);
  check('self report → onSelfAction(action, actionType=report)', reports.length === 1 && !!reports[0].inner.encrypted);
  check('self chat merged into canon (getMessages)', rel.getMessages().some((m) => m.text === 'hi from other client'));
  check('self receipt → onSelfAction(receipt, {actionHash,...})', receipts.length === 1 && typeof receipts[0].inner.actionHash === 'string');
  check('tampered self vote rejected (exactly 1 vote self-action)', votes.length === 1);

  // ── チャネル層: 自セッションのエコーは onSelfAction に渡さない（別クライアントのみ観測）──
  {
    const fired = [];
    const ch = new GameRelayChannel({
      signKey: meSignKey, blockNum: BLOCK, groupId: GROUP, uid: meUid, members,
      signMessage: async (m) => meAccount.signMessage({ message: m }),
      verifyInnerSignature: makeVerifyRelayInner(() => members, BLOCK, GROUP),
      onSelfAction: (type, inner) => fired.push({ type, sig: inner.signature }),
    });
    const { sk: nsk, pubkey: npk } = deriveNostrKey(meSignKey, BLOCK, GROUP);
    const tag = groupTag(BLOCK, GROUP);
    const selfEvent = async (inner) => buildEvent(nsk, npk, [['t', tag]], JSON.stringify(inner));
    ch.validNostrByUid.set(meUid, npk);

    const ts = 6000;
    const encrypted = encryptAction({ targetUid: otherUid }, meEncryptKey);
    const sig = await meAccount.signMessage({ message: actionSignStringV2('vote', BLOCK, GROUP, meUid, encrypted, ts) });
    const inner = { type: 'action', actionType: 'vote', blockNum: BLOCK, groupId: GROUP, uid: meUid, encrypted, timestamp: ts, signature: sig };

    // ①自セッションが発行した署名 → エコーは無視される
    ch._ingestAction(inner); // 本人の控えが保存されたときだけ抑止する
    ch._ownPublishedSigs.add(sig);
    await ch._handleEvent(await selfEvent(inner));
    check('own-session echo skipped (not observed)', fired.length === 0);

    // ②別クライアント（未発行の署名）→ 観測される
    ch._ownPublishedSigs.clear();
    await ch._handleEvent(await selfEvent(inner));
    check('other-client self action observed', fired.length === 1 && fired[0].type === 'action');
  }

  const failed = checks.filter((c) => !c.ok);
  console.log(failed.length === 0 ? '\nself-action-unit: ALL PASSED' : `\nself-action-unit: ${failed.length} FAILED`);
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
