// test/scenario.mjs — 検閲シナリオの共有フィクスチャ（bundle-unit と recovery-e2e で再利用・v3.2）
//
// 4人グループ。p2 が運営WSから締め出される想定で、p2 の提出バンドルを復元クライアントの
// buildSubmissionBundle で再構成する。他3人は正常提出（自分の発信＋観測セクション＋全受領証明）。
// v3.2: 鍵は単一ウォレット署名から deriveKeysFromSignature で signKey/encryptKey を兄弟導出。
// チャット/投票は signKey 署名、投票対象は encryptKey で自己暗号化。全メッセージ・全投票に
// 他メンバーの受領証明（既読バッチ／action受領）を付けて正典条件を満たす。

import { keccak256, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString,
  computeChatHashV2, computeMsgKeyV2, msgRefOf,
  compareHexAsc,
} from '../vendor/workers/game_workers/lib/protocol-v2.js';
import { deriveKeysFromSignature } from '../vendor/src/utils/walletTools.js';
import { encryptAction } from '../vendor/src/utils/ecies.js';
import { buildSubmissionBundle } from '../src/recovery/bundle.js';

export const fixedWalletKey = (i) => '0x' + BigInt(i + 1).toString(16).padStart(64, '0');

// keyIndex 0..3 が hardhat account #0..#3 とは別（ウォレット署名者。deposit/gas とは無関係）。
// chain E2E では名簿に載るプレイヤー本人のウォレットで Evidence を提出する。
export async function makePlayer(uid, keyIndex, depositEth, blockNum) {
  const wallet = privateKeyToAccount(fixedWalletKey(keyIndex + 100)); // hardhat account と衝突しない領域
  const walletSignature = await wallet.signMessage({ message: `bitcoinu_mining_block${blockNum}_user${uid}` });
  const { signKey, encryptKey, blockAddress } = deriveKeysFromSignature(walletSignature, blockNum);
  const signAccount = privateKeyToAccount(signKey);
  const depositWei = BigInt(Math.round(depositEth * 1e6)) * 10n ** 12n;
  return {
    uid, wallet, signKey, encryptKey, signAccount, addr: wallet.address,
    bAddr: JSON.parse(blockAddress),
    bAddrString: blockAddress,
    // 🔴 本番は10進**文字列**（entry_workers/lib/deposit-id.js の canonicalizeDepositId が
    //    `BigInt(x).toString(10)` を返す）。数値のままだと提出署名のバイト列が本番と食い違い、
    //    P-2026-0806 の型検査（isCanonicalDepositIds）で invalid_signature になる。
    depIds: JSON.stringify({ deposit: depositWei.toString(), ids: [String(Number(uid.slice(-1)))] }),
  };
}

export async function buildScenario({ blockNum = 5, groupId = 0, base = 1750000000000 } = {}) {
  const players = await Promise.all([
    makePlayer('user0001', 0, 1.0, blockNum),
    makePlayer('user0002', 1, 0.5, blockNum),
    makePlayer('user0003', 2, 0.25, blockNum),
    makePlayer('user0004', 3, 0.5, blockNum),
  ]);
  const [p1, p2, p3, p4] = players;
  const members = players.map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddrString, depIds: p.depIds }));

  // チャット（signKey署名）
  const makeMsg = async (p, text, ts) => {
    const normalized = text;
    const signature = await p.signAccount.signMessage({ message: chatSignStringV2(blockNum, groupId, p.uid, normalized, ts) });
    return { type: 'chat', blockNum, groupId, uid: p.uid, text: normalized, timestamp: ts, signature };
  };
  // 投票/密告（encryptKeyで自己暗号化・signKeyで署名）
  const makeAction = async (p, type, payload, ts) => {
    const encrypted = encryptAction(payload, p.encryptKey);
    const signature = await p.signAccount.signMessage({ message: actionSignStringV2(type, blockNum, groupId, p.uid, encrypted, ts) });
    return { encrypted, signature, timestamp: ts };
  };
  // 既読受領証明（receiver が sender の全メッセージを **msgRef** バッチで裏書・signKey署名）
  // ⚠️ 案B（2026-07-28）: 参照は msgKey 全32バイトではなく先頭 MSG_REF_BYTES バイト（msgRefOf）。
  //    Evidence の gzip 後 128KB（geth の tx 伝播上限）に収めるための短縮。
  //    正典クライアント src/hooks/useGameWebSocket.js と同一形にすること
  //    （ずれると受領証明が1件も採用されず、全員が min_chars で失格する）。
  const makeReadReceipt = async (receiver, senderUid, msgs, ts) => {
    const msgRefs = msgs.filter((m) => m.uid === senderUid)
      .map((m) => msgRefOf(computeMsgKeyV2(blockNum, groupId, m)))
      .sort(compareHexAsc);
    const signature = await receiver.signAccount.signMessage({
      message: readReceiptSignString(blockNum, groupId, receiver.uid, senderUid, msgRefs, ts),
    });
    return { receiverUid: receiver.uid, senderUid, msgRefs, timestamp: ts, signature };
  };
  // action受領証明
  const makeActionReceipt = async (receiver, actorUid, type, action, ts) => {
    const actionHash = actionHashV2(type, blockNum, groupId, actorUid, action.encrypted, action.timestamp);
    const signature = await receiver.signAccount.signMessage({
      message: receiptSignString(blockNum, groupId, receiver.uid, actionHash, ts),
    });
    return { receiverUid: receiver.uid, actionHash, timestamp: ts, signature };
  };

  const sharedMessages = [];
  for (let turn = 0; turn < 14; turn++) {
    for (const p of players) {
      sharedMessages.push(await makeMsg(p, `hello turn${turn} from ${p.uid} `.padEnd(60, 'x'), base + turn * 40000 + sharedMessages.length * 10));
    }
  }

  const votes = {
    [p1.uid]: await makeAction(p1, 'vote', { targetUid: p3.uid }, base + 1),
    [p2.uid]: await makeAction(p2, 'vote', { targetUid: p1.uid }, base + 2),
    [p3.uid]: await makeAction(p3, 'vote', { targetUid: p1.uid }, base + 3),
    [p4.uid]: await makeAction(p4, 'vote', { targetUid: p1.uid }, base + 4),
  };

  // 全受領証明: 既読（全ペア・sender毎バッチ）＋ action受領（各投票に隣のメンバーが1件）。
  // v3.3: 受領証明は発信主張timestampの±10分（600000ms）以内のみ有効（isReceiptTimely）。
  //   既読バッチ ts = base+550000 … メッセージは base+0 〜 base+520550 に分布＝全件 ±10分内。
  //   action受領 ts = base+500000+i … 投票は base+1〜4 ＝ ±10分内。
  const allReceipts = [];
  for (const receiver of players) {
    for (const sender of players) {
      if (receiver.uid === sender.uid) continue;
      allReceipts.push(await makeReadReceipt(receiver, sender.uid, sharedMessages, base + 550000));
    }
  }
  for (let i = 0; i < players.length; i++) {
    const actor = players[i];
    const receiver = players[(i + 1) % players.length]; // 発信者以外の1名が受領
    allReceipts.push(await makeActionReceipt(receiver, actor.uid, 'vote', votes[actor.uid], base + 500000 + i));
  }

  // 正常提出者（自分の発信＋観測セクション＋全受領証明・§6.8）
  const makeHonestSubmission = async (p, msgs, receipts = allReceipts) => {
    const submittedAt = base + 999999;
    const depositIds = JSON.parse(p.depIds).ids;
    const chatHash = computeChatHashV2(msgs, blockNum, groupId);
    const snapshot = { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };
    snapshot.votes[p.uid] = votes[p.uid];
    for (const q of players) {
      if (q.uid === p.uid) continue;
      snapshot.observed.votes[q.uid] = [votes[q.uid]];
    }
    snapshot.observed.receipts = [...receipts]
      .sort((a, b) => (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0));
    const encryptedDataHash = keccak256(toHex(JSON.stringify(snapshot)));
    const dataString = JSON.stringify({
      blockNum: Number(blockNum), uid: p.uid, encryptKey: p.encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds,
    });
    const signature = await p.wallet.signMessage({ message: dataString });
    const messages = msgs.map((m) => ({ type: 'chat', blockNum: Number(blockNum), groupId: Number(groupId), uid: m.uid, text: m.text, timestamp: m.timestamp, signature: m.signature }));
    return { uid: p.uid, encryptKey: p.encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions: snapshot, messages };
  };

  // p2 の復元バンドル（自分の投票＋観測アクション＋観測受領証明から再構成）。
  // v3.3: myVote/myVotePrev/intent を差し替え可能（void再送・受領済み優先選択のテスト用）
  const makeP2Recovery = ({
    receipts = allReceipts, messages = sharedMessages,
    myVote = votes[p2.uid], myVotePrev = [], intent = { vote: p1.uid, reports: [] },
  } = {}) => buildSubmissionBundle({
    blockNum, groupId, myUid: p2.uid, encryptKey: p2.encryptKey,
    members, messages, myDepositIds: JSON.parse(p2.depIds).ids,
    myVote, myVotePrev, myReports: [],
    observedActions: {
      votes: { [p1.uid]: votes[p1.uid], [p3.uid]: votes[p3.uid], [p4.uid]: votes[p4.uid] },
      reports: {},
    },
    receipts,
    intent,
    submittedAt: base + 999999,
    signWallet: async (message) => p2.wallet.signMessage({ message }),
  });
  const p2Recovery = await makeP2Recovery();

  return {
    blockNum, groupId, base, players, members, sharedMessages, votes, allReceipts,
    makeAction, makeReadReceipt, makeActionReceipt,
    p2Recovery, makeP2Recovery, makeHonestSubmission,
    async allSubmissions() {
      return {
        [p1.uid]: await makeHonestSubmission(p1, sharedMessages),
        [p3.uid]: await makeHonestSubmission(p3, sharedMessages),
        [p4.uid]: await makeHonestSubmission(p4, sharedMessages),
        [p2.uid]: p2Recovery.bundle,
      };
    },
  };
}
