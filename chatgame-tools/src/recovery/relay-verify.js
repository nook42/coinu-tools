// src/recovery/relay-verify.js — inner署名検証（MIRROR: src/hooks/useGameWebSocket.js verifyRelayInner）
//
// GameRelayChannel に opts.verifyInnerSignature として渡す関数を作る。
// 正典（フックの「P2P リレー層の内側署名検証」クロージャ・v3.2: chat・action・receipt・presence）を
// バイト等価に写す。VENDOR_SYNC.md に行範囲sha256を記録。
// members は {uid, bAddr}（bAddr は JSON文字列 or オブジェクト）の配列。
// 署名者 = receipt は inner.receiverUid、それ以外は inner.uid（検証アドレスは登録blockAddress）。

import { verifyMessage } from 'viem';
import { isClientTimestampAllowed } from '../../vendor/src/utils/relay.js';
import {
  chatSignStringV2, actionSignStringV2, receiptSignString, readReceiptSignString, presenceSignStringV2,
  isMsgRef, isActionHash, receiptMaxRefsPerReceipt, compareHexAsc,
} from '../../vendor/src/utils/protocol.js';
// 🔴 正典フロント（`src/hooks/useGameWebSocket.js:23`）と同じく **protocol-v2 から直接**取る。
//    `src/utils/protocol.js` のバレルはこの述語を再エクスポートしていないため。
import { isCanonicalActionCiphertext, isCanonicalTimestamp, isCanonicalSignature, isCanonicalText } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { hasVisibleContent } from '../../vendor/workers/game_workers/lib/char-counter.js';

export function makeVerifyRelayInner(getMembers, blockNum, groupId, maxMessages = 100) {
  return async (type, inner) => {
    try {
      const members = typeof getMembers === 'function' ? getMembers() : getMembers;
      const signerUid = type === 'receipt' ? inner.receiverUid : inner.uid;
      // 🔴 P-2026-0829（2026-08-07）: リレー内側も正準 timestamp のみ。
      //    受領証明（`type === 'receipt'`）が本丸 —— DO を締めても Nostr で直送されれば
      //    小数 ts の受領証明が取り込まれ、`buildReceiptMaps` は正準性を見ないので
      //    **画面だけ「受領済み」**になり、採点は void にする（標的型の冤罪）。
      //    action / presence / chat も同じ述語で揃える（正当な `0` は通る）。
      if (!isCanonicalTimestamp(inner?.timestamp)) return false;
      // 🔴 P-2026-0836（2026-08-08・ラウンド19 判断不要-2）: **署名の正準性（形式＋low-s）も課す。**
      //    viem の `verifyMessage` は high-s の「双子」に true を返す（`protocol-v2.js:117-122`）が、
      //    採点正典（`isCanonicalSignature`）と Rust（`is_low_s`）は落とす。
      //    リレー経由の双子受領証明を取り込むと、画面だけ「受領済み」になって
      //    採点は void ＝ 標的型の冤罪になり、しかも再送導線が出ない。
      //    ⚠️ 過剰遮断ゼロ: viem `signMessage` 500サンプルで high-s は 0件。
      if (!isCanonicalSignature(inner?.signature)) return false;
      const member = members.find((m) => m.uid === signerUid);
      if (!member || !member.bAddr) return false;
      const bAddr = typeof member.bAddr === 'string' ? JSON.parse(member.bAddr) : member.bAddr;
      let dataString;
      if (type === 'chat') {
        if (!isCanonicalText(inner.text ?? '') || !hasVisibleContent(inner.text)) return false;
        dataString = chatSignStringV2(blockNum, groupId, inner.uid, inner.text, inner.timestamp);
      } else if (type === 'action') {
        if (inner.actionType !== 'vote' && inner.actionType !== 'report') return false;
        if (!isCanonicalActionCiphertext(inner.encrypted)) return false;
        dataString = actionSignStringV2(inner.actionType, blockNum, groupId, inner.uid, inner.encrypted, inner.timestamp);
      } else if (type === 'presence') {
        if (inner.state !== 'active' && inner.state !== 'away') return false;
        dataString = presenceSignStringV2(blockNum, groupId, inner.uid, inner.state, inner.timestamp);
      } else if (type === 'receipt') {
        // K-S6-002（2026-07-29）: 署名が正しくても**形式が不正な参照**は取り込まない。
        // 受領証明は全員が提出物に同梱する設計なので、ここを通した異物は
        // グループ全員の提出物を肥大させ、WS提出もオンチェーン提出も同時に潰せた。
        if (Array.isArray(inner.msgRefs) && typeof inner.senderUid === 'string') {
          if (!members.some(m => m.uid === inner.senderUid)) return false;
          if (inner.msgRefs.length === 0) return false;
          if (inner.msgRefs.length > receiptMaxRefsPerReceipt(maxMessages)) return false;
          if (!inner.msgRefs.every(isMsgRef)) return false;
          if (inner.msgRefs.some((ref, i) => i > 0 && compareHexAsc(inner.msgRefs[i - 1], ref) >= 0)) return false;
          dataString = readReceiptSignString(blockNum, groupId, inner.receiverUid, inner.senderUid, inner.msgRefs, inner.timestamp);
        } else if (isActionHash(inner.actionHash)) {
          dataString = receiptSignString(blockNum, groupId, inner.receiverUid, inner.actionHash, inner.timestamp);
        } else {
          return false;
        }
      } else {
        return false;
      }
      return await verifyMessage({ address: bAddr.address, message: dataString, signature: inner.signature });
    } catch {
      return false;
    }
  };
}
