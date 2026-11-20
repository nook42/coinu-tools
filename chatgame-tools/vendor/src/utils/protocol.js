// src/utils/protocol.js
// P2Pプロトコルv2のフロントエンド入口。実体は workers/game_workers/lib/protocol-v2.js
// （フロント・DO・calculator・reconciler・検証ツールでバイト厳密一致を保つ単一実装）。
//
// v3.2: タブー系・v1レガシー削除。署名鍵は signKey（永遠に非公開）、受領証明を新設。

export {
  chatSignStringV2,
  actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString,
  presenceSignStringV2,
  computeMsgKeyV2, buildMsgKeyGetter, canonicalComparatorV2,
  sortCanonicalV2, computeChatHashV2, dedupAndSortV2,
  compareHexAsc,
  canonicalizeSignature,
  isCanonicalActionCiphertext,
  isLowSSignature,
  isReceiptTimely, RECEIPT_FRESH_WINDOW_MS, IDLE_TIMEOUT_MS,
  REPORT_MIN_READ_RECEIPTS, REPORT_ELIGIBILITY_RULE_VERSION,
  MSG_REF_BYTES, msgRefOf, isMsgRef, isActionHash,
  receiptBundleCap, receiptMaxRefsPerReceipt,
  MAX_OBSERVED_ACTIONS_PER_ACTOR, buildRealTargets,
  receiptCoverClaim, selectBundleReceipts,
  buildReceiptMaps, collectKnownActions,
  CHAT_WINDOW_CLOCK_SKEW_MS, chatWindowMsFromTimeline
} from '../../workers/game_workers/lib/protocol-v2.js';
