// src/utils/voidDisplay.js
// 便 VOIDKEEP（2026-11-25・ユーザーの指示「10分未読となり、ボツになったチャットや投票・密告は、
// 半透明で画面に残しましょう。伝言板としても使えるので！」「ボツになったチャットは既読の代わりに
// 「無効」と表示するようにしましょう。自分以外のチャットも同様です。」）。
//
// void（他のメンバーの受領証明が無いまま10分を過ぎた発信。提出期間以降は受領証明の無い発信）を、
// チャットの欄と提出画面のチャットの記録から消さずに残すための純粋な部品。**表示だけ**:
// 受理・採点・提出物・受領証明の発行・会話数・最優先欄の計画・表示した発言の記憶は変えない
// （void の行は呼び出し側がそれらから外す）。公式（src/components/game/chatTimeline.js）と
// 復元（chatgame-tools/src/recovery/app.js の renderChatLog）が同じ関数を使う。

import { RECEIPT_FRESH_WINDOW_MS } from './protocol.js';
import { GUEST_PINNED_RULES, countHalfWidthChars } from '../../workers/game_workers/lib/char-counter.js';

// 送り手ごとに残す void の発言の上限。正直なクライアントの送信の上限（全発言の件数と半角の字数）と同じ。
// 正直な送り手の void の発言は必ずこの内に入る。改造したクライアントが古い時刻の発言を大量に
// 流し込んでも、その送り手の分が画面に残るのはこの内だけになる（他の送り手の行は押し出されない）。
export const VOID_DISPLAY_CAPS = Object.freeze({
  maxMessages: GUEST_PINNED_RULES.maxMessages,
  maxChars: GUEST_PINNED_RULES.maxChars,
});

// 今の表示の決まりで出さない（visible が偽の）項目のうち、void として残すものか。
//   - 受領証明がある（readCount > 0）ものは void ではない（今どおり表示される）。
//   - 時刻が安全な整数でないものは残さない。
//   - 確定したチャット窓（window = { startMs, endMs }・採点の窓と同じ式）の外のものは残さない。窓が分からなければ
//     何も残さない（反証 VK-R02: 改造クライアントが窓の前や時刻0へ遡らせた発言を「無効」の行で差し込めた）。
//   - receiptedOnly（観戦と提出画面）で nowMs があるとき、鮮度の内（|nowMs − ts| ≤ 10分）の
//     受領証明の無い項目はまだ確定前なので出さない（観戦はスナップショットの時刻、提出画面は締切の時刻を渡す。
//     締切の前10分の未読は最優先欄の自己集約で有効になりうるため・反証 VK-R04）。nowMs が無ければ、
//     受領証明の無い項目は全部 void。
//   - それ以外（プレイヤーの画面で鮮度の外）は void。
export function isVoidTimelineItem(timestamp, readCount, { nowMs = null, receiptedOnly = false, window = null } = {}) {
  if (readCount > 0) return false;
  if (!Number.isSafeInteger(timestamp)) return false;
  if (!Number.isFinite(window?.startMs) || !Number.isFinite(window?.endMs)
    || timestamp < window.startMs || timestamp > window.endMs) return false;
  if (receiptedOnly) {
    if (nowMs == null) return true;
    return !(Math.abs(nowMs - timestamp) <= RECEIPT_FRESH_WINDOW_MS);
  }
  if (nowMs == null) return false;
  return !(Math.abs(nowMs - timestamp) <= RECEIPT_FRESH_WINDOW_MS);
}

const compareKey = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// void として残してよい発言の鍵の集合。entries は { uid, timestamp, text, key } の配列
// （その画面が持つ発言の全部・隠した発言も含む）。送り手ごとに（時刻, 鍵）の昇順に並べ、
// 1件目から数えた件数が caps.maxMessages 以下、かつ半角の字数の累計が caps.maxChars 以下の
// 発言の鍵だけを返す。上限を越えた後の発言は全部外す。caps が壊れていれば空の集合（何も残さない）。
export function voidDisplayMessageKeys(entries, caps = VOID_DISPLAY_CAPS) {
  const allowed = new Set();
  const maxMessages = caps?.maxMessages;
  const maxChars = caps?.maxChars;
  if (!Number.isSafeInteger(maxMessages) || maxMessages < 0
    || !Number.isSafeInteger(maxChars) || maxChars < 0 || !Array.isArray(entries)) return allowed;
  const bySender = new Map();
  for (const entry of entries) {
    if (entry === null || typeof entry !== 'object' || typeof entry.key !== 'string') continue;
    const list = bySender.get(entry.uid);
    if (list) list.push(entry);
    else bySender.set(entry.uid, [entry]);
  }
  const tsOf = (entry) => (Number.isSafeInteger(entry.timestamp) ? entry.timestamp : Number.MAX_SAFE_INTEGER);
  for (const list of bySender.values()) {
    list.sort((a, b) => (tsOf(a) - tsOf(b)) || compareKey(a.key, b.key));
    let count = 0;
    let chars = 0;
    for (const entry of list) {
      count += 1;
      chars += countHalfWidthChars(typeof entry.text === 'string' ? entry.text : '');
      if (count > maxMessages || chars > maxChars) break;
      allowed.add(entry.key);
    }
  }
  return allowed;
}
