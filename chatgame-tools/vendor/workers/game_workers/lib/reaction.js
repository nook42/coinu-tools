// workers/game_workers/lib/reaction.js
// 便 LIKE（2026-11-26・ユーザーの指示「単純にチャットにいいねをつけるのも無理なのでしょうか？Xのポストのように。
// 何人からいいねがついたか見れるようにする感じで。」「いいねボタンは会話の内容には入らないので、提出データに
// 含める必要はありません。」「いいねボタンも特許を侵害してなければ作ってください。」）。
// 最初は5種のスタンプを発言に付ける形（便 STAMP の初版）だったが、特許の調べ（audit/reply-stamp/PATENT_SCAN.md）で
// 「発言の位置に複数の選択肢を出して選ぶ」形をやめ、スタンプは普通の発言として送る形（src/utils/chatStamp.js）にし、
// 発言に付けるのは1種類のいいね（押すとすぐ付く・選ぶ列は出さない）だけにした。
//
// 発言へのいいね（反応）の共有の形。**表示だけ**: 採点・受理・提出物・受領証明・会話数・在席の判定には使わない。
//   { uid, ref, stamp, on, timestamp, signature }
//     uid: 押した人（名簿のメンバー）  ref: 発言の鍵（msgKey＝0x＋64桁）  stamp: 反応の種類（今は LIKE_REACTION＝1 だけ）
//     on: 押した（true）／外した（false）  timestamp: 押した人の時計（C）の ms
//     signature: 押した人の signKey で reactionSignString を署名したもの（運営もリレーも、他人の押下を作れない）
// 同じ（uid, ref, stamp）は、時刻の新しいもの（同じ時刻なら署名の文字列の大きい方）だけを残す。
// 1人が残せる（ref, stamp）の組は MAX_REACTIONS_PER_UID まで（WS・リレー・端末とも同じ上限）。

export const LIKE_REACTION = 1;
export const REACTION_STAMPS = Object.freeze([LIKE_REACTION]); // 1 いいね（ハート）
export const MAX_REACTIONS_PER_UID = 300;
const MSG_KEY_RE = /^0x[0-9a-f]{64}$/;
const SIGNATURE_RE = /^0x[0-9a-f]{130}$/;

// 署名する文字列（在席の合図 presenceSignStringV2 と同じ作り方）。
export function reactionSignString(blockNum, groupId, uid, ref, stamp, on, timestamp) {
  return JSON.stringify({
    type: 'reaction',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    ref,
    stamp,
    on: on === true,
    timestamp,
  });
}

// 形だけを確かめる（署名の正しさは呼び手が名簿の鍵で確かめる）。
export function isReactionShape(r) {
  return r !== null && typeof r === 'object' && !Array.isArray(r)
    && typeof r.uid === 'string' && r.uid.length > 0 && r.uid.length <= 64
    && typeof r.ref === 'string' && MSG_KEY_RE.test(r.ref)
    && REACTION_STAMPS.includes(r.stamp)
    && typeof r.on === 'boolean'
    && Number.isSafeInteger(r.timestamp) && r.timestamp >= 0
    && typeof r.signature === 'string' && SIGNATURE_RE.test(r.signature);
}

// 共有する欄だけを取り出す（余分な欄は運ばない）。
export function pickReaction(r) {
  return { uid: r.uid, ref: r.ref, stamp: r.stamp, on: r.on, timestamp: r.timestamp, signature: r.signature };
}

export const reactionSlot = (r) => `${r.ref}|${r.stamp}`;

// a が b より新しいか（同じ時刻なら署名の文字列の大きい方。同じ署名は新しくない）。
export function isNewerReaction(a, b) {
  if (!b) return true;
  if (a.timestamp !== b.timestamp) return a.timestamp > b.timestamp;
  return a.signature > b.signature;
}

// 1人ぶんの表（slot → 反応）へ足す。足したら true。古い・同じ・上限を超える新しい組は false（表は変えない）。
export function mergeReactionInto(table, r, max = MAX_REACTIONS_PER_UID) {
  if (!table || typeof table !== 'object' || !isReactionShape(r)) return false;
  const slot = reactionSlot(r);
  const prev = Object.prototype.hasOwnProperty.call(table, slot) ? table[slot] : null;
  if (prev && !isNewerReaction(r, prev)) return false;
  if (!prev && Object.keys(table).length >= max) return false;
  table[slot] = pickReaction(r);
  return true;
}

// 画面の形: 発言の鍵 → [{ stamp, uids: [押している人の uid…] }]（stamp の番号の順・押している人がいる stamp だけ）。
export function reactionsByMessage(reactions) {
  const byRef = new Map();
  for (const r of Array.isArray(reactions) ? reactions : []) {
    if (!isReactionShape(r) || r.on !== true) continue;
    let stamps = byRef.get(r.ref);
    if (!stamps) { stamps = new Map(); byRef.set(r.ref, stamps); }
    const uids = stamps.get(r.stamp) || [];
    if (!uids.includes(r.uid)) uids.push(r.uid);
    stamps.set(r.stamp, uids);
  }
  const out = new Map();
  for (const [ref, stamps] of byRef) {
    out.set(ref, REACTION_STAMPS.filter((s) => stamps.has(s)).map((s) => ({ stamp: s, uids: stamps.get(s) })));
  }
  return out;
}
