// Evidence オンチェーン提出用の legacy receipt 保持方針。
//
// このファイルを chatgame-tools/vendor へ byte-exact で配布し、Web 本体と
// recovery クライアントが同じ A〜H と R・V の判定を実行する。ここでは receipt を削らず、
// 各 receipt の保持クラスだけを決定する。

import {
  GUEST_PINNED_RULES,
  countVisibleChars,
} from '../../workers/game_workers/lib/char-counter.js';
import { receiptCanonCmp } from '../../workers/game_workers/lib/game-result-calculator.js';
import { MAX_REFS_PER_RECEIPT, isPlainRecord } from '../../workers/game_workers/lib/submission-limits.js';
import { priorityTurnGuarantee } from '../../workers/game_workers/lib/priority-fields.js';
import {
  actionHashV2,
  buildRealTargets,
  buildMsgKeyGetter,
  canonicalComparatorV2,
  msgRefOf,
  receiptCoverClaim,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { decryptAction } from './ecies.js';

const OWN_ACTION_TYPES = ['vote', 'report'];

function normalizedActions(section, uid) {
  const raw = section?.[uid];
  return (Array.isArray(raw) ? raw : (raw ? [raw] : []))
    .filter((action) => action?.encrypted && action?.timestamp != null)
    .sort((a, b) => Number(a.timestamp) - Number(b.timestamp)
      || String(a.encrypted).localeCompare(String(b.encrypted)));
}

function targetForAction(type, blockNum, groupId, uid, action) {
  return `a:${actionHashV2(type, blockNum, groupId, uid, action.encrypted, action.timestamp)}`;
}

/**
 * legacy receipt を A〜H と R・V の保持クラスへ決定論的に分類する。
 *
 * A は selfReceiptAggregate 全体で 1 個の不可分な署名として扱う。戻り値の
 * protectedA は aggregate の個数（0/1）であり、entry 数ではない。
 */
function classifyEvidenceReceiptsStrict({ bundle, blockNum, groupId, myUid, chatWindow = null }) {
  const uid = String(myUid);
  const snapshot = bundle?.encryptedActions || {};
  const observed = snapshot.observed || {};
  const priority = isPlainRecord(snapshot.priority) ? snapshot.priority : null;
  const receipts = [...(observed.receipts || [])].sort(receiptCanonCmp);
  const getMsgKey = buildMsgKeyGetter(blockNum, groupId);
  const carried = bundle?.messages || [];
  const orderedMessages = priority
    ? [...new Map([...carried, ...(priority.messages || [])]
      .map((message) => [getMsgKey(message), message])).values()]
      .sort(canonicalComparatorV2(getMsgKey))
    : [...carried].sort(canonicalComparatorV2(getMsgKey));

  const readTarget = (senderUid, ref) => `r:${ref}|${senderUid}`;
  const messageTarget = (message) => readTarget(message.uid, msgRefOf(getMsgKey(message)));
  const realTargets = buildRealTargets(snapshot, orderedMessages, blockNum, groupId);

  // 採点・提出物組立と同じ適格性判定を共有する。実在だけでなく、自己受領・型・
  // 署名表現・±10分鮮度もここで落とす。
  //
  // 🔴 J-40b 同型の是正（2026-08-20・第6ラウンド）: **宣言窓（`chatWindow`）を渡す。**
  //    以前はここへ窓を渡しておらず、`receiptCoverClaim` の fail-open により
  //    **窓外の受領証明が満額のカバーとして扱われていた**。採点は窓外を
  //    `game-result-calculator.js` の `if (!inChatWindow(rc.timestamp)) continue;` で
  //    読み飛ばす（＝価値ゼロ）ので、それが保護級 B/C/D/E/F を占めると
  //    **被害者の本物の証拠から先に削られる**（J-40b は採点側で同じ穴を踏み、
  //    実測で冤罪失格が再現している）。
  // 🔴 窓が読めないとき（`chatWindow = null`＝RPC 全滅／未取得）は **fail-open のまま**。
  //    例外時に自分の正当な証拠を捨てないため（ユーザー確定・2026-08-20 判断1(c)）。
  const claimOf = (receipt) => {
    const claim = receiptCoverClaim(receipt, realTargets, {
      maxRefsPerReceipt: MAX_REFS_PER_RECEIPT,
      chatWindow,
    });
    // U-7 (B'): 自分が発行した行動受領証明は採点の出どころではない。
    // legacy atom は H へ落とし、他人の有効な atom を覆ったことにも使わない。
    if (receipt?.receiverUid === uid && receipt.actionHash != null
      && !(Array.isArray(receipt.msgRefs) && receipt.senderUid != null)) {
      return { ...claim, targetKeys: [] };
    }
    return claim;
  };
  // A: self aggregate は署名 1 個で不可分。entries は A が既に覆う対象として使う。
  const aggregate = observed.selfReceiptAggregate;
  const aggregatePriority = aggregate?.signature
    ? (aggregate.entries?.some((entry) => entry?.targetType === 'read') ? 'A' : 'H')
    : null;
  const aCovered = new Set();
  for (const entry of aggregate?.entries || []) {
    if (entry?.targetType === 'action') continue;
    const synthetic = entry?.targetType === 'read'
      ? {
        receiverUid: aggregate.receiverUid, senderUid: entry.senderUid,
        msgRefs: [entry.msgRef], timestamp: entry.timestamp, signature: aggregate.signature,
      }
      : {
        receiverUid: aggregate?.receiverUid, actionHash: entry?.actionHash,
        timestamp: entry?.timestamp, signature: aggregate?.signature,
      };
    const claim = claimOf(synthetic);
    if (!claim.windowed) continue;   // 窓外の entry は covered を汚さない（採点では読み飛ばされる）
    for (const target of claim.targetKeys) aCovered.add(target);
  }

  // E′ の覆いは E の発言についてだけ級の初期覆いにする。
  // 通常欄の発言は、後で E′ が刈られても B1/B2 の根拠を保てるよう通常欄で判定する。
  const eTargets = new Set((priority?.messages || []).map((message) => messageTarget(message)));
  const ePrimeCovered = new Set();
  if (priority) {
    const addPriorityClaim = (receipt) => {
      const claim = claimOf(receipt);
      if (claim.windowed) for (const target of claim.targetKeys) ePrimeCovered.add(target);
    };
    for (const receipt of priority.receipts || []) addPriorityClaim(receipt);
    const eAggregate = priority.selfReceiptAggregate;
    for (const entry of eAggregate?.entries || []) {
      addPriorityClaim(entry?.targetType === 'read'
        ? { receiverUid: eAggregate.receiverUid, senderUid: entry.senderUid,
          msgRefs: [entry.msgRef], timestamp: entry.timestamp, signature: eAggregate.signature }
        : { receiverUid: eAggregate.receiverUid, actionHash: entry?.actionHash,
          timestamp: entry?.timestamp, signature: eAggregate.signature });
    }
  }

  const availableTargets = new Set(aCovered);
  const receiptTargets = new Map();
  const outOfWindow = new Set();
  for (const receipt of receipts) {
    const claim = claimOf(receipt);
    receiptTargets.set(receipt, claim.targetKeys);
    if (!claim.windowed) {
      outOfWindow.add(receipt);
      continue;
    }
    for (const target of claim.targetKeys) availableTargets.add(target);
  }
  if (priority) for (const target of ePrimeCovered) if (eTargets.has(target)) availableTargets.add(target);

  // 🔴 RESULT_GRACE と RECEIPT_FRESH_WINDOW_MS には暗黙の結合がある。
  // 最早 receipt = scheduledGameStart + grace - 10分、宣言窓の開始 =
  // scheduledGameStart - 2分なので、grace >= 8分なら先頭側は必ず窓内に入る。
  // 本番 7,200秒 / テスト 1,200秒は安全だが、8分未満へ縮めると先頭側に
  // 「鮮度は合法だが宣言窓外」の帯が開き、availableTargets から除外される。

  // 自分の全発言・全 action は E の境界にも使う。閾値までに必要な部分だけを
  // B/C へ昇格し、残りは他の補助 receipt より先に保護する。
  const ownTargets = new Set();
  for (const message of orderedMessages) {
    if (message.uid === uid) ownTargets.add(messageTarget(message));
  }
  for (const type of OWN_ACTION_TYPES) {
    for (const section of [snapshot[type === 'vote' ? 'votes' : 'reports'],
      observed[type === 'vote' ? 'votes' : 'reports']]) {
      for (const action of normalizedActions(section, uid)) {
        ownTargets.add(targetForAction(type, blockNum, groupId, uid, action));
      }
    }
  }

  // 再送で公開枠が変わっても、採点が採る最初の有効な投票を守る。
  const ownVoteTargets = new Set([
    ...normalizedActions(snapshot.votes, uid),
    ...normalizedActions(observed.votes, uid),
  ].map((action) => targetForAction('vote', blockNum, groupId, uid, action)));

  // R: 自分の public report 受領証明を最大 2 個保護する。
  const ownReportActions = normalizedActions(snapshot.reports, uid).slice(0, 2);
  const ownReportTargets = new Set(ownReportActions
    .map((action) => targetForAction('report', blockNum, groupId, uid, action)));

  // C2: distinct 最大 2 名について、receipt が実在する正準先頭 5 発言を取れるだけ取る。
  // report の個別復号失敗や発言不足はその action/発言だけを飛ばし、提出を止めない。
  const reportMessageTargets = new Set();
  const reportTargetUids = [];
  try {
    const reports = [
      ...normalizedActions(snapshot.reports, uid),
      ...normalizedActions(observed.reports, uid),
    ].sort((a, b) => Number(a.timestamp) - Number(b.timestamp)
      || String(a.encrypted).localeCompare(String(b.encrypted)));
    for (const report of reports) {
      let targetUid = null;
      try {
        targetUid = decryptAction(report.encrypted, bundle.encryptKey)?.targetUid || null;
      } catch {
        continue;
      }
      if (typeof targetUid !== 'string' || targetUid === uid || reportTargetUids.includes(targetUid)) continue;
      reportTargetUids.push(targetUid);
      if (reportTargetUids.length >= 2) break;
    }
    for (const targetUid of reportTargetUids) {
      const candidates = orderedMessages
        .filter((message) => message.uid === targetUid)
        .map((message) => messageTarget(message))
        .filter((target) => availableTargets.has(target));
      for (const target of candidates.slice(0, 5)) reportMessageTargets.add(target);
    }
  } catch {
    // C の部分計算が不可能でも、R と計算済み C2 は保持したまま続行する。
  }

  const bRequired = new Set();
  const dRequired = new Set();
  let bChars = 0;
  let bTurns = 0;
  let dChars = 0;
  let dTurns = 0;
  let policyFallback = false;

  // B1/B2 と D は、receipt が実在する正準列だけを歩いて閾値到達点を決める。
  // 「turn」は自分の発言直前にある別 uid の発言との組で 1 回と数える。
  try {
    if (priority) {
      const gBefore = priorityTurnGuarantee(priority, {
        ownerUid: uid, blockNum, groupId, minMessages: GUEST_PINNED_RULES.minMessages,
      });
      for (const message of priority.messages || []) {
        if (message.uid === uid) bChars += countVisibleChars(message.text || '');
      }
      for (const message of orderedMessages) {
        const target = messageTarget(message);
        if (message.uid !== uid || eTargets.has(target) || !availableTargets.has(target)) continue;
        if (bChars >= GUEST_PINNED_RULES.minChars) break;
        bRequired.add(target);
        bChars += countVisibleChars(message.text || '');
      }
      if (gBefore < GUEST_PINNED_RULES.minMessages) {
        let counted = 0;
        let previous = null;
        const present = (target) => eTargets.has(target) || availableTargets.has(target);
        for (const message of orderedMessages) {
          const target = messageTarget(message);
          if (message.uid === uid && present(target) && previous && previous.uid !== uid) {
            const previousTarget = messageTarget(previous);
            if (present(previousTarget)) {
              if (!eTargets.has(target)) bRequired.add(target);
              if (!eTargets.has(previousTarget)) bRequired.add(previousTarget);
              counted += 1;
              if (counted >= GUEST_PINNED_RULES.minMessages) break;
            }
          }
          previous = message;
        }
        bTurns = Math.max(gBefore, counted);
      } else bTurns = gBefore;
    }
    let previousMessage = null;
    for (const message of orderedMessages) {
      const currentTarget = messageTarget(message);
      if (message.uid === uid && (availableTargets.has(currentTarget) || (priority && eTargets.has(currentTarget)))) {
        // turn 境界は「receipt がある列の直前」ではなく、正準列で本当に直前の
        // メッセージだけを見る。中間の未受領メッセージを飛ばして隣接扱いしない。
        const previousIsOther = previousMessage && previousMessage.uid !== uid;
        const previousTarget = previousIsOther ? messageTarget(previousMessage) : null;
        const previousTargetAvailable = previousTarget && (availableTargets.has(previousTarget)
          || (priority && eTargets.has(previousTarget)));
        const chars = countVisibleChars(message.text || '');

        if (!priority && (bChars < GUEST_PINNED_RULES.minChars || bTurns < GUEST_PINNED_RULES.minMessages)) {
          bRequired.add(currentTarget);
          bChars += chars;
          if (previousTargetAvailable) {
            bRequired.add(previousTarget);
            bTurns += 1;
          }
        }
        if (dChars < GUEST_PINNED_RULES.minChars * 2 || dTurns < GUEST_PINNED_RULES.minMessages * 2) {
          dRequired.add(currentTarget);
          dChars += chars;
          if (previousTargetAvailable) {
            dRequired.add(previousTarget);
            dTurns += 1;
          }
        }
      }
      previousMessage = message;
    }
    for (const target of bRequired) dRequired.delete(target);
    if (priority) for (const target of eTargets) dRequired.delete(target);
  } catch {
    // 方針計算自体の異常時は旧 B より狭めない。全 own target と全 turn 境界を
    // B に昇格する fail-open で、採点根拠を誤って削らない。
    policyFallback = true;
    bRequired.clear();
    for (const target of ownTargets) bRequired.add(target);
    let previous = null;
    for (const message of orderedMessages) {
      if (message.uid === uid && previous && previous.uid !== uid) {
        bRequired.add(messageTarget(previous));
      }
      previous = message;
    }
    dRequired.clear();
  }

  // S3R5-U-R13-SELF: 自分の密告の根拠（標的の投票で密告の自称時刻より前・自分と標的以外の
  // 宣言窓内の受領証明が覆う最も早い1件）を、自分の密告への受領証明と同じ R に置く。
  const rootVoteTargets = new Set();
  try {
    for (const report of [
      ...normalizedActions(snapshot.reports, uid),
      ...normalizedActions(observed.reports, uid),
    ]) {
      let targetUid = null;
      try {
        targetUid = decryptAction(report.encrypted, bundle.encryptKey)?.targetUid || null;
      } catch {
        continue;
      }
      if (typeof targetUid !== 'string' || targetUid === uid) continue;
      for (const vote of normalizedActions(observed.votes, targetUid)) {
        if (!(Number(vote.timestamp) < Number(report.timestamp))) break;
        const target = targetForAction('vote', blockNum, groupId, targetUid, vote);
        if (availableTargets.has(target)) { rootVoteTargets.add(target); break; }
      }
    }
  } catch {
    // 根拠の計算が不可能でも、他の級はそのまま続行する。
  }
  const rRequired = new Set([...ownReportTargets, ...rootVoteTargets]);
  const cRequired = new Set([...reportMessageTargets]);
  const priorities = new Map();
  const covered = new Set(aCovered);
  if (priority) for (const target of ePrimeCovered) if (eTargets.has(target)) covered.add(target);
  // H は採点に効く対象を1件も持たない atom。最初に削るため、他クラスへ昇格させない。
  for (const receipt of receipts) {
    if ((receiptTargets.get(receipt) || []).length === 0) priorities.set(receipt, 'H');
  }
  // 🔴 宣言窓の外の atom は採点で読み飛ばされる（価値ゼロ）。保護級へ昇格させず G へ落とす。
  //    H（何もカバーしていない）とは区別するが、提出時点の宣言窓は固定済みであり、
  //    extendGrace 後にこの同じ提出 atom が窓内へ戻ることはない。
  for (const receipt of receipts) {
    if (!priorities.has(receipt) && outOfWindow.has(receipt)) priorities.set(receipt, 'G');
  }

  const assign = (priority, requiredTargets) => {
    for (const receipt of receipts) {
      if (priorities.has(receipt)) continue;
      const targets = receiptTargets.get(receipt) || [];
      if (!targets.some((target) => requiredTargets.has(target) && !covered.has(target))) continue;
      priorities.set(receipt, priority);
      for (const target of targets) covered.add(target);
    }
  };

  // 投票は一件欠けるだけで失格するため、チャットの下限とは別の最終保護級にする。
  assign('V', ownVoteTargets);
  assign('B', bRequired);
  assign('R', rRequired);
  assign('C', cRequired);
  assign('D', dRequired);
  assign('E', ownTargets);
  assign('F', availableTargets);
  for (const receipt of receipts) if (!priorities.has(receipt)) priorities.set(receipt, 'G');

  const classCounts = { A: aggregatePriority === 'A' ? 1 : 0, B: 0, C: 0, D: 0, E: 0, F: 0, G: 0, H: aggregatePriority === 'H' ? 1 : 0, R: 0, V: 0 };
  for (const priority of priorities.values()) classCounts[priority] += 1;

  return {
    receipts,
    priorities,
    receiptTargets,
    classCounts,
    protectedA: classCounts.A,
    aggregatePriority,
    protectedB: classCounts.B,
    protectedV: classCounts.V,
    protectedC: classCounts.C,
    protectedR: classCounts.R,
    requiredTargets: {
      B: bRequired,
      V: ownVoteTargets,
      R: rRequired,
      C: cRequired,
      D: dRequired,
      E: ownTargets,
    },
    thresholds: {
      minChars: GUEST_PINNED_RULES.minChars,
      minTurns: GUEST_PINNED_RULES.minMessages,
      safetyChars: GUEST_PINNED_RULES.minChars * 2,
      safetyTurns: GUEST_PINNED_RULES.minMessages * 2,
      bChars,
      bTurns,
      dChars,
      dTurns,
      bReached: bChars >= GUEST_PINNED_RULES.minChars && bTurns >= GUEST_PINNED_RULES.minMessages,
      dReached: dChars >= GUEST_PINNED_RULES.minChars * 2 && dTurns >= GUEST_PINNED_RULES.minMessages * 2,
    },
    policyFallback,
  };
}

/**
 * 方針計算の前処理を含むどの異常でも Evidence 提出経路へ例外を漏らさない。
 * strict 判定を完了できなければ全 legacy receipt を B に昇格する。これは通常の
 * 旧 B（自分の全発言・全 turn 境界）よりさらに広い保護であり、採点根拠を
 * 誤削除する向きへは絶対に倒れない。
 */
export function classifyEvidenceReceipts(input) {
  try {
    return classifyEvidenceReceiptsStrict(input);
  } catch {
    const raw = input?.bundle?.encryptedActions?.observed?.receipts;
    const receipts = Array.isArray(raw) ? [...raw] : [];
    try { receipts.sort(receiptCanonCmp); } catch { /* 元の順序を維持する */ }
    const priorities = new Map(receipts.map((receipt) => [receipt, 'B']));
    return {
      receipts,
      priorities,
      receiptTargets: new Map(receipts.map((receipt) => [receipt, []])),
      classCounts: { A: 0, B: receipts.length, C: 0, D: 0, E: 0, F: 0, G: 0, H: 0, R: 0, V: 0 },
      protectedA: 0,
      aggregatePriority: input?.bundle?.encryptedActions?.observed?.selfReceiptAggregate ? 'A' : null,
      protectedB: receipts.length,
      protectedV: 0,
      protectedC: 0,
      protectedR: 0,
      requiredTargets: {
        B: new Set(), C: new Set(), D: new Set(), E: new Set(), R: new Set(), V: new Set(),
      },
      thresholds: {
        minChars: GUEST_PINNED_RULES.minChars,
        minTurns: GUEST_PINNED_RULES.minMessages,
        safetyChars: GUEST_PINNED_RULES.minChars * 2,
        safetyTurns: GUEST_PINNED_RULES.minMessages * 2,
        bChars: 0,
        bTurns: 0,
        dChars: 0,
        dTurns: 0,
        bReached: false,
        dReached: false,
      },
      policyFallback: true,
    };
  }
}
