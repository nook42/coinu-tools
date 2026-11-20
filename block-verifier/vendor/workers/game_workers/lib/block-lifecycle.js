// TokenMining のブロック別lifecycleを listener / 第三者verifierで共有する純粋ロジック。
// 現在状態の権威は getBlockLifecycle、履歴の権威はevent replayであり、どちらも推測で補わない。

export const BLOCK_MODE_ADMIN_COMMIT = 0;
export const BLOCK_MODE_ETH_STAKE = 1;
export const BLOCK_STAGE = Object.freeze({ LOCKED: 0, ROOT_MISSING: 1, WAITING: 2, CLAIM: 3, CLOSED: 4 });
export const MAX_VERIFICATION_EXTENSION_SEC = 90 * 24 * 60 * 60;
export const TIMELINE_NO_GAME_ROOT_STATE = Object.freeze({
  NOT_TIMELINE_NO_GAME: 'not_timeline_no_game',
  DEADLINE_UNKNOWN: 'deadline_unknown',
  OMISSION_PENDING: 'omission_pending',
  OMITTED_TERMINAL: 'omitted_terminal',
  ROOT_SUBMITTED: 'root_submitted',
});
export const TIMELINE_NO_GAME_BASIS_STRENGTH = Object.freeze({
  NOT_APPLICABLE: 'not_applicable',
  LABEL_ONLY: 'label_only',
  VERIFIED: 'verified',
});

const finiteInt = (value, name, { min = 0 } = {}) => {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min) throw new Error(`invalid ${name}: ${value}`);
  return n;
};

export function normalizeBlockLifecycle(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('block lifecycle is unavailable');
  const lifecycle = {
    mode: finiteInt(raw.mode ?? raw[0], 'lifecycle.mode'),
    merkleRoot: raw.merkleRoot ?? raw[1] ?? null,
    verificationStartedAt: finiteInt(raw.verificationStartedAt ?? raw[2], 'lifecycle.verificationStartedAt'),
    verificationEndsAt: finiteInt(raw.verificationEndsAt ?? raw[3], 'lifecycle.verificationEndsAt'),
    claimEndsAt: finiteInt(raw.claimEndsAt ?? raw[4], 'lifecycle.claimEndsAt'),
    stage: finiteInt(raw.stage ?? raw[5], 'lifecycle.stage'),
  };
  if (![BLOCK_MODE_ADMIN_COMMIT, BLOCK_MODE_ETH_STAKE].includes(lifecycle.mode)) {
    throw new Error(`unsupported lifecycle mode: ${lifecycle.mode}`);
  }
  if (lifecycle.stage > BLOCK_STAGE.CLOSED) throw new Error(`invalid lifecycle stage: ${lifecycle.stage}`);
  if (lifecycle.verificationEndsAt > lifecycle.claimEndsAt && lifecycle.claimEndsAt !== 0) {
    throw new Error('lifecycle claimEndsAt precedes verificationEndsAt');
  }
  return lifecycle;
}

export function adminCommitPermanentEnd(resultCloseAt, claimPeriodSec) {
  return finiteInt(resultCloseAt, 'resultWindow.closeAt')
    + MAX_VERIFICATION_EXTENSION_SEC
    + finiteInt(claimPeriodSec, 'claimPeriod');
}

// TokenMining._submitMerkleRoot と同じ初回root提出の最終時刻。
// block.timestamp + verificationPeriod <= resultCloseAt + 90日 の間だけ提出できる。
export function adminCommitRootSubmissionDeadline(resultCloseAt, verificationPeriodSec) {
  const closeAt = finiteInt(resultCloseAt, 'resultWindow.closeAt');
  const period = finiteInt(verificationPeriodSec, 'verificationPeriod', { min: 1 });
  const deadline = closeAt + MAX_VERIFICATION_EXTENSION_SEC - period;
  if (!Number.isSafeInteger(deadline) || deadline < closeAt) {
    throw new Error('verificationPeriod exceeds the root submission cap');
  }
  return deadline;
}

/**
 * Q40-01(b) の timeline no-game 専用分類。
 * 通常ブロックと zero_entries は一切緩和せず、timeline_unverified のときだけ
 * root あり／提出期限前の省略予定／期限後の期待された省略終端を区別する。
 */
export function classifyTimelineNoGameRoot({
  summary,
  chainRoot = null,
  rootSubmissionDeadlineSec = null,
  nowSec,
  proofRequired = null,
  verification = null,
}) {
  const timelineNoGame = summary?.noGame === true
    && summary?.noGameReason === 'timeline_unverified';
  const root = typeof chainRoot === 'string' ? chainRoot.toLowerCase() : null;
  const rootSubmitted = /^0x[0-9a-f]{64}$/.test(root || '')
    && root !== `0x${'0'.repeat(64)}`;
  const normalizedProofRequired = typeof proofRequired === 'boolean' ? proofRequired : null;
  const normalizedBasisNumber = (value) => value !== null && value !== undefined
    && Number.isSafeInteger(Number(value)) ? Number(value) : null;
  const basis = {
    safeResultWindowClosed: verification?.safeResultWindowClosed === true,
    evidenceResultCount: normalizedBasisNumber(verification?.evidenceResultCount),
    selectedPlayerCount: normalizedBasisNumber(verification?.selectedPlayerCount),
    chatStartEvidenceAbsent: verification?.chatStartEvidenceAbsent === true,
  };
  const basisVerified = basis.safeResultWindowClosed
    && basis.evidenceResultCount === 0
    && basis.selectedPlayerCount >= 3
    && basis.chatStartEvidenceAbsent;
  const common = {
    timelineNoGame,
    rootSubmitted,
    expectedRootOmission: false,
    terminal: false,
    deadlineKnown: false,
    deadlinePassed: null,
    rootSubmissionDeadlineSec: null,
    proofRequired: normalizedProofRequired,
    basis,
    basisStrength: timelineNoGame
      ? (basisVerified
        ? TIMELINE_NO_GAME_BASIS_STRENGTH.VERIFIED
        : TIMELINE_NO_GAME_BASIS_STRENGTH.LABEL_ONLY)
      : TIMELINE_NO_GAME_BASIS_STRENGTH.NOT_APPLICABLE,
  };

  if (!timelineNoGame) {
    return { ...common, state: TIMELINE_NO_GAME_ROOT_STATE.NOT_TIMELINE_NO_GAME };
  }
  if (rootSubmitted) {
    return { ...common, state: TIMELINE_NO_GAME_ROOT_STATE.ROOT_SUBMITTED };
  }

  const now = finiteInt(nowSec, 'nowSec');
  if (rootSubmissionDeadlineSec === null || rootSubmissionDeadlineSec === undefined) {
    return {
      ...common,
      state: TIMELINE_NO_GAME_ROOT_STATE.DEADLINE_UNKNOWN,
      expectedRootOmission: basisVerified,
    };
  }
  const deadline = finiteInt(rootSubmissionDeadlineSec, 'rootSubmissionDeadlineSec');
  // 契約は等号を許すため、終端は deadline を「過ぎた」最初の秒から。
  const deadlinePassed = now > deadline;
  return {
    ...common,
    state: deadlinePassed
      ? TIMELINE_NO_GAME_ROOT_STATE.OMITTED_TERMINAL
      : TIMELINE_NO_GAME_ROOT_STATE.OMISSION_PENDING,
    expectedRootOmission: basisVerified,
    terminal: deadlinePassed,
    deadlineKnown: true,
    deadlinePassed,
    rootSubmissionDeadlineSec: deadline,
  };
}

/**
 * listener用分類。AdminCommitのstage=4は90日capまで再延長・root再提出で再開し得るため、
 * currentClosedとpermanentlyTerminalを分離する。EthStakeはcontract lifecycleだけで閉じる。
 */
export function classifyBlockForClaimListener({ lifecycle: raw, nowSec, resultCloseAt = null, claimPeriodSec = null }) {
  const lifecycle = normalizeBlockLifecycle(raw);
  const now = finiteInt(nowSec, 'nowSec');
  if (lifecycle.mode === BLOCK_MODE_ETH_STAKE) {
    return {
      lifecycle,
      currentClosed: lifecycle.stage === BLOCK_STAGE.CLOSED,
      permanentlyTerminal: lifecycle.stage === BLOCK_STAGE.CLOSED && now >= lifecycle.claimEndsAt,
      permanentEndAt: lifecycle.claimEndsAt,
    };
  }
  const permanentEndAt = adminCommitPermanentEnd(resultCloseAt, claimPeriodSec);
  const permanentlyClosedStage = lifecycle.stage === BLOCK_STAGE.CLOSED
    || lifecycle.stage === BLOCK_STAGE.ROOT_MISSING;
  return {
    lifecycle,
    currentClosed: lifecycle.stage === BLOCK_STAGE.CLOSED,
    permanentlyTerminal: permanentlyClosedStage && now >= permanentEndAt,
    permanentEndAt,
  };
}

export function advancePermanentTerminalPrefix(floor, walked) {
  let next = finiteInt(floor, 'terminal floor');
  for (const item of walked || []) {
    if (finiteInt(item.blockNum, 'walked.blockNum') !== next || item.kind !== 'terminal') break;
    next++;
  }
  return next;
}

export function classifyProofAttachment(proofAttachedAt, verificationEndsAt) {
  const proofAt = finiteInt(proofAttachedAt, 'proofAttachedAt');
  const endAt = finiteInt(verificationEndsAt, 'verificationEndsAt', { min: 1 });
  return proofAt < endAt ? 'proof_available_before_claim' : 'post_claim_assurance_only';
}

function eventPosition(event) {
  return [
    finiteInt(event.evtBlock ?? event.blockNumber, 'event.blockNumber'),
    finiteInt(event.transactionIndex, 'event.transactionIndex'),
    finiteInt(event.logIndex, 'event.logIndex'),
  ];
}

export function compareLifecycleEventOrder(a, b) {
  const ap = eventPosition(a);
  const bp = eventPosition(b);
  return ap[0] - bp[0] || ap[1] - bp[1] || ap[2] - bp[2];
}

/** MerkleRootSubmitted / MerkleRootInvalidated / VerificationExtended をEthereum event順に再生する。 */
export function replayAdminCommitLifecycle({ rootEvents, invalidationEvents, extensionEvents, verificationPeriodSec, verificationCap }) {
  const period = finiteInt(verificationPeriodSec, 'verificationPeriod', { min: 1 });
  const cap = finiteInt(verificationCap, 'verificationCap', { min: 1 });
  const events = [
    ...(rootEvents || []).map((event) => ({ ...event, kind: 'root' })),
    ...(invalidationEvents || []).map((event) => ({ ...event, kind: 'invalidation' })),
    ...(extensionEvents || []).map((event) => ({ ...event, kind: 'extension' })),
  ].sort(compareLifecycleEventOrder);
  const errors = [];
  let root = null;
  let startedAt = 0;
  let floor = 0;
  const history = [];

  for (const event of events) {
    const timestamp = finiteInt(event.timestamp, `${event.kind}.timestamp`);
    if (event.kind === 'extension') {
      const nextFloor = finiteInt(event.newEndFloor, 'VerificationExtended.newEndFloor', { min: 1 });
      const effectiveBefore = root === null ? 0 : Math.max(startedAt + period, floor);
      if (root === null) errors.push(`extension occurred before a Merkle root at ${timestamp}`);
      if (root !== null && nextFloor <= effectiveBefore) errors.push(`extension did not increase effective end at ${timestamp}`);
      if (nextFloor > cap) errors.push(`extension exceeded verification cap at ${timestamp}`);
      // 🔴 R26-C1 のミラー（2026-08-13）: **閉じた窓は開け直せない。**
      //    契約側 `TokenMining.extendVerification` は
      //    `if (effectiveEnd != 0 && block.timestamp >= effectiveEnd) revert VerificationPeriodEnded();`
      //    を強制する。ここに同じ規則が無いと、**請求開始後に窓を開け直して root を差し替えた履歴**
      //    （＝ R26-C1 の窃取そのもの）を replay が `ok: true` と判定し、
      //    Stage C は `rootSubmissionRules` / `lifecycleReplayCurrent` を pass にしてしまう。
      //    残る信号は `rootResubmitted` の warn だけで、正当な窓内修復と区別できない。
      //    block-verifier は TokenMining を**アドレスでしか束縛していない**（`index.js` は
      //    `getCode` が空でないことしか見ない）ので、ガードを外した契約を配備された場合に
      //    それを機械検出できる層は**この replay しかない**。だから契約と同じ規則をここに置く。
      //    ↔ 6行下の root 分岐が既に持っている `at/after effective end` と同型。
      if (root !== null && timestamp >= effectiveBefore) {
        errors.push(`extension re-opened a closed verification window at ${timestamp} (>= ${effectiveBefore})`);
      }
      floor = Math.max(floor, nextFloor);
    } else if (event.kind === 'invalidation') {
      root = null;
      startedAt = 0;
    } else {
      if (typeof event.root !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(event.root)) {
        errors.push(`invalid root event at ${timestamp}`);
      }
      if (timestamp + period > cap) errors.push(`root left less than a full verificationPeriod at ${timestamp}`);
      if (root !== null) {
        const effectiveBefore = Math.max(startedAt + period, floor);
        if (timestamp >= effectiveBefore) errors.push(`root resubmission at/after effective end (${timestamp} >= ${effectiveBefore})`);
      }
      root = event.root;
      startedAt = timestamp;
    }
    history.push({
      kind: event.kind,
      timestamp,
      evtBlock: Number(event.evtBlock ?? event.blockNumber),
      transactionIndex: Number(event.transactionIndex),
      logIndex: Number(event.logIndex),
      root,
      verificationStartedAt: startedAt,
      verificationEndFloor: floor,
      verificationEndsAt: root === null ? 0 : Math.max(startedAt + period, floor),
    });
  }

  const verificationEndsAt = root === null ? 0 : Math.max(startedAt + period, floor);
  return {
    ok: errors.length === 0,
    errors,
    root,
    verificationStartedAt: startedAt,
    verificationEndFloor: floor,
    verificationEndsAt,
    history,
  };
}

export function lifecycleReplayMatchesCurrent(replay, currentRaw, claimPeriodSec) {
  const current = normalizeBlockLifecycle(currentRaw);
  const claimPeriod = finiteInt(claimPeriodSec, 'claimPeriod');
  const mismatches = [];
  if (current.mode !== BLOCK_MODE_ADMIN_COMMIT) mismatches.push(`mode=${current.mode} is not AdminCommit`);
  if (String(replay.root || '').toLowerCase() !== String(current.merkleRoot || '').toLowerCase()) mismatches.push('root');
  if (replay.verificationStartedAt !== current.verificationStartedAt) mismatches.push('verificationStartedAt');
  if (replay.verificationEndsAt !== current.verificationEndsAt) mismatches.push('verificationEndsAt');
  const expectedClaimEnd = replay.verificationEndsAt === 0 ? 0 : replay.verificationEndsAt + claimPeriod;
  if (expectedClaimEnd !== current.claimEndsAt) mismatches.push('claimEndsAt');
  return { ok: replay.ok && mismatches.length === 0, mismatches, current, expectedClaimEnd };
}
