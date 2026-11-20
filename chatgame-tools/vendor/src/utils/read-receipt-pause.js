// 自動既読を止める時間窓。窓の期限には performance.now() だけを使う。
export function readReceiptTickGap(previous, monotonicNow, wallNow) {
  return !!previous && (monotonicNow - previous.lastTickAt >= 30000
    || (Number.isFinite(previous.lastTickWallAt) && wallNow - previous.lastTickWallAt >= 30000));
}

// 接続状態の変化だけを見る。最初の接続は「再接続」ではない。
export function readReceiptConnectionChange(previous, connected, now) {
  const wasConnected = !!previous?.connected;
  const disconnectedAt = wasConnected && !connected ? now : previous?.disconnectedAt ?? null;
  return {
    connected,
    disconnectedAt: connected ? null : disconnectedAt,
    reopen: connected && !wasConnected && disconnectedAt !== null && now - disconnectedAt >= 30000,
  };
}

export function openReadReceiptPause(previous, now, fresh = false, wallNow = null) {
  const cap = previous?.sequenceStartAt + 30000;
  // 上限に達した連なりは次の tick が窓の外を観測するまで開き直さない。
  // 画面の出入りと tick の位相が重なっても、30秒の上限を越えて止まらない。
  const capped = previous && !previous.settled && previous.until >= cap && now >= cap;
  // スリープからの復帰は新しく10秒開く。同じ連なりで tick 遅延が反復しても
  // 次々と連なりを作り直さず、30秒上限の後の tick は発行可能にする。
  const gapReopen = !!previous && fresh
    && (!previous.gapReopenUsed || readReceiptTickGap(previous, now, wallNow));
  const newSequence = !previous || previous.settled || gapReopen;
  const sequenceStartAt = newSequence ? now : previous.sequenceStartAt;
  return {
    until: capped && !newSequence ? previous.until : Math.min(now + 10000, sequenceStartAt + 30000),
    sequenceStartAt,
    lastTickAt: now,
    lastTickWallAt: wallNow ?? previous?.lastTickWallAt ?? null,
    gapReopenUsed: gapReopen || (!newSequence && !!previous.gapReopenUsed),
  };
}
