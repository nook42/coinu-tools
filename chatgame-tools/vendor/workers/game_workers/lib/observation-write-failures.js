// 観測用 writer 自身が失敗した事実を、別の writer を増やさずに保持する。
// total / acknowledged の世代で管理するため、書込み中に新しい失敗が増えても
// 古い成功が後発分まで誤って消すことはない。
export function createObservationWriteFailureCounter() {
  return { total: 0, acknowledged: 0, lastReason: null };
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function safeReason(reason) {
  return typeof reason === 'string' && /^[a-z0-9_:-]{1,64}$/.test(reason)
    ? reason
    : 'observation_write_failed';
}

export function recordObservationWriteFailure(counter, reason = 'observation_write_failed') {
  if (!counter || typeof counter !== 'object') return 0;
  counter.total = Math.min(Number.MAX_SAFE_INTEGER, safeCount(counter.total) + 1);
  counter.acknowledged = Math.min(safeCount(counter.acknowledged), counter.total);
  counter.lastReason = safeReason(reason);
  return counter.total - counter.acknowledged;
}

export function captureObservationWriteFailures(counter) {
  const total = safeCount(counter?.total);
  const acknowledged = Math.min(safeCount(counter?.acknowledged), total);
  return {
    count: Math.max(0, total - acknowledged),
    through: total,
    reason: counter?.lastReason ? safeReason(counter.lastReason) : null,
  };
}

export function acknowledgeObservationWriteFailures(counter, snapshot) {
  if (!counter || typeof counter !== 'object') return 0;
  const through = Math.min(safeCount(snapshot?.through), safeCount(counter.total));
  counter.acknowledged = Math.max(safeCount(counter.acknowledged), through);
  return captureObservationWriteFailures(counter).count;
}

export function observationWriteFailureFields(counter) {
  const snapshot = captureObservationWriteFailures(counter);
  return {
    observationWriteFailures: snapshot.count,
    observationWriteFailureReason: snapshot.count > 0 ? snapshot.reason : null,
  };
}

// 既存の観測オブジェクトへ pending 件数だけを加算する。呼出元は実際の
// observation write が成功した後にだけ acknowledge すること。
export function carryObservationWriteFailures(target, counter) {
  const snapshot = captureObservationWriteFailures(counter);
  const previous = safeCount(target?.observationWriteFailures);
  if (target && typeof target === 'object') {
    target.observationWriteFailures = Math.min(Number.MAX_SAFE_INTEGER, previous + snapshot.count);
    if (snapshot.count > 0) target.observationWriteFailureReason = snapshot.reason;
    else if (!('observationWriteFailureReason' in target)) target.observationWriteFailureReason = null;
  }
  return snapshot;
}
