// VDC: 見える確定した投票と厳密な時刻境界。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hasTimestampVisibleConfirmedVote, isTimestampVisible } from '../src/recovery/app.js';

const NOW = 1_750_000_000_000;
const vote = (timestamp) => ({ encrypted: 'cipher', timestamp });
const eligible = (votes, receiptors, nowMs = NOW) => hasTimestampVisibleConfirmedVote({
  votes, ownUid: 'self', targetUid: 'target', nowMs,
  receiptorsForVote: () => receiptors,
});

assert.equal(isTimestampVisible(NOW, NOW), false);
assert.equal(isTimestampVisible(NOW - 1, NOW), true);
assert.equal(eligible([vote(NOW)], ['third']), false, '同じミリ秒は送れない');
assert.equal(eligible([vote(NOW - 1)], ['third']), true, '1ms 後は送れる');
assert.equal(eligible([vote(NOW - 1)], ['self']), false, '見る人自身は第三者でない');
assert.equal(eligible([vote(NOW - 1)], ['target']), false, '標的自身は第三者でない');
assert.equal(eligible([vote(NOW + 1)], ['third']), false, '未来の票は見えない');
assert.equal(eligible([vote(NOW), vote(NOW - 1)], ['third']), true, '__extras の票も数える');

// 公式の useCallback 本体も同じ盤面で実行し、見る人自身を数えないことを固定する。
const chat = readFileSync(new URL('../../src/components/game/ChatPhase.js', import.meta.url), 'utf8');
const marker = 'const hasVisibleConfirmedVote = useCallback(';
const start = chat.indexOf(marker);
const end = chat.indexOf('\n  }, [observedActions', start);
assert(start >= 0 && end > start);
const callback = chat.slice(start + marker.length, end + '\n  }'.length);
const official = (primary, extras, receiptors, nowMs = NOW) => {
  const observedActions = { votes: { target: primary, 'target__extras': extras } };
  const receiptorsByActionHash = Object.fromEntries([primary, ...extras].filter(Boolean)
    .map((v) => [`${v.encrypted}:${v.timestamp}`, new Set(receiptors)]));
  const scope = { observedActions, receiptorsByActionHash, blockNum: 1, groupId: 2, myUid: 'self',
    actionHashV2: (_type, _block, _group, _actor, encrypted, timestamp) => `${encrypted}:${timestamp}`,
    isTimestampVisible };
  const fn = new Function(...Object.keys(scope), `return (${callback});`)(...Object.values(scope));
  return fn('target', nowMs);
};
for (const [primary, extras, readers, expected] of [
  [vote(NOW - 1), [], ['third'], true],
  [vote(NOW), [], ['third'], false],
  [vote(NOW - 1), [], ['self'], false],
  [vote(NOW - 1), [], ['target'], false],
  [null, [vote(NOW - 1)], ['third'], true],
  [null, [], ['third'], false],
]) {
  assert.equal(official(primary, extras, readers), expected);
  assert.equal(eligible([primary, ...extras], readers), expected);
}

// 締切不明ではラスト10分の枝を開かず、ちょうど cutoff から誰にでも開く。
const officialGateMarker = 'const canReportTarget = useCallback(';
const officialGateStart = chat.indexOf(officialGateMarker);
const officialGateEnd = chat.indexOf(',\n  [voteCutoff, hasVisibleConfirmedVote]);', officialGateStart);
assert(officialGateStart >= 0 && officialGateEnd > officialGateStart);
const officialGateSource = chat.slice(officialGateStart + officialGateMarker.length, officialGateEnd);
const recoverySource = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const recoveryGateStart = recoverySource.indexOf('function canReportTarget(targetUid, atMs) {');
const recoveryGateEnd = recoverySource.indexOf('\n// 自分の発信', recoveryGateStart);
assert(recoveryGateStart >= 0 && recoveryGateEnd > recoveryGateStart);
const recoveryGateSource = recoverySource.slice(recoveryGateStart, recoveryGateEnd);
const gatePair = (cutoff, confirmed) => {
  const hasVisibleConfirmedVote = () => confirmed;
  const officialGate = new Function('voteCutoff', 'hasVisibleConfirmedVote',
    `return (${officialGateSource});`)(cutoff, hasVisibleConfirmedVote);
  const recoveredGate = new Function('submissionChatCloseAt', 'VOTE_RECEIPT_CUTOFF_MS',
    'hasVisibleConfirmedVote', `${recoveryGateSource}\nreturn canReportTarget;`)(
    () => cutoff === null ? null : cutoff + 600000, 600000, hasVisibleConfirmedVote);
  return [officialGate, recoveredGate];
};
for (const [cutoff, confirmed, atMs, expected] of [
  [600000, false, 599999, false],
  [600000, false, 600000, true],
  [600000, true, 599999, true],
  [null, false, 600000, false],
  [null, true, 600000, true],
]) {
  assert.deepEqual(gatePair(cutoff, confirmed).map((gate) => gate('target', atMs)),
    [expected, expected]);
}
assert.match(chat, /const voteCutoff = Number\.isSafeInteger\(chatCloseAt\) \? chatCloseAt - VOTE_RECEIPT_CUTOFF_MS : null;/);
console.log('timestamp-visibility-unit: ALL PASSED (19 checks, official/recovery parity)');
