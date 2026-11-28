import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { soleRemainingReportTarget } from '../../src/utils/receipt-warnings.js';
import { actionHashV2, clientChatSourcedReceipts, isReceiptTimely, markActionReceiptSource } from '../../workers/game_workers/lib/protocol-v2.js';
import { formatName } from '../../src/utils/tool.js';
import { playerNumberOf, pointedTemplateText, pointedTemplateParts } from '../vendor/src/utils/playerNumber.js';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
const originalChat = read('src/components/game/ChatPhase.js');
const page = read('src/pages/game.js');
const phaseCall = (name) => {
  const start = page.indexOf(`<${name}`);
  assert.notEqual(start, -1, `${name} の描画がある`);
  const end = page.indexOf('/>', start);
  assert.notEqual(end, -1, `${name} の属性が閉じる`);
  return page.slice(start, end + 2);
};
const chatCall = phaseCall('ChatPhase');
const waitingCall = phaseCall('WaitingPhase');
const originalRecovery = process.env.T8_RECOVERY_APP_SOURCE
  ? readFileSync(process.env.T8_RECOVERY_APP_SOURCE, 'utf8') : read('chatgame-tools/src/recovery/app.js');
const mutations = {
  'notice-band-off': [originalChat, "showActionNotice('error', t('game.action.votingClosed'));", 'void 0;'],
  'last10-no-warning': [originalChat, 'if (!unconfirmedApproved && !hasVisibleConfirmedVote(targetUid, nowTick))', 'if (false)'],
  'vote-recheck': [originalChat, 'if (voteCutoff !== null && sendAt >= voteCutoff)', 'if (false)'],
  'report-recheck': [originalChat, "if (!canReportTarget(targetUid, sendAt)) { showActionNotice('error', t('game.action.reportNotSent')); return; }", 'if (false) return;'],
  'report-warning-target': [originalChat, 'if (!warningApproved && soleTarget === targetUid)', 'if (!warningApproved && !!soleTarget)'],
  'recovery-vote-recheck': [originalRecovery,
    'if (Number.isSafeInteger(sendCloseAt) && ts >= sendCloseAt - VOTE_RECEIPT_CUTOFF_MS)', 'if (false)'],
  'recovery-report-recheck': [originalRecovery, 'if (!canReportTarget(targetUid, ts)) return;', 'if (false) return;'],
};
const mutation = mutations[process.env.VDC_G2_MUTATION];
if (mutation) assert(mutation[0].includes(mutation[1]), '変異位置が現物にある');
const chat = mutation?.[0] === originalChat ? originalChat.replace(mutation[1], mutation[2]) : originalChat;
const recovery = mutation?.[0] === originalRecovery ? originalRecovery.replace(mutation[1], mutation[2]) : originalRecovery;
const gameUtils = read('src/utils/gameUtils.js');
const officialPointedSource = gameUtils.slice(gameUtils.indexOf('export const getMemberDisplayName ='), gameUtils.indexOf('// 失格理由コード'))
  .replace('export const getMemberDisplayName', 'const getMemberDisplayName').replace('export function pointedMemberText', 'function pointedMemberText')
  .replace('export function playerNumberTitle', 'function playerNumberTitle').split('export function pointedMemberNodes')[0];
const pointedMemberText = new Function('formatName', 'playerNumberOf', 'pointedTemplateText',
  `${officialPointedSource}\nreturn pointedMemberText;`)(formatName, playerNumberOf, pointedTemplateText);
const recoveryPointedSource = `${recovery.slice(recovery.indexOf('function reportWarningName('), recovery.indexOf('\nasync function freshRecoveryClockReading('))}\n${recovery.slice(recovery.indexOf('function memberName(m) {'), recovery.indexOf('\n// デポジットポイントは', recovery.indexOf('function memberName(m) {')))}`;
const bindRecoveryPointed = (state, el = () => null) => new Function('state', 'el', 'playerNumberOf', 'pointedTemplateText', 'pointedTemplateParts',
  `${recoveryPointedSource}\nreturn { recoveryPointedText, recoveryPointedElement };`)(state, el, playerNumberOf, pointedTemplateText, pointedTemplateParts);
const i18n = read('chatgame-tools/src/common/i18n.js');
const warnings = await import(`data:text/javascript,${encodeURIComponent(read('src/utils/chatWarnings.js'))}`);
const ja = JSON.parse(read('public/locales/ja/game_ja.json'));
const en = JSON.parse(read('public/locales/en/game_en.json'));
const hook = read('src/hooks/useGameWebSocket.js');
assert.match(hook, /const chatCloseAt = chainTimeline\?\.chatCloseAt[\s\S]*?confirmedChatWindow\.endMs - CHAT_WINDOW_CLOCK_SKEW_MS/);
assert.match(chatCall, /chatCloseAt=\{ws\.chatCloseAt\}/);
assert.doesNotMatch(waitingCall, /chatCloseAt/);
assert.match(chatCall, /phaseEndTime=\{currentPhaseEndTime\}/);
assert.match(chat, /const voteCutoff = Number\.isSafeInteger\(chatCloseAt\) \? chatCloseAt - VOTE_RECEIPT_CUTOFF_MS : null;/);

const disabledExpression = chat.match(/const voteDisabled = ([\s\S]*?);/)?.[1];
assert(disabledExpression);
const isVoteDisabled = (myVoteVoid, votingClosed) => new Function('myVoteVoid', 'votingClosed',
  'member', 'localVoteTarget', 'myVote', 'p2pSelfVoted', `return ${disabledExpression};`)(
  myVoteVoid, votingClosed, { uid: 'B' }, 'B', null, false);
assert.equal(isVoteDisabled(true, false), false, 'void 票は cutoff の1ms前なら再送できる');
assert.equal(isVoteDisabled(true, true), true, 'void 票も cutoff ちょうどで閉じる');
assert.equal(isVoteDisabled(false, false), true, '既投票の one-shot 門は維持する');
assert.equal(new Function('myVoteVoid', 'votingClosed', 'member', 'localVoteTarget',
  'myVote', 'p2pSelfVoted', `return ${disabledExpression};`)(
  false, false, { uid: 'B' }, null, null, false), false,
  '締切不明なら新しい投票ボタンは開く');
assert.match(chat, /myVoteVoid \? t\(votingClosed \? 'game\.action\.voteVoidNoResend'/);

// J-29 は送った全件で判定する。最低条件の既読付き会話数とは別の単位。
assert.equal(warnings.shouldWarnConsecutivePosts(70, 9), true);
const voidHeavy = { allSent: 70, receipted: 45, turns: 9, maxSent: 100, minTurns: 20 };
assert.equal(warnings.shouldWarnConsecutivePosts(voidHeavy.allSent, voidHeavy.turns), true);
assert.equal(warnings.shouldWarnConsecutivePosts(voidHeavy.receipted, voidHeavy.turns), false);
assert.equal(voidHeavy.maxSent - voidHeavy.allSent, 30);
assert.equal(voidHeavy.minTurns - voidHeavy.turns, 11);
assert.match(chat, /const myMessageCount = messageCounts\[myUid\] \|\| 0;/);
assert.equal(warnings.shouldWarnConsecutivePosts(50, 9), false);
assert.equal(warnings.shouldWarnConsecutivePosts(51, 10), true);
assert.equal(warnings.shouldWarnConsecutivePosts(51, 11), false);
assert.match(chat, /shouldWarnConsecutivePosts\(myMessageCount, myShownTurns\)/);

const officialAsyncConfirmation = (scope, decide) => ({
  actionInFlightRef: { current: null }, actionScope: scope,
  actionLifetimeRef: { current: scope }, latestActionScopeRef: { current: scope },
  requestActionConfirmation: async ({ messageKey }) => decide(messageKey),
});
// 公式の投票確認は進捗モーダル後も既存の確認を通り、開いたときの種類を保持する。
assert.match(chat, /setPendingVoteWarningKey\(warningKey\)/);
assert.match(chat, /t\(pendingVoteWarningKey === 'turns'/);
const voteStart = chat.indexOf('const handleVote = useCallback(');
const voteBodyStart = voteStart + 'const handleVote = useCallback('.length;
const voteBodyEnd = chat.indexOf('\n  }, [signKey', voteBodyStart);
const voteCallback = chat.slice(voteBodyStart, voteBodyEnd + 4);
assert.match(voteCallback, /await requestActionConfirmation\(/);
assert.doesNotMatch(chat, /\bwindow\.alert\s*\(/, '#13: action results use the notice band');
const runOfficialVote = async (approved, confirm, resend = false, timing = {}) => {
  const sent = [], confirms = [], pending = [], alerts = [];
  let clock = timing.before ?? 123;
  const scope = {
    showActionNotice: (tone, text) => alerts.push({ tone, text }),
    signKey: 'SIGN', encryptKey: 'ENC', localVoteTarget: resend ? 'B' : null, myVoteVoid: resend,
    myShownTurns: 19, myCharCount: 600, minTurnCount: 20, minChars: 500,
    ...officialAsyncConfirmation('vote', (messageKey) => { confirms.push(messageKey); if (timing.after != null) clock = timing.after; return confirm; }),
    latestActionGatesRef: { current: { voteCutoff: timing.cutoff ?? null, localVoteTarget: resend ? 'B' : null, myVoteVoid: resend } },
    blockNum: 1, myUid: 'ME', t: (key) => key, members: [{ uid: 'B', name: 'B' }], numberedMembers: null, pointedMemberText,
    voteProgressWarningKey: warnings.voteProgressWarningKey,
    setPendingVoteTarget: (value) => pending.push(value),
    setPendingVoteWarningKey: () => {},
    encryptAction: ({ targetUid }) => `cipher:${targetUid}`,
    sendVote: async (...args) => { sent.push(args); return true; },
    voteCutoff: timing.cutoff ?? null, nowTick: timing.before ?? 123, clientNow: () => clock,
    setLocalVoteTarget: () => {}, saveActionIntent: () => {},
    window: { confirm: () => { throw new Error('公式でblocking confirmを使わない'); } },
    console: { error: () => {} },
  };
  const fn = new Function(...Object.keys(scope), `return (${voteCallback});`)(...Object.values(scope));
  await fn('B', approved);
  return { sent, confirms, pending, alerts };
};
assert.deepEqual(await runOfficialVote(false, true), { sent: [], confirms: [], pending: ['B'], alerts: [] });
assert.deepEqual(await runOfficialVote(true, false), { sent: [], confirms: ['game.action.voteConfirm'], pending: [], alerts: [] });
assert.deepEqual((await runOfficialVote(true, true)).sent, [['cipher:B', 'SIGN']]);
assert.deepEqual((await runOfficialVote(true, false, true)).confirms, ['game.action.voteResendConfirm']);
const crossedCutoff = await runOfficialVote(true, true, false, { before: 599999, after: 600000, cutoff: 600000 });
assert.deepEqual(crossedCutoff.sent, [], '確認窓中に時計だけ進んだら投票しない');
assert.deepEqual(crossedCutoff.alerts, [{ tone: 'error', text: 'game.action.votingClosed' }], '#13: the cutoff reason is shown in a band');
assert.match(voteCallback, /await requestActionConfirmation\(/);
assert.match(voteCallback, /messageKey: myVoteVoid \? 'game\.action\.voteResendConfirm' : 'game\.action\.voteConfirm'/);

// 復元でも進捗確認の後に既存確認が出る。通常経路と送信引数は同じ。
const recoveryVoteStart = recovery.indexOf('async function sendVote(targetUid) {');
const recoveryVoteEnd = recovery.indexOf('\nasync function sendReport(targetUid)', recoveryVoteStart);
const recoveryVoteSource = recovery.slice(recoveryVoteStart, recoveryVoteEnd);
const runRecoveryVote = async (approved, confirm, resend = false, timing = {}) => {
  const sent = [], confirms = [], alerts = [];
  let clock = timing.before ?? 123;
  const state = { voteWarningAccepted: approved, pendingVoteTarget: null,
    myVote: resend ? { encrypted: 'cipher:B', signature: 'old', timestamp: 1 } : null,
    myVotePrev: [], intent: { vote: resend ? 'B' : null },
    cfg: { pins: { minMessages: 20, minChars: 500 } },
    relay: { getMessages: () => [], publishAction: async (...args) => { sent.push(args); return true; } },
    identity: { encryptKey: 'ENC', signKey: 'SIGN' }, blockNum: 1, groupId: 1, uid: 'ME',
    ownSessionSignatures: new Set(), tr: (key) => key };
  const scope = { state, recoveryPointedText: bindRecoveryPointed(state).recoveryPointedText, GUEST_PINNED_RULES: { minMessages: 20 }, rosterReady: () => true, p2pSendReady: () => true,
    myVoteIsVoid: () => resend, myShownProgress: () => ({ turns: 19, chars: 600 }),
    renderGame: () => {}, encryptAction: ({ targetUid }) => `cipher:${targetUid}`,
    privateKeyToAccount: () => ({ signMessage: async () => 'sig' }), canonicalizeSignature: (v) => v,
    actionSignStringV2: () => 'bytes', Date: { now: () => 123 },
    clientNow: () => clock,
    submissionChatCloseAt: () => timing.close ?? null, VOTE_RECEIPT_CUTOFF_MS: 600000,
    window: { confirm: (v) => { confirms.push(v); if (timing.after != null) clock = timing.after; return confirm; }, alert: (v) => alerts.push(v) },
    localStorage: { setItem: () => {} }, showPersistenceWarning: () => {}, log: () => {},
    decryptSelfTarget: () => null };
  const fn = new Function(...Object.keys(scope), `${recoveryVoteSource}\nreturn sendVote;`)(...Object.values(scope));
  await fn('B');
  return { sent, confirms, state, alerts };
};
assert.equal((await runRecoveryVote(false, true)).sent.length, 0);
assert.deepEqual((await runRecoveryVote(true, false)).confirms, ['recovery.action.voteConfirm']);
assert.deepEqual((await runRecoveryVote(true, false, true)).confirms, ['recovery.action.voteResendConfirm']);
assert.deepEqual((await runRecoveryVote(true, true)).sent[0].slice(0, 2), ['vote', { encrypted: 'cipher:B', signature: 'sig', timestamp: 123 }]);
const recoveryCrossed = await runRecoveryVote(true, true, false,
  { before: 599999, after: 600000, close: 1_200_000 });
assert.deepEqual(recoveryCrossed.sent, []);
assert.deepEqual(recoveryCrossed.alerts, ['recovery.action.votingClosed']);
assert.match(recovery, /state\.pendingVoteWarningKey = progress\.turns < GUEST_PINNED_RULES\.minMessages \? 'turns' : 'chars'/);

// 密告の門は確認後に補正時計で判定し直し、警告は押した相手が唯一の有資格者のときだけ。
const reportStart = chat.indexOf('const handleReport = useCallback(');
const reportEnd = chat.indexOf('\n  }, [signKey', reportStart);
const reportCallback = chat.slice(reportStart + 'const handleReport = useCallback('.length, reportEnd + 4);
assert.doesNotMatch(voteCallback, /phaseEndTime|currentPhaseEndTime/);
assert.doesNotMatch(reportCallback, /phaseEndTime|currentPhaseEndTime/);
const runOfficialReport = async ({ target = 'B', before = 101, after = 101,
  voteAt = 100, cutoff = 1000, approved = true, unconfirmedApproved = true } = {}) => {
  const sent = [], pending = [], unconfirmed = [], notices = [];
  let clock = before;
  const hasVisibleConfirmedVote = (uid, at) => uid === 'B' && at > voteAt;
  const canReportTarget = (uid, at) => at >= cutoff || hasVisibleConfirmedVote(uid, at);
  const scope = { signKey: 'SIGN', encryptKey: 'ENC', localReportTargets: [],
    reportTargetStatus: {}, activeReportSlots: 0, members: [{ uid: 'ME' }, { uid: 'B' }, { uid: 'C' }],
    myUid: 'ME', blockNum: 1, groupId: 1, nowTick: before, hasVisibleConfirmedVote, canReportTarget,
    soleRemainingReportTarget, setPendingReportWarningTarget: (uid) => pending.push(uid),
    ...officialAsyncConfirmation('report', () => { clock = after; return true; }),
    latestActionGatesRef: { current: { canReportTarget, localReportTargets: [], reportTargetStatus: {}, activeReportSlots: 0 } },
    setPendingUnconfirmedReportTarget: (targetUid) => unconfirmed.push(targetUid),
    showActionNotice: (tone, text) => notices.push({ tone, text }),
    t: (key) => key, numberedMembers: null, pointedMemberText, clientNow: () => after,
    encryptAction: ({ targetUid }) => `cipher:${targetUid}`,
    encryptReportDeterministic: (targetUid) => `cipher:${targetUid}`,
    sendReport: async (...args) => { sent.push(args); return true; },
    setLocalReportTargets: () => {}, saveActionIntent: () => {}, console: { error: () => {} },
    window: { confirm: () => { throw new Error('公式でblocking confirmを使わない'); } } };
  const fn = new Function(...Object.keys(scope), `return (${reportCallback});`)(...Object.values(scope));
  await fn(target, approved, unconfirmedApproved && !hasVisibleConfirmedVote(target, before));
  return { sent, pending, unconfirmed, notices };
};
assert.equal((await runOfficialReport()).sent.length, 1, '確定投票の後は送れる');
assert.equal((await runOfficialReport({ before: 100 })).sent.length, 0, '投票と同じミリ秒は閉じる');
assert.equal((await runOfficialReport({ before: 101, after: 100 })).sent.length, 0,
  '確認窓の間に時計を戻して門の外へ出たら送らない');
assert.equal((await runOfficialReport({ target: 'C', before: 1000, after: 1000 })).sent.length, 1,
  'ラスト10分は未確定の相手にも送れる');
assert.deepEqual((await runOfficialReport({ approved: false })).pending, ['B'],
  '唯一の有資格者を押したとき警告する');
assert.deepEqual((await runOfficialReport({ target: 'C', before: 1000, approved: false })).pending, [],
  '唯一の有資格者と押した相手が違えば警告しない');

// #15: ラスト10分でも、未確定の相手には先に確認を出し、承認後にだけ送る。
const unconfirmedPress = await runOfficialReport({ target: 'C', before: 1000, unconfirmedApproved: false });
assert.deepEqual(unconfirmedPress.unconfirmed, ['C']);
assert.deepEqual(unconfirmedPress.sent, []);
const unconfirmedAccepted = await runOfficialReport({ target: 'C', before: 1000, after: 1000 });
assert.deepEqual(unconfirmedAccepted.sent, [['cipher:C', 'SIGN', 'C']]);
assert.deepEqual(unconfirmedAccepted.notices, [{ tone: 'ok', text: 'game.action.reportSuccess' }]);
assert.deepEqual((await runOfficialReport({ target: 'C', before: 1000, after: 999 })).sent, [],
  'unconfirmed approval still rechecks the current time and report gate');

const recoveryReportStart = recovery.indexOf('async function sendReport(targetUid) {');
const recoveryReportEnd = recovery.indexOf('\n// A-3', recoveryReportStart);
const recoveryReportSource = recovery.slice(recoveryReportStart, recoveryReportEnd).trim();
const runRecoveryReport = async ({ target = 'B', before = 101, after = 101,
  voteAt = 100, cutoff = 1000, approved = true } = {}) => {
  const published = [];
  let clock = before;
  const state = { reportWarningAccepted: approved, pendingReportWarningTarget: null,
    members: [{ uid: 'ME' }, { uid: 'B' }, { uid: 'C' }], uid: 'ME',
    intent: { reports: [] }, myReports: [], cfg: { pins: { maxReports: 2 } },
    identity: { signKey: 'SIGN', encryptKey: 'ENC' }, blockNum: 1, groupId: 1,
    ownSessionSignatures: new Set(), tr: (key) => key,
    relay: { publishAction: async (...args) => { published.push(args); return true; } } };
  const hasVisibleConfirmedVote = (uid, at) => uid === 'B' && at > voteAt;
  const canReportTarget = (uid, at) => at >= cutoff || hasVisibleConfirmedVote(uid, at);
  const scope = { state, recoveryPointedText: bindRecoveryPointed(state).recoveryPointedText, rosterReady: () => true, p2pSendReady: () => true,
    reportTargetStatusMap: () => ({}), decryptSelfTarget: () => null,
    clientNow: () => clock, hasVisibleConfirmedVote, canReportTarget,
    soleRemainingReportTarget, renderGame: () => {}, log: () => {},
    encryptAction: ({ targetUid }) => `cipher:${targetUid}`,
    encryptReportDeterministic: (targetUid) => `cipher:${targetUid}`,
    privateKeyToAccount: () => ({ signMessage: async () => 'sig' }),
    canonicalizeSignature: (value) => value, actionSignStringV2: () => 'bytes',
    window: { confirm: () => { clock = after; return true; }, alert: () => {} } };
  const fn = new Function(...Object.keys(scope), `return (${recoveryReportSource});`)(...Object.values(scope));
  await fn(target);
  return { published, pending: state.pendingReportWarningTarget };
};
assert.equal((await runRecoveryReport()).published.length, 1);
assert.equal((await runRecoveryReport({ before: 100 })).published.length, 0);
assert.equal((await runRecoveryReport({ before: 101, after: 100 })).published.length, 0);
assert.equal((await runRecoveryReport({ target: 'C', before: 1000, after: 1000 })).published.length, 1);
assert.equal((await runRecoveryReport({ approved: false })).pending, 'B');
assert.equal((await runRecoveryReport({ target: 'C', before: 1000, after: 1000, approved: false })).pending, null);

// エラー条件は維持し、既知の原因のみ訳す。取り込み案内は実ボタン文言を埋め込む。
assert.match(page, /reloginErrorArmed && authError &&/);
assert.match(page, /reloginErrorKey\(authError\)/);
for (const locale of [ja, en]) {
  assert(locale.session.reloginPopupBlocked);
  assert(locale.session.reloginTimeout);
}
assert.match(ja.session.reloginPopupBlocked, /ポップアップ.*許可/);
assert.match(en.session.reloginPopupBlocked, /popup.*allow|allow.*popups/i);
assert.match(i18n, /\{signLabel\}/);
assert.match(recovery, /state\.tr\('recovery\.import\.description', \{ signLabel: state\.tr\('recovery\.sign'\) \}\)/);

// 3つのモーダルは game-area の外の同じ DOM を維持し、表示状態が変わると更新する。
assert.match(recovery, /function renderGameModals\(phase\)/);
assert.match(recovery, /g\.after\(modalRoot\)/);
assert.match(recovery, /if \(modalRenderKey === nextKey\) return;/);
assert.doesNotMatch(recovery.slice(recovery.indexOf('function renderGame() {'), recovery.indexOf('function renderContractStatus()')), /g\.append\(modal\)/);
assert.match(recovery, /renderGameModals\(phase\)/);
// 実際のモーダル描画関数を軽量 DOM で動かす。毎秒 tick 相当の再呼び出しで
// 3枚のノードとスクロールが残り、文言・表示状態の変化で更新される。
const modalStart = recovery.indexOf('let modalRoot = null;');
const modalEnd = recovery.indexOf('\nfunction renderGame() {', modalStart);
assert(modalStart >= 0 && modalEnd > modalStart);
const parent = {};
const gameArea = { parentNode: parent, after(node) { node.isConnected = true; node.parentNode = parent; this.modalRoot = node; },
  set innerHTML(value) { assert.equal(value, ''); } };
const body = { append(node) { node.isConnected = true; node.parentNode = body; } };
const el = (tag, props = {}) => {
  const node = { tag, ...props, children: [], isConnected: true, scrollTop: 0,
    append(...children) { this.children.push(...children); } };
  Object.defineProperty(node, 'innerHTML', { set(value) { assert.equal(value, ''); this.children = []; } });
  return node;
};
const modalState = { lang: 'ja', voteDeadlineNoticeOpen: true, away: false,
  myVote: null, uid: 'ME', pendingVoteTarget: 'B', pendingVoteWarningKey: 'turns',
  otherSessionReadReceipt: true, cfg: { pins: { minMessages: 20, minChars: 500 } },
  tr: (key, args) => args?.time ? `${key}:${args.time}`
    : args?.mm !== undefined ? `${key}:${args.mm}:${args.ss}` : key };
let modalNow = 599999;
let modalClose = 1_200_000;
const modalScope = { state: modalState, $: (id) => id === 'game-area' ? gameArea : null,
  el, actionReceipted: () => false, ownVoteReceipted: () => false, renderGame: () => {}, sendVote: () => {}, // 便 VOTEEXTRA: 締切の注意は自分の全部の投票から決める
  resumeOtherSession: () => {}, endThisTab: () => {}, playerNumberOf, pointedTemplateText, pointedTemplateParts, document: { body },
  submissionChatCloseAt: () => modalClose, clientNow: () => modalNow,
  VOTE_RECEIPT_CUTOFF_MS: 600000, GUEST_PINNED_RULES: { minMessages: 20 } };
const renderModals = new Function(...Object.keys(modalScope),
  `${recovery.slice(recovery.indexOf('function reportWarningName('), recovery.indexOf('\nasync function freshRecoveryClockReading('))}\n${recovery.slice(recovery.indexOf('function memberName(m) {'), recovery.indexOf('\n// デポジットポイントは', recovery.indexOf('function memberName(m) {')))}\n${recovery.slice(modalStart, modalEnd)}\nreturn renderGameModals;`)(...Object.values(modalScope));
renderModals('chatting');
const content = gameArea.modalRoot.children[0];
const initial = [...content.children];
assert.equal(initial.length, 3);
const cutoffDate = new Date(modalClose - 600000);
const cutoffText = `${String(cutoffDate.getHours()).padStart(2, '0')}:${String(cutoffDate.getMinutes()).padStart(2, '0')}`;
assert.equal(initial[0].children[0].children[0].textContent,
  `recovery.action.deadlineVoteNotice recovery.action.deadlineVoteReceiptNotice:${cutoffText}`);
for (const modal of initial) modal.children[0].scrollTop = 77;
gameArea.innerHTML = ''; // renderGame の毎秒の #game-area クリア
renderModals('chatting');
assert.deepEqual(content.children, initial);
for (let i = 0; i < 3; i++) {
  assert.strictEqual(content.children[i], initial[i]);
  assert.equal(initial[i].children[0].scrollTop, 77);
}
modalClose = null;
renderModals('chatting');
assert.equal(content.children[0].children[0].children[0].textContent,
  'recovery.action.deadlineVoteNotice', '締切不明なら追加文だけ外す');
modalClose = 1_200_000;
renderModals('chatting');
modalNow = 600000;
renderModals('chatting');
assert.notStrictEqual(content.children[0], initial[0], '締切を跨ぐと同じモーダルを描き直す');
assert.equal(content.children[0].children[0].children[0].textContent,
  'recovery.action.votingClosed');
modalState.pendingVoteWarningKey = 'chars';
renderModals('chatting');
assert.notStrictEqual(content.children[1], initial[1]);
assert.equal(content.children[1].children[0].children[0].textContent,
  'recovery.action.voteProgressChars');
modalState.pendingVoteTarget = null;
renderModals('chatting');
assert.equal(content.children.length, 2);
modalState.voteDeadlineNoticeOpen = false;
modalState.otherSessionReadReceipt = false;
renderModals('chatting');
assert.equal(content.children.length, 0);
modalState.pendingReportWarningTarget = 'B';
modalState.members = [{ uid: 'ME' }, { uid: 'B' }];
renderModals('chatting');
const reportModal = content.children.find((modal) =>
  modal.children[0].children[0].textContent.startsWith('recovery.action.reportRevealWarning'));
assert(reportModal, '密告の警告を表示する');
const reportCancel = reportModal.children[0].children.find((node) =>
  node.textContent === 'recovery.action.reportRevealCancel');
assert(reportCancel, '密告の警告に閉じる操作がある');
reportCancel.onclick();
renderModals('chatting');
assert.equal(modalState.pendingReportWarningTarget, null);
assert.equal(content.children.length, 0, '閉じた密告の警告は消える');

// 締切後の自分の投票だけ残り時間を外し、密告は既存の残り時間を維持する。
assert.match(chat, /nowMs=\{row\.actorUid === myUid && row\.actionType === 'vote' && votingClosed \? undefined : nowTick\}/);
const unreadStart = recovery.indexOf('function unreadCountdownLabel(ts, actionType = null) {');
const unreadEnd = recovery.indexOf('\n// 自分の未読発信バッジ', unreadStart);
assert(unreadStart >= 0 && unreadEnd > unreadStart);
let unreadNow = 599999;
const unreadScope = { submissionChatCloseAt: () => 1_200_000, clientNow: () => unreadNow,
  VOTE_RECEIPT_CUTOFF_MS: 600000, RECEIPT_FRESH_WINDOW_MS: 600000,
  state: { tr: () => '未読' } };
const unreadLabel = new Function(...Object.keys(unreadScope),
  `${recovery.slice(unreadStart, unreadEnd)}\nreturn unreadCountdownLabel;`)(...Object.values(unreadScope));
assert.match(unreadLabel(500000, 'vote'), /^未読 \d+:\d\d$/);
unreadNow = 600000;
assert.equal(unreadLabel(500000, 'vote'), '未読');
assert.match(unreadLabel(500000, 'report'), /^未読 \d+:\d\d$/);
assert.match(recovery, /unreadCountdownLabel\(ts, b\.dataset\.actionType \|\| null\)/);

const authStart = page.indexOf('export function reloginErrorKey(message) {');
const authEnd = page.indexOf('\nconst readLocalStorageItem', authStart);
const reloginErrorKey = new Function(`${page.slice(authStart, authEnd).replace('export ', '')}\nreturn reloginErrorKey;`)();
assert.equal(reloginErrorKey('ポップアップがブロックされました。このサイトのポップアップを許可してください。'), 'reloginPopupBlocked');
assert.equal(reloginErrorKey('認証がタイムアウトしました。もう一度お試しください。'), 'reloginTimeout');
assert.equal(reloginErrorKey('unknown'), 'reloginError');
const catalogs = await import(`data:text/javascript,${encodeURIComponent(i18n)}`);
for (const lang of ['ja', 'en', 'zh']) {
  const tr = catalogs.t(lang);
  assert(tr('recovery.import.description', { signLabel: tr('recovery.sign') }).includes(tr('recovery.sign')));
}
// T8: display count uses the same timely, carried receipts as actionReceipted.
const extractRecovery = (name) => {
  const start = recovery.indexOf(`function ${name}(`);
  const end = recovery.indexOf('\n}\n', start);
  assert(start >= 0 && end > start, `T8 extracts ${name}`);
  return recovery.slice(start, end + 3);
};
let countBody = extractRecovery('actionReadCount');
if (process.argv.includes('--mutation=t8-read-count-all-receipts')) {
  const guarded = 'for (const rc of clientChatSourcedReceipts(state.receipts, chatWindow, submissionChatCloseAt())) {\n    if (rc.actionHash === h && rc.receiverUid !== actorUid && isReceiptTimely(rc.timestamp, action.timestamp)\n      && actionReceiptInChatWindow(rc.timestamp, chatWindow))';
  assert.equal(countBody.split(guarded).length, 2, 'T8 count mutation hits once');
  countBody = countBody.replace(guarded,
    'for (const rc of Object.values(state.receipts)) {\n    if (rc.actionHash === h && rc.receiverUid !== actorUid)');
}
const t8Now = 1_800_000_000_000, t8Close = t8Now + 3_600_000;
const t8State = { blockNum: 3, groupId: 2, receipts: {} };
// 便 VOTEEXTRA（Lean VE-L03）: 表示でも宣言窓の外の行動の受領証明を数えない（公式の J-26 と同じ式）
const actionReceiptInChatWindow = new Function(`${extractRecovery('actionReceiptInChatWindow')}\nreturn actionReceiptInChatWindow;`)();
const t8Deps = { state: t8State, actionHashV2, clientChatSourcedReceipts, isReceiptTimely, actionReceiptInChatWindow,
  submissionChatWindow: () => ({ startMs: t8Now - 600_000, endMs: t8Close }),
  submissionChatCloseAt: () => t8Close };
const t8Build = (body, name) => new Function(...Object.keys(t8Deps), `${body}\nreturn ${name};`)(...Object.values(t8Deps));
const t8Count = t8Build(countBody, 'actionReadCount');
const t8Receipted = t8Build(extractRecovery('actionReceipted'), 'actionReceipted');
const t8Vote = { encrypted: 'enc', timestamp: t8Now };
const t8Hash = actionHashV2('vote', 3, 2, 'V', 'enc', t8Now);
const t8Receipt = (timestamp, hash = t8Hash) => markActionReceiptSource({ receiverUid: 'M',
  actionHash: hash, timestamp, signature: `0x${'11'.repeat(64)}1b` },
{ source: 'device', chatCloseAt: t8Close, nowMs: timestamp });
for (const [label, receipt, expected] of [
  ['stale', t8Receipt(t8Now + 11 * 60_000), 0],
  ['fresh', t8Receipt(t8Now + 5 * 60_000), 1],
]) {
  t8State.receipts = { one: receipt };
  assert.equal(t8Count('V', 'vote', t8Vote), expected, `T8 ${label} display count`);
  assert.equal(Number(t8Receipted('V', 'vote', t8Vote)), expected, `T8 ${label} vote status`);
}
const t8LateVote = { encrypted: 'late', timestamp: t8Close - 60_000 };
const t8LateHash = actionHashV2('vote', 3, 2, 'V', 'late', t8LateVote.timestamp);
t8State.receipts = { one: t8Receipt(t8Close + 1000, t8LateHash) };
assert.equal(isReceiptTimely(t8Close + 1000, t8LateVote.timestamp), true);
assert.equal(t8Count('V', 'vote', t8LateVote), 0, 'T8 timely but not carried is absent from display');
assert.equal(t8Receipted('V', 'vote', t8LateVote), false, 'T8 timely but not carried is absent from vote status');
const t8EarlyVote = { encrypted: 'early', timestamp: t8Now - 590_000 };
const t8EarlyHash = actionHashV2('vote', 3, 2, 'V', 'early', t8EarlyVote.timestamp);
t8State.receipts = { one: t8Receipt(t8Now - 605_000, t8EarlyHash) };
assert.equal(isReceiptTimely(t8Now - 605_000, t8EarlyVote.timestamp), true);
assert.equal(t8Count('V', 'vote', t8EarlyVote), 0, 'T8 timely but before the declared window is absent from display (VE-L03)');
assert.equal(t8Receipted('V', 'vote', t8EarlyVote), false, 'T8 timely but before the declared window is absent from vote status (VE-L03)');
const memberStart = recovery.indexOf('function renderMemberList(displayNow) {');
const memberEnd = recovery.indexOf('\n// 開始待機（waiting）', memberStart);
assert(memberStart >= 0 && memberEnd > memberStart);
const memberBody = recovery.slice(memberStart, memberEnd);
const t8MemberBody = process.argv.includes('--mutation=t8-member-raw-clock')
  ? memberBody.replace('const now = displayNow;', 'const now = Date.now();') : memberBody;
assert(/const activityAt = lastActivityMap\(msgs\);\s*const now = displayNow;/.test(t8MemberBody),
  'T8 peer presence compares signed activity to the one render clock');
assert.equal((1_000_000 - (1_000_000 - 7 * 60_000)) < 10 * 60_000, true,
  'T8 corrected display clock sees seven-minute-old peer as online');
console.log('s3fix-g2-display: all checks passed');
