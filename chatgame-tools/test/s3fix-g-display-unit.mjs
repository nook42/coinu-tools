import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { formatName } from '../../src/utils/tool.js';
import { playerNumberOf, pointedTemplateText, pointedTemplateParts } from '../vendor/src/utils/playerNumber.js';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
let chat = read('src/components/game/ChatPhase.js');
const uiMutation = process.env.UI_S3_G_MUTATION;
if (uiMutation === 'deadline-call') chat += '\nshouldShowVoteDeadlineNotice(phaseEndTime, nowTick, false);';
if (uiMutation === 'deadline-state') chat += '\nconst showDeadlineVoteNotice = true;';
if (uiMutation === 'receipt-copy') chat += "\n t('game.action.receiptNotice');";
const page = read('src/pages/game.js');
const warnings = await import(`data:text/javascript,${encodeURIComponent(read('src/utils/chatWarnings.js'))}`);
const recovery = read('chatgame-tools/src/recovery/app.js');
const gameUtils = read('src/utils/gameUtils.js');
const officialPointedSource = gameUtils.slice(gameUtils.indexOf('export const getMemberDisplayName ='), gameUtils.indexOf('// 失格理由コード'))
  .replace('export const getMemberDisplayName', 'const getMemberDisplayName').replace('export function pointedMemberText', 'function pointedMemberText')
  .replace('export function playerNumberTitle', 'function playerNumberTitle').split('export function pointedMemberNodes')[0];
const pointedMemberText = new Function('formatName', 'playerNumberOf', 'pointedTemplateText',
  `${officialPointedSource}\nreturn pointedMemberText;`)(formatName, playerNumberOf, pointedTemplateText);
const recoveryPointedSource = `${recovery.slice(recovery.indexOf('function reportWarningName('), recovery.indexOf('\nasync function freshRecoveryClockReading('))}\n${recovery.slice(recovery.indexOf('function memberName(m) {'), recovery.indexOf('\n// デポジットポイントは', recovery.indexOf('function memberName(m) {')))}`;
const bindRecoveryPointed = (state) => new Function('state', 'el', 'playerNumberOf', 'pointedTemplateText', 'pointedTemplateParts',
  `${recoveryPointedSource}\nreturn recoveryPointedText;`)(state, () => null, playerNumberOf, pointedTemplateText, pointedTemplateParts);
const translations = read('chatgame-tools/src/common/i18n.js');
const ja = JSON.parse(read('public/locales/ja/game_ja.json'));
const en = JSON.parse(read('public/locales/en/game_en.json'));
if (uiMutation === 'deadline-locale-ja') ja.action.deadlineVoteNotice = 'obsolete';
if (uiMutation === 'deadline-locale-en') en.action.deadlineVoteNotice = 'obsolete';

assert.equal(warnings.voteProgressWarningKey(19, 500, 20, 500), 'turns');
assert.equal(warnings.voteProgressWarningKey(20, 499, 20, 500), 'chars');
assert.equal(warnings.voteProgressWarningKey(19, 499, 20, 500), 'turns');
assert.equal(warnings.voteProgressWarningKey(20, 500, 20, 500), null);
const end = 100_000_000;
assert.equal(warnings.shouldShowVoteDeadlineNotice(end, end - 10_800_001, false), false);
assert.equal(warnings.shouldShowVoteDeadlineNotice(end, end - 10_800_000, false), true);
assert.equal(warnings.shouldShowVoteDeadlineNotice(end, end - 10_800_000, true), false);
assert.equal(warnings.shouldShowVoteDeadlineNotice(end, end - 3_600_000, false), true);
assert.equal(warnings.shouldShowVoteDeadlineNotice(end, end + 1, false), false);
assert.equal(warnings.shouldWarnConsecutivePosts(51, 10), true);
assert.equal(warnings.shouldWarnConsecutivePosts(50, 10), false);
assert.match(chat, /shouldWarnConsecutivePosts\(myMessageCount, myShownTurns\)/);
const eightyVoidAndOneRead = [{ uid: 'ME' }];
assert.equal(warnings.shouldWarnConsecutivePosts(80, 10), true);
assert.equal(eightyVoidAndOneRead.filter(m => m.uid === 'ME').length, 1);
const fiftyOneRead = Array.from({ length: 51 }, () => ({ uid: 'ME' }));
assert.equal(warnings.shouldWarnConsecutivePosts(fiftyOneRead.filter(m => m.uid === 'ME').length, 10), true);
assert.match(chat, /voteProgressWarningKey\(myShownTurns, myCharCount, minTurnCount, minChars\)/);
assert.doesNotMatch(chat, /\bshouldShowVoteDeadlineNotice\s*\(/, '#12: no automatic deadline notice call');
assert.match(page, /hasValidVote=\{voteReceiptedUids\.has\(myUid\)\}/);
assert.doesNotMatch(chat, /deadlineEntryPendingRef|setShowDeadlineVoteNotice|showDeadlineVoteNotice/, '#12: removed notice state is not wired');
assert.doesNotMatch(chat, /t\('game\.action\.receiptNotice'\)/, '#10: receipt copy is removed');
assert.match(chat, /capCharsLeft.*maxChars|capCharsLeft/);
assert.match(chat, /myCharCountRaw.*maxChars/);
assert.match(chat, /const overTotalCap = capMessagesLeft <= 0 \|\| inputChars > capCharsLeft;/);
assert.match(chat, /\{\(overTotalCap \|\| capCharsLeft <= 0\) && \(/);
assert.match(page, /phaseEndTime=\{currentPhaseEndTime\}/);
assert.match(page, /reloginErrorArmed/);
assert.match(read('src/styles/Game.module.css'), /\.multiSessionPanel\s*\{[^}]*max-height:[^}]*overflow-y:/s);
assert.match(recovery, /max-height:calc\(100dvh - 48px\);overflow-y:auto/);
assert.match(recovery, /recovery\.action\.receiptNotice/);
assert.match(recovery, /recovery\.action\.voteProgressTurns/);
assert.match(recovery, /recovery\.action\.deadlineVoteNotice/);
assert.match(recovery, /const remaining = state\.timeline\.chatCloseAt - renderNow/);
assert.match(recovery, /g\.append\(renderHeader\(phase, renderNow\)\)/);
assert.match(recovery, /const timerInit = isStage1 \? timerText\(phase, nowMs\)/);
assert.match(recovery, /myRawChatTotals\(\)/);
for (const locale of [ja, en]) {
  for (const key of ['voteProgressTurns', 'voteProgressChars', 'voteProgressProceed', 'voteProgressBack'])
    assert.equal(typeof locale.action[key], 'string', key);
  for (const key of ['deadlineVoteNotice', 'receiptNotice']) assert.equal(Object.hasOwn(locale.action, key), false, key);
  assert.match(locale.members.multiSessionEnded, /再読み込み|reload/i);
  assert.equal(typeof locale.session.reloginError, 'string');
}
for (const key of ['recovery.action.voteProgressTurns', 'recovery.action.voteProgressChars',
  'recovery.action.deadlineVoteNotice', 'recovery.action.receiptNotice']) {
  assert.equal(translations.split(`'${key}':`).length, 4, key);
}
assert.match(translations, /copy[^\n]*close[^\n]*\{signLabel\}/i);

// 公式の実ハンドラを切り出し、警告の有無と署名済み発信へ渡す引数を両方向で確かめる。
const voteStart = chat.indexOf('const handleVote = useCallback(');
const voteBodyStart = voteStart + 'const handleVote = useCallback('.length;
const voteBodyEnd = chat.indexOf('\n  }, [signKey', voteBodyStart);
assert(voteStart >= 0 && voteBodyEnd > voteBodyStart);
const voteCallback = chat.slice(voteBodyStart, voteBodyEnd + 4);
const makeVote = (turns, chars, confirmation = true) => {
  const sent = [], pending = [], confirms = [];
  const actionScope = {};
  const scope = {
    actionScope, actionInFlightRef: { current: null }, actionLifetimeRef: { current: actionScope },
    latestActionScopeRef: { current: actionScope },
    latestActionGatesRef: { current: { voteCutoff: null, localVoteTarget: null, myVoteVoid: false } },
    requestActionConfirmation: async ({ messageKey }) => { confirms.push(messageKey); return confirmation; },
    showActionNotice: () => {},
    signKey: 'SIGN', encryptKey: 'ENCRYPT', localVoteTarget: null, myVoteVoid: false,
    myShownTurns: turns, myCharCount: chars, minTurnCount: 20, minChars: 500,
    blockNum: 7, myUid: 'ME', t: (key) => key, members: [{ uid: 'H', name: 'H' }], numberedMembers: null, pointedMemberText,
    voteProgressWarningKey: warnings.voteProgressWarningKey,
    setPendingVoteTarget: (target) => pending.push(target), setPendingVoteWarningKey: () => {},
    encryptAction: ({ targetUid }) => `cipher:${targetUid}`,
    sendVote: async (...args) => { sent.push(args); return true; },
    voteCutoff: null, clientNow: () => 123,
    setLocalVoteTarget: () => {}, saveActionIntent: () => {},
    window: { confirm: (text) => { confirms.push(text); return confirmation; }, alert: () => {} },
    console: { error: () => {} },
  };
  const fn = new Function(...Object.keys(scope), `return (${voteCallback});`)(...Object.values(scope));
  return { fn, sent, pending, confirms };
};
const lowTurns = makeVote(19, 500);
await lowTurns.fn('H');
assert.deepEqual(lowTurns.pending, ['H']);
assert.equal(lowTurns.sent.length, 0);
await lowTurns.fn('H', true);
assert.deepEqual(lowTurns.sent, [['cipher:H', 'SIGN']]);
assert.deepEqual(lowTurns.confirms, ['game.action.voteConfirm']);
const lowChars = makeVote(20, 499);
await lowChars.fn('H');
assert.deepEqual(lowChars.pending, ['H']);
assert.equal(lowChars.sent.length, 0);
const reached = makeVote(20, 500);
await reached.fn('H');
assert.deepEqual(reached.pending, []);
assert.deepEqual(reached.sent, lowTurns.sent, 'confirming the warning keeps the same send arguments');
const cancelled = makeVote(20, 500, false);
await cancelled.fn('H');
assert.equal(cancelled.sent.length, 0);
assert.match(chat, /setPendingVoteTarget\(null\); setPendingVoteWarningKey\(null\); \}\}>\{t\('game\.action\.voteProgressBack'\)/);

// #12: UI の自動表示は削除。純粋関数の3時間境界の検査は上で維持する。
assert.doesNotMatch(chat, /validVoteForNotice/);
assert.doesNotMatch(chat, /aria-label=\{t\('game\.action\.deadlineVoteNotice'\)\}/);
assert.doesNotMatch(chat, /t\('game\.action\.deadlineVoteReceiptNotice'/);
assert.doesNotMatch(chat, /import\s*\{[^}]*\bshouldShowVoteDeadlineNotice\b/s);

// 復元の実ハンドラでも、確認前は発信せず、確認後のアクション引数は通常投票と同じ。
const recoveryVoteStart = recovery.indexOf('async function sendVote(targetUid) {');
const recoveryVoteEnd = recovery.indexOf('\nasync function sendReport(targetUid)', recoveryVoteStart);
assert(recoveryVoteStart >= 0 && recoveryVoteEnd > recoveryVoteStart);
const recoveryVoteSource = recovery.slice(recoveryVoteStart, recoveryVoteEnd);
const makeRecoveryVote = (turns, chars, confirmation = true) => {
  const published = [], confirms = [];
  const state = {
    voteWarningAccepted: false, pendingVoteTarget: null,
    myVote: null, myVotePrev: [], intent: { vote: null },
    cfg: { pins: { minMessages: 20, minChars: 500 } },
    relay: { getMessages: () => [], publishAction: async (...args) => { published.push(args); return true; } },
    identity: { encryptKey: 'ENC', signKey: 'SIGN' }, blockNum: 7, groupId: 2, uid: 'ME',
    ownSessionSignatures: new Set(), tr: (key) => key,
  };
  const scope = {
    state, recoveryPointedText: bindRecoveryPointed(state), rosterReady: () => true, p2pSendReady: () => true, myVoteIsVoid: () => false,
    myShownProgress: () => ({ turns, chars }), GUEST_PINNED_RULES: { minMessages: 20 }, renderGame: () => {},
    encryptAction: ({ targetUid }) => `cipher:${targetUid}`,
    privateKeyToAccount: () => ({ signMessage: async () => 'signature' }),
    canonicalizeSignature: (signature) => signature,
    actionSignStringV2: () => 'signed bytes', Date: { now: () => 123 },
    submissionChatCloseAt: () => null, VOTE_RECEIPT_CUTOFF_MS: 600000,
    clientNow: () => 123,
    window: { confirm: (text) => { confirms.push(text); return confirmation; }, alert: () => {} },
    localStorage: { setItem: () => {} }, showPersistenceWarning: () => {},
    log: () => {}, console: { error: () => {} }, decryptSelfTarget: () => null,
  };
  const fn = new Function(...Object.keys(scope), `${recoveryVoteSource}\nreturn sendVote;`)(...Object.values(scope));
  return { fn, state, published, confirms };
};
const recoveryLow = makeRecoveryVote(19, 500);
await recoveryLow.fn('H');
assert.equal(recoveryLow.state.pendingVoteTarget, 'H');
assert.equal(recoveryLow.published.length, 0);
recoveryLow.state.voteWarningAccepted = true;
await recoveryLow.fn('H');
assert.deepEqual(recoveryLow.confirms, ['recovery.action.voteConfirm']);
const recoveryReached = makeRecoveryVote(20, 500);
await recoveryReached.fn('H');
assert.deepEqual(recoveryLow.published, recoveryReached.published);
const recoveryCancelled = makeRecoveryVote(20, 500, false);
await recoveryCancelled.fn('H');
assert.equal(recoveryCancelled.published.length, 0);

const reloginEffectStart = page.indexOf('useEffect(() => {', page.indexOf('const showSessionExpiredWarning'));
const reloginEffectEnd = page.indexOf('\n  }, [showSessionExpiredWarning', reloginEffectStart);
assert(reloginEffectStart >= 0 && reloginEffectEnd > reloginEffectStart);
const reloginEffect = page.slice(reloginEffectStart + 'useEffect('.length, reloginEffectEnd + 4);
let reloginAttempted = false, reloginErrorArmed = false;
const runReloginEffect = (authError, showSessionExpiredWarning = true) => {
  const scope = { authError, showSessionExpiredWarning, reloginAttempted,
    setReloginAttempted: (value) => { reloginAttempted = value; },
    setReloginErrorArmed: (value) => { reloginErrorArmed = value; } };
  new Function(...Object.keys(scope), `return (${reloginEffect});`)(...Object.values(scope))();
};
runReloginEffect('stale page-load error');
assert.equal(reloginErrorArmed, false);
reloginAttempted = true; // 再ログインを押した直後
runReloginEffect('stale page-load error');
assert.equal(reloginErrorArmed, false);
runReloginEffect(null); // startXAuth が共有エラーを消した
assert.equal(reloginErrorArmed, true);
runReloginEffect(null, false);
assert.equal(reloginErrorArmed, false);
const deadlineStart = recovery.indexOf('if (state.away) state.voteDeadlineEntryPending = true;');
const deadlineEnd = recovery.indexOf('\n  const focusKey =', deadlineStart);
assert(deadlineStart >= 0 && deadlineEnd > deadlineStart);
const deadlineBody = recovery.slice(deadlineStart, deadlineEnd);
const recoveryEntryState = { away: false, voteDeadlineEntryPending: true,
  voteDeadlineNoticeOpen: false, timeline: { chatCloseAt: end }, myVote: null, uid: 'ME' };
const runRecoveryEntry = (now, phase = 'chatting', valid = false) => {
  new Function('state', 'phase', 'renderNow', 'Number', 'actionReceipted', deadlineBody)(
    recoveryEntryState, phase, now, Number, () => valid);
};
runRecoveryEntry(end - 10_800_001);
runRecoveryEntry(end - 10_800_000);
assert.equal(recoveryEntryState.voteDeadlineNoticeOpen, false);
recoveryEntryState.away = true;
runRecoveryEntry(end - 10_800_000);
recoveryEntryState.away = false;
runRecoveryEntry(end - 10_800_000);
assert.equal(recoveryEntryState.voteDeadlineNoticeOpen, true);
recoveryEntryState.voteDeadlineNoticeOpen = false;
recoveryEntryState.away = true;
runRecoveryEntry(end - 3_600_000);
recoveryEntryState.away = false;
recoveryEntryState.myVote = { encrypted: 'cipher' };
runRecoveryEntry(end - 3_600_000, 'chatting', true);
assert.equal(recoveryEntryState.voteDeadlineNoticeOpen, false);
console.log('s3fix-g-display: all checks passed');
