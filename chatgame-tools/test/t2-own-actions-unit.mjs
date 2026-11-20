import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { GameRelayChannel, isClientTimestampAllowed } from '../vendor/src/utils/relay.js';
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { encryptReportDeterministic, decryptAction } from '../vendor/src/utils/ecies.js';
import { loadReportGrounds, withReportGroundReceipts } from '../vendor/src/utils/reportGround.js';

const data = new Map();
globalThis.localStorage = {
  getItem: (key) => data.get(key) ?? null,
  setItem: (key, value) => data.set(key, String(value)),
  removeItem: (key) => data.delete(key),
};
const uid = '12345';
const peer = '67890';
const opts = {
  signKey: `0x${'1'.repeat(64)}`, blockNum: 9, groupId: 0, uid,
  members: [{ uid }, { uid: peer }], verifyInnerSignature: async () => true,
};
const vote = { actionType: 'vote', uid, encrypted: 'vote', timestamp: 1000, signature: 'own-vote' };
const report = { actionType: 'report', uid, encrypted: 'report', timestamp: 1001, signature: 'own-report' };
const peerVote = { actionType: 'vote', uid: peer, encrypted: 'peer', timestamp: 1002, signature: 'peer-vote' };

// The idle tab has read an old shared cache. The voting tab writes between
// that read and the idle tab's stale-observation cleanup.
const cleaningVoter = new GameRelayChannel({ ...opts, sinceSec: 2 });
data.set(cleaningVoter._actionsStoreKey(), JSON.stringify({
  [peer]: { vote: { encrypted: 'old', timestamp: 1000, signature: 'old-peer' }, reports: [] },
}));
const originalGetItem = localStorage.getItem;
let interleaved = false;
localStorage.getItem = (key) => {
  if (key === cleaningVoter._receiptsStoreKey() && !interleaved) {
    interleaved = true;
    cleaningVoter._ingestAction({ ...vote, timestamp: 3000 });
  }
  return originalGetItem(key);
};
new GameRelayChannel({ ...opts, sinceSec: 2 });
localStorage.getItem = originalGetItem;
assert.equal(new GameRelayChannel({ ...opts, sinceSec: 2 })
  .getRelayActionsRaw().votes[uid].signature, vote.signature);
data.clear();

// Both tabs start before the vote. The idle tab then saves its old snapshot.
const voter = new GameRelayChannel(opts);
const idle = new GameRelayChannel(opts);
voter._ingestAction(vote);
idle._ingestAction(peerVote);
assert(!JSON.stringify(JSON.parse(data.get(voter._actionsStoreKey()))).includes(vote.signature));
let reloaded = new GameRelayChannel(opts);
assert.equal(reloaded.getRelayActionsRaw().votes[uid].signature, vote.signature);

// A second tab's own report must join the vote, including after another stale
// shared-cache write. This covers the two possible own action types.
idle._ingestAction(report);
voter._ingestAction(peerVote);
reloaded = new GameRelayChannel(opts);
assert.equal(reloaded.getRelayActionsRaw().votes[uid].signature, vote.signature);
assert(reloaded.getRelayActionsRaw().reports[uid].some((item) => item.signature === report.signature));
const priorStart = GameRelayChannel.prototype.start;
const priorWebSocket = globalThis.WebSocket;
globalThis.WebSocket = class {};
GameRelayChannel.prototype.start = function noNetwork() {};
try {
  const restored = [];
  const recovery = new RecoveryRelay({ ...opts, onActionsChange: (raw) => restored.push(raw) });
  await recovery.start();
  assert.equal(restored.at(-1).votes[uid].signature, vote.signature);
  assert(restored.at(-1).reports[uid].some((item) => item.signature === report.signature));
} finally {
  GameRelayChannel.prototype.start = priorStart;
  if (priorWebSocket === undefined) delete globalThis.WebSocket;
  else globalThis.WebSocket = priorWebSocket;
}

// A saved signature alone must not suppress a self echo if the action record
// is missing. The echo is verified before the callback in the product path.
data.delete(voter._actionsStoreKey());
data.delete(voter._selfActionsStoreKey());
data.set(voter._ownSigsStoreKey(), JSON.stringify([vote.signature]));
const observed = [];
const echo = new GameRelayChannel({ ...opts, onSelfAction: (type, inner) => observed.push([type, inner.signature]) });
echo.validNostrByUid.set(uid, echo.nostrPubkey);
await echo._handleEvent({ pubkey: echo.nostrPubkey,
  content: JSON.stringify({ ...vote, type: 'action', blockNum: 9, groupId: 0 }) });
assert.deepEqual(observed, [['action', vote.signature]]);
assert.equal(new GameRelayChannel(opts).getRelayActionsRaw().votes[uid].signature, vote.signature);

// Execute the official hook's self echo callback. A second signed vote from
// another client belongs in myVotePrev so the submission keeps both actions.
const hook = readFileSync(process.env.DTAG_HOOK_SOURCE
  || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const callbackStart = hook.indexOf('onSelfAction: async (type, inner) => {');
const callbackEnd = hook.indexOf('\n        },\n      });', callbackStart);
assert(callbackStart >= 0 && callbackEnd > callbackStart);
const saved = new Map();
let currentVote = null;
let currentReports = [];
let currentVotePrev = [];
const myVoteRef = { current: null };
const myVotePrevRef = { current: [] };
const bound = {
  isGameIdentityCurrent: () => true, handleRelayChat: () => {}, queueReceipt: async () => true,
  verifyRelayInner: async () => true, setOtherSessionReadReceipt: () => {},
  flagOtherSession: () => {},
  SELF_VOTE_KEY: () => 'officialVote', SELF_VOTE_PREV_KEY: () => 'officialVotePrev',
  SELF_REPORTS_KEY: () => 'officialReports', blockNum: 9, uid,
  loadJson: (key, fallback) => saved.get(key) ?? fallback,
  saveJson: (key, value) => { saved.set(key, value); return true; },
  warnActionPersistenceFailure: () => { throw Error('unexpected persistence failure'); },
  setP2pSelfVoted: () => {}, setVotedUids: () => {}, setP2pSelfReportCount: () => {},
  setMyReports: (update) => { currentReports = update(currentReports); },
  setMyVote: (update) => { currentVote = update(currentVote); },
  myVoteRef, myVotePrevRef,
  setMyVotePrev: (update) => { currentVotePrev = update(currentVotePrev); },
  isClientTimestampAllowed, effectiveClientNow: () => Date.now(),
};
const onSelfAction = new Function(...Object.keys(bound),
  `return (${hook.slice(callbackStart + 'onSelfAction: '.length, callbackEnd + 10)});`)(...Object.values(bound));
await onSelfAction('action', vote);
await onSelfAction('action', { ...vote, signature: 'second-vote', timestamp: 2000 });
assert.equal(saved.get('officialVote').signature, vote.signature);
assert.deepEqual(saved.get('officialVotePrev').map((item) => item.signature), ['second-vote']);
const sameCipher = 'same-target-ciphertext';
for (let i = 0; i < 12; i++) await onSelfAction('action', {
  actionType: 'report', uid, encrypted: sameCipher, signature: `retry-${i}`, timestamp: 3000 + i,
});
await onSelfAction('action', { actionType: 'report', uid, encrypted: 'second-target-ciphertext',
  signature: 'target-C', timestamp: 4000 });
await onSelfAction('action', { actionType: 'report', uid, encrypted: 'third-target-ciphertext',
  signature: 'target-D', timestamp: 5000 });
assert.equal(currentReports.length, 13, 'retries do not consume the second target slot');
assert.equal(new Set(currentReports.map((item) => item.encrypted)).size, 2);
assert.equal(saved.get('officialReports').length, 13);
await onSelfAction('action', { actionType: 'report', uid, encrypted: sameCipher,
  signature: 'retry-0', timestamp: 3000 });
assert.equal(currentReports.length, 13, 'a repeated signature is still deduplicated');

const sendReportStart = hook.indexOf('const sendReport = useCallback(');
const sendReportEnd = hook.indexOf('\n  }, [send, uid, blockNum, groupId, signKey', sendReportStart);
assert(sendReportStart >= 0 && sendReportEnd > sendReportStart);
const sendReportBody = hook.slice(sendReportStart + 'const sendReport = useCallback('.length, sendReportEnd + 4);
let nextSignature = 0;
const sendScope = {
  signKey: 'sign-key', rosterStartConfirmedRef: { current: true }, isGameIdentityCurrent: () => true,
  clientNow: () => 7000 + nextSignature, privateKeyToAccount: () => ({
    signMessage: async () => `send-${++nextSignature}` }),
  actionSignStringV2: () => 'message', canonicalizeSignature: (value) => value,
  sessionActivityRef: { current: { ownSignatures: new Set() } }, blockNum: 9, groupId: 0, uid,
  myVotePrevRef, setMyVotePrev: (update) => { currentVotePrev = update(currentVotePrev); },
  SELF_REPORTS_KEY: () => 'sent-reports', loadJson: (key, fallback) => saved.get(key) ?? fallback,
  saveJson: (key, value) => { saved.set(key, value); return true; },
  warnActionPersistenceFailure: () => { throw Error('unexpected persistence failure'); },
  setMyReports: (update) => { currentReports = update(currentReports); }, setReportCounts: () => {},
  relayChannelRef: { current: null }, send: () => true,
};
const sendReport = new Function(...Object.keys(sendScope), `return (${sendReportBody});`)(...Object.values(sendScope));
await sendReport(sameCipher);
await sendReport(sameCipher);
assert.deepEqual(saved.get('sent-reports').map((item) => item.signature), ['send-1', 'send-2']);
assert(currentReports.some((item) => item.signature === 'send-2'),
  'the second signed retry reaches myReports for submission');
const chatSource = readFileSync(new URL('../../src/components/game/ChatPhase.js', import.meta.url), 'utf8');
const evaluateMemo = (name, context) => {
  const start = chatSource.indexOf(`const ${name} = useMemo(`);
  const end = chatSource.indexOf('\n  }, [', start);
  assert(start >= 0 && end > start);
  const callback = chatSource.slice(start + `const ${name} = useMemo(`.length, end + 4);
  return new Function(...Object.keys(context), `return (${callback})();`)(...Object.values(context));
};
const encryptKey = `0x${'42'.repeat(32)}`;
const context = { useMemo: (fn) => fn(), encryptKey, decryptAction,
  myReports: [
    ...Array.from({ length: 12 }, (_, i) => ({
      encrypted: encryptReportDeterministic('A', encryptKey, { blockNum: 9, groupId: 0 }),
      signature: `A-${i}`, timestamp: 1000 + i,
    })),
    { encrypted: encryptReportDeterministic('C', encryptKey, { blockNum: 9, groupId: 0 }),
      signature: 'C', timestamp: 2000 },
  ],
  actionHashV2: () => 'hash', blockNum: 9, groupId: 0, myUid: uid,
  receiptorsByActionHash: {}, nowTick: 3000, RECEIPT_FRESH_WINDOW_MS: 600000 };
const reportTargetStatus = evaluateMemo('reportTargetStatus', context);
assert.deepEqual(Object.keys(reportTargetStatus).sort(), ['A', 'C']);
assert.equal(evaluateMemo('activeReportSlots', { ...context, reportTargetStatus }), 2,
  'A retries and C consume both official report target slots');
{
const here = new URL('./', import.meta.url);
const T = (p) => new URL(`../../${p}`, here);
const require = createRequire(new URL('../../package.json', import.meta.url));
const { parse } = require('@babel/parser');
const acorn = require('acorn');
const eslintScope = require('eslint-scope');
const viem = await import('viem');
const { keccak256, concat, stringToBytes, toHex, toBytes, verifyMessage } = viem;
const { privateKeyToAccount } = await import('viem/accounts');
const P = await import(T('workers/game_workers/lib/protocol-v2.js'));
const CC = await import(T('workers/game_workers/lib/char-counter.js'));
const RV = await import(T('src/utils/roster-verification.js'));
const E = await import(T('src/utils/ecies.js'));
const K = await import(T('src/utils/p2pKeys.js'));
const SL = await import(T('workers/game_workers/lib/submission-limits.js'));
const EC = await import(T('workers/game_workers/lib/evidence-compact-v1.js'));
const GRC = await import(T('workers/game_workers/lib/game-result-calculator.js'));
const RH = await import(T('src/utils/relay.js'));

let hook = readFileSync(process.env.T4_HOOK_SOURCE || T('src/hooks/useGameWebSocket.js'), 'utf8');
const mutation = process.argv.find(arg => arg.startsWith('--mutation='))?.slice('--mutation='.length)
  || process.env.T4_MUTATION;
if (mutation === 't4-latest-by-order') hook = hook.replace(/const newest = allVotes\.reduce\([\s\S]*?\);/, 'const newest = allVotes.at(-1);');
if (mutation === 't4-prev-promoted') hook = hook.replace('const chosen = myVoteRef.current || storedVote || newest;', 'const chosen = myVoteRef.current || storedVote || myVotePrevRef.current[0] || newest;');
if (mutation === 't4-receipt-myvote-only') hook = hook.replace('? { [uid]: [myVoteRef.current, ...myVotePrevRef.current] } : {}', '? { [uid]: myVoteRef.current } : {}');
if (mutation === 't4f-overwrite-saved') {
  for (const [before, after] of [
    ['if (blockNum != null && uid && !storedVote) {', 'if (blockNum != null && uid && storedVote?.signature !== chosen.signature) {'],
    ['if (!first) {', 'if (first?.signature !== current.signature) {'],
  ]) {
    assert.ok(hook.includes(before), `T4F mutation target missing: ${before}`);
    hook = hook.replace(before, after);
  }
}
const subSrc = readFileSync(T('src/components/game/SubmissionPhase.js'), 'utf8');
// The transcribed submission lines below must still be present verbatim in the real file.
for (const line of [
  'const cands = [myVote, ...prevVotes].filter(v => v?.encrypted && v?.signature && v?.timestamp);',
  'const chosen = (intent?.vote && cands.find((v) => {',
  '})) || cands.find(isReceipted) || cands[0];',
  'snapshotData.votes[myUid] = { encrypted: chosen.encrypted, signature: chosen.signature, timestamp: chosen.timestamp };',
  'const sourcedReceipts = clientChatSourcedReceipts(withReportGroundReceipts(receipts, pressReportGrounds), confirmedChatWindow, chatCloseAt);',
]) assert.ok(subSrc.includes(line), `SubmissionPhase line moved: ${line}`);
function walk(node, pred, out = []) {
  if (!node || typeof node !== 'object') return out;
  if (pred(node)) out.push(node);
  for (const [k, v] of Object.entries(node)) {
    if (['loc', 'start', 'end', 'leadingComments', 'trailingComments', 'innerComments'].includes(k)) continue;
    if (Array.isArray(v)) v.forEach((c) => walk(c, pred, out)); else if (v && typeof v === 'object') walk(v, pred, out);
  }
  return out;
}
const one = (rows, label) => { assert.equal(rows.length, 1, label); return rows[0]; };

// T7: execute the real official submission blocks. Mutations change the source before AST extraction.
let t7Source = subSrc;
const t7Mutation = process.argv.find((a) => a.startsWith('--mutation=t7-'))?.split('=')[1];
if (t7Mutation === 't7-receipted-first') {
  t7Source = t7Source.replace(/const chosen = \(intent\?\.vote && cands\.find\(\(v\) => \{[\s\S]*?\}\)\) \|\| cands\.find\(isReceipted\) \|\| cands\[0\];/,
    'const chosen = cands.find(isReceipted) || cands[0];');
} else if (t7Mutation === 't7-a3-chosen-only') {
  t7Source = t7Source.replace(/const hasIntentVote = snapVoteTarget === intent\?\.vote \|\| \(intent\?\.vote && observedSnapVotes\.some\(\(vote\) => \{[\s\S]*?\}\)\);/,
    'const hasIntentVote = snapVoteTarget === intent?.vote;');
} else if (t7Mutation === 't7-a3-any-target') {
  t7Source = t7Source.replace('const observedSnapVotes = Array.isArray(snapshotData.observed?.votes?.[myUid])\n        ? snapshotData.observed.votes[myUid] : [];',
    'const observedSnapVotes = Object.values(snapshotData.observed?.votes || {}).flatMap((votes) => Array.isArray(votes) ? votes : [votes]);');
}
if (t7Mutation) assert.notEqual(t7Source, subSrc, `T7 mutation target missing: ${t7Mutation}`);
{
  const subAst = parse(t7Source, { sourceType: 'module', plugins: ['jsx'] });
  const voteBlock = one(walk(subAst, (n) => n.type === 'IfStatement'
    && t7Source.slice(n.test.start, n.test.end).startsWith('myVote?.encrypted && myVote?.signature')), 'official vote block');
  const a3Block = one(walk(subAst, (n) => n.type === 'BlockStatement'
    && n.body?.some((s) => s.type === 'VariableDeclaration'
      && s.declarations?.some((d) => d.id?.name === 'snapVote'))), 'official A-3 block');
  const start = a3Block.body.find((s) => s.declarations?.some((d) => d.id?.name === 'snapVote')).start;
  const end = a3Block.body.find((s) => s.declarations?.some((d) => d.id?.name === 'publicSnapReports')).start;
  const decrypt = (encrypted) => {
    if (encrypted === 'bad') throw new Error('undecryptable');
    return { targetUid: encrypted };
  };
  // eslint-disable-next-line no-new-func
  const chooseBlock = Function('myVote', 'prevVotes', 'intent', 'received', 'decryptAction',
    'actionHashV2', 'buildReceiptMaps', 'collectKnownActions',
    `const myUid='V', blockNum=9, groupId=1, encryptKey='key', sourcedReceipts=[];
     const snapshotData={votes:{},observed:{votes:{}}};
     const localStorage={getItem:()=>JSON.stringify(prevVotes)};
     const messages=[],myReports=[],observedActions={};
     ${t7Source.slice(voteBlock.start, voteBlock.end)}
     return snapshotData;`);
  const choose = (myVote, prevVotes, intent, received, decryptAction) => chooseBlock(
    myVote, prevVotes, intent, received, decryptAction,
    (_type, _bn, _group, _uid, encrypted) => encrypted,
    () => ({ receiptorsByActionHash: Object.fromEntries(received.map((target) => [target, new Set(['W'])])) }),
    P.collectKnownActions);
  // eslint-disable-next-line no-new-func
  const verify = Function('snapshotData', 'intent', 'decryptAction',
    `const myUid='V', encryptKey='key', t=(_key,message)=>message;
     ${t7Source.slice(start, end)}
     return true;`);
  const voteFor = (target, signature) => ({ encrypted: target, signature, timestamp: 1 });
  const W = voteFor('W', 'voteW'); const C = voteFor('C', 'voteC');
  const chosen = choose(W, [C], { vote: 'C' }, ['W', 'C'], decrypt);
  assert.equal(chosen.votes.V.signature, C.signature, 'T7: later receipted intent vote wins');
  assert.equal(verify(chosen, { vote: 'C' }, decrypt), true);
  const newDevice = choose(C, [W], { vote: 'C' }, ['W'], decrypt);
  assert.equal(newDevice.votes.V.signature, W.signature, 'T7: sole receipted vote remains chosen');
  assert.equal(verify(newDevice, { vote: 'C' }, decrypt), true, 'T7: carried own history satisfies A-3');
  const mirror = choose(W, [C], { vote: 'W' }, ['C'], decrypt);
  assert.equal(mirror.votes.V.signature, C.signature);
  assert.equal(verify(mirror, { vote: 'W' }, decrypt), true, 'T7: original device can submit');
  const noIntent = choose(W, [C], null, ['C'], decrypt);
  assert.equal(noIntent.votes.V.signature, C.signature, 'T7: missing intent keeps receipted-first choice');
  const skipped = choose(voteFor('bad', 'unreadable'), [W], { vote: 'W' }, ['bad', 'W'], decrypt);
  assert.equal(skipped.votes.V.signature, W.signature, 'T7: undecryptable candidate does not block another vote');
  const substituted = choose(W, [C], { vote: 'B' }, ['C'], decrypt);
  assert.throws(() => verify(substituted, { vote: 'B' }, decrypt), /Self-verification failed/);
  substituted.observed.votes.C = [voteFor('B', 'other-signer')];
  assert.throws(() => verify(substituted, { vote: 'B' }, decrypt), /Self-verification failed/,
    'T7: another uid cannot satisfy A-3');
  const honest = choose(W, [], { vote: 'W' }, ['W'], decrypt);
  assert.equal(JSON.stringify(honest), JSON.stringify({ votes: { V: W }, observed: { votes: {} } }),
    'T7: one honest vote keeps snapshot bytes');
  const undecryptable = { votes: { V: voteFor('bad', 'bad') }, observed: { votes: {} } };
  assert.throws(() => verify(undecryptable, { vote: 'W' }, decrypt), /could not decrypt/);
}
let ast = parse(hook, { sourceType: 'module', plugins: ['jsx', 'logicalAssignment'] });
const cb = (name) => {
  const n = one(walk(ast, (x) => x.type === 'VariableDeclarator' && x.id?.name === name
    && x.init?.type === 'CallExpression' && x.init.callee?.name === 'useCallback'), name);
  const a = n.init.arguments[0];
  return hook.slice(a.start, a.end);
};
const prop = (name) => {
  const n = one(walk(ast, (x) => x.type === 'ObjectProperty' && x.key?.name === name), name);
  return hook.slice(n.value.start, n.value.end);
};
const caseText = (label) => {
  const c = one(walk(ast, (x) => x.type === 'SwitchCase' && x.test?.value === label), label);
  const stmts = c.consequent.length === 1 && c.consequent[0].type === 'BlockStatement' ? c.consequent[0].body : c.consequent;
  return `(data) => { ${stmts.filter((s) => s.type !== 'BreakStatement').map((s) => hook.slice(s.start, s.end)).join('\n')} }`;
};
const fnText = (name) => {
  const n = one(walk(ast, (x) => x.type === 'FunctionDeclaration' && x.id?.name === name), name);
  return hook.slice(n.start, n.end).replace(new RegExp(`^(async )?function ${name}`), '$1function');
};
const GLOBALS = new Set(['Array', 'Boolean', 'Date', 'Error', 'JSON', 'Map', 'Math', 'Number', 'Object',
  'Promise', 'Set', 'String', 'Symbol', 'console', 'undefined', 'setTimeout', 'clearTimeout', 'performance', 'RegExp']);
function freeIds(text) {
  const a = acorn.parse(`const __x = (${text});`, { ecmaVersion: 'latest', sourceType: 'script', ranges: true });
  const sm = eslintScope.analyze(a, { ecmaVersion: 2024, sourceType: 'script' });
  return [...new Set(sm.globalScope.through.map((r) => r.identifier.name))].filter((n) => n !== '__x').sort();
}
function bind(label, text, provided) {
  const missing = freeIds(text).filter((n) => !GLOBALS.has(n) && !(n in provided));
  if (missing.length) throw new Error(`${label}: unbound ${missing.join(',')}`);
  const names = Object.keys(provided);
  // eslint-disable-next-line no-new-func
  return Function(...names, `'use strict'; return (${text});`)(...names.map((n) => provided[n]));
}
const flush = async () => { for (let i = 0; i < 200; i++) await new Promise((r) => setImmediate(r)); };

// ------------------------------------------------------------------ players
const BN = 9; const G = 1;
const base = 1760000000000; const MIN = 60000;
const chatCloseAt = base + 86400000;
const chatWindow = { startMs: base - 7200000 - 120000, endMs: chatCloseAt + 120000 };
async function player(uid, eth, seedHex) {
  const wallet = privateKeyToAccount(`0x${seedHex.repeat(64)}`);
  const sig = await wallet.signMessage({ message: `bitcoinu_mining_block${BN}_user${uid}` });
  const master = keccak256(toBytes(sig));
  const signKey = keccak256(concat([toBytes(master), stringToBytes('sign')]));
  const encryptKey = keccak256(concat([toBytes(master), stringToBytes('encrypt')]));
  const acc = privateKeyToAccount(signKey);
  const wei = BigInt(Math.round(eth * 1e6)) * 10n ** 12n;
  return { uid, wallet, signKey, encryptKey, acc, addr: wallet.address,
    bAddr: { address: acc.address, pubKey: acc.publicKey }, nostr: K.deriveNostrKey(signKey, BN).pubkey,
    depIds: JSON.stringify({ deposit: wei.toString(), ids: [uid.slice(-2)] }) };
}
const sign = async (p, m) => P.canonicalizeSignature(await p.acc.signMessage({ message: m }));
const act = async (p, type, enc, ts) => ({ encrypted: enc, timestamp: ts,
  signature: await sign(p, P.actionSignStringV2(type, BN, G, p.uid, enc, ts)) });
const rcAct = async (rv, actorUid, type, a, ts) => { const h = P.actionHashV2(type, BN, G, actorUid, a.encrypted, a.timestamp);
  return { receiverUid: rv.uid, actionHash: h, timestamp: ts, signature: await sign(rv, P.receiptSignString(BN, G, rv.uid, h, ts)) }; };
function makeRoster(ps) {
  const pubs = ps.map((p) => ({ uid: p.uid, walletAddress: p.addr, blockAddress: p.acc.address, pubKey: p.acc.publicKey,
    nostrPubkey: p.nostr, depositIds: [p.uid.slice(-2)] }));
  return { status: 'verified', blockNum: BN, groupId: G, members: RV.publicRosterToGameMembers(pubs, []), publicMembers: pubs,
    anchorStatus: 'canonical', chainHash: '0x' + 'a'.repeat(64), observedAtMs: base + 5000, chattingStartMs: base,
    rosterProofSaved: true };
}

// V (voter, honest), W (present, issues receipts), B (third member, absent: no messages, no submission)
const V = await player('user0031', 0.25, '5'); const W = await player('user0032', 0.25, '6'); const B = await player('user0033', 0.25, '7');
const ps = [V, W, B];
const roster = makeRoster(ps);
const members = ps.map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddr, depIds: p.depIds }));
const msgs = [];
for (let t = 0; t < 12; t++) for (const p of [V, W]) {
  const ts = base + t * 40000 + msgs.length * 10; const text = `turn ${t} from ${p.uid} `.padEnd(60, 'y');
  msgs.push({ type: 'chat', blockNum: BN, groupId: G, uid: p.uid, text, timestamp: ts, signature: await sign(p, P.chatSignStringV2(BN, G, p.uid, text, ts)) });
}
const reads = [];
for (const [rv, s] of [[V, W], [W, V]]) {
  const msgRefs = msgs.filter((m) => m.uid === s.uid).map((m) => P.msgRefOf(P.computeMsgKeyV2(BN, G, m))).sort(P.compareHexAsc);
  const ts = base + 600000;
  reads.push({ receiverUid: rv.uid, senderUid: s.uid, msgRefs, timestamp: ts, signature: await sign(rv, P.readReceiptSignString(BN, G, rv.uid, s.uid, msgRefs, ts)) });
}
// V votes W (vote1); nobody receipts it within 10 min (W away) -> void. V resends to W (vote2), W receipts it.
const vote1 = await act(V, 'vote', E.encryptAction({ targetUid: W.uid }, V.encryptKey), base + 1 * MIN);
const vote2 = await act(V, 'vote', E.encryptAction({ targetUid: W.uid }, V.encryptKey), base + 20 * MIN);
const rcW_vote2 = await rcAct(W, V.uid, 'vote', vote2, vote2.timestamp + 30000);
const rcW_vote1 = await rcAct(W, V.uid, 'vote', vote1, vote1.timestamp + 30000);
const voteW = await act(W, 'vote', E.encryptAction({ targetUid: V.uid }, W.encryptKey), base + 21 * MIN);
const rcV_voteW = await rcAct(V, W.uid, 'vote', voteW, voteW.timestamp + 30000);
const NOW = base + 40 * MIN; // V opens a NEW browser during chatting (well before the last 10 minutes)

// ------------------------------------------------------------------ one fresh official page for V
function newStorage() {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k),
    key: (i) => [...m.keys()][i] ?? null, get length() { return m.size; } };
}
const SELF_VOTE_KEY = (bn, u) => `myVote_${bn}_user${u}`;
const SELF_VOTE_PREV_KEY = (bn, u) => `myVotePrev_${bn}_user${u}`;
const SELF_REPORTS_KEY = (bn, u) => `myReports_${bn}_user${u}`;
for (const line of ["const SELF_VOTE_KEY = (blockNum, uid) => `myVote_${blockNum}_user${uid}`;",
  'export const SELF_VOTE_PREV_KEY = (blockNum, uid) => `myVotePrev_${blockNum}_user${uid}`;',
  "const SELF_REPORTS_KEY = (blockNum, uid) => `myReports_${blockNum}_user${uid}`;"]) assert.ok(hook.includes(line), line);

async function runPage({ myVoteMsg, relayOrder, initialVote = null, initialPrev = [],
  ownReceipts = [rcW_vote2] }) {
  const storage = newStorage();
  globalThis.localStorage = storage;
  const uid = V.uid;
  if (initialVote) storage.setItem(SELF_VOTE_KEY(BN, uid), JSON.stringify(initialVote));
  if (initialPrev.length) storage.setItem(SELF_VOTE_PREV_KEY(BN, uid), JSON.stringify(initialPrev));
  const loadJson = (k, f) => { try { const raw = storage.getItem(k); return raw ? JSON.parse(raw) : f; } catch { return f; } };
  const saveJson = (k, v) => { storage.setItem(k, JSON.stringify(v)); return true; };
  const state = { myVote: initialVote ? { ...initialVote, voted: true } : null,
    myVotePrev: initialPrev, myReports: [], p2pSelfVoted: false, p2pSelfReportCount: 0 };
  const refs = { myVoteRef: { current: state.myVote }, myVotePrevRef: { current: initialPrev }, myReportsRef: { current: [] }, messagesRef: { current: msgs },
    observedActionsRef: { current: { votes: { [W.uid]: voteW }, reports: {} } }, receiptsRef: { current: {} },
    confirmedChatWindowRef: { current: chatWindow }, verifiedRosterRef: { current: roster },
    sessionActivityRef: { current: { entryAt: NOW - 5000, awayIntervals: [], ownSignatures: new Set(), ended: false, warned: false } } };
  const setMyVote = (u) => { state.myVote = typeof u === 'function' ? u(state.myVote) : u; refs.myVoteRef.current = state.myVote; };
  const setMyVotePrev = (u) => { state.myVotePrev = typeof u === 'function' ? u(state.myVotePrev) : u; refs.myVotePrevRef.current = state.myVotePrev; };
  const setMyReports = (u) => { state.myReports = typeof u === 'function' ? u(state.myReports) : u; refs.myReportsRef.current = state.myReports; };
  const selectCurrentRoster = () => RV.selectCurrentRoster(refs.verifiedRosterRef.current, null, BN, G);
  const flagOtherSession = () => {};
  const verifySelfActionEcho = bind('verifySelfActionEcho', fnText('verifySelfActionEcho'), {
    isCanonicalSignature: P.isCanonicalSignature, isCanonicalTimestamp: P.isCanonicalTimestamp,
    privateKeyToAccount, verifyMessage, actionSignStringV2: P.actionSignStringV2 });
  const myVoteCase = bind('my_vote', caseText('my_vote'), {
    verifySelfActionEcho, blockNum: BN, groupId: G, uid, signKeyRef: { current: V.signKey },
    isCurrentMessageOwner: () => true, flagOtherSession, setMyVote, setMyVotePrev, myVoteRef: refs.myVoteRef, myVotePrevRef: refs.myVotePrevRef, loadJson, saveJson,
    SELF_VOTE_KEY, SELF_VOTE_PREV_KEY, warnActionPersistenceFailure: () => {} });
  const verifyRelayInner = bind('verifyRelayInner', cb('verifyRelayInner'), {
    blockNum: BN, groupId: G, selectCurrentRoster, effectiveClientNow: () => NOW,
    isCanonicalTimestamp: P.isCanonicalTimestamp, isCanonicalSignature: P.isCanonicalSignature,
    isCanonicalText: P.isCanonicalText, hasVisibleContent: CC.hasVisibleContent, chatSignStringV2: P.chatSignStringV2,
    actionSignStringV2: P.actionSignStringV2, isCanonicalActionCiphertext: P.isCanonicalActionCiphertext,
    presenceSignStringV2: P.presenceSignStringV2, isMsgRef: P.isMsgRef, receiptMaxRefsPerReceipt: P.receiptMaxRefsPerReceipt,
    GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES, compareHexAsc: P.compareHexAsc,
    readReceiptSignString: P.readReceiptSignString, isActionHash: P.isActionHash, receiptSignString: P.receiptSignString,
    verifyMessage });
  const onSelfAction = bind('onSelfAction', prop('onSelfAction'), {
    isGameIdentityCurrent: () => true, handleRelayChat: () => {}, flagOtherSession,
    isClientTimestampAllowed: RH.isClientTimestampAllowed, effectiveClientNow: () => NOW,
    queueReceipt: async () => true, verifyRelayInner, uid, blockNum: BN,
    SELF_VOTE_KEY, SELF_VOTE_PREV_KEY, SELF_REPORTS_KEY, loadJson, saveJson,
    warnActionPersistenceFailure: () => {}, myVoteRef: refs.myVoteRef, myVotePrevRef: refs.myVotePrevRef, setMyVotePrev, setP2pSelfVoted: (u) => { state.p2pSelfVoted = typeof u === 'function' ? u(state.p2pSelfVoted) : u; },
    setMyVote, setVotedUids: () => {},
    setP2pSelfReportCount: (u) => { state.p2pSelfReportCount = u(state.p2pSelfReportCount); }, setMyReports });
  const isAccepted = bind('isAccepted', prop('isAccepted'), {
    messagesRef: refs.messagesRef, receiptsRef: refs.receiptsRef, receiptIdentityDigest: P.receiptIdentityDigest,
    observedActionsRef: refs.observedActionsRef, liveOnlyMessagesRef: { current: new Set() }, retryReceiptForAcceptedAction: async () => {}, uid });
  const resolveReceiptTarget = bind('resolveReceiptTarget', cb('resolveReceiptTarget'), {
    messagesRef: refs.messagesRef, observedActionsRef: refs.observedActionsRef, myVoteRef: refs.myVoteRef,
    myReportsRef: refs.myReportsRef, myVotePrevRef: refs.myVotePrevRef, uid, buildRealTargets: P.buildRealTargets, blockNum: BN, groupId: G,
    isActionHash: P.isActionHash, receiptCoverClaim: P.receiptCoverClaim, clientReadReceiptAdmission: P.clientReadReceiptAdmission, confirmedChatWindowRef: refs.confirmedChatWindowRef,
    receiptMaxRefsPerReceipt: P.receiptMaxRefsPerReceipt, GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES, actionHashV2: P.actionHashV2 });

  // 1) WS init: my_vote echo (server-chosen order of genuine own votes)
  if (myVoteMsg) { myVoteCase({ type: 'my_vote', ...myVoteMsg }); await flush(); }
  // 2) relay history: own vote echoes through the REAL GameRelayChannel._handleEvent self branch
  const ch = new RH.GameRelayChannel({ signKey: V.signKey, blockNum: BN, groupId: G, uid, members: roster.members,
    now: () => NOW, futureMarks: new RH.FutureAdmissionMarks({ blockNum: BN, groupId: G, now: () => NOW, correction: () => 0 }),
    isAccepted, verifyInnerSignature: (type, inner) => verifyRelayInner(type, inner), onSelfAction,
    onActionsChange: () => {}, onReceiptsChange: () => {}, onFactsChange: () => {}, onChat: () => {} });
  for (const member of ch.members) {
    const bAddr = typeof member.bAddr === 'string' ? JSON.parse(member.bAddr) : member.bAddr;
    if (K.isValidNostrPubkey(bAddr?.nostrPubkey)) ch.validNostrByUid.set(member.uid, bAddr.nostrPubkey);
  }
  ch.pool = { publish: () => {}, closed: false, sockets: new Map() };
  for (const a of relayOrder) {
    const content = JSON.stringify({ type: 'action', actionType: 'vote', blockNum: BN, groupId: G, uid, ...a });
    await ch._handleEvent({ id: keccak256(toBytes(content)), pubkey: V.nostr, content });
  }
  await flush();

  // 3) W's receipt on vote2 and V's own receipt on W's vote arrive during chat (receipt_history / relay)
  const resolved = { rcW_vote2: resolveReceiptTarget(rcW_vote2, ps.map((p) => p.uid)).state,
    rcV_voteW: resolveReceiptTarget(rcV_voteW, ps.map((p) => p.uid)).state };
  for (const rc of ownReceipts) resolved[rc.signature] = resolveReceiptTarget(rc, ps.map((p) => p.uid)).state;
  // ReceiptAdmissionQueue keeps a non-covered entry 'pending' and drops it with target_expired after
  // RECEIPT_PENDING_TTL_MS (relay.js:921-923); only covered entries reach ingestReceipt -> `receipts` state.
  const receipts = {};
  for (const [name, rc] of [...ownReceipts.map(rc => [rc.signature, rc]), ['rcV_voteW', rcV_voteW]]) {
    if (resolved[name] === 'covered') receipts[rc.signature] = P.markActionReceiptSource(rc,
      { source: 'do', chatCloseAt, chainTimeMs: NOW, nowMs: NOW });
  }
  for (const rd of reads) receipts[rd.signature] = rd;
  return { state, storage, loadJson, receipts, resolved };
}

// ------------------------------------------------------------------ V's submission (SubmissionPhase.js:546-590 + observed)
function buildVBundle(page) {
  const myUid = V.uid; const myVote = page.state.myVote; const blockNum = BN; const groupId = G;
  const intent = page.loadJson(`actionIntent_${blockNum}_user${myUid}`, null);
  const snapshotData = { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };
  const grounds = loadReportGrounds(blockNum, myUid, page.storage);
  const sourcedReceipts = P.clientChatSourcedReceipts(withReportGroundReceipts(page.receipts, grounds), chatWindow, chatCloseAt);
  const prevVotes = page.loadJson(SELF_VOTE_PREV_KEY(BN, myUid), []);
  if (myVote?.encrypted && myVote?.signature && myVote?.timestamp) {
    const cands = [myVote, ...prevVotes].filter(v => v?.encrypted && v?.signature && v?.timestamp);
    const voteReceiptors = P.buildReceiptMaps(sourcedReceipts,
      { messages: msgs, actions: P.collectKnownActions({ myUid, myVote, myVotePrev: prevVotes, myReports: [], observedActions: { votes: { [W.uid]: voteW }, reports: {} } }) },
      blockNum, groupId).receiptorsByActionHash;
    const isReceipted = (v) => { const h = P.actionHashV2('vote', blockNum, groupId, myUid, v.encrypted, v.timestamp);
      const set = voteReceiptors?.[h]; return !!set && [...set].some(u => u !== myUid); };
    const chosen = (intent?.vote && cands.find((v) => {
      if (!isReceipted(v)) return false;
      try { return E.decryptAction(v.encrypted, V.encryptKey)?.targetUid === intent.vote; }
      catch (e) { return false; }
    })) || cands.find(isReceipted) || cands[0];
    snapshotData.votes[myUid] = { encrypted: chosen.encrypted, signature: chosen.signature, timestamp: chosen.timestamp };
    const rest = cands.filter(v => v.signature !== chosen.signature)
      .map(v => ({ encrypted: v.encrypted, signature: v.signature, timestamp: v.timestamp }));
    if (rest.length > 0) snapshotData.observed.votes[myUid] = rest;
  }
  snapshotData.observed.votes[W.uid] = [voteW];
  const n = SL.normalizeActionSnapshotForSubmission(snapshotData, { blockNum: BN, groupId: G, memberUids: ps.map((p) => p.uid),
    submitterUid: V.uid, reportTargetOf: () => null });
  const accepted = Object.values(sourcedReceipts).map(({ _chainSeenAt, _deviceSeenAt, _chatSources, _seq, ...rc }) => rc);
  const carried = EC.filterReceiptsToCarriedTargets({ ...n, observed: { ...n.observed, receipts: accepted } }, msgs, BN, G);
  return { ...carried, observed: { ...carried.observed, receipts: [...carried.observed.receipts].sort((a, b) => (a.signature < b.signature ? -1 : 1)) } };
}
// W carries everything it saw except what U-7 discards anyway (its own receipt on V's vote is in W's bundle,
// but the issuer's own copy is not counted).
const bundleW = { votes: { [W.uid]: voteW }, reports: {}, observed: {
  votes: { [V.uid]: [vote1, vote2] }, reports: {},
  receipts: [...reads, rcW_vote2, rcV_voteW].sort((a, b) => (a.signature < b.signature ? -1 : 1)) } };
async function sub(p, snapshot) {
  const messages = P.sortCanonicalV2(msgs, BN, G); const submittedAt = base + 99999999;
  const depositIds = JSON.parse(p.depIds).ids; const chatHash = P.computeChatHashV2(messages, BN, G);
  const encryptedDataHash = keccak256(toHex(JSON.stringify(snapshot)));
  const signature = await p.wallet.signMessage({ message: JSON.stringify({ blockNum: BN, uid: p.uid, encryptKey: p.encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds }) });
  return { uid: p.uid, encryptKey: p.encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions: structuredClone(snapshot), messages };
}
async function score(vBundle, wBundle = bundleW) {
  const submissions = { [V.uid]: await sub(V, vBundle), [W.uid]: await sub(W, wBundle) }; // B absent
  for (const [u, s] of Object.entries(submissions)) {
    const chk = SL.validateSubmissionStructure(s, { blockNum: BN, groupId: G, memberUids: ps.map((p) => p.uid) });
    if (!chk.ok) console.error('structure', u, JSON.stringify(chk).slice(0, 400));
  }
  const { results } = await GRC.calculateGroupResults({ members, submissions, meta: { blockNum: BN, groupId: G } }, 500, 10, {}, null);
  const nm = (u) => (u === V.uid ? 'V' : u === W.uid ? 'W' : 'B');
  return Object.fromEntries(results.map((r) => [nm(r.uid), { dq: r.isDisqualified, reason: r.disqualifyReason || null, total: r.totalPoints }]));
}

// Keep React state and the passive-effect ref separate. A vote echo can arrive
// after sendVote writes storage but before commit updates myVoteRef.
function openVotePage(storage) {
  globalThis.localStorage = storage;
  const uid = V.uid;
  const loadJson = (key, fallback) => { try { const raw = storage.getItem(key); return raw ? JSON.parse(raw) : fallback; } catch { return fallback; } };
  const saveJson = (key, value) => { storage.setItem(key, JSON.stringify(value)); return true; };
  const stored = loadJson(SELF_VOTE_KEY(BN, uid), null);
  const previous = loadJson(SELF_VOTE_PREV_KEY(BN, uid), []);
  const state = { myVote: stored ? { ...stored, voted: true } : null, myVotePrev: previous };
  const myVoteRef = { current: state.myVote };
  const myVotePrevRef = { current: previous };
  const setMyVote = update => { state.myVote = typeof update === 'function' ? update(state.myVote) : update; };
  const setMyVotePrev = update => { state.myVotePrev = typeof update === 'function' ? update(state.myVotePrev) : update; };
  const commit = () => { myVoteRef.current = state.myVote; myVotePrevRef.current = state.myVotePrev; };
  const common = { blockNum: BN, groupId: G, uid, SELF_VOTE_KEY, SELF_VOTE_PREV_KEY,
    loadJson, saveJson, myVoteRef, myVotePrevRef, setMyVote, setMyVotePrev,
    warnActionPersistenceFailure: () => { throw new Error('vote persistence failed'); } };
  const verifySelfActionEcho = bind('verifySelfActionEcho', fnText('verifySelfActionEcho'), {
    isCanonicalSignature: P.isCanonicalSignature, isCanonicalTimestamp: P.isCanonicalTimestamp,
    privateKeyToAccount, verifyMessage, actionSignStringV2: P.actionSignStringV2 });
  const myVoteCase = bind('my_vote', caseText('my_vote'), { ...common,
    verifySelfActionEcho, signKeyRef: { current: V.signKey }, isCurrentMessageOwner: () => true,
    flagOtherSession: () => {} });
  const onSelfAction = bind('onSelfAction', prop('onSelfAction'), { ...common,
    isGameIdentityCurrent: () => true, handleRelayChat: () => {}, flagOtherSession: () => {},
    isClientTimestampAllowed: RH.isClientTimestampAllowed, effectiveClientNow: () => NOW,
    queueReceipt: async () => true, verifyRelayInner: async () => true,
    setP2pSelfVoted: () => {}, setVotedUids: () => {},
    SELF_REPORTS_KEY, setP2pSelfReportCount: () => {}, setMyReports: () => {} });
  const sendVote = bind('sendVote', cb('sendVote'), { ...common,
    signKey: V.signKey, rosterStartConfirmedRef: { current: true },
    isGameIdentityCurrent: () => true, clientNow: () => vote2.timestamp,
    privateKeyToAccount, actionSignStringV2: P.actionSignStringV2,
    canonicalizeSignature: P.canonicalizeSignature,
    sessionActivityRef: { current: { ownSignatures: new Set() } },
    setVotedUids: () => {}, relayChannelRef: { current: null }, send: () => true });
  const resolveReceiptTarget = bind('resolveReceiptTarget', cb('resolveReceiptTarget'), {
    messagesRef: { current: msgs }, observedActionsRef: { current: { votes: { [W.uid]: voteW }, reports: {} } },
    myVoteRef, myVotePrevRef, myReportsRef: { current: [] }, uid, buildRealTargets: P.buildRealTargets,
    blockNum: BN, groupId: G, isActionHash: P.isActionHash, receiptCoverClaim: P.receiptCoverClaim, clientReadReceiptAdmission: P.clientReadReceiptAdmission,
    confirmedChatWindowRef: { current: chatWindow }, receiptMaxRefsPerReceipt: P.receiptMaxRefsPerReceipt,
    GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES, actionHashV2: P.actionHashV2 });
  const receipts = Object.fromEntries(reads.map(r => [r.signature, r]));
  receipts[rcV_voteW.signature] = P.markActionReceiptSource(rcV_voteW,
    { source: 'do', chatCloseAt, chainTimeMs: NOW, nowMs: NOW });
  return { state, loadJson, receipts, commit,
    saved: () => loadJson(SELF_VOTE_KEY(BN, uid), null),
    async resend() { await sendVote(vote2.encrypted); },
    async myVote(v) { myVoteCase({ type: 'my_vote', vote: v }); await flush(); },
    async relayVote(v) { await onSelfAction('action', { ...v, actionType: 'vote', uid }); },
    receive(receipt) {
      const result = resolveReceiptTarget(receipt, ps.map(p => p.uid)).state;
      if (result === 'covered') receipts[receipt.signature] = P.markActionReceiptSource(receipt,
        { source: 'do', chatCloseAt, chainTimeMs: NOW, nowMs: NOW });
      return result;
    },
  };
}

if (!process.env.T4_HONEST_ONLY) {
  const noOtherReceipt = { ...bundleW, observed: { ...bundleW.observed,
    receipts: [...reads, rcV_voteW] } };
  const checkReopened = async (storage, label) => {
    const page = openVotePage(storage);
    page.commit();
    const receiptState = page.receive(rcW_vote2);
    const bundle = buildVBundle(page);
    const result = await score(bundle, noOtherReceipt);
    assert.notEqual(result.V.reason, 'no_vote', `${label}: voter is not no_vote`);
    assert.equal(page.state.myVote?.signature, vote2.signature, `${label}: reopened current vote is the resend`);
    assert.equal(receiptState, 'covered', `${label}: resend receipt remains covered`);
    assert.equal(bundle.votes[V.uid]?.signature, vote2.signature, `${label}: resend reaches submission`);
  };
  const raceStorage = newStorage();
  raceStorage.setItem(SELF_VOTE_KEY(BN, V.uid), JSON.stringify(vote1));
  const racePage = openVotePage(raceStorage);
  await racePage.resend();
  assert.equal(racePage.saved()?.signature, vote2.signature, 'sendVote stores the resend');
  assert.equal(racePage.state.myVote?.signature, vote2.signature, 'sendVote updates state');
  assert.equal(racePage.loadJson(SELF_VOTE_PREV_KEY(BN, V.uid), [])[0]?.signature, vote1.signature,
    'sendVote keeps the previous vote in history');
  await racePage.myVote(vote1); // before commit: ref still points at vote1
  await checkReopened(raceStorage, 'sendVote / stale my_vote / reopen');

  for (const path of ['my_vote', 'relay']) {
    const shared = newStorage();
    shared.setItem(SELF_VOTE_KEY(BN, V.uid), JSON.stringify(vote1));
    const oldTab = openVotePage(shared);
    const votingTab = openVotePage(shared);
    await votingTab.resend();
    assert.equal(votingTab.saved()?.signature, vote2.signature, `${path}: voting tab stores the resend`);
    if (path === 'my_vote') await oldTab.myVote(vote1);
    else await oldTab.relayVote(vote1);
    await checkReopened(shared, `two tabs / stale ${path} / reopen`);
  }
  console.log('T4F race and two tabs: saved resend, receipt and scoring PASS');
}

const name = (a) => (a?.signature === vote1.signature ? 'vote1' : a?.signature === vote2.signature ? 'vote2' : a ? '?' : null);
const out = { scenarios: {} };
const scenarios = {
  // control: honest DO that saw both votes over WS (stores first as votes:uid, later as voteExtras)
  C_honest_ws_both: { myVoteMsg: { vote: vote1, extras: [vote2] }, relayOrder: [vote2, vote1] },
  // operator: same genuine signed votes, unsigned order swapped
  A_operator_swaps_vote_extras: { myVoteMsg: { vote: vote2, extras: [vote1] }, relayOrder: [vote2, vote1] },
  // operator: withholds the later vote from extras ("selective") — relay still delivers it
  B_operator_withholds_extra: { myVoteMsg: { vote: vote1, extras: [] }, relayOrder: [vote2, vote1] },
  // accident: the resend went out while WS was down -> honest DO only has vote1
  D_honest_resend_was_p2p_only: { myVoteMsg: { vote: vote1, extras: [] }, relayOrder: [vote2, vote1] },
  // accident: no WS echo yet, the first relay to answer lacks vote2 at first (older event first)
  E_relay_first_old_first: { myVoteMsg: null, relayOrder: [vote1, vote2] },
  // relay-first newest-first (typical relay history order) — control
  F_relay_first_newest_first: { myVoteMsg: null, relayOrder: [vote2, vote1] },
};
const recoveryApp = readFileSync(T('chatgame-tools/src/recovery/app.js'), 'utf8');
const recoveryAst = parse(recoveryApp, { sourceType: 'module', plugins: ['jsx'] });
function recoveryFn(name) {
  const n = one(walk(recoveryAst, x => x.type === 'FunctionDeclaration' && x.id?.name === name), name);
  return recoveryApp.slice(n.start, n.end).replace(new RegExp(`^(async )?function ${name}`), '$1function');
}
const { buildSubmissionBundle } = await import(T('chatgame-tools/src/recovery/bundle.js'));
async function recoveryPage(relayOrder) {
  globalThis.localStorage = newStorage();
  const state = { uid: V.uid, myVote: null, myVotePrev: [], myReports: [], observedP2P: {},
    importedActions: { votes: {}, reports: {} }, observedActions: { votes: {}, reports: {} },
    cfg: { pins: { maxReports: 2 } }, intent: { vote: null, reports: [] } };
  const stubs = { state, MAX_OBSERVED_ACTIONS_PER_ACTOR: P.MAX_OBSERVED_ACTIONS_PER_ACTOR,
    observeOtherSessionItem: () => {}, issueActionReceipt: () => {}, decryptSelfTarget: () => null,
    renderGame: () => {}, log: () => {}, mergeReceipts: () => {}, isMsgRef: P.isMsgRef, isActionHash: P.isActionHash };
  const handleObservedActions = bind('handleObservedActions', recoveryFn('handleObservedActions'), stubs);
  const handleSelfAction = bind('handleSelfAction', recoveryFn('handleSelfAction'), stubs);
  let ch;
  ch = new RH.GameRelayChannel({ signKey: V.signKey, blockNum: BN, groupId: G, uid: V.uid, members: roster.members,
    now: () => NOW, futureMarks: new RH.FutureAdmissionMarks({ blockNum: BN, groupId: G, now: () => NOW, correction: () => 0 }),
    isAccepted: (type, inner) => {
      if (type !== 'action') return false;
      const slot = ch?.relayActions?.[inner.uid];
      const prior = inner.actionType === 'vote' ? [slot?.vote, ...(slot?.voteExtras || [])] : (slot?.reports || []);
      return prior.some(k => k?.signature === inner.signature && k.timestamp === inner.timestamp && k.encrypted === inner.encrypted);
    },
    verifyInnerSignature: async () => true,
    onSelfAction: (type, inner) => handleSelfAction(type, inner),
    onActionsChange: raw => handleObservedActions(raw),
    onReceiptsChange: () => {}, onFactsChange: () => {}, onChat: () => {} });
  for (const member of ch.members) {
    const bAddr = typeof member.bAddr === 'string' ? JSON.parse(member.bAddr) : member.bAddr;
    if (K.isValidNostrPubkey(bAddr?.nostrPubkey)) ch.validNostrByUid.set(member.uid, bAddr.nostrPubkey);
  }
  ch.pool = { publish: () => {}, closed: false, sockets: new Map() };
  for (const a of relayOrder) {
    const content = JSON.stringify({ type: 'action', actionType: 'vote', blockNum: BN, groupId: G, uid: V.uid, ...a });
    await ch._handleEvent({ id: keccak256(toBytes(content)), pubkey: V.nostr, content });
  }
  await flush();
  const allReceipts = [...reads, rcW_vote2, rcV_voteW].map(rc => rc.actionHash
    ? P.markActionReceiptSource(rc, { source: 'do', chatCloseAt, chainTimeMs: NOW, nowMs: NOW }) : rc);
  const result = await buildSubmissionBundle({ blockNum: BN, groupId: G, myUid: V.uid,
    encryptKey: V.encryptKey, members, messages: msgs, myDepositIds: JSON.parse(V.depIds).ids,
    myVote: state.myVote, myVotePrev: state.myVotePrev, myReports: [],
    observedActions: { votes: { [W.uid]: voteW }, reports: {} }, receipts: allReceipts,
    chatWindow, chatCloseAt, submittedAt: base + 99999999,
    signWallet: message => V.wallet.signMessage({ message }) });
  return { state, bundle: result.snapshotData };
}
const signatures = values => (values || []).map(v => v.signature).sort();
if (process.env.T4_HONEST_ONLY) {
  for (const [label, initialVote, initialPrev] of [
    ['one-vote', vote2, []], ['same-screen-resend', vote2, [vote1]],
  ]) {
    const page = await runPage({ myVoteMsg: null, relayOrder: [], initialVote, initialPrev });
    const bundle = buildVBundle(page);
    const bytes = JSON.stringify({ myVote: page.state.myVote, receipts: page.receipts,
      encryptedActions: bundle });
    if (process.env.T4_BEFORE_SOURCE) {
      const afterHook = hook, afterAst = ast;
      hook = readFileSync(process.env.T4_BEFORE_SOURCE, 'utf8');
      ast = parse(hook, { sourceType: 'module', plugins: ['jsx', 'logicalAssignment'] });
      const beforePage = await runPage({ myVoteMsg: null, relayOrder: [], initialVote, initialPrev });
      const beforeBytes = JSON.stringify({ myVote: beforePage.state.myVote,
        receipts: beforePage.receipts, encryptedActions: buildVBundle(beforePage) });
      assert.equal(bytes, beforeBytes, `${label}: honest state, receipts and submission bytes unchanged`);
      hook = afterHook; ast = afterAst;
    }
    console.log(`T4 honest ${label}: bytes unchanged`);
  }
} else for (const [label, sc] of Object.entries(scenarios)) {
  const page = await runPage(sc);
  const expectedCurrent = ['C_honest_ws_both', 'A_operator_swaps_vote_extras',
    'F_relay_first_newest_first'].includes(label) ? vote2.signature : vote1.signature;
  assert.equal(page.state.myVote?.signature, expectedCurrent, `${label}: current self vote`);
  assert.equal(page.loadJson(SELF_VOTE_KEY(BN, V.uid), null)?.signature, expectedCurrent,
    `${label}: saved current vote agrees with state`);
  const vb = buildVBundle(page);
  const scores = await score(vb);
  const recovery = await recoveryPage(sc.relayOrder);
  assert.equal(vb.votes[V.uid]?.signature, recovery.bundle.votes[V.uid]?.signature, `${label}: own chosen vote`);
  assert.deepEqual(signatures(vb.observed.votes[V.uid]), signatures(recovery.bundle.observed.votes[V.uid]), `${label}: remaining votes`);
  const ownReceiptSignatures = b => signatures(b.observed.receipts.filter(rc => rc.actionHash === rcW_vote2.actionHash));
  assert.deepEqual(ownReceiptSignatures(vb), ownReceiptSignatures(recovery.bundle), `${label}: own vote receipt`);
  assert.notEqual(scores.V.reason, 'no_vote', `${label}: V not no_vote`);
  out.scenarios[label] = {
    myVote: name(page.state.myVote), storedSelfVote: name(page.loadJson(SELF_VOTE_KEY(BN, V.uid), null)),
    storedPrev: page.loadJson(SELF_VOTE_PREV_KEY(BN, V.uid), []).map(name),
    resolve_rcW_on_vote2: page.resolved.rcW_vote2,
    vBundle: { ownVote: name(vb.votes?.[V.uid]), ownVoteObserved: (vb.observed?.votes?.[V.uid] || []).map(name),
      carriesRcW_on_vote2: vb.observed.receipts.some((r) => r.signature === rcW_vote2.signature) },
    scores,
  };
}
if (!process.env.T4_HONEST_ONLY) {
  const stalePrevPage = await runPage({ myVoteMsg: { vote: vote1, extras: [] },
    relayOrder: [], initialPrev: [vote2] });
  assert.equal(stalePrevPage.state.myVote?.signature, vote1.signature,
    'saved PREV alone is never promoted to the current vote');
  const fixedPage = await runPage({ myVoteMsg: { vote: vote1,
    extras: [{ ...vote2, uid: 'unsigned-uid', actionType: 'report' }] },
    relayOrder: [], initialVote: vote1 });
  assert.equal(fixedPage.state.myVote?.signature, vote1.signature,
    'an already selected current vote stays fixed after my_vote');
  assert.deepEqual(fixedPage.loadJson(SELF_VOTE_PREV_KEY(BN, V.uid), []).map(name), ['vote2'],
    'every other signed my_vote entry goes to history, not the current vote');
  assert.deepEqual(Object.keys(fixedPage.loadJson(SELF_VOTE_PREV_KEY(BN, V.uid), [])[0]).sort(),
    ['encrypted', 'signature', 'timestamp'], 'unsigned extras are not saved with a self vote');
  const sameTsVote = await act(V, 'vote', E.encryptAction({ targetUid: W.uid }, V.encryptKey), vote1.timestamp);
  const tiePage = await runPage({ myVoteMsg: { vote: sameTsVote, extras: [vote1] }, relayOrder: [] });
  assert.equal(tiePage.state.myVote?.signature, sameTsVote.signature,
    'equal timestamps keep the first input, like recovery stable sort');
  const sentStorage = new Map([[SELF_VOTE_KEY(BN, V.uid), vote1]]);
  let sentCurrent = { ...vote1, voted: true }, sentHistory = [];
  const sentHistoryRef = { current: [] };
  const sendVote = bind('sendVote', cb('sendVote'), {
    signKey: V.signKey, rosterStartConfirmedRef: { current: true },
    isGameIdentityCurrent: () => true, clientNow: () => vote2.timestamp,
    privateKeyToAccount, actionSignStringV2: P.actionSignStringV2,
    canonicalizeSignature: P.canonicalizeSignature,
    sessionActivityRef: { current: { ownSignatures: new Set() } },
    blockNum: BN, groupId: G, uid: V.uid, SELF_VOTE_KEY, SELF_VOTE_PREV_KEY,
    loadJson: (key, fallback) => sentStorage.get(key) ?? fallback,
    saveJson: (key, value) => { sentStorage.set(key, value); return true; },
    warnActionPersistenceFailure: () => {},
    myVotePrevRef: sentHistoryRef,
    setMyVotePrev: update => { sentHistory = update(sentHistory); sentHistoryRef.current = sentHistory; },
    setMyVote: update => { sentCurrent = update(sentCurrent); }, setVotedUids: () => {},
    relayChannelRef: { current: null }, send: () => true,
  });
  await sendVote(vote2.encrypted);
  assert.equal(sentCurrent.signature, vote2.signature, 'the local resend becomes the current vote');
  assert.deepEqual(sentHistory.map(name), ['vote1'], 'the local resend archives its previous vote');
  const oldReceiptedPage = await runPage({ myVoteMsg: { vote: vote1, extras: [vote2] },
    relayOrder: [vote2, vote1], ownReceipts: [rcW_vote1] });
  const oldReceiptedBundle = buildVBundle(oldReceiptedPage);
  assert.equal(oldReceiptedPage.resolved[rcW_vote1.signature], 'covered',
    'a delayed receipt for the former vote resolves from history');
  assert.equal(oldReceiptedBundle.votes[V.uid].signature, vote1.signature,
    'the receipted former vote is carried in the own vote slot');
  assert(oldReceiptedBundle.observed.receipts.some(rc => rc.signature === rcW_vote1.signature),
    'the delayed former-vote receipt is carried');
  const noWCarrier = { ...bundleW, observed: { ...bundleW.observed,
    receipts: [...reads, rcV_voteW] } };
  assert.notEqual((await score(oldReceiptedBundle, noWCarrier)).V.reason, 'no_vote',
    'a V-carried former-vote receipt prevents no_vote without another carrier');
}




if (!process.env.T4_HONEST_ONLY) assert.equal(Object.keys(out.scenarios).length, 6);
if (!process.env.T4_HONEST_ONLY) console.log('T4 A-F: official hook / recovery app / recovery bundle / scorer PASS');

}
console.log('t2-own-actions-unit: ALL PASSED (two tabs, vote/report union, recovery and official self echo)');
