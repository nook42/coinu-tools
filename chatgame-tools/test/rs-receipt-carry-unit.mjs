// S3R4-U-DUPGATE: 署名済みの一部重複を受け入れ、表示し、提出する経路。
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, cpSync, rmSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { verifyMessage } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { buildScenario, makePlayer } from './scenario.mjs';
import { buildSubmissionBundle } from '../src/recovery/bundle.js';
import { separatorPoint } from '../../src/utils/priorityEvidence.js';
import { ReceiptAdmissionQueue, ReceiptClaimMemo } from '../vendor/src/utils/relay.js';
import { calculateGroupResults, receiptCanonCmp } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { validateSubmissionStructure } from '../vendor/workers/game_workers/lib/submission-limits.js';
import { buildMembersIndex, validateResultBundle } from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import { limitCarriedReceiptFacts, encodeEvidenceCompactV1, aggregateSelfReceipts,
  decodeSubmissionPayloadString } from '../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { GUEST_PINNED_RULES, countMessageTurns, filterVisibleMessages, countVisibleChars } from '../vendor/workers/game_workers/lib/char-counter.js';
import { encryptAction } from '../vendor/src/utils/ecies.js';
import {
  admitReadReceiptsByArrival, buildRealTargets, buildReceiptMaps, clientScoreableMessages,
  computeMsgKeyV2, msgRefOf, readReceiptSignString, chatSignStringV2, canonicalizeSignature,
  receiptCoverClaim, compareHexAsc, actionHashV2, receiptSignString, actionSignStringV2,
} from '../vendor/workers/game_workers/lib/protocol-v2.js';

const require = createRequire(import.meta.url);
const { parse } = require('@babel/parser');
const acorn = require('acorn');
const eslintScope = require('eslint-scope');

const GLOBALS = new Set([
  'Array', 'BigInt', 'Boolean', 'Date', 'Error', 'Infinity', 'JSON', 'Map', 'Math', 'NaN',
  'Number', 'Object', 'Promise', 'Proxy', 'RangeError', 'ReferenceError', 'Reflect', 'RegExp', 'Set', 'String',
  'Symbol', 'TypeError', 'URIError', 'Uint8Array', 'clearInterval', 'clearTimeout', 'console',
  'decodeURIComponent', 'encodeURIComponent', 'globalThis', 'parseFloat', 'parseInt',
  'queueMicrotask', 'setInterval', 'setTimeout', 'structuredClone', 'undefined', 'WeakMap', 'WeakSet',
  'isFinite', 'isNaN', 'TextEncoder', 'TextDecoder', 'performance', 'process',
]);

export function freeIdentifiers(code) {
  const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'script', ranges: true });
  const sm = eslintScope.analyze(ast, { ecmaVersion: 2024, sourceType: 'script' });
  return [...new Set(sm.globalScope.through.map((r) => r.identifier.name))].sort();
}

export class SourceModule {
  constructor(file) {
    this.file = file;
    this.text = readFileSync(file, 'utf8');
    this.ast = parse(this.text, { sourceType: 'module',
      plugins: ['jsx', 'bigInt', 'numericSeparator', 'optionalChaining', 'nullishCoalescingOperator'] });
    this.imports = new Map();
    for (const node of this.ast.program.body) {
      if (node.type !== 'ImportDeclaration') continue;
      for (const s of node.specifiers) {
        this.imports.set(s.local.name, { source: node.source.value,
          imported: s.type === 'ImportDefaultSpecifier' ? 'default'
            : s.type === 'ImportNamespaceSpecifier' ? '*' : s.imported.name });
      }
    }
  }
  walk(node, predicate, out = []) {
    if (!node || typeof node !== 'object') return out;
    if (predicate(node)) out.push(node);
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'tokens', 'comments', 'leadingComments', 'trailingComments'].includes(key)) continue;
      if (Array.isArray(value)) value.forEach((child) => this.walk(child, predicate, out));
      else if (value && typeof value === 'object') this.walk(value, predicate, out);
    }
    return out;
  }
  unique(predicate, label) {
    const rows = this.walk(this.ast, predicate);
    if (rows.length !== 1) throw new Error(`${label}: expected 1 match, got ${rows.length} in ${this.file}`);
    return rows[0];
  }
  textOf(node) { return this.text.slice(node.start, node.end); }
  fnDecl(name) {
    return this.textOf(this.unique((n) => n.type === 'FunctionDeclaration' && n.id?.name === name, name));
  }
  classDecl(name) {
    return this.textOf(this.unique((n) => n.type === 'ClassDeclaration' && n.id?.name === name, name));
  }
  varInit(name) {
    const d = this.unique((n) => n.type === 'VariableDeclarator' && n.id?.name === name, name);
    return this.textOf(d.init);
  }
  hookCallback(name, hook) {
    const d = this.unique((n) => n.type === 'VariableDeclarator' && n.id?.name === name, name);
    if (d.init?.type !== 'CallExpression' || d.init.callee?.name !== hook) throw new Error(`${name}: not ${hook}`);
    return this.textOf(d.init.arguments[0]);
  }
  resolveSpecifier(spec) {
    if (!spec.startsWith('.')) return spec;
    const base = path.resolve(path.dirname(this.file), spec);
    for (const candidate of [base, `${base}.js`, `${base}.mjs`, path.join(base, 'index.js')]) {
      if (existsSync(candidate) && !candidate.endsWith('/')) {
        try { if (readFileSync(candidate)) return pathToFileURL(candidate).href; } catch { /* dir */ }
      }
    }
    throw new Error(`cannot resolve ${spec} from ${this.file}`);
  }
  async importBinding(name) {
    const info = this.imports.get(name);
    if (!info) return { found: false };
    const mod = await import(this.resolveSpecifier(info.source));
    if (info.imported === '*') return { found: true, value: mod };
    if (!(info.imported in mod)) throw new Error(`${name}: ${info.imported} not exported by ${info.source}`);
    return { found: true, value: mod[info.imported] };
  }
}

// Evaluate `code` (an expression or a block returning a value) with all free
// identifiers resolved: overrides first, then imports of `mod`.
export async function bindCode(mod, code, overrides = {}, { wrapExpression = true } = {}) {
  const probe = wrapExpression ? `const __x = (${code});` : `function __wrap(){${code}}`;
  const free = freeIdentifiers(probe);
  const names = [];
  const values = [];
  const missing = [];
  for (const name of free) {
    if (Object.prototype.hasOwnProperty.call(overrides, name)) { names.push(name); values.push(overrides[name]); continue; }
    if (GLOBALS.has(name)) continue;
    const imported = await mod.importBinding(name);
    if (imported.found) { names.push(name); values.push(imported.value); continue; }
    missing.push(name);
  }
  if (missing.length) throw new Error(`unbound identifiers in ${mod.file}: ${missing.join(', ')}`);
  const body = wrapExpression ? `'use strict'; return (${code});` : `'use strict'; ${code}`;
  return Function(...names, body)(...values);
}

const mutationArg = process.argv.find((arg) => arg.startsWith('--mutation='));
if (mutationArg) {
  const relay = 'chatgame-tools/vendor/src/utils/relay.js';
  const protocol = 'chatgame-tools/vendor/workers/game_workers/lib/protocol-v2.js';
  const compact = 'chatgame-tools/vendor/workers/game_workers/lib/evidence-compact-v1.js';
  const mutants = {
    'rs-queue-eligible': [relay, [["if (Array.isArray(receipt.msgRefs) && entry.status === 'eligible') {",
      "if (false && Array.isArray(receipt.msgRefs) && entry.status === 'eligible') {"]], /both real signed reads accepted/],
    'rs-admit-first-arrival': [protocol, [["// 宣言窓外は既存の第2階層でだけ運ぶ。\n    accepted.push(rc);",
      "// 宣言窓外は既存の第2階層でだけ運ぶ。\n    if (accepted.some((old) => old.receiverUid === rc.receiverUid && old.msgRefs?.some((ref) => rc.msgRefs.includes(ref)))) continue;\n    accepted.push(rc);"]], /rs-accept-all|both real signed reads accepted/],
    'rs-display-clash': [protocol, [["// S3R4-U-DUPGATE: 受け入れた既読は包含・一部重複にかかわらず全部数える。\n      for (const ref of rc.msgRefs) {",
      "// S3R4-U-DUPGATE: 受け入れた既読は包含・一部重複にかかわらず全部数える。\n      if (rc.msgRefs.some((ref) => readersByMsgKey[ref]?.has(rc.receiverUid))) continue;\n      for (const ref of rc.msgRefs) {"]], /all overlapping atoms shown|rs-display-all/],
    'rs-agg-clash': [compact, [["      legacyEntries.push(normalized);\n      continue;",
      "      if (!legacyEntries.some((old) => old.receiverUid === normalized.receiverUid && old.msgRefs?.some((ref) => normalized.msgRefs?.includes(ref)))) legacyEntries.push(normalized);\n      continue;"]], /rs-carry-all aggregate preserves both/],
    'rs-no-fact-limit': [compact, [["if (total <= MAX_RECEIPT_FACTS && legacy.length <= MAX_RECEIPT_OBJECTS) return snapshot;",
      "if (total <= MAX_RECEIPT_FACTS && legacy.length <= MAX_RECEIPT_OBJECTS) return snapshot;\n  return snapshot;"]], /rs-chain-flood|receipt facts exceed/],
    'rs-limit-global-order': [compact, [["const share = Math.floor(budget / byIssuer.size);", "const share = budget;\n  let globalUsed = 0;"],
      ["    let used = actions.length;", "    let used = globalUsed + actions.length;"],
      ["    }\n  }\n  const receipts = legacy.filter", "    }\n    globalUsed = used;\n  }\n  const receipts = legacy.filter"]], /earlier attacker floods cannot consume the honest issuer share/],
    'rs-limit-drops-actions': [compact, [["for (const receipt of actions) kept.add(receipt);",
      "for (const receipt of actions) { /* action receipt dropped */ }"]], /rs-vote-kept action carried/],
    'rs-limit-always': [compact, [["if (total <= MAX_RECEIPT_FACTS && legacy.length <= MAX_RECEIPT_OBJECTS) return snapshot;",
      "if (false && total <= MAX_RECEIPT_FACTS && legacy.length <= MAX_RECEIPT_OBJECTS) return snapshot;"]], /rs-honest-max keeps snapshot identity/],
    'rs-atomic-off': [protocol, [["const claimOptions = { ...opts, atomic: true };",
      "const claimOptions = { ...opts, atomic: false };"]], /one stale ref excludes the whole signed receipt/],
    'rs-limit-no-owncover-first': [[compact, 'workers/game_workers/lib/evidence-compact-v1.js'], [[
      "const ordered = [\n      ...reads.filter((receipt) => receipt.senderUid === submitterUid).sort(cmp),\n      ...reads.filter((receipt) => receipt.senderUid !== submitterUid).sort(cmp),\n    ];",
      "const ordered = [...reads].sort(cmp);",
    ]], /rs-own-cover-pushout: V cover 25/],
  };
  const requested = mutationArg.slice('--mutation='.length);
  const part = process.argv.find((arg) => arg.startsWith('--part='))?.slice(7) || '1/1';
  const [partNo, partTotal] = part.split('/').map(Number);
  assert(Number.isSafeInteger(partNo) && Number.isSafeInteger(partTotal)
    && partNo >= 1 && partNo <= partTotal);
  const ids = requested === 'all' ? Object.keys(mutants).filter((_, i) => i % partTotal === partNo - 1) : [requested];
  const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
  assert(process.env.TEST_SCRATCH_ROOT, 'mutation requires TEST_SCRATCH_ROOT');
  const scratch = path.resolve(process.env.TEST_SCRATCH_ROOT);
  assert(scratch.startsWith(path.join(root, 'tmp') + path.sep), 'mutation scratch is isolated');
  mkdirSync(scratch, { recursive: true });
  for (const id of ids) {
    assert(mutants[id], `known mutation ${id}`);
    const tree = mkdtempSync(path.join(scratch, `${id}-`));
    try {
      for (const dir of ['src', 'workers/game_workers/lib', 'chatgame-tools/src', 'chatgame-tools/vendor']) {
        const destination = path.join(tree, dir);
        mkdirSync(path.dirname(destination), { recursive: true });
        cpSync(path.join(root, dir), destination, { recursive: true });
      }
      mkdirSync(path.join(tree, 'chatgame-tools/test'), { recursive: true });
      for (const file of ['rs-receipt-carry-unit.mjs', 'scenario.mjs']) {
        cpSync(path.join(root, 'chatgame-tools/test', file), path.join(tree, 'chatgame-tools/test', file));
      }
      cpSync(path.join(root, 'chatgame-tools/config.js'), path.join(tree, 'chatgame-tools/config.js'));
      const [file, edits, expected] = mutants[id];
      for (const copy of Array.isArray(file) ? file : [file]) {
        const target = path.join(tree, copy);
        let content = readFileSync(target, 'utf8');
        for (const [before, after] of edits) {
          assert.equal(content.split(before).length - 1, 1, `${id}: unique mutation site`);
          content = content.replace(before, after);
        }
        writeFileSync(target, content);
      }
      const child = spawnSync(process.execPath, [path.join(tree, 'chatgame-tools/test/rs-receipt-carry-unit.mjs')], {
        cwd: root, timeout: 60_000, encoding: 'utf8', env: { ...process.env, RS_BASE_ROOT: '' },
      });
      assert.equal(child.error, undefined, `${id}: child spawn`);
      assert.equal(child.signal, null, `${id}: child signal`);
      assert.notEqual(child.status, 0, `${id}: mutant must fail`);
      assert.match(`${child.stdout}\n${child.stderr}`, expected, `${id}: expected behavior detected`);
      if (id === 'rs-limit-no-owncover-first') {
        console.log(child.stdout.split('\n').find((line) => line.startsWith('rs-own-cover-pushout: recovery=')));
      }
      console.log(`${id}: killed by ${expected}`);
    } finally { rmSync(tree, { recursive: true, force: true }); }
  }
  console.log(`rs-receipt-carry-unit: ${ids.length} mutations killed`);
  process.exit(0);
}

const sc = await buildScenario();
const [A, V, S, B] = sc.players;
const p2 = V;
const getRef = (message) => msgRefOf(computeMsgKeyV2(sc.blockNum, sc.groupId, message));
const makeMessage = async (player, text, timestamp) => ({
  type: 'chat', blockNum: sc.blockNum, groupId: sc.groupId, uid: player.uid, text, timestamp,
  signature: canonicalizeSignature(await player.signAccount.signMessage({
    message: chatSignStringV2(sc.blockNum, sc.groupId, player.uid, text, timestamp),
  })),
});
const messages = [...sc.sharedMessages];
for (let i = 0; i < 8; i++) {
  messages.push(await makeMessage(A, `extra A ${i} `.padEnd(60, 'a'), sc.base + 560_000 + 20_000 * i));
  messages.push(await makeMessage(V, `extra V ${i} `.padEnd(60, 'v'), sc.base + 570_000 + 20_000 * i));
}
const vMessages = messages.filter((item) => item.uid === V.uid);
assert.equal(vMessages.length, 22);
const refs = vMessages.map(getRef);
const makeRead = async (issuer, senderUid, readRefs, timestamp) => {
  const msgRefs = [...readRefs].sort(compareHexAsc);
  return { receiverUid: issuer.uid, senderUid, msgRefs, timestamp,
    signature: canonicalizeSignature(await issuer.signAccount.signMessage({
      message: readReceiptSignString(sc.blockNum, sc.groupId, issuer.uid, senderUid, msgRefs, timestamp),
    })) };
};
const L = await makeRead(A, V.uid, refs.slice(0, 2), sc.base + 550_000);
const P1 = await makeRead(A, V.uid, refs.slice(1, 4), sc.base + 550_100);
const otherReads = [];
for (let i = 4; i < refs.length; i++) otherReads.push(await makeRead(A, V.uid, [refs[i]],
  sc.base + (i < 14 ? 550_000 : 650_000)));
const extraAReads = [];
for (const message of messages.filter((item) => item.uid === A.uid && item.timestamp >= sc.base + 560_000)) {
  extraAReads.push(await makeRead(V, A.uid, [getRef(message)], sc.base + 650_000));
}
const background = sc.allReceipts.filter((receipt) => !(receipt.receiverUid === A.uid && receipt.senderUid === V.uid));
const overlapReceipts = [...background, ...extraAReads, ...otherReads, L, P1];
const chatWindow = { startMs: sc.base, endMs: sc.base + 1_200_000 };
const targets = buildRealTargets({}, messages, sc.blockNum, sc.groupId);
const readerOf = (receipt) => sc.players.find((player) => player.uid === receipt.receiverUid);
async function verifiedQueue(order) {
  const accepted = [], removed = [];
  const queue = new ReceiptAdmissionQueue({
    getRosterUids: () => sc.members.map((member) => member.uid), isRosterVerified: () => true,
    getChatWindow: () => chatWindow, getSelectionContext: () => ({ myUid: V.uid }),
    verifyReceipt: async (receipt) => verifyMessage({
      address: readerOf(receipt).signAccount.address,
      message: readReceiptSignString(sc.blockNum, sc.groupId, receipt.receiverUid,
        receipt.senderUid, receipt.msgRefs, receipt.timestamp), signature: receipt.signature,
    }),
    resolveReceipt: (receipt) => {
      const claim = receiptCoverClaim(receipt, targets, {
        chatWindow, memberUids: sc.members.map((member) => member.uid), selfUid: V.uid, atomic: true,
      });
      return claim.keys.length ? { state: 'covered', facts: claim.keys, priority: 'F' } : { state: 'invalid' };
    },
    onAccept: (receipt) => accepted.push(receipt.signature),
    onRemove: (receipt, reason) => removed.push([receipt.signature, reason]),
  });
  for (const receipt of order) await queue.offer(receipt);
  const retained = queue.getAcceptedReceipts().map((receipt) => receipt.signature);
  queue.dispose();
  return { accepted, retained, removed };
}
function label(name, detail) { console.log(`${name}: ${detail}`); }

// The official callback is evaluated from SubmissionPhase.js with its real imports.
// The source extractor rejects unbound names, so this exercises the same submission
// assembly as the page instead of reimplementing its receipt selection here.
async function submitWithOfficialHandle(board, receipts, actions) {
  const source = new SourceModule(fileURLToPath(new URL('../../src/components/game/SubmissionPhase.js', import.meta.url)));
  const { player, members, blockNum, groupId, chatWindow, messages, base } = board;
  const myUid = player.uid;
  const now = base + 45 * 60_000;
  const chainTimeline = { chatOpenAt: chatWindow.startMs, chatCloseAt: chatWindow.endMs - 120_000,
    resultOpenAt: chatWindow.endMs - 120_000, resultCloseAt: now + 3_600_000 };
  const myMember = members.find((member) => member.uid === myUid);
  const storage = new Map([[`actionIntent_${blockNum}_user${myUid}`, JSON.stringify(actions.intent)]]);
  const localStorage = { getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)) };
  const top = {
    RUN_ERROR: await bindCode(source, source.varInit('RUN_ERROR')),
    runError: await bindCode(source, source.fnDecl('runError')),
    isGameIdentityCallbackCurrent: await bindCode(source, source.fnDecl('isGameIdentityCallbackCurrent')),
    walletClientAddress: await bindCode(source, source.fnDecl('walletClientAddress')),
    clientNow: () => now,
    separatorPoint,
  };
  top.assertSubmissionRunCurrent = await bindCode(source, source.fnDecl('assertSubmissionRunCurrent'), top);
  top.assertSubmissionWalletCurrent = await bindCode(source, source.fnDecl('assertSubmissionWalletCurrent'), top);
  top.whitelistReceiptsForSubmission = await bindCode(source, source.varInit('whitelistReceiptsForSubmission'));
  const memoBindings = { messages, blockNum, groupId, myUid, receipts, chainTimeline,
    confirmedChatWindow: chatWindow, myMember, submissionClaimMemoRef: { current: { identity: 'x', memo: null } },
    console: { error() {}, log() {}, warn() {} }, getClientMsgKey: null };
  const cappedMessages = (await bindCode(source, source.hookCallback('cappedMessages', 'useMemo'), memoBindings))();
  const chatHash = (await bindCode(source, source.hookCallback('chatHash', 'useMemo'),
    { ...memoBindings, cappedMessages }))();
  const myDepositIds = (await bindCode(source, source.hookCallback('myDepositIds', 'useMemo'), memoBindings))();
  const sent = [];
  let error = null;
  const identityCheck = () => true;
  const walletClient = { account: player.wallet,
    signMessage: ({ message }) => player.wallet.signMessage({ message }) };
  const submissionBindings = {
    ...top, signKey: player.signKey, encryptKey: player.encryptKey, connectedAddress: player.addr,
    walletClient, getWalletClient: async () => walletClient, config: {},
    blockNum, groupId, myUid, isGameIdentityCurrent: identityCheck,
    submitInFlightRef: { current: null }, componentLifetimeRef: { current: Symbol('rs') },
    latestIdentityCheckRef: { current: identityCheck }, registeredAddress: player.addr,
    myVote: actions.myVote, myReports: [], myReportGrounds: {}, members, messages, cappedMessages, chatHash,
    priorityLock: null, rosterOperatorUsed: false,
    myDepositIds, observedActions: actions.observedActions, receipts, chainTimeline,
    confirmedChatWindow: chatWindow, hiddenMessageKeys: null, shownMessageKeys: null,
    resolvePressFieldWindow: async () => ({ kind: 'current' }),
    sendSubmission: (payload) => { sent.push(payload); return true; },
    setIsSubmitting() {}, setError: (value) => { error = value; }, setEvidencePayloadExists() {},
    setServerSendTried() {}, // 2026-11-19（反証 D-2）: サーバーへ送る直前に立てる「送った」印の setter
    localStorage, t: (key, fallback) => fallback || key,
    console: { log() {}, warn() {}, error() {} }, Date: { now: () => now },
  };
  submissionBindings.assembleSubmission = await bindCode(source,
    source.hookCallback('assembleSubmission', 'useCallback'), submissionBindings);
  submissionBindings.encodeSubmission = await bindCode(source,
    source.hookCallback('encodeSubmission', 'useCallback'), submissionBindings);
  const callback = await bindCode(source, source.hookCallback('handleSubmit', 'useCallback'), submissionBindings);
  const hadStorage = Object.prototype.hasOwnProperty.call(globalThis, 'localStorage');
  const previousStorage = globalThis.localStorage;
  globalThis.localStorage = localStorage;
  try { await callback(); } finally {
    if (hadStorage) globalThis.localStorage = previousStorage;
    else delete globalThis.localStorage;
  }
  assert.equal(error, null, `official handleSubmit: ${error}`);
  assert.equal(sent.length, 1, 'official handleSubmit sends exactly one payload');
  return decodeSubmissionPayloadString(sent[0]).bundle;
}
for (const order of [[L, P1], [P1, L]]) {
  const queue = await verifiedQueue(order);
  const recovered = admitReadReceiptsByArrival(order, targets, {
    selfUid: V.uid, chatWindow, memberUids: sc.members.map((member) => member.uid),
  });
  assert.deepEqual(new Set(queue.retained), new Set([L.signature, P1.signature]), 'both real signed reads accepted');
  assert.deepEqual(new Set(recovered.map((receipt) => receipt.signature)), new Set([L.signature, P1.signature]),
    'rs-accept-all recovery keeps both real signed reads');
  assert.equal(queue.removed.filter((row) => row[1] === 'reselected').length, 0);
  label('rs-accept-all', `order=${order.map((rc) => rc === L ? 'L' : 'P1').join('>')} accepted=${queue.retained.length}`);
}
const maps = buildReceiptMaps([L, P1], { messages, myUid: V.uid }, sc.blockNum, sc.groupId, chatWindow);
for (const ref of refs.slice(0, 4)) assert(maps.readersByMsgKey[ref]?.has(A.uid), 'all overlapping atoms shown');
const scoredMessages = clientScoreableMessages(messages, overlapReceipts, {
  blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid, chatWindow, caps: GUEST_PINNED_RULES,
});
assert.equal(scoredMessages.filter((message) => message.uid === V.uid).length, 22);
const screenTurns = countMessageTurns(filterVisibleMessages(scoredMessages))[V.uid] || 0;
const recoverySource = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const progressStart = recoverySource.indexOf('function myReceiptedChatProgress(');
const progressEnd = recoverySource.indexOf('\nlet recoveryPriorityLock', progressStart);
assert(progressStart >= 0 && progressEnd > progressStart);
const progressMaps = buildReceiptMaps(overlapReceipts, { messages, myUid: V.uid },
  sc.blockNum, sc.groupId, chatWindow);
const recoveryProgress = new Function('readersByMsgKey', 'locallyProvableMessages', 'state',
  'msgRefOf', 'computeMsgKeyV2', 'isTimestampVisible', 'countVisibleChars',
  'countMessageTurns', 'filterVisibleMessages', 'clientNow',
  `return (${recoverySource.slice(progressStart, progressEnd)});`)(
  () => progressMaps.readersByMsgKey, () => scoredMessages,
  { blockNum: sc.blockNum, groupId: sc.groupId, uid: V.uid },
  msgRefOf, computeMsgKeyV2, (timestamp, now) => timestamp < now,
  countVisibleChars, countMessageTurns, filterVisibleMessages, () => sc.base + 3_000_000);
const progress = recoveryProgress(messages, sc.base + 3_000_000);
assert.equal(progress.turns, screenTurns,
  'rs-display-all recovery myReceiptedChatProgress counts both overlapping receipts');
label('rs-display-all', `refs=4 V-messages=${scoredMessages.filter((message) => message.uid === V.uid).length} turns=${screenTurns}`);
const build = (receipts, givenMessages = messages) => sc.makeP2Recovery({ receipts, messages: givenMessages });
const overlap = await build(overlapReceipts);
const carried = overlap.snapshotData.observed.receipts;
assert(carried.some((receipt) => receipt.signature === L.signature), 'rs-carry-all L carried');
assert(carried.some((receipt) => receipt.signature === P1.signature), 'rs-carry-all P1 carried');
const legacyOverlap = await aggregateSelfReceipts([L, P1], V.uid, sc.blockNum, sc.groupId,
  async () => { throw new Error('no self aggregate expected'); });
assert.equal(legacyOverlap.receipts.length, 2, 'rs-carry-all aggregate preserves both other-issued overlapping legacy receipts');
const structure = validateSubmissionStructure(overlap.bundle, {
  blockNum: sc.blockNum, groupId: sc.groupId, memberUids: sc.members.map((member) => member.uid),
});
assert.equal(structure.ok, true, structure.reason);
encodeEvidenceCompactV1(overlap.bundle, {
  blockNum: sc.blockNum, groupId: sc.groupId, memberUids: sc.members.map((member) => member.uid),
});
const checked = await validateResultBundle(overlap.payload, sc.blockNum,
  buildMembersIndex([{ group_id: sc.groupId, members: sc.members }]), V.addr);
assert.equal(checked.valid, true, checked.reason);
const scoreBundle = async (bundle, minMessages = 20, members = sc.members) => {
  const submissions = await sc.allSubmissions();
  submissions[V.uid] = bundle;
  for (const uid of Object.keys(submissions)) if (!members.some((member) => member.uid === uid)) delete submissions[uid];
  const result = await calculateGroupResults({ members, submissions,
    meta: { blockNum: sc.blockNum, groupId: sc.groupId } }, 500, minMessages, GUEST_PINNED_RULES, chatWindow);
  return result.results.find((row) => row.uid === V.uid);
};
const score = await scoreBundle(overlap.bundle);
assert(!score.isDisqualified, JSON.stringify(score.disqualifyReasons));
label('rs-carry-all', `legacy=${carried.length} L=true P1=true gate=${structure.ok} valid=${checked.valid} score=${score.scoreableTurns ?? score.chatTurns ?? '?'} dq=${score.isDisqualified}`);

const G2early = await makeRead(A, V.uid, refs.slice(0, 2), sc.base + 548_000);
const G1late = await makeRead(A, V.uid, refs.slice(0, 1), sc.base + 549_000);
const supersetFirst = await build([...background, ...extraAReads, ...otherReads, G1late, G2early]);
assert(supersetFirst.snapshotData.observed.receipts.some((receipt) => receipt.signature === G2early.signature));
assert(!supersetFirst.snapshotData.observed.receipts.some((receipt) => receipt.signature === G1late.signature),
  'addsNew omits an already covered subset');
const G1early = await makeRead(A, V.uid, refs.slice(0, 1), sc.base + 548_000);
const G2late = await makeRead(A, V.uid, refs.slice(0, 2), sc.base + 549_000);
const subsetFirst = await build([...background, ...extraAReads, ...otherReads, G2late, G1early]);
assert(subsetFirst.snapshotData.observed.receipts.some((receipt) => receipt.signature === G1early.signature));
assert(subsetFirst.snapshotData.observed.receipts.some((receipt) => receipt.signature === G2late.signature));
label('rs-carry-all', 'containment: superset first carries 1; subset first carries 2');

const stale = await makeRead(A, V.uid, [refs[0], refs.at(-1)], sc.base + 1_180_000);
assert.equal(admitReadReceiptsByArrival([stale], targets, {
  selfUid: V.uid, chatWindow, memberUids: sc.members.map((member) => member.uid),
}).length, 0, 'one stale ref excludes the whole signed receipt');
label('rs-stale-ref', 'atomic exclusion retained');

// Same logical inputs must give identical payload bytes on the old and new honest path.
const baseRoot = process.env.RS_BASE_ROOT;
if (baseRoot) {
  const oldBuild = (await import(new URL(`file://${baseRoot}/chatgame-tools/src/recovery/bundle.js`))).buildSubmissionBundle;
  const oldProtocol = await import(new URL(`file://${baseRoot}/chatgame-tools/vendor/workers/game_workers/lib/protocol-v2.js`));
  const [p1, p2, p3, p4] = sc.players;
  const argsFor = (givenMessages, receipts) => ({ blockNum: sc.blockNum, groupId: sc.groupId, myUid: p2.uid,
    encryptKey: p2.encryptKey, members: sc.members, messages: givenMessages,
    myDepositIds: JSON.parse(p2.depIds).ids, myVote: sc.votes[p2.uid], myVotePrev: [], myReports: [],
    observedActions: { votes: { [p1.uid]: sc.votes[p1.uid], [p3.uid]: sc.votes[p3.uid], [p4.uid]: sc.votes[p4.uid] }, reports: {} },
    receipts, intent: { vote: p1.uid, reports: [] }, submittedAt: sc.base + 999999,
    signWallet: async (message) => p2.wallet.signMessage({ message }),
  });
  const args = argsFor(sc.sharedMessages, sc.allReceipts);
  const older = await oldBuild(args);
  const newer = await buildSubmissionBundle(args);
  assert.equal(newer.payload, older.payload, 'honest payload byte identity');
  label('rs-base-bytes', `honest payload bytes=${newer.payload.length} identical=true`);
  const fifthHonest = await makePlayer('user0005', 4, 0.5, sc.blockNum);
  const shuffle = (rows, seed) => {
    const out = [...rows]; let value = seed;
    for (let i = out.length - 1; i > 0; i--) {
      value = (Math.imul(value, 1664525) + 1013904223) >>> 0;
      const j = value % (i + 1);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
  };
  for (let seed = 1; seed <= 20; seed++) {
    const count = 3 + (seed % 3);
    const chosen = count === 5 ? [...sc.members, { uid: fifthHonest.uid,
      addr: fifthHonest.addr, bAddr: fifthHonest.bAddrString, depIds: fifthHonest.depIds }]
      : sc.members.slice(0, count);
    const uids = new Set(chosen.map((member) => member.uid));
    const boardMessages = shuffle(sc.sharedMessages.filter((message) => uids.has(message.uid)), seed);
    const boardReceipts = shuffle(sc.allReceipts.filter((receipt) =>
      uids.has(receipt.receiverUid) && (!receipt.senderUid || uids.has(receipt.senderUid))), seed * 31);
    const boardArgs = { ...argsFor(boardMessages, boardReceipts), members: chosen,
      observedActions: { votes: Object.fromEntries(Object.entries(sc.votes)
        .filter(([actor]) => actor !== V.uid && uids.has(actor))), reports: {} } };
    const oldBoard = await oldBuild(boardArgs);
    const newBoard = await buildSubmissionBundle(boardArgs);
    assert.equal(newBoard.payload, oldBoard.payload, `rs-base-bytes seed=${seed} full payload`);
    const displayOpts = { blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid,
      chatWindow, caps: GUEST_PINNED_RULES };
    const oldDisplay = oldProtocol.clientScoreableMessages(boardMessages, boardReceipts, displayOpts);
    const newDisplay = clientScoreableMessages(boardMessages, boardReceipts, displayOpts);
    assert.equal(JSON.stringify(newDisplay), JSON.stringify(oldDisplay), `rs-base-bytes seed=${seed} screen`);
    label('rs-base-bytes', `seed=${seed} members=${count} payloadBytes=${newBoard.payload.length} display=${newDisplay.length}`);
  }
  // P2a-1 makePattern's honest alternating partner/owner shape (20 rounds).
  const patternMessages = [], patternReceipts = [];
  for (let round = 0; round < 20; round++) {
    const at = sc.base + 10_000 + round * 50_000;
    const partner = await makeMessage(A, `reply ${round}`, at);
    const own = await makeMessage(V, `victim ${round}`.padEnd(40, 'v'), at + 6_000);
    patternMessages.push(partner, own);
    patternReceipts.push(await makeRead(V, A.uid, [getRef(partner)], at + 2_000));
    patternReceipts.push(await makeRead(S, A.uid, [getRef(partner)], at + 2_500));
    patternReceipts.push(await makeRead(A, V.uid, [getRef(own)], at + 9_000));
  }
  const patternWindow = { startMs: sc.base, endMs: sc.base + 1_100_000 };
  const patternMembers = sc.members.slice(0, 3);
  const patternArgs = { ...argsFor(patternMessages, patternReceipts), members: patternMembers,
    chatWindow: patternWindow,
    observedActions: { votes: { [A.uid]: sc.votes[A.uid], [S.uid]: sc.votes[S.uid] }, reports: {} },
    signReceiptAggregate: (message) => V.signAccount.signMessage({ message }),
  };
  const oldPattern = await oldBuild(patternArgs);
  const newPattern = await buildSubmissionBundle(patternArgs);
  assert.equal(newPattern.payload, oldPattern.payload, 'rs-base-bytes P2a-1 makePattern honest full payload');
  const patternOpts = { blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid,
    chatWindow: patternWindow, caps: GUEST_PINNED_RULES };
  assert.equal(JSON.stringify(clientScoreableMessages(patternMessages, patternReceipts, patternOpts)),
    JSON.stringify(oldProtocol.clientScoreableMessages(patternMessages, patternReceipts, patternOpts)),
    'rs-base-bytes P2a-1 makePattern honest screen');
  label('rs-base-bytes', `P2a-1 honest pattern rounds=20 payloadBytes=${newPattern.payload.length} identical=true`);
  const oldOverlap = await oldBuild(argsFor(messages, overlapReceipts));
  const oldScore = await scoreBundle(oldOverlap.bundle);
  assert(!score.isDisqualified && (oldScore.isDisqualified || score.totalPoints >= oldScore.totalPoints),
    'partially overlapping receipt does not lower the submitter score');
  label('rs-carry-all', `basePoints=${oldScore.totalPoints} newPoints=${score.totalPoints} baseDQ=${oldScore.isDisqualified}`);
  const duplicateEarlier = await makeRead(A, V.uid, refs.slice(0, 2), sc.base + 549_000);
  const reissued = [...background, ...extraAReads, ...otherReads, L, duplicateEarlier];
  const before = await oldBuild(argsFor(messages, reissued));
  const after = await buildSubmissionBundle(argsFor(messages, reissued));
  assert.equal(after.payload, before.payload, 'same-group reissue keeps earliest canonical receipt byte for byte');
  label('rs-reissue', `payloadBytes=${after.payload.length} identical=true`);
}

// The pure limiter must preserve honest snapshots by reference and isolate a flooder's budget.
{
  const plain = { observed: { receipts: overlapReceipts } };
  assert.strictEqual(limitCarriedReceiptFacts(plain, { submitterUid: V.uid, compare: receiptCanonCmp }), plain,
    'rs-honest-max keeps snapshot identity before and at the bound');
  const floodRefs = Array.from({ length: 100 }, (_, i) => `0x${i.toString(16).padStart(32, '0')}`);
  const chain = [];
  for (let i = 1; i <= 100; i++) chain.push(await makeRead(A, S.uid, floodRefs.slice(0, i), sc.base + 550_000 + i));
  const honestB = await makeRead(B, V.uid, [refs[0]], sc.base + 550_000);
  const ownAction = sc.allReceipts.find((receipt) => receipt.receiverUid === V.uid && receipt.actionHash);
  const all = [...chain, honestB, ownAction];
  const snapshot = { observed: { receipts: all, selfReceiptAggregate: { entries: Array.from({length: 40}, (_, i) => ({ i })) } } };
  const limited = limitCarriedReceiptFacts(snapshot, { submitterUid: V.uid, compare: receiptCanonCmp });
  const legacy = limited.observed.receipts;
  const raw = legacy.reduce((n, receipt) => n + (receipt.msgRefs?.length || 1), 40);
  assert(raw <= 2400 && legacy.length <= 2400, 'rs-chain-flood raw facts stay within gate');
  assert(legacy.some((receipt) => receipt.signature === honestB.signature));
  assert(legacy.some((receipt) => receipt.signature === ownAction.signature), 'rs-vote-kept action carried');
  assert.equal(limited.observed.selfReceiptAggregate, snapshot.observed.selfReceiptAggregate);
  assert(legacy.filter((receipt) => chain.includes(receipt)).length < 100);
  assert.deepEqual(snapshot.observed.receipts, all, 'pure limiter does not mutate input');
  label('rs-chain-flood', `before=5052 after=${raw} chainKept=${legacy.filter((receipt) => chain.includes(receipt)).length}`);

  const secondFlood = [];
  for (let i = 1; i <= 100; i++) secondFlood.push(await makeRead(B, V.uid,
    floodRefs.slice(0, i), sc.base + 540_000 + i));
  const honestIssuer = [];
  for (const sender of [A, V, B]) for (let i = 0; i < 100; i++) {
    honestIssuer.push(await makeRead(S, sender.uid,
      [`0x${(1000 + i).toString(16).padStart(32, '0')}`], sc.base + 560_000 + i));
  }
  const cross = limitCarriedReceiptFacts({ observed: { receipts: [
    ...chain, ...secondFlood, ...honestIssuer,
  ], selfReceiptAggregate: snapshot.observed.selfReceiptAggregate } }, {
    submitterUid: V.uid, compare: receiptCanonCmp,
  });
  const crossSigs = new Set(cross.observed.receipts.map((receipt) => receipt.signature));
  assert(honestIssuer.every((receipt) => crossSigs.has(receipt.signature)),
    'earlier attacker floods cannot consume the honest issuer share');
  const crossFacts = cross.observed.receipts.reduce((n, receipt) => n + (receipt.msgRefs?.length || 1), 40);
  assert(crossFacts <= 2400);
  label('rs-cross-issuer', `flooders=2 honest=${honestIssuer.length}/${honestIssuer.length} facts=${crossFacts}`);

  const fifth = await makePlayer('user0005', 4, 0.5, sc.blockNum);
  const five = [A, V, S, B, fifth];
  const maxReceipts = [];
  for (const issuer of five.filter((player) => player.uid !== V.uid)) {
    for (const sender of five.filter((player) => player.uid !== issuer.uid)) {
      maxReceipts.push(await makeRead(issuer, sender.uid,
        Array.from({ length: 100 }, (_, index) => `0x${(index + 10_000).toString(16).padStart(32, '0')}`),
        sc.base + 550_000));
    }
    for (let i = 0; i < 80; i++) {
      const actionHash = `0x${(10_000 + five.indexOf(issuer) * 80 + i).toString(16).padStart(64, '0')}`;
      const timestamp = sc.base + 550_000 + i;
      maxReceipts.push({ receiverUid: issuer.uid, actionHash, timestamp,
        signature: canonicalizeSignature(await issuer.signAccount.signMessage({ message: receiptSignString(
          sc.blockNum, sc.groupId, issuer.uid, actionHash, timestamp,
        ) })) });
    }
  }
  const maxSnapshot = { observed: { receipts: maxReceipts,
    selfReceiptAggregate: { entries: Array.from({ length: 480 }, (_, i) => ({ i })) } } };
  const maxRaw = maxReceipts.reduce((n, receipt) => n + (receipt.msgRefs?.length || 1), 480);
  assert.equal(maxRaw, 2400);
  assert.strictEqual(limitCarriedReceiptFacts(maxSnapshot, { submitterUid: V.uid,
    compare: receiptCanonCmp }), maxSnapshot, 'rs-honest-max keeps snapshot identity');
  label('rs-honest-max', `players=5 rawFacts=${maxRaw} identity=true`);

  const floodMessages = [...messages];
  for (let i = 0; i < 86; i++) floodMessages.push(await makeMessage(S,
    `flood S ${i} `.padEnd(60, 's'), sc.base + 710_000 + i * 4_000));
  const actualRefs = floodMessages.filter((message) => message.uid === S.uid).map(getRef).sort(compareHexAsc);
  assert.equal(actualRefs.length, 100);
  const signedChain = [];
  for (let i = 1; i <= 100; i++) signedChain.push(await makeRead(A, S.uid,
    actualRefs.slice(0, i), sc.base + 550_000 + i));
  const controlReceipts = overlapReceipts.filter((receipt) => !(receipt.receiverUid === A.uid && receipt.senderUid === S.uid));
  const floodReceipts = [...controlReceipts, ...signedChain];
  const floodBundle = await build(floodReceipts, floodMessages);
  const floodStructure = validateSubmissionStructure(floodBundle.bundle, {
    blockNum: sc.blockNum, groupId: sc.groupId, memberUids: sc.members.map((member) => member.uid),
  });
  assert.equal(floodStructure.ok, true, floodStructure.reason);
  const floodCheck = await validateResultBundle(floodBundle.payload, sc.blockNum,
    buildMembersIndex([{ group_id: sc.groupId, members: sc.members }]), V.addr);
  assert.equal(floodCheck.valid, true, floodCheck.reason);
  const carriedFlood = floodBundle.snapshotData.observed.receipts;
  const floodFacts = carriedFlood.reduce((n, receipt) => n + (receipt.msgRefs?.length || 1),
    floodBundle.snapshotData.observed.selfReceiptAggregate?.entries?.length || 0);
  assert(floodFacts <= 2400);
  const controlBundle = await build(controlReceipts, floodMessages);
  const controlSignatures = new Set(controlBundle.snapshotData.observed.receipts.map((receipt) => receipt.signature));
  for (const receipt of controlReceipts.filter((row) => row.receiverUid !== A.uid || row.actionHash)) {
    if (controlSignatures.has(receipt.signature)) assert(carriedFlood.some((row) => row.signature === receipt.signature),
      'flood cannot evict another issuer or an action receipt');
  }
  const floodScore = await scoreBundle(floodBundle.bundle);
  const controlScore = await scoreBundle(controlBundle.bundle);
  const threeMembers = sc.members.slice(0, 3);
  const threeUids = new Set(threeMembers.map((member) => member.uid));
  const threeMessages = floodMessages.filter((message) => threeUids.has(message.uid));
  const threeControlReceipts = controlReceipts.filter((receipt) => threeUids.has(receipt.receiverUid)
    && (!receipt.senderUid || threeUids.has(receipt.senderUid)));
  threeControlReceipts.push(await sc.makeActionReceipt(A, S.uid, 'vote', sc.votes[S.uid], sc.base + 500_100));
  const threeFloodReceipts = [...threeControlReceipts, ...signedChain];
  const buildThree = (player, receipts) => buildSubmissionBundle({
    blockNum: sc.blockNum, groupId: sc.groupId, myUid: player.uid,
    encryptKey: player.encryptKey, members: threeMembers, messages: threeMessages,
    myDepositIds: JSON.parse(player.depIds).ids, myVote: sc.votes[player.uid], myVotePrev: [], myReports: [],
    observedActions: { votes: Object.fromEntries([A, V, S].filter((other) => other.uid !== player.uid)
      .map((other) => [other.uid, sc.votes[other.uid]])), reports: {} },
    receipts, intent: { vote: player.uid === A.uid ? S.uid : A.uid, reports: [] }, chatWindow,
    submittedAt: sc.base + 999999, signWallet: async (message) => player.wallet.signMessage({ message }),
  });
  const threeControl = await buildThree(V, threeControlReceipts);
  const threeFlood = await buildThree(V, threeFloodReceipts);
  const threePeers = { [A.uid]: (await buildThree(A, threeControlReceipts)).bundle,
    [S.uid]: (await buildThree(S, threeControlReceipts)).bundle };
  const scoreThree = async (bundle) => {
    const result = await calculateGroupResults({ members: threeMembers,
      submissions: { ...threePeers, [V.uid]: bundle }, meta: { blockNum: sc.blockNum, groupId: sc.groupId } },
    500, 20, GUEST_PINNED_RULES, chatWindow);
    return result.results.find((row) => row.uid === V.uid);
  };
  const floodScore3 = await scoreThree(threeFlood.bundle);
  const controlScore3 = await scoreThree(threeControl.bundle);
  assert(!floodScore3.isDisqualified && !controlScore3.isDisqualified,
    `rs-chain-flood 3-player scoring remains qualified: ${JSON.stringify([floodScore3.disqualifyReasons, controlScore3.disqualifyReasons])}`);
  assert(floodScore3.totalPoints >= controlScore3.totalPoints,
    'rs-chain-flood 3-player score does not fall below control');
  label('rs-chain-flood', `members=3 controlPoints=${controlScore3.totalPoints} floodPoints=${floodScore3.totalPoints} dq=${floodScore3.isDisqualified}`);
  label('rs-chain-flood', `members=4 controlPoints=${controlScore.totalPoints} floodPoints=${floodScore.totalPoints} dq=${floodScore.isDisqualified}`);
  assert(!floodScore.isDisqualified && !controlScore.isDisqualified);
  assert(floodScore.totalPoints >= controlScore.totalPoints, 'flood cannot lower V scoring');
  const ownCoverScore = await scoreBundle(floodBundle.bundle, screenTurns);
  assert(!ownCoverScore.isDisqualified, 'rs-own-cover-pushout: scored turns must reach displayed turns');
  label('rs-own-cover-pushout', `screenTurns=${screenTurns} threshold=${screenTurns} dq=${ownCoverScore.isDisqualified} controlPoints=${controlScore.totalPoints} floodPoints=${floodScore.totalPoints}`);
  label('rs-chain-flood', `real before=5050 carriedFacts=${floodFacts} gate=${floodStructure.ok} valid=${floodCheck.valid} Vpoints=${controlScore.totalPoints}/${floodScore.totalPoints}`);

  if (process.argv.includes('--speed')) {
  const speedReceipts = [];
  for (const [issuerIndex, issuer] of [A, V, B, fifth].entries()) for (let i = 0; i < 700; i++) {
    speedReceipts.push({ receiverUid: issuer.uid, senderUid: S.uid, msgRefs: actualRefs,
      timestamp: sc.base + 550_000, signature: `0x${(50_000 + issuerIndex * 700 + i).toString(16).padStart(128, '0')}1b` });
  }
  const coldStart = performance.now();
  const speedMaps = buildReceiptMaps(speedReceipts, { messages: floodMessages, myUid: V.uid },
    sc.blockNum, sc.groupId, chatWindow);
  const mapMs = Math.round(performance.now() - coldStart);
  const coldMessages = clientScoreableMessages(floodMessages, speedReceipts, {
    blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid, chatWindow,
    caps: GUEST_PINNED_RULES, claimMemo: new ReceiptClaimMemo(),
  });
  const coldMs = Math.round(performance.now() - coldStart);
  label('rs-speed-flood', `cold mapMs=${mapMs} scoreMs=${coldMs - mapMs} displayMs=${coldMs} uptime=${process.uptime().toFixed(1)}`);
  const speedClaimMemo = new ReceiptClaimMemo();
  const acceptStart = performance.now();
  let maxPrimeMs = 0;
  for (const receipt of speedReceipts) {
    const oneStart = performance.now();
    speedClaimMemo.primeScoreable(receipt, floodMessages, {
      blockNum: sc.blockNum, groupId: sc.groupId, selfUid: V.uid, chatWindow,
      caps: GUEST_PINNED_RULES,
    });
    maxPrimeMs = Math.max(maxPrimeMs, performance.now() - oneStart);
  }
  const acceptMs = Math.round(performance.now() - acceptStart);
  label('rs-speed-flood', `acceptPrimeTotalMs=${acceptMs} maxPerReceiptMs=${maxPrimeMs.toFixed(2)}`);
  const warmStart = performance.now();
  buildReceiptMaps(speedReceipts, { messages: floodMessages, myUid: V.uid },
    sc.blockNum, sc.groupId, chatWindow);
  const speedMessages = clientScoreableMessages(floodMessages, speedReceipts, {
    blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid, chatWindow,
    caps: GUEST_PINNED_RULES, claimMemo: speedClaimMemo,
  });
  const screenMs = Math.round(performance.now() - warmStart);
  assert.deepEqual(speedMessages, coldMessages, 'acceptance-warmed claim memo preserves display bytes');
  label('rs-speed-flood', `acceptanceWarmDisplayMs=${screenMs}`);
  assert(speedMaps.readersByMsgKey[actualRefs[0]]?.has(A.uid));
  assert(speedMessages.length > 0);
  const recoveryStart = performance.now();
  const speedBundle = await buildSubmissionBundle({
    blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid, encryptKey: V.encryptKey,
    members: [...sc.members, { uid: fifth.uid, addr: fifth.addr, bAddr: fifth.bAddrString, depIds: fifth.depIds }],
    messages: floodMessages, myDepositIds: JSON.parse(V.depIds).ids,
    myVote: sc.votes[V.uid], observedActions: { votes: { [A.uid]: sc.votes[A.uid],
      [S.uid]: sc.votes[S.uid], [B.uid]: sc.votes[B.uid] }, reports: {} },
    receipts: speedReceipts, intent: { vote: A.uid, reports: [] }, chatWindow,
    submittedAt: sc.base + 999999, signWallet: async (message) => V.wallet.signMessage({ message }),
  });
  const recoveryMs = Math.round(performance.now() - recoveryStart);
  assert(speedBundle.payload);
  label('rs-speed-flood', `receipts=${speedReceipts.length} refs=${speedReceipts.length * 100} coldMs=${coldMs} warmMs=${screenMs} recoveryMs=${recoveryMs}`);
  assert(acceptMs < 5000, `receipt acceptance priming ${acceptMs}ms < 5s`);
  assert(screenMs < 1000, `screen flood ${screenMs}ms < 1s`);
  assert(recoveryMs < 5000, `recovery flood ${recoveryMs}ms < 5s`);
  }
}

// RSI-13 (a): A alone reads V's 25 replies. Earlier canonical timestamps on
// A's overlapping S-chain consume the whole issuer share in the plain-order
// mutant, whereas the submitter-cover order retains every V receipt.
{
  const members = sc.members.slice(0, 3);
  const players = [A, V, S];
  const boardWindow = { startMs: sc.base, endMs: sc.base + 40 * 60_000 };
  const boardMessages = [], boardReceipts = [], vCover = [];
  for (let i = 0; i < 25; i++) {
    const at = sc.base + 20 * 60_000 + i * 24_000;
    const a = await makeMessage(A, `a says ${i}`.padEnd(30, 'a'), at);
    const v = await makeMessage(V, `v replies ${i}`.padEnd(30, 'v'), at + 5_000);
    boardMessages.push(a, v);
    boardReceipts.push(await makeRead(V, A.uid, [getRef(a)], at + 2_000));
    const cover = await makeRead(A, V.uid, [getRef(v)], at + 7_000);
    boardReceipts.push(cover);
    vCover.push(cover);
  }
  const sMessages = [];
  for (let i = 0; i < 100; i++) {
    sMessages.push(await makeMessage(S, `s ${i}`, sc.base + 10 * 60_000 + i * 5_400));
  }
  boardMessages.push(...sMessages);
  for (const message of sMessages) {
    boardReceipts.push(await makeRead(V, S.uid, [getRef(message)], message.timestamp + 1_500));
  }
  const sRefs = sMessages.map(getRef).sort(compareHexAsc);
  for (let count = 1; count <= 100; count++) {
    boardReceipts.push(await makeRead(A, S.uid, sRefs.slice(0, count), sc.base + 19 * 60_000 + count));
  }
  boardMessages.sort((left, right) => left.timestamp - right.timestamp);
  const votes = {};
  for (const [voter, target] of [[A, V], [V, A], [S, V]]) {
    const timestamp = sc.base + 5 * 60_000 + players.indexOf(voter);
    const encrypted = encryptAction({ targetUid: target.uid }, voter.encryptKey);
    const signature = canonicalizeSignature(await voter.signAccount.signMessage({
      message: actionSignStringV2('vote', sc.blockNum, sc.groupId, voter.uid, encrypted, timestamp),
    }));
    votes[voter.uid] = { encrypted, signature, timestamp };
    const hash = actionHashV2('vote', sc.blockNum, sc.groupId, voter.uid, encrypted, timestamp);
    for (const reader of players.filter((player) => player.uid !== voter.uid)) {
      const receiptTimestamp = timestamp + 1_000;
      const receiptSignature = canonicalizeSignature(await reader.signAccount.signMessage({
        message: receiptSignString(sc.blockNum, sc.groupId, reader.uid, hash, receiptTimestamp),
      }));
      boardReceipts.push({ receiverUid: reader.uid, actionHash: hash,
        timestamp: receiptTimestamp, signature: receiptSignature });
    }
  }
  const actions = { myVote: votes[V.uid], observedActions: { votes: {
    [A.uid]: votes[A.uid], [S.uid]: votes[S.uid],
  }, reports: {} }, intent: { vote: A.uid, reports: [] } };
  const receiptMap = Object.fromEntries(boardReceipts.map((receipt, index) => [receipt.signature,
    { ...receipt, _seq: index + 1, ...(receipt.actionHash ? {
      _deviceSeenAt: receipt.timestamp + 100, _chatSources: ['device'],
    } : {}) }]));
  const recovered = await buildSubmissionBundle({
    blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid, encryptKey: V.encryptKey,
    members, messages: boardMessages, myDepositIds: JSON.parse(V.depIds).ids,
    myVote: actions.myVote, myVotePrev: [], myReports: [], observedActions: actions.observedActions,
    receipts: receiptMap, intent: actions.intent, chatWindow: boardWindow,
    chatCloseAt: boardWindow.endMs - 120_000, submittedAt: sc.base + 45 * 60_000,
    signWallet: async (message) => V.wallet.signMessage({ message }),
    signReceiptAggregate: async (message) => canonicalizeSignature(
      await privateKeyToAccount(V.signKey).signMessage({ message })),
  });
  const official = await submitWithOfficialHandle({ player: V, members, blockNum: sc.blockNum,
    groupId: sc.groupId, chatWindow: boardWindow, messages: boardMessages, base: sc.base },
  receiptMap, actions);
  const expectedCover = new Set(vCover.map((receipt) => receipt.signature));
  const outcomes = [];
  for (const [client, bundle] of [['recovery', recovered.bundle], ['official', official]]) {
    const carried = bundle.encryptedActions.observed.receipts.filter((receipt) =>
      receipt.receiverUid === A.uid && receipt.senderUid === V.uid);
    const gate = validateSubmissionStructure(bundle, {
      blockNum: sc.blockNum, groupId: sc.groupId, memberUids: members.map((member) => member.uid),
    });
    assert.equal(gate.ok, true, `${client}: ${gate.reason}`);
    const result = await calculateGroupResults({ members, submissions: { [V.uid]: bundle },
      meta: { blockNum: sc.blockNum, groupId: sc.groupId } },
    500, 20, GUEST_PINNED_RULES, boardWindow);
    const turns = countMessageTurns(filterVisibleMessages(
      result.canonicalTimeline.filter((entry) => entry.kind === 'chat')));
    const row = result.results.find((item) => item.uid === V.uid);
    outcomes.push({ client, carried, turns: turns[V.uid] || 0, row });
  }
  label('rs-own-cover-pushout', outcomes.map(({ client, carried, turns, row }) =>
    `${client}=${carried.length}/${turns}/${row.disqualifyReasons.join('+') || 'none'}`).join(' '));
  for (const { client, carried, turns, row } of outcomes) {
    assert.deepEqual(new Set(carried.map((receipt) => receipt.signature)), expectedCover,
      `rs-own-cover-pushout: V cover 25 (${client})`);
    assert.equal(turns, 25, `rs-own-cover-pushout: V scored turns 25 (${client})`);
    assert.equal(row.isDisqualified, false, `rs-own-cover-pushout: V qualified (${client})`);
  }
}

const fakeRead = (issuer, index) => ({ receiverUid: issuer, senderUid: V.uid,
  msgRefs: [refs[0]], timestamp: sc.base + 550_000,
  signature: `0x${(index + 1).toString(16).padStart(128, '0')}1b` });
const actionReceipt = await sc.makeActionReceipt(B, A.uid, 'vote', sc.votes[A.uid], sc.base + 500_010);
const actionHash = actionHashV2('vote', sc.blockNum, sc.groupId, A.uid,
  sc.votes[A.uid].encrypted, sc.votes[A.uid].timestamp);
function floodQueue() {
  const accepted = new Set(), removed = [];
  const queue = new ReceiptAdmissionQueue({ maxPerIssuer: 700,
    getRosterUids: () => sc.members.map((member) => member.uid), isRosterVerified: () => true,
    getChatWindow: () => chatWindow, now: () => sc.base + 600_000,
    getSelectionContext: () => ({ myUid: V.uid }),
    resolveReceipt: (receipt) => ({ state: 'covered', priority: 'F', facts: receipt.msgRefs
      ? [`${receipt.receiverUid}|r:${receipt.senderUid}|${receipt.msgRefs[0]}`]
      : [`${receipt.receiverUid}|a:${receipt.actionHash}`] }),
    onAccept: (receipt) => accepted.add(receipt.signature),
    onRemove: (receipt, reason) => { accepted.delete(receipt.signature); removed.push([receipt.signature, reason]); },
  });
  return { queue, accepted, removed };
}
{
  const { queue, accepted } = floodQueue();
  for (const [j, issuer] of [A.uid, S.uid, V.uid].entries()) {
    for (let i = 0; i < 700; i++) await queue.offer(fakeRead(issuer, j * 700 + i), { verified: true });
  }
  const before = accepted.size;
  await queue.offer(actionReceipt, { verified: true });
  assert(accepted.has(actionReceipt.signature), 'unflooded third-party vote receipt is accepted in its offer');
  const actionMaps = buildReceiptMaps([actionReceipt], {
    actions: [{ ...sc.votes[A.uid], type: 'vote', uid: A.uid }], messages: [], myUid: V.uid,
  }, sc.blockNum, sc.groupId, chatWindow);
  assert(actionMaps.receiptorsByActionHash[actionHash]?.has(B.uid), 'vote confirmation visible');
  const chatPhase = readFileSync(new URL('../../src/components/game/ChatPhase.js', import.meta.url), 'utf8');
  const gateMarker = 'const hasVisibleConfirmedVote = useCallback(';
  const gateStart = chatPhase.indexOf(gateMarker);
  const gateEnd = chatPhase.indexOf('\n  }, [observedActions', gateStart);
  assert(gateStart >= 0 && gateEnd > gateStart, 'official ChatPhase vote gate exists');
  const gateCallback = chatPhase.slice(gateStart + gateMarker.length, gateEnd + '\n  }'.length);
  const gateScope = {
    observedActions: { votes: { [A.uid]: sc.votes[A.uid] } },
    receiptorsByActionHash: actionMaps.receiptorsByActionHash,
    blockNum: sc.blockNum, groupId: sc.groupId, myUid: V.uid, actionHashV2,
    isTimestampVisible: (timestamp, atMs) => timestamp < atMs,
  };
  const officialGate = new Function(...Object.keys(gateScope), `return (${gateCallback});`)(...Object.values(gateScope));
  assert.equal(officialGate(A.uid, sc.base + 600_000), true,
    'rs-vote-gate-flood official ChatPhase expression confirms after one accepted offer');
  label('rs-vote-gate-flood', `before=${before} after=${accepted.size} actionAccepted=true evaluations=1`);
  queue.dispose();
}
{
  const { queue, accepted, removed } = floodQueue();
  for (let i = 0; i < 700; i++) await queue.offer(fakeRead(A.uid, 3000 + i), { verified: true });
  const later = await sc.makeActionReceipt(A, B.uid, 'vote', sc.votes[B.uid], sc.base + 500_020);
  await queue.offer(later, { verified: true });
  assert(!accepted.has(later.signature));
  assert(removed.some(([signature, reason]) => signature === later.signature && reason === 'issuer_cap'));
  label('rs-cap-action', 'late third-party action receipt dropped by issuer_cap at 700');
  queue.dispose();
}
{
  const priorStorage = globalThis.localStorage;
  const backup = new Map([['clientReadSelection_v1_5_group0_useruser0002', JSON.stringify({
    version: 1, signatures: [L.signature],
  })]]);
  let writes = 0;
  globalThis.localStorage = { getItem: (key) => backup.get(key) || null,
    setItem: (key, value) => { writes++; backup.set(key, value); } };
  try {
    const restored = await build(overlapReceipts);
    assert.equal(restored.payload, overlap.payload);
    assert.equal(writes, 0, 'submission never writes the retired selection key');
  } finally { globalThis.localStorage = priorStorage; }
  label('rs-storage', 'old selection backup ignored; new writes=0');
}
const code = [
  '../../src/utils/relay.js', '../../src/hooks/useGameWebSocket.js', '../../src/pages/game.js',
  '../src/recovery/app.js', '../src/recovery/bundle.js',
  '../vendor/workers/game_workers/lib/protocol-v2.js', '../vendor/workers/game_workers/lib/evidence-compact-v1.js',
].map((path) => readFileSync(new URL(path, import.meta.url), 'utf8'));
for (const source of code) assert.doesNotMatch(source,
  /attackedReadIssuers|attackedReadNotice|attackedReadReport|SelectionCoalescer|selectClientReadReceipts|read-selection/);
label('rs-band-absent', 'selection and attack banner absent');
console.log('rs-receipt-carry-unit: ALL PASSED');
