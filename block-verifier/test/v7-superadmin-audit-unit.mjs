// V7: 正典 ABI・実 viem・起点の走査と照合。変異はメモリ上だけに適用する。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { custom, createPublicClient, parseAbiItem, encodeAbiParameters, toEventSelector, encodeEventTopics, getAddress } from 'viem';
import { ArchiveUnavailableError } from '../src/archive.js';
import { emitNonInteractiveOutcome } from '../src/index.js';
import { applyVerifiedTokenDisplay } from '../src/token-display.js';

const BASE = 'c97eec70f38e3d6fbb81806a8d15421b49dbf8f6';
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
const root = new URL('../../', import.meta.url);
const files = ['chain', 'report', 'verification-areas', 'i18n', 'index'];
const sources = Object.fromEntries(files.map((name) => [name, readFileSync(new URL(`../src/${name}.js`, import.meta.url), 'utf8')]));
const guarantees = {
  ja: 'TokenMining・Evidence・HashStorage・BitcoinuDonate の管理者（admin）と SuperAdmin の交代の記録を、配備の時から全部読んだことが保証されます。交代があった場合は警告に表示されます。',
  en: 'It is guaranteed that all records of admin and SuperAdmin changes for TokenMining, Evidence, HashStorage, and BitcoinuDonate have been read from deployment onward. Any changes are shown as warnings.',
  zh: '可以保证，已从合约部署时起读取 TokenMining、Evidence、HashStorage、BitcoinuDonate 的管理员（admin）和 SuperAdmin 变更记录，且无遗漏。如有变更，会在警告中显示。',
};
const oldGuarantees = {
  en: 'It is guaranteed that all records of admin changes for TokenMining, Evidence, and HashStorage, and SuperAdmin changes for BitcoinuDonate, have been read from deployment onward. Any changes are shown as warnings.',
  ja: 'TokenMining・Evidence・HashStorage の管理者（admin）の交代と、BitcoinuDonate の SuperAdmin の交代の記録を、配備の時から全部読んだことが保証されます。交代があった場合は警告に表示されます。',
  zh: '可以保证，已从合约部署时起读取 TokenMining、Evidence、HashStorage 的管理员（admin）变更记录，以及 BitcoinuDonate 的 SuperAdmin 变更记录，且无遗漏。如有变更，会在警告中显示。',
};
const factTexts = {
  ja: ['【注視】SuperAdminChangedイベントによるsuperAdmin変更を検出しました — {authorities}',
    '【告知】BitcoinuDonateの即時admin変更イベントが{count}件あります。最新: {last}',
    'AdminChanged・SuperAdminChangedイベント履歴を取得できませんでした — {error}',
    '【告知】BitcoinuDonateのSuperAdminChanged・AdminChanged履歴を取得できませんでした: {error}'],
  en: ['ATTENTION: SuperAdminChanged events were observed — {authorities}',
    'NOTICE: BitcoinuDonate has {count} immediate admin change event(s); latest: {last}',
    'AdminChanged/SuperAdminChanged event history could not be read — {error}',
    'NOTICE: BitcoinuDonate SuperAdminChanged/AdminChanged history could not be read: {error}'],
  zh: ['【注意】检测到 SuperAdminChanged 事件所记录的 superAdmin 变更 — {authorities}',
    '【通知】BitcoinuDonate有{count}条即时admin变更事件；最新: {last}',
    '无法读取 AdminChanged、SuperAdminChanged 事件历史 — {error}',
    '【通知】无法读取BitcoinuDonate的SuperAdminChanged、AdminChanged历史: {error}'],
};
const chunkCall = `(f, t) => publicClient.getLogs(events
        ? { address, events, strict: false, fromBlock: f, toBlock: t }
        : { address, event, args, fromBlock: f, toBlock: t })`;
const mutations = {
  omit_super: ['chain', (s) => s.replaceAll('[ADMIN_CHANGED_INDEXED_EVENT, SUPER_ADMIN_CHANGED_INDEXED_EVENT]', '[ADMIN_CHANGED_INDEXED_EVENT]')
    .replace('[ADMIN_CHANGED_UNINDEXED_EVENT, DONATE_SUPER_ADMIN_CHANGED_EVENT]', '[ADMIN_CHANGED_UNINDEXED_EVENT]')],
  omit_donate_admin: ['chain', (s) => s.replace('const events = [DONATE_SUPER_ADMIN_CHANGED_EVENT, ADMIN_CHANGED_UNINDEXED_EVENT];', 'const events = [DONATE_SUPER_ADMIN_CHANGED_EVENT];')],
  super_single_suppressed: ['index', (s) => s.replace('if (audit.superAdminChanges.length) {', 'if (audit.superAdminChanges.length > 1) {')],
  donate_admin_single_suppressed: ['index', (s) => s.replace('if (audit.donateAdminChanges.length) {', 'if (audit.donateAdminChanges.length > 1) {')],
  indexed_super: ['chain', (s) => s.replace('event SuperAdminChanged(address indexed oldSuperAdmin, address indexed newSuperAdmin)', 'event SuperAdminChanged(address oldSuperAdmin, address newSuperAdmin)')],
  unindexed_super: ['chain', (s) => s.replace('event SuperAdminChanged(address oldSuperAdmin, address newSuperAdmin)', 'event SuperAdminChanged(address indexed oldSuperAdmin, address indexed newSuperAdmin)')],
  unindexed_admin: ['chain', (s) => s.replace('event AdminChanged(address oldAdmin, address newAdmin)', 'event AdminChanged(address indexed oldAdmin, address indexed newAdmin)')],
  matches_super: ['verification-areas', (s) => s.replace('|superAdminRotation', '')],
  matches_donate: ['verification-areas', (s) => s.replace('|donateAdminChanges', '')],
  donate_condition: ['report', (s) => s.replace("      if (area === 'adminHistory' && getFact('system.audit')?.donateChecked !== true) return false;\n", '')],
  ...Object.fromEntries(Object.keys(guarantees).map((lang) => [`guarantee_${lang}`, ['i18n', (s) => s.replace(JSON.stringify(guarantees[lang]), JSON.stringify(oldGuarantees[lang]))]])),
  split_scans: ['chain', (s) => s.replace(chunkCall, `async (f, t) => events
        ? (await Promise.all(events.map((event) => publicClient.getLogs({ address, event, args, fromBlock: f, toBlock: t })))).flat()
        : publicClient.getLogs({ address, event, args, fromBlock: f, toBlock: t })`)],
  strict_drops: ['chain', (s) => s.replace('address, events, strict: false, fromBlock', 'address, events, strict: true, fromBlock')],
  empty_args_drops: ['chain', (s) => s.replace('address, events, strict: false, fromBlock', 'address, events, strict: false, args: {}, fromBlock')],
};
if (mutation) {
  assert.ok(mutations[mutation], '既知の変異');
  const [file, edit] = mutations[mutation], before = sources[file];
  sources[file] = edit(before);
  assert.notEqual(sources[file], before, '変異を適用');
  console.log(`MUTATION_APPLIED ${mutation}`);
}
let assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
const urlOf = (name) => new URL(`../src/${name}.js`, import.meta.url);
function moduleUrl(name, source = sources[name], overrides = {}) {
  const url = urlOf(name);
  const absolute = source.replace(/from '([^']+)'/g, (_, p) =>
    `from '${overrides[p] ?? (p.startsWith('.') ? new URL(p, url).href : import.meta.resolve(p))}'`);
  return `data:text/javascript;base64,${Buffer.from(absolute).toString('base64')}`;
}
const { createChain, getLogsChunkedAdaptive } = await import(moduleUrl('chain'));
const baseSource = execFileSync('git', ['show', `${BASE}:block-verifier/src/chain.js`], { cwd: root, encoding: 'utf8' });
const { createChain: baseChain, getLogsChunkedAdaptive: baseChunked } = await import(moduleUrl('chain', baseSource));
const areasUrl = moduleUrl('verification-areas');
const { VERIFICATION_AREAS } = await import(areasUrl);
const { createReport, verificationCoverage } = await import(moduleUrl('report', sources.report, { './verification-areas.js': areasUrl }));
const { t } = await import(moduleUrl('i18n'));
const baseModule = (name) => moduleUrl(name, execFileSync('git', ['show', `${BASE}:block-verifier/src/${name}.js`], { cwd: root, encoding: 'utf8' }));
const { createReport: baseReport } = await import(baseModule('report'));
const { t: baseT } = await import(baseModule('i18n'));
function auditEmitter(source) {
  const begin = source.indexOf("  if (typeof chain.systemAudit === 'function') {");
  const end = source.indexOf('\n\n  if (chain.client?.getBlockNumber', begin);
  assert.ok(begin > 0 && end > begin, '実際の systemAudit 呼出・全記録部分を抽出');
  return new (Object.getPrototypeOf(async function () {}).constructor)(
    'chain', 'report', 'ui', 'ArchiveUnavailableError', 'applyVerifiedTokenDisplay', source.slice(begin, end));
}
const emitAudit = auditEmitter(sources.index);
const baseEmitAudit = auditEmitter(execFileSync('git', ['show', `${BASE}:block-verifier/src/index.js`], { cwd: root, encoding: 'utf8' }));
async function recorded(audit, emit = emitAudit, factory = createReport) {
  const report = factory();
  await emit({ systemAudit: async () => audit }, report, { t: t('ja'), println() {} }, ArchiveUnavailableError, applyVerifiedTokenDisplay);
  ok(!report.get('check.system.auditUnavailable'), '監査の記録は完了');
  return report;
}
const addr = (n) => `0x${n.toString(16).padStart(40, '0')}`;
const contracts = { tokenMining: addr(1), evidence: addr(2), hashStorage: addr(3), donate: addr(4), ethLock: addr(5), ethStake: addr(6) };
const token = addr(7), old = getAddress(addr(10)), next = getAddress(addr(11)), zero = addr(0), bytes32 = `0x${'00'.repeat(32)}`;
const names = ['TokenMining', 'Evidence', 'HashStorage', 'BitcoinuDonate'];
const addresses = [contracts.tokenMining, contracts.evidence, contracts.hashStorage, contracts.donate];
const deployments = [3n, 7n, 13n, 19n], head = 6020n;
function abi(kind, indexed) {
  const field = kind === 'AdminChanged' ? 'Admin' : 'SuperAdmin';
  return parseAbiItem(`event ${kind}(address ${indexed ? 'indexed ' : ''}old${field}, address ${indexed ? 'indexed ' : ''}new${field})`);
}
const adminTopic = toEventSelector(abi('AdminChanged', true));
const superTopic = toEventSelector(abi('SuperAdminChanged', true));
function rawLog(which, kind, height = 30, transactionIndex = 1, logIndex = 2) {
  const indexed = which < 2, event = abi(kind, indexed);
  const field = kind === 'AdminChanged' ? 'Admin' : 'SuperAdmin';
  return { address: addresses[which], topics: encodeEventTopics({ abi: [event], eventName: kind,
    args: { [`old${field}`]: old, [`new${field}`]: next } }),
  data: indexed ? '0x' : encodeAbiParameters([{ type: 'address' }, { type: 'address' }], [old, next]),
  blockNumber: `0x${height.toString(16)}`, transactionIndex: `0x${transactionIndex.toString(16)}`,
  logIndex: `0x${logIndex.toString(16)}`, transactionHash: `0x${height.toString(16).padStart(64, '0')}`,
  blockHash: bytes32, removed: false };
}
function fixture(factory = createChain, { logs = [], archive = false, donate = contracts.donate, chainIdExpected = 1, fault } = {}) {
  const requests = [], calls = [];
  const transport = custom({ request: async (r) => {
    requests.push(structuredClone(r));
    if (r.method === 'eth_blockNumber') return `0x${head.toString(16)}`;
    if (r.method === 'eth_getCode') {
      const [address, height] = r.params;
      if (height === 'latest') return '0x6000';
      if (archive && BigInt(height) < head - 100n) throw { code: -32602, message: 'Archive requests require a personal token.' };
      return BigInt(height) >= (deployments[addresses.indexOf(address)] ?? 0n) ? '0x6000' : '0x';
    }
    if (r.method === 'eth_getLogs') {
      const q = r.params[0];
      const topics = [q.topics[0]].flat();
      return logs.filter((l) => l.address === q.address && topics.includes(l.topics[0])
        && BigInt(l.blockNumber) >= BigInt(q.fromBlock) && BigInt(l.blockNumber) <= BigInt(q.toBlock));
    }
    throw new Error(`unexpected RPC ${r.method}`);
  } }, { retryCount: 0 });
  const cfg = { chainIdExpected, rpcUrls: ['http://stub.invalid'], contracts: { ...contracts, donate } };
  const chain = factory(cfg, null, transport);
  chain.client.readContract = async ({ address, functionName: f }) => {
    calls.push([address, f]);
    const values = { evidence: contracts.evidence, ethLock: contracts.ethLock, ethStake: contracts.ethStake, token, hashStorage: contracts.hashStorage,
      TOKEN_MINING: contracts.tokenMining, HASH_STORAGE: contracts.hashStorage, tokenMining: contracts.tokenMining,
      START_TIME: 1800000000n, BLOCK_INTERVAL: 345600n, MAX_BLOCK_NUM: 363n, verificationPeriod: 345600n, CLAIM_PERIOD: 3456000n,
      ethStakeFromBlock: (1n << 256n) - 1n, getCurrentTimeUnlockedBlock: 7n,
      pendingVkey: bytes32, pendingGuestSourceHash: bytes32, pendingVkeyEta: 0n,
      name: 'COINU', symbol: 'COINU', nameChanged: false, totalSupply: 21000000n * 10n ** 18n, balanceOf: 21000000n * 10n ** 18n,
      GAME_PERIOD: 86400n, SUBMIT_PERIOD: 86400n, INITIAL_GRACE: 7200n, START_PAST_TOLERANCE: 3600n,
      MAX_RESULTS_PER_SENDER: 3n, entryAcc: bytes32, admin: old, superAdmin: next, pendingSuperAdmin: zero, pendingSuperAdminEta: 0n };
    assert.ok(Object.hasOwn(values, f), `unexpected getter ${f}`);
    return values[f];
  };
  if (fault) {
    const original = chain.client.getLogs;
    chain.client.getLogs = async (r, ...rest) => { if (r.address === fault.address) throw fault.error; return original(r, ...rest); };
  }
  return { chain, requests, calls, cfg };
}
const ranges = (f) => f.requests.filter((r) => r.method === 'eth_getLogs').map((r) => r.params[0]);
const withoutTopics = (q) => { const { topics, ...rest } = q; return rest; };
function machine(report) {
  const lines = [];
  const outcome = emitNonInteractiveOutcome({ println: (line) => lines.push(line) }, { report, fatal: false, stopped: false }, null);
  return { lines, outcome };
}
function summary(report, lang) {
  const records = structuredClone(report.list()), coverage = verificationCoverage(report), marker = machine(report), lines = [];
  report.renderSummary({ t: t(lang), println: (line) => lines.push(line) }, { blockNum: 8, data: {} });
  eq(report.list(), records, '描画が全レコードを保持'); eq(verificationCoverage(report), coverage, '描画が分類を保持');
  eq(machine(report), marker, '描画が機械行・終了コードを保持');
  return lines;
}
const adminRow = (report) => verificationCoverage(report).find((r) => r.area === 'adminHistory');
const rowPrefix = (lang) => `  ${t(lang)('summary.area.adminHistory')}: `;
const factIds = ['superAdminRotation', 'donateAdminChanges', 'adminRotationUnavailable', 'donateEventUnavailable'].map((id) => `fact.system.${id}`);
for (const lang of ['ja', 'en', 'zh']) {
  eq(t(lang)('summary.guarantee.adminHistory'), guarantees[lang], `${lang}: 保証文は逐語`);
  factIds.forEach((id, i) => eq(t(lang)(id, { authorities: '{authorities}', count: '{count}', last: '{last}', error: '{error}' }), factTexts[lang][i], `${lang}/${id}: 全文逐語`));
}

// I1/I2: 起点の実 chain.js と比較。ログ要求の topic0 OR と audit の3新欄だけを名前で許す。
for (const archive of [false, true]) {
  const before = fixture(baseChain, { archive }), after = fixture(createChain, { archive });
  const a = await before.chain.systemAudit(), b = await after.chain.systemAudit();
  const { superAdminChanges, donateAdminChanges, donateChecked, ...oldFields } = b;
  eq([superAdminChanges, donateAdminChanges, donateChecked], [[], [], true], 'I1: system.audit の許された3追加欄');
  eq(oldFields, a, 'I1: system.audit の既存欄は同一');
  const ra = await recorded(a, baseEmitAudit, baseReport), rb = await recorded(b);
  eq(rb.list(), ra.list(), 'I1: id・状態・params・順序は起点と同一');
  eq(machine(rb), machine(ra), 'I1: 機械行・終了コードは同一');
  eq(verificationCoverage(rb), verificationCoverage(ra), 'I6: coverageは同一');
  eq(ranges(after).map(withoutTopics), ranges(before).map(withoutTopics), 'I2: getLogs回数・高さ・アドレスは起点と同一');
  eq(after.requests.filter((r) => r.method !== 'eth_getLogs'), before.requests.filter((r) => r.method !== 'eth_getLogs'), 'I2: 配備高探索の全要求は同一');
  eq(after.calls, before.calls, 'I7: 他のgetterも同一');
  for (const lang of ['ja', 'en', 'zh']) {
    const original = [], current = summary(rb, lang);
    ra.renderSummary({ t: baseT(lang), println: (line) => original.push(line) }, { blockNum: 8, data: {} });
    // I1(a) の保証文1行と、SUMMARY-ZKPで未検証欄の先頭に追加した⓪だけを許す。
    // 既存行を削除せず、⓪の数・文・位置も含む配列全体を比較する。
    const allowedBefore = rowPrefix(lang) + oldGuarantees[lang], allowedAfter = rowPrefix(lang) + guarantees[lang];
    const expected = original.map((line) => line === allowedBefore ? allowedAfter : line);
    const pendingHeader = t(lang)('summary.notVerifiedHeader');
    eq(expected.filter((line) => line === pendingHeader).length, 1, 'I1: 起点の未検証見出しは1つ');
    expected.splice(expected.indexOf(pendingHeader) + 1, 0,
      `  ${t(lang)('notVerified.zk', { reason: t(lang)('reason.stopped') })}`);
    eq(current, expected, 'I1: まとめの差は名前を挙げた保証文と未検証の⓪の1行だけ');
  }
  eq(ranges(after).length, archive ? 0 : 16, '4アドレス×4チャンク、配備高を読めない場合は走査しない');
  for (const q of ranges(after)) eq(q.topics, [q.address === contracts.donate ? [superTopic, adminTopic] : [adminTopic, superTopic]], 'I2: 2つのtopic0のOR');
  for (const address of addresses) {
    const count = after.requests.length;
    try { await after.chain.findContractDeploymentBlock(address); } catch (e) { ok(e instanceof ArchiveUnavailableError, '過去状態の型付き失敗'); }
    if (!archive) eq(after.requests.length, count, 'I2: 配備高のキャッシュを保持');
  }
}
// 応答過大時の分割も、1イベントの起点と同じ範囲・回数。
{
  async function read(reader, multiple) {
    const requests = [], event = abi('AdminChanged', true);
    await reader({ getLogs: async (r) => {
      requests.push({ address: r.address, fromBlock: r.fromBlock, toBlock: r.toBlock });
      if (r.toBlock - r.fromBlock >= 1000n) throw { code: -32005, message: 'query returned more than 10000 results' };
      return [];
    } }, { address: old, ...(multiple ? { events: [event, abi('SuperAdminChanged', true)] } : { event }), args: {}, fromBlock: 5n, toBlock: 4006n });
    return requests;
  }
  eq(await read(getLogsChunkedAdaptive, true), await read(baseChunked, false), 'I2: 適応分割時も回数と範囲は起点と同一');
}
// 単一 event の呼出は JS 引数まで従来どおり。複数 event も同じ適応分割を使う。
{
  const calls = [], event = abi('AdminChanged', true), args = {};
  await getLogsChunkedAdaptive({ getLogs: async (r) => { calls.push(r); return []; } }, { address: old, event, args, fromBlock: 5n, toBlock: 2006n });
  eq(calls, [ { address: old, event, args, fromBlock: 5n, toBlock: 2004n }, { address: old, event, args, fromBlock: 2005n, toBlock: 2006n } ], '既存event呼出の要求はbyte同一');
}
// I3: インストール済み viem 2.42 の実挙動。indexedの両方向の食い違いを確認。
for (const [which, kind] of [[0, 'SuperAdminChanged'], [1, 'SuperAdminChanged'], [2, 'SuperAdminChanged'], [3, 'AdminChanged'], [0, 'AdminChanged'], [2, 'AdminChanged'], [3, 'SuperAdminChanged']]) {
  const raw = rawLog(which, kind), wrong = abi(kind, which >= 2);
  const client = createPublicClient({ transport: custom({ request: async () => [raw] }, { retryCount: 0 }) });
  const request = { address: raw.address, events: [wrong], fromBlock: 0n, toBlock: head };
  const loose = await client.getLogs(request);
  eq(loose.length, 1, 'viem strict未指定は対象ログを保持');
  eq(loose[0].args, which < 2 ? undefined : {}, 'viemのindexed食い違いはundefinedまたは空args');
  eq((await client.getLogs({ ...request, strict: true })).length, 0, 'viem strict:trueは黙って捨てる');
  eq((await client.getLogs({ address: raw.address, event: wrong, args: {}, fromBlock: 0n, toBlock: head })).length,
    which < 2 ? 0 : 1, '起点のevent+args:{}はindexedをnon-indexedと誤るとログを捨てる');
  // 正しいABIの読みへ壊れた配置の対象ログを返すと、空argsを件数へ通さず既存エラーにする。
  const other = rawLog(which < 2 ? 2 : 0, kind);
  const malformed = { ...raw, topics: other.topics, data: other.data };
  const fx = fixture(createChain, { logs: [malformed] }), audit = await fx.chain.systemAudit();
  ok(which === 3 ? audit.donateEventError : audit.adminChangeError, 'I3: 対象topic0の不正ログは読み失敗');
  const report = await recorded(audit);
  eq(report.get(which === 3 ? 'fact.system.donateEventUnavailable' : 'fact.system.adminRotationUnavailable').status, 'warn', 'I3: 黙って落とさずWARN');
}
for (const kinds of [['AdminChanged'], ['SuperAdminChanged'], ['AdminChanged', 'SuperAdminChanged']]) {
  const logs = addresses.flatMap((_, i) => kinds.map((kind) => rawLog(i, kind, 30 + i)));
  const audit = await fixture(createChain, { logs }).chain.systemAudit();
  const oldAudit = await fixture(baseChain, { logs }).chain.systemAudit();
  const report = await recorded(audit), isAdmin = kinds.includes('AdminChanged'), isSuper = kinds.includes('SuperAdminChanged');
  eq(audit.adminChanges, oldAudit.adminChanges, '既存adminChangesの形・値・順序を保持');
  eq(audit.donateChanges, oldAudit.donateChanges, '既存donateChangesの形・値・順序を保持');
  eq(audit.adminChanges.length, isAdmin ? 3 : 0, 'adminだけを既存欄へ');
  eq(audit.superAdminChanges.length, isSuper ? 3 : 0, '3契約のSuperAdminだけを新欄へ');
  eq(audit.donateChanges.length, isSuper ? 1 : 0, 'Donate SuperAdminだけを既存欄へ');
  eq(audit.donateAdminChanges.length, isAdmin ? 1 : 0, 'Donate adminだけを新欄へ');
  const expectedItem = (i, superAdmin) => ({ contract: names[i], address: addresses[i],
    ...(superAdmin ? { oldSuperAdmin: old, newSuperAdmin: next } : { oldAdmin: old, newAdmin: next }),
    blockNumber: 30 + i, transactionIndex: 1, logIndex: 2, txHash: logs.find((l) => l.address === addresses[i]).transactionHash });
  if (isSuper) eq(audit.superAdminChanges, [0, 1, 2].map((i) => expectedItem(i, true)), '新欄の全キーと値');
  if (isAdmin) eq(audit.donateAdminChanges, [{ oldAdmin: old, newAdmin: next, blockNumber: 33, txHash: logs.at(-1).transactionHash }], 'Donate新欄の形');
  eq(report.list().filter((r) => ['adminRotation', 'superAdminRotation', 'donateSuperAdminChanges', 'donateAdminChanges'].some((id) => r.id === `fact.system.${id}`)).map((r) => r.id),
    [ ...(isAdmin ? ['fact.system.adminRotation'] : []), ...(isSuper ? ['fact.system.superAdminRotation', 'fact.system.donateSuperAdminChanges'] : []), ...(isAdmin ? ['fact.system.donateAdminChanges'] : []) ], '事実idと記録の順序');
  if (isSuper) eq(report.get('fact.system.superAdminRotation').params, { authorities: [0, 1, 2].map((i) => `${names[i]}: ${old} -> ${next} @ block ${30 + i}`).join('; ') }, '全件を表示');
  if (isAdmin) eq(report.get('fact.system.donateAdminChanges').params, { count: 1, last: `${old} -> ${next} @ block 33` }, 'Donate件数と最新');
  for (const lang of ['ja', 'en', 'zh']) {
    const lines = summary(report, lang);
    ok(lines.includes(rowPrefix(lang) + t(lang)('summary.areaVerified')), '交代のWARNは短い検証できた文');
    for (const [i, present] of [[0, isSuper], [1, isAdmin]]) {
      const record = report.get(factIds[i]);
      if (present) {
        eq(record.status, 'warn', '新事実の状態はWARN');
        const text = factTexts[lang][i].replace(/\{([^}]+)\}/g, (_, key) => record.params[key]);
        eq(t(lang)(factIds[i], record.params), text, '新事実の実データを埋めた3言語全文');
        ok(lines.some((line) => line.includes(text)), '新事実を実際のまとめへ表示');
      } else eq(record, null, '0件なら新事実なし');
    }
  }
}
// FIX1 R-2: 3契約それぞれで交代がちょうど1件でもWARNを出し、保証文を抑制する。
for (const which of [0, 1, 2]) {
  const log = rawLog(which, 'SuperAdminChanged', 30 + which);
  const audit = await fixture(createChain, { logs: [log] }).chain.systemAudit();
  const report = await recorded(audit), label = `${names[which]}だけのSuperAdmin交代1件`;
  eq(audit.superAdminChanges, [{ contract: names[which], address: addresses[which],
    oldSuperAdmin: old, newSuperAdmin: next, blockNumber: 30 + which,
    transactionIndex: 1, logIndex: 2, txHash: log.transactionHash }], `${label}: 全キーと値`);
  eq([audit.adminChanges, audit.donateChanges, audit.donateAdminChanges], [[], [], []], `${label}: ほかの交代なし`);
  eq(audit.donateChecked, true, `${label}: Donateも走査済み`);
  const record = report.get('fact.system.superAdminRotation');
  ok(record, `${label}: 1件から警告を記録`);
  eq(record.status, 'warn', `${label}: WARN`);
  const authorities = `${names[which]}: ${old} -> ${next} @ block ${30 + which}`;
  eq(record.params, { authorities }, `${label}: authorities全文`);
  eq(adminRow(report).verified, true, `${label}: 検証できたの分類を保持`);
  for (const lang of ['ja', 'en', 'zh']) {
    const text = factTexts[lang][0].replace('{authorities}', authorities), lines = summary(report, lang);
    eq(t(lang)('fact.system.superAdminRotation', record.params), text, `${label}/${lang}: 事実の全文`);
    ok(lines.some((line) => line.includes(text)), `${label}/${lang}: 警告をまとめに表示`);
    eq(lines.filter((line) => line.startsWith(rowPrefix(lang))),
      [rowPrefix(lang) + t(lang)('summary.areaVerified')], `${label}/${lang}: adminHistoryは短い検証できた文`);
    ok(!lines.includes(rowPrefix(lang) + guarantees[lang]), `${label}/${lang}: 保証文を出さない`);
  }
}
// 同一ブロックでは transactionIndex → logIndex。Donateは従来のログ順のまま最新を採る。
{
  const logs = [rawLog(0, 'SuperAdminChanged', 40, 2, 1), rawLog(1, 'SuperAdminChanged', 40, 1, 9), rawLog(2, 'SuperAdminChanged', 40, 1, 2),
    rawLog(0, 'AdminChanged', 40, 2, 2), rawLog(1, 'AdminChanged', 40, 1, 8), rawLog(2, 'AdminChanged', 40, 1, 1),
    rawLog(3, 'AdminChanged', 40, 1, 2), rawLog(3, 'SuperAdminChanged', 40, 1, 3), rawLog(3, 'AdminChanged', 41, 0, 0)];
  const audit = await fixture(createChain, { logs }).chain.systemAudit();
  for (const key of ['adminChanges', 'superAdminChanges']) eq(audit[key].map((r) => r.contract), ['HashStorage', 'Evidence', 'TokenMining'], `${key}: 同一ブロックの順序`);
  const report = await recorded(audit);
  eq(report.get('fact.system.donateAdminChanges').params, { count: 2, last: `${old} -> ${next} @ block 41` }, 'Donateは全件数と最新1件');
  // 全6 id を同時に出す場合の厳密な順序。既存の失敗欄は別途実走査からも検査する。
  audit.adminChangeError = 'ordinary'; audit.donateEventError = 'ordinary';
  const all = await recorded(audit);
  eq(all.list().filter((r) => /^fact.system.(?:adminRotation|superAdminRotation|donate)/.test(r.id)).map((r) => r.id),
    ['fact.system.adminRotation', 'fact.system.superAdminRotation', 'fact.system.adminRotationUnavailable', 'fact.system.donateSuperAdminChanges', 'fact.system.donateAdminChanges', 'fact.system.donateEventUnavailable'], '指定の6事実の順序');
}
// 新読取の失敗も既存の型付き／通常の経路へ。失敗した契約以外のログ・現在値は保持する（0-a）。
for (let which = 0; which < 4; which++) for (const typed of [false, true]) {
  const error = typed ? new ArchiveUnavailableError() : new Error('ordinary failure');
  const logs = addresses.map((_, i) => rawLog(i, i === 3 ? 'AdminChanged' : 'SuperAdminChanged'));
  const fx = fixture(createChain, { logs, fault: { address: addresses[which], error } }), audit = await fx.chain.systemAudit();
  eq(which === 3 ? audit.donateEventArchiveError : audit.adminChangeArchiveErrors[0], typed ? error : which === 3 ? null : undefined, 'I5: 型を保つ');
  const report = await recorded(audit), id = which === 3 ? 'fact.system.donateEventUnavailable' : 'fact.system.adminRotationUnavailable';
  const entry = report.get(id);
  eq(entry.status, 'warn', 'I5: どちらもwarn');
  eq(entry.reason, typed ? 'archive_unavailable' : undefined, 'I5: 型付きだけunverified');
  eq(audit.superAdminChanges.length, which === 3 ? 3 : 2, '0-a: 他契約の読めたログを保持');
  eq(audit.donateAdminChanges.length, which === 3 ? 0 : 1, '0-a: Donateの読めたログを保持');
  eq(report.get('check.system.authoritySeparation').status, 'pass', '0-a: 現在の分離検査は実施');
  eq(adminRow(report).reason, typed ? 'archiveUnavailable' : 'rpcRequestFailed', '失敗種別の行分類');
  for (const lang of ['ja', 'en', 'zh']) ok(!summary(report, lang).includes(rowPrefix(lang) + guarantees[lang]), '失敗では保証しない');
}
for (const donate of [undefined, null, '', contracts.donate]) {
  const fx = fixture(createChain, { donate: donate ?? '' }), audit = await fx.chain.systemAudit(), report = await recorded(audit);
  eq(audit.donateChecked, Boolean(donate), 'I6: Donate走査を試みた真偽');
  eq(adminRow(report).verified, true, 'I6: completeとcoverageの分類は変更しない');
  for (const lang of ['ja', 'en', 'zh']) ok(summary(report, lang).includes(rowPrefix(lang) + (donate ? guarantees[lang] : t(lang)('summary.areaVerified'))), 'Donate未走査は短文、全読取は保証全文');
}
{
  const fx = fixture(); delete fx.cfg.contracts.donate;
  const audit = await fx.chain.systemAudit(), report = await recorded(audit);
  eq(audit.donateChecked, false, 'contracts.donate自体が無い場合も未走査');
  eq(ranges(fx).length, 12, '未設定なら3アドレスだけを読む');
  for (const lang of ['ja', 'en', 'zh']) ok(summary(report, lang).includes(rowPrefix(lang) + t(lang)('summary.areaVerified')), 'Donate未設定で保証しない');
}
for (const donateChecked of [undefined, false, 1, 'true', true]) {
  const report = createReport(); report.fact('system.audit', { adminHistoryChecked: true, donateChecked });
  for (const lang of ['ja', 'en', 'zh']) ok(summary(report, lang).includes(rowPrefix(lang)
    + (donateChecked === true ? guarantees[lang] : t(lang)('summary.areaVerified'))), 'donateCheckedは厳密にtrueの時だけ保証');
}
{
  const fx = fixture(createChain, { chainIdExpected: 31337 }), audit = await fx.chain.systemAudit();
  eq([audit.donateChecked, audit.adminHistoryChecked, ranges(fx).length], [false, false, 0], 'mainnet以外は履歴の対象外');
  eq(adminRow(await recorded(audit)).notApplicable, true, '対象なしの意味は維持');
}
// matches の新idは保証を抑制するが coverage/complete の意味は変えない。
for (const id of ['fact.system.adminRotation', 'fact.system.superAdminRotation', 'fact.system.adminRotationUnavailable', 'fact.system.donateSuperAdminChanges', 'fact.system.donateAdminChanges', 'fact.system.donateEventUnavailable']) {
  ok(VERIFICATION_AREAS[0].matches.test(id), `${id}: 管理者履歴に属する`);
  const report = createReport(); report.fact('system.audit', { adminHistoryChecked: true, donateChecked: true }); report.check(id, 'warn', {});
  eq(adminRow(report).verified, true, 'WARNだけでcompleteを変えない');
  for (const lang of ['ja', 'en', 'zh']) ok(summary(report, lang).includes(rowPrefix(lang) + t(lang)('summary.areaVerified')), `${id}: WARNに保証を出さない`);
}
if (!mutation) for (const name of Object.keys(mutations)) {
  const result = spawnSync(process.execPath, [import.meta.filename, `--mutation=${name}`], { env: process.env, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  eq(result.status, 1, `${name}: 変異は赤`);
  ok(result.stdout.includes(`MUTATION_APPLIED ${name}`) && result.stderr.includes('AssertionError'), `${name}: 起動失敗ではなくassertionで検出`);
}
console.log(`v7-superadmin-audit-unit: PASS (${assertions} assertions; ${Object.keys(mutations).length} mutants killed; viem 2.42.0)`);
