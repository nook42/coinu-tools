import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync as writeFixtureSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { createReport } from '../src/report.js';
import { createR2 } from '../src/r2.js';
import { hashLikeBackend } from '../src/json-utils.js';
import { setupChain, providerRpcUrl, makeUi, categorize, EXIT_CODE_OF } from '../src/index.js';
import { run as realSelection } from '../src/stages/selection.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';

const sourceUrl = new URL('../src/entry-membership.js', import.meta.url);
const source = readFileSync(sourceUrl, 'utf8');
const baseSource = execFileSync('git', ['show', 'f52095ab2:block-verifier/src/entry-membership.js'],
  { cwd: new URL('../../', import.meta.url), encoding: 'utf8' });
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
const slotExpression = "String(uid).slice(-4).padStart(4, '0').slice(0, 2)";
const mutations = {
  m1_no_padding: (s) => s.replace(slotExpression, 'String(uid).slice(-4).slice(0, 2)'),
  m2_first_two: (s) => s.replace(slotExpression, 'String(uid).slice(0, 2)'),
  m3_no_reads_all: (s) => s.replace('if (!verified) {', 'if (false) {'),
  m4_no_prefix_check: (s) => s.replace('if (!filenamePattern.test(String(info?.filename)))', 'if (false)'),
  m5_yes_slot_only: (s) => s.replace('for (let i = 0; i < 100; i++) {',
    `for (let i = Number(${slotExpression}); i === Number(${slotExpression}); i++) {`),
  m6_no_overwrite: (s) => s.replace('included ||= rows.some', 'included = rows.some'),
  m7_numeric_uid: (s) => s.replace(slotExpression, "String(Number(uid)).slice(-4).padStart(4, '0').slice(0, 2)"),
  f1_prompt_first: (s) => s.replace('initial = await findEntry(ctx, uid, false);',
    "const yes = await ctx.ui.askYesNo('entry.verifyAll');\n    initial = await findEntry(ctx, uid, false);")
    .replace("if (!await ctx.ui.askYesNo('entry.verifyAll'))", 'if (!yes)'),
  f2_no_guarantee: (s) => s.replace("if (!await ctx.ui.askYesNo('entry.verifyAll')) return { ...initial, verified: false };",
    "if (!await ctx.ui.askYesNo('entry.verifyAll')) { ctx.ui.println(ctx.ui.t('entry.onchainIncluded')); return { ...initial, verified: false }; }"),
  f3_wrong_wiring_guarantee: (s) => s.replace("verified = typeof onchain === 'string'", "verified = true || typeof onchain === 'string'"),
  f4_reused_prompt: (s) => s.replace('if (reused) {', "if (reused) {\n    await ctx.ui.askYesNo('entry.verifyAll');"),
  f5_failed_unchecked: (s) => s.replace(": 'entry.verifyFailed'));", ": 'entry.onchainUnchecked'));"),
  f6_incomplete_guarantee: (s) => s.replace('verified && result.included && result.complete', 'verified && result.included')
    .replace('ctx.ui.t(verified && result.complete', 'ctx.ui.t(verified'),
  f7_missing_block: (s) => s.replaceAll('{ block: ctx.blockNum }', '{}'),
  g1_no_selection: (s) => s.replace('await runSelectionReusable({ ...ctx, report }, sessions)', '({ stop: false })')
    .replace("selectionChecks.some((e) => e.id === 'check.stageB.playersMatch' && e.status === 'pass')", 'true'),
  g2_players_only: (s) => s.replace("selectionChecks.every((e) => e.status === 'pass')", 'true'),
  g3_ignore_stop: (s) => s.replace('!selection?.stop', 'true'),
  g4_find_after_selection: (s) => s.replace('const result = reused || stageAVerified ? await findEntry(ctx, uid, stageAVerified) : initial;',
    'let result = { included: true, complete: true };')
    .replace("  ctx.ui.section?.(ctx.ui.t('entry.sectionResult'));\n  if (reused)",
      "  result = reused || stageAVerified ? await findEntry(ctx, uid, stageAVerified) : initial;\n  ctx.ui.section?.(ctx.ui.t('entry.sectionResult'));\n  if (reused)"),
  g5_select_absent: (s) => s.replace('verified && result.included && result.complete', 'verified && result.complete'),
  g6_pending_verified: (s) => s.replace('verified = !selection?.stop', 'verified = selection?.stop || !selection?.stop'),
  r1_save_failed: (s) => s.replace('if (passed && ctx.data.gameSelection)', 'if (ctx.data.gameSelection)'),
  r2_ignore_selection: (s) => s.replace('hashLikeBackend(current.data) === saved.selectionHash', 'true'),
  r3_ignore_inputs: (s) => s.replace('isDeepStrictEqual(inputs, saved.inputs)', 'true'),
  r4_noninteractive: (s) => 'const unintendedSessions = new Map();\n' + s.replace(
    'if (!sessions || ctx.cfg.nonInteractive) return runSelection(ctx);', 'sessions ||= unintendedSessions;'),
  r5_no_checks: (s) => s.replace('ctx.report[method](...args);\n      Object.assign',
    "{ if (method !== 'check') ctx.report[method](...args); }\n      Object.assign"),
  r6_keep_indexes: (s) => s.replace('Object.assign(ctx.data, replay.data);',
    'delete replay.data.infos; delete replay.data.entryFileHashes; Object.assign(ctx.data, replay.data);'),
  // index.jsだけの変異は下の実main用モジュールへ適用する。
  r7_menu1_direct: (s) => s + '\n// r7_menu1_direct\n',
  r8_reuse_in_fingerprint: (s) => s.replace("const names = ['applicantHash'", "const names = ['reuseFiles', 'applicantHash'"),
  r9_ignore_current_reuse: (s) => s.replace('if (saved && ctx.data.reuseFiles && saved.chain === ctx.chain',
    'if (saved && saved.chain === ctx.chain'),
  M2_no_replay_section: (s) => s.replace('      ctx.ui.section?.();\n', ''),
  M16_no_result_clone: (s) => s.replace('return replay.result;', 'return saved.result;'),
};
let currentSource = source;
if (mutation) {
  assert.ok(mutations[mutation], '既知の変異');
  currentSource = mutations[mutation](source);
  assert.notEqual(currentSource, source, '変異を適用');
}
function moduleUrl(s) {
  const absolute = s.replace(/from '([^']+)'/g, (_, p) =>
    `from '${p.startsWith('.') ? new URL(p, sourceUrl).href : import.meta.resolve(p)}'`);
  return `data:text/javascript;base64,${Buffer.from(absolute).toString('base64')}`;
}
const { parseEntryUid, findEntry, runEntriesReusable, runSelectionReusable, verifyOwnEntry } = await import(moduleUrl(currentSource));
const { findEntry: baseFindEntry } = await import(moduleUrl(baseSource));
// importまで成功してから印を出す。起動・構文エラーは変異検出に数えない。
if (mutation) console.log(`MUTATION_APPLIED ${mutation}`);

let assertions=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);assertions++;};
const ok = (value, label) => { assert.ok(value, label); assertions++; };
const infoKey = (slot, block = 17) => `entries/block${block}/info/${slot}_info.json`;
const bodyKey = (name, block = 17) => `entries/block${block}/entries/${name}.json`;
function recordR2(r2) {
  const calls = [], events = [];
  const fetchJson = r2.fetchJson.bind(r2), release = r2.release?.bind(r2);
  r2.fetchJson = async (key, options) => {
    calls.push([key, structuredClone(options)]);
    events.push(['fetch', key, structuredClone(options)]);
    return fetchJson(key, options);
  };
  r2.release = (key) => { events.push(['release', key]); release?.(key); };
  return { calls, events };
}
function fixtureContext(files, data = {}, blockNum = 17) {
  const r2 = { fetchJson: async (key) => files.has(key) ? { data: structuredClone(files.get(key)) } : null };
  return { ctx: { blockNum, data: structuredClone(data), r2 }, ...recordR2(r2) };
}
function verifiedFixture(change = () => {}) {
  const files = new Map();
  for (let i = 0; i < 100; i++) files.set(infoKey(String(i).padStart(2, '0')), { entries: [] });
  files.set(infoKey('12'), { entries: [{ filename: '12_2', number: 1 }, { filename: '12_0', number: 1 }] });
  files.set(bodyKey('12_2'), [{ uid: '5678' }]);
  files.set(bodyKey('12_0'), [{ uid: '1234' }]);
  files.set(infoKey('83'), { entries: [{ filename: '83_1', number: 1 }] });
  files.set(bodyKey('83_1'), [{ uid: '7777' }]);
  const data = {
    infos: Array.from({ length: 100 }, (_, i) => structuredClone(files.get(infoKey(String(i).padStart(2, '0'))))),
    entryFileHashes: new Map(['12_2', '12_0', '83_1'].map((name) => [name, hashLikeBackend(files.get(bodyKey(name)))])),
  };
  change(files, data);
  return { files, data };
}
async function observedFind(reader, files, data, uid, verified) {
  const tracked = fixtureContext(files, data);
  let result;
  try { result = await reader(tracked.ctx, uid, verified); }
  catch (error) { result = { error: error.message, name: error.name }; }
  return { result, calls: tracked.calls, events: tracked.events };
}

// I1: 起点の実装と、鍵・順序・全引数・解放・戻り値・例外を比較する。
for (const [label, uid, change] of [
  ['存在', '1234', () => {}],
  ['不在', '9999', () => {}],
  ['置き場の外に存在', '7777', () => {}],
  ['info欠落', '1234', (files) => files.delete(infoKey('12'))],
  ['info非配列', '1234', (files) => files.set(infoKey('12'), { entries: {} })],
  ['本体欠落', '1234', (files) => files.delete(bodyKey('12_2'))],
  ['本体非配列', '1234', (files) => files.set(bodyKey('12_2'), {})],
  ['Stage Aの一覧と不一致', '1234', (_files, data) => { data.infos[12] = { entries: [] }; }],
  ['Stage Aのhashと不一致', '1234', (files) => files.set(bodyKey('12_0'), [{ uid: '9999' }])],
  ['不正filename', '1234', (files, data) => {
    files.get(infoKey('12')).entries.push({ filename: '../83_1', number: 1 });
    data.infos[12] = structuredClone(files.get(infoKey('12')));
  }],
  ['infoの番号と異なる本体も探す', '1234', (files, data) => {
    files.get(infoKey('12')).entries = [{ filename: '83_1', number: 1 }];
    data.infos[12] = structuredClone(files.get(infoKey('12')));
  }],
]) {
  const { files, data } = verifiedFixture(change);
  const before = await observedFind(baseFindEntry, files, data, uid, true);
  const after = await observedFind(findEntry, files, data, uid, true);
  eq(after, before, `I1 Yes/${label}: 起点と全動作が一致`);
}
{
  const { files, data } = verifiedFixture();
  const yes = await observedFind(findEntry, files, data, '1234', true);
  const expectedKeys = [];
  for (let i = 0; i < 100; i++) {
    expectedKeys.push(infoKey(String(i).padStart(2, '0')));
    if (i === 12) expectedKeys.push(bodyKey('12_2'), bodyKey('12_0'));
    if (i === 83) expectedKeys.push(bodyKey('83_1'));
  }
  eq(yes.calls, expectedKeys.map((key) => [key, { reuse: true, cacheOnly: true }]), 'I1: Yesの鍵と順序を固定');
  eq(yes.result, { included: true, complete: true }, 'I1: Yesの戻り値の形');
}

// I2/I3: 期待する置き場は定数で固定し、正典と同じ境界を実際の取得鍵で確認する。
eq(parseEntryUid('18446744073709551615'), '18446744073709551615', 'I3: 20桁のuidを精度を落とさず受理');
for (const [uid, slot] of [['1275295862265012224', '22'], ['18446744073709551615', '16'], ['1234', '12'], ['123', '01'],
  ['7', '00'], ['10000', '00'], ['99', '00']]) {
  const files = new Map([
    [infoKey(slot), { entries: [{ filename: `${slot}_9` }, { filename: `${slot}_0` }] }],
    [bodyKey(`${slot}_9`), [null, {}, { uid: 'unrelated' }]],
    [bodyKey(`${slot}_0`), [{ uid }]],
    [infoKey('98'), { entries: [{ filename: '98_0' }] }],
    [bodyKey('98_0'), [{ uid }]],
  ]);
  const no = await observedFind(findEntry, files, {}, uid, false);
  const keys = [infoKey(slot), bodyKey(`${slot}_9`), bodyKey(`${slot}_0`)];
  eq(no.calls, keys.map((key) => [key, { reuse: true, cacheOnly: false }]), `I2/I3 uid=${uid}: この置き場だけ読む`);
  eq(no.events, keys.flatMap((key) => [['fetch', key, { reuse: true, cacheOnly: false }], ['release', key]]), `I2 uid=${uid}: 読んだら解放する`);
  eq(no.result, { included: true, complete: true }, `I4 uid=${uid}: 存在`);
}
// I4: 失敗や不正な行が混ざっても、正しい本体の走査を続ける。
for (const [label, change, included, complete, bodies] of [
  ['不在', (files) => files.set(bodyKey('12_0'), []), false, true, ['12_2', '12_0']],
  ['数値uidも一致', (files) => files.set(bodyKey('12_0'), [{ uid: 1234 }]), true, true, ['12_2', '12_0']],
  ['空の一覧', (files) => files.set(infoKey('12'), { entries: [] }), false, true, []],
  ['info欠落', (files) => files.delete(infoKey('12')), false, false, []],
  ['infoがnull', (files) => files.set(infoKey('12'), null), false, false, []],
  ['info非配列', (files) => files.set(infoKey('12'), { entries: {} }), false, false, []],
  ['本体欠落', (files) => files.delete(bodyKey('12_2')), true, false, ['12_2', '12_0']],
  ['本体非配列', (files) => files.set(bodyKey('12_2'), {}), true, false, ['12_2', '12_0']],
  ['発見後も本体を読む', (files) => { files.set(bodyKey('12_2'), [{ uid: '1234' }]); files.delete(bodyKey('12_0')); }, true, false, ['12_2', '12_0']],
  ['発見後の不一致本体でも存在を保持', (files) => {
    files.get(infoKey('12')).entries = [{ filename: '12_0', number: 1 }, { filename: '12_2', number: 1 }];
  }, true, true, ['12_0', '12_2']],
  ['別の接頭辞', (files) => files.get(infoKey('12')).entries.unshift({ filename: '83_1' }), true, false, ['12_2', '12_0']],
  ['不正filename', (files) => files.get(infoKey('12')).entries.unshift(...['12_x', '12_0.json', '../12_0', '12_0/other', '112_0', '12_', '12_0x'].map((filename) => ({ filename })), null, {}), true, false, ['12_2', '12_0']],
]) {
  const { files } = verifiedFixture(change);
  const no = await observedFind(findEntry, files, {}, '1234', false);
  eq(no.result, { included, complete }, `I4 No/${label}`);
  eq(no.calls, [infoKey('12'), ...bodies.map((name) => bodyKey(name))].map((key) => [key, { reuse: true, cacheOnly: false }]), `I2 No/${label}: 他の鍵は読まない`);
}
{
  const { files, data } = verifiedFixture((files) => {
    files.set(bodyKey('12_0'), []);
    files.set(bodyKey('83_1'), [{ uid: '1234' }]);
  });
  for (const name of ['12_0', '83_1']) data.entryFileHashes.set(name, hashLikeBackend(files.get(bodyKey(name))));
  const no = await observedFind(findEntry, files, data, '1234', false);
  eq(no.result, { included: false, complete: true }, 'I5: 置き場の外の本人はNoで見つからない');
  eq(no.calls.map(([key]) => key), [infoKey('12'), bodyKey('12_2'), bodyKey('12_0')], 'I5: Noは外のinfoも本体も読まない');
  const yes = await observedFind(findEntry, files, data, '1234', true);
  eq(yes.result, { included: true, complete: true }, 'I5: 同じデータの外の本人をYesで発見');
}

// SLOTのI6を維持し、FLOWのI1/I3〜I6: 自動確認→質問→未完了の結論を固定する。
for (const lang of SUPPORTED_LANGS) for (const verifyAll of [false, true]) {
  for (const [label, entries, body, included, complete, message] of [
    ['存在', [{ filename: '12_0' }], [{ uid: '1234' }], true, true, 'entry.included'],
    ['不在', [{ filename: '12_0' }], [], false, true, 'entry.absent'],
    ['不明', [{ filename: '12_0' }], undefined, false, false, 'entry.unknown'],
    ['一覧欠落', undefined, undefined, false, false, 'entry.unknown'],
    ['存在するが一部欠落', [{ filename: '12_0' }, { filename: '12_1' }], [{ uid: '1234' }], true, false, 'entry.included'],
  ]) {
    const files = new Map();
    if (entries) files.set(infoKey('12'), { entries });
    if (body) files.set(bodyKey('12_0'), body);
    const tracked = fixtureContext(files), keys = [], lines = [], prompts = [];
    const translate = t(lang);
    Object.assign(tracked.ctx, {
      cfg: {}, report: createReport(),
      chain: { getApplicantHash: async () => null, applicantRegistrationCount: async () => 0 },
      ui: {
        t: (key, params) => { keys.push(key); return translate(key, params); },
        println: (line) => lines.push(line), section() {},
        askYesNo: async (key) => {
          eq(lines, [translate(message, { block: tracked.ctx.blockNum }), translate('entry.onchainUnchecked')], 'FLOW I1/I5/I6: 質問前に確認全文を表示');
          eq(tracked.calls, [infoKey('12'), ...(entries ? [bodyKey('12_0'), ...(entries.length === 2 ? [bodyKey('12_1')] : [])] : [])]
            .map((name) => [name, { reuse: true, cacheOnly: false }]), 'FLOW I1: 質問前はこの置き場だけ');
          prompts.push(key); return verifyAll;
        },
      },
    });
    eq(await verifyOwnEntry(tracked.ctx, '1234', new Map()), { included, complete, verified: false }, `I6 ${lang}/${verifyAll}/${label}: 戻り値の全欄`);
    eq(prompts, ['entry.verifyAll'], 'I6: 質問の鍵');
    eq(keys.filter((key) => key.startsWith('entry.')), ['entry.sectionResult', message, 'entry.onchainUnchecked', 'entry.sectionVerify',
      ...(verifyAll ? ['entry.sectionResult', 'entry.verifyFailed'] : [])], 'FLOW I5: 表示の鍵と順序');
    eq(lines.slice(0, 2), [translate(message, { block: tracked.ctx.blockNum }), translate('entry.onchainUnchecked')], 'I6: 表示の全文');
    if (verifyAll) eq(lines.at(-1), translate('entry.verifyFailed'), 'FLOW I2: Stage A未完了は失敗の結論');
    eq(tracked.calls, [infoKey('12'), ...(entries ? [bodyKey('12_0'), ...(entries.length === 2 ? [bodyKey('12_1')] : [])] : [])]
      .map((key) => [key, { reuse: true, cacheOnly: false }]), 'I2/I6: NoまたはStage A未完了なら置き場だけ');
  }
}

// FLOW: 文面は実装の翻訳から生成せず、依頼書と保持対象の全文を固定する。
const flowTexts = {
  en: {
    'entry.verifyAll': 'Download all of this public entry data and verify that it was used for the lottery?',
    'entry.onchainIncluded': 'Also verified that the public entry data containing your entry was used for the lottery. Your entry is therefore guaranteed to have taken part in the lottery.',
    'entry.verifyFailed': 'Could not verify that this public entry data was used for the lottery.',
    'entry.included': 'Confirmed that your entry is included in the public entry data of block 17.',
    'entry.onchainUnchecked': '(However, it has not been verified that this public data was used for the lottery.)',
  },
  ja: {
    'entry.verifyAll': 'この公開応募データを全てダウンロードして抽選に使われたデータであることを検証しますか？',
    'entry.onchainIncluded': 'あなたの応募が含まれていた公開応募データが抽選に使われていることも検証しました。よってあなたの応募は抽選に参加していることが保証されます。',
    'entry.verifyFailed': 'この公開応募データが抽選に使われていることは検証できませんでした。',
    'entry.included': 'ブロック17の公開応募データにあなたの応募が含まれていることを確認しました。',
    'entry.onchainUnchecked': '(ただし、この公開データが抽選に使われていることは検証していません。)',
  },
  zh: {
    'entry.verifyAll': '要下载此公开报名数据的全部内容并验证它确实用于抽选吗？',
    'entry.onchainIncluded': '还验证了包含您报名的公开报名数据确实用于抽选。因此可以保证您的报名参加了抽选。',
    'entry.verifyFailed': '无法验证此公开报名数据确实用于抽选。',
    'entry.included': '已确认区块 17 的公开报名数据中包含您的报名。',
    'entry.onchainUnchecked': '(但尚未验证该公开数据确实用于抽选。)',
  },
};
for (const lang of SUPPORTED_LANGS) for (const [key, expected] of Object.entries(flowTexts[lang])) {
  eq(t(lang)(key, { block: 17 }), expected, `FLOW I6 ${lang}/${key}: 翻訳の全文`);
}

// FLOW2 I5: 前便の3言語・entry.* 42行の鍵と文を丸ごと固定する。
const entryCatalog = readFileSync(new URL('../src/i18n.js', import.meta.url), 'utf8')
  .match(/^  ["']entry\..*$/gm);
eq(entryCatalog.length, 42, 'FLOW2 I5: 3言語のentry.*の鍵数');
eq(createHash('sha256').update(entryCatalog.join('\n')).digest('hex'),
  '00dc0a32bf03a3b888615c00d8d6bc2f95576d9ffafa1ee7d3e1fcb30f8b6482', 'FLOW2 I5: 前便の全entry.*の鍵と文を保持');
const allCatalog = readFileSync(new URL('../src/i18n.js', import.meta.url), 'utf8').match(/^  ["'].*$/gm);
eq(allCatalog.length, 1425, 'REUSE R5: Stage3RUN-FIX3更新後とまとめの⓪の12文・FIX1の21文・enのrandomness・FIX2の3文とzhの公示中見出しを含む全言語の鍵数');
eq(createHash('sha256').update(allCatalog.join('\n')).digest('hex'),
  'aa63bad50e1c948698835f3d120352b620d82209625186f696f5b9063fc05882', 'REUSE R5: Stage3RUN-FIX3の保存文・一致時の結論と、メニュー1・2の項目名（2026-11-20 ユーザーの文）とまとめの⓪の12文・FIX1の21文・enのrandomness・FIX2の3文（分配データまたは採用表の照合が不合格の言い回し）とzhの公示中見出しを反映した全文');
ok(!/\b(?:runGrouping|runResults)\s*\(/.test(currentSource), 'FLOW2 I2: グループ分けとStage Cは呼ばない');

// Stage A/Bの結果だけ代役。再利用・入力再確認・配線・findEntry・表示は実関数を通す。
const flow = await import(moduleUrl(currentSource
  .replace("import { run as runEntries } from './stages/entries.js';", 'const runEntries = async (ctx) => ctx.flowRunEntries();')
  .replace("import { run as runSelection } from './stages/selection.js';", 'const runSelection = async (ctx) => ctx.flowRunSelection(ctx);')));
const flowCases = [
  { label: '通る・含まれる' },
  { label: '通る・含まれない', final: 'absent' },
  { label: 'Stage Aが通らない', stageFail: true },
  { label: '配線が違う', wiring: 'mismatch' },
  { label: '配線の読みの例外', wiring: 'error' },
  { label: '本人の検証済み本体が欠落', final: 'missing-own' },
  { label: '本人は発見・別の検証済み本体が欠落', final: 'missing-other' },
  { label: '検証済み一覧が差し替わる', final: 'changed-info' },
  { label: '最初は不在・検証済み写しでは別置き場に存在', initial: 'absent', final: 'outside-slot' },
  { label: '最初は不明・検証済み写しでは存在', initial: 'unknown' },
  { label: '保存結果のチェーン登録が変わった', invalidSaved: true },
  ...['pending', 'selectionPresent-fail', 'randao-fail', 'playersMatch-fail', 'entryPeriodEndField-warn',
    'randao-skip', 'stop-all-pass', 'throw-before-checks', 'throw-after-pass', 'missing-players',
    'no-checks', 'warn-overwritten-pass', 'stale-fail', 'unrelated-warning']
    .map((selection) => ({ label: `抽選/${selection}`, selection })),
];
for (const lang of SUPPORTED_LANGS) for (const path of ['N', 'Y', 'A']) {
  const cases = path === 'N' ? [
    { label: '存在' }, { label: '不在', initial: 'absent' }, { label: '不明', initial: 'unknown' },
  ] : flowCases.filter((sample) => path !== 'A' || (!sample.stageFail && !sample.invalidSaved));
  for (const sample of cases) {
    const label = `FLOW ${lang}/${path}/${sample.label}`;
    const canonical = verifiedFixture();
    const initialFiles = structuredClone(canonical.files);
    if (sample.initial === 'absent') initialFiles.set(bodyKey('12_0'), []);
    if (sample.initial === 'unknown') initialFiles.delete(infoKey('12'));
    if (sample.final === 'absent' || sample.final === 'outside-slot') canonical.files.set(bodyKey('12_0'), []);
    if (sample.final === 'outside-slot') canonical.files.set(bodyKey('83_1'), [{ uid: '1234' }]);
    for (const [name] of canonical.data.entryFileHashes) canonical.data.entryFileHashes.set(name, hashLikeBackend(canonical.files.get(bodyKey(name))));
    const finalFiles = structuredClone(canonical.files);
    if (sample.final === 'missing-own') finalFiles.delete(bodyKey('12_0'));
    if (sample.final === 'missing-other') finalFiles.delete(bodyKey('83_1'));
    if (sample.final === 'changed-info') finalFiles.set(infoKey('12'), { entries: [] });

    const translate = t(lang), keys = [], translations = [], output = [], events = [], prompts = [];
    const storage = '0x' + '11'.repeat(20), sessions = new Map();
    let stageCalls = 0, selectionCalls = 0, wiringCalls = 0, finalLookup = false, registrationHash = 'original';
    const chain = {
      applicantRegistrationCount: async () => 0,
      getApplicantHash: async () => ({ hash: registrationHash }),
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
      hashStorageAddress: async () => {
        wiringCalls++; finalLookup = true; events.push(['wiring']);
        if (sample.wiring === 'error') throw new Error('temporary RPC failure');
        return sample.wiring === 'mismatch' ? '0x' + '22'.repeat(20) : storage;
      },
    };
    const ctx = {
      blockNum: 17, cfg: { contracts: { hashStorage: storage } }, chain,
      report: createReport(), data: { reuseFiles: true },
      r2: { baseDir: '/flow-fixture', fetchJson: async (key, opts) => {
        events.push(['fetch', key, structuredClone(opts)]);
        const files = opts.cacheOnly === false ? initialFiles : finalLookup ? finalFiles : canonical.files;
        return files.has(key) ? { data: structuredClone(files.get(key)) } : null;
      } },
      ui: {
        t: (key, params) => { keys.push(key); translations.push([key, params]); return translate(key, params); },
        section: (line) => output.push(['section', line]), println: (line) => output.push(['line', line]),
        askYesNo: async (key) => {
          prompts.push(key); keys.push(`ask:${key}`); events.push(['ask', key]);
          return path === 'Y';
        },
      },
      flowRunEntries: async () => {
        stageCalls++; events.push(['stageA']);
        ctx.ui.println(ctx.ui.t('stageA.start', { n: 17 }));
        await ctx.r2.fetchJson(infoKey('00'), { reuse: ctx.data.reuseFiles });
        for (const id of ['rootMatch', 'earlyFreeze']) ctx.report.check(`check.stageA.${id}`, sample.stageFail ? 'fail' : 'pass');
        Object.assign(ctx.data, structuredClone(canonical.data));
        return { stop: !!sample.stageFail };
      },
      flowRunSelection: async (selectionCtx) => {
        selectionCalls++; events.push(['selection']);
        ok(ctx.data.infos !== null && ctx.data.entryFileHashes instanceof Map, `${label}: FLOW2 I3 抽選開始時に索引が残る`);
        const report = selectionCtx.report;
        if (sample.selection === 'throw-before-checks') throw new Error('selection unavailable');
        let stop = false;
        if (sample.selection !== 'no-checks') {
          for (const id of ['selectionPresent', 'randao', 'entryPeriodEndField', 'playersMatch']) {
            if (id === 'playersMatch' && sample.selection === 'missing-players') continue;
            const status = sample.selection === `${id}-fail` ? 'fail'
              : sample.selection === `${id}-warn` || (id === 'randao' && sample.selection === 'warn-overwritten-pass') ? 'warn'
              : sample.selection === `${id}-skip` || (id === 'selectionPresent' && sample.selection === 'pending') ? 'skip' : 'pass';
            report.check(`check.stageB.${id}`, status);
            if (sample.selection === 'pending' || sample.selection === 'selectionPresent-fail') { stop = true; break; }
          }
          if (sample.selection === 'warn-overwritten-pass') report.check('check.stageB.randao', 'pass');
          if (sample.selection === 'unrelated-warning') report.check('fact.other', 'warn');
        }
        // 実物のrunと同じ破棄を行い、後からfindEntryしても合格できないようにする。
        ctx.data.infos = null; ctx.data.entryFileHashes = null;
        if (sample.selection === 'throw-after-pass') throw new Error('selection interrupted');
        return { stop: stop || sample.selection === 'stop-all-pass' };
      },
    };
    const reads = recordR2(ctx.r2);
    if (path === 'A' || sample.invalidSaved) {
      await flow.runEntriesReusable(ctx, sessions);
      eq(sessions.size, 1, `${label}: 実際の保存結果を準備`);
      if (sample.invalidSaved) registrationHash = 'changed';
      ctx.report = createReport(); ctx.data = { reuseFiles: true };
      keys.length = translations.length = output.length = events.length = reads.calls.length = reads.events.length = 0;
      stageCalls = 0;
    }
    // reportは同じidを上書きする。以前のpass/failやグループ分けのwarnは今回の抽選に混ぜない。
    ctx.report.check('check.stageB.playersMatch', 'pass');
    ctx.report.check('check.stageB.groupsMatch', 'warn');
    if (sample.selection === 'stale-fail') ctx.report.check('check.stageB.randao', 'fail');
    const result = await flow.verifyOwnEntry(ctx, '1234', sessions);
    const initial = { included: !sample.initial, complete: sample.initial !== 'unknown' };
    const final = {
      included: !['absent', 'missing-own', 'changed-info'].includes(sample.final),
      complete: !['missing-own', 'missing-other', 'changed-info'].includes(sample.final),
    };
    const stagePassed = path !== 'N' && !sample.stageFail;
    const selectionExpected = stagePassed && !sample.wiring && final.included && final.complete;
    const selectionPassed = !sample.selection || ['stale-fail', 'unrelated-warning'].includes(sample.selection);
    const verified = stagePassed && !sample.wiring && (!final.included || final.complete && selectionPassed);
    eq(result, { ...(stagePassed ? final : initial), verified }, `${label}: I4 戻り値の全欄`);
    eq(prompts, path === 'A' ? [] : ['entry.verifyAll'], `${label}: I3 質問回数と鍵`);
    eq(stageCalls, path === 'Y' ? 1 : 0, `${label}: I1/I3 Stage A実行回数`);
    eq(selectionCalls, selectionExpected ? 1 : 0, `${label}: FLOW2 I2/I6 抽選はincludedかつcompleteかつ前提通過時だけ1回`);
    eq(wiringCalls, stagePassed ? 1 : 0, `${label}: I2 今の配線を1回読む`);
    eq(ctx.report.get('check.system.hashStorageWiring')?.status ?? null,
      !stagePassed || sample.wiring === 'error' ? null : sample.wiring === 'mismatch' ? 'fail' : 'pass', `${label}: I2 配線の判定`);
    eq(ctx.report.get('check.system.auditUnavailable')?.status ?? null,
      stagePassed && sample.wiring === 'error' ? 'warn' : null, `${label}: I2 読取例外はWARN`);

    const initialMessage = initial.included ? 'entry.included' : initial.complete ? 'entry.absent' : 'entry.unknown';
    const finalMessage = final.included ? 'entry.included' : final.complete ? 'entry.absent' : 'entry.unknown';
    const conclusion = verified && final.complete ? final.included ? 'entry.onchainIncluded' : 'entry.onchainAbsent' : 'entry.verifyFailed';
    const expectedKeys = path === 'A'
      ? ['entry.sectionVerify', 'entry.reused', 'entry.sectionResult', finalMessage, conclusion]
      : ['entry.sectionResult', initialMessage, 'entry.onchainUnchecked', 'entry.sectionVerify', 'ask:entry.verifyAll',
        ...(path === 'Y' ? ['stageA.start', 'entry.sectionResult', conclusion] : [])];
    eq(keys, expectedKeys, `${label}: I5 表示と質問・Stage Aの鍵の順序`);
    const expectedOutput = path === 'A'
      ? [['section', translate('entry.sectionVerify')], ['line', translate('entry.reused')],
        ['section', translate('entry.sectionResult')], ['line', translate(finalMessage, { block: 17 })], ['line', translate(conclusion)]]
      : [['section', translate('entry.sectionResult')], ['line', translate(initialMessage, { block: 17 })],
        ['line', translate('entry.onchainUnchecked')], ['section', translate('entry.sectionVerify')],
        ...(path === 'Y' ? [['line', translate('stageA.start', { n: 17 })],
          ['section', translate('entry.sectionResult')], ['line', translate(conclusion)]] : [])];
    eq(output, expectedOutput, `${label}: I5/I6 表示の全文と行数`);
    eq(output.some(([, line]) => line === flowTexts[lang]['entry.onchainIncluded']),
      path !== 'N' && verified && final.included && final.complete, `${label}: I2 保証の文の必要条件`);
    for (const [key, params] of translations.filter(([key]) => key === 'entry.included')) {
      eq(params, { block: 17 }, `${label}: I6 block引数`);
      eq(translate(key, params), flowTexts[lang][key], `${label}: I6 現在ブロックの全文（-にならない）`);
    }
    const publicReads = [infoKey('12'), ...(sample.initial === 'unknown' ? [] : [bodyKey('12_2'), bodyKey('12_0')])]
      .map((key) => [key, { reuse: true, cacheOnly: false }]);
    if (path !== 'A') {
      const atAsk = events.findIndex(([kind]) => kind === 'ask');
      eq(events.slice(0, atAsk), publicReads.map(([key, opts]) => ['fetch', key, opts]), `${label}: I1 質問前は置き場の一覧1個と同じ置き場の本体のみ`);
      if (path === 'Y') ok(events.findIndex(([kind]) => kind === 'stageA') > atAsk, `${label}: I1 Stage Aは質問後`);
    }
    if (!stagePassed) eq(reads.calls.filter(([, opts]) => opts.cacheOnly === true), [], `${label}: I4 Stage A失敗/Nでは検証済み写しを走査しない`);
    else {
      const atWiring = events.findIndex(([kind]) => kind === 'wiring');
      const atSelection = events.findIndex(([kind]) => kind === 'selection');
      const finalReads = events.slice(atWiring + 1, atSelection < 0 ? undefined : atSelection).filter(([kind]) => kind === 'fetch');
      const expected = [];
      for (let i = 0; i < 100; i++) {
        expected.push(infoKey(String(i).padStart(2, '0')));
        if (i === 12 && sample.final !== 'changed-info') expected.push(bodyKey('12_2'), bodyKey('12_0'));
        if (i === 83) expected.push(bodyKey('83_1'));
      }
      eq(finalReads, expected.map((key) => ['fetch', key, { reuse: true, cacheOnly: true }]), `${label}: I2/I4 最後は検証済み写しだけを全走査`);
      if (selectionExpected) {
        eq(events.slice(atSelection + 1).filter(([kind]) => kind === 'fetch'), [], `${label}: FLOW2 I3 抽選後には応募を走査しない`);
        ok(atSelection > atWiring, `${label}: FLOW2 I3 配線と検証済み走査の後で抽選`);
      }
    }
  }
}

// REUSE R2/R3/R4: 実selection.runの記録順・全事実・全data・戻り値を再現と比較する。
function selectionFixture(count = 3) {
  const hash = '0x' + '33'.repeat(32), randao = '0x' + '55'.repeat(32), targetHash = '0x' + '44'.repeat(32);
  const rows = Array.from({ length: count }, (_, i) => ({ uid: String(1234 + i) }));
  const infos = Array.from({ length: 100 }, () => ({ entries: [] }));
  if (count) infos[12].entries.push({ filename: '12_0', number: count });
  const selection = { hashRegisteredBlock: 100, confirmationBlocks: 64, targetBlockNum: 164,
    entryPeriodEnd: 1000, applicantHash: hash, targetBlockHash: targetHash, randao,
    totalEntries: count, totalSelected: count,
    players: rows.map((data, i) => ({ globalIndex: i, localIndex: i, file: '12_0', data })) };
  const data = { reuseFiles: true, applicantHash: hash, registeredBlock: 100, entryPeriodEnd: 1000,
    entriesTotal: count, infos, entryFileHashes: new Map(count ? [['12_0', hashLikeBackend(rows)]] : []),
    legacyHashStorage: false, untouched: { keep: true } };
  const state = { selection, cache: true, cacheThrows: false, targets: 0, fetches: [] };
  const cfg = { pins: { confirmationBlocks: 64, gameMaxPlayers: 2100 }, r2Base: 'https://r2.invalid' };
  const chain = { getBlock: async (n) => {
    eq(n, 164, 'REUSE: 実抽選のtarget block'); state.targets++;
    return { hash: targetHash, mixHash: randao, timestamp: 1000n };
  }, isApplicantRegistered: async () => false };
  const context = () => {
    const report = createReport(), trace = [], output = [], keys = [];
    for (const id of ['rootMatch', 'earlyFreeze']) report.check(`check.stageA.${id}`, 'pass');
    // 上書き・事実の既存値も、その場での実行と同じにする。
    report.check('check.stageB.randao', 'fail', { old: true });
    report.fact('randao', 'old');
    for (const method of ['check', 'fact']) {
      const original = report[method];
      report[method] = (...args) => { trace.push([method, structuredClone(args)]); original(...args); };
    }
    const r2 = { baseDir: '/selection-fixture', release() {}, fetchJson: async (key, opts) => {
      state.fetches.push([key, structuredClone(opts)]);
      if (key.endsWith('/game_selection.json')) {
        if (opts.cacheOnly && state.cacheThrows) throw new Error('unreadable cache');
        return opts.cacheOnly && !state.cache ? null : { data: structuredClone(state.selection) };
      }
      eq(key, bodyKey('12_0'), 'REUSE: 当選者の実データ読取');
      return { data: structuredClone(rows) };
    }, refetch: async () => ({ data: structuredClone(rows) }) };
    const ctx = { blockNum: 17, cfg: structuredClone(cfg), chain, r2, report, data: structuredClone(data),
      ui: { t: (key, params) => { keys.push(key); return t('ja')(key, params); },
        section: (line) => output.push(['section', line]), println: (line) => output.push(['line', line]) } };
    return { ctx, trace, output, keys };
  };
  return { context, state };
}
for (const count of [0, 1, 2, 3]) {
  const { context, state } = selectionFixture(count), sessions = new Map();
  const first = context(); await runSelectionReusable(first.ctx, sessions);
  ok([...sessions.values()][0]?.selection, `R2/${count}: 合格抽選を保存`);
  const replay = context(), beforeTargets = state.targets, beforeFetches = state.fetches.length;
  const result = await runSelectionReusable(replay.ctx, sessions);
  eq(state.targets, beforeTargets, `R1/${count}: 抽選のチェーン読取は増えない`);
  eq(state.fetches.slice(beforeFetches), [[`entries/block17/game_selection.json`, { reuse: true, cacheOnly: true }]],
    `R1/${count}: 使い回しは抽選の手元の写しだけ確認`);
  eq(replay.keys, ['stageB.selStart'], `R2/${count}: 既存の見出しだけ保ち、抽選途中の行・新しい文を出さない`);
  const fresh = context(), freshResult = await realSelection(fresh.ctx);
  eq(replay.output, [['section', undefined], ['line', t('ja')('stageB.selStart', { n: 17 })]],
    `R2/${count}: 使い回しも区切りと見出しをこの順で1回ずつ出す`);
  eq(replay.output, fresh.output.slice(0, 2), `R2/${count}: 区切り・見出しは実runと同じ`);
  eq(result, freshResult, `R2/${count}: 戻り値の全欄`);
  eq(replay.trace, fresh.trace, `R2/${count}: check/factの引数と混ざった記録順の全体`);
  eq(replay.ctx.report.list(), fresh.ctx.report.list(), `R2/${count}: 上書きを含め全検査のid/status/params`);
  eq(replay.ctx.data, fresh.ctx.data, `R2/${count}: 欠けた欄・null・Mapも含め全data`);
  eq([replay.ctx.data.infos, replay.ctx.data.entryFileHashes], [null, null], `R2/${count}: 索引を解放`);
  const factNames = fresh.trace.filter(([method]) => method === 'fact').map(([, [name]]) => name);
  eq(factNames, ['targetBlockNum', 'targetBlockTime', 'randao', 'selectionSeed', 'totalSelected'], `R2/${count}: 実物の全5事実`);
  for (const name of factNames) eq(replay.ctx.report.getFact(name), fresh.ctx.report.getFact(name), `R2/${count}/${name}: 事実`);
  for (const sample of [replay, fresh]) { sample.output.length = 0; sample.ctx.report.renderSummary(sample.ctx.ui, sample.ctx); }
  eq(replay.output, fresh.output, `R2/${count}: 記録から決まるまとめの全文`);
  // 復元先の変更で保存済み結果を壊さない。
  result.stop = true;
  result.callerOnly = { changed: true };
  replay.ctx.data.gameSelection.randao = 'changed';
  replay.ctx.report.get('check.stageB.playersMatch').params.count = -1;
  const again = context(), againResult = await runSelectionReusable(again.ctx, sessions);
  eq(againResult, freshResult, `R2/${count}: 返却値の変更で次の返却値を壊さない`);
  eq(again.ctx.data, fresh.ctx.data, `R2/${count}: 保存値は復元先と独立`);
  eq(again.trace, fresh.trace, `R2/${count}: 記録のparamsも保存値と独立`);
}

// 戻り値がdataを指す場合も、複製内の参照を保ち、保存値から切り離す。
{
  const { context, state } = selectionFixture(), sessions = new Map();
  let calls = 0;
  const run = async (ctx) => {
    calls++;
    ctx.data.gameSelection = structuredClone(state.selection);
    ctx.data.players = ctx.data.gameSelection.players;
    ctx.data.infos = null; ctx.data.entryFileHashes = null;
    ctx.report.check('check.stageB.playersMatch', 'pass', { count: ctx.data.players.length });
    return { stop: false, selection: ctx.data.gameSelection, players: ctx.data.players };
  };
  const first = context(); first.ctx.flowRunSelection = run;
  const initialResult = await flow.runSelectionReusable(first.ctx, sessions);
  const expectedResult = structuredClone(initialResult), expectedData = structuredClone(first.ctx.data);
  initialResult.stop = true; initialResult.players[0].data.uid = 'first-caller';
  for (let attempt = 0; attempt < 2; attempt++) {
    const replay = context(); replay.ctx.flowRunSelection = run;
    const result = await flow.runSelectionReusable(replay.ctx, sessions);
    eq(calls, 1, `R2/参照/${attempt}: 実runを追加しない`);
    eq(result, expectedResult, `R2/参照/${attempt}: 呼び出し側の変更から戻り値を保護`);
    eq(replay.ctx.data, expectedData, `R2/参照/${attempt}: 戻り値が指すdataも保存値と独立`);
    ok(result.selection === replay.ctx.data.gameSelection && result.players === replay.ctx.data.players
      && result.players === result.selection.players, `R2/参照/${attempt}: 戻り値とdataの参照関係を保持`);
    result.stop = true;
    result.selection.randao = 'returned-selection';
    result.players[0].data.uid = 'returned-player';
    replay.ctx.data.gameSelection.applicantHash = 'changed-through-data';
  }
}

// RU-2: 旧HashStorageでも新規取得は保存を使わず、差し替わった公開ファイルで再検証する。
{
  const { context, state } = selectionFixture(), sessions = new Map();
  const folder = mkdtempSync(join(tmpdir(), 'selection-fresh-download-'));
  const originalFetch = globalThis.fetch;
  let selectionDownloads = 0;
  globalThis.fetch = async (input) => {
    const key = new URL(input).pathname.slice(1);
    if (key === 'entries/block17/game_selection.json') {
      selectionDownloads++;
      return new Response(JSON.stringify(state.selection), { status: 200 });
    }
    eq(key, bodyKey('12_0'), 'RU-2: 抽選以外の取得は当選者の応募だけ');
    return new Response(JSON.stringify(state.selection.players.map((player) => player.data)), { status: 200 });
  };
  const freshContext = () => {
    const sample = context();
    sample.ctx.cfg.dataDir = folder;
    sample.ctx.data.reuseFiles = false;
    sample.ctx.data.legacyHashStorage = true;
    sample.ctx.r2 = createR2(sample.ctx.cfg, sample.ctx.ui, 17);
    return sample;
  };
  try {
    const first = freshContext(); await runSelectionReusable(first.ctx, sessions);
    eq(first.ctx.report.get('check.stageB.randao')?.status, 'pass', 'RU-2: 初回の公開ファイルは合格');
    ok([...sessions.values()][0]?.selection, 'RU-2: reuseFiles=falseの合格結果も保存する');
    const savedPath = join(folder, 'block17/entries/block17/game_selection.json');
    eq(JSON.parse(readFileSync(savedPath, 'utf8')), state.selection, 'RU-2: 初回の正しい写しが手元にある');
    state.selection.randao = '0x' + '66'.repeat(32);
    const next = freshContext(); await runSelectionReusable(next.ctx, sessions);
    eq([state.targets, selectionDownloads], [2, 2], 'RU-2: false→falseでも抽選を2回取得・再現する');
    eq(next.ctx.report.get('check.stageB.randao')?.status, 'fail', 'RU-2: 公開ファイル差し替え後は古い合格を出さない');
    eq(next.ctx.data.gameSelection, state.selection, 'RU-2: 新しい公開ファイルを採る');
    ok(![...sessions.values()][0]?.selection, 'RU-2: 不合格後は前の合格結果も破棄');
    const fresh = freshContext(); await realSelection(fresh.ctx);
    eq(next.trace, fresh.trace, 'RU-2: 検査・事実・記録順がその場の再現と同じ');
    eq(next.ctx.data, fresh.ctx.data, 'RU-2: 全dataがその場の再現と同じ');
  } finally { globalThis.fetch = originalFetch; rmSync(folder, { recursive: true, force: true }); }
}

const invalidReuseCases = [
  ['applicantHash', (ctx) => { ctx.data.applicantHash = '0x' + '66'.repeat(32); }],
  ['registeredBlock', (ctx) => { ctx.data.registeredBlock++; }],
  ['entryPeriodEnd', (ctx) => { ctx.data.entryPeriodEnd++; }],
  ['entriesTotal', (ctx) => { ctx.data.entriesTotal--; }],
  ['infos', (ctx) => { ctx.data.infos[0].extra = true; }],
  ['entryFileHashes', (ctx) => { ctx.data.entryFileHashes.set('12_0', 'changed'); }],
  ['legacyHashStorage', (ctx) => { ctx.data.legacyHashStorage = true; }],
  ['欄の欠落とfalse', (ctx) => { delete ctx.data.legacyHashStorage; }],
  ['reuseFiles', (ctx) => { ctx.data.reuseFiles = false; }],
  ['pins.confirmationBlocks', (ctx) => { ctx.cfg.pins.confirmationBlocks++; }],
  ['pins.gameMaxPlayers', (ctx) => { ctx.cfg.pins.gameMaxPlayers--; }],
  ['抽選ファイル変更', (_ctx, state) => { state.selection.randao = '0x' + '66'.repeat(32); }],
  ['抽選ファイルが手元に無い', (_ctx, state) => { state.cache = false; }],
  ['抽選ファイル読取不能', (_ctx, state) => { state.cacheThrows = true; }],
  ['別chain', (ctx) => { ctx.chain = { ...ctx.chain }; }],
  ...['warn', 'skip', 'fail'].map((status) => [`Stage A ${status}`, (ctx) => { ctx.report.check('check.stageA.rootMatch', status); }]),
  ['Stage A未実行', (ctx) => { ctx.report = createReport(); }],
];
for (const [label, change] of invalidReuseCases) {
  const { context, state } = selectionFixture(), sessions = new Map();
  await runSelectionReusable(context().ctx, sessions);
  const next = context(); change(next.ctx, state);
  await runSelectionReusable(next.ctx, sessions);
  eq(state.targets, 2, `R3/${label}: 使い回さず実runのチェーン読取まで通す`);
  ok(next.keys.includes('stageB.runningLottery'), `R3/${label}: 実runの抽選を再現`);
}
// 失敗を上書きしてpassにした記録や、pass後の中断も合格に数えない。
for (const failure of ['warn', 'skip', 'fail', 'overwritten', 'stop', 'throw-before', 'throw-after', 'missing-players', 'no-checks']) {
  const { context } = selectionFixture(), sessions = new Map();
  let calls = 0;
  for (let attempt = 0; attempt < 2; attempt++) {
    const { ctx } = context();
    ctx.flowRunSelection = async (stageCtx) => {
      calls++; stageCtx.data.gameSelection = { failure };
      if (failure === 'throw-before') throw new Error('before');
      if (failure !== 'no-checks') {
        stageCtx.report.check('check.stageB.randao', ['warn', 'skip', 'fail'].includes(failure) ? failure : failure === 'overwritten' ? 'warn' : 'pass');
        if (failure === 'overwritten') stageCtx.report.check('check.stageB.randao', 'pass');
        if (failure !== 'missing-players') stageCtx.report.check('check.stageB.playersMatch', 'pass');
      }
      if (failure === 'throw-after') throw new Error('after');
      return { stop: failure === 'stop' };
    };
    let thrown;
    try { await flow.runSelectionReusable(ctx, sessions); } catch (error) { thrown = error.message; }
    eq(thrown, failure.startsWith('throw-') ? failure.slice(6) : undefined, `R3/${failure}: 例外をそのまま伝える`);
    ok(![...sessions.values()].some((saved) => saved.selection), `R3/${failure}: 不合格の抽選を保存しない`);
  }
  eq(calls, 2, `R3/${failure}: 次もrunを呼ぶ`);
}
// nullは非対話mainから渡る値。Mapを渡してもcfg.nonInteractiveなら再利用しない。
for (const mode of ['null', 'non-interactive']) {
  const { context, state } = selectionFixture(), sessions = mode === 'null' ? null : new Map();
  for (let i = 0; i < 2; i++) {
    const { ctx } = context(); ctx.cfg.nonInteractive = mode === 'non-interactive';
    await runSelectionReusable(ctx, sessions);
  }
  eq(state.targets, 2, `R4/${mode}: 毎回実runを呼ぶ`);
  eq(sessions?.size ?? 0, 0, `R4/${mode}: 抽選結果を保存しない`);
}

// FLOW2 I4: index.js:760の式を写さず、実mainのメニュー3を通す。抽選は実物のrun。
const menuMembership = await import(moduleUrl(currentSource.replace("import { run as runEntries } from './stages/entries.js';", `
  const runEntries = async (ctx) => {
    globalThis.__flow2Menu.entriesCalls = (globalThis.__flow2Menu.entriesCalls || 0) + 1;
    const { reuseFiles, ...stageAData } = globalThis.__flow2Menu.data;
    Object.assign(ctx.data, structuredClone(stageAData));
    for (const id of ['rootMatch', 'earlyFreeze']) ctx.report.check('check.stageA.' + id, globalThis.__flow2Menu.stageAStatus?.() ?? 'pass');
    return { stop: false };
  };`)));
const menuSource = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8')
  .replace("import { createPrompts } from './prompts.js';", 'const createPrompts = () => globalThis.__flow2Menu.prompts;')
  .replace("import { createLocalR2, createR2 } from './r2.js';", 'const createR2 = () => globalThis.__flow2Menu.r2;')
  .replace("import { parseEntryUid, runEntriesReusable, runSelectionReusable, verifyOwnEntry } from './entry-membership.js';",
    'const { parseEntryUid, runEntriesReusable, runSelectionReusable } = globalThis.__flow2Menu.membership; const verifyOwnEntry = (...args) => globalThis.__flow2Menu.membership.verifyOwnEntry(...args);')
  .replace('const cfg = loadConfig(argv);', 'const cfg = globalThis.__flow2Menu.cfg;')
  .replace('const chain = await setupChain(cfg, ui, prompts);', 'const chain = globalThis.__flow2Menu.chain;');
globalThis.__flow2Menu = { membership: menuMembership };
const menu = await import(moduleUrl(menuSource));
for (const path of ['Y', 'A']) for (const [state, expectedExit] of [
  ['success', 0], ['absent', 0], ['pending', 1], ['selectionPresent-fail', 2],
  ['randao-fail', 2], ['playersMatch-fail', 2], ['entryPeriodEndField-warn', 1], ['throw', 1],
]) {
  const label = `FLOW2 実メニュー3/${path}/${state}`, lines = [], outcomes = [], fetched = [];
  const hash = '0x' + '33'.repeat(32), targetHash = '0x' + '44'.repeat(32), randao = '0x' + '55'.repeat(32);
  const storage = '0x' + '11'.repeat(20), rows = [{ uid: '1234' }], infos = Array.from({ length: 100 }, () => ({ entries: [] }));
  infos[12].entries.push({ filename: '12_0', number: 1 });
  const files = new Map(infos.map((info, i) => [infoKey(String(i).padStart(2, '0'), 0), info]));
  files.set(bodyKey('12_0', 0), rows);
  const selection = { hashRegisteredBlock: 100, confirmationBlocks: 64, targetBlockNum: 164, entryPeriodEnd: 1000,
    applicantHash: hash, targetBlockHash: targetHash, randao, totalEntries: 1, totalSelected: 1,
    players: [{ globalIndex: 0, localIndex: 0, file: '12_0', data: rows[0] }] };
  let calls = 0, answers = 0, reuse = 0, closed = false;
  const activeState = () => path === 'A' && calls === 1 ? 'success' : state;
  globalThis.__flow2Menu = {
    data: { infos, entryFileHashes: new Map([['12_0', hashLikeBackend(rows)]]), entriesTotal: 1,
      applicantHash: hash, registeredBlock: 100, entryPeriodEnd: 1000 },
    membership: { ...menuMembership, verifyOwnEntry: async (...args) => {
      calls++; if (calls === 2) lines.length = 0;
      const result = await menuMembership.verifyOwnEntry(...args); outcomes.push({ ctx: args[0], result }); return result;
    } },
    cfg: { lang: 'ja', flags: { lang: 'ja', block: null }, blockNum: null, nonInteractive: false,
      contracts: { hashStorage: storage }, pins: { confirmationBlocks: 64, gameMaxPlayers: 2100 },
      emergencyAuthority: null, emergencyApplicantRegistration: null, emergencyApplicantRoot: null },
    prompts: { choice: async () => 2, text: async () => state === 'absent' ? '9999' : '1234', number: async () => 0,
      yesNo: async () => ++answers === 1 || (path === 'A' && answers === 2), close: () => { closed = true; } },
    chain: { evidenceAddress: async () => storage, getCode: async () => '0x6000', hashStorageAddress: async () => storage,
      applicantRegistrationCount: async () => 0, getApplicantHash: async () => ({ hash }),
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
      getBlock: async () => {
        if (activeState() === 'throw') throw new Error('target block unavailable');
        return { timestamp: 1000n, hash: targetHash, mixHash: randao };
      } },
    r2: { baseDir: '/flow2-menu', setDefaultReuse: (value) => { eq(value, true, `${label}: 保存を質問せず使う`); reuse++; },
      fetchJson: async (key, options) => {
        fetched.push([calls, key, options]);
        if (key.endsWith('/game_selection.json')) {
          const current = activeState();
          if (current === 'pending') return null;
          if (current === 'selectionPresent-fail') return { data: null };
          const data = structuredClone(selection);
          if (current === 'randao-fail') data.randao = '0x' + '66'.repeat(32);
          if (current === 'playersMatch-fail') data.players[0].data.uid = '9999';
          if (current === 'entryPeriodEndField-warn') data.entryPeriodEnd = null;
          // 再利用条件を外してからRPC例外を試す。同じ有効入力ならRPC再読取自体が不要。
          if (current === 'throw') data.changedBeforeRpcError = true;
          return { data };
        }
        ok(files.has(key), `${label}: 抽選以外の成果物（グループ分け・Stage C）を読まない: ${key}`);
        return { data: structuredClone(files.get(key)) };
      } },
  };
  const write = process.stdout.write, previousExit = process.exitCode;
  let exit;
  try { process.stdout.write = (line) => { lines.push(String(line)); return true; }; await menu.main(); exit = process.exitCode; }
  finally { process.stdout.write = write; process.exitCode = previousExit; }
  const outcome = outcomes.at(-1), text = lines.join(''), translate = t('ja');
  eq(exit, expectedExit, `${label}: index.js:760の終了コード`);
  eq(outcome.result, { included: state !== 'absent', complete: true, verified: expectedExit === 0 }, `${label}: 戻り値`);
  eq(text.includes(translate('entry.onchainIncluded')), state === 'success', `${label}: 保証の文は成功時だけ`);
  ok(text.includes(translate(state === 'success' ? 'entry.onchainIncluded' : state === 'absent' ? 'entry.onchainAbsent' : 'entry.verifyFailed')), `${label}: 結論`);
  eq([calls, answers, reuse, closed], path === 'A' ? [2, 3, 2, true] : [1, 2, 1, true], `${label}: 再利用では質問せず実メニューを終了`);
  const selectionReads = fetched.filter(([, key, opts]) => key.endsWith('/game_selection.json') && !opts.cacheOnly);
  eq(selectionReads.length, state === 'absent' ? 0 : path === 'A' && state !== 'success' ? 2 : 1, `${label}: 同じ合格結果なら実抽選は1回、変更時は再現`);
  if (state === 'success') {
    eq(outcome.ctx.report.get('check.stageB.playersMatch')?.status, 'pass', `${label}: 実当選者照合`);
    eq([outcome.ctx.data.infos, outcome.ctx.data.entryFileHashes], [null, null], `${label}: 実抽選の索引破棄`);
    ok(text.includes(translate('stageB.selStart', { n: 0 })), `${label}: 使い回しでも既存の見出しを保つ`);
  }
  if (state === 'entryPeriodEndField-warn') {
    eq(outcome.ctx.report.get('check.stageB.playersMatch')?.status, 'pass', `${label}: players一致でもWARNは保証しない`);
    eq(outcome.ctx.report.get('check.stageB.entryPeriodEndField')?.status, 'warn', `${label}: 実物のWARN`);
  }
}
delete globalThis.__flow2Menu;

// R1/R2/R6: 実mainでメニュー3→1と1→3を実行。Stage Aだけ入力注入、抽選は実物。
// 同じ順序の再実行（sessions=null）と、結果・全記録・全事実・全data・表示の結論・終了コードを比較。
let reuseMenuSource = menuSource
  .replace("import { run as runGrouping } from './stages/grouping.js';", `const runGrouping = async (ctx) => {
    globalThis.__flow2Menu.groupingCalls++;
    ctx.report.check('check.stageB.groupsMatch', 'pass', { count: ctx.data.players.length });
    ctx.data.groupsDerived = ctx.data.players.length ? [{ members: ctx.data.players }] : [];
    return { stop: false };
  };`)
  .replace("import { run as runResults } from './stages/results.js';", `const runResults = async (ctx) => {
    globalThis.__flow2Menu.resultsCalls++;
    ctx.report.check('check.stageC.summaryMatch', 'pass', { selected: ctx.data.players.length });
    ctx.data.testResultsPlayers = ctx.data.players.length;
    return { stop: false };
  };`)
  .replace("import { createReport, displayParams, messageId, stageVerdictIssues } from './report.js';", `
    import { createReport as actualCreateReport, displayParams, messageId, stageVerdictIssues } from './report.js';
    const createReport = () => globalThis.__flow2Menu.trackReport(actualCreateReport());`)
  .replace('const outcome = await verifyOneBlock(cfg, chain, ui, blockNum, { entrySessions: cfg.nonInteractive ? null : entrySessions });',
    'const outcome = await globalThis.__flow2Menu.replayBlock(() => verifyOneBlock(cfg, chain, ui, blockNum, { entrySessions: cfg.nonInteractive ? null : entrySessions }));');
if (mutation === 'r7_menu1_direct') reuseMenuSource = reuseMenuSource
  .replace('const resSel = await runSelectionReusable(ctx, entrySessions);', 'const resSel = await directSelection(ctx);')
  + `\nimport { run as directSelection } from './stages/selection.js';`;
globalThis.__flow2Menu = { membership: {
  parseEntryUid,
  runEntriesReusable: (...args) => globalThis.__flow2Menu.entries(...args),
  runSelectionReusable: (...args) => globalThis.__flow2Menu.selection(...args),
} };
const reuseMenu = await import(moduleUrl(reuseMenuSource));
const menuPairFolder = mkdtempSync(join(tmpdir(), 'selection-menu-pair-'));
async function runMenuPair(order, fresh, lang, extra = {}) {
  const { context } = selectionFixture(extra.count ?? 3), base = context().ctx;
  const lines = [], outcomes = [], reports = new WeakMap();
  const storage = '0x' + '11'.repeat(20);
  const fixtureFiles = new Map(base.data.infos.map((info, i) => [infoKey(String(i).padStart(2, '0'), 17), info]));
  fixtureFiles.set(bodyKey('12_0'), Array.from({ length: extra.count ?? 3 }, (_, i) => ({ uid: String(1234 + i) })));
  const folder = menuPairFolder;
  if (!extra.noFolder) mkdirSync(folder, { recursive: true });
  eq(existsSync(folder), !extra.noFolder, 'R1: メニュー開始前の保存フォルダの有無');
  let visit = 0, returns = 0, targets = 0;
  const reusePrompts = [];
  const modes = [...order];
  const state = {
    lines, data: base.data, entriesCalls: 0, groupingCalls: 0, resultsCalls: 0,
    cfg: { ...base.cfg, lang, flags: { lang, block: null }, blockNum: null, nonInteractive: false,
      contracts: { hashStorage: storage }, emergencyAuthority: null,
      emergencyApplicantRegistration: null, emergencyApplicantRoot: null },
    trackReport(report) {
      const trace = []; reports.set(report, trace);
      for (const method of ['check', 'fact']) {
        const original = report[method];
        report[method] = (...args) => { trace.push([method, structuredClone(args)]); original(...args); };
      }
      return report;
    },
    entries: (ctx, sessions) => menuMembership.runEntriesReusable(ctx, sessions),
    stageAStatus: () => extra.stageFail && visit > 1 ? 'fail' : 'pass',
    selection: (ctx, sessions) => menuMembership.runSelectionReusable(ctx, fresh ? null : sessions),
    async replayBlock(run) {
      const at = lines.length, outcome = await run();
      outcomes.push({ mode: 0, result: { stopped: outcome.stopped, fatal: outcome.fatal, stopReason: outcome.stopReason,
        category: categorize(outcome), exit: EXIT_CODE_OF[categorize(outcome)] },
        ctx: outcome.ctx, text: lines.slice(at).join('') });
      return outcome;
    },
    prompts: {
      choice: async () => { visit++; return modes.shift(); },
      text: async () => extra.absent ? '9999' : '1234', number: async () => 17,
      yesNo: async (message) => {
        if (message === t(lang)('main.returnMenu')) return ++returns < order.length;
        if (message === t(lang)('main.folderReuse', { path: folder })) reusePrompts.push(visit);
        return true;
      },
      close() {},
    },
    chain: { ...base.chain,
      getBlock: async (n) => { targets++; return base.chain.getBlock(n); },
      evidenceAddress: async () => storage, getCode: async () => '0x6000', hashStorageAddress: async () => {
        if (visit > 1 && extra.wiring === 'error') throw new Error('wiring unavailable');
        return visit > 1 && extra.wiring === 'mismatch' ? '0x' + '22'.repeat(20) : storage;
      },
      applicantRegistrationCount: async () => 0,
      getApplicantHash: async () => ({ hash: extra.stageFail && visit > 1 ? 'changed' : base.data.applicantHash }),
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
      blockStates: async () => ({ root: '0x' + '00'.repeat(32) }), proofRequired: async () => false,
    },
    r2: { baseDir: folder, setDefaultReuse() {}, release() {},
      fetchJson: async (key, options) => {
        if (!options.cacheOnly) mkdirSync(folder, { recursive: true });
        if (key.endsWith('/game_selection.json')) {
          state.selectionReads.push([visit, structuredClone(options)]);
          return base.r2.fetchJson(key, options);
        }
        ok(fixtureFiles.has(key), `R1: グループ分けとStage C以外の取得は応募データだけ: ${key}`);
        if (visit > 1 && extra.incomplete && key === infoKey('00') && options.cacheOnly) return null;
        return { data: structuredClone(fixtureFiles.get(key)) };
      } },
    selectionReads: [],
    membership: { parseEntryUid,
      runEntriesReusable: (...args) => state.entries(...args),
      runSelectionReusable: (...args) => state.selection(...args),
      verifyOwnEntry: async (ctx, uid, sessions) => {
        const at = lines.length;
        // Stage Aの保存は有効なまま、比較用の実行だけ抽選の保存を渡さない。
        if (fresh) for (const saved of sessions.values()) delete saved.selection;
        const result = await menuMembership.verifyOwnEntry(ctx, uid, sessions);
        outcomes.push({ mode: 2, result, ctx, text: lines.slice(at).join('') });
        return result;
      },
    },
  };
  globalThis.__flow2Menu = state;
  const write = process.stdout.write, previousExit = process.exitCode;
  let exit;
  try {
    process.stdout.write = (line) => { lines.push(String(line)); return true; };
    await reuseMenu.main(); exit = process.exitCode;
  } finally { process.stdout.write = write; process.exitCode = previousExit; rmSync(folder, { recursive: true, force: true }); }
  const records = outcomes.map(({ mode, result, ctx, text }) => ({ mode, result, data: structuredClone(ctx.data),
    checks: ctx.report.list(), trace: reports.get(ctx.report),
    conclusion: mode === 2 ? text.split('\n').filter((line) => ['entry.onchainIncluded', 'entry.onchainAbsent', 'entry.verifyFailed'].some((key) => line === t(lang)(key)))
      : text.slice(text.indexOf(t(lang)('summary.title', { block: 17 }))),
    verdict: mode === 0 ? text.split('\n').filter((line) => line.includes(t(lang)('verdict.label.B'))) : [],
  }));
  return { exit, targets, records, outcomes, entries: state.entriesCalls, groups: state.groupingCalls,
    results: state.resultsCalls, reads: state.selectionReads, reusePrompts };
}
for (const lang of SUPPORTED_LANGS) for (const order of [[2, 0], [0, 2]]) {
  const label = `R1/R2/${lang}/メニュー${order.map((mode) => mode + 1).join('→')}`;
  const replay = await runMenuPair(order, false, lang), fresh = await runMenuPair(order, true, lang);
  eq(replay.targets, 1, `${label}: 実抽選のtarget block読取は1回だけ`);
  eq(fresh.targets, 2, `${label}: 対照は実抽選を2回実行`);
  eq(replay.reads.filter(([, opts]) => !opts.cacheOnly).length, 1, `${label}: R2からの抽選取得も1回分`);
  eq(replay.reads.filter(([, opts]) => opts.cacheOnly).length, 1, `${label}: 再利用時はcacheOnly確認だけ`);
  eq([replay.entries, replay.groups, replay.results], [1, 1, 1], `${label}: Stage Aは共用、グループ分けとStage Cは実mainから1回`);
  eq(replay.records, fresh.records, `${label}: 全記録・順序・事実・data・戻り値・まとめ全文・Stage B結果行・保証の文が再現と同じ`);
  eq([replay.exit, fresh.exit], [0, 0], `${label}: 実mainの終了コード`);
  for (const record of replay.records) ok(record.conclusion.length > 0, `${label}: 結論が実際に表示された`);
  const second = replay.outcomes[1].text, first = replay.outcomes[0].text;
  ok(first.includes(t(lang)('stageB.seedDerived', { seed: replay.records[0].data.selectionSeed })), `${label}: 初回は実runの途中表示あり`);
  ok(second.includes(t(lang)('stageB.selStart', { n: 17 })), `${label}: 使い回しでも既存のStage B見出しを保つ`);
  for (const key of ['stageB.seedDerived', 'stageB.runningLottery']) {
    const values = { seed: replay.records[1].data.selectionSeed, total: 3, count: 3, n: 17 };
    ok(!second.includes(t(lang)(key, values)), `${label}: 使い回しの途中表示なし/${key}`);
  }
}
for (const lang of SUPPORTED_LANGS) for (const order of [[0, 2], [0, 0]]) {
  const label = `R1/RU-1/${lang}/フォルダ無し/メニュー${order.map((mode) => mode + 1).join('→')}`;
  const replay = await runMenuPair(order, false, lang, { noFolder: true });
  const fresh = await runMenuPair(order, true, lang, { noFolder: true });
  eq(replay.records.map((record) => record.data.reuseFiles), [false, true], `${label}: 初回は新規取得、次は保存を使う`);
  eq(replay.reusePrompts, order[1] === 0 ? [2] : [], `${label}: フォルダの質問は2回目のメニュー1だけ`);
  eq(replay.targets, 1, `${label}: 抽選のtarget block読取は1回だけ`);
  eq(fresh.targets, 2, `${label}: 対照は実抽選を2回実行`);
  eq(replay.reads, [[1, { reuse: false }], [2, { reuse: true, cacheOnly: true }]],
    `${label}: 新規取得の後は手元の写しのhash確認だけ`);
  const menu1Count = order.filter((mode) => mode === 0).length;
  eq([replay.entries, replay.groups, replay.results], [1, menu1Count, menu1Count], `${label}: Stage Aを共有し、各メニュー1で後続を実行`);
  eq(replay.records, fresh.records, `${label}: 全記録・事実・data・戻り値・結論は再現と同じ`);
  eq([replay.exit, fresh.exit], [0, 0], `${label}: 終了コードも同じ`);
}
// メニュー1の通常/自動配布のStage B結果行とまとめも全体比較し、absentは抽選を呼ばない。
for (const extra of [{ count: 1 }, { count: 2 }, { absent: true }]) {
  const replay = await runMenuPair([0, 2], false, 'ja', extra), fresh = await runMenuPair([0, 2], true, 'ja', extra);
  eq(replay.records, fresh.records, `R2/R6/${JSON.stringify(extra)}: 結論・データ・記録が再現と同じ`);
  eq(replay.targets, 1, `R1/R6/${JSON.stringify(extra)}: 抽選は1回`);
  eq(replay.exit, 0, `R6/${JSON.stringify(extra)}: 実mainの終了コード0`);
}
for (const [extra, exit] of [[{ wiring: 'error' }, 1], [{ wiring: 'mismatch' }, 2], [{ incomplete: true }, 1], [{ stageFail: true }, 2]]) {
  const replay = await runMenuPair([0, 2], false, 'ja', extra), fresh = await runMenuPair([0, 2], true, 'ja', extra);
  eq(replay.records, fresh.records, `R6/${JSON.stringify(extra)}: 保存済み抽選があっても前提不成立の結果・全記録・表示は再現と同じ`);
  eq([replay.targets, replay.exit], [1, exit], `R6/${JSON.stringify(extra)}: 追加抽選を呼ばず終了コードを維持`);
  eq(replay.records[1].conclusion, [t('ja')('entry.verifyFailed')], `R6/${JSON.stringify(extra)}: 保存済み抽選で保証を出さない`);
}
delete globalThis.__flow2Menu;

for(const input of ['1234',' 1234 ','https://bitcoinu.org/user/?id=1234','https://bitcoinu.org/user?id=1234&lang=ja','https://bitcoinu.org/user/?lang=en&id=1234#x']) eq(parseEntryUid(input),'1234','uid/URLを取り出す');
for(const input of ['','abc','1e4','123456789012345678901','https://bitcoinu.org/block/?id=1234','https://bitcoinu.org/user/?id=1234&id=5678','https://bitcoinu.org/user/?id=abc','file:///user/?id=1234']) eq(parseEntryUid(input),null,'異なるURL/壊れたuidは拒否');
eq(providerRpcUrl('alchemy','abc'),'https://eth-mainnet.g.alchemy.com/v2/abc','Alchemy URL');
eq(providerRpcUrl('infura','abc'),'https://mainnet.infura.io/v3/abc','Infura URL');
const account=privateKeyToAccount('0x'+'01'.repeat(32));
const row={uid:'1234',bAddr:JSON.stringify({address:account.address,pubKey:account.publicKey,nostrPubkey:account.publicKey.slice(4,68)})};
const files=new Map();const hashes=[];
for(let i=0;i<100;i++) {
  const ww=String(i).padStart(2,'0');const entries=i===12?[{filename:'12_0',number:1}]:[];
  files.set(`entries/block0/info/${ww}_info.json`,JSON.stringify({entries}));
  hashes.push({filename:`${ww}_hash`,hash:hashLikeBackend({block_num:0,status:'success',entries:entries.map(e=>({...e,hash:hashLikeBackend([row])})).map(e=>({filename:e.filename,hash:e.hash,number:e.number}))})});
}
files.set('entries/block0/entries/12_0.json',JSON.stringify([row]));
const root='0x'+hashLikeBackend({block_num:0,status:'success',hash:hashes});
const targetHash='0x'+'44'.repeat(32),randao='0x'+'55'.repeat(32);
files.set('entries/block0/game_selection.json',JSON.stringify({hashRegisteredBlock:100,confirmationBlocks:64,targetBlockNum:164,
  entryPeriodEnd:1000,applicantHash:root,targetBlockHash:targetHash,randao,totalEntries:1,totalSelected:1,
  players:[{globalIndex:0,localIndex:0,file:'12_0',data:row}]}));
const storage='0x'+'11'.repeat(20);
let activeStorage=storage,wiringReads=0;
const chain={hashStorageAddress:async()=>{wiringReads++;return activeStorage;},getApplicantHash:async()=>({hash:root,updated:100}),getTimingConstants:async()=>({startTimeEntryMs:0,blockTimeMs:1000}),applicantRegistrationCount:async()=>1,applicantRegistrationAt:async()=>({hash:root,registeredBlock:100}),getBlock:async()=>({timestamp:1000n,hash:targetHash,mixHash:randao})};
const task=mkdtempSync(join(tmpdir(),'fix1-entry-'));let downloads=0;const fetch=globalThis.fetch;
globalThis.fetch=async(input)=>{downloads++;const key=new URL(input).pathname.slice(1);return files.has(key)?new Response(files.get(key),{status:200}):new Response('',{status:404});};
try {
 for(const lang of SUPPORTED_LANGS) {
  const cfg={contracts:{hashStorage:storage},pins:{confirmationBlocks:64,gameMaxPlayers:2100},dataDir:join(task,lang),r2Base:'https://r2.invalid'};const sessions=new Map();const output=[];let asks=0;
  const ui={t:t(lang),println:s=>output.push(s),warn(){},section:title=>output.push(`\n--------\n\n【${title}】`),askYesNo:async()=>{asks++;return true;}};
  const context=()=>{const r2=createR2(cfg,ui,0);r2.setDefaultReuse(true);return {cfg,chain,ui,r2,blockNum:0,report:createReport(),data:{reuseFiles:true}};};
  // FIX4 N3-1: Noを選ぶ前のdataDirは空。実R2ローダーが取得し、欠落とは表示しない。
  const noCfg={...cfg,dataDir:join(task,lang,'no-empty')};const noLines=[];const noBefore=downloads;
  const freshR2=createR2(noCfg,ui,0);freshR2.setDefaultReuse(true);const freshReads=recordR2(freshR2);
  const freshNo=await verifyOwnEntry({cfg:noCfg,chain,ui:{...ui,askYesNo:async()=>false,println:s=>noLines.push(s)},r2:freshR2,blockNum:0,report:createReport(),data:{}},'1234',new Map());
  eq(freshNo,{included:true,complete:true,verified:false},'No: 空dataDirからも公開データ上の存在を確認');
  eq(freshReads.calls,[[infoKey('12',0),{reuse:true,cacheOnly:false}],[bodyKey('12_0',0),{reuse:true,cacheOnly:false}]],'I2: 実R2でもNoは自分の置き場だけ');
  eq(downloads-noBefore,2,'No: 空dataDirからは一覧1個と本体1個だけ取得');
  assert.ok(downloads>noBefore && !noLines.includes(ui.t('entry.unknown')) && noLines.includes(ui.t('entry.onchainUnchecked')));assertions++;
  const yesCtx=context();const yes=await verifyOwnEntry(yesCtx,'1234',sessions);
  eq(yes,{included:true,complete:true,verified:true},'Yes: 本物Stage Aと抽選を通して含まれる');eq(asks,1,'初回は全件の確認を質問');
  ok(yesCtx.report.list().filter(e=>e.id.startsWith('check.stageB.')).every(e=>e.status==='pass'),'FLOW2 I1: 実物の抽選の全検査がpass');
  eq(yesCtx.report.get('check.stageB.playersMatch')?.status,'pass','FLOW2 I1: 実物の当選者照合を通す');
  eq([yesCtx.data.infos,yesCtx.data.entryFileHashes],[null,null],'FLOW2 I3: 実物の抽選による索引破棄後も本人の結果を保持');
  assert.ok(output.includes(ui.t('entry.onchainIncluded')));assertions++;
  // 実R2の同じインスタンスに古いmemoが残っていても、現在のディスクの写しを比較する。
  const selectionKey = 'entries/block0/game_selection.json';
  const selectionPath = join(cfg.dataDir, 'block0', selectionKey);
  const changedSelection = JSON.parse(files.get(selectionKey)); changedSelection.randao = '0x' + '66'.repeat(32);
  await runEntriesReusable(yesCtx, sessions);
  writeFixtureSync(selectionPath, JSON.stringify(changedSelection));
  await runSelectionReusable(yesCtx, sessions);
  eq(yesCtx.report.get('check.stageB.randao')?.status, 'fail', 'R3: 実R2のmemoを解放して抽選の写しの改変を検出');
  ok(![...sessions.values()][0].selection, 'R3: 改変後の不合格で以前の抽選保存も破棄');
  writeFixtureSync(selectionPath, files.get(selectionKey)); yesCtx.r2.release(selectionKey);
  await runEntriesReusable(yesCtx, sessions); await runSelectionReusable(yesCtx, sessions);
  eq(yesCtx.report.get('check.stageB.randao')?.status, 'pass', 'R3: 正しい写しへ戻れば再現して合格結果を置換');
  await runEntriesReusable(yesCtx, sessions); rmSync(selectionPath);
  const missingBefore = downloads;
  await runSelectionReusable(yesCtx, sessions);
  eq(downloads - missingBefore, 1, 'R3: 実R2で手元の抽選ファイルが無ければ通常runで取得し直す');
  eq(yesCtx.report.get('check.stageB.playersMatch')?.status, 'pass', 'R3: 抽選ファイル再取得後に実物の抽選を再現');
  const before=downloads;
  const absent=await verifyOwnEntry(context(),'9999',sessions);
  eq(absent,{included:false,complete:true,verified:true},'検証済みの集合に含まれない');eq(asks,1,'メニュー1/3の検証結果を同一セッションで再利用');eq(downloads,before,'保存から再利用、ダウンロード重複なし');
  const replay=context();await runEntriesReusable(replay,sessions);eq(replay.report.get('check.stageA.rootMatch').status,'pass','3から1へも結果を再利用');
  assert.ok(output.includes(ui.t('entry.reused')));assertions++;
  const again=await verifyOwnEntry(context(),'1234',new Map());eq(again.verified,true,'次の実行は保存の旗を信じずStage Aを再実行');eq(downloads,before,'次の実行も保存した全ファイルを使う');
  const noCtx=context();noCtx.ui={...ui,askYesNo:async()=>false};const noOut=[];noCtx.ui.println=s=>noOut.push(s);
  eq(await verifyOwnEntry(noCtx,'1234',new Map()),{included:true,complete:true,verified:false},'No: 公開データの有無だけ');
  assert.ok(noOut.includes(ui.t('entry.onchainUnchecked'))&&!noOut.includes(ui.t('entry.onchainIncluded')));assertions++;
  eq(readFileSync(join(cfg.dataDir,'block0/entries/block0/entries/12_0.json'),'utf8'),JSON.stringify([row]),'data/blockNの保存');
  // メニュー1/3でStage Aを再利用できても、今の同じ接続の配線を確認する。
  activeStorage='0x'+'22'.repeat(20);const wiringBefore=wiringReads;const wrongCtx=context(),wrongLines=[];
  wrongCtx.ui={...ui,println:s=>wrongLines.push(s)};
  eq((await verifyOwnEntry(wrongCtx,'1234',sessions)).verified,false,'保存済みStage Aでも今の配線が違えば未確認');
  eq(wiringReads-wiringBefore,1,'再利用でも同じ接続の現在getterを1回読む');
  assert.ok(wrongLines.includes(ui.t('entry.verifyFailed'))&&!wrongLines.includes(ui.t('entry.onchainIncluded'))&&!wrongLines.includes(ui.t('entry.onchainUnchecked')));assertions++;
  activeStorage=storage;
 }
 // メニュー4択・publicnode説明・選び直し・APIキー秘密入力を実関数で確認。
 for(const provider of ['alchemy','infura']) {
  const cfg={rpcUrls:null,rpcPresets:[{url:'https://ethereum-rpc.publicnode.com'}],customRpcs:[],flags:{},savedConfigPath:join(task,'config.json')};
  const lines=[];const menus=[];const choices=[0,1,provider==='alchemy'?1:2];
  const prompts={isInteractive:true,choice:async(msg,items)=>{menus.push(items);return choices.shift();},text:async(msg,opts)=>{eq(opts.secret,true,'APIキーは秘密入力');return 'SECRET_API_KEY';}};
  const ui=makeUi(t('ja'),prompts,cfg);const write=process.stdout.write;process.stdout.write=s=>{lines.push(s);return true;};
  try {
    const connected=await setupChain(cfg,ui,prompts,async(_cfg,_ui,urls)=>{cfg.rpcUrls=urls;ui.println(urls[0]);return {ok:true};});eq(connected.ok,true,'選び直して接続');
  } finally {process.stdout.write=write;}
  eq(menus[0].length,4,'4つのノード選択肢');eq(menus[1].length,2,'publicnodeは続ける/選び直す');eq(menus[2].length,4,'一覧へ戻る');
  const text=lines.join('');assert.ok(text.includes('【publicnode で検証できること・できないこと】')&&text.includes('Stage A'));assertions++;
  assert.ok(!text.includes('SECRET_API_KEY')&&text.includes('/…'));assertions++;
 }
 // 一致検証後に保存ファイルを改変した場合、結果再利用で合格にしてはいけない。
 const cfg={dataDir:join(task,'tamper'),r2Base:'https://r2.invalid'};const ui={t:t('ja'),println(){},warn(){},askYesNo:async()=>true};const sessions=new Map();
 const ctx={cfg,chain,ui,blockNum:0,report:createReport(),data:{reuseFiles:true},r2:createR2(cfg,ui,0)};ctx.r2.setDefaultReuse(true);
 await runEntriesReusable(ctx,sessions);
 const {writeFileSync}=await import('node:fs');writeFileSync(join(cfg.dataDir,'block0/entries/block0/entries/12_0.json'),JSON.stringify([{...row,uid:'9999'}]));
 const changed={...ctx,report:createReport(),data:{reuseFiles:true},r2:createR2(cfg,ui,0)};changed.r2.setDefaultReuse(true);await runEntriesReusable(changed,sessions);
 eq(changed.report.get('check.stageA.rootMatch').status,'fail','保存改変はroot不一致として検出');
 const failedCtx={...ctx,report:createReport(),data:{reuseFiles:true},r2:createR2(cfg,ui,0)};failedCtx.r2.setDefaultReuse(true);
 const failedReads=recordR2(failedCtx.r2);
 eq(await verifyOwnEntry(failedCtx,'1234',new Map()),{included:false,complete:true,verified:false},'I6: 本物Stage Aのroot不一致でも戻り値の形を維持');
 eq(failedCtx.report.get('check.stageA.rootMatch').status,'fail','I6: Stage A失敗の経路を通った');
 eq(failedReads.calls.filter(([,opts])=>opts.cacheOnly===false),[[infoKey('12',0),{reuse:true,cacheOnly:false}],[bodyKey('12_0',0),{reuse:true,cacheOnly:false}]],'I2: Stage A失敗時も最初の存在確認は置き場だけ');
} finally {globalThis.fetch=fetch;rmSync(task,{recursive:true,force:true});}
if (!mutation) for (const name of Object.keys(mutations)) {
  const result = spawnSync(process.execPath, [import.meta.filename, `--mutation=${name}`],
    { encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  eq(result.status, 1, `${name}: 変異は赤`);
  ok(result.stdout.includes(`MUTATION_APPLIED ${name}`) && result.stderr.includes('AssertionError'), `${name}: 起動失敗ではなくassertionで検出`);
  console.log(`entry-membership-unit: ${name} killed (exit ${result.status}; AssertionError)`);
}
console.log(`entry-membership-unit: PASS (${assertions} assertions; ${Object.keys(mutations).length} mutants killed)`);
