// c9-summary-canonical-json-unit.mjs — 公開 summary.json の**正準JSON検査**（P-2026-0822）
//
// 背景（2026-08-07・ユーザー判断 C-1）:
//   JSON では同じ数を複数の書き方で表せる: `100` / `100.0` / `1e2` / `1.0e2`。
//   JS の `JSON.parse` は4つとも `100` として読むが、Rust の採点コア
//   （`crates/scoring-core/src/json.rs`）は**整数トークンだけ**を受け付け、`100.0` を見たら
//   summary 全体を `JsonMalformed` として拒否する。
//
//   さらに厄介な例: `{"group_id":9007199254740991.4}` を V8 の `JSON.parse` は
//   **9007199254740991 に丸める**。丸まった後は安全整数なので JS 側の検査（`normalizeGid`）を
//   素通りする。Rust は元のトークンを見て「小数」と判断し、そのグループを NO_GID として
//   請求葉から外す。実測された結末: **JS は 115384615384615000000000 wei を配り、Rust は 0 wei**。
//   ＝同一入力から2つの答えが出て証明が通らない。
//
//   規約（CLAUDE.md「全 R2 JSON は minified `JSON.stringify`」）は既にあり、
//   `JSON.stringify` は `100.0` も `1e2` も絶対に出さない。検査していなかっただけなので、
//   規約を検査へ格上げした（正典 `workers/game_workers/lib/canonical-json.js`）。
//
// 本ファイルが固定するのは **block-verifier 側**の受理条件:
//   正典が拒否する入力を検証ツールが受理すると、今度は逆向きに答えが割れる。
//   よって Stage C も同じ検査を通し、**非正準なら fail（exit 2）**で終わる
//   ——`fatal`（exit 3・「ツールが原因不明で落ちた」）にしないことが要件。
//
// ⚠️ 空振り防止の設計:
//   ・テストデータは**JSON 文字列から**作る。オブジェクトリテラルを `JSON.stringify` すると
//     必ず正準になるので非正準ケースが作れない。`mutateRaw()` は置換対象が見つからなければ
//     throw する（＝summary の形が変わってテストが無言で無効化されるのを防ぐ）。
//   ・「例外が出ないこと」だけを見ない。チェックID の status・停止理由・アノマリー文面・
//     そして**正常な summary では最後まで通って summaryMatch が pass する**ことまで見る。
//
// 🔬 空振りしていないことの実測（2026-08-07・全て緑=70件からの差分）:
//   | 壊し方                                                                | 結果        |
//   | `results.js` の 2b ブロック（正準検査）を丸ごと削除                    | 38 件 FAIL（T1〜T4 の判定が全て absent になる） |
//   | 同ブロックの try/catch を外して `parseCanonicalJson` を素通しさせる     | 42 件 FAIL（run() が throw ＝ fatal / exit 3 に化ける） |
//   | vendor `canonical-json.js` の `canonical !== text` を `===` に反転     | 46 件 FAIL（非正準を受理し、正常 summary を拒否する） |
//   | 適用範囲を誤って merkle にも検査をかける                               | 2 件 FAIL（T7-g / T7-h ＝ 偽陽性で停止する） |
//
// 実行: node block-verifier/test/c9-summary-canonical-json-unit.mjs （Node 22）

import { run as runResults } from '../src/stages/results.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { canonicalRosterText } from '../vendor/workers/game_workers/lib/roster-canonical.js';
import {
  isCanonicalJsonRequiredKey, parseCanonicalJson,
} from '../vendor/workers/game_workers/lib/canonical-json.js';
import { DEFAULTS } from '../src/config.js';
import { t as makeTranslator } from '../src/i18n.js';
import { createReport } from '../src/report.js';

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};
const eq = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

// ---------------- 固定パラメータ ----------------
const N = 0;
const ETH_LOCK = '0x' + '11'.repeat(20);
const EVIDENCE = '0x' + '22'.repeat(20);
const TIMING = {
  startTimeEntryMs: 1700000000000,
  blockTimeMs: 3600000,
  gamePeriodMs: 1800000,
  submitPeriodMs: 600000,
  invariantOk: true,
};
const UNLOCK_SEC = 2000000000;
const ETH = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 12n).toString();
const depIdsJson = (totalWei, ids) => JSON.stringify({ deposit: totalWei, ids });

// ---------------- スタブ ----------------
function makeUi(lang) {
  const tr = makeTranslator(lang);
  const lines = [];
  return { println: (s) => lines.push(String(s)), warn() {}, t: tr, askYesNo: async () => false, lines };
}

function makeChainStub({ depositsById, readIds, root = '0x' + 'ab'.repeat(32) }) {
  // R26-C4: 検証に使う EthLock は TokenMining.ethLock()（チェーン値）が権威。
  //   スタブは config と同じアドレスを返す（不一致だと ethLockWiring が FAIL になる）。
  const client = {
    async readContract({ functionName, args }) {
      if (functionName !== 'getLock') throw new Error(`unexpected readContract: ${functionName}`);
      const id = String(args[0]);
      readIds.push(id);
      const d = depositsById[id];
      if (!d) throw new Error(`no such deposit ${id}`);
      return d;
    },
  };
  return {
    client,
    async ethLockAddress() { return ETH_LOCK; },
    async blockStates() { return { root, verificationStartedAt: root === '0x' + '00'.repeat(32) ? 0 : 1700000100 }; },
    async getTimingConstants() { return { ...TIMING }; },
    async getResultHash() { return { hash: '0x' + '00'.repeat(32), updated: 0 }; },
    async resultRegistrationCount() { return 1; },
    async latest() { return { number: 1000n }; },
    async getBlock() { return { number: 936n, timestamp: 1900000000n, hash: '0x' + 'cd'.repeat(32), mixHash: '0x' + 'ef'.repeat(32) }; },
    async resultCount() { return 0; },
    async resultWindow() { return { openAt: 0, closeAt: 0 }; },
    async chatWindow() { return { chatOpenAt: 0, chatCloseAt: 0 }; },
    async findBlockByTimestamp() { return 900n; },
    async merkleRootEvents() { return []; },
    async verificationPeriod() { return 600; },
    async claimPeriod() { return 10800; },
  };
}

// 🔴 c8 の makeR2Stub と違い **raw を呼び出し側が指定する**。
//   `raw: JSON.stringify(data)` にしてしまうと raw が必ず正準になり、
//   このテストが検証したい「非正準バイト列」を一切作れない（＝完全な空振り）。
function makeR2Stub(rawByKey) {
  return {
    baseDir: '/dev/null/block0',
    async fetchJson(key) {
      if (!(key in rawByKey)) return null;
      const raw = rawByKey[key];
      return { data: JSON.parse(raw), raw };
    },
    async refetch() { return null; },
    async exists() { return false; },
    setDefaultReuse() {},
  };
}

function makeCtx({ lang = 'ja', players, rawByKey, chain, emergency = false }) {
  const report = createReport();
  const ui = makeUi(lang);
  const fixtureRaw = { ...rawByKey };
  if ([1, 2].includes(players?.length)) {
    const key = `games/block${N}/roster/group0.json`;
    if (!Object.hasOwn(fixtureRaw, key)) fixtureRaw[key] = canonicalRosterText(N, 0,
      players.map(p => ({ ...p.data, globalIndex: p.globalIndex })));
  }
  return {
    cfg: { lang, pins: DEFAULTS.pins, contracts: { ethLock: ETH_LOCK, evidence: EVIDENCE } },
    chain,
    r2: makeR2Stub(fixtureRaw),
    ui,
    report,
    blockNum: N,
    data: {
      autoDistribute: true,
      gameSelection: { players, targetBlockNum: 64 },
      reuseFiles: false,
      ...(emergency ? {
        emergencySource: { chainResultMarker: null },
        emergencyServerSubmissions: {},
      } : {}),
    },
  };
}

const player = (uid, depIds, globalIndex) => ({
  globalIndex, localIndex: globalIndex, file: '00_0',
  data: { uid, addr: '0x' + 'aa'.repeat(20), bAddr: null, lang: 'ja', depIds, name: null, img: null, verified: false },
});
const deposit = (idFrom, idTo, ethAmount) => ({
  amount: ETH(ethAmount), idFrom, idTo, unlockTime: UNLOCK_SEC,
  lockOwnerAddress: '0x' + 'bb'.repeat(20), unlocked: false,
});

// ---------------- 公開 summary.json（autoDistribute 版・完全形） ----------------
// 形状の正典は game-master-DO.js autoDistribute（results.js の rebuilt と同形）。
const REWARD_WEI = getBlockRewardWei(N);
const P_ADDR = '0x' + 'aa'.repeat(20);
const P_DEPOSITER = '0x' + 'bb'.repeat(20);

function buildAutoSummary(rows) {
  const total = rows.reduce((s, r) => s + r.points, 0);
  const members = [];
  const depositorResults = [];
  for (const row of rows) {
    const full = total === 0 ? 0n : REWARD_WEI * BigInt(row.points) / BigInt(total);
    const deps = row.deposits || [];
    const totalDep = deps.reduce((s, d) => s + BigInt(d.amountWei), 0n);
    let btcu = full, playerShare = null, depositorShare = null;
    if (full !== 0n && deps.length > 0 && totalDep > 0n) {
      playerShare = full / 2n;
      depositorShare = full - playerShare;
      btcu = playerShare;
      for (const d of deps) {
        depositorResults.push({
          depositorUid: d.idFrom, playerUid: row.uid, depositId: d.depositId,
          depositerAddress: P_DEPOSITER,
          btcuReward: (depositorShare * BigInt(d.amountWei) / totalDep).toString(),
          isPlayerSelf: d.idFrom === row.uid,
          depositorName: null, depositorImg: null, depositorVerified: false,
        });
      }
    } else if (full !== 0n) {
      playerShare = full;
    }
    members.push({
      userId: row.uid, address: P_ADDR, img: null, name: null, lang: 'ja', verified: false,
      depIds: row.depIds, deposit_points: row.points, bonus_points: 0, total_points: row.points,
      is_disqualified: 0, disqualify_reason: null,
      btcu_reward: btcu.toString(), full_btcu_reward: full.toString(),
      player_share: playerShare === null ? null : playerShare.toString(),
      depositor_share: depositorShare === null ? null : depositorShare.toString(),
      claimed: 0,
    });
  }
  return {
    blockNum: N, blockReward: REWARD_WEI.toString(), totalPlayers: rows.length, totalGroups: 0,
    autoDistributed: true, majorLangs: [],
    groups: [{
      group_id: 0, lang: 'auto', member_count: members.length, status: 'auto_distributed',
      total_points: total, members, depositor_results: depositorResults,
    }],
  };
}

const P1_DEPIDS = depIdsJson(ETH(1.0), ['1']);
const P2_DEPIDS = depIdsJson(ETH(0.25), ['2']);
// floor(sqrt(1e18/1e14)) = 100 / floor(sqrt(2.5e17/1e14)) = 50
const SUMMARY_ROWS = [
  { uid: '20000001', depIds: P1_DEPIDS, points: 100,
    deposits: [{ depositId: '1', amountWei: ETH(1.0), idFrom: '20000001' }] },
  { uid: '20000002', depIds: P2_DEPIDS, points: 50,
    deposits: [{ depositId: '2', amountWei: ETH(0.25), idFrom: '20000002' }] },
];
// 🔴 正準バイト列はここでしか作らない。以降のケースは**この文字列を編集して**作る。
const CANONICAL_SUMMARY_RAW = JSON.stringify(buildAutoSummary(SUMMARY_ROWS));

// 置換が起きなければ throw（summary の形が変わってケースが無言で無効化されるのを防ぐ）。
// 既定では対象が2回以上現れても throw する（どこを壊したのか曖昧なテストを残さないため）。
// 複数出現が自然なフィールド（メンバーごとの `is_disqualified` など）は allowMultiple で明示する。
function mutateRaw(raw, from, to, { allowMultiple = false } = {}) {
  const at = raw.indexOf(from);
  if (at < 0) throw new Error(`mutateRaw: token not found in the canonical summary: ${from}`);
  if (!allowMultiple && raw.indexOf(from, at + 1) >= 0) {
    throw new Error(`mutateRaw: token is ambiguous (appears twice): ${from}`);
  }
  return raw.slice(0, at) + to + raw.slice(at + from.length);
}

const MERKLE_RAW = JSON.stringify({ blockNum: N, root: '0x' + 'ab'.repeat(32), items: [] });
const MANIFEST_RAW = JSON.stringify({
  blockNum: N, algorithm: 'sha256', manifestHash: '0x00', rules: { evidence: null }, files: {},
});

function filesWith(summaryRaw, over = {}) {
  return {
    [`games/block${N}/summary.json`]: summaryRaw,
    [`merkle/block_${N}.json`]: MERKLE_RAW,
    [`verification/block${N}/manifest.json`]: MANIFEST_RAW,
    ...over,
  };
}

async function callRun(ctx) {
  try {
    const res = await runResults(ctx);
    return { threw: false, error: null, res };
  } catch (e) {
    return { threw: true, error: e, res: null };
  }
}
const statusOf = (ctx, id) => ctx.report.get(id)?.status ?? 'absent';
const paramsOf = (ctx, id) => ctx.report.get(id)?.params ?? {};

// 非正準 summary を1本流す共通ルーチン
async function runWithSummaryRaw(summaryRaw, {
  lang = 'ja', over = {}, emergency = false, root = '0x' + 'ab'.repeat(32),
} = {}) {
  const readIds = [];
  const chain = makeChainStub({
    depositsById: {
      1: deposit('20000001', '20000001', 1.0),
      2: deposit('20000002', '20000002', 0.25),
    },
    readIds,
    root,
  });
  const players = [player('20000001', P1_DEPIDS, 0), player('20000002', P2_DEPIDS, 1)];
  const ctx = makeCtx({ lang, players, rawByKey: filesWith(summaryRaw, over), chain, emergency });
  const r = await callRun(ctx);
  return { ctx, r, readIds };
}

// 非正準ケースの共通アサーション（fatal ではなく fail で終わる）
async function expectRejected(label, summaryRaw, extraAssert) {
  const { ctx, r } = await runWithSummaryRaw(summaryRaw);
  ok(`${label}: run() が例外を投げない（= ##RESULT fatal / exit 3 にならない）`, !r.threw, r.error?.message);
  eq(`${label}: check.stageC.summaryCanonicalJson = fail`,
    statusOf(ctx, 'check.stageC.summaryCanonicalJson'), 'fail');
  eq(`${label}: reason = noncanonical`, paramsOf(ctx, 'check.stageC.summaryCanonicalJson').reason, 'noncanonical');
  eq(`${label}: stopReason = fail（= ##RESULT fail / exit 2）`, ctx.data.stopReason, 'fail');
  ok(`${label}: report.hasFail()（categorize が 'fail' を返す条件）`, ctx.report.hasFail());
  ok(`${label}: 食い違い位置（offset）が数値で記録される`,
    typeof paramsOf(ctx, 'check.stageC.summaryCanonicalJson').offset === 'number',
    JSON.stringify(paramsOf(ctx, 'check.stageC.summaryCanonicalJson')));
  ok(`${label}: 採点まで進まない（summaryMatch は記録されない）`,
    statusOf(ctx, 'check.stageC.summaryMatch') === 'absent',
    statusOf(ctx, 'check.stageC.summaryMatch'));
  if (extraAssert) extraAssert(ctx, r);
  return ctx;
}

console.log('c9: 公開 summary.json の正準JSON検査（block-verifier Stage C）');
console.log('');

// ============================================================
// T1: 数値の別表記 100.0 / 1e2 / 1.0e2 が拒否される
// ============================================================
console.log('[T1 数値の別表記]');
await expectRejected('T1-a "total_points":150.0',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"total_points":150', '"total_points":150.0'));
await expectRejected('T1-b "deposit_points":1e2',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"deposit_points":100', '"deposit_points":1e2'));
await expectRejected('T1-c "deposit_points":1.0e2',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"deposit_points":100', '"deposit_points":1.0e2'));

// ============================================================
// T2: V8 が整数へ丸める `9007199254740991.4`
//   （JS 側の検査を素通りするのに Rust は NO_GID にする — 本件の起点）
// ============================================================
console.log('');
console.log('[T2 V8 が整数へ丸める group_id]');
{
  const raw = mutateRaw(CANONICAL_SUMMARY_RAW, '"group_id":0', '"group_id":9007199254740991.4');
  // まず「JS 側の素通り」を実測で固定する（この前提が崩れたら本件の危険性が変わる）
  eq('T2 前提: JSON.parse が 9007199254740991.4 を整数へ丸める',
    JSON.parse(raw).groups[0].group_id, 9007199254740991);
  ok('T2 前提: 丸めた後は Number.isSafeInteger を通ってしまう',
    Number.isSafeInteger(JSON.parse(raw).groups[0].group_id));
  await expectRejected('T2 "group_id":9007199254740991.4', raw);
}

// ============================================================
// T3: 真偽値相当・ブロック番号の 0.0
// ============================================================
console.log('');
console.log('[T3 0.0 表記]');
await expectRejected('T3-a "is_disqualified":0.0',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"is_disqualified":0', '"is_disqualified":0.0', { allowMultiple: true }));
await expectRejected('T3-b "blockNum":0.0',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"blockNum":0', '"blockNum":0.0'));

// ============================================================
// T3b: 制限文法（2段目）の**拒否側** — 往復は一致するのに Rust が読めない形
//
// 🔴 R-3（2026-08-09・ラウンド21 回帰-3）: 正典 `canonical-json.js` の検査は2段ある。
//      1段目 `JSON.stringify(JSON.parse(t)) === t`（往復一致）
//      2段目 `isCanonicalRestrictedJson(t)`（J-13 案B2・Rust `json::check_canonical_json` と同文法）
//    T1〜T3 のケースは**全部1段目で落ちる**ため、2段目の `if` を `if (false && …)` に
//    変異してもこのファイルは全緑のままだった（＝2段目の拒否側が一度も実行されていない）。
//    Rust 側には専用テスト（`crates/scoring-core/tests/json_hardening.rs`）があるのに
//    JS 側には無い、という片側だけの整備だった。
//
// ⚠️ 2段目の拒否には**食い違い位置（offset）が無い**（「どのバイトから違う」という概念が
//    そもそも無い）。`expectRejected` は offset が数値であることを assert するので、
//    そのまま使うと**壊れていなくても落ちる**。ここは専用ヘルパーで受ける。
// ⚠️ 各ケースは「1段目を通ること」を先に実測で固定する。ここが false になったら
//    そのケースは2段目に届いておらず、検査が空振りしている。
// ============================================================
console.log('');
console.log('[T3b 制限文法（2段目）の拒否側]');
async function expectRejectedGrammar(label, summaryRaw) {
  ok(`${label}: 1段目（往復一致）は通る＝2段目に到達する`,
    JSON.stringify(JSON.parse(summaryRaw)) === summaryRaw,
    'このケースは1段目で落ちるので制限文法の検査を一度も実行しない');
  const { ctx, r } = await runWithSummaryRaw(summaryRaw);
  const p = paramsOf(ctx, 'check.stageC.summaryCanonicalJson');
  ok(`${label}: run() が例外を投げない（= ##RESULT fatal / exit 3 にならない）`, !r.threw, r.error?.message);
  eq(`${label}: check.stageC.summaryCanonicalJson = fail`,
    statusOf(ctx, 'check.stageC.summaryCanonicalJson'), 'fail');
  eq(`${label}: reason = noncanonical`, p.reason, 'noncanonical');
  eq(`${label}: stopReason = fail（= ##RESULT fail / exit 2）`, ctx.data.stopReason, 'fail');
  ok(`${label}: report.hasFail()`, ctx.report.hasFail());
  ok(`${label}: 1段目（往復不一致）ではなく**制限文法**の理由で落ちる`,
    /restricted grammar/.test(String(p.error || '')) &&
    !/does not reproduce the published bytes/.test(String(p.error || '')),
    String(p.error).slice(0, 200));
  // 2段目に offset は無い。`results.js` は `?? null` で受けるので null になる（数値ではない）。
  eq(`${label}: offset は null（2段目には食い違い位置が無い）`, p.offset, null);
  ok(`${label}: 採点まで進まない（summaryMatch は記録されない）`,
    statusOf(ctx, 'check.stageC.summaryMatch') === 'absent',
    statusOf(ctx, 'check.stageC.summaryMatch'));
  return ctx;
}
// 🔴 `-0` と `9007199254740993` は使わないこと — `JSON.stringify(-0)==="0"` /
//    `JSON.parse` が …993 を …992 へ丸めるので、どちらも**1段目**で落ちて空振りする（実測）。
await expectRejectedGrammar('T3b-a "total_points":150.5（非整数）',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"total_points":150', '"total_points":150.5'));
await expectRejectedGrammar('T3b-b "deposit_points":1e+30（指数表記）',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"deposit_points":100', '"deposit_points":1e+30'));
await expectRejectedGrammar('T3b-c "bonus_points":1e-7（指数表記・小さい数）',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"bonus_points":0', '"bonus_points":1e-7', { allowMultiple: true }));
await expectRejectedGrammar('T3b-d "group_id":9007199254740992（2^53＝安全整数の外）',
  mutateRaw(CANONICAL_SUMMARY_RAW, '"group_id":0', '"group_id":9007199254740992'));
// 過剰遮断ゼロ: 正準 summary は2段目も通る（vendored 述語で直接固定）
{
  const { isCanonicalRestrictedJson } =
    await import('../vendor/workers/game_workers/lib/protocol-v2.js');
  ok('T3b-e 正準 summary は制限文法の中（過剰遮断ゼロ）',
    isCanonicalRestrictedJson(CANONICAL_SUMMARY_RAW) === true);
}

// ============================================================
// T4: 3言語のメッセージ（第三者が「運営側の問題」と読めること）
// ============================================================
console.log('');
console.log('[T4 3言語メッセージ]');
{
  const bad = mutateRaw(CANONICAL_SUMMARY_RAW, '"total_points":150', '"total_points":1.5e2');
  for (const [lang, needles] of [
    ['ja', ['正準JSON', '運営側の問題', '未検証']],
    ['en', ['not canonical JSON', 'on the operator’s side', 'UNVERIFIED']],
    ['zh', ['不是正准 JSON', '运营方', '未经验证']],
  ]) {
    const { ctx } = await runWithSummaryRaw(bad, { lang });
    const printed = ctx.ui.lines.join('\n');
    ok(`T4/${lang} 画面出力に「非正準＝運営側の問題／未検証扱い」が出る`,
      needles.every((nd) => printed.includes(nd)),
      printed.slice(-600));
    const anomalies = ctx.report.getFact('stageC.anomalies') || [];
    ok(`T4/${lang} アノマリーにも1行残る`,
      anomalies.some((a) => a.includes('summary.json')), JSON.stringify(anomalies));
  }
}

// ============================================================
// T5: JSON として読めないバイト列（reason = 'parse'）
// ============================================================
console.log('');
console.log('[T5 JSON として読めない]');
{
  // R2 スタブの fetchJson が JSON.parse する前に落ちるので、ここは helper を直接測る
  let caught = null;
  try { parseCanonicalJson('{"a":1,', 'games/block0/summary.json'); } catch (e) { caught = e; }
  ok('T5 parse 失敗は canonicalJsonError として拒否される', !!caught && caught.canonicalJsonError === true);
  eq('T5 reason = parse', caught?.canonicalJsonReason, 'parse');
  ok('T5 メッセージに対象名が入る', String(caught?.message).includes('games/block0/summary.json'),
    String(caught?.message));
}

// ============================================================
// T6: 正常な summary（実物と同じ形）は通る — 過剰遮断の回帰
//   ⚠️ 「通る」を「fail が無い」で測るのは弱い。**最後まで走って
//     summaryMatch が pass する**ところまで見る。
// ============================================================
console.log('');
console.log('[T6 正常な summary は通る（過剰遮断の回帰）]');
{
  const { ctx, r, readIds } = await runWithSummaryRaw(CANONICAL_SUMMARY_RAW);
  ok('T6 run() が例外を投げない', !r.threw, r.error?.message);
  eq('T6 check.stageC.summaryCanonicalJson = pass',
    statusOf(ctx, 'check.stageC.summaryCanonicalJson'), 'pass');
  ok('T6 stopReason は設定されない（途中終了しない）', ctx.data.stopReason == null, String(ctx.data.stopReason));
  eq('T6 check.stageC.autoDistribute = pass', statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  eq('T6 totalPoints = 100 + 50', ctx.report.getFact('stageC.totalPoints'), 150);
  eq('T6 check.stageC.summaryMatch = pass（最後まで到達して一致する）',
    statusOf(ctx, 'check.stageC.summaryMatch'), 'pass');
  eq('T6 チェーンから読まれた depositId', [...new Set(readIds)].sort(), ['1', '2']);
}

// ============================================================
// T7: 適用範囲 — summary.json **以外**のキーには検査がかからない
//   `game_groups.json` などは整数に見えるキーを含み、`JSON.parse` がそれを昇順へ
//   並べ替えるため、正しく書かれたファイルでも往復が一致しない＝偽陽性になる。
//   （実測: R2 の実物は summary.json 106/106 一致・他 315 件は上記の理由で不一致になりうる）
// ============================================================
console.log('');
console.log('[T7 適用範囲は summary.json だけ]');
{
  eq('T7-a summary.json は検査対象',
    isCanonicalJsonRequiredKey('games/block0/summary.json'), true);
  eq('T7-b game_groups.json は検査対象外',
    isCanonicalJsonRequiredKey('entries/block0/game_groups.json'), false);
  eq('T7-c group{G}.json は検査対象外',
    isCanonicalJsonRequiredKey('games/block0/group3.json'), false);
  eq('T7-d merkle は検査対象外',
    isCanonicalJsonRequiredKey('merkle/block_0.json'), false);

  // 整数に見えるキーの並べ替えが実際に起きること（偽陽性の実体）を実測で固定
  const intKeyRaw = '{"10":1,"2":2}';
  ok('T7-e 整数に見えるキーは JSON.parse の時点で並べ替わる（＝他ファイルへ広げると偽陽性）',
    JSON.stringify(JSON.parse(intKeyRaw)) !== intKeyRaw,
    JSON.stringify(JSON.parse(intKeyRaw)));

  // Stage C 実走: summary 以外（merkle）が非正準でも、正準検査は pass のまま通過する
  const badMerkle = mutateRaw(MERKLE_RAW, '"blockNum":0', '"blockNum":0.0');
  const { ctx, r } = await runWithSummaryRaw(CANONICAL_SUMMARY_RAW, {
    over: { [`merkle/block_${N}.json`]: badMerkle },
  });
  ok('T7-f 非正準な merkle があっても run() は落ちない', !r.threw, r.error?.message);
  eq('T7-g summary が正準なら summaryCanonicalJson は pass のまま',
    statusOf(ctx, 'check.stageC.summaryCanonicalJson'), 'pass');
  ok('T7-h 正準検査を理由に停止しない', ctx.data.stopReason == null, String(ctx.data.stopReason));
}

// ============================================================
// T8: キー順の入れ替え — **この検査では検出できない**（既知の限界を明文化）
//
//   🔴 依頼時の想定は「キー順を入れ替えただけの summary は拒否される」だったが、
//     実測（2026-08-07）では **素の文字列キーの並べ替えは往復が一致して受理される**。
//     `JSON.parse` はキーの挿入順を保ち、`JSON.stringify` もその順で出すため。
//     並べ替えは manifest の sha256 照合（`check.stageC.manifestFiles`）と
//     summary のバイト比較（`check.stageC.summaryByteExact` / `summaryMatch`）が受け持つ。
//     ここでその事実を固定しておき、将来「キー順も弾けているはず」と誤解するのを防ぐ。
// ============================================================
console.log('');
console.log('[T8 キー順の入れ替えはこの検査では検出できない（既知の限界）]');
{
  const reordered = '{"b":1,"a":2}';
  let threw = false;
  try { parseCanonicalJson(reordered, 'games/block0/summary.json'); } catch { threw = true; }
  ok('T8-a 素の文字列キーの並べ替えは往復一致 → 受理される（限界の明文化）', !threw);

  // ただし「並べ替えた結果 JSON.stringify の出力と違う」形なら弾ける（整数に見えるキー）
  let threw2 = false;
  try { parseCanonicalJson('{"10":1,"2":2}', 'games/block0/summary.json'); } catch { threw2 = true; }
  ok('T8-b 整数に見えるキーの順序違いは拒否される', threw2);
}

// ============================================================
// T9: T2 緊急再計算だけは公開 summary / 既存 root の差を記録して先へ進む
// ============================================================
console.log('');
console.log('[T9 緊急再計算は公開差を記録して続行、通常モードは不変]');
{
  const noncanonical = mutateRaw(
    CANONICAL_SUMMARY_RAW, '"total_points":150', '"total_points":150.0',
  );
  const normal = await runWithSummaryRaw(noncanonical);
  const emergency = await runWithSummaryRaw(noncanonical, { emergency: true });
  eq('T9-a 同じ非正準summaryを通常モードで読むと従来どおりfail',
    statusOf(normal.ctx, 'check.stageC.summaryCanonicalJson'), 'fail');
  eq('T9-b 緊急モードだけ非正準summaryをwarnへ降格する',
    statusOf(emergency.ctx, 'check.stageC.summaryCanonicalJson'), 'warn');
  ok('T9-c 緊急モードは正準検査で停止せず採点まで進む',
    statusOf(emergency.ctx, 'check.stageC.autoDistribute') === 'pass'
      && statusOf(emergency.ctx, 'check.stageC.summaryMatch') !== 'absent',
    emergency.r.error?.message || JSON.stringify(emergency.ctx.report.list()));
  ok('T9-d 非正準summaryのチェーン値・再計算値を構造化差分へ残す',
    emergency.ctx.data.emergencyDifferences?.some((difference) => (
      difference.checkId === 'check.stageC.summaryCanonicalJson'
      && Object.hasOwn(difference, 'chain')
      && Object.hasOwn(difference, 'rebuilt')
    )));

  const zeroRoot = '0x' + '00'.repeat(32);
  const normalRootless = await runWithSummaryRaw(CANONICAL_SUMMARY_RAW, { root: zeroRoot });
  const emergencyRootless = await runWithSummaryRaw(CANONICAL_SUMMARY_RAW, {
    root: zeroRoot, emergency: true,
  });
  eq('T9-e root無しの通常モードは従来どおりnot_readyで停止',
    normalRootless.ctx.data.stopReason, 'not_ready');
  eq('T9-f root無しの緊急モードはrootSubmitted=warnで続行',
    statusOf(emergencyRootless.ctx, 'check.stageC.rootSubmitted'), 'warn');
  ok('T9-g root無しでも独立再計算summary由来のMerkleを必須検査にする',
    statusOf(emergencyRootless.ctx, 'check.stageC.merkleRebuild') === 'pass'
      && paramsOf(emergencyRootless.ctx, 'check.stageC.merkleRebuild').source === 'recomputed-summary'
      && emergencyRootless.ctx.data.emergencyRebuild?.rebuiltSummary,
    emergencyRootless.r.error?.message || JSON.stringify(emergencyRootless.ctx.report.list()));
  ok('T9-h root無しのチェーン値・再計算値を構造化差分へ残す',
    emergencyRootless.ctx.data.emergencyDifferences?.some((difference) => (
      difference.checkId === 'check.stageC.rootSubmitted'
      && Object.hasOwn(difference, 'chain')
      && Object.hasOwn(difference, 'rebuilt')
    )));
}

console.log('');
console.log(`c9: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
