// c8-hostile-public-data-unit.mjs — Stage C（src/stages/results.js）が
// **敵対的な公開データ**を渡されたときの挙動を固定するユニットテスト。
//
// 背景（2026-08-07）:
//   本ツールの脅威モデルは「運営（サーバーを掌握する側）自身も攻撃者でありうる」。
//   つまり公開 R2 のバイト列は**全て運営が書いた敵対的入力**として扱わねばならない。
//   ところが Stage C には次の3つの穴があった。
//
//   ① `perUid` が素の `{}` … uid は `isCanonicalUid` が `/^[\x21-\x7E]+$/` を許すので
//      `__proto__` を置ける。`perUid['__proto__'] = [ids]`（配列＝オブジェクト）は
//      **own property にならず [[Prototype]] の差し替えになる**ため、そのプレイヤーは
//      `Object.entries(perUid)` から消え、**オンチェーンのデポジット検証を丸ごと素通り**する。
//      → 運営が uid を配る立場である以上、検証されないデポジットポイントを作れてしまう。
//
//   ② 正典の再現計算が公開データ由来の値で例外を投げると index.js の最外殻 catch に落ち、
//      `##RESULT fatal` / exit 3 になる。これは「運営の不正を検出した」ではなく
//      「ツールが原因不明で落ちた」という出方で、以降のチェックが全部スキップされる。
//      → 公開データの破損は**運営側の問題**なので FAIL（exit 2）で報告しなければならない。
//
//      ⚠️ 2026-08-07 の正典修正（P-2026-0820）でこの網を踏む入口が移動した。
//        ・`parseDepositWei` / `calculateDepositPoints` は **fail-soft**（非正準 wei → `'0'` / 0pt）に
//          なったので、autoDistribute 経路（`runAutoDistribute` の try/catch）は
//          **公開データだけでは例外に到達できない**（U2 参照。旧テストはここで空振りしていた）。
//          その try/catch は多層防御として残すが、回帰は張れない。
//        ・いま実際に例外が出る入口は **ゲーム経路の `calculateGroupResults`**（fail-closed の塊）で、
//          `results.js` の採点ループ try/catch（`check.stageC.scoring` fail）がそれを受ける。
//          → **U7** がこの網を固定する（4種の公開データ破損 × 3言語）。
//
//   ③ `checkManifest` の `rawOf`（R2キー → 生バイト）が素の `{}`（2026-08-07 追加）…
//      引く鍵は `manifest.files` のキー＝運営が書いた公開バイト列そのもの。
//      `rawOf['toString']` が Object.prototype の関数を返し、`sha256HexOfString()` の
//      `Buffer.from(関数,'utf8')` が TypeError → ②と同じく `##RESULT fatal` / exit 3。
//      manifest は Stage C のほぼ最初に読むので、**1キー仕込むだけで検証全体を止められた**。
//
// ⚠️ 検証点の設計方針（空振り防止）:
//   「例外が出ないこと」だけを見ない。戻り値の形（どのチェックIDがどの status か）・
//   ポイント（totalPoints）・**チェーンから実際に読まれた depositId の集合**まで見る。
//   ③ の readIds が無いと、①の修正を巻き戻しても「players 件数」以外は緑のままになる。
//   また、公開 summary を最小形にすると `summaryMatch` は破損と無関係に常に fail するので、
//   U2 は完全形の summary を組み立て**対照（pass）→ 破損（fail）の反転**で測る。
//
// 🔬 空振りしていないことの実測（2026-08-07・すべて `src/stages/results.js` を壊して確認）:
//   | 壊し方                                                   | 赤くなる assertion            |
//   | 採点ループの try/catch を外す（②の網）                    | U7 全ケース 23件（run() が throw＝fatal） |
//   | runAutoDistribute の `perUid` を `Object.create(null)`→`{}` | U3 3件（players 1 / readIds に 777 無し / totalPoints 170） |
//   | ゲーム経路の `perUid` を `Object.create(null)`→`{}`        | U5 2件（readIds に 888 無し / scoring fail） |
//   | `compareSummary` を常に pass にする                        | U2-b・U2-c 6件               |
//   U2-b の「0 点で再現される」は U2-a との差分（同じ土台で depIds の1トークンだけ違う→150 vs 100）
//   が担保する。正典 `parseDepositWei` の fail-soft 自体は vendor 側なのでここでは壊さない。
//
// 実行: node block-verifier/test/c8-hostile-public-data-unit.mjs （Node 22）

import {
  run as runResults,
  rebuildCanonicalGroupGameResults,
  compareGroupGameResultRows,
  compareGroupCanonicalTimelineRows,
  isClaimMutableArtifact,
  DEPOSIT_IDS_PER_UNIT,
  verifyDepositsOnChainInUnits,
  classifyDepositVerificationError,
} from '../src/stages/results.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { canonicalRosterText } from '../vendor/workers/game_workers/lib/roster-canonical.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { DEFAULTS } from '../src/config.js';
import { t as makeTranslator } from '../src/i18n.js';
import { createReport } from '../src/report.js';
import { sha256HexOfString } from '../src/json-utils.js';
import { keccak256, stringToHex } from 'viem';

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
const HASH_STORAGE = '0x' + '33'.repeat(20);
const ROSTER_MANIFEST = { blockNum: 0, indexSha256: '11'.repeat(32), groups: [] };
const ROSTER_HASH = keccak256(stringToHex(JSON.stringify(ROSTER_MANIFEST)));
const TIMING = {
  startTimeEntryMs: 1700000000000,
  blockTimeMs: 3600000,
  gamePeriodMs: 1800000,
  submitPeriodMs: 600000,
  invariantOk: true,
};
// 適格ロック期限（requiredLockUntilMs = START_TIME + (N+2)*BLOCK_TIME）より十分未来
const UNLOCK_SEC = 2000000000;
const ETH = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 12n).toString(); // n ETH → wei 文字列

// depIds（entry-worker 形式の最小形）
const depIdsJson = (totalWei, ids) => JSON.stringify({ deposit: totalWei, ids });

// ---------------- スタブ ----------------
function makeUi(lang) {
  const tr = makeTranslator(lang);
  return { println() {}, warn() {}, t: tr, askYesNo: async () => false };
}

// EthLock の getLock を返す偽 publicClient。読まれた depositId を記録する（①の実効性測定）。
function makeChainStub({ depositsById, readIds }) {
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
    async blockStates() { return { root: '0x' + 'ab'.repeat(32), verificationStartedAt: 1700000100 }; },
    async getTimingConstants() { return { ...TIMING }; },
    // アンカー未登録 → checkManifest は warn（例外は出さない）
    async getResultHash() { return { hash: '0x' + '00'.repeat(32), updated: 0 }; },
    async resultRegistrationCount() { return 1; },
    // 以下はゲーム経路（reproduceEvidence）でのみ使う
    async latest() { return { number: 1000n }; },
    async getBlock() { return { number: 936n, timestamp: 1900000000n, hash: '0x' + 'cd'.repeat(32), mixHash: '0x' + 'ef'.repeat(32) }; },
    // Q-4（2026-08-08）: Evidence のアドレスは **TokenMining.evidence()**（set-once）から読む。
    //   スタブでは config と同じアドレスを返す（`null` を返すと「未配線」＝6件 FAIL の枝になる）。
    async evidenceAddress() { return EVIDENCE; },
    // R26-C4: 検証に使う EthLock は TokenMining.ethLock()（チェーン値）が権威。
    //   スタブでは config と同じアドレスを返す（`null` は「未配線」＝FAIL の枝になる）。
    async ethLockAddress() { return ETH_LOCK; },
    async resultCount() { return 0; },   // evidence 無効宣言をチェーンが裏付ける経路
    async resultWindow() { return { openAt: 0, closeAt: 0 }; },
    async chatWindow() { return { chatOpenAt: 0, chatCloseAt: 0 }; },
    async currentGrace() { return 100; },
    async otherRegistrationCount() { return 1; },
    async otherRegistrationAt() { return { hash: ROSTER_HASH, registeredBlock: 1, registeredAt: 1 }; },
    // 再現成功時に走る verifyMerkle / verifyTimeline 用（本テストの検証対象ではない）
    async findBlockByTimestamp() { return 900n; },
    async merkleRootEvents() { return []; },
    async verificationPeriod() { return 600; },
    async claimPeriod() { return 10800; },
  };
}

// 🔴 F-6（2026-08-08・ラウンド20 判断不要-6）: 「あるが読めない」を表現できるようにする。
//   値が `CORRUPT_BYTES(str)` なら `r2.js` の parse 失敗と同じ形
//   （`{ data: undefined, raw, parseError }`）を返す。
//   値が `null` / 配列以外の非オブジェクトなら、`JSON.parse('null')` と同じ形をそのまま返す。
const CORRUPT = Symbol('corrupt-bytes');
const CORRUPT_BYTES = (raw) => ({ [CORRUPT]: raw });

function makeR2Stub(files) {
  return {
    baseDir: '/dev/null/block0',
    async fetchJson(key) {
      if (!(key in files)) return null;
      const data = files[key];
      if (data && typeof data === 'object' && CORRUPT in data) {
        const raw = data[CORRUPT];
        return { data: undefined, raw, parseError: `R2 JSON parse failed: ${key}: Unexpected end of JSON input` };
      }
      return { data, raw: JSON.stringify(data) };
    },
    async refetch() { return null; },
    async exists() { return false; },
    setDefaultReuse() {},
  };
}

// 公開アーティファクトの最小セット（manifest は意図的に最小＝該当チェックは fail するが、
// このテストが見るのは深部の autoDistribute / depositVerification だけ）
function makeFiles({ summary, extra = {} }) {
  return {
    [`games/block${N}/summary.json`]: summary,
    [`merkle/block_${N}.json`]: { blockNum: N, root: '0x' + 'ab'.repeat(32), items: [] },
    [`verification/block${N}/manifest.json`]: {
      blockNum: N, algorithm: 'sha256', manifestHash: '0x00', rules: { evidence: null }, files: {},
    },
    ...extra,
  };
}

function makeCtx({ lang = 'ja', players, autoDistribute = true, files, chain }) {
  const report = createReport();
  const fixtureFiles = files;
  if (autoDistribute && [1, 2].includes(players?.length)) {
    const key = `games/block${N}/roster/group0.json`;
    if (!Object.hasOwn(fixtureFiles, key)) {
      try { fixtureFiles[key] = JSON.parse(canonicalRosterText(N, 0, players.map(p => ({ ...p.data, globalIndex: p.globalIndex })))); }
      catch { fixtureFiles[key] = { blockNum: N, groupId: 0, members: players.map(p => ({ ...p.data, globalIndex: p.globalIndex })) }; }
    }
  }
  return {
    cfg: {
      lang,
      pins: DEFAULTS.pins,
      contracts: { ethLock: ETH_LOCK, evidence: EVIDENCE, hashStorage: HASH_STORAGE },
    },
    chain,
    r2: makeR2Stub(fixtureFiles),
    ui: makeUi(lang),
    report,
    blockNum: N,
    data: { autoDistribute, gameSelection: { players, targetBlockNum: 64 }, reuseFiles: false },
  };
}

const player = (uid, depIds, globalIndex) => ({
  globalIndex,
  localIndex: globalIndex,
  file: '00_0',
  data: { uid, addr: '0x' + 'aa'.repeat(20), bAddr: null, lang: 'ja', depIds, name: null, img: null, verified: false },
});

const deposit = (idFrom, idTo, ethAmount) => ({
  amount: ETH(ethAmount), idFrom, idTo, unlockTime: UNLOCK_SEC,
  lockOwnerAddress: '0x' + 'bb'.repeat(20), unlocked: false,
});

// run() を呼び、throw したかどうかも返す（throw = index.js:242-245 が fatal / exit 3 にする経路）
async function callRun(ctx) {
  try {
    await runResults(ctx);
    return { threw: false, error: null };
  } catch (e) {
    return { threw: true, error: e };
  }
}
const statusOf = (ctx, id) => ctx.report.get(id)?.status ?? 'absent';
const paramsOf = (ctx, id) => ctx.report.get(id)?.params ?? {};

// ============================================================
// U1: 正常系（対照実験）— 自動配布が再現でき、ポイントが期待値どおり
// ============================================================
{
  const readIds = [];
  const chain = makeChainStub({
    depositsById: { 1: deposit('20000001', '20000001', 1.0), 2: deposit('20000002', '20000002', 0.25) },
    readIds,
  });
  const players = [
    player('20000001', depIdsJson(ETH(1.0), ['1']), 0),
    player('20000002', depIdsJson(ETH(0.25), ['2']), 1),
  ];
  const ctx = makeCtx({ players, files: makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } }), chain });
  const r = await callRun(ctx);

  ok('U1 run() が例外を投げない', !r.threw, r.error?.message);
  eq('U1 check.stageC.autoDistribute', statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  eq('U1 check.stageC.depositVerification', statusOf(ctx, 'check.stageC.depositVerification'), 'pass');
  eq('U1 depositVerification.players', paramsOf(ctx, 'check.stageC.depositVerification').players, 2);
  // floor(sqrt(1e18/1e14)) = 100 / floor(sqrt(2.5e17/1e14)) = 50
  eq('U1 totalPoints = 100 + 50', ctx.report.getFact('stageC.totalPoints'), 150);
  eq('U1 チェーンから読まれた depositId', [...readIds].sort(), ['1', '2']);
}

// ============================================================
// U2: 公開データ破損（uid 欠落 ＋ deposit が非正準 wei）— 自動配布経路
//
//   旧前提（〜2026-08-07）: `parseDepositWei('abc')` → `BigInt('abc')` が SyntaxError を投げ、
//   `runAutoDistribute` の try/catch が `check.stageC.autoDistribute = fail` に落とす。
//
//   新前提（P-2026-0820・正典修正後の実測）: `parseDepositWei` は **fail-soft** で `'0'` を返し、
//   `calculateDepositPoints` も非正準 wei を 0pt に丸める。つまり **例外は起きず、再現は成功する**。
//   その代わり、そのプレイヤーは **0 点**として再現され、運営が公開した summary（そのレコードに
//   点数と報酬を付けている）と食い違って **`check.stageC.summaryMatch` が fail** になる。
//   → クラッシュではなく「運営の公開データと再現結果が食い違う」という本来の形で検出される。
//
//   ⚠️ 空振り防止: `summary.json` を最小形にすると summaryMatch は**破損と無関係に**必ず fail する。
//     そこで公開 summary は `buildAutoSummary()` で**完全形**を組み立て、
//     U2-a（健全な depIds）では summaryMatch が **pass** することを先に示してから、
//     U2-b（壊れた depIds）で fail に反転することを見る。差分の中身（当該プレイヤーが 0 点）まで見る。
// ============================================================

// RA-01: U1 の盤の公開値だけを深くする。FAIL 後も Merkle と timeline まで到達すること。
{
  const chain = makeChainStub({
    depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds: [],
  });
  const published = JSON.parse('['.repeat(2000) + ']'.repeat(2000));
  const ctx = makeCtx({
    players: [player('20000001', depIdsJson(ETH(1.0), ['1']), 0)], chain,
    files: makeFiles({ summary: { blockNum: N, autoDistributed: published, groups: [] } }),
  });
  const r = await callRun(ctx);
  ok('RA-01 深さ2000の公開値で fatal にしない', !r.threw, r.error?.message);
  eq('RA-01 名前つきの FAIL', statusOf(ctx, 'check.stageC.autoDistributeConsistent'), 'fail');
  ok('RA-01 公開値の参照を保持', paramsOf(ctx, 'check.stageC.autoDistributeConsistent').published === published);
  eq('RA-01 再計算を続ける', statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  ok('RA-01 後段の Merkle 検査に到達', statusOf(ctx, 'check.stageC.merkleRoot') !== 'absent');
  ok('RA-01 後段の timeline 検査に到達', statusOf(ctx, 'check.stageC.timelineWindows') !== 'absent');
}

const REWARD_WEI = getBlockRewardWei(N);
// RB-03: 結果manifestの深いrules.protocolが、緊急の書き手へ渡る許容checkに残る。
for (const depth of [3000, 4000, 6000]) {
  const protocol = JSON.parse('['.repeat(depth) + ']'.repeat(depth));
  const files = makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } });
  files[`verification/block${N}/manifest.json`].rules.protocol = protocol;
  const ctx = makeCtx({
    players: [player('20000001', depIdsJson(ETH(1.0), ['1']), 0)], files,
    chain: makeChainStub({ depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds: [] }),
  });
  const result = await callRun(ctx);
  ok(`RB-03 manifest protocol深さ${depth}でStage Cを続ける`, !result.threw);
  eq(`RB-03 manifest protocol深さ${depth}は名前つきFAIL`, statusOf(ctx, 'check.stageC.rulesReward'), 'fail');
  ok(`RB-03 manifest protocol深さ${depth}の参照を保持`, paramsOf(ctx, 'check.stageC.rulesReward').protocol === protocol);
  ok(`RB-03 manifest protocol深さ${depth}でも後段に到達`, statusOf(ctx, 'check.stageC.timelineWindows') !== 'absent');
}
const P_ADDR = '0x' + 'aa'.repeat(20);
const P_DEPOSITER = '0x' + 'bb'.repeat(20);

// 運営が公開する summary.json（autoDistribute 版）を**テスト側で独立に**組み立てる。
// 形状の正典は game-master-DO.js autoDistribute:3404-3449（results.js の rebuilt と同形）。
// rows: [{ uid, depIds, points, deposits:[{ depositId, amountWei, idFrom }] }]
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
      playerShare = full;   // 適格デポジット無し＝50/50 スプリットせず全額プレイヤー
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

const P1_DEPIDS = depIdsJson(ETH(1.0), ['1']);          // 1.0 ETH をチェーンで裏付け → 100pt
const P2_DEPIDS_OK = depIdsJson(ETH(0.25), []);         // 自己申告 0.25 ETH（正準 wei）→ 50pt
const P2_DEPIDS_BAD = '{"deposit":"abc","ids":[]}';     // 自己申告の wei が非正準 → fail-soft で 0pt

// 運営はどちらの場合も「player2 に 50 点／その分の報酬を配った」と公表する。
// 違うのは公開エントリー（game_selection.json）側の depIds が正準かどうかだけ。
const publishedSummaryFor = (p2DepIds) => buildAutoSummary([
  { uid: '20000001', depIds: P1_DEPIDS, points: 100,
    deposits: [{ depositId: '1', amountWei: ETH(1.0), idFrom: '20000001' }] },
  { uid: null, depIds: p2DepIds, points: 50, deposits: [] },
]);

async function autoDistributeDepositCase(p2DepIds, lang = 'ja') {
  const readIds = [];
  const chain = makeChainStub({ depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds });
  const players = [
    player('20000001', P1_DEPIDS, 0),
    // uid 欠落なら自己申告 wei を読む。例外にせず名前付き FAIL を返すことも検査する。
    player(null, p2DepIds, 1),
  ];
  const ctx = makeCtx({ lang, players, files: makeFiles({ summary: publishedSummaryFor(p2DepIds) }), chain });
  return { ctx, r: await callRun(ctx), readIds };
}

// U2-a 対照: 自己申告が正準 wei なら再現は公開 summary と一致する
{
  const { ctx, r } = await autoDistributeDepositCase(P2_DEPIDS_OK);
  ok('U2-a 対照: run() が例外を投げない', !r.threw, r.error?.message);
  eq('U2-a 対照: check.stageC.autoDistribute', statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  eq('U2-a 対照: totalPoints = 100 + 50', ctx.report.getFact('stageC.totalPoints'), 150);
  eq('U2-a 対照: check.stageC.summaryMatch = pass（この土台では summaryMatch は通る）',
    statusOf(ctx, 'check.stageC.summaryMatch'), 'pass');
  // 🔴 P-2026-0842（2026-08-08・台帳 C-3）: 正典が公開 summary に実行時刻
  //    （`updatedAt` / `createdAt`）を入れなくなったので、再構築版と**バイト単位で一致**する
  //    ようになった。`compareSummary` はその場合 `{ mode: 'byte' }` で早期 return し、
  //    中立化比較（`diffCount`）まで進まない。byteExact は diffCount===0 より強い性質なので、
  //    どちらかが成立していれば PASS とする（旧ブロック＝時刻入り summary は後者を通る）。
  {
    const byteExact = statusOf(ctx, 'check.stageC.summaryByteExact') === 'pass';
    const dc = paramsOf(ctx, 'check.stageC.summaryMatch').diffCount;
    ok('U2-a 対照: 差分0件（byteExact か diffCount=0）', byteExact || dc === 0,
      `byteExact=${byteExact} diffCount=${dc}`);
  }
}

// U2-b 本番: 自己申告 wei が非正準 → fail-soft で 0pt → 公開 summary と食い違う
// WR-3: K11 の後に同じ uid 宛てのロック番号が作られた場合、K11 で作った
// summary は一致し、旧 GM の latest で作った summary は不一致になる。
{
  const readHeights = [];
  const chain = makeChainStub({ depositsById: {
    1: deposit('20000001', '20000001', 1.0),
    2: deposit('20000002', '20000002', 0.25),
  }, readIds: [] });
  const originalRead = chain.client.readContract;
  chain.client.readContract = async (args) => {
    readHeights.push(args.blockNumber);
    if (String(args.args[0]) === '2' && args.blockNumber === 64n) {
      return { ...deposit('0', '0', 0), unlockTime: 0 };
    }
    return originalRead(args);
  };
  const players = [player('20000001', P1_DEPIDS, 0), player('20000002', P2_DEPIDS_OK, 1)];
  const k11Summary = buildAutoSummary([
    { uid: '20000001', depIds: P1_DEPIDS, points: 100,
      deposits: [{ depositId: '1', amountWei: ETH(1.0), idFrom: '20000001' }] },
    { uid: '20000002', depIds: P2_DEPIDS_OK, points: 0, deposits: [] },
  ]);
  k11Summary.groups[0].members[1].is_disqualified = 1;
  k11Summary.groups[0].members[1].disqualify_reason = 'ineligible_deposit';
  const ctx = makeCtx({ players, files: makeFiles({ summary: k11Summary }), chain });
  const result = await callRun(ctx);
  ok('WR-3 K11 summary: Stage C が例外なし', !result.threw, result.error?.message);
  ok('WR-3 K11 summary: 一致', statusOf(ctx, 'check.stageC.summaryMatch') === 'pass',
    JSON.stringify(paramsOf(ctx, 'check.stageC.summaryMatch')));
  ok('WR-3 K11 summary: 全 getLock は K11 を指定', readHeights.length > 0 && readHeights.every(h => h === 64n));

  const latestCtx = makeCtx({ players, files: makeFiles({ summary: publishedSummaryFor(P2_DEPIDS_OK) }), chain });
  const latestResult = await callRun(latestCtx);
  ok('WR-3 latest summary: Stage C が例外なし', !latestResult.threw, latestResult.error?.message);
  eq('WR-3 latest summary: 不一致', statusOf(latestCtx, 'check.stageC.summaryMatch'), 'fail');

  for (const invalidTarget of [undefined, -1, 1.5, '64']) {
    const reads = [];
    const badChain = makeChainStub({ depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds: reads });
    const badCtx = makeCtx({ players, files: makeFiles({ summary: k11Summary }), chain: badChain });
    badCtx.data.gameSelection.targetBlockNum = invalidTarget;
    const badResult = await callRun(badCtx);
    ok(`WR-3 不正K11 ${String(invalidTarget)}: 例外なしで停止`, !badResult.threw && badCtx.data.stopReason === 'fail');
    eq(`WR-3 不正K11 ${String(invalidTarget)}: getLock 前に停止`, reads.length, 0);
  }
}

// U2-b 本番: 自己申告 wei が非正準 → fail-soft で 0pt → 公開 summary と食い違う
{
  const { ctx, r } = await autoDistributeDepositCase(P2_DEPIDS_BAD);
  ok('U2-b run() が例外を投げない（= ##RESULT fatal / exit 3 にならない）', !r.threw, r.error?.message);
  eq('U2-b uid 欠落は rosterIndex の名前付き FAIL', statusOf(ctx, 'check.stageC.rosterIndex'), 'fail');
  eq('U2-b uid 欠落は rosterKeys の名前付き FAIL', statusOf(ctx, 'check.stageC.rosterKeys'), 'fail');
  // 再現は「成功する」。クラッシュではなく食い違いとして出るのが新しい正しい姿。
  eq('U2-b check.stageC.autoDistribute = pass（再現自体は成立する）',
    statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  eq('U2-b 当該プレイヤーは 0 点で再現される（totalPoints = 100 + 0）',
    ctx.report.getFact('stageC.totalPoints'), 100);
  eq('U2-b autoDistribute.players は 2 のまま（レコードは落とさない）',
    paramsOf(ctx, 'check.stageC.autoDistribute').players, 2);
  // 結論: 運営の公表値と食い違う（= ##RESULT fail / exit 2）
  eq('U2-b check.stageC.summaryMatch = fail', statusOf(ctx, 'check.stageC.summaryMatch'), 'fail');
  const diffs = String(paramsOf(ctx, 'check.stageC.summaryMatch').diffs || '');
  ok('U2-b 差分に「当該プレイヤーの deposit_points が 0（公表は 50）」が載る',
    diffs.includes('groups.0.members.1.deposit_points') && diffs.includes('"a":"0"') && diffs.includes('"b":"50"'),
    diffs.slice(0, 400));
  ok('U2-b 差分にグループ合計点の食い違いが載る',
    diffs.includes('groups.0.total_points'), diffs.slice(0, 400));
  // 深部チェックは「動かせなかった」ではなく「動いて食い違った」— 記録されていること自体を固定
  eq('U2-b autoDistributeConsistent は記録される',
    statusOf(ctx, 'check.stageC.autoDistributeConsistent'), 'pass');
}

// U2-c 3言語: 第三者が「運営の公開データと再現結果が食い違っている」と読めること
for (const [lang, needles] of [
  ['ja', ['再構築したsummaryが公開版と', 'フィールドで異なります']],
  ['en', ['Rebuilt summary differs from the published one', 'field(s)']],
  ['zh', ['重建的 summary 与公布版本在', '个字段上不同']],
]) {
  const { ctx } = await autoDistributeDepositCase(P2_DEPIDS_BAD, lang);
  const anomalies = ctx.report.getFact('stageC.anomalies') || [];
  const msg = anomalies.find(a => needles.every(nd => a.includes(nd)));
  // sample には先頭5件が載る。運営の公表合計（150）と再現合計（100）の食い違いが
  // その先頭に来る＝第三者が最初に読む1行で「公表値と再現値が違う」と分かること。
  ok(`U2-c/${lang} アノマリーに summary 食い違いのメッセージがある（公表150 vs 再現100）`,
    !!msg && msg.includes('groups.0.total_points') && msg.includes('"a":"100"') && msg.includes('"b":"150"'),
    JSON.stringify(anomalies));
}

// ============================================================
// U3: uid = '__proto__'（プロトタイプ穴・自動配布経路）
//   素の `{}` だと perUid への代入が [[Prototype]] 差し替えになって
//   **そのプレイヤーがオンチェーン検証から丸ごと消える**。
//   → 「players 件数」「実際にチェーンから読まれた depositId」「合計ポイント」で測る。
//
//   実測（2026-08-07・vendor 同期後）: 正典側の `verifiedDepositWei` / `verifiedDeposits` も
//   `Object.create(null)` になったので、`__proto__` の uid は**素直に権威表へ載る**。
//   ただし契約 `TokenMining._parseUint` が数字以外の uid を受け付けないため
//   （`calcFilterEligibleDeposits` の `/^\d{1,20}$/` ゲート）、適格デポジットは 0 ＝ **0 点**。
//   ＝ U4 と同じ fail-closed で着地し、例外も FAIL も出ない。
//
//   🔴 ここで `totalPoints = 100` を固定するのが本体の検査:
//     `results.js` の `perUid` を素の `{}` に戻すと、`__proto__` プレイヤーは perUid から消え
//     → 権威表に行が無い → **自己申告 depIds（0.5 ETH）へフォールバックして 50 点**になり
//     合計 150 になる。「オンチェーン検証を素通りした点数」が数値として現れる。
// ============================================================
{
  const readIds = [];
  const chain = makeChainStub({
    depositsById: { 1: deposit('20000001', '20000001', 1.0), 777: deposit('20000001', '20000001', 0.5) },
    readIds,
  });
  const players = [
    player('20000001', depIdsJson(ETH(1.0), ['1']), 0),
    player('__proto__', depIdsJson(ETH(0.5), ['777']), 1),
  ];
  const ctx = makeCtx({ players, files: makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } }), chain });
  const r = await callRun(ctx);

  eq('U3 depositVerification.players = 2（__proto__ の uid が落ちない）',
    paramsOf(ctx, 'check.stageC.depositVerification').players, 2);
  ok('U3 __proto__ プレイヤーの depositId もチェーン照合される',
    readIds.includes('777'), `readIds=${JSON.stringify(readIds)}`);
  ok('U3 fatal にはならない（例外を投げない）', !r.threw, r.error?.message);
  eq('U3 check.stageC.autoDistribute = pass（再現は成立する）',
    statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  eq('U3 totalPoints = 100（__proto__ の適格デポジットは 0 ＝ 自己申告へ落ちない）',
    ctx.report.getFact('stageC.totalPoints'), 100);
}

// ============================================================
// U4: uid が 'constructor' / 'toString' / 'valueOf' / 'hasOwnProperty'
//   （own property として素直に載る名前。回帰ガード＝壊さないことの確認）
// ============================================================
{
  const readIds = [];
  const names = ['constructor', 'toString', 'valueOf', 'hasOwnProperty'];
  const depositsById = {};
  const players = names.map((uid, i) => {
    depositsById[String(100 + i)] = deposit('20000001', '20000001', 1.0);
    return player(uid, depIdsJson(ETH(1.0), [String(100 + i)]), i);
  });
  const chain = makeChainStub({ depositsById, readIds });
  const ctx = makeCtx({ players, files: makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } }), chain });
  const r = await callRun(ctx);

  ok('U4 run() が例外を投げない', !r.threw, r.error?.message);
  eq('U4 depositVerification.players = 4', paramsOf(ctx, 'check.stageC.depositVerification').players, 4);
  eq('U4 4件とも depositId がチェーン照合される', [...readIds].sort(), ['100', '101', '102', '103']);
  // uid が数字でない＝契約 TokenMining._parseUint を通らないので適格デポジット0＝0ポイント。
  // 「例外なく 0 点で確定する」ところまで固定する（fail-closed の維持）。
  eq('U4 check.stageC.autoDistribute', statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
  eq('U4 totalPoints = 0（数字でない uid は適格デポジット0）', ctx.report.getFact('stageC.totalPoints'), 0);
}

// ============================================================
// U5: ゲーム経路（autoDistribute ではない方）の perUid も同じ穴を塞げているか
// ============================================================
{
  const readIds = [];
  const chain = makeChainStub({
    depositsById: { 1: deposit('20000001', '20000001', 1.0), 888: deposit('20000001', '20000001', 0.5) },
    readIds,
  });
  const members = [
    player('20000001', depIdsJson(ETH(1.0), ['1']), 0),
    player('__proto__', depIdsJson(ETH(0.5), ['888']), 1),
  ];
  // reconstructD1Groups が作る membersJson と同形（アーカイブ members はこれと一致必須）
  const archiveMembers = members.map(m => ({
    uid: m.data.uid, addr: m.data.addr, bAddr: m.data.bAddr, lang: m.data.lang,
    depIds: m.data.depIds, globalIndex: m.globalIndex, name: null, img: null, verified: false,
  }));
  const files = makeFiles({
    summary: { blockNum: N, autoDistributed: false, groups: [{ group_id: 0, members: [] }] },
    extra: {
      [`entries/block${N}/game_selection.json`]: { blockNum: N, players: members },
      [`entries/block${N}/game_groups.json`]: { blockNum: N, groups: [] },
      [`games/block${N}/group0.json`]: {
        meta: { blockNum: N, groupId: 0 },
        members: archiveMembers,
        submissions: {}, submissionsRaw: {},
      },
    },
  });
  const ctx = makeCtx({ players: members, autoDistribute: false, files, chain });
  ctx.data.groupsDerived = [{ groupId: 0, members }];
  const r = await callRun(ctx);

  ok('U5 run() が例外を投げない', !r.threw, r.error?.message);
  eq('U5 check.stageC.depositVerification', statusOf(ctx, 'check.stageC.depositVerification'), 'pass');
  ok('U5 ゲーム経路でも __proto__ プレイヤーの depositId がチェーン照合される',
    readIds.includes('888'), `readIds=${JSON.stringify(readIds)}`);
  // 正典 calculateGroupResults の fail-closed ゲート（P-2026-0822: 名簿の全員が権威表に
  // own property で載っていること）を通過できることまで見る。perUid が素の `{}` に戻ると
  // `__proto__` の行が権威表から消えて、このゲートが throw → scoring が fail に反転する。
  eq('U5 check.stageC.scoring = pass（権威表に __proto__ の行がある）',
    statusOf(ctx, 'check.stageC.scoring'), 'pass');
}

// WR-3 通常ゲーム: K11 後のロック番号を latest が返す盤で summary を両方向に照合する。
{
  const members = [
    player('20000001', depIdsJson(ETH(1.0), ['1']), 0),
    player('20000002', depIdsJson(ETH(0.5), ['2']), 1),
    player('20000003', depIdsJson(ETH(0.25), ['3']), 2),
  ];
  const archiveMembers = members.map(m => ({
    uid: m.data.uid, addr: m.data.addr, bAddr: m.data.bAddr, lang: m.data.lang,
    depIds: m.data.depIds, globalIndex: m.globalIndex, name: null, img: null, verified: false,
  }));
  const filesFor = (summary) => makeFiles({ summary, extra: {
    [`entries/block${N}/game_selection.json`]: { blockNum: N, players: members, targetBlockNum: 64 },
    [`entries/block${N}/game_groups.json`]: { blockNum: N, groups: [] },
    [`games/block${N}/group0.json`]: { meta: { blockNum: N, groupId: 0 },
      members: archiveMembers, submissions: {}, submissionsRaw: {} },
  } });
  const readHeights = [];
  let lateAtK11 = false;
  const chain = makeChainStub({ depositsById: {
    1: deposit('20000001', '20000001', 1.0),
    2: deposit('20000002', '20000002', 0.5),
    3: deposit('20000003', '20000003', 0.25),
  }, readIds: [] });
  const originalRead = chain.client.readContract;
  chain.client.readContract = async (args) => {
    readHeights.push(args.blockNumber);
    if (String(args.args[0]) === '3' && args.blockNumber === 64n && !lateAtK11) {
      return { ...deposit('0', '0', 0), unlockTime: 0 };
    }
    return originalRead(args);
  };
  const originalWriter = GameMasterDO.prototype.buildBlockSummaryWithResults;
  let rebuilt;
  GameMasterDO.prototype.buildBlockSummaryWithResults = async function (...args) {
    rebuilt = await originalWriter.apply(this, args);
    return rebuilt;
  };
  const runCase = async (summary) => {
    const ctx = makeCtx({ players: members, autoDistribute: false, files: filesFor(summary), chain });
    ctx.data.groupsDerived = [{ groupId: 0, members }];
    const result = await callRun(ctx);
    ok('WR-3 通常ゲーム: 例外なし', !result.threw, result.error?.message);
    return ctx;
  };
  try {
    await runCase({ blockNum: N, autoDistributed: false, groups: [{ group_id: 0, members: [] }] });
    const k11Summary = rebuilt;
    ok('WR-3 通常ゲーム: K11 summary を再構築', !!k11Summary);
    const k11Ctx = await runCase(k11Summary);
    eq('WR-3 通常ゲーム: K11 summary 一致', statusOf(k11Ctx, 'check.stageC.summaryMatch'), 'pass');
    ok('WR-3 通常ゲーム: getLock は K11', readHeights.length > 0 && readHeights.every(h => h === 64n));
    lateAtK11 = true;
    await runCase({ blockNum: N, autoDistributed: false, groups: [{ group_id: 0, members: [] }] });
    const latestSummary = rebuilt;
    lateAtK11 = false;
    const latestCtx = await runCase(latestSummary);
    eq('WR-3 通常ゲーム: latest summary 不一致', statusOf(latestCtx, 'check.stageC.summaryMatch'), 'fail');
  } finally {
    GameMasterDO.prototype.buildBlockSummaryWithResults = originalWriter;
  }
}

// ============================================================
// U6: manifest.files のキーが Object.prototype 由来の名前
//     （'__proto__' / 'toString' / 'constructor' / 'valueOf'）
//
//   checkManifest は「manifest が宣言した sha256」と「手元の生バイトの sha256」を突き合わせる
//   ために `rawOf`（R2キー → 生バイト）を引く。この辞書が素の `{}` だと
//   `rawOf['toString']` が **Object.prototype の関数**を返し、直後の
//   `sha256HexOfString(関数)` の `Buffer.from(関数,'utf8')` が TypeError を投げる。
//   → index.js:242-245 の最外殻 catch に落ちて `##RESULT fatal` / exit 3。
//     そこで検証が打ち切られ、採点再現・merkle・タイムラインは全部スキップされる。
//     第三者には「運営の不正を検出した」ではなく「ツールが原因不明で落ちた」としか見えない。
//   `manifest.files` のキーは**運営が書いた公開バイト列そのもの**なので、
//   ここは FAIL（exit 2）＝検証結果として報告しなければならない。
//
//   ⚠️ テストデータの作り方（ここを間違えると空振りする）:
//     実物の `r2.fetchJson` は必ず `JSON.parse` を通る。`JSON.parse('{"__proto__":1}')` は
//     **own property** を作るので `Object.keys()` に出てくる。一方 JS のオブジェクト
//     リテラル `{ __proto__: 1 }` は [[Prototype]] 差し替えで own property にならない＝
//     本物の公開データを再現できない。したがって必ず JSON 文字列から組み立てる。
// ============================================================
const manifestFromJson = (filesJson) => JSON.parse(
  `{"blockNum":${N},"algorithm":"sha256","manifestHash":"0x00","rules":{"evidence":null},"files":${filesJson}}`
);

async function manifestFilesCase(filesJson) {
  const readIds = [];
  const chain = makeChainStub({ depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds });
  const players = [player('20000001', depIdsJson(ETH(1.0), ['1']), 0)];
  const base = makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } });
  const files = { ...base, [`verification/block${N}/manifest.json`]: manifestFromJson(filesJson) };
  const ctx = makeCtx({ players, files, chain });
  return { ctx, r: await callRun(ctx), base };
}

const HASH64 = 'a'.repeat(64);
for (const key of ['__proto__', 'toString', 'constructor', 'valueOf']) {
  const { ctx, r } = await manifestFilesCase(`{"${key}":"${HASH64}"}`);
  ok(`U6[${key}] run() が例外を投げない（= ##RESULT fatal / exit 3 にならない）`, !r.threw, r.error?.message);
  eq(`U6[${key}] check.stageC.manifestFiles = fail`,
    statusOf(ctx, 'check.stageC.manifestFiles'), 'fail');
  ok(`U6[${key}] failures に当該キーが載る`,
    String(paramsOf(ctx, 'check.stageC.manifestFiles').failures || '').includes(key),
    JSON.stringify(paramsOf(ctx, 'check.stageC.manifestFiles')));
  // 「fatal で打ち切られていない」ことを、後続の深部チェックが到達している事実で測る
  eq(`U6[${key}] 検証は打ち切られず autoDistribute の再現まで到達する`,
    statusOf(ctx, 'check.stageC.autoDistribute'), 'pass');
}

// U6-a 対照: 正当な R2 キーの宣言ハッシュは従来どおり引けて pass になる
//（`rawOf` の作り替えで通常経路を壊していないことの担保）
{
  const shape = makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } });
  const decl = {};
  for (const k of [`games/block${N}/summary.json`, `merkle/block_${N}.json`]) {
    decl[k] = sha256HexOfString(JSON.stringify(shape[k]));
  }
  const { ctx, r } = await manifestFilesCase(JSON.stringify(decl));
  ok('U6-a 対照: run() が例外を投げない', !r.threw, r.error?.message);
  eq('U6-a 対照: check.stageC.manifestFiles = pass', statusOf(ctx, 'check.stageC.manifestFiles'), 'pass');
  eq('U6-a 対照: 宣言2件とも照合された', paramsOf(ctx, 'check.stageC.manifestFiles').checked, 2);
}

// ============================================================
// U7（②の網）: 正典 `calculateGroupResults` が公開データ由来の値で例外を投げても
//              `##RESULT fatal` / exit 3 にせず、FAIL（exit 2）で報告する
//
//   `results.js` の採点ループ try/catch がこの網。ここが無いと index.js:242-245 の最外殻
//   catch に落ち、第三者には「運営の不正を検出した」ではなく「ツールが原因不明で落ちた」と
//   しか見えず、以降のチェック（報酬按分・merkle・タイムライン）が全部スキップされる。
//
//   ⚠️ 入口はすべて**公開データだけで作れる形**であること（第三者が実際に踏む経路）:
//     (a)(b) `games/block{N}/group{G}.json` の `meta`（運営が書くアーカイブ）
//            → 正典 `canonMetaInt`（P-2026-0820 C-4）が fail-closed で throw。
//            🔴 本ツール側の `buildGroupDataList` の meta 照合は `Number(...)` 比較なので
//               `'0x0'` / `' 0 '` は**素通りして groupMeta が pass する**（実測）。
//               ゆるい自前チェックではなく正典の fail-closed が効いていることの確認になる。
//     (c)    `entries/block{N}/game_selection.json` に同じ uid を2件（→ Stage B のグループにも
//            重複が乗る）→ 正典の名簿検査（P-2026-0811 #7/#14）が throw。
//     (d)    アーカイブ名簿にだけ居て `game_selection.json` に居ないメンバー
//            → 権威表にその行が作られない → 正典の fail-closed ゲート（P-2026-0822）が throw。
// ============================================================
function gameScoringCase({
  metaOverride = {}, members, selectionPlayers = null, lang = 'ja', groupResults = undefined,
  canonicalTimeline = undefined, summarySchemaVersion = 3,
}) {
  const readIds = [];
  const chain = makeChainStub({
    depositsById: { 1: deposit('20000001', '20000001', 1.0), 2: deposit('20000002', '20000002', 0.5) },
    readIds,
  });
  const archiveMembers = members.map(m => ({
    uid: m.data.uid, addr: m.data.addr, bAddr: m.data.bAddr, lang: m.data.lang,
    depIds: m.data.depIds, globalIndex: m.globalIndex, name: null, img: null, verified: false,
  }));
  const selection = selectionPlayers ?? members;
  const groupArchive = {
    meta: { blockNum: N, groupId: 0, ...metaOverride },
    members: archiveMembers, submissions: {}, submissionsRaw: {},
  };
  if (groupResults !== undefined) groupArchive.gameResults = JSON.parse(JSON.stringify(groupResults));
  if (canonicalTimeline !== undefined) {
    groupArchive.canonicalTimeline = JSON.parse(JSON.stringify(canonicalTimeline));
  }
  const files = makeFiles({
    summary: { schemaVersion: summarySchemaVersion, blockNum: N, autoDistributed: false, groups: [{ group_id: 0, members: [] }] },
    extra: {
      [`entries/block${N}/game_selection.json`]: { blockNum: N, players: selection },
      [`entries/block${N}/game_groups.json`]: { blockNum: N, groups: [] },
      [`games/block${N}/group0.json`]: groupArchive,
      [`games/block${N}/roster/manifest.json`]: ROSTER_MANIFEST,
    },
  });
  const ctx = makeCtx({ lang, players: selection, autoDistribute: false, files, chain });
  ctx.data.groupsDerived = [{ groupId: 0, members }];
  // U11 で「アンカー後に claimed だけ書き換わったR2」を、同じ公開バイト経路で作る。
  ctx.__testFiles = files;
  return ctx;
}
const healthyRoster = () => [
  player('20000001', depIdsJson(ETH(1.0), ['1']), 0),
  player('20000002', depIdsJson(ETH(0.5), ['2']), 1),
];

// R31-D-4c-01: public Evidence report remains adversarial in ordinary run().
// Re-anchor every changed report byte in the public manifest, so the verdict
// is evidenceReportMatch rather than an unrelated manifest hash failure.
const m3EvidenceKey = `verification/block${N}/evidence-report.json`;
const m3EvidenceReport = {
  contractAddress: EVIDENCE, blockNum: N, resultCount: 0,
  window: { openAt: 0, closeAt: 0 },
  chatWindow: { chatOpenAt: 0, chatCloseAt: 0,
    clockSkewAllowMs: DEFAULTS.pins.clockSkewAllowMs },
  safeBlock: '936', confirmations: DEFAULTS.pins.confirmationBlocks,
  adopted: [], invalid: [],
};
for (const [label, change] of [
  ['control', (report) => report],
  ['adopted', (report) => ({ ...report, adopted: [{ uid: '20000001', groupId: 0,
    seq: 1, txHash: '0x' + '11'.repeat(32) }] })],
  ['invalid', (report) => ({ ...report, invalid: [{ seq: 1, reason: 'forged' }] })],
  ['resultCount', (report) => ({ ...report, resultCount: 1 })],
]) {
  const ctx = gameScoringCase({ members: healthyRoster() });
  const files = ctx.__testFiles;
  const publicReport = change(structuredClone(m3EvidenceReport));
  files[m3EvidenceKey] = publicReport;
  const manifest = files[`verification/block${N}/manifest.json`];
  manifest.files[m3EvidenceKey] = sha256HexOfString(JSON.stringify(publicReport));
  manifest.manifestHash = sha256HexOfString(JSON.stringify({
    blockNum: manifest.blockNum, algorithm: manifest.algorithm,
    rules: manifest.rules, files: manifest.files,
  }));
  const ran = await callRun(ctx);
  ok(`M3 通常モード Evidence report ${label}: run() 完走`, !ran.threw, ran.error?.message);
  eq(`M3 通常モード Evidence report ${label}: evidenceReportMatch`,
    statusOf(ctx, 'check.stageC.evidenceReportMatch'), label === 'control' ? 'pass' : 'fail');
}

const U7_CASES = [
  ['a: meta.groupId が非正準（"0x0"）', { metaOverride: { groupId: '0x0' }, members: healthyRoster() },
    'invalid meta.groupId'],
  ['b: meta.blockNum が非正準（" 0 "）', { metaOverride: { blockNum: ' 0 ' }, members: healthyRoster() },
    'invalid meta.blockNum'],
  ['c: 名簿に uid 重複', {
    members: [
      player('20000001', depIdsJson(ETH(1.0), ['1']), 0),
      player('20000001', depIdsJson(ETH(0.5), ['2']), 1),
    ],
  }, 'invalid member roster'],
  ['d: 権威表に行が無いメンバー', (() => {
    const m = healthyRoster();
    return { members: m, selectionPlayers: [m[0]] };
  })(), 'verified deposit table is incomplete'],
];

for (const [label, spec, needle] of U7_CASES) {
  const ctx = gameScoringCase(spec);
  const r = await callRun(ctx);
  ok(`U7[${label}] run() が例外を投げない（= ##RESULT fatal / exit 3 にならない）`, !r.threw, r.error?.message);
  eq(`U7[${label}] check.stageC.scoring = fail`, statusOf(ctx, 'check.stageC.scoring'), 'fail');
  ok(`U7[${label}] fail に正典の例外メッセージが載る`,
    String(paramsOf(ctx, 'check.stageC.scoring').failures || '').includes(needle),
    JSON.stringify(paramsOf(ctx, 'check.stageC.scoring')));
  eq(`U7[${label}] 採点できたグループは0`, paramsOf(ctx, 'check.stageC.scoring').groups, 0);
  // 採点0件で Stage C は停止する。index.js は fatal ではなく FAIL（exit 2）として分類する。
  eq(`U7[${label}] stopReason = fail（exit 2 側）`, ctx.data.stopReason, 'fail');
  // 深部チェックは動かせないので pass にしない（空振り防止）
  eq(`U7[${label}] summaryMatch は記録されない`, statusOf(ctx, 'check.stageC.summaryMatch'), 'absent');
  eq(`U7[${label}] merkleRoot は記録されない`, statusOf(ctx, 'check.stageC.merkleRoot'), 'absent');
}

// U7-meta: 自前の meta 照合はゆるい（`Number('0x0') === 0`）ので pass してしまう。
// 「正典の fail-closed が最後の砦である」ことを事実として固定する。
{
  const ctx = gameScoringCase({ metaOverride: { groupId: '0x0' }, members: healthyRoster() });
  await callRun(ctx);
  eq('U7-meta 本ツールの groupMeta 照合は "0x0" を素通しする（正典側が止める）',
    statusOf(ctx, 'check.stageC.groupMeta'), 'pass');
}

// U7-ctrl 対照: 同じ土台で健全な公開データなら採点は通る（土台が壊れていないことの担保）
{
  const ctx = gameScoringCase({ members: healthyRoster() });
  const r = await callRun(ctx);
  ok('U7-ctrl 対照: run() が例外を投げない', !r.threw, r.error?.message);
  eq('U7-ctrl 対照: check.stageC.scoring = pass', statusOf(ctx, 'check.stageC.scoring'), 'pass');
  eq('U7-ctrl 対照: 1グループ採点できた', paramsOf(ctx, 'check.stageC.scoring').groups, 1);
  eq('U7-ctrl 対照: 停止しない', ctx.data.stopReason, undefined);
}

// U7-lang 3言語: 第三者が「運営の公開データがおかしい（本番も同じくスキップする）」と読めること
for (const [lang, needles] of [
  ['ja', ['グループ0を採点できませんでした', '本番も同様にスキップします']],
  ['en', ['Group 0 could not be scored', 'production would skip it too']],
  ['zh', ['小组 0 无法计分', '生产环境同样会跳过']],
]) {
  const ctx = gameScoringCase({ metaOverride: { groupId: '0x0' }, members: healthyRoster(), lang });
  await callRun(ctx);
  const anomalies = ctx.report.getFact('stageC.anomalies') || [];
  const msg = anomalies.find(a => needles.every(nd => a.includes(nd)));
  ok(`U7-lang/${lang} アノマリーに採点不能の理由が載る`,
    !!msg && msg.includes('invalid meta.groupId'), JSON.stringify(anomalies));
}

// ============================================================
// U8: 権威デポジット表（`verifiedDepositWei`）が **uid 添字のオブジェクトでない**
//     → `##RESULT fatal`（exit 3）ではなく **FAIL（exit 2）** で報告する
//
//   正典 `calculateGroupResults` は `groupData.verifiedDepositWei` が `undefined` / `null` だと
//   **自己申告デポジット（`member.depIds`）へフォールバックする枝**へ落ちる。その枝は
//   B1 の上限も下限も一切かけない（実測: 自己申告 1e12 ETH が無音で 100,000,000pt）。
//   フォールバック枝はテストと一部ツールのために意図的に残してある経路なので、
//   **枝を塞ぐのではなく、そこへ続く扉に鍵をかける**（ユーザー判断 J-10 (B)・2026-08-07）。
//   本ツール側の鍵が `check.stageC.depositTableShape`。
//
//   ⚠️ 公開データだけではこの形は作れない（`calcFilterEligibleDeposits` は必ず
//     `Object.create(null)` の表を返す）。＝ これは「公開データが敵対的」ではなく
//     **「本ツールが正典へ渡す値が壊れていないこと」を確かめる自己検査**。
//     したがって vendored の `GameMasterDO.prototype` を**その場だけ**差し替えて駆動する
//     （ファイルは触らない・毎ケース復元する）。
//
//   ⚠️ 空振り防止:
//     ・`null` は `Object.keys(null)` が TypeError を投げるので、検査を
//       `Object.keys` の**後ろ**に置くと `depositVerifyFailed` に化けて一度も到達しない。
//       → `check.stageC.depositTableShape` が `absent` でないことを毎ケース見る。
//     ・「例外が出ない」だけでなく、**採点まで到達していないこと**（scoring / summaryMatch /
//       merkleRoot が `absent`）と `stopReason === 'fail'` まで固定する。
//
//   🔬 実測（2026-08-07・`src/stages/results.js` の当該検査を消して確認）:
//     | 壊し方                                        | 赤くなる assertion |
//     | `if (tableShape !== 'object')` ブロックを削除 | U8 の 4形状 × 6件（うち `null`/`undefined` は
//     |                                               |  `depositVerifyFailed` / 自己申告フォールバックへ流れる）＋ U8-lang 3件 |
// ============================================================
{
  const { GameMasterDO } = await import('../vendor/workers/game_workers/game-master-DO.js');
  const REAL_FILTER = GameMasterDO.prototype.calcFilterEligibleDeposits;

  // 表だけを差し替える（`verifiedDeposits` は正常な形のまま＝壊れているのは表の形だけ）
  async function withCorruptTable(table, fn) {
    GameMasterDO.prototype.calcFilterEligibleDeposits = function (...args) {
      const real = REAL_FILTER.apply(this, args);
      return { verifiedDepositWei: table, verifiedDeposits: real.verifiedDeposits };
    };
    try { return await fn(); }
    finally { GameMasterDO.prototype.calcFilterEligibleDeposits = REAL_FILTER; }
  }

  const SHAPES = [
    ['null', null, 'null'],
    ['undefined', undefined, 'undefined'],
    ['文字列', 'x', 'string'],
    ['配列', [], 'array'],
  ];

  for (const [label, table, expectShape] of SHAPES) {
    const ctx = gameScoringCase({ members: healthyRoster() });
    const r = await withCorruptTable(table, () => callRun(ctx));

    ok(`U8[${label}] run() が例外を投げない（= ##RESULT fatal / exit 3 にならない）`,
      !r.threw, r.error?.message);
    eq(`U8[${label}] check.stageC.depositTableShape = fail`,
      statusOf(ctx, 'check.stageC.depositTableShape'), 'fail');
    eq(`U8[${label}] 実測の型が params に載る`,
      paramsOf(ctx, 'check.stageC.depositTableShape').shape, expectShape);
    // FAIL が1件でもあれば index.js の categorize は 'fail'（exit 2）を選ぶ
    ok(`U8[${label}] report.hasFail() = true（##RESULT fail / exit 2 の条件）`, ctx.report.hasFail());
    eq(`U8[${label}] stopReason = fail（exit 2 側）`, ctx.data.stopReason, 'fail');
    // 採点へは一歩も進まない（フォールバック枝を踏ませない＝この検査の目的そのもの）
    eq(`U8[${label}] 採点は走らない`, statusOf(ctx, 'check.stageC.scoring'), 'absent');
    eq(`U8[${label}] summaryMatch は記録されない`, statusOf(ctx, 'check.stageC.summaryMatch'), 'absent');
    eq(`U8[${label}] merkleRoot は記録されない`, statusOf(ctx, 'check.stageC.merkleRoot'), 'absent');
  }

  // U8-ctrl 対照: 本物の表（`Object.create(null)`）なら pass し、採点まで到達する
  {
    const ctx = gameScoringCase({ members: healthyRoster() });
    const r = await callRun(ctx);
    ok('U8-ctrl 対照: run() が例外を投げない', !r.threw, r.error?.message);
    eq('U8-ctrl 対照: check.stageC.depositTableShape = pass',
      statusOf(ctx, 'check.stageC.depositTableShape'), 'pass');
    eq('U8-ctrl 対照: shape = object',
      paramsOf(ctx, 'check.stageC.depositTableShape').shape, 'object');
    eq('U8-ctrl 対照: 採点まで到達する', statusOf(ctx, 'check.stageC.scoring'), 'pass');
    eq('U8-ctrl 対照: 停止しない', ctx.data.stopReason, undefined);
  }

  // U8-lang 3言語: 第三者が「運営側の問題であり、このブロックは未検証」と読めること
  for (const [lang, needles] of [
    ['ja', ['uid 添字のオブジェクトではなく', '自己申告ロック中のETH', '未検証']],
    ['en', ['instead of a per-uid map', 'self-reported Locked ETH', 'UNVERIFIED']],
    ['zh', ['不是以 uid 为键的对象', '自报已锁定 ETH', '未经验证']],
  ]) {
    const ctx = gameScoringCase({ members: healthyRoster(), lang });
    await withCorruptTable(null, () => callRun(ctx));
    const anomalies = ctx.report.getFact('stageC.anomalies') || [];
    const msg = anomalies.find(a => needles.every(nd => a.includes(nd)));
    ok(`U8-lang/${lang} アノマリーに「フォールバックさせないために採点しない」理由が載る`,
      !!msg && msg.includes('null'), JSON.stringify(anomalies));
  }
}

// ============================================================
// 🔴 U9（F-6・2026-08-08・ラウンド20 判断不要-6）:
//   壊れた公開データは **FAIL（exit 2）** であって fatal（exit 3）ではない
// ============================================================
//
// 実測（是正前・実 Hardhat e2e）:
//   | ケース                       | exit | ##RESULT | 記録された checks |
//   | control-green                | 0    | full     | 63 |
//   | `summary.json` を切る        | **3**| **fatal**| 27 |
//   | 対照: 同ファイルを pretty-print | 2  | fail     | 31 |
//   | `manifest.json` を切る       | **3**| **fatal**| 30 |
//   | 対照: 同ファイル = `{}`      | 2    | fail     | 62 |
//   | 同ファイル = `null`          | **3**| **fatal**| 44（**20件消失**）|
// ＝ **同じファイルの、より軽い異常が FAIL・より重い異常が fatal** という逆転。
// `null` だけは fail-open → TypeError（`Cannot read properties of null (reading 'rules')`）で
// キー名も原因も出なかった。
{
  console.log('\n--- U9（F-6）: 壊れた公開データは FAIL であって fatal ではない ---');
  const mkCase = (key, value) => {
    const chain = makeChainStub({
      depositsById: { 1: deposit('20000001', '20000001', 1.0) },
      readIds: [],
    });
    const players = [player('20000001', depIdsJson(ETH(1.0), ['1']), 0)];
    const files = makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } });
    files[key] = value;
    return makeCtx({ players, files, chain });
  };

  for (const [label, key, value] of [
    ['summary.json が途中で切れている', `games/block${N}/summary.json`, CORRUPT_BYTES('{"blockNum":0,"grou')],
    ['manifest.json が途中で切れている', `verification/block${N}/manifest.json`, CORRUPT_BYTES('{"blockNum":0,')],
    ['manifest.json = null（旧実装は20チェックが無記録で消えた）', `verification/block${N}/manifest.json`, null],
    ['summary.json = null', `games/block${N}/summary.json`, null],
    ['merkle/block_N.json = 数値', `merkle/block_${N}.json`, 42],
  ]) {
    const ctx = mkCase(key, value);
    const r = await callRun(ctx);
    ok(`U9 [${label}] run() が throw しない（throw = ##RESULT fatal / exit 3）`, !r.threw, r.error?.message);
    eq(`U9 [${label}] stopReason = fail（exit 2）`, ctx.data.stopReason, 'fail');
    eq(`U9 [${label}] check.stageC.downloads = fail`, statusOf(ctx, 'check.stageC.downloads'), 'fail');
    const p = paramsOf(ctx, 'check.stageC.downloads');
    ok(`U9 [${label}] どのキーが読めなかったかが記録される`,
      String(p.corrupt ?? p.missing ?? '').includes(key.split('/').pop()), JSON.stringify(p));
  }

  // 過剰遮断ゼロ: 健全な公開データは従来どおり downloads = pass
  {
    const chain = makeChainStub({ depositsById: { 1: deposit('20000001', '20000001', 1.0) }, readIds: [] });
    const players = [player('20000001', depIdsJson(ETH(1.0), ['1']), 0)];
    const ctx = makeCtx({ players, files: makeFiles({ summary: { blockNum: N, autoDistributed: true, groups: [] } }), chain });
    await callRun(ctx);
    eq('U9-ctrl 健全な公開データは downloads = pass', statusOf(ctx, 'check.stageC.downloads'), 'pass');
  }
}

// ============================================================
// 🔴 U10（F-6）: 共通入口 `src/r2.js` の3経路すべてが throw しない
// ============================================================
//
// 実 `createR2` の fetch をインメモリ応答へ差し替えて（listen禁止環境でも実行可能）、
//   (1) fetchJson（ネットワーク経路）
//   (2) fetchJson の `--reuse` 経路（ローカルキャッシュ・**旧実装は try すら無かった**）
//   (3) refetch（manifest 鮮度回復）
// の3つとも「壊れたバイト列で throw せず `parseError` を返す」ことを固定する。
// ⚠️ 1箇所だけ直すのが最頻の失敗パターンなので、3つとも見る。
{
  console.log('\n--- U10（F-6）: r2.js の3経路が壊れたバイト列で throw しない ---');
  const { createR2 } = await import('../src/r2.js');
  const { mkdtemp, mkdir, writeFile } = await import('node:fs/promises');
  const os = await import('node:os');
  const nodePath = await import('node:path');

  const bodies = new Map([
    ['broken.json', '{"blockNum":0,"grou'],
    ['good.json', '{"blockNum":0}'],
  ]);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const key = new URL(String(url)).pathname.replace(/^\//, '');
    const raw = bodies.get(key);
    return raw == null
      ? new Response(null, { status: 404 })
      : new Response(raw, { status: 200, headers: { 'content-length': String(Buffer.byteLength(raw)) } });
  };
  const dataDir = await mkdtemp(nodePath.join(os.tmpdir(), 'bv-cache-'));
  const ui = makeUi('ja');
  try {
    // (1) ネットワーク経路
    {
      const r2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, N);
      let threw = null, res = null;
      try { res = await r2.fetchJson('broken.json'); } catch (e) { threw = e; }
      ok('U10 fetchJson が壊れたバイト列で throw しない', threw === null, threw?.message);
      ok('U10 fetchJson が parseError を返す', !!res?.parseError, JSON.stringify(res));
      ok('U10 parseError にキー名が入る', String(res?.parseError).includes('broken.json'), res?.parseError);
      eq('U10 data は undefined', res?.data, undefined);
      ok('U10 raw は保持される（byte 照合用）', res?.raw === '{"blockNum":0,"grou"'.slice(0, 19), res?.raw);
      // 対照: 健全な JSON は従来どおり
      const okRes = await r2.fetchJson('good.json');
      eq('U10-ctrl 健全な JSON は data が読める', okRes?.data?.blockNum, 0);
      ok('U10-ctrl 健全な JSON に parseError は付かない', !okRes?.parseError);
    }
    // (2) --reuse（ローカルキャッシュ）経路 — 旧実装は try すら無く、キー名も出なかった
    {
      const cacheDir = nodePath.join(dataDir, `block${N}`);
      await mkdir(cacheDir, { recursive: true });
      await writeFile(nodePath.join(cacheDir, 'cached.json'), '{"a":');
      const r2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, N);
      r2.setDefaultReuse(true);
      let threw = null, res = null;
      try { res = await r2.fetchJson('cached.json'); } catch (e) { threw = e; }
      ok('U10 reuse 経路が throw しない', threw === null, threw?.message);
      ok('U10 reuse 経路も parseError を返す（キー名つき）',
        String(res?.parseError).includes('cached.json'), JSON.stringify(res));
    }
    // (3) refetch
    {
      const r2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, N);
      let threw = null, res = null;
      try { res = await r2.refetch('broken.json'); } catch (e) { threw = e; }
      ok('U10 refetch が throw しない', threw === null, threw?.message);
      ok('U10 refetch も parseError を返す', !!res?.parseError, JSON.stringify(res));
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ============================================================
// 🔴 U11（R2-F1・2026-08-10）:
//   game.js が表示する group{G}.json / gameResults を正典再計算と照合する
// ============================================================
//
// 検査する網:
//   1. 期待行は手書きミラーではなく、vendored 正典 writer 自身から投影する。
//   2. schema v3 は claimed を含め全項目不変。旧schemaだけ inline claimed を中立化する。
//   3. 行欠落・追加フィールド・報酬/得点・投票/密告関係は全て差分とする。
//   4. manifest hash が claimed 更新でズレた場合でも、この内容検査が PASS のときだけ
//      WARN へ降格する。claimed に便乗した total_points 改竄は FAIL のまま。
{
  const scored = [{
    groupId: 7,
    members: [
      {
        uid: '20000001', addr: '0x' + 'aa'.repeat(20), btcuReward: '123',
        depositPoints: 20, bonusPoints: 30, totalPoints: 50, isDisqualified: false,
        reportGainPoints: 4, voteTargetUid: '20000002',
        reportTargetUids: ['20000003'], votedByUids: ['20000004'],
      },
      {
        uid: '20000002', addr: '', btcuReward: '0',
        depositPoints: 0, bonusPoints: 0, totalPoints: 0, isDisqualified: true,
        disqualifyReasons: ['no_submit', 'invalid_vote'], reportGainPoints: 0,
        voteTargetUid: '', reportTargetUids: [], votedByUids: [],
      },
    ],
  }];
  const depositorResults = [{
    groupId: 7, depositorUid: '30000001', depositId: 'dep-1',
    depositerAddress: null, btcuReward: '61', playerUid: '20000001',
  }];
  const logBefore = console.log;
  const projected = await rebuildCanonicalGroupGameResults(9, scored, depositorResults, []);
  ok('U11 正典writer投影後に console.log が必ず復元される', console.log === logBefore);

  const expectedRows = [
    {
      userId: '20000001', role: 'player', deposit_id: '', address: '0x' + 'aa'.repeat(20),
      btcu_reward: '123', deposit_to: null,
      deposit_points: 20, bonus_points: 30, total_points: 50, is_disqualified: 0,
      disqualify_reason: null, report_gain_points: 4, vote_target_uid: '20000002',
      report_target_uids: '["20000003"]', voted_by_uids: '["20000004"]',
    },
    {
      userId: '20000002', role: 'player', deposit_id: '', address: null,
      btcu_reward: '0', deposit_to: null,
      deposit_points: 0, bonus_points: 0, total_points: 0, is_disqualified: 1,
      disqualify_reason: 'no_submit,invalid_vote', report_gain_points: 0,
      vote_target_uid: null, report_target_uids: null, voted_by_uids: null,
    },
    {
      userId: '30000001', role: 'depositor', deposit_id: 'dep-1', address: null,
      btcu_reward: '61', deposit_to: '20000001',
    },
  ];
  eq('U11 vendored正典writerから得た行形状が仕様値と一致', projected.get(7), expectedRows);
  ok('U11 完全一致行は pass', compareGroupGameResultRows(expectedRows, expectedRows, 3).ok);

  const claimedOnly = JSON.parse(JSON.stringify(expectedRows));
  for (const row of claimedOnly) row.claimed = { time: 1700000000, txHash: '0xabc' };
  ok('S4 schema v3のclaimed注入は fail',
    !compareGroupGameResultRows(expectedRows, claimedOnly, 3).ok);
  ok('U11 旧schema v2のinline claimed更新は従来どおり pass',
    compareGroupGameResultRows(expectedRows, claimedOnly, 2).ok);

  for (const [label, mutate, path] of [
    ['userId改竄', (r) => { r[0].userId = 'attacker'; }, '0.userId'],
    ['role改竄', (r) => { r[0].role = 'depositor'; }, '0.role'],
    ['address改竄', (r) => { r[0].address = '0x' + 'ff'.repeat(20); }, '0.address'],
    ['btcu_reward改竄', (r) => { r[0].btcu_reward = '999'; }, '0.btcu_reward'],
    ['deposit_points改竄', (r) => { r[0].deposit_points = 21; }, '0.deposit_points'],
    ['bonus_points改竄', (r) => { r[0].bonus_points = 31; }, '0.bonus_points'],
    ['total_points改竄', (r) => { r[0].total_points = 51; }, '0.total_points'],
    ['is_disqualified改竄', (r) => { r[0].is_disqualified = 1; }, '0.is_disqualified'],
    ['disqualify_reason改竄', (r) => { r[1].disqualify_reason = 'fake'; }, '1.disqualify_reason'],
    ['report_gain_points改竄', (r) => { r[0].report_gain_points = 5; }, '0.report_gain_points'],
    ['vote_target_uid改竄', (r) => { r[0].vote_target_uid = 'attacker'; }, '0.vote_target_uid'],
    ['report_target_uids改竄', (r) => { r[0].report_target_uids = '["attacker"]'; }, '0.report_target_uids'],
    ['voted_by_uids改竄', (r) => { r[0].voted_by_uids = '["attacker"]'; }, '0.voted_by_uids'],
    ['deposit_id改竄', (r) => { r[2].deposit_id = 'fake-dep'; }, '2.deposit_id'],
    ['deposit_to改竄', (r) => { r[2].deposit_to = 'attacker'; }, '2.deposit_to'],
    ['余分なフィールド', (r) => { r[0].operator_note = 'fake'; }, '0.operator_note'],
    ['行順序の入替え', (r) => { [r[0], r[1]] = [r[1], r[0]]; }, '0.userId'],
    ['行欠落', (r) => { r.pop(); }, '2'],
  ]) {
    const changed = JSON.parse(JSON.stringify(expectedRows));
    mutate(changed);
    const cmp = compareGroupGameResultRows(expectedRows, changed, 3);
    ok(`U11 ${label}は fail`, !cmp.ok);
    ok(`U11 ${label}の差分パスが記録される`,
      cmp.diffs.some((d) => d.path === path), JSON.stringify(cmp.diffs));
  }
  ok('U11 gameResults 自体の欠落は fail',
    !compareGroupGameResultRows(expectedRows, undefined, 3).ok);

  const expectedTimeline = [
    { kind: 'chat', uid: '20000001', text: 'hello', timestamp: 1700000000000, msgKey: '0x' + '12'.repeat(32) },
    { kind: 'vote', actorUid: '20000001', targetUid: '20000002', timestamp: 1700000000001, actionHash: '0x' + '34'.repeat(32) },
    { kind: 'report', actorUid: '20000002', targetUid: '20000001', nth: 1, timestamp: 1700000000002, actionHash: '0x' + '56'.repeat(32) },
  ];
  ok('U11 canonicalTimeline 完全一致は pass',
    compareGroupCanonicalTimelineRows(expectedTimeline, expectedTimeline).ok);
  ok('U11 canonicalTimeline 自体の欠落は fail',
    !compareGroupCanonicalTimelineRows(expectedTimeline, undefined).ok);
  {
    const changed = JSON.parse(JSON.stringify(expectedTimeline));
    changed[1].targetUid = 'attacker';
    const cmp = compareGroupCanonicalTimelineRows(expectedTimeline, changed);
    ok('U11 canonicalTimeline の投票標的改竄は fail', !cmp.ok);
    ok('U11 canonicalTimeline の標的差分パスが記録される',
      cmp.diffs.some(d => d.path === '1.targetUid'), JSON.stringify(cmp.diffs));
  }
  {
    const beforeLog = console.log;
    const beforeError = console.error;
    let projectionError = null;
    try {
      await rebuildCanonicalGroupGameResults(9, [{ groupId: 'not-an-int', members: [] }], [], []);
    } catch (e) {
      projectionError = e;
    }
    ok('U11 正典writer投影が失敗したときは fail-closed で throw', !!projectionError);
    ok('U11 失敗経路でも console.log/error を必ず復元',
      console.log === beforeLog && console.error === beforeError);
  }

  // run() への配線と、「claimed-only の hash 差分だけ WARN」の条件を実経路で固定する。
  // 1回目の健全な採点で正典に渡った結果を捕捉し、2回目の公開アーカイブに使う。
  const realBuildSummary = GameMasterDO.prototype.buildBlockSummaryWithResults;
  let captured = null;
  GameMasterDO.prototype.buildBlockSummaryWithResults = async function (...args) {
    captured = {
      allGroupResults: JSON.parse(JSON.stringify(args[1])),
      groups: JSON.parse(JSON.stringify(args[2])),
      depositorResults: JSON.parse(JSON.stringify(args[4])),
    };
    return await realBuildSummary.apply(this, args);
  };
  try {
    await callRun(gameScoringCase({ members: healthyRoster() }));
  } finally {
    GameMasterDO.prototype.buildBlockSummaryWithResults = realBuildSummary;
  }
  ok('U11 run()の採点結果を正典summary writer入口で捕捉できた', !!captured);
  const runRows = (await rebuildCanonicalGroupGameResults(
    N, captured.allGroupResults, captured.depositorResults, captured.groups
  )).get(0);
  const runTimeline = captured.allGroupResults[0].canonicalTimeline;

  {
    const ctx = gameScoringCase({ members: healthyRoster(), groupResults: runRows, canonicalTimeline: runTimeline });
    await callRun(ctx);
    eq('U11-ctrl run()正常経路で gameResults = pass',
      statusOf(ctx, 'check.stageC.groupGameResultsMatch'), 'pass');
    eq('U11-ctrl run()正常経路で canonicalTimeline = pass',
      statusOf(ctx, 'check.stageC.groupCanonicalTimelineMatch'), 'pass');
  }
  {
    const rows = JSON.parse(JSON.stringify(runRows));
    for (const row of rows) row.claimed = { time: 1700000000, txHash: '0xclaim' };
    const ctx = gameScoringCase({ members: healthyRoster(), groupResults: rows, canonicalTimeline: runTimeline });
    await callRun(ctx);
    eq('S4 run()でも schema v3 claimed注入は fail',
      statusOf(ctx, 'check.stageC.groupGameResultsMatch'), 'fail');
  }
  {
    const rows = JSON.parse(JSON.stringify(runRows));
    rows[0].total_points += 1;
    const ctx = gameScoringCase({ members: healthyRoster(), groupResults: rows, canonicalTimeline: runTimeline });
    await callRun(ctx);
    eq('U11 run()で total_points 改竄は gameResults = fail',
      statusOf(ctx, 'check.stageC.groupGameResultsMatch'), 'fail');
    ok('U11 run()の失敗詳細に total_points が載る',
      String(paramsOf(ctx, 'check.stageC.groupGameResultsMatch').failures).includes('total_points'));
  }
  {
    const changedTimeline = [
      ...JSON.parse(JSON.stringify(runTimeline)),
      { kind: 'vote', actorUid: '20000001', targetUid: 'attacker', timestamp: 1, actionHash: '0x' + '99'.repeat(32) },
    ];
    const ctx = gameScoringCase({
      members: healthyRoster(), groupResults: runRows, canonicalTimeline: changedTimeline,
    });
    await callRun(ctx);
    eq('U11 run()で canonicalTimeline 改竄は fail',
      statusOf(ctx, 'check.stageC.groupCanonicalTimelineMatch'), 'fail');
  }

  const groupKey = `games/block${N}/group0.json`;
  const manifestKey = `verification/block${N}/manifest.json`;
  const summaryKey = `games/block${N}/summary.json`;
  const makeParkedCase = (tamperSemantic, summarySchemaVersion = 3) => {
    const ctx = gameScoringCase({
      members: healthyRoster(), groupResults: runRows, canonicalTimeline: runTimeline,
      summarySchemaVersion,
    });
    const files = ctx.__testFiles;
    // アンカー時の group archive hash。この後の書換えで manifest 不一致を作る。
    files[manifestKey].files = { [groupKey]: sha256HexOfString(JSON.stringify(files[groupKey])) };
    for (const row of files[groupKey].gameResults) {
      row.claimed = { time: 1700000000, txHash: '0xclaim' };
    }
    if (tamperSemantic) files[groupKey].gameResults[0].total_points += 1;
    return ctx;
  };
  const runWithSummaryOtherwiseMatching = async (ctx) => {
    const real = GameMasterDO.prototype.buildBlockSummaryWithResults;
    GameMasterDO.prototype.buildBlockSummaryWithResults = async function () {
      return JSON.parse(JSON.stringify(ctx.__testFiles[summaryKey]));
    };
    try { return await callRun(ctx); }
    finally { GameMasterDO.prototype.buildBlockSummaryWithResults = real; }
  };

  // R12-43: claim 可変判定は results.js の単一述語を precheck / 本体が共有する。
  // まず集合そのものを固定し、その後に実際の precheck 短絡経路を通す。
  eq('R12 規則: schema v1 summary は claim 可変',
    isClaimMutableArtifact(summaryKey, N, 1), true);
  eq('R12 規則: schema v2 summary は不変',
    isClaimMutableArtifact(summaryKey, N, 2), false);
  eq('R12 floor: schemaVersion 不明の summary は安全側の不変',
    isClaimMutableArtifact(summaryKey, N, undefined), false);
  eq('R12 規則: group{G}.json は従来どおり claim 可変',
    isClaimMutableArtifact(groupKey, N, 2), true);
  eq('R12 規則: auto-results.json は従来どおり claim 可変',
    isClaimMutableArtifact(`games/block${N}/auto-results.json`, N, 2), true);
  eq('S4 規則: schema v3 group{G}.json は不変',
    isClaimMutableArtifact(groupKey, N, 3), false);
  eq('S4 規則: schema v3 auto-results.json は不変',
    isClaimMutableArtifact(`games/block${N}/auto-results.json`, N, 3), false);

  const makeSummaryClaimCase = (schemaVersion) => {
    const ctx = gameScoringCase({
      members: healthyRoster(), groupResults: runRows, canonicalTimeline: runTimeline,
    });
    const files = ctx.__testFiles;
    const summary = files[summaryKey];
    if (schemaVersion === undefined) delete summary.schemaVersion;
    else summary.schemaVersion = schemaVersion;
    summary.groups[0].members = [{ userId: '20000001', claimed: 0 }];
    // アンカー時の summary hash。この後、listen-worker と同じ claimed 後書きで差分を作る。
    files[manifestKey].files = { [summaryKey]: sha256HexOfString(JSON.stringify(summary)) };
    summary.groups[0].members[0].claimed = { time: 1700000000, txHash: '0xclaim' };
    return ctx;
  };

  {
    const ctx = makeSummaryClaimCase(2);
    await runWithSummaryOtherwiseMatching(ctx);
    eq('R12 M1 v2 summary のアンカー後バイト変更は summaryMatch が通っても hard FAIL',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'fail');
    ok('R12 M1 hard FAIL の failures に summary.json が載る',
      String(paramsOf(ctx, 'check.stageC.manifestFiles').failures).includes(summaryKey));
  }
  {
    const ctx = makeSummaryClaimCase(1);
    await runWithSummaryOtherwiseMatching(ctx);
    eq('R12 M2 v1 summary のアンカー後 claimed 変更は parked 後に WARN',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'warn');
  }
  {
    const ctx = makeSummaryClaimCase(undefined);
    await runWithSummaryOtherwiseMatching(ctx);
    eq('R12 floor schemaVersion 不明の summary は可変と推測せず hard FAIL',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'fail');
  }

  {
    const ctx = makeParkedCase(false);
    await runWithSummaryOtherwiseMatching(ctx);
    eq('U11 claimed-onlyケースの summaryMatch は pass', statusOf(ctx, 'check.stageC.summaryMatch'), 'pass');
    eq('U11 claimed-onlyケースの archiveChainConsistency は pass',
      statusOf(ctx, 'check.stageC.archiveChainConsistency'), 'pass');
    eq('S4 schema v3 claimed注入は groupGameResults = fail',
      statusOf(ctx, 'check.stageC.groupGameResultsMatch'), 'fail');
    eq('S4 schema v3 group{G}.json の claimed hash差分は hard FAIL',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'fail');
  }
  {
    const ctx = makeParkedCase(false, 2);
    await runWithSummaryOtherwiseMatching(ctx);
    eq('R12 旧schema v2 group{G}.json の claimed-only 差分は従来どおり WARN',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'warn');
  }
  {
    const ctx = makeParkedCase(true);
    await runWithSummaryOtherwiseMatching(ctx);
    eq('U11 claimedに便乗したtotal_points改竄は groupGameResults = fail',
      statusOf(ctx, 'check.stageC.groupGameResultsMatch'), 'fail');
    eq('U11 意味データ改竄時はmanifest hash不一致を WARN へ降格しない',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'fail');
  }
  {
    const ctx = makeParkedCase(false);
    ctx.__testFiles[groupKey].canonicalTimeline.push({
      kind: 'vote', actorUid: '20000001', targetUid: 'attacker',
      timestamp: 1, actionHash: '0x' + '88'.repeat(32),
    });
    await runWithSummaryOtherwiseMatching(ctx);
    eq('U11 canonicalTimeline改竄は内容照合で fail',
      statusOf(ctx, 'check.stageC.groupCanonicalTimelineMatch'), 'fail');
    eq('U11 canonicalTimeline改竄時はmanifest hash不一致を WARN へ降格しない',
      statusOf(ctx, 'check.stageC.manifestFiles'), 'fail');
  }
}

// BV-SCALE-04: 読取不能は不一致FAILにせず、partial/not_readyで止める。
{
  const realFetch = GameMasterDO.prototype.calcFetchDepositsFromChain;
  GameMasterDO.prototype.calcFetchDepositsFromChain = async (ids) => ({
    chainData: {}, failedReads: [ids[0]],
  });
  const ctx = gameScoringCase({ members: healthyRoster() });
  try { await callRun(ctx); }
  finally { GameMasterDO.prototype.calcFetchDepositsFromChain = realFetch; }
  eq('BV-SCALE-04 取得不能のcheckはskip', statusOf(ctx, 'check.stageC.depositVerification'), 'skip');
  eq('BV-SCALE-04 取得不能の分類語彙', paramsOf(ctx, 'check.stageC.depositVerification').classification, 'unavailable');
  eq('BV-SCALE-04 取得不能はpartial側のnot_ready', ctx.data.stopReason, 'not_ready');
  eq('BV-SCALE-04 未確認のまま採点しない', statusOf(ctx, 'check.stageC.scoring'), 'absent');
}

// BV-SCALE-04: 本番上限2,100人×10 IDでも正典250 ID単位で完走し、
// RPC取得不能とデータ不一致を同じFAILへ潰さない。
{
  const ids = Array.from({ length: 21000 }, (_, index) => String(index + 1));
  const calls = [];
  const gm = {
    calcCollectDepositIds: GameMasterDO.prototype.calcCollectDepositIds,
    readDepositSelectionK11: async () => 64n,
    calcFetchDepositsFromChain: async (unit) => {
      calls.push([...unit]);
      return {
        chainData: Object.fromEntries(unit.map((id) => [id, { amount: '1' }])),
        failedReads: [],
      };
    },
    calcFilterEligibleDeposits: (_block, _perUid, chainData) => ({
      verifiedDepositWei: { count: String(Object.keys(chainData).length) },
      verifiedDeposits: {},
    }),
  };
  const canonicalEntry = GameMasterDO.prototype.verifyDepositsOnChainForUids;
  let canonicalEntryCalls = 0;
  GameMasterDO.prototype.verifyDepositsOnChainForUids = async function (...args) {
    canonicalEntryCalls++;
    return canonicalEntry.apply(this, args);
  };
  let verified;
  try {
    verified = await verifyDepositsOnChainInUnits(gm, N, { user: ids });
  } finally {
    GameMasterDO.prototype.verifyDepositsOnChainForUids = canonicalEntry;
  }
  eq('BV-SCALE-04 COPY済み正典B1入口を直接実行', canonicalEntryCalls, 1);
  eq('BV-SCALE-04 正典のchain unit定数', DEPOSIT_IDS_PER_UNIT, 250);
  eq('BV-SCALE-04 21,000読取を84 unitで完走', calls.length, 84);
  eq('BV-SCALE-04 1 unitの最大ID数', Math.max(...calls.map((unit) => unit.length)), 250);
  eq('BV-SCALE-04 全21,000 IDを適格判定へ渡す', verified.verifiedDepositWei.count, '21000');

  const callsAtLimit = calls.length;
  let limitError = null;
  try { await verifyDepositsOnChainInUnits(gm, N, { user: [...ids, '21001'] }); }
  catch (error) { limitError = error; }
  eq('BV-SCALE-04 21,001 distinct IDはmismatchとしてfail-closed', classifyDepositVerificationError(limitError), 'mismatch');
  eq('BV-SCALE-04 総数超過はRPC読取前に停止', calls.length, callsAtLimit);

  const unreadable = {
    ...gm,
    calcFetchDepositsFromChain: async (unit) => ({ chainData: {}, failedReads: [unit[0]] }),
  };
  let unavailableError = null;
  try { await verifyDepositsOnChainInUnits(unreadable, N, { user: ids.slice(0, 1) }); }
  catch (error) { unavailableError = error; }
  eq('BV-SCALE-04 RPC取得不能はunavailable', classifyDepositVerificationError(unavailableError), 'unavailable');

  const mismatch = {
    ...gm,
    calcFilterEligibleDeposits: () => { throw new Error('authoritative deposit mismatch'); },
  };
  let mismatchError = null;
  try { await verifyDepositsOnChainInUnits(mismatch, N, { user: ids.slice(0, 1) }); }
  catch (error) { mismatchError = error; }
  eq('BV-SCALE-04 検証済み値の食い違いはmismatch', classifyDepositVerificationError(mismatchError), 'mismatch');
}

console.log(`\nc8-hostile-public-data-unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
