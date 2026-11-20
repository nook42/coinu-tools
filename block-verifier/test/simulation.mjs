// simulation.mjs — 網羅シミュレーション・マトリクス（SIMULATION_HANDOFF.md §3）。
//
// 目的: 「サーバーが正常稼働している限り、あらゆるケースで block-verifier の検証結果が
// 公開結果と一致する」ことをローカル Hardhat で網羅的に実証する。
// 各シナリオ: フレッシュ Hardhat node → generateFixture（本番コードで偽ブロック生成）→
// verifyFixtureInternalConsistency（files⇔chain の独立照合）→ ローカルR2 → ツール非対話実行 →
// ##CHECK/##RESULT 解析（mutations.mjs 流用）→ 期待 ##RESULT・期待チェック status・
// 公開 summary の期待値（失格理由・ポイント・按分・グループ構成）を assert。
//
//   node block-verifier/test/simulation.mjs [--only KEY] [--list]
//
// マトリクス対応（v3.2）: S1=default / S2=all_dq_zero_evidence / S3=auto_two / S4=zero_players /
// S5+S16=sizes_and_merkle / S17=calc_chunked / S8=votes / S9=reports / S10=thresholds /
// S11=deposits / S12=major_langs / S13=evidence / S14a,b=reward_tiers / S15=rereg /
// S18=receipt_canon(S-RC) / S19=vote_fraud(S-VF) / S20=report_fraud(S-RF) / S21=chat_canon_union(S-CM)
//（旧S6/S7=タブー系はタブー全廃で削除）
import { readFileSync, existsSync, rmSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateFixture, verifyFixtureInternalConsistency, emptyMerkleSentinel,
} from './gen-fixture.mjs';
import { startR2Server } from './r2-server.mjs';
import { runTool, toolLooksComplete, writeToolConfig } from './e2e.mjs';
import { parseChecks } from './mutations.mjs';
import { getBlockRewardWei } from './canonical.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

// ---------------- ヘルパー ----------------
// uid = '2100' + ワーカー番号(2桁) + 連番(2桁)。末尾4桁の先頭2桁 = collect-worker 番号の規約に適合。
const uidFor = (i) => `2100${String(i % 3).padStart(2, '0')}${String(Math.floor(i / 3)).padStart(2, '0')}`;
const mkPlayers = (n, { lang = () => 'ja', eth = () => '0.25' } = {}) =>
  Array.from({ length: n }, (_, i) => ({
    uid: uidFor(i),
    lang: typeof lang === 'function' ? lang(i) : lang,
    eth: typeof eth === 'function' ? eth(i) : eth,
    name: null, img: null, verified: false,
  }));
// デポジットポイント = floor(sqrt(wei / 1e14))（エントリー額が小さいので Number で厳密）
const dp = (eth) => Math.floor(Math.sqrt(Number(eth) * 1e4));

const readJson = (r2Dir, key) => JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
// S4 schema v3 は claim/ZKP 用indexだけをsummaryに持ち、表示詳細はmanifest固定page、
// 行別claimedはmanifest外のgroup overlayへ分冊する。期待値検査だけUIと同じ形で合成する。
const summaryOf = (fx) => {
  const summary = readJson(fx.r2Dir, `games/block${fx.chainInfo.blockNum}/summary.json`);
  if (Number(summary.schemaVersion || 1) < 2) return summary;
  return {
    ...summary,
    groups: (summary.groups || []).map((indexGroup) => {
      if (!indexGroup.detailKey) return indexGroup;
      const page = readJson(fx.r2Dir, indexGroup.detailKey);
      const rows = Array.isArray(page.gameResults) ? page.gameResults : [];
      const claimOverlay = indexGroup.claimOverlayKey
        ? readJson(fx.r2Dir, indexGroup.claimOverlayKey)
        : null;
      const claimByIdentity = new Map((claimOverlay?.claims || []).map(row => [
        `${row.role === 'depositor' ? 'dep' : 'player'}_${String(row.id)}`,
        row.claimed,
      ]));
      const profiles = new Map((page.members || []).map(member => [String(member.uid ?? member.userId), member]));
      const indexMembers = new Map((indexGroup.members || []).map(member => [String(member.userId), member]));
      const members = rows.filter(row => row.role === 'player').map((row) => {
        const uid = String(row.userId);
        const lean = indexMembers.get(uid) || {};
        const full = BigInt(lean.full_btcu_reward || row.btcu_reward || '0');
        const player = BigInt(row.btcu_reward || '0');
        return {
          ...(profiles.get(uid) || {}), ...lean, ...row, userId: uid,
          full_btcu_reward: full.toString(), player_share: player.toString(),
          depositor_share: (full - player).toString(),
          claimed: claimByIdentity.get(`player_${uid}`) ?? row.claimed,
        };
      });
      const depositor_results = rows.filter(row => row.role === 'depositor').map(row => ({
        depositorUid: String(row.userId), playerUid: String(row.deposit_to),
        depositId: String(row.deposit_id), depositerAddress: row.address,
        btcuReward: String(row.btcu_reward || '0'),
        claimed: claimByIdentity.get(`dep_${String(row.deposit_id)}`) ?? row.claimed,
      }));
      return { ...indexGroup, members, depositor_results };
    }),
  };
};
const merkleOf = (fx) => readJson(fx.r2Dir, `merkle/block_${fx.chainInfo.blockNum}.json`);

// 請求データ自己完結化（2026-08-01）: Merkle の葉の**期待値**を summary から組む。
//   プレイヤー葉  … 報酬>0 のプレイヤーごとに1枚（amount = player_share）
//   デポッター葉  … **プレイヤー単位1枚**（旧: デポジットごと1枚）。amount = depositor_share（配分**合計**）
// ⚠️ totalAmount は「per-deposit btcuReward の合計」とは一致しない。
//    全員切り捨てで未配布になる端数（最大 N−1 wei/人）のぶんだけ totalAmount のほうが大きい。
//    ここを等号で書くと、端数が出た瞬間だけ落ちる（旧規則の名残）。
function expectedMerkleShape(summary) {
  let leaves = 0, total = 0n, undistributed = 0n;
  for (const g of (summary.groups || [])) {
    for (const m of (g.members || [])) {
      if (BigInt(m.btcu_reward) > 0n) { leaves++; total += BigInt(m.btcu_reward); }
      const rows = (g.depositor_results || []).filter(d => d.playerUid === m.userId);
      const dst = BigInt(m.depositor_share || '0');
      if (rows.length > 0 && dst > 0n) {
        leaves++;
        total += dst;
        undistributed += dst - rows.reduce((s, d) => s + BigInt(d.btcuReward), 0n);
      }
    }
  }
  return { leaves, total, undistributed };
}
const manifestOf = (fx) => readJson(fx.r2Dir, `verification/block${fx.chainInfo.blockNum}/manifest.json`);
const memberOf = (summary, uid) => {
  for (const g of summary.groups) {
    const m = (g.members || []).find(x => x.userId === uid);
    if (m) return m;
  }
  return null;
};
const reasonsOf = (m) => (m?.disqualify_reason || '').split(',').filter(Boolean);

// assert 収集器
function makeAsserter() {
  const errors = [];
  const eq = (actual, expected, label) => {
    const okv = JSON.stringify(actual) === JSON.stringify(expected);
    if (!okv) errors.push(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  };
  const ok = (cond, label) => { if (!cond) errors.push(label); };
  return { errors, eq, ok };
}

// メンバーの (dp, bonus, total, DQ理由) を一括検証
function assertMember(a, summary, uid, { dp: d, bonus, total, reasons, dq }) {
  const m = memberOf(summary, uid);
  if (!m) { a.ok(false, `member ${uid} not in summary`); return; }
  if (d !== undefined) a.eq(m.deposit_points, d, `${uid}.deposit_points`);
  if (bonus !== undefined) a.eq(m.bonus_points, bonus, `${uid}.bonus_points`);
  if (total !== undefined) a.eq(m.total_points, total, `${uid}.total_points`);
  if (reasons !== undefined) a.eq(reasonsOf(m), reasons, `${uid}.disqualify_reason`);
  if (dq !== undefined) a.eq(m.is_disqualified, dq ? 1 : 0, `${uid}.is_disqualified`);
}

// ---------------- シナリオ・マトリクス ----------------
// 各シナリオ:
//   scenario           … generateFixture へ渡すスペック（null = DEFAULT_SCENARIO）
//   expectResult       … 期待 ##RESULT（'full' | 'partial'）
//   expectExit         … 許容 exit code
//   expectChecks       … { checkId: status } の厳密期待（部分集合）
//   allowWarn          … true なら warn を許容（既定: full は fail のみ禁止・warn 許容は明示）
//   assertFixture(fx)  … 公開成果物（summary/merkle/manifest）の期待値検証 → エラー配列
const SCENARIOS = [];

// ── S1: 標準（既存 e2e 相当・回帰維持） ──
SCENARIOS.push({
  key: 'S1', name: 'default-regression',
  scenario: null,
  expectResult: 'full', expectExit: [0],
  expectChecks: {
    'check.stageC.archiveChainConsistency': 'pass',
    'check.stageC.summaryMatch': 'pass',
    'check.stageC.merkleRoot': 'pass',
  },
});

// ── S2: 全員失格・オンチェーン提出0件（resultCount=0・a629453回帰） ──
{
  const players = mkPlayers(4);
  SCENARIOS.push({
    key: 'S2', name: 'all-dq-result-count-zero',
    scenario: {
      name: 'S2', players,
      behavior: {
        noSubmit: players.map(p => p.uid),
        reports: {},
        evidence: { chain: [], censorServer: [], tamperServer: [], garbage: 0 },
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: {
      'check.stageC.evidenceCompleteness': 'pass',
      'check.stageC.archiveChainConsistency': 'pass',
      'check.stageC.evidenceReportMatch': 'pass',
      'check.stageC.summaryMatch': 'pass',
      'check.stageC.merkleRebuild': 'pass',
      'check.stageC.merkleRoot': 'pass',
    },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      for (const p of players) {
        const m = memberOf(summary, p.uid);
        a.eq(m?.is_disqualified, 1, `${p.uid} disqualified`);
        a.ok(reasonsOf(m).includes('no_submit'), `${p.uid} reason includes no_submit`);
        a.eq(m?.btcu_reward, '0', `${p.uid} reward 0`);
      }
      const merkle = merkleOf(fx);
      a.eq(merkle.leafCount, 0, 'merkle leafCount');
      a.eq(merkle.root.toLowerCase(), emptyMerkleSentinel(0).toLowerCase(), 'merkle sentinel root');
      const manifest = manifestOf(fx);
      a.eq(manifest.rules.evidence.resultCount, 0, 'manifest evidence.resultCount');
      a.eq(manifest.rules.evidence.adoptedCount, null, 'manifest evidence.adoptedCount (writer早期リターン仕様)');
      return a.errors;
    },
  });
}

// ── S3: 2名 → autoDistribute（ゲーム無し） ──
{
  const players = [
    { uid: uidFor(0), lang: 'ja', eth: '1.0', name: null, img: null, verified: false },
    { uid: uidFor(1), lang: 'en', eth: '0.09', name: null, img: null, verified: false },
  ];
  SCENARIOS.push({
    key: 'S3', name: 'auto-distribute-two-players',
    scenario: {
      name: 'S3', players,
      externalDepositors: [{ uid: '31009000', keyIndex: 90, eth: '0.5', forUid: uidFor(0) }],
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: {
      'check.stageB.groupingSkippedAuto': 'skip',
      'check.stageC.autoDistributeConsistent': 'pass',
      'check.stageC.autoDistribute': 'pass',
      'check.stageC.summaryMatch': 'pass',
      'check.stageC.merkleRoot': 'pass',
      'check.stageC.majorLangsMatch': 'skip',
    },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      a.eq(summary.autoDistributed, true, 'summary.autoDistributed');
      // 検証済みwei（自己1.0+外部0.5 / 自己0.09）からのデポジットポイント
      assertMember(a, summary, uidFor(0), { dp: dp('1.5'), bonus: 0, total: dp('1.5'), dq: false });
      assertMember(a, summary, uidFor(1), { dp: dp('0.09'), bonus: 0, total: dp('0.09'), dq: false });
      const g = summary.groups[0];
      a.eq(g.status, 'auto_distributed', 'group status');
      a.eq((g.depositor_results || []).length, 3, 'depositor rows (self×2 + external×1)');
      // 請求データ自己完結化（2026-08-01・SPEC §7）: 端数規則が「末尾へ寄せる」から
      // **全員切り捨て**へ変わったため、保存則は**等号ではなく不等号**になる。
      // 未配布として残るのは最大 N−1 wei（N = そのプレイヤーの適格 deposit 件数）。
      for (const m of g.members) {
        if (m.player_share != null) {
          const rows = g.depositor_results.filter(d => d.playerUid === m.userId);
          const sum = rows.reduce((s, d) => s + BigInt(d.btcuReward), 0n);
          const full = BigInt(m.full_btcu_reward);
          const undistributed = full - (BigInt(m.player_share) + sum);
          a.eq(undistributed >= 0n, true, `${m.userId} 50/50 conservation (player+depositors <= full)`);
          a.eq(undistributed <= BigInt(Math.max(0, rows.length - 1)), true,
            `${m.userId} undistributed remainder <= N-1 wei (got ${undistributed}, N=${rows.length})`);
        }
      }
      return a.errors;
    },
  });
}

// ── S4: 0名 → noGame summary・標識root・manifestをStage Cまで検証 ──
SCENARIOS.push({
  key: 'S4', name: 'zero-players-no-game-finalized',
  scenario: { name: 'S4', players: [] },
  expectResult: 'full', expectExit: [0],
  expectChecks: {
    'check.stageA.rootMatch': 'pass',
    'check.stageA.recordCounts': 'pass',
    'check.stageA.earlyFreeze': 'pass',
    'check.stageA.registrationCount': 'pass',
    'check.stageB.playersMatch': 'pass',
    'check.stageB.groupingSkippedNoGame': 'skip',
    'check.stageC.noGameSummary': 'pass',
    'check.stageC.summaryMatch': 'pass',
    'check.stageC.merkleRoot': 'pass',
    'check.stageC.onchainClaimData': 'pass',
  },
});

// ── S5+S16: グループ規模 5/4/4・端数吸収 ＋ merkle多数claim・zero-reward除外 ──
{
  const players = mkPlayers(13, { lang: (i) => (i % 2 === 0 ? 'ja' : 'en') });
  SCENARIOS.push({
    key: 'S5', name: 'sizes-and-merkle (S5+S16)',
    scenario: {
      name: 'S5', players,
      externalDepositors: [
        { uid: '31009000', keyIndex: 90, eth: '0.3', forUid: uidFor(0) },
        { uid: '31009100', keyIndex: 91, eth: '0.2', forUid: uidFor(5) },
      ],
      // behavior 既定: members[3] が [0,2] に密告されDQ / rotation投票 / 全受領証明 / evidence三分類
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.merkleRoot': 'pass', 'check.stageC.summaryMatch': 'pass' }, // G1: merkleProofs検査はデュアルroot検証に置換（proof個別検証は数学的に冗長＝削除）
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const sizes = summary.groups.map(g => g.members.length).sort();
      a.eq(sizes, [4, 4, 5], 'group sizes 4/4/5');
      // 各グループ: 正準順 members[3] は密告DQ・密告報酬 = floor(被密告者P/(n−1)) を
      // 各密告者に定額（v3.2 §6.9）。基礎dpは自己0.25＋外部デポジット（uid0:+0.3 / uid5:+0.2）
      const baseEth = (uid) => 0.25 + (uid === uidFor(0) ? 0.3 : 0) + (uid === uidFor(5) ? 0.2 : 0);
      const baseDp = (uid) => Math.floor(Math.sqrt(baseEth(uid) * 1e4));
      for (const g of fx.chainInfo.groups) {
        const sg = summary.groups.find(x => x.group_id === g.groupId);
        const n = g.memberUids.length;
        const targetUid = g.memberUids[3];
        const reported = sg.members.find(m => m.userId === targetUid);
        a.ok(reasonsOf(reported).includes('reported'), `group${g.groupId} members[3] reported-DQ`);
        const gain = Math.floor(baseDp(targetUid) / (n - 1));
        for (const ri of [0, 2]) {
          const uid = g.memberUids[ri];
          const rep = sg.members.find(m => m.userId === uid);
          a.eq(rep.deposit_points, baseDp(uid) + gain, `group${g.groupId} reporter[${ri}] gain floor(P/(n-1))`);
        }
      }
      // S16: merkle の葉（請求データ自己完結化・2026-08-01 で形が変わった）
      //   プレイヤー葉  … 報酬>0 のプレイヤーごとに1枚（従来どおり・amount = player_share）
      //   デポッター葉  … **プレイヤー単位1枚**（旧: デポジットごと1枚）
      //                    amount = depositor_share（配分**合計**。個別配分は契約が請求時に計算する）
      //   ⚠️ したがって totalAmount は「per-deposit btcuReward の合計」とは一致しない。
      //      切り捨てで未配布になる端数（最大 N−1 wei/人）のぶんだけ totalAmount のほうが大きい。
      const merkle = merkleOf(fx);
      const exp = expectedMerkleShape(summary);
      a.eq(merkle.leafCount, exp.leaves, 'merkle leafCount == players + playersWithDeposits');
      a.eq(merkle.totalAmount, exp.total.toString(), 'merkle totalAmount == Σplayer_share + Σdepositor_share');
      a.ok(exp.undistributed >= 0n, 'undistributed remainder (floor rounding) is non-negative');
      a.ok(merkle.leafCount >= 10, 'many claims (>=10 leaves)');
      return a.errors;
    },
  });
}

// ── S17: A1チャンク実行の等価性（S5と同一プラン・1ユニット/drive強制＋タスク喪失→自己復旧） ──
// 結果集計をalarm駆動の最小チャンク（1ユニットずつ）で完走させ、公開アーティファクト・検証結果が
// 一括実行（S5）と同一の合格になることを検証する。pump#3でcalc_chunkタスクを故意に喪失させ、
// alarmのresurrection経路（A3同型のタスク消失からの自己復旧）もE2Eで通す。
{
  const players = mkPlayers(13, { lang: (i) => (i % 2 === 0 ? 'ja' : 'en') });
  SCENARIOS.push({
    key: 'S17', name: 'calc-chunked-equivalence (A1)',
    scenario: {
      name: 'S17', players,
      externalDepositors: [
        { uid: '31009000', keyIndex: 90, eth: '0.3', forUid: uidFor(0) },
        { uid: '31009100', keyIndex: 91, eth: '0.2', forUid: uidFor(5) },
      ],
      gmEnv: { GAME_CALC_UNITS_PER_DRIVE: '1' },
      calcTaskLossAt: 3,
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.merkleRoot': 'pass', 'check.stageC.summaryMatch': 'pass' }, // G1: merkleProofs検査はデュアルroot検証に置換（proof個別検証は数学的に冗長＝削除）
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const sizes = summary.groups.map(g => g.members.length).sort();
      a.eq(sizes, [4, 4, 5], 'group sizes 4/4/5');
      for (const g of fx.chainInfo.groups) {
        const sg = summary.groups.find(x => x.group_id === g.groupId);
        const reported = sg.members.find(m => m.userId === g.memberUids[3]);
        a.ok(reasonsOf(reported).includes('reported'), `group${g.groupId} members[3] reported-DQ`);
      }
      const merkle = merkleOf(fx);
      const exp = expectedMerkleShape(summary);
      a.eq(merkle.leafCount, exp.leaves, 'merkle leafCount == players + playersWithDeposits');
      a.eq(merkle.totalAmount, exp.total.toString(), 'merkle totalAmount == Σplayer_share + Σdepositor_share');
      a.ok(merkle.leafCount >= 10, 'many claims (>=10 leaves)');
      return a.errors;
    },
  });
}

// ── S18 (S-RC): 受領証明正典（既読受領なし=正典外→min_chars / 投票受領なし=no_vote） ──
{
  const players = mkPlayers(5);
  SCENARIOS.push({
    key: 'S18', name: 'receipt-canon',
    scenario: {
      name: 'S18', players,
      gamePlan(groupRows) {
        const m = groupRows[0].members.map(x => x.uid); // 正準順
        return {
          noReadReceiptsFor: [m[1]],  // m1のメッセージには誰も既読受領証明を出さない → 正典外 → min_chars
          noVoteReceipt: [m[2]],      // m2の投票には受領証明なし → 受領0 = no_vote
          reports: {},
        };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.scoring': 'pass', 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const m = fx.chainInfo.groups[0].memberUids;
      const P = 50; // 全員 0.25 ETH = 50pt
      // m1: 発言は全員の提出物に載っているが受領証明ゼロ → 正典外 → min_chars 失格
      assertMember(a, summary, m[1], { dq: true, total: 0 });
      a.ok(reasonsOf(memberOf(summary, m[1])).includes('min_chars'), 'm1 min_chars (unreceipted messages excluded from canon)');
      // m2: 投票の受領証明ゼロ → no_vote 失格
      assertMember(a, summary, m[2], { dq: true, total: 0 });
      a.ok(reasonsOf(memberOf(summary, m[2])).includes('no_vote'), 'm2 no_vote (unreceipted vote invalid)');
      // m0/m3/m4 は非失格
      assertMember(a, summary, m[0], { dq: false, dp: P });
      assertMember(a, summary, m[3], { dq: false, dp: P });
      assertMember(a, summary, m[4], { dq: false, dp: P });
      return a.errors;
    },
  });
}

// ── S19 (S-VF): 投票の union 正典（取下げも対象矛盾も**失格にならない**） ──
// 🔴 P-2026-0805（2026-08-05）: 期待値を反転した。
//    ・取下げ（受領済み発信を自分の提出物から外す）→ 検証⑥(b) を廃止したので union で成立
//    ・対象矛盾（別対象の2票目）→ 失格にせず正準順序の先頭1件を採る
//    どちらも「乗り換えの利得ゼロ」は保たれたまま、冤罪だけが消える。
{
  const players = mkPlayers(5);
  SCENARIOS.push({
    key: 'S19', name: 'vote-fraud',
    scenario: {
      name: 'S19', players,
      gamePlan(groupRows) {
        const m = groupRows[0].members.map(x => x.uid);
        return {
          withdrawVote: [m[1]],                       // 受領済み投票を自分の提出から外す → union で成立
          conflictVote: [{ uid: m[2], target: m[0] }], // 2票目（別対象・正当署名）→ 先頭1件を採用
          reports: {},
        };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.scoring': 'pass', 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const m = fx.chainInfo.groups[0].memberUids;
      // 取下げ: 他メンバーの観測＋受領証明から投票が成立する（罰しない）
      assertMember(a, summary, m[1], { dq: false });
      // 対象矛盾: 正準順序の先頭1件が有効な投票になる（罰しない）
      assertMember(a, summary, m[2], { dq: false });
      assertMember(a, summary, m[0], { dq: false });
      assertMember(a, summary, m[3], { dq: false });
      assertMember(a, summary, m[4], { dq: false });
      return a.errors;
    },
  });
}

// ── S20 (S-RF): 密告の union 正典（取下げは失格にならず、密告は有効なまま） ──
// 🔴 P-2026-0805（2026-08-05）: 期待値を反転した。
//    受領済み密告を提出物から外しても union で成立する＝取下げにならない。
//    **これがテストラン block1 の冤罪（クライアントが提出物から密告を落とした）の直接の是正**。
{
  const players = mkPlayers(4);
  SCENARIOS.push({
    key: 'S20', name: 'report-fraud',
    scenario: {
      name: 'S20', players,
      gamePlan(groupRows) {
        const m = groupRows[0].members.map(x => x.uid);
        return {
          reports: { [m[3]]: [m[0], m[2]] },  // m0,m2 が m3 を密告（両方受領あり）
          withdrawReport: [m[0]],             // m0 は受領済み密告を提出から外す → union で成立
        };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.scoring': 'pass', 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const m = fx.chainInfo.groups[0].memberUids;
      // 取下げでは失格しない（冤罪の是正）
      assertMember(a, summary, m[0], { dq: false });
      // m0 の密告が union で生きるので密告者は2名 → m3 は reported になる
      const m3 = memberOf(summary, m[3]);
      a.ok(reasonsOf(m3).includes('reported'), 'm3 is reported (union で密告者2名が成立)');
      return a.errors;
    },
  });
}

// ── S21 (S-CM): チャット正典union（事後削除耐性: 本人が提出から削っても受領証明で復活） ──
{
  const players = mkPlayers(4);
  SCENARIOS.push({
    key: 'S21', name: 'chat-canon-union',
    scenario: {
      name: 'S21', players,
      gamePlan(groupRows) {
        const m = groupRows[0].members.map(x => x.uid);
        // m1 は自分の22発言中15件を自分の提出物から削除（残7×60字=420 < 500）。
        // 他メンバーの提出物＋受領証明から正典復活 → min_chars にならない＝事後削除は不可能。
        return { dropOwnMessages: { [m[1]]: 15 }, reports: {} };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.scoring': 'pass', 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const m = fx.chainInfo.groups[0].memberUids;
      assertMember(a, summary, m[1], { dq: false });
      a.ok(!reasonsOf(memberOf(summary, m[1])).includes('min_chars'),
        'm1 not min_chars (deleted messages restored from union+receipts)');
      return a.errors;
    },
  });
}

// ── S8: 投票（正常ボーナス / no_vote / 自己投票=vote_fraud / 失格者投票無効） ──
{
  const players = mkPlayers(5);
  SCENARIOS.push({
    key: 'S8', name: 'vote-branches',
    scenario: {
      name: 'S8', players,
      gamePlan(groupRows) {
        const m = groupRows[0].members.map(x => x.uid);
        return {
          votes: { [m[0]]: m[1], [m[1]]: null, [m[2]]: 'self', [m[3]]: m[0], [m[4]]: m[0] },
          lowChars: [m[4]], // m4 は min_chars 失格 → その投票はボーナス無効
          reports: {},
        };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const m = fx.chainInfo.groups[0].memberUids;
      const P = 50;
      assertMember(a, summary, m[1], { dq: true, reasons: ['no_vote'], bonus: P, total: 0 }); // m0票は記録されるが total 0
      // v3.3追補: 復号できたのに対象が無効（自己投票）＝デタラメ発信なので vote_fraud
      assertMember(a, summary, m[2], { dq: true, reasons: ['vote_fraud'], total: 0 });
      assertMember(a, summary, m[4], { dq: true, reasons: ['min_chars'], total: 0 });
      // m0 のボーナス = m3 の票のみ（m4 は失格投票で無効）
      assertMember(a, summary, m[0], { dq: false, dp: P, bonus: P, total: 2 * P });
      assertMember(a, summary, m[3], { dq: false, dp: P, bonus: 0, total: P });
      return a.errors;
    },
  });
}

// ── S9: 密告（≥2＋点超過で失格＋report_gain / 2名でも点不足なら非失格 / 1名は非失格） ──
{
  const eths = ['0.09', '0.16', '0.25', '1.0', '0.25']; // 30/40/50/100/50 pt
  const players = mkPlayers(5, { eth: (i) => eths[i] });
  SCENARIOS.push({
    key: 'S9', name: 'report-branches',
    scenario: {
      name: 'S9', players,
      gamePlan(groupRows) {
        const uidsByEth = Object.fromEntries(players.map(p => [p.eth, p.uid])); // eth→uid（一意でないethは25専用処理）
        const p009 = players.find(p => p.eth === '0.09').uid;
        const p016 = players.find(p => p.eth === '0.16').uid;
        const [p025a, p025b] = players.filter(p => p.eth === '0.25').map(p => p.uid);
        const p100 = players.find(p => p.eth === '1.0').uid;
        void uidsByEth;
        return {
          reports: {
            [p009]: [p025a, p025b],  // 50+50 > 30 → DQ・gain 7pt ずつ
            [p100]: [p016, p009],    // 40+30 <= 100 → 非失格（点不足分岐）
          },

        };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const p009 = players.find(p => p.eth === '0.09').uid;
      const p100 = players.find(p => p.eth === '1.0').uid;
      const [p025a, p025b] = players.filter(p => p.eth === '0.25').map(p => p.uid);
      const gain = Math.floor(Math.floor(30 / 2) / 2); // = 7
      assertMember(a, summary, p009, { dq: true, reasons: ['reported'], total: 0 });
      assertMember(a, summary, p100, { dq: false });
      const ra = memberOf(summary, p025a);
      const rb = memberOf(summary, p025b);
      a.eq(ra.deposit_points, 50 + gain, `${p025a} report gain`);
      a.eq(rb.deposit_points, 50 + gain, `${p025b} report gain`);
      return a.errors;
    },
  });
}

// ── S10: min_chars / min_messages 失格 ──
{
  const players = mkPlayers(4);
  SCENARIOS.push({
    key: 'S10', name: 'chat-thresholds',
    scenario: {
      name: 'S10', players,
      gamePlan(groupRows) {
        const m = groupRows[0].members.map(x => x.uid);
        return { lowChars: [m[1]], lowTurns: [m[2]], reports: {} };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      const m = fx.chainInfo.groups[0].memberUids;
      assertMember(a, summary, m[1], { dq: true, reasons: ['min_chars'], total: 0 });
      assertMember(a, summary, m[2], { dq: true, reasons: ['min_messages'], total: 0 });
      assertMember(a, summary, m[0], { dq: false, total: 50 }); // m2票(DQ)・m3票? rotation: m2→m0 無効, m3→m1
      assertMember(a, summary, m[3], { dq: false });
      return a.errors;
    },
  });
}

// ── S11: デポジット（ineligible_deposit / 外部デポジター50/50按分・端数last） ──
{
  const eths = ['1.0', '0.5', '0.5', '0.25', '0.25'];
  const players = mkPlayers(5, { eth: (i) => eths[i] });
  const ineligibleUid = uidFor(2);
  SCENARIOS.push({
    key: 'S11', name: 'deposit-branches',
    scenario: {
      name: 'S11', players,
      externalDepositors: [
        { uid: '31009000', keyIndex: 90, eth: '0.3', forUid: uidFor(0) },
        { uid: '31009100', keyIndex: 91, eth: '0.2', forUid: uidFor(0) },
        { uid: '31009200', keyIndex: 92, eth: '0.5', forUid: uidFor(1) },
      ],
      behavior: { ineligibleDeposit: [ineligibleUid] },
      gamePlan() { return { reports: {} }; },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.depositVerification': 'pass', 'check.stageC.summaryMatch': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      assertMember(a, summary, ineligibleUid, { dq: true, reasons: ['ineligible_deposit'], total: 0 });
      // uid0: 自己1.0 + 外部0.3+0.2 = 検証済み1.5 ETH → 122pt。50/50＋**全員切り捨て**
      const m0 = memberOf(summary, uidFor(0));
      a.eq(m0.deposit_points, dp('1.5'), 'uid0 verified deposit points');
      const g0 = summary.groups.find(g => g.members.some(x => x.userId === uidFor(0)));
      const rows0 = (g0.depositor_results || []).filter(d => d.playerUid === uidFor(0));
      a.eq(rows0.length, 3, 'uid0 depositor rows (self + 2 external)');
      const sum0 = rows0.reduce((s, d) => s + BigInt(d.btcuReward), 0n);
      // SPEC §7: 端数（最大 N−1 wei）は誰にも配らない → 等号ではなく不等号
      const undist0 = BigInt(m0.full_btcu_reward) - (BigInt(m0.player_share) + sum0);
      a.eq(undist0 >= 0n, true, 'uid0 50/50 conservation (player+depositors <= full)');
      a.eq(undist0 <= BigInt(rows0.length - 1), true, `uid0 undistributed <= N-1 wei (got ${undist0})`);
      a.eq(BigInt(m0.player_share).toString(), (BigInt(m0.full_btcu_reward) / 2n).toString(), 'uid0 player_share = floor(full/2)');
      // ineligible の行は全て 0
      for (const g of summary.groups) {
        for (const d of (g.depositor_results || []).filter(x => x.playerUid === ineligibleUid)) {
          a.eq(d.btcuReward, '0', 'ineligible depositor rows are 0');
        }
      }
      return a.errors;
    },
  });
}

// ── S12: majorLangs（前ブロック≥200/言語→同言語グループ化 vs ミックス・端数吸収） ──
{
  const players = mkPlayers(10, { lang: (i) => (i === 9 ? 'en' : 'ja') });
  SCENARIOS.push({
    key: 'S12', name: 'major-langs-block1',
    scenario: {
      name: 'S12', blockNum: 1, players,
      prevBlock: { type: 'summary', langs: { ja: { ok: 205, dq: 20 }, en: { ok: 150 } } },
      gamePlan() { return { reports: {} }; },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: {
      'check.stageB.prevAnchor': 'pass',
      'check.stageB.majorLangs': 'pass',
      'check.stageB.groupsMatch': 'pass',
      'check.stageC.majorLangsMatch': 'pass',
      'check.stageC.summaryMatch': 'pass',
    },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      a.eq(summary.majorLangs, ['ja'], 'summary.majorLangs == [ja] (205 >= 200, en 150 < 200, DQ除外)');
      // 端数吸収: 8 ja → 4+4、端数2名（en+拠出ja）は最小グループへ吸収 → 6名 > 5 → 再分割 3+3
      //（absorbStragglers:3763-3777 の resplit 経路 = 3人組新設の分岐も同時に踏む）
      const gg = readJson(fx.r2Dir, 'entries/block1/game_groups.json');
      const sizes = gg.groups.map(g => g.memberCount).sort();
      a.eq(sizes, [3, 3, 4], 'groups 3/3/4 (stragglers absorbed then resplit)');
      a.eq(gg.groups.filter(g => g.mixed).length, 1, 'exactly one mixed group (en straggler)');
      return a.errors;
    },
  });
}

// ── S13: Evidence 全分類（identical/missing/mismatch/invalid＋完全性） ──
{
  const players = mkPlayers(8, { lang: (i) => (i % 2 === 0 ? 'ja' : 'en') });
  SCENARIOS.push({
    key: 'S13', name: 'evidence-classification',
    scenario: {
      name: 'S13', players,
      behavior: { evidence: { garbage: 1 } }, // garbage は静的宣言（資金供給）。uid リストは gamePlan で確定
      gamePlan(groupRows) {
        const g0 = groupRows[0];
        const g1 = groupRows[1] || g0;
        const identical = g0.members[0].uid;
        const censored = g0.members[1].uid;
        const tampered = (g1 === g0 ? g0.members[2] : g1.members[0]).uid;
        const chainOnly = g1.members[1].uid; // WS未提出＋チェーン提出 = 検閲と同型（missing→復元）
        return {
          noSubmit: [chainOnly],
          evidence: {
            chain: [identical, censored, tampered, chainOnly],
            censorServer: [censored],
            tamperServer: [tampered],
          },
        };
      },
    },
    expectResult: 'full', expectExit: [0],
    expectChecks: {
      'check.stageC.evidenceCompleteness': 'pass',
      'check.stageC.archiveChainConsistency': 'pass',
      'check.stageC.evidenceReportMatch': 'pass',
      'check.stageC.summaryMatch': 'pass',
    },
    assertFixture(fx) {
      const a = makeAsserter();
      const N = fx.chainInfo.blockNum;
      const report = readJson(fx.r2Dir, `verification/block${N}/evidence-report.json`);
      a.eq(report.resultCount, 5, 'resultCount = 4 bundles + 1 garbage');
      a.eq(report.invalid.length, 1, 'one invalid event');
      a.eq(report.invalid[0]?.seq, fx.chainInfo.evidence.garbageSeqs[0], 'invalid seq == garbage seq');
      const states = Object.fromEntries(report.adopted.map(x => [x.uid, x.serverState]));
      const meta = fx.chainInfo.meta.evidence;
      for (const uid of meta.identical) a.eq(states[uid], 'identical', `${uid} identical`);
      for (const uid of meta.missing) a.eq(states[uid], 'missing', `${uid} missing`);
      for (const uid of meta.mismatch) a.eq(states[uid], 'mismatch', `${uid} mismatch`);
      // チェーン復元の実効性: missing 組は no_submit になっていない
      const summary = summaryOf(fx);
      for (const uid of meta.missing) {
        a.ok(!reasonsOf(memberOf(summary, uid)).includes('no_submit'), `${uid} restored (not no_submit)`);
      }
      return a.errors;
    },
  });
}

// ── S14: 報酬階層（block 91 / 182。block 0 は他シナリオで網羅） ──
//
// 🔴 T-1（2026-08-08・ラウンド20 判断不要-4）: **期待値を BigInt リテラルで直書きする。**
//    旧実装は `getBlockRewardWei(blockNum)` を期待値にしていたので、
//    段境界を `<=90 → <=91` にずらしても **S14a（block 91）が緑のまま**だった
//    （検査対象と期待値が同じ関数から出るので一緒に動く）。
//    Solidity（`Hardhat/bitcoinu/scripts/test_local.js` §17）と Rust
//    （`crates/scoring-core/tests/summary_differential.rs`）は同じ値を絶対 pin している。
const REWARD_TIER_WEI = { 0: '115384615384615000000000', 91: '57692307692307700000000', 182: '28846153846153800000000' };
for (const [key, blockNum] of [['S14a', 91], ['S14b', 182]]) {
  const players = mkPlayers(4, { lang: (i) => (i % 2 === 0 ? 'ja' : 'en') });
  const wantReward = REWARD_TIER_WEI[blockNum];
  SCENARIOS.push({
    key, name: `reward-tier-block${blockNum}`,
    scenario: { name: key, blockNum, players },
    expectResult: 'full', expectExit: [0],
    expectChecks: { 'check.stageC.rulesReward': 'pass', 'check.stageC.merkleTotals': 'pass' },
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      a.eq(summary.blockReward, wantReward, `blockReward tier for block ${blockNum}（絶対値 pin）`);
      a.eq(manifestOf(fx).rules.blockRewardWei, wantReward, 'manifest rules.blockRewardWei（絶対値 pin）');
      // 正典の関数も同じ値を返すこと（段境界のズレをここで殺す）
      a.eq(getBlockRewardWei(blockNum).toString(), wantReward, `getBlockRewardWei(${blockNum}) が絶対 pin と一致`);
      a.eq(getBlockRewardWei(blockNum - 1).toString(),
        REWARD_TIER_WEI[blockNum === 91 ? 0 : 91], `getBlockRewardWei(${blockNum - 1}) は1つ前の段`);
      return a.errors;
    },
  });
}

// ── S15: registrationCount>1（同一ハッシュ再登録 → Stage A WARN、Stage Bは最初の登録） ──
{
  const players = mkPlayers(4, { lang: (i) => (i % 2 === 0 ? 'ja' : 'en') });
  SCENARIOS.push({
    key: 'S15', name: 'hash-reregistration-warn',
    scenario: { name: 'S15', players, registerHashTwice: true },
    expectResult: 'full', expectExit: [0],
    expectChecks: {
      'check.stageA.registrationCount': 'warn',
      'check.stageA.rootMatch': 'pass',
      'check.stageB.hashRegisteredBlock': 'pass',
    },
  });
}

// ── S22: Request3 T-11 — live roster anchor の意味別分類 ──
// 未登録/hash不一致/公開manifest欠落は FAIL。遅着は grace 延長後の開始で PASS。
// RPC読取不能だけは警告に留める。
// S22a は R33-U-B1D01 により、WS 提出があっても全員0点・空ツリー標識ルートになる。
for (const spec of [
  {
    key: 'S22a', name: 'roster-anchor-unregistered-fail', mode: 'missing',
    expectResult: 'fail', expectExit: [2], status: 'fail', allowFail: true,
    assertFixture(fx) {
      const a = makeAsserter();
      const summary = summaryOf(fx);
      for (const player of mkPlayers(4)) {
        const member = memberOf(summary, player.uid);
        a.ok(member != null, `${player.uid} exists in summary`);
        if (member) {
          a.eq(member.total_points, 0, `${player.uid} total_points without prestart roster`);
          a.eq(member.btcu_reward, '0', `${player.uid} reward without prestart roster`);
        }
      }
      const merkle = merkleOf(fx);
      a.eq(merkle.leafCount, 0, 'unregistered roster merkle leafCount');
      a.eq(merkle.root.toLowerCase(), emptyMerkleSentinel(fx.chainInfo.blockNum).toLowerCase(),
        'unregistered roster sentinel root');
      return a.errors;
    },
  },
  {
    // 周31 R31-U-B（2026-09-24 ユーザー決定）: 名簿の正典は開始前の最後の登録で、開始以後の登録は無視する。
    // フィクスチャの mismatch は GM がチャット開始を張った後・チェーンの開始時刻の後に別 hash を登録するので、
    // 無視されて rosterLiveAnchor=warn になる（正典は変えず件数を警告する）。
    // 開始前の不一致は R31-U-A で正直な GM が開始を張らず、検証ツールの判定は v25 の開始前の盤面が縛る。
    key: 'S22b', name: 'roster-anchor-overwrite-after-start-ignored', mode: 'mismatch',
    expectResult: 'full', expectExit: [0], status: 'warn', allowFail: false,
  },
  {
    key: 'S22c', name: 'roster-manifest-missing-fail', mode: null,
    expectResult: 'fail', expectExit: [2], status: 'fail', allowFail: true,
    mutateFixture(fx) {
      rmSync(join(fx.r2Dir, `games/block${fx.chainInfo.blockNum}/roster/manifest.json`));
    },
  },
  {
    key: 'S22d', name: 'roster-anchor-late-grace-extended-pass', mode: 'late',
    expectResult: 'full', expectExit: [0], status: 'pass', allowFail: false,
    assertFixture(fx) {
      const t = fx.chainInfo.timing;
      const originalStart = t.entryEnd + t.GRACE;
      return t.chattingStart > originalStart
        ? [] : [`S22d: grace did not extend beyond ${originalStart} (actual ${t.chattingStart})`];
    },
  },
]) {
  const players = mkPlayers(4, { lang: (i) => (i % 2 === 0 ? 'ja' : 'en') });
  SCENARIOS.push({
    key: spec.key,
    name: spec.name,
    scenario: { name: spec.key, players, rosterAnchorMode: spec.mode },
    expectResult: spec.expectResult,
    expectExit: spec.expectExit,
    expectChecks: { 'check.stageC.rosterLiveAnchor': spec.status },
    allowFail: spec.allowFail,
    mutateFixture: spec.mutateFixture,
    assertFixture: spec.assertFixture,
  });
}

// ---------------- ランナー ----------------
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const argOf = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const only = argOf('--only', null);
  const outRoot = resolve(argOf('--out', resolve(__dir, 'out/simulation')));

  if (args.includes('--list')) {
    for (const s of SCENARIOS) console.log(`${s.key}\t${s.name}`);
    process.exit(0);
  }
  if (!toolLooksComplete()) {
    console.error('tool not complete (need src/{index,i18n,report}.js) — aborting');
    process.exit(1);
  }

  const list = SCENARIOS.filter(s => !only || s.key === only);
  const results = [];
  for (let i = 0; i < list.length; i++) {
    const s = list[i];
    const t0 = Date.now();
    console.log('═'.repeat(60));
    console.log(`scenario ${s.key}: ${s.name}`);
    console.log('═'.repeat(60));
    const caseDir = join(outRoot, s.key);
    const errors = [];
    let fx = null;
    let srv = null;
    try {
      fx = await generateFixture({ port: 8600 + i * 2, outDir: caseDir, scenario: s.scenario });

      // 内部整合（files ⇔ chain）
      const consistency = await verifyFixtureInternalConsistency({ r2Dir: fx.r2Dir, chainInfo: fx.chainInfo });
      for (const f of consistency.failures) errors.push(`consistency: ${f}`);

      // 負の公開物シナリオは、正典生成物の内部整合を確認した後で対象だけを変異させる。
      if (s.mutateFixture) await s.mutateFixture(fx);

      // ツール実行
      srv = await startR2Server({ rootDir: fx.r2Dir, port: 9100 + i });
      const configPath = writeToolConfig({
        outDir: caseDir, chainInfo: fx.chainInfo, r2BaseUrl: srv.baseUrl,
        dataDir: join(caseDir, 'verifier-data'),
      });
      const run = await runTool({ configPath, blockNum: fx.chainInfo.blockNum });
      const { checks, result } = parseChecks(run.stdout);
      console.log(`  tool exit=${run.code} ##RESULT=${result ?? '(none)'} checks=${checks.size}`);

      if (result !== s.expectResult) errors.push(`##RESULT: expected ${s.expectResult}, got ${result}`);
      if (!s.expectExit.includes(run.code)) errors.push(`exit: expected ${s.expectExit.join('/')}, got ${run.code}`);
      // 「サーバー正常＝FAIL無し」の大前提: 全シナリオで fail は1つも出ないこと
      const fails = [...checks.entries()].filter(([, st]) => st === 'fail').map(([id]) => id);
      if (!s.allowFail && fails.length > 0) errors.push(`unexpected FAIL checks: ${fails.join(', ')}`);
      for (const [id, st] of Object.entries(s.expectChecks || {})) {
        if (checks.get(id) !== st) errors.push(`${id}: expected ${st}, got ${checks.get(id) ?? 'absent'}`);
      }
      if (s.assertFixture) {
        try {
          errors.push(...s.assertFixture(fx));
        } catch (e) {
          errors.push(`assertFixture threw: ${e.message}`);
        }
      }
      if (errors.length > 0) {
        const tail = (x) => x.split('\n').slice(-30).join('\n');
        console.error(`  --- tool stdout (tail) ---\n${tail(run.stdout)}`);
        if (run.stderr) console.error(`  --- tool stderr (tail) ---\n${tail(run.stderr)}`);
      }
    } catch (e) {
      errors.push(`fatal: ${e.message}`);
      console.error(e);
    } finally {
      try { srv?.stop(); } catch { /* noop */ }
      try { fx?.stop(); } catch { /* noop */ }
    }
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    if (errors.length === 0) {
      console.log(`  ${s.key}: OK (${secs}s)`);
    } else {
      console.error(`  ${s.key}: NG (${secs}s)`);
      for (const e of errors) console.error(`   - ${e}`);
    }
    results.push({ key: s.key, name: s.name, ok: errors.length === 0, errors, secs });
  }

  console.log('═'.repeat(60));
  console.log('simulation matrix summary');
  console.log('═'.repeat(60));
  let failCount = 0;
  for (const r of results) {
    console.log(`  ${r.ok ? 'OK ' : 'NG '} ${r.key.padEnd(5)} ${r.name} (${r.secs}s)`);
    if (!r.ok) failCount++;
  }
  console.log(failCount === 0 ? `simulation: PASS (${results.length} scenarios)` : `simulation: FAIL (${failCount}/${results.length} scenarios NG)`);
  process.exit(failCount === 0 ? 0 : 1);
}
