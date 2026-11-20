// gen-fixture.mjs — 偽ブロック一式を【本番コード実行】で生成するフィクスチャジェネレータ。
//
//   entries(100シャード) → applicantHash連鎖(collect-DO正典) → HashStorage.registerHash(ローカル実チェーン)
//   → RANDAO読取 → 抽選(LotteryDO正典) → game_selection.json → GameMasterDO.startGrouping(正典)
//   → ChatGameDO実プロトコル進行(実鍵署名・実ECIES) → Evidence.submitResult(実チェーン・検閲/改ざんケース込み)
//   → GameMasterDO.calculateAndStoreResults(正典: reconcile/デポジット再検証/採点/summary/merkle/manifest
//     ＋ submitMerkleRoot / registerResultHash を実チェーンへ実送信)
//
// SIMULATION_HANDOFF.md §2.1: scenario スペックでパラメータ化済み。
//   generateFixture({ port, outDir, node, scenario })
//   scenario 省略時は DEFAULT_SCENARIO（従来の固定8人シナリオ・回帰維持）。
//   0名（S4）は noGame summary・空ツリー標識root・manifestまで本番経路で生成し、
//   1〜2名（S3）は startGrouping 内の autoDistribute（本番コード）が summary/merkle/manifest まで完結する。
//
// 使い方:
//   node block-verifier/test/gen-fixture.mjs [--port 8547] [--out block-verifier/test/out/fixture] [--keep-alive]
// ライブラリ:
//   const { chainInfo, r2Dir, stop } = await generateFixture({ port, outDir });
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { keccak256, concatHex, stringToHex, parseEther } from 'viem';
import { buildRosterMemberCommitment, createRosterMemberProof } from '../../workers/game_workers/lib/roster-member-root.js';

import {
  GameMasterDO, ChatGameDO, LotteryDO,
  readWorkerHashFiles, createIntermediateHash, createRootHash, collectCalculateHash,
  getBlockRewardWei,
  decodeSubmissionPayloadString, encodeEvidenceCompactV1, compactBytesToPayload,
} from './canonical.mjs';
import {
  makeStorage, makeState, makeFakeWs, makeR2Bucket, makeD1Stub, makeChatGameNamespace,
} from './stubs.mjs';
// G1: proofsステージの発注先＝本物のclaim-worker（/build-proofs）をfixture R2に直結する
import claimWorker from '../../workers/claim_workers/claim-worker.js';
import {
  makePlayer, buildDepIdsJson, makeChatWsData, makeActionWsData,
  makeActionReceipt, makeReadReceipt,
  buildSubmissionPayload, evidenceBytesFor, bytesToHex, eciesEncryptFor, fixedWalletKey,
} from './players.mjs';
import {
  TIMING, timingDerived, CHAIN_ID, DEPLOYER_KEY,
  startNode, deployContracts, makeClients, write, rpc,
  setNextTimestamp, mineOne, mineMany,
} from './chain-setup.mjs';
import adminTxCoordinatorWorker, {
  AdminTxCoordinatorDO,
} from '../../workers/admin_tx_coordinator/index.js';

const __dir = dirname(fileURLToPath(import.meta.url));

const sha256Hex = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

// S22d は長い BLOCK_TIME と開始遅延のため、通常の近傍 S より余裕が要る。
// 時計の予備検査にも使えるよう、シナリオの時刻選択をチェーン起動から分離する。
export function fixtureTimingForScenario(scenario, nowMs = Date.now()) {
  if (scenario?.name !== 'S22d' || scenario?.rosterAnchorMode !== 'late') return TIMING;
  // shieldStartWindow の30分+2分を収めるため、この盤面の BLOCK_TIME は
  // 1時間とし、応募開始を実時刻の近くに置く（平時シナリオの TIMING は不変）。
  return { ...TIMING, S: Math.floor(nowMs / 1000) + 300, BLOCK_TIME: 3600 };
}

// 空ツリー標識ルート（game-master-DO.js buildMerkleTree:3023-3025 と同一式）
export const emptyMerkleSentinel = (blockNum) => keccak256(stringToHex(`bitcoinu:empty-merkle:${blockNum}`));

// ---------------- プレイヤー計画（決定論・固定uid/固定鍵） ----------------
// uid 末尾4桁の先頭2桁 = collect-worker 番号（'0001'→00 / '0101'→01 / '0201'→02）
// → ワーカー 00/01/02 にエントリー、残り97ワーカーは空（空でも info/hash を必ず出力する契約）。
const PLAYER_PLAN = [
  { uid: '20000001', lang: 'ja', eth: '1.0', name: '田中テスト', img: 'https://example.com/a.png', verified: true },
  { uid: '20000002', lang: 'en', eth: '0.5', name: 'alice',      img: null, verified: false },
  { uid: '20000003', lang: 'ja', eth: '0.25', name: null,        img: null, verified: false },
  { uid: '20000101', lang: 'en', eth: '0.09', name: 'bob',       img: 'https://example.com/b.png', verified: true },
  { uid: '20000102', lang: 'ja', eth: '0.3',  name: 'う〜みん',   img: null, verified: false },
  { uid: '20000103', lang: 'en', eth: '0.15', name: 'carol',     img: null, verified: false },
  { uid: '20000201', lang: 'ja', eth: '0.2',  name: 'dave',      img: null, verified: true },
  { uid: '20000202', lang: 'en', eth: '0.1',  name: 'erin',      img: null, verified: false },
];
const EXTERNAL_DEPOSITOR = { uid: '30000001', keyIndex: 8, eth: '0.5', forUid: '20000001' };

// ---------------- シナリオ・スペック（SIMULATION_HANDOFF.md §2.1） ----------------
// scenario = {
//   name, blockNum,
//   players: [{ uid, lang, eth, name?, img?, verified? }],
//   externalDepositors: [{ uid, keyIndex, eth, forUid }],
//   registerHashTwice: false,           // S15: 同一ハッシュ再登録（registrationCount=2）
//   evidenceRescue: false,              // V25-03: completed後にChatGameDO/group archive/roster index cacheを喪失させ、Evidence救済を実行
//   rosterAnchorMode: null | 'missing' | 'late' | 'mismatch', // Request3 T-11
//   coordinatorAlarmMode: 'alarm' | 'disabled', // disabled=復旧alarm不実行の失敗注入（負の対だけ）
//   prevBlock: null                     // N>0 のデフォルト: 前ブロック「ゲーム無し」summary＋実manifestアンカー
//     | { type: 'noGameSummary' }        //   （finalizeNoGameBlock と同形の noGame:true summary → majorLangs 無し）
//     | { type: 'selectionStub', players: [] }   // 🔴 Q-5 以降は**負のシナリオ専用**。
//         // summary.json を書かず game_selection.json だけ置く＝正典 computeMajorLangs は
//         // MAJOR_LANG_PREV_NOT_READY で止まる（フォールバックを削除したため）。
//     | { type: 'summary', langs: { ja: { ok: 205, dq: 20 }, en: { ok: 150 } } },  // S12: 合成前summary＋実manifestアンカー
//   behavior: {
//     votes: { voterUid: targetUid | 'self' | null } | undefined, // 指定なきuidは rotation (i+2)%n。null=未投票
//     reports: { targetUid: [reporterUid...] } | undefined,       // undefined = 従来既定（n>=4 で [0,2]→3）
//     lowChars: [uid...],   // 22発言×22字 = 484 < 500（min_chars）
//     lowTurns: [uid...],   // 5発言×120字 = 600 ≥ 500・5ターン < 20（min_messages）
//     noSubmit: [uid...],   // WS提出しない（payloadは構築＝chain提出には使える）
//     ineligibleDeposit: [uid...],        // 自己デポジットの unlockTime を適格閾値未満に（B1 ineligible_deposit）
//     chatRounds: 22,
//     --- v3.2 受領証明・不正系フック ---
//     noReadReceiptsFor: [uid...],  // 誰も uid のメッセージに既読受領証明を出さない（正典外→文字数不算入）
//     noVoteReceipt: [uid...],      // uid の投票に受領証明を出さない（受領0＝no_vote）
//     noReportReceipt: [uid...],    // uid の密告に受領証明を出さない（受領0＝密告無効）
//     withdrawVote: [uid...],       // 受領済み投票を自分の提出物から外す（検証⑥b: vote_fraud）
//     withdrawReport: [uid...],     // 受領済み密告を自分の提出物から外す（検証⑥b: report_fraud）
//     conflictVote: [{ uid, target }],  // uid の2票目（別対象・正当署名）を他メンバー観測に混入（検証⑥a: vote_fraud）
//     dropOwnMessages: { uid: N },  // 自分の提出物から自分の末尾Nメッセージを削除（union復活＝事後削除耐性の検証）
//     evidence: { chain: [uid...], censorServer: [uid...], tamperServer: [uid...], garbage: 0 } | undefined,
//       // undefined = 従来既定（identical=g0.m0 / censored=g0.m1(削除) / tampered=g1.m0(改変) の3件提出）
//       // ※ garbage（無効イベント数）はウォレット資金供給の都合上、静的 behavior.evidence 側で宣言すること
//   },
//   gamePlan: (groupRows, byUid) => behaviorPatch,
//     // グループ構成（メンバー正準順序）は seeded shuffle で事前に決められないため、
//     // 順序依存の行動（rotation 相対のタブー上書き・グループ内位置指定など）は
//     // グループ確定後に呼ばれるこのコールバックで behavior を上書きして指定する。
//     // 返り値は behavior と shallow merge される（ineligibleDeposit / evidence.garbage は事前資金供給の
//     // 都合で静的 behavior 側が正）。
// }
export const DEFAULT_SCENARIO = Object.freeze({
  name: 'default',
  blockNum: 0,
  players: PLAYER_PLAN,
  externalDepositors: [EXTERNAL_DEPOSITOR],
  registerHashTwice: false,
  prevBlock: null,
  behavior: {},
});

function normalizeScenario(scenario) {
  const sc = { ...DEFAULT_SCENARIO, ...(scenario || {}) };
  sc.behavior = { ...(scenario?.behavior || {}) };
  sc.players = sc.players || [];
  sc.externalDepositors = sc.externalDepositors || [];
  // 🔴 Q-5（2026-08-08）: 既定を `selectionStub` から `noGameSummary` へ変えた。
  //    正典 `finalizeNoGameBlock` は 0名ブロックでも summary.json ＋ 検証 manifest を必ず書くので、
  //    「前ブロックはゲーム無し」の**実際の公開状態**はこちらが正しい。
  //    `computeMajorLangs` の `game_selection.json` フォールバックは削除済み。
  if (sc.blockNum > 0 && !sc.prevBlock) sc.prevBlock = { type: 'noGameSummary' };
  return sc;
}

// S12: 合成前ブロック summary（buildBlockSummaryWithResults 出力と同形）。
// computeMajorLangs が読むフィールド（groups[].status / members[].is_disqualified / members[].lang）を
// 正典 writer と同じキー順・同じ形で持つ。中身はゲーム未実行の合成データ（majorLangs 検証用の入力）。
function buildSyntheticPrevSummary(prevBlockNum, langs) {
  const members = [];
  let seq = 0;
  for (const [lang, spec] of Object.entries(langs)) {
    for (let i = 0; i < (spec.ok || 0); i++) {
      members.push({ uid: `P${lang}${String(seq++).padStart(4, '0')}`, lang, dq: false });
    }
    for (let i = 0; i < (spec.dq || 0); i++) {
      members.push({ uid: `P${lang}${String(seq++).padStart(4, '0')}`, lang, dq: true });
    }
  }
  const groups = [];
  for (let g = 0; g * 4 < members.length; g++) {
    const chunk = members.slice(g * 4, g * 4 + 4);
    const groupMembers = chunk.map(m => ({
      userId: m.uid, address: null, img: null, name: null, lang: m.lang, verified: false,
      depIds: null, deposit_points: 10, bonus_points: 0,
      total_points: m.dq ? 0 : 10,
      is_disqualified: m.dq ? 1 : 0,
      disqualify_reason: m.dq ? 'no_submit,no_vote' : null,
      btcu_reward: '0', full_btcu_reward: '0', player_share: null, depositor_share: null, claimed: 0,
    }));
    groups.push({
      group_id: g,
      lang: new Set(chunk.map(m => m.lang)).size > 1 ? 'mixed' : chunk[0].lang,
      member_count: chunk.length,
      status: 'completed',
      total_points: groupMembers.reduce((s, m) => s + m.total_points, 0),
      members: groupMembers,
      depositor_results: [],
    });
  }
  return {
    blockNum: prevBlockNum,
    majorLangs: [],
    groups,
    blockReward: getBlockRewardWei(prevBlockNum).toString(),
    updatedAt: new Date().toISOString(),
  };
}

// ---------------- メイン ----------------
export async function generateFixture({ port = 8547, outDir = resolve(__dir, 'out/fixture'), node = null, scenario = null } = {}) {
  const sc = normalizeScenario(scenario);
  const beh = sc.behavior;
  const t = fixtureTimingForScenario(sc);
  const BLOCK_NUM = sc.blockNum;
  const D = timingDerived(t, BLOCK_NUM);
  const base = D.entryStart; // ブロックNの応募期間開始（従来コードの S に相当するオフセット基準）
  let observedChatTimeline = null;

  rmSync(outDir, { recursive: true, force: true });
  const r2Dir = join(outDir, 'r2');
  mkdirSync(r2Dir, { recursive: true });

  // ---- 1. チェーン起動＋デプロイ ----
  const ownNode = node == null;
  const nodeHandle = node ?? await startNode({ port });
  const rpcUrl = nodeHandle.rpcUrl;
  const dep = await deployContracts(rpcUrl, t);
  const { clients } = dep;
  const contracts = {
    ethStake: dep.ethStake.address,
    tokenMining: dep.tokenMining.address,
    bitcoinu: dep.bitcoinu.address,
    ethLock: dep.ethLock.address,
    hashStorage: dep.hashStorage.address,
    evidence: dep.evidence.address,
  };
  console.log(`[gen:${sc.name}] contracts:`, JSON.stringify(contracts));

  // ---- 2. プレイヤー生成＋資金供給＋EthLock実デポジット（応募期間内の時刻に振付） ----
  const players = [];
  for (let i = 0; i < sc.players.length; i++) {
    players.push(await makePlayer({ ...sc.players[i], blockNum: BLOCK_NUM, keyIndex: i }));
  }
  const byUid = Object.fromEntries(players.map(p => [p.uid, p]));
  const extWallets = sc.externalDepositors.map(ed => ({ ed, clients: makeClients(rpcUrl, fixedWalletKey(ed.keyIndex)) }));

  // 資金供給（deployer → 各ウォレット 3 ETH）
  for (const p of players) {
    const h = await clients.walletClient.sendTransaction({ to: p.addr, value: parseEther('3') });
    await clients.publicClient.waitForTransactionReceipt({ hash: h });
  }
  for (const { clients: extC } of extWallets) {
    const h = await clients.walletClient.sendTransaction({ to: extC.account.address, value: parseEther('3') });
    await clients.publicClient.waitForTransactionReceipt({ hash: h });
  }
  // 無効 data も名簿本人から提出する。契約は非メンバーの送信を拒否する。
  const garbageCount = beh.evidence?.garbage || 0;

  // デポジット（応募期間 [base, base+BT) 内。unlockTime は適格条件 unlock*1000 >= START+(N+2)*BT を満たす）
  const eligibleUnlock = t.S + (BLOCK_NUM + 3) * t.BLOCK_TIME;
  const ineligibleUnlock = t.S + (BLOCK_NUM + 2) * t.BLOCK_TIME - 60; // 閾値未満 → B1 で不適格
  const ineligibleSet = new Set(beh.ineligibleDeposit || []);
  if (players.length > 0) await setNextTimestamp(rpcUrl, base + 10);
  let nextDepositId = 1;
  // 請求データ自己完結化（2026-08-01）: EthLock の idFrom/idTo は **uint256（X ユーザーIDの数値）**、
  // 表示用の name / profile_image_url は profileFrom/profileTo（JSON 文字列）へ分離された。
  //   deposit(uint256 idFrom, uint256 idTo, string profileFrom, string profileTo, uint256 unlockTime)
  // 契約は `idTo == uid` の整数比較で適格判定するので、uid は数字列でなければならない。
  const profileOf = (uid) => {
    const p = sc.players.find((x) => String(x.uid) === String(uid))
      || sc.externalDepositors.find((x) => String(x.uid) === String(uid));
    return JSON.stringify({ name: p?.name ?? null, profile_image_url: p?.img ?? null });
  };
  const depositTx = async (fromClients, depositorUid, playerUid, eth, unlockTime) => {
    for (const [label, u] of [['idFrom', depositorUid], ['idTo', playerUid]]) {
      if (!/^[1-9][0-9]{0,19}$/.test(String(u))) {
        throw new Error(`[gen] ${label}=${u} は EthLock（uint256・0不可）に載せられない。fixture の uid は数字列にすること`);
      }
    }
    const receipt = await write(fromClients, dep.ethLock, 'lockETH',
      [BigInt(depositorUid), BigInt(playerUid), profileOf(depositorUid), profileOf(playerUid), BigInt(unlockTime)],
      { value: parseEther(eth) });
    return { id: nextDepositId++, receipt };
  };
  const depositsOf = {}; // uid -> [{id, from}]
  for (const p of players) {
    const playerClients = makeClients(rpcUrl, p.walletKey);
    const unlock = ineligibleSet.has(p.uid) ? ineligibleUnlock : eligibleUnlock;
    const { id } = await depositTx(playerClients, p.uid, p.uid, sc.players.find(x => x.uid === p.uid).eth, unlock);
    (depositsOf[p.uid] ||= []).push({ id, from: p.uid });
    for (const { ed, clients: extC } of extWallets) {
      if (ed.forUid !== p.uid) continue;
      const { id: id2 } = await depositTx(extC, ed.uid, p.uid, ed.eth, eligibleUnlock);
      depositsOf[p.uid].push({ id: id2, from: ed.uid });
    }
  }
  // オンチェーン値で depIds（entry-worker 形式）を確定（amount/unlockTime/depositerAddress はチェーンが権威）
  for (const p of players) {
    const list = [];
    for (const d of depositsOf[p.uid]) {
      const cd = await clients.publicClient.readContract({
        address: dep.ethLock.address, abi: dep.ethLock.abi, functionName: 'getLock', args: [BigInt(d.id)],
      });
      list.push({
        id: d.id,
        idFrom: d.from,
        amount: BigInt(cd.amount).toString(),
        depositerAddress: cd.lockOwnerAddress,
        unlockTime: Number(cd.unlockTime),
      });
    }
    p.deposits = list;
    p.depIds = buildDepIdsJson(list);
  }

  // ---- 3. entries R2ツリー（collect-worker 形式・100ワーカー全出力） ----
  const r2 = makeR2Bucket(r2Dir);
  const workers = {}; // 'WW' -> [record]
  for (const p of players) {
    const ww = p.uid.slice(-4).slice(0, 2);
    (workers[ww] ||= []).push(p);
  }
  const aggregate = { totalRecords: 0, totalFiles: 0, countByLang: {}, depositWei: 0n };
  for (let i = 0; i < 100; i++) {
    const ww = String(i).padStart(2, '0');
    const ps = (workers[ww] || []).sort((a, b) => (a.uid < b.uid ? -1 : 1)); // ORDER BY userId ASC（バイト辞書順）
    // レコード形（collect-worker.js:121-130 のキー順）
    const recs = ps.map(p => ({
      uid: p.uid, addr: p.addr, bAddr: p.bAddrString, lang: p.lang,
      depIds: p.depIds, name: p.name || null, img: p.img || null, verified: p.verified === true,
    }));
    const stats = { entriesRecords: recs.length, countByLang: {}, depositWei: 0n };
    for (const p of ps) {
      stats.countByLang[p.lang] = (stats.countByLang[p.lang] || 0) + 1;
      stats.depositWei += BigInt(JSON.parse(p.depIds).deposit);
    }
    const info = { block_num: BLOCK_NUM, status: 'success', entries: [] };
    const hashFile = { block_num: BLOCK_NUM, status: 'success', entries: [] };
    if (recs.length > 0) {
      const filename = `${ww}_0`;
      await r2.put(`entries/block${BLOCK_NUM}/entries/${filename}.json`, JSON.stringify(recs));
      info.entries.push({ filename, number: recs.length, uid_start: recs[0].uid, uid_end: recs[recs.length - 1].uid });
      // level-1 ハッシュ = SHA-256(JSON.stringify(JSON.parse(bytes)))（collect-worker calculateHash 正典）
      const stored = JSON.parse(await (await r2.get(`entries/block${BLOCK_NUM}/entries/${filename}.json`)).text());
      hashFile.entries.push({ filename, hash: await collectCalculateHash(stored), number: recs.length });
      aggregate.totalFiles += 1;
    }
    info.stats = { entriesRecords: stats.entriesRecords, countByLang: stats.countByLang, depositWei: stats.depositWei.toString() };
    await r2.put(`entries/block${BLOCK_NUM}/info/${ww}_info.json`, JSON.stringify(info));
    await r2.put(`entries/block${BLOCK_NUM}/hash/${ww}_hash.json`, JSON.stringify(hashFile));
    aggregate.totalRecords += recs.length;
    for (const [l, c] of Object.entries(stats.countByLang)) aggregate.countByLang[l] = (aggregate.countByLang[l] || 0) + c;
    aggregate.depositWei += stats.depositWei;
  }
  // collect summary（collect-DO finalizeResults / aggregateWorkerResults のキー順）
  await r2.put(`entries/block${BLOCK_NUM}/summary.json`, JSON.stringify({
    blockNum: BLOCK_NUM, status: 'completed', completedAt: new Date().toISOString(),
    totalRecords: aggregate.totalRecords, totalEntriesRecords: aggregate.totalRecords,
    totalFiles: aggregate.totalFiles, countByLang: aggregate.countByLang,
    totalDepositWei: aggregate.depositWei.toString(), statsMissingWorkers: 0,
    totalWorkers: 100,
    workerStatus: { notStarted: 0, pending: 0, collecting: 0, completed: 100, failed: 0, retrying: 0, requestFailed: 0 },
  }));

  // ---- 4. applicantHash 連鎖（collect-DO 正典メソッド実行）＋オンチェーン登録（早期凍結後） ----
  const hashList = await readWorkerHashFiles(r2, BLOCK_NUM);        // A5 全100完全性込み
  const intermediate = createIntermediateHash(BLOCK_NUM, hashList);
  await r2.put(`entries/block${BLOCK_NUM}/intermediate_hash.json`, JSON.stringify(intermediate));
  const rootHashData = await createRootHash(BLOCK_NUM, intermediate);
  const applicantHash = rootHashData.hash;
  console.log(`[gen:${sc.name}] applicantHash =`, applicantHash);

  // 早期凍結規則: 登録ブロック timestamp*1000 >= entryPeriodEnd = (base+BLOCK_TIME)*1000
  await setNextTimestamp(rpcUrl, D.entryEnd + 1);
  const regReceipt = await write(clients, dep.hashStorage, 'registerHash',
    [BigInt(BLOCK_NUM), applicantHash, clients.account.address]);
  let hashRegisteredBlock = Number(regReceipt.blockNumber);
  if (sc.registerHashTwice) {
    // S15: 同一ハッシュでの再登録（登録リトライの再現）→ registrationCount=2・Stage A WARN。
    // 抽選は同じ root の締切後の最初の登録を使うため、hashRegisteredBlock は動かさない。
    await write(clients, dep.hashStorage, 'registerHash',
      [BigInt(BLOCK_NUM), applicantHash, clients.account.address]);
  }
  await r2.put(`entries/block${BLOCK_NUM}/root_hash.json`, JSON.stringify({
    ...rootHashData,
    txhash: regReceipt.transactionHash, status: 'success',
    blockNumber: hashRegisteredBlock, registeredAt: new Date().toISOString(),
  }));

  // ---- 5. CONFIRMATION_BLOCKS 採掘 → RANDAO 読取 → 抽選（LotteryDO 正典） ----
  await mineMany(rpcUrl, t.CONFIRMATION_BLOCKS, 1);
  const targetBlockNum = hashRegisteredBlock + t.CONFIRMATION_BLOCKS;
  const targetBlock = await rpc(rpcUrl, 'eth_getBlockByNumber', ['0x' + targetBlockNum.toString(16), false]);
  const randao = targetBlock.mixHash;   // lottery-DO getBlockRandao と同じフィールドを verbatim 採用
  if (!/^0x[0-9a-fA-F]{64}$/.test(randao)) throw new Error(`unexpected mixHash from hardhat: ${randao}`);
  console.log(`[gen:${sc.name}] randao(mixHash) =`, randao, 'target =', targetBlockNum);

  const lot = new LotteryDO({ storage: makeStorage() }, {});
  lot.getR2Object = async (_env, key) => {
    const o = await r2.get(key);
    return o ? await o.json() : null;
  };
  const selectionSeed = lot.deriveSelectionSeed(randao, applicantHash);
  const totalEntries = await lot.countCommittedEntries(BLOCK_NUM, 'entries');
  const selectedCount = Math.min(totalEntries, 2100);
  const selectedIndices = await lot.selectWinners(selectionSeed, totalEntries, selectedCount);
  const selectedPlayers = await lot.collectWinnerData(BLOCK_NUM, 'entries', selectedIndices, {});
  if (selectedPlayers.length !== selectedIndices.length) throw new Error('winner mapping mismatch');

  // game_selection.json（lottery-DO.js:717-734 の厳密キー順）
  const gameSelectionData = {
    blockNum: BLOCK_NUM,
    hashRegisteredBlock,
    confirmationBlocks: t.CONFIRMATION_BLOCKS,
    entryPeriodEnd: D.entryEnd * 1000,
    targetBlockNum,
    targetBlockHash: targetBlock.hash,
    randao,
    mainnetBlockNumber: targetBlockNum,
    applicantHash,
    totalEntries,
    totalSelected: selectedPlayers.length,
    players: selectedPlayers,
    createdAt: new Date().toISOString(),
  };
  await r2.put(`entries/block${BLOCK_NUM}/game_selection.json`, JSON.stringify(gameSelectionData));

  // Round 26: Evidence.anchorBlockHash(target) は blockhash(current) を読めない。
  // lottery が target block を取得した直後の実運用と同じく、次のblock到達後に grouping を始める。
  // Hardhatの既定推奨gas価格はbase fee＋tipで1 gweiを超えることがあり、本番Coordinatorの
  // hard cap（1 gwei）が正しくfail-closedする。上限をテスト都合で緩めず、無料ローカル網だけ
  // 次ブロックのbase feeを0にして同じCoordinator経路を通す。
  await rpc(rpcUrl, 'hardhat_setNextBlockBaseFeePerGas', ['0x0']);
  await mineOne(rpcUrl);

  // ---- 6. GameMasterDO（正典）セットアップ ----
  // Coordinatorのハード上限1 gweiと、Hardhatの既定base feeを明示的に整合させる。
  // これは送信結果の偽装ではなく、このローカルchainの次block feeを設定するHardhat RPC。
  // 以後の署名・nonce・simulate・raw tx・receiptはすべて実AdminTxCoordinatorDOと実chainが扱う。
  await rpc(rpcUrl, 'hardhat_setNextBlockBaseFeePerGas', ['0x0']);
  await mineOne(rpcUrl);
  const coordinatorGasPrice = BigInt(await rpc(rpcUrl, 'eth_gasPrice'));
  if (coordinatorGasPrice > 1_000_000_000n) {
    throw new Error(`fixture coordinator gas price ${coordinatorGasPrice} exceeds the production hard cap 1000000000`);
  }

  const d1 = makeD1Stub();
  // S3-002: ChatGameDO の HTTP 制御面は API_SECRET 必須。
  // 本番では GameMasterDO と同一ワーカー＝同一 env なので、フィクスチャでも同じ値を持たせる。
  const cgEnv = { R2_BUCKET: r2, RELEASE_TIME: '2999-01-01T00:00:00Z', API_SECRET: 'test-secret' };
  const chatNS = makeChatGameNamespace(ChatGameDO, cgEnv);
  // 本番の private Service Binding -> index.js -> named DO instance と同じAPI面。
  // PRIVATE_KEYはGameMasterに渡さず、Coordinatorだけが持つ。
  const coordinatorStorage = makeStorage();
  const coordinatorEnv = {
    ETH_CHAIN_ID: String(CHAIN_ID),
    ETHEREUM_MAINNET_RPC_URL: rpcUrl,
    ...(process.env.E2E_IN_PROCESS === '1' ? { ETHEREUM_MAINNET_RPC_URL_BACKUP: rpcUrl.replace('127.0.0.1', 'localhost') } : {}),
    HASH_STORAGE_CONTRACT_ADDRESS: contracts.hashStorage,
    EVIDENCE_CONTRACT_ADDRESS: contracts.evidence,
    TOKEN_MINING_CONTRACT_ADDRESS: contracts.tokenMining,
    PRIVATE_KEY: DEPLOYER_KEY,
    SIGNER_ADDRESS: clients.account.address,
    ADMIN_TX_MAX_GAS_PRICE_GWEI: '1',
  };
  const coordinator = new AdminTxCoordinatorDO({ storage: coordinatorStorage }, coordinatorEnv);
  const coordinatorNamespace = {
    idFromName(name) { return name; },
    get(id) {
      if (id !== 'admin-wallet') throw new Error(`unexpected coordinator DO id: ${id}`);
      return { fetch: (request) => coordinator.fetch(request) };
    },
  };
  const coordinatorGatewayEnv = { ADMIN_TX_COORDINATOR_DO: coordinatorNamespace };
  const adminTxBinding = {
    fetch(input, init) {
      const request = input instanceof Request ? input : new Request(input, init);
      return adminTxCoordinatorWorker.fetch(request, coordinatorGatewayEnv);
    },
  };
  const gmEnv = {
    BITCOINU_DATA: d1,
    CHAT_GAME_DO: chatNS,
    R2_BUCKET: r2,
    API_SECRET: 'test-secret',
    RELEASE_TIME: '2999-01-01T00:00:00Z',
    START_TIME: String(t.S * 1000),
    BLOCK_TIME: String(t.BLOCK_TIME * 1000),
    GAME_PERIOD: String(t.GAME_PERIOD * 1000),
    SUBMIT_PERIOD: String(t.SUBMIT_PERIOD * 1000),
    RESULT_GRACE: String(t.GRACE),
    CONFIRMATION_BLOCKS: String(t.CONFIRMATION_BLOCKS),
    ETH_CHAIN_ID: String(CHAIN_ID),
    ETHEREUM_MAINNET_RPC_URL: rpcUrl,
    ETH_LOCK_CONTRACT_ADDRESS: contracts.ethLock,
    TOKEN_MINING_CONTRACT_ADDRESS: contracts.tokenMining,
    HASH_STORAGE_CONTRACT_ADDRESS: contracts.hashStorage,
    EVIDENCE_CONTRACT_ADDRESS: contracts.evidence,
    ADMIN_TX_COORDINATOR: adminTxBinding,
    SIGNER_ADDRESS: clients.account.address,
    // A1: シナリオからのenv上書き（例: GAME_CALC_UNITS_PER_DRIVE='1' でチャンク実行経路を検証）
    ...(sc.gmEnv || {}),
  };
  // 管理者txは本番と同じ単一Coordinator経路へ通す。2026-09のnonce競合対策以降、
  // GameMasterDOはこのprivate Service Bindingが無い場合にRANDAOアンカーを
  // fail-closedするため、旧fixtureの直接署名envだけではgroupingを開始できない。
  // ローカルでも実Coordinator＋実Hardhat RPCを使い、nonce割当・事前照合・receipt判定を
  // 省略しない（sc.gmEnvで明示したbindingは負のシナリオ用に尊重する）。
  if (!gmEnv.ADMIN_TX_COORDINATOR) {
    const coordinator = new AdminTxCoordinatorDO(makeState(), {
      ETH_CHAIN_ID: String(CHAIN_ID),
      ETHEREUM_MAINNET_RPC_URL: rpcUrl,
      HASH_STORAGE_CONTRACT_ADDRESS: contracts.hashStorage,
      EVIDENCE_CONTRACT_ADDRESS: contracts.evidence,
      TOKEN_MINING_CONTRACT_ADDRESS: contracts.tokenMining,
      PRIVATE_KEY: DEPLOYER_KEY,
      SIGNER_ADDRESS: clients.account.address,
      ADMIN_TX_MAX_GAS_PRICE_GWEI: '1',
    });
    gmEnv.ADMIN_TX_COORDINATOR = { fetch: (request) => coordinator.fetch(request) };
  }
  const gm = new GameMasterDO(makeState(), gmEnv);
  const coordinatorRecovery = {
    mode: sc.coordinatorAlarmMode || 'alarm',
    pendingIntent: null,
    alarmResumed: false,
    callerResumed: false,
    receiptBlock: null,
  };
  if (!['alarm', 'disabled'].includes(coordinatorRecovery.mode)) {
    throw new Error(`unknown coordinatorAlarmMode: ${coordinatorRecovery.mode}`);
  }

  const readCoordinatorStatus = async () => {
    const response = await adminTxBinding.fetch('https://admin-tx-coordinator/status');
    const body = await response.json();
    if (!response.ok) throw new Error(`coordinator status HTTP ${response.status}: ${JSON.stringify(body)}`);
    return body;
  };
  const readCoordinatorIntent = async (intentId) => {
    const response = await adminTxBinding.fetch(`https://admin-tx-coordinator/intent/${encodeURIComponent(intentId)}`);
    const body = await response.json();
    if (!response.ok) throw new Error(`coordinator intent ${intentId} HTTP ${response.status}: ${JSON.stringify(body)}`);
    return body;
  };
  const coordinatorTimeoutState = async (status = null) => {
    const current = status || await readCoordinatorStatus().catch((error) => ({ statusReadError: error.message }));
    const intent = current?.inflight?.intentId
      ? await readCoordinatorIntent(current.inflight.intentId).catch((error) => ({ intentReadError: error.message }))
      : null;
    return { status: current, intent };
  };
  const runCoordinatorAlarm = async () => {
    if (coordinatorRecovery.mode === 'disabled') return false;
    await coordinator.alarm();
    return true;
  };
  const pumpCoordinatorUntilIdle = async (label, timeoutMs = 5000) => {
    const deadline = Date.now() + timeoutMs;
    let status = await readCoordinatorStatus();
    while (status.inflight || status.queued > 0) {
      if (Date.now() >= deadline) {
        throw new Error(`${label}: coordinator deadline exceeded: ${JSON.stringify(await coordinatorTimeoutState(status))}`);
      }
      await runCoordinatorAlarm();
      status = await readCoordinatorStatus();
      if (status.inflight || status.queued > 0) {
        await new Promise((resolveWait) => setTimeout(resolveWait, 25));
      }
    }
    return status;
  };
  const waitUntil = async (timestamp, label, timeoutMs, stateReader) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < Number(timestamp)) {
      if (Date.now() >= deadline) {
        const state = stateReader ? await stateReader() : null;
        throw new Error(`${label}: deadline exceeded: ${JSON.stringify(state)}`);
      }
      const remaining = Math.min(Number(timestamp) - Date.now(), deadline - Date.now(), 50);
      await new Promise((resolveWait) => setTimeout(resolveWait, Math.max(1, remaining)));
    }
  };
  const waitForPhaseTask = async (type, blockNum, timeoutMs = 5000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const queue = (await gm.storage.get('phase_task_queue')) || [];
      const task = queue.find((item) => item.type === type && Number(item.blockNum) === Number(blockNum));
      if (!task) {
        throw new Error(`phase task ${type}/${blockNum} missing: ${JSON.stringify({ queue, active: await gm.storage.get('phase_task_active') })}`);
      }
      if (Number(task.executeAt) <= Date.now()) return task;
      if (Date.now() >= deadline || Number(task.executeAt) > deadline) {
        throw new Error(`phase task ${type}/${blockNum} deadline exceeded: ${JSON.stringify({ task, queue })}`);
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, Math.min(50, Math.max(1, Number(task.executeAt) - Date.now()))));
    }
  };
  const runCoordinatorBacked = async (label, invoke, completed, timeoutMs = 5000) => {
    const deadline = Date.now() + timeoutMs;
    let result = await invoke();
    while (!completed(result)) {
      const status = await readCoordinatorStatus();
      if (!status.inflight && status.queued === 0) {
        throw new Error(`${label}: caller failed without a pending coordinator intent: ${JSON.stringify({ result, status })}`);
      }
      await pumpCoordinatorUntilIdle(label, Math.max(1, deadline - Date.now()));
      if (Date.now() >= deadline) {
        throw new Error(`${label}: caller resume deadline exceeded: ${JSON.stringify({ result, state: await coordinatorTimeoutState() })}`);
      }
      result = await invoke();
    }
    return result;
  };
  // シャードDB書き込み（write-worker への実HTTP）はスコープ外 → no-op（フォールバック、最終レポートに記載）
  gm.writeGameGroupsToShards = async () => ({ totalWritten: 0, totalErrors: 0, workerResults: {} });
  gm.updateGamePhaseToShards = async () => ({ totalWritten: 0, totalErrors: 0 });
  gm.writeGameResultsToShards = async () => ({ totalWritten: 0, totalErrors: 0 });
  // G1: proofs発注は実HTTPの代わりに本物のclaim-worker /build-proofs をfixture R2上で直結
  //（proofファイル生成まで実コードでE2E。レンジ・完全性の意味論は本番と同一）
  gm.dispatchBuildProofs = async (bn, from, to) => {
    const res = await claimWorker.fetch(new Request('http://claim-worker.local/build-proofs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Secret': gmEnv.API_SECRET },
      body: JSON.stringify({ block_number: bn, from, to }),
    }), { R2_BUCKET: r2, API_SECRET: gmEnv.API_SECRET });
    if (!res.ok) throw new Error(`fixture build-proofs: HTTP ${res.status}`);
    return await res.json();
  };
  // merkle root / manifest hash のキャプチャ（送信は本物のメソッドが実チェーンへ行う。
  // 前ブロックアンカー等の別ブロック向け送信はキャプチャせず素通しする）
  const captured = { merkleRoot: null, merkleSubmit: null, manifestHash: null, resultRegister: null };
  const realSubmitMerkle = gm.submitMerkleRootOnChain.bind(gm);
  gm.submitMerkleRootOnChain = async (bn, root) => {
    const res = await realSubmitMerkle(bn, root);
    if (Number(bn) === BLOCK_NUM) { captured.merkleRoot = root; captured.merkleSubmit = res; }
    return res;
  };
  const realRegisterResult = gm.registerResultHashOnChain.bind(gm);
  gm.registerResultHashOnChain = async (bn, hash) => {
    const res = await realRegisterResult(bn, hash);
    if (Number(bn) === BLOCK_NUM) { captured.manifestHash = hash; captured.resultRegister = res; }
    return res;
  };

  // ---- 6b. 前ブロックアーティファクト（N>0: computeMajorLangs / prevAnchor の入力） ----
  if (sc.prevBlock) {
    const prevN = BLOCK_NUM - 1;
    if (sc.prevBlock.type === 'noGameSummary' || sc.prevBlock.type === 'summary') {
      // WR-3 (S45R-U-X17): 合成前ブロックの manifest も公開 selection の K11 確認深さから規則を作る。
      // 前ブロックの選出自体は検証しないため、合成登録高1と正典の確認深さを置く。
      await r2.put(`entries/block${prevN}/game_selection.json`, JSON.stringify({
        blockNum: prevN,
        hashRegisteredBlock: 1,
        confirmationBlocks: t.CONFIRMATION_BLOCKS,
        targetBlockNum: 1 + t.CONFIRMATION_BLOCKS,
      }));
    }
    if (sc.prevBlock.type === 'noGameSummary') {
      // 前ブロックがゲーム無し（応募0名）: 正典 `finalizeNoGameBlock`（game-master-DO.js:544-565）と
      // **同じ形**の summary.json ＋ 実 manifest アンカー。`noGame: true` を見て majorLangs=[] になる。
      await r2.put(`games/block${prevN}/summary.json`, JSON.stringify({
        blockNum: prevN,
        blockReward: getBlockRewardWei(prevN).toString(),
        totalPlayers: 0,
        totalGroups: 0,
        noGame: true,
        majorLangs: [],
        groups: [],
      }));
      // WR-5: 正典 finalizeNoGameBlock と同じく、manifest の前に空の必須 artifact を書く。
      await gm.publishEmptyEvidenceSegmentArtifact(prevN);
      const pv = await runCoordinatorBacked(
        `prev-block ${prevN} no-game manifest`,
        () => gm.publishVerificationManifest(prevN, []),
        (result) => result?.ok === true && result?.registered?.submitted === true,
      );
      if (!pv?.ok || !pv?.registered?.submitted) {
        throw new Error(`prev-block (no-game) manifest anchor failed: ${JSON.stringify(pv)}`);
      }
      console.log(`[gen:${sc.name}] prev block ${prevN} no-game summary anchored: ${pv.manifestHash}`);
    } else if (sc.prevBlock.type === 'selectionStub') {
      // 🔴 負のシナリオ専用（Q-5 以降）。summary.json を書かず game_selection.json だけ置く。
      //    正典はここで MAJOR_LANG_PREV_NOT_READY を投げる（フォールバック削除の実測用）。
      await r2.put(`entries/block${prevN}/game_selection.json`, JSON.stringify({
        blockNum: prevN, totalEntries: sc.prevBlock.players.length,
        totalSelected: sc.prevBlock.players.length, players: sc.prevBlock.players,
        createdAt: new Date().toISOString(),
      }));
    } else if (sc.prevBlock.type === 'summary') {
      // S12: 合成前 summary を書き、本物の publishVerificationManifest(prevN) で
      // sha256 を manifest 化 → HashStorage.registerResultHash(prevN) に実アンカー
      //（検証ツールの G7 prevAnchor が要求する公開整合を成立させる）。
      const prevSummary = buildSyntheticPrevSummary(prevN, sc.prevBlock.langs);
      const summaryKey = `games/block${prevN}/summary.json`;
      const summaryRaw = JSON.stringify(prevSummary);
      await r2.put(summaryKey, summaryRaw);
      // 合成前ブロックはmajorLangs分岐専用でD1/チャット成果物を持たない。
      // 現行manifest builderは通常ゲームの全pageを要求するため、summaryの実bytesだけを
      // 同じrules/core/hash/HashStorage経路で固定する最小manifestを作る。
      const prevFiles = { [summaryKey]: await gm.sha256Hex(summaryRaw) };
      const pv = await runCoordinatorBacked(
        `prev-block ${prevN} synthetic manifest`,
        () => gm.finalizeVerificationManifest(prevN, prevFiles),
        (result) => result?.ok === true && result?.registered?.submitted === true,
      );
      if (!pv?.ok || !pv?.registered?.submitted) {
        throw new Error(`prev-block manifest anchor failed: ${JSON.stringify(pv)}`);
      }
      console.log(`[gen:${sc.name}] prev block ${prevN} summary anchored: ${pv.manifestHash}`);
    }
  }

  // ---- 6c. グループ分け（0名/1〜2名/3名以上の3経路） ----
  const evidenceSeqs = {};
  const garbageSeqs = [];
  const meta = {
    name: sc.name,
    blockNum: BLOCK_NUM,
    totalPlayers: players.length,
    zeroPlayers: players.length === 0,
    autoDistributed: players.length > 0 && players.length <= 2,
    hasGame: players.length >= 3,
    expectedRegCount: sc.registerHashTwice ? 2 : 1,
    evidenceRescue: sc.evidenceRescue === true,
    rosterAnchorMode: sc.rosterAnchorMode || null,
    prevBlockType: sc.prevBlock?.type || null,
    coordinatorRecovery,
    evidence: null, // hasGame のとき後段で確定
  };

  // 0〜2名経路は startGrouping() の1呼出しで adminCommit まで完結させる
  // fixture なので、root 提出が許可される Evidence resultClose まで時刻を進める。
  // 本番ではスケジューラが同じ窓終了を待つ。3名以上は後段のゲーム進行で振り付ける。
  if (players.length <= 2) await setNextTimestamp(rpcUrl, D.resultClose);

  // 実chainのpending txを強制的に1回作り、Coordinator alarm -> receipt確認 ->
  // GameMaster grouping_watchdogの呼び出し側再開を通す。Service Binding側で待ち切って
  // submittedを偽造しない。後続操作もpendingになれば同じ実DO alarmを駆動する。
  const driveGroupingThroughCoordinator = async () => {
    const originalStartGrouping = gm.startGrouping.bind(gm);
    const groupingRuns = [];
    gm.startGrouping = async (...args) => {
      const result = await originalStartGrouping(...args);
      groupingRuns.push(result);
      return result;
    };
    let automineDisabled = false;
    const intentId = `anchorBlockHash:${targetBlockNum}`;
    try {
      await rpc(rpcUrl, 'evm_setAutomine', [false]);
      automineDisabled = true;
      const first = await gm.startGrouping(BLOCK_NUM);
      if (first?.success || first?.resumable !== true) {
        throw new Error(`expected resumable grouping pause on coordinator pending, got: ${JSON.stringify(first)}`);
      }
      const pending = await readCoordinatorIntent(intentId);
      if (pending.status !== 'in_flight' || pending.submitted !== false || !pending.txHash || pending.receipt !== null) {
        throw new Error(`coordinator did not durably expose pending intent: ${JSON.stringify(pending)}`);
      }
      coordinatorRecovery.pendingIntent = {
        intentId, status: pending.status, reason: pending.reason,
        txHash: pending.txHash, nonce: pending.nonce,
      };
      console.log(`[gen:${sc.name}] COORDINATOR_PENDING_PERSISTED intent=${intentId} status=${pending.status} reason=${pending.reason} tx=${pending.txHash}`);

      await mineOne(rpcUrl);
      await runCoordinatorAlarm();
      await pumpCoordinatorUntilIdle(`RANDAO ${intentId}`);
      const resumedIntent = await readCoordinatorIntent(intentId);
      if (resumedIntent.status !== 'succeeded' || resumedIntent.submitted !== true
          || !resumedIntent.txHash || resumedIntent.txHash !== pending.txHash) {
        throw new Error(`coordinator alarm did not reach a durable success: ${JSON.stringify(resumedIntent)}`);
      }
      // preflight.done は「既にchainへ反映済み」を検出すると already_anchored で成功し、
      // DO recordのreceiptをnullのまま終える正規経路がある。booleanだけへ弱めず、pending時に
      // 保存した同じ実txHashをRPCへ照会し、receipt成功とblockNumberを独立に要求する。
      const chainReceipt = await clients.publicClient.getTransactionReceipt({ hash: resumedIntent.txHash });
      if (chainReceipt.status !== 'success' || chainReceipt.blockNumber == null
          || chainReceipt.transactionHash.toLowerCase() !== resumedIntent.txHash.toLowerCase()) {
        throw new Error(`coordinator tx did not have a successful chain receipt: ${JSON.stringify({
          intent: resumedIntent,
          receipt: {
            status: chainReceipt.status,
            blockNumber: chainReceipt.blockNumber?.toString(),
            transactionHash: chainReceipt.transactionHash,
          },
        })}`);
      }
      if (resumedIntent.receipt && (resumedIntent.receipt.status !== 'success'
          || String(resumedIntent.receipt.blockNumber) !== String(chainReceipt.blockNumber))) {
        throw new Error(`coordinator receipt record disagrees with chain receipt: ${JSON.stringify({ intent: resumedIntent, chainBlock: chainReceipt.blockNumber.toString() })}`);
      }
      coordinatorRecovery.alarmResumed = true;
      coordinatorRecovery.receiptBlock = chainReceipt.blockNumber.toString();
      const anchoredBlockHash = await clients.publicClient.readContract({
        address: dep.evidence.address,
        abi: dep.evidence.abi,
        functionName: 'blockHashOf',
        args: [BigInt(targetBlockNum)],
      });
      if (String(anchoredBlockHash).toLowerCase() !== String(targetBlock.hash).toLowerCase()) {
        throw new Error(`RANDAO anchor mismatch after coordinator alarm: chain=${anchoredBlockHash} target=${targetBlock.hash}`);
      }
      console.log(`[gen:${sc.name}] COORDINATOR_ALARM_RESUMED intent=${intentId} status=${resumedIntent.status} reason=${resumedIntent.reason} receiptBlock=${chainReceipt.blockNumber}`);

      await rpc(rpcUrl, 'evm_setAutomine', [true]);
      automineDisabled = false;
      const callerDeadline = Date.now() + 30_000;
      for (;;) {
        const last = groupingRuns[groupingRuns.length - 1];
        if (last?.success) {
          coordinatorRecovery.callerResumed = true;
          console.log(`[gen:${sc.name}] GROUPING_CALLER_RESUMED block=${BLOCK_NUM} success=true runs=${groupingRuns.length}`);
          return last;
        }
        if (last && last.resumable !== true) {
          throw new Error(`grouping caller reached non-resumable failure: ${JSON.stringify(last)}`);
        }
        if (Date.now() >= callerDeadline) {
          throw new Error(`grouping caller resume deadline exceeded: ${JSON.stringify({
            grouping: await gm.storage.get(`grouping_block${BLOCK_NUM}_progress`),
            coordinator: await coordinatorTimeoutState(),
            queue: await gm.storage.get('phase_task_queue'),
          })}`);
        }
        await pumpCoordinatorUntilIdle('grouping caller resume', Math.max(1, callerDeadline - Date.now()));
        await waitForPhaseTask('grouping_watchdog', BLOCK_NUM, Math.max(1, callerDeadline - Date.now()));
        const runCount = groupingRuns.length;
        await gm.alarm();
        if (groupingRuns.length === runCount) {
          throw new Error(`grouping watchdog alarm did not invoke startGrouping: ${JSON.stringify({
            queue: await gm.storage.get('phase_task_queue'), active: await gm.storage.get('phase_task_active'),
          })}`);
        }
      }
    } finally {
      if (automineDisabled) await rpc(rpcUrl, 'evm_setAutomine', [true]).catch(() => {});
      gm.startGrouping = originalStartGrouping;
    }
  };

  const groupingResult = await driveGroupingThroughCoordinator();

  if (players.length === 0) {
    // S4(B4是正後・2026-07-16): 0名ブロックも「ゲーム無し」として確定する正典仕様。
    // startGrouping は noGame サマリーを公開し、空ツリーの標識ルート（empty-merkle sentinel）を
    // 提出して請求期間を開始→終了させる（＝ブロック報酬の永久凍結がオンチェーンで確定・
    // root未提出の「未確定」と判別可能）。検証ツールはStage Aで止まらず、Stage Cまで検証する。
    if (!groupingResult.success || groupingResult.noGame !== true) {
      throw new Error(`expected no-game finalization, got: ${JSON.stringify(groupingResult)}`);
    }
    if (!groupingResult.merkle?.ok || !groupingResult.merkle?.submit?.submitted) {
      throw new Error(`no-game sentinel merkle submit failed: ${JSON.stringify(groupingResult.merkle)}`);
    }
    if (!groupingResult.verification?.ok || !groupingResult.verification?.registered?.submitted) {
      throw new Error(`no-game manifest publish failed: ${JSON.stringify(groupingResult.verification)}`);
    }
    console.log(`[gen:${sc.name}] zero players: finalized as no-game (sentinel root submitted)`);
    const chainInfo = buildChainInfo();
    writeMetaFiles(chainInfo);
    return finish(chainInfo);
  }

  if (players.length <= 2) {
    // S3: autoDistribute（本番コード）が summary/merkle/manifest＋オンチェーン提出まで完結する
    if (!groupingResult.success || !groupingResult.autoDistributed) {
      throw new Error(`autoDistribute grouping failed: ${JSON.stringify(groupingResult)}`);
    }
    if (!groupingResult.merkle?.ok || !groupingResult.merkle?.submit?.submitted) {
      throw new Error(`autoDistribute merkle publish failed: ${JSON.stringify(groupingResult.merkle)}`);
    }
    if (!groupingResult.verification?.ok || !groupingResult.verification?.registered?.submitted) {
      throw new Error(`autoDistribute manifest publish failed: ${JSON.stringify(groupingResult.verification)}`);
    }
    console.log(`[gen:${sc.name}] auto-distributed: ${players.length} players, totalPoints=${groupingResult.totalPoints}`);
    const chainInfo = buildChainInfo();
    writeMetaFiles(chainInfo);
    return finish(chainInfo);
  }

  if (!groupingResult.success) throw new Error(`startGrouping failed: ${groupingResult.error}`);
  console.log(`[gen:${sc.name}] grouping: ${groupingResult.totalGroups} groups from ${groupingResult.totalPlayers} players`);

  // v3.2: 早着待機ガードは撤廃（waiting はカウントダウン表示のみ・initは即時実行される）
  if (groupingResult.chatInitResult?.deferred) {
    throw new Error('unexpected deferred chat init (v3.2 removed the early-arrival guard)');
  }
  // F-1: ライブ名簿をチャット開始前にアンカーするため、確認ブロック待ちで開始時刻を
  // 越えた場合は正典 worker が grace を延長する。以後のチェーン時刻振付は初期値 D ではなく、
  // 実際に延長された Evidence 窓を使う。
  const effectiveTimeline = await gm.readEvidenceTimelineSnapshot(BLOCK_NUM);
  let effectiveChattingStart = effectiveTimeline
    ? effectiveTimeline.chatCloseAt - t.GAME_PERIOD
    : D.chattingStart;
  let effectiveChatClose = effectiveTimeline?.chatCloseAt ?? D.chatClose;
  let effectiveResultClose = effectiveTimeline?.resultCloseAt ?? D.resultClose;

  // roster は本番と同じ phase task -> GameMasterDO.alarm 経路だけで処理する。
  // missing はbinding先アドレスを無効化した失敗、late は実行直前にchain時刻を窓後へ進める。
  await waitForPhaseTask('roster_anchor', BLOCK_NUM);
  if (sc.rosterAnchorMode === 'late') {
    const latest = await rpc(rpcUrl, 'eth_getBlockByNumber', ['latest', false]);
    const latestTimestamp = parseInt(latest.timestamp, 16);
    await setNextTimestamp(rpcUrl, Math.max(effectiveChattingStart, latestTimestamp + 1));
  }
  const rosterHashStorageAddress = gm.env.HASH_STORAGE_CONTRACT_ADDRESS;
  if (sc.rosterAnchorMode === 'missing') gm.env.HASH_STORAGE_CONTRACT_ADDRESS = '';
  try {
    await gm.alarm();
    if (sc.rosterAnchorMode === 'missing') {
      // 公開と全量再読は別 invocation。失敗注入は登録を試す後段にも掛ける。
      const pending = await gm.storage.get('phase_task_queue') || [];
      const retry = pending.find((task) => task.type === 'roster_anchor'
        && Number(task.blockNum) === BLOCK_NUM && task.anchorOnly === true);
      if (!retry) throw new Error(`missing roster scenario has no anchor-only task: ${JSON.stringify(pending)}`);
      await gm.storage.put('phase_task_queue', pending.map((task) =>
        task === retry ? { ...task, executeAt: 0 } : task).sort((a, b) => a.executeAt - b.executeAt));
      await gm.alarm();
    }
  } finally {
    gm.env.HASH_STORAGE_CONTRACT_ADDRESS = rosterHashStorageAddress;
  }
  // receipt の直後は確認深さが足りない。正典 GM の再判定タスクを、実チェーンを
  // CONFIRMATION_BLOCKS だけ進めながら駆動する。late は grace の着地もここで待つ。
  if (sc.rosterAnchorMode !== 'missing') {
    for (let attempt = 0; attempt < 6; attempt++) {
      const q = (await gm.storage.get('phase_task_queue')) || [];
      if (q.filter((task) => task.type === 'phase_transition' && Number(task.blockNum) === BLOCK_NUM).length === 3) break;
      const retry = q.find((task) => task.type === 'roster_anchor' && Number(task.blockNum) === BLOCK_NUM);
      if (!retry) throw new Error(`roster start gate has no retry: ${JSON.stringify(q)}`);
      await pumpCoordinatorUntilIdle('roster start gate');
      await mineMany(rpcUrl, t.CONFIRMATION_BLOCKS, 1);
      await gm.storage.put('phase_task_queue', q.map((task) =>
        task === retry ? { ...task, executeAt: 0 } : task).sort((a, b) => a.executeAt - b.executeAt));
      await gm.alarm();
    }
    const settled = await gm.readEvidenceTimelineSnapshot(BLOCK_NUM);
    effectiveChattingStart = settled.chatCloseAt - t.GAME_PERIOD;
    effectiveChatClose = settled.chatCloseAt;
    effectiveResultClose = settled.resultCloseAt;
    observedChatTimeline = {
      chattingStart: effectiveChattingStart, chatClose: effectiveChatClose,
      resultClose: effectiveResultClose,
    };
  }
  const rosterQueue = (await gm.storage.get('phase_task_queue')) || [];
  const rosterActive = await gm.storage.get('phase_task_active');
  if (rosterActive != null) {
    throw new Error(`roster alarm left active task behind: ${JSON.stringify(rosterActive)}`);
  }
  if (sc.rosterAnchorMode === 'missing') {
    if (!rosterQueue.some((task) => task.type === 'roster_anchor' && Number(task.blockNum) === BLOCK_NUM)) {
      throw new Error(`failed roster task was not durably retried: ${JSON.stringify(rosterQueue)}`);
    }
    if (await gm.storage.get(`roster_anchor_block${BLOCK_NUM}`)) {
      throw new Error('missing roster scenario recorded a false success marker');
    }
    if (!(await gm.storage.get(`roster_anchor_failed_block${BLOCK_NUM}`))) {
      throw new Error('missing roster scenario did not persist its failure marker');
    }
  } else {
    if (rosterQueue.some((task) => task.type === 'roster_anchor' && Number(task.blockNum) === BLOCK_NUM)) {
      throw new Error(`successful roster task was not removed: ${JSON.stringify(rosterQueue)}`);
    }
    if (!(await gm.storage.get(`roster_anchor_block${BLOCK_NUM}`))) {
      throw new Error('successful roster alarm did not persist its success marker');
    }
    if (rosterQueue.filter((task) => task.type === 'phase_transition' && Number(task.blockNum) === BLOCK_NUM).length !== 3) {
      throw new Error(`confirmed roster did not schedule chat: ${JSON.stringify(rosterQueue)}`);
    }
  }

  if (sc.rosterAnchorMode === 'mismatch') {
    // 「開始後」の上書きにする。契約の正典は開始前の最後の登録なので、
    // ここが開始前だと提出 proof が無効になる別の盤面を作ってしまう。
    const latest = await rpc(rpcUrl, 'eth_getBlockByNumber', ['latest', false]);
    await setNextTimestamp(rpcUrl, Math.max(effectiveChattingStart + 1, parseInt(latest.timestamp, 16) + 1));
    const key = keccak256(stringToHex(`bitcoinu:roster:${BLOCK_NUM}`));
    await write(clients, dep.hashStorage, 'setOtherHash', [key, `0x${'ab'.repeat(32)}`]);
  }

  // ---- 7. ゲーム進行（実プロトコルデータを本物の ChatGameDO WSハンドラへ注入） ----
  const groupRows = d1.__store.gameGroups
    .filter(r => r.block_num === BLOCK_NUM)
    .sort((a, b) => a.group_id - b.group_id)
    .map(r => ({ group_id: r.group_id, members: JSON.parse(r.members) }));
  let rosterCommitment = null;
  if (groupRows.length > 0) {
    const manifestText = await (await r2.get(`games/block${BLOCK_NUM}/roster/manifest.json`)).text();
    const manifest = JSON.parse(manifestText);
    const groupTexts = new Map();
    for (const group of manifest.groups) {
      groupTexts.set(group.groupId,
        await (await r2.get(`games/block${BLOCK_NUM}/roster/group${group.groupId}.json`)).text());
    }
    rosterCommitment = buildRosterMemberCommitment({ blockNum: BLOCK_NUM, manifestText, groupTexts });
  }
  const evidenceArgsFor = (address, bytes) => [BigInt(BLOCK_NUM), bytesToHex(bytes),
    rosterCommitment.manifestHash, createRosterMemberProof(rosterCommitment, address)];

  // グループ確定後の行動プラン（gamePlan があれば behavior を上書き）
  const plan = sc.gamePlan ? { ...beh, ...sc.gamePlan(groupRows, byUid) } : beh;

  const wsOf = (uid) => makeFakeWs(uid);
  const assertNoWsError = (ws, what) => {
    const err = ws.lastError();
    if (err) throw new Error(`${what}: WS error: ${err.message || JSON.stringify(err)}`);
  };

  // waiting → chatting（正典 advancePhase）
  const advChat = await gm.advancePhase(BLOCK_NUM, 'chatting');
  if (!advChat.success) throw new Error('advancePhase(chatting) failed');

  // --- 7a. チャット（既定 22ラウンド×各員 ~60字。宣言チャット窓内のタイムスタンプ） ---
  // v3.2 Evidenceチャット窓 = [entryEnd, entryEnd+GRACE+GAME_PERIOD]（= [base+600, base+900]）
  const rounds = plan.chatRounds ?? 22;   // minMessages=20 を全員が超える（20超×60字）
  const lowCharsSet = new Set(plan.lowChars || []);
  const lowTurnsSet = new Set(plan.lowTurns || []);
  const groupMsgsOf = {}; // group_id -> 正準形メッセージ配列（既読受領証明・提出物構築用）
  for (const g of groupRows) {
    const inst = chatNS.instance(`${BLOCK_NUM}-${g.group_id}`);
    const groupPlayers = g.members.map(m => byUid[m.uid]);
    const groupMsgs = (groupMsgsOf[g.group_id] = []);
    let ts = (sc.rosterAnchorMode === 'late' ? effectiveChattingStart + 40 : base + 640) * 1000
      + g.group_id * 30000;
    for (let round = 0; round < rounds; round++) {
      for (const p of groupPlayers) {
        if (lowTurnsSet.has(p.uid) && round >= 5) continue; // 5ターンのみ（min_messages 失格・文字数は十分）
        let text;
        if (lowCharsSet.has(p.uid)) {
          text = `r${round} c ${p.uid} `.padEnd(22, 'x');          // 22×22=484 < 500（min_chars・ターン数は20以上）
        } else if (lowTurnsSet.has(p.uid)) {
          text = `r${round} turns ${p.uid} `.padEnd(120, 'z');     // 5×120=600 ≥ 500
        } else {
          text = `round${round} hello from ${p.uid} `.padEnd(60, 'x');
        }
        const ws = wsOf(p.uid);
        const wsData = await makeChatWsData(p, BLOCK_NUM, g.group_id, text, ts);
        await inst.handleWsChat(ws, p.uid, wsData);
        assertNoWsError(ws, `chat ${p.uid} r${round}`);
        groupMsgs.push({
          type: 'chat', blockNum: BLOCK_NUM, groupId: g.group_id,
          uid: p.uid, text: wsData.text, timestamp: wsData.timestamp, signature: wsData.signature,
        });
        ts += 500;
      }
    }

    // --- 7b. 既読受領証明（v3.2 §6.7: 受領≥1で正典。既定=全ペアのバッチ受領証明） ---
    const noReadSet = new Set(plan.noReadReceiptsFor || []);
    let rts = (sc.rosterAnchorMode === 'late' ? effectiveChattingStart + 90 : base + 790) * 1000
      + g.group_id * 1000;
    for (const receiver of groupPlayers) {
      for (const sender of groupPlayers) {
        if (sender.uid === receiver.uid) continue;
        if (noReadSet.has(sender.uid)) continue; // sender のメッセージには誰も受領証明を出さない
        const rc = await makeReadReceipt(receiver, sender.uid, groupMsgs, BLOCK_NUM, g.group_id, rts++);
        if (!rc) continue;
        const ws = wsOf(receiver.uid);
        await inst.handleWsReceipt(ws, receiver.uid, { receipt: rc });
        assertNoWsError(ws, `read receipt ${receiver.uid}<-${sender.uid}`);
      }
    }

    // --- 7c. 投票（既定: member[i] → member[(i+2)%n]。votes 指定で self / null / 明示先）＋受領証明 ---
    const noVoteRcSet = new Set(plan.noVoteReceipt || []);
    const noReportRcSet = new Set(plan.noReportReceipt || []);
    let ats = (sc.rosterAnchorMode === 'late' ? effectiveChattingStart + 100 : base + 800) * 1000
      + g.group_id * 1000;
    const voteActionOf = {}; // voterUid -> action（受領証明・conflict用）
    for (let i = 0; i < groupPlayers.length; i++) {
      const voter = groupPlayers[i];
      let target;
      if (plan.votes && Object.prototype.hasOwnProperty.call(plan.votes, voter.uid)) {
        const v = plan.votes[voter.uid];
        if (v === null) continue;                    // 未投票（no_vote 失格）
        target = v === 'self' ? voter : byUid[v];    // 自己投票は calculator が no_vote 扱い
      } else {
        target = groupPlayers[(i + 2) % groupPlayers.length];
      }
      const ws = wsOf(voter.uid);
      const action = await makeActionWsData(voter, 'vote', { targetUid: target.uid }, BLOCK_NUM, g.group_id, ats++);
      await inst.handleWsVote(ws, voter.uid, action);
      assertNoWsError(ws, `vote ${voter.uid}`);
      voteActionOf[voter.uid] = action;
      if (!noVoteRcSet.has(voter.uid)) {
        const receiver = groupPlayers[(i + 1) % groupPlayers.length];
        const rc = await makeActionReceipt(receiver, voter.uid, 'vote', action, BLOCK_NUM, g.group_id, ats++);
        const rws = wsOf(receiver.uid);
        await inst.handleWsReceipt(rws, receiver.uid, { receipt: rc });
        assertNoWsError(rws, `vote receipt for ${voter.uid}`);
      }
    }
    // --- 7d. 密告（既定: n>=4 のとき members[0], members[2] が members[3] を密告）＋受領証明 ---
    const doReport = async (reporter, targetUid) => {
      const ws = wsOf(reporter.uid);
      const action = await makeActionWsData(reporter, 'report', { targetUid, reason: 'suspected_bot' }, BLOCK_NUM, g.group_id, ats++);
      await inst.handleWsReport(ws, reporter.uid, action);
      assertNoWsError(ws, `report ${reporter.uid}`);
      if (!noReportRcSet.has(reporter.uid)) {
        const idx = groupPlayers.findIndex(x => x.uid === reporter.uid);
        const receiver = groupPlayers[(idx + 1) % groupPlayers.length];
        const rc = await makeActionReceipt(receiver, reporter.uid, 'report', action, BLOCK_NUM, g.group_id, ats++);
        const rws = wsOf(receiver.uid);
        await inst.handleWsReceipt(rws, receiver.uid, { receipt: rc });
        assertNoWsError(rws, `report receipt for ${reporter.uid}`);
      }
    };
    if (plan.reports !== undefined) {
      const groupUidSet = new Set(g.members.map(m => m.uid));
      for (const [targetUid, reporterUids] of Object.entries(plan.reports)) {
        if (!groupUidSet.has(targetUid)) continue;
        for (const reporterUid of reporterUids) {
          await doReport(byUid[reporterUid], targetUid);
        }
      }
    } else if (groupPlayers.length >= 4) {
      for (const reporterIdx of [0, 2]) {
        await doReport(groupPlayers[reporterIdx], groupPlayers[3].uid);
      }
    }
    // conflictVote（検証⑥a）: 2票目はサーバーがone-shotで拒否するため、オフバンド発信
    // （P2Pリレー観測相当）として構築し、提出段で他メンバーの observed に混入する。
    // v3.3: 矛盾判定はリアルタイム受領済みの発信のみが材料 → 受領証明も発行しサーバーへ中継
    for (const cv of (plan.conflictVote || [])) {
      if (!g.members.some(m => m.uid === cv.uid)) continue;
      const voter = byUid[cv.uid];
      const action = await makeActionWsData(voter, 'vote', { targetUid: cv.target }, BLOCK_NUM, g.group_id, ats++);
      (plan.__conflictActions ||= {})[cv.uid] = action;
      const idx = groupPlayers.findIndex(x => x.uid === voter.uid);
      const receiver = groupPlayers[(idx + 1) % groupPlayers.length];
      const rc = await makeActionReceipt(receiver, voter.uid, 'vote', action, BLOCK_NUM, g.group_id, ats++);
      const rws = wsOf(receiver.uid);
      await inst.handleWsReceipt(rws, receiver.uid, { receipt: rc });
      assertNoWsError(rws, `conflict-vote receipt for ${voter.uid}`);
    }
  }

  // chatting → submitting
  const advSub = await gm.advancePhase(BLOCK_NUM, 'submitting');
  if (!advSub.success) throw new Error('advancePhase(submitting) failed');

  // ---- 8. 提出（SubmissionPhase と同一構築の正規バンドル。WS /submit 経由） ----
  // payload は全員分を構築（Evidence チェーン提出に使うため）。WS提出は noSubmit を除く。
  const noSubmitSet = new Set(plan.noSubmit || []);
  const withdrawVoteSet = new Set(plan.withdrawVote || []);
  const withdrawReportSet = new Set(plan.withdrawReport || []);
  const dropOwnMessages = plan.dropOwnMessages || {};
  const conflictActions = plan.__conflictActions || {};
  const payloads = {}; // uid -> payload string（Evidence 提出・検証用）
  let subK = 0;
  for (const g of groupRows) {
    const inst = chatNS.instance(`${BLOCK_NUM}-${g.group_id}`);
    const serverMessages = await inst.loadMessages(); // Z2: 分割キー対応の読み出し（本番と同一メソッド）
    const receipts = await inst.loadReceipts();       // サーバー観測受領証明（WS配布と同一集合）
    // サーバー保存の votes/reports（WSブロードキャスト action_made の観測と同一内容）
    const serverVotes = {};
    const serverReports = {};
    for (const m of g.members) {
      const v = await inst.storage.get(`votes:${m.uid}`);
      if (v) serverVotes[m.uid] = v;
      const rep = await inst.storage.get(`reports:${m.uid}`);
      if (Array.isArray(rep) && rep.length > 0) serverReports[m.uid] = rep;
    }
    for (const m of g.members) {
      const p = byUid[m.uid];
      // このプレイヤー視点の観測ビュー（withdraw = 自分の発信を自分の提出から外す。
      // 他メンバーの観測には残る＝検証⑥bの不正証拠が成立する）
      const myVotes = { ...serverVotes };
      const myReports = { ...serverReports };
      if (withdrawVoteSet.has(p.uid)) delete myVotes[p.uid];
      if (withdrawReportSet.has(p.uid)) delete myReports[p.uid];
      // conflictVote: 他メンバーの観測にのみ2票目を混入（本人の提出物は1票目のまま）
      for (const [cvUid, action] of Object.entries(conflictActions)) {
        if (cvUid === p.uid || !myVotes[cvUid]) continue;
        myVotes[cvUid] = [myVotes[cvUid], action];
      }
      // dropOwnMessages: 自分の提出物から自分の末尾Nメッセージを削除（chatHashは自己整合を保つ）
      let myMessages = serverMessages;
      const dropN = Number(dropOwnMessages[p.uid] || 0);
      if (dropN > 0) {
        const ownIdx = [];
        serverMessages.forEach((msg, i) => { if (msg.uid === p.uid) ownIdx.push(i); });
        const dropSet = new Set(ownIdx.slice(-dropN));
        myMessages = serverMessages.filter((_, i) => !dropSet.has(i));
      }
      const depositIds = JSON.parse(p.depIds).ids;
      const { payload } = await buildSubmissionPayload(p, {
        blockNum: BLOCK_NUM, groupId: g.group_id,
        serverMessages: myMessages, serverVotes: myVotes, serverReports: myReports, receipts,
        submittedAt: (sc.rosterAnchorMode === 'late' ? effectiveChatClose + 70 : base + 970) * 1000
          + subK++, depositIds,
        memberUids: g.members.map((m) => m.uid),
      });
      payloads[p.uid] = payload;
      if (noSubmitSet.has(p.uid)) continue;
      const ws = wsOf(p.uid);
      await inst.handleWsSubmit(ws, p.uid, { payload });
      assertNoWsError(ws, `submit ${p.uid}`);
      if (!ws.sent.some(x => x.type === 'submit_ack')) throw new Error(`submit ${p.uid}: no ack`);
    }
  }

  // ---- 9. Evidence オンチェーン提出（結果提出窓内）＋検閲/改ざんケースの仕込み ----
  // 既定（evidence 未指定）: 従来どおり identical=g0.m0 / censored=g0.m1（サーバー削除） /
  // tampered=g1.m0 or g0.m2（サーバー改変）の3件提出。
  let evPlan;
  if (plan.evidence !== undefined) {
    evPlan = {
      chain: plan.evidence.chain || [],
      censorServer: plan.evidence.censorServer || [],
      tamperServer: plan.evidence.tamperServer || [],
      garbage: garbageCount, // 資金供給済みの静的宣言（behavior.evidence.garbage）が正
    };
  } else {
    const g0 = groupRows[0];
    const g1 = groupRows[1] || groupRows[0];
    const identicalUid = g0.members[0].uid;
    const censoredUid = g0.members[1].uid;
    const tamperedUid = (g1 === g0 ? g0.members[2] : g1.members[0]).uid;
    evPlan = { chain: [identicalUid, censoredUid, tamperedUid], censorServer: [censoredUid], tamperServer: [tamperedUid], garbage: 0 };
  }
  if (sc.rosterAnchorMode === 'missing') {
    // 開始前の登録が無いと契約は所属 proof を受け付けない。
    // サーバーへの WS 提出は残し、R33-U-B1D01 の全員0点を検査する。
    evPlan = { chain: [], censorServer: [], tamperServer: [], garbage: 0 };
  }

  let seq = 0;
  if (evPlan.chain.length > 0 || evPlan.garbage > 0) {
    await setNextTimestamp(rpcUrl, effectiveChatClose + 15); // resultWindow = [chatClose, chatClose+TERM3)
    for (const uid of evPlan.chain) {
      const evClient = makeClients(rpcUrl, byUid[uid].walletKey);
      const bytes = await evidenceBytesFor(payloads[uid]);
      if (bytes.length < 256) throw new Error(`evidence bytes for ${uid} below MIN_DATA_BYTES`);
      await write(evClient, dep.evidence, 'submitResult', evidenceArgsFor(byUid[uid].addr, bytes));
      evidenceSeqs[uid] = ++seq;
    }
    // 無効イベント（S13: decode 不能な生バイト → invalid 分類）
    for (let k = 0; k < evPlan.garbage; k++) {
      const junk = new Uint8Array(300).fill(0x78); // 'x' ×300（>=256・非gzip・非JSON）
      const invalidSender = byUid[groupRows[0].members[k % groupRows[0].members.length].uid];
      const invalidClient = makeClients(rpcUrl, invalidSender.walletKey);
      await write(invalidClient, dep.evidence, 'submitResult', evidenceArgsFor(invalidSender.addr, junk));
      garbageSeqs.push(++seq);
    }
  }

  // 検閲: 提出をサーバーから丸ごと削除（no_submit を誘発する握り潰し。チェーン版が復元されるべき）
  // Z2: 分割チャンクも含めて完全削除する本番同一メソッドを使用
  for (const uid of evPlan.censorServer) {
    const g = groupRows.find(x => x.members.some(m => m.uid === uid));
    const inst = chatNS.instance(`${BLOCK_NUM}-${g.group_id}`);
    await inst.deleteSubmissionKeys(uid);
  }
  // 改ざん: サーバー保存 raw を1フィールドだけ書き換え（バイト不一致 → チェーン版が勝つ）
  // Z2: 分割対応の読み書きヘルパー経由（小さいデータは従来と同一の単一キー形状になる）
  for (const uid of evPlan.tamperServer) {
    const gT = groupRows.find(g => g.members.some(m => m.uid === uid));
    const inst = chatNS.instance(`${BLOCK_NUM}-${gT.group_id}`);
    const raw = await inst.loadSubmissionRaw(uid);
    const parsed = decodeSubmissionPayloadString(raw).bundle;
    parsed.submittedAt = parsed.submittedAt + 1; // 署名不整合になるが「サーバーが差し替えた」状況の再現
    const newRaw = compactBytesToPayload(encodeEvidenceCompactV1(parsed, {
      blockNum: BLOCK_NUM,
      groupId: gT.group_id,
      memberUids: gT.members.map((m) => m.uid),
    }));
    await inst.storeSubmissionRaw(uid, newRaw);
    await inst.storeSubmissionBundle(uid, parsed);
  }

  meta.evidence = {
    resultCount: evPlan.chain.length + evPlan.garbage,
    identical: evPlan.chain.filter(u => !evPlan.censorServer.includes(u) && !evPlan.tamperServer.includes(u) && !noSubmitSet.has(u)),
    missing: evPlan.chain.filter(u => evPlan.censorServer.includes(u) || noSubmitSet.has(u)),
    mismatch: evPlan.chain.filter(u => evPlan.tamperServer.includes(u)),
    invalidCount: evPlan.garbage,
  };

  // ---- 10. 窓クローズ＋confirmations 経過を採掘 → completed（アーカイブ）→ 本番結果集計 ----
  await setNextTimestamp(rpcUrl, effectiveResultClose + 1);
  await mineOne(rpcUrl);
  await mineMany(rpcUrl, t.CONFIRMATION_BLOCKS + 8, 1); // safeBlock(=latest-64) が閉窓後になる余裕

  // completed 遷移（各DOが games/blockN/group{G}.json をアーカイブ）。
  // advancePhase('completed') は内部で結果集計を try/catch で飲み込むため、
  // 集計は一旦スタブして遷移だけ行い、直後に本物を呼んで失敗を顕在化させる。
  const realCalc = gm.calculateAndStoreResults.bind(gm);
  gm.calculateAndStoreResults = async () => ({ deferred: true });
  const advDone = await gm.advancePhase(BLOCK_NUM, 'completed');
  if (!advDone.success) throw new Error('advancePhase(completed) failed');
  gm.calculateAndStoreResults = realCalc;

  // V25-03: ChatGameDOが未初期化／消失した状態でも、正式Evidenceが1件以上あれば
  // committed grouping（R2 game_groups + D1 roster）から全グループを復元し、通常採点へ進む。
  // completedまでは本物のゲームを走らせて正式compact Evidenceを作り、その直後に
  // DO storage・既存group archive・roster index cacheを消すことで本番障害境界を再現する。
  // roster/group は開始前に C へ固定された公開物であり、検証時の実バイトを残す。
  if (sc.evidenceRescue === true) {
    if (evPlan.chain.length === 0) {
      throw new Error('evidenceRescue scenario requires at least one formal Evidence submission');
    }
    for (const g of groupRows) {
      const inst = chatNS.instance(`${BLOCK_NUM}-${g.group_id}`);
      await inst.storage.deleteAll();
      rmSync(join(r2Dir, `games/block${BLOCK_NUM}/group${g.group_id}.json`), { force: true });
    }
    rmSync(join(r2Dir, `games/block${BLOCK_NUM}/roster/index.json`), { force: true });
    console.log(`[gen:${sc.name}] V25-03 fault injected: ChatGameDO state/group archives/roster index cache removed`);
  }

  let calcResult = await realCalc(BLOCK_NUM);
  // A1: チャンク実行モード（sc.gmEnv で GAME_CALC_UNITS_PER_DRIVE 等を注入した場合）は
  // alarm駆動で完走させる。既定envでは1回のdriveで同期完了する（pendingにならない）ため0周。
  // sc.calcTaskLossAt を指定すると、その周回でcalc_chunkタスクをキューから削除し
  // 「実行前dequeue＋runtime killでのタスク喪失」→ alarmの自己復旧(resurrection)経路を検証する。
  let lossInjected = false;
  for (let guard = 0; calcResult?.pending; guard++) {
    if (guard > 2000) throw new Error('calc pump exceeded 2000 iterations (pipeline stuck?)');
    let injectedThisIter = false;
    if (sc.calcTaskLossAt != null && guard === sc.calcTaskLossAt && !lossInjected) {
      const q = await gm.storage.get('phase_task_queue') || [];
      await gm.storage.put('phase_task_queue', q.filter(t => t.type !== 'calc_chunk'));
      lossInjected = true;
      injectedThisIter = true;
    }
    // Coordinatorへ渡したchain書込がpendingなら、実DOのalarmでreceiptまで進める。
    // calcの再試行時刻も実progressに従い、固定sleepや未実行の成功扱いはしない。
    await pumpCoordinatorUntilIdle(`calc block ${BLOCK_NUM}`, 5000);
    const calcProgress = await gm.storage.get(`calc_block${BLOCK_NUM}_progress`);
    if (Number(calcProgress?.waitUntil) > Date.now()) {
      await waitUntil(
        Number(calcProgress.waitUntil),
        `calc block ${BLOCK_NUM} waitUntil`,
        20_000,
        async () => ({
          progress: await gm.storage.get(`calc_block${BLOCK_NUM}_progress`),
          coordinator: await coordinatorTimeoutState(),
          queue: await gm.storage.get('phase_task_queue'),
        }),
      );
    }
    await gm.alarm();
    if (injectedThisIter) {
      const prog2 = await gm.storage.get(`calc_block${BLOCK_NUM}_progress`);
      const q2 = await gm.storage.get('phase_task_queue') || [];
      if (prog2?.stage !== 'done' && !q2.some(t => t.type === 'calc_chunk')) {
        throw new Error('calc resurrection did not re-enqueue after task loss');
      }
      console.log(`[gen:${sc.name}] calc task loss injected at pump#${guard} — resurrection verified`);
    }
    calcResult = await realCalc(BLOCK_NUM);
  }
  if (!calcResult.success) throw new Error('calculateAndStoreResults failed');
  if (!calcResult.merkle?.ok) throw new Error(`merkle publish failed: ${JSON.stringify(calcResult.merkle)}`);
  if (!calcResult.merkle?.submit?.submitted) throw new Error(`submitMerkleRoot not submitted: ${JSON.stringify(calcResult.merkle?.submit)}`);
  if (!calcResult.verification?.ok) throw new Error(`manifest publish failed: ${JSON.stringify(calcResult.verification)}`);
  if (!calcResult.verification?.registered?.submitted) throw new Error(`registerResultHash not submitted: ${JSON.stringify(calcResult.verification?.registered)}`);
  console.log(`[gen:${sc.name}] results calculated: groups =`, calcResult.groupCount, 'totalPoints =', calcResult.totalPoints);
  console.log(`[gen:${sc.name}] merkle root =`, captured.merkleRoot);
  console.log(`[gen:${sc.name}] manifest hash =`, captured.manifestHash);

  {
    const chainInfo = buildChainInfo(groupRows);
    writeMetaFiles(chainInfo);
    return finish(chainInfo, payloads);
  }

  // ---------------- 内部ヘルパー ----------------
  function buildChainInfo(rows = []) {
    // 従来互換のトップレベル形状（e2e / mutations が参照）＋ meta（シナリオ期待値）
    const evidence = meta.hasGame && meta.evidence
      ? {
        identicalUid: meta.evidence.identical[0] ?? null,
        censoredUid: meta.evidence.missing[0] ?? null,
        tamperedUid: meta.evidence.mismatch[0] ?? null,
        seqs: evidenceSeqs ?? {},
        garbageSeqs: garbageSeqs ?? [],
      }
      : null;
    return {
      chainId: CHAIN_ID,
      rpcUrl,
      port: nodeHandle.port,
      blockNum: BLOCK_NUM,
      timing: { ...t, ...D, ...(observedChatTimeline || {}) },
      contracts,
      admin: clients.account.address,
      applicantHash,
      hashRegisteredBlock,
      targetBlockNum,
      randao,
      merkleRoot: captured.merkleRoot,
      manifestHash: captured.manifestHash,
      evidence,
      groups: rows.map(g => ({ groupId: g.group_id, memberUids: g.members.map(m => m.uid) })),
      // 秘密鍵は呼び出し側の権限付き台帳だけに保持する。chain-info は公開情報のみ。
      players: players.map(p => ({ uid: p.uid, lang: p.lang, addr: p.addr, blockAddress: p.bAddrObj.address })),
      meta,
    };
  }

  function writeMetaFiles(chainInfo) {
    writeFileSync(join(outDir, 'chain-info.json'), JSON.stringify(chainInfo, null, 2));
    // 検証ツール --config 用の雛形（r2Base/dataDir は e2e / simulation が実ポートで上書きする）
    writeFileSync(join(outDir, 'verifier-config.json'), JSON.stringify({
      chainIdExpected: CHAIN_ID,
      rpcUrls: [rpcUrl],
      r2Base: 'http://127.0.0.1:8788',
      dataDir: join(outDir, 'verifier-data'),
      contracts: {
        hashStorage: contracts.hashStorage,
        tokenMining: contracts.tokenMining,
        evidence: contracts.evidence,
        ethLock: contracts.ethLock,
        ethStake: contracts.ethStake,
      },
    }, null, 2));
  }

  function finish(chainInfo, pl = {}) {
    return {
      chainInfo, r2Dir, outDir, payloads: pl,
      node: nodeHandle,
      stop: () => { if (ownNode) nodeHandle.stop(); },
    };
  }
}

// ---------------- 内部整合性検証（生成物とチェーンの独立照合） ----------------
// gen-fixture 自身の中間値を使わず、ディスク上のバイト列とチェーン読取だけで検算する。
// 期待値は chainInfo.meta（シナリオ由来）で分岐する（0名 / autoDistribute / 全員失格 / 再登録等）。
export async function verifyFixtureInternalConsistency({ r2Dir, chainInfo }) {
  const failures = [];
  const ok = (cond, label) => {
    console.log(`  ${cond ? 'ok' : 'NG'}: ${label}`);
    if (!cond) failures.push(label);
  };
  const readText = (key) => readFileSync(join(r2Dir, key), 'utf8');
  const readJson = (key) => JSON.parse(readText(key));
  const hasFile = (key) => existsSync(join(r2Dir, key));
  const { publicClient } = makeClients(chainInfo.rpcUrl);
  const N = chainInfo.blockNum;
  const meta = chainInfo.meta || {
    totalPlayers: 8, zeroPlayers: false, autoDistributed: false, hasGame: true, expectedRegCount: 1,
    evidence: {
      resultCount: 3,
      identical: [chainInfo.evidence.identicalUid],
      missing: [chainInfo.evidence.censoredUid],
      mismatch: [chainInfo.evidence.tamperedUid],
      invalidCount: 0,
    },
  };

  const HS_ABI = [
    { name: 'getApplicantHash', type: 'function', stateMutability: 'view', inputs: [{ name: 'blockNumber', type: 'uint256' }], outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }] },
    { name: 'registrationCount', type: 'function', stateMutability: 'view', inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] },
    { name: 'applicantRegistrationAt', type: 'function', stateMutability: 'view', inputs: [{ name: 'blockNumber', type: 'uint256' }, { name: 'index', type: 'uint256' }], outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'registeredBlock', type: 'uint256' }, { name: 'signer', type: 'address' }] },
    { name: 'isApplicantRegistered', type: 'function', stateMutability: 'view', inputs: [{ name: 'blockNumber', type: 'uint256' }, { name: 'registeredBlock', type: 'uint256' }, { name: 'hash', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
    { name: 'resultHashes', type: 'function', stateMutability: 'view', inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }] },
    { name: 'resultRegistrationCount', type: 'function', stateMutability: 'view', inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] },
    { name: 'getOtherHash', type: 'function', stateMutability: 'view', inputs: [{ name: 'key', type: 'bytes32' }], outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }] },
  ];
  const TM_ABI = [
    { name: 'blockStates', type: 'function', stateMutability: 'view', inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: 'merkleRoot', type: 'bytes32' }, { name: 'verificationStartedAt', type: 'uint64' }] },
  ];
  const EVIDENCE_ANCHOR_ABI = [
    { name: 'blockHashOf', type: 'function', stateMutability: 'view', inputs: [{ name: 'ethBlockNumber', type: 'uint256' }], outputs: [{ name: '', type: 'bytes32' }] },
  ];

  // 1) applicantHash 連鎖の再計算（ディスクのバイト列から独立にやり直す）
  console.log('[verify] applicantHash chain');
  const hashItems = [];
  for (let i = 0; i < 100; i++) {
    const ww = String(i).padStart(2, '0');
    const hashFileText = readText(`entries/block${N}/hash/${ww}_hash.json`);
    const hashFile = JSON.parse(hashFileText);
    ok(hashFile.status === 'success', `hash file ${ww} status success`);
    for (const e of hashFile.entries) {
      const fileParsed = JSON.parse(readText(`entries/block${N}/entries/${e.filename}.json`));
      const recomputed = sha256Hex(JSON.stringify(fileParsed));
      ok(recomputed === e.hash, `level-1 hash of ${e.filename}`);
    }
    hashItems.push({ filename: `${ww}_hash`, hash: sha256Hex(JSON.stringify(hashFile)) });
  }
  hashItems.sort((a, b) => a.filename.localeCompare(b.filename));
  const intermediateObj = { block_num: N, status: 'success', hash: hashItems };
  ok(JSON.stringify(intermediateObj) === readText(`entries/block${N}/intermediate_hash.json`),
    'intermediate_hash.json byte-equal to independent rebuild');
  const root = '0x' + sha256Hex(JSON.stringify(intermediateObj));

  const regCount = await publicClient.readContract({
    address: chainInfo.contracts.hashStorage, abi: HS_ABI, functionName: 'registrationCount', args: [BigInt(N)],
  });
  ok(Number(regCount) === meta.expectedRegCount, `registrationCount == ${meta.expectedRegCount}`);
  let firstRootRegistration = null;
  let firstEligibleRootRegistration = null;
  for (let index = 0; index < Number(regCount); index++) {
    const [registeredHash, registeredBlock] = await publicClient.readContract({
      address: chainInfo.contracts.hashStorage,
      abi: HS_ABI,
      functionName: 'applicantRegistrationAt',
      args: [BigInt(N), BigInt(index)],
    });
    if (registeredHash.toLowerCase() !== root.toLowerCase()) continue;
    const block = await publicClient.getBlock({ blockNumber: registeredBlock });
    const registeredTimeMs = Number(block.timestamp) * 1000;
    if (firstRootRegistration === null) firstRootRegistration = { registeredBlock, registeredTimeMs };
    if (firstEligibleRootRegistration === null
        && registeredTimeMs >= chainInfo.timing.entryEnd * 1000) {
      firstEligibleRootRegistration = { registeredBlock, registeredTimeMs };
    }
  }
  ok(firstEligibleRootRegistration !== null, `recomputed root has an eligible on-chain registration (${root})`);
  ok(firstRootRegistration?.registeredTimeMs >= chainInfo.timing.entryEnd * 1000,
    'early-freeze: first root registration ts >= entryPeriodEnd');

  // 2) game_selection.json の整合
  console.log('[verify] game_selection');
  const sel = readJson(`entries/block${N}/game_selection.json`);
  ok(sel.applicantHash === root, 'selection.applicantHash == recomputed root');
  ok(sel.hashRegisteredBlock === Number(firstEligibleRootRegistration?.registeredBlock),
    'selection.hashRegisteredBlock == first eligible root registration');
  const selectionRegistered = await publicClient.readContract({
    address: chainInfo.contracts.hashStorage,
    abi: HS_ABI,
    functionName: 'isApplicantRegistered',
    args: [BigInt(N), BigInt(sel.hashRegisteredBlock), sel.applicantHash],
  });
  ok(selectionRegistered === true, 'selection registration is present in HashStorage history');
  ok(sel.targetBlockNum === sel.hashRegisteredBlock + sel.confirmationBlocks, 'targetBlockNum == reg + confirmations');
  const tb = await rpc(chainInfo.rpcUrl, 'eth_getBlockByNumber', ['0x' + sel.targetBlockNum.toString(16), false]);
  ok(tb.mixHash === sel.randao, 'selection.randao == chain mixHash(targetBlockNum)');
  ok(tb.hash === sel.targetBlockHash, 'selection.targetBlockHash == chain block hash');
  const anchoredRandaoBlockHash = await publicClient.readContract({
    address: chainInfo.contracts.evidence,
    abi: EVIDENCE_ANCHOR_ABI,
    functionName: 'blockHashOf',
    args: [BigInt(sel.targetBlockNum)],
  });
  ok(anchoredRandaoBlockHash.toLowerCase() === tb.hash.toLowerCase(),
    'Evidence.blockHashOf(targetBlockNum) == actual target block hash');
  if (meta.coordinatorRecovery) {
    ok(meta.coordinatorRecovery.mode === 'alarm', 'coordinator recovery used alarm mode');
    ok(meta.coordinatorRecovery.pendingIntent?.status === 'in_flight'
      && meta.coordinatorRecovery.pendingIntent?.txHash,
    'coordinator persisted an in-flight intent before receipt');
    ok(meta.coordinatorRecovery.alarmResumed === true && meta.coordinatorRecovery.receiptBlock != null,
      'coordinator alarm observed a successful real-chain receipt');
    ok(meta.coordinatorRecovery.callerResumed === true,
      'grouping watchdog resumed the paused caller');
  }
  ok(sel.totalEntries === meta.totalPlayers && sel.totalSelected === meta.totalPlayers,
    `all ${meta.totalPlayers} entries selected (all-win shortcut)`);

  // N>0: 前ブロックmanifestは公開された正確なbytesからcore hashを再構成し、
  // HashStorage.resultHashes(N-1)と一致することを確認する。
  if (N > 0 && meta.prevBlockType !== 'selectionStub') {
    const prevManifestKey = `verification/block${N - 1}/manifest.json`;
    ok(hasFile(prevManifestKey), `previous block ${N - 1} manifest is publicly readable`);
    if (hasFile(prevManifestKey)) {
      const prevManifest = readJson(prevManifestKey);
      const prevCore = {
        blockNum: prevManifest.blockNum,
        algorithm: prevManifest.algorithm,
        rules: prevManifest.rules,
        files: prevManifest.files,
      };
      const prevCoreHash = `0x${sha256Hex(JSON.stringify(prevCore))}`;
      ok(prevCoreHash.toLowerCase() === String(prevManifest.manifestHash).toLowerCase(),
        'previous manifestHash == sha256(previous public core bytes)');
      const [prevChainHash, prevUpdated] = await publicClient.readContract({
        address: chainInfo.contracts.hashStorage,
        abi: HS_ABI,
        functionName: 'resultHashes',
        args: [BigInt(N - 1)],
      });
      ok(Number(prevUpdated) !== 0 && prevChainHash.toLowerCase() === prevCoreHash.toLowerCase(),
        'previous public manifest bytes == previous on-chain result hash');
    }
  }

  // 0名（S4・B4是正後 2026-07-16）: 「ゲーム無し」も確定させるのが正典 —
  // noGameサマリー・空ツリー標識ルート（オンチェーン提出済み＝請求期間が開始→終了し
  // ブロック報酬の永久凍結が確定）・manifest が「存在する」ことを検証する。
  // （旧仕様は何も生成せずfailed終了＝summary恒久欠落＋凍結未確定の穴だった）
  if (meta.zeroPlayers) {
    ok(!hasFile(`entries/block${N}/game_groups.json`), 'zero players: no game_groups.json');
    const zsum = readJson(`games/block${N}/summary.json`);
    ok(zsum.noGame === true && zsum.totalPlayers === 0 && Array.isArray(zsum.groups) && zsum.groups.length === 0,
      'zero players: noGame summary published');
    ok(typeof zsum.blockReward === 'string' && BigInt(zsum.blockReward) > 0n,
      'zero players: summary carries blockReward (frozen amount)');
    const zmerkle = readJson(`merkle/block_${N}.json`);
    ok(zmerkle.leafCount === 0 && zmerkle.root.toLowerCase() === emptyMerkleSentinel(N).toLowerCase(),
      'zero players: empty-tree sentinel root published');
    const zstate = await publicClient.readContract({
      address: chainInfo.contracts.tokenMining, abi: TM_ABI, functionName: 'blockStates', args: [BigInt(N)],
    });
    const zchainRoot = Array.isArray(zstate) ? zstate[0] : zstate.merkleRoot;
    ok(zchainRoot.toLowerCase() === zmerkle.root.toLowerCase(),
      'zero players: sentinel root on-chain (claim period started => freeze will finalize)');
    const zmanifest = readJson(`verification/block${N}/manifest.json`);
    ok(typeof zmanifest.manifestHash === 'string' && zmanifest.manifestHash.startsWith('0x'),
      'zero players: verification manifest published');
    return { failures, passed: failures.length === 0 };
  }

  // 3) game_groups.json の groupSeed 再導出（autoDistribute はグループ分け無し）
  if (!meta.autoDistributed) {
    const gg = readJson(`entries/block${N}/game_groups.json`);
    const expectedSeed = keccak256(concatHex([sel.randao, sel.applicantHash, stringToHex('group')]));
    ok(gg.groupSeed === expectedSeed, 'game_groups.groupSeed == keccak256(randao‖applicantHash‖"group")');
  } else {
    ok(!hasFile(`entries/block${N}/game_groups.json`), 'autoDistribute: no game_groups.json');
  }

  // 通常ゲーム: roster manifest の公開bytesそのものをotherHashesへ結び付け、
  // missing/mismatch/lateの負シナリオも実chain状態で判別する。
  if (meta.hasGame) {
    const rosterKey = `games/block${N}/roster/manifest.json`;
    ok(hasFile(rosterKey), 'live roster manifest is publicly readable');
    if (hasFile(rosterKey)) {
      const rosterRaw = readText(rosterKey);
      const roster = JSON.parse(rosterRaw);
      ok(JSON.stringify(roster) === rosterRaw, 'live roster manifest uses minified canonical JSON bytes');
      const groupTexts = new Map();
      for (const group of roster.groups) {
        groupTexts.set(group.groupId, readText(`games/block${N}/roster/group${group.groupId}.json`));
      }
      const expectedRosterHash = buildRosterMemberCommitment({
        blockNum: N, manifestText: rosterRaw, groupTexts,
      }).C;
      const [chainRosterHash, chainRosterUpdated] = await publicClient.readContract({
        address: chainInfo.contracts.hashStorage,
        abi: HS_ABI,
        functionName: 'getOtherHash',
        args: [keccak256(stringToHex(`bitcoinu:roster:${N}`))],
      });
      if (meta.rosterAnchorMode === 'missing') {
        ok(Number(chainRosterUpdated) === 0, 'missing roster scenario remains unregistered on chain');
      } else if (meta.rosterAnchorMode === 'mismatch') {
        ok(Number(chainRosterUpdated) !== 0 && chainRosterHash.toLowerCase() !== expectedRosterHash.toLowerCase(),
          'mismatch roster scenario differs from recomputed C on chain');
        if (Number(chainRosterUpdated) !== 0) {
          const overwriteBlock = await publicClient.getBlock({ blockNumber: chainRosterUpdated });
          ok(Number(overwriteBlock.timestamp) >= Number(chainInfo.timing.chattingStart),
            'mismatch roster overwrite happened after the canonical start boundary');
        }
      } else {
        ok(Number(chainRosterUpdated) !== 0 && chainRosterHash.toLowerCase() === expectedRosterHash.toLowerCase(),
          'public roster C == on-chain roster hash');
        if (Number(chainRosterUpdated) !== 0) {
          const rosterBlock = await publicClient.getBlock({ blockNumber: chainRosterUpdated });
          const chattingStartMs = Number(chainInfo.timing.chattingStart) * 1000;
          if (meta.rosterAnchorMode === 'late') {
            const originalStart = timingDerived(chainInfo.timing, N).chattingStart;
            ok(Number(rosterBlock.timestamp) >= originalStart
                && Number(rosterBlock.timestamp) * 1000 < chattingStartMs,
              'late roster was after original start but before extended chattingStart');
          } else {
            ok(Number(rosterBlock.timestamp) * 1000 < chattingStartMs,
              'normal roster was anchored before chattingStart');
          }
        }
      }
    }
  }

  // 4) manifest: core ハッシュ == チェーン resultHashes、files == ディスクの sha256（null=未公開はスキップ）
  console.log('[verify] manifest / merkle / evidence');
  const manifest = readJson(`verification/block${N}/manifest.json`);
  const core = { blockNum: manifest.blockNum, algorithm: manifest.algorithm, rules: manifest.rules, files: manifest.files };
  const coreHash = '0x' + sha256Hex(JSON.stringify(core));
  ok(coreHash === manifest.manifestHash, 'manifestHash == sha256(core) recomputed');
  const [resHash, resUpdated] = await publicClient.readContract({
    address: chainInfo.contracts.hashStorage, abi: HS_ABI, functionName: 'resultHashes', args: [BigInt(N)],
  });
  ok(Number(resUpdated) !== 0 && resHash.toLowerCase() === coreHash.toLowerCase(), 'on-chain resultHashes == manifestHash');
  const resRegCount = await publicClient.readContract({
    address: chainInfo.contracts.hashStorage, abi: HS_ABI, functionName: 'resultRegistrationCount', args: [BigInt(N)],
  });
  ok(Number(resRegCount) === 1, 'resultRegistrationCount == 1');
  ok(manifest.files[`games/block${N}/summary.json`] != null, 'manifest declares summary.json');
  for (const [key, h] of Object.entries(manifest.files)) {
    if (h === null) {
      // 未公開エントリ（autoDistribute のグループ/evidence-report 等）はファイル不在と整合していること
      ok(!hasFile(key), `manifest null entry has no file on disk: ${key}`);
      continue;
    }
    ok(sha256Hex(readText(key)) === h, `manifest.files[${key}] == sha256(bytes on disk)`);
  }

  // 5) merkle root == チェーン blockStates(N).root（0配分ブロックは空ツリー標識ルート）
  const merkle = readJson(`merkle/block_${N}.json`);
  const state = await publicClient.readContract({
    address: chainInfo.contracts.tokenMining, abi: TM_ABI, functionName: 'blockStates', args: [BigInt(N)],
  });
  const chainRoot = Array.isArray(state) ? state[0] : state.merkleRoot;
  ok(merkle.root.toLowerCase() === chainRoot.toLowerCase(), `merkle root on disk == on-chain (${merkle.root})`);
  if (merkle.leafCount === 0) {
    ok(merkle.root.toLowerCase() === emptyMerkleSentinel(N).toLowerCase(),
      'empty merkle: root == sentinel keccak256("bitcoinu:empty-merkle:{N}")');
    ok(merkle.totalAmount === '0' && !merkle.items, 'empty merkle: totalAmount 0, no items (G1b: v2メタはitemsを持たない)');
  } else {
    ok(BigInt(merkle.leafCount) > 0n, 'merkle has leaves');
  }

  // 6) evidence-report: 分類が期待どおり（hasGame のみ。autoDistribute は reconcile 自体が走らない）
  let noPrestartRoster = false;
  if (meta.hasGame && meta.evidence) {
    const report = readJson(`verification/block${N}/evidence-report.json`);
    ok(report.resultCount === meta.evidence.resultCount, `evidence resultCount == ${meta.evidence.resultCount}`);
    noPrestartRoster = meta.rosterAnchorMode === 'missing'
      && report.rosterSubmission?.accepted === false
      && report.rosterSubmission.reason === 'no_prestart_canonical_roster';
    if (report.rosterSubmission?.accepted === false) {
      ok(noPrestartRoster, 'rejected submissions only match the unregistered-roster fixture');
    }
    if (meta.rosterAnchorMode === 'missing') {
      ok(noPrestartRoster, 'missing roster: report rejects submissions for no_prestart_canonical_roster');
    }
    if (noPrestartRoster) {
      ok(Array.isArray(report.adopted) && report.adopted.length === 0,
        'missing roster: no Evidence submissions adopted');
      for (const g of chainInfo.groups) {
        const arch = readJson(`games/block${N}/group${g.groupId}.json`);
        // ChatGameDO の先行アーカイブには WS raw が残り得る。採点へ渡した入力は witness で検査する。
        const witness = readJson(`zkp/block${N}/group-${g.groupId}.json`);
        ok(Array.isArray(witness.submissions) && witness.submissions.length === 0,
          `missing roster: scoring witness group${g.groupId} submissions empty`);
        ok(Object.keys(arch.evidenceSources || {}).length === 0,
          `missing roster: archive group${g.groupId} evidenceSources empty`);
      }
    } else {
      const stateOf = (uid) => report.adopted.find(a => a.uid === uid)?.serverState;
      for (const uid of meta.evidence.identical) ok(stateOf(uid) === 'identical', `adopted[${uid}] identical`);
      for (const uid of meta.evidence.missing) ok(stateOf(uid) === 'missing', `adopted[${uid}] missing (censorship restored)`);
      for (const uid of meta.evidence.mismatch) ok(stateOf(uid) === 'mismatch', `adopted[${uid}] mismatch (tamper overridden)`);

      // 7) グループアーカイブ: 復元/上書きされた提出がチェーン採用分と一致し evidenceSources を持つ
      for (const uid of [...meta.evidence.missing, ...meta.evidence.mismatch]) {
        const g = chainInfo.groups.find(x => x.memberUids.includes(uid));
        const arch = readJson(`games/block${N}/group${g.groupId}.json`);
        ok(typeof arch.submissionsRaw?.[uid] === 'string' && arch.submissionsRaw[uid].length > 0,
          `archive group${g.groupId} has submissionsRaw[${uid}]`);
        ok(arch.evidenceSources?.[uid]?.seq === chainInfo.evidence.seqs[uid],
          `archive evidenceSources[${uid}].seq == on-chain seq`);
        // 復元後の raw はバンドルとして自己整合（uid＝そのメンバー・encryptKey公開済み）
        const bundle = decodeSubmissionPayloadString(arch.submissionsRaw[uid]).bundle;
        ok(bundle.uid === uid && bundle.encryptKey && bundle.chatHash, `restored bundle[${uid}] has core fields`);
      }
    }
    ok(report.invalid.length === meta.evidence.invalidCount, `invalid evidence events == ${meta.evidence.invalidCount}`);
  } else {
    ok(!hasFile(`verification/block${N}/evidence-report.json`) || meta.hasGame,
      'autoDistribute: no evidence-report.json (reconcile not run)');
  }

  // 8) summary: 全グループが期待ステータス・全員に btcu_reward、merkle totalAmount <= blockReward
  const summary = readJson(`games/block${N}/summary.json`);
  const expectedStatus = meta.autoDistributed ? 'auto_distributed' : 'completed';
  ok(Array.isArray(summary.groups) && (meta.autoDistributed || summary.groups.length === chainInfo.groups.length),
    'summary group count');
  ok(summary.groups.every(g => g.status === expectedStatus), `all summary groups ${expectedStatus}`);
  ok(summary.groups.every(g => g.members.every(m => typeof m.full_btcu_reward === 'string')),
    'every lean-summary member has full_btcu_reward');
  ok(BigInt(merkle.totalAmount) <= BigInt(summary.blockReward), 'merkle totalAmount <= blockReward');
  ok(summary.blockReward === getBlockRewardWei(N).toString(), 'summary.blockReward == getBlockRewardWei(N)');

  if (noPrestartRoster) {
    ok(summary.groups.every(g => g.members.every(m => m.total_points === 0 && m.full_btcu_reward === '0')),
      'missing roster: every member has 0 points and 0 full reward');
    for (const g of chainInfo.groups) {
      const arch = readJson(`games/block${N}/group${g.groupId}.json`);
      const scored = (arch.gameResults || []).filter(r => typeof r.total_points === 'number');
      ok(scored.length === g.memberUids.length
        && scored.every(r => r.total_points === 0 && r.btcu_reward === '0'),
        `missing roster: archive group${g.groupId} all members score 0 and btcu_reward 0`);
    }
    ok(merkle.leafCount === 0, 'missing roster: empty merkle leaf count');
  }

  // 検閲されたプレイヤーが no_submit になっていない（チェーン復元の実効性）
  if (!noPrestartRoster && meta.hasGame && meta.evidence) {
    for (const censored of meta.evidence.missing) {
      const cg = summary.groups.find(g => g.members.some(m => m.userId === censored));
      const cm = cg.members.find(m => m.userId === censored);
      ok(!(cm.disqualify_reason || '').includes('no_submit'), `censored ${censored} NOT no_submit (restored from chain)`);
    }
  }

  return { failures, passed: failures.length === 0 };
}

// ---------------- CLI ----------------
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const argOf = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
  const port = parseInt(argOf('--port', '8547'));
  const outDir = resolve(argOf('--out', resolve(__dir, 'out/fixture')));
  const keepAlive = args.includes('--keep-alive');

  const t0 = Date.now();
  const fx = await generateFixture({ port, outDir });
  console.log(`[gen] fixture generated in ${((Date.now() - t0) / 1000).toFixed(1)}s → ${fx.r2Dir}`);
  const { failures, passed } = await verifyFixtureInternalConsistency({ r2Dir: fx.r2Dir, chainInfo: fx.chainInfo });
  if (!passed) {
    console.error(`\n[gen] INTERNAL CONSISTENCY FAILED (${failures.length}):`);
    for (const f of failures) console.error('  -', f);
  } else {
    console.log('\n[gen] internal consistency: ALL OK');
  }
  if (keepAlive) {
    console.log(`[gen] hardhat node kept alive on ${fx.chainInfo.rpcUrl} (Ctrl-C to stop)`);
  } else {
    fx.stop();
    process.exit(passed ? 0 : 1);
  }
}
