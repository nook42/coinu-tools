// mutations.mjs — green フィクスチャに1点だけ改変を入れ、検証ツールが【期待する特定チェックID】で
// 検出することを、非対話モードの機械可読出力（##CHECK <id> <status> / ##RESULT …）で assert する。
//
//   node block-verifier/test/mutations.mjs [--port 8547] [--r2-port 0] [--out DIR] [--only CASE]
//
// 手順: フィクスチャを1回生成（チェーンはそのまま生かす）→ ケースごとに r2 ツリーをコピー →
// 改変 →（manifest 対象キーの改変ケースは manifest 再計算＋チェーン再アンカー）→ ツール実行 →
// exit code と ##CHECK 行を assert。
// 🔴 ツール未完成のときは**中断（exit 1）**する（2026-08-09・ラウンド24）。
//    以前はここで全ケースを SKIP して exit 0 を返していた＝検証ツールを1度も起動せずに緑。
//
// ⚠ manifest マスクについて:
//   summary / merkle / グループアーカイブは D2 manifest（files の sha256 がオンチェーンアンカー）で
//   覆われているため、素朴な改変は manifest 照合(FAIL)で先に落ち、深部チェックの実効性を証明できない。
//   そこで reanchor:true のケースは改変後に manifest.files の sha256 を改変後バイトで再計算し、
//   manifest.json を書き直し、admin 鍵で HashStorage.registerResultHash を再実行して
//   【manifest 検査を PASS させた上で】深部チェックが単独で FAIL することを証明する。
//   再アンカーは resultRegistrationCount を増やし、直後の同一root再提出はroot提出履歴を増やすため、
//   check.stageC.resultReregistration / rootResubmitted の WARN が出るのは想定内。
//
// ⚠ ケース順序の制約:
//   再アンカーはフィクスチャチェーンの resultHashes[0] を上書きする共有状態の変更なので、
//   「チェーンが green のままであること」を前提とするケース（claim-mutation 等の reanchor:false）は
//   必ず reanchor:true のケースより【前】に並べること。
import { cpSync, rmSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { generateFixture } from './gen-fixture.mjs';
import { startR2Server } from './r2-server.mjs';
import { runTool, TOOL_ENTRY, toolLooksComplete, writeToolConfig } from './e2e.mjs';
import { TIMING, makeClients, write, rpc, setNextTimestamp, mineMany } from './chain-setup.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

// 0はOS採番。明示portを指定した場合だけ従来どおりケースごとにずらす。
// 既定を固定帯8790..へ戻すと、chatgame-tools loader-e2eやBV v25と並列実行した際に衝突する。
export const DEFAULT_MUTATION_R2_PORT = 0;
export function mutationR2PortForCase(configuredPort, caseIndex) {
  return configuredPort === 0 ? 0 : configuredPort + caseIndex;
}

const sha256Hex = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

// registerResultHash のみの最小 ABI（HashStorage.registerResultHash — admin 専用・上書き可）
const HS_MIN_ABI = [{
  name: 'registerResultHash', type: 'function', stateMutability: 'nonpayable',
  inputs: [
    { name: 'blockNumber', type: 'uint256' },
    { name: 'hash', type: 'bytes32' },
    { name: 'signer', type: 'address' },
  ],
  outputs: [],
}];

const TM_MIN_ABI = [{
  name: 'submitMerkleRoot', type: 'function', stateMutability: 'nonpayable',
  inputs: [
    { name: 'blockNum', type: 'uint256' },
    { name: 'root', type: 'bytes32' },
  ],
  outputs: [],
}];

// ---------------- manifest 再正当化（改変の再アンカー） ----------------
// 1) manifest.files の各 sha256 をディスク上の【現在バイト】で再計算
// 2) core = {blockNum, algorithm, rules, files} を再ハッシュ → manifestHash 更新・manifest.json 書き直し
// 3) admin(=deployer) 鍵で HashStorage.registerResultHash(N, newHash, admin) を実チェーンへ送信
// 4) 同じ正規 Merkle root を再提出し、manifest anchor < verificationStartedAt を成立させる
// 5) safe-block（latest - CONFIRMATION_BLOCKS）読取でも両txが見えるよう追加採掘
export async function reanchorManifest(r2Dir, chainInfo, deps = {}) {
  const makeClientsFn = deps.makeClientsFn || makeClients;
  const writeFn = deps.writeFn || write;
  const setNextTimestampFn = deps.setNextTimestampFn || setNextTimestamp;
  const mineManyFn = deps.mineManyFn || mineMany;
  const N = chainInfo.blockNum;
  const manifestKey = `verification/block${N}/manifest.json`;
  const manifest = JSON.parse(readFileSync(join(r2Dir, manifestKey), 'utf8'));
  for (const key of Object.keys(manifest.files || {})) {
    if (manifest.files[key] === null) continue; // 未公開エントリ（autoDistribute等）はそのまま
    manifest.files[key] = sha256Hex(readFileSync(join(r2Dir, key), 'utf8'));
  }
  const core = {
    blockNum: manifest.blockNum, algorithm: manifest.algorithm,
    rules: manifest.rules, files: manifest.files,
  };
  manifest.manifestHash = '0x' + sha256Hex(JSON.stringify(core));
  writeFileSync(join(r2Dir, manifestKey), JSON.stringify(manifest));

  const clients = makeClientsFn(chainInfo.rpcUrl); // DEPLOYER_KEY = HashStorage admin
  const anchorReceipt = await writeFn(clients, { address: chainInfo.contracts.hashStorage, abi: HS_MIN_ABI },
    'registerResultHash', [BigInt(N), manifest.manifestHash, clients.account.address]);

  // mutation は green fixture の root 提出後に行う。アンカーだけを上書きすると
  // inspectResultManifestAnchor が正しく anchored_after_root_submission を返すため、
  // shadow期間で契約が明示的に許す同一root再提出により検証時計をアンカー後へ進める。
  // Hardhatの自動採掘が同一timestampを選んでも strict `<` を破らないよう次block時刻も固定する。
  const anchorBlock = await clients.publicClient.getBlock({ blockNumber: anchorReceipt.blockNumber });
  await setNextTimestampFn(chainInfo.rpcUrl, Number(anchorBlock.timestamp) + 1);
  await writeFn(clients, { address: chainInfo.contracts.tokenMining, abi: TM_MIN_ABI },
    'submitMerkleRoot', [BigInt(N), chainInfo.merkleRoot]);

  // ツールのsafe-block読取とイベント再生に新アンカー・root再提出の両方を含める。
  await mineManyFn(chainInfo.rpcUrl, TIMING.CONFIRMATION_BLOCKS + 2, 1);
  return manifest.manifestHash;
}

// 正式 Evidence がある uid の raw は検証時にチェーン版へ復元される。
// 変異が消えないよう、必ず少なくとも一方を非提出者から選ぶ。
export function chooseSubmissionSwapUids(arch, chainInfo) {
  const uids = Object.keys(arch.submissionsRaw || {});
  if (uids.length < 2) throw new Error('submission-swap requires >=2 submissionsRaw');
  const seqs = chainInfo.evidence?.seqs;
  if (!seqs) throw new Error('submission-swap requires chainInfo.evidence.seqs');
  const nonChainUid = uids.find(uid => !Object.hasOwn(seqs, uid));
  if (!nonChainUid) throw new Error('submission-swap requires a uid without formal chain submission');
  const otherUid = uids.find(uid => uid !== nonChainUid && Object.hasOwn(seqs, uid))
    || uids.find(uid => uid !== nonChainUid);
  return [nonChainUid, otherUid];
}

// ---------------- ケース定義 ----------------
// 各ケース:
//   mutate(r2Dir, chainInfo)  … コピー済み r2 ツリーを1点改変（async 可）
//   reanchor                  … true なら改変後に manifest 再計算＋チェーン再アンカー
//   expectFail                … 'fail' でなければならないチェックID。'a|b' はいずれか一方で可
//   expectWarnOnly            … 指定IDが 'warn' で、かつ【全チェックに fail が1つも無い】こと
//   expectPass                … 'pass' でなければならないチェックID
//   expectExit                … 許容する exit code（G4: 0=full / 1=not-ready / 2=fail / 3=fatal / 64=usage）
export const CASES = [
  // ── reanchor:false 群（チェーン無変更。reanchor 群より前に置くこと） ──
  {
    name: 'entries-byte-flip',
    expect: 'Stage A FAIL: entries データファイル改変 → ローカル再計算ルートがオンチェーン登録値と不一致（hashファイル非依存化後は rootMatch が唯一の検出点）',
    reanchor: false,
    mutate(r2Dir) {
      const key = 'entries/block0/entries/00_0.json';
      const recs = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      recs[0].lang = recs[0].lang === 'ja' ? 'jA' : 'eN'; // 1バイト級の意味改変
      writeFileSync(join(r2Dir, key), JSON.stringify(recs));
    },
    expectFail: ['check.stageA.rootMatch'],
    expectExit: [2],
  },
  {
    name: 'claim-mutation',
    expect: 'S4: schema v3 summary.json へのclaimed注入は不変成果物の改変として manifestFiles/summaryMatch hard FAIL',
    reanchor: false,
    mutate(r2Dir) {
      // 対照ケース: schema v3 の manifest 固定 summary へ旧形式 claimed を注入する。
      // 本番の請求更新先は claim-status/group{G}.json であり、summary は更新しない。
      const key = 'games/block0/summary.json';
      const summary = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      if (Number(summary.schemaVersion) !== 3) throw new Error('claim-mutation requires schemaVersion 3 fixture');
      const claimedData = { time: 1798763500, txHash: '0x' + 'ab'.repeat(32) };
      const group = summary.groups[0];
      group.members[0].claimed = claimedData;
      if (group.depositor_results?.length > 0) group.depositor_results[0].claimed = claimedData;
      writeFileSync(join(r2Dir, key), JSON.stringify(summary));
    },
    expectFail: ['check.stageC.manifestFiles', 'check.stageC.summaryMatch'],
    expectExit: [2],
  },
  {
    name: 'group-claimed-mutation',
    expect: 'S4 production path: manifest固定group0.jsonのgameResults行へclaimedを注入するとmanifestFiles/groupGameResultsMatchがhard FAIL',
    reanchor: false,
    mutate(r2Dir) {
      const summaryKey = 'games/block0/summary.json';
      const summary = JSON.parse(readFileSync(join(r2Dir, summaryKey), 'utf8'));
      if (Number(summary.schemaVersion) !== 3) throw new Error('group-claimed-mutation requires schemaVersion 3 fixture');
      const key = summary.groups?.[0]?.detailKey;
      if (key !== 'games/block0/group0.json') throw new Error(`unexpected group detailKey: ${String(key)}`);
      const page = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      if (!Array.isArray(page.gameResults) || page.gameResults.length === 0) throw new Error('group0 gameResults missing');
      if (page.gameResults.some(row => Object.prototype.hasOwnProperty.call(row, 'claimed'))) {
        throw new Error('schema v3 fixture unexpectedly contains inline claimed');
      }
      page.gameResults[0].claimed = { time: 1798763500, txHash: '0x' + 'cd'.repeat(32) };
      writeFileSync(join(r2Dir, key), JSON.stringify(page));
    },
    expectFail: ['check.stageC.manifestFiles', 'check.stageC.groupGameResultsMatch'],
    expectExit: [2],
  },
  {
    name: 'confirmations-grind',
    expect: 'Stage B FAIL（G2a）: game_selection.json の confirmationBlocks を 65 に改変（targetBlockNum/randao 等も辻褄合わせ）→ pins.confirmationBlocks=64 との不一致で FAIL',
    reanchor: false,
    async mutate(r2Dir, chainInfo) {
      const key = 'entries/block0/game_selection.json';
      const sel = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      sel.confirmationBlocks = 65;
      sel.targetBlockNum = sel.hashRegisteredBlock + 65;
      sel.mainnetBlockNumber = sel.targetBlockNum;
      // 内部整合（targetBlockHash/randao == チェーン実値）を保ち、pins 照合だけが落ちるようにする
      const tb = await rpc(chainInfo.rpcUrl, 'eth_getBlockByNumber',
        ['0x' + sel.targetBlockNum.toString(16), false]);
      sel.targetBlockHash = tb.hash;
      sel.randao = tb.mixHash;
      writeFileSync(join(r2Dir, key), JSON.stringify(sel));
    },
    expectFail: ['check.stageB.confirmationBlocks'],
    expectExit: [2],
  },
  {
    name: 'manifest-withheld',
    expect: 'Stage C FAIL（握り潰し検出）: verification/block0/manifest.json を R2 から削除。正典は adminCommit を最終段階に置く（merkle→manifest→proofs→adminCommit）ため「root 提出済み ⟹ manifest 公開済み」が不変条件。root があるのに manifest 欠落＝異常＝downloads FAIL。',
    reanchor: false,
    mutate(r2Dir) {
      rmSync(join(r2Dir, 'verification/block0/manifest.json'), { force: true });
    },
    expectFail: ['check.stageC.downloads'],
    expectExit: [2],
  },
  {
    // 🔴 F-6（2026-08-08・ラウンド20 判断不要-6）
    name: 'bytes-corrupt',
    expect: 'FAIL（壊れた公開データ）: summary.json を途中で切る。旧実装は共通入口 r2.js の JSON.parse が throw して **##RESULT fatal / exit 3**（＝「契約コード欠落」と同じ終了コード）になっていた。同じファイルを pretty-print しただけなら exit 2 の FAIL なので、「重い異常のほうが弱い信号」という逆転が起きていた。⚠️ summary.json は **Stage B の summaryStructure** が先に読むので、赤くなるのはそこ（Stage C の downloads までは進まない）。要点は「fatal ではなく名前のついた FAIL / exit 2」。',
    reanchor: false,
    mutate(r2Dir) {
      const key = 'games/block0/summary.json';
      const raw = readFileSync(join(r2Dir, key), 'utf8');
      writeFileSync(join(r2Dir, key), raw.slice(0, Math.floor(raw.length / 2)));
    },
    expectFail: ['check.stageB.summaryStructure'],
    expectExit: [2],
  },
  {
    // 🔴 F-6: `manifest.json = null` は旧実装で **20 チェックが無記録のまま消え**、
    //    その後 `Cannot read properties of null (reading 'rules')` で exit 3（キー名も出ない）だった。
    name: 'manifest-null',
    expect: 'Stage C FAIL（fail-open の封じ）: verification/block0/manifest.json を `null` に置換。旧実装は `if (!manifest) return;` で黙って 20 チェックを飛ばし、最後に TypeError で fatal になっていた。',
    reanchor: false,
    mutate(r2Dir) {
      writeFileSync(join(r2Dir, 'verification/block0/manifest.json'), 'null');
    },
    expectFail: ['check.stageC.downloads'],
    expectExit: [2],
  },

  // ── reanchor:true 群（manifest 再計算＋チェーン再アンカーで深部チェックまで到達させる） ──
  {
    // 🔴 F-7(a)（2026-08-08・ラウンド20 判断不要-7）
    name: 'summary-timeline',
    expect: 'Stage C FAIL: summary.json の timeline を改変（graceSec と chattingStart を嘘の値へ・manifest 再アンカー済）→ timelineMatch FAIL。旧実装は **exit 0 / ##RESULT full / FAIL 0**（しかも summaryByteExact は pass のまま）だった＝参加者に見せるカウントダウンを自由に書き換えられた。',
    reanchor: true,
    mutate(r2Dir) {
      const key = 'games/block0/summary.json';
      const s2 = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      if (!s2.timeline) throw new Error('fixture の summary.json に timeline が無い（この変異は timeline 前提）');
      s2.timeline.graceSec = 999999;
      s2.timeline.chattingStart = s2.timeline.chattingStart + 14 * 24 * 3600 * 1000;
      writeFileSync(join(r2Dir, key), JSON.stringify(s2));
    },
    expectFail: ['check.stageC.timelineMatch'],
    expectExit: [2],
  },
  {
    name: 'summary-points',
    expect: 'Stage C FAIL: summary.json の total_points 改変（manifest 再アンカー済）→ C6 summary 再構築比較で採点フィールド差分 FAIL',
    reanchor: true,
    mutate(r2Dir) {
      const key = 'games/block0/summary.json';
      const s = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      s.groups[0].members[0].total_points = (s.groups[0].members[0].total_points || 0) + 7;
      writeFileSync(join(r2Dir, key), JSON.stringify(s));
    },
    expectFail: ['check.stageC.summaryMatch'],
    expectExit: [2],
  },
  {
    name: 'merkle-root',
    expect: 'Stage C FAIL: merkle/block_0.json の root 改変（manifest 再アンカー済）→ C7 再構築 root ⇔ 公開 root / オンチェーン blockStates.root 不一致で FAIL',
    reanchor: true,
    mutate(r2Dir) {
      const key = 'merkle/block_0.json';
      const m = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      m.root = '0x' + 'de'.repeat(32);
      writeFileSync(join(r2Dir, key), JSON.stringify(m));
    },
    expectFail: ['check.stageC.merkleRebuild|check.stageC.merkleRoot'],
    expectExit: [2],
  },
  {
    name: 'submission-swap',
    expect: 'Stage C FAIL: グループアーカイブの submissionsRaw を2人分入れ替え（manifest 再アンカー済）→ Evidence差分はV25-03規則で復元しつつ、非Evidence入力の改変は独立再採点／summary／Merkle比較でFAIL',
    reanchor: true,
    mutate(r2Dir, chainInfo) {
      const gid = chainInfo.groups[0].groupId;
      const key = `games/block0/group${gid}.json`;
      const arch = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      const [a, b] = chooseSubmissionSwapUids(arch, chainInfo);
      console.log(`  swapped submissionsRaw: ${a} (non-chain) <-> ${b}`);
      [arch.submissionsRaw[a], arch.submissionsRaw[b]] = [arch.submissionsRaw[b], arch.submissionsRaw[a]];
      writeFileSync(join(r2Dir, key), JSON.stringify(arch));
    },
    expectFail: ['check.stageC.groupGameResultsMatch|check.stageC.summaryMatch|check.stageC.merkleRoot'],
    expectExit: [2],
  },
  {
    name: 'censorship-erase',
    expect: 'V25-03正常系: チェーンに正式提出済みのプレイヤーをアーカイブから抹消しても、current compact Evidenceから復元して独立再採点・summary・Merkle比較がPASSする',
    reanchor: true,
    mutate(r2Dir, chainInfo) {
      const uid = chainInfo.evidence.censoredUid;
      const g = chainInfo.groups.find(x => x.memberUids.includes(uid));
      const key = `games/block0/group${g.groupId}.json`;
      const arch = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      delete arch.submissions[uid];
      delete arch.submissionsRaw[uid];
      if (arch.evidenceSources) delete arch.evidenceSources[uid];
      writeFileSync(join(r2Dir, key), JSON.stringify(arch));
    },
    expectPass: [
      'check.stageC.archiveChainConsistency',
      'check.stageC.evidenceReportMatch',
      'check.stageC.summaryMatch',
      'check.stageC.merkleRoot',
    ],
    expectNoFail: true,
    expectExit: [0],
  },
  {
    name: 'depositor-set-drop',
    expect: 'Stage C FAIL（SPEC §8 L1 の受容根拠を実測で担保）: summary.json のあるプレイヤーの depositor_results から depositId を1件だけ削除（manifest 再アンカー済）→ 検証ツールは提出物／applicantHash 固定の depIds を起点に EthLock を読み直して適格集合を再構成するので、抜けた1件が復活し summaryMatch が FAIL する。新方式では setHash が葉の鍵に入るため merkleRoot も同時にずれる',
    reanchor: true,
    mutate(r2Dir) {
      const key = 'games/block0/summary.json';
      const summary = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      let dropped = null;
      for (const g of summary.groups || []) {
        const byUid = new Map();
        for (const d of (g.depositor_results || [])) {
          if (!byUid.has(d.playerUid)) byUid.set(d.playerUid, []);
          byUid.get(d.playerUid).push(d);
        }
        for (const [uid, rows] of byUid) {
          if (rows.length < 2) continue;
          const victim = rows[0];
          g.depositor_results = g.depositor_results.filter(
            (d) => !(d.playerUid === uid && d.depositId === victim.depositId));
          dropped = { uid, depositId: victim.depositId };
          break;
        }
        if (dropped) break;
      }
      if (!dropped) throw new Error('depositor-set-drop: 複数デポジットを持つプレイヤーがフィクスチャに居ない');
      console.log(`  dropped depositId ${dropped.depositId} from player ${dropped.uid}`);
      writeFileSync(join(r2Dir, key), JSON.stringify(summary));
    },
    expectFail: ['check.stageC.summaryMatch'],
    expectExit: [2],
  },
  {
    name: 'depositor-rounding-pin',
    expect: 'Stage C FAIL（SPEC §7-3）: manifest の rules.depositorRounding を別値に改変（manifest 再アンカー済）→ pins との厳密照合で rulesPins FAIL。「分配規則の宣言を書き換えるだけで規則を無効化できる」穴が塞がっていることの実測',
    reanchor: true,
    mutate(r2Dir) {
      const key = 'verification/block0/manifest.json';
      const m = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      m.rules.depositorRounding = 'remainder-to-last';
      writeFileSync(join(r2Dir, key), JSON.stringify(m));
    },
    expectFail: ['check.stageC.rulesPins'],
    expectExit: [2],
  },
  {
    name: 'depositor-leaf-format-undeclared',
    expect: 'Stage C FAIL（未宣言も逸脱）: manifest の rules.depositorLeafFormat を**削除**（manifest 再アンカー済）→ 宣言を落とすだけで検査を回避できないことの実測（maxDepositWei と同じ厳密照合）',
    reanchor: true,
    mutate(r2Dir) {
      const key = 'verification/block0/manifest.json';
      const m = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      delete m.rules.depositorLeafFormat;
      writeFileSync(join(r2Dir, key), JSON.stringify(m));
    },
    expectFail: ['check.stageC.rulesPins'],
    expectExit: [2],
  },
  {
    name: 'evidence-null',
    expect: 'Stage C FAIL（G1）: manifest の rules.evidence を null に改変（manifest 再アンカー済）→ チェーンの resultCount>0 と矛盾 → evidenceDeclaredDisabled FAIL',
    reanchor: true,
    mutate(r2Dir, chainInfo) {
      const key = `verification/block${chainInfo.blockNum}/manifest.json`;
      const manifest = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      manifest.rules.evidence = null; // 「evidence 無効」を偽装（manifestHash は reanchor が再計算）
      writeFileSync(join(r2Dir, key), JSON.stringify(manifest));
    },
    expectFail: ['check.stageC.evidenceDeclaredDisabled'],
    expectExit: [2],
  },
  {
    name: 'roster-nostr-key-swap',
    expect: 'Stage C FAIL: roster の Nostr 公開鍵だけをすり替えて再アンカーしても応募値との照合で検出する',
    reanchor: true,
    mutate(r2Dir, chainInfo) {
      const key = `games/block${chainInfo.blockNum}/roster/group0.json`;
      const roster = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      const original = roster.members[0].nostrPubkey;
      roster.members[0].nostrPubkey = original === '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        ? 'c6047f9441ed7d6d3045406e95c07cd85a691184debf5a9fcf937e55d8a5e276'
        : '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
      writeFileSync(join(r2Dir, key), JSON.stringify(roster));
    },
    expectFail: ['check.stageC.rosterKeys'],
    expectExit: [2],
  },
  {
    // 🔴 Q-6（2026-08-08・ユーザー確定）: **名簿の鍵差し替え。**
    //    `roster/group{G}.json` は P2P 冗長経路の**信頼の起点**（`relay-verify.js` が内側署名を
    //    `member.bAddr.address` で内側署名を検証し、`relay.js` が名簿の `nostrPubkey` と封筒鍵を照合する）。
    //    改修前の実測: 1人の `blockAddress`/`pubKey` を攻撃者鍵へ差し替えても
    //    **exit 0 / ##RESULT full / pass 62 / warn 0 / fail 0**（名簿は artifactKeys に無く、
    //    検証ツールが一度も読んでいなかった）。差し替えは無言なので、被害者には
    //    「相手が何も喋っていない」ようにしか見えない。
    //    🔴 **manifest を再アンカーしてもなお落ちる**ことが要点。バイト列の固定だけでは
    //    「運営が差し替えた名簿を目録に含めて一貫させる」攻撃が通ってしまうので、
    //    応募データ（`applicantHash` でチェーンに固定）との突き合わせが要る。
    name: 'roster-key-swap',
    expect: 'Stage C FAIL（Q-6）: roster/group0.json の1人の blockAddress/pubKey を攻撃者鍵へ差し替え（manifest 再アンカー済）→ 応募データとの突き合わせで rosterKeys FAIL',
    reanchor: true,
    mutate(r2Dir, chainInfo) {
      const key = `games/block${chainInfo.blockNum}/roster/group0.json`;
      const roster = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      const victim = roster.members.find((m) => m.blockAddress) || roster.members[0];
      victim.blockAddress = '0xdeadBEEFdeadBEEFdeadBEEFdeadBEEFdeadBEEF';
      victim.pubKey = '04' + 'ab'.repeat(64);
      writeFileSync(join(r2Dir, key), JSON.stringify(roster));
    },
    expectFail: ['check.stageC.rosterKeys'],
    expectExit: [2],
  },
  {
    // Q-6: 名簿索引（uid → groupId）の差し替え。改修前は `warn` 止まりで `fail` が存在しなかった。
    name: 'roster-index-swap',
    expect: 'Stage C FAIL（Q-6）: roster/index.json の uid を別グループへ付け替え（manifest 再アンカー済）→ rosterIndex FAIL（旧実装は warn 止まりで fail が無かった）',
    reanchor: true,
    mutate(r2Dir, chainInfo) {
      const key = `games/block${chainInfo.blockNum}/roster/index.json`;
      const idx = JSON.parse(readFileSync(join(r2Dir, key), 'utf8'));
      const uid = Object.keys(idx)[0];
      idx[uid] = Number(idx[uid]) + 1; // 別グループへ付け替え
      writeFileSync(join(r2Dir, key), JSON.stringify(idx));
    },
    expectFail: ['check.stageC.rosterIndex'],
    expectExit: [2],
  },
];

// ---------------- ##CHECK / ##RESULT 解析（G4 の機械可読出力・i18n 非依存） ----------------
export function parseChecks(stdout) {
  const checks = new Map(); // id -> status（同一IDが複数回出たら最後を採用）
  let result = null;
  for (const line of stdout.split('\n')) {
    const mc = line.match(/^##CHECK\s+(\S+)\s+(pass|warn|fail|skip)\s*$/);
    if (mc) { checks.set(mc[1], mc[2]); continue; }
    const mr = line.match(/^##RESULT\s+(\S+)\s*$/);
    if (mr) result = mr[1];
  }
  return { checks, result };
}

// ケース1件の実行結果を assert。エラー文字列の配列を返す（空=OK）。
export function assertCase(c, run) {
  const errors = [];
  const { checks, result } = parseChecks(run.stdout);

  if (c.expectExit && !c.expectExit.includes(run.code)) {
    errors.push(`exit code: expected one of [${c.expectExit.join(', ')}], got ${run.code}`);
  }
  if (checks.size === 0) {
    errors.push('no ##CHECK lines in stdout (G4 machine-readable output missing?)');
    return { errors, checks, result };
  }
  for (const spec of c.expectFail || []) {
    const alts = spec.split('|');
    if (!alts.some(id => checks.get(id) === 'fail')) {
      errors.push(`expected FAIL on ${spec}, statuses: ${alts.map(id => `${id}=${checks.get(id) ?? 'absent'}`).join(', ')}`);
    }
  }
  for (const id of c.expectWarnOnly || []) {
    if (checks.get(id) !== 'warn') {
      errors.push(`expected WARN on ${id}, got ${checks.get(id) ?? 'absent'}`);
    }
  }
  if (c.expectWarnOnly) {
    const anyFail = [...checks.entries()].filter(([, s]) => s === 'fail').map(([id]) => id);
    if (anyFail.length > 0) errors.push(`expected no FAIL at all, but got: ${anyFail.join(', ')}`);
  }
  if (c.expectNoFail) {
    const anyFail = [...checks.entries()].filter(([, s]) => s === 'fail').map(([id]) => id);
    if (anyFail.length > 0) errors.push(`expected no FAIL at all, but got: ${anyFail.join(', ')}`);
  }
  if (c.reanchor) {
    if (checks.get('check.stageC.manifestAnchor') !== 'pass') {
      errors.push(`re-anchored manifest must PASS manifestAnchor, got ${checks.get('check.stageC.manifestAnchor') ?? 'absent'}`);
    }
    if (checks.get('check.stageC.rootResubmitted') !== 'warn') {
      errors.push(`manifest re-anchor must refresh the root clock, rootResubmitted=${checks.get('check.stageC.rootResubmitted') ?? 'absent'}`);
    }
    if (checks.get('check.stageC.rootSubmissionRules') !== 'pass') {
      errors.push(`root resubmission history must obey lifecycle rules, got ${checks.get('check.stageC.rootSubmissionRules') ?? 'absent'}`);
    }
  }
  for (const id of c.expectPass || []) {
    if (checks.get(id) !== 'pass') {
      errors.push(`expected PASS on ${id}, got ${checks.get(id) ?? 'absent'}`);
    }
  }
  return { errors, checks, result };
}

// ---------------- メイン ----------------
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const argOf = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const port = parseInt(argOf('--port', '8547'));
  const r2Port = parseInt(argOf('--r2-port', String(DEFAULT_MUTATION_R2_PORT)));
  const outDir = resolve(argOf('--out', resolve(__dir, 'out/mutations')));
  const only = argOf('--only', null);

  // 🔴 2026-08-09（ラウンド24）: ここは以前 `toolReady=false` でも**素通りして exit 0** だった。
  //    NOTE 行を1本出したうえで全ケースを `run: SKIP (tool missing)` で飛ばし、
  //    最後に `mutations: PASS` を印字する＝**検証ツールを1度も起動せずに緑**。
  //    しかも mutations はリリースゲートの KNOWN_RED に登録されているので、
  //    緑になった瞬間 `stale`（「既知の赤が解消しています」）という**間違った診断**に化ける。
  //    `simulation.mjs` は同じ状況を最初から exit 1 で中断している（3本のうちここだけ直っていなかった）。
  //    → simulation と同じく**中断**する。準備だけしたいときは `--run-tool` ではなく
  //      ツールを揃えてから走らせること（ツールが無ければ検証していないのだから緑ではない）。
  if (!toolLooksComplete() && !args.includes('--run-tool')) {
    console.error(`tool not complete (need src/{index,i18n,report}.js next to ${TOOL_ENTRY}) — aborting`);
    process.exit(1);
  }

  let exitCode = 0;
  let fx = null;
  const servers = [];
  try {
    console.log('═'.repeat(60));
    console.log('mutations: generating green fixture first');
    console.log('═'.repeat(60));
    fx = await generateFixture({ port, outDir: join(outDir, 'green') });

    const cases = CASES.filter(c => !only || c.name === only);
    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];
      console.log('═'.repeat(60));
      console.log(`mutation case: ${c.name}`);
      console.log(`  expect: ${c.expect}`);
      const caseDir = join(outDir, 'cases', c.name);
      rmSync(caseDir, { recursive: true, force: true });
      mkdirSync(caseDir, { recursive: true });
      const r2Copy = join(caseDir, 'r2');
      cpSync(fx.r2Dir, r2Copy, { recursive: true });
      await c.mutate(r2Copy, fx.chainInfo);
      console.log(`  mutated copy at ${r2Copy}`);
      if (c.reanchor) {
        // 改変を manifest レベルで再正当化（深部チェックの実効性を試すため）
        const newHash = await reanchorManifest(r2Copy, fx.chainInfo);
        console.log(`  manifest re-anchored on chain: ${newHash} (resultReregistration/rootResubmitted WARNs are expected)`);
      }

      // ケースごとに専用R2サーバー＋専用dataDir（キャッシュ汚染防止）
      const srv = await startR2Server({
        rootDir: r2Copy,
        port: mutationR2PortForCase(r2Port, i),
      });
      servers.push(srv);
      const configPath = writeToolConfig({
        outDir: caseDir, chainInfo: fx.chainInfo, r2BaseUrl: srv.baseUrl,
        dataDir: join(caseDir, 'verifier-data'),
      });
      const run = await runTool({ configPath, blockNum: 0 });
      const { errors, checks, result } = assertCase(c, run);
      console.log(`  tool exit = ${run.code}, ##RESULT = ${result ?? '(none)'}, ##CHECK lines = ${checks.size}`);
      if (errors.length === 0) {
        console.log('  ASSERTIONS: OK');
        // 参考表示: 落ちたチェック
        const failed = [...checks.entries()].filter(([, s]) => s === 'fail').map(([id]) => id);
        if (failed.length > 0) console.log(`   failed checks: ${failed.join(', ')}`);
      } else {
        console.error('  ASSERTIONS: NG');
        for (const e of errors) console.error(`   - ${e}`);
        const tail = (s) => s.split('\n').slice(-40).join('\n');
        console.error(`  --- tool stdout (tail) ---\n${tail(run.stdout)}\n  --- tool stderr (tail) ---\n${tail(run.stderr)}`);
        exitCode = 1;
      }
      srv.stop();
    }
  } catch (e) {
    console.error('mutations fatal:', e);
    exitCode = 1;
  } finally {
    for (const s of servers) { try { s.stop(); } catch {} }
    try { fx?.stop(); } catch {}
  }
  console.log('═'.repeat(60));
  console.log(exitCode === 0 ? 'mutations: PASS (all prepared/detected)' : 'mutations: FAIL');
  process.exit(exitCode);
}
