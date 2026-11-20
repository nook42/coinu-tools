# 検証ツール網羅シミュレーション — 次セッション引き継ぎ

> 目的（ユーザー確定・2026-07-12）: **「サーバーが正常稼働している限り、あらゆるケースで
> block-verifier の検証結果が公開結果と一致する」ことをローカルで網羅的にシミュレーション・実証する。**
> = ゲームの全分岐（採点・報酬・グループ分け・Evidence・自動配布…）を本番コードで生成した
> 偽ブロック群に対し、ツールが独立再現して「一致（##RESULT full 等・期待どおり）」になることを
> シナリオ・マトリクスで確認する。

---

## 0. なぜやるか（今回の全員失格バグが示したこと）

現行 `test/e2e.mjs` は**1シナリオ固定**（8人2グループ・提出3件・検閲/改竄あり）で緑を確認しているだけ。
このため「当選者全員失格＝オンチェーン提出0件（resultCount=0）」のブロックは**一度もテストされておらず**、
`adoptedCount=null≠0` の writer モデル化ズレを実機ユーザーテストで初めて踏んだ（a629453 で修正）。
**分岐網羅のマトリクスがあれば事前に捕まえられた**。同種のズレ（writer と tool のモデル差）を
潰すのがこのシミュレーションの本質価値。

## 1. 結論: 実行可能（既存土台の拡張）

`test/e2e.mjs` + `test/gen-fixture.mjs` が既に「**本番コードで偽ブロック一式を生成**（Hardhatローカル＋
R2スタブ・実鍵署名・実ECIES・実 Evidence.submitResult）→ **ツールを非対話実行して緑を確認** →
**内部整合を byte で検査**」を実現済み。網羅版 = これを**シナリオ・スペックでパラメータ化**し、
マトリクスを回すだけ。

### 一致の意味（タウトロジー回避・重要）
- フィクスチャは**正典 `workers/` を直接 import して生成**（`canonical.mjs`）、ツールは**`vendor/` の
  正典コピーで再現**（`check-vendor-sync` で同一を担保）。同じ計算式なので「採点結果が一致」は一部自明。
- **真の検証価値は次の2点**:
  1. **公開成果物どうしの相互整合**を、ツールが**独立に**再構成して確認する:
     `summary.json`（server writer が書く）⇔ tool 再構成採点、`merkle/block_N.json` ⇔ tool 再構成ツリー、
     `verification/block{N}/manifest.json` の files/rules/evidence ⇔ tool 計算、
     `evidence-report.json` ⇔ tool の reconcile 再現、オンチェーン `resultHash/merkleRoot/resultCount` ⇔ tool。
     server の**writer 経路**（buildBlockSummaryWithResults / publishVerificationManifest /
     reconcileEvidence / collectClaimEntriesFromSummary）は tool が実行するコードとは**別物**なので、
     ここの一致は非自明＝writer と tool のモデル差（adoptedCount=null 型のバグ）を炙り出す。
  2. **全分岐の網羅**: 採点・失格・報酬・グループ分けの各ルートを1回以上通す（下記マトリクス）。

## 2. 実装計画

### 2.1 `gen-fixture.mjs` のパラメータ化
現状は `PLAYER_PLAN`（固定8人）・`BLOCK_NUM=0`・固定行動（先頭がタブー違反・全員投票・0/2番が密告・
1人検閲・1人改竄）がハードコード。これを **scenario スペック**で受けるよう refactor:

```
generateFixture({ scenario, port, outDir })
scenario = {
  blockNum,                         // 報酬階層（0-90 / 91-181 / 182+）を変えるのに使う
  players: [{ uid, lang, eth, name?, img?, verified? }],   // 人数=グループ規模・言語構成
  externalDepositors: [{ uid, keyIndex, eth, forUid }],
  timing: { … } or デフォルト,        // confirmationBlocks は 64（本番ピン）で通せる（hardhat可）
  prevBlock?: { players, … },        // majorLangs 検証用（前ブロックで≥200/言語を作る簡便化オプション）
  behavior: {                        // 各プレイヤーの行動を明示（決定論・v3.2）
    votes: { voterUid: targetUid | 'self' | null },  // null=no_vote 失格を作れる
    reports: { targetUid: [reporterUid…] },
    lowChars: [uid…],                // min_chars 失格を作る（500未満）
    lowTurns: [uid…],                // min_messages 失格
    noSubmit: [uid…],                // 提出しない（no_submit）
    ineligibleDeposit: [uid…],       // 適格閾値未満unlockで ineligible_deposit
    // --- v3.2 受領証明・不正系フック ---
    noReadReceiptsFor: [uid…],       // uidの発言に既読受領証明なし → 正典外（min_chars）
    noVoteReceipt: [uid…],           // uidの投票に受領証明なし → no_vote
    noReportReceipt: [uid…],         // uidの密告に受領証明なし → 無効密告
    withdrawVote: [uid…],            // 受領済み投票の取下げ → vote_fraud（検証⑥b）
    withdrawReport: [uid…],          // 受領済み密告の取下げ → report_fraud
    conflictVote: [{ uid, target }], // 2票目を他者観測に混入 → vote_fraud（検証⑥a）
    dropOwnMessages: { uid: N },     // 自提出から自発言N件削除 → union復活の検証
    evidence: { chain, censorServer, tamperServer, garbage },  // Evidence分類の明示指定
  }
}
```
（タブー系フック taboos/violate/noTaboo/soloSwapTaboo はタブー全廃（v3.2）で削除）
- **既存の固定シナリオはデフォルト値**として温存（回帰維持）。`verifyFixtureInternalConsistency` も
  scenario から期待値を導けるよう引数化。

### 2.2 マトリクス駆動 `test/simulation.mjs`（新規）
各シナリオごとに: フレッシュ Hardhat node 起動（分離のため。`hardhat_mine` 予約ブロック地雷を避け
`evm_mine` 1個ずつ＝`chain-setup.mjs mineMany` を使う）→ deploy → generateFixture → R2 server →
`runTool(--non-interactive --block N --config …)` → **##CHECK/##RESULT を解析して期待と一致を assert** →
`verifyFixtureInternalConsistency` → node/r2 停止。1シナリオ ≈ 数十秒。
- 機械可読出力（`##CHECK <id> <status>` / `##RESULT full|partial|fail|fatal`）は `mutations.mjs` の
  regex 解析を流用。各シナリオは**期待 ##RESULT** と**期待する主要チェックの status**を宣言する。

## 3. シナリオ・マトリクス（最低限これを網羅）

| # | シナリオ | 期待 | 主眼 |
|---|---|---|---|
| S1 | 標準（既存 e2e 相当・4人×2グループ・違反/密告/検閲/改竄あり） | full | 回帰維持 |
| S2 | **全員失格・提出0件（resultCount=0）** | full・adoptedCount=null受理 | **a629453 回帰**（今回のバグ） |
| S3 | ≤2名 → autoDistribute（ゲーム無し・グループ無し・roster無し） | full（自動配布経路） | Stage B autoDistribute / Stage C 自動配布採点 |
| S4 | 0名 → summary無し | not_ready（Stage B で終了） | ゲーム無しの終端 |
| S5 | グループ規模 3/4/5・端数吸収（3人組新設・5人組吸収） | full | formGroups 端数処理・member正準順序 |
| S8 | 投票: 正常ボーナス / no_vote失格 / 自己投票=no_vote / 失格者投票無効 | full | ④ vote |
| S9 | 密告: reported失格(≥2＋点超過)・報酬 floor(P/(n−1)) 定額 / <2で非失格 | full | ⑤ report・reported |
| S10 | min_chars / min_messages 失格 | full | 閾値 |
| S11 | デポジット: ineligible_deposit(B1)・外部デポジター50/50按分・端数last | full | B1 再検証・按分 |
| S12 | majorLangs: 前ブロック≥200/言語→同言語グループ化 vs ミックス | full | computeMajorLangs・formGroups 言語分岐 |
| S13 | Evidence: 検閲(chain-only採用)・改竄(byte不一致でchain勝ち)・完全性・窓外 | full | reconcile 全分類 |
| S14 | 報酬階層: block 0 / 91 / 182（getBlockRewardWei 3段） | full | 報酬式 |
| S15 | registrationCount>1（同一ハッシュ再登録） | full＋WARN | Stage A WARN 分岐 |
| S16 | merkle: 多数claim・zero-reward除外・全proof検証 | full | Stage C7 |
| S18 | 受領証明正典（S-RC）: 既読受領なし=min_chars / 投票受領なし=no_vote | full | v3.2 §6.3/§6.7 |
| S19 | 投票不正（S-VF）: 取下げ=vote_fraud / 対象矛盾2票=vote_fraud | full | 検証⑥a/b |
| S20 | 密告不正（S-RF）: 取下げ=report_fraud・不正者の密告は密告数に不算入 | full | 検証⑥ |
| S21 | チャット正典union（S-CM）: 自提出から削除しても受領証明で復活 | full | 事後削除耐性 |

（旧S6/S7=タブー系シナリオは v3.2 タブー全廃に伴い削除）

> 追加方針: **今後バグを直すたびに、その状況を再現する最小シナリオを本マトリクスに恒久追加**する
> （S2 がそのテンプレート）。

## 4. 前提・ガードレール（次セッション向け）

- **Node ≥ 20.19（または ≥22.15）が必須**。`canonical.mjs` が `module.registerHooks`（ethers CF
  フォークの specifier 解決）を使うため、現行環境の **Node 20.7.0 では e2e/gen-fixture が import 時に落ちる**。
  最初に `nvm install 20`（20.19+）→ `nvm use` してから着手。
- **自己確認の回避**: フィクスチャは `workers/` を直接（`canonical.mjs`）、ツールは `vendor/` を使う分離を維持。
  `npm run check-vendor-sync` が両者一致を担保（正典更新時は vendor 更新＋sha256取り直し）。
- **定数ピンの扱い**: ツールは confirmationBlocks 等の**公開ピン逸脱を FAIL にする**（grinding検知）。
  「サーバー正常稼働＝公開ルール遵守」の一致を見るので、フィクスチャは**本番ピン値**で生成する
  （hardhat は 64 ブロック採掘可）か、シナリオ固有定数を `--config pins` で明示宣言して回す。
  テスト環境の confirmationBlocks=5 のような値は「逸脱＝FAIL」が正しい挙動なので、シミュレーションでは使わない。
- コントラクトは**ローカル Hardhat**（`chain-setup.mjs` の 8コントラクト・config 注入）。mainnet 不触。
- **push 禁止**（契約バッチ以降のフロント非互換は継続）。コミットは main。
- 既存実装が正（byte-exact）。差異はまずツール側のバグを疑う。「改善」目的のアルゴリズム変更禁止
  （F-L5 modulo bias・F7 tiebreak 等は受容済み＝そのまま再現）。

## 5. 最初に読む（この順）

1. 本書
2. `block-verifier/DESIGN.md`（§3 検証ステージ・§5 テスト戦略）・`README.md`・`VENDOR_SYNC.md`
3. `test/e2e.mjs`（現行の1シナリオE2E駆動）・`test/gen-fixture.mjs`（本番コードでの生成・
   `verifyFixtureInternalConsistency`）・`test/chain-setup.mjs`（TIMING・deployContracts・時刻振付）・
   `test/players.mjs`（byte-exact プレイヤー）・`test/mutations.mjs`（##CHECK/##RESULT 解析の前例）・
   `test/canonical.mjs`（正典の直接 import・ethers hook）・`test/r2-server.mjs`・`test/stubs.mjs`
4. `workers/game_workers/game-master-DO.js`（writer 経路: buildBlockSummaryWithResults /
   publishVerificationManifest / reconcileEvidence / collectClaimEntriesFromSummary / autoDistribute）
5. `workers/game_workers/lib/game-result-calculator.js`（採点の全分岐＝マトリクスの網羅対象）

## 6. 完了条件（Definition of Done）

- `test/simulation.mjs` が §3 の全シナリオを回し、各シナリオで
  **期待 ##RESULT ＋ 期待チェック status ＋ 内部整合（files⇔chain⇔公開成果物）** を全て満たす。
- 少なくとも S2（全員失格）・S3/S4（自動配布/0名）・S13（Evidence 3分類）は必須。
- `node test/e2e.mjs`（既存単発）・`node test/mutations.mjs`（改ざん8ケース）も引き続き緑。
- 到達した網羅範囲と**未カバー分岐**を simulation.mjs のヘッダ or 本書 §7 に明記（silent gap 禁止）。

## 7. カバレッジ記録（2026-08-17 更新・v3.6 REQUEST3対応）

### 実行結果

- `node test/simulation.mjs`: **23/23 シナリオ緑**（S1〜S15＋S17〜S21＋S22a〜d。S5 は S5+S16 統合実装。
  旧S6/S7（タブー系）は v3.2 タブー全廃で削除。S22a〜d は REQUEST3 のライブ名簿アンカー4分類を追加。
  2026-08-17 実測はシナリオ本体合計 ≈ 235秒）
- `node test/e2e.mjs`・`node test/mutations.mjs`（8ケース）・`npm run check-vendor-sync`: 引き続き緑
- 実行環境: Node 22.21.0（`module.registerHooks` 要件 ≥20.19 / ≥22.15 を満たす。nvm 導入済みの 22 系で可）

### 実装対応（§3 マトリクス → simulation.mjs SCENARIOS）

| § | key | 実装名 | 主な網羅分岐 |
|---|-----|--------|--------------|
| S1 | S1 | default-regression | 既存 e2e 相当（8人2グループ・違反/密告/検閲/改ざん） |
| S2 | S2 | all-dq-result-count-zero | 全員 no_submit・resultCount=0・**adoptedCount=null 受理（a629453回帰）**・空マークル標識ルート |
| S3 | S3 | auto-distribute-two-players | startGrouping 内 autoDistribute 完結・グループ/evidence-report 無し manifest（null files）・50/50按分 |
| S4 | S4 | zero-players-not-ready | 応募0件 = Stage A 完了で verifiedStop（partial/exit1）。writer は 'No players found' bail |
| S5+S16 | S5 | sizes-and-merkle | 13人→5/4/4・密告DQ・報酬 floor(P/(n−1)) 定額・**merkle 葉数=正報酬行数（zero-reward除外）** |
| S-RC | S18 | receipt-canon | 既読受領なし=正典外→min_chars / 投票受領なし=no_vote（v3.2 §6.3/§6.7） |
| S-VF | S19 | vote-fraud | 受領済み投票の取下げ=vote_fraud（⑥b）/ 対象矛盾2票=vote_fraud（⑥a） |
| S-RF | S20 | report-fraud | 受領済み密告の取下げ=report_fraud・不正者の密告は密告数に不算入（1名<2名→非reported） |
| S-CM | S21 | chat-canon-union | 自提出から自発言15件削除→他者提出＋受領証明で正典復活（事後削除耐性） |
| S8 | S8 | vote-branches | 正常ボーナス / no_vote / 自己投票=no_vote / 失格者投票無効（全員の dp/bonus/total 厳密一致） |
| S9 | S9 | report-branches | ≥2＋点超過→reported＋報酬 floor(P/(n−1))=+7 / 2名でも点不足→非失格 |
| S10 | S10 | chat-thresholds | min_chars(480<500) / min_messages(5<10) 単独理由 |
| S11 | S11 | deposit-branches | B1 ineligible_deposit（unlockTime不足）・外部デポジター×2 50/50按分・端数last・保存則 |
| S12 | S12 | major-langs-block1 | 合成前summary（205ja≥200・DQ除外・en150<200）＋実manifestアンカー→prevAnchor PASS・同言語グループ＋**端数吸収→6人超→再分割（3人組新設）** |
| S13 | S13 | evidence-classification | identical / missing（削除＋チェーン専用提出の2型）/ mismatch / **invalid（ゴミバイト）**・seq完全性・no_submit回避 |
| S14 | S14a/b | reward-tier-block91/182 | getBlockRewardWei 3段（block0 は他シナリオ全部） |
| S15 | S15 | hash-reregistration-warn | 同一ハッシュ再登録 → registrationCount=2 → Stage A WARN・FAILなし |
| S22a | S22a | roster-anchor-unregistered-fail | manifest 公開済み・開始前の正典名簿登録なし。WS 提出は残すが Evidence 提出は成立せず、全員 `total_points=0`・`btcu_reward=0`、Merkle `leafCount=0`・空ツリー標識 root（R33-U-B1D01）。公開と全量再読・登録は別 alarm なので後段にも失敗を注入し、失敗印と再試行を確認。`rosterLiveAnchor` FAIL、`##RESULT fail`・終了コード2 |
| S22b | S22b | roster-anchor-overwrite-after-start-ignored | 正しい C の登録・開始後、別 hash を上書きする。開始前の最後の登録が正典のままで、上書きは正典を変えない。`rosterLiveAnchor` WARN、`##RESULT full`・終了コード0 |
| S22c | S22c | roster-manifest-missing-fail | オンチェーン登録済み・公開manifest欠落 → `rosterLiveAnchor` FAIL |
| S22d | S22d | roster-anchor-late-warn | 正しいhashの登録が`chattingStart`以後 → `rosterLiveAnchor` WARN、全体はfull |

### 一致検証の実質（タウトロジー回避の実効）

- ツールの `##RESULT`/`##CHECK` に加え、**シナリオ仕様から独立に手計算した期待値**（失格理由の厳密集合・
  deposit/bonus/total ポイント・50/50保存則・merkle 葉数と totalAmount）を公開 summary/merkle/manifest に
  対して assert。writer 経路とツール再構成が別コードのため、「手計算期待値 ⇔ writer 出力 ⇔ ツール再構成」の
  三点一致が非自明な検証になる。
- S21 の事後削除耐性は挙動的証明: union復活が無ければ min_chars 失格（残420字<500）のところ、
  期待=非失格で一致 = 受領証明付き正典が実際に削除を無効化している。

### 発見事項（初回マトリクスで確認）

1. **応募0件の正当終端はStage A**（S4）: ツールは「空の応募データ集合の固定」を検証して
   verifiedStop（entries.js:214-218）。Stage B へは進まない（当初期待の Stage B 停止は誤り）。
2. **ハーネス D1 スタブに autoDistribute の INSERT 形（result/completed_at 列付き）が未対応**だった
   → stubs.mjs に追加（本番コード無変更・ハーネス側バグ）。
3. **formGroups 端数吸収は「全端数を最小グループへ→6人超なら再分割」**: 9ja+1en/majorLangs=[ja] は
   4+4+端数2 → 4+3+3 になる（5+5 ではない）。S12 の期待値として実証・固定化。

### 未カバー分岐（silent gap 禁止・明示列挙）

- 抽選 draw-smaller-side / `counter>N*1000` throw（応募>2100 が必要・フィクスチャ重量の都合）＝ all-win 短絡のみ網羅
- calculator の 1人グループ特別ケース（members.length===1。formGroups は3人未満グループを作らないため通常到達不能）
- applyChatCaps のキャップ超過発動（WS 層が同キャップを先に強制。チェーン専用提出の水増しでのみ到達可能。
  calc-v2-test Test8c がキャップ強制自体は単体網羅）
- 宣言チャット窓外タイムスタンプの除外（メッセージ/投票/密告。全行動を窓内で振付済み。
  calc-v2-test Test7/Test8b が単体網羅）
- 検証⑥(c) 復号不能発信=vote_fraud（シミュレーションは正規WS経由のため到達不能。calc-v2-test Test5c が単体網羅）
- evidenceBytesFor の raw 選択枝（<256B ペイロード。実ペイロードは常に gzip 側が小さい）
- MAJOR_LANG_PREV_NOT_READY → ツール majorLangs FAIL 分岐（サーバー異常系＝mutations 領域）
- 複数主要言語（2言語≥200）・proportionalContribute の最大剰余端数配分
- TokenMining root 再提出（rootResubmitted WARN・検証期間内再提出の複数イベント規則）
- Evidence grace 延長（extendGrace）
- collect の複数エントリーファイル/ワーカー（`{WW}_1` 以降。生成は1ワーカー1ファイル）

> 異常系（改ざん・差し替え・grinding 検出）は従来どおり `test/mutations.mjs`（8ケース）が担当。
> 本マトリクスは「**サーバー正常稼働 ⇒ ツール結果が公開結果と一致（FAIL ゼロ）**」の証明を受け持つ。

### 追加方針（§3 の再掲）

今後バグを直すたびに、その状況を再現する最小シナリオを `test/simulation.mjs` の SCENARIOS へ
恒久追加する（S2 = a629453 のテンプレート）。
