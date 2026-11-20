# COINU 独立ブロック検証ツール — 設計書

> 2026-07-09 確定。ユーザー承認済みスコープ: **①ブロックの正当性検証のみ**。
> F1ローダー（配信JS照合）と最小復元クライアントは**別プロジェクト**（チャットゲーム補助ツール）へ分離。
> 旧称 `p2p-verifier/` → `block-verifier/` に改名。

## 0. 大原則

- **既存実装が正・ツールは byte-exact の写像**。差異が出たらまずツールのバグを疑う。
- 信頼アンカーは「ユーザーが選ぶ独立RPC経由のチェーン読取」と「公開R2データ」のみ。運営の主張（evidence-report.json の serverState 等）は照合対象であって根拠にしない。
- F-L5 受容済み: 抽選は modulo bias 込みでそのまま再現する（rejection sampling 等の"改善"禁止）。
- 検証は途中で止まっても、**そこまでに確認できた内容を平易な言葉でまとめて表示**する。

## 1. ベンダリング戦略（byte-exact の担保）

「抜き書きコピー」ではなく**正典ファイルを丸ごとコピーして本物のコードを実行**する
（`script/test-grouping/run.mjs` = 本番 GameMasterDO を直接 import しストレージ/R2をスタブする実証済みパターンを踏襲）。

```
vendor/                                  ← リポジトリ相対構造を保存（相対importがそのまま解決する）
  workers/auth_workers/lib/cors.js
  workers/game_workers/game-master-DO.js
  workers/game_workers/lib/protocol-v2.js
  workers/game_workers/lib/game-result-calculator.js
  workers/game_workers/lib/evidence-reconciler.js
  workers/game_workers/lib/timeline-check.js
  workers/game_workers/lib/char-counter.js
  workers/lottery_workers/select-winners.js   ← 例外: 行範囲抽出（下記）
```

- 例外 = lottery-DO.js: `ethers`（コミット未固定のGitHubフォーク）にモジュールトップで依存するため丸ごとは不可。
  `selectWinners` のみをマーカー付きで**verbatim抽出**。🔴 **抽出元の行範囲は `VENDOR_SYNC.md` が正典**なので、ここには再掲しない（再掲すると必ず取り残される）。
  抽選シード `keccak256(concat(randao, applicantHash))` はツール側で viem により再導出（keccakは実装非依存）。
- `VENDOR_SYNC.md` に 元パス → vendor パス + sha256 の表を置き、`scripts/check-vendor-sync.mjs`
  がモノレポ内でバイト一致（抽出分は行範囲一致）を検査する（CI/開発時ガード。独立リポジトリ化後はsha256が正）。
- 依存は root の実バージョンに固定: `viem@2.42.0`, `eciesjs@0.4.17`, `@noble/curves@1.9.1`,
  `@noble/hashes@1.8.0`, `@noble/ciphers@1.3.0`。Node >= 20（crypto.subtle / CompressionStream 前提）。

## 2. CLI フロー（ユーザー確定仕様）

1. **言語選択**: English / 日本語 / 中文
2. **RPC選択**: 毎回選択する（プリセット=publicnode。llamarpc/drpc/cloudflare-eth は実機接続不良で削除
   2026-07-12）。カスタムURLを追加でき、追加分のみ `verifier-config.json` に永続化（次回から選択肢に表示）。
   接続テスト（chainId 確認）。
3. **ブロック番号入力** →（`block{N}/` ディレクトリが既存なら再利用するか確認）
4. **段階検証**（下記 §3。各段階、前提が未成立なら「まだ〜が終わっていません」でそこまでのまとめへ）
5. **まとめ**: 検証できた内容を番号付きの平易な文で表示（時刻・ブロック番号・フォルダ位置を埋め込む）。
   別ブロックの検証 or 終了へループ。

非対話モード（テスト用・undocumented）: `--lang en --block N --rpc URL --reuse --yes --config FILE`。
`--config` で contracts / r2Base / dataDir / **`chainIdExpected`**（🔴 `expectedChainId` ではない。綴りが違うと黙って無視される）/ `pins` を上書き（Hardhat ローカル検証・fixtureサーバー用）。

## 3. 検証ステージと照合内容

対象コントラクト（mainnetデフォルト・configで上書き可）: HashStorage / TokenMining / Evidence / EthLock。
タイミング定数（START_TIME・BLOCK_TIME・TERM1/2/3）は **オンチェーン getter から取得**
（🔴 2026-09-22 訂正: **両者とも応募開始基準**である。不変量は
`Evidence.START_TIME == TokenMining.START_TIME` かつ `Evidence.BLOCK_TIME == TokenMining.BLOCK_INTERVAL`。
正典は `src/chain.js:813-815` のコメントと CLAUDE.md の「START_TIME は全レイヤーで統一されている」。
env/.env は信頼しない）。

### Stage A: エントリーデータ固定の検証（ユーザーフロー5）

1. `HashStorage.getApplicantHash(N)` 読取。未登録 → 「集計未完了」で終了。
2. R2 `entries/block{N}/` をダウンロード（応募一覧 info/{WW}_info.json ×100 → 応募データ本体
   entries/{WW}_{i}.json 全ファイル。再利用確認あり）。**info×100 が全欠落＝未集計は目立つ
   未完了メッセージで not_ready 終了**（一部欠落のみ FAIL）。**hash ファイルはダウンロードしない**。
3. ハッシュ連鎖を info+entries だけから**ローカルで再計算**（collect-DO と同一:
   **SHA-256 over UTF-8 of JSON.stringify(parse(bytes))**、per-file → {WW}_hash 相当オブジェクト
   （collect-worker writer と同形 `{block_num, status:'success', entries:[{filename,hash,number}]}`）→
   intermediate（filename localeCompare ソート・100件必須）→ root）。サーバーの中間生成物に依存しない
   ＝「ダウンロードした応募データそのもの」がチェーン登録値と一致するかを検証する。
4. 照合: root == オンチェーン hash。不一致は結論文で報告（「ダウンロードした応募データがサーバーの
   集計した応募データと一致しない」）。**イベント履歴は走査しない**（2026-07-12・無料RPCのアーカイブ
   制限に依存しないため）: 差し替え検出は `registrationCount(N)`（単調増加・リセット不能）のみで行い、
   1回=PASS / 2回以上=WARN（差し替えの可能性を可視化）。
5. **早期凍結チェック**: HashStorage が記録した登録ブロック（`getApplicantHash.updated`）の
   timestamp*1000 >= entryPeriodEnd(N) = Evidence.START_TIME*1000ベースの
   `START_TIME + (N+1)*BLOCK_TIME`。違反 → FAIL（後発エントリー締め出しの疑い）。

### Stage B: 抽選・グループ分けの検証（ユーザーフロー6）

> 表示は1ステージに統合（=== Stage B: 抽選・グループ分け ===）。**抽選側の検証にFAILが出た時点で
> グループ分けへ進まず停止**し、Stage B 全体の ❌ 結果1行で報告する（2026-07-12 ユーザーテスト反映）。

1. R2 `entries/block{N}/game_selection.json` 取得。無し → 「抽選未実施」で終了。
2. 整合検査: hashRegisteredBlock == getApplicantHash(N).updated、
   targetBlockNum == hashRegisteredBlock + confirmationBlocks、entryPeriodEnd == 公式値、
   confirmationBlocks が期待値（config ピン・grinding検知）と一致。
3. RPC から block(targetBlockNum).mixHash（=RANDAO）取得、targetBlockHash 照合。
   selectionSeed = keccak256(randao ‖ applicantHash) を再導出。
4. 総エントリー数 N を info ファイルから独立集計 → vendored `selectWinners` で当選 index を再現
   （all-win shortcut・draw-smaller-side 補集合・counter>N*1000 throw 込み）→
   players[] の globalIndex/uid/addr/bAddr/lang/depIds を全件照合。
5. R2 `entries/block{N}/game_groups.json` 取得。無し → 「グループ分け未実施」で終了。
6. groupSeed = keccak256(randao ‖ applicantHash ‖ utf8"group") 再導出・公開値と照合。
   前ブロック `games/block{N-1}/summary.json` から computeMajorLangs を再現（vendored GameMasterDO、
   R2スタブ経由）→ formGroups 再現 → グループ構成・**メンバー正準順序**（タブーrotationの基準）を全件照合。
   R33-U-GROUPING の組分け規則は正典仕様書 `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §3「組分け」を参照。
   players<=2 の autoDistribute ブロックは Stage C の autoDistribute 検証へ分岐。

### Stage C: 採点・報酬・オンチェーン確定の検証（ユーザーフロー7・D2込み）

1. `TokenMining.blockStates(N)` 読取。root 未提出 → 「結果未確定」で終了。
2. R2 取得: `games/block{N}/summary.json`・`games/block{N}/group{G}.json`（全グループ・提出物アーカイブ）・
   `games/block{N}/roster/*`・`merkle/block_{N}.json`・`verification/block{N}/manifest.json`・`evidence-report.json`。
   （2026-09-30 S3R3 の注記: 通常モードでも `group{G}.json` と `roster/*` が取れない場合は任意取得の欠落として扱う。採用 Evidence が0件の組は `check.stageC.scoring` が FAIL になる。取れない資料は検証できず、その欠落自体は改ざんの証拠ではない。）
3. **D2 manifest照合**: manifest core = {blockNum, algorithm, rules, files} の sha256 ==
   `HashStorage.getResultHash(N)`。files の各エントリ == ダウンロード済み各ファイルの sha256
   （＝アーカイブ差し替え検出）。rules の公開定数（minChars=500/minMessages=20/caps/
   maxReports=2/blockRewardWei/期間）をツールのピン値・オンチェーン値と照合。
   （2026-09-30 S3R3 の注記: 宣言済みの `group{G}.json` または `roster/*` を取れない場合、`manifestFiles` は `unavailable/reconstructed` の warn になる。その組は Stage B の名簿と採用 Evidence だけで再採点する。WS の提出だけがあれば再採点との差が生じ得る。正本は `block-verifier/README.md` と仕様書 §5.2。）
4. **Evidence reconcile 再現**: `ResultSubmitted` イベント全走査（vendored fetchResultEvents/
   verifyCompleteness: seq 1..resultCount(N) 完全性）→ vendored validateResultBundle + selectAdoptedResults
   で採用集合を独立再導出 → アーカイブ submissionsRaw とチェーン採用分の byte 照合
   （`archiveChainConsistency` は情報表示で pass 固定。`serverState` は分類のメモで不正の証拠ではない。握り潰し・改変は独立再採点の `summaryMatch`／`groupGameResultsMatch` と `evidenceReportMatch` が検出する。`evidence-report.json` 自体は根拠にしない）→ 採点入力となる正準提出集合を確定。chatWindow は Evidence.chatWindow(N) から。
   `validateResultBundle` はイベントの sender が名簿本人の addr でなければ `sender_mismatch` で採らない（S3R2-U-8）。`check.stageC.rosterCommitment` は名簿値 C を独立に作り直し、開始前の正典行と照合する（S3R2-U-8b。正本は `block-verifier/README.md` と仕様書 §5.2）。
   R33-U-B1D01: 開始前の正典名簿登録が無ければ、GM と通常モードは Evidence／WS 提出を採らず全員0点とする。読取失敗は結果を推測せず停止する（規則の正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §5.2）。GCP 緊急入口の Stage B の停止条件は `block-verifier/README.md`「結果 manifest を権威にしない緊急復旧」を参照。
5. **採点再現**: グループごとに vendored `calculateGroupResults`（本物）を正準提出集合＋検証済み
   グループデータで実行。Lock 再検証は EthLock.getLock を選択RPCで読取（本番と同じ検査:
   unlockTime*1000 >= START_TIME+(N+2)*BLOCK_TIME 等）。50/50 depositor 按分・getBlockRewardWei・
   BigInt 按分順序まで本物のコードで再現。autoDistribute ブロックも同経路で再現。
6. **summary.json 照合**: 再構築した summary と公開 summary.json を byte 照合。
   本番 schema v2 の summary には行別 `claimed` も `updatedAt` もなく、listen-worker は summary を
   書き換えない。claim 集約は別ファイル `claim-status.json`、行別状態は group/auto 詳細 page へ書く。
   schema v1 との互換検証に限り、summary 内の `members[].claimed` / `depositor_results[].claimed`
   と時刻メタを中立化する。採点関連フィールド完全一致を PASS 条件とする。
7. **Merkle 照合**: 公開 summary（→⑥で自前再現と一致確認済み）から vendored ロジックで
   claim entries 収集（key ソート・checksum・>0のみ）→ ツリー再構築（double-keccak leaf・
   duplicate-last padding・sorted-pair）→ root == merkle/block_{N}.json の root == オンチェーン root。
   全 items の proof を root に対して検証。
   配分0件のブロック（全員失格等）は空ツリー標識ルート
   `keccak256(utf8("bitcoinu:empty-merkle:{N}"))` が提出される（root=0 はコントラクトが拒否し
   「未提出」と区別不能なため）。この値はどの leaf にもならないため請求は成立しない。
   vendored `buildMerkleTree` が同値を再導出するので照合経路は通常ブロックと同一。
8. **タイムライン照合**: vendored timeline-check の公式で宣言時刻とチェーン窓を照合。
   `MerkleRootSubmitted` イベント履歴（再提出は検証期間内のみ＝F-EL1規則）・verificationStartedAt →
   検証期間・請求期間を計算し、最終まとめの文言に埋め込む。

### FAIL / WARN 方針と終了コード

- **FAIL**: グラインディング系（confirmationBlocks のピン逸脱・前回登録の RANDAO ターゲットが
  観測可能になった後の applicantHash 再登録＝再ロール・早期凍結）、採点に影響するルールの
  ピン逸脱（minChars / minMessages / chatCaps / maxReports / minDepositWei ほか。`tabooMinLength` は存在しない）、
  登録イベント走査を広げても全登録が見つからない（＝登録履歴を証明できない）、
  manifest が evidence 無効を宣言しているのにチェーンに提出が存在する、等。
  正当な定数変更は `--config` の pins 上書きによる**明示承認**でのみ許容（README参照）。
- **WARN**: 真に無害な運用差のみ — 同一ハッシュでの登録リトライ、結果ハッシュの再登録可視化、
  **旧形式**（schema v3 未満）の result page における claim 検知後の `gameResults[].claimed` 更新
  による manifest sha256 不一致（降格条件は `settleManifestParked`。summaryMatch と
  group{G}.json / gameResults 内容照合が全て PASS のときだけ）。
  🔴 **schema v3（周13 の乙）以降、この WARN は本番では発生しない。**
  行別 claimed は manifest 対象の `group{G}.json` / `auto-results.json` から
  **封印外の per-group overlay** へ分離され、集約は `claim-status.json` にある
  （どちらも `artifactKeys` に載らない）。したがって v3 の result page は **immutable** 扱いで、
  claimed の注入は `manifestFiles` / `groupGameResultsMatch` の **hard FAIL** になる
  （`test/mutations.mjs` の `group-claimed-mutation` が固定）。
  判定源は `isClaimMutableArtifact`（`src/stages/results.js:167-180`）ひとつだけで、
  `schemaVersion` が欠落・不正型なら**推測せず安全側の不変扱い**に倒す。
- **運用禁止（manifest 不一致の「自己修復」）**: Merkle root 提出後に manifest を再生成して
  `registerResultHash` を再実行しない。`HashStorage.registerResultHash` は同一ハッシュでも
  `resultRegistrationCount[blockNumber]++` を無条件に実行するため、`check.stageC.resultReregistration`
  が WARN になる。さらに再アンカーの登録ブロック時刻は `verificationStartedAt` 以後なので、
  `check.stageC.manifestAnchor` は `anchored_after_root_submission` として hard FAIL になる。
  したがって再アンカーは不一致を PASS に戻せず、検証結果を厳密に悪化させる。
  元のアンカーと公開バイト列を保存し、不一致の原因調査と事故対応を行う。
- **終了コード**: 0 = Stage C まで自然完走し FAIL 無し / 1 = FAIL 無しだが正当な未完了ゲートで停止
  （not-ready: applicantHash未登録・抽選未実施・root未提出等）/ 2 = FAIL あり /
  3 = fatal（ステージ例外＝`check.main.fatal` 記録・設定エラー・stdin EOF）/
  **4 = 緊急固定一式を書き出したが結果に影響する差分あり（`emergency_with_differences`）** /
  64 = usage エラー。正典は `src/index.js` の `EXIT_CODE_OF`。
- **機械可読出力**（非対話モード）: 最終まとめの後に全チェックを `##CHECK <id> <status>` 行で、
  最後に `##RESULT full|partial|fail|fatal|emergency_with_differences` を stdout へ出す
  （i18n 非依存。テストが解析する）。

### まとめ（ユーザーフロー8）

各 Stage の結果（PASS/WARN/FAIL/未実施）を蓄積する `report` コンテキストに集約し、
①エントリー固定（時刻付き）②抽選・グループ分けの無作為性（RANDAOブロック時刻付き）
③採点・配分のルール準拠＋オンチェーン提出（提出時点・検証期間・請求期間付き）を
選択言語の平易な文で出力。途中終了でも到達分は必ず表示。

## 4. モジュール構成

```
src/
  index.js       CLIエントリ・メインループ（言語→RPC→ブロック→段階実行→まとめ→ループ）
  i18n.js        en/ja/zh メッセージカタログ
  prompts.js     readline ヘルパ（選択・y/n・数値・Enter待ち）
  config.js      デフォルト（mainnetアドレス・R2ベース・RPCプリセット）+ verifier-config.json + フラグ
  chain.js       viem client（fallback構成）・コントラクト読取・イベント走査・タイミング定数取得
  r2.js          R2ダウンロード + block{N}/ キャッシュ + 再利用
  json-utils.js  sha256(JSON.stringify(parse()))・byte比較・差分整形
  report.js      ステージ結果の蓄積と最終まとめ生成
  stages/
    entries.js selection.js grouping.js results.js
vendor/          §1 のとおり
scripts/check-vendor-sync.mjs
test/            §5 のとおり
```

## 5. テスト戦略

1. **fixtures生成** (`test/gen-block-fixture.mjs`): calc-v2-test.mjs のプレイヤーファクトリ（実鍵・実署名・
   実ECIES・実chatHash）を再利用し、偽ブロック一式（entries 100シャード → game_selection →
   game_groups → group アーカイブ → summary → merkle → manifest）を**本番コードで**生成。
2. **ローカルR2** (`test/r2-server.mjs`): node:http 静的サーバー。GET /<key> → fixtures ディレクトリ。
3. **ローカルチェーン**: `npx hardhat node`（chainId 31337）に HashStorage/TokenMining/Evidence/EthLock
   をデプロイ（Hardhat/bitcoinu/scripts/test_local.js の deployFresh パターン）、applicantHash/resultHash/
   merkleRoot を登録、Evidence へ ResultSubmitted を実投稿。
4. **E2E green**: ツールを非対話モードで実行 → 全ステージ PASS を確認。
5. **mutation tests**: エントリー1バイト改変→Stage A FAIL / summary改変→Stage C6 FAIL /
   merkle改変→C7 FAIL / 提出物差し替え→C4 anomaly / 早期凍結違反→A5 FAIL / 途中終了の部分まとめ表示。

## 6. ガードレール（再掲）

デプロイ・mainnet書込・本番シークレット・Alchemy webhook 不触。GameRewardModal.js 不触。
正典（workers/・Hardhat/bitcoinu/contracts/）は一切変更しない。コミットは main、**push 禁止**。
