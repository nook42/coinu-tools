# COINU 独立ブロック検証ツール（block-verifier）

公開データ（R2）とEthereumチェーンだけから、COINUの各ブロックの
**エントリー固定 → 抽選 → グループ分け → 採点 → 報酬按分 → オンチェーン確定** を
独立に再導出し、運営の公開結果と byte-exact に照合する対話式CLIツール。

> 旧称 `p2p-verifier/`。F1ローダー（配信JS照合）と最小復元クライアントは
> **別プロジェクト（チャットゲーム補助ツール）へ分離**（ユーザー決定 2026-07-10）。
> このツールは「①ブロックの正当性検証」専用。設計の全容は [DESIGN.md](DESIGN.md)。

## 何を保証するか

**D-08 の形式切替**: 現行ツールは blockAddress に `address`・`pubKey`・`nostrPubkey` の3キー、正典名簿に Nostr 鍵を要求する。切替前の2キー応募・5キー名簿のブロックは `check.stageA.entryKeyIntegrity` と名簿再構築の経路で FAIL になる。E2E の合否は切替後のブロックだけで判定し、テスト環境の応募・ゲーム状態・R2 名簿をリセットしてから走らせる。配備順は entry worker 100本 → game workers → フロント・復元クライアント `dist`（`docs/OPS_TASKS.md` §5）。

- **①エントリー固定**: ダウンロードした全エントリーデータのハッシュ連鎖が、HashStorage に
  登録された applicantHash と一致（登録時刻・登録回数・**早期凍結**=エントリー期間終了前の
  登録がないことも検査）。
- **②無作為性**: 当選者とグループ分けが「登録ブロック+confirmationBlocks の RANDAO」だけから
  既定アルゴリズム（modulo bias 込み・F-L5受容どおり）で決定論的に再現できること。
  メンバーの正準順序（タブーrotationの基準）まで照合。
- **③採点・配分**: プレイヤー署名付き提出物（＋Evidence コントラクトのオンチェーン提出。
  握り潰し・改変はここで検出）から本物の採点コードで再計算した結果が、公開 summary.json・
  各 `group{G}.json` の `gameResults`／`canonicalTimeline`・merkle ツリー・TokenMining の
  AdminCommit ルートと一致すること。結果画面のチャット・投票・密告（復号済み標的を含む）も
  採点器が確定した union と完全一致させ、検証期間・請求期間のタイムライン整合も検査。
- **④ZKP提出**: 各rootが証明付きかshadowの証明なしか、提出時に記録されたvkey世代、
  verifier / vkey / guestSourceHash、現在の`proofRequired`を区別して表示する。証明付きなら
  提出tx（中継コントラクト経由なら call trace 内の一意な TokenMining 呼び出し）のproof selector・
  356-byte proof・480-byte（15語。15語目は名簿 manifest の hash＝R31-U-C）public valuesを検査し、public valuesは公開チェーン/R2から
  共有ZKP入力コアで再計算する。word7 は calldata の `prevRegistrationIndex` が名乗った
  `resultRegistrationAt(N-1,index)` から作る。名乗った行がグループ分け時点の行かは別の証人検査
  （`check.stageC.zkPrevRegistrationWitness`。見張り役の `firstSeenAt` を締切にする）が警告する。 N が組分けの後・N+1 の名簿の登録の前に同じ主要言語で登録し直された盤では、組を再現する正しい行を名乗った証明にもこの警告が出うる（配分と root は変わらない。`docs/external-audit/stage4-review/step2c/WIRE_DESIGN_RESULT.md` §2.1 の K7 の必須条件の注）。
  取得不能をshadow扱いで通すことはしない。
- 検証用アーカイブ一式は sha256 manifest として HashStorage（resultHashes）にアンカーされて
  おり、**事後差し替えも検出**する（D2）。

保証しないこと: 運営コードの「正直さ」そのものの証明（それは別プロジェクトの
ローダー＝配り分け排除と、ソース公開・再現ビルドの範疇）。

## 使い方

```bash
cd block-verifier
npm install
node src/index.js        # 対話式: 言語(en/ja/zh) → RPC選択 → ブロック番号 → 検証 → まとめ
```

- ノード選択は publicnode・Alchemy・Infura・その他カスタム RPC の4択。Alchemy / Infura は API キーを伏せて入力し、URLを組み立てる。カスタム URL は `verifier-config.json` に保存する。publicnode では、確認できる範囲の説明後に「続ける／選び直す」を選ぶ。
  **全部の検証には、過去の状態を読めるアーカイブ対応 RPC が必要**。接続直後、ノードごとに1万ブロック前の `eth_call`（mainnet は `WETH.totalSupply()`）を1回だけ試す。若いローカルチェーンや一時障害は「判定不能」とする。試験結果にかかわらず、必要な個々の読み取りを実際に試す。
  契約の配備高を過去のコードから探せない場合、管理者の交代の全履歴と現在状態への履歴再現は未検証になる。root・proofはアンロック時刻付近から走査し、早期提出・イベント欠落・calldataの不正を引き続き検査する。genesisからの全履歴走査で代用しない。時刻に対応する高さはheadから倍々に遡って探し、code 4444で古いブロックを拒否された場合は、そのヘッダを要する検査だけ未検証にする。Evidenceの累積値は、安全ブロックの提出数を読んだ直後に同じ高さで確保し、提出ログの走査後に照合する。
  Stage C の EthLock `getLock` は `game_selection.json` の `targetBlockNum`（K11）を読む。K11 を latest で代用しない。その読み取りが型付き `ArchiveUnavailableError` を返した場合だけ未検証にし、応募の申告明細が揃えばそれを仮定した計算・比較を続ける。依存する検査は合格にせず、検証材料の params は保存したまま、別欄の `comparisonStatus` に比較結果を記録する。明細が無ければ採点を省き、公開 summary と Merkle・チェーン上の請求データ・時系列の照合を続ける。安全ブロック（head−64）の Evidence は通常どおり読み、読める検査は従来どおり実行する。
  publicnode の説明とまとめは同じ検証領域の定義・行名を使う。「Stage C — ZKP の公開値」と「Stage C — 証明の時点の状態」を分け、証明高の状態を型付きで取得できない場合だけ、公開値を語ごとに検証済みの応募登録・見出し、追記履歴、閉鎖後の安全ブロック、請求チャンクのログと照合する。期待値を確定できない語と理由は `zkPublicValues` の params に残し、一部でも未検証なら公開値の行も未検証になる。futureAnchorsHash は既存の独立検査で扱う。まとめは領域内の全検査から判定し、配布方式により対象が無い検査は「対象なし」、証明時点の状態を読めない検査は「未検証」と表示する。まとめの最初に確認できた範囲・できなかった範囲を表示する。前提不足の比較に食い違いがあれば冒頭と `##COMPARISON <id> fail archive_unavailable` に残す。前提未検証は `##RESULT partial` / exit 1、独立した検査の FAIL は従来どおり exit 2。公開 summary とチェーンの root の一致は、ロック適格性・報酬の公正さの保証とは別である。`merkleRebuild` は木を構築できたことを示し、root の照合は別検査で行う。HTTP の生の要求・応答は通常のエラー表示で短文化する（検証データの書換えはしない）。
  （2026-10-23・S45R2 X2-GAP-09）Evidence の取得は seq 400件ずつで、1つの Eth ブロックの提出は1応答にまとまる。1ブロックに最大長の提出が集まると、応答の上限の小さい RPC では `[getlogs] block {n} alone exceeds the provider limit` で止まる（誤った PASS は出ない）。0埋めの最大長は1件約1.86M gas の見積もりで、ガス上限60M なら約32件・約8.35MB、EIP-7934 のブロックの大きさの上限で約64件・約16.7MB になる。GM が読めたブロックでも止まりうる。そのときは応答の上限の大きい `--rpc` に替える。
- 検証メニューの「3) 自分の応募が抽選に含まれていることを確認」では uid または `https://bitcoinu.org/user/?id=...` とブロック番号を指定し、未検証ならまず uid の下4桁（4桁未満は先頭を0埋め）の上2桁の置き場（収集の worker の番号）の一覧1個と、そこに載る同じ置き場の応募データ本体だけを自動で読み、有無と抽選への使用が未検証であることを示してから、公開応募データ全件を Stage A で検証するか尋ねる。No なら最初の確認で終わり、Yes なら全件検証後に結論を1行だけ示す（自分の応募が検証済みの完全な写しに含まれ、Stage A と同じ接続の今の `TokenMining.hashStorage()` と設定の一致に加えて、抽選の再現で Stage B の抽選の検査がすべて pass になった場合に保証し、Stage A と配線が一致して完全な写しに含まれていなければ抽選を再現せず含まれていないことを検証したと示し、検証できなかった場合はその旨を表示する）。メニュー1と3の結果は同一実行中でファイルとチェーン登録を再確認してから質問せずに相互に再利用し、別の実行でも `data/block{N}/` の保存を質問せずに使うが Stage A は改めて検証し、保存された「検証済み」の旗だけでは合格にしない。
- メニュー1と3では、同一実行中の抽選の再現も、全検査が pass で応募データ・抽選ファイル・チェーン登録が変わっていない場合に相互に使い回す。
- ダウンロードは `data/block{N}/` にキャッシュされ、再実行時に再利用を選べる
  （非対話モードでは `--reuse` を明示した場合のみ再利用。無指定はフレッシュダウンロード）。
- R2本文は`Content-Length`と実stream bytesの両方で上限検査する。主な上限は
  selection 96 MiB、lean summary v2 8 MiB、group archive 48 MiB、ゲーム成果物合計24 GiB。
  現行最大2,100人・420組・1人10デポジットに加え、Evidence生2 MiB×5人とJSON escape増幅まで
  実測して決めた値。表示詳細はmanifest固定のgroup/pageを逐次読む。応募総数には上限がないため
  entries全体には固定合計を置かず、5 MiB chunkを
  逐次hash・解放する。cache予算到達時は保存だけを省略し、正常な検証は続行する。
- 検証が途中段階で止まっても（例: 抽選未実施）、**そこまでに確認できた内容を平易な言葉で
  まとめ表示**する。
  「検証できたこと」の各行は、その領域の記録と必須検査がすべて PASS の場合に保証される内容を表示する。応募データの行は抽選の再現も PASS、抽選・グループ分けの行は結論②が裁量なしと言い切れる場合に限る。URL を含む保証文は公開 R2 から取得した場合だけに限り、`--artifact-dir` または `--emergency-source` で手元の写しを読む場合は既存の短文に戻す。条件を満たさない検証済みの行は「検証できた」と表示する。応募データの場所は実際の `r2Base` の `entries/block{N}/`、公開結果は `https://bitcoinu.org/block/?n={N}` を示す。行名・未検証と対象なしの表示は共通定義のまま、結果まとめの見出しは `====` の線の直後に表示し、番号付き結論の見出しは「✅まとめ:」とする。
  番号付き結論と未検証の欄では、ZKP の状態を⓪として各欄の先頭に表示する。証明つきの保証には、世代の verifier が vendor の `ZKP_EXPECTED.verifier`（Succinct の SP1 Groth16 verifier v6.1.0）と一致し、公開値の領域が検証済みで保証文の条件を満たすことと、証明時点の状態の領域が検証済みであることを求める。verifier の不一致、公開 Merkle ルートまたは Evidence との不一致は⓪の保証より優先して未検証にする。公開値を保証できるときは、⓪に公開値の結び付きは確認できたが証明つきの分配データまたは採用表の照合が不合格のため証明の保証を出せない旨を表示し、理由は問題一覧と③に任せる。公開値を保証できないときは、⓪にも③と同じ理由を出す。証明時点の状態の行の保証には、証人などの検査に加えて verifier の照合の PASS を必要とする。公開値を保証できても証明時点の状態が未検証なら、将来のアンカーとチェーンの一致が未検証であることを示す。前ブロックが無い場合や見張り役の記録を指定しない場合の証人検査の SKIP は、既存の領域行の表示条件のまま扱う。時刻の窓が成立しない no-game で root 省略が終端になった場合は⓪を表示しない。
  SKIP・未到達の詳細一覧は省き、未検証の範囲は「検証できなかったこと」と件数行で示す。WARN の詳細は過去状態の型付き読取不能だけを省き、その他の警告と FAIL の詳細は表示する。
  正典（vendor）の console ログは通常表示しない。`DEBUG=1 node src/index.js` など、`DEBUG` 環境変数が存在するときだけ表示する。
- 非対話モード（テスト・CI用）: `--non-interactive --lang en --block N --rpc URL --config FILE`
  （`--config` で contracts / r2Base / dataDir / chainIdExpected / pins を上書き）。
  最終まとめの後に機械可読行 `##CHECK <id> <status>`（全チェック）と
  `##RESULT full|partial|fail|fatal` を stdout に出力する（i18n 非依存・テストが解析）。

### 前ブロックの旧版を使った組分けの検証（`--observer-source`）

ブロック N の結果ハッシュが N+1 の組分け後に再登録されると、公開 R2 に残る N の
`summary.json` は最新版だけになる。その場合も Stage B は N+1 の公開 `summary.majorLangs` で
実際の `game_groups.json` を再現し、組の検査を省略しない。主要言語そのものを検証するには、
見張り役の保管庫を読める人が `tools/r2-backup-observer` の `materialize-block` で N+1 を書き出し、
その出力ディレクトリを渡す。

```bash
node src/index.js --lang ja --block 12 --non-interactive \
  --rpc https://YOUR_TRUSTED_RPC \
  --observer-source /absolute/path/to/materialized-block12
```

- `--observer-source` は任意で、既存の `--observer-manifest`（観測時刻の証人）とは別の入力である。
- 出力は `_observer/generation-index.json` を持つ完了済み `materialize-block` アーカイブで、
  検証対象を M とすると前ブロックの `verification/block{M-1}/manifest.json` と
  `games/block{M-1}/summary.json` の全保存世代を含む必要がある。M の応募終了前の
  `bitcoinu:roster:{M}` 登録を除き、応募終了から確定 grace による `chattingStart` の直前までの
  最後の登録を名簿の正典とする（`selectCanonicalRosterRegistration()`）。その hash の
  応募終了以後の最初の登録時刻と `chattingStart` の早い方を組分け上限とする
  （`deriveGroupingUpperBound()`）。正典が無ければ `chattingStart` を使う。
  取得先の R2 名簿 manifest の取得が例外で失敗した場合は、履歴例外へ進まず理由を
  `stageB.previousResultVersionSearch.error` に fact としてだけ残す。この値は `##CHECK`・まとめ・警告には出力されない。
  結果登録履歴は状態 getter の登録時刻で上限位置を二分探索し、対象範囲の
  `ResultHashRegistered` ログの件数・添字・最終行 hash で網羅を確かめる。
  実際に候補・採用するログ行は状態 getter の hash・登録ブロック・signer と突き合わせる。
  緊急経路でもこの窓の中の版だけを採る。窓外の登録（組分け後の固定一式を含む）は
  N+1 の主要言語の根拠にしない。窓内版に組と宣言主要言語を再現するものがあれば採る。再現する窓内版が無く、1版以上の manifest または summary が未保存なら、
  チェーン錨つきの N+1 正典名簿と N+1 summary の宣言主要言語で進み、
  `##PREVIOUS_SUMMARY_LOST` と日本語・英語・中国語の警告を出す。
  J1 の `--manifest` 書き出しで「消失」と出た場合、それはこの書き出しに版が無いという意味であり、後の台帳の保存世代は採用せず別欄へ記録される。保管庫の後の N の版を確認してから告知する。
- 通常 Stage B が履歴例外へ入るのは、現在目印が組分け上限後にあり、窓内の最新行の hash が現在目印と異なる場合だけ。上限は正典名簿 hash の応募終了以後の最初の登録時刻と `chattingStart` の早い方。 N の再登録が N+1 の組分けの後・上限以前に着いた盤では例外へ入らない。そのため、組分けが旧版で行われていても `check.stageB.groupsMatch=fail` になる（`--observer-source` を渡しても同じ・既知の制約・S45R2 X1-4-01）。緊急の前ブロック入力の選択は、下記の記録方式に従う。宣言主要言語で公開の組を再現できても、`--observer-source` が無ければ `##OBSERVER_SOURCE_REQUIRED` と warn を出す。保管庫を渡した場合、窓内に未保存版が1つでもあり再現版が無ければ、保存された正典名簿で組を照合できるときだけ消失の warn にする。正典名簿の保存世代も無ければ通常モードは従来どおり fail とし、緊急入口の正典 C による再構成へ進む。全版保存済みで再現しなければ fail にする。消失の warn には、保存済みの不一致版と未保存版の添字・hash を別々に示す。

WR-4 の記録方式では、緊急入口は `entries/block{N+1}/game_groups.json.prevResultRegistration` の行を優先し、その行の保存世代で組と宣言主要言語を再現する。記録が無い当選0〜2名の盤、および明示された登録0件の盤だけ現在の最新行を採る。記録が不正・欠落した当選3名以上の盤は停止する。通常 Stage B の上記入口と M1 fixture の向きは維持するため、組分け後・正典名簿の登録前に N を登録し直した盤の通常 `groupsMatch=fail` は既知の制約として残る。Stage C の見張り役を基準とする証人は変更しない。
- 保管庫の公開読み取りを許すか、読み出し proxy を配備するかは、配備時にユーザーが選ぶ運用事項である
  （第三者が運営への都度の依頼なしに、常設の公開読み取りか読み出し proxy で保管庫を自分で読めることが前提）。
  この CLI は保管庫を自動公開しない。

### 運営のサイトが信用できないときの取得先（`--source-base`）

Cloudflare 上の公開先（既定 `https://r2.bitcoinu.org`）が信用できない事故では、運営が別管理の
バックアップの読み取り専用 URL を告知する。**取得先だけ**を差し替えて、平常時と同じ厳しさで検証する。

```bash
node src/index.js --lang ja --block 12 --non-interactive \
  --rpc https://YOUR_TRUSTED_RPC \
  --source-base https://storage.googleapis.com/BUCKET/r2-observer/v1/bases/incident-2026-09-18-block12
```

- 既定（フラグ無し）との違いは**ダウンロード元だけ**である。契約アドレス・chain ID・検査の固定値（pins）は
  ツールに焼き込まれたままなので、**チェーンと突き合わせる検査は1つも弱まらない**。合わない公開データは
  従来どおり FAIL になる。
- 🔴 **告知に `--config` を使わせてはならない。** `--config` は同じファイルで契約アドレスや pins まで
  差し替えられるため、偽の告知の被害が大きくなる。取得先を替えるだけなら `--source-base` で足りる。
- `--config` と同時に渡した場合、取得先は `--source-base` が勝つ（告知の1行が config に上書きされない）。
- URL の末尾スラッシュは有無どちらでもよい。
- `--artifact-dir` / `--emergency-source` とは併用できない（usage エラー・exit 64）。`--artifact-dir` の公開成果物と `--emergency-source` の Stage A〜C の採用入力はローカルから読む。ただし緊急書き出しは、上書き前の保存確認に限り `r2Base`（既定 `https://r2.bitcoinu.org`）の公開 R2 固定 manifest／summary キーを live で読む。緊急書き出しのこの取得先を変える設定口は `--config` の `r2Base` であり、`--source-base` は併用できない。
  どちらが勝ったのか分からないまま「告知された場所を検証した」と誤解しないための排他である。
  （`--artifact-dir` と `--emergency-source` を同時に渡したときの既存挙動は従来どおりで、
  緊急モードが勝つ。）
- 告知が本物かは、告知文の `keccak256` が `HashStorage.getOtherHash(keccak256("bitcoinu:incident:{N}"))`
  と一致することで確かめる。手順と告知文の雛形は
  [`docs/EMERGENCY_CLOUDFLARE_COMPROMISE_RUNBOOK.md`](../docs/EMERGENCY_CLOUDFLARE_COMPROMISE_RUNBOOK.md)
  の「第三者への告知」にある。
- **S3R2-U-8 の名簿値 C**: `keccak256(abi.encode(keccak256(manifest 実バイト), memberRoot))`。`memberRoot` は manifest が宣言する全 group の実バイト中の本人アドレスから作る。Stage B と Stage C は C を正典行・再構成物・保存実バイトから独立照合する。Evidence は名簿本人が所属証明つきで提出し、1人最大3件。正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §5.2。
- 名簿目印（`bitcoinu:roster:N`）は、HashStorage の追記履歴から応募終了以後・確定した grace で見たチャット開始より前の最後の登録を選ぶ。
  履歴が読める場合、開始以後の登録は採用せず、件数があれば `check.stageC.rosterLiveAnchor` を warn にして表示する。通常モードで開始前の正典行が無いときの提出物0件・全員0点の再計算は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §5.2 に従う。GCP 緊急入口の Stage B は下記の名簿選択条件に従う。
  履歴 getter のない許可リスト内の旧 HashStorage（現 mainnet テスト配備）では現在値を legacy として照合し、開始以後・応募終了前の登録は fail になる。履歴の読取失敗時も通常検証は現在値で判定し、再登録の確認は skip とする。
  **既知の制約（R33-B-1dr-01、旧版のテスト配備だけ）**: `resolveRosterSubmissionEligibility()` は旧版の未登録 `getOtherHash` 応答 `(zero hash, updated=0)` を GM の `calcRosterSubmissionEligibility()` と異なる形で記録し、`evidenceReportMatch` を誤って FAIL にしうる。また `getOtherHash` の RPC `-32603` を `src/chain.js` の `getOtherHash()` が null にすると、開始前登録のある正直なブロックも名簿なし・全員0点で再計算しうる。総合 FAIL は既存の `check.stageC.rosterLiveAnchor` でも生じるため、誤るのは検証 FAIL の帰属であり、GM の配布採点には及ばない。旧版でこの FAIL を採点の誤りと断定せず、別の RPC で名簿を読み直す。本番は履歴付き HashStorage の再配備を前提とする（採否の正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §5.2）。
  同じ旧 HashStorage では `getResultHash` の RPC `-32603` が `isInternalRpcError`（`src/chain.js:41-48,457-467`）で拾われない文面の場合、`check.stageC.manifestAnchor` が fail ではなく `not_anchored` の warn へ落ちうる（同 `src/stages/results.js:1463-1470,1583-1592`）。現 mainnet テスト配備の E2E でこの warn を合格と扱わず、別の RPC で再実行して登録値を照合する。
  応募終了以後の最初の登録と正典の hash が違えば `check.stageC.rosterReregistration` が warn する。同じ hash に戻したやり直しはツールでは表示しない。回数はチェーンの `otherRegistrationCount` で読む。
  公開の組と異なる compact 枠で真正な提出が見つかった場合は
  `check.stageC.evidenceContradictsGrouping` が warn する。これらの warn は合否を変えない。
  ただし `check.stageC.rosterLiveAnchor` の warn が `on-chain roster anchor could not be read` または `anchor registration time could not be read`（`src/stages/results.js:3760-3765`）なら名簿のチェーン読取ができていない。合格と扱わず別の RPC で再実行し、pass／fail を確かめる。
  「名簿の正典と公開物、および他の必須検査が合格する」は、告知された取得先が**復旧版の公開データ**
  （R2 を復旧版へ戻した後の世代、または再計算した固定一式を同じ相対キーで公開したもの）を指している場合である。
  復旧前の世代を指した取得先では、result manifest のアンカー検査なども不合格になる。

### 結果 manifest を権威にしない緊急復旧

結果 manifest の保存世代が無い、またはその申告を信用できない **groupGame・自動配布（応募1〜2名）・応募0名** ブロックでは、
運営が `--emergency-authority=gcp` を明示して GCP 保存物とチェーンから固定一式を再構成できる。
`--emergency-source` と `--emergency-out` は従来どおり両方必要。

```bash
node src/index.js --lang ja --block 12 --non-interactive \
  --rpc https://YOUR_TRUSTED_RPC \
  --emergency-source /absolute/path/to/block12-observer \
  --emergency-out /absolute/path/to/block12-result \
  --emergency-authority=gcp
```

この入口は公開の結果 manifest を読んで採用世代を決めない。応募者の登録と RANDAO から
`game_selection`、前ブロックの実際に使った主要言語と再計算した組から `game_groups`、
Evidence の時刻から groupGame summary を選ぶ。自動配布と応募0名では、保存 summary や公開結果が無くても
チェーン由来の応募者・選出者・配布額から正典 writer の結果を再計算する。自動配布の
保存 summary と auto-results は比較の証跡だけに使う。深さ・バイト数・正準性を満たさない
保存世代は hash と理由を差分に残して評価から外し、試算には auto-results の保存写しを渡さない。
比較記録には保存値そのものを写さず、SHA-256・バイト数・型だけを残す。
N≥1 の groupGame（この段落から下の N=0 の段落までは、N を検証対象の `--block`、N−1 を前ブロックと書く）では、応募終了以後・確定した grace で見たチャット開始より前の最後の `bitcoinu:roster:{N}` 登録を正典とする。manifest と宣言された全 group の保存実バイトから値 C を再計算し、正典行に一致する保存名簿があれば、その `indexSha256` と再構成索引が一致する `game_groups` 世代を候補にする。一致する保存世代が無ければ、保全済みの選出者と `game_groups` から GM と同じ manifest・group 実バイトを組み、再計算した C が正典登録と一致する世代だけを候補にする。候補は実際の組と N の保存 summary が宣言する `majorLangs` の両方を再現しなければ採らない。

**既知の制約**: 開始前の正典名簿登録が無い N≥1 の groupGame は、GM と通常モードでは R33-U-B1D01 に従い Evidence／WS 提出を採らず全員0点にする。一方、GCP 緊急入口は Stage B で正典名簿に一致する世代を選べず、採点に進む前に停止する。保存名簿にも再構成名簿にも正典 C へ一致する候補が無ければ停止する。名簿履歴や grace の読取失敗も未登録扱いせず停止する。復旧時は手順書 B「GCP を権威にする入口」の停止手順を確認する。

公開 roster group が1つでも欠けると、通常モードの `check.stageC.rosterCommitment` は FAIL になる。組分けから同じ group バイトを再構成できても通常モードでは代用しない。緊急入口では正典 C と照合した再構成を使う。

停止文には正典の添字・hash と試した保存世代の件数を出す。見張り役の `firstSeenAt`／`observedAt` で別の組を選ばない。組分け上限は正典 hash の応募終了以後の最初の登録時刻と `chattingStart` の早い方である。名簿の正典登録の解決と保存 manifest 世代の走査は `game_groups` の世代ループの外で行い、候補ごとに繰り返さない。窓内のチェーン登録へ束縛された前ブロック summary・manifest はバイト上限を保ち、非意味欄の JSON 深さでは候補から外さない。`emergency.gcpGroupsGeneration` に採用規則・選択世代・不採用理由を残す。

N=0 の groupGame は、最初の名簿錨も上限も使わない（前ブロックが無いので主要言語は空で、保存 summary の宣言 `majorLangs` も空でなければ採らない）。組を再現する最初の保存世代を観測順に採り、保存世代が2本以上のときだけ、世代・SHA-256・観測順・理由を `emergency.gcpGroupsGeneration` に残す。どの N でも、組を再現する世代が無ければ推測せず終了コード3で停止し、固定一式も差分ファイルも書かない（世代ごとの理由 `emergency.gcpGroupsCandidates` は例外に載るだけで画面に出ない）。出口は手順書 B「GCP を権威にする入口」の停止の中黒。

緊急採点で group archive・その組の保全提出・採用 Evidence がすべて無い場合、別の組の
採用 Evidence、保存提出／錨付き group archive、または署名で裏づけられたチャット開始から
そのブロックのゲーム実施を示せるときだけ、確定名簿の人数を保った空の組（全員提出なし）として
採点する。`emergency.missingGroupWithoutSubmissions` に組・人数・根拠を記録する。
ゲーム実施を示せなければ空組にせず（全員0点にせず）、groupGame の採点は `check.stageC.scoring=fail` で停止し、固定一式を作らない。GCP 入口の合成 manifest は群アーカイブの宣言 SHA-256 を持たないため、Stage B が選んだ他組アーカイブでも、この開始証拠としては数えられない。

保存済みの Merkle メタと Evidence レポートは再生成物の比較資料であり、保存の有無にかかわらず正準 writer が作り直す。
選ばれた `game_selection`・`game_groups`・group archive は保存バイトを運ぶため、
それらの追加欄が固定一式の core に入る場合がある。root と core は別々に照合する。
GCP の Evidence 安全高は、結果窓の閉鎖時刻を含む最初のチェーンブロックに確認ブロック数を足した高さに固定する。
既定経路の保存レポートが別の安全高なら結果 manifest core も異なり得る。同じ安全高のレポートを与えた
ローカルチェーン比較では結果ファイルのバイト列と core が一致する。
GCP 入口の中継された旧 root の証明が `internal_call_trace_unavailable`・`internal_call_ambiguous`・RPC／ノード由来の `trace_too_large` なら、Stage C の `zkProofFormat`／`zkPublicValues` は warn にする。ただし `writeEmergencyResultSet()` は正準 writer の書き出し core と現在の結果目印が違えば、その core を表示して固定一式を1ファイルも書かずに停止する。登録条件と再実行の出口は手順書 B「証明付きの旧 root があるとき」を参照する。
証明付きの旧 root がある場合は、証明が縛る結果 hash の追記履歴行を確認し、再計算 core が
チェーンの現在の結果目印と一致しなければ再計算 core の hash を表示し、固定一式を1ファイルも書かずに停止する
（`writeEmergencyResultSet()`）。表示された core が正しいことを独立に確かめてから登録して再実行すると、旧証明を
差分に記録して続ける（登録の条件と手順は手順書 B「GCP を権威にする入口」の「証明付きの旧 root があるとき」）。証明形式・固定一式のファイル SHA の不一致は停止する。ただし固定一式 core が現在の結果目印と
一致する緊急実行では、置き換える旧 root の中継証明 call trace が取得不能（応答過大・時間切れを含む）または添付2件で曖昧な場合だけ
`emergency.hijackPeriodProof` に差分化して書き出す。旧 root の calldata は差分に写さない。
当選者の再計算と応募 entry の読取は応募者登録ごとに1回で、保存 selection の囮世代は再実行させない。
入力候補が合わなければ推測せず停止する。timeline no-game の `noGameReason` / `noGameCause` は
writer の過去の観測であり、現時点のチェーンから復元できない場合は欄と理由を表示して停止する。
入口の選択は必ず
`emergency.resultManifestNotAuthoritative` 差分を残し、固定一式の終了コードは 4 になる。
フラグを省略した経路は従来どおり結果 manifest の保存世代を使用する。
N+1 が組分け時に使った N の本文を失った場合は、固定一式 F を代用せず上記の警告で進む。
N 自身の緊急書き出しでは、N+1 の正典名簿が登録済みなら、窓内にある N の全登録版の添字・hash と、manifest／summary 各鍵の保存状況を `##NEXT_GROUPING_PREVIOUS_VERSION` の `versions` で確認する。J1 の `--manifest` 書き出しでは、後の台帳から別欄に写した保存世代もバイトの SHA-256 が一致すれば保存確認に数える。`currentR2Source` は既定で `live public R2 fixed key` を指し、`currentR2Responses` に取得 URL と応答 SHA-256 を示す。`manifestInR2`・`summaryInR2` と `missingInR2` は鍵ごとの状態を示す。現物は manifest と summary の取得失敗を `currentR2ProbeError` に共用するため、manifest 固定キーが 404 で summary だけの取得が失敗した場合も `manifestInR2`／`inR2` が null になる。この null だけから manifest の確認不能を断定せず、`currentR2Responses` の鍵ごとの URL・error と公開キーの手動観測を照合する。summary の取得失敗は `summaryInR2=null` となる。R2 に本文が残る未保存鍵だけ書き出し前に止め、見張り役を `run --block N --phase manual` で回して保存した新しい A から再実行する。R2 にも保管庫にも無い鍵は保存できない消失として事故記録に残して N の上書きへ進み、N+1 は消失警告で評価する。`##NEXT_GROUPING_R2_PROBE_UNAVAILABLE` は公開 R2 の manifest または summary の取得失敗を示す。manifest の取得失敗でも `inR2=null` になる。確認不能のときは見張り役を `run --block N --phase manual` で1回回し、新しい A で確認し直す。見張り役の記録でも取れないと確かめたときだけ消失を記録して N の上書きへ進む。窓内登録が空なら `emptyWindow=true` を示して書き出しを続ける。旧 `##NEXT_GROUPING_PREVIOUS_VERSION_R2_LOST` と対話式の消失承認は使わない。
N のチェーン側の前提は N+1 の枝で分かれる。組のある N+1 では、候補になるのは N の結果ハッシュ履歴の
組分け時刻の窓内の行と core が一致する保存 manifest だけ（`loadPreviousResultVersionCandidates()`）である。
組の無い N+1（N+1 の保存 summary が無い場合を含む）は、
N の現在の目印と core が一致する保存 manifest だけを選ぶ（`selectPreviousBlockInputsByCurrentMarker()`）ので、
N の現在の目印に一致する保存世代を要する（条件は手順書 B「連続ブロックの🔴」枝2）。

### 緊急復旧で応募者ハッシュ登録を選ぶ

`--emergency-source` の保存世代から再現できる適格な `applicantHash` 登録が複数ある場合、
検証器は自動選択せずに停止する。表示される登録添字・root・登録ブロック／時刻・応募者総数と、
候補間で最初に違うワーカー／ファイルを確認し、正しい応募者データに対応する一方を指定して再実行する。

```bash
node src/index.js --lang ja --block 12 --non-interactive \
  --rpc https://YOUR_TRUSTED_RPC \
  --emergency-source /absolute/path/to/block12-observer \
  --emergency-out /absolute/path/to/block12-result \
  --emergency-applicant-registration 3

# または、正しい応募者データから得た登録済み root で指定する
node src/index.js --lang ja --block 12 --non-interactive \
  --rpc https://YOUR_TRUSTED_RPC \
  --emergency-source /absolute/path/to/block12-observer \
  --emergency-out /absolute/path/to/block12-result \
  --emergency-applicant-root 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

- `--emergency-applicant-registration INDEX` と `--emergency-applicant-root HASH` は同時指定できない。
- どちらも `--emergency-source` 専用である。指定した登録は、締切時刻の既存適格条件を満たし、
  オンチェーン履歴に存在し、保存世代から再現できなければならない。履歴に無い root は受け付けない。
- 表示される `signer` は `registerHash` 呼び出し時に渡された引数であり、トランザクション送信者の認証情報ではない。
- 指定を使った固定一式には `emergency.applicantRegistrationOverride` 差分が必ず入り、
  採用した添字／root、飛ばした全適格登録、指定方式（添字または root）を記録する。この場合の終了コードは 4。
- 指定なしで再現可能な適格登録が1本だけなら、従来どおりその1本を採用し、選択差分は追加しない。

### 終了コード

| コード | 意味 |
|-------|------|
| 0 | Stage C まで自然完走し FAIL 無し（フルパス） |
| 1 | FAIL は無いが、正当な未完了ゲートで停止（applicantHash未登録・抽選未実施・root未提出等） |
| 2 | 1つ以上のチェックが FAIL |
| 3 | fatal（ステージ例外・stdin EOF・RPC/コントラクト設定エラー） |
| 4 | 緊急固定一式を書き出したが、結果に影響する差分あり |
| 64 | usage エラー（`--block` 欠落/不正等） |

### pins 上書きの運用（グラインディング／ルール逸脱の FAIL）

`confirmationBlocks`・`ethereumHeaderRuleVersion`・`ethereumHeaderFork` や採点ルール（minChars / minMessages / chatCaps /
maxReports / minDepositWei）が本ツールのピン値（`src/config.js` DEFAULTS.pins）から逸脱している
場合は **FAIL** になる（ブロック単位の逸脱＝RANDAOターゲット grinding・採点操作の兆候）。
運営が定数を正当に変更した場合は、ユーザーが変更内容を確認した上で `--config` の JSON に
`"pins": { ... }` を書いて**明示的に承認**する（暗黙のWARN容認はしない）。

（2026-10-23 注・S45R3 Y-07-01）受理規則・密告の資格・可視文字の版（`receiptAcceptanceRule`・`reportEligibilityRule`・`visibleCharsRule`）の pins を上書きしても、替わるのは manifest の宣言との照合（`check.stageC.rulesPins`）だけで、本ツールが vendor した採点のコードの版は替わらない。版の違うブロックは、そのブロックの版の採点を vendor した本ツールの版で検証する。

⚠️ `src/config.js` のコントラクトアドレスは**現行のテストデプロイ**。契約再デプロイバッチ後に
更新が必要（`--config` でも上書き可能）。

## ZKPの検証範囲と再現ビルド

通常のブロック検証では、証明付き提出について次を自動確認する。

1. `blockStates.zkEpochPlusOne`から、提出時に使われた`vkeyEpochs[index]`を1世代だけ読む。
2. 最終`MerkleRootSubmitted` / `MerkleRootProofAttached`の transaction が TokenMining 直送なら
   その calldata を使う。中継コントラクト宛てなら `debug_traceTransaction`（`callTracer`）を読み、
   成功した（自身と全祖先に error／revert の無い）通常の `CALL` で、TokenMining 宛て、復号した `blockNum` が
   検証対象ブロックの `submitMerkleRootWithProof` / `attachProofToMerkleRoot` がちょうど1件のときだけ
   その内側 calldata を使う（`src/zkp.js` の `resolveProofSubmissionCalldata()`）。通常検証では trace不能・0件・2件以上は FAIL にする。
   RPC が応答を大きすぎるとして失敗させたときは `trace_too_large`、取得に15秒を超えたときは取得不能として区別する。一意にたどれた応答はフレーム数の見積もりで拒否しない。
   revert した囮や別ブロックへの添付は数えない。
3. proof先頭selectorが`0x4388a21c`、proofが356 bytes、public valuesが480 bytes（15語）であることを確認する（14語・448 bytes の旧ゲストの証明は新しい契約では受理されない。ゲストの15語化はロードマップ ⑤）。
4. `Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs`と同じ共有実装で15語を再計算し、calldataと照合する（15語目は共有の名簿の規則 `roster-anchor-rule.js` で求めた正典の名簿の hash。無ければ 0）。
   前ブロック結果の word7 は、番兵なら提出時点の登録0件を確認して0、通常の添字なら提出時点の
   `resultRegistrationAt(N-1,index)` の hash とする。範囲外の添字は FAIL にする。

前ブロックの登録の時点は別の `zkPrevRegistrationWitness` で見張り役の `chainSnapshots` を基準に確認し、後から積まれた行を使った可能性は warn まで表示する。判定の時刻に運営設定の grace は使わない。

4にはroot提出時点の過去stateが必要なため、深い履歴を検証するRPCには
`eth_call`とログ取得をそのEthereumブロック高で提供できるarchive機能が必要になる。
RPCが履歴を返せない場合は「証明なし」ではなく「検証できなかった」としてFAILし、必要な
Ethereumブロック高を表示する。shadow（`zkEpochPlusOne == 0`）は正常な証明なしとしてWARN表示し、
proof外形/public values検査は理由付きでskipする。画面に出る`proofRequired`は**現在値**であり、
過去ブロックの提出時点の設定を推測した値ではない。

SP1 Groth16の暗号検証そのものは、root提出transaction内で対象世代のverifierが成功させており、
その結果としてepochが`blockStates`へ記録される。本CLIには別の重いnative/Docker暗号検証器を
組み込んでいない。配布可能なWASM経路を優先し、Dockerを通常検証の必須条件にしないためである。

「公開ゲストソースが本当にその vkey を生成するか」まで独立に確かめる場合は、対話メニューの「ZKPシステムのコード整合性」を選ぶ。適用済みの世代に加え、14日待機中の提案があれば `[P] 公示中の提案: 未発効` を選べる。メニュー1の告知には提案の `pendingGuestSourceHash` が表示される。メニュー2では各段の説明を表示する。Stage1 はオンチェーンの state → block locator → `GuestSourceChunkPublished` 列とソースの整合を確認し、展開したソースの名前・配線の形・Cargo 入力の監査の門を確かめる。門を通ったソースだけを保存し、保存に成功したときだけ保存先を表示する。同じ名前があれば `-2`・`-3`… の新しいフォルダへ保存し、既存フォルダを上書き・削除しない。保存先は `--config` の `dataDir`（既定は `./data`）。Stage2 はツールのピン留め値と登録済み vkey を比較し、選んだ世代または公示中の提案の verifier を vendor の `ZKP_EXPECTED.verifier` と大文字小文字を区別せず照合する。この verifier は設定・CLI・環境変数で差し替えられない。不一致でも Stage3 の確認・処理へ進み、最後は verifier 不一致の結論を優先して終了コード2となる。門に落ちたソースは書き出さず、Stage2 を表示した後、Stage3 の見出し直後に質問・子プロセスの起動なしで「照合不能」・終了コード2となる。門を通ったソースと登録された鍵の対応を調べる処理は任意で、「証明プログラムからvkeyを算出します。重い処理ですが、実行してもよろしいですか？」に `[y/n]` で答える。既定の答えはなく、空の Enter は同じ質問で待つ。いいえ・非対話でも Stage1 で保存を試みる。保存が手元の環境の問題（dataDir の書き込み権限不足、O_NOFOLLOW が無い環境など）で失敗しても、保存の文を出さずに Stage2・Stage3 の確認へ進む。いいえ・非対話では Docker と cargo-prove は起動せず、子の照合は未実施・終了コード0（別の pin・verifier の不一致や走査不能が無い場合）となる。

はいの場合、ツールが Docker のデーモンへの接続と、手元の cargo-prove が SP1 6.3.1（commit `8252c29`）であることを確かめる。道具が無いか版が違う場合だけ、その道具のインストール命令を表示する（ネイティブ Windows では案内と命令を表示しない）。デーモンの応答が無い場合も定型の失敗文で未実施となる。道具を確認できた後、Stage1 の保存に失敗していれば、その理由で従来の「照合不能」・終了コード2となり、組み直し・鍵の算出を始めない。保存に成功していれば、この時点で環境変数ファイルの作成・マウントの検査・argv の組み立てを行い、Stage1 で保存したフォルダで組み直す。準備に失敗した場合（保存先の絶対パスに `:`・`,` を含む場合など）は「照合不能」・終了コード2となり、その準備で作った環境変数ファイルだけを消して、Stage1 で保存したソースは残す。いいえ・非対話・道具の確認失敗では準備せず、これらの文字を含むパスでも書き出しに成功したソースは保持され、照合は未実施となる。Stage 3 の単一ゲストの束や、監査した形から外れる束は書き出さず、組み直さない。

ツール自身が束の digest 固定の SP1 image で12本の Docker 組み直しを順に実行し、その ELF から cargo-prove で12本の鍵を算出して照合する。初回は各処理の開始時に「実行中...（n/24）」を表示し、組み直しに落ちた部品の算出の番は飛ばす。組み直し命令・子プロセスの標準出力／標準エラー・内部の例外理由は表示しない。Docker は `shell: false` で起動し、ソースを読み取り専用、各ゲストの `target` だけを書き込み可能で載せる。環境変数ファイルは束の隣に作り、`CARGO_TARGET_DIR`・`RUSTUP_TOOLCHAIN`・`RUSTC_BOOTSTRAP`・`CARGO_ENCODED_RUSTFLAGS`・`RUSTC`・`CFLAGS_riscv32im_succinct_zkvm_elf` を渡す。AGG の4段には各段の bin と feature を指定する。cargo-prove の cwd は展開した木の外の空の一時ディレクトリで、こちらも `shell: false` で起動する。版の固定は `services/zkp-prover/Dockerfile.batch` と一致させる。

照らす子の辺は FINAL→BIND・L3、BIND→ROOT・EVIDENCE_SEGMENT・BIND_CHILD、ROOT→CHUNK・NODE、L3→L2→L1→L0→GROUP の11本と、最上段の FINAL→適用済み `vkeyEpochs[i].vkey` または未発効 `pendingVkey` の1本。公示中の提案の結果・結論は適用済み世代と分ける。NODE は子の vkey を私的入力で受ける。定数の名前と形を照合するもので、その定数がどう使われるかは Level 2 の公開ソース確認が必要である。

各辺は pass／fail（値の不一致）／照合不能（定数・子 crate の欠落、Rust の字句・構造・属性・macro が許容形から外れる場合等）／未実施を表示する。12本すべての組み直し・算出と全辺の一致がそろえば pass となる。適用済みの世代の pass では、確定したブロックの有無によらず「オンチェーンで公開されている証明プログラムのソースコードは、検証コントラクトで検証されている証明内容と一致していることが確認されました。」という結論と、Stage1 と同じ保存先を表示する。公示中の提案の pass は従来の未発効の結論を表示する。組み直しの非0終了・ELF の欠け・算出の例外があっても、残りを最後まで試して照合する。子の部品が失敗した辺と、親の部品が失敗して不一致が確定していない辺は照合不能（詳細は `-`）となる。親の部品が失敗しても、親のソースの定数と子から算出できた鍵の不一致は保持する。照合できた辺に不一致があれば、リトライを聞かず不一致・終了コード2となる。不一致がなく失敗した部品があれば、失敗数と2行の説明を表示して、既定の答えなしの `[y/n]` でリトライを聞く。はいなら失敗した部品だけ組み直しからやり直し、その回の進捗は1から部品数×2までとなる。いいえなら辺の行と「検証できませんでした。」を表示し、終了コード2で終わる。照合不能が残る場合も pass にはならない。はいの直後から道具の版確認を含め、最初の Ctrl+C で子プロセスを停止し、残りを始めず、一時ディレクトリを片付けて終了コード130でツールを終了する。実物の Docker では CLI を SIGKILL しても、コンテナ内の組み直しはデーモン配下で最後まで走り続ける場合がある。いいえ（最初の確認）・非対話・道具不足・デーモンの応答なしは未実施で終了コード0（適用済み世代では別の pin 不一致や走査不能が無い場合）となり、結論にも子の照合が未実施であると明記する。公示中の提案の終了コードには、適用済みブロックの走査不能を混ぜない。

メニュー1は証明つきブロックの K13 を `future_anchors_hash(N, TokenMining.evidence().GAME_PERIOD())` と照合し、供給元が0なら K13=0 を確かめる。system 検査では現行・公示中の供給元の `evidence()`、正典の runtime code（metadata を含み、immutable の2箇所を照合）、現在のブロック番号での `anchorsHash(N)` を照らす。メニュー1の root または採用表の再実行不一致は、子の鍵の照合をその実行では行っていないため、運営が選んだ program の操作の可能性を残す。K13 も違えば供給元を名指す。検証期間の延長を判断する前にこの検査結果を確認する。

## byte-exact の担保（ベンダリング）

検証ロジックは「抜き書き」ではなく、**正典ファイルの丸ごとコピーを実行**する:
`vendor/workers/...` に game-master-DO.js / protocol-v2.js / game-result-calculator.js /
evidence-reconciler.js / timeline-check.js / char-counter.js をバイト同一でベンダリングし、
本物の `formGroups` / `calculateGroupResults` / `buildMerkleTree` 等を直接呼ぶ。
R33-U-GROUPING の比率とミックス組の配布順は正典仕様書
[`docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §3](../docs/CHAT_GAME_SIMPLIFICATION_SPEC.md) に従い、
第三者検証でも vendored `formGroups` が同じ規則を再計算する。
唯一の例外（抽選 selectWinners の行範囲抽出と、報酬按分のミラー関数）を含む対応表は
[VENDOR_SYNC.md](VENDOR_SYNC.md)。同期検査: `npm run check-vendor-sync`。

## テスト

```bash
node test/e2e.mjs        # Hardhatローカルチェーン + 本番コード生成fixture + ローカルR2 → ツール実走（全緑）
node test/mutations.mjs  # 改ざん18ケース（エントリー改変/採点改変/merkle改変/提出すり替え/検閲抹消/
                         #   confirmationsグラインディング/evidence無効宣言 — manifest再アンカーによる
                         #   隠蔽工作込み — ＋正常系claim後変更のWARN降格）の検出
```

fixture は workers/ の本番コード（collect-DO・LotteryDO・GameMasterDO・ChatGameDO）を直接
実行して生成する（ツール自身のコードでは生成しない＝自己確認の循環なし）。

## 将来

完成後は独立リポジトリ（GitHub＋IPFSミラー）へ切り出し予定（信頼アンカーを運営の外へ）。
モノレポ内では `check-vendor-sync` が正典との drift を検知する。

## 参照

- 設計: [DESIGN.md](DESIGN.md) / ベンダリング台帳: [VENDOR_SYNC.md](VENDOR_SYNC.md)
- 背景: `../docs/FAIRNESS_AUDIT_FIX_PLAN.md`（step 6）・`../docs/P2P_REDUNDANT_CHANNEL_PLAN.md` §11・
  `../docs/archive/VERIFIER_TOOL_HANDOFF.md`（作成時の引き継ぎ・履歴）
- ドキュメント索引: `../docs/README.md`
