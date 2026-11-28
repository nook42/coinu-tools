> **2026-11-25 便 PLAYAT:** 参加予定時刻の事前設定（GM の集める仕事 `availability_seed`・ChatGameDO の受け取る口 `/seed-availability` と WS の印）を正典から byte 同一で COPY。採点・名簿・提出物の行は変えていない。GM・ChatGameDO を源とする MIRROR の窓は、旧 sha256 の同じ行数の窓を新しい正典で全走査し、各1か所だけ一致した位置へ行範囲だけを付け直した（本文と sha256 は据え置き）。COPY の sha256 を更新した。
> **2026-11-15 WR-PRE-ADMINGAS-FIX1:** GMの正常待ちからfee_cap_blockedを外した正典をbyte同一でCOPY。同じ行数の全GM MIRROR窓を旧sha256で全走査し、各1箇所に一致（行位置・本文・sha256は不変）。COPYのsha256を更新し、復元distを再生成した。ChatGameDOの写しは変更していない。
> **2026-11-15 便 WR-PRE-PRESENCE:** presence の枠を容量120・30秒に1つ戻る形にし、不変activeの合図をuidごと60秒に1回まで配る ChatGameDO を正典から byte 同一で COPY。完了した WR-PRE-ADMINGAS の GM も同期した。対象の MIRROR は旧 sha256 の同長窓を全走査し、唯一一致の位置へ行範囲だけを付け直した。dist は Node 22 の既存 build/bundle.mjs で再生成する。
> **2026-10-27 WR-RPC2-GM-FIX4:** `game-master-DO.js` を正典から byte 同一で COPY。GM MIRROR 9 窓は旧写しの本文・sha256 と新正典の同長全走査を照らし、各窓が一意に一致した。本文と sha256 は据え置き、行範囲だけ更新。
> **2026-10-27 WR-ADOPT-FIX2:** GM の Evidence レポート公開直前の注だけを訂正。正典を byte 同一で COPY。GM MIRROR は旧台帳の窓の本文と sha256 を照合し、新正典の同長全走査で各1箇所だけ一致した。本文・sha256 は据え置き、注の後方の行範囲だけ +1 行。

> **WR-E2E-S2F-ABANDON-FIX1（2026-11-11）:** GM の保存済み fallback を受信時の run（startedAt・runId）と同時 restart の requestId に結び付け、却下記録・認証 deep 表示・継続の前倒しを COPY に同期した。GM を源とする全 MIRROR 窓は旧 sha256 の同長全走査で唯一一致する位置へ移動し、窓本体と sha256 は据え置き。COPY の sha256 を更新し、chatgame-tools の dist は Node 22 の `npm run bundle` で再生成した。
> **2026-10-27 WR-RPC2-GM-FIX3:** GM・finality・admin-tx-client を正典から byte 同一で COPY。GM MIRROR 9 窓は旧写しの本文と sha256 を照合し、新正典の同長全走査で各1箇所だけ一致したため、本文・sha256を据え置き行範囲だけ更新。
> **2026-10-27 WR-RPC2-GM-FIX2:** GM-R2・GM-R3・TX-B の GM 側を正典から byte 同一で COPY。GM の MIRROR は旧 vendor の窓と正典の同長全走査で各1箇所だけ本文が一致したため、sha256 を据え置き行範囲だけ更新した。
> **2026-10-27 WR-RPC2-GM-FIX1:** Evidence の固定・名簿読取・延長判断・RPC 独立票を正典から byte 同一で COPY。GM を源とする MIRROR は旧 sha256 の同長窓を全走査し、すべて唯一一致したため本文と sha256 を据え置き、行範囲だけ更新した。
> **2026-10-27 WR-GROUPIO-FIX7:** GM の組分け再開と監視・alarm・R2 後退を正典から byte-exact に COPY。GM を源とする MIRROR は旧 sha256 の同長全走査で本文が各1箇所に一致し、行範囲だけ更新。
> **2026-10-27 WR-RPC2-GM:** GM の Evidence/grace RPC 2本一致を正典から byte-exact に COPY。GM MIRROR は旧 sha256 の同長窓を全走査し、各本文の唯一一致を確認したうえで行範囲だけを更新。finality.js を COPY 台帳へ追加。
> **WR-GROUPIO-FIX4（2026-10-27）:** GM の MIRROR 9窓を FIX2 の写しと現行正典で同長全走査し、各本文が一意に byte 一致することを確認。sha256 は据え置き、行範囲だけ移した。GM の COPY sha256 は正典と写しの一致値に更新した。
> **WR-GROUPIO-FIX2（2026-10-27）:** FIX1 の GM に対し、旧正典 `e212b6528` の MIRROR 9窓と現行正典の同長窓を本文で比較した。各窓は全走査で一意に byte 一致したため、sha256 を据え置き、行範囲だけ移した。GM の COPY sha256 は現行の正典と写しの一致値に更新した。
> **WR-14-FIX3（2026-10-25）:** pre-commit の 404 と post-commit の遅延 issue を正典 GM から byte 同一で COPY。MIRROR は旧 sha256 の同長窓を全走査して一意に一致した位置へ行番号だけ移し、本体は不変。
> **WR-14-FIX2（2026-10-25）:** post-commit の追跡修正を正典 GM から byte 同一で COPY。MIRROR は旧 sha256 の同長窓が一意に一致した位置へ行番号だけ移し、本体は不変。
> **WR-14-FIX1（2026-10-25）:** GM の post-commit 連続失敗・K6 の確定と未登録の区別・見積もりを正典から byte 同一で COPY。MIRROR は旧 sha256 の同長窓が全走査で一意に一致した位置へ行番号だけ移し、本体は不変。
> **WR-4-FIX1（2026-10-24）:** GM の記録読取・再試行を正典から COPY。MIRROR の旧 hash が同じ長さの窓に一意に一致したため、範囲だけ移した。
> **WR-4（2026-10-24）:** GM の K7 記録・証明発注の追加後、COPY を正典から更新し、MIRROR の旧 sha256 が同じ行数で唯一一致する位置へ窓を移した。
> **S3R8 段4 第2波（2026-10-19・周8 の統括）:** 便 R8-SVA8 で正典の提出窓の前が +9 行、便 R8-MSGKEY で窓の中が発言の鍵の getter（性能だけ）を使うようになった。試験束の本体は据え置き、窓だけ 589-1326・sha256 `cee4b6c9a589…` へ取り直した。
> **S3R8 段4 第1波（2026-10-19・周8 の統括）:** 便 R8-POSTSEND で正典の提出窓の前が +15 行。中身は byte 不変なので試験束の本体は据え置き、窓だけ 565-1302→580-1317 へ張り直した。
> **C33F1 / C33F1-FIX1（2026-10-23）:** GM・claim-data-codec・deposit-id のコメントを正典から byte 同一に COPY し、3行の sha256 を更新した。GM は行数 18,582 を維持し、MIRROR の行範囲と本体の sha256 を再照合して据え置いた。
> **S3R6 便 SYNC6B（2026-10-17）:** SV5 の提出窓を正典と試験束で再レビューし、SV6 の窓の前の行のずれも合わせて 565-1302 へ張り直した。試験束の本体は据え置いた。
> **S3R6 便 SYNC6（2026-10-16）:** G1 の calculator COPY sha256 を実測へ合わせ、SUBMITVIEW・SUBMITVIEW2・SUBMITVIEW3・SV4 の提出窓を正典と試験束で再レビューして張り直した。試験束の本体は据え置いた。
> **UI_IMPROVEMENTS_S3（2026-11-15・版 2〜版 6 の提出画面の直し）:** 提出窓 `SubmissionPhase.js` は、窓より前の行が増えて `589-1326` から `731-1468` へ移った（+142 行）。同じ長さ738行で sha256 は `cee4b6c9…` のまま＝窓の中身は byte 不変。`players.mjs` の試験束の本体は変えていない。行番号だけを数え直した。

> **2026-11-19（ユーザーの指示・0ae797985・反証 D-1/D-2/D-4）:** 提出窓 `SubmissionPhase.js` を `731-1468` から `742-1485`（744行）へ取り直し、sha256 は `8d3bdc1d…`。窓の前に state 2つ・準備中の印の try/finally・再提出の確認の文の差し替えが入って +11 行。窓の中の差は handleSubmit の `prepareOnly`（オンチェーンの準備の押下では署名・保存だけで WS へ送らず、`isSubmitting` を立てない）と、送る直前の `setServerSendTried(true)`（2か所）だけ（旧窓との diff で +6 行・1行の置き換え）。提出物の組立・バイト列は変わらず、`players.mjs` は送信も画面の state も写さないので試験束の本体は不変。
>
> **S3R5 便 DISP5（2026-10-14）:** 提出窓 `SubmissionPhase.js:504-1264` の中は自己検証の失敗の文言（i18n の既定文）だけが変わったので、試験束の本体は変えずに sha256 だけを張り直した。
> **S3R5 便 SYNC2（2026-10-14）:** LOCK（2b479a6af）の提出窓を正典の差分で再レビューして 504-1264 へ張り直した。試験束は確定を渡さないため MIRROR-BODY は不変。timeline-check.js は注だけを直し正典から byte 同一に写した。
> **S3R5 便 SYNC1（2026-10-13）:** 便 PLAN の protocol-v2.js COPY の sha256 を実測へ合わせた。便 SELF の提出窓は正典だけを張り直し、根拠を持たない試験束の MIRROR-BODY は不変であることを再レビューした。
> **S3R4 便 P2b-2b（2026-10-11）:** SubmissionPhase の提出窓は prop 追加で1行移動した。旧 sha256 の同長全走査で唯一一致し、players.mjs と窓の中身は不変。
> **S3R4 便 P2b-2a-2（2026-10-11）:** 提出窓の区切り判定時刻と記憶の配線、T9 注記の訂正を照合し、正典 MIRROR の行範囲・sha256 を再計算した。players.mjs の本体は不変。
> **S3R4 便 P2b-2a-1（2026-10-10）:** 区切りの池の `protocol-v2.js` を正典から byte-exact に COPY。MIRROR 窓の配線は a-2 で照合する。
> **S3R4 便 P2b-1a（2026-10-10）:** `clientReceiptCapExcluded` と F1・F2・手数の守りを正典から COPY。公式の提出窓は隠す集合を計画へ渡す1行を含めて張り直した。block-verifier の `test/players.mjs` は欄を組まない試験の束なので MIRROR-BODY は不変。
> **S3R4 便 RPCWIN（2026-10-10）:** 公式の提出窓を読み比べと組み直しに合わせて張り直した。players.mjs は最優先欄を組まない試験の束なので本体と MIRROR-BODY は不変。
> **S3R4 便 P2a-2（2026-10-09）:** `test/players.mjs` は任意の最優先欄を組まない試験用の束であり、欄なしも有効。公式の提出構築窓と priority-fields.js の OPRPC-E 注記 COPY を更新し、本体は変えていない。
> **S3R4 便 RS-AB5（2026-10-09）:** `evidence-compact-v1.js` の guard 注記を正典から byte-exact に COPY。採点行は不変。
> **S3R4 便 RS-AB3（2026-10-09）:** `test/players.mjs` の提出 MIRROR が参照する uid を、同関数の `player.uid` に揃えた。`limitCarriedReceiptFacts` の引数だけの訂正で、正典窓は不変。MIRROR-BODY の sha256 を再計算した。
> **S3R4 便 RS-0（2026-10-09）:** `protocol-v2.js` の省略可能な画面の覆い memo と `evidence-compact-v1.js` の純粋な保存上限関数を byte-exact に COPY。採点行は不変。SubmissionPhase の提出窓は memo 引数の1行だけを加え、`429-1052` に張り直した。`test/players.mjs` の MIRROR-BODY は不変。
> **S3R4 便 P1a-i-1（2026-10-08）:** priority-fields.js と DO・submission-limits.js を規則版数18の入口に合わせて再同期した。
> **S3R4 便 P1a-i-2（2026-10-08）:** EVC 版2と priority の符号化・復号を正典から再同期した。
> **S3R4 便 P1a-ii（2026-10-08）:** 規則版数18の採点手順を正典から再同期し、COPY と DO・submission-limits.js の注記を照合した。

> **S3R4 便 C1（2026-10-07）:** 規則版数17の計算器・字数カウンター・protocol-v2 を正典から byte-exact に再同期。COPY 3行の sha256 を更新。既存 MIRROR の源と本体は不変。

> **S3R4 便 T5f（2026-10-06）:** 正典 `src/utils/relay.js` の sha256 は `2d12670ee100a1e6797ec91de3257cc51527776a10260baf777aa4e4e7f9d802`。block-verifier に同ファイルの COPY はなく、COPY 台帳と MIRROR の源・本体は不変。

> **S3R4 便 T5d（2026-10-06）:** 正典 `src/utils/relay.js` の sha256 は `981d9a579c9c207552d5df40aabf79b06054cadf2c0bf30a55bc7f4091337c4d`。block-verifier に同ファイルの COPY はなく、COPY 台帳と MIRROR の源・本体は不変。

> **S3R4 便 T5c（2026-10-06）:** 正典 `src/utils/relay.js` の sha256 は `bf4bdc8abd630d53f41f77f0d4f38fa66ee02d2e8e210e82a97de128a79bdcb5`。block-verifier に `relay.js` の COPY は無く、COPY 台帳と MIRROR は不変。同期検査で照合した。
>
> **S3R4 便 T5a（2026-10-06）:** 正典 `src/utils/relay.js` の sha256 は `77ad0bc86593cb8f52595da87399b82fec8ff3a32edef416e07d7845184710ab`。block-verifier に `relay.js` の COPY は無く、COPY 台帳と MIRROR は不変。同期検査で照合した。

> **WR-BAKE-WRITE（2026-10-26）:** 焼成済み FINAL の vkey と ELF SHA-256 を正典から byte-exact に COPY。

# VENDOR_SYNC — ベンダリング台帳
> **S3R4 便 T7（2026-10-06）:** 公式の投票選択と A-3 を直したため、正典窓を `423-1045`・sha256 `09957e57e2d2640150de7ae99057a2f8f679928dc8a57d4721536a597348a813` に更新した。`players.mjs` はこの節を写していないので、本体と MIRROR-BODY sha256 `76d3e839108b15e1a9203d9cb0ead496ed361136fa05f984a044e05143173a03` は据え置く。
>
> **S3R4 段5（2026-10-06・S3R4-C-4-01）:** `test/players.mjs buildSubmissionPayload` は正典と同じ構築ではない。① 上限は `applyChatCaps`（自称時刻の正準順・既読の被覆なし）で、正典の `clientScoreableMessages`（他人の発言は手元の既読で被覆したものだけ・最初の既読の時刻の順の上限〈周2 便 T1 `5797eaf1`・S3FIX 便 B1 `e4b16e05`〉）と違う。② 正典の `clientWindowedReceipts` が無い。③ `selectBundleReceipts` に `chatWindow: null` を渡す（同じ関数の `aggregateSelfReceipts` には窓を渡す）。④ 便 T7 の投票の選び方と A-3（上の注）も写していない。容量 fixture（z2-storage-limit ほか）の分割パスを残すための差で、便 SYNC2・T1・T7 は正典窓と sha256 だけを付け直し、便 RS-AB3 は `limitCarriedReceiptFacts` の uid の引数だけを直した。MIRROR の sha256 は「変わっていない」ことしか見ないので、この差は同期検査では捕まらない。block-verifier の提出 fixture は本物の提出物と違う形（誰も読んでいない他人の発言を運ぶなど）を検証する。採点への害は無い（歯の判別力の制約）。`scripts/check-vendor-sync.mjs` の D2-03 のコメント（上限適用・snapshot正規化・receipt集約・sanitize再署名を追随させる）は今の写しと合わない。
>
> **S3R4 便 T1（2026-10-05）:** 正典 `SubmissionPhase.js` の `__extras` を提出前に署名の3欄へ作り直した。MIRROR 正典窓を `423-1033` と sha256 `ad5c050a185dfbc6e4eef8af9138fff16204b5f519dbff8e7bc3e44e942198fd` に付け直した。写し先の `makeActionWsData`・gen-fixture の DO 保存（3欄）・q24 はいずれも3欄を渡すため、`players.mjs` の組み立て本体と出力は変わらず、MIRROR-BODY sha256 も再照合して据え置いた。
> **S3FIX 便 W3N（2026-10-02）:** 表示専用の `receipt-warnings.js`・`ChatPhase.js` はこの台帳の COPY / MIRROR 対象外。既存34 COPY・10 MIRROR と EXTRACT を同期検査で再照合し、sha256・行範囲・本体は不変。
> **S3FIX 便 D1b（2026-10-02）:** `SubmissionPhase.js:423-1030` の提出窓判定が C に替わったため正典 MIRROR sha256 を更新した。提出束の組立ミラー本体と採点・DO・契約の COPY は変更していない。
> **S3FIX 便 E3F（2026-10-03）:** 正典 `src/utils/relay.js` の既定タイマー修正後の sha256 は `403ac33f36565b826ea374f1281db4d435753e71213c1d9ba95f9e26bb10ac0c`。block-verifier に `relay.js` の COPY は無く、COPY 台帳・MIRROR の源と本体 sha256 は不変。同期検査で再照合した。
>
> **S3FIX 便 FX1（2026-10-01）:** `_scheduleReconnect` の復元で正典 `src/utils/relay.js` の sha256 は `e05a31319c2a3155e7b390282823d0aab6fee6bb8c5891f8c5421cd520001169` になった。block-verifier の COPY 先に `relay.js` は無く、COPY 台帳・MIRROR の源と本体 sha256 は不変。同期検査で再照合した。
> **S3FIX 便 SYNC3（2026-10-01）:** 便 C2 の `read-receipt-pause.js` は公式 `src/utils/` へ移したが、block-verifier の COPY 先から import されないため追加しない。便 C2 が変更した公式 hook と復元クライアントもこの台帳の COPY/MIRROR の源ではない。COPY 33行の sha256 と MIRROR の窓・sha256 はすべて再照合し不変。
> **S3FIX 便 SYNC2（2026-10-01）:** 便 B1 の `protocol-v2.js`・`evidence-compact-v1.js` を正典から byte-exact に再同期した。便 MD の新設 `MultiSessionModal.js` は COPY 対象でなく、便 D1a・E1 の新設モジュールも vendor 内から import されないため追加しない。`SubmissionPhase.js` の MIRROR 窓内変更は照合待ち。
> **S3FIX 便 SYNC（2026-10-01）:** 便 C の `workers/game_workers/lib/protocol-v2.js` を正典から byte-exact に再同期した。便 D1a・E1・B2・H1 の変更も照合したが、この台帳の追加 COPY・MIRROR 窓の変更は不要（D1a/E1 の新設モジュールは vendor 内から import されていない）。
> **便 A2（2026-10-01・S3FIX-Q1R）:** v15 の上限比較を最早の既読時刻1つ、同点は正準順へ訂正した。`char-counter.js`・`game-result-calculator.js`・`protocol-v2.js` を正典から byte-exact に再同期した。MIRROR 窓の本体と行範囲は不変。

> **便 A（2026-10-01・S3FIX）:** 採点の上限を最初の既読の時刻列の順に選ぶ規則版数15。`game-result-calculator.js`・`char-counter.js`・`protocol-v2.js` を正典から byte-exact に同期した。MIRROR 窓の本体は不変。


> **T1l（2026-09-30）:** `test/players.mjs` の `chatCloseAt` 引数は正典の出どころ門へ接続されているが、現行の `buildSubmissionPayload` 呼び出し元はこの引数を渡していない。従って block-verifier の既存 fixture はこの門の検査にはならず、出どころの回帰はクライアントの歯で検査する。

正典（モノレポ `workers/`）から `block-verifier/vendor/` へ持ち込んだコードの台帳。
**COPY = cp によるバイト同一コピー / EXTRACT = 行範囲のverbatim抽出 / MIRROR = 手書き忠実ミラー（別担当が実装）**。

検査: `npm run check-vendor-sync`（= `node scripts/check-vendor-sync.mjs`）。
モノレポ内では vendor/ の全ファイルが COPY または EXTRACT 台帳にあること、COPY のバイト一致・EXTRACT の本体一致・MIRROR の正典行範囲sha256を検証し、不一致で exit 1。
🔴 **2026-08-08（F-7(b)）訂正**: 独立リポジトリ化後（モノレポ不在時）は照合対象が存在しないので、
スクリプトは **exit 1**（「ここでは検証できない」）で終わる。以前は skip として exit 0 を返しており、
vendor を改変した standalone コピーでも緑になっていた（実測: `MAX_DEPOSIT_WEI` を 10 ETH → 1000 ETH に
改変しても `skipping` ＋ exit 0）。
⚠️ **本表は「ドリフト検知の台帳」であって真正性の証明ではない**。vendor を書ける者は同じコミットで
この表も書ける。コピーの真正性が要るなら `HashStorage.buildHashes` への登録が必要（別項目）。

sha256 の対象: COPY/EXTRACT 行は **vendor ファイルの生バイト**（COPY は正典と同一バイトなので正典の sha256 でもある）。
MIRROR 行は **正典ソースの該当行範囲**（1-indexed、`\n` 結合・末尾改行なし）の sha256（ミラー元が変わったら再レビューが必要、のシグナル）。

> 🔴 **2026-08-07 訂正**: この行に**ファイル全体の sha256** が入っていた時期があった。
>   `check-vendor-sync.mjs` が実際に検証するのは**行範囲**の sha256（`acabb6d2…`）なので、
>   全体の sha を入れると「台帳の数字」と「検査が使う数字」が別物になり、
>   しかも**ファイルのどこを触っても行が churn する**（区間の中身が変わっていなくても）。
>   ⚠️ この行を更新するときは**行範囲の sha256** を入れること。
>     区間の中身がバイト一致なら sha256 は**据え置き**で、**行番号だけ**動かす。

> **S3R4 便 RS:** 既読の選び方を撤去し、重なる既読を運ぶ正典と提出 fixture を同期した。旧 COPY 行を削除した。

| vendor path | source path | sha256 | type |
|---|---|---|---|
| `vendor/workers/auth_workers/lib/cors.js` | `workers/auth_workers/lib/cors.js` | `bcfcfc13e854eafcc6636b74a1498e29d41fb6c210712987037c7b638ca3d296` | COPY |
| `vendor/workers/game_workers/game-master-DO.js` | `workers/game_workers/game-master-DO.js` | `ea94fd3d7e0e68a4f151deba497af5c93f7d600f131d498426adb084129563c4` | COPY |
| `vendor/workers/game_workers/lib/roster-anchor-rule.js` | `workers/game_workers/lib/roster-anchor-rule.js` | `182deb697a5162478af2fc136b41619199b5796677a67fc09d8096a6e0d04453` | COPY |
| `vendor/workers/game_workers/lib/roster-canonical.js` | `workers/game_workers/lib/roster-canonical.js` | `03e771389271388cc3433f57e5bf8013830a451ad1c3fad741b052262bf6d0ce` | COPY |
| `vendor/workers/game_workers/chat-game-DO.js` | `workers/game_workers/chat-game-DO.js` | `8e7327c6620a091ea34c4bfcafedc70d06c10afab7e837915ceec0146a6254fb` | COPY |
| `vendor/workers/game_workers/lib/reaction.js` | `workers/game_workers/lib/reaction.js` | `167fef1444fc2e526894fe9cd360e25e93297b27c4484dd53af0b0257aaeee97` | COPY |
| `vendor/workers/game_workers/lib/protocol-v2.js` | `workers/game_workers/lib/protocol-v2.js` | `6e7a9eb7b6b619481de7799df812290be3afcb244a51fbc839082a0b542e5a69` | COPY |
| `vendor/workers/game_workers/lib/submission-limits.js` | `workers/game_workers/lib/submission-limits.js` | `22976d4c33b8d4e793b4c26910c7185cb09ff80705f7b80d1791353bf1e6056b` | COPY |
| `vendor/workers/game_workers/lib/priority-fields.js` | `workers/game_workers/lib/priority-fields.js` | `b7437dc57fa403c562f0a99d10e155fa07bf182eac95904f80a12c6f53a0e2ec` | COPY |
| `vendor/workers/game_workers/lib/evidence-compact-v1.js` | `workers/game_workers/lib/evidence-compact-v1.js` | `133523bd5dafb9c7aafcd557119401be7ab05ebee596abe17021a871caa96f2c` | COPY |
| `vendor/workers/game_workers/lib/zkp-protocol.js` | `workers/game_workers/lib/zkp-protocol.js` | `b7a968747de416c752264b598842b4d7b0919647c7039070f7baaa064aa46172` | COPY |
| `vendor/workers/game_workers/lib/roster-member-root.js` | `workers/game_workers/lib/roster-member-root.js` | `de7e359205c8abb590acc40384f7abb7bb768ed62181aa8f78fcb1b407641564` | COPY |
| `vendor/workers/game_workers/lib/evidence-sender-vectors.json` | `workers/game_workers/lib/evidence-sender-vectors.json` | `faa23efaa3455e6fd8507fa970a80f2ee47158f124c0bc21d776a43bea5d539d` | COPY |
| `vendor/workers/game_workers/lib/group-witness.js` | `workers/game_workers/lib/group-witness.js` | `b658cea31609c05e218f1a510a1114718106daf395180d6ec8eabf823be2c3ce` | COPY |
| `vendor/workers/entry_workers/lib/deposit-id.js` | `workers/entry_workers/lib/deposit-id.js` | `082dd30c8b6244567bbe0df0f94350a4dda1eb5c18eef570e974f27890f14e58` | COPY |
| `vendor/workers/entry_workers/lib/nostr-key.js` | `workers/entry_workers/lib/nostr-key.js` | `b64777b36b2b6fc100bbe1217bb72f477872b5dfe9795d0a1d0465bb17451307` | COPY |
| `vendor/workers/game_workers/lib/game-result-calculator.js` | `workers/game_workers/lib/game-result-calculator.js` | `887f3f15a20ebb6de68fb663f15d8daa24ed01c354954ff754fbd764dab7f2d5` | COPY |
| `vendor/workers/game_workers/lib/evidence-reconciler.js` | `workers/game_workers/lib/evidence-reconciler.js` | `d83e723ba4edeef68507bfdb7a6dbbe1b6f0c29c8cad62d43d10cb2119875fa0` | COPY |
| `vendor/workers/game_workers/lib/finality.js` | `workers/game_workers/lib/finality.js` | `efc5af8d969692f8c54497178ef85389f120ffb51c5d7131e0e6211065497745` | COPY |
| `vendor/workers/game_workers/lib/evidence-segment-plan.js` | `workers/game_workers/lib/evidence-segment-plan.js` | `c996e7f55b589d8bbe2c41d1e825256cae9183d71fb843732d2c31c540fea3f6` | COPY |
| `vendor/workers/game_workers/lib/getlogs-adaptive.js` | `workers/game_workers/lib/getlogs-adaptive.js` | `208c542eac569f2e9bf50e901ab6306866297a214d02ada19eeeb670c9a4869b` | COPY |
| `vendor/workers/game_workers/lib/timeline-check.js` | `workers/game_workers/lib/timeline-check.js` | `a68867797b1fc497b7115d8226b6c72ec5a088d6d5239c62d00f9330c0b14dff` | COPY |
| `vendor/workers/game_workers/lib/block-lifecycle.js` | `workers/game_workers/lib/block-lifecycle.js` | `ba4c30e81ca10811fa7b8cd391038f4b1737557dbc09456fb6650d15c8bdcc2b` | COPY |
| `vendor/workers/game_workers/lib/char-counter.js` | `workers/game_workers/lib/char-counter.js` | `ac2d679c0adc5a725de39687489bfe94057ec9f4006d60778537dd4d3c3bfe87` | COPY |
| `vendor/workers/game_workers/lib/selection-integrity.js` | `workers/game_workers/lib/selection-integrity.js` | `43fa43e7dbc08183f689810a534964a51b170369ec7f48320c3a898040510c8c` | COPY |
| `vendor/workers/game_workers/lib/grouping-integrity.js` | `workers/game_workers/lib/grouping-integrity.js` | `1fc51a515d95106c6c4af962ecfd150b112f573c6207c6b08852052c996311d9` | COPY |
| `vendor/workers/game_workers/lib/canonical-json.js` | `workers/game_workers/lib/canonical-json.js` | `8d994e475947d94a6fb8ee2845cd7047e8efd7e05ab86d62ffe72090a04e341f` | COPY |
| `vendor/workers/game_workers/lib/select-winners.js` | `workers/game_workers/lib/select-winners.js` | `04f9432845786255d21d488af3b84cb0cc09ac240610de9a6a6f6457154dd786` | COPY |
| `vendor/workers/game_workers/lib/claim-data-codec.js` | `workers/game_workers/lib/claim-data-codec.js` | `41d5a1028bdb38e6ee4d3f89a3dc15cbc4d51544197664d23de2158fae97fcf0` | COPY |
| `vendor/workers/game_workers/lib/service-binding.js` | `workers/game_workers/lib/service-binding.js` | `c5822b482a89a8cd5152d948cb1d134daf60011f3a0f1fdb34058c9021cee337` | COPY |
| `vendor/workers/game_workers/lib/admin-tx-client.js` | `workers/game_workers/lib/admin-tx-client.js` | `e28a10df8cedb10943ae2d156756477beb2d1b76f5d85d8de17e7cf24b2def80` | COPY |
| `vendor/workers/game_workers/lib/rpc-urls.js` | `workers/game_workers/lib/rpc-urls.js` | `f3d0bdb1e69b365a95bf11440a07acbbbc2754da83ba7b3a2607726af07d073b` | COPY |
| `vendor/workers/game_workers/lib/rpc-independence.js` | `workers/game_workers/lib/rpc-independence.js` | `8d5c93a56942b7d5c1af6bebf8e2e38d5c9903baffa81ddbe4312ec3c9141b5b` | COPY |
| `vendor/workers/game_workers/lib/alert.js` | `workers/game_workers/lib/alert.js` | `35781307cc3497b6e30a4741e4e4e853d3743d803bce0bea7ea69ac682414e64` | COPY |
| `vendor/workers/game_workers/lib/observation-write-failures.js` | `workers/game_workers/lib/observation-write-failures.js` | `25916214d12e97ef11a8ad424b73ccb6878667578d3e7d5ac3a3a9aceb201cfa` | COPY |
| `vendor/workers/lottery_workers/select-winners.js` | `workers/lottery_workers/lottery-DO.js:2572-2659`（本体=2573-2658）／ `workers/game_workers/lib/select-winners.js` | `04f9432845786255d21d488af3b84cb0cc09ac240610de9a6a6f6457154dd786` | EXTRACT + COPY |
| `src/stages/results.js mirrorRewardSplit` | `workers/game_workers/game-master-DO.js:11929-12087` | `320b6e967119dca5931207551995bdd3543d5a639feaec439f627fa3a269553e` | MIRROR |
| `src/stages/results.js autoRosterTextFromSelection` | `workers/game_workers/game-master-DO.js:17311-17315`（Stage B selection から group0 を構築し、vendor の正準化を呼ぶ） | `c77ef5c98b2e2f974483c5e4b533628bf748e7566bf94da7ea963fdbe20b7986` | MIRROR |
| `src/stages/results.js runAutoDistribute` | `workers/game_workers/game-master-DO.js:17352-17477`（`autoDistribute` の点数計算部＝B1 オンチェーン再検証 → memberResults（適格帯判定込み）→ COINU 按分 → 50/50 Split） | `1df9664d0e69182291d074fae90dff646eebe257ce47a6d3b07a72e4ba22060b` | MIRROR |
| `src/stages/grouping.js toPublishedShape` | `workers/game_workers/game-master-DO.js:18675-18681`（`createGroupSummary` 内の公開 `groups` 写像） | `8c0caf301712ae3b40201922a1810e04190e1199fb2f573ff4721199786022d6` | MIRROR |
| `src/stages/grouping.js countGroupsByLang` | `workers/game_workers/game-master-DO.js:18687-18697` | `46451a5b65b4a77861508ec844322cf4e47a0edd66776dc16b604841cf7a38ae` | MIRROR |
| `src/stages/results.js rosterMembersOf` | `workers/game_workers/chat-game-DO.js:861-879`（`publishRosterFile` の canonicalRosterText 呼び出し・R2公開。公開キャッシュ喪失時にアンカー済み sha256 の照合相手を再構成するために要る） | `1e548c657d58f66ed592d2af8199e1aa5aa5092456c69dec9a6502f9684f33c2` | MIRROR |
| `src/stages/results.js reconstructedRosterIndexSha256` | `workers/game_workers/game-master-DO.js:7451-7476`（`buildRosterIndex` と `publishRosterIndexBestEffort` 呼び手の groupId sort。配列添字以外の uid は挿入順） | `ebde280106257101672f3c27f9996225f96a142f9022d0fa2efaa5b5d630cb61` | MIRROR |
| `src/stages/results.js reconstructCanonicalRosterPayloads index order` | `workers/game_workers/game-master-DO.js:7511-7514`（`rebuildAndPublishRosterManifest` の index 用 groupId sort と indexText） | `9e4206afcf1aa3579903b523eb55dde7ef7c5c4be9641a9f8a2224dbe3329c84` | MIRROR |
| `src/stages/results.js reconstructCanonicalRosterPayloads manifest order` | `workers/game_workers/game-master-DO.js:7547-7548`（同関数の groups.sort と manifestText） | `6a41a1467ea787aa4dc9942ee15a46be57f83fa5e76eba6f09abca3c37a61f56` | MIRROR |
| `src/stages/grouping.js getGroupSizeDistribution` | `workers/game_workers/game-master-DO.js:18701-18707` | `bb24b57c75500851c6d8751c2bb8b649a6f256e1cc1a3d92913c1f78aa39a8be` | MIRROR |
| `test/players.mjs buildSubmissionPayload` | `src/components/game/SubmissionPhase.js:742-1485`（`cappedMessages`、action snapshot正規化、receipt選別・自己集約、compact sanitize再署名まで。欄は任意で、この試験束は欄を組まない。D1b の提出窓判定は C） | `8d3bdc1d69f10f9548716084bf6262102d0b59182150c590081935e85ad8496b` | MIRROR |
| `vendor/workers/game_workers/lib/load-test-context.js` | `workers/game_workers/lib/load-test-context.js` | `dfb455ef5f2b282925fa831cb1bbc9da0f0fac6d071ec3ef962fce5152e7b78b` | COPY |
| `src/stages/results.js mirrorRewardSplit` | `src/stages/results.js`（ミラー本体＝`function mirrorRewardSplit(...)` のシグネチャ行から列0の `}` まで。F-7(b)-3 の**逆方向**の固定） | `489f45c5a68da54066417e181325dc4c42aa49329618301ae24c4d955f359cb9` | MIRROR-BODY |
| `src/stages/results.js autoRosterTextFromSelection` | `src/stages/results.js`（ミラー本体） | `4aee3a139fd6ce49bcf46ff993113315e7498e3af621de873bebc5be265a4862` | MIRROR-BODY |
| `src/stages/results.js runAutoDistribute` | `src/stages/results.js`（ミラー本体＝`async function runAutoDistribute(...)` のシグネチャ行から列0の `}` まで。R26-C5 の**逆方向**の固定。周15 T5 で検証ツール固有の取得境界を250 depositId単位にし、取得不能を mismatch と分けて採点前に not_ready で止める分岐を追加。周25 Q24 の緊急再構築メタデータを再レビューし、取得成功後の正典点数計算規則が不変であることを確認） | `32d7a6ef6170af8799145d2617ea4743f3e242c15adf83034725972393f6f2f0` | MIRROR-BODY |
| `src/stages/grouping.js toPublishedShape` | `src/stages/grouping.js`（ミラー本体＝`function toPublishedShape(...)` のシグネチャ行から列0の `}` まで） | `658476c7aaec92d22ad2f8d1e530439d83e9542c1a96ebe5c9e5a598fb342d12` | MIRROR-BODY |
| `src/stages/grouping.js countGroupsByLang` | `src/stages/grouping.js`（ミラー本体＝`function countGroupsByLang(...)` のシグネチャ行から列0の `}` まで） | `5fedf0570fdb7550d910ea28e9347a77feba10b6e63cbfd58c8c569e2f68f9f3` | MIRROR-BODY |
| `src/stages/grouping.js getGroupSizeDistribution` | `src/stages/grouping.js`（ミラー本体＝`function getGroupSizeDistribution(...)` のシグネチャ行から列0の `}` まで） | `634613c9ea1e8d4c1b2b819ad94dba67fc49c4ed9c911807d53a2ebefc9b741e` | MIRROR-BODY |
| `src/stages/results.js rosterMembersOf` | `src/stages/results.js`（ミラー本体＝`export function rosterMembersOf(...)` のシグネチャ行から列0の `}` まで） | `64a1924f009af93037974cab73a97c771dffbc9620458dad4a5af77fff187f27` | MIRROR-BODY |
| `src/stages/results.js reconstructedRosterIndexSha256` | `src/stages/results.js`（ミラー本体＝`export function reconstructedRosterIndexSha256(...)` のシグネチャ行から列0の `}` まで） | `02922779c8e03763257ef04ebc7372e1caee5fa532a4b0d4111c6f49e1390f32` | MIRROR-BODY |
| `src/stages/results.js reconstructCanonicalRosterPayloads index order` | `src/stages/results.js`（ミラー本体＝`export function reconstructCanonicalRosterPayloads(...)` のシグネチャ行から列0の `}` まで） | `86b6b8edbf52e3c3e37cc13ed5dc92777de7fc0de1f9f1309be232f722d853ea` | MIRROR-BODY |
| `src/stages/results.js reconstructCanonicalRosterPayloads manifest order` | `src/stages/results.js`（ミラー本体＝`export function reconstructCanonicalRosterPayloads(...)` のシグネチャ行から列0の `}` まで） | `86b6b8edbf52e3c3e37cc13ed5dc92777de7fc0de1f9f1309be232f722d853ea` | MIRROR-BODY |
| `test/players.mjs buildSubmissionPayload` | `test/players.mjs`（fixture本体＝`export async function buildSubmissionPayload(...)` のシグネチャ行から列0の `}` まで） | `fb4a2f84c3af2c94505b406540314e6e8e85c5321e672d4e135cce838c89718a` | MIRROR-BODY |

> **2026-09-14 M1:** main の Stage 3 本番安定化を取り込んだ最終正典から COPY を再照合し、
> `game-master-DO.js` の sha256 と7本の MIRROR 行範囲を再計算した。MIRROR は関数全体ではなく、
> 検証ツールが忠実に写す意味上の窓（報酬按分・自動配布・公開グループ統計）へ合わせた。

> **2026-09-15 M1b:** no-game原因台帳、依存待ちshield、manifest欠落分類を正典から再同期した。

> **2026-09-15 周24 T2:** 依存待ちshieldの着地確認・同一intent再送・6時間発火を追加し、
> 後続の GM MIRROR 6窓を一律 +74 行移動した。各旧sha256は新位置で唯一一致した。
> GM前方の42行増加に追随して6本のMIRROR窓を移動し、窓本体のsha256不変を再確認した。

> **2026-09-15 周25 T2:** GM-LATCH（宣言intentの再照合・終端巻戻し・chain増加追従・
> chain `chatCloseAt` 期限・P4宣言床・依存待ち期限）を正典と両vendorへ byte-exact に同期した。
> GM MIRROR 6窓は旧sha256の全走査で各1箇所だけ一致し、窓本体は不変のまま移動した。

> **2026-09-16 周25 T2b:** GM-LATCH の `landing_unverified` を同一intentでは非終端の
> 着地観測待ちとして保持し、intent期限後だけchainへ戻す G8 を両vendorへ同期した。
> GM MIRROR 6窓は前方へ32行移動し、旧sha256の全走査で各1箇所だけ一致した。

> **2026-09-16 周25 Q7:** 預託を正準uid文字列で個別照合し、全体重複除外を廃止したGMを
> byte-exactに同期した。GM MIRROR 6窓は旧sha256が新位置で各1箇所だけ一致した。

> **2026-09-16 周25 Q11:** 前ブロック依存待ちのgraceを必要量だけ段階延長するGMを
> byte-exactに同期した。前方+21行に追随したGM MIRROR 6窓は旧sha256が各1箇所だけ一致した。

> **2026-09-16 周25 Q11b:** 前ブロック依存待ちのgraceを初期値から6時間刻みにし、
> 延長intentを約6時間に1件へ抑えたGMをbyte-exactに同期した。GM MIRROR 6窓は前方+4行へ追随した。

> **2026-09-16 周25 Q22:** 提出保存成功後の非権威 raw 公開、completed 遷移時の最終公開、
> R2 失敗を `submit_ack` から分離した `chat-game-DO.js` を正典から byte-exact に同期した。

> **2026-09-16 周25 Q23:** `TokenMining.hashStorage()` の実行時照合を加えた
> `game-master-DO.js` を byte-exact に同期した。GM MIRROR 6窓は旧sha256の全走査で
> 各1箇所だけ一致し、窓本体は不変のまま前方へ +3 / +94 / +111 行移動した。

> **2026-09-16 周25 Q25:** 正準でない depositId の拒否、依存待ち shield の完了時閉鎖、
> Coordinator の鍵差し替え破棄一覧の監視転送、提出公開の末尾 alarm と completed 最終版再送を
> byte-exact に同期した。GM 6窓と chat 1窓は旧sha256の全走査で各1箇所だけ一致した。
> 並行便 Q24 が `runAutoDistribute` に加えた緊急再構築メタデータもレビューし、採点規則を
> 変えていないことを確認して MIRROR-BODY の逆方向 pin のみ現物へ追随させた。

> **2026-09-17 周25 Q39:** 前ブロック依存待ちのgrace目標からQ11bの6時間境界への
> 切り上げだけを外し、経過時間＋32分の必要量へ戻したGMをbyte-exactに同期した。
> 4行減に追随したGM MIRROR 6窓は旧sha256の全走査で各1箇所だけ一致し、窓本体は不変だった。

> **2026-09-17 周25 Q52:** Q50/Q51後の `game-master-DO.js` と `block-lifecycle.js` を
> byte-exactに同期した。GM MIRROR 6窓は既存sha256の全走査で各1箇所だけ一致したため、
> 意味上の部分区間を保つ行窓方式のまま位置だけ更新した。

> **2026-09-18 周26 R4:** timeline no-game の本番用終端入口と、Evidence から読む
> RANDAO anchor window を含む GM / ChatGameDO を正典から byte-exact に同期した。
> GM MIRROR 6窓と ChatGameDO 1窓は旧sha256の全走査で各1箇所だけ一致し、窓本体は不変だった。

> **2026-09-18 周26 T1:** `admin_freeze` 待ちと棚上げ警報を含む `game-master-DO.js` を
> byte-exact に同期した。GM MIRROR 6窓は旧sha256の全走査で各1箇所だけ一致し、
> 窓本体のsha256は不変のまま位置だけ更新した。

> **2026-09-18 周26 T1b:** manifest段の `admin_freeze` 待ちと送信係の正典保留メタデータを
> 含む `game-master-DO.js` を byte-exact に同期した。GM MIRROR 6窓は旧sha256の全走査で
> 各1箇所だけ一致し、後方4窓はsha256不変のまま位置だけ+33行更新した。

> **2026-09-18 周26 T1c:** 自動配布・ゲームなし・手動APIの管理tx専用待機、送信係不達の
> 区別、`extendGrace` 凍結保護を含む `game-master-DO.js` を byte-exact に同期した。
> GM MIRROR 6窓は旧sha256の全走査で各1箇所だけ一致し、窓本体はbyte不変のまま位置だけ更新した。

> **2026-09-18 周26 T1d:** 管理tx待ち判定の一元化、root pipeline の待機・印・連続警報期間、
> read-only の凍結照会を含む `game-master-DO.js` を byte-exact に同期した。GM MIRROR 6窓は
> 旧sha256の全走査で各1箇所だけ一致し、窓本体はbyte不変のまま位置だけ更新した。

> **2026-09-19 周26 T1f:** timeline確定再開、管理tx不達の失敗会計、待機印の解消を含む
> `game-master-DO.js` を byte-exact に同期した。GM MIRROR 6窓は旧sha256の全走査で
> 各1箇所だけ一致し、窓本体はbyte不変のまま位置だけ更新した。

> **2026-09-19 周26 T1h:** no-game のR2/RPC例外再登録、棚上げ解除の永続化、復旧履歴を含む
> `game-master-DO.js` を byte-exact に同期した。GM MIRROR 6窓は窓本体のsha256不変で位置だけ+13行更新した。

> **2026-09-22 周29 便 PV:** 契約の7引数化（`submitMerkleRootWithProof` / `attachProofToMerkleRoot` の
> 第7引数 `prevRegistrationIndex`）に合わせ、ABI・HashStorage 結果登録履歴の読取
> （`readPrevResultRegistrationOnChain`）・提出 payload の第7欄を含む `game-master-DO.js` を
> byte-exact に同期した。GM MIRROR 6窓は窓本体のsha256不変で、位置だけ +28 行（前方2窓）/
> +152 行（後方4窓）更新した（同じ行数の窓を全走査し、各1箇所だけ一致することを確認）。

> **2026-09-22 周29 便 Z7:** 0履歴時の最新ビュー検算と、`prevRegistrationIndex` を含む
> proof intent ID を追加した `game-master-DO.js` を byte-exact に再同期した。
> 後方4窓は窓本体のsha256不変で位置だけ +20 行更新し、全走査で各1箇所だけ一致した。

> 🔴 **2026-08-09（ラウンド23）: MIRROR 行の第1列を `check-vendor-sync.mjs` の `MIRRORS[].name` と
> 完全一致する識別キーに揃え、`MIRROR-BODY` 行（ミラー本体側の pin）を追加した。**
> 同時に、スクリプトと本表を**機械で突き合わせる** `LEDGER MIRROR` 検査を新設した。
> それまで LEDGER 検査は COPY 行と EXTRACT 行範囲しか見ておらず、**MIRROR 行は
> スクリプトとも正典とも突き合わされていなかった**（＝本表側は書き放題で、古びても誰も気づけない）。
> 実際 `chatgame-tools` 側では同じ穴で行範囲が2本とも食い違っていた（script 329-382 / MD 326-379）。
> `mirrorSha256`（ミラー本体の pin・50/50 → 90/10 の改変を実際に捕まえた検査）は
> 本表に**行が1つも無かった**ので、`MIRROR-BODY` として載せた。

> **2026-09-10（周17 K4）:** `block-verifier/src` と `test` の明示的な `// MIRROR:` 宣言は2件、
> 対応する MIRRORS 登録も2件で全数一致する。`check-vendor-sync.mjs` が宣言集合と登録集合を
> 双方向に照合するため、今後 `// MIRROR:` だけを追加して台帳へ載せ忘れると赤になる。

> **2026-09-10（周17 D2-03）:** `test/players.mjs` の提出fixtureを宣言走査と
> MIRROR/MIRROR-BODY台帳へ追加した。本番クライアントそのものを実行する証拠ではないが、
> `SubmissionPhase.js` またはfixtureの構築が変われば同期検査が再レビューを要求する。

> 🔴 **2026-08-23（R12-19）: `src/stages/grouping.js` の台帳外ミラー3本を登録した。**
> `toPublishedShape` / `countGroupsByLang` / `getGroupSizeDistribution` の正典区間と
> ミラー本体を双方向に pin し、どちら側の変更も `check-vendor-sync` で検出する。

> 🔴 **2026-08-09（ラウンド22 タスク2-a）: `runAutoDistribute` の MIRROR 行を追加した。**
> `docs/external-audit/FINDINGS_LEDGER.md` 冒頭の指摘への対処。それまで MIRROR 行は
> `mirrorRewardSplit` の1本だけで、**正典 `autoDistribute` が変わってもミラーが追随しなくても
> `check-vendor-sync` が鳴らなかった**。J-31（自動配布経路に適格帯判定が無い）では
> 両側とも同じ穴を持ったまま「45項目・FAIL 0・WARN 0」が出ていた＝
> ミラーの同期が台帳で守られていなかったことが原因。
> 範囲は検証ツールが実際に写している点数計算部に限定する（D1/R2 書き込みや summary 生成は
> 写していないので入れない＝無関係な churn で偽 FAIL を量産させないため）。
> ⚠️ **同種の未登録ミラーが他にもないかの棚卸しは継続中。**

## 補足

- COPY 対象の選定根拠: `game-master-DO.js` の import は
  `../auth_workers/lib/cors.js` / `./lib/game-result-calculator.js` / `./lib/evidence-reconciler.js` /
  `./lib/timeline-check.js` / `viem` / `viem/accounts` / `viem/chains`。
  `game-result-calculator.js` は追加で `./lib/char-counter.js` / `./lib/protocol-v2.js` / `eciesjs` を import する。
  相対 import はリポジトリ相対構造を保存しているためそのまま解決する。npm 依存は package.json の正確ピンで解決。
- EXTRACT の理由: `lottery-DO.js` はモジュールトップで `ethers`（コミット未固定のGitHubフォーク）に依存し丸ごとベンダー不可。
  `selectWinners` は `this` 非依存の純関数のため本体のみを verbatim 抽出した（F-L5 の modulo bias 込みで無改変）。
- MIRROR は stage-C 担当が `src/stages/results.js` に `mirrorRewardSplit` として実装する
  50/50 player/depositor 按分（正典の行範囲は**上の表が正典**。ここに数字を再掲すると必ず古びる
  ＝2026-08-09 まで `5208-5366` という表と食い違う値が残っていた）の忠実ミラー。コード同一性は機械検証できないため、
  正典行範囲の sha256 で「ミラー元が変わっていないこと」のみを機械検査し、変更検出時は手動再レビューする。

> **2026-09-24 周31 M10a:** チャット開始関門の確定深さ・grace 着地待ち・手動 park 復旧を正典 GM から byte-exact に再同期した。block-verifier の GM MIRROR 6 窓は旧 sha256 の同じ行数の全走査で各1箇所だけ一致し、窓本体は不変。

> **2026-09-26 周33 便 S3C4（D-05）:** ワーカーの読み取りの順（`URLS → _URL_BACKUP → _URL → _URL_BACKUP2`）を足した `lib/rpc-urls.js`（`rpcReadUrlsFromEnv`・`describeRpcConfig` の `readOrder`／`sendOrder`）と、読み取りをその順へ切り替えた `game-master-DO.js`（同じ行での置き換えだけ・行数不変）を正典から byte-exact に同期した。GM の行数が変わらないので MIRROR の窓は位置も本体も不変。

> **2026-09-27 周33 便 S3C5（D-06）:** Evidence の取り込みの段でその場で判定し、D1 `evidence_events` には要約と判定だけを置く（中身は各 uid の採用候補だけ・cleanup で空ける）`game-master-DO.js`（`calcEvidenceUnit`・`calcLoadAdoptedRaw`・`calcFinalizeUnit`）を正典から byte-exact に同期した。GM の行は `calcEvidenceUnit` の後で +44、`calcLoadAdoptedRaw` の後で +52、`calcFinalizeUnit` の後で +69 ずれた（2026-09-27 便 S3C7 が `git diff -U0 cb48248e~1 cb48248e` の hunk から数え直して訂正。旧記載は「+69 行（`calcEvidenceUnit` 以降）」）ので、MIRROR の GM 窓5つ（mirrorRewardSplit・runAutoDistribute・toPublishedShape・countGroupsByLang・getGroupSizeDistribution）は旧 sha256 の同じ行数の窓を全走査し、それぞれ唯一一致した新しい位置へ行番号だけ動かした（sha256 と窓本体は不変）。`calcEvidenceUnit` より前の窓（6068-6093・6128-6131・6164-6165）は位置も不変。

> **2026-09-27 周33 便 S3C6（D-07）:** `/group-status?lifecycle=1` を `deep=1` と同じく API_SECRET 必須にし（無認証は 401・チェーンを読まない）、送信係の凍結中だけ `collectLifecycleBlockers` が読む Evidence.chatWindow をブロック番号を鍵にした有効期間つきの使い回し（新設 `readAdminFreezeChatCloseSec`・`BLOCK_LIFECYCLE_CACHE_TTL_MS`／`BLOCK_LIFECYCLE_CACHE_LIMIT`）へ入れた `game-master-DO.js` を正典から byte-exact に同期した。GM の MIRROR 窓8つ（6068-6093・6128-6131・6164-6165・9801-9959・14085-14210・15347-15353・15359-15369・15373-15379）はすべて `/group-status` より後・`collectLifecycleBlockers` より前にあり、`/group-status` の直しは同じ行数での置き換え（+0 行）なので、位置も sha256 も本体も不変。

> **2026-09-27 周33 便 S3C7（D-03〜D-06 の後の文書の直し・コメントだけ）:** `game-master-DO.js` のコメント3か所（`advancePhase` の飛び越し警報の「`completed` タスクの `executeAt` は宣言 `completedAt`」・`calcEvidenceUnit` の採用候補の入れ替えの収束・`submitMerkleRootOnChain` の上の RPC の読み取りの順）と `lib/protocol-v2.js` の規則の版数の履歴（v13 の項を追加）を正典から byte-exact に同期した。コメントを除いた差分はどちらも空（TypeScript の `transpileModule` の `removeComments` で比較）。GM は同じ行数での置き換え（+0 行）で、変えた行（6974-6975・8785-8789・13772）は MIRROR の GM 窓8つのどれにも入らないので、窓の位置・sha256・本体は不変。`lib/protocol-v2.js` は +6 行だが、MIRROR の源に使っていない。MIRROR `test/players.mjs buildSubmissionPayload` の源 `src/components/game/SubmissionPhase.js:406-971` は、chatHash の見出しコメント1行だけが変わった（コメントを除いた差分は空）ので、源の sha256 だけを更新した（ミラー本体は不変）。上の S3C5 の追記の行のずれ（+44／+52／+69）もこの便で訂正した。




> **2026-09-27 C30F1:** 案 U の開始後延長ガードと PV 第15語を含む `game-master-DO.js`／`lib/zkp-protocol.js` を byte-exact に同期した。GM の MIRROR 8窓は旧 sha256 の唯一一致を全走査し、中身不変のまま位置を更新した。

> **2026-09-27 便 C30F1c:** 開始関門の shield の前倒し幅を理由ごとにした（`rosterShieldLeadMs`）ことと、遅れた開始の印（`started_with_roster_late`）を書く所・消す所を変えた `game-master-DO.js` を正典から byte-exact に同期した。GM の MIRROR 8窓は旧 sha256 の同じ行数の全走査で各1箇所だけ一致し（前3窓は位置不変・後5窓は +49 行）、窓本体は不変。

> **2026-09-27 周33 便 S3C8（D-09）:** `calcFetchGroupData` で取得の失敗（例外・200 以外・JSON として読めない本文）を救済（`calcRecoverEvidenceGroupData`）より前に throw するようにした `game-master-DO.js` を正典から byte-exact に同期した。救済に入るのは「取得に成功し `members` が空か無い」ときだけ（救済の関数の中身は不変）。GM は `calcFetchGroupData` の中と `calcRecoverEvidenceGroupData` の上のコメントで +7 行。MIRROR の GM 窓8つのうち前の3つ（6107-6132・6167-6170・6203-6204）は変えた行より前なので位置も不変、後の5つ（mirrorRewardSplit・runAutoDistribute・toPublishedShape・countGroupsByLang・getGroupSizeDistribution）は旧 sha256 の同じ行数の窓を全走査し、それぞれ唯一一致した +7 行の位置（9904-10062・14188-14313・15450-15456・15462-15472・15476-15482）へ行番号だけ動かした（sha256 と窓本体は不変）。

> **2026-09-27 周33 便 S3C11（D-12・R33-F-1-01）:** WS の接続に uid ごとの本数の上限（`WS_MAX_SOCKETS_PER_UID`＝4・超えたら本人の最も古い接続を close code `WS_CLOSE_SUPERSEDED`＝4001 で閉じてから受け付ける）と、認証に通った upgrade の頻度の上限（`WS_UPGRADE_RATE_MAX`／`WS_UPGRADE_RATE_WINDOW_MS`・auth の前で 429）を置き、同じ uid の接続が残っている間は `member_disconnected` を配らないようにした `chat-game-DO.js` を正典から byte-exact に同期した。定数と helper（`openSocketsOfUidOldestFirst`・`supersedeOldSocketsOf`・`hasOtherOpenSocketOfUid` ほか）を前方へ足して +95 行。MIRROR `src/stages/results.js rosterMembersOf` の20行窓は旧 sha256 の同じ行数の全走査で唯一一致した 754-773 へ行番号だけ動かした（sha256 と窓本体は不変）。

> **2026-09-27 便 S3C11b:** `chat-game-DO.js` の OPEN＋CLOSING の uid ごと16本制限、非 OPEN の受信破棄、auth 後の同期した頻度再判定を byte-exact に同期。`rosterMembersOf` の21行窓は旧 sha256 の全走査で唯一一致した 771-791 へ移動し、中身は不変。

> **2026-09-27 周33 便 S3C13（文書の一括・コメントだけ）と S3C15b:** `game-master-DO.js`（`CALC_GROUP_WORST_MS` のコメントと、MIRROR `mirrorRewardSplit` の窓の中のコメント2行〈改名前の契約の関数名〉）と `chat-game-DO.js`（定数のコメントで +1 行）を正典から byte-exact に同期した（便は写しに触れない約束で並走したので統括が同期）。`mirrorRewardSplit` の窓は位置が不変でコメントだけが変わったので正典の窓の sha256 だけを更新し、`rosterMembersOf` の21行窓は旧 sha256 の全走査で唯一一致した 772-792 へ行番号だけ動かした。

> **2026-09-27 便 S3C15c:** `lib/protocol-v2.js` の旧 sendkey の説明コメントを正典から byte-exact に同期した。COPY sha256 は `7083d4e6db4c4d88c0152a20c41230b4a5f02138b46846e317c9d5a1450ccf5e`。MIRROR の源・窓と本体は変えていない。

> **2026-09-27 便 S3C15d:** `lib/protocol-v2.js` の旧 reshare の説明コメントを正典から byte-exact に同期した。COPY sha256 は `446f959daeb80048eaae206ec98175122daaa25fe841bba40bac00d20b8be42b`。MIRROR の源・窓と本体は変えていない。

> **2026-09-27 便 C32F1（C32-A-14）:** grace が上限（BLOCK_TIME）で頭打ちの shield でも、名簿つきで開始に達していれば開始関門の `roster_pipeline_late` の枝が遅れた開始の出口へ入るようにした `game-master-DO.js`（`extendGraceOnChain` の `already_sufficient` に頼まれたときだけ `startedWithRoster` を添える）を正典から byte-exact に同期した。GM の MIRROR 8窓は旧 sha256 の同じ行数の全走査で各1箇所だけ一致し（前3窓は +23 行・後5窓は +27 行）、窓本体は不変。

> **2026-09-27 便 C32F2（C32-B-01）:** Evidence.extendGrace の `Start in past`（新しい開始が block.timestamp − START_PAST_TOLERANCE 以下の延長を拒否）に合わせ、`extendGraceOnChain` が送る前に同じ条件で止め（`start_in_past`）、送信係の `StartInPast` を同じ理由で受け、依存 shield が古い目標を取り直し、上限で頭打ちの shield の `start_in_past` を終端にする `game-master-DO.js` を正典から byte-exact に同期した。GM の MIRROR 8窓は旧 sha256 の同じ行数の全走査で各1箇所だけ一致し（前3窓は +73 行・後5窓は +76 行）、窓本体は不変。

> **2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流）:** main（S3C8〜S3C15d）と contract-review-2026-09-r2（C32F1〜C32F3・`281d06dd`）を合流した `game-master-DO.js` を正典から byte-exact に同期した（自動の合流で写し2か所とも正典と同じバイトになった）。MIRROR の GM の窓は、同じ行数の窓を全走査して sha256 の唯一一致の位置へ付け直した（中身は不変）。

> **2026-09-29 T4（S3R1-B-2-01）:** GM の Evidence 最終集計を seq 400行ずつ、無効一覧を storage 200件ずつ、summary の report を R2 multipart part ごとのユニットへ分けた。正典と GM の COPY は byte 一致。MIRROR の GM 8窓は旧 sha256・同じ行数の全走査で各1か所に一致し、位置だけ付け直した。MIRROR-BODY は採点を変えておらず不変。

> **2026-09-29 T4b:** R2 の非最終 part を同じ 6 MiB に揃え、バイト位置から再開する GM を byte-exact に同期した。GM の MIRROR 8窓は旧 sha256 の同長全走査で各1か所に一致し、5窓の位置だけ付け直した。MIRROR-BODY は不変。

> **2026-09-29 T5（S3R1-C-4r-01・E-2r-02）:** `protocol-v2.js` の到着順包含関数追加と `chat-game-DO.js` の live 末尾公開を正典から byte-exact に同期した。`rosterMembersOf` の21行窓は、窓より前の定数追加によって 772-792 から 773-793 へ移っただけで、窓の sha256 と本体は不変。

> **2026-09-29 便 T1d:** `protocol-v2.js` のクライアント既読候補・衝突成分選抜と `evidence-trim.js` のトリムを正典から byte-exact に同期した。並走便の `zkp-protocol.js`・`roster-member-root.js`・`game-master-DO.js`・`evidence-reconciler.js` も正典を変更せず COPY を照合して同期した。GM の MIRROR 8窓は旧 sha256 の同長全走査で各1か所に一致し、窓本体を変えず行位置だけ更新した。MIRROR-BODY は不変。

> **2026-09-29 便 T1e:** `protocol-v2.js` の選抜時間上限を正典から byte-exact に同期した。GM を源とする MIRROR 8窓は不変。選び方の方式そのものは U-17 待ちのため変えていない。

> **2026-09-29 便 T1f:** U-15 のクライアント専用補助関数を含む `protocol-v2.js` を正典から byte-exact に同期し、COPY sha256 を `5fdf09e27875ac9bfc7670d6b15837357d146b96127c968a593e3035a012dac4` に更新した。採点と GM の MIRROR 本体は変更していない。

> **2026-09-29 便 T1g:** U-17 のクライアント専用選抜と警告関数を含む `protocol-v2.js` を byte-exact に COPY した。採点関数と MIRROR 本体は変更していない。

> **2026-09-29 便 T3b:** 規則版14と DO の受領時刻を含む `protocol-v2.js`・`chat-game-DO.js` を正典から byte-exact に同期した。`receiptAcceptanceRule` の pin と COPY 台帳を更新し、MIRROR 窓の内容不変を再確認した。

> **2026-09-29 便 T1j:** `protocol-v2.js` のクライアント専用 U-18 判定を正典から byte-exact に COPY した。台帳にない `vendor/workers/game_workers/lib/evidence-trim.js` は利用箇所がなく、台帳と実体の全数照合を足して削除した。`test/players.mjs buildSubmissionPayload` は受領証明の出どころ門を共通述語へ接続し、`chatCloseAt` 引数を持つ。ただし現行の呼び出し元は渡していないので、既存の窓無し fixture は U-12 と同じく fail-open であり、出どころの検査ではない（T1l で訂正）。公式の提出構築 MIRROR は `423-1029` へ広げて再計算した。採点正典と GM を源とする窓は変更していない。

> **2026-09-30 周3 便 T1:** `protocol-v2.js` のクライアント専用 U-18 端末時計退避と `chat-game-DO.js` の空の受領証明履歴を正典から byte-exact に COPY した。採点関数と MIRROR 窓の本体は不変。

> **2026-09-30 周3 便 T2:** `protocol-v2.js` のクライアント用既読選抜だけを正典から byte-exact に COPY した。成分ごとに探索・採点予算を独立させ、時計上限後も内容順候補を採る。採点関数と MIRROR 窓の本体は不変。

> **2026-09-30 周3 便 T3:** 同じ `protocol-v2.js` のクライアント用選抜だけを byte-exact に COPY した。一部重複4枚以下の枝と大きい成分の内容順位を訂正。採点関数と GM の MIRROR 窓は不変。

> **2026-10-01 S3FIX 便 B1（e4b16e05）・統括:** `SubmissionPhase.js` の handleSubmit で自己集約に確定した窓を渡す1行を、正典と写し先の両方に足した（同じ意味であることを統括が確認）。MIRROR の窓を 423-1030 にし、正典の窓の sha256 と写し先の本体の sha256 を更新した。

> **2026-10-24 WR-4:** K7 の記録と前ブロック行の選択を変更した `game-master-DO.js` を正典から byte-exact に COPY。MIRROR の本体は不変で、後方の行範囲だけを新位置へ移した。
> **S3R4 便 P2b-2c（2026-10-11）:** `clientReadReceiptAdmission` を正典から byte-exact に COPY。公式提出の MIRROR 窓は旧 sha256 と一致し、窓の中身は不変。

> **2026-10-27 WR-GROUPIO-FIX6:** `game-master-DO.js` の組分け再開、公開組一覧の読取再試行、理由別警報と復旧案内を正典から byte-exact に COPY。GM を源とする MIRROR は旧 sha256 の同長窓を HEAD の前後で全走査し、それぞれ唯一一致して本文不変を確認したため、行範囲のみ更新した。
> **2026-10-27 WR-SAFECHECK-FIX2:** 前ブロック summary の版数欄省略を版1として読む修正を GM から byte-exact に COPY。GM の MIRROR 9窓は旧 vendor 本文との同長全走査で各1件だけ一致し、後方3窓の行範囲を +1、sha256 と本文は据え置き。
> **2026-10-27 WR-SAFECHECK-FIX3:** 採用記録の可変チャンク読取と summary uid の Rust 互換検査を GM / claim codec から byte-exact に COPY。GM の MIRROR 9窓を旧 sha256 の同長全走査で照合し、各窓が唯一一致した。読取修正より後方の6窓だけ行範囲を +1、全 MIRROR 本文と sha256 は不変。

> **2026-10-31 WR-E2E-15H:** GM の証明遅延を12／14／15時間、shadow の既定・上限を15時間へ変更した正典を byte 同一で COPY。GM の MIRROR 9窓は行数・本文・sha256 が不変であることを旧本文と照合した。

> **2026-11-01 WR-E2E-AUTOZK-FIX2:** Evidence の窓の正常な確定待ちの応答・固定期限・監視を正典 GM から COPY。GM MIRROR は旧本文の一意一致で行位置だけ更新し、本文 hash と照合規則は不変。

> **2026-11-01 WR-E2E-AUTOZK-FIX3:** GM の monitor 既知flagの型、正常待ち予約失敗の失敗会計、前ブロック待ち返却前の有限開始窓再読を正典から byte-exact に COPY。MIRROR は旧本文の同長窓が新正典に一意一致することを確認し、本文hashを変えず位置だけ更新。復元 dist は規定 bundle で再生成し2回のバイト一致を検査する。
