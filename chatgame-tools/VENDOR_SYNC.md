> **2026-11-27 便 SIDES:** 組のメンバーでない人が見るチャットの左右の振り分けで、`ChatPhase.js` の前方に useMemo・prop・onRight の行を足した。ChatPhase の MIRROR の窓 `isTimestampVisible` は、旧 sha256 の同じ行数の窓を全走査した唯一一致の位置（1180-1183）へ行範囲を付け直した（中身は不変）。ほかの2窓（`hasVisibleConfirmedVote`・`chatSendBlockReason`）は足した行より前で動かない。復元のコードと dist は変えていない。
> **2026-11-26 便 STAMPFIX:** スタンプの発言に返信・いいねの道具を出さない直しで、`ChatPhase.js` の発言の行の関数に2行を足した。ChatPhase の MIRROR の窓 `isTimestampVisible` は、旧 sha256 の同じ行数の窓を全走査した唯一一致の位置（1173-1176）へ行範囲を付け直した（中身は不変）。ほかの2窓（`hasVisibleConfirmedVote`・`chatSendBlockReason`）は足した行より前で動かない。復元のコードと dist は変えていない。
> **2026-11-26 便 REPLY・STAMP（未コミット・スタンプは特許の確認でユーザーへ伺う）:** 発言へのスタンプの共有の形 `workers/game_workers/lib/reaction.js` を新しく COPY。ChatGameDO（`reaction` の口・init_response の `reactions`）と relay.js（`publishReaction`・`_handleReaction`）を正典から byte 同一で COPY。復元は verifyReaction を渡さないのでスタンプを読み飛ばす。MIRROR の窓は前方に足した行の分だけ付け直し、`chatSendBlockReason` は handleSend の返信の印の分を再レビューして窓と sha256 を付け直した。
> **2026-11-25 便 VOIDKEEP:** void の発信（受領証明の無いまま10分を過ぎた発言・投票・密告）を消さずに半透明＋「無効」の札で残す表示の判定（確定したチャット窓の内だけ）と、送り手ごとの上限（正直な送信の上限の100件・半角1万字）を `src/utils/voidDisplay.js` に置き、byte 同一で COPY した（新規）。ChatPhase の MIRROR の窓3つ（`hasVisibleConfirmedVote`・`chatSendBlockReason`・`isTimestampVisible`）は、前方に足した import・prop の行の分だけ、旧 sha256 の同長全走査の唯一一致の位置へ行範囲を付け直した（中身は不変）。復元の `renderChatLog` はこれを import する。採点・受理・提出物・受領証明の行は変えていない。復元の dist を作り直した。
> **2026-11-25 便 PLAYAT:** 参加予定時刻の事前設定（GM の集める仕事 `availability_seed`・ChatGameDO の受け取る口 `/seed-availability` と WS の印）を正典から byte 同一で COPY。採点・名簿・提出物の行は変えていない。GM・ChatGameDO を源とする MIRROR の窓は、旧 sha256 の同じ行数の窓を新しい正典で全走査し、各1か所だけ一致した位置へ行範囲だけを付け直した（本文と sha256 は据え置き）。COPY の sha256 を更新し、復元の dist を Node 22 の `npm run bundle` で作り直した。
> **版 11 便 RL11（2026-11-23）:** 既定の Nostr リレーの一覧を5本から7本にした（`nos.lol`・`relay.primal.net`・`yabu.me`・`relay.satlantis.io`・`relay.angor.io`・`purplerelay.com`・`relay.ditto.pub`。ユーザーの決め・国ごとの到達と書き込みの実測で選んだ）。正典 `src/utils/relay.js` は `DEFAULT_RELAYS` とその上のコメントだけを変え、`vendor/src/utils/relay.js` へ byte-exact に COPY（sha256 `6809b449bbf4c1de1367e5ca4b0bf3f64f5d0a6972df6a5ab2ce415aca0ff882`）。復元の設定欄（`src/recovery/app.js`）は入力欄の行数を5から8にしただけ。記録は `docs/external-audit/RELEASE_CHECKLIST.md` の R5-RELAY1／R5-RELAY2 と `audit/relay-list-v11/`。
> **2026-11-15 WR-PRE-ADMINGAS-FIX1:** GMの正常待ちからfee_cap_blockedを外した正典をbyte同一でCOPY。同じ行数の全GM MIRROR窓を旧sha256で全走査し、各1箇所に一致（行位置・本文・sha256は不変）。COPYのsha256を更新し、復元distを再生成した。ChatGameDOの写しは変更していない。
> **2026-11-15 便 WR-PRE-PRESENCE:** presence の枠を容量120・30秒に1つ戻る形にし、不変activeの合図をuidごと60秒に1回まで配る ChatGameDO を正典から byte 同一で COPY。完了した WR-PRE-ADMINGAS の GM も同期した。対象の MIRROR は旧 sha256 の同長窓を全走査し、唯一一致の位置へ行範囲だけを付け直した。dist は Node 22 の既存 build/bundle.mjs で再生成する。
> **2026-10-27 WR-RPC2-GM-FIX4:** `game-master-DO.js` を正典から byte 同一で COPY。GM MIRROR 1 窓は旧写しの本文・sha256 と新正典の同長全走査を照らし、各窓が一意に一致した。本文と sha256 は据え置き、行範囲だけ更新。
> **2026-10-27 WR-ADOPT-FIX2:** GM の Evidence レポート公開直前の注だけを訂正。正典を byte 同一で COPY。GM MIRROR は旧台帳の窓の本文と sha256 を照合し、新正典の同長全走査で各1箇所だけ一致した。本文・sha256 は据え置き、注の後方の行範囲だけ +1 行。

> **WR-E2E-S2F-ABANDON-FIX1（2026-11-11）:** GM の保存済み fallback を受信時の run（startedAt・runId）と同時 restart の requestId に結び付け、却下記録・認証 deep 表示・継続の前倒しを COPY に同期した。GM を源とする全 MIRROR 窓は旧 sha256 の同長全走査で唯一一致する位置へ移動し、窓本体と sha256 は据え置き。COPY の sha256 を更新し、chatgame-tools の dist は Node 22 の `npm run bundle` で再生成した。
> **2026-10-27 WR-RPC2-GM-FIX3:** GM・finality・admin-tx-client を正典から byte 同一で COPY。GM MIRROR 1 窓は旧写しの本文と sha256 を照合し、新正典の同長全走査で各1箇所だけ一致したため、本文・sha256を据え置き行範囲だけ更新。
> **2026-10-27 WR-RPC2-GM-FIX2:** GM-R2・GM-R3・TX-B の GM 側を正典から byte 同一で COPY。GM の MIRROR は旧 vendor の窓と正典の同長全走査で各1箇所だけ本文が一致したため、sha256 を据え置き行範囲だけ更新した。
> **2026-10-27 WR-RPC2-GM-FIX1:** Evidence の固定・名簿読取・延長判断・RPC 独立票を正典から byte 同一で COPY。GM を源とする MIRROR は旧 sha256 の同長窓を全走査し、すべて唯一一致したため本文と sha256 を据え置き、行範囲だけ更新した。
> **2026-10-27 WR-GROUPIO-FIX7:** GM の組分け再開と監視・alarm・R2 後退を正典から byte-exact に COPY。GM を源とする MIRROR は旧 sha256 の同長全走査で本文が各1箇所に一致し、行範囲だけ更新。
> **2026-10-27 WR-RPC2-GM:** GM の Evidence/grace RPC 2本一致を正典から byte-exact に COPY。GM MIRROR は旧 sha256 の同長窓を全走査し、各本文の唯一一致を確認したうえで行範囲だけを更新。finality.js を COPY 台帳へ追加。
> **WR-GROUPIO-FIX4（2026-10-27）:** `publishAutoRosterFile` MIRROR 窓を FIX2 の写しと現行正典で同長全走査し、本文が一意に byte 一致することを確認。sha256 は据え置き、行範囲だけ移した。GM の COPY sha256 を正典と写しの一致値に更新し、`npm run bundle` で `dist/` を再生成した。
> **WR-GROUPIO-FIX2（2026-10-27）:** FIX1 前の `publishAutoRosterFile` MIRROR 窓と現行正典の本文を比較し、同長全走査の一意な byte 一致を確認した。sha256 は据え置き、行範囲だけ移した。GM の COPY sha256 を現行値に合わせ、`npm run bundle` で `dist/` を再生成した。
> **WR-14-FIX3（2026-10-25）:** pre-commit の 404 と post-commit の遅延 issue を正典 GM から byte 同一で COPY。MIRROR は旧 sha256 の同長窓を全走査して一意に一致した位置へ行番号だけ移し、本体は不変。dist は Node 22 で再生成。
> **WR-14-FIX2（2026-10-25）:** post-commit の追跡修正を正典 GM から byte 同一で COPY。MIRROR は旧 sha256 の同長窓が一意に一致した位置へ行番号だけ移し、本体は不変。
> **WR-14-FIX1（2026-10-25）:** GM の post-commit 連続失敗・K6 の確定と未登録の区別・見積もりを正典から byte 同一で COPY。MIRROR は旧 sha256 の同長窓が全走査で一意に一致した位置へ行番号だけ移し、本体は不変。
> **WR-4-FIX1（2026-10-24）:** GM の記録読取・再試行を正典から COPY。MIRROR の旧 hash が同じ長さの窓に一意に一致したため、範囲だけ移した。
> **WR-4（2026-10-24）:** GM の K7 記録・証明発注の追加後、COPY を正典から更新し、MIRROR の旧 sha256 が同じ行数で唯一一致する位置へ窓を移した。
> **S3R8 段4 第2波（2026-10-19・周8 の統括）:** 便 R8-SVA8 で正典の提出窓の前が +9 行、便 R8-MSGKEY で窓の中の `cappedMessages` が発言の鍵の getter（性能だけ・鍵の値と提出のバイト列は不変）を使うようになり、窓を 580-1317→589-1326・sha256 `cee4b6c9a589…` へ取り直した（写し先 `bundle.js` の本体は据え置き）。便 R8-CLOCKBAND で `chainClock.js`（`802ea3c1…`）、便 R8-SVA8 で `submissionGuarantee.js`（`de17bd5c…`）の COPY を byte 同一に同期。復元の `app.js`・`i18n.js` が変わり dist を作り直した。

> **2026-11-19（ユーザーの指示・0ae797985・反証 D-1/D-2/D-4）:** 正典の提出窓を `731-1468` から `742-1485`（744行）・sha256 `8d3bdc1d…` へ取り直した。窓の中の差は handleSubmit の `prepareOnly`（公式のオンチェーンの準備では署名・保存だけで WS へ送らず `isSubmitting` を立てない）と送る直前の `setServerSendTried(true)` だけで、束の組立とバイト列は不変。写し先 `bundle.js` は送信も画面の state も写さないので本体は不変（宣言の行範囲のコメント1行だけを直した）。
> **S3R8 段4 第1波（2026-10-19・周8 の統括）:** 便 R8-POSTSEND で正典の提出窓の前が +15 行（中身は byte 不変・565-1302→580-1317）。便 R8-WARN2 で `receipt-warnings.js` の COPY を byte 同一に同期（sha256 `99daf5746e3c3284e0afe4fe8e07d2a473a67e84a26032872b9c5f8920b1c204`）。便 R8-RCVNAME で復元の `app.js`・`discovery.js` が変わり dist を作り直した。
> **C33F1 / C33F1-FIX1（2026-10-23）:** GM・claim-data-codec・deposit-id のコメントを正典から byte 同一に COPY し、3行の sha256 を更新した。GM は行数 18,582 を維持し、MIRROR の行範囲と本体の sha256 を再照合して据え置いた。chatgame-tools の dist は Node 22 で再生成した。
> **S3R6 便 PREVIEW（2026-10-17）:** `submissionGuarantee.js` に押す前のオンチェーンの見積もりの時刻（`onChainDryRunSubmittedAt`）と自己集約の門（`trimPlanDropsSelfAggregate`）を足し、COPY の sha256 を張り直した。提出窓（`SubmissionPhase.js:565-1302`）の前の行数と中身は変えていないので、MIRROR の範囲と sha256 は不変。dist は統括が main で作り直す。
> **S3R6 便 SYNC6B（2026-10-17）:** SV5 の提出窓の1行を正典の差分で再レビューし、SV5・SV6 の窓の前の行のずれと合わせて 565-1302 へ張り直した（写し先の本体は不変）。FREETEXT2・RESULTHASH・RESULTHASH3 の部品は復元が import しないので COPY にしない。SV8 の app.js、TIPFLOOR の relay-client.js と公式 hook の変更は MIRROR の窓と本体の外で、台帳を動かさない。dist は統括が main で作り直す。
> **S3R6 便 SYNC6（2026-10-16）:** G1 の calculator、CLOCK・CLOCK2・CLOCK3 の chainClock の COPY sha256 を実測へ合わせ、SUBMITVIEW・SUBMITVIEW2 の submissionGuarantee と TRIMWARN の trimGuaranteeCheck を COPY に登録した。提出窓は SUBMITVIEW・SUBMITVIEW2・SUBMITVIEW3・SV4 の差を正典と写し先で再レビューして張り直し、C3B の import による ChatPhase 3窓の +1 は旧 sha256 の唯一一致で移した。dist は統括が main で作り直す。
> **S3R5 便 DISP5（2026-10-14）:** 提出窓 `SubmissionPhase.js:504-1264` の中は自己検証の失敗の文言（i18n の既定文）だけが変わったので、写し先の本体は変えずに sha256 だけを張り直した。dist は統括が main で再生成した。
> **S3R5 便 SYNC2（2026-10-14）:** LOCK の priorityEvidence.js・reportGround.js、OWNH の relay.js、PLAYERNO の playerNumber.js の COPY を現物へ合わせ、旧 memberNameCollision.js を台帳から外した。LOCK の提出窓は正典と復元の確定段を再レビューして張り直し、hook の検証2窓は旧 sha の同長全走査の唯一一致位置へ移した。timeline-check.js と evidence-trim.js は注だけを直し正典から byte 同一に写した。dist は統括が main で作り直す。
> **S3R5 便 SYNC1（2026-10-13）:** 便 NAME・SELF の COPY 2本を登録し、PHASE・WIN・STORE・RELAY・SELF・PLAN の正典 sha256 を実測へ合わせた。公式 hook の検証2窓は旧 sha の同長全走査で唯一一致した位置へ移し、SELF の提出窓は正典と写し先の同じ根拠優先規則を再レビューして張り直した。dist は統括が main で再生成する。
> **S3R4 便 P2b-2b2（2026-10-11）:** 復元の保存の上限を前の保存の鍵優先と新しい鍵の均等配分に合わせ、復元の後始末に `priorityShownSeparators` を追加した。MIRROR の窓と本体は変更していない。dist は統括の取り込み時に生成する。
> **S3R4 便 P2b-2a-3（2026-10-11）:** DP の Pareto 集合を64件で打ち切って貪欲へ戻し、覚えの非文字列入力と数値の経路同点順を正典から byte-exact に COPY。Node 22 で dist を再生成。
> **S3R4 便 P2b-2b（2026-10-11）:** 表示の隠す集合から画面の記憶を引く部品を正典から byte-exact に COPY。ChatPhase の3窓と SubmissionPhase の提出窓は旧 sha256 の同長全走査で各1件だけ一致し、窓の中身は不変。
> **S3R4 便 P2b-2a-2（2026-10-11）:** 公式提出窓と復元 bundle に区切りの判定時刻・記憶を配線し、T9 の注記を訂正した。MIRROR の行範囲・正典 sha256・復元本体 sha256 を再計算した。
> **S3R4 便 P2b-2a-1（2026-10-10）:** 区切りの池と候補 A・F・M の計画を正典から byte-exact に COPY。Node 22 で dist を再生成し、MIRROR は a-2 の配線で照合する。
> **S3R4 便 C3b（2026-10-10）:** 限定ロックの旧判定を正典と COPY から削除し、復元も C3a の警告判定と状態遷移を読む。`chainClock.js` の COPY sha256 は `11388f6042267557c2e409b453b4ef1e3c8746fc1404b1462fd36c62f6135ba6`。hook の MIRROR 2窓は C3b で変えていない。`dist/` は symlink のある作業ツリーで生成せず、統括が main で生成する。
> **S3R4 便 MATURE18（2026-10-10）:** 成熟の取り寄せ直しを60秒ごとの固定の見回りにした。正典 relay.js と COPY は変えていない。公式 hook の検証 MIRROR 2窓は前方の -74 行に伴い旧 hash の同長全走査で 1014-1068・1071-1114 に一意一致し、本体は byte 不変。dist は統括が main で作り直す。
> **S3R4 便 P2b-1a（2026-10-10）:** `clientReceiptCapExcluded` と F1・F2・手数の守りを正典から COPY。公式の提出窓は隠す集合を計画へ渡す1行を含めて張り直した。block-verifier の `test/players.mjs` は欄を組まない試験の束なので MIRROR-BODY は不変。
> **S3R4 便 RPCWIN（2026-10-10）:** 最優先欄の押下時の窓の比較を公式正典から復元へ byte-exact に COPY。公式の読み比べと WS を送らない組み直しは handleSubmit、復元の読み比べは app.js、bundle.js は priorityChatWindow を4つの口だけへ渡す。MIRROR 窓と本体を再照合した。
> **S3R4 便 P2a-2（2026-10-09）:** 名簿と窓が確定した提出で E・E′ を署名前に確かめる公式・復元の配線を照合した。priority-fields.js の OPRPC-E 注記を正典から byte-exact に COPY し、MIRROR 窓と dist を更新した。
> **S3R4 便 RS-AB5（2026-10-09）:** `evidence-compact-v1.js` の guard 注記を正典から COPY。復元の旧 selectionStorage オプションを削除し、Node 22 で `dist/` を再生成。公式 hook の cleanup に同期 flush を追加した。MIRROR 窓は再照合した。
> **S3R4 便 RS-AB2（2026-10-09）:** 受理時の札ごとの覆いの事前計算を正典 `src/utils/relay.js` から byte-exact に同期。公式 hook の検証 MIRROR 2窓は、前方の6行追加に伴い旧 hash の同長全走査でそれぞれ `1088-1142`・`1145-1188` に一意一致し、本体の byte は不変。復元画面への配線を dist に反映。
> **S3R4 便 RS-0（2026-10-09）:** `protocol-v2.js`・`evidence-compact-v1.js`・`src/utils/relay.js` を byte-exact に COPY。公式の保存書き手と復元の保存を (A′) にし、画面の覆いを札ごとに覚える。提出窓は memo 引数の1行だけを加えて `429-1052` に張り直した。公式 hook の検証 MIRROR は同長の旧 hash が `1085-1139`・`1142-1185` に一意一致し、本体は不変。復元 bundle の MIRROR-BODY は不変。
> **S3R4 便 P1a-i-1（2026-10-08）:** priority-fields.js と DO・submission-limits.js を規則版数18の入口に合わせて再同期した。
> **S3R4 便 P1a-i-2（2026-10-08）:** EVC 版2と priority の符号化・復号を正典から再同期した。
> **S3R4 便 P2a-1（2026-10-08）:** 最優先欄の純粋な組み立て部品 `priorityEvidence.js` を正典から byte-exact に COPY した。両クライアントの提出経路にはまだ配線していない。
> **S3R4 便 P1a-ii（2026-10-08）:** 規則版数18の採点手順を正典から再同期し、COPY と DO・submission-limits.js の注記を照合した。

> **S3R4 便 C3a（2026-10-10）:** `chainClock.js` の警告判定と状態遷移を正典から byte 一致で COPY（sha256 `ea729c47b24b04f881e5036fdbc681cd3829baa22c8b6871ebd97a158e8e0bed`）。hook の MIRROR 2窓は前方の行数を保ち、行範囲と本体 hash は不変。`dist/` はこの作業ツリーの node_modules が main への symlink なので作り直さず、統括が main への取り込み後に作り直す。
> **S3R4 便 C1（2026-10-07）:** 規則版数17の計算器・字数カウンター・protocol-v2 を正典から byte-exact に再同期。COPY 3行の sha256 を更新。既存 MIRROR の源と本体は不変。

> **S3R4 便 T5h（2026-10-07）:** 公式 hook の限定ロックの起点は既存の chatting 表示後 effect だけに置く。同じ行の書き換えなので MIRROR 2窓の位置・sha256 は不変。復元 `app.js` の起点とタイマーは既存の `renderGameModals` の初表示枝だけに置き、Node 22 で `dist/` を再生成した。COPY 本体は不変。

> **S3R4 便 T5g（2026-10-07）:** 公式 hook の限定ロックの門と初表示時刻を更新し、前方の4行増分で MIRROR 2窓を旧 sha256 の唯一一致位置 1024-1078・1081-1124 へ付け直した。復元の同じ門と初表示時刻を `dist/` に同期した。COPY 本体は不変。

> **S3R4 便 T5f（2026-10-06）:** `src/utils/relay.js` の確定表示版数を読む入力に合わせ、正典から byte-exact に COPY（sha256 `2d12670ee100a1e6797ec91de3257cc51527776a10260baf777aa4e4e7f9d802`）。公式 hook と ChatPhase の MIRROR 5窓の行範囲・本体 hash は不変。復元の確定説明モーダルを別 root に分離し、Node 22 で `dist/` を再生成した。

> **S3R4 便 T5d（2026-10-06）:** `relay.js` の確定表示版数と ids CLOSED/EOSE のソケット照合を正典から byte-exact に COPY（sha256 `981d9a579c9c207552d5df40aabf79b06054cadf2c0bf30a55bc7f4091337c4d`）。hook の成熟タイマーと ChatPhase の表示計画の変更は MIRROR 5窓より前なので、旧 sha256 の同長全走査で各1か所だけ一致し、行範囲のみ付け直した。

> **S3R4 便 T6G（2026-10-06）:** 公式 hook の開始 poll を便 T6 前の間隔に戻した。前方の行数は差引5行減り、MIRROR 2窓は旧 sha256 の同長全走査でそれぞれ唯一一致した 914-968・971-1014 に付け直した。中身と sha256 は不変。
>
> **S3R4 便 T6（2026-10-06）:** 公式 hook の名簿・RPC 配線で前方の行数が増えたため、MIRROR 2窓を旧 sha256 の同長全走査で唯一一致した 919-973・976-1019 に付け直した。中身と sha256 は不変。
>
> **S3R4 便 T5b（2026-10-06）:** 未来破棄の通知を `FutureAdmissionMarks` に追加し、公式と復元の時計ロックが同じ入口を受ける。`chainClock.js` の2本以上の L 判定、`clientClock.js` のロック中だけの補正間隔解除を正典から byte-exact に COPY。公式 hook の MIRROR 2窓は旧 sha256 の同長全走査で唯一一致（1011-1065、1068-1111）し、中身の sha256 は不変。復元の UI と `dist/` を同期した。
> **S3R4 便 T5a（2026-10-06）:** `src/utils/relay.js` の未来印の成熟と ids 指定 REQ を `vendor/src/utils/relay.js` へ byte-exact に同期した。正典と COPY の sha256 は `77ad0bc86593cb8f52595da87399b82fec8ff3a32edef416e07d7845184710ab`。公式 hook の MIRROR 2窓は旧 sha256 の同長全走査でそれぞれ唯一一致（851-905→873-927、908-951→930-973）。中身と sha256 は不変。

> **WR-BAKE-WRITE（2026-10-26）:** 焼成済み FINAL の vkey と ELF SHA-256 を正典から byte-exact に COPY。

# VENDOR_SYNC — ベンダリング台帳（chatgame-tools）
> **S3R4 便 T5e（2026-10-06）:** `chainClock.js` の小数の L 判定を正典から byte-exact に COPY（sha256 `580223610c619567bf76b87bef31fea117f2fbae5e149f67d736a31159147b96`）。公式 hook の2つの MIRROR 窓より前の条件を同じ行数で修正し、窓 1020-1074・1077-1120 と sha256 は不変。復元のロック解除条件と Node 22 の `dist/` を同期した。
> **S3R4 便 T7（2026-10-06）:** 公式と復元の投票選択・A-3 をそろえ、正典窓を `423-1045`・sha256 `09957e57e2d2640150de7ae99057a2f8f679928dc8a57d4721536a597348a813` に更新した。復元の MIRROR-BODY sha256 は `542331bb0bed0ab3eb61ea2e600e10e02edf1328cb5be2928e126f957f925143`。
>
> **S3R4 便 T1（2026-10-05）:** 正典 `SubmissionPhase.js` の `__extras` を提出前に署名の3欄へ作り直した。MIRROR 正典窓を `423-1033` と sha256 `ad5c050a185dfbc6e4eef8af9138fff16204b5f519dbff8e7bc3e44e942198fd` に付け直した。復元の入口（vendor `relay.js`、`import-local-storage.js`、`relay-client.js`）はどれも3欄を渡すため、`bundle.js` の組み立て本体と出力は変わらず、MIRROR-BODY sha256 も再照合して据え置いた。
> **S3FIX 便 U8（2026-10-04）:** `relay.js` の発行者上限で未検証の保留を先に捨て、確かめる前に上限で捨てた写しを受け取り直せるようにした。同じ digest の確かめ済みの写しの合流も犠牲の順へ反映する。正典と COPY を byte-exact に同期し、Node 22 で `dist/` を再生成した。
> **S3FIX 便 W7F（2026-10-03）:** `relay.js` の選び直しの待ちを最大120秒にし、古い警告③にだけ使われた配線を撤去した。正典と COPY を byte-exact に同期し、Node 22 で `dist/` を再生成した。
> **S3FIX 便 W3Xa（2026-10-03）:** W3N の新しい警告③を撤去し、`receipt-warnings.js` の COPY を byte-exact に同期した（sha256 `0bc18d243ad0ce4d744f5c5c2d7bb78568560056b2de90e710e37839a81dd17f`）。密告ボタンの警告と ChatPhase の MIRROR 3窓は不変。復元の Node 22 dist を再生成した。
> **S3FIX 便 E3F（2026-10-03）:** `relay.js` の `SelectionCoalescer` と公式待ち行列の既定タイマーをブラウザでも無束縛で呼ぶ包みに直し、正典から byte-exact に同期した。注入した時計・選び直しの規則、公式 hook の MIRROR 2窓と提出物の MIRROR は不変。Node 22 で `dist/` を再生成した。
>
> **S3FIX 便 E3（2026-10-02）:** `relay.js` の `SelectionCoalescer` と待ち行列の譲りを正典から byte-exact に同期した。復元の表示選択も同じ class を使い、提出前に予約を解消する。公式 hook の MIRROR 2窓と提出物の MIRROR は不変。Node 22 で `dist/` を再生成した。
> **S3FIX 便 D1e（2026-10-02）:** `receipt-warnings.js` の見積もりを正典から byte-exact に COPY。公式フックの MIRROR 2窓は旧 sha256 の同長全走査でそれぞれ唯一一致（837-891・894-937）し、本文は不変。復元の確認と日英中の文言を反映して Node 22 で `dist/` を再生成した。
> **S3FIX 便 D1b（2026-10-02）:** `chainClock.js` と `clientClock.js` を新しい COPY として追加。`relay.js` は運営の時計の採用を撤去し、補正時計に合わせる保留のタイマーを変更して byte-exact に同期した。`SubmissionPhase.js` の MIRROR 窓内の提出窓判定は C に替わったため正典 sha256 を更新し、提出束の組立ミラー本体が不変なことを照合した。復元の時刻専用読み先・モーダルを `dist/` へ Node 22 で反映した。
> **S3FIX 便 C3（2026-10-02）:** 接続全断と tick の30秒判定を `src/utils/read-receipt-pause.js` に集約し、復元用 vendor へ byte-exact に COPY。`src/utils/relay.js` の接続状態通知も byte-exact に COPY。公式 hook の MIRROR 2窓は行範囲・sha256 とも不変。復元 `app.js`・`relay-client.js` を含む `dist/` は Node 22 で再生成した。
> **S3FIX 便 B2R（2026-10-02）:** `src/utils/evidence-trim-policy.js` と `workers/game_workers/lib/evidence-trim.js` を `bbbfd813^`（`f78bc892`）のバイト列へ戻し、両 COPY を byte-exact に同期した。sha256 はそれぞれ `e60dee7469987adf476186456ae45d4bfdd7f4950c99bf8537edab799ef29cb0`・`86a9628da7a98e17bb04c7c1aa4d7bb43bb4ec484d00ae53b57c2ce295a6e7ce`。MIRROR の正典窓と本体 sha256 は不変。`dist/` は Node 22 で再生成した。
> **S3FIX 便 FX1（2026-10-01）:** `src/utils/relay.js` の `_scheduleReconnect` を便 C より前の7行と逐語一致で復元し、`vendor/src/utils/relay.js` へ byte-exact に COPY した。COPY sha256 は `e05a31319c2a3155e7b390282823d0aab6fee6bb8c5891f8c5421cd520001169`。公式 hook の MIRROR 2窓は源を変更していないため、行範囲・本体 sha256 とも不変。`dist/` は Node 22 で再生成した。
> **S3FIX 便 SYNC3（2026-10-01）:** 便 C2 の `read-receipt-pause.js` を `src/utils/` 正典へ中身を変えずに移し、`vendor/src/utils/` へ COPY した。復元 `app.js` と歯は COPY を読む。便 C2 の `app.js`・`relay-client.js` を Node 22 の `dist/` に反映した。公式 hook の MIRROR 2窓は旧 sha256 の同長全走査で各1箇所だけ一致し、行範囲のみ更新した。便 D1a の `chainClock.js`、便 E1 の `read-selection.js` は vendor 内から import されず COPY 対象外。block-verifier 側からも新設関数は import されない。
> **S3FIX 便 SYNC2（2026-10-01）:** 便 B1 の `protocol-v2.js`・`evidence-compact-v1.js` を正典から byte-exact に再同期した。便 MD の復元 `app.js`・`i18n.js` と便 B1 の `bundle.js` を Node 22 の `dist/` に反映した。便 D1a・E1 の新設モジュールは vendor 内から import されず、便 MD の `MultiSessionModal.js` も COPY 対象ではない。`SubmissionPhase.js` の MIRROR 窓内変更は照合待ち。
> **S3FIX 便 SYNC（2026-10-01）:** 便 C の `protocol-v2.js`・`relay.js`、便 B2 の `evidence-trim.js`・`evidence-trim-policy.js` を正典から byte-exact に再同期した。便 C で公式 hook の前方を削ったため `verifyRelayInner` と `_verifyChat` の MIRROR 窓は旧 sha256 の唯一一致位置へ移した（中身・sha256 は不変）。便 D1a・E1 の新設モジュールは vendor 内の import が無く、H1 は文書のみのため COPY を追加しない。`dist/` は Node 22 で再生成した。
> **便 A2（2026-10-01・S3FIX-Q1R）:** v15 の上限比較を最早の既読時刻1つ、同点は正準順へ訂正した。`char-counter.js`・`game-result-calculator.js`・`protocol-v2.js` を正典から byte-exact に再同期し、Node 22 で `dist/` を再生成した。MIRROR 窓の本体と行範囲は不変。

> **便 A（2026-10-01・S3FIX）:** 採点の上限を最初の既読の時刻列の順に選ぶ規則版数15。`game-result-calculator.js`・`char-counter.js`・`protocol-v2.js` を正典から byte-exact に同期した。MIRROR 窓の本体は不変。


> **T1m（2026-09-30）:** `src/utils/relay.js` の既読 lease・自己発行の先行受理と、開いているリレーの EOSE 判定を byte-exact に再同期した。復元の自動既読を変更したため `dist/` を Node 22 で再生成した。
>
> **便 T3（2026-09-30）:** RelayPool の履歴 drain、未来入力と保存優先、U-17 のクライアント選抜を正典から byte-exact に同期した。公式フックの MIRROR 2窓は旧 sha256 の同長全走査で各1箇所に一致し、位置だけ +1 行。復元の `dist/` は Node 22 で再生成した。
>
> **T1l（2026-09-30）:** クライアント専用の受領証明選択・出どころ時刻・タブ間 lease を正典から byte-exact に再同期した。公式フックの署名検証 MIRROR 2窓は前方に移動したが本体ハッシュは不変。復元の取り込みと文面を変更したため `dist/` を Node 22 で再生成した。

正典（モノレポ `workers/` `src/`）から `chatgame-tools/vendor/` へ持ち込んだコードの台帳。
**COPY = cp によるバイト同一コピー / EXTRACT = 行範囲のverbatim抽出 / MIRROR = 手書き忠実ミラー**。

検査: `npm run check-vendor-sync`（= `node scripts/check-vendor-sync.mjs`）。
モノレポ内では COPY のバイト一致・MIRROR の正典行範囲sha256を検証し、不一致で exit 1。
🔴 **2026-08-08（F-7(b)）訂正**: 独立リポジトリ化後（モノレポ不在時）は照合対象が存在しないので、
スクリプトは **exit 1**（「ここでは検証できない」）で終わる。以前は skip として exit 0 を返しており、
vendor を改変した standalone コピーでも緑になっていた（実測: `MAX_DEPOSIT_WEI` を 10 ETH → 1000 ETH に
改変しても `skipping` ＋ exit 0）。
⚠️ **本表は「ドリフト検知の台帳」であって真正性の証明ではない**。vendor を書ける者は同じコミットで
この表も書ける。コピーの真正性が要るなら `HashStorage.buildHashes` への登録が必要（別項目）。

sha256 の対象: COPY 行は **vendor ファイルの生バイト**（正典と同一バイト）。
MIRROR 行は **正典ソースの該当行範囲**（1-indexed・両端含む・`\n` 結合・末尾改行なし）の sha256
（ミラー元が変わったら再レビューが必要、のシグナル）。
`check-vendor-sync.mjs` は COPY 登録の一意性も検査し、同じ vendor/source 組の二重計上を失敗にする。
また `// MIRROR: path:start-end` 形式の宣言は、台帳の `source` / `startLine` / `endLine` と
数値まで一致することを検査する（宣言文字列だけを台帳側へ複写して空振りさせない）。


## 🔴 dist の再ホスティング／registerBuildHash はここでは行わない（2026-08-26 ユーザー確定）

`npm run bundle` でローカル `dist/` を最新の `vendor/` へ揃えることと、
**その成果物をホスティングへ上げて `registerBuildHash` すること**は**別の作業**である。

🔴 **後者は契約バッチの最後にセットで行う。単独で先行させてはいけない。**

| 理由 | 出典 |
|---|---|
| 🔴 **darwin でビルドした成果物を登録・配信すると、linux で再現した第三者とバイトが一致せず「改ざん」に見える**。登録・配信するのは **Docker `node:20-bookworm` の linux-x64 で clean checkout から二重ビルドし 0 byte diff を確認した成果物**だけ | `docs/OPS_TASKS.md:316`（⑤） |
| 🔴 config.js のアドレス更新／dist 再ホスティング／`registerBuildHash`／`.env.production` は**4つで1セット**。1つでも抜けると第三者検証ツールが正しい本番を「不正」と判定する | `docs/CLAIM_LEAF_DEPOSITID_INVENTORY.md:193` |
| `registerBuildHash(<N>, ...)` の `<N>` は**単調増加するリリース番号**。vkey バッチ（U2 の L4 実測）が残っている間に消費しない | `docs/OPS_TASKS.md:369` |

⇒ 🔴 **ローカル `dist/` がコミット済みで `check-vendor-sync` が緑なら、この時点でやることは無い。**

---

> **S3R4 便 RS:** 既読の選び方を撤去し、重なる既読を受け入れて運ぶ。正典・COPY・提出の MIRROR を更新し、旧 COPY 行を削除した。

## COPY（byte-exact・repo相対構造を保存＝相対importがそのまま解決）

| vendor path | source path | sha256 | type |
|---|---|---|---|
| `vendor/workers/game_workers/lib/protocol-v2.js` | `workers/game_workers/lib/protocol-v2.js` | `6e7a9eb7b6b619481de7799df812290be3afcb244a51fbc839082a0b542e5a69` | COPY |
| `vendor/workers/game_workers/lib/submission-limits.js` | `workers/game_workers/lib/submission-limits.js` | `22976d4c33b8d4e793b4c26910c7185cb09ff80705f7b80d1791353bf1e6056b` | COPY |
| `vendor/workers/game_workers/lib/priority-fields.js` | `workers/game_workers/lib/priority-fields.js` | `b7437dc57fa403c562f0a99d10e155fa07bf182eac95904f80a12c6f53a0e2ec` | COPY |
| `vendor/workers/game_workers/lib/evidence-compact-v1.js` | `workers/game_workers/lib/evidence-compact-v1.js` | `133523bd5dafb9c7aafcd557119401be7ab05ebee596abe17021a871caa96f2c` | COPY |
| `vendor/workers/game_workers/lib/evidence-trim.js` | `workers/game_workers/lib/evidence-trim.js` | `d637a5a8f316612c7467da29947f55611ad79a81055a976d9d8bb051fc2dc90f` | COPY |
| `vendor/workers/game_workers/lib/zkp-protocol.js` | `workers/game_workers/lib/zkp-protocol.js` | `b7a968747de416c752264b598842b4d7b0919647c7039070f7baaa064aa46172` | COPY |
| `vendor/workers/game_workers/lib/roster-member-root.js` | `workers/game_workers/lib/roster-member-root.js` | `de7e359205c8abb590acc40384f7abb7bb768ed62181aa8f78fcb1b407641564` | COPY |
| `vendor/workers/game_workers/lib/evidence-sender-vectors.json` | `workers/game_workers/lib/evidence-sender-vectors.json` | `faa23efaa3455e6fd8507fa970a80f2ee47158f124c0bc21d776a43bea5d539d` | COPY |
| `vendor/workers/game_workers/lib/group-witness.js` | `workers/game_workers/lib/group-witness.js` | `b658cea31609c05e218f1a510a1114718106daf395180d6ec8eabf823be2c3ce` | COPY |
| `vendor/workers/entry_workers/lib/deposit-id.js` | `workers/entry_workers/lib/deposit-id.js` | `082dd30c8b6244567bbe0df0f94350a4dda1eb5c18eef570e974f27890f14e58` | COPY |
| `vendor/workers/entry_workers/lib/nostr-key.js` | `workers/entry_workers/lib/nostr-key.js` | `b64777b36b2b6fc100bbe1217bb72f477872b5dfe9795d0a1d0465bb17451307` | COPY |
| `vendor/workers/game_workers/lib/char-counter.js` | `workers/game_workers/lib/char-counter.js` | `ac2d679c0adc5a725de39687489bfe94057ec9f4006d60778537dd4d3c3bfe87` | COPY |
| `vendor/workers/game_workers/lib/game-result-calculator.js` | `workers/game_workers/lib/game-result-calculator.js` | `887f3f15a20ebb6de68fb663f15d8daa24ed01c354954ff754fbd764dab7f2d5` | COPY |
| `vendor/workers/game_workers/lib/evidence-reconciler.js` | `workers/game_workers/lib/evidence-reconciler.js` | `d83e723ba4edeef68507bfdb7a6dbbe1b6f0c29c8cad62d43d10cb2119875fa0` | COPY |
| `vendor/workers/game_workers/lib/finality.js` | `workers/game_workers/lib/finality.js` | `efc5af8d969692f8c54497178ef85389f120ffb51c5d7131e0e6211065497745` | COPY |
| `vendor/workers/game_workers/lib/evidence-segment-plan.js` | `workers/game_workers/lib/evidence-segment-plan.js` | `c996e7f55b589d8bbe2c41d1e825256cae9183d71fb843732d2c31c540fea3f6` | COPY |
| `vendor/workers/game_workers/lib/getlogs-adaptive.js` | `workers/game_workers/lib/getlogs-adaptive.js` | `208c542eac569f2e9bf50e901ab6306866297a214d02ada19eeeb670c9a4869b` | COPY |
| `vendor/workers/game_workers/lib/timeline-check.js` | `workers/game_workers/lib/timeline-check.js` | `a68867797b1fc497b7115d8226b6c72ec5a088d6d5239c62d00f9330c0b14dff` | COPY |
| `vendor/workers/game_workers/lib/block-lifecycle.js` | `workers/game_workers/lib/block-lifecycle.js` | `ba4c30e81ca10811fa7b8cd391038f4b1737557dbc09456fb6650d15c8bdcc2b` | COPY |
| `vendor/workers/game_workers/lib/selection-integrity.js` | `workers/game_workers/lib/selection-integrity.js` | `43fa43e7dbc08183f689810a534964a51b170369ec7f48320c3a898040510c8c` | COPY |
| `vendor/workers/game_workers/lib/grouping-integrity.js` | `workers/game_workers/lib/grouping-integrity.js` | `1fc51a515d95106c6c4af962ecfd150b112f573c6207c6b08852052c996311d9` | COPY |
| `vendor/workers/game_workers/lib/canonical-json.js` | `workers/game_workers/lib/canonical-json.js` | `8d994e475947d94a6fb8ee2845cd7047e8efd7e05ab86d62ffe72090a04e341f` | COPY |
| `vendor/workers/game_workers/lib/select-winners.js` | `workers/game_workers/lib/select-winners.js` | `04f9432845786255d21d488af3b84cb0cc09ac240610de9a6a6f6457154dd786` | COPY |
| `vendor/workers/game_workers/lib/claim-data-codec.js` | `workers/game_workers/lib/claim-data-codec.js` | `41d5a1028bdb38e6ee4d3f89a3dc15cbc4d51544197664d23de2158fae97fcf0` | COPY |
| `vendor/workers/game_workers/game-master-DO.js` | `workers/game_workers/game-master-DO.js` | `ea94fd3d7e0e68a4f151deba497af5c93f7d600f131d498426adb084129563c4` | COPY |
| `vendor/workers/game_workers/lib/roster-anchor-rule.js` | `workers/game_workers/lib/roster-anchor-rule.js` | `182deb697a5162478af2fc136b41619199b5796677a67fc09d8096a6e0d04453` | COPY |
| `vendor/workers/game_workers/lib/roster-canonical.js` | `workers/game_workers/lib/roster-canonical.js` | `03e771389271388cc3433f57e5bf8013830a451ad1c3fad741b052262bf6d0ce` | COPY |
| `vendor/workers/game_workers/chat-game-DO.js` | `workers/game_workers/chat-game-DO.js` | `8e7327c6620a091ea34c4bfcafedc70d06c10afab7e837915ceec0146a6254fb` | COPY |
| `vendor/workers/auth_workers/lib/cors.js` | `workers/auth_workers/lib/cors.js` | `bcfcfc13e854eafcc6636b74a1498e29d41fb6c210712987037c7b638ca3d296` | COPY |
| `vendor/src/utils/protocol.js` | `src/utils/protocol.js` | `7e8c45913f7640ed7b542313c7071c8fbf3f6c407756408bd15734882f2724fd` | COPY |
| `vendor/src/utils/ecies.js` | `src/utils/ecies.js` | `b52e8a64fc0d0dbbad0364ce4c2fe739a7167a70f6e06e55382271ec033f979d` | COPY |
| `vendor/src/utils/evidence-trim-policy.js` | `src/utils/evidence-trim-policy.js` | `f6a3f7a37247d925fc64cdc2abf8c7a4ba78ea215db1972f1cc3cd2f09baf3e4` | COPY |
| `vendor/src/utils/walletTools.js` | `src/utils/walletTools.js` | `864f708324d7a1cd328c63c03a2aed7e058a9c0dd3fd5788c02808a4d2c2c0c1` | COPY |
| `vendor/src/utils/p2pKeys.js` | `src/utils/p2pKeys.js` | `79a10eb0e3196d1e04450356a346c8a73c5325242bfa3e592a65fc65f8cac56f` | COPY |
| `vendor/src/utils/relay.js` | `src/utils/relay.js` | `7ba974c2f91d39d996e57d139b77a787511ed5fb798c7ccb76ed1d2fea529a45` | COPY |
| `vendor/src/utils/priorityEvidence.js` | `src/utils/priorityEvidence.js` | `1740a73d4234f20b95c4c89a3dc86bd5f88f060e2ee4274c16769cd2dd837d35` | COPY |
| `vendor/src/utils/receipt-warnings.js` | `src/utils/receipt-warnings.js` | `99daf5746e3c3284e0afe4fe8e07d2a473a67e84a26032872b9c5f8920b1c204` | COPY |
| `vendor/src/utils/chainClock.js` | `src/utils/chainClock.js` | `802ea3c15b3f6efd4630a23578e44d9ce2770f1e87240874e800e7f6a4f5f43e` | COPY |
| `vendor/src/utils/clientClock.js` | `src/utils/clientClock.js` | `f2fdcea61b80207b733988be4037e122d951cd511faeb31c3df05f694cbfdd92` | COPY |
| `vendor/src/utils/read-receipt-batching.js` | `src/utils/read-receipt-batching.js` | `9c6158e6660cdb001ef1015a807738d39378cc60bfef9696cd69018ceec77685` | COPY |
| `vendor/src/utils/read-receipt-pause.js` | `src/utils/read-receipt-pause.js` | `5fb3af66d16a3e5e35e2a17050e4fb013d3fab7549a9b444745e4adf519ae87c` | COPY |
| `vendor/src/utils/windowCompare.js` | `src/utils/windowCompare.js` | `3633dc3aad2452800f637d1d77fe64f911dcfe94f82ff1343d6db7c9f4476a03` | COPY |
| `vendor/src/utils/chainAgreement.js` | `src/utils/chainAgreement.js` | `017f786b5de633dd200afca145c0e5dfde2d321b72fd828bc1e8e30704cfc8e8` | COPY |
| `vendor/src/utils/playerNumber.js` | `src/utils/playerNumber.js` | `8fbcae4c97451264bf7a3c9004103b8f17c4381544eda7d96a944c9f530d5f79` | COPY |
| `vendor/src/utils/reportGround.js` | `src/utils/reportGround.js` | `d6bd987407e25c55be07c7dba99808d8f1460dba56f8c2a069fb56618016a938` | COPY |
| `vendor/src/utils/submissionGuarantee.js` | `src/utils/submissionGuarantee.js` | `de17bd5c67907c95bddcbf91a8c024e70bcf80e84cd4fb13c94ac4324c0aae93` | COPY |
| `vendor/src/utils/trimGuaranteeCheck.js` | `src/utils/trimGuaranteeCheck.js` | `c81139cd32d42a2fe652cf7a85cef8372371a53da08316085299ef60816dca77` | COPY |
| `vendor/src/utils/voidDisplay.js` | `src/utils/voidDisplay.js` | `3a32ba40e4985a639d5c2aacda1df7b55e9658e1b94bb28c7a06c949c6ffa603` | COPY |
| `vendor/workers/game_workers/lib/reaction.js` | `workers/game_workers/lib/reaction.js` | `167fef1444fc2e526894fe9cd360e25e93297b27c4484dd53af0b0257aaeee97` | COPY |
| `vendor/workers/game_workers/lib/service-binding.js` | `workers/game_workers/lib/service-binding.js` | `c5822b482a89a8cd5152d948cb1d134daf60011f3a0f1fdb34058c9021cee337` | COPY |
| `vendor/workers/game_workers/lib/admin-tx-client.js` | `workers/game_workers/lib/admin-tx-client.js` | `e28a10df8cedb10943ae2d156756477beb2d1b76f5d85d8de17e7cf24b2def80` | COPY |
| `vendor/workers/game_workers/lib/rpc-urls.js` | `workers/game_workers/lib/rpc-urls.js` | `f3d0bdb1e69b365a95bf11440a07acbbbc2754da83ba7b3a2607726af07d073b` | COPY |
| `vendor/workers/game_workers/lib/rpc-independence.js` | `workers/game_workers/lib/rpc-independence.js` | `8d5c93a56942b7d5c1af6bebf8e2e38d5c9903baffa81ddbe4312ec3c9141b5b` | COPY |
| `vendor/workers/game_workers/lib/alert.js` | `workers/game_workers/lib/alert.js` | `35781307cc3497b6e30a4741e4e4e853d3743d803bce0bea7ea69ac682414e64` | COPY |
| `vendor/workers/game_workers/lib/observation-write-failures.js` | `workers/game_workers/lib/observation-write-failures.js` | `25916214d12e97ef11a8ad424b73ccb6878667578d3e7d5ac3a3a9aceb201cfa` | COPY |
| `vendor/workers/game_workers/lib/load-test-context.js` | `workers/game_workers/lib/load-test-context.js` | `dfb455ef5f2b282925fa831cb1bbc9da0f0fac6d071ec3ef962fce5152e7b78b` | COPY |

> **2026-09-14 M1:** main の Stage 3 本番安定化を取り込んだ最終正典から COPY を再照合し、
> `game-master-DO.js` の vendor 写しと sha256 を更新した。その他の衝突行は stage4-review 側の
> より新しい正典と byte-exact な値を維持した。

> **2026-09-15 M1b:** no-game原因台帳、依存待ちshield、manifest欠落分類を含む
> `game-master-DO.js` / `timeline-check.js` / `grouping-integrity.js` を正典から再同期した。

> **2026-09-15 周24 T2:** 依存待ちshieldの着地確認・同一intent再送・6時間発火を追加した
> `game-master-DO.js` を正典から byte-exact に再同期した。

> **2026-09-15 周25 T2:** GM-LATCH（宣言intentの再照合・終端巻戻し・chain増加追従・
> chain `chatCloseAt` 期限・P4宣言床・依存待ち期限）を含む `game-master-DO.js` を
> 正典から byte-exact に再同期し、`dist/` を2回生成して決定性を確認した。

> **2026-09-16 周25 T2b:** 同一intentの `landing_unverified` を非終端の着地観測待ちにし、
> intent期限後だけchainへ戻す G8 を含む `game-master-DO.js` を byte-exact に再同期した。
> `dist/` を再生成し、2回の出力一致で決定性を確認した。

> **2026-09-16 周25 Q7:** 正準uid文字列による預託の個別照合、distinct読取上限、
> uid内集合化を含む `game-master-DO.js` を byte-exact に同期し、`dist/` を再生成した。

> **2026-09-16 周25 Q11:** 前ブロック依存待ちのgraceを必要量だけ段階延長する
> `game-master-DO.js` を byte-exact に同期し、`dist/` を再生成した。

> **2026-09-16 周25 Q11b:** 前ブロック依存待ちのgraceを初期値から6時間刻みにして
> intentを約6時間に1件へ抑えた `game-master-DO.js` をbyte-exactに同期し、`dist/` を再生成した。

> **2026-09-16 周25 Q22:** 提出保存成功後の非権威 raw 公開、completed 遷移時の最終公開、
> R2 失敗を `submit_ack` から分離した `chat-game-DO.js` を正典から byte-exact に同期し、
> 現在の vendor tree fingerprint を反映するため `dist/` を再生成した。

> **2026-09-16 周25 Q23:** `TokenMining.hashStorage()` の実行時照合を加えた
> `game-master-DO.js` を正典から byte-exact に同期し、`dist/` を再生成した。

> **2026-09-16 周25 Q25:** 正準でない depositId の拒否、依存待ち shield の完了時閉鎖、
> Coordinator の鍵差し替え破棄一覧の監視転送、提出公開の末尾 alarm と completed 最終版再送を
> 正典から byte-exact に同期した。`dist/` を2回生成し、出力一致で決定性を確認した。

> **2026-09-17 周25 Q39:** 前ブロック依存待ちのgrace目標からQ11bの6時間境界への
> 切り上げだけを外し、経過時間＋32分の必要量へ戻した `game-master-DO.js` を
> byte-exactに同期した。`dist/` は同じ入力から2回再生成し、出力のbyte一致を確認した。

> **2026-09-22 周29 便 PV:** 契約の7引数化（`submitMerkleRootWithProof` / `attachProofToMerkleRoot` の
> 第7引数 `prevRegistrationIndex`）に合わせ、ABI・HashStorage 結果登録履歴の読取・提出 payload の
> 第7欄を含む `game-master-DO.js` を byte-exact に同期し、`dist/` を再生成した。

> **2026-09-22 周29 便 Z7:** 0履歴時の最新ビュー検算と、`prevRegistrationIndex` を含む
> proof intent ID を追加した `game-master-DO.js` を byte-exact に再同期し、`dist/` を再生成した。

> **2026-09-17 周25 Q52:** Q50/Q51後の `game-master-DO.js` と `block-lifecycle.js` を
> byte-exactに同期し、現在のvendor treeから `dist/` を再生成した。

> **2026-09-18 周26 R4:** timeline no-game の本番用終端入口と、Evidence から読む
> RANDAO anchor window を含む GM / ChatGameDO を正典から byte-exact に同期し、
> 現在の vendor tree から `dist/` を再生成した。

> **2026-09-18 周26 T1:** `admin_freeze` 待ちと棚上げ警報を含む `game-master-DO.js` を
> byte-exact に同期し、現在の vendor tree から `dist/` を二重生成して決定性を確認した。

> **2026-09-18 周26 T1b:** manifest段の `admin_freeze` 待ちと送信係の正典保留メタデータを
> 含む `game-master-DO.js` を byte-exact に同期し、現在の vendor tree から `dist/` を再生成した。

> **2026-09-18 周26 T1c:** 自動配布・ゲームなし・手動APIの管理tx専用待機、送信係不達の
> 区別、`extendGrace` 凍結保護を含む `game-master-DO.js` を byte-exact に同期し、
> 現在の vendor tree から `dist/` を再生成した。

> **2026-09-18 周26 T1d:** 管理tx待ち判定の一元化、root pipeline の待機・印・連続警報期間、
> read-only の凍結照会を含む `game-master-DO.js` を byte-exact に同期し、現在の vendor treeから
> `dist/` を再生成した。

> **2026-09-19 周26 T1f:** timeline確定再開、管理tx不達の失敗会計、待機印の解消を含む
> `game-master-DO.js` を byte-exact に同期し、現在の vendor treeから `dist/` を再生成した。

> **2026-09-19 周26 T1h:** no-game のR2/RPC例外再登録、棚上げ解除の永続化、復旧履歴を含む
> `game-master-DO.js` を byte-exact に同期し、現在の vendor treeから `dist/` を再生成した。

## MIRROR（手書き忠実ミラー・実装済みになり次第 sha256 を確定）

| mirror | source range | sha256 | type |
|---|---|---|---|
| `vendor/workers/game_workers/game-master-DO.js publishAutoRosterFile` | `workers/game_workers/game-master-DO.js:17310-17319`（auto group0 の正準 writer） | `9580ed4dc1c7754e1d6c202b63527160393bcf5c84e8c2fef8e6a447888e02cd` | MIRROR |
| `src/recovery/bundle.js buildSubmissionBundle` | `src/components/game/SubmissionPhase.js:742-1485`（提出バンドルの組立。T4-3 の開始名簿・送信者確認はこの窓の外。D1b の提出窓判定は C。組み立ては `assembleSubmission`・`encodeSubmission` の2つの callback） | `8d3bdc1d69f10f9548716084bf6262102d0b59182150c590081935e85ad8496b` | MIRROR |
| `src/recovery/relay-verify.js verifyRelayInner` | `src/hooks/useGameWebSocket.js:1118-1172`（inner署名検証・chat/action/presence/receipt。55行の中身は byte 同一） | `f0a85e6c5ff2edf6c339ce7a5c5e5621dba27b42f8cd11526c195bcfc91736cf` | MIRROR |
| `src/recovery/app.js hasVisibleConfirmedVote` | `src/components/game/ChatPhase.js:282-294`（規則版数5の見える確定した投票とラスト10分の門。復元側の `hasVisibleConfirmedVote`・`canReportTarget`・純粋 helper `hasTimestampVisibleConfirmedVote` の3本を連結した hash） | `ee4215ec57745f108e5db9f6ff196ed74f70d9902312ad7e8a0a80041cef9a3e` | MIRROR |
| `src/recovery/app.js chatSendBlockReason` | `src/components/game/ChatPhase.js:365-387`（`handleSend` の4ゲート＝可視内容 / 1メッセージ上限 / 発言数上限 / 総文字数上限。W3N と P2b-1b で前方の行だけ移動し、中身は byte 一致） | `385afcbfcf7bc432d6caf8b75597672b69f6bab7483e36136643ad8bd7e32712` | MIRROR |
| `src/recovery/relay-client.js _verifyChat` | `src/hooks/useGameWebSocket.js:1175-1218`（`verifyIncomingMessage` の v2 経路。署名検証後に共有の未来印を照合・記録する） | `d09af814385d5ddb7d8e2cdb580dc1e7f42b16d18edcbc8faee5048597cb76ad` | MIRROR |
| `src/recovery/discovery.js verifyLiveRosterAnchor` | `src/utils/roster-verification.js:204-423`（開始時に公開全組の実バイトを sha256 照合し、正本の C とチェーンの正典値を比較。復元側は `chain.js` に正典行選択を委譲。T1i で画面側の C 照合後の cache 保存と mismatch 時の破棄を再レビュー） | `3e6c955b73d1db93ffb84567f6ed27062536c8cba815a5a66758cd144e0b01e0` | MIRROR |
| `src/recovery/app.js isTimestampVisible` | `src/components/game/ChatPhase.js:1180-1183`（未来 timestamp を端末時刻が厳密に超えるまで表示・カウントしない述語。W3N と P2b-1b で前方の行だけ移動し、中身は byte 一致） | `d094f4d3dc282229ddf76e8c5066c511304d97544e83cad26ec2bff7afb16473` | MIRROR |
| `vendor/workers/game_workers/game-master-DO.js publishAutoRosterFile` | `vendor/workers/game_workers/game-master-DO.js`（正準 writer の byte 固定） | `9580ed4dc1c7754e1d6c202b63527160393bcf5c84e8c2fef8e6a447888e02cd` | MIRROR-BODY |
| `src/recovery/bundle.js buildSubmissionBundle` | `src/recovery/bundle.js`（ミラー本体） | `31e2bc39e85e82d5b40a4ae08557a0fe45ace5f605d2aad66ff6098fcea249e7` | MIRROR-BODY |
| `src/recovery/relay-verify.js verifyRelayInner` | `src/recovery/relay-verify.js`（ミラー本体） | `b6a09ba571fd787d93fb271a2bc42f03d15d8bb2e796049175b0761e8ff2e1f9` | MIRROR-BODY |
| `src/recovery/app.js hasVisibleConfirmedVote` | `src/recovery/app.js`（`hasVisibleConfirmedVote`・`canReportTarget`・`hasTimestampVisibleConfirmedVote` の3関数本体） | `1bad2054d6a912050208b44e4125c2a46c4260dbe9bfb56dcd4a5973d1a9ae9f` | MIRROR-BODY |
| `src/recovery/app.js chatSendBlockReason` | `src/recovery/app.js`（ミラー本体） | `b0efdf815247aeef164a6e976463c02a39e02b35b300c50dbfae9bffcb4f2b05` | MIRROR-BODY |
| `src/recovery/relay-client.js _verifyChat` | `src/recovery/relay-client.js`（ミラー本体） | `7768aa31554cc580fa9dfe5317163bdb4573c63f6122a1c214a4de140b7928f2` | MIRROR-BODY |
| `src/recovery/discovery.js verifyLiveRosterAnchor` | `src/recovery/discovery.js`（正典行を読み全組ファイルから C と本人 proof を計算する復元側本体） | `d3dbe0069e0d39f710867813434474dbd2a6d3378a629745e215408f954a6f1c` | MIRROR-BODY |
| `src/recovery/app.js isTimestampVisible` | `src/recovery/app.js`（ミラー本体） | `6a1ccbdc7629c20aa8d70feeefe4c6adaf8ecb64bc020559c0ef2efdd0b72310` | MIRROR-BODY |

既知の MIRROR 例外（PASS-MIRROR-01・前のコード）: 自分の投票候補の受領証明が宣言窓の外だけにあると公式と復元で `votes` の選択と提出バイト列が割れるが、確認した盤面の採点は同じだった。

既知の MIRROR 例外（S3R5-E-2-03・前のコード）: 宣言窓の外の行動への受領証明は、公式の待ち行列が捨て、復元は受け入れて束の第2階層で運ぶ。提出バイト列だけが割れ、採点は同じ。

> 🔴 **2026-08-09（ラウンド22 タスク2-a）: 未登録の手写しミラーを2本追加した。**
> それまで MIRROR 行は `bundle.js` と `relay-verify.js` の2本だけで、
> `src/recovery/app.js`（本体 `ChatPhase.js` の入口ゲートの手写し）と
> `src/recovery/relay-client.js` の `_verifyChat`（自分で「MIRROR相当」と書いてあるのに未登録）が
> 台帳の外にあった。**正典にゲートが増えても `check-vendor-sync` が鳴らない**状態で、
> 実際に送信側の4ゲートが1つも移植されておらず、1メッセージ上限超の貼り付けが警告ゼロで送信でき、
> 画面 2,142字/20ターン ⇄ 採点 1,140字/**19ターン**（`min_messages` 失格）という形で表に出た。
> **2026-09-07（周14 T7）:** `chatgame-tools/src` の明示的な `// MIRROR:` 宣言は3件、
> MIRRORS 登録も3件で全数一致する。`block-verifier/src` は宣言1件／登録1件。
> 両 `check-vendor-sync.mjs` が宣言集合と登録集合を双方向に照合するため、今後の未登録宣言も赤になる。

## DIST（配信物が現在の vendor/・src/・config.js から作られているか・R-6・2026-08-09 追加）

`dist/build-info.json` に**ビルド時点の `vendor/` と `src/` のツリー指紋**（相対パス昇順の
`path sha256` 行を連結した sha256 ＋ 各ファイルの sha256）と、ツリー外にある
**`config.js` の単独 sha256** を焼き、`npm run check-vendor-sync` が現在値と突き合わせる。
いずれかがズレたら exit 1。`config.js` は契約アドレス（ブロックキーの導出ドメインと
Evidence の提出先）を持つため、配布 `dist` だけ古い状態も検出対象にする。

**なぜ必要か**: 従来 `check-vendor-sync.mjs` に `dist` の参照が **0 件**で、
「ソースは新しいのにビルドが古い」を自動検知する仕掛けが無かった。実例として
P-2026-0842（投票・密告の平文を固定長パディング）でソース（`vendor/src/utils/ecies.js`）だけが
進み、配信済みの `dist/recovery.bundle.js`（2026-08-06 15:14 ビルド）はパディング無しの
暗号文を作る状態だった。正典が暗号文長（450 hex）を強制した瞬間、そのクライアントで
投票した人は `no_vote` 相当で無言に落ち、その人に投票していた第三者も投票ボーナスを失う
（実測・3人組: 600 → 300）。**エラーも警告も出ない。**

⚠️ `build-info.json` の `files`（dist 実体のハッシュ）を dist と突き合わせるだけでは**不足**。
ソースを更新してもビルドしなければ dist も build-info も動かず、両方古いまま整合してしまう。
基準は必ず**現在の `vendor/`・`src/`・`config.js`**。

> （2026-09-28 S3R1 の注記: この検査は現在緑で、`dist/` は現在の `vendor/`・`src/`・`config.js` からの再生成物とバイト同一。旧「既知の赤」は解消済み。今後赤になった場合は古い配信物として扱う。再ホスティングと `registerBuildHash` は契約バッチの手順に従う。）
> 指紋計算 `digestVendorTree()` は `build/bundle.mjs` と `scripts/check-vendor-sync.mjs` の
> **2箇所に byte 同一で置いてある**。片方だけ変えると突き合わせが必ず失敗する。

## 補足

- COPY 対象の依存閉包:
  - `src/utils/submissionGuarantee.js` → `../../workers/game_workers/lib/{game-result-calculator,priority-fields,char-counter,evidence-compact-v1,protocol-v2}.js`・`./ecies.js`・`viem`（公式と復元の提出の区画で同じ要約）。
  - `src/utils/trimGuaranteeCheck.js` → `./submissionGuarantee.js`・`../../workers/game_workers/lib/{evidence-trim,protocol-v2}.js`（公式・救済・復元の切り詰めの確認で同じ比べ）。
  - `src/utils/voidDisplay.js` → `./protocol.js`・`../../workers/game_workers/lib/char-counter.js`（公式のチャットの記録と復元の `renderChatLog` で、void の行を残す判定と送り手ごとの上限が同じ）。
  - `src/utils/relay.js` → `./p2pKeys.js`（vendor/src/utils/p2pKeys.js）・`./protocol.js`（vendor/src/utils/protocol.js）・
    `../../workers/game_workers/lib/protocol-v2.js`（vendor/workers/…）・
    `../../workers/game_workers/lib/char-counter.js`（vendor/workers/…）・
    `viem` / `@noble/hashes` / `@noble/curves`（npm）。
  - `src/recovery/app.js` → `vendor/src/utils/read-receipt-batching.js`（本体 hook と同じ自動既読バッチ間隔）。
  - `src/utils/protocol.js` → `../../workers/game_workers/lib/protocol-v2.js`（vendor/workers/…・repo相対で解決）。
  - `src/utils/ecies.js` → `eciesjs`（npm・CJS。browser条件で `@noble/ciphers` gcm を使う＝16B nonce/tag先）。
  - `src/utils/evidence-trim-policy.js` → `workers/game_workers/lib/{char-counter,game-result-calculator,protocol-v2,submission-limits,priority-fields}.js` と `src/utils/ecies.js`。本体／復元でA〜H分類を共有する。
  - `workers/game_workers/lib/evidence-trim.js` → `evidence-compact-v1.js` / `protocol-v2.js` / `priority-fields.js` / `char-counter.js` / `game-result-calculator.js` / `submission-limits.js` / `src/utils/evidence-trim-policy.js` / `viem`。本体／復元で容量計測・帰属・トリムを共有する。
  - `game-result-calculator.js` → `./char-counter.js` / `./protocol-v2.js` / `eciesjs` / `viem`。
  - `evidence-reconciler.js` → `./protocol-v2.js` / `viem`。
  - `game-master-DO.js` → `../auth_workers/lib/cors.js` / `./lib/*` / `viem`（fixture生成・grouping再現用）。
- **config注入化して使う（byte-exactでない・ベンダーしない）**:
  `src/utils/evidence.js`（NEXT_PUBLIC_EVIDENCE 依存）・`src/utils/rpcClient.js`（NEXT_PUBLIC_RPC 依存）は
  ハッシュ/署名バイトに無関係（gzip選択規則・ABI・R4順序のみ）ので、config注入版を `src/common/` に忠実再現する
  （256B規則・ABI・R4順序は DESIGN §2.4/§3.4 の通り byte 影響のある部分を保存）。
- 依存ピン（正典root解決値）: `viem@2.42.0 eciesjs@0.4.17 @noble/curves@1.9.1 @noble/hashes@1.8.0 @noble/ciphers@1.3.0`
  （eciesjs内 @noble/curves は nested 1.9.7）。Node >= 20。

> **2026-09-24 周31 M10a:** チャット開始関門の確定深さ・grace 着地待ち・手動 park 復旧を正典 GM から byte-exact に再同期した。block-verifier の GM MIRROR 6 窓は旧 sha256 の同じ行数の全走査で各1箇所だけ一致し、窓本体は不変。

> **2026-09-26 周33 便 S3C4（D-05）:** ワーカーの読み取りの順（`URLS → _URL_BACKUP → _URL → _URL_BACKUP2`）を足した `lib/rpc-urls.js`（`rpcReadUrlsFromEnv`・`describeRpcConfig` の `readOrder`／`sendOrder`）と、読み取りをその順へ切り替えた `game-master-DO.js`（同じ行での置き換えだけ・行数不変）を正典から byte-exact に同期した。GM の行数が変わらないので MIRROR の窓は位置も本体も不変。

> **2026-09-27 周33 便 S3C5（D-06）:** Evidence の取り込みの段でその場で判定し、D1 `evidence_events` には要約と判定だけを置く（中身は各 uid の採用候補だけ・cleanup で空ける）`game-master-DO.js`（`calcEvidenceUnit`・`calcLoadAdoptedRaw`・`calcFinalizeUnit`）を正典から byte-exact に同期し、`dist/` を既存の手順（`npm run bundle`）で作り直した。chatgame-tools に GM の MIRROR 窓は無い。

> **2026-09-27 周33 便 S3C6（D-07）:** `/group-status?lifecycle=1` を `deep=1` と同じく API_SECRET 必須にし（無認証は 401・チェーンを読まない）、送信係の凍結中だけ `collectLifecycleBlockers` が読む Evidence.chatWindow をブロック番号を鍵にした有効期間つきの使い回し（新設 `readAdminFreezeChatCloseSec`・`BLOCK_LIFECYCLE_CACHE_TTL_MS`／`BLOCK_LIFECYCLE_CACHE_LIMIT`）へ入れた `game-master-DO.js` を正典から byte-exact に同期した。`dist/` を既存の手順（`npm run bundle`）で作り直した。chatgame-tools に GM の MIRROR 窓は無い。

> **2026-09-27 周33 便 S3C7（D-03〜D-06 の後の文書の直し・コメントだけ）:** `game-master-DO.js` のコメント3か所と `lib/protocol-v2.js` の規則の版数の履歴（v13 の項を追加）を正典から byte-exact に同期した（コメントを除いた差分はどちらも空）。MIRROR `src/recovery/bundle.js buildSubmissionBundle` は、正典（`src/components/game/SubmissionPhase.js:409-1000` の chatHash の見出し）とミラー（`bundle.js` の chatHash の見出し）のコメント1行ずつを規則版13 の chatHash の呼び名へ直しただけなので、源と本体の sha256 だけを更新した（窓の位置は不変）。`dist/` を既存の手順（`npm run bundle`）で作り直した。




> **2026-09-27 C30F1:** `game-master-DO.js`／`lib/zkp-protocol.js` を正典から byte-exact に同期した。`dist/` は `tmp/C30F1/chatgame-stage/` にオフライン依存を配置して再生成し、生成物をこのディレクトリへ反映した。元の `node_modules` は別作業ツリーを指す symlink なので、その実体は読まない。

> **2026-09-27 便 C30F1c:** 開始関門の shield の前倒し幅（`rosterShieldLeadMs`）と遅れた開始の印の書き場所・消し場所を変えた `game-master-DO.js` を正典から byte-exact に同期し、`dist/` を `npm run bundle` で再生成した。

> **2026-09-27 周33 便 S3C8（D-09）:** `calcFetchGroupData` で取得の失敗（例外・200 以外・JSON として読めない本文）を救済（`calcRecoverEvidenceGroupData`）より前に throw するようにした `game-master-DO.js`（+7 行）を正典から byte-exact に同期し、`dist/` を既存の手順（`npm run bundle`）で作り直した。chatgame-tools に GM の MIRROR 窓は無い。

> **2026-09-27 周33 便 S3C11（D-12・R33-F-1-01）:** WS の接続に uid ごとの本数の上限（超えたら本人の最も古い接続を close code 4001 で閉じる）と upgrade の頻度の上限を置いた `chat-game-DO.js` を正典から byte-exact に同期し、`dist/` を既存の手順（`npm run bundle`）で作り直した。正典 `src/hooks/useGameWebSocket.js` は冒頭に close code の定数（3行）を足し、onclose でその code のときに自動の再接続をしない枝を足した（MIRROR の窓より後ろ）。MIRROR `verifyRelayInner`（60行窓）と `_verifyChat`（39行窓）は旧 sha256 の同じ行数の全走査で唯一一致した 656-715・718-756 へ行番号だけ動かした（sha256 と窓本体は不変）。復元クライアントは DO の WS を使わない（WebSocket は Nostr リレーだけ）ので、close code の扱いは対象外。

> **2026-09-27 便 S3C11b:** `chat-game-DO.js` の uid ごと合計16本・非 OPEN の受信破棄・auth 後の再判定を byte-exact に同期。`useGameWebSocket.js` は変更していないため MIRROR 窓の範囲と sha256 は不変。`dist/` は `npm run bundle` で再生成。

> **2026-09-27 便 S3C14b（D-08 の直しへの反証の追い便）:** `src/utils/p2pKeys.js`（`deriveNostrKey` のブロック番号の検査を厳しくした）と `src/utils/relay.js` を正典から byte-exact に同期した（便は写しに触れない約束で並走したので、統括が同期）。`dist/` は S3C11b と S3C14b の変更を合わせて `npm run bundle`（Node 22）で作り直した。

> **2026-09-27 周33 便 S3C13（文書の一括・コメントだけ）:** `game-master-DO.js` と `chat-game-DO.js` のコメントの直しを正典から byte-exact に同期し（便は写しに触れない約束で並走したので統括が同期）、S3C15b の変更と合わせて `dist/` を `npm run bundle`（Node 22）で作り直した。chatgame-tools に GM・ChatGameDO の MIRROR 窓は無い。

> **2026-09-27 便 S3C15c:** 履歴ページのカーソルを直した `src/utils/relay.js` と、旧 sendkey の説明コメントを直した `workers/game_workers/lib/protocol-v2.js` を正典から byte-exact に同期した。COPY sha256 は順に `f0e24664c49ce7b39735cdd4f350ea9337863ac4928ffd65186c2044c9ae8567`、`7083d4e6db4c4d88c0152a20c41230b4a5f02138b46846e317c9d5a1450ccf5e`。MIRROR の窓・本体は不変。Node 22 の `npm run bundle` で `dist/` を再生成した。

> **2026-09-27 便 S3C15d:** 履歴の既知 ID を初回検証時刻だけで O(1) 処理し、ページ当たりの既知件数、境界秒の再要求、cap 超過の送り手のカーソルを是正した `relay.js` と、旧 reshare の説明コメントを加えた `protocol-v2.js` を正典から byte-exact に同期した。COPY sha256 は順に `40b7a3bc00847890709c034a1565aab1d0e34809f005092b124ff0e99834a1de`、`446f959daeb80048eaae206ec98175122daaa25fe841bba40bac00d20b8be42b`。MIRROR の窓・本体は不変。Node 22 の `npm run bundle` で `dist/` を再生成した。

> **2026-09-27 便 C32F1（C32-A-14）:** grace が上限（BLOCK_TIME）で頭打ちの shield でも、名簿つきで開始に達していれば開始関門の `roster_pipeline_late` の枝が遅れた開始の出口へ入るようにした `game-master-DO.js` を正典から byte-exact に同期し、`dist/` を `npm run bundle` で再生成した。

> **2026-09-27 便 C32F2（C32-B-01）:** Evidence.extendGrace の `Start in past` に合わせて延長の事前検査と呼び手の扱いを足した `game-master-DO.js` を正典から byte-exact に同期し、`dist/` を再生成した。

> **2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流）:** main（S3C8〜S3C15d）と contract-review-2026-09-r2（C32F1〜C32F3・`281d06dd`）を合流した `game-master-DO.js` を正典から byte-exact に同期した（自動の合流で写し2か所とも正典と同じバイトになった）。MIRROR の GM の窓は、同じ行数の窓を全走査して sha256 の唯一一致の位置へ付け直した（中身は不変）。`dist/` は Node 22 の `npm run bundle` で作り直した。

> **2026-09-29 T4（S3R1-B-2-01）:** GM の Evidence 最終集計を seq 400行ずつ、無効一覧を storage 200件ずつ、summary の report を R2 multipart part ごとのユニットへ分けた。正典と GM の COPY は byte 一致。この台帳には GM を源とする MIRROR 窓は無い。

> **2026-09-29 T4b:** R2 の非最終 part を同じ 6 MiB に揃え、バイト位置から再開する GM を byte-exact に同期して Node 22 で `dist/` を再生成した。この台帳には GM を源とする MIRROR 窓は無い。

> **2026-09-29 T5（S3R1-C-3r-01・C-4r-01・E-2r-02）:** `relay.js` の既出鍵は形式を検査した後の生の検証対象バイト列に対応させ、`protocol-v2.js` に到着順の包含を共通関数として追加した。復元の `bundle.js` は他人の既読にこの包含を `selectBundleReceipts` より前に適用する。上表の「第10ラウンド便B/Cで選抜後だけ到着順へ戻す」は当時の変更履歴であり、現在の他人の既読の入口の順番はこの T5 の記述に従う。`chat-game-DO.js` は共有 alarm で live スナップショットの末尾公開を予約する。いずれも正典と COPY を byte 一致させ、`dist/` を Node 22 で再生成した。`bundle.js` の MIRROR は公式の取り込み待ち行列と復元のローカル選抜という既存の経路差を含む。正典窓は不変で、ミラー本体の sha256 を更新して追跡する。

> **2026-09-29 便 T1d:** `protocol-v2.js` のクライアント既読候補・衝突成分選抜、`relay.js` の保留・受領証明待機・封筒計数、`evidence-trim.js` と `evidence-trim-policy.js` のトリムを正典から byte-exact に同期した。並走便の `zkp-protocol.js`・`roster-member-root.js`・`game-master-DO.js`・`evidence-reconciler.js` も正典を変更せず COPY を照合して同期した。復元の `dist/` は Node 22 で再生成。MIRROR の既存の公式関数窓は旧 sha256 の同長全走査で各1か所に一致し、位置と必要なミラー記述だけを更新した。

> **2026-09-29 便 T1e:** `protocol-v2.js` の選抜時間上限と `relay.js` の待ち行列の間欠処理を正典から byte-exact に同期した。提出・受信・名簿の変更に対応する MIRROR 窓は現物を再確認して sha256 を更新した。復元の `dist/` は Node 22 で再生成した。選び方の方式そのものは U-17 待ちのため変えていない。

> **2026-09-29 便 T1f:** U-15 の再読込後の到着順控えと DO 履歴受理順の補助関数を `protocol-v2.js` のクライアント専用域に追加し、COPY sha256 を `5fdf09e27875ac9bfc7670d6b15837357d146b96127c968a593e3035a012dac4` に更新した。公式の MIRROR 57行・40行は旧 sha256 の同長全走査で各1か所（756-812・815-854）に一致し、本体は不変。復元の `dist/` は Node 22 で再生成した。

> **2026-09-29 便 T1g:** U-17 のクライアント選抜・一部重複警告と複数タブの既読調整を正典から COPY した。公式署名検証の MIRROR 2窓は前方の state 追加で各 +8 行、旧 sha256 が新しい窓に唯一一致し本体不変。復元は同じ選抜正典を参照し、dist を Node 22 で再生成した。

> **2026-09-29 便 T3b:** 規則版14、DO 受領時刻、受領証明の出どころを含む `protocol-v2.js`・`chat-game-DO.js`・`relay.js` を正典から byte-exact に同期した。`buildSubmissionBundle` の手書きミラーとその台帳を更新し、公式署名検証の MIRROR 窓は内容不変を確認した。復元の `dist/` は Node 22 で再生成した。

> **2026-09-29 便 T1j:** `protocol-v2.js` の U-18 出どころ述語と `relay.js` の受理後の既読印・短い複数タブ調整を正典から byte-exact に COPY した。復元 `bundle.js` は宣言 `chatCloseAt` を出どころ門へ渡し、窓が読めないときは U-12 に従い警告して提出を続ける。公式の提出構築 MIRROR は `423-1029` の内容と復元側本体を再計算した。公式署名検証の2窓はそれぞれ前方 +5 行の位置で旧 sha256 が唯一一致し、本体は変わっていない。`dist/` は Node 22 arm64 で再生成した。

> **2026-09-30 周3 便 T2:** `protocol-v2.js` の既読成分ごとの予算、`relay.js` の受領証明保存の容量上限・本人行動の専用鍵を正典から byte-exact に COPY した。復元の到着印の保存は参照先の無い既読を永続化せず、行動の印を優先する。公式の保存失敗は画面に記録一般の警告を出す。採点と MIRROR 本体は不変。`dist/` は Node 22 で再生成した。

> **2026-09-30 周3 便 T1:** `relay.js` の既読保留・未来時刻の行動と受領証明・履歴同期・既出 ID の修正、`protocol-v2.js` の U-18 端末時計退避、`chat-game-DO.js` の空の受領証明履歴を正典から COPY した。`verifyRelayInner` の正典 MIRROR 窓を 882-936 に合わせ、復元側と `dist/` を Node 22 で更新した。

> **2026-10-01 S3FIX 便 B1（e4b16e05）・統括:** `SubmissionPhase.js` の handleSubmit で自己集約に確定した窓を渡す1行を、正典と写し先の両方に足した（同じ意味であることを統括が確認）。MIRROR の窓を 423-1030 にし、正典の窓の sha256 と写し先の本体の sha256 を更新した。

> **2026-10-02 S3FIX 便 D1c:** Q18・Q12A・Q34A・Q9C の未来印、履歴再要求、既読の床を正典 `relay.js`・`chainClock.js` から byte-exact に COPY した。公式 `verifyIncomingMessage` の MIRROR は 889-932 に張り直し、復元 `_verifyChat` から `allowFuture` を除いた本体 hash を更新した。`verifyRelayInner` の本体は不変で、行範囲のみ 832-886 へ動かした。`dist/` は Node 22 arm64 で再生成した。
> **S3R4 便 P2b-2c（2026-10-11）:** `clientReadReceiptAdmission` と待ちの切り替え定数を正典から byte-exact に COPY。2回目の起動で、検証済み名簿の外の発行者を窓待ちより前に落とし、窓待ちを年齢タイマーから除いた。公式 hook の検証 MIRROR 2窓は旧 sha256 と一致し、窓の中身は不変。Node 22 で dist を再生成。
> **S3R4 便 RPC1-C:** 押下の既定の印（2票以上の一意の最多・無ければ端末の窓）と同じ読み先の1票を COPY した。
> **2026-10-11 周4 便 RPC1-B:** 公式の `src/utils/chainAgreement.js` を復元へ byte-exact に COPY し、形の検査・公開の一致・先端時刻・承認保存の純粋な規則を共用した。`dist/` はこの作業ツリーでは作らず、3便を取り込んだ後に統括が再生成する。

> **2026-10-11 周4 便 RPC1-H:** `chainAgreement.js` の COPY を帯・選んだノードの待ち・閉じた後の120秒へ更新し、byte-exact と sha256 を照合した。公式と復元の読みを同じ規則にし、`dist/` は統括が main へ取り込んだ後に作り直す。

> **2026-10-24 WR-4:** `game-master-DO.js` の K7 記録・行選択を正典から byte-exact に COPY。`publishAutoRosterFile` の MIRROR 本体は不変で行範囲を移し、Node 22 arm64 で `dist/` を再生成した。

> **2026-10-27 WR-GROUPIO-FIX6:** `game-master-DO.js` の組分け再開、公開組一覧の読取再試行、理由別警報と復旧案内を正典から byte-exact に COPY。GM を源とする MIRROR は旧 sha256 の同長窓を HEAD の前後で全走査し、それぞれ唯一一致して本文不変を確認したため、行範囲のみ更新した。 Node 22 arm64 の `npm run bundle` で `dist/` を再生成した。
> **2026-10-27 WR-SAFECHECK-FIX2:** GM の旧 summary 版数欄省略の互換修正を正典から byte-exact に COPY。GM の MIRROR 窓は旧 vendor 本文との同長全走査で1件だけ一致し、行範囲と sha256 は不変。Node 22 で dist を再生成。
> **2026-10-27 WR-SAFECHECK-FIX3:** 採用記録の可変チャンク読取と summary uid の Rust 互換検査を GM / claim codec から byte-exact に COPY。GM の MIRROR 窓は旧 sha256 の同長全走査で唯一一致し、行範囲だけ +1。本文と sha256 は不変。Node 22 で dist を再生成。

> **2026-10-31 WR-E2E-15H:** GM の証明遅延を12／14／15時間、shadow の既定・上限を15時間へ変更した正典を byte 同一で COPY。GM の MIRROR 1窓は行数・本文・sha256 が不変であることを旧本文と照合した。 `npm run bundle` で dist と build-info の指紋を再生成し、二重ビルドの全6ファイル（build-info を含む）の byte 一致を確認した。

> **2026-11-01 WR-E2E-AUTOZK-FIX2:** Evidence の窓の正常な確定待ちの応答・固定期限・監視を正典 GM から COPY。GM MIRROR は旧本文の一意一致で行位置だけ更新し、本文 hash と照合規則は不変。

> **2026-11-01 WR-E2E-AUTOZK-FIX3:** GM の monitor 既知flagの型、正常待ち予約失敗の失敗会計、前ブロック待ち返却前の有限開始窓再読を正典から byte-exact に COPY。MIRROR は旧本文の同長窓が新正典に一意一致することを確認し、本文hashを変えず位置だけ更新。復元 dist は規定 bundle で再生成し2回のバイト一致を検査する。
