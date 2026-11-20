# COINU（コいぬ）チャットゲーム補助ツール — 設計書

> 2026-07-11 確定（ユーザー要件ヒアリング反映）。
> （2026-09-28 S3R1 の注記: §0・§1・§2.3〜§2.5・§8 は後の実装で変わったため現物に合わせて訂正した。以下の設計経緯は現行仕様の正本ではない。正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` と現行コード。）
> block-verifier（完成済み・独立ブロック検証ツール）から分離した**別プロジェクト**。
> スコープ = **① F1ローダー（配信JS照合）＋ ② 最小復元クライアント（フル参加ゲームクライアント）**。
> 信頼モデルは block-verifier と共通:「運営の外に置く・チェーンに錨を下ろした独立監査コード」。

---

## 0. 大原則（block-verifier から継承・全節に優先）

- **既存実装が正・ツールは byte-exact の写像**。再現結果が合わないときはまずツールのバグを疑う。
  「改善」目的のアルゴリズム変更禁止（F-L5 の modulo bias、F7 の grindable tiebreak 等は
  受容済み＝そのまま再現）。
- 信頼アンカーは「仕様書 §6.3『チェーンの読みの一致』に従うチェーン読取」と「公開R2データ」と「ウォレット署名」のみ。復元の R4 では拡張ウォレットが答えればその1本、公開は固定3本のうち2本以上の一致、単独は警告と承認、食い違いは選択、全部無答なら設定済みの運営 RPC だけを使う。
  **運営RPC・運営WS・運営配信JS・運営配信のserverStateは根拠にしない**（照合対象であって権威ではない）。
- タイミング定数（START_TIME/BLOCK_TIME/GAME_PERIOD/SUBMIT_PERIOD/grace）は**オンチェーン getter が正**。
  env/.env の値を埋め込まない（不変量 `Evidence.START_TIME == TokenMining.START_TIME` と BLOCK_TIME/BLOCK_INTERVAL の一致を検査）。旧 TERM1 とタブーは廃止済み。
- 途中で止まっても、そこまでに確認・実行できた内容を平易な言葉でまとめて表示（3言語 en/ja/zh）。

## 1. この2機能の脅威モデル（なぜ両方要るか）

検閲面は2つあり、対策が別物である。**ローダーはコード面、復元クライアントはサービス面**を塞ぐ。

| 検閲面 | 攻撃 | 対策（本ツール） | ローダーが「✓一致」のまま? |
|---|---|---|---|
| **コード面** | 標的だけに毒入りJSを配り分け | **① F1ローダー**（配信バンドルをチェーン錨と照合） | — |
| **サービス面** | 正しいJSのまま、標的のWS切断・提出握り潰し・配信拒否 | **② 復元クライアント**（運営インフラ非依存で参加完遂） | Yes（コードは正） |

- ローダーが保証するのは**「コードの正直さ」ではなく「全員が同一コードを実行（配り分け排除）＋
  全体攻撃がオンチェーンに公開証拠化」**。標的型無音サボタージュ → 公開自爆への変換。
- ローダーの照合結果は3通り＋1: **一致→実行 / 不一致（改竄）→拒否＋証拠 / 取得失敗（配信拒否）→復元へ /
  （コードは正だがサービス面で締め出し）→ユーザーが自分で復元入口を開く**。
  よって復元クライアントは**改竄検知時の自動フォールバック**であると同時に**常時アクセス可能な独立入口**とする。

### アプリの入口構造（1アプリ2機能・静的1サイト・ウォレット接続前提）

```
チャットゲーム補助ツール（GitHub Pages 主・IPFS互換・en/ja/zh）
├─ 入口A「検証して起動」（ローダー）
│    チェーンから buildHash 読取 → 配信バンドル照合
│    ├─ 一致       → 検証SW経由でアプリ実行（普段使い）
│    ├─ 不一致     → 実行拒否＋証拠表示 → 「復元クライアントへ」
│    └─ 取得失敗   → その旨表示       → 「復元クライアントへ」
└─ 入口B「復元クライアント」（常時アクセス可）
     ウォレット署名＋公開Nostrリレー＋Evidence直接提出だけで、
     チャット（発言・閲覧）→投票・密告→結果提出の全行動を完遂
```

---

## 2. 前提事実（現行実装に照合・2026-09-28）

### 2.1 鍵導出チェーン（現行・D-08）

ウォレットの personal_sign 1回の署名から master = keccak256(署名バイト) を作る。signKey = keccak256(master || 「sign」)、encryptKey = keccak256(master || 「encrypt」) を兄弟導出する（src/utils/walletTools.js の deriveKeysFromSignature）。signKey は発言・投票・密告・受領証明の署名用で非公開を保ち、encryptKey は投票・密告の自己暗号化用で結果提出時に公開する。

blockAddress は JSON.stringify({address, pubKey, nostrPubkey}) の3キーをこの順で持つ。address と非圧縮 pubKey は signKey の口座から取り、nostrPubkey は signKey から deriveNostrKey(signKey, blockNum) で作る。Nostr 鍵の HKDF-SHA256 は salt = keccak256(「bitcoinu/p2p/nostr-key/v2」) のバイト列、info = UTF-8 の「blockNum=${N}」、長さ32バイト。無効スカラーなら ctr を付けて再試行する（src/utils/p2pKeys.js）。**Nostr 鍵はブロック単位**で、組番号を導出に入れない。

復元時は本人のウォレット署名から同じ3キーを再導出し、applicantHash に固定された自分の名簿行と照合する（chatgame-tools/src/recovery/identity.js）。名簿に Nostr 鍵が無ければ P2P 発信・受信は使えず、復元クライアントでは発言・投票・密告が届かない。オンチェーン提出はできる。

### 2.2 現行プロトコルの正準形

発言、投票、密告、受領証明は signKey の署名とブロック・組の文脈に束縛する。正準形、msgKey、chatHash v3（形は受理規則の版数13 から変わっていない）は workers/game_workers/lib/protocol-v2.js を正本にする。ターンと文字数の計算と上限の選び方（受理規則18: 最優先欄の E の和集合を先に入れ、残りを最初の既読の時刻の順で選ぶ・`capMessagesWithEvidence`〈E が空なら `capMessagesByFirstReceipt`〉）は workers/game_workers/lib/char-counter.js を、規則は docs/CHAT_GAME_SIMPLIFICATION_SPEC.md を正本にする。今の受理規則の版数（18）と密告の資格の版数（5）は protocol-v2.js の `RECEIPT_ACCEPTANCE_RULE_VERSION`・`REPORT_ELIGIBILITY_RULE_VERSION` を正本にする。P2P は chat・action・receipt・presence の4種別を平文封筒で運ぶ。sendkey、再共有、タブーの署名形式は現行の受信種別ではない。

### 2.3 提出バンドル（compact の版2・規則版数18）

`SubmissionPhase.js` は `dataString = JSON.stringify({blockNum, uid, encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds})` を登録ウォレットで署名する。`encryptedDataHash` の原像は `actionSnapshotPreimage(encryptedActions)` で、snapshot は `votes`・`reports`・`observed` と、最優先欄があれば4つ目のキー `priority`（仕様書 §6.8）を持つ。発言の本文は NFC 正規化しない。`blockKey`・`walletSignature`・タブーは現行提出形にない。提出物に載せる発言は protocol-v2.js の `clientScoreableMessages` で選ぶ。他人の発言は手元に有効な既読がある分だけを運び、上限は手元の最初の既読の時刻の順で掛け（まだ既読の無い自分の発言は最後）、選んだ後は msgKey で重複を落として正準順に並べる（受理規則版数15 からの上限の順・仕様書 §6.7）。最優先欄を置くときの組み方は仕様書 §6.8 と §6.10「最優先欄の組み立て」を正本にする。

WS と Evidence の提出は `evidence-compact-v1` のフレーム（名のまま版2・format `bitcoinu-evidence-compact/2`・提出物の形の版8・仕様書 §6.8「EVC の版2」）を使う。フレームの `blockNum`・`groupId`・名簿 `memberUids` の順序は `validateSubmissionStructure` と `validateResultBundle` が照合する。`decodeEvidenceData` は compact magic 以外を `unsupported_format` で拒否する。`verifyBundleCore` はウォレット署名、chatHash（v3・形は受理規則の版数13 から変わっていない）、`encryptedDataHash` を再計算して照合する。`submittedAt` は正準な値として検査し、truthy だけでは判定しない。正準形と提出物の同一バイト条件は仕様書 §6.6・`evidence-reconciler.js` を正本にする。

オンチェーン Evidence の seq は最小の**有効**イベントが採用される。提出前に vendored calculator/reconciler で同じ compact bytes を検証する。

### 2.4 Evidence 直接提出（復元の権威チャネル）

2026-10-02 のユーザー決定（S3FIX-W2a-TR-01）で、切り詰めの「上限を溢れた発信者の発言の最も早い既読を遅い既読より先に削らない」は取り下げた。提出物に入れる優先順位は A〜H と V の級だけで決める（自分の得点を守る観点）。いちばん早い既読を付けた人が提出しないと、正典での最初の既読時刻が鮮度の10分の内で遅く見え、上限を超えた送り手のどの100件を数えるかが変わりうる（受容・S3R3-U-FRO (6)-3 と同じ類）。級と削除順の正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` の「容量超過時のトリム」。

- `submitResult(uint256 blockNum, bytes data, bytes32 manifestHash, bytes32[] proof)` は開始前に登録された正典名簿の本人のウォレットだけが送れる（1ブロック・本人あたり3件まで）。`proof` は名簿の Merkle 所属証明で、登録値 `C = keccak256(abi.encode(keccak256(manifestText), memberRoot))` に結び付ける。Evidence の `MAX_DATA_BYTES` は **130,000 B**。提出は compact（`evidence-compact-v1` の名のまま版2）の単一形式で、gzip・生 JSON は受理しない。
- チェーンの `Evidence.chatWindow(N)` は `[応募終了, 応募終了+currentGrace(N)+GAME_PERIOD]`。`resultWindow` は `[chatCloseAt, chatCloseAt+SUBMIT_PERIOD)`。実際のチャット開始は応募終了＋grace。時刻は env 値でなくチェーンから読み、reconcile は結果窓の終了と安全ブロック確認後に行う（仕様書 §4.2・§5.2）。

### 2.5 運営インフラと復元の経路

- ChatGameDO の member WS への書込には X セッション token が要る。ウォレット署名だけの復元クライアントは P2P リレーで発信・受信し、Evidence へ直接提出する。
- 観戦 WS は廃止済み（ChatGameDO は拒否する）。ChatGameDO の `/get-results` は `API_SECRET` 必須で公開読取ではない。復元時の公開読取は R2 の `live/` 保全用写し等を使い、採点の権威はチェーンと正典提出物に置く。

### 2.6 ロスター/uid/グループの公開R2発見（ゼロサーバー）

- 組の決め方（2026-09-24・`R31-U-B` 後の現物＝`src/recovery/discovery.js` の `reconstructCommittedRoster()`）:
  `readCanonicalRosterRegistration()` は共有規則 `roster-anchor-rule.js` で応募終了以上・確定したチャット開始未満の
  最後の名簿登録を選ぶ。錨つき名簿の manifest → index → 対象 group を照合できれば、その組を採る。
  公開ファイルが使えず、検証済み selection と錨照合済み前ブロック summary から `formGroups` で再計算するときは、
  本番の名簿書き手と同じバイトの manifest と memberRoot を組み立て、登録値 C が正典行と一致した場合だけ起動する。採点時の提出採否は別の規則で、開始前の正典行の有無だけを見る（`docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §5.2）。
  R33-U-GROUPING の比率と主要→非主要の組内順は正典仕様書 `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §3「組分け」に従う。
  不一致・正典行なし・再計算不能では起動しない。錨つき名簿（index と旧 manifest）の経路では、
  照合の欄（uid・`addr`・`bAddr` の address／pubKey／nostrPubkey）を登録値 C で確かめた名簿ファイルの値から作り、
  `depIds` は名簿ファイルの `depositIds` と型・順が一致した選出の文字列をそのまま、表示の欄（`globalIndex`・name・img・verified）は
  検証済み selection の `players[].data` から採る（`anchoredRosterRuntimeMember()`）。照合の欄は選出・名簿ファイルとも
  文字列でなければ止める（`comparableRosterMember()`・S3R7-RB-RCVTYPE-STOP-01・便 RCVTYPE2）。再計算の経路は選出の値
  （`rosterMemberOf()`）を使い、入口で選出の照合の欄の型を確かめて外れれば `roster_reconstruction_unavailable` で止める。
  表示用の name・img は文字列だけを採る（S3R7-B-1c-01・便 RCVTYPE）。名簿選択規則の正本は共有 `roster-anchor-rule.js`。
  `readCanonicalRosterRegistration()` は `getBlockNumber()` で固定した同一ブロックから履歴 count・各行・`chatWindow` を読み、そのブロックの timestamp で開始前の provisional／開始後の確定を分ける。旧 HashStorage への退避は許可リスト内かつ履歴 getter の revert に限る。復元画面の `deriveAndLoad()` は provisional なら鍵・relay を作らず、`pollRecoveryRosterAtStart()` でチェーン観測が開始に達した canonical／legacy 行まで読み直す。行が無ければ `chatCloseAt` まで確定を待ち、その後に停止する。待機は利用者が中止できる。恒久の再構成不一致・不能・選抜外は理由を出して抜け、チェーンだけの一過性読取失敗は1秒間隔で再試行し、R2 の再構成の一過性失敗だけ1秒から倍増して最大30秒の backoff とする。利用者の中止口は開始前の待機中だけに適用する。復元タブは R2 bytes で検証した結果を hash ごとに保持し、開始境界・`refreshTimeline()` の延長・`reconstructAndSubmit()` の組立前と送信直前はチェーンの正典行だけで再照合する。提出前の再照合でチェーンを読めない回は提出を保留し、次回の再照合が出口となる（正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §9）。同じ hash なら R2 を再読せず、開始後に変われば relay を止めて再読込を促す。開始後に届いた登録は採らず件数を警告する。公式画面は `fetchVerifiedLiveRoster()`・`pollVerifiedRosterAtStart()` で同じ開始境界へ到達するまでキャッシュなしで読み直す。
  `previous_summary_anchor_unavailable` は一過性の読取失敗でも停止し、読取回復後の Sign & load の押し直しで再照合する。条件と出口の正本は `docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §9「復元時の停止例外」を参照する。
- ロスター（R2 上のファイル）: `games/block{N}/roster/manifest.json`（チェーン錨の対象・`indexSha256` と group ごとの SHA-256）＋
  `games/block{N}/roster/index.json`（uid→groupId）＋ `games/block{N}/roster/group{G}.json`
  （members: `{uid, walletAddress, blockAddress, pubKey, nostrPubkey, depositIds}`・**配布順=formGroups正準順**）。
  `roster_anchor` タスクが manifest・index・group を再公開して上限まで再試行し、登録確定までチャットを開始しない。開始後の欠落は公開物の削除・改変として扱う。
- wallet→uid: `game_selection.json` の players[].data.addr と `summary.json` の groups[].members[].address を**大小無視で照合**する（`discoverUidCandidates()`）。照合するのは文字列のアドレスを持ち、uid も空でない文字列の行だけとする（S3R7-B-1c-01）。EthLock の `idTo` は自己申告で wallet と束縛されないため、チェーンログだけから uid を確定しない。
- ゲーム無し判定（`computeMajorLangs` と同一ロジック）: `summary.autoDistributed===true` **または**
  いずれかのgroup `status==='auto_distributed'`（D1フォールバックで top-level flag が落ちるため両方見る）**または**
  （summary無し AND `game_selection.players.length≤2`）→ ゲーム無し。
  `players≥3` なのに summary/roster が無い＝**「未確定/ロスター欠落」であって「ゲーム無し」ではない**
  （roster欠落だけでは no-game と断じない）。roster が欠けるときの members・bAddr/pubKey は検証済み `game_selection.json` の
  `players[].data` から取り、再計算 manifest の正典 hash 照合が通るまで起動しない（錨つき名簿がある経路は上の「組の決め方」）。

---

## 3. ① F1ローダー — 設計

### 3.1 実行アーキテクチャ（**検証ServiceWorkerプロキシ**を採用）

**課題**: 配信バイトを時刻Tに照合しても、ユーザーが実際にナビゲートする瞬間に運営が別バイトを返せる
（TOCTOU）。よって**「照合したバイト＝実行するバイト」を結ぶ**必要がある。アプリ内自己照合は循環で不可。

**採用**: ローダー独自オリジンに登録した **verifying ServiceWorker が運営アプリをプロキシ**する。
Next.js は `output:'export'`・ルート相対URL（`/_next/...`）なので、SWスコープ `/` の下でアプリを走らせれば
アプリの全リクエストをSWが横取りできる。

```
1. ユーザーが loader-origin/ (ローダーUI) を開く。
2. UI: 言語選択 → RPC選択（独立公開のみ・運営RPCは使わない） → チェーン読取
   latestBuildVersion() → getBuildHash(v) → (hash, updated, signer, buildRegistrationCount)
3. manifest.json を運営の**イミュータブル配信元**（bitcoinu.pages.dev / <deploy>.pages.dev。
   カスタムドメインのzone HTML書換=Rocket Loader等を回避）から取得 →
   keccak256(canonical(manifestCore)) が on-chain buildHash と一致するか照合（第1層）。
4. SW を scope '/' で登録し、検証済み manifest（path→sha256 マップ）を渡す。
5. 上位ウィンドウを loader-origin/ の検証アプリ入口へナビゲート。以降アプリが要求する
   /（HTML）, /_next/..., /locales/..., /game/ 等を SW が横取り:
     - manifest に無いパス → 拒否（403相当）
     - 運営配信元から fetch → sha256 再計算が manifest 値と一致しなければ拒否（第2層）
     - 一致 → 返す（HTMLレスポンスには厳格CSPヘッダを注入）
6. 一致が続く限りアプリは検証済みバイトのみで動作。1バイトでも不一致なら即拒否＝
   ユーザーは「検証失敗」を見て復元クライアントへ誘導される。
```

- **なぜSWで結べるか**: SWは同一オリジンの fetch/navigation に対し、任意元から取得したバイトで応答できる。
  アプリは loader-origin 上で same-origin として実行され、全アセット要求をSWが検証配信する。
  運営SWは登録されていない（loaderオリジン）ので毒キャッシュ経路は塞がる（＝handoff の「SW無効化」の実体）。
- **ホスティング要件（デプロイ時にユーザーが満たす）**: SWスコープ `/` とアプリのルート相対URLを一致させるため、
  ローダーは**オリジンのルート**に置く（github.io の user/org サイトルート、または専用カスタムドメイン）。
  プロジェクトサブパス（`/<repo>/`）では `/_next/...` がスコープ外に出るため不可。
  IPFS は path gateway ではルート相対が壊れるため **subdomain gateway / 専用IPNS+DNSLink** を想定（互換設計）。
- **CSP**: SWが注入する `Content-Security-Policy` は `default-src 'self'; script-src 'self' 'unsafe-inline'`
  （Next の `__NEXT_DATA__` インラインのため unsafe-inline は script に限り許容。将来 per-hash 化）、
  `connect-src` は運営worker/RPC/Nostrリレー/R2/WalletConnect をユーザー設定に応じて許可、
  `font-src`/`style-src` は Google Fonts を許可 or strip（実行コード注入は script-src で封じる）。
  外部リソース（フォント・WC・運営worker）は manifest 対象外＝**そのままパススルー**（buildの一部ではない）。
- **保証の限界（正確に明記）**: 運営はビルドハッシュ登録権限を持つ（毒ビルドのハッシュ登録は可能）。
  ただしその瞬間、不正は「世界に公開された唯一の成果物」に固定され、`buildRegistrationCount` の増加と
  `BuildHashRegistered(isUpdate=true)` が恒久証拠になる。ローダーは「コードの正直さ」ではなく
  「配り分けの排除＋全体攻撃の公開証拠化」を保証する（README に block-verifier 流で明記）。

**設計代替案と却下理由**: 「全取得→照合→iframe/blobで起動」は、ルート相対URLの書換が必要で
`_next/data`・13ページ多重ナビゲーション・動的importを漏れなく捕捉できず、照合と実行の結合も緩い（TOCTOU）。
SWプロキシは多重ナビゲーションと後出し注入を構造的に塞ぐため採用。

### 3.2 manifest / buildHash 形式（**チェーン錨・本ツールで新規確定**）

正典にformが無いため、旧 p2p-verifier スケルトンの `computeManifestHash` と block-verifier の manifest 規約を
踏まえ**単一式を確定**する。

```
対象     = 配信ディレクトリ out/ の全ファイル（HTML+全JSチャンク[動的import閉包]+CSS+locales JSON+画像+ico+
           _buildManifest/_ssgManifest+_next/data。.DS_Store は除外）
path     = out/ からの POSIX 相対パスに先頭 '/' を付与（=ブラウザが要求するURLパス。例 /index.html,
           /_next/static/chunks/xxx.js, /game/index.html, /locales/en/game_en.json, /404.html, /404/index.html）
files[path] = sha256hex(生バイト)   // 小文字hex・0xなし・再シリアライズしない
sortedPaths = Object.keys(files).sort()   // JS既定=コードユニット昇順
preimage    = `bitcoinu-build-manifest/v1|buildVersion=${buildVersion}|algorithm=sha256|`
              + sortedPaths.map(p => `${p}:${files[p]}`).join('|')
buildHash   = keccak256(toBytes(preimage))   // ← registerBuildHash(buildVersion, buildHash, signer) の bytes32
```
- 公開する `manifest.json` = `{ schema:'bitcoinu-build-manifest/v1', buildVersion, algorithm:'sha256',
  commit, builtAt, fileCount, files }`。**buildHash は preimage から再計算**（manifestのキー順に依存しない）。
- ローダー照合の2層: (第1) 取得 manifest の files から preimage 再構成 → keccak == on-chain buildHash。
  (第2) 各ファイル取得 → sha256 == files[path]。両方一致で「配信物＝チェーン錨のビルド」。
- buildVersion = 単調増加リリース番号。`buildRegistrationCount(v)==1` を WARN条件（再登録=差し替え可視化）。
  ローダーは `latestBuildVersion()` と `getBuildHash(latestBuildVersion)` を**必ず一緒に読む**
  （旧版の hash 差し替えトラップ回避）。

### 3.3 HashStorage buildHash ABI（コード済み・契約バッチ待ち）

```solidity
function registerBuildHash(uint256 buildVersion, bytes32 hash, address signer) external onlyAdmin;
function getBuildHash(uint256 buildVersion) external view returns (bytes32 hash, uint256 updated, address signer);
                                                    // 未登録は revert "No build hash registered for this version"
uint256 public latestBuildVersion;                  // buildVersion>latest のときのみ前進
mapping(uint256=>uint256) public buildRegistrationCount;   // 単調増加・リセット不可
event BuildHashRegistered(uint256 indexed buildVersion, bytes32 hash, address signer, bool isUpdate,
                          uint256 updatedAt, uint256 registrationCount);
```
- **現デプロイの HashStorage（0xf38C9d4a…・2026-07-05）には buildHash API が無い**（コミット ee4e180 で追加）。
  ローダーは**契約再デプロイバッチ後の HashStorage** が対象＝それまで **Hardhatローカルでのみ検証可**。
- **契約テストが未存在**（`Hardhat/bitcoinu/test/` 空・test_local.js に buildHash 節なし）。
  → §7 で buildHash 契約テストを chatgame-tools 側の Hardhat E2E に追加（バッチ前提の実装検証）。

### 3.4 RPC / アドレス方針

- ローダーは**運営RPCを一切使わない**（照合前に運営RPCを信じるとフェイク値注入の余地）。
  固定プリセット（publicnode/Tenderly/dRPC）とユーザー追加の RPC、mainnet ウォレットを使い、
  一覧の先頭から fallback する。ローダーの読取方式は変えない。
  復元の R4 は注入ウォレットが答えればその1本、ほかは固定プリセット S の2本以上の一致を使う。
  一致が続けて得られなければ本人の承認・選択を求め、公開が全部無答のときだけ設定済みの運営 RPC を使う。運営 RPC の設定は運営への依存を生むため非推奨で、設定した端末の画面には毎回その旨を示す（便 DISP6）。
  復元の窓・名簿・時刻には利用者が足した `rpcUrls` を使わない。正本は仕様書 §6.3「チェーンの読みの一致（S3R4-U-RPC1）」。
- アドレスは `config.js` にベイク（block-verifier と同じ現テストデプロイ値・**バッチ後に差し替え**）・ユーザー上書き可。
  HashStorage アドレスはフロントに存在しない → 本ツールがベイクする唯一の出所。

---

## 4. ② 最小復元クライアント — 現行設計

運営 WS へ書けないプレイヤーも、ウォレット署名・検証済み正典名簿・独立 Nostr リレー・Evidence 直接提出を使う。応募時の blockAddress にある Nostr 公開鍵で authors を固定し、グループタグと kind 7742 を購読する（src/utils/relay.js の GameRelayChannel.start、RelayPool._subscribe）。sendkey の告知、K_uid、AEAD 外包、再共有、保留バッファ、発見モードは無い。

### 4.1 受信と発信

リレーの content は平文 JSON の内側オブジェクト。外側 NIP-01 の署名と ID を確認し、(1) 封筒 pubkey と内側の発信者（receipt は receiverUid）の名簿 Nostr 鍵の一致、(2) 内側の signKey 署名、(3) blockNum と groupId の一致、(4) chat・action・receipt・presence の既知種別を満たすときだけ取り込む（GameRelayChannel._handleEvent、chatgame-tools/src/recovery/relay-verify.js の makeVerifyRelayInner）。投票・密告の対象だけは encryptKey による自己暗号化のままで、種別はリレーから見える。

復元の順序は uid とブロックを特定 → applicantHash に束縛された名簿を検証 → ウォレット署名から鍵を導出・照合 → 名簿 authors のリレーを購読 → 署名済み発言・行動・受領証明を集める → compact-v1 提出物を一度構築 → Evidence.submitResult。正式な採点は提出物の union と受領証明の規則による。WS を使わずに Evidence へ出せる。保存では対象の見つからない既読はメモリにだけ保持する（前に確かめた保存済みの札は、対象の発言が届き直すまで残す）。保存する集合は公式と同じ (A′)（提出物が運ぶのと同じ形の集合・仕様書 §6.10「既読の受け入れと運び方」）で、3MiB を超えるときだけ自分の既読→行動受領証明→本人の発言を覆う札→残りの順で収める。容量不足なら行動の印だけに縮めて再試行する。確定した前ブロックの復元用の写し・到着印・本人行動・旧版の選抜鍵（`clientReadSelection_v1`・便 RS の後は書かない）は次ブロックの開始前に掃除する。本人の投票・密告は共有の観測集合とは別の小さな鍵へ署名ごとに合流して保存し、二つのタブの一方が古い観測集合を書き戻しても失わない。署名だけ残って行動の控えがない場合は、リレーの自己エコーを再検証して取り込む。到着印・本人行動の保存失敗は画面に警告する。

復元クライアントはチャット中と提出前に公開 `live/block{N}/group{G}.json` を約30秒間隔で読む。公式クライアントも WS が OPEN でない間だけ同じ周期で読む（`useGameWebSocket`）。両者は `src/utils/relay.js` の `readLiveSnapshot` と `verifyLiveSnapshotEntries` を共有する。共有の live の確かめは32呼び出しか16msでタイマーへ譲り、恒久の拒否だけを同じ名簿の鍵で発行者ごとに1,200件まで覚える（便 RELAY）。ChatGameDO は間引いた発言・受領証明の更新を alarm の末尾公開で拾うため、**発言と受領証明**について成功した公開の古さは約30秒＋CDN の max-age に有界である。WS の投票・密告は次の発言・受領証明、またはフェーズ遷移で公開が起きたときに載る（`chat-game-DO.js` の `publishLiveSnapshot` / `alarm`）。これは信頼しない補助入力であり、16MiB の本文上限・時刻・block/group を検査した後、発言・投票・密告・受領証明を検証済み名簿鍵の署名、正準形、未来時刻、発信者ごとの件数上限に通して P2P と同じ手元集合へ入れる。未来時刻の取り込みは S3FIX-Q18 の決定に従う（正本は仕様書 §6.3・§6.4）。受領証明の出どころと到着順には端末で記録した最初の到着時刻を使い、live JSON の `_firstArrivalAt` は使わない。発言の進捗は宣言窓→鮮度内の既読→採点と同じ上限の順で手元の集合から導く。密告の画面資格は、標的の見える投票に自分と標的以外の期限内受領証明があり、その投票より現在時刻が後なら成立する。ラスト10分は密告の送信門が全員へ開くが、標的の投票が確定していなければ採点では無効となる。投票はチャット終了の10分前で閉じ、その後は投票への受領証明も発行しない。live から拾った項目は P2P へ再発信せず、live だけの発言へ新たな既読を出さない。取得に失敗しても最後に検証できた live の項目は残し、画面に未読の印を出して次の取得を試す（`src/recovery/app.js` の `pollLiveSnapshot`。`src/recovery/relay-client.js` の `clearLiveSnapshot` は製品コードから呼ばれない）。

行動の受領証明は、公式の WS と復元の P2P・live のいずれも、端末到着時のチェーン最新ブロック時刻と到着時の補正した時計 C−2分の遅い方を印にする（S3R6-U-E301B・便 TIPFLOOR）。読めない場合だけ到着時の補正した時計 C を使い、運営のフェーズ通知や DO の `_receivedAt` を出どころの根拠にしない（仕様書 §6.4）。公式 localStorage の取り込みは発言を取り込まない。発言はリレーか公開 live から得る。取り込んだ投票・密告は再読み込み後の表示と組み直す提出物には戻らない。再読み込み後は貼り直すか、取り込んだ公式の提出バイト列を Evidence 救済ボタンで送る。公式の控えに押下で選んで組んだ窓の欄があれば、同じ payload の SHA と照合できたときだけ窓も取り込み、提出欄の保証の表示に使う（欄の無い控えは今の確定窓で表示する・便 SUBMITVIEW2・SUBMITVIEW3）。公式から取り込んだ既読は P2P・live と同じ到着の受け入れ（`src/recovery/relay-client.js` の `_ingestReceiptArrivals`）へ入れ、受け入れた全部を表示と提出物の材料にする（既読の組の選び方は便 RS で外した・正本は仕様書 §6.10「既読の受け入れと運び方」）。復元クライアントは起動時にチェーンのタイムラインを読めなければ停止し、起動後は直近の読みを保つ。保存窓・窓なし警告の枝は防御的な枝で、窓が未確認なら警告して提出を続ける（仕様書 §9）。

（2026-09-30 S3R3 の既知の制約を 2026-10-18 に更新: 保存済みの控え〈取り込んだ公式の提出バイト列は同じ保存に入る〉から送る R2 不要の救済は、130,000 B 以上なら組み直しの提出と同じく切り詰め、確認の後に接続したウォレットで署名し直して送る〈収まらない・キャンセル・署名者の違いは送らない・`recoverySavedRescueTrim`・S3R7-H-5b-01・便 SVLAST〉。公式の控えの取り込みは 260,000 文字を超えるものを受けない。）

**S3FIX-Q4 と I3 の既知の制約（2026-10-01）**: Q4 のユーザー逐語「控えがなくて困るのは、P2PのLiveも使えない時だけだよね。それはない前提で良いです。」（`docs/external-audit/stage3-rereview/fix/S3FIX_DECISIONS.md:35`、目印 `S3FIX-Q4`）。公式の `messageArrivals_` を外した後、`import-local-storage.js` は発言を取り込まず、リレーまたは公開 live（R2）が発言の入手元になる。両方が使えなければ、取り込んだ既読の対象発言を提出物に載せられない。これはユーザーが採った接続の前提に依存する。

`S3R3-U-S3DOC` の逐語「S3以下は全て文章記録・文章修正のみにしてください。」（`docs/external-audit/stage3-rereview/r3/S3R3_DECISIONS.md:193`）に従い、`S3R3-C-4d-03`・`S3R3-C-4d-04`・`S3R3-D-1d-04` は既知の制約として残す。`relay-client.js` の `_saveReceiptArrivals` が容量不足時に行動の受領証明だけで到着控えを書き戻すと、チャネルの写しを消せば全体が入る場合でも既読の控えを警告なしに失いうる（`chatgame-tools/src/recovery/relay-client.js:174`、`docs/external-audit/stage3-rereview/r3/S3R3_ACCEPTED.md:261` の `C-4d-03`）。復元の確定ブロックの掃除は公式の `ResultPhase.clearFinalizedBlockKeys` より狭く、`evidence_result_N` など復元自身の鍵を残しうる（`docs/external-audit/stage3-rereview/r3/S3R3_ACCEPTED.md:262` の `C-4d-04`、`relay-client.js:193` の目印 `p2pRelayReceipts_`）。また live の束の行動受領証明の到着印は、`readReceiptChainTime` の読み直しで過去の到着が後のチェーン時刻へ切り上がりうる（`src/utils/relay.js:70`、`chatgame-tools/src/recovery/relay-client.js:255`、`docs/external-audit/stage3-rereview/r3/S3R3_ACCEPTED.md:264` の `D-1d-04`）。受容の一覧は [`ATTACK_COUNTERMEASURES.md`](../docs/ATTACK_COUNTERMEASURES.md) §5-a。

周5 の復元の既知の制約（S3R3-U-S3DOC）: 一致なしの画面の「ウォレットを接続する」が読み込みの後に Find と Sign & load を出し直し、やり直しが名簿の確定の前で終わると、動いていた画面が `rosterAnchorHash=null` の「再確認中」のまま止まる（本人がもう一度押すか再読込するまで既読・受領証明・発言・投票・提出が止まる・S3R5-H-3c-01・S4）。やり直しの `deriveAndLoad` は前の `RecoveryRelay` を止めずに上書きするので、走っている名簿の確かめが null の帯をまたぐと、正しい名簿なのに「最終名簿が変わりました」で止まる（S3R5-H-3c-02・S4）。どちらも Restart か再読込で戻る。一致なしの画面の「ウォレットを接続する」で拡張の今の口座が名簿の口座と違うと、読み込みの後でも署名の口座が黙って置き換わり、提出は tx の前に技術的な英文の log だけで拒まれ続ける（戻し方は Restart だけ）。その押下で保存済みの名簿の口座の束が別の口座の束で上書きされ、R2 を要らない保存の救済も使えなくなる（S3R5-H-3d-01・S4・事故。保存の救済の上書きが効くのは R2 が読めない〈運営が配らない〉ときだけ）。運営が R2 を配らない形（運営の停止）は受容（S3R5-U-PREMISES・S3R5-U-S3S4-OPERATOR-ACCEPT）。読み込みの後に uid を替えてやり直すと（1つの引き出しアドレスを共有する2つの uid）、`deriveAndLoad` は前の uid の myVote・intent・myReports・observedP2P・既読と行動の受領証明の発行済み集合を置き直さず前の relay も止めないので、新しい uid の画面は投票ボタンが全部押せず未投票の警告も消える。気づかなければ新しい uid は no_vote になりうる（S3R5-H-3d-02・S3・事故・警報なし）。送信の記録（`onchainTxHash`）と Evidence の件数は、便 SV8 から身元（ブロック・uid）を読み込むときに空にし、送信の記録は今の身元の保存から読み直すので、前の uid の tx を「提出済み」と出さない（S3R6-RB-SV7-STOP-01・STOP-02）。別の uid は Restart で扱う。便 SVLAST（S3R7-A-2b-01）から、提出の押下は押下の始めの身元（ブロック・uid）の鍵で送信の記録・オンチェーンの記録・控えの読み直しを行い、画面の tx と件数は今の身元が同じときだけ書く。押下の待ちの間は Find と Sign & load を押せない。読み込んだ後は、一致なしの画面の「ウォレットを接続する」でブロックの入力・Find・保存済みの救済を出し直さず、保存済みの救済は読み込んだ身元を書き換えない。このため上の S3R5-H-3c-01・02 と S3R5-H-3d-02 の読み込んだ後のやり直しは、この画面からは起きず、別の uid へは Restart の後の新しい読み込みで移る（S3R5-H-3d-01 の口座の置き換えは残る）。復元は Sign & load の時の網でウォレットを使う。その後に網を mainnet から切り替えたら、mainnet へ戻すか Sign & load し直す（名簿の読みが黙って止まる・S3R5-I-3-02・S4）。チャットの入力欄とその祖先は (ブロック, 組, uid) ごとに1回だけ作り（`recoveryChatInputFor`）、毎秒の描き直しでは文書から外さないので、変換中の文字とキャレットは描き直しで失われない（S3R5-E-3-01・便 DISP5・表示だけ）。

### 4.2 歴史取得と縮退

RelayPool は1ページ6005件・接続ごとに最大12012ページ（`MAX_SEEN_EVENT_IDS * 2 + 2`）で履歴を読む。subId・until と名簿・kind・タグ・署名の検査を通った ID は、既知でも初回検証時の created_at で最古秒を進める。EOSE で該当0件なら停止、新規 ID があれば同じ境界秒を再要求し、なければ最古秒の前へ（境界再要求中は until の前へ）進む。警告1000件、1200件超で送り手の後続を止め、ID の LRU 記憶は6005件（src/utils/relay.js）。全リレーが止まれば復元クライアントの発信は届かない。自分の名簿行に有効な nostrPubkey が無いと、公式クライアントでは WS 行動を続けられるが、復元クライアントは発言・投票・密告を届けられず、オンチェーン提出だけが残る。

### 4.3 配備境界

旧版の2キー応募・5キー名簿と新版の3キー応募は互換でない。フロント・ChatGameDO・復元クライアント dist を同じ版で配り、テスト環境の応募・ゲーム状態・R2 名簿をリセットする。切替前ブロックは verifier の check.stageA.entryKeyIntegrity と名簿再構築が FAIL になるため、E2E 判定は切替後のブロックだけを使う（docs/OPS_TASKS.md §5）。

### 4.4 ベンダリング

browser 用の正典コードは vendor へ byte 同一で写し、VENDOR_SYNC.md と check-vendor-sync.mjs が検査する。P2P の主な正典は src/utils/p2pKeys.js・relay.js・ecies.js と workers/game_workers/lib/protocol-v2.js。ecies.js は投票・密告の自己暗号化を担う。復元クライアントの組み立ては chatgame-tools/src/recovery/bundle.js、署名確認は relay-verify.js を参照する。

G3 密告行為の警告は署名を確かめた密告の暗号文の種類数で判定し、公式画面と復元画面の両方に出す。例外は、署名検証時に投票・密告への重複した既読を5枚数える警告だけである。復元の `app.js` はこの警告を数えず、従来の発言への既読警告は続ける。

## 5. モジュール構成・リポジトリ配置

```
chatgame-tools/                     ← 本体リポジトリ内の新ディレクトリ（block-verifier と同じ流儀）
  DESIGN.md  README.md  VENDOR_SYNC.md  package.json
  config.js                         mainnetアドレス(バッチ後差替)・RPCプリセット・R2ベース・pins
  src/
    common/  chain.js               viem loader fallback・復元の一致読取・HashStorage/Evidence/EthLock/TokenMining読取
             manifest.js            §3.2 buildHash計算（生成/照合で共有）
             rpc.js                 独立RPC選択（loader用は運営RPC除外）
             i18n.js                en/ja/zh フラットカタログ（block-verifier流）
    loader/  sw.js                  検証ServiceWorkerプロキシ
             loader.js              チェーン読取→manifest取得→照合→SW起動
             index.html app.js      ローダーUI（言語→RPC→照合→起動/失敗表示）
    recovery/
             wallet.js              EIP-6963選択・chainId・personal_sign
             identity.js            signKey/encryptKey・ブロック単位Nostr鍵の導出と名簿照合
             discovery.js           uid/roster/group発見（R2/EthLogs）
             timeline.js            Evidenceフェーズ/窓（チェーン権威）
             relay-client.js        GameRelayChannel駆動（平文封筒の発行/名簿authors購読）
             bundle.js              提出バンドル再構成（byte-exact移植）
             submit.js              evidence-compact-v1→Evidence.submitResult
             ui/                    チャット/投票密告/提出 の素朴UI（3言語）
             index.html app.js
  build/
    gen-manifest.mjs                out/ → manifest.json + buildHash（ツール側配置・本体無変更）
    verify-determinism.mjs          2回ビルドしてバイト差分（D4）
    bundle.mjs                      esbuild で recovery/loader を静的化＋再現手順
  vendor/                           §4.5（VENDOR_SYNC台帳）
  scripts/check-vendor-sync.mjs
  test/                             §7（block-verifier の chain-setup/players/r2-server を再利用）
```

---

## 6. D4 — 完全決定論ビルド（再現ビルド）

**目的**: 「同じソース → 必ず同じ buildHash」をローカルで成立させる。第三者（AIでも）がソースから
バンドルを再現しハッシュを算出でき、ローダーのチェーン錨照合が意味を持つ。

**Next.js（14.1.0・output:'export'）の非決定論源と対処**:

| # | 源 | 対処 | 本体変更 |
|---|---|---|---|
| 1 | buildId（乱数nanoid・dir名＋各HTMLの`__NEXT_DATA__`。チャンク内には無い） | `generateBuildId: async()=>process.env.BUILD_ID||null`（未設定時は現挙動） | **next.config.js 1行・要ユーザー確認** |
| 2 | `NEXT_PUBLIC_*`（CFダッシュボードのみ・チャンクに焼込） | 本番値を `.env.production` にコミット or manifest metadata に固定 | **要ユーザー確認** |
| 3 | SWC minifier のdarwin/linuxバイト差（未確認） | 正準環境=linux-x64/Node20（Docker=CF Pages相当）を宣言・二重ビルドで実証 | なし |
| 4 | SSG HTMLへの Date.now() 混入（未確認） | 二重ビルド byte-diff で特定→該当pageをmounted-gate | 判明次第・要確認 |
| 5 | `.DS_Store` 混入 | manifest生成で除外＋clean checkoutビルド | なし |
| 6 | ethers git+ssh 依存（install-scriptあり・src未使用） | 再現手順に insteadOf 注記（バイトには無影響） | なし |
| 7 | webpack chunk id/hash・CSS module名 | 既定で決定論（root相対パスhash）。clean checkout必須 | なし |

- **手順**: (a) chatgame-tools 側の `verify-determinism.mjs` が pinned環境で `next build` を2回実行し `out/` を byte-diff。
  (b) 差分ゼロを確認→ `gen-manifest.mjs` で manifest+buildHash 生成。(c) 差分が残れば手順書に記録し個別対処。
- **本体変更は #1・#2 のみ**（generateBuildId 1行と本番値コミット）。両方 D4「完全決定論化」に必須だが
  **main-repo への変更＝ガードレール上ユーザー確認事項**。実装着手時に具体diffを提示して承認を得る
  （それまでは §7 のローカル検証は固定 BUILD_ID を注入して代替）。

---

## 7. テスト戦略（block-verifier流 Hardhatローカル）

（2026-09-28 S3R1 の注記: 以下の `TERM1/2/3` 固定 fixture は 2026-07-11 時点のテスト計画。現行の時刻定数は §0・§2.4 の `GAME_PERIOD`／`SUBMIT_PERIOD`／grace を参照。）

`block-verifier/test/` の `chain-setup.mjs`・`canonical.mjs`・`players.mjs`・`r2-server.mjs`・`stubs.mjs` を
再利用（相対import。独立リポジトリ化時にベンダー）。TIMING 固定（S=2027-01-01・BLOCK_TIME600・TERM120/180/180・
GRACE60・CONFIRMATION64）。

### 7.1 ローダー E2E（buildHash 照合）
1. `deployContracts`（chain-setup）でHashStorage含む一式デプロイ。**buildHash契約テスト**を追加
   （registerBuildHash/getBuildHash/latestBuildVersion/buildRegistrationCount の期待動作・revert）。
2. 小さな擬似 `out/`（HTML+チャンク+JSON数枚）を用意 → `gen-manifest.mjs` で manifest+buildHash →
   `registerBuildHash(v, buildHash, signer)`。
3. ローカル静的サーバー（r2-server流）で `out/` を配信 → ローダーの照合ロジックを非対話実行 → **green**
   （第1層 keccak一致・第2層 全ファイルsha256一致）。
4. **mutation**: (a) 1ファイル1バイト改変→第2層FAIL / (b) manifest改変→第1層FAIL /
   (c) 配信欠落→取得失敗 / (d) `buildRegistrationCount>1`→WARN / (e) 旧版hash差替トラップ→検知。
   SWの検証配信/拒否ロジックはNode環境でユニット化（fetch差替）。

### 7.2 復元クライアント E2E（現行）

1. 切替後の3キー応募と Nostr 鍵つき名簿を固定し、応募 hash と名簿を照合する。
2. 独立リレーで平文 chat・action・receipt の封筒を往復させ、名簿 authors、外側 Schnorr と内側 signKey 署名、blockNum／groupId／種別の4条件を確認する。
3. 運営 WS を使わずに受領証明つきの提出物を compact-v1 に符号化し Evidence へ提出、reconcile と採点 union に入ることを確かめる。
4. 対照として名簿外鍵、壊れた封筒署名、内側発信者と鍵の不一致、古い blockNum、未確認種別を拒否する。切替前ブロックの FAIL は新版 E2E の失敗に数えない。

## 8. 未決事項の確定記録（ヒアリング 2026-07-11）

| 項目 | 確定 |
|---|---|
| 形態 | 1アプリ2機能・静的・ウォレット接続前提 |
| 配置 | 本体リポジトリ内 `chatgame-tools/`（将来 GitHub＋IPFS 独立リポジトリへ切出前提） |
| ホスト | GitHub Pages主・IPFS互換設計（実デプロイは契約バッチ後・今回は設計＋ビルド成果物準備まで） |
| UI言語 | en/ja/zh 3言語 |
| buildHash対象 | **ビルド出力全体**（out/ 全ファイル・.DS_Store除外） |
| manifest生成 | **新ツール側に配置**・本体ビルドの仕組みは不変（registerBuildHash はユーザーが契約バッチ時に実行） |
| D4 | **完全決定論化まで**（本体変更 next.config.js generateBuildId・本番env値コミット は着手時に確認） |
| 復元範囲 | **フル参加**（チャット発言/閲覧→投票/密告→結果提出。ウォレット＋公開リレーと Evidence で完遂） |
| ローダー実行 | **検証ServiceWorkerプロキシ**（オリジンルート要件・CSP・運営SW無効化） |
| RPC | ローダー=先頭から fallback（運営RPC不使用）・復元=注入ウォレット、または固定Sの2本以上の一致（承認・選択あり、全公開無答時のみ運営） |

## 9. ガードレール（再掲）

- **push 絶対禁止**（契約バッチまで）。コミットは main。
- `src/components/GameRewardModal.js` 不触。デプロイ・mainnet書込・本番シークレット・Alchemy webhook 不触。
- 正典（workers/・src/・Hardhat/bitcoinu/contracts/）は原則変更しない。**D4のnext.config.js等 本体変更が
  必要になったらユーザー確認してから**。コントラクトを触るなら正典 `Hardhat/bitcoinu/contracts/` のみ。
- 既存実装が正（byte-exact）。差異はまずツール側のバグを疑う。ethers禁止・新規コードは viem。
