# COINU（コいぬ）チャットゲーム補助ツール（chatgame-tools）

運営の外に置く・チェーンに錨を下ろした独立ツール（en/ja/zh）。静的1サイト・2機能:

1. **F1ローダー（検証して起動）** — 運営が配信するアプリ（CF Pages バンドル）が、チェーン上の
   `HashStorage.getBuildHash(latestBuildVersion)` に錨を下ろしたビルドと一致するかを2層照合し、
   **一致時のみ**検証ServiceWorkerプロキシ経由で実行する。
2. **最小復元クライアント** — 運営に完全に締め出されたプレイヤーが、**ウォレット署名＋公開Nostrリレー＋
   名簿本人の所属証明を添えた Evidence直接提出**だけで、チャット（発言・閲覧）→投票・密告→結果提出の全行動を完遂する。
   組の起動前に、応募終了から確定したチャット開始までの最後の名簿登録を正典として照合する。開始前の暫定行では署名せず、チェーンが開始へ達してから正典行を読み直す。検証済み名簿値 C が同じなら公開名簿は読み直さない。
   公開名簿が欠ける場合は再計算した名簿値 C が正典行に一致するときだけ起動する
   （詳しくは [DESIGN.md](DESIGN.md) §2.6）。

> **保証の正確な言明**: ローダーが証明するのは「全員が同一コードを実行している（配り分けの排除）＋
> 全体攻撃がオンチェーンに恒久的な公開証拠を残す」こと。「コードが正直であること」の証明ではない
> （それは D4 再現ビルド＋ソース公開＋第三者監査の層 — `BUILD_DETERMINISM.md`）。
> 復元クライアントの保証は「提出・自分の投票/密告の完全復元」。最優先欄の記憶（画面に出した他人の発言・画面で20の組の確定）は端末・オリジンごとで移らない。公式で WS 提出が承認済みのときにここで組み直してオンチェーンへ出すと、承認済みの版より優先して置き換わる（S3R5-C-4b-01）。live（運営の記録）が自分の WS 受理を示すときだけ、組み直す前に置き換わることを知らせる確認が出る（S3R5-B-2-01・便 DISP5）。その確認は、受理が運営の申告でこの画面では確かめられないことと、やめると運営を信頼することになり非推奨であることも示す（S3R6-CARRY-OPTRUST・便 DISP6）。チャットの採点算入は
> 少なくとも1人の正直なグループ相手がリレー経由で受信したときのみ（独立リレー追加が唯一の脱出路）。

> **運営 RPC の設定（非推奨）**: この端末の localStorage の `chatgameToolsConfig.operatorRpc` に運営の RPC を置くと、ウォレットも公開ノードも答えない読みで、そのつど知らせずに運営のノードの値を使います（名簿・窓・期間など。時計の時刻には使いません）。運営を信頼することになり、運営への依存を生むため非推奨です。置いた端末では、画面の上の「Contracts in use」の枠に毎回その旨を示します（S3R6-CARRY-OPTRUST・便 DISP6）。

### 公式画面の localStorage を復元画面へ取り込む

公式画面を参加中のブラウザで開き、開発者ツールの Console に復元画面の「公式画面の記録を取り込む」欄に表示されたコードを貼り付ける。Console に表示された JSON をコピーして、復元画面の入力欄へ貼り付け「読み込む」を押す。同じブロック・組・uid のキーだけを読み、受領証明・投票・密告の署名を検証してから取り込む。発言は取り込まない（S3FIX-Q4）。取り込むと、復元が先に組んで保存した提出の束は公式の束に置き換わり、保存済みの救済と提出欄の保証の表示は公式の束を使う（S3R5-E-3-02）。発言はリレーか公開 live から得る。受領証明は署名が覆う欄を確かめるが、署名の外の欄を落とさずに取り込む（既知の制約・仕様書 §6.4 の S3R4-C-2-02）。T1e の所属証明と T1f の提出 payload も同じ貼り付けで運ぶ（T1g の選択した既読の組は便 RS で既読の組の選び方とともに外したので運ばない）。所属証明は名簿値 C と proof、提出 payload はウォレット署名も照合する。行動の受領証明の保存済み出どころは端末の記録として扱い、チャット中だったことの暗号学的な証明にはならない。JSON には個人の記録が含まれるため、公開チャットへ貼り付けない。

取り込んだ投票・密告は、再読み込み後の手元集合には戻らない。ただし確かめた自分の密告の根拠の票と受領証明は別の `myReportGrounds_` の控えとして保存・再読み込みし、提出の時に優先して運ぶ。公式の記録の貼り付けか同じ端末での密告が要る。再読み込みした場合は公式記録を貼り直すか、取り込んだ公式の提出バイト列を Evidence 救済ボタンで送る。公式画面を同時に開いたままにすると同じ既読を二画面から発行しうるため、復元へ移ったら公式画面を閉じる。

投票はチェーン由来のチャット終了時刻の10分前までに送る。最後の10分は投票への既読を発行せず、void の投票も再送できない。密告は標的の投票が自分と標的以外のメンバーに既読された後に送れる。最後の10分は誰にでも密告できるが、標的の投票が確定していなければ採点では無効になる。時計と締切が読めない場合の扱いは [DESIGN.md](DESIGN.md) の復元経路を参照。

G3 密告行為の警告は署名を確かめた密告の暗号文の種類数で判定し、公式画面と復元画面の両方に出る。投票・密告への重複した既読を5枚数える警告は公式画面だけに出る（従来の発言への既読警告は復元画面にも出る）。

（2026-09-30 S3R3 の既知の制約を 2026-10-18 に更新: 保存済みの控え〈取り込んだ公式の提出バイト列は同じ保存に入る〉から送る R2 不要の救済は、130,000 B 以上なら組み直しの提出と同じく切り詰め、確認の後に接続したウォレットで署名し直して送る〈収まらない・キャンセル・署名者の違いは送らない・S3R7-H-5b-01〉。公式の控えの取り込みは 260,000 文字を超えるものを受けない。）復元クライアントは開始時にチェーンのタイムラインを読めなければ起動しない。起動後は直近の読みを保つ。窓が読めない場合は警告を出して提出を続ける防御的な枝がある。

## 構成

```
DESIGN.md              設計書（脅威モデル・アーキテクチャ・凍結仕様）
VENDOR_SYNC.md         ベンダリング台帳（COPY=バイト同一 / MIRROR=行範囲sha256）
BUILD_DETERMINISM.md   D4 再現ビルド手順書＋実行記録
config.js              既定値（アドレスは現テストデプロイ・契約バッチで要差し替え）
src/common/            manifest式（buildHash凍結仕様）・チェーン読取・i18n
src/loader/            verify-core（2層照合）・sw.js（検証SWプロキシ）・loader・UI
src/recovery/          identity（鍵導出）・discovery（uid/ロスター）・relay-client・
                       bundle（提出バンドル byte-exact 再構成）・submit（Evidence）・UI
build/                 gen-manifest（buildHash生成）・verify-determinism（D4）・bundle（esbuild）
vendor/                正典のバイト同一コピー（protocol-v2 / relay / ecies / calculator / reconciler 等）
test/                  bundle-unit（採点linchpin）・loader-e2e / recovery-e2e（Hardhatローカル）
dist/                  配布静的サイト（npm run bundle の出力・監査用に未minify）
```

## クイックスタート

```bash
cd chatgame-tools && npm install    # 依存は正典rootと同一版にピン（viem 2.42.0 / eciesjs 0.4.17 …）

npm run check-vendor-sync           # ベンダリング drift 検査（正典と1バイトでも違えば fail）
node test/bundle-unit.mjs           # 復元バンドル linchpin（vendored calculator/reconciler で採点まで検証）
node test/loader-e2e.mjs            # ローダー Hardhat E2E（buildHash実登録→green＋mutation 5種）
node test/recovery-e2e.mjs          # 復元 Hardhat E2E（Evidence実提出→バイト等価回収＋first-write-wins）

npm run bundle                      # dist/ に静的サイトを生成（loader/recovery/sw）
```

## ローカル配信（テスト用）

`npm run bundle` で更新した `dist/` をローカルで配信してテストする（公開ホスト前の動作確認）。
**`dist/` はオリジンのルートに置く**必要があるため（検証SWの scope `/`・§デプロイ参照）、
`dist` を直接ルートとして配る:

```bash
cd chatgame-tools                   # dist を相対パスで指すため必須
npx http-server dist -p 8788 -c-1   # :8788 のルートで配信（-c-1 = キャッシュ無効）
# → http://localhost:8788/recovery.html（復元クライアント）/ index.html（ローダー）
```

- ポートは任意の空きで可（リポジトリの `.claude/launch.json` は `chatgame-tools-dist` として :8791 を使用）。
- **バンドル更新を反映するには**: `-c-1` でHTTPキャッシュは無効だが、復元ツールは検証用
  **ServiceWorker（sw.js）を登録してキャッシュ**する。ブラウザで DevTools → Application →
  Service Workers を **Unregister**（または Clear site data）してからハードリロードすること。

## テストが証明していること

- **loader-e2e**: 未登録検知 / green / 1バイト改変検知 / manifest改変検知 / 配信握り潰し検知 /
  再登録WARN — すべて実チェーン（Hardhat・HashStorage buildHash API）に対して。
- **bundle-unit**: 検閲下で再構成した提出バンドルが、**本番採点コード（vendored）そのもの**で
  「有効・非失格・投票/チャット反映」になること。および設計上の天井（誰も裏書しなければ
  min_chars 失格＝§9.9）の再現。
- **recovery-e2e**: 再構成バンドルの Evidence 実提出 → イベント回収 → **解凍結果がバイト等価** →
  reconciler 検証通過 → 窓ガード（開始前 revert）→ first-write-wins（seq最小優先）。

## デプロイ（契約再デプロイバッチ後・ユーザー作業）

1. `config.js` の contracts 4アドレスをバッチ後の実アドレスへ差し替え（HashStorage buildHash API は
   バッチ後にのみ存在する）。
2. `BUILD_DETERMINISM.md` の手順で本体を正準環境ビルド → `gen-manifest` → `registerBuildHash`。
   `build-manifest.json` は out/ に入れて本体と一緒にデプロイする。
3. `npm run bundle` → `dist/` を **オリジンのルート** にホスト（GitHub Pages の user/org サイト等）。
   **プロジェクトサブパス（`/repo/`）不可** — 検証SWの scope `/` と Next.js のルート相対URLを
   一致させる必要があるため（DESIGN §3.1）。IPFS は subdomain gateway 想定。

## ガードレール

既存実装が正（byte-exact）。差異はまずツール側のバグを疑う。`npm run check-vendor-sync` が
正典との同期を機械検査する（正典更新時は vendor を更新し台帳の sha256 を取り直す）。
push 禁止（契約バッチまで）・デプロイ/mainnet書込/本番シークレット不触。
