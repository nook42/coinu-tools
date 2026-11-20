# 再現ビルド（D4）手順書 — chatgame-tools

> DESIGN.md §6 の運用版。「同じソース → 必ず同じ buildHash」を成立させ、ローダーの
> チェーン錨照合（§3.2）を意味あるものにする。第三者（AIでも）がソースからバンドルを再現し
> ハッシュを算出できる状態が目標。

## 「再現ビルド」とは（平易版）

同じソースコードから何度ビルドしても、**1バイトも違わない同じ成果物**が出るようにすること。
普通のビルドは、毎回ランダムなビルドID・ビルド時刻・環境差などで微妙に中身が変わる。それだと
「チェーンに登録したハッシュ」と「今ビルドした成果物のハッシュ」が一致しない。再現ビルドは
その揺らぎを全部潰し、**誰がいつどこでビルドしても同じハッシュになる**ようにする。これで初めて
「配信されているコード＝チェーンに約束したコード」を第三者が独立に検証できる。

## 正準ビルド環境（本番一致の前提）

- OS/CPU: **linux-x64**（CF Pages のビルドイメージと同じ。SWC バイナリのターゲット差を排除）
- Node: **20.x**（`.nvmrc` の major に一致・minor も固定推奨）
- 依存: `npm ci`（`package-lock.json` lockfileVersion 3・全依存ピン済み）
- 実行: clean checkout（`.next` キャッシュ・`.DS_Store` を持ち込まない）
- 推奨: Docker で `node:20-bookworm` 等を用い、`npm ci && BUILD_ID=<git sha> npm run build`

## 非決定論源と対処（DESIGN §6 の運用表）

| # | 源 | 対処 | 状態 |
|---|---|---|---|
| 1 | buildId（乱数nanoid・`_next/static/{buildId}/`・各HTMLの`__NEXT_DATA__`） | next.config.js `generateBuildId` で固定（git sha 等）。**K-S6-010（2026-07-29）でリリースビルドは未設定なら失敗する（fail-closed）** | ✅ **適用済み＋fail-closed化** |
| 2 | `NEXT_PUBLIC_*`（CFダッシュボードのみ・チャンクに焼込） | 本番値を `.env.production` にコミット。**K-S6-010 で「無ければリリースビルド失敗」「値が食い違えば失敗」の検査を追加**（`scripts/gen-build-inputs.mjs`） | ⬜ **残・要ユーザー**（値はCFダッシュボードのみ。検査だけ先に入った＝忘れるとビルドが止まる） |
| 3 | SWC minifier の darwin/linux バイト差 | 正準環境=linux-x64 を宣言・二重ビルドで実証。**K-S6-010 で `out/build-inputs.json` に platform / canonicalPlatform を記録し、非正準環境のリリースビルドは警告する** | ⬜ 残（linux正準環境での二重ビルド1回） |
| 8 | 再現に要る入力（BUILD_ID / 本番 NEXT_PUBLIC_* / Node / OS）がどこにも公開されていない | **`out/build-inputs.json` を成果物に含める**（out/ 配下なので buildHash の対象＝申告自体が改ざん検知される） | ✅ **適用済み（2026-07-29・K-S6-010）** |
| 4 | SSG HTML への Date.now() 混入 | 二重ビルド byte-diff で検出 | ✅ **混入なしを実証**（下記 2026-07-11 結果） |
| 5 | `.DS_Store` 混入 | manifest/差分検査で除外＋clean checkout | ツール側（実装済み） |
| 6 | ethers git+ssh 依存（install-scriptあり・src未使用） | `git config --global url."https://github.com/".insteadOf "git@github.com:"` で https 化 | 手順注記 |
| 7 | webpack chunk id/hash・CSS module名 | 既定で決定論（root相対パスhash）。clean checkout 必須 | 既定 |

## 手順

```bash
# 正準環境（Docker linux-x64 / Node20）内で:
npm ci
# 1) 二重ビルドで決定論を検証（本体 next.config.js の generateBuildId 適用後）
BUILD_ID=$(git rev-parse HEAD) node chatgame-tools/build/verify-determinism.mjs
#   → ##DETERMINISM full なら決定論成立。fail なら差分ファイルを本節に記録し #4 等を個別対処。

# 2) manifest + buildHash 生成
node chatgame-tools/build/gen-manifest.mjs --dir out --build-version <N> --commit $(git rev-parse HEAD)
#   → out/build-manifest.json を書き、buildHash（bytes32）を表示。

# 3) チェーン登録（契約再デプロイバッチ時にユーザーが実行）
#   HashStorage.registerBuildHash(<N>, "<buildHash>", <signerAddress>)
```

## 実行記録

### 2026-07-11（darwin-arm64 / Node 20・#1 適用後の初回検証）

```
BUILD_ID=testfixedid1234 node chatgame-tools/build/verify-determinism.mjs
→ files A=257 B=257
→ ##DETERMINISM full  (0 differing files — same source → same bytes)
```

**同一マシン・同一環境での完全決定論が成立**（buildId固定で全257ファイルがバイト一致。
SSG HTML への Date.now() 混入なし＝#4 解消・webpack/CSS も決定論＝#7 実証）。
残り: #2（NEXT_PUBLIC_* 本番値コミット・ユーザー作業）と #3（linux-x64 正準環境でのクロス環境
二重ビルド1回＝darwin と linux のバイト一致確認 or linux 内での一致確認＋登録も linux で実施）。

## 本体リポジトリへの変更（#2 のみ残）— 適用は要ユーザー承認

- ~~`next.config.js` generateBuildId~~ → **適用済み（2026-07-11・ユーザー承認・後方互換）**
- 本番 `NEXT_PUBLIC_*` の固定: CF ダッシュボードの値と一致する `.env.production` をコミット
  （現状ダッシュボードのみ＝再現不能。2026-06-23 の stale アドレス事故と同じギャップ）。

両方とも「完全決定論化」に必須。ガードレール（AGENTS.md・本体変更は要確認）に従い、適用前に
ユーザーへ具体 diff を提示して承認を得る。
