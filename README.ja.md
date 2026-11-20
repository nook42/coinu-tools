# coinu-tools

[English](README.md) | **日本語** | [简体中文](README.zh-CN.md)

[COINU](https://bitcoinu.org) を、運営を信頼せずに自分で確かめるための独立したツールです。

COINU は「**運営も攻撃者でありうる**」という前提で設計されています。サーバー（Cloudflare Workers・データベース・ストレージ）は運営が握っているので、公開データとイーサリアムのチェーンだけで、誰でも結果を確かめられる作りにしています。このリポジトリには、そのための2つのツールがあります。

| ツール | フォルダ | 何をするか |
|---|---|---|
| ブロック検証ツール | [`block-verifier/`](block-verifier/) | 各ブロックの「応募の固定 → 抽選 → グループ分け → 採点 → 報酬の配分 → オンチェーンの確定」を公開データとチェーンから作り直し、運営の公開した結果と照らし合わせる |
| チャットゲームの復元ツール | [`chatgame-tools/`](chatgame-tools/) | ① 運営が配る画面が、チェーンに登録されたビルドと一致するかを確かめてから動かす。② 運営に締め出されたプレイヤーでも、ウォレットの署名・公開の Nostr リレー・オンチェーンへの直接の提出だけで、チャット・投票・密告・結果の提出を最後までできる |

復元ツールは **https://nook42.github.io/** で動いています（`chatgame-tools/` から作ったもの）。

## ブロック検証ツール

必要なもの: Node.js 20 以上。全部を検証するには、過去の状態を読めるイーサリアム mainnet の RPC（アーカイブ RPC）。

```bash
npm install          # このリポジトリの根で（「このリポジトリについて」を参照）
cd block-verifier
npm install
node src/index.js
```

対話式です。言語（en / ja / zh）・RPC・ブロック番号を選ぶと、確認できたことと確認できなかったことを平易な言葉でまとめて表示します。メニュー3では、自分の応募が抽選に含まれていることを確かめられます。詳しくは [`block-verifier/README.md`](block-verifier/README.md) と [`block-verifier/DESIGN.md`](block-verifier/DESIGN.md)。

## チャットゲームの復元ツール

ブラウザで **https://nook42.github.io/** を開くだけで使えます。インストールは要りません。自分でビルドする場合:

```bash
cd chatgame-tools
npm install
npm run bundle   # 出力は dist/
```

`dist/` はオリジンのルートに置く必要があります（`/repo/` のような一段下のパスでは動きません）。詳しくは [`chatgame-tools/README.md`](chatgame-tools/README.md)・[`chatgame-tools/DESIGN.md`](chatgame-tools/DESIGN.md)・[`chatgame-tools/BUILD_DETERMINISM.md`](chatgame-tools/BUILD_DETERMINISM.md)。

## このリポジトリについて

- COINU のプロジェクトから、リリースした版のツールのフォルダだけを写したものです。プロジェクトのほかの部分はここには公開していません。
- `Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs`・`Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs`・`workers/game_workers/lib/roster-anchor-rule.js`・`workers/game_workers/lib/roster-member-root.js`（と `workers/game_workers/lib/package.json`）は、ブロック検証ツールが読み込むので同じ相対パスのまま入れています。これらはリポジトリの根の `node_modules` から `viem` を読み込むので、最初に根で `npm install` をします。
- 両ツールの `test/` はプロジェクトのほかの部分のファイルを多く読み込むので、このリポジトリでは試験は動きません。
- 各ツールの `vendor/` には、本番のコード（採点のコードなど）をバイト単位で同じに写してあります。ツールは運営が動かしているのと同じコードで結果を計算します。写しの一覧と SHA-256 は各ツールの `VENDOR_SYNC.md` にあります。
- COINU の仕組みとルール: https://bitcoinu.org/rules
