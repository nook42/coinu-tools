# coinu-tools

**English** | [日本語](README.ja.md) | [简体中文](README.zh-CN.md)

Independent tools for checking [COINU](https://bitcoinu.org) yourself, without trusting the operator.

COINU is designed on the assumption that **the operator may also be an attacker**. The operator controls the servers (Cloudflare Workers, databases, storage), so the system is built so that anyone can check the results using only public data and the Ethereum chain. This repository contains the two tools for doing that.

| Tool | Folder | What it does |
|---|---|---|
| Block verifier | [`block-verifier/`](block-verifier/) | Re-derives each block's entry snapshot → lottery → grouping → scoring → reward allocation → on-chain commitment from public data and the chain, and compares it with the operator's published results |
| Chat game recovery client | [`chatgame-tools/`](chatgame-tools/) | ① Checks that the app the operator serves matches the build anchored on-chain before running it. ② Lets a player who has been shut out by the operator still chat, vote, report and submit results using only a wallet signature, public Nostr relays and a direct on-chain submission |

The recovery client runs at **https://nook42.github.io/** (built from `chatgame-tools/`).

## Block verifier

Requirements: Node.js 20 or later, and an Ethereum mainnet RPC that can read past state (an archive RPC) for a full check.

```bash
npm install          # at the root of this repository (see "About this repository")
cd block-verifier
npm install
node src/index.js
```

The tool is interactive: choose a language (en / ja / zh), choose an RPC, enter a block number, and it shows a plain-language summary of what was confirmed and what could not be confirmed. Menu 3 checks that your own entry was included in the lottery. Details: [`block-verifier/README.md`](block-verifier/README.md) (Japanese) and [`block-verifier/DESIGN.md`](block-verifier/DESIGN.md).

## Chat game recovery client

Open **https://nook42.github.io/** in a browser. You do not need to install anything. To build it yourself:

```bash
cd chatgame-tools
npm install
npm run bundle   # output: dist/
```

`dist/` must be served at the root of an origin (not under a sub-path). Details: [`chatgame-tools/README.md`](chatgame-tools/README.md) (Japanese), [`chatgame-tools/DESIGN.md`](chatgame-tools/DESIGN.md) and [`chatgame-tools/BUILD_DETERMINISM.md`](chatgame-tools/BUILD_DETERMINISM.md).

## About this repository

- This is a copy of the tool folders from the COINU project at the released version. The rest of the project is not published here.
- `Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs`, `Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs`, `workers/game_workers/lib/roster-anchor-rule.js` and `workers/game_workers/lib/roster-member-root.js` (with `workers/game_workers/lib/package.json`) are included because the block verifier imports them. They are kept at the same relative paths. They load `viem` from the `node_modules` at the root of this repository, which is why `npm install` is run at the root first.
- The `test/` folders of both tools import many files from the rest of the project, so the tests do not run in this repository.
- `vendor/` in each tool contains byte-exact copies of the production code (for example the scoring code), so that the tools compute results with the same code the operator runs. `VENDOR_SYNC.md` in each tool lists the copies and their SHA-256.
- The rules and specification of COINU: https://bitcoinu.org/rules
