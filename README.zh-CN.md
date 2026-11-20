# coinu-tools

[English](README.md) | [日本語](README.ja.md) | **简体中文**

用于在不信任运营方的情况下，自行核实 [COINU](https://bitcoinu.org) 的独立工具。

COINU 的设计前提是“**运营方本身也可能是攻击者**”。服务器（Cloudflare Workers、数据库、存储）由运营方掌握，因此系统被设计为任何人都能仅凭公开数据和以太坊链上数据来核实结果。本仓库收录了为此提供的两个工具。

| 工具 | 文件夹 | 用途 |
|---|---|---|
| 区块验证工具 | [`block-verifier/`](block-verifier/) | 根据公开数据和链上数据，重新推导每个区块的“报名固定 → 抽选 → 分组 → 评分 → 奖励分配 → 链上确认”，并与运营方公布的结果进行比对 |
| 聊天游戏恢复工具 | [`chatgame-tools/`](chatgame-tools/) | ① 先确认运营方提供的应用与链上登记的构建一致，再运行。② 即使玩家被运营方拒之门外，也能仅凭钱包签名、公开的 Nostr 中继和直接上链提交，完成聊天、投票、举报和结果提交 |

恢复工具运行于 **https://nook42.github.io/**（由 `chatgame-tools/` 构建）。

## 区块验证工具

需要：Node.js 20 或以上版本；若要进行完整验证，还需要能读取历史状态的以太坊主网 RPC（归档 RPC）。

```bash
npm install          # 在本仓库的根目录执行（参见“关于本仓库”）
cd block-verifier
npm install
node src/index.js
```

工具为交互式：选择语言（en / ja / zh）、选择 RPC、输入区块编号后，会用浅显的语言汇总显示已确认和未能确认的内容。菜单 3 可以确认你自己的报名已包含在抽选中。详情见 [`block-verifier/README.md`](block-verifier/README.md)（日文）和 [`block-verifier/DESIGN.md`](block-verifier/DESIGN.md)。

## 聊天游戏恢复工具

在浏览器中打开 **https://nook42.github.io/** 即可使用，无需安装。如需自行构建：

```bash
cd chatgame-tools
npm install
npm run bundle   # 输出目录：dist/
```

`dist/` 必须部署在源站的根路径（不能放在 `/repo/` 这样的子路径下）。详情见 [`chatgame-tools/README.md`](chatgame-tools/README.md)（日文）、[`chatgame-tools/DESIGN.md`](chatgame-tools/DESIGN.md) 和 [`chatgame-tools/BUILD_DETERMINISM.md`](chatgame-tools/BUILD_DETERMINISM.md)。

## 关于本仓库

- 本仓库是从 COINU 项目中复制的已发布版本的工具文件夹。项目的其他部分未在此公开。
- 区块验证工具会引用 `Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs`、`Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs`、`workers/game_workers/lib/roster-anchor-rule.js` 和 `workers/game_workers/lib/roster-member-root.js`（以及 `workers/game_workers/lib/package.json`），因此按相同的相对路径收录。这些文件从本仓库根目录的 `node_modules` 加载 `viem`，所以需要先在根目录执行 `npm install`。
- 两个工具的 `test/` 目录引用了项目其他部分的许多文件，因此测试无法在本仓库中运行。
- 各工具的 `vendor/` 中包含与生产代码（例如评分代码）逐字节一致的副本，使工具使用与运营方相同的代码计算结果。副本清单及其 SHA-256 见各工具的 `VENDOR_SYNC.md`。
- COINU 的机制与规则：https://bitcoinu.org/rules
