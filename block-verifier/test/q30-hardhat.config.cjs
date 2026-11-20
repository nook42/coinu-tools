// Q30: Ledger/.env/外部RPCを読まず、Hardhat in-process chainだけを使う統合試験設定。
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '../..');
const hardhatRoot = path.join(repoRoot, 'Hardhat/bitcoinu');
require(path.join(hardhatRoot, 'node_modules/@nomicfoundation/hardhat-toolbox'));

module.exports = {
  solidity: {
    compilers: [
      { version: '0.8.20', settings: { optimizer: { enabled: true, runs: 200 } } },
      {
        version: '0.8.24',
        settings: { optimizer: { enabled: true, runs: 1 }, evmVersion: 'cancun' },
      },
    ],
  },
  paths: {
    root: hardhatRoot,
    sources: path.join(hardhatRoot, 'contracts'),
    tests: path.join(repoRoot, 'tmp/Q30/hardhat-tests'),
    cache: path.join(repoRoot, 'tmp/Q30/hardhat-cache'),
    artifacts: path.join(repoRoot, 'tmp/Q30/hardhat-artifacts'),
  },
};
