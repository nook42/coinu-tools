// E2E専用。.env/Ledger/外部ネットワークを設定せず、既存artifactsを読み取る。
const path = require('node:path');
const root = path.resolve(__dirname, '../../Hardhat/bitcoinu');
module.exports = {
  solidity: '0.8.24',
  paths: { root, artifacts: path.join(root, 'artifacts'), cache: '/private/tmp/fix1-hardhat-cache' },
  networks: { hardhat: { chainId: 31337 } },
};
