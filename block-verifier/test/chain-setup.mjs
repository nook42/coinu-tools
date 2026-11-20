// chain-setup.mjs — ローカル hardhat チェーンの起動・本番コントラクト一式のデプロイ・時刻振付。
//
// - 現在のNodeでHardhat CLIを直接起動（artifacts が無ければ compile のみ実行 — 正典無変更）
// - デプロイは viem（ethers 不使用）。フローは Hardhat/bitcoinu/scripts/test_local.js deployFresh
//   （:142-194）＋ HashStorage(:5439-5444)・Evidence(:5860) デプロイを踏襲。
// - タイミング規約（オンチェーンが正・全て秒・v3.2 TERM1撤廃後）:
//     Evidence.START_TIME = TokenMining.START_TIME = 応募開始 S
//     entryPeriodEnd(0) = S + BLOCK_TIME / chatWindow(0) = [S+BT, S+BT+grace+GAME_PERIOD]
//     resultWindow(0) = [chatClose, chatClose+SUBMIT_PERIOD)
// - 既定の S は実行時刻の近傍。E2E_START_TIME_SEC で全プロセスに同じ値を渡せる。
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPublicClient, createWalletClient, http, defineChain, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { REPO_ROOT } from './canonical.mjs';

export const HARDHAT_DIR = resolve(REPO_ROOT, 'Hardhat/bitcoinu');
const HARDHAT_CLI = resolve(HARDHAT_DIR, 'node_modules/hardhat/internal/cli/cli.js');

// hardhat 標準ニーモニックの account #0（デプロイヤー＝各コントラクト admin）
export const DEPLOYER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
// account #2 を superAdmin に（test_local.js の役割分離と同じ形）
export const SUPERADMIN_ADDR = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';

export const CHAIN_ID = 31337;

// ---- タイミング定数（秒）。Evidence 制約: GAME_PERIOD+SUBMIT_PERIOD+GRACE <= BLOCK_TIME ----
export const TIMING = Object.freeze({
  // 管理txの期限は実時計から96時間以内。ローカルチェーンの応募開始を実行時刻の近傍に置く。
  S: Number(process.env.E2E_START_TIME_SEC) || Math.floor(Date.now() / 1000) + 3600,
  BLOCK_TIME: 600,
  GAME_PERIOD: 180,
  SUBMIT_PERIOD: 180,
  // applicant hash 確定後の64確認ブロック＋grouping/roster anchor が宣言開始より前に収まる値。
  // 180 + 180 + 120 <= 600 なので Evidence constructor の期間不変量も維持する。
  GRACE: 120,
  // 検証ツールの config ピン（DEFAULTS.pins.confirmationBlocks=64）と一致させる。
  // hardhat_mine で64ブロックは一括採掘できるため、小さい値に縮める必要がない。
  CONFIRMATION_BLOCKS: 64,
  VERIFICATION_PERIOD: 300,
  CLAIM_PERIOD: 1800,
  // C32F2（C32-B-01）: Evidence の constructor 第8引数 START_PAST_TOLERANCE（秒）。block 0 E2E の値。
  // GM の延長は未来の開始（今＋α）を狙うので、ローカルの即時着地では幅に触れない。
  START_PAST_TOLERANCE: 60,
});

export function timingDerived(t = TIMING, blockNum = 0) {
  const entryStart = t.S + blockNum * t.BLOCK_TIME;          // 応募期間開始（ブロックN）
  const entryEnd = entryStart + t.BLOCK_TIME;                // N=0 のとき = TokenMining.START_TIME
  const chatOpen = entryEnd;                                 // Evidence.chatWindow開始（トレランス側）
  const chattingStart = entryEnd + t.GRACE;                  // 宣言チャット開始（waiting終了）
  const chatClose = entryEnd + t.GRACE + t.GAME_PERIOD;
  const resultClose = chatClose + t.SUBMIT_PERIOD;
  return { entryStart, entryEnd, chatOpen, chattingStart, chatClose, resultClose };
}

// ---- raw JSON-RPC ----
export async function rpc(rpcUrl, method, params = []) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`RPC ${method}: ${body.error.message}`);
  return body.result;
}

function artifactsDir() {
  // Q30 の in-process 統合試験は生成物を tmp/Q30 だけへ置く。通常のchain suiteは
  // 従来どおり Hardhat/bitcoinu/artifacts を使う。
  return process.env.Q30_HARDHAT_ARTIFACTS
    ? resolve(process.env.Q30_HARDHAT_ARTIFACTS)
    : resolve(HARDHAT_DIR, 'artifacts');
}

function artifact(name) {
  const p = resolve(artifactsDir(), `contracts/${name}.sol/${name}.json`);
  const a = JSON.parse(readFileSync(p, 'utf8'));
  return { abi: a.abi, bytecode: a.bytecode };
}

async function ensureArtifacts() {
  const probe = resolve(artifactsDir(), 'contracts/Evidence.sol/Evidence.json');
  if (existsSync(probe)) return;
  console.log('[chain-setup] artifacts missing — running npx hardhat compile (build only)');
  await new Promise((res, rej) => {
    const p = spawn(process.execPath, [HARDHAT_CLI, 'compile'], { cwd: HARDHAT_DIR, stdio: 'inherit' });
    p.on('exit', c => (c === 0 ? res() : rej(new Error(`hardhat compile exited ${c}`))));
  });
}

// ---- hardhat node 起動 ----
export async function startNode({ port = 8547 } = {}) {
  if (process.env.E2E_IN_PROCESS === '1') {
    const { startInProcessNode } = await import('./fix1-in-process.mjs');
    return startInProcessNode({ port });
  }
  await ensureArtifacts();
  const proc = spawn(process.execPath, [HARDHAT_CLI, 'node', '--port', String(port)], {
    cwd: HARDHAT_DIR,
    stdio: ['ignore', 'pipe', 'pipe'],
    // .env.local の Pages token 事故回避（memory: wrangler --env-file /dev/null と同族の注意）は
    // hardhat には不要だが、環境は素通しにする。
  });
  const rpcUrl = `http://127.0.0.1:${port}`;
  let stderrBuf = '';
  proc.stderr.on('data', d => { stderrBuf += d; });
  // RPC が応答するまで待つ（最長 60s）
  const deadline = Date.now() + 60000;
  for (;;) {
    if (proc.exitCode != null) throw new Error(`hardhat node exited early (${proc.exitCode}): ${stderrBuf}`);
    try {
      const id = await rpc(rpcUrl, 'eth_chainId', []);
      if (parseInt(id, 16) === CHAIN_ID) break;
    } catch { /* not ready yet */ }
    if (Date.now() > deadline) { proc.kill('SIGKILL'); throw new Error('hardhat node did not become ready in 60s'); }
    await new Promise(r => setTimeout(r, 300));
  }
  const stop = () => { try { proc.kill('SIGINT'); } catch {} };
  process.on('exit', stop);
  return { proc, rpcUrl, port, stop };
}

// ---- viem クライアント ----
export function makeChain(rpcUrl) {
  return defineChain({
    id: CHAIN_ID, name: 'hardhat-local',
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

export function makeClients(rpcUrl, privateKey = DEPLOYER_KEY) {
  const chain = makeChain(rpcUrl);
  const account = privateKeyToAccount(privateKey);
  const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
  const walletClient = createWalletClient({ chain, transport: http(rpcUrl), account });
  return { chain, account, publicClient, walletClient };
}

async function deployOne(clients, name, args) {
  const { abi, bytecode } = artifact(name);
  const hash = await clients.walletClient.deployContract({ abi, bytecode, args });
  const receipt = await clients.publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`${name} deploy reverted`);
  return { address: getAddress(receipt.contractAddress), abi };
}

// ---- 一式デプロイ（deployFresh 準拠 + EthLock/HashStorage/Evidence） ----
export async function deployContracts(rpcUrl, t = TIMING) {
  const clients = makeClients(rpcUrl);
  // 2026-07-27: START_TIME は全契約で「ブロック0の応募開始」に統一（旧: TokenMining のみ +BLOCK_TIME）
  const tmStart = t.S;

  // 1. EthStake（TokenMining constructor の verifier 引数用。test_local deployFresh :153-161）
  const ethStake = await deployOne(clients, 'EthStake', [BigInt(tmStart), BigInt(t.BLOCK_TIME)]);
  // 1b. HashStorage（admin = deployer / superAdmin = 引数）
  //     🔴 **TokenMining より先にデプロイする**（ZKP Stage 2・2026-08-04）。
  //     TokenMining が HashStorage を constructor 引数＋immutable で受け取るようになった
  //     （set-once セッターにしないことで「呼び忘れ」の罠を構造的に消す設計）。
  //     本番 deploy.js の step 1b と同じ順序。
  const hashStorage = await deployOne(clients, 'HashStorage', [SUPERADMIN_ADDR]);
  // 2. TokenMining
  const tokenMining = await deployOne(clients, 'TokenMining', [
    BigInt(tmStart), SUPERADMIN_ADDR, BigInt(t.BLOCK_TIME),
    BigInt(t.VERIFICATION_PERIOD), BigInt(t.CLAIM_PERIOD), ethStake.address,
    hashStorage.address,
  ]);
  // 2b. (旧) EthStake ← TokenMining 配線は 2026-07-27 に廃止（S1 監査 K-S1-001 是正）。
  //     EthStake は getClaimBasis で按分の材料だけを返し、報酬額の計算・判定は
  //     TokenMining が自身の報酬テーブルで行う。依存は TokenMining → EthStake の一方向のみ。
  // 3. Bitcoinu — 全 21M を TokenMining に発行（deployFresh :180-184）
  const votingEnabledTime = BigInt(t.S + 86400 * 365);
  const bitcoinu = await deployOne(clients, 'Bitcoinu', [votingEnabledTime, tokenMining.address]);
  await write(clients, tokenMining, 'setTokenAddress', [bitcoinu.address]);
  // 4. EthLock（デポジット元帳。constructor は tokenMining 参照のみ）
  const ethLock = await deployOne(clients, 'EthLock', [tokenMining.address]);
  // 4b. TokenMining → EthLock を **set-once** で配線（2026-07-31・請求データ自己完結化）。
  //     claimLockReward が受取先と按分の重みを EthLock から読むために必要。
  //     R26 決定0: root提出時の配線自己検査は置かない。claimLockReward の台帳として必要。
  await write(clients, tokenMining, 'setEthLock', [ethLock.address]);
  // 5. (HashStorage は 1b へ前倒し済み — TokenMining の constructor 引数になったため)
  // 6. Evidence（startTime=応募開始S・全て秒。v3.2: TERM1撤廃。K-S1-003 で7引数・C32F2 で8引数）
  const evidence = await deployOne(clients, 'Evidence', [
    BigInt(t.S), BigInt(t.BLOCK_TIME), BigInt(t.GAME_PERIOD), BigInt(t.SUBMIT_PERIOD),
    BigInt(t.GRACE), SUPERADMIN_ADDR,
    tokenMining.address,   // K-S1-003: constructor で時刻基準の一致を検証
    BigInt(t.START_PAST_TOLERANCE ?? TIMING.START_PAST_TOLERANCE), // C32F2: 第8引数（末尾）
  ]);
  // 6c. TokenMining → Evidence を **set-once** で配線（本番 deploy.js の step 6c と同じ）。
  //     shadow 期間（proofRequired=false）の submitMerkleRoot には不要だが、
  //     submitMerkleRootWithProof が evidenceAcc を読むので実機と同じ状態にしておく。
  await write(clients, tokenMining, 'setEvidence', [evidence.address]);

  return { clients, ethStake, tokenMining, bitcoinu, ethLock, hashStorage, evidence };
}

export async function write(clients, contract, functionName, args, opts = {}) {
  const hash = await clients.walletClient.writeContract({
    address: contract.address, abi: contract.abi, functionName, args, ...opts,
  });
  const receipt = await clients.publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`${functionName} reverted (tx ${hash})`);
  return receipt;
}

// ---- 時刻振付ヘルパー ----
export async function setNextTimestamp(rpcUrl, tsSec) {
  await rpc(rpcUrl, 'evm_setNextBlockTimestamp', [tsSec]);
}
export async function mineOne(rpcUrl) {
  await rpc(rpcUrl, 'evm_mine', []);
}
// count ブロックを interval 秒間隔で採掘。
// 注意: hardhat_mine の一括採掘は「予約ブロック」を作り、その高さへの過去状態読み
// （eth_call at blockNumber）が "task panicked" で落ちる（reconcileEvidence の safeBlock 固定読取が
// まさにそれを踏む）。そのため 1 ブロックずつ evm_mine する（全ブロック実体化・履歴読取可能）。
export async function mineMany(rpcUrl, count, intervalSec = 1) {
  const latest = await rpc(rpcUrl, 'eth_getBlockByNumber', ['latest', false]);
  let ts = parseInt(latest.timestamp, 16);
  for (let i = 0; i < count; i++) {
    ts += intervalSec;
    await rpc(rpcUrl, 'evm_mine', [ts]);
  }
}
export async function latestBlock(rpcUrl) {
  return rpc(rpcUrl, 'eth_getBlockByNumber', ['latest', false]);
}
