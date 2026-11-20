// R15-W11: 取消不能なEthStake切替、14日vkey提案、即時変更可能なadminを
// systemAuditが実読し、CLIがwarnとして描画することを固定する。
// 実行: node block-verifier/test/r15-w11-system-audit-unit.mjs

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { createReport } from '../src/report.js';
import { applyVerifiedTokenDisplay } from '../src/token-display.js';

const ROOT = path.resolve(import.meta.dirname, '..');
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1] || null;
const authorityProbe = process.argv.find((arg) => arg.startsWith('--authority-probe='))?.split('=')[1] || null;
const MAX_UINT256 = (1n << 256n) - 1n;
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;
const METADATA_BLOCK = 12_345n;
const ADDR = Object.freeze({
  tokenMining: `0x${'1'.repeat(40)}`,
  evidence: `0x${'2'.repeat(40)}`,
  ethLock: `0x${'3'.repeat(40)}`,
  ethStake: `0x${'4'.repeat(40)}`,
  token: `0x${'5'.repeat(40)}`,
  hashStorage: `0x${'6'.repeat(40)}`,
  tmAdmin: `0x${'a'.repeat(40)}`,
  tmSuperAdmin: `0x${'b'.repeat(40)}`,
  evAdmin: `0x${'c'.repeat(40)}`,
  evSuperAdmin: `0x${'d'.repeat(40)}`,
  hsAdmin: `0x${'e'.repeat(40)}`,
  hsSuperAdmin: `0x${'f'.repeat(40)}`,
});

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (error) {
    console.error(`  NG  ${name}: ${error.message}`);
    failed++;
  }
}

async function loadChainModule() {
  let source = await readFile(path.join(ROOT, 'src/chain.js'), 'utf8');
  if (mutation === 'eth-stake-read') {
    source = source.replace(
      "read(tm, TOKEN_MINING_ABI, 'ethStakeFromBlock'),",
      'Promise.resolve(UINT256_MAX),',
    );
  } else if (mutation === 'pending-vkey-read') {
    source = source
      .replace("read(tm, TOKEN_MINING_ABI, 'pendingVkey'),", 'Promise.resolve(ZERO_BYTES32_FOR_TEST),')
      .replace("read(tm, TOKEN_MINING_ABI, 'pendingVkeyEta'),", 'Promise.resolve(0n),');
  } else if (mutation === 'admin-read') {
    source = source.replace(
      `      adminRotation.push({
        contract: name, address, admin, superAdmin,
        immediateAdminRotation: true,
        separated: !same(admin, superAdmin),
      });`,
      '      // mutation: admin authority omitted',
    );
  } else if (mutation === 'authority-compare') {
    source = source.replace(
      'separated: !same(admin, superAdmin),',
      'separated: true,',
    );
  } else if (mutation === 'evidence-hash-storage-compare') {
    // 便 C30F1b: Evidence.HASH_STORAGE の配線照合を外す変異（照合が無い＝便 C30F1 の前の形）。
    const before = source;
    source = source.replace('ok: same(evidenceHashStorage, hashStorageAddr),', 'ok: true,');
    assert.notEqual(source, before, 'evidence-hash-storage-compare の変異を適用できない');
  } else if (mutation === 't4-4-sender-limit') {
    source = source.replace('ok: BigInt(maxResultsPerSenderRaw) === 3n,', 'ok: true,');
  } else if (mutation === 't4-4-entry-selector') {
    source = source.replace('ok: typeof evidenceCode === \'string\' && !entrySelectorPresent,', 'ok: true,');
  } else if (mutation === 't4-4-entry-acc') {
    source = source.replace('ok: ZERO_BYTES32.test(String(entryAccZero))\n            && ZERO_BYTES32.test(String(entryAccMax)),', 'ok: true,');
  } else if (mutation === 'entry-signature') {
    const before = source;
    source = source.replace("toFunctionSelector('submitEntry(uint256,bytes)')",
      "toFunctionSelector('submitEntrz(uint256,bytes)')");
    assert.notEqual(source, before, 'entry-signature の変異を適用できない');
  } else if (mutation === 'entry-push4') {
    // fixture だけを壊す。PUSH4 が無ければ旧入口の検出が赤になる。
  } else if (mutation === 'entry-detector-no-push4') {
    const before = source;
    source = source.replace('includes(`63${oldEntrySelector.slice(2).toLowerCase()}`)',
      'includes(`${oldEntrySelector.slice(2).toLowerCase()}`)');
    assert.notEqual(source, before, 'entry-detector-no-push4 の変異を適用できない');
  } else if (mutation === 'evidence-start-past-tolerance-compare') {
    // 便 C32F2: 許容幅の方針照合を外す変異（照合が無い＝便 C32F2 の前の形）。
    const before = source;
    source = source.replace(
      'ok: inRange && (profile === null || tolerance === profile.startPastTolerance),', 'ok: true,');
    assert.notEqual(source, before, 'evidence-start-past-tolerance-compare の変異を適用できない');
  } else if (mutation === 'evidence-start-past-tolerance-profile') {
    // 便 C32F2: プロファイルの値の照合だけを外す変異（範囲の検査は残る）。
    const before = source;
    source = source.replace('(profile === null || tolerance === profile.startPastTolerance)', 'true');
    assert.notEqual(source, before, 'evidence-start-past-tolerance-profile の変異を適用できない');
  } else if (mutation === 'evidence-start-past-tolerance-upper') {
    // 便 C32F2（検証役の指摘の是正）: 範囲の上限を修正前の「GAME_PERIOD 未満」へ戻す変異（GAME_PERIOD−1 を通す）。
    const before = source;
    source = source.replace('tolerance <= actual.gamePeriod - 2;', 'tolerance < actual.gamePeriod;');
    assert.notEqual(source, before, 'evidence-start-past-tolerance-upper の変異を適用できない');
  } else if (mutation !== null) {
    throw new Error(`unknown mutation: ${mutation}`);
  }

  source = source
    .replace(
      "import { createPublicClient, http, fallback, parseAbiItem, toFunctionSelector, decodeEventLog } from 'viem';",
      "const createPublicClient = () => globalThis.__R15_W11_CLIENT;\nconst http = (value) => value;\nconst fallback = (value) => value;\nconst parseAbiItem = (value) => value;\nconst decodeEventLog = () => { throw new Error('unexpected authority log'); };\nconst toFunctionSelector = (signature) => { if (signature !== 'submitEntry(uint256,bytes)') throw new Error('unexpected selector signature: ' + signature); return '0xa323807c'; };\nconst ZERO_BYTES32_FOR_TEST = `0x${'0'.repeat(64)}`;",
    )
    .replace("import { mainnet } from 'viem/chains';", 'const mainnet = {};')
    .replace(
      "import { getLogs as getLogsAction } from 'viem/actions';",
      `const { getLogs: getLogsAction } = await import(${JSON.stringify(import.meta.resolve('viem/actions'))});`,
    )
    .replace(
      "import { displayRpcUrl } from './rpc-privacy.js';",
      `const { displayRpcUrl } = await import(${JSON.stringify(new URL('../src/rpc-privacy.js', import.meta.url).href)});`,
    )
    .replace(
      "import { archiveProbe, ArchiveUnavailableError, historicalStateFailure, isLogRangeFailure } from './archive.js';",
      `const { archiveProbe, ArchiveUnavailableError, historicalStateFailure, isLogRangeFailure } = await import(${JSON.stringify(new URL('../src/archive.js', import.meta.url).href)});`,
    )
    .replace(
      "import { LEGACY_HASH_STORAGE_ALLOWLIST } from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';",
      'const LEGACY_HASH_STORAGE_ALLOWLIST = [];',
    )
    .replace(
      "import { getLogsAdaptive } from '../vendor/workers/game_workers/lib/getlogs-adaptive.js';",
      'const getLogsAdaptive = async (fetchRange, from, to) => fetchRange(from, to);',
    );
  assert.equal(/^import /m.test(source), false, 'chain.jsのimportスタブ化に失敗');
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}#${Date.now()}`);
}

function makeClient({
  fromBlock,
  currentUnlocked,
  pendingVkey,
  pendingGuestSourceHash = ZERO_BYTES32,
  pendingVkeyEta,
  pendingVerifier = ZERO_ADDRESS,
  pendingProposedAt = 0n,
  pendingAnchorProvider = ZERO_ADDRESS,
  authority = {},
  tokenMetadata = { name: 'COINU', symbol: 'COINU', nameChanged: false },
  // 便 C30F1b: 便 C30F1 で chain.js が Evidence.HASH_STORAGE を読み、TokenMining.hashStorage と照合する。
  evidenceHashStorage = ADDR.hashStorage,
  // 便 C32F2: chain.js が Evidence.START_PAST_TOLERANCE を読み、デプロイの方針と照合する。
  //   null なら getter の無い Evidence（C32F2 以前）として読取を失敗させる。
  evidenceStartPastTolerance = 3_600n,
  senderLimit = 3n,
  entryAccValue = ZERO_BYTES32,
  evidenceCode = '0x6000',
  // 期間を差し替える（block 0 E2E・ローカル試験の盤面）。既定は本番の期間。
  periods = {},
}) {
  const calls = [];
  const authorityByAddress = {
    [ADDR.tokenMining]: { admin: ADDR.tmAdmin, superAdmin: ADDR.tmSuperAdmin },
    [ADDR.evidence]: { admin: ADDR.evAdmin, superAdmin: ADDR.evSuperAdmin },
    [ADDR.hashStorage]: { admin: ADDR.hsAdmin, superAdmin: ADDR.hsSuperAdmin },
  };
  for (const [address, values] of Object.entries(authority)) {
    authorityByAddress[address] = { ...authorityByAddress[address], ...values };
  }
  const client = {
    calls,
    async getCode() { return evidenceCode; },
    async getBlock() { throw new Error("unexpected block header read in system audit fixture"); },
    async getLogs() { return []; },
    async getBlockNumber() { return METADATA_BLOCK; },
    async readContract({ address, functionName, args = [], blockNumber }) {
      calls.push({ address, functionName, blockNumber });
      if (authorityByAddress[address]?.[functionName]) return authorityByAddress[address][functionName];
      if (authorityByAddress[address] && functionName === 'pendingSuperAdmin') return ZERO_ADDRESS;
      if (authorityByAddress[address] && functionName === 'pendingSuperAdminEta') return 0n;
      if (address === ADDR.tokenMining) {
        if (functionName === 'getBlockMode') return BigInt(args[0]) >= BigInt(fromBlock) ? 1 : 0;
        const values = {
          evidence: ADDR.evidence,
          ethLock: ADDR.ethLock,
          ethStake: ADDR.ethStake,
          token: ADDR.token,
          hashStorage: ADDR.hashStorage,
          START_TIME: 1_800_000_000n,
          BLOCK_INTERVAL: periods.BLOCK_INTERVAL ?? 345_600n,
          MAX_BLOCK_NUM: 363n,
          verificationPeriod: periods.verificationPeriod ?? 345_600n,
          CLAIM_PERIOD: periods.CLAIM_PERIOD ?? 3_456_000n,
          ethStakeFromBlock: fromBlock,
          getCurrentTimeUnlockedBlock: currentUnlocked,
          pendingVkey,
          pendingGuestSourceHash,
          pendingVkeyEta,
          pendingVerifier,
          pendingProposedAt,
          pendingAnchorProvider,
        };
        if (Object.hasOwn(values, functionName)) return values[functionName];
      }
      if (address === ADDR.evidence) {
        const values = {
          TOKEN_MINING: ADDR.tokenMining,
          HASH_STORAGE: evidenceHashStorage,
          MAX_RESULTS_PER_SENDER: senderLimit,
          entryAcc: entryAccValue,
          MAX_BLOCK_NUM: 363n,
          GAME_PERIOD: periods.GAME_PERIOD ?? 86_400n,
          SUBMIT_PERIOD: periods.SUBMIT_PERIOD ?? 86_400n,
          INITIAL_GRACE: periods.INITIAL_GRACE ?? 7_200n,
        };
        if (functionName === 'START_PAST_TOLERANCE') {
          if (evidenceStartPastTolerance === null) {
            throw new Error('execution reverted: START_PAST_TOLERANCE() is not a function of this Evidence');
          }
          return evidenceStartPastTolerance;
        }
        if (Object.hasOwn(values, functionName)) return values[functionName];
      }
      if (address === ADDR.ethLock && functionName === 'tokenMining') return ADDR.tokenMining;
      if (address === ADDR.ethStake) {
        if (functionName === 'START_TIME') return 1_800_000_000n;
        if (functionName === 'BLOCK_INTERVAL') return periods.BLOCK_INTERVAL ?? 345_600n;
        if (functionName === 'MAX_BLOCK_NUM') return 363n;
      }
      if (address === ADDR.token && Object.hasOwn(tokenMetadata, functionName)) return tokenMetadata[functionName];
      if (address === ADDR.token && functionName === 'totalSupply') return 21_000_000n * 10n ** 18n;
      if (address === ADDR.token && functionName === 'balanceOf') return 21_000_000n * 10n ** 18n;
      throw new Error(`unexpected read: ${address} ${functionName}`);
    },
  };
  return client;
}

function createAudit(chainModule, client) {
  globalThis.__R15_W11_CLIENT = client;
  return chainModule.createChain({
    chainIdExpected: 31337,
    rpcUrls: ['http://stub.invalid'],
    rpcPresets: [],
    contracts: {
      tokenMining: ADDR.tokenMining,
      evidence: ADDR.evidence,
      ethLock: ADDR.ethLock,
      ethStake: ADDR.ethStake,
      hashStorage: ADDR.hashStorage,
      donate: null,
    },
  });
}

console.log('R15-W11 block-verifier system audit');
const chainModule = await loadChainModule();
const indexSource = await readFile(path.join(ROOT, 'src/index.js'), 'utf8');
const categorizeSource = indexSource.match(/function categorize\(outcome\) \{[\s\S]*?\n\}/)?.[0];
const exitCodesSource = indexSource.match(/const EXIT_CODE_OF = (\{[^;]+\});/)?.[1];
assert.ok(categorizeSource, 'index.jsからcategorizeを抽出できない');
assert.ok(exitCodesSource, 'index.jsからEXIT_CODE_OFを抽出できない');
const liveExit = Function(
  `"use strict"; ${categorizeSource}; return { categorize, EXIT_CODE_OF: ${exitCodesSource} };`,
)();

function authorityExitCode(audit) {
  const report = createReport();
  report.check(
    'check.system.authoritySeparation',
    audit.wiring.authoritySeparation.ok ? 'pass' : 'fail',
    audit.wiring.authoritySeparation,
  );
  return liveExit.EXIT_CODE_OF[liveExit.categorize({ fatal: false, report, stopped: false })];
}

if (authorityProbe !== null) {
  assert.ok(['separated', 'collapsed'].includes(authorityProbe), `unknown authority probe: ${authorityProbe}`);
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
    authority: authorityProbe === 'collapsed'
      ? { [ADDR.tokenMining]: { superAdmin: ADDR.tmAdmin } }
      : {},
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  const exitCode = authorityExitCode(audit);
  console.log(`##CHECK check.system.authoritySeparation ${audit.wiring.authoritySeparation.ok ? 'pass' : 'fail'}`);
  console.log(`##RESULT ${exitCode === 2 ? 'fail' : 'full'}`);
  process.exit(exitCode);
}

await test('未設定のEthStake切替と空のvkey提案を誤検出しない', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.ethStakeSwitch.announced, false);
  assert.equal(audit.pendingVkey.pending, false);
  assert.deepEqual(audit.pendingSuperAdmin, []);
});

await test('U-8/U-16 の送信者3枠・旧入口不在・entryAccゼロを両方向で照合する', async () => {
  const base = { fromBlock: MAX_UINT256, currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32, pendingVkeyEta: 0n };
  const good = (await createAudit(chainModule, makeClient(base)).systemAudit()).wiring;
  assert.equal(good.evidenceSenderLimit.ok, true);
  assert.equal(good.evidenceEntryRemoved.ok, true);
  assert.equal(good.evidenceEntryAccZero.ok, true);
  const wrongLimit = (await createAudit(chainModule, makeClient({ ...base, senderLimit: 4n })).systemAudit()).wiring;
  assert.equal(wrongLimit.evidenceSenderLimit.ok, false);
  const oldEntry = (await createAudit(chainModule, makeClient({ ...base,
    evidenceCode: mutation === 'entry-push4' ? '0xa323807c00' : '0x63a323807c00' })).systemAudit()).wiring;
  assert.equal(oldEntry.evidenceEntryRemoved.ok, false);
  const selectorOutsidePush4 = (await createAudit(chainModule, makeClient({ ...base,
    evidenceCode: '0x00a323807c00' })).systemAudit()).wiring;
  assert.equal(selectorOutsidePush4.evidenceEntryRemoved.ok, true);
  const nonzeroAcc = (await createAudit(chainModule, makeClient({ ...base,
    entryAccValue: '0x' + '01'.repeat(32) })).systemAudit()).wiring;
  assert.equal(nonzeroAcc.evidenceEntryAccZero.ok, false);
  for (const id of ['evidenceSenderLimit', 'evidenceEntryRemoved', 'evidenceEntryAccZero']) {
    assert.ok(indexSource.includes(`['check.system.${id}', audit.wiring.${id}]`));
    for (const lang of SUPPORTED_LANGS) assert.ok(t(lang, `check.system.${id}`));
  }
});

await test('N<KでgetBlockModeが0の公示期間にもEthStake切替を8日warnへ載せる', async () => {
  const client = makeClient({
    fromBlock: 9n,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const chain = createAudit(chainModule, client);
  assert.equal(await chain.getBlockMode(8), 0);
  const audit = await chain.systemAudit();
  assert.deepEqual(audit.ethStakeSwitch, {
    announced: true,
    fromBlock: 9,
    currentUnlocked: 7,
    blocksAhead: 2,
    daysLeft: 8,
  });
  assert.ok(client.calls.some((call) => call.functionName === 'ethStakeFromBlock'));
  assert.ok(indexSource.includes("report.check('fact.system.ethStakeFromBlockSet', 'warn', audit.ethStakeSwitch)"));
});

await test('14日vkey提案を実読してwarnへ載せる', async () => {
  const eta = BigInt(Math.floor(Date.now() / 1000) + 14 * 86400);
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: `0x${'9'.repeat(64)}`,
    pendingGuestSourceHash: `0x${'8'.repeat(64)}`,
    pendingVkeyEta: eta,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.pendingVkey.pending, true);
  assert.equal(audit.pendingVkey.vkey, `0x${'9'.repeat(64)}`);
  assert.equal(audit.pendingVkey.guestSourceHash, `0x${'8'.repeat(64)}`);
  assert.ok(audit.pendingVkey.daysLeft >= 13 && audit.pendingVkey.daysLeft <= 14);
  assert.ok(client.calls.some((call) => call.functionName === 'pendingVkey'));
  assert.ok(client.calls.some((call) => call.functionName === 'pendingGuestSourceHash'));
  assert.ok(client.calls.some((call) => call.functionName === 'pendingVkeyEta'));
  assert.ok(indexSource.includes("report.check('fact.system.pendingVkey', 'warn', audit.pendingVkey)"));
});

await test('メニュー2用の公示中の提案を契約の6 viewから読む', async () => {
  const eta = BigInt(Math.floor(Date.now() / 1000) + 14 * 86400);
  const client = makeClient({ fromBlock: MAX_UINT256, currentUnlocked: 7n,
    pendingVerifier: ADDR.tmSuperAdmin, pendingVkey: `0x${'9'.repeat(64)}`,
    pendingGuestSourceHash: `0x${'8'.repeat(64)}`, pendingProposedAt: eta - 14n * 86400n,
    pendingVkeyEta: eta, pendingAnchorProvider: ADDR.evidence });
  const proposal = await createAudit(chainModule, client).pendingVkeyProposal();
  assert.equal(proposal.pending, true);
  assert.equal(proposal.verifier, ADDR.tmSuperAdmin);
  assert.equal(proposal.vkey, `0x${'9'.repeat(64)}`);
  assert.equal(proposal.guestSourceHash, `0x${'8'.repeat(64)}`);
  assert.equal(proposal.proposedAt, Number(eta - 14n * 86400n));
  assert.equal(proposal.eta, Number(eta));
  assert.equal(proposal.anchorProvider, ADDR.evidence);
  for (const functionName of ['pendingVerifier', 'pendingVkey', 'pendingGuestSourceHash',
    'pendingProposedAt', 'pendingVkeyEta', 'pendingAnchorProvider']) {
    assert(client.calls.some((call) => call.functionName === functionName), functionName);
  }
});

await test('メニュー2は提案なしならETAだけを読み適用済み経路を保つ', async () => {
  const client = makeClient({ fromBlock: MAX_UINT256, currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32, pendingVkeyEta: 0n });
  const proposal = await createAudit(chainModule, client).pendingVkeyProposal();
  assert.deepEqual(proposal, { pending: false, eta: 0 });
  assert.deepEqual(client.calls.map((call) => call.functionName), ['pendingVkeyEta']);
});

await test('即時変更可能なadminとsuperAdminを3契約ともwarnへ載せる', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.deepEqual(audit.adminRotation.map(({ contract, admin, superAdmin }) => ({ contract, admin, superAdmin })), [
    { contract: 'TokenMining', admin: ADDR.tmAdmin, superAdmin: ADDR.tmSuperAdmin },
    { contract: 'Evidence', admin: ADDR.evAdmin, superAdmin: ADDR.evSuperAdmin },
    { contract: 'HashStorage', admin: ADDR.hsAdmin, superAdmin: ADDR.hsSuperAdmin },
  ]);
  assert.ok(indexSource.includes("report.check('fact.system.adminRotation', 'warn'"));
});

await test('3契約のadminとsuperAdminが別鍵ならauthority separationを通す', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.wiring.authoritySeparation.ok, true);
  assert.equal(audit.wiring.authoritySeparation.collapsed, '-');
  assert.equal(authorityExitCode(audit), 0);
});

await test('COINU初期メタデータを総供給量と合わせて検証する', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.wiring.token.ok, true);
  assert.equal(audit.wiring.token.metadataOk, true);
  assert.equal(audit.wiring.token.name, 'COINU');
  assert.equal(audit.wiring.token.symbol, 'COINU');
});

await test('投票成立後のBitcoin / BTCメタデータを許可する', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
    tokenMetadata: { name: 'Bitcoin', symbol: 'BTC', nameChanged: true },
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.wiring.token.ok, true);
  assert.equal(audit.wiring.token.metadataOk, true);
});

await test('name/symbol/nameChangedを同一ブロックから読む', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  const metadataCalls = client.calls.filter((call) =>
    call.address === ADDR.token && ['name', 'symbol', 'nameChanged'].includes(call.functionName));
  assert.equal(metadataCalls.length, 3);
  assert.deepEqual(metadataCalls.map((call) => call.blockNumber), [METADATA_BLOCK, METADATA_BLOCK, METADATA_BLOCK]);
  assert.equal(audit.wiring.token.blockNumber, METADATA_BLOCK.toString());
});

await test('nameChangedと矛盾する名称・シンボルをfailにする', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
    tokenMetadata: { name: 'COINU', symbol: 'COINU', nameChanged: true },
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.wiring.token.ok, false);
  assert.equal(audit.wiring.token.metadataOk, false);
});

await test('未検証メタデータをFAIL行と結論行へ流し込まない', () => {
  const translate = t('en');
  const applied = applyVerifiedTokenDisplay(translate, {
    name: 'Attacker Coin', symbol: 'EVIL', nameChanged: false, metadataOk: false,
  });
  assert.equal(applied, false);
  const failLine = translate('check.system.tokenSupply');
  const conclusion = translate('conclusion.results', {
    block: 1, reward: 1, players: 1, groups: 1, dq: 0,
    rootTime: '-', verEnd: '-', claimEnd: '-',
  });
  assert.doesNotMatch(`${failLine}\n${conclusion}`, /Attacker Coin|EVIL/);
  assert.match(`${failLine}\n${conclusion}`, /COINU/);
});

await test('検証済みの投票後メタデータだけを表示既定へ採用する', () => {
  const translate = t('en');
  const applied = applyVerifiedTokenDisplay(translate, {
    name: 'Bitcoin', symbol: 'BTC', nameChanged: true, metadataOk: true,
  });
  assert.equal(applied, true);
  assert.match(translate('conclusion.results', {
    block: 1, reward: 1, players: 1, groups: 1, dq: 0,
    rootTime: '-', verEnd: '-', claimEnd: '-',
  }), /BTC/);
});

await test('ZKP・オフラインproofの表示文言がトークン既定値に依存しない', () => {
  for (const lang of SUPPORTED_LANGS) {
    assert.doesNotMatch(t(lang)('zk.conclusionSourceMatches', { path: '/source' }), /COINU|BTC|\{token/);
    for (const id of ['proof.header', 'proof.rebuilt', 'proof.howToClaim']) {
      assert.doesNotMatch(t(lang)(id, { block: 1, path: '-', root: '-', count: 1 }), /\{token/);
    }
  }
});

await test('adminとsuperAdminが同一ならauthority separationをfailにする', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
    authority: {
      [ADDR.tokenMining]: { superAdmin: ADDR.tmAdmin },
    },
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.equal(audit.wiring.authoritySeparation.ok, false);
  assert.match(audit.wiring.authoritySeparation.collapsed, /TokenMining/);
  assert.equal(authorityExitCode(audit), 2);
});

// 便 C30F1b: Evidence.HASH_STORAGE の配線検査（便 C30F1・chain.js の evidenceHashStorage）を両方向で縛る。
function systemCheckExitCode(id, value) {
  const report = createReport();
  report.check(id, value.ok ? 'pass' : 'fail', value);
  return liveExit.EXIT_CODE_OF[liveExit.categorize({ fatal: false, report, stopped: false })];
}

await test('Evidence.HASH_STORAGE が TokenMining.hashStorage と一致すれば配線検査を通す', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.deepEqual(audit.wiring.evidenceHashStorage, {
    ok: true, evidence: ADDR.hashStorage, tokenMining: ADDR.hashStorage,
  });
  assert.ok(client.calls.some((call) => call.address === ADDR.evidence && call.functionName === 'HASH_STORAGE'));
  assert.equal(systemCheckExitCode('check.system.evidenceHashStorage', audit.wiring.evidenceHashStorage), 0);
});

await test('Evidence.HASH_STORAGE が別の HashStorage を指せば配線検査を fail にする', async () => {
  const other = `0x${'7'.repeat(40)}`;
  const client = makeClient({
    fromBlock: MAX_UINT256,
    currentUnlocked: 7n,
    pendingVkey: ZERO_BYTES32,
    pendingVkeyEta: 0n,
    evidenceHashStorage: other,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  assert.deepEqual(audit.wiring.evidenceHashStorage, {
    ok: false, evidence: other, tokenMining: ADDR.hashStorage,
  });
  assert.equal(systemCheckExitCode('check.system.evidenceHashStorage', audit.wiring.evidenceHashStorage), 2);
});

await test('Evidence.HASH_STORAGE の配線検査をCLIのsystem検査へ配線し、3言語の実文言がある', () => {
  assert.ok(indexSource.includes(
    "['check.system.evidenceHashStorage', audit.wiring.evidenceHashStorage]",
  ));
  const id = 'check.system.evidenceHashStorage';
  for (const lang of SUPPORTED_LANGS) {
    const rendered = t(lang)(id, {});
    assert.notEqual(rendered, id, `${lang}: ${id}`);
    assert.match(rendered, /HASH_STORAGE/, `${lang}: ${id}`);
  }
});

// 便 C32F2（C32-B-01）: Evidence.START_PAST_TOLERANCE の方針照合（決定0 で必須の第三者の検査）を両方向で縛る。
const E2E_PERIODS = Object.freeze({
  BLOCK_INTERVAL: 5_400n, verificationPeriod: 300n, CLAIM_PERIOD: 10_800n,
  GAME_PERIOD: 1_200n, SUBMIT_PERIOD: 600n, INITIAL_GRACE: 3_000n,
});
const STAGE3_E2E_PERIODS = Object.freeze({
  BLOCK_INTERVAL: 10_800n, verificationPeriod: 300n, CLAIM_PERIOD: 43_200n,
  GAME_PERIOD: 3_600n, SUBMIT_PERIOD: 1_200n, INITIAL_GRACE: 3_600n,
});
const TIMING1_E2E_PERIODS = Object.freeze({
  BLOCK_INTERVAL: 3_600n, verificationPeriod: 600n, CLAIM_PERIOD: 10_800n,
  GAME_PERIOD: 1_800n, SUBMIT_PERIOD: 600n, INITIAL_GRACE: 1_200n,
});
const TIMING2_E2E_PERIODS = Object.freeze({
  BLOCK_INTERVAL: 3_600n, verificationPeriod: 300n, CLAIM_PERIOD: 10_800n,
  GAME_PERIOD: 1_200n, SUBMIT_PERIOD: 600n, INITIAL_GRACE: 1_800n,
});
const LOCAL_PERIODS = Object.freeze({
  BLOCK_INTERVAL: 600n, verificationPeriod: 300n, CLAIM_PERIOD: 1_800n,
  GAME_PERIOD: 180n, SUBMIT_PERIOD: 180n, INITIAL_GRACE: 120n,
});
async function toleranceAudit(evidenceStartPastTolerance, periods = {}) {
  const client = makeClient({
    fromBlock: MAX_UINT256, currentUnlocked: 7n, pendingVkey: ZERO_BYTES32, pendingVkeyEta: 0n,
    evidenceStartPastTolerance, periods,
  });
  const audit = await createAudit(chainModule, client).systemAudit();
  return { audit, client };
}

await test('C32F2: 方針のプロファイルの許容幅は Hardhat の mainnet-parameter-policy.js と同じ固定値', async () => {
  const { createRequire } = await import('node:module');
  const policy = createRequire(import.meta.url)('../../Hardhat/bitcoinu/scripts/lib/mainnet-parameter-policy.js');
  const [production, e2e, stage3] = chainModule.START_PAST_TOLERANCE_PROFILES;
  assert.equal(chainModule.START_PAST_TOLERANCE_PROFILES.length, 3);
  assert.deepEqual(chainModule.START_PAST_TOLERANCE_PROFILES.map((p) => p.name),
    ['production', 'block0-e2e', 'block0-e2e-stage3']);
  assert.equal(production.startPastTolerance, 3600);
  assert.equal(e2e.startPastTolerance, 60);
  assert.equal(stage3.startPastTolerance, 180);
  assert.deepEqual(stage3.params, {
    blockInterval: 10800, verificationPeriod: 300, claimPeriod: 43200,
    gamePeriod: 3600, submitPeriod: 1200, initialGrace: 3600,
  });
  for (const [profile, source] of [[production, policy.PRODUCTION_PROFILE], [e2e, policy.BLOCK0_E2E_PROFILE],
    [stage3, policy.BLOCK0_E2E_STAGE3_PROFILE]]) {
    assert.deepEqual({
      blockInterval: source.BLOCK_INTERVAL, verificationPeriod: source.VERIFICATION_PERIOD,
      claimPeriod: source.CLAIM_PERIOD, gamePeriod: source.GAME_PERIOD_SEC,
      submitPeriod: source.SUBMIT_PERIOD_SEC, initialGrace: source.RESULT_GRACE,
    }, { ...profile.params }, `${profile.name}: 期間が方針と一致`);
    assert.equal(profile.startPastTolerance, source.START_PAST_TOLERANCE_SEC, `${profile.name}: 許容幅が方針と一致`);
  }
});

await test('C32F2: 本番の期間で許容幅 3600 なら配線検査と productionParams を通す', async () => {
  const { audit, client } = await toleranceAudit(3_600n);
  assert.deepEqual(audit.wiring.evidenceStartPastTolerance, {
    ok: true, startPastTolerance: '3600', profile: 'production', expected: '3600', gamePeriod: 86400,
  });
  assert.ok(client.calls.some((call) => call.address === ADDR.evidence && call.functionName === 'START_PAST_TOLERANCE'));
  assert.equal(systemCheckExitCode('check.system.evidenceStartPastTolerance', audit.wiring.evidenceStartPastTolerance), 0);
  assert.equal(audit.production.actual.startPastTolerance, 3600);
  assert.equal(audit.production.expected.startPastTolerance, 3600);
  assert.equal(audit.production.ok, true);
});

for (const [label, value] of [['E2E の 60', 60n], ['3599', 3_599n], ['3601', 3_601n], ['0（厳格）', 0n], ['GAME_PERIOD 以上', 86_400n]]) {
  await test(`C32F2: 本番の期間で許容幅 ${label} なら配線検査と productionParams を fail にする`, async () => {
    const { audit } = await toleranceAudit(value);
    assert.equal(audit.wiring.evidenceStartPastTolerance.ok, false);
    assert.equal(audit.wiring.evidenceStartPastTolerance.profile, 'production');
    assert.equal(audit.wiring.evidenceStartPastTolerance.expected, '3600');
    assert.equal(systemCheckExitCode('check.system.evidenceStartPastTolerance', audit.wiring.evidenceStartPastTolerance), 2);
    assert.equal(audit.production.ok, false);
    assert.ok(audit.production.mismatches.some((line) => line.startsWith('startPastTolerance=')));
  });
}

await test('C32F2: block 0 E2E の期間では許容幅 60 だけを通す', async () => {
  const { audit } = await toleranceAudit(60n, E2E_PERIODS);
  const ok60 = audit.wiring.evidenceStartPastTolerance;
  assert.deepEqual(ok60, { ok: true, startPastTolerance: '60', profile: 'block0-e2e', expected: '60', gamePeriod: 1200 });
  assert.equal(systemCheckExitCode('check.system.evidenceStartPastTolerance', ok60), 0);
  assert.equal(audit.production.ok, false, '新 E2E も本番の正典とは区別する');
  assert.equal(systemCheckExitCode('check.system.productionParams', audit.production), 2);
  for (const value of [3_600n, 59n, 61n, 1_198n, 1_199n, 1_200n]) {
    const bad = (await toleranceAudit(value, E2E_PERIODS)).audit.wiring.evidenceStartPastTolerance;
    assert.equal(bad.ok, false, `E2E で ${value} は fail`);
    assert.equal(bad.profile, 'block0-e2e');
  }
});

await test('W-U-E2E-TIMING3: TIMING1・TIMING2・各期間の旧値／±1秒を本番とも E2E とも判定しない', async () => {
  const legacyProfiles = [['TIMING1', TIMING1_E2E_PERIODS], ['TIMING2', TIMING2_E2E_PERIODS]];
  const offProfiles = legacyProfiles.map(([label, profile]) => [`${label} の旧い組`, profile]);
  for (const [key, value] of Object.entries(E2E_PERIODS)) {
    for (const delta of [-1n, 1n]) {
      offProfiles.push([`${key} ${delta}秒`, { ...E2E_PERIODS, [key]: value + delta }]);
    }
    for (const [label, legacy] of legacyProfiles) {
      if (legacy[key] !== value) {
        offProfiles.push([`${key} だけ ${label} の旧値`, { ...E2E_PERIODS, [key]: legacy[key] }]);
      }
    }
  }
  for (const [label, periods] of offProfiles) {
    const { audit } = await toleranceAudit(60n, periods);
    assert.equal(audit.wiring.evidenceStartPastTolerance.profile, 'none', label);
    assert.equal(audit.production.ok, false, label);
    assert.equal(systemCheckExitCode('check.system.productionParams', audit.production), 2, label);
    assert.ok(audit.production.mismatches.length > 0, label);
  }
});

await test('W-C-E2E-S3-TIMING: 段3の期間では180だけ通し、productionParamsだけをfailに保つ', async () => {
  const { audit } = await toleranceAudit(180n, STAGE3_E2E_PERIODS);
  assert.deepEqual(audit.wiring.evidenceStartPastTolerance, {
    ok: true, startPastTolerance: '180', profile: 'block0-e2e-stage3', expected: '180', gamePeriod: 3600,
  });
  const failures = Object.entries(audit.wiring).filter(([, value]) => value.ok === false).map(([key]) => key);
  assert.deepEqual(failures, [], '段3の配線検査はすべて通る');
  assert.equal(systemCheckExitCode('check.system.evidenceStartPastTolerance', audit.wiring.evidenceStartPastTolerance), 0);
  assert.equal(audit.production.ok, false);
  assert.equal(systemCheckExitCode('check.system.productionParams', audit.production), 2);
  for (const value of [179n, 181n, 120n, 240n, 60n, 3600n, 3598n, 3599n, 0n]) {
    const judged = (await toleranceAudit(value, STAGE3_E2E_PERIODS)).audit.wiring.evidenceStartPastTolerance;
    assert.equal(judged.ok, false, `段3の許容幅${value}は拒否`);
    assert.equal(judged.profile, 'block0-e2e-stage3');
    assert.equal(judged.expected, '180');
  }
});

await test('W-C-E2E-S3-TIMING: 段3の6期間の単項目変更とE2E混成は固定プロファイルに一致しない', async () => {
  const offPeriods = [];
  for (const [key, value] of Object.entries(STAGE3_E2E_PERIODS)) {
    const variants = new Set([value - 60n, value - 1n, value + 1n, value + 60n,
      E2E_PERIODS[key], TIMING1_E2E_PERIODS[key], TIMING2_E2E_PERIODS[key]]);
    variants.delete(value);
    for (const variant of variants) offPeriods.push({ ...STAGE3_E2E_PERIODS, [key]: variant });
  }
  const keys = Object.keys(E2E_PERIODS).filter((key) => E2E_PERIODS[key] !== STAGE3_E2E_PERIODS[key]);
  for (let mask = 1; mask < (1 << keys.length) - 1; mask++) {
    const periods = { ...E2E_PERIODS };
    keys.forEach((key, bit) => { if (mask & (1 << bit)) periods[key] = STAGE3_E2E_PERIODS[key]; });
    offPeriods.push(periods);
  }
  for (const periods of offPeriods) {
    const { audit } = await toleranceAudit(180n, periods);
    assert.equal(audit.wiring.evidenceStartPastTolerance.profile, 'none');
    assert.equal(audit.production.ok, false);
  }
});

await test('W-U-E2E-TIMING3: チャット1200秒の範囲検査は1198秒まで（方針外のローカル期間）', async () => {
  const localPeriods = { ...E2E_PERIODS, CLAIM_PERIOD: 10_801n };
  for (const [value, ok] of [[1n, true], [60n, true], [1_198n, true], [1_199n, false], [1_200n, false], [0n, false]]) {
    const judged = (await toleranceAudit(value, localPeriods)).audit.wiring.evidenceStartPastTolerance;
    assert.equal(judged.profile, 'none');
    assert.equal(judged.expected, '1..1198');
    assert.equal(judged.ok, ok, `許容幅 ${value}`);
    assert.equal(systemCheckExitCode('check.system.evidenceStartPastTolerance', judged), ok ? 0 : 2);
  }
});

// 上限は GAME_PERIOD−2: Extend only と Chat window closed により遡りは GAME_PERIOD−2 秒までなので、
// GAME_PERIOD−1（ここでは 179）ではガードが一度も働かない（便 C32F2 の検証役の指摘）。
await test('C32F2: どの方針でもない期間（ローカル試験）では 1 以上 GAME_PERIOD−2 以下だけを通す', async () => {
  for (const [value, ok] of [[1n, true], [60n, true], [178n, true], [179n, false], [0n, false], [180n, false], [3_600n, false]]) {
    const judged = (await toleranceAudit(value, LOCAL_PERIODS)).audit.wiring.evidenceStartPastTolerance;
    assert.equal(judged.ok, ok, `ローカルの期間で ${value}`);
    assert.equal(judged.profile, 'none');
    assert.equal(judged.expected, '1..178');
  }
});

await test('C32F2: START_PAST_TOLERANCE の無い Evidence（C32F2 以前）は systemAudit を読めない（auditUnavailable の fail へ）', async () => {
  const client = makeClient({
    fromBlock: MAX_UINT256, currentUnlocked: 7n, pendingVkey: ZERO_BYTES32, pendingVkeyEta: 0n,
    evidenceStartPastTolerance: null,
  });
  await assert.rejects(() => createAudit(chainModule, client).systemAudit(), /START_PAST_TOLERANCE/);
  assert.ok(indexSource.includes("report.check('check.system.auditUnavailable', 'fail'"));
});

await test('C32F2: 許容幅の配線検査をCLIのsystem検査へ配線し、3言語の実文言がある', () => {
  assert.ok(indexSource.includes(
    "['check.system.evidenceStartPastTolerance', audit.wiring.evidenceStartPastTolerance]",
  ));
  const id = 'check.system.evidenceStartPastTolerance';
  for (const lang of SUPPORTED_LANGS) {
    const rendered = t(lang)(id, { startPastTolerance: '3600', profile: 'production', expected: '3600', gamePeriod: 86400 });
    assert.notEqual(rendered, id, `${lang}: ${id}`);
    assert.match(rendered, /START_PAST_TOLERANCE/, `${lang}: ${id}`);
    assert.match(rendered, /3600/, `${lang}: ${id}`);
    assert.doesNotMatch(rendered, /\{[a-zA-Z]+\}/, `${lang}: ${id} の差し込みが残らない`);
    assert.match(t(lang)('check.system.productionParams', {}), /1\s*h|1小时|1h/, `${lang}: productionParams に許容幅`);
    const stage3 = t(lang)(id, { startPastTolerance: '180', profile: 'block0-e2e-stage3', expected: '180', gamePeriod: 3600 });
    assert.match(stage3, /block0-e2e-stage3/);
    assert.match(stage3, /180/);
    assert.doesNotMatch(stage3, /\{[a-zA-Z]+\}/);
  }
});

await test('authority separationをCLIのsystem fail検査へ配線する', () => {
  assert.ok(indexSource.includes(
    "['check.system.authoritySeparation', audit.wiring.authoritySeparation]",
  ));
});

await test('3言語すべてに新warnの実文言がある', () => {
  const params = {
    fromBlock: 9,
    blocksAhead: 2,
    daysLeft: 8,
    vkey: `0x${'9'.repeat(64)}`,
    eta: 1_900_000_000,
    authorities: `TokenMining: admin ${ADDR.tmAdmin} / superAdmin ${ADDR.tmSuperAdmin}`,
  };
  for (const lang of SUPPORTED_LANGS) {
    const translate = t(lang);
    for (const id of ['fact.system.ethStakeFromBlockSet', 'fact.system.pendingVkey', 'fact.system.adminRotation']) {
      const rendered = translate(id, params);
      assert.notEqual(rendered, id, `${lang}: ${id}`);
      assert.ok(rendered.length > id.length, `${lang}: ${id}`);
    }
  }
});

await test('3言語すべてにauthority separationの実文言がある', () => {
  const id = 'check.system.authoritySeparation';
  for (const lang of SUPPORTED_LANGS) {
    const rendered = t(lang)(id, { collapsed: '-' });
    assert.notEqual(rendered, id, `${lang}: ${id}`);
    assert.ok(rendered.length > id.length, `${lang}: ${id}`);
  }
});

delete globalThis.__R15_W11_CLIENT;
console.log(`\nR15-W11 system audit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
