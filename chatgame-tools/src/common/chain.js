// src/common/chain.js — チェーン読取（viem・ローダー/復元クライアント共通）
//
// RPC 方針（DESIGN.md §3.4）:
//   - ローダー: 独立公開RPCのみ（運営RPCは使わない。照合前に運営を信じない）＋ウォレット(chainId=1のみ)
//   - 復元クライアント: S3R4-U-RPC1。注入ウォレットが答えればその1本、ほかは固定の公開プリセット S の
//     2本以上の一致。続く不一致は本人の承認・選択を求め、全公開先が無答のときだけ運営 RPC を使う。
//     利用者が足した cfg.rpcUrls は復元の読みに使わない（ローダーは従来どおり）。
// タイミングはチェーンが権威。Evidence.START_TIME=応募開始基準 / TokenMining.START_TIME=応募終了基準、
// 不変量 evStart + evBlockTime == tmStart を検査する（block-verifier chain.js と同じ流儀）。

import { createPublicClient, http, fallback, custom, defineChain } from 'viem';
import { mainnet } from 'viem/chains';
import { derivePhaseFromWindows } from '../../vendor/workers/game_workers/lib/timeline-check.js';
import { rosterAnchorKey, selectCanonicalRosterRegistration } from '../../vendor/workers/game_workers/lib/roster-anchor-rule.js';
import { classifyRpcAnswer, classifyRpcError, readKeyOf, numberedBlockOf, selectAgreedPublic,
  settledEarly, shouldStepBelow, selectPublicBlockNumber, selectPublicChainTip, acceptApprovedTip,
  createNoAgreementTracker, parseNodeTrust, serializeNodeTrust, describeRpcAnswer,
  missingHeadBelow, refreshStepBelow, createStaleBlockNotice, chosenWaitApplies, createChosenWaitTracker,
  STEP_BELOW_TTL_MS, SHALLOW_STEP_BLOCKS, TIP_READ_TIMEOUT_MS, REVERT_ANSWER_KEY,
} from '../../vendor/src/utils/chainAgreement.js';

// 旧 HashStorage は履歴 getter を持たない。collector と同じテスト配備だけに限定する。
export const LEGACY_HASH_STORAGE_ALLOWLIST = Object.freeze([
  ['0xd2c8a3be50d9a158bd57', '9a26a346f54cfb93426d'].join(''),
]);

// ---- ABI（正典 Hardhat/bitcoinu/contracts/*.sol から転記・読取と submitResult のみ） ----

export const HASH_STORAGE_ABI = [
  {
    type: 'function', name: 'getOtherHash', stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }],
  },
  { type: 'function', name: 'otherRegistrationCount', stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'otherRegistrationAt', stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }, { name: 'index', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'registeredBlock', type: 'uint256' }, { name: 'registeredAt', type: 'uint256' }] },
  {
    type: 'function', name: 'getApplicantHash', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }],
  },
  {
    type: 'function', name: 'getResultHash', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }],
  },
  {
    type: 'function', name: 'resultRegistrationCount', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }],
    outputs: [{ type: 'uint256' }],
  },
  {
    type: 'function', name: 'resultRegistrationAt', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }, { name: 'index', type: 'uint256' }],
    outputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'registeredAt', type: 'uint256' },
      { name: 'signer', type: 'address' },
    ],
  },
  { type: 'function', name: 'registrationCount', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }] },
  {
    type: 'function', name: 'applicantRegistrationAt', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }, { name: 'index', type: 'uint256' }],
    outputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'signer', type: 'address' },
    ],
  },
  {
    type: 'function', name: 'isApplicantRegistered', stateMutability: 'view',
    inputs: [
      { name: 'blockNumber', type: 'uint256' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'hash', type: 'bytes32' },
    ],
    outputs: [{ type: 'bool' }],
  },
  { type: 'function', name: 'latestBuildVersion', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  {
    type: 'function', name: 'getBuildHash', stateMutability: 'view',
    inputs: [{ name: 'buildVersion', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }],
  },
  {
    type: 'function', name: 'buildRegistrationCount', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    type: 'function', name: 'registerBuildHash', stateMutability: 'nonpayable',
    inputs: [
      { name: 'buildVersion', type: 'uint256' }, { name: 'hash', type: 'bytes32' }, { name: 'signer', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'event', name: 'BuildHashRegistered',
    inputs: [
      { name: 'buildVersion', type: 'uint256', indexed: true },
      { name: 'hash', type: 'bytes32', indexed: false },
      { name: 'signer', type: 'address', indexed: false },
      { name: 'isUpdate', type: 'bool', indexed: false },
      { name: 'updatedAt', type: 'uint256', indexed: false },
      { name: 'registrationCount', type: 'uint256', indexed: false },
    ],
  },
];

export const EVIDENCE_ABI = [
  { type: 'function', name: 'START_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'BLOCK_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'GAME_PERIOD', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'SUBMIT_PERIOD', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'INITIAL_GRACE', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'TOKEN_MINING', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  {
    type: 'function', name: 'currentGrace', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    type: 'function', name: 'chatWindow', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }],
    outputs: [{ name: 'chatOpenAt', type: 'uint256' }, { name: 'chatCloseAt', type: 'uint256' }],
  },
  {
    type: 'function', name: 'resultWindow', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }],
    outputs: [{ name: 'openAt', type: 'uint256' }, { name: 'closeAt', type: 'uint256' }],
  },
  {
    type: 'function', name: 'windowFinal', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }], outputs: [{ type: 'bool' }],
  },
  {
    type: 'function', name: 'resultCount', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    type: 'function', name: 'resultCountOf', stateMutability: 'view',
    inputs: [{ type: 'uint256' }, { type: 'address' }], outputs: [{ type: 'uint256' }],
  },
  { type: 'function', name: 'HASH_STORAGE', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'scheduledGameStart', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'currentGrace', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }] },
  {
    type: 'function', name: 'blockHashOf', stateMutability: 'view',
    inputs: [{ name: 'ethBlockNumber', type: 'uint256' }], outputs: [{ type: 'bytes32' }],
  },
  {
    type: 'function', name: 'submitResult', stateMutability: 'nonpayable',
    inputs: [{ name: 'blockNum', type: 'uint256' }, { name: 'data', type: 'bytes' },
      { name: 'manifestHash', type: 'bytes32' }, { name: 'proof', type: 'bytes32[]' }], outputs: [],
  },
  {
    type: 'event', name: 'ResultSubmitted',
    inputs: [
      { name: 'blockNum', type: 'uint256', indexed: true },
      { name: 'seq', type: 'uint256', indexed: true },
      { name: 'sender', type: 'address', indexed: true },
      { name: 'data', type: 'bytes', indexed: false },
      { name: 'timestamp', type: 'uint256', indexed: false },
    ],
  },
];

export const TOKEN_MINING_ABI = [
  { type: 'function', name: 'START_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'BLOCK_INTERVAL', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
];

// ---- ウォレット読取トランスポート（正典 rpcClient.js:27-36 と同一の gate） ----
export async function getWalletTransportIfMainnet(expectedChainId = 1, provider = null) {
  const eth = provider || (typeof window !== 'undefined' ? window.ethereum : null);
  if (!eth) return null;
  try {
    const chainIdHex = await eth.request({ method: 'eth_chainId' });
    if (parseInt(chainIdHex, 16) !== expectedChainId) return null;
    return custom(eth);
  } catch {
    return null;
  }
}

function chainFor(chainIdExpected, rpcUrls) {
  if (chainIdExpected === 1) return mainnet;
  return defineChain({
    id: chainIdExpected,
    name: `chain-${chainIdExpected}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: rpcUrls } },
  });
}

// ローダー用クライアント: 独立公開RPC（＋任意でウォレット）。運営RPCは含めない。
export function makeLoaderClient({ rpcUrls, chainIdExpected = 1, walletTransport = null }) {
  const transports = [
    ...(walletTransport ? [walletTransport] : []),
    ...rpcUrls.map((u) => http(u)),
  ];
  return createPublicClient({ chain: chainFor(chainIdExpected, rpcUrls), transport: fallback(transports) });
}

export function makeRecoveryAgreementState({ storage = null, storageKey = null, voterUrls = [],
  onPrompt = null, now = () => performance.now(), clientNowMs = () => Date.now() } = {}) {
  const urls = Object.freeze([...new Map(voterUrls.map((url) => [new URL(url).host, url])).values()]);
  const allowedHosts = new Set(urls.map((url) => new URL(url).host));
  let saved = null;
  if (storage && storageKey) {
    try {
      const raw = storage.getItem(storageKey);
      if (raw !== null) {
        saved = parseNodeTrust(raw, allowedHosts);
        if (!saved) storage.removeItem(storageKey);
      }
    } catch { /* 保存が使えなくてもメモリで続ける */ }
  }
  const persist = (agreement) => {
    if (!storage || !storageKey) return;
    try { storage.setItem(storageKey, serializeNodeTrust(agreement)); }
    catch { /* 保存が使えなくてもメモリで続ける */ }
  };
  const agreement = {
    voterUrls: urls, approved: saved?.approved || new Set(), chosen: saved?.chosen || null,
    tracker: createNoAgreementTracker(), chosenWait: createChosenWaitTracker(), stepBelow: null, lastHeads: new Map(),
    unagreed: 0, prompt: null,
    staleBlock: createStaleBlockNotice({ clientNowMs, monoNowMs: now }), // S3R4-U-RPC1-STALE2: 表示だけの帯
    approve(host) {
      if (!allowedHosts.has(host)) return;
      this.approved.add(host); this.tracker.approved(); this.prompt = null; persist(this);
    },
    choose(host) {
      if (!allowedHosts.has(host)) return;
      this.chosen = host; this.approved.add(host); this.tracker.clear(); this.chosenWait.reset(); this.prompt = null; persist(this);
    },
    dismiss() {
      if (this.prompt?.kind === 'chosen-wait' || this.prompt?.kind === 'pick') this.chosenWait.dismissed(now());
      this.prompt = null;
    },
    // S3R4-U-RPC1-CHOICE: 公式の recordChosenMiss・recordChosenAnswer・waitForChosen・pickAnotherNode と同じ。
    recordChosenMiss(key, event) {
      const warning = this.chosenWait.missed(key, event, now());
      if (!warning || this.prompt) return;
      this.prompt = { ...warning, host: this.chosen };
      onPrompt?.(this.prompt, this);
    },
    recordChosenAnswer(key) {
      const at = now();
      this.chosenWait.answered(key, at);
      if (!this.chosenWait.closableBy(this.prompt, key, at)) return;
      this.chosenWait.closedByAnswer(at); this.prompt = null;
      onPrompt?.(null, this);
    },
    recordOtherAnswer(host, value, key) { this.chosenWait.heard(host, value, now(), key); },
    waitChosen() {
      if (this.prompt?.kind !== 'chosen-wait') return;
      this.chosenWait.waited(now()); this.prompt = null;
    },
    pickAnother() {
      if (this.prompt?.kind !== 'chosen-wait') return null;
      this.prompt = this.chosenWait.pick(urls.map((url) => new URL(url).host), now())
        || { ...this.prompt, noCandidates: true };
      onPrompt?.(this.prompt, this);
      return this.prompt;
    },
    recordNoAgreement(key, event) {
      const warning = this.tracker.record(key, event, now());
      if (warning && !this.prompt && (warning.kind !== 'single' || !this.approved.has(warning.host))) {
        this.prompt = warning;
        onPrompt?.(warning, this);
      }
    },
  };
  return agreement;
}

// S3R4-U-RPC1: 復元も公式と同じ純粋な判定を使う。S は呼び手が固定プリセットだけを渡す。
export function makeR4Client({ rpcUrls, operatorRpc = null, chainIdExpected = 1,
  walletTransport = null, agreementState = null }) {
  const agreement = agreementState || makeRecoveryAgreementState({ voterUrls: rpcUrls });
  const voters = agreement.voterUrls.map((url) => ({ sourceId: new URL(url).host,
    transport: http(url, { timeout: 3000, retryCount: 0 }) }));
  const operator = operatorRpc ? { sourceId: 'operator', transport: http(operatorRpc, { timeout: 3000, retryCount: 0 }) } : null;
  const chain = chainFor(chainIdExpected, rpcUrls);
  const bounded = (operation) => {
    let timer;
    return Promise.race([operation(), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('game RPC read timed out')), 3000);
    })]).finally(() => clearTimeout(timer));
  };
  const askOne = async ({ sourceId, transport }, args) => {
    try {
      const value = await bounded(() => transport({ chain, retryCount: 0, timeout: 3000 }).request(args));
      const shape = classifyRpcAnswer(args.method, value);
      if (shape.kind === 'value') return { sourceId, kind: 'value', key: shape.key, value };
      if (shape.kind === 'missing') return { sourceId, kind: 'missing' };
      return { sourceId, kind: 'malformed', error: new Error('RPC returned a malformed answer') };
    } catch (error) {
      const kind = classifyRpcError(error);
      return kind === 'revert' ? { sourceId, kind, key: REVERT_ANSWER_KEY, error } : { sourceId, kind, error };
    }
  };
  const askAll = (args, key) => new Promise((resolve) => {
    const answers = []; let pending = voters.length;
    if (!pending) { resolve(answers); return; }
    const chosen = agreement.chosen;
    for (const voter of voters) askOne(voter, args)
      .catch((error) => ({ sourceId: voter.sourceId, kind: 'malformed', error })).then((answer) => {
      answers.push(answer); pending--;
      if (pending === 0 || (args.method !== 'eth_blockNumber' && settledEarly(answers))) resolve(answers.slice());
      // 早い打ち切りの後に届いた答えも数える。chosen の答えはその鍵の待ちを終え、ほかの答えは選ぶ画面の候補になる。
      if (chosen && (answer.kind === 'value' || answer.kind === 'revert') && agreement.chosen === chosen) {
        try {
          if (answer.sourceId === chosen) agreement.recordChosenAnswer?.(key);
          else agreement.recordOtherAnswer?.(answer.sourceId, answer.kind === 'revert' ? 'revert' : describeRpcAnswer(args.method, answer.value), key);
        } catch { /* 画面の失敗で読みを止めない */ }
      }
    });
  });
  const yieldAnswer = (answer) => { if (answer.kind === 'revert') throw answer.error; return answer.value; };
  const provider = { async request(args) {
    const key = readKeyOf(args);
    const errors = [];
    if (walletTransport) {
      const wallet = await askOne({ sourceId: 'wallet', transport: walletTransport }, args);
      // S3R4-U-RPC1-STALE2: 採った答えを表示だけの帯へ見せる（値・流れは変えない・運営の答えは見せない）。
      if (wallet.kind === 'value') agreement.staleBlock?.noteRead(args, wallet.value, 'wallet');
      if (wallet.kind === 'value') return wallet.value;
      if (wallet.kind === 'revert') throw wallet.error;
      if (wallet.kind !== 'missing') errors.push(wallet.error);
    }
    let answers = await askAll(args, key);
    for (const answer of answers) if (['transport', 'malformed', 'rejected'].includes(answer.kind)) errors.push(answer.error);
    // S3R4-U-RPC1-CHOICE: chosen の欠けの読みは chosen に1回だけ聞き直し、答えればその答えを足して同じ規則で選び直す。
    for (let retried = false; ; retried = true) {
    let result;
    if (args.method === 'eth_blockNumber') {
      const values = answers.filter((answer) => answer.kind === 'value')
        .map((answer) => ({ sourceId: answer.sourceId, value: BigInt(answer.value) }));
      agreement.lastHeads = new Map(values.map(({ sourceId, value }) => [sourceId, value]));
      if (agreement.stepBelow) agreement.stepBelow = refreshStepBelow(agreement.stepBelow, values);
      const below = agreement.stepBelow && performance.now() - agreement.stepBelow.at <= STEP_BELOW_TTL_MS
        ? agreement.stepBelow.n : null;
      result = selectPublicBlockNumber(values, { stepBelow: below });
      if (result.kind === 'agreed') agreement.staleBlock?.noteRead(args, `0x${result.value.toString(16)}`, 'public');
      if (result.kind === 'agreed') {
        return `0x${result.value.toString(16)}`; }
      const publicAnswers = selectAgreedPublic(answers);
      if (publicAnswers.kind === 'agreed' && publicAnswers.first.kind === 'revert') return yieldAnswer(publicAnswers.first);
      result = { ...result, valueHosts: publicAnswers.valueHosts };
    } else {
      result = selectAgreedPublic(answers);
      if (result.kind === 'agreed') agreement.staleBlock?.noteRead(args, result.first.value, 'public');
      if (result.kind === 'agreed') {
        return yieldAnswer(result.first);
      }
    }
    const hosts = result.valueHosts || [];
    const answerOf = (host) => answers.find((answer) => answer.sourceId === host);
    if (hosts.length === 1 && agreement.approved.has(hosts[0])) {
      agreement.staleBlock?.noteRead(args, answerOf(hosts[0])?.value, 'public');
      agreement.unagreed++; return yieldAnswer(answerOf(hosts[0]));
    }
    if (hosts.length >= 2 && agreement.chosen && hosts.includes(agreement.chosen)) {
      agreement.staleBlock?.noteRead(args, answerOf(agreement.chosen)?.value, 'public');
      agreement.unagreed++; return yieldAnswer(answerOf(agreement.chosen));
    }
    const number = numberedBlockOf(args);
    if (number !== null && shouldStepBelow(answers)) {
      const head = missingHeadBelow(answers, agreement.lastHeads, number);
      if (head !== null && number - head <= SHALLOW_STEP_BLOCKS) {
        agreement.stepBelow = { n: head, at: performance.now(), sources: answers.filter((answer) =>
          answer.kind === 'missing' && agreement.lastHeads.get(answer.sourceId) < number).map((answer) => answer.sourceId) };
      } else {
        agreement.stepBelow = null;
      }
    }
    if (hosts.length) {
      const event = { shape: hosts.length === 1 ? 'single' : 'split', hosts,
        candidates: hosts.map((host) => ({ host, value: answerOf(host)?.kind === 'revert'
          ? 'revert' : describeRpcAnswer(args.method, answerOf(host)?.value) })) };
      const chosen = agreement.chosen;
      const waitChosen = chosenWaitApplies(chosen, hosts) && typeof agreement.recordChosenMiss === 'function';
      const chosenVoter = waitChosen && !retried ? voters.find((voter) => voter.sourceId === chosen) : null;
      if (chosenVoter) {
        const again = await askOne(chosenVoter, args)
          .catch((error) => ({ sourceId: chosenVoter.sourceId, kind: 'malformed', error }));
        // 聞き直し中に選び直したら旧 chosen の結果を捨て、新しい chosen で同じ規則を通す。
        // この読みの聞き直しは合計1回のまま。
        if (agreement.chosen !== chosen) continue;
        if ((again.kind === 'value' || again.kind === 'revert') && agreement.chosen === chosen) {
          try { agreement.recordChosenAnswer?.(key); } catch { /* 画面の失敗で読みを止めない */ }
          answers = [...answers.filter((answer) => answer.sourceId !== chosen), again];
          continue;
        }
      }
      if (waitChosen) agreement.recordChosenMiss(key, event); else agreement.recordNoAgreement(key, event);
      const error = new Error(waitChosen ? 'the chosen public RPC has not answered'
        : hosts.length === 1 ? 'only one public RPC answered' : 'chain read sources disagree');
      error.agreement = { kind: waitChosen ? 'chosen-wait' : hosts.length === 1 ? 'single' : 'split', hosts };
      throw error;
    }
    break;
    }
    if (operator) {
      const answer = await askOne(operator, args);
      if (answer.kind === 'value' || answer.kind === 'revert') {
        agreement.unagreed++; return yieldAnswer(answer);
      }
      if (answer.error) errors.push(answer.error);
    }
    throw errors[errors.length - 1] || new Error('game RPC unavailable');
  } };
  const client = createPublicClient({ chain, transport: custom(provider, { retryCount: 0 }) });
  return Object.assign(client, { unagreedCount: () => agreement.unagreed });
}

// Clock observations and chain-tip deadline gates use the fixed public presets.
// The caller supplies that list independently of saved R4 settings.
export function makeTimeReadClient({ rpcUrls, walletTransport = null, agreementState = null,
  clientNowMs = () => Date.now() }) {
  const uniqueUrls = [...new Map(rpcUrls.map((url) => [new URL(url).host, url])).values()];
  const sources = [
    ...(walletTransport ? [{ sourceId: 'wallet', client: createPublicClient({ chain: mainnet, transport: walletTransport }) }] : []),
    ...uniqueUrls.map((url) => ({ sourceId: new URL(url).host,
      client: createPublicClient({ chain: mainnet, transport: http(url, { timeout: 3000, retryCount: 0 }) }) })),
  ];
  const bounded = (operation) => {
    let timer;
    return Promise.race([operation(), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('time read timed out')), 3000);
    })]).finally(() => clearTimeout(timer));
  };
  const validBlock = async (client) => {
    const block = await bounded(() => client.getBlock());
    if (!Number.isSafeInteger(Number(block.timestamp) * 1000)) throw new TypeError('invalid chain timestamp');
    return block;
  };
  return {
    sources: sources.map(({ sourceId }) => sourceId),
    async getBlock() {
      const readTip = async ({ sourceId, client }) => {
        let timer;
        try {
          const block = await Promise.race([client.getBlock(), new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('chain tip timed out')), TIP_READ_TIMEOUT_MS);
          })]);
          const timeMs = Number(block.timestamp) * 1000;
          if (!Number.isSafeInteger(timeMs)) throw new TypeError('invalid chain timestamp');
          return { sourceId, block, timeMs, observedMonoMs: performance.now() };
        } catch { return null; }
        finally { clearTimeout(timer); }
      };
      const reads = sources.map((source) => readTip(source));
      const walletRead = walletTransport ? reads[0] : Promise.resolve(null);
      const publicReads = walletTransport ? reads.slice(1) : reads;
      const wallet = await walletRead;
      if (wallet) agreementState?.staleBlock?.noteTip(wallet.timeMs, 'wallet'); // STALE2: 表示だけ
      if (wallet) return wallet.block;
      const publicResults = (await Promise.all(publicReads)).filter(Boolean);
      const selected = selectPublicChainTip({ samples: publicResults.map((item) => ({
        sourceId: item.sourceId, blockTimestampMs: item.timeMs, observedMonoMs: item.observedMonoMs,
      })), nowMonoMs: performance.now() });
      if (selected.kind === 'agreed') {
        const chosen = publicResults.find((item) => selected.sources.includes(item.sourceId) && item.timeMs === selected.timeMs);
        if (chosen) agreementState?.staleBlock?.noteTip(chosen.timeMs, 'public');
        if (chosen) return chosen.block;
      }
      if (selected.kind === 'single' && agreementState?.approved.has(selected.valueHosts[0])) {
        const accepted = acceptApprovedTip(selected.timeMs, clientNowMs());
        if (accepted !== null) agreementState?.staleBlock?.noteTip(accepted, 'public');
        if (accepted !== null) return publicResults.find((item) => item.sourceId === selected.valueHosts[0]).block;
      }
      throw new Error('time read sources do not agree');
    },
    async readSamples() {
      const samples = await Promise.all(sources.map(async ({ sourceId, client }) => {
        try {
          const block = await validBlock(client);
          return { sourceId, chainId: 1, blockTimestampMs: Number(block.timestamp) * 1000,
            observedMonoMs: performance.now() };
        } catch { return null; }
      }));
      return { walletSample: samples.find((sample) => sample?.sourceId === 'wallet') || null,
        publicSamples: samples.filter((sample) => sample && sample.sourceId !== 'wallet') };
    },
  };
}

// S3R4-U-RPCWIN: 固定の公開プリセットと mainnet ウォレットから、各1回・3秒で並列に読む。
// 運営 RPC は参考表示だけに返す。
export async function readPressChatWindowsMs({ rpcUrls, walletTransport = null, operatorRpc = null,
  evidenceAddress, blockNum }) {
  const uniqueUrls = [...new Map((rpcUrls || []).map((url) => [new URL(url).host, url])).values()];
  const bounded = (operation) => {
    let timer;
    return Promise.race([operation(), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('press window read timed out')), 3000);
    })]).finally(() => clearTimeout(timer));
  };
  const readOne = async (sourceId, transport) => {
    try {
      const client = createPublicClient({ chain: mainnet, transport });
      const win = await bounded(() => client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI,
        functionName: 'chatWindow', args: [BigInt(blockNum)] }));
      return { sourceId, chatOpenAt: Number(win[0]) * 1000, chatCloseAt: Number(win[1]) * 1000 };
    } catch { return { sourceId, error: true }; }
  };
  const [operator, ...answers] = await Promise.all([
    operatorRpc ? readOne('operator', http(operatorRpc, { timeout: 3000, retryCount: 0 })) : Promise.resolve(null),
    ...(walletTransport ? [readOne('wallet', (params) => walletTransport({ ...params, retryCount: 0 }))] : []),
    ...uniqueUrls.map((url) => readOne(new URL(url).host, http(url, { timeout: 3000, retryCount: 0 }))),
  ]);
  return { answers, operator };
}

// ---- HashStorage 読取（ローダー） ----

// latestBuildVersion と getBuildHash は【必ず一緒に】読む（旧版hash差し替えトラップ回避・DESIGN §3.2）
export async function readLatestBuildHash(client, hashStorageAddress) {
  const latest = await client.readContract({
    address: hashStorageAddress, abi: HASH_STORAGE_ABI, functionName: 'latestBuildVersion',
  });
  if (latest === 0n) {
    // buildVersion 0 が登録済みかは getBuildHash(0) の revert 有無でしか区別できない
    try {
      const r = await readBuildHash(client, hashStorageAddress, 0n);
      return r;
    } catch {
      return null; // 未登録（1件も無い）
    }
  }
  return readBuildHash(client, hashStorageAddress, latest);
}

export async function readBuildHash(client, hashStorageAddress, buildVersion) {
  const [hash, updated, signer] = await client.readContract({
    address: hashStorageAddress, abi: HASH_STORAGE_ABI, functionName: 'getBuildHash', args: [BigInt(buildVersion)],
  });
  const registrationCount = await client.readContract({
    address: hashStorageAddress, abi: HASH_STORAGE_ABI, functionName: 'buildRegistrationCount', args: [BigInt(buildVersion)],
  });
  return {
    buildVersion: BigInt(buildVersion),
    hash: String(hash).toLowerCase(),
    updatedBlock: updated,
    signer,
    registrationCount,
  };
}

// V25-03/T8: recovery roster を公開キャッシュではなくオンチェーンcommitへ束縛する読取。
// 現行 HashStorage は selection が使った (registeredBlock,hash) の membership を読む。
// 許可リストの旧契約だけは履歴 getter が無いため、従来どおり最新値との一致を使う。
export async function readSelectionAnchors(
  client,
  { hashStorage, evidence },
  blockNum,
  confirmationBlocks = 64,
  selection = null,
  { legacyHashStorage = false } = {},
) {
  const n = BigInt(blockNum);
  if (!selection || typeof selection !== 'object') {
    throw new Error('game_selection.json is required for applicant registration verification');
  }
  const selectedBlock = Number(selection.hashRegisteredBlock);
  const selectedHash = String(selection.applicantHash || '').toLowerCase();
  if (!Number.isSafeInteger(selectedBlock) || selectedBlock < 0
      || !/^0x[0-9a-f]{64}$/.test(selectedHash)) {
    throw new Error('game_selection.json applicantHash/hashRegisteredBlock is invalid');
  }
  const [applicant, registrationCount] = await Promise.all([
    client.readContract({ address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'getApplicantHash', args: [n] }),
    client.readContract({ address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'registrationCount', args: [n] }),
  ]);
  const applicantHash = String(applicant[0]).toLowerCase();
  const applicantUpdatedBlock = Number(applicant[1]);
  const legacyFallback = legacyHashStorage === true;
  let selectionRegistered;
  if (legacyFallback) {
    selectionRegistered = selectedHash === applicantHash && selectedBlock === applicantUpdatedBlock;
  } else {
    try {
      selectionRegistered = await client.readContract({
        address: hashStorage,
        abi: HASH_STORAGE_ABI,
        functionName: 'isApplicantRegistered',
        args: [n, BigInt(selectedBlock), selectedHash],
      });
    } catch (error) {
      throw new Error(`HashStorage ${hashStorage} applicant registration getter is unavailable`, { cause: error });
    }
    selectionRegistered = selectionRegistered === true;
  }
  const randaoEthBlockNumber = selectedBlock + Number(confirmationBlocks);
  const randaoBlockHash = await client.readContract({
    address: evidence, abi: EVIDENCE_ABI, functionName: 'blockHashOf', args: [BigInt(randaoEthBlockNumber)],
  });
  return {
    applicantHash,
    applicantUpdatedBlock,
    applicantSigner: applicant[2],
    registrationCount: Number(registrationCount),
    selectionApplicantHash: selectedHash,
    selectionRegisteredBlock: selectedBlock,
    selectionRegistered,
    legacyFallback,
    randaoEthBlockNumber,
    randaoBlockHash: String(randaoBlockHash).toLowerCase(),
  };
}

export async function readResultHash(client, hashStorageAddress, blockNum) {
  const r = await client.readContract({
    address: hashStorageAddress, abi: HASH_STORAGE_ABI,
    functionName: 'getResultHash', args: [BigInt(blockNum)],
  });
  return { hash: String(r[0]).toLowerCase(), updated: Number(r[1]), signer: r[2] };
}

// N+1 の組分け後に N の結果が変わっていないことを、結果登録履歴から保守的に判定する材料。
// 最終履歴行と現在の目印を共に返す。未変更の証明では双方の一致も検査する。
export async function readResultRegistrationHistoryHead(client, hashStorageAddress, blockNum) {
  const countRaw = await client.readContract({
    address: hashStorageAddress, abi: HASH_STORAGE_ABI,
    functionName: 'resultRegistrationCount', args: [BigInt(blockNum)],
  });
  const count = BigInt(countRaw);
  if (count < 0n || count > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`invalid result registration count for block ${blockNum}: ${count}`);
  }
  if (count === 0n) return { count: 0, latest: null };
  const [row, current] = await Promise.all([
    client.readContract({
      address: hashStorageAddress, abi: HASH_STORAGE_ABI,
      functionName: 'resultRegistrationAt', args: [BigInt(blockNum), count - 1n],
    }),
    client.readContract({
      address: hashStorageAddress, abi: HASH_STORAGE_ABI,
      functionName: 'getResultHash', args: [BigInt(blockNum)],
    }),
  ]);
  return {
    count: Number(count),
    current: { hash: String(current[0]).toLowerCase(), updated: Number(current[1]) },
    latest: {
      index: Number(count - 1n),
      hash: String(row[0]).toLowerCase(),
      registeredBlock: Number(row[1]),
      registeredAt: Number(row[2]),
      signer: row[3],
    },
  };
}

// When the preferred time window has no usable result, the recovery client can
// still prove stability if every registered core equals the currently anchored
// summary core. Distinct older cores have no readable body in this client.
export async function readResultRegistrationHashesMatch(client, hashStorageAddress,
  blockNum, count, expectedHash) {
  if (!Number.isSafeInteger(count) || count < 1) throw new Error('invalid result registration count');
  for (let index = 0; index < count; index++) {
    const row = await client.readContract({ address: hashStorageAddress, abi: HASH_STORAGE_ABI,
      functionName: 'resultRegistrationAt', args: [BigInt(blockNum), BigInt(index)] });
    if (String(row[0]).toLowerCase() !== String(expectedHash).toLowerCase()) {
      return { matches: false, firstDifferentIndex: index };
    }
  }
  return { matches: true, firstDifferentIndex: null };
}

const isHistoryGetterRevert = (error) => typeof error?.walk === 'function'
  && !!error.walk((cause) => cause?.name === 'ContractFunctionRevertedError'
    || cause?.name === 'ContractFunctionZeroDataError'
    || cause?.name === 'ExecutionRevertedError');

// M9b: 書き手と公式クライアントが使う共有 selector で、開始前の最後の行を選ぶ。
// 旧 HashStorage の履歴 getter だけは従来の現在値へ戻し、legacy を明示する。
export async function readCanonicalRosterRegistration(client, hashStorageAddress, evidenceAddress,
  blockNum, { chatWindowReader = readChatWindow, legacyHashStorage = false } = {}) {
  const key = rosterAnchorKey(blockNum);
  const blockNumber = await client.getBlockNumber();
  const snapshot = await client.getBlock({ blockNumber });
  const observedAtMs = Number(snapshot.timestamp) * 1000;
  if (!Number.isSafeInteger(observedAtMs) || observedAtMs < 0) {
    throw new Error('invalid roster snapshot timestamp');
  }
  let count;
  try {
    count = BigInt(await client.readContract({ address: hashStorageAddress, abi: HASH_STORAGE_ABI,
      functionName: 'otherRegistrationCount', args: [key], blockNumber }));
  } catch (error) {
    if (legacyHashStorage === true && isHistoryGetterRevert(error)) {
      const current = await readOtherHash(client, hashStorageAddress, key, blockNumber);
      return { status: 'legacy', legacy: true, row: current.updated && !/^0x0{64}$/i.test(current.hash)
        ? { hash: current.hash, registeredBlock: current.updated, registeredAt: null } : null,
      observedAtMs };
    }
    throw error;
  }
  if (count < 0n || count > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('invalid roster registration count');
  }
  if (!evidenceAddress) throw new Error('Evidence address is required for roster timeline');
  const window = await chatWindowReader(client, evidenceAddress, blockNum, blockNumber);
  const selected = await selectCanonicalRosterRegistration({
    count: Number(count),
    at: async (index) => {
      const row = await client.readContract({ address: hashStorageAddress, abi: HASH_STORAGE_ABI,
        functionName: 'otherRegistrationAt', args: [key, BigInt(index)], blockNumber });
      return { hash: row[0], registeredBlock: row[1], registeredAt: row[2] };
    },
    entryEndSec: window.chatOpenAt,
    chattingStartSec: window.chattingStart,
    nowSec: Number(snapshot.timestamp),
  });
  return { ...selected, legacy: false, key, observedAtMs,
    chattingStartMs: window.chattingStart * 1000,
    chatCloseAtMs: window.chatCloseAt * 1000 };
}

export async function readChatWindow(client, evidenceAddress, blockNum, blockNumber = undefined) {
  const [row, gamePeriodRaw] = await Promise.all([
    client.readContract({
      address: evidenceAddress, abi: EVIDENCE_ABI,
      functionName: 'chatWindow', args: [BigInt(blockNum)],
      ...(blockNumber === undefined ? {} : { blockNumber }),
    }),
    client.readContract({
      address: evidenceAddress, abi: EVIDENCE_ABI, functionName: 'GAME_PERIOD',
      ...(blockNumber === undefined ? {} : { blockNumber }),
    }),
  ]);
  const chatOpenAt = Number(row[0]);
  const chatCloseAt = Number(row[1]);
  const gamePeriod = Number(gamePeriodRaw);
  const chattingStart = chatCloseAt - gamePeriod;
  if (!Number.isSafeInteger(chatOpenAt) || chatOpenAt < 0
      || !Number.isSafeInteger(chatCloseAt) || chatCloseAt < chatOpenAt
      || !Number.isSafeInteger(gamePeriod) || gamePeriod < 0
      || !Number.isSafeInteger(chattingStart) || chattingStart < chatOpenAt) {
    throw new Error(`invalid chat window for block ${blockNum}`);
  }
  return { chatOpenAt, chatCloseAt, chattingStart };
}

export async function readOtherHash(client, hashStorageAddress, key, blockNumber = undefined) {
  const result = await client.readContract({
    address: hashStorageAddress, abi: HASH_STORAGE_ABI, functionName: 'getOtherHash', args: [key],
    ...(blockNumber === undefined ? {} : { blockNumber }),
  });
  return {
    hash: String(result[0]).toLowerCase(), updated: Number(result[1]),
  };
}

// ---- Evidence タイムライン読取（復元クライアント） ----

// タイミング定数＋不変量検査（block-verifier getTimingConstants と同じ検査）
// v3.2: TERM1撤廃・GAME_PERIOD/SUBMIT_PERIOD改名
export async function readTimingConstants(client, { evidence, tokenMining }) {
  const [evStart, evBlockTime, gamePeriod, submitPeriod, initialGrace] = await Promise.all([
    client.readContract({ address: evidence, abi: EVIDENCE_ABI, functionName: 'START_TIME' }),
    client.readContract({ address: evidence, abi: EVIDENCE_ABI, functionName: 'BLOCK_TIME' }),
    client.readContract({ address: evidence, abi: EVIDENCE_ABI, functionName: 'GAME_PERIOD' }),
    client.readContract({ address: evidence, abi: EVIDENCE_ABI, functionName: 'SUBMIT_PERIOD' }),
    client.readContract({ address: evidence, abi: EVIDENCE_ABI, functionName: 'INITIAL_GRACE' }),
  ]);
  let invariantOk = null;
  let tokenMiningLinkOk = null;
  try {
    const [tmStart, tmInterval, linkedTokenMining] = await Promise.all([
      client.readContract({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'START_TIME' }),
      client.readContract({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'BLOCK_INTERVAL' }),
      client.readContract({ address: evidence, abi: EVIDENCE_ABI, functionName: 'TOKEN_MINING' }),
    ]);
    // 2026-07-27: START_TIME は全契約で「ブロック0の応募開始」に統一（Evidence constructor が強制）
    tokenMiningLinkOk = String(linkedTokenMining).toLowerCase() === String(tokenMining).toLowerCase();
    invariantOk = (evStart === tmStart) && (evBlockTime === tmInterval) && tokenMiningLinkOk;
  } catch { /* TokenMining または Evidence 逆参照の読取失敗時は不変量は検査不能（null） */ }
  return {
    evidenceStartTimeSec: evStart, blockTimeSec: evBlockTime,
    gamePeriodSec: gamePeriod, submitPeriodSec: submitPeriod, initialGraceSec: initialGrace,
    invariantOk, tokenMiningLinkOk,
  };
}

// ゲームタイムライン（ms）。正典 src/utils/evidence.js readGameTimeline と同一の値を返し、
// さらに resultWindow / grace を加える（フェーズ判定・提出窓の全てをチェーンから）。
export async function readGameTimelineMs(client, evidenceAddress, blockNum) {
  const [win, resWin, gamePeriod, grace] = await Promise.all([
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI, functionName: 'chatWindow', args: [BigInt(blockNum)] }),
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI, functionName: 'resultWindow', args: [BigInt(blockNum)] }),
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI, functionName: 'GAME_PERIOD' }),
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI, functionName: 'currentGrace', args: [BigInt(blockNum)] }),
  ]);
  const chatOpenAt = Number(win[0]) * 1000;
  const chatCloseAt = Number(win[1]) * 1000;
  const gamePeriodMs = Number(gamePeriod) * 1000;
  return {
    chatOpenAt,                                 // 応募終了（許容包絡の始点・grace非依存）
    chatCloseAt,
    chattingStart: chatCloseAt - gamePeriodMs,  // grace追従の実チャット開始（開始待機の終端）
    resultOpenAt: Number(resWin[0]) * 1000,
    resultCloseAt: Number(resWin[1]) * 1000,
    graceSec: Number(grace),
  };
}

// フェーズ判定（チェーンのみ・運営サーバー非依存）
//   entry: now < 応募終了(chatOpenAt) / waiting: [応募終了, 実チャット開始) /
//   chatting: [chattingStart(=chatCloseAt-GAME_PERIOD), chatCloseAt) /
//   submitting: [resultOpenAt, resultCloseAt) / completed
// 注意: チェーンの chatOpenAt は grace 非依存の下限（採点窓）・実フェーズは grace 追従。
// K-S6-006（2026-07-29）: 実装は正典（vendor の timeline-check.js）へ移した。
// 本体アプリと復元クライアントで判定が分かれないよう、両者とも同じ関数を使う。
export function derivePhase(nowMs, t) {
  return derivePhaseFromWindows(nowMs, t);
}
