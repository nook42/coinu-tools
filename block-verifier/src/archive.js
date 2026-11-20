// RPCの履歴state/ヘッダの型付き取得不能。応答から分類し、必要な検査だけへ伝える。
export const ARCHIVE_UNAVAILABLE = 'archive_unavailable';

// viem の表示用 message / URL / body（要求）を判定材料にしない。
// JSON-RPC の生 error、または HttpRequestError.details に保存された応答だけを見る。
export function historicalStateFailure(error) {
  const seen = new Set();
  const errors = [];
  for (let e = error; e && !seen.has(e); e = e.cause) {
    seen.add(e);
    errors.push(e);
  }
  if (errors.some((e) => [429, 500, 502, 503, 504].includes(e.status ?? e.statusCode))) return 'rpc_unavailable';
  for (const e of errors) {
    if (e instanceof ArchiveUnavailableError) return ARCHIVE_UNAVAILABLE;
    let response = e;
    if (e.name === 'HttpRequestError') {
      // details は viem が応答 data.error から作る欄。body は要求なので読まない。
      if (![200, 403].includes(e.status) || typeof e.details !== 'string') continue;
      try { response = JSON.parse(e.details); } catch { response = e.details; }
      if (typeof response === 'string') {
        if (e.status === 403 && /^Archive requests require a personal token(?:\.|!|$)/i.test(response.trim())) return ARCHIVE_UNAVAILABLE;
        continue;
      }
    } else if (e.shortMessage != null || (e.name && e.name !== 'Error')) continue;
    if (response?.jsonrpc === '2.0' && response.error) response = response.error;
    // EIP-4444: stateだけでなく古いヘッダも保持されない。RPCのcodeだけで分類する。
    if (response?.code === 4444) return ARCHIVE_UNAVAILABLE;
    // Flashbotsの履歴ログ拒否。表示文ではなく、RPC応答の本文の先頭だけを見る。
    if (Number.isInteger(response?.code) && typeof response.message === 'string'
        && /^pruned history unavailable\b/i.test(response.message.trim())) return ARCHIVE_UNAVAILABLE;
    if (!response || ![-32000, -32001, -32002, -32602].includes(response.code)
        || typeof response.message !== 'string') continue;
    const message = response.message.trim();
    // header not found は正典同様、追随遅延等と区別できないので含めない。
    if (/header not found/i.test(message)) continue;
    if (/^(?:missing trie node\b|state not available\b|no state available for block\b|world state unavailable\b|state at block .* pruned\b|history has been pruned\b|historical state\b|pruned state\b|archive (?:node|state)\b|Archive requests require a personal token(?:\.|!|$))/i.test(message)) {
      return ARCHIVE_UNAVAILABLE;
    }
  }
  return 'rpc_unavailable';
}

// 予算つきログ探索だけで使う範囲拒否の分類。code単独・要求・表示文では縮小しない。
export function isLogRangeFailure(error) {
  const seen = new Set();
  for (let e = error; e && !seen.has(e); e = e.cause) {
    seen.add(e);
    let response = e;
    if (e.name === 'HttpRequestError') {
      if (e.status !== 200 || typeof e.details !== 'string') continue;
      try { response = JSON.parse(e.details); } catch { continue; }
    } else if (e.shortMessage != null || (e.name && e.name !== 'Error')) continue;
    if (response?.jsonrpc === '2.0' && response.error) response = response.error;
    if (typeof response?.message !== 'string') continue;
    const message = response.message.trim();
    if (response.code === 35 && /^ranges over \d+ blocks are not supported\b/i.test(message)) return true;
    if ([-32000, -32005, -32602].includes(response.code)
        && /^(?:block range (?:is too (?:wide|large)|exceeds\b)|query returned more than \d+ (?:results|logs)\b)/i.test(message)) return true;
  }
  return false;
}

export class ArchiveUnavailableError extends Error {
  constructor(cause) {
    super(ARCHIVE_UNAVAILABLE, cause ? { cause } : undefined);
    this.name = 'ArchiveUnavailableError';
    this.code = ARCHIVE_UNAVAILABLE;
  }
}

// これらの計算/比較は実行するが、K11のロック適格性を確かめない限り合格とは呼ばない。
export const LOCK_DEPENDENT_CHECKS = new Set([
  'check.stageC.depositTableShape', 'check.stageC.scoring', 'check.stageC.autoDistribute',
  'check.stageC.autoResultPage', 'check.stageC.groupGameResultsMatch',
  'check.stageC.summaryByteExact', 'check.stageC.summaryMatch', 'check.stageC.merkleRebuild',
]);
// 1接続につき1回だけ。失敗を記憶し、ブロックを選び直しても繰り返さない。
export function archiveProbe(client, cfg) {
  let promise;
  return () => promise ||= (async () => {
    let head;
    try {
      head = await client.getBlockNumber({ cacheTime: 0 });
      const block = head >= 10000n ? head - 10000n : 0n;
      // K11のgetLockと同じeth_callの履歴state経路を試す。getCodeの成功では代用しない。
      // 選択前なのでK11自体は未確定。mainnetでは十分古いWETH.totalSupply()を使い、
      // 実際のK11は後で必ず読む。若いローカルchainでは空の戻り値を成功と断定しない。
      const address = cfg.chainIdExpected === 1
        ? '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2' : cfg.contracts.tokenMining;
      const data = cfg.chainIdExpected === 1 ? '0x18160ddd' : '0xddaa26ad'; // totalSupply() / START_TIME()
      const code = await client.request({ method: 'eth_call', params: [{ to: address, data }, `0x${block.toString(16)}`] }, { retryCount: 0 });
      return { status: /^0x[0-9a-f]+$/i.test(code ?? '') ? 'available' : 'unknown',
        reason: code && code !== '0x' ? 'probe_succeeded' : 'probe_empty', head, block };
    } catch (error) {
      const reason = historicalStateFailure(error);
      return { status: reason === ARCHIVE_UNAVAILABLE ? 'unavailable' : 'unknown', reason, head };
    }
  })();
}

// 通常表示にHTTP要求/応答本文を流さない。DEBUGでのstack出力は呼出側に残す。
export function conciseRpcText(value, translate = (key) => key) {
  if (value instanceof ArchiveUnavailableError) return translate('reason.archiveUnavailable');
  const text = String(value ?? '');
  const fallback = text.split('\n--- original error ---\n');
  if (fallback.length === 2) {
    const shown = conciseRpcText(fallback[1], translate);
    if (shown !== fallback[1]) return `${fallback[0]}\n${shown}`;
  }
  // systemAuditが契約名を添えて結合したerror欄。検証行全体や比較材料には適用しない。
  const labelled = /^(?:TokenMining|Evidence|HashStorage|head): (.*)$/s.exec(text);
  if (labelled) {
    const shown = conciseRpcText(labelled[1], translate);
    if (shown !== labelled[1]) return shown;
  }
  if (/^(?:ArchiveUnavailableError: )?archive_unavailable(?:;|$)/.test(text)) return translate('reason.archiveUnavailable');
  if (/^(?:(?:HttpRequestError|RpcRequestError|ContractFunctionExecutionError|CallExecutionError): )?(?:HTTP request failed\.|RPC Request failed\.)|^\[B1\] on-chain deposit reads unavailable for unit \d+: HTTP request failed\./i.test(text)) {
    return translate('reason.rpcRequestFailed');
  }
  return text;
}
