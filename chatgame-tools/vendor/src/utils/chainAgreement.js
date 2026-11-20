// S3R4-U-RPC1: 公式と復元で共有する、チェーンの答えを選ぶ純粋な規則。
import { formatBlock } from 'viem';
import { CHAT_WINDOW_CLOCK_SKEW_MS } from '../../workers/game_workers/lib/protocol-v2.js';

export const AGREEMENT_MIN_VOTES = 2;
export const BLOCK_AGREEMENT_SPREAD = 3n;
export const STEP_BELOW_TTL_MS = 60_000;
export const STEP_BELOW_MAX_BLOCKS = 64n;
export const STEP_BELOW_MIN_MISSING = 2;
export const SHALLOW_STEP_BLOCKS = 5n;
export const TIP_GROUP_SPREAD_MS = 24_000;
export const TIP_READ_TIMEOUT_MS = 2_500;
export const NO_AGREEMENT_WINDOW_MS = 60_000;
export const NO_AGREEMENT_SPACING_MS = 5_000;
export const NO_AGREEMENT_NEEDED = 3;
export const NO_AGREEMENT_PROMPT_GAP_MS = 120_000;
export const CHOSEN_WAIT_MS = 20_000;
export const CHOSEN_WAIT_MAX_KEYS = 64;
export const CHOSEN_MISS_SHARE_DEN = 4;
export const CHOSEN_RATE_MAX_EVENTS = 1_024;
export const DESCRIBE_MAX_CHARS = 64;
export const REVERT_ANSWER_KEY = '"__revert__"';
export const NODE_TRUST_VERSION = 1;

const quantityPattern = /^0x[0-9a-fA-F]{1,16}$/;
const hashPattern = /^0x[0-9a-fA-F]{64}$/;
const bytesPattern = /^0x([0-9a-fA-F]{2})*$/;
const quantity = (value, positive = false) => {
  if (typeof value !== 'string' || !quantityPattern.test(value)) return null;
  const n = BigInt(value);
  return n <= BigInt(Number.MAX_SAFE_INTEGER) && (!positive || n > 0n) ? n : null;
};

export function classifyRpcAnswer(method, result) {
  try {
    if (result == null) return { kind: 'missing' };
    if (method === 'eth_blockNumber' || method === 'eth_chainId') {
      const n = quantity(result, method === 'eth_blockNumber');
      return n === null ? { kind: 'malformed' } : { kind: 'value', key: n.toString() };
    }
    if (method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash') {
      if (!result || typeof result !== 'object' || Array.isArray(result)) return { kind: 'malformed' };
      const number = quantity(result.number);
      const timestamp = quantity(result.timestamp);
      if (number === null || timestamp === null) return { kind: 'malformed' };
      for (const field of ['hash', 'parentHash', 'mixHash']) {
        if (result[field] != null && (typeof result[field] !== 'string' || !hashPattern.test(result[field]))) return { kind: 'malformed' };
      }
      formatBlock(result);
      return { kind: 'value', key: JSON.stringify([
        number.toString(), result.hash?.toLowerCase() ?? null, result.parentHash?.toLowerCase() ?? null,
        timestamp.toString(), result.mixHash?.toLowerCase() ?? null,
      ]) };
    }
    if (method === 'eth_call') {
      return typeof result === 'string' && bytesPattern.test(result)
        ? { kind: 'value', key: result.toLowerCase() } : { kind: 'malformed' };
    }
    const key = JSON.stringify(result);
    return typeof key === 'string' ? { kind: 'value', key } : { kind: 'malformed' };
  } catch { return { kind: 'malformed' }; }
}

export function rpcAnswerKey(method, result) {
  const answer = classifyRpcAnswer(method, result);
  return answer.kind === 'value' ? answer.key : null;
}

export function classifyRpcError(error) {
  const seen = new Set(); let rejected = false; let missing = false;
  for (let current = error; current && typeof current === 'object' && !seen.has(current); current = current.cause) {
    seen.add(current);
    const message = `${current.message || ''} ${current.shortMessage || ''} ${current.details || ''}`;
    if (/execution reverted/i.test(message)) return 'revert';
    if ([4001, 5000].includes(Number(current.code))) rejected = true;
    if (/header not found|unknown block|missing trie node|block not found/i.test(message)) missing = true;
  }
  return rejected ? 'rejected' : missing ? 'missing' : 'transport';
}

export function numberedBlockOf(args) {
  const param = args?.method === 'eth_getBlockByNumber' ? args.params?.[0]
    : args?.method === 'eth_call' ? args.params?.[1] : null;
  return quantity(param);
}

export function readKeyOf(args) {
  try {
    const params = Array.isArray(args?.params) ? [...args.params] : [];
    if (numberedBlockOf(args) !== null) params[args.method === 'eth_call' ? 1 : 0] = 'N';
    return `${args?.method || ''}:${JSON.stringify(params)}`;
  } catch { return String(args?.method || ''); }
}

export function selectAgreedPublic(answers) {
  const seen = new Set(); const groups = new Map(); const valueHosts = [];
  for (const answer of Array.isArray(answers) ? answers : []) {
    if (!answer || typeof answer.sourceId !== 'string' || seen.has(answer.sourceId)) continue;
    seen.add(answer.sourceId);
    if (answer.kind !== 'value' && answer.kind !== 'revert') continue;
    const key = answer.kind === 'revert' ? REVERT_ANSWER_KEY : answer.key;
    if (typeof key !== 'string') continue;
    valueHosts.push(answer.sourceId);
    const group = groups.get(key) || { key, first: answer, sources: [] };
    group.sources.push(answer.sourceId); groups.set(key, group);
  }
  const list = [...groups.values()].sort((a, b) => b.sources.length - a.sources.length);
  if (!list.length) return { kind: 'none', valueHosts, groups: list };
  const first = list[0];
  if (first.sources.length >= AGREEMENT_MIN_VOTES && first.sources.length > (list[1]?.sources.length || 0))
    return { kind: 'agreed', key: first.key, first: first.first, sources: first.sources, valueHosts, groups: list };
  return { kind: valueHosts.length === 1 ? 'single' : 'split', valueHosts, groups: list };
}

export function settledEarly(answers) {
  const result = selectAgreedPublic(answers);
  return result.kind === 'agreed' && result.groups.length === 1;
}

export function shouldStepBelow(answers) {
  return new Set((Array.isArray(answers) ? answers : []).filter((a) => a?.kind === 'missing').map((a) => a.sourceId)).size >= STEP_BELOW_MIN_MISSING;
}

export function missingHeadBelow(answers, lastHeads, number) {
  const heads = (Array.isArray(answers) ? answers : []).filter((answer) => answer?.kind === 'missing')
    .map((answer) => lastHeads?.get(answer.sourceId)).filter((head) => typeof head === 'bigint' && head < number);
  return heads.length ? heads.reduce((lowest, head) => head < lowest ? head : lowest) : null;
}

export function refreshStepBelow(stepBelow, values) {
  if (!stepBelow || !Array.isArray(stepBelow.sources)) return stepBelow;
  const heads = values.filter((item) => stepBelow.sources.includes(item.sourceId)).map((item) => item.value);
  if (!heads.length) return stepBelow;
  const n = heads.reduce((lowest, head) => head < lowest ? head : lowest);
  return { ...stepBelow, n: n > stepBelow.n ? n : stepBelow.n };
}

export function selectPublicBlockNumber(values, { stepBelow = null } = {}) {
  const seen = new Set(); const valid = [];
  for (const item of Array.isArray(values) ? values : []) {
    if (!item || typeof item.sourceId !== 'string' || seen.has(item.sourceId) || typeof item.value !== 'bigint' || item.value <= 0n) continue;
    seen.add(item.sourceId); valid.push(item);
  }
  valid.sort((a, b) => a.value > b.value ? -1 : a.value < b.value ? 1 : 0);
  const valueHosts = valid.map((item) => item.sourceId);
  if (!valid.length) return { kind: 'none', valueHosts };
  if (valid.length === 1) return { kind: 'single', valueHosts, value: valid[0].value };
  if (valid.length === 2 && valid[0].value - valid[1].value > BLOCK_AGREEMENT_SPREAD)
    return { kind: 'split', valueHosts, values: valid };
  let value = valid[1].value;
  if (valid.length >= 3 && typeof stepBelow === 'bigint' && value >= stepBelow
    && value - stepBelow <= SHALLOW_STEP_BLOCKS) {
    const floor = value > STEP_BELOW_MAX_BLOCKS ? value - STEP_BELOW_MAX_BLOCKS : 0n;
    value = stepBelow > floor ? stepBelow : floor;
  }
  return { kind: 'agreed', value, valueHosts };
}

export function selectPublicChainTip({ samples = [], nowMonoMs }) {
  const seen = new Set(); const valid = [];
  for (const sample of Array.isArray(samples) ? samples : []) {
    if (!sample || typeof sample.sourceId !== 'string' || seen.has(sample.sourceId)
      || !Number.isSafeInteger(sample.blockTimestampMs) || !Number.isFinite(sample.observedMonoMs)
      || !Number.isFinite(nowMonoMs) || sample.observedMonoMs > nowMonoMs) continue;
    seen.add(sample.sourceId);
    valid.push({ sourceId: sample.sourceId, rawMs: sample.blockTimestampMs,
      adjustedMs: sample.blockTimestampMs + Math.max(0, Math.floor(nowMonoMs - sample.observedMonoMs)) });
  }
  const valueHosts = valid.map((item) => item.sourceId);
  if (!valid.length) return { kind: 'none', timeMs: null, valueHosts };
  if (valid.length === 1) return { kind: 'single', timeMs: valid[0].rawMs, valueHosts };
  let best = null;
  for (let mask = 1; mask < (1 << valid.length); mask++) {
    const group = valid.filter((_, i) => mask & (1 << i));
    if (group.length < AGREEMENT_MIN_VOTES) continue;
    const times = group.map((item) => item.adjustedMs);
    if (Math.max(...times) - Math.min(...times) > TIP_GROUP_SPREAD_MS) continue;
    const max = Math.max(...times);
    if (!best || group.length > best.group.length || (group.length === best.group.length && max > best.max)) best = { group, max };
  }
  if (!best) return { kind: 'split', timeMs: null, valueHosts };
  const raw = best.group.map((item) => item.rawMs).sort((a, b) => a - b);
  return { kind: 'agreed', timeMs: raw[raw.length >= 3 ? 1 : 0], valueHosts, sources: best.group.map((item) => item.sourceId) };
}

export function acceptApprovedTip(timeMs, clientNowMs) {
  return Number.isSafeInteger(timeMs) && Number.isFinite(clientNowMs)
    && timeMs <= clientNowMs + CHAT_WINDOW_CLOCK_SKEW_MS ? timeMs : null;
}

export function createNoAgreementTracker({ windowMs = NO_AGREEMENT_WINDOW_MS, spacingMs = NO_AGREEMENT_SPACING_MS,
  needed = NO_AGREEMENT_NEEDED, promptGapMs = NO_AGREEMENT_PROMPT_GAP_MS } = {}) {
  let marks = []; let lastPromptAt = -Infinity;
  return {
    record(key, event, now) {
      marks = marks.filter((mark) => now - mark.at <= windowMs);
      marks.push({ key, shape: event.shape, hosts: [...event.hosts], candidates: event.candidates.map((candidate) => ({
        host: candidate.host, value: String(candidate.value).slice(0, DESCRIBE_MAX_CHARS),
      })), at: now });
      let count = 0; let lastAt = -Infinity;
      for (const mark of marks) if (mark.at - lastAt >= spacingMs) { count++; lastAt = mark.at; }
      if (count < needed || now - lastPromptAt < promptGapMs) return null;
      lastPromptAt = now;
      const split = [...marks].reverse().find((mark) => mark.shape === 'split');
      if (split) return { kind: 'split', key: split.key, candidates: split.candidates };
      const latest = marks[marks.length - 1];
      return { kind: 'single', key: latest.key, host: latest.hosts[0], candidates: latest.candidates };
    },
    clear() { marks = []; },
    approved() { marks = []; if (Number.isFinite(lastPromptAt)) lastPromptAt -= promptGapMs - 30_000; },
    size() { return marks.length; },
  };
}

// S3R4-U-RPC1-CHOICE: 本人が選んだノード（chosen）が値を返さず、ほかの読み先だけが値を返した読みは、
// 呼び手が chosen に1回だけ聞き直し、それでも答えなければ一致なしの印を付けずに chosen を待つ。
// 同じ読み（鍵）に chosen が W 以上答えないか、同じ鍵の直近の読みの4回に1回以上が欠ければ「待つ／別のノードを選ぶ」。
export function chosenWaitApplies(chosen, hosts) {
  return typeof chosen === 'string' && Array.isArray(hosts) && hosts.length > 0 && !hosts.includes(chosen);
}

export function createChosenWaitTracker({ waitMs = CHOSEN_WAIT_MS, promptGapMs = NO_AGREEMENT_PROMPT_GAP_MS,
  maxKeys = CHOSEN_WAIT_MAX_KEYS, windowMs = NO_AGREEMENT_WINDOW_MS, spacingMs = NO_AGREEMENT_SPACING_MS,
  needed = NO_AGREEMENT_NEEDED, shareDen = CHOSEN_MISS_SHARE_DEN, maxEvents = CHOSEN_RATE_MAX_EVENTS } = {}) {
  const since = new Map(); const rates = new Map(); const heard = new Map();
  let notBefore = -Infinity; let lastKey = null;
  const recent = (list, now) => {
    const kept = list.filter((at) => now - at <= windowMs);
    return kept.length > maxEvents ? kept.slice(kept.length - maxEvents) : kept;
  };
  // 鍵ごとの直近の欠けと答え（割合の2択の数え）。鍵は maxKeys まで（古い鍵から捨てる）。
  const rateOf = (key, now) => {
    let rate = rates.get(key);
    if (!rate) {
      if (rates.size >= maxKeys) rates.delete(rates.keys().next().value);
      rate = { misses: [], answers: [] }; rates.set(key, rate);
    }
    rate.misses = recent(rate.misses, now); rate.answers = recent(rate.answers, now);
    return rate;
  };
  const rateDue = (key, now) => {
    const rate = rates.get(key);
    if (!rate) return false;
    const misses = recent(rate.misses, now); const answers = recent(rate.answers, now);
    let spaced = 0; let lastAt = -Infinity;
    for (const at of misses) if (at - lastAt >= spacingMs) { spaced++; lastAt = at; }
    return spaced >= needed && misses.length * shareDen >= misses.length + answers.length && now - misses[0] >= waitMs;
  };
  const remember = (host, value, now, key) => {
    heard.delete(host);
    heard.set(host, { host, value: String(value).slice(0, DESCRIBE_MAX_CHARS), key: String(key ?? ''), at: now });
  };
  return {
    // chosen が聞き直しにも値を返さず、ほかの読み先が値を返した読み。2択を出してよければその中身を返す。
    missed(key, event, now) {
      if (!since.has(key)) {
        if (since.size >= maxKeys) since.delete(since.keys().next().value);
        since.set(key, now);
      }
      lastKey = key;
      for (const candidate of event.candidates) remember(candidate.host, candidate.value, now, key);
      const rate = rateOf(key, now); rate.misses.push(now);
      if (now < notBefore) return null;
      const first = since.get(key);
      if (now - first >= waitMs) return { kind: 'chosen-wait', key, reason: 'key', waitedMs: Math.floor(now - first) };
      if (rateDue(key, now)) return { kind: 'chosen-wait', key, reason: 'rate', waitedMs: Math.floor(now - rate.misses[0]) };
      return null;
    },
    // chosen 以外の読み先が値（か revert）を返した（一致した読み・早い打ち切りの後に届いた答えも）。選ぶ画面の候補。
    heard(host, value, now, key) { remember(host, value, now, key); },
    // chosen がその鍵の読みに値（か revert）を返した。
    answered(key, now) {
      if (Number.isFinite(now)) rateOf(key, now).answers.push(now);
      return since.delete(key);
    },
    // 2択を chosen の答えで閉じてよいか: 同じ鍵の続く欠け（key）の2択は閉じる。欠けの割合（rate）の2択はその鍵の割合が下がってから。
    closableBy(prompt, key, now) {
      return prompt?.kind === 'chosen-wait' && prompt.key === key && (prompt.reason !== 'rate' || !rateDue(key, now));
    },
    waited(now) { notBefore = now + waitMs; },
    dismissed(now) { notBefore = now + Math.max(waitMs, promptGapMs); },
    // 2択の鍵に chosen が答えて2択を閉じた。次の2択は W の後。
    closedByAnswer(now) { notBefore = Math.max(notBefore, now + waitMs); },
    // 「別のノードを選ぶ」: max(W, 60秒) の内に値を返した読み先を、読み先の決まった順（order）に並べる。
    pick(order, now) {
      if (Number.isFinite(now)) for (const [host, item] of heard) if (now - item.at > Math.max(waitMs, windowMs)) heard.delete(host);
      if (lastKey === null || !heard.size) return null;
      const list = Array.isArray(order) ? order : [];
      const rank = (host) => { const i = list.indexOf(host); return i < 0 ? list.length : i; };
      return { kind: 'pick', key: lastKey, candidates: [...heard.values()].sort((a, b) => rank(a.host) - rank(b.host))
        .map(({ host, value, key }) => ({ host, value, key })) };
    },
    reset() { since.clear(); rates.clear(); heard.clear(); notBefore = -Infinity; lastKey = null; },
    size() { return since.size; },
  };
}

export function parseNodeTrust(raw, allowedHosts) {
  try {
    const value = JSON.parse(raw);
    if (!value || value.v !== NODE_TRUST_VERSION || !Array.isArray(value.approved)
      || !value.approved.every((host) => typeof host === 'string')
      || !(value.chosen === null || typeof value.chosen === 'string')) return null;
    const allowed = new Set(allowedHosts);
    return { approved: new Set(value.approved.filter((host) => allowed.has(host))),
      chosen: allowed.has(value.chosen) ? value.chosen : null };
  } catch { return null; }
}

export function serializeNodeTrust({ approved, chosen }) {
  return JSON.stringify({ v: NODE_TRUST_VERSION, approved: [...approved].sort(), chosen: chosen ?? null });
}

export function describeRpcAnswer(method, value) {
  try {
    if (method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash')
      return `#${BigInt(value.number)}・${BigInt(value.timestamp)}・${String(value.hash).slice(0, 10)}`.slice(0, DESCRIBE_MAX_CHARS);
    if (typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value)) return BigInt(value).toString().slice(0, DESCRIBE_MAX_CHARS);
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return text.length > 18 ? `${text.slice(0, 18)}…` : text.slice(0, DESCRIBE_MAX_CHARS);
  } catch { return '?'; }
}

// S3R4-U-RPC1-STALE2（表示だけ）: 読んだブロックが補正した時計 C より約3分以上古い状態が続いたら帯で知らせる。
// 読みは2種類（番号の読みで選んだ番号の固定ブロック・先端）に分け、種類ごとに出し入れする（先端が新しくても固定ブロックの古さは消えない）。
// 出す: 3分以上古い読みが60秒以上続いた（間に2分未満の読みが無く、古い読みどうしの間が5分以内）。眠りの直後の1回の古い読みでは出さない。
// 消す: 2分未満の読みの後60秒その種類に2分以上の読みが来ない、またはその種類に2分以上の読みが5分来ない。C を直した
// （C と単調時計の差が30秒を超えて動いた）ら数え直し、次の2分未満の読みですぐ消す。分はその種類の直近5分の3分以上の読みの最大
// （読みごとに上下させない）。出所はその種類の最後の古い読み（固定ブロックは番号の出所）。採る値・読みの回数・承認と画面には触れない。
export const STALE_BLOCK_NOTICE_MS = 180_000;
export const STALE_BLOCK_CLEAR_MS = 120_000;
export const STALE_BLOCK_CONFIRM_MS = 60_000;
export const STALE_BLOCK_HOLD_MS = 300_000;
export const STALE_BLOCK_PAIR_MS = 30_000;
export const STALE_BLOCK_CLOCK_STEP_MS = 30_000;

export function createStaleBlockNotice({ clientNowMs = () => Date.now(), monoNowMs = () => performance.now() } = {}) {
  const listeners = new Set(); let picked = null; let notice = null; let offset = null;
  const blank = () => ({ on: false, source: null, minutes: 0, since: null, lastStale: -Infinity, lastWarm: -Infinity, okSince: null, peaks: new Map() });
  const kinds = { block: blank(), tip: blank() };
  const see = (kind, blockTimeMs, source) => {
    const now = clientNowMs(); const lagMs = now - blockTimeMs; const at = monoNowMs();
    if (!Number.isSafeInteger(blockTimeMs) || !Number.isFinite(lagMs) || !Number.isFinite(at)) return;
    const stepped = offset !== null && Math.abs(now - at - offset) > STALE_BLOCK_CLOCK_STEP_MS;
    offset = now - at;
    if (stepped) for (const x of Object.values(kinds)) { x.since = null; x.peaks.clear(); x.okSince = -Infinity; }
    const k = kinds[kind];
    if (lagMs >= STALE_BLOCK_NOTICE_MS) {
      if (k.since === null || at - k.lastStale > STALE_BLOCK_HOLD_MS) k.since = at;
      k.lastStale = at; k.lastWarm = at; k.okSince = null; k.source = source;
      k.peaks.set(Math.floor(lagMs / 60_000), at);
      if (at - k.since >= STALE_BLOCK_CONFIRM_MS) k.on = true;
    } else if (lagMs >= STALE_BLOCK_CLEAR_MS) { k.lastWarm = at; k.okSince = null; }
    else { k.since = null; if (k.okSince === null) k.okSince = at; }
    for (const name of Object.keys(kinds)) {
      const x = kinds[name];
      if (x.on && ((x.okSince !== null && at - x.okSince >= STALE_BLOCK_CONFIRM_MS) || at - x.lastWarm >= STALE_BLOCK_HOLD_MS)) { kinds[name] = blank(); continue; }
      for (const [m, t] of x.peaks) if (at - t >= STALE_BLOCK_HOLD_MS) x.peaks.delete(m);
      if (x.peaks.size) x.minutes = Math.max(...x.peaks.keys());
    }
    const top = [kinds.block, kinds.tip].filter((x) => x.on).sort((a, b) => b.minutes - a.minutes)[0];
    const next = top ? { source: top.source, minutes: top.minutes } : null;
    if (next?.source === notice?.source && next?.minutes === notice?.minutes) return;
    notice = next;
    for (const listener of [...listeners]) { try { listener(notice); } catch { /* 表示だけ */ } }
  };
  return {
    get: () => notice,
    subscribe(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    // 固定ブロックの出所は番号の出所だけで決める（同じ番号のブロックはどこで読んでも同じ・古さは番号の選びから来る）。
    noteRead(args, value, source) {
      try {
        if (args?.method === 'eth_blockNumber') { picked = { n: BigInt(value), source, at: monoNowMs() }; return; }
        const n = args?.method === 'eth_getBlockByNumber' ? numberedBlockOf(args) : null;
        if (n === null || picked?.n !== n || !(monoNowMs() - picked.at <= STALE_BLOCK_PAIR_MS)) return;
        see('block', Number(BigInt(value.timestamp)) * 1000, picked.source);
      } catch { /* 表示だけ。読みには触れない */ }
    },
    noteTip(timeMs, source) { try { see('tip', timeMs, source); } catch { /* 同上 */ } },
  };
}
