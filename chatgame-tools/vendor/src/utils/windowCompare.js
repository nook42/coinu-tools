// S3R4-U-RPCWIN: 提出の押下で読んだ Evidence.chatWindow(N) の純粋な比較。
// 運営の答えは表示専用で、票と選択肢には入れない。
// S3R4-U-RPC1: 既定の印は、2票以上の一意の最多の組、無ければこの端末の窓（一致の規則で決まる窓）。同じ読み先は1票。
import { chatWindowMsFromTimeline, CHAT_WINDOW_CLOCK_SKEW_MS } from '../../workers/game_workers/lib/protocol-v2.js';

export const PRESS_WINDOW_READ_TIMEOUT_MS = 3000;

const validWindow = (w) => Boolean(w) && Number.isSafeInteger(w.startMs)
  && Number.isSafeInteger(w.endMs) && w.startMs <= w.endMs;
const sameWindow = (a, b) => validWindow(a) && validWindow(b)
  && a.startMs === b.startMs && a.endMs === b.endMs;

export function pressAnswerWindow(answer) {
  if (!answer || answer.error || !Number.isSafeInteger(answer.chatOpenAt)
    || !Number.isSafeInteger(answer.chatCloseAt) || answer.chatOpenAt > answer.chatCloseAt) return null;
  const win = chatWindowMsFromTimeline(answer);
  return validWindow(win) ? win : null;
}

export function comparePressWindows({ current = null, answers = [], operator = null, walletRoute = 'none', headHost = null } = {}) {
  const here = validWindow(current) ? { startMs: current.startMs, endMs: current.endMs } : null;
  const read = [];
  const unanswered = [];
  const seen = new Set();
  for (const answer of Array.isArray(answers) ? answers : []) {
    const sourceId = String(answer?.sourceId ?? '?');
    if (seen.has(sourceId)) continue;
    seen.add(sourceId);
    const win = pressAnswerWindow(answer);
    if (win) read.push({ sourceId, win });
    else unanswered.push(sourceId);
  }
  const groups = [];
  const groupOf = (win) => {
    let group = groups.find((g) => sameWindow(g.window, win));
    if (!group) {
      group = { key: `${win.startMs}:${win.endMs}`, window: win,
        chatOpenAt: win.startMs + CHAT_WINDOW_CLOCK_SKEW_MS,
        chatCloseAt: win.endMs - CHAT_WINDOW_CLOCK_SKEW_MS,
        sources: [], isCurrent: false };
      groups.push(group);
    }
    return group;
  };
  if (here) groupOf(here).isCurrent = true;
  for (const r of read) groupOf(r.win).sources.push(r.sourceId);
  const agree = read.length <= 1 || read.every((r) => sameWindow(r.win, here || read[0].win));
  // 端末の窓が無い控えでは、1本だけの答えで控えを判定しない。
  const agreedWindow = agree ? (here || (read.length >= 2 ? read[0].win : null)) : null;
  const most = Math.max(0, ...groups.map((g) => g.sources.length));
  const top = most > 0 ? groups.filter((g) => g.sources.length === most) : [];
  const operatorWindow = pressAnswerWindow(operator);
  // S3R4-U-RPC1: 2票以上の一意の最多の組があればその組。無ければこの端末の窓（2本以上の読み先の一致などで決めた窓）。
  // どちらも無ければ印なし（1票対0票で印を付けない）。
  const majority = top.length === 1 && top[0].sources.length >= 2 ? top[0] : null;
  const deviceGroup = here ? groups.find((g) => g.isCurrent) : null;
  return {
    agree, agreedWindow, readCount: read.length, groups, unanswered,
    defaultKey: majority ? majority.key : (deviceGroup ? deviceGroup.key : null),
    defaultReason: majority ? 'majority' : (deviceGroup ? 'device' : null), walletRoute, headHost,
    operator: operator ? { sourceId: String(operator.sourceId ?? 'operator'), window: operatorWindow,
      matchesKey: operatorWindow ? (groups.find((g) => sameWindow(g.window, operatorWindow))?.key ?? null) : null } : null,
  };
}

export function priorityFieldInsideWindow(priority, chatWindow) {
  if (!priority || typeof priority !== 'object') return true;
  if (!validWindow(chatWindow)) return false;
  const inWin = (ts) => Number.isFinite(ts) && chatWindow.startMs <= ts && ts <= chatWindow.endMs;
  return (Array.isArray(priority.messages) ? priority.messages : []).every((m) => inWin(m?.timestamp))
    && (Array.isArray(priority.receipts) ? priority.receipts : []).every((r) => inWin(r?.timestamp))
    && (Array.isArray(priority.selfReceiptAggregate?.entries) ? priority.selfReceiptAggregate.entries : [])
      .every((e) => inWin(e?.timestamp));
}

export function pressPromptFor({ comparison, storedPriority = null, canRebuild = false } = {}) {
  const stored = storedPriority && typeof storedPriority === 'object' ? storedPriority : null;
  const keep = stored ? { kind: 'stored' } : { kind: 'current' };
  if (!comparison) return { decision: keep };
  const agreed = comparison.agreedWindow;
  if (comparison.agree && (!stored || !agreed || priorityFieldInsideWindow(stored, agreed))) return { decision: keep };
  const mode = !stored ? 'build' : (canRebuild ? 'stored-rebuild' : 'stored-only');
  const storedInside = stored
    ? Object.fromEntries(comparison.groups.map((g) => [g.key, priorityFieldInsideWindow(stored, g.window)])) : null;
  const initial = mode === 'stored-only'
    ? (comparison.defaultKey && storedInside[comparison.defaultKey] === true ? { kind: 'stored' } : null)
    : (comparison.defaultKey ? { kind: 'group', key: comparison.defaultKey } : null);
  return { prompt: { mode, storedInside, initial } };
}

export function pressDecisionFor({ comparison, prompt, choice, current = null } = {}) {
  const group = choice?.kind === 'group'
    ? (comparison?.groups || []).find((g) => g.key === choice.key) || null : null;
  if (prompt?.mode === 'build') {
    if (group) return group.isCurrent ? { kind: 'current' } : { kind: 'window', fieldWindow: group.window };
    return choice?.kind === 'none' ? { kind: 'none' } : { kind: 'cancel' };
  }
  if (prompt?.mode === 'stored-rebuild') {
    if (group) return prompt.storedInside?.[group.key] === true ? { kind: 'stored' }
      : { kind: 'rebuild', fieldWindow: group.isCurrent && validWindow(current) ? current : group.window };
    return choice?.kind === 'none' ? { kind: 'rebuild', fieldWindow: null } : { kind: 'cancel' };
  }
  return choice?.kind === 'stored' ? { kind: 'stored' } : { kind: 'cancel' };
}
