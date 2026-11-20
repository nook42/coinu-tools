// メニュー1と3はStage Aと抽選の再現を共有する。保存済みファイルも、未検証の旗は信用しない。
import { isDeepStrictEqual } from 'node:util';
import { run as runEntries } from './stages/entries.js';
import { run as runSelection } from './stages/selection.js';
import { hashLikeBackend, canonicalEqual } from './json-utils.js';
import { verificationCoverage } from './report.js';

const FACTS = ['entryPeriodEnd', 'totalEntries', 'applicantHashRegistrations',
  'applicantHashDifferentRegistrations', 'applicantHash', 'hashRegisteredBlock', 'hashRegisteredTime'];

export function parseEntryUid(input) {
  const raw = String(input ?? '').trim();
  if (/^[0-9]{1,20}$/.test(raw)) return raw;
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || !/^\/user\/?$/.test(url.pathname)
        || url.searchParams.getAll('id').length !== 1) return null;
    const uid = url.searchParams.get('id');
    return /^[0-9]{1,20}$/.test(uid ?? '') ? uid : null;
  } catch { return null; }
}

async function authority(chain, blockNum) {
  const count = Number(await chain.applicantRegistrationCount(blockNum));
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('invalid registration count');
  const rows = [];
  for (let i = 0; i < count; i++) {
    const row = await chain.applicantRegistrationAt(blockNum, i);
    const block = await chain.getBlock(row.registeredBlock);
    rows.push({ row, block });
  }
  return { latest: await chain.getApplicantHash(blockNum), rows, timing: await chain.getTimingConstants() };
}

function sessionKey(ctx) {
  return `${ctx.blockNum}:${ctx.r2.baseDir}:${ctx.cfg.sourceBase || ctx.cfg.r2Base || ''}:${ctx.cfg.artifactDir || ''}`;
}

async function inputsUnchanged(ctx, saved) {
  if (!saved.data) return false;
  if (saved.chain !== ctx.chain || !isDeepStrictEqual(await authority(ctx.chain, ctx.blockNum), saved.authority)) return false;
  for (let i = 0; i < saved.data.infos.length; i++) {
    const key = `entries/block${ctx.blockNum}/info/${String(i).padStart(2, '0')}_info.json`;
    const res = await ctx.r2.fetchJson(key, { reuse: true, cacheOnly: true });
    const info = res?.data;
    if (!info || !Array.isArray(info.entries) || !canonicalEqual({ entries: info.entries.map((e) => ({ filename: e.filename, number: e.number })) }, saved.data.infos[i])) return false;
    ctx.r2.release?.(key);
  }
  for (const [filename, expected] of saved.data.entryFileHashes) {
    const key = `entries/block${ctx.blockNum}/entries/${filename}.json`;
    const res = await ctx.r2.fetchJson(key, { reuse: true, cacheOnly: true });
    if (!Array.isArray(res?.data) || await hashLikeBackend(res.data) !== expected) return false;
    ctx.r2.release?.(key);
  }
  return true;
}

export async function runEntriesReusable(ctx, sessions) {
  const key = sessionKey(ctx);
  const saved = sessions?.get(key);
  if (saved && ctx.data.reuseFiles && await inputsUnchanged(ctx, saved)) {
    Object.assign(ctx.data, structuredClone(saved.data));
    for (const e of saved.checks) ctx.report.check(e.id, e.status, e.params);
    for (const [name, value] of saved.facts) ctx.report.fact(name, value);
    ctx.ui.println(ctx.ui.t('entry.reused'));
    return { stop: false };
  }
  const result = await runEntries(ctx);
  if (sessions && verificationCoverage(ctx.report).find((row) => row.area === 'entries').verified
      && !ctx.data.legacyHashStorage) {
    sessions.set(key, { chain: ctx.chain, authority: await authority(ctx.chain, ctx.blockNum),
      data: structuredClone(Object.fromEntries(['legacyHashStorage', 'entryPeriodEnd', 'infos', 'entryFileHashes', 'entriesTotal', 'applicantHash', 'registeredBlock', 'applicantRegistration', 'hashRegisteredTimeMs', 'zeroEntries'].filter((name) => name in ctx.data).map((name) => [name, ctx.data[name]]))),
      checks: ctx.report.list().filter((e) => e.id.startsWith('check.stageA.')),
      facts: FACTS.map((name) => [name, ctx.report.getFact(name)]),
    });
  }
  return result;
}

// selection.runが読むStage Aの値を、欠けた欄とundefinedも区別して固定する。
function selectionInputs(ctx) {
  const names = ['applicantHash', 'registeredBlock', 'entryPeriodEnd',
    'entriesTotal', 'infos', 'entryFileHashes', 'legacyHashStorage'];
  return structuredClone({
    data: Object.fromEntries(names.filter((name) => name in ctx.data).map((name) => [name, ctx.data[name]])),
    confirmationBlocks: Number(ctx.cfg.pins?.confirmationBlocks ?? 64),
    gameMaxPlayers: Number(ctx.cfg.pins?.gameMaxPlayers),
  });
}

export async function runSelectionReusable(ctx, sessions) {
  if (!sessions || ctx.cfg.nonInteractive) return runSelection(ctx);
  const key = sessionKey(ctx);
  const saved = sessions.get(key)?.selection;
  const inputs = selectionInputs(ctx);
  if (saved && ctx.data.reuseFiles && saved.chain === ctx.chain
      && verificationCoverage(ctx.report).find((row) => row.area === 'entries').verified
      && isDeepStrictEqual(inputs, saved.inputs)) {
    // メモリ上の古い応答ではなく手元の写しを確認する。欠落・読取不能なら通常の再現へ。
    const fileKey = `entries/block${ctx.blockNum}/game_selection.json`;
    ctx.r2.release?.(fileKey);
    let current;
    try { current = await ctx.r2.fetchJson(fileKey, { reuse: true, cacheOnly: true }); } catch { /* 再現で判定 */ }
    if (current?.data && hashLikeBackend(current.data) === saved.selectionHash) {
      // 見出しは現行runが出すため同じ既存の鍵で保つ。再現の途中経過は出さない。
      ctx.ui.section?.();
      ctx.ui.println(ctx.ui.t('stageB.selStart', { n: ctx.blockNum }));
      const replay = structuredClone({ events: saved.events, data: saved.data, result: saved.result });
      for (const { method, args } of replay.events) ctx.report[method](...args);
      Object.assign(ctx.data, replay.data);
      return replay.result;
    }
  }
  // 再現が不合格・中断・例外になった場合、以前の抽選結果も残さない。
  const session = sessions.get(key);
  if (session) delete session.selection;
  const events = [], written = new Set();
  const report = { ...ctx.report };
  for (const method of ['check', 'fact']) report[method] = (...args) => {
    ctx.report[method](...args);
    events.push({ method, args: structuredClone(args) });
  };
  // 条件分岐で実際に書いた欄だけ戻す。infos/entryFileHashesのnull化も含む。
  const data = new Proxy(ctx.data, { set(target, name, value) {
    written.add(name);
    target[name] = value;
    return true;
  } });
  const result = await runSelection({ ...ctx, report, data });
  const checks = events.filter((e) => e.method === 'check' && e.args[0].startsWith('check.stageB.'));
  const passed = !result?.stop
    && checks.some((e) => e.args[0] === 'check.stageB.playersMatch' && e.args[1] === 'pass')
    && checks.every((e) => e.args[1] === 'pass');
  if (passed && ctx.data.gameSelection) {
    sessions.set(key, { ...sessions.get(key), selection: {
      chain: ctx.chain, inputs, selectionHash: hashLikeBackend(ctx.data.gameSelection),
      ...structuredClone({ events, result,
        data: Object.fromEntries([...written].map((name) => [name, ctx.data[name]])) }),
    } });
  }
  return result;
}

export async function findEntry(ctx, uid, verified) {
  let complete = true, included = false;
  if (!verified) {
    // entry-workerと同じ置き場の一覧と本体だけを読む（rootの再計算はしない）。
    const slot = String(uid).slice(-4).padStart(4, '0').slice(0, 2);
    const key = `entries/block${ctx.blockNum}/info/${slot}_info.json`;
    const res = await ctx.r2.fetchJson(key, { reuse: true, cacheOnly: verified });
    const infos = res?.data?.entries;
    ctx.r2.release?.(key);
    if (!Array.isArray(infos)) return { included, complete: false };
    const filenamePattern = new RegExp(`^${slot}_\\d+$`);
    for (const info of infos) {
      if (!filenamePattern.test(String(info?.filename))) { complete = false; continue; }
      const fileKey = `entries/block${ctx.blockNum}/entries/${info.filename}.json`;
      const file = await ctx.r2.fetchJson(fileKey, { reuse: true, cacheOnly: verified });
      const rows = file?.data;
      if (!Array.isArray(rows)) { complete = false; continue; }
      included ||= rows.some((row) => String(row?.uid) === uid);
      ctx.r2.release?.(fileKey);
    }
    return { included, complete };
  }
  for (let i = 0; i < 100; i++) {
    const key = `entries/block${ctx.blockNum}/info/${String(i).padStart(2, '0')}_info.json`;
    const res = await ctx.r2.fetchJson(key, { reuse: true, cacheOnly: verified });
    const infos = res?.data?.entries;
    ctx.r2.release?.(key);
    if (!Array.isArray(infos)) { complete = false; continue; }
    // Stage Aが固定した一覧と同じでなければ、欠落した応募について断定できない。
    if (verified && !canonicalEqual({ entries: infos.map((e) => ({ filename: e?.filename, number: e?.number })) }, ctx.data.infos?.[i])) {
      complete = false;
      continue;
    }
    for (const info of infos) {
      if (!/^\d{2}_\d+$/.test(String(info.filename))) { complete = false; continue; }
      const fileKey = `entries/block${ctx.blockNum}/entries/${info.filename}.json`;
      const file = await ctx.r2.fetchJson(fileKey, { reuse: true, cacheOnly: verified });
      const rows = file?.data;
      if (!Array.isArray(rows)) { complete = false; continue; }
      if (verified && await hashLikeBackend(rows) !== ctx.data.entryFileHashes?.get(info.filename)) {
        throw new Error('entry bytes differ from the Stage A verified snapshot');
      }
      included ||= rows.some((row) => String(row?.uid) === uid);
      ctx.r2.release?.(fileKey);
    }
  }
  return { included, complete };
}

export async function verifyOwnEntry(ctx, uid, sessions) {
  // セッションの検証済み結果は、現在の入力とチェーン権威が同じ場合だけ使う。
  let verified = false;
  const saved = sessions?.get(sessionKey(ctx));
  const reused = saved && await inputsUnchanged(ctx, saved);
  let initial;
  if (reused) {
    ctx.ui.section?.(ctx.ui.t('entry.sectionVerify'));
  } else {
    initial = await findEntry(ctx, uid, false);
    ctx.ui.section?.(ctx.ui.t('entry.sectionResult'));
    ctx.ui.println(ctx.ui.t(initial.included ? 'entry.included' : initial.complete ? 'entry.absent' : 'entry.unknown', { block: ctx.blockNum }));
    ctx.ui.println(ctx.ui.t('entry.onchainUnchecked'));
    ctx.ui.section?.(ctx.ui.t('entry.sectionVerify'));
    if (!await ctx.ui.askYesNo('entry.verifyAll')) return { ...initial, verified: false };
  }
  await runEntriesReusable(ctx, sessions);
  const stageAVerified = verificationCoverage(ctx.report).find((row) => row.area === 'entries').verified;
  if (stageAVerified) {
    // Stage Aの再利用時も、この接続の今のgetterを1回読んで配線を確かめる。
    try {
      const onchain = await ctx.chain.hashStorageAddress();
      const config = ctx.cfg.contracts.hashStorage;
      verified = typeof onchain === 'string' && typeof config === 'string'
        && onchain.toLowerCase() === config.toLowerCase();
      ctx.report.check('check.system.hashStorageWiring', verified ? 'pass' : 'fail', { onchain, config });
    } catch (error) {
      ctx.report.check('check.system.auditUnavailable', 'warn', { error: error?.message || String(error) });
    }
  }
  const result = reused || stageAVerified ? await findEntry(ctx, uid, stageAVerified) : initial;
  // 抽選は応募索引を解放するため、先に検証済みの写しで本人と完全性を確認する。
  if (verified && result.included && result.complete) {
    const selectionChecks = [];
    // reportは同じidを上書きする。過去の記録を混ぜず、この呼び出しの全記録を採る。
    const report = { ...ctx.report, check(id, status, params) {
      ctx.report.check(id, status, params);
      if (id.startsWith('check.stageB.')) selectionChecks.push({ id, status });
    } };
    try {
      const selection = await runSelectionReusable({ ...ctx, report }, sessions);
      verified = !selection?.stop
        && selectionChecks.some((e) => e.id === 'check.stageB.playersMatch' && e.status === 'pass')
        && selectionChecks.every((e) => e.status === 'pass');
    } catch {
      // 再現が完了しなければ、途中までpassでも保証しない。
      verified = false;
    }
  } else if (result.included) {
    verified = false;
  }
  ctx.ui.section?.(ctx.ui.t('entry.sectionResult'));
  if (reused) ctx.ui.println(ctx.ui.t(result.included ? 'entry.included' : result.complete ? 'entry.absent' : 'entry.unknown', { block: ctx.blockNum }));
  ctx.ui.println(ctx.ui.t(verified && result.complete
    ? result.included ? 'entry.onchainIncluded' : 'entry.onchainAbsent'
    : 'entry.verifyFailed'));
  return { ...result, verified };
}
