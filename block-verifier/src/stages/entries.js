// Stage A: エントリーデータ固定（applicantHash）の検証
//
// 正典（byte-exact 写像元）:
//   - workers/collect_workers/collect-worker.js:236-293 (per-worker hash file 構築)
//   - workers/collect_workers/collect-DO.js:1196-1403 (calculateHash / readWorkerHashFiles /
//     createIntermediateHash / createRootHash / 早期凍結ガード)
// ハッシュは常に SHA-256 over UTF-8 of JSON.stringify(parse(bytes))（= hashLikeBackend）。
import { hashLikeBackend, displayTime } from '../json-utils.js';
import { publicKeyToAddress } from 'viem/accounts';
import { secp256k1 } from '@noble/curves/secp256k1';
import { isValidNostrPubkey } from '../../vendor/workers/entry_workers/lib/nostr-key.js';

const WORKER_COUNT = 100;
const DL_CONCURRENCY = 10;
const ww = (i) => String(i).padStart(2, '0');

// 応募入口を迂回して applicantHash に固定された行を検知する。抽選対象からは外さない。
export function frozenEntryKeyFailure(row) {
  let block;
  try { block = typeof row?.bAddr === 'string' ? JSON.parse(row.bAddr) : row?.bAddr; }
  catch { return 'invalid bAddr JSON'; }
  if (!block || !isValidNostrPubkey(block.nostrPubkey)) return 'invalid nostrPubkey';
  if (typeof block.pubKey !== 'string' || !/^0x04[0-9a-fA-F]{128}$/.test(block.pubKey)
      || typeof block.address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(block.address)) {
    return 'invalid block address or pubKey';
  }
  try {
    secp256k1.ProjectivePoint.fromHex(block.pubKey.slice(2)).assertValidity();
    if (publicKeyToAddress(block.pubKey).toLowerCase() !== block.address.toLowerCase()) {
      return 'address does not match pubKey';
    }
  } catch { return 'invalid pubKey point'; }
  return null;
}

// collect-worker の per-worker hash file と同じバイト列を作る。
// number は Array.length 由来の JSON number に限り、暗黙の型変換はしない。
export function applicantHashEntry(fileInfo, hash) {
  const number = fileInfo?.number;
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(
      `Invalid info.entries[].number for ${String(fileInfo?.filename ?? '(missing filename)')}: `
      + 'expected a non-negative safe integer'
    );
  }
  return { filename: fileInfo.filename, hash, number };
}

// 並列ダウンロード（順序保存）
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) || 1 }, worker));
  return results;
}

export async function run(ctx) {
  const { cfg, chain, r2, ui, report, blockNum: N } = ctx;
  const fetchOpts = { reuse: ctx.data.reuseFiles };

  ui.section?.();
  ui.println(ui.t('stageA.start', { n: N }));

  // --- 1. オンチェーン applicantHash（未登録 = 集計未完了 → ここで終了） ---
  // 最新ビューは readiness と旧 HashStorage の互換判定にだけ使う。現行契約で Stage A/B の
  // 権威になるのは、後段で再計算した root と登録履歴を照合して選ぶ登録である。
  const legacyHashStorage = chain.isLegacyHashStorage?.() === true;
  const onchain = await chain.getApplicantHash(N);
  if (!onchain) {
    if (!legacyHashStorage) {
      try {
        const count = Number(await chain.applicantRegistrationCount(N));
        if (count !== 0) {
          report.check('check.stageA.applicantHashRegistered', 'fail', {
            n: N, hash: '-', block: '-', error: `latest view missing with registrationCount=${count}`,
          });
          ctx.data.stopReason = 'fail';
          return { stop: true };
        }
      } catch (error) {
        report.check('check.stageA.applicantHashRegistered', 'fail', {
          n: N, hash: '-', block: '-', error: `registration history unavailable: ${error?.message || error}`,
        });
        ctx.data.stopReason = 'fail';
        return { stop: true };
      }
    }
    report.check('check.stageA.applicantHashRegistered', 'skip', { n: N, hash: '-', block: '-' });
    ui.println(ui.t('stageA.noHash', { n: N }));
    ctx.data.stopReason = 'not_ready';
    return { stop: true };
  }
  const latestHash = String(onchain.hash).toLowerCase();
  const latestRegisteredBlock = Number(onchain.updated);
  report.check('check.stageA.applicantHashRegistered', 'pass', {
    n: N, hash: latestHash, block: latestRegisteredBlock,
  });
  ctx.data.legacyHashStorage = legacyHashStorage;

  // --- 2. エントリー期間終了時刻（オンチェーンのタイミング定数から。env は信頼しない） ---
  // entryPeriodEnd(N) = START_TIME + (N+1) × BLOCK_TIME（collect-DO.js:1216 と同式・ms）
  const timing = await chain.getTimingConstants();
  const entryPeriodEnd = timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs;
  ctx.data.entryPeriodEnd = entryPeriodEnd;
  report.fact('entryPeriodEnd', displayTime(entryPeriodEnd));

  // --- 3. info ×100（全ワーカー必須。欠落＝グローバルindexが崩れるため FAIL で停止） ---
  ui.println(ui.t('stageA.downloadingInfo'));
  const infoKeys = Array.from({ length: WORKER_COUNT }, (_, i) => `entries/block${N}/info/${ww(i)}_info.json`);
  const infoFetched = await mapLimit(infoKeys, DL_CONCURRENCY, async (key) => {
    const fetched = await r2.fetchJson(key, fetchOpts);
    const data = fetched?.data;
    // infoの付加フィールドは後段で一切使わない。攻撃者が上限内の巨大なダミー値を
    // 100ファイルへ積んでもheapへ残さないよう、必要な2フィールドだけへ即時投影する。
    const projected = data && Array.isArray(data.entries)
      ? { entries: data.entries.map((e) => ({ filename: e?.filename, number: e?.number })) }
      : null;
    const result = fetched == null ? null : {
      data: projected,
      parseError: fetched.parseError,
      sizeError: fetched.sizeError,
    };
    r2.release?.(key);
    return result;
  });
  const infoMissing = [];
  const infoCorrupt = [];
  const infos = [];
  for (let i = 0; i < WORKER_COUNT; i++) {
    const fetched = infoFetched[i];
    const data = fetched?.data;
    if (!data || !Array.isArray(data.entries)) {
      // 空ワーカーでも entries: [] を必ず出力する契約（A5, lottery-DO.js:923-947）
      infoMissing.push(infoKeys[i]);
      if (fetched?.parseError || fetched?.sizeError) {
        infoCorrupt.push(`${infoKeys[i]}: ${fetched.parseError || fetched.sizeError}`);
      }
      infos.push(null);
    } else {
      infos.push(data);
    }
  }
  if (infoMissing.length === WORKER_COUNT && infoCorrupt.length === 0) {
    // 100個すべて欠落 = まだ応募データが公開/集計されていない（＝未完了ゲート・FAILではない）。
    // 目立つメッセージで「まだ集計が終わっていない」と案内し、not_ready として終了する。
    // （一部だけ欠落は下の FAIL 分岐＝グローバルindex破損/一部握り潰しの疑い。）
    report.check('check.stageA.infoComplete', 'skip', { count: WORKER_COUNT, missing: WORKER_COUNT, first: '-' });
    const banner = '─'.repeat(60);
    ui.println('');
    ui.println(banner);
    ui.println(`  ⚠  ${ui.t('stageA.notAggregated', { n: N })}`);
    ui.println(banner);
    ctx.data.stopReason = 'not_ready';
    return { stop: true };
  }
  if (infoMissing.length > 0) {
    report.check('check.stageA.infoComplete', 'fail', {
      count: WORKER_COUNT,
      missing: infoMissing.length,
      first: infoCorrupt[0] || infoMissing[0],
    });
    ui.println(ui.t('stageA.infoIncomplete', { missing: infoMissing.length }));
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  report.check('check.stageA.infoComplete', 'pass', { count: WORKER_COUNT, missing: 0, first: '-' });
  ctx.data.infos = infos;

  // --- 3b. info 由来 filename の検証（G9: これを元に R2 キー／キャッシュパスを構築するため、
  //     正準形 /^\d{2}_\d+$/ 以外は即 FAIL で停止 — パストラバーサル・キー偽装防止） ---
  const badFilenames = [];
  for (let i = 0; i < WORKER_COUNT; i++) {
    for (const fileInfo of infos[i].entries) {
      if (!/^\d{2}_\d+$/.test(String(fileInfo.filename))) badFilenames.push(String(fileInfo.filename));
    }
  }
  if (badFilenames.length > 0) {
    report.check('check.stageA.badFilename', 'fail', { count: badFilenames.length, first: badFilenames[0] });
    ui.println(ui.t('stageA.badFilename', { first: badFilenames[0] }));
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  report.check('check.stageA.badFilename', 'pass', { count: 0, first: '-' });

  // number は root 材料に入る。undefined を JSON.stringify で落としたり、
  // 文字列/小数/負数を0へ寄せると writer と別の root になるためここで停止する。
  const badNumbers = [];
  for (const info of infos) {
    for (const fileInfo of info.entries) {
      if (!Number.isSafeInteger(fileInfo.number) || fileInfo.number < 0) {
        badNumbers.push(
          `${String(fileInfo.filename)} (info.number must be a non-negative safe integer)`
        );
      }
    }
  }
  if (badNumbers.length > 0) {
    report.check('check.stageA.recordCounts', 'fail', {
      total: 0, mismatches: badNumbers.length, first: badNumbers[0],
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  // --- 4. 全応募データ本体（entries）ファイルの取得 ---
  const allFileInfos = [];
  for (let i = 0; i < WORKER_COUNT; i++) {
    for (const fileInfo of infos[i].entries) allFileInfos.push({ worker: i, fileInfo });
  }
  ui.println(ui.t('stageA.downloadingEntries', { n: allFileInfos.length }));
  const fileErrors = [];
  const entryKeyFailures = [];
  let entryKeyFailureCount = 0;
  const fetchedFiles = await mapLimit(allFileInfos, DL_CONCURRENCY, async ({ fileInfo }) => {
    const key = `entries/block${N}/entries/${fileInfo.filename}.json`;
    const res = await r2.fetchJson(key, fetchOpts);
    if (!res || !Array.isArray(res.data)) {
      fileErrors.push(`${key}${res?.sizeError ? `: ${res.sizeError}` : res?.parseError ? `: ${res.parseError}` : ''}`);
      r2.release?.(key);
      return null;
    }
    const actual = res.data.length;
    for (let rowIndex = 0; rowIndex < res.data.length; rowIndex++) {
      const failure = frozenEntryKeyFailure(res.data[rowIndex]);
      if (failure) {
        entryKeyFailureCount++;
        if (entryKeyFailures.length < 5) entryKeyFailures.push(`${key}#${rowIndex}: ${failure}`);
      }
    }
    const hash = await hashLikeBackend(res.data);
    // Stage Bは当選indexを含むファイルだけ再読込する。全応募者をheapへ保持しない。
    r2.release?.(key);
    return { filename: fileInfo.filename, expected: fileInfo.number, actual, hash };
  });
  if (fileErrors.length > 0) {
    report.check('check.stageA.entryFilesComplete', 'fail', { count: allFileInfos.length, missing: fileErrors.length, first: fileErrors[0] });
    ui.println(ui.t('stageA.entryFilesIncomplete', { missing: fileErrors.length }));
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  report.check('check.stageA.entryFilesComplete', 'pass', { count: allFileInfos.length, missing: 0, first: '-' });
  report.check('check.stageA.entryKeyIntegrity', entryKeyFailureCount ? 'fail' : 'pass', {
    count: entryKeyFailureCount, first: entryKeyFailures[0] || '-',
    reason: entryKeyFailureCount ? ui.t('stageA.entryKeyInvalidReason') : '-',
  });

  // レコード件数照合（info.number == 実件数）
  const countMismatches = [];
  let entriesTotal = 0;
  const fileHashes = new Map();
  for (const item of fetchedFiles) {
    if (!item) continue;
    entriesTotal += item.actual;
    fileHashes.set(item.filename, item.hash);
    if (item.actual !== item.expected) {
      countMismatches.push(`${item.filename} (info:${item.expected} actual:${item.actual})`);
    }
  }
  // D-30 (1): 空の応募集合には行0のファイルも含めない。ROOT の空枝と同じ条件。
  if (entriesTotal === 0 && allFileInfos.length > 0) {
    countMismatches.push(ui.t('stageA.emptyFilesInvalid', { count: allFileInfos.length }));
  }
  // A-01: Stage Bはローカルキャッシュを読み直した後、このStage A指紋と再照合する。
  // `--reuse` 由来の旧キャッシュか今回保存したキャッシュかに依存せず、Stage Aが実際に
  // root計算へ使った内容と一致しないチャンクを当選者決定へ使わせない。
  ctx.data.entryFileHashes = fileHashes;
  if (countMismatches.length > 0) {
    report.check('check.stageA.recordCounts', 'fail', { total: entriesTotal, mismatches: countMismatches.length, first: countMismatches[0] });
  } else {
    report.check('check.stageA.recordCounts', 'pass', { total: entriesTotal, mismatches: 0, first: '-' });
  }
  ctx.data.entriesTotal = entriesTotal;
  report.fact('totalEntries', entriesTotal);

  // --- 5. ルートハッシュのローカル再計算（hash ファイルはダウンロードしない） ---
  // ダウンロードした info + entries だけから、collect-worker が書く hash ファイルと同形のオブジェクト
  // （collect-worker.js の writer 形
  //   { block_num, status:'success', entries:[{filename,hash,number}] }）を
  // ローカルで構築し、collect-DO と同じハッシュ連鎖（per-file → per-worker → intermediate → root）を
  // 再計算する。サーバーの中間生成物（hash ファイル）には一切依存しない ＝
  // 「ダウンロードした応募データそのもの」がオンチェーンの登録値と一致するかを検証する。
  ui.println(ui.t('stageA.computingRoot'));
  const hashList = [];
  for (let i = 0; i < WORKER_COUNT; i++) {
    const entriesHashes = [];
    for (const fileInfo of infos[i].entries) {
      entriesHashes.push(applicantHashEntry(fileInfo, fileHashes.get(fileInfo.filename)));
    }
    const localHashFile = { block_num: N, status: 'success', entries: entriesHashes };
    hashList.push({ workerIndex: i, hash: await hashLikeBackend(localHashFile) });
  }
  // intermediate（localeCompare ソート。"00_hash".."99_hash" では辞書順と同一）→ root
  const hashArray = hashList.map((item) => ({ filename: `${ww(item.workerIndex)}_hash`, hash: item.hash }));
  hashArray.sort((a, b) => a.filename.localeCompare(b.filename));
  const intermediate = { block_num: N, status: 'success', hash: hashArray };
  const root = '0x' + (await hashLikeBackend(intermediate));
  ui.println(ui.t('stageA.rootRecomputed', { hash: root }));

  // --- 6. 追記履歴を全件読む（getLogsには依存しない） ---
  // 旧 HashStorage の許可リスト対象だけは履歴 getter が無いため、従来どおり最新値を使う。
  // 許可リスト外で履歴 getter を読めない場合は、最新値への暗黙 fallback をせず FAIL にする。
  let regCount;
  let registrations;
  try {
    regCount = Number(await chain.applicantRegistrationCount(N));
    if (!Number.isSafeInteger(regCount) || regCount < 0) {
      throw new Error(`invalid registrationCount: ${regCount}`);
    }
    if (legacyHashStorage) {
      registrations = [{
        index: Math.max(0, regCount - 1),
        hash: latestHash,
        registeredBlock: latestRegisteredBlock,
        signer: onchain.signer,
      }];
    } else {
      registrations = [];
      for (let index = 0; index < regCount; index++) {
        const registration = await chain.applicantRegistrationAt(N, index);
        const registeredBlock = Number(registration.registeredBlock);
        if (!Number.isSafeInteger(registeredBlock) || registeredBlock < 0) {
          throw new Error(`invalid applicant registration block at index ${index}: ${registeredBlock}`);
        }
        registrations.push({
          index,
          hash: String(registration.hash).toLowerCase(),
          registeredBlock,
          signer: registration.signer,
        });
      }
    }
  } catch (error) {
    const message = `registration history unavailable: ${error?.message || error}`;
    report.check('check.stageA.rootMatch', 'fail', {
      recomputed: root, latest: latestHash, reason: 'registration_history_unavailable',
    });
    report.check('check.stageA.registrationCount', 'warn', {
      count: 'unavailable', registrations: [], error: message,
    });
    report.check('check.stageA.earlyFreeze', 'fail', {
      registered: 'unavailable', entryEnd: displayTime(entryPeriodEnd), error: message,
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  const registrationDetail = registrations.map((registration) => ({
    index: registration.index,
    registeredBlock: registration.registeredBlock,
    hash: registration.hash,
    matchesRoot: registration.hash === root,
  }));
  report.check('check.stageA.registrationCount', regCount === 1 ? 'pass' : 'warn', {
    count: regCount,
    registrations: registrationDetail,
    legacyLatestOnly: legacyHashStorage,
  });
  report.fact('applicantHashRegistrations', registrationDetail);
  const differentRegistrations = registrationDetail.filter((registration) => !registration.matchesRoot);
  if (differentRegistrations.length > 0) {
    report.fact('applicantHashDifferentRegistrations', differentRegistrations);
  }

  // root と同じ最初の登録を早期凍結の判定に使い、そのうち応募締切以後の最初のものを
  // 抽選が使う権威登録 U_A とする。同じ root の再登録や、その後の別 root は U_A を動かさない。
  let firstRootRegistration = null;
  let firstEligibleRootRegistration = null;
  for (const registration of registrations) {
    if (registration.hash !== root) continue;
    const block = await chain.getBlock(registration.registeredBlock);
    const registeredTimeMs = Number(block.timestamp) * 1000;
    const timed = { ...registration, registeredTimeMs };
    if (firstRootRegistration === null) firstRootRegistration = timed;
    if (firstEligibleRootRegistration === null && registeredTimeMs >= entryPeriodEnd) {
      firstEligibleRootRegistration = timed;
    }
  }

  if (firstEligibleRootRegistration) {
    const authoritative = firstEligibleRootRegistration;
    report.check('check.stageA.rootMatch', 'pass', {
      recomputed: root,
      onchain: authoritative.hash,
      registeredBlock: authoritative.registeredBlock,
    });
    report.check('check.stageA.applicantHashRegistered', 'pass', {
      n: N, hash: root, block: authoritative.registeredBlock,
    });
    ui.println(ui.t('stageA.rootMatchOk'));
    ctx.data.applicantHash = root;
    ctx.data.registeredBlock = authoritative.registeredBlock;
    ctx.data.applicantRegistration = authoritative;
    report.fact('applicantHash', root);
    report.fact('hashRegisteredBlock', authoritative.registeredBlock);
  } else {
    const reason = firstRootRegistration
      ? 'first_matching_registration_before_entry_deadline'
      : 'no_matching_registration_at_or_after_entry_deadline';
    report.check('check.stageA.rootMatch', 'fail', {
      recomputed: root,
      latest: latestHash,
      reason,
    });
    // Stage AのFAIL後も残りの独立検査を走らせる。抽選seedの根は、登録の有無にかかわらず
    // ダウンロード済み応募データから再計算した値を使い、権威登録 U_A は「無し」と明示する。
    ctx.data.applicantHash = root;
    ctx.data.registeredBlock = null;
    ctx.data.applicantRegistration = null;
    report.fact('applicantHash', root);
    const banner = '─'.repeat(60);
    ui.println('');
    ui.println(banner);
    ui.println(`  ✗  ${ui.t('stageA.rootMismatch', {
      recomputed: root,
      latest: latestHash,
      reason: ui.t(`stageA.rootMismatchReason.${reason}`),
    })}`);
    ui.println(banner);
  }

  // --- 7. 早期凍結チェック: root と同じ最初の登録の時刻を使う。 ---
  const firstRootTimeMs = firstRootRegistration?.registeredTimeMs ?? null;
  report.fact('hashRegisteredTime', firstRootTimeMs == null ? '-' : displayTime(firstRootTimeMs));
  ctx.data.hashRegisteredTimeMs = firstRootTimeMs;
  report.check('check.stageA.earlyFreeze', firstRootTimeMs !== null && firstRootTimeMs >= entryPeriodEnd ? 'pass' : 'fail', {
    registered: firstRootTimeMs == null ? 'unregistered' : displayTime(firstRootTimeMs),
    entryEnd: displayTime(entryPeriodEnd),
  });

  // --- 8. 応募0件: 「空の応募データ集合が固定された」ことを確認したうえで Stage B/Cへ進む。
  //     正典は game_selection.json、noGame summary、空ツリー標識root、manifestまで公開する。
  //     ここで止めると「0配分としてオンチェーン確定したか」を検査できない（R22-F3）。 ---
  if (entriesTotal === 0) {
    ui.println(ui.t('stageA.noEntries', { n: N }));
    ctx.data.zeroEntries = true;
  }

  return { stop: false };
}
