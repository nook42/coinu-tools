// FIX7B: 表示2行だけを削除。実probeを代役transportへ通し、3言語・3応答で確かめる。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { custom } from 'viem';
import { createChain } from '../src/chain.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';

const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
const [kind, onlyLang, onlyStatus] = mutation?.split(':') ?? [];
const statuses = ['unavailable', 'available', 'unknown'];
let assertions = 0;
const eq = (actual, expected, message) => { assert.deepEqual(actual, expected, message); assertions++; };

async function load(file, edit) {
  const url = new URL(file, import.meta.url);
  const source = edit(readFileSync(url, 'utf8')).replace(/from '([^']+)'/g,
    (_, path) => `from '${path.startsWith('.') ? new URL(path, url).href : import.meta.resolve(path)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}

const index = await load('../src/index.js', (source) => {
  source = source.replace("import { createChain } from './chain.js';",
    'const createChain = (...args) => globalThis.__FIX7B_CREATE_CHAIN(...args);');
  return kind === 'node' ? source.replace('      await node.probeArchive();',
    "      const capability = await node.probeArchive();\n      ui.println(ui.t('main.archive.node', { url: displayRpcUrl(url), status: ui.t(`main.archive.${capability.status}`) }));") : source;
});
const { createReport } = await load('../src/report.js', (source) => kind === 'summary'
  ? source.replace('    const unrun = CHECK_INVENTORY',
    "    if (f('stageC.lockStateUnchecked')) ui.println(t('summary.provisionalCalculation'));\n    const unrun = CHECK_INVENTORY") : source);

// 変異では削除前のキーも復元して、実際の文が戻った場合を検出する。
const removed = {
  en: {
    'main.archive.node': 'Node {url}: {status}',
    'main.archive.available': 'Historical state probe succeeded. Full verification will be attempted; individual reads may still be unavailable.',
    'main.archive.unavailable': 'The old-state probe was refused. Each required read will still be attempted, including the safe block. Unreadable checks remain unverified; full verification requires an archive-capable RPC.',
    'main.archive.unknown': 'Historical state support is undetermined (temporary failure or no old contract code). Checks will be attempted; unavailable reads remain unverified.',
    'summary.provisionalCalculation': 'Scoring and rewards were compared using declared lock inputs. comparisonStatus records that conditional outcome. Lock eligibility and dependent payouts remain unverified.',
  },
  ja: {
    'main.archive.node': 'ノード {url}: {status}',
    'main.archive.available': '過去の状態の読取試験に成功しました。全検査を試みます（個々の読取ができない場合は未検証になります）。',
    'main.archive.unavailable': '古い状態の読取試験は拒否されました。安全ブロックを含め、必要な読み取りは実際に試します。読めなかった検査は未検証です。全部の検証にはアーカイブ対応の RPC が必要です。',
    'main.archive.unknown': '過去の状態を読めるか判定できませんでした（一時的な失敗、または古い契約コードがありません）。検査を試み、読めない部分は未検証とします。',
    'summary.provisionalCalculation': '採点と報酬は応募時のロック申告値を前提に計算・照合しました。comparisonStatus はその照合の結果です。ロックの適格性と、それに依存する配分の正しさは未検証です。',
  },
  zh: {
    'main.archive.node': '节点 {url}: {status}',
    'main.archive.available': '历史状态读取测试成功。将尝试全部检查；个别读取失败时仍会标为未验证。',
    'main.archive.unavailable': '旧状态读取测试被拒绝。仍将实际尝试每个必要读取，包括安全区块。无法读取的检查保持未验证；完整验证需要支持归档的 RPC。',
    'main.archive.unknown': '无法确定历史状态支持情况（临时故障或旧区块无合约代码）。将尝试检查，无法读取的部分仍标为未验证。',
    'summary.provisionalCalculation': '评分和奖励按报名时申报的锁定数据计算并核对。comparisonStatus 记录此条件核对结果；锁定资格及依赖它的分配正确性仍未验证。',
  },
};

for (const lang of onlyLang ? [onlyLang] : SUPPORTED_LANGS) {
  const translate = (key, params = {}) => removed[lang][key]
    ? removed[lang][key].replace(/\{([^}]+)\}/g, (_, name) => params[name] ?? `{${name}}`) : t(lang)(key, params);
  for (const key of Object.keys(removed[lang])) eq(t(lang)(key), key, `${lang}: 未使用キーを削除`);
  const cases = onlyStatus ? [[onlyStatus]] : [...statuses.map((status) => [status]), statuses];
  for (const nodeStatuses of cases) {
    const urls = nodeStatuses.map((_, i) => `http://127.0.0.1:${31000 + i}`);
    const created = [];
    globalThis.__FIX7B_CREATE_CHAIN = (cfg, ui) => {
      const status = nodeStatuses[urls.indexOf(cfg.rpcUrls[0])];
      const requests = [];
      const chain = createChain(cfg, ui, custom({ request: async ({ method, params }) => {
        requests.push({ method, params });
        if (method === 'eth_chainId') return '0x1';
        if (method === 'eth_blockNumber') return '0x4e20';
        eq(method, 'eth_call', 'probeはeth_callのまま');
        if (status === 'unavailable') throw { code: -32602, message: 'Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode' };
        if (status === 'unknown') throw { code: -32602, message: 'Invalid params' };
        return '0x01';
      } }, { retryCount: 0 }));
      created.push({ chain, requests, status });
      return chain;
    };
    const lines = [];
    const ui = { t: translate, println: (line) => lines.push(line), warn: (line) => assert.fail(line) };
    const connected = await index.tryConnect({ chainIdExpected: 1, contracts: {} }, ui, urls);
    assert.ok(connected); assertions++;
    eq(lines, [translate('main.rpcConnecting', { url: urls.join(', ') }), translate('main.rpcConnected', { chainId: 1 })],
      `${lang}/${nodeStatuses}: 接続後に能力の行を出さない`);
    eq(created.length, urls.length === 1 ? 1 : urls.length + 1, 'ノードごとのprobe構成を維持');
    for (const { chain, requests, status } of urls.length === 1 ? created : created.slice(1)) {
      const capability = await chain.probeArchive();
      eq(capability.status, status, 'probeの判定を保持');
      eq(requests.filter(({ method }) => method === 'eth_call'), [{ method: 'eth_call', params: [
        { to: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', data: '0x18160ddd' }, '0x2710',
      ] }], '接続中にprobeを1回実施し、再呼出しでは増やさない');
    }

    for (const unchecked of [true, false]) for (const comparison of ['pass', 'fail']) {
      const report = createReport();
      report.fact('stageC.lockStateUnchecked', unchecked);
      if (unchecked) {
        const error = new ArchiveUnavailableError();
        report.fact('stageC.lockStateError', error);
        report.unverified('check.stageC.depositVerification', error, { reason: 'archive_unavailable' });
      }
      const params = { diffCount: comparison === 'fail' ? 1 : 0 };
      report.check('check.stageC.summaryMatch', comparison, params);
      const records = structuredClone(report.list());
      const summary = [];
      report.renderSummary({ ...ui, println: (line) => summary.push(line) }, { blockNum: 8, data: {} });
      for (const [key, text] of Object.entries(removed[lang])) {
        eq(summary.some((line) => line.includes(key) || line.includes(text)), false, `${lang}/${nodeStatuses}: 削除した文を出さない (${key})`);
      }
      for (const key of ['summary.coverageVerified', 'summary.coverageUnverified']) {
        assert.ok(summary.includes(translate(key))); assertions++;
      }
      if (unchecked && comparison === 'fail') {
        const mismatch = translate('summary.comparisonMismatch', { checks: 'check.stageC.summaryMatch' });
        assert.ok(summary.includes(mismatch) && summary.indexOf(mismatch) < summary.indexOf(translate('summary.coverageVerified')),
          '前提未検証の不一致の冒頭行を維持'); assertions++;
      }
      eq(report.list(), records, '表示で状態・params・metadataを変えない');
      assert.equal(report.get('check.stageC.summaryMatch').params, params); assertions++;
      eq(report.getFact('stageC.lockStateUnchecked'), unchecked, 'ロック未検証のfactを維持');
      const markers = [];
      const result = index.emitNonInteractiveOutcome({ println: (line) => markers.push(line) }, { report, fatal: false, stopped: false }, null);
      const category = unchecked ? 'partial' : comparison === 'fail' ? 'fail' : 'full';
      eq(result, { category, exitCode: unchecked ? 1 : comparison === 'fail' ? 2 : 0 }, '終了コードを維持');
      eq(markers, unchecked ? [
        '##CHECK check.stageC.depositVerification skip', '##CHECK check.stageC.summaryMatch skip',
        `##COMPARISON check.stageC.summaryMatch ${comparison} archive_unavailable`, '##RESULT partial',
      ] : [`##CHECK check.stageC.summaryMatch ${comparison}`, `##RESULT ${category}`], '機械行を維持');
    }
  }
}
delete globalThis.__FIX7B_CREATE_CHAIN;

if (!mutation) for (const lang of SUPPORTED_LANGS) for (const status of statuses) for (const name of ['node', 'summary']) {
  const result = spawnSync(process.execPath, [new URL(import.meta.url).pathname, `--mutation=${name}:${lang}:${status}`],
    { encoding: 'utf8', env: process.env });
  assert.equal(result.status, 1, `${name}/${lang}/${status}: 行を戻すと赤`); assertions++;
  assert.match(result.stderr, /AssertionError/, '起動失敗ではなく表示のassertionで検出'); assertions++;
  assert.match(result.stderr, name === 'node' ? /接続後に能力の行を出さない/ : /削除した文を出さない/); assertions++;
}
console.log(`fix7b-display-unit: PASS (${assertions} assertions${mutation ? '' : '; 18 mutants killed'})`);
