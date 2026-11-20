// FIX15: 手元の写しに公開URLの保証を出さず、管理者履歴の保証を実際の読取対象に限定する。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { VERIFICATION_AREAS } from '../src/verification-areas.js';
import { emitNonInteractiveOutcome } from '../src/index.js';

const expected = JSON.parse(readFileSync(new URL('./fixtures/fix13-summary.json', import.meta.url), 'utf8'));
const short = { en: 'Verified', ja: '検証できた', zh: '已验证' };
const admin = {
  en: 'It is guaranteed that all records of admin and SuperAdmin changes for TokenMining, Evidence, HashStorage, and BitcoinuDonate have been read from deployment onward. Any changes are shown as warnings.',
  ja: 'TokenMining・Evidence・HashStorage・BitcoinuDonate の管理者（admin）と SuperAdmin の交代の記録を、配備の時から全部読んだことが保証されます。交代があった場合は警告に表示されます。',
  zh: '可以保证，已从合约部署时起读取 TokenMining、Evidence、HashStorage、BitcoinuDonate 的管理员（admin）和 SuperAdmin 变更记录，且无遗漏。如有变更，会在警告中显示。',
};
const oldAdmin = {
  en: "It is guaranteed that all records of changes to the contracts' administrators have been read from deployment onward. Any changes are shown as warnings.",
  ja: '契約の管理者の交代の記録を配備の時から全部読んだことが保証されます。交代があった場合は警告に表示されます。',
  zh: '可以保证，已从合约部署时起读取全部管理员变更记录。如有变更，会在警告中显示。',
};
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
const mutations = {
  url_source: ["      if (!publicR2 && ['entries', 'selection', 'grouping', 'resultFiles', 'scoring', 'publicMerkle'].includes(area)) return false;", ''],
  artifact_source: ['!ctx.cfg?.artifactDir', 'true'],
  emergency_source: ['!ctx.cfg?.emergencySource', 'true'],
  // 再反証 G-1b: 公式以外の取得元の判定を外すと、ミラーの走りで公式の頁の保証が出て赤。
  source_base: ['!ctx.cfg?.sourceBase', 'true'],
  official_r2: ["=== 'https://r2.bitcoinu.org';", "!== '';"],
  ...Object.fromEntries(Object.keys(admin).map((lang) => [`admin_${lang}`, [JSON.stringify(admin[lang]), JSON.stringify(oldAdmin[lang])]])),
};
if (mutation) assert.ok(Object.hasOwn(mutations, mutation), '既知の変異');
async function loadModule(path, mutate) {
  const url = new URL(path, import.meta.url);
  let source = readFileSync(url, 'utf8');
  if (mutate) {
    const [before, after] = mutations[mutation];
    assert.equal(source.split(before).length - 1, 1, '変異対象は1か所');
    source = source.replace(before, after);
    console.log(`MUTATION_APPLIED ${mutation}`);
  }
  source = source.replace(/from '(\.\.?\/[^']+)'/g, (_, path) => `from '${new URL(path, url).href}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
const { createReport, verificationCoverage } = await loadModule('../src/report.js', mutation && !mutation.startsWith('admin_'));
const { t, SUPPORTED_LANGS } = await loadModule('../src/i18n.js', mutation?.startsWith('admin_'));
let assertions = 0;
const eq = (actual, wanted, label) => { assert.deepEqual(actual, wanted, label); assertions++; };
const ok = (value, label) => { assert.ok(value, label); assertions++; };
function complete() {
  const report = createReport();
  for (const id of CHECK_INVENTORY) report.check(id, 'pass', { fixture: id });
  report.fact('system.audit', { adminHistoryChecked: true, donateChecked: true });
  return report;
}
function machine(report) {
  const lines = [];
  const outcome = emitNonInteractiveOutcome({ println: (line) => lines.push(line) }, { report, fatal: false, stopped: false }, null);
  return { lines, outcome };
}
function render(report, lang, cfg) {
  const before = structuredClone(report.list()), coverage = verificationCoverage(report), markers = machine(report);
  const audit = structuredClone(report.getFact('system.audit'));
  const ctx = { blockNum: 8, data: {}, ...(cfg === undefined ? {} : { cfg }) };
  const context = structuredClone(ctx), lines = [];
  report.renderSummary({ t: t(lang), println: (line) => lines.push(line) }, ctx);
  eq(report.list(), before, `${lang}: 全検査の状態・params・理由を保持`);
  eq(report.getFact('system.audit'), audit, `${lang}: 管理者監査のfactを保持`);
  eq(verificationCoverage(report), coverage, `${lang}: 領域の分類を保持`);
  eq(machine(report), markers, `${lang}: 機械行・分類・終了コードを保持`);
  eq(ctx, context, `${lang}: 取得元の設定を保持`);
  return lines;
}
const r2Cases = [undefined, {}, { artifactDir: null, emergencySource: null },
  { artifactDir: '', emergencySource: '' }, { r2Base: 'https://r2.bitcoinu.org/' }];
const localCases = [
  // 再反証 G-1b: 公式以外の取得元（--source-base・別の r2Base）。データはミラーから読んでいる。
  { r2Base: 'https://mirror.example.org/snapshot///' },
  { r2Base: 'https://mirror.example', sourceBase: 'https://mirror.example' },
  { sourceBase: 'https://mirror.example' },
  { artifactDir: '/tmp/artifact-copy' },
  { emergencySource: '/tmp/emergency-copy' },
  { artifactDir: '/tmp/gcp-copy', emergencySource: '/tmp/gcp-copy' },
  { emergencySource: '/tmp/gcp-copy', emergencyAuthority: 'gcp' },
  { artifactDir: '/tmp/artifact-copy', emergencySource: null, r2Base: 'https://mirror.example.org/snapshot///' },
  { artifactDir: null, emergencySource: '/tmp/emergency-copy', r2Base: 'https://r2.bitcoinu.org' },
];
for (const lang of SUPPORTED_LANGS) {
  eq(t(lang)('summary.guarantee.adminHistory'), admin[lang], `${lang}: G-2の全文`);
  eq(expected[lang].guarantees.adminHistory, admin[lang], `${lang}: FIX13/FIX14の固定期待も同じ対象範囲`);
  eq(t(lang)('summary.areaVerified'), short[lang], `${lang}: 既存の短文を保持`);
  const urls = Object.entries(expected[lang].guarantees)
    .filter(([, text]) => /\{(?:entriesUrl|blockUrl)\}/.test(text)).map(([area]) => area);
  eq(urls, ['entries', 'selection', 'grouping', 'resultFiles', 'scoring', 'publicMerkle'], `${lang}: URLを含む全6領域を確認`);
  const report = complete();
  const baseline = render(report, lang);
  for (const cfg of [...r2Cases, ...localCases]) {
    const local = localCases.includes(cfg), lines = render(report, lang, cfg);
    const entriesUrl = `${(cfg?.r2Base ?? 'https://r2.bitcoinu.org').replace(/\/+$/, '')}/entries/block8/`;
    const rowPrefixes = urls.map((area) => `  ${expected[lang].labels[area]}: `);
    for (const { area } of VERIFICATION_AREAS) {
      const prefix = `  ${expected[lang].labels[area]}: `;
      const body = local && urls.includes(area) ? short[lang] : expected[lang].guarantees[area]
        .replaceAll('{entriesUrl}', entriesUrl).replaceAll('{blockUrl}', 'https://bitcoinu.org/block/?n=8');
      eq(lines.filter((line) => line.startsWith(prefix)), [prefix + body], `${lang}/${area}/${JSON.stringify(cfg)}: 保証文か短文を全文一致で1回表示`);
      if (local && urls.includes(area)) ok(!lines.find((line) => line.startsWith(prefix)).includes('https://'), `${lang}/${area}: 公開URLの保証を出さない`);
    }
    // URLを含む6行以外は、URLなしの保証・未検証・対象なし・件数・結論①②③も含めてそのまま。
    const rest = (output) => output.filter((line) => !rowPrefixes.some((prefix) => line.startsWith(prefix)));
    eq(rest(lines), rest(baseline), `${lang}: 対象の6行以外に新しい文や変化を加えない`);
  }
  // G-1の再現に用いられた部分実行も、公開R2のときだけ応募データの保証を出す。
  const partial = createReport();
  for (const id of CHECK_INVENTORY.filter((id) => id.startsWith('check.stageA.'))) partial.check(id, 'pass');
  for (const id of ['check.stageB.playersMatch', 'check.stageB.randao']) partial.check(id, 'pass');
  for (const cfg of [undefined, ...localCases]) {
    const lines = render(partial, lang, cfg), prefix = `  ${expected[lang].labels.entries}: `;
    const body = cfg ? short[lang] : expected[lang].guarantees.entries.replaceAll('{entriesUrl}', 'https://r2.bitcoinu.org/entries/block8/');
    eq(lines.filter((line) => line.startsWith(prefix)), [prefix + body], `${lang}: G-1の部分実行の再現`);
  }
}
if (!mutation) for (const name of Object.keys(mutations)) {
  const result = spawnSync(process.execPath, [import.meta.filename, '--mutation=' + name], { encoding: 'utf8', env: process.env });
  eq(result.status, 1, `${name}: 変異で赤`);
  ok(result.stdout.includes(`MUTATION_APPLIED ${name}`) && result.stderr.includes('AssertionError'), `${name}: 起動失敗ではなくassertionで検出`);
}
console.log(`fix15-summary-unit: PASS (${assertions} assertions; ${Object.keys(mutations).length} mutants killed)`);
