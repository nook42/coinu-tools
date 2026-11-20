// RPC の伏せ字は出力文字列だけ。実 transport / .env / ネットワークは使わない。
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, mkdirSync, cpSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import { inspect, stripVTControlCharacters } from 'node:util';
import { custom, http, fallback } from 'viem';

const repo = resolve(import.meta.dirname, '../..');
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='));
if (mutation || process.argv.includes('--mutations')) {
  const result = spawnSync(process.execPath, [join(import.meta.dirname, 'rpc-privacy-mutations.mjs'),
    ...(mutation ? [mutation, '--probe'] : [])], { cwd: repo, env: process.env, stdio: 'inherit' });
  process.exit(result.status ?? 1);
}
const src = resolve(process.env.RPC_PRIVACY_SRC || join(repo, 'block-verifier/src'));
const source = (name) => readFileSync(join(src, name), 'utf8');
const load = (name) => import(pathToFileURL(join(src, name)));
const privacy = await load('rpc-privacy.js');
const { createChain } = await load('chain.js');
const { createReport } = await load('report.js');
const { makeUi } = await load('index.js');
const { saveConfig } = await load('config.js');
const { t } = await load('i18n.js');
const temp = mkdtempSync(join(tmpdir(), 'coinu-rpc-privacy-'));
let failures = 0;
async function test(name, run) {
  try { await run(); console.log(`PASS ${name}`); }
  catch (error) { failures++; console.error(`FAIL ${name}: [${error.code || error.name}] ${error.message}`); }
}
function noKeys(text, keys) {
  for (const key of keys) assert.ok(!text.includes(key), `RPC credential leaked (${key})`);
}
const cases = [
  ['https://eth-mainnet.g.alchemy.com/v2/FAKE-ALCHEMY-KEY', 'https://eth-mainnet.g.alchemy.com/…', ['FAKE-ALCHEMY-KEY']],
  ['https://FAKE-USER:FAKE-PASSWORD@rpc.example.test:8545/FAKE-PATH?api=FAKE-QUERY#FAKE-FRAGMENT',
    'https://rpc.example.test:8545/…', ['FAKE-USER', 'FAKE-PASSWORD', 'FAKE-PATH', 'FAKE-QUERY', 'FAKE-FRAGMENT']],
  ['HTTPS://USER:FAKE-UPPER@RPC.EXAMPLE.TEST/v2/KEY', 'https://rpc.example.test/…', ['FAKE-UPPER']],
  ['wss://rpc.example.test/ws/FAKE-WS', 'wss://rpc.example.test/…', ['FAKE-WS']],
  ['https://rpc.example.test?token=FAKE-QUERY-ONLY', 'https://rpc.example.test/…', ['FAKE-QUERY-ONLY']],
  ['https://rpc.example.test#FAKE-FRAGMENT-ONLY', 'https://rpc.example.test/…', ['FAKE-FRAGMENT-ONLY']],
  ['http://[::1]:8545/FAKE-IPV6', 'http://[::1]:8545/…', ['FAKE-IPV6']],
  ['https://rpc.example.test/v2/FAKE%2FENCODED?token=FAKE%20QUERY#FAKE-FRAGMENT',
    'https://rpc.example.test/…', ['FAKE%2FENCODED', 'FAKE%20QUERY', 'FAKE-FRAGMENT']],
];
const endpoint = cases[0][0];
const docs = 'https://viem.sh/docs/contract/readContract';
const r2 = 'https://r2.bitcoinu.org/games/block4/summary.json';
function indexModule(text) {
  // 実 index の setupChain を偽 chain で動かす。プロンプト呼出箇所を固定する歯。
  const rewritten = text
    .replace("import { createChain } from './chain.js';", 'const createChain = globalThis.__RPC_TEST_CHAIN;')
    .replace(/^async function setupChain\(/m, 'export async function setupChain(')
    .replace(/from '(\.\.?\/[^']+)'/g, (_, name) => `from '${pathToFileURL(resolve(src, name)).href}'`);
  return import(`data:text/javascript;base64,${Buffer.from(rewritten + `\n// invocation ${indexModule.sequence++}`).toString('base64')}`);
}
indexModule.sequence = 0;

// makeUi の実 stdout/stderr と、readline の実出力・入力のこだまを同じ順で捕まえる。
async function withPromptTerminal(run, { nonInteractive = false, terminal = true, code = source('prompts.js') } = {}) {
  const input = new PassThrough(); input.isTTY = false;
  const chunks = [];
  const output = new Writable({ write(chunk, _encoding, done) { chunks.push(chunk.toString()); done(); } });
  output.isTTY = terminal; output.columns = 200;
  const stdoutWrite = process.stdout.write, stderrWrite = process.stderr.write;
  process.stdout.write = (...args) => output.write(...args);
  process.stderr.write = (chunk, encoding, done) => {
    chunks.push(chunk.toString());
    (typeof encoding === 'function' ? encoding : done)?.();
    return true;
  };
  globalThis.__RPC_TEST_TTY = { input, output };
  let prompts;
  try {
    code = code.replace("import { stdin as input, stdout as output } from 'node:process';",
      'const { input, output } = globalThis.__RPC_TEST_TTY;') + `\n// spacing ${withPromptTerminal.sequence++}`;
    const { createPrompts } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    const originalOutputWrite = output.write, originalErrorWrite = process.stderr.write;
    const listeners = input.listenerCount('data');
    prompts = createPrompts({ nonInteractive });
    if (nonInteractive) {
      assert.equal(output.write, originalOutputWrite, '非対話はstdoutを包まない');
      assert.equal(process.stderr.write, originalErrorWrite, '非対話はstderrを包まない');
    }
    const ui = makeUi(t('ja'), prompts, { nonInteractive });
    const screen = () => stripVTControlCharacters(chunks.join('')).replaceAll('\r', '');
    await run({ input, output, prompts, ui, screen, raw: () => Buffer.from(chunks.join('')) });
    prompts.close();
    assert.equal(output.write, originalOutputWrite, 'closeでstdoutを戻す');
    assert.equal(process.stderr.write, originalErrorWrite, 'closeでstderrを戻す');
    if (nonInteractive) assert.equal(input.listenerCount('data'), listeners, '非対話はstdinを開かない');
  } finally {
    prompts?.close(); input.destroy(); output.destroy();
    process.stdout.write = stdoutWrite; process.stderr.write = stderrWrite;
    delete globalThis.__RPC_TEST_TTY;
  }
}
withPromptTerminal.sequence = 0;

try {
  await test('RA-01 deep check/fact preserve inputs without recursion', () => {
    const report = createReport({ rpcUrls: [endpoint] });
    const deep = JSON.parse('['.repeat(4000) + ']'.repeat(4000));
    const params = { published: deep, diagnostic: endpoint };
    report.check('deep', 'fail', params); report.fact('deep', deep);
    assert.equal(report.get('deep').params, params);
    assert.equal(report.getFact('deep'), deep);
    assert.equal(report.get('deep').params.diagnostic, endpoint);
  });
  await test('RA-02 fact reference includes finally cleanup anomaly', () => {
    const report = createReport(); const anomalies = [];
    report.fact('stageC.anomalies', anomalies);
    anomalies.push('Evidence spool cleanup failed: EBUSY');
    let screen = '';
    report.renderSummary({ t: t('en'), println: (s = '') => { screen += s + '\n'; } }, { blockNum: 7, data: {} });
    assert.equal(report.getFact('stageC.anomalies'), anomalies);
    assert.ok(screen.includes('Evidence spool cleanup failed: EBUSY'));
  });
  await test('RA-03 save and language-only save preserve prior custom RPC bytes', () => {
    const file = join(temp, 'verifier-config.json');
    const customRpcs = [endpoint, 'https://rpc.ankr.com/eth', 'https://public.example.test'];
    saveConfig({ lang: 'ja', customRpcs }, file); saveConfig({ lang: 'en' }, file);
    assert.deepEqual(JSON.parse(readFileSync(file)).customRpcs, customRpcs);
    const head = execFileSync('git', ['show', '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7:block-verifier/src/config.js'], { cwd: repo, encoding: 'utf8' });
    return import(`data:text/javascript;base64,${Buffer.from(head).toString('base64')}`).then(({ saveConfig: saveHead }) => {
      const other = join(temp, 'head-config.json');
      saveHead({ lang: 'ja', customRpcs }, other); saveHead({ lang: 'en' }, other);
      assert.deepEqual(readFileSync(file), readFileSync(other));
    });
  });
  await test('RA-05 only registered RPCs are redacted; public userinfo stays byte-exact', () => {
    const publicOrigin = 'https://public.example.test/';
    assert.equal(privacy.displayRpcUrl(publicOrigin), publicOrigin);
    const text = `${docs}\n${r2}\n${r2}?contact=user@example.test\n${docs}/path@revision\n${publicOrigin}\nhttps://unknown.test/public/path`;
    assert.equal(privacy.redactRpcText(text, [publicOrigin]), text);
    const unknown = 'https://FAKE-U:FAKE-P@rpc.unknown.test/v2/FAKE-UNKNOWN?k=FAKE-Q';
    const safe = privacy.redactRpcText(`${text}\n${unknown}`);
    assert.equal(safe, `${text}\n${unknown}`);
    const ftp = 'ftp://user:FAKE-FTP@archive.test/private';
    assert.equal(privacy.redactRpcText(ftp), ftp);
    assert.equal(privacy.redactRpcText(`(published: ${endpoint})`, [endpoint]), `(published: ${cases[0][1]})`);
    assert.equal(privacy.redactRpcText('https://FAKE-HOST.rpc.test/v2/KEY', ['https://FAKE-HOST.rpc.test/v2/KEY']),
      'https://fake-host.rpc.test/…');
  });
  await test('RF-01 long output uses literal matches only and has a no-secret fast path', () => {
    // 任意の文を走査する正規表現を復活させる変異は、時間切れを待たず検出する。
    const replace = String.prototype.replace, replaceAll = String.prototype.replaceAll;
    const regexpExec = RegExp.prototype.exec;
    let literalCalls = 0;
    RegExp.prototype.exec = function (value) {
      assert.ok(String(value).length < 10000, 'no regexp may scan arbitrary long output');
      return regexpExec.call(this, value);
    };
    String.prototype.replace = function (search, ...args) {
      literalCalls++;
      assert.equal(typeof search, 'string', 'no regexp on arbitrary output');
      return replace.call(this, search, ...args);
    };
    String.prototype.replaceAll = function (search, ...args) {
      literalCalls++;
      assert.equal(typeof search, 'string', 'no regexp on arbitrary output');
      return replaceAll.call(this, search, ...args);
    };
    try {
      const value = 'a'.repeat(2_000_000);
      const start = performance.now();
      assert.equal(privacy.redactRpcText(value), value);
      assert.equal(privacy.redactRpcText(value, ['https://public.example.test']), value);
      assert.equal(literalCalls, 0, 'no-secret fast path must do no output replacement');
      assert.equal(privacy.redactRpcText(value + endpoint, [endpoint]), value + cases[0][1]);
      assert.ok(performance.now() - start < 1000, '2M chars must finish under 1s');
    } finally { String.prototype.replace = replace; String.prototype.replaceAll = replaceAll; RegExp.prototype.exec = regexpExec; }
  });
  await test('RF-02 invalid and under-16-character spellings never rewrite output', () => {
    for (const url of ['1', 'e', 'l', '123456789012345', 'FAKE-INVALID-RPC-OVER-16', 'rpc.example.test/v2/FAKE-NO-SCHEME', 'http://a.test/p']) {
      const value = `root: 0x1111eeee; ${url}; ${JSON.stringify({ level: false, schemaVersion: 1 })}`;
      assert.equal(privacy.redactRpcText(value, [url]), value);
    }
    assert.equal(privacy.displayRpcUrl('1'), privacy.INVALID_RPC_URL);
    const sixteen = 'http://a.test/pp';
    assert.equal(sixteen.length, 16);
    assert.equal(privacy.redactRpcText(sixteen, [sixteen]), 'http://a.test/…');
  });
  await test('RA-06 message, early-access stack, causes and util.inspect at UI/JSON boundaries', () => {
    for (const [url, expected, keys] of cases) {
      assert.equal(privacy.displayRpcUrl(url), expected);
      const error = new Error(`Request failed: ${url}`, { cause: new Error(`URL: ${url}`) });
      const earlyStack = error.stack; const causeStack = error.cause.stack;
      const originalMessage = error.message;
      let screen = '';
      const out = process.stdout.write, err = process.stderr.write;
      process.stdout.write = process.stderr.write = (s) => { screen += s; return true; };
      try {
        const cfg = { rpcUrls: [url], rpcPresets: [], customRpcs: [] };
        const ui = makeUi(t('en'), {}, cfg);
        for (const value of [error.message, earlyStack, causeStack, inspect(error, { depth: 10 }), JSON.stringify(JSON.stringify({ error: url }))]) {
          ui.println(value); ui.warn(value);
        }
        // 保存済み・既定リスト、後から対話で追加されたRPCも同じUIに反映する。
        cfg.rpcUrls = []; cfg.customRpcs = [url]; ui.warn(error.message);
        cfg.customRpcs = []; cfg.rpcPresets = [{ url }]; ui.println(error.message);
      } finally { process.stdout.write = out; process.stderr.write = err; }
      noKeys(screen, keys); assert.ok(screen.includes(expected));
      const original = { reason: originalMessage, nested: [{ [url]: `at ${url}` }], docs, r2 };
      // report JSON を書く出口にも同じ文字列処理。report の中身は生の参照を保持する。
      const report = createReport(); report.check('error', 'fail', original); report.fact('diagnostic', original);
      const json = privacy.redactRpcText(JSON.stringify({ checks: report.list(), fact: report.getFact('diagnostic') }), [url]);
      const file = join(temp, 'report.json'); writeFileSync(file, json);
      noKeys(readFileSync(file, 'utf8'), keys); assert.ok(JSON.parse(json).fact.docs === docs);
      assert.equal(report.get('error').params, original); assert.equal(error.message, originalMessage);
      assert.equal(error.stack, earlyStack); assert.equal(error.cause.stack, causeStack);
    }
  });
  await test('RF-01 registered raw/trim/href and JSON escapes use literal replacement', () => {
    const raw = '  HTTPS://USER:FAKE-PASS@RPC.EXAMPLE.TEST:443/v2/FAKE-RAW?x="quote"#hash  ';
    const expected = 'https://rpc.example.test/…';
    for (let form of [raw, raw.trim(), new URL(raw).href]) {
      for (let depth = 0; depth < 3; depth++) {
        assert.equal(privacy.redactRpcText(form, [raw]), expected);
        form = JSON.stringify(form).slice(1, -1);
      }
    }
    const dollar = 'https://$&.rpc.test/v2/FAKE-LITERAL';
    assert.equal(privacy.redactRpcText(dollar, [dollar]), 'https://$&.rpc.test/…');
    // WHATWG URLが受け入れる引用符入りhostも、JSONの鍵/値/入れ子の文字列を壊さない。
    for (const raw of ['https://a"b.test/v2/FAKE-JSON-KEY', 'https://rpc.test/a\\b/FAKE-JSON-KEY',
      ' \tHTTPS://u:p@RPC.TEST:443/v2/FAKE-JSON-KEY?x="quote"\t ', 'https://rpc.test/a\nb/FAKE-JSON-KEY']) {
      for (let depth = 0, value = { [raw]: raw }; depth < 2; depth++, value = JSON.stringify(value)) {
        const encoded = privacy.redactRpcText(JSON.stringify(value), [raw]);
        JSON.parse(encoded); assert.ok(!encoded.includes('FAKE-JSON-KEY'));
      }
    }
  });
  await test('RA-07 hidden RPC reverts leave errors/ABI untouched', async () => {
    const error = new Error(`execution reverted at ${endpoint}`); void error.stack;
    let inspections = 0;
    Object.defineProperty(error, 'abi', { get() { inspections++; throw new Error('must not inspect ABI'); } });
    const chain = createChain({ rpcUrls: [endpoint], chainIdExpected: 31337, contracts: {} }, null,
      custom({ request: async () => { throw error; } }, { retryCount: 0 }));
    const before = Object.getOwnPropertyDescriptors(error);
    await assert.rejects(chain.chainId());
    assert.equal(inspections, 0); assert.equal(error.message, before.message.value);
    assert.equal(error.stack, before.stack.get ? before.stack.get.call(error) : before.stack.value);
  });
  await test('HTTP/fallback retain configured URL; viem errors redact only on output', async () => {
    for (const [url, , keys] of cases) {
      const cfg = { rpcUrls: [url], chainIdExpected: 31337, contracts: {} };
      const transport = fallback([http(url, {
        retryCount: 0,
        fetchFn: async () => { throw new Error(`fake upstream at ${url}`); },
      })], { retryCount: 0 });
      const chain = createChain(cfg, null, transport);
      await assert.rejects(chain.chainId(), (error) => {
        assert.deepEqual(cfg.rpcUrls, [url]);
        assert.equal(chain.rpcUrl, url);
        const text = [error.message, error.stack, inspect(error, { depth: 10 })].join('\n');
        noKeys(privacy.redactRpcText(text, [url]), keys);
        return true;
      });
    }
  });
  await test('RA-04 interactive setup caller hides input/history and saved option', async () => {
    globalThis.__RPC_TEST_CHAIN = () => ({ chainId: async () => 31337, probeArchive: async () => ({ status: 'available' }) });
    const { setupChain } = await indexModule(source('index.js'));
    const input = new PassThrough(); input.isTTY = true; input.setRawMode = () => {};
    let screen = '';
    const output = new Writable({ write(chunk, encoding, done) { screen += chunk.toString(); done(); } });
    output.isTTY = true; output.columns = 120;
    globalThis.__RPC_TEST_TTY = { input, output };
    const promptSource = source('prompts.js').replace("import { stdin as input, stdout as output } from 'node:process';",
      'const { input, output } = globalThis.__RPC_TEST_TTY;');
    const { createPrompts } = await import(`data:text/javascript;base64,${Buffer.from(promptSource).toString('base64')}`);
    const realPrompts = createPrompts();
    const prompts = {
      choice: async (_message, items) => { screen += items.join('\n'); return items.length - 1; },
      text: async (message, options) => {
        const answer = realPrompts.text(message, options); input.write(endpoint + '\r'); return answer;
      },
    };
    const cfg = { rpcPresets: [], customRpcs: [cases[2][0]], savedConfigPath: join(temp, 'interactive.json'), chainIdExpected: 31337 };
    const ui = { t: t('en'), println: (s) => { screen += s; }, warn: (s) => { screen += s; }, section() {} };
    try {
      await setupChain(cfg, ui, prompts);
      const next = realPrompts.text('next'); input.write('\u001b[AVISIBLE\r'); assert.equal(await next, 'VISIBLE');
      noKeys(screen, [...cases[0][2], ...cases[2][2]]);
      assert.deepEqual(JSON.parse(readFileSync(cfg.savedConfigPath)).customRpcs, [cases[2][0], endpoint]);
    } finally { realPrompts.close(); delete globalThis.__RPC_TEST_TTY; }
  });
  await test('RA-09 synchronous createChain construction errors remain fatal', async () => {
    const sentinel = new Error('construction failure'); globalThis.__RPC_TEST_CHAIN = () => { throw sentinel; };
    const { tryConnect } = await indexModule(source('index.js'));
    await assert.rejects(tryConnect({}, { t: t('en'), println() {}, warn() {} }, [endpoint]), (e) => e === sentinel);
  });
  await test('RF-04 non-TTY stdin preserves prior pipe behavior for both stdout modes', async () => {
    for (const terminal of [false, true]) {
      const input = new PassThrough(); input.isTTY = false;
      let screen = '';
      const output = new Writable({ write(chunk, _encoding, done) { screen += chunk; done(); } });
      output.isTTY = terminal; output.columns = 120;
      globalThis.__RPC_TEST_TTY = { input, output };
      const code = source('prompts.js').replace("import { stdin as input, stdout as output } from 'node:process';",
        'const { input, output } = globalThis.__RPC_TEST_TTY;') + `\n// non-TTY ${terminal}`;
      const { createPrompts } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
      const prompts = createPrompts();
      try {
        const answer = prompts.text('RPC URL:', { secret: true }); input.write(endpoint + '\n');
        assert.equal(await answer, endpoint); assert.ok(!screen.includes(endpoint));
        const next = prompts.text('next'); input.write((terminal ? '\u001b[A' : '') + 'VISIBLE\n');
        assert.equal(await next, 'VISIBLE'); assert.ok(!screen.includes(endpoint), 'secret must not survive in history');
      } finally { prompts.close(); delete globalThis.__RPC_TEST_TTY; }
    }
  });
  await test('SP-01 publicnode explanation before choice', async () => {
    // 実 setupChain/makeUi/翻訳/説明/choice を通す。接続だけを代役にして通信しない。
    const { setupChain } = await load('index.js');
    const { publicnodeExplanation } = await load('verification-areas.js');
    await withPromptTerminal(async ({ input, prompts, ui, screen }) => {
      const cfg = { flags: {}, rpcUrls: null, rpcPresets: [{ url: 'https://ethereum-rpc.publicnode.com' }] };
      const chain = {};
      let nextPrompt = 0;
      const nodeQuestion = ui.t('main.rpcPrompt'), publicQuestion = ui.t('main.publicnodePrompt');
      const questions = [nodeQuestion, publicQuestion];
      const answer = () => {
        if (nextPrompt < questions.length && screen().includes(questions[nextPrompt]) && screen().endsWith('> ')) {
          nextPrompt++;
          input.write('1\n');
        }
      };
      // setupChain は await を挟むため、質問の表示を待って1問ずつ答える。
      const timer = setInterval(answer, 1);
      try {
        assert.equal(await setupChain(cfg, ui, prompts, async (_cfg, _ui, urls) => {
          assert.deepEqual(urls, [cfg.rpcPresets[0].url]); return chain;
        }), chain);
      } finally { clearInterval(timer); }
      const section = (title) => `\n--------\n\n【${title}】\n`;
      const options = (keys) => keys.map((key, i) => `  ${i + 1}) ${ui.t(key)}\n`).join('');
      assert.equal(screen(), section(ui.t('main.sectionNode')) + nodeQuestion + '\n'
        + options(['main.rpcPublicnode', 'main.rpcAlchemy', 'main.rpcInfura', 'main.rpcCustomOption']) + '> 1\n'
        + section(ui.t('main.publicnodeTitle')) + publicnodeExplanation(ui.t).join('\n') + '\n\n'
        + publicQuestion + '\n' + options(['main.publicnodeContinue', 'main.publicnodeReselect']) + '> 1\n');
      assert.equal(nextPrompt, 2);
    });
  });
  await test('SP-02 heading immediately before question', async () => {
    await withPromptTerminal(async ({ input, prompts, ui, screen }) => {
      ui.section('ノード選択');
      const pending = prompts.choice('選んでください:', ['そのまま', '選び直す']);
      assert.equal(screen(), '\n--------\n\n【ノード選択】\n選んでください:\n  1) そのまま\n  2) 選び直す\n> ');
      input.write('\n'); assert.equal(await pending, 0);
      // 見出しは分割書込でも行として認識し、見出し以外の文字があれば説明扱い。
      process.stdout.write('【分割'); process.stdout.write(Buffer.from('見出し】\r\n'));
      const text = prompts.text('入力:');
      assert.ok(screen().endsWith('【分割見出し】\n入力: '));
      input.write('abc\n'); assert.equal(await text, 'abc');
      ui.println('【見出し】の説明');
      const yes = prompts.yesNo('続ける？');
      assert.ok(screen().endsWith('【見出し】の説明\n\n続ける？ [Y/n] '));
      input.write('n\n'); assert.equal(await yes, false);
    });
  });
  await test('SP-03 blank line is not doubled', async () => {
    await withPromptTerminal(async ({ input, prompts, ui, screen }) => {
      ui.println('説明'); ui.println();
      const pending = prompts.text('入力:', { defaultValue: '既定' });
      assert.equal(screen(), '説明\n\n入力: [既定] ');
      input.write('\n'); assert.equal(await pending, '既定');
    });
  });
  await test('SP-04 stderr warning before question', async () => {
    await withPromptTerminal(async ({ input, prompts, ui, screen }) => {
      ui.println(); ui.warn('注意');
      const pending = prompts.yesNo('続ける？', { defaultValue: false });
      assert.equal(screen(), '\n⚠ 注意\n\n続ける？ [y/N] ');
      input.write('y\n'); assert.equal(await pending, true);
      // 逆順ではstdoutの空行/見出しが最後。stderrだけを別に覚える実装は不可。
      ui.warn('前の警告'); ui.println();
      const number = prompts.number('番号:', { defaultValue: 2 });
      assert.ok(screen().endsWith('⚠ 前の警告\n\n番号: [2] '));
      input.write('\n'); assert.equal(await number, 2);
      ui.warn('前の警告'); ui.section('次の見出し');
      const text = prompts.text('入力:');
      assert.ok(screen().endsWith('【次の見出し】\n入力: '));
      input.write('\n'); assert.equal(await text, '');
    });
  });
  await test('SP-05 echoed answers and retries precede the next question', async () => {
    await withPromptTerminal(async ({ input, prompts, ui, screen }) => {
      const first = prompts.text('最初:');
      assert.equal(screen(), '最初: ');
      input.write('abc\n'); assert.equal(await first, 'abc');
      const second = prompts.number('番号:', { defaultValue: 2, min: 1, max: 3 });
      assert.equal(screen(), '最初: abc\n\n番号: [2] ');
      input.write('4\n'); await new Promise(setImmediate);
      assert.ok(screen().endsWith('番号: [2] 4\n\n番号: [2] '));
      input.write('3\n'); assert.equal(await second, 3);
      const choice = prompts.choice('選択:', ['A', 'B'], { defaultIndex: 1 });
      assert.ok(screen().endsWith('番号: [2] 3\n\n選択:\n  1) A\n  2) B\n> '));
      input.write('x\n'); await new Promise(setImmediate);
      assert.ok(screen().endsWith('> x\n\n> '));
      input.write('\n'); assert.equal(await choice, 1);
      const yes = prompts.yesNo('確認？');
      input.write('maybe\n'); await new Promise(setImmediate);
      assert.ok(screen().endsWith('確認？ [Y/n] maybe\n\n確認？ [Y/n] '));
      input.write('\n'); assert.equal(await yes, true);
      ui.println('説明');
      const enter = prompts.pressEnter('Enter');
      assert.ok(screen().endsWith('説明\n\nEnter '));
      input.write('\n'); await enter;
    });
  });
  await test('SP-06 non-interactive output is byte-exact against the starting implementation', async () => {
    const baseline = execFileSync('git', ['show', 'f9c40aba5a548f730f29503c8c10ab452107f37d:block-verifier/src/prompts.js'],
      { cwd: repo, encoding: 'utf8' });
    const { loadConfig } = await load('config.js');
    const { emitNonInteractiveOutcome } = await load('index.js');
    for (const flag of ['--non-interactive', '--yes']) {
      const { nonInteractive } = loadConfig([flag]);
      assert.equal(nonInteractive, true);
      const capture = async (code) => {
        let bytes;
        await withPromptTerminal(async ({ prompts, ui, raw }) => {
          ui.println('説明'); ui.warn('注意'); ui.section('非表示');
          assert.equal(await prompts.choice('選択:', ['A', 'B'], { defaultIndex: 1 }), 1);
          assert.equal(await prompts.yesNo('確認？', { defaultValue: false }), false);
          assert.equal(await prompts.number('番号:', { defaultValue: 7 }), 7);
          assert.equal(await prompts.text('入力:', { defaultValue: '既定' }), '既定');
          assert.equal(await prompts.text('秘密:', { secret: true, defaultValue: 'FAKE-SECRET' }), 'FAKE-SECRET');
          assert.equal(await prompts.pressEnter('Enter'), undefined);
          // 本物の機械可読行と終了コードも、通常・一部未検証・不合格・異常で固定する。
          for (const [category, exitCode] of [['full', 0], ['partial', 1], ['fail', 2], ['fatal', 3]]) {
            const report = createReport();
            report.check('check.stageA.rootMatch', category === 'fail' ? 'fail' : 'pass');
            const outcome = { report, stopped: category === 'partial', fatal: category === 'fatal' };
            assert.deepEqual(emitNonInteractiveOutcome(ui, outcome), { category, exitCode });
          }
          bytes = raw();
        }, { nonInteractive, code });
        return bytes;
      };
      const actual = await capture(source('prompts.js'));
      assert.deepEqual(actual, await capture(baseline), `${flag}: 起点と全バイト一致`);
      assert.deepEqual(actual, Buffer.from('説明\n⚠ 注意\n' + ['full', 'partial', 'fail', 'fatal']
        .map((category) => `##CHECK check.stageA.rootMatch ${category === 'fail' ? 'fail' : 'pass'}\n##RESULT ${category}\n`).join('')));
    }
  });
  await test('SP-07 hidden and piped answers leave one blank line before the next question', async () => {
    for (const terminal of [true, false]) await withPromptTerminal(async ({ input, prompts, ui, screen }) => {
      ui.println('説明');
      const secret = prompts.text('RPC_KEY:', { secret: true });
      assert.equal(screen(), '説明\n\nRPC_KEY: ');
      input.write('FAKE-SECRET\n'); assert.equal(await secret, 'FAKE-SECRET');
      const next = prompts.text('次:');
      assert.equal(screen(), '説明\n\nRPC_KEY: \n\n次: ');
      input.write('visible\n'); assert.equal(await next, 'visible');
      assert.ok(!screen().includes('FAKE-SECRET'));
    }, { terminal });
  });
  await test('RF-02 invalid connection failure uses a fixed message only at that exit', async () => {
    const invalid = 'FAKE-NO-SCHEME-PRIVATE-INPUT';
    globalThis.__RPC_TEST_CHAIN = () => ({ chainId: async () => { throw new Error(`failed: ${invalid}`); } });
    const { tryConnect } = await indexModule(source('index.js'));
    let screen = '';
    assert.equal(await tryConnect({}, { t: t('en'), println: s => { screen += s; }, warn: s => { screen += s; } }, [invalid]), null);
    assert.ok(screen.includes(privacy.INVALID_RPC_URL)); assert.ok(!screen.includes(invalid));
  });
  await test('RA-04 top-level fatal redacts --rpc and loaded saved/config RPCs', () => {
    // CLI 本体を起動。接続を偽 chain に置換し、実 catch と exit 3 を通す。
    const tree = join(temp, 'fatal-tree'); const bv = join(tree, 'block-verifier');
    mkdirSync(bv, { recursive: true }); cpSync(src, join(bv, 'src'), { recursive: true });
    symlinkSync(join(repo, 'node_modules'), join(tree, 'node_modules'));
    symlinkSync(join(repo, 'Hardhat'), join(tree, 'Hardhat'));
    symlinkSync(join(repo, 'block-verifier/vendor'), join(bv, 'vendor'));
    writeFileSync(join(tree, 'package.json'), '{"type":"module"}');
    const fake = `const createChain = (cfg) => { const url = cfg.rpcUrls[0]; const e = new Error('fatal ' + url + ' Docs: ${docs} R2: ${r2}', { cause: new Error('cause ' + url) }); void e.stack; throw e; };`;
    let cli = source('index.js').replace("import { createChain } from './chain.js';", fake);
    // RA-09 が未修正でも最上位 catch を実行するため、同じ cfg の次の出口から投げる。
    cli = cli.replace('const chain = await setupChain(cfg, ui, prompts);', 'const chain = createChain(cfg);');
    writeFileSync(join(bv, 'src/index.js'), cli);
    for (const url of [endpoint, cases[1][0], cases[3][0]]) {
      for (const mode of ['flag', 'config', 'saved']) {
        const config = join(temp, 'fatal-config.json'); writeFileSync(config, JSON.stringify({ rpcUrls: [url] }));
        writeFileSync(join(temp, 'verifier-config.json'), JSON.stringify(mode === 'saved' ? { customRpcs: [url] } : {}));
        // saved custom URL は選択前の構築例外の文に出るものを模す。
        const args = mode === 'flag' ? ['--rpc', url] : mode === 'config' ? ['--config', config] : [];
        const savedCli = mode === 'saved' ? cli.replace('const url = cfg.rpcUrls[0];', 'const url = cfg.customRpcs[0];') : cli;
        writeFileSync(join(bv, 'src/index.js'), savedCli);
        const result = spawnSync(process.execPath, [join(bv, 'src/index.js'), '--lang', 'en', '--non-interactive', '--block', '0', ...args],
          { cwd: temp, encoding: 'utf8', timeout: 15000 });
        assert.equal(result.status, 3, result.stderr);
        noKeys(result.stdout + result.stderr, cases.find(([raw]) => raw === url)[2]);
        assert.ok(result.stderr.includes(docs)); assert.ok(result.stderr.includes(r2));
      }
    }
  });
  await test('RB-01 redact full params before 300-character truncation (384 real viem cases)', () => {
    execFileSync(process.execPath, [join(import.meta.dirname, 'rpc-privacy-truncation.mjs')], {
      env: { ...process.env, RPC_PRIVACY_SRC: src }, timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'],
    });
  });
  await test('RB-05 compat temporary evidence cleanup and explicit retention', () => {
    execFileSync(process.execPath, [join(import.meta.dirname, 'rpc-privacy-compat-cleanup.mjs')], { timeout: 10000 });
  });
  await test('RB-06 malformed candidate must not erase a valid candidate 401 failure', async () => {
    const invalid = 'FAKE-NO-SCHEME-PRIVATE-INPUT';
    globalThis.__RPC_TEST_CHAIN = () => ({ chainId: async () => { throw new Error(`HTTP request failed. Status: 401. URL: ${endpoint}`); } });
    const { tryConnect } = await indexModule(source('index.js'));
    let screen = '';
    const cfg = { rpcUrls: [invalid, endpoint] };
    const out = process.stdout.write, err = process.stderr.write;
    process.stdout.write = process.stderr.write = (s) => { screen += s; return true; };
    try {
      assert.equal(await tryConnect(cfg, makeUi(t('en'), {}, cfg), cfg.rpcUrls), null);
      assert.ok(screen.includes(t('en')('reason.rpcRequestFailed')), 'valid candidate failure is concise');
      noKeys(screen, [invalid, ...cases[0][2]]);
      screen = '';
      assert.equal(await tryConnect(cfg, makeUi(t('en'), {}, cfg), []), null);
      assert.ok(screen.includes(t('en')('reason.rpcRequestFailed')), 'no malformed candidate retains concise failure');
    } finally { process.stdout.write = out; process.stderr.write = err; }
  });
  await test('RB-06 real viem identifies the failing candidate in mixed URL lists', async () => {
    const invalid = 'FAKE-NO-SCHEME-PRIVATE-INPUT';
    for (const urls of [[invalid, endpoint], [endpoint, invalid], ['https', endpoint], ['1', endpoint], ['e', endpoint]]) {
      globalThis.__RPC_TEST_CHAIN = (cfg, ui) => createChain(cfg, ui, fallback(urls.map((url) => http(url, {
        retryCount: 0, fetchFn: async () => {
          if (url !== endpoint) throw new Error(`Cannot parse ${url}`);
          return new Response('unauthorized', { status: 401 });
        },
      })), { retryCount: 0 }));
      const { tryConnect } = await indexModule(source('index.js'));
      let screen = '';
      const out = process.stdout.write, err = process.stderr.write;
      process.stdout.write = process.stderr.write = (s) => { screen += s; return true; };
      try {
        const cfg = { rpcUrls: urls, chainIdExpected: 1 };
        assert.equal(await tryConnect(cfg, makeUi(t('en'), {}, cfg), urls), null);
        if (urls.at(-1) === endpoint) assert.ok(screen.includes(t('en')('reason.rpcRequestFailed')));
        else assert.ok(screen.includes(privacy.INVALID_RPC_URL));
        noKeys(screen, [invalid, ...cases[0][2]]);
      } finally { process.stdout.write = out; process.stderr.write = err; }
    }
  });
  await test('RA-04 起点コミットのデータ同一性と非RPC診断の保持: report JSON, summary screen/logs and non-RPC diagnostics', async () => {
    const headReport = execFileSync('git', ['show', '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7:block-verifier/src/report.js'], { cwd: repo, encoding: 'utf8' })
      .replace(/from '(\.\.?\/[^']+)'/g, (_, name) => `from '${pathToFileURL(resolve(src, name)).href}'`);
    const { createReport: createHeadReport } = await import(`data:text/javascript;base64,${Buffer.from(headReport).toString('base64')}`);
    function capture(factory, safe) {
      const report = factory(); const anomalies = [`Docs: ${docs}`, `R2: ${r2}`];
      report.check('check.main.fatal', 'fail', { error: `R2 fetch failed: ${r2} Docs: ${docs}` });
      report.fact('stageC.anomalies', anomalies); anomalies.push('Evidence spool cleanup failed: EBUSY');
      let output = ''; const ui = { t: t('en'), println: (s = '') => { output += safe(s) + '\n'; } };
      report.renderSummary(ui, { blockNum: 7, data: {} });
      return [output, safe(JSON.stringify({ checks: report.list(), anomalies: report.getFact('stageC.anomalies') }))];
    }
    const [output, data] = capture(createReport, (s) => privacy.redactRpcText(s));
    const [baseline, baselineData] = capture(createHeadReport, (s) => s);
    assert.equal(data, baselineData);
    assert.ok(output.includes(t('en')('summary.coverageVerified')));
    assert.ok(output.includes(t('en')('summary.coverageUnverified')));
    // 確認範囲の前置きとFIX12で削除した未到達節以外は、非RPC診断を全バイト比較する。
    const start = output.indexOf(t('en')('summary.coverageVerified'));
    const end = output.indexOf(t('en')('summary.counts', {pass:0,warn:0,fail:1,skip:0,unrun:114}));
    assert.ok(start >= 0 && end > start);
    // FIX4: fatalの全行伝播を除去したため、未到達②③は実際のstoppedに合わせる。
    let expectedBaseline = baseline;
    for (const id of ['notVerified.selection', 'notVerified.results']) {
      const before = t('en')(id, { reason: t('en')('reason.failed') });
      assert.ok(expectedBaseline.includes(before));
      expectedBaseline = expectedBaseline.replace(before, t('en')(id, { reason: t('en')('reason.stopped') }));
    }
    const { CHECK_INVENTORY } = await load('check-inventory.js');
    const unrun = CHECK_INVENTORY.filter((id) => id !== 'check.main.fatal');
    const unrunSection = '\n' + t('en')('summary.unrunHeader', { count: unrun.length })
      + '\n' + unrun.map((id) => `  ◌ ${id}\n`).join('');
    assert.ok(expectedBaseline.includes(unrunSection), '起点の未到達節を正確に特定する');
    expectedBaseline = expectedBaseline.replace(unrunSection, '');
    assert.ok(!output.includes(t('en')('summary.unrunHeader', { count: unrun.length })) && !output.includes('  ◌ '));
    // SUMMARY-ZKP: 起点との差には、未検証欄の先頭に追加する⓪の1行だけも含める。
    const pendingHeader = t('en')('summary.notVerifiedHeader') + '\n';
    assert.equal(expectedBaseline.split(pendingHeader).length - 1, 1, '起点の未検証見出しを正確に特定する');
    expectedBaseline = expectedBaseline.replace(pendingHeader, pendingHeader
      + `  ${t('en')('notVerified.zk', { reason: t('en')('reason.stopped') })}\n`);
    const { VERIFICATION_AREAS } = await load('verification-areas.js');
    for (const { area } of VERIFICATION_AREAS) {
      const row = `  ${t('en')(`summary.area.${area}`)}: `;
      assert.ok(output.slice(start, end).includes(row + t('en')('summary.areaUnverified', { reason: t('en')('reason.stopped') })),
        `未到達のある${area}を未検証として表示する`);
      assert.ok(!output.slice(start, end).split(t('en')('summary.coverageUnverified'))[0].includes(row));
    }
    assert.equal(output.slice(0, start) + output.slice(end), expectedBaseline);
  });
} finally { rmSync(temp, { recursive: true, force: true }); delete globalThis.__RPC_TEST_CHAIN; }
if (failures) process.exitCode = 1;
else console.log('RPC privacy unit: PASS');
