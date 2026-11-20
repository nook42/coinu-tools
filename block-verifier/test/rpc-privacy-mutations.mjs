// 共有ツリーは変えず、src の写しに変異を置く。
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
const repo = resolve(import.meta.dirname, '../..');
const temp = mkdtempSync(join(tmpdir(), 'coinu-rpc-mutants-'));
const specs = [
  ['input-echo', 'index.js', "ui.t('main.rpcCustomUrl'), { secret: true }", "ui.t('main.rpcCustomUrl')", 'interactive setup'],
  ['fatal-raw', 'index.js', 'redactRpcText(e?.stack || e, configRpcUrls(activeRpcConfig))', 'e?.stack || e', 'top-level fatal'],
  ['check-fact-recursion', 'report.js', 'checks.set(id, { status, params });',
    'checks.set(id, { status, params: privacyCopy(params) });', 'deep check/fact'],
  ['fact-copy', 'report.js', 'facts.set(name, value);', 'facts.set(name, structuredClone(value));', 'fact reference'],
  ['raw-url', 'rpc-privacy.js', 'return hasPrivateRpcParts(url) ? `${url.protocol}//${url.host}/…` : String(raw);', 'return raw;', 'early-access stack'],
  ['ui-raw', 'index.js', "const safe = (value) => redactRpcText(value, configRpcUrls(cfg));", 'const safe = (value) => value;', 'early-access stack'],
  ['broad-url', 'rpc-privacy.js', '  if (replacements.size === 0)', '  text = text.replace(/https?:\\/\\/[^\\s]+/g, (url) => displayRpcUrl(url));\n  if (replacements.size === 0)', 'only registered RPCs'],
  ...['public-differences', 'submission-selection', 'writer-provenance'].map((name) => [
    `diagnostic-${name}`, 'emergency.js',
    `capture.set('_emergency/${name}.json', diagnosticBytes({`,
    `capture.set('_emergency/${name}.json', bytesOfJson({`, `RF-03 ${name}`, 'q24',
  ]),
  ['diagnostic-replacer', 'emergency.js', "Buffer.from(redactRpcText(bytesOfJson(value).toString('utf8'), rpcUrls))",
    "Buffer.from(JSON.stringify(value, (_key, item) => typeof item === 'string' ? redactRpcText(item, rpcUrls) : item))", 'RB-03', 'q24'],
  ['redact-after-truncate', 'report.js', '  s = redactText(s);', '', 'RB-01'],
  ['short-spelling', 'rpc-privacy.js', 'if (form.length < 16) continue;', '', 'under-16-character'],
  ['invalid-registration', 'rpc-privacy.js', '    const url = parseRpcUrl(raw);',
    '    if (!parseRpcUrl(raw)) { text = text.replaceAll(raw, INVALID_RPC_URL); continue; }\n    const url = parseRpcUrl(raw);', 'under-16-character'],
  ['stdin-vs-stdout', 'prompts.js', 'if (secret && input.isTTY)', 'if (secret && iface.terminal && input.isTTY)', 'stdoutパイプでもstdinはraw', 'pty'],
  ['job-control', 'prompts.js', "if (process.platform !== 'win32') reader.on('SIGTSTP', suspend);", '', 'fgでrawに復帰', 'pty'],
  ['s1', 'prompts.js', "if (lastLineKind === 'text')", 'if (false)', 'SP-01 publicnode explanation before choice', 'spacing'],
  ['s2', 'prompts.js', "if (lastLineKind === 'text')", "if (lastLineKind !== 'empty')", 'SP-02 heading immediately before question', 'spacing'],
  ['s3', 'prompts.js', "if (lastLineKind === 'text')", "if (lastLineKind !== 'heading')", 'SP-03 blank line is not doubled', 'spacing'],
  ['s4', 'prompts.js', '[output, process.stderr]', '[output]', 'SP-04 stderr warning before question', 'spacing'],
];
const selected = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1];
const spacingOnly = process.argv.includes('--spacing');
const probe = process.argv.includes('--probe');
let failures = 0;
try {
  for (const [name, file, from, to, expected, suite] of specs.filter(([name, , , , , suite]) =>
    (!selected || selected === name) && (!spacingOnly || suite === 'spacing'))) {
    const tree = join(temp, name); const bv = join(tree, 'block-verifier'); const src = join(bv, 'src');
    mkdirSync(bv, { recursive: true }); cpSync(join(repo, 'block-verifier/src'), src, { recursive: true });
    symlinkSync(join(repo, 'node_modules'), join(tree, 'node_modules'));
    symlinkSync(join(repo, 'Hardhat'), join(tree, 'Hardhat'));
    symlinkSync(join(repo, 'block-verifier/vendor'), join(bv, 'vendor'));
    writeFileSync(join(tree, 'package.json'), '{"type":"module"}');
    let text = readFileSync(join(src, file), 'utf8'); assert.ok(text.includes(from), `mutation ${name} must apply`);
    text = text.replace(from, to);
    if (name === 'check-fact-recursion') {
      text += '\nfunction privacyCopy(v) { if (Array.isArray(v)) return v.map(privacyCopy); if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, privacyCopy(x)])); return v; }\n';
      text = text.replace('facts.set(name, value);', 'facts.set(name, privacyCopy(value));');
    }
    if (name === 'redact-after-truncate') {
      text = text.replace("  return `\\n      ${s}`;", "  s = redactText(s);\n  return `\\n      ${s}`;");
    }
    writeFileSync(join(src, file), text);
    const command = suite === 'pty' ? 'python3' : process.execPath;
    const args = suite === 'pty' ? ['-I', join(import.meta.dirname, 'rpc-privacy-prompts-pty.py')]
      : [join(import.meta.dirname, suite === 'q24' ? 'q24-emergency-unit.mjs' : 'rpc-privacy-unit.mjs')];
    const result = spawnSync(command, args, {
      cwd: repo, env: { ...process.env, RPC_PRIVACY_SRC: src,
        ...(suite === 'q24' ? { T1C_EMERGENCY_MODULE: join(src, 'emergency.js') } : {}) },
      encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1024 * 1024,
    });
    if (probe) {
      process.stdout.write(result.stdout); process.stderr.write(result.stderr);
      process.exitCode = result.status ?? 1;
      continue;
    }
    const killed = result.status === 1 && (suite === 'spacing'
      ? result.stderr.split('\n').some((line) => line.startsWith(`FAIL ${expected}: [ERR_ASSERTION]`))
      : result.stderr.includes('FAIL') && result.stderr.includes(expected));
    if (!killed) { failures++; console.error(result.stdout + result.stderr); }
    console.log(`${killed ? 'KILLED' : 'SURVIVED'} ${name} (exit ${result.status}; ${expected})`);
  }
  if (selected) assert.ok(specs.some(([name]) => name === selected), 'unknown mutation');
} finally { rmSync(temp, { recursive: true, force: true }); }
if (failures) process.exitCode = 1;
