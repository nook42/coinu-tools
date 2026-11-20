// PTY専用。実promptsを呼び、値を画面に出さず受理・中断・closeだけを観測する。
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const src = resolve(process.env.RPC_PRIVACY_SRC || new URL('../src', import.meta.url).pathname);
const { createPrompts } = await import(pathToFileURL(resolve(src, 'prompts.js')));
console.log(`PROBE_PID=${process.pid}`);
const prompts = createPrompts();
let status = 0;
try {
  const value = await prompts.text('RPC_SECRET> ', { secret: true });
  assert.equal(value, 'FAKE-AFTER-FG');
  console.log('PROBE_ACCEPTED');
} catch {
  console.log('PROBE_ABORTED'); status = 3;
} finally { prompts.close(); }
console.log('PROBE_CLOSED');
// 親がclose後の端末設定を検査してから終了する。
await new Promise((resolve) => { process.stdin.once('data', resolve); process.stdin.resume(); });
process.exit(status);
