// 正典の console 出力だけを呼出中に抑える。戻り値・例外・検査データには触れない。
import { AsyncLocalStorage } from 'node:async_hooks';

const calls = new AsyncLocalStorage();
const methods = ['log', 'error', 'warn'];
let active = 0;
let originals;

export function withVendorLogging(run, { onError } = {}) {
  if (active++ === 0) {
    originals = methods.map((method) => console[method]);
    for (const [index, method] of methods.entries()) {
      const original = originals[index];
      console[method] = (...args) => {
        const call = calls.getStore();
        if (call) {
          if (method === 'error') call.onError?.(...args);
          if (process.env.DEBUG === undefined) return;
        }
        original.apply(console, args);
      };
    }
  }
  const restore = () => {
    if (--active === 0) {
      for (const [index, method] of methods.entries()) console[method] = originals[index];
    }
  };
  let value;
  try {
    value = calls.run({ onError: onError ?? calls.getStore()?.onError }, run);
  } catch (error) {
    restore();
    throw error;
  }
  // 同期の正典関数は同期のまま。並行・入れ子の非同期呼出でも他の出力を抑えない。
  if (value && typeof value.then === 'function') return Promise.resolve(value).finally(restore);
  restore();
  return value;
}
