// この依頼の試験では外部通信と .env 読取をプロセス境界でも拒否する。
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const local = (host) => !host || ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host);
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const arg = Array.isArray(args[0]) ? args[0][0] : args[0];
  const host = typeof arg === 'object' ? arg?.host : typeof args[1] === 'string' ? args[1] : null;
  if (!local(host)) throw new Error('FIX1 external network forbidden');
  return connect.apply(this, args);
};
const fetch = globalThis.fetch;
if (fetch) globalThis.fetch = (input, ...args) => {
  if (!local(new URL(typeof input === 'string' || input instanceof URL ? input : input.url).hostname)) throw new Error('FIX1 external fetch forbidden');
  return fetch(input, ...args);
};
function guard(p) {
  const name = path.basename(p instanceof URL ? p.pathname : String(p));
  if (/^\.env(?:[.].*)?$/.test(name)) throw new Error('FIX1 .env read forbidden');
}
for (const name of ['readFile', 'readFileSync', 'open', 'openSync', 'createReadStream']) {
  const original = fs[name];
  fs[name] = function (p, ...args) { guard(p); return original.call(this, p, ...args); };
}
for (const name of ['readFile', 'open']) {
  const original = fs.promises[name];
  fs.promises[name] = function (p, ...args) { guard(p); return original.call(this, p, ...args); };
}
require('node:module').syncBuiltinESMExports();
