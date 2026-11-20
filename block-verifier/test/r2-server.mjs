// r2-server.mjs — フィクスチャの R2 ツリーを配信するローカル静的サーバー（公開 R2 の代役）。
// GET /<key> → <rootDir>/<key> のバイト列を verbatim 返却（それ以外は 404）。
// 使い方:
//   node block-verifier/test/r2-server.mjs --root block-verifier/test/out/fixture/r2 --port 8788
// ライブラリ:
//   const { server, port, stop } = await startR2Server({ rootDir, port });
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, normalize, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// 同じ fixture を socket なしで配信する試験モード（実ネットワーク禁止の便用）。
const memoryRoots = new Map();
let originalFetch;
let nextMemoryPort = 18000;
function startMemoryFixture(root) {
  if (memoryRoots.size === 0) {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : input);
      const fixtureRoot = memoryRoots.get(url.origin);
      if (!fixtureRoot) return originalFetch(input, init);
      try {
        const key = decodeURIComponent(url.pathname).replace(/^\/+/, '');
        const filename = normalize(join(fixtureRoot, key));
        if (!filename.startsWith(fixtureRoot + sep) || !key) return new Response('not found', { status: 404 });
        const body = await readFile(filename);
        return new Response(body, { headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.length) } });
      } catch { return new Response('not found', { status: 404 }); }
    };
  }
  const port = nextMemoryPort++;
  const baseUrl = `http://127.0.0.1:${port}`;
  memoryRoots.set(baseUrl, root);
  const stop = () => {
    memoryRoots.delete(baseUrl);
    if (memoryRoots.size === 0) globalThis.fetch = originalFetch;
  };
  return { server: { close: stop }, port, baseUrl, stop };
}

export async function startR2Server({ rootDir, port = 8788 }) {
  const root = resolve(rootDir);
  if (process.env.R2_FIXTURE_IN_MEMORY === '1') return startMemoryFixture(root);
  const server = createServer(async (req, res) => {
    try {
      const key = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '');
      const path = normalize(join(root, key));
      if (!path.startsWith(root + sep) || key === '') { res.writeHead(404); res.end('not found'); return; }
      const body = await readFile(path);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': body.length });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  });
  await new Promise((res, rej) => { server.on('error', rej); server.listen(port, '127.0.0.1', res); });
  const address = server.address();
  const boundPort = typeof address === 'object' && address ? address.port : port;
  return { server, port: boundPort, baseUrl: `http://127.0.0.1:${boundPort}`, stop: () => server.close() };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const argOf = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const { baseUrl } = await startR2Server({
    rootDir: argOf('--root', 'block-verifier/test/out/fixture/r2'),
    port: parseInt(argOf('--port', '8788')),
  });
  console.log(`[r2-server] serving at ${baseUrl} (Ctrl-C to stop)`);
}
