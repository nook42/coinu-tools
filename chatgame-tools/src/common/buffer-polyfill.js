// eciesjs 0.4.x はグローバル Buffer を要求する（encrypt() が Buffer.from(...) を返す）。
// 本体 Next.js では webpack が Buffer ポリフィルを自動注入するため動くが、
// このツールの esbuild バンドルには無い → 明示的に補う（feross/buffer 6.x）。
// 必ず各エントリの最初に import すること。
import { Buffer } from 'buffer';
if (typeof globalThis.Buffer === 'undefined') globalThis.Buffer = Buffer;
