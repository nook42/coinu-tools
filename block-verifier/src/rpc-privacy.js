// RPC の接続値・例外・check/fact には触れない。出力直前の文字列だけを伏せる。
export const INVALID_RPC_URL = '[invalid RPC URL]';

export function displayRpcUrl(raw) {
  const url = parseRpcUrl(raw);
  if (!url) return INVALID_RPC_URL;
  return hasPrivateRpcParts(url) ? `${url.protocol}//${url.host}/…` : String(raw);
}

function parseRpcUrl(raw) {
  try {
    const url = new URL(raw);
    return ['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) && url.hostname ? url : null;
  } catch { return null; }
}

function hasPrivateRpcParts(url) {
  return Boolean(url.username || url.password || url.pathname !== '/' || url.search || url.hash);
}

// 文字列の一致だけを見る。Docs/R2 等の未登録URLの path は消さない。
// JSON 内や、診断 JSON を再び文字列にした文でも同じ URL を伏せる。
export function redactRpcText(value, urls = []) {
  let text = String(value);
  const replacements = new Map();
  for (const raw of urls) {
    if (typeof raw !== 'string') continue;
    const url = parseRpcUrl(raw);
    if (!url || !hasPrivateRpcParts(url)) continue;
    const safe = `${url.protocol}//${url.host}/…`;
    const forms = new Set([raw, raw.trim(), url.href]);
    for (const form of forms) {
      if (form.length < 16) continue;
      let from = form, to = safe;
      for (let depth = 0; depth < 3; depth++) {
        replacements.set(from, to);
        from = JSON.stringify(from).slice(1, -1);
        to = JSON.stringify(to).slice(1, -1);
      }
    }
  }
  // 秘密のない実行では、公開文に対する走査も置換もしない。
  if (replacements.size === 0) return text;
  for (const [from, to] of [...replacements].sort(([a], [b]) => b.length - a.length)) {
    text = text.replaceAll(from, () => to);
  }
  return text;
}

export function configRpcUrls(cfg) {
  return [...(cfg.rpcUrls || []), ...(cfg.customRpcs || []), ...(cfg.rpcPresets || []).map((p) => p.url)];
}
