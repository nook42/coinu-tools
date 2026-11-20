// RPC の投票単位。URL の path、API key、ポート、サブドメインは票を増やさない。
// よく使われる複合 public suffix は明示し、それ以外は通常の二ラベル名にする。
const COMPOUND_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.jp', 'or.jp', 'ne.jp', 'com.br', 'com.cn', 'com.hk', 'co.kr',
  'co.nz', 'com.sg', 'com.tw', 'co.in', 'com.mx', 'com.tr', 'co.za',
]);
const COUNTRY_SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ne', 'or']);

export function rpcProvider(url) {
  const host = new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') || /^\d+(?:\.\d+){3}$/.test(host) || host === 'localhost') return host;
  const labels = host.split('.');
  if (labels.length < 2) return host;
  const suffix = labels.slice(-2).join('.');
  const compound = COMPOUND_SUFFIXES.has(suffix)
    || (labels.at(-1).length === 2 && COUNTRY_SECOND_LEVEL.has(labels.at(-2)));
  return labels.slice(-(compound && labels.length > 2 ? 3 : 2)).join('.');
}

export function rpcProviderCount(urls) {
  return new Set(urls.map(rpcProvider)).size;
}
