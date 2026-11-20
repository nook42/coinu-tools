import assert from 'node:assert/strict';
// C-6e probe 1: U-13 の「Nostr の既出の印は中身の検査の後」(T1 5797eaf1) で、
// 既出にならない chat イベント（自分の発言のエコー・受信時点で未来時刻の発言）が
// 再配信のたびに per-pubkey の件数へ数え直される。
//   A1: 正直な自分の発言のエコー（5リレー）
//   A2: 履歴ページの境界秒に自分の発言があると、同じ until の再要求が上限まで回る
//   A3: V の時計が H より 3 分遅い組で、1つのリレーが H の発言（V にとって未来）を再送すると
//       H に氾濫の警告（1000）が出て、1200 を超えると H の以後の P2P が V の端末で捨てられる
// 同じ盤面を起点 2f96ce6b の relay.js（relay_base.js）でも走らせて対照にする。
//
// 実行: tmp/s3r2/C-6e/run.sh（git archive で HEAD の chatgame-tools を取り、起点の relay.js を relay_base.js として置く）
import { generatePrivateKey } from 'viem/accounts';

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};

// ---- 最小の Nostr リレー（NIP-01 の REQ/EVENT/EOSE/CLOSE と until/since/limit/authors/#t）----
const relays = new Map();
class FakeRelay {
  constructor(url) { this.url = url; this.events = []; this.clients = new Set(); this.reqCount = 0; relays.set(url, this); }
  match(f, ev) {
    if (f.kinds && !f.kinds.includes(ev.kind)) return false;
    if (f['#t'] && !ev.tags.some((t) => t[0] === 't' && f['#t'].includes(t[1]))) return false;
    if (f.authors && !f.authors.includes(ev.pubkey)) return false;
    if (f.since != null && ev.created_at < f.since) return false;
    if (f.until != null && ev.created_at > f.until) return false;
    return true;
  }
  onClientMessage(ws, raw) {
    const msg = JSON.parse(raw);
    if (msg[0] === 'REQ') {
      this.reqCount += 1;
      const [, subId, f] = msg;
      const live = f.until == null;
      if (live) ws._subs.set(subId, f);
      const hits = this.events.filter((ev) => this.match(f, ev))
        .sort((a, b) => b.created_at - a.created_at).slice(0, f.limit ?? 100000);
      for (const ev of hits) ws._deliver(['EVENT', subId, ev]);
      ws._deliver(['EOSE', subId]);
    } else if (msg[0] === 'CLOSE') {
      ws._subs.delete(msg[1]);
    } else if (msg[0] === 'EVENT') {
      const ev = msg[1];
      this.events.push(ev);
      for (const c of this.clients) for (const [subId, f] of c._subs) if (this.match(f, ev)) c._deliver(['EVENT', subId, ev]);
    }
  }
  replay(ev, times) { // 悪意のある（または非準拠の）リレーが同じイベントを何度も流す
    for (const c of this.clients) for (const [subId] of c._subs) for (let i = 0; i < times; i++) c._deliver(['EVENT', subId, ev]);
  }
}
class FakeWS {
  static OPEN = 1;
  constructor(url) {
    this.url = url; this.readyState = 0; this._subs = new Map();
    this.relay = relays.get(url); this.relay.clients.add(this);
    setImmediate(() => { this.readyState = 1; this.onopen?.(); });
  }
  send(data) { const r = this.relay; setImmediate(() => r.onClientMessage(this, data)); }
  _deliver(m) { const s = JSON.stringify(m); setImmediate(() => this.onmessage?.({ data: s })); }
  close() { this.readyState = 3; this.relay.clients.delete(this); setImmediate(() => this.onclose?.()); }
}
globalThis.WebSocket = FakeWS;
const settle = async (n = 30) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

async function runOn(label, modPath) {
  const mod = await import(modPath);
  const { GameRelayChannel, buildEvent, groupTag, deriveNostrKey } = mod;
  const BLOCK = 7; const GROUP = 3;
  const kV = generatePrivateKey(); const kH = generatePrivateKey();
  const nV = deriveNostrKey(kV, BLOCK); const nH = deriveNostrKey(kH, BLOCK);
  const members = [
    { uid: 'V', bAddr: { address: '0x0', pubKey: '0x04', nostrPubkey: nV.pubkey } },
    { uid: 'H', bAddr: { address: '0x0', pubKey: '0x04', nostrPubkey: nH.pubkey } },
  ];
  const tag = groupTag(BLOCK, GROUP);
  const inner = (uid, text, ts) => JSON.stringify({ type: 'chat', blockNum: BLOCK, groupId: GROUP, uid, text, timestamp: ts, signature: '0x' + '11'.repeat(65) });
  const out = {};

  // ---------- A1: 自分の発言のエコー（5リレー・正直な運用） ----------
  {
    relays.clear();
    const urls = ['wss://a1', 'wss://a2', 'wss://a3', 'wss://a4', 'wss://a5'];
    for (const u of urls) new FakeRelay(u);
    localStorage.setItem('p2pRelays', JSON.stringify(urls));
    const floods = [];
    const ch = new GameRelayChannel({ signKey: kV, blockNum: BLOCK, groupId: GROUP, uid: 'V', members,
      verifyInnerSignature: async () => true, sinceSec: 1, onFlood: (u, p, c) => floods.push([u, c]) });
    ch.start(); await settle();
    const now = Date.now();
    for (let i = 0; i < 100; i++) ch.publishChat({ uid: 'V', text: `own ${i}`, timestamp: now + i, signature: '0x' + (i.toString(16).padStart(2, '0')).repeat(65) });
    await settle(80);
    out.A1_ownCount = ch.pool.perPubkeyCount.get(nV.pubkey) || 0;
    out.A1_ownSeenIds = [...ch.pool.seenIds].length;
    out.A1_ownOverCap = ch.pool.verifiedOverCap.has(nV.pubkey);
    ch.stop();
  }

  // ---------- A2: 履歴の境界秒に自分の発言（接続し直し・再読み込み） ----------
  {
    relays.clear();
    const r = new FakeRelay('wss://b1');
    localStorage.setItem('p2pRelays', JSON.stringify(['wss://b1']));
    const t0 = Math.floor(Date.now() / 1000) - 3600;
    r.events.push(buildEvent(nV.sk, nV.pubkey, [['t', tag]], inner('V', 'my first message', t0 * 1000), t0));
    for (let i = 1; i <= 40; i++) r.events.push(buildEvent(nH.sk, nH.pubkey, [['t', tag]], inner('H', `h ${i}`, (t0 + i) * 1000), t0 + i));
    const ch = new GameRelayChannel({ signKey: kV, blockNum: BLOCK, groupId: GROUP, uid: 'V', members,
      verifyInnerSignature: async () => true, sinceSec: 1 });
    r.reqCount = 0;
    ch.start();
    await settle(20000);
    out.A2_historyReqs = r.reqCount;
    out.A2_ownCount = ch.pool.perPubkeyCount.get(nV.pubkey) || 0;
    out.A2_ownOverCap = ch.pool.verifiedOverCap.has(nV.pubkey);
    ch.stop();
  }

  // ---------- A3: V の時計が 3 分遅い（H の発言は V にとって未来）＋1つのリレーが再送 ----------
  {
    relays.clear();
    const r = new FakeRelay('wss://c1');
    localStorage.setItem('p2pRelays', JSON.stringify(['wss://c1']));
    const floods = [];
    const delivered = [];
    const ch = new GameRelayChannel({ signKey: kV, blockNum: BLOCK, groupId: GROUP, uid: 'V', members,
      verifyInnerSignature: async () => true, sinceSec: 1,
      onChat: (i) => { delivered.push(i.text); }, onFlood: (u, p, c) => floods.push([u, c]) });
    ch.start(); await settle();
    const nowV = Date.now();
    // H の端末時計は V より 3 分進んでいる（= V の時計が 3 分遅い）。H の正直な発言
    const hTs = nowV + 180_000;
    const evH = buildEvent(nH.sk, nH.pubkey, [['t', tag]], inner('H', 'honest H, clock 3min ahead of V', hTs), Math.floor(nowV / 1000));
    r.replay(evH, 1300);
    await settle(8000);
    out.A3_Hcount = ch.pool.perPubkeyCount.get(nH.pubkey) || 0;
    out.A3_floodAlertOnH = floods.filter(([u]) => u === 'H').length > 0;
    out.A3_HoverCap = ch.pool.verifiedOverCap.has(nH.pubkey);
    // その後の H の現在時刻の発言（未来ではない）は V に届くか
    const before = delivered.length;
    const evH2 = buildEvent(nH.sk, nH.pubkey, [['t', tag]], inner('H', 'H later normal message', nowV), Math.floor(nowV / 1000));
    r.replay(evH2, 1);
    await settle(50);
    out.A3_laterHDelivered = delivered.length > before && delivered.includes('H later normal message');
    ch.stop();
  }
  console.log(label, JSON.stringify(out));
  return out;
}

const head = await runOn('T1d', process.env.T1D_RELAY_OVERRIDE || '../../src/utils/relay.js');
assert.equal(head.A1_ownCount, 100);
assert(head.A2_historyReqs < 10, `history requests ${head.A2_historyReqs}`);
assert.equal(head.A3_Hcount, 1);
assert.equal(head.A3_floodAlertOnH, false);
assert.equal(head.A3_HoverCap, false);
assert.equal(head.A3_laterHDelivered, true);
console.log('T1d relay recount: ALL PASSED');
