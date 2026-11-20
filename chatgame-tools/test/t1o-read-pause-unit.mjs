import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { openReadReceiptPause, readReceiptTickGap, readReceiptConnectionChange } from '../vendor/src/utils/read-receipt-pause.js';

assert.equal(readReceiptTickGap({ lastTickAt: 0, lastTickWallAt: 0 }, 31_000, 29_000), true);
assert.equal(readReceiptTickGap({ lastTickAt: 0, lastTickWallAt: 0 }, 29_000, 29_000), false);
assert.equal(readReceiptTickGap({ lastTickAt: 0, lastTickWallAt: 0 }, 0, 31_000), true);
let connection = readReceiptConnectionChange(null, true, 0);
connection = readReceiptConnectionChange(connection, false, 0);
assert.equal(readReceiptConnectionChange(connection, true, 29_000).reopen, false);
assert.equal(readReceiptConnectionChange(connection, true, 31_000).reopen, true);

const mutation = process.env.T1O_MUTATION;
const pauseRule = mutation === 'old-window'
  ? (previous, now) => ({ until: previous ? Math.min(now + 10000, 30000) : now + 10000,
    lastTickAt: now })
  : mutation === 'uncapped'
    ? (previous, now) => ({ until: now + 10000, sequenceStartAt: previous?.sequenceStartAt ?? now,
      lastTickAt: now })
  : openReadReceiptPause;
let pause = pauseRule(null, 0);
assert.equal(pause.until, 10000, '入室後10秒');
let delayed = openReadReceiptPause(null, 0);
for (const at of [10_000, 20_000, 30_000]) delayed = openReadReceiptPause(delayed, at);
assert.equal(delayed.until, 30_000, '10秒間隔の遅延が続いても上限を越えない');
delayed = openReadReceiptPause(null, 0);
for (const at of [11_000, 22_000, 33_000]) delayed = openReadReceiptPause(delayed, at, true);
assert.equal(delayed.until, 41_000, '11秒遅延の最初の復帰から30秒を超えない');
delayed = openReadReceiptPause(delayed, 44_000, true);
assert.equal(delayed.until, 41_000, '反復する遅延では次の連なりを開かない');
delayed = openReadReceiptPause(delayed, 344_000, true);
assert.equal(delayed.until, 354_000, '反復遅延の後でも長いスリープからは10秒');
pause = pauseRule(pause, 300000, true);
assert.equal(pause.until, 310000, '5分のスリープ後は前回発行時刻と無関係に10秒');
pause = pauseRule(null, 0);
for (let now = 2_000; now <= 32_000; now += 2_000) {
  pause = pauseRule(pause, now);
}
assert.equal(pause.until, 30_000, '2秒ごとの復帰でも連なりは30秒を超えない');
let shortSleep = openReadReceiptPause(null, 0);
for (let at = 2_000; at <= 28_000; at += 2_000) shortSleep = openReadReceiptPause(shortSleep, at);
shortSleep = openReadReceiptPause(shortSleep, 45_000, true);
assert.equal(shortSleep.until, 55_000, '上限後の短いスリープから戻っても新しい10秒');
pause.settled = true; // 窓外の次の tick が観測した状態
pause = pauseRule(pause, 32_000);
assert.equal(pause.until, 42_000, '窓外の tick 後は新しい連なり');
pause = pauseRule(null, 32_000);
assert.equal(pause.until, 42_000, '閉じた後の次の連なりは10秒');

const hook = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const relay = readFileSync(new URL('../src/recovery/relay-client.js', import.meta.url), 'utf8');
assert.doesNotMatch(hook, /wsReconnectPendingRef/, 'WS 単独の再接続印はない');
assert.match(hook, /ws\.onopen = \(\) => \{[\s\S]*?observeReadReceiptConnection\(\)/);
assert.match(hook, /ws\.onclose = \(event\) => \{[\s\S]*?observeReadReceiptConnection\(\)/);
assert.match(hook, /onConnectionChange:\s*observeReadReceiptConnection/);
const observeAt = hook.indexOf('const observeReadReceiptConnection = useCallback(() => {');
const observeEnd = hook.indexOf('\n  }, []);', observeAt);
assert(observeAt >= 0 && observeEnd > observeAt);
let observeBody = hook.slice(observeAt + 'const observeReadReceiptConnection = useCallback('.length,
  observeEnd + '\n  }'.length);
if (mutation === 'no-ws') observeBody = observeBody.replace(
  'openReadReceiptPause(pause, now,', '((old) => old)(pause, now,');
const makeOfficialObserver = () => {
  let now = 0;
  const ws = { readyState: 3 };
  const relaySocket = { readyState: 3 };
  const wsRef = { current: ws };
  const relayChannelRef = { current: { pool: { sockets: new Map([['a', relaySocket]]) } } };
  const readReceiptConnectionRef = { current: null };
  const readReceiptPauseRef = { current: { until: 10_000, sequenceStartAt: 0,
    lastTickAt: 0, lastTickWallAt: 0, settled: true } };
  const observer = new Function('wsRef', 'relayChannelRef', 'readReceiptConnectionRef',
    'readReceiptPauseRef', 'WebSocket', 'Date', 'performance', 'readReceiptConnectionChange',
    'openReadReceiptPause', 'readReceiptTickGap', `return (${observeBody});`)(wsRef, relayChannelRef,
    readReceiptConnectionRef, readReceiptPauseRef, { OPEN: 1 }, { now: () => now },
    { now: () => now }, readReceiptConnectionChange, openReadReceiptPause, readReceiptTickGap);
  return { ws, relaySocket, observer, pause: readReceiptPauseRef, setNow: (value) => { now = value; } };
};
let official = makeOfficialObserver();
official.ws.readyState = 1; official.observer();
assert.equal(official.pause.current.until, 10_000, 'WS 初回接続は入室窓以外を開かない');
official.relaySocket.readyState = 1; official.observer();
official.ws.readyState = 3; official.observer();
official.setNow(31_000); official.ws.readyState = 1; official.observer();
assert.equal(official.pause.current.until, 10_000, 'リレーが生きたままの WS 再接続では開かない');
official.relaySocket.readyState = 3; official.observer();
official.setNow(62_000); official.relaySocket.readyState = 1; official.observer();
assert.equal(official.pause.current.until, 10_000, 'WS が生きたままのリレー再接続では開かない');
official = makeOfficialObserver();
official.ws.readyState = 1; official.observer();
official.ws.readyState = 3; official.observer();
official.setNow(29_000); official.ws.readyState = 1; official.observer();
assert.equal(official.pause.current.until, 10_000, '全断29秒では開かない');
official = makeOfficialObserver();
official.ws.readyState = 1; official.observer();
official.ws.readyState = 3; official.observer();
official.setNow(31_000); official.relaySocket.readyState = 1; official.observer();
assert.equal(official.pause.current.until, 41_000, '全断31秒後のリレー1本で開く');
assert.match(app, /onReconnect:\s*reopenReadReceiptPause/,
  '復元リレーの開き直しを窓へ渡す');
assert.match(relay, /onReconnect[\s\S]*?addEventListener\('open'/,
  'リレーの接続イベントを観測する');

const reconnectAt = relay.indexOf('    const pool = this.channel.pool;');
const reconnectEnd = relay.indexOf('    // GameRelayChannel restores', reconnectAt);
assert(reconnectAt >= 0 && reconnectEnd > reconnectAt);
const connected = [];
let now = 0;
let openCount = 0;
const makeSocket = () => {
  const handlers = { open: [], close: [] };
  return {
    readyState: 0,
    addEventListener: (type, callback) => handlers[type].push(callback),
    fire(type) {
      this.readyState = type === 'open' ? 1 : 3;
      for (const callback of handlers[type]) callback();
    },
  };
};
const pool = { closed: false, sockets: new Map(), _connectOne(url) {
  const socket = makeSocket();
  this.sockets.set(url, socket);
  connected.push(socket);
} };
pool._connectOne('a'); pool._connectOne('b');
const recovery = { channel: { pool }, onReconnect: () => { openCount++; } };
const relayReconnectSource = mutation === 'no-relay'
  ? relay.slice(reconnectAt, reconnectEnd).replace('this.onReconnect();', 'void 0;')
  : relay.slice(reconnectAt, reconnectEnd);
new Function('WebSocket', 'Date', 'readReceiptConnectionChange', relayReconnectSource)
  .call(recovery, { OPEN: 1 }, { now: () => now }, readReceiptConnectionChange);
connected[0].fire('open'); connected[1].fire('open');
assert.equal(openCount, 0, '最初の接続では再開扱いにしない');
connected[0].fire('close'); pool.sockets.delete('a');
pool._connectOne('a'); connected[2].fire('open');
assert.equal(openCount, 0, '他のリレーが生きている間の張り直しでは開かない');
connected[1].fire('close'); pool.sockets.delete('b');
connected[2].fire('close'); pool.sockets.delete('a');
now = 29_000;
pool._connectOne('a'); connected[3].fire('open');
assert.equal(openCount, 0, '全断29秒未満では開かない');
connected[3].fire('close'); pool.sockets.delete('a');
now = 60_000;
pool._connectOne('a'); connected[4].fire('open');
assert.equal(openCount, 1, '全断31秒後の最初の open で窓を開く');
pool._connectOne('b'); connected[5].fire('open');
assert.equal(openCount, 1, '同じ全断からの2本目では重ねて開かない');
console.log('T1o read pause: ALL PASSED');
