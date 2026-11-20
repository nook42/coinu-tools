// R14-06: 復元クライアントの void 同一対象再送を本体と完全に揃える。
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const recoveryPath = process.env.R14_RECOVERY_APP_PATH
  ? resolve(process.env.R14_RECOVERY_APP_PATH)
  : new URL('../src/recovery/app.js', import.meta.url);
const chatPhasePath = process.env.R14_CHAT_PHASE_PATH
  ? resolve(process.env.R14_CHAT_PHASE_PATH)
  : new URL('../../src/components/game/ChatPhase.js', import.meta.url);
const recoverySource = readFileSync(recoveryPath, 'utf8');
const chatPhaseSource = readFileSync(chatPhasePath, 'utf8');

let failures = 0;
const check = (condition, label) => {
  if (condition) console.log(`  ok: ${label}`);
  else {
    console.error(`  NG: ${label}`);
    failures += 1;
  }
};

function canResendFrom(source, alreadyName) {
  const match = source.match(/const canResend = ([^;]+);/);
  if (!match) return null;
  return new Function(alreadyName, 'st', 'repStatus', 'm', 'maxReached', `return (${match[1]});`);
}

// 関数本体を括弧対応で切り出す。後続コメント名に依存しないため、終端アンカーの
// -1 や、同じ文字列を別関数へ移しただけの回帰を handler 内と誤認しない。
function extractFunctionBody(source, startNeedle) {
  const start = source.indexOf(startNeedle);
  if (start < 0) return null;
  const open = source.indexOf('{', start + startNeedle.length);
  if (open < 0) return null;
  let depth = 0;
  let state = 'code';
  let regexClass = false;
  const regexCanStartAt = (index) => {
    const prefix = source.slice(0, index).replace(/\s+$/, '');
    if (prefix === '') return true;
    const previous = prefix[prefix.length - 1];
    if (/[\[({=,:;!?&|+\-*%^~<>]/.test(previous)) return true;
    const word = prefix.match(/([A-Za-z_$][\w$]*)$/)?.[1];
    return /^(?:return|throw|case|delete|void|typeof|instanceof|in|of|new|yield|await)$/.test(word || '');
  };
  for (let i = open; i < source.length; i++) {
    const char = source[i];
    const next = source[i + 1];
    if (state === 'code') {
      if (char === '/' && next === '/') { state = 'line'; i += 1; continue; }
      if (char === '/' && next === '*') { state = 'block'; i += 1; continue; }
      if (char === '/' && regexCanStartAt(i)) { state = 'regex'; regexClass = false; continue; }
      if (char === "'") { state = 'single'; continue; }
      if (char === '"') { state = 'double'; continue; }
      if (char === '`') { state = 'template'; continue; }
      if (char === '{') depth += 1;
      if (char === '}' && --depth === 0) return source.slice(start, i + 1);
      continue;
    }
    if (state === 'line') { if (char === '\n') state = 'code'; continue; }
    if (state === 'block') { if (char === '*' && next === '/') { state = 'code'; i += 1; } continue; }
    if (state === 'regex') {
      if (char === '\\') { i += 1; continue; }
      if (char === '[') { regexClass = true; continue; }
      if (char === ']') { regexClass = false; continue; }
      if (char === '/' && !regexClass) state = 'code';
      continue;
    }
    if (char === '\\') { i += 1; continue; }
    if ((state === 'single' && char === "'")
        || (state === 'double' && char === '"')
        || (state === 'template' && char === '`')) state = 'code';
  }
  return null;
}

const regexLiteralFixture = [
  'function target() {',
  "  const apostrophe = /don't/;",
  '  return true;',
  '}',
  'function decoy() { return false; }',
].join('\n');
check(extractFunctionBody(regexLiteralFixture, 'function target()')
    === regexLiteralFixture.split('\n').slice(0, 4).join('\n'),
  '正規表現リテラル内の引用符で関数境界を見失わない');

console.log('[R14-06] 2枠使用後でも void 同一対象へ再送できる');
const mainCanResend = canResendFrom(chatPhaseSource, 'alreadyReported');
const recoveryCanResend = canResendFrom(recoverySource, 'already');
check(typeof mainCanResend === 'function' && typeof recoveryCanResend === 'function',
  '本体・復元から canResend の実式を切り出せる');

const cases = [
  { already: true, status: 'void', maxReached: true, expected: true, label: '2枠使用後のvoid同一対象' },
  { already: true, status: 'void', maxReached: false, expected: true, label: '1枠時のvoid同一対象' },
  { already: true, status: 'pending', maxReached: true, expected: false, label: 'pending対象' },
  { already: true, status: 'receipted', maxReached: true, expected: false, label: 'receipted対象' },
  { already: false, status: 'void', maxReached: true, expected: false, label: '未発信対象' },
];
for (const item of cases) {
  const main = mainCanResend?.(
    item.already,
    item.status,
    { target: item.status },
    { uid: 'target' },
    item.maxReached,
  );
  const recovery = recoveryCanResend?.(
    item.already,
    item.status,
    { target: item.status },
    { uid: 'target' },
    item.maxReached,
  );
  check(main === item.expected && recovery === item.expected && main === recovery,
    `${item.label}: 本体=${main} 復元=${recovery}`);
}

console.log('[ハンドラ parity] 再送時も見える確定した投票の門を再検査する');
const mainHandler = extractFunctionBody(chatPhaseSource, 'const handleReport = useCallback');
const recoveryHandler = extractFunctionBody(recoverySource, 'async function sendReport(targetUid)');
check(mainHandler !== null, '本体の密告ハンドラを関数境界で切り出せる');
check(recoveryHandler !== null, '復元の密告ハンドラを関数境界で切り出せる');
// UI_IMPROVEMENTS_S3 #24: 止めた出口は理由を帯に出してから return する（門の式と return は同じ）。
check(/if \(!canReportTarget\(targetUid, nowTick\)\) \{ if \(warningApproved \|\| unconfirmedApproved\) showActionNotice\('error', t\('game\.action\.reportNotSent'\)\); return; \}/.test(mainHandler)
    && /if \(!canReportTarget\(targetUid, sendAt\)\) \{ showActionNotice\('error', t\('game\.action\.reportNotSent'\)\); return; \}/.test(mainHandler),
  '本体ハンドラは再送も送る直前に判定し直す');
check(/const reportNow = clientNow\(\);\s*if \(!canReportTarget\(targetUid, reportNow\)\) return;/.test(recoveryHandler)
    && /if \(!canReportTarget\(targetUid, ts\)\) return;/.test(recoveryHandler),
  '復元ハンドラは署名時刻 ts で再送も判定し直す');
check(!/if \(!isResend && \(myReadCountByMember\(\)\[targetUid\]/.test(recoveryHandler),
  '復元ハンドラに旧 !isResend 例外が残らない');

if (failures > 0) {
  console.error(`r14-resend-parity-unit: FAILED (${failures})`);
  process.exit(1);
}
console.log('r14-resend-parity-unit: ALL PASSED');
