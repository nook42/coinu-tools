// REQUEST8 F-1: 最低条件の表示だけは採点と同じ可視文字規則を使う。
import { readFileSync } from 'node:fs';
import { countHalfWidthChars, countVisibleChars }
  from '../vendor/workers/game_workers/lib/char-counter.js';

let failures = 0;
const check = (condition, label) => {
  if (condition) console.log(`  ok: ${label}`);
  else {
    console.error(`  NG: ${label}`);
    failures++;
  }
};

const source = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
check(/countHalfWidthChars, countVisibleChars, countMessageTurns/.test(source),
  'countVisibleChars は vendored 正典から import する');
check(/charsMap\[msg\.uid\].*countVisibleChars\(msg\.text \|\| ''\)/.test(source),
  'メンバーカードの最低文字数は countVisibleChars');
check(/chars: mine\.reduce\(\(s, m\) => s \+ countVisibleChars\(m\.text \|\| ''\), 0\)/.test(source)
  && /const myChars = progress\.chars/.test(source)
  && /const progress = myReceiptedChatProgress\(msgs, renderNow\)/.test(source),
  '自分の最低文字数は既読付きの countVisibleChars');
check(/function myRawChatTotals\(\) \{[\s\S]*?chars: mine\.reduce\(\(s, m\) => s \+ countHalfWidthChars\(m\.text \|\| ''\), 0\)/.test(source)
  && /const myCharsRaw = myRawChatTotals\(\)\.chars/.test(source),
  'キャップ判定用 myCharsRaw は生カウントのまま');

const legalText = `A${'\u200B'.repeat(249)}`;
const messages = Array.from({ length: 10 }, () => ({ text: legalText }));
const raw = messages.reduce((sum, message) => sum + countHalfWidthChars(message.text), 0);
const displayed = messages.reduce((sum, message) => sum + countVisibleChars(message.text), 0);
const scored = messages.reduce((sum, message) => sum + countVisibleChars(message.text), 0);
check(countHalfWidthChars(legalText) === 499 && countVisibleChars(legalText) === 1,
  '合法入力1件は生499文字・可視1文字');
check(raw === 4990, '上限会計は10件で4,990文字');
check(displayed === 10 && displayed === scored,
  '最低条件の表示10文字 = 採点10文字');

if (failures) {
  console.error(`\n❌ FAILED (${failures})`);
  process.exit(1);
}
console.log('\n✅ ALL PASSED');
