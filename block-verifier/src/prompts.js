// block-verifier/src/prompts.js
// readline/promises ベースの対話ヘルパ（選択肢・y/n・数値・自由入力・Enter待ち）。
// 文言は呼び出し側（ui / i18n）が翻訳済みの文字列を渡す — ここは言語中立。
// 非対話モード（--yes / --non-interactive）では既定値を即返し、stdin を一切開かない。

import readline from 'node:readline/promises';
import { PassThrough } from 'node:stream';
import { stdin as input, stdout as output } from 'node:process';
import { stripVTControlCharacters } from 'node:util';

// 通常の読み手の履歴・kill ring・data購読から秘密の入力を切り離す。
async function readSecret(iface, query) {
  const wasRaw = !!input.isRaw;
  const wasPaused = iface.paused;
  const suspended = [
    ...['data', 'keypress', 'end', 'error'].map((event) => [input, event, input.rawListeners(event)]),
    [output, 'resize', output.rawListeners('resize')],
  ];
  iface.pause();
  for (const [stream, event, listeners] of suspended) {
    for (const listener of listeners) stream.removeListener(event, listener);
  }
  const secretInput = new PassThrough();
  let reader, onError, onEnd;
  const resume = () => { input.setRawMode(true); reader.resume(); input.resume(); };
  const suspend = () => {
    process.once('SIGCONT', resume);
    input.setRawMode(false);
    // teeも同じジョブとして止め、シェルに端末を返す。
    process.kill(0, 'SIGTSTP');
  };
  try {
    input.setRawMode(true);
    reader = readline.createInterface({ input: secretInput, output: null, terminal: true, historySize: 0 });
    if (process.platform !== 'win32') reader.on('SIGTSTP', suspend);
    return await new Promise((resolve, reject) => {
      onError = reject;
      onEnd = () => reject(new Error('stdin closed (EOF) — cannot prompt'));
      reader.once('line', resolve);
      reader.once('SIGINT', () => reject(new Error('stdin interrupted — cannot prompt')));
      reader.once('close', onEnd);
      reader.once('error', onError);
      input.once('error', onError);
      input.once('end', onEnd);
      input.pipe(secretInput);
      output.write(query);
    });
  } finally {
    process.removeListener('SIGCONT', resume);
    input.unpipe(secretInput);
    if (onError) input.removeListener('error', onError);
    if (onEnd) input.removeListener('end', onEnd);
    reader?.close();
    secretInput.destroy();
    try { input.setRawMode(wasRaw); }
    finally {
      for (const [stream, event, listeners] of suspended) {
        for (const listener of listeners) stream.on(event, listener);
      }
      if (!wasPaused) iface.resume();
    }
    output.write('\n');
  }
}

export function createPrompts({ nonInteractive = false } = {}) {
  let rl = null;
  let closing = false;
  let eofSeen = false;
  let lastLineKind = 'empty';
  let lineStarted = false;
  let startsHeading = false;
  let endedWithNewline = true;
  const restoreWrites = [];

  // stdout/stderr を書込順に合わせて追う。行の内容（入力値）は保存しない。
  function observeWrite(chunk, encoding) {
    const text = typeof chunk === 'string' ? chunk
      : Buffer.from(chunk).toString(typeof encoding === 'string' ? encoding : undefined);
    for (const char of stripVTControlCharacters(text)) {
      if (char === '\r') continue;
      if (char === '\n') {
        if (!lineStarted) lastLineKind = 'empty';
        lineStarted = false;
        endedWithNewline = true;
      } else {
        if (!lineStarted) startsHeading = char === '【';
        lineStarted = true;
        lastLineKind = startsHeading && char === '】' ? 'heading' : 'text';
        endedWithNewline = false;
      }
    }
  }

  if (!nonInteractive) for (const stream of [output, process.stderr]) {
    const write = stream.write;
    function trackedWrite(chunk, ...args) {
      observeWrite(chunk, args[0]);
      return write.call(this, chunk, ...args);
    }
    stream.write = trackedWrite;
    restoreWrites.push(() => { if (stream.write === trackedWrite) stream.write = write; });
  }

  function separateQuestion() {
    if (lastLineKind === 'text') output.write(endedWithNewline ? '\n' : '\n\n');
  }

  function eofError() {
    return new Error('stdin closed (EOF) — cannot prompt');
  }

  function ensureRl() {
    if (eofSeen) throw eofError();
    if (!rl) {
      rl = readline.createInterface({ input, output });
      // ユーザー起因でない close（Ctrl-D / パイプ終端）は EOF として記録し、以後の ask は throw
      rl.on('close', () => {
        if (!closing) eofSeen = true;
        rl = null;
      });
    }
    return rl;
  }

  // stdin の EOF / クローズを検知したら throw（呼び出し元＝index が fatal 扱い・exit 3）。
  // フォールバック値を返して再入力ループに戻ると空応答の busy-loop になるため構造的に排除する。
  async function ask(query, { secret = false, separate = true } = {}) {
    const iface = ensureRl();
    if (separate) separateQuestion();
    if (secret && input.isTTY) {
      try { return await readSecret(iface, query); }
      catch { eofSeen = true; throw eofError(); }
    }
    const hidden = secret && iface.terminal;
    const write = output.write;
    const history = iface.history;
    let answer;
    try {
      if (hidden) {
        iface.history = [];
        output.write = () => true;
        write.call(output, query);
      }
      answer = await iface.question(hidden ? '' : query);
    } catch {
      eofSeen = true;
      throw eofError();
    } finally {
      if (hidden) {
        iface.history = history;
        output.write = write;
        output.write('\n');
      }
    }
    if (eofSeen) throw eofError();
    return answer;
  }

  // 選択肢リスト → 選択 index（0起点）。非対話時は defaultIndex。
  // items は文字列配列（表示のまま）。
  async function choice(message, items, { defaultIndex = 0 } = {}) {
    if (nonInteractive) return defaultIndex;
    separateQuestion();
    output.write(`${message}\n`);
    items.forEach((item, i) => output.write(`  ${i + 1}) ${item}\n`));
    let separate = false; // 初回の入力欄は同じ質問の選択肢に続ける。
    for (;;) {
      const answer = (await ask('> ', { separate })).trim();
      separate = true;
      if (answer === '') return defaultIndex;
      const n = Number(answer);
      if (Number.isInteger(n) && n >= 1 && n <= items.length) return n - 1;
    }
  }

  // y/n。null は既定なし（空Enterで再質問・非対話では false）。
  async function yesNo(message, { defaultValue = true } = {}) {
    if (nonInteractive) return defaultValue ?? false;
    const hint = defaultValue === null ? '[y/n]' : defaultValue ? '[Y/n]' : '[y/N]';
    for (;;) {
      const answer = (await ask(`${message} ${hint} `)).trim().toLowerCase();
      if (answer === '' && defaultValue !== null) return defaultValue;
      if (answer === 'y' || answer === 'yes') return true;
      if (answer === 'n' || answer === 'no') return false;
    }
  }

  // 数値入力（既定は整数）。空Enter＝defaultValue（nullなら再入力）。非対話時は defaultValue。
  async function number(message, { defaultValue = null, min = -Infinity, max = Infinity, integer = true } = {}) {
    if (nonInteractive) return defaultValue;
    const hint = defaultValue != null ? ` [${defaultValue}]` : '';
    for (;;) {
      const answer = (await ask(`${message}${hint} `)).trim();
      if (answer === '' && defaultValue != null) return defaultValue;
      if (answer === '') continue;
      const n = Number(answer);
      if (!Number.isFinite(n)) continue;
      if (integer && !Number.isInteger(n)) continue;
      if (n < min || n > max) continue;
      return n;
    }
  }

  // 自由入力。空Enter＝defaultValue。非対話時は defaultValue。
  async function text(message, { defaultValue = '', secret = false } = {}) {
    if (nonInteractive) return defaultValue;
    const hint = defaultValue && !secret ? ` [${defaultValue}]` : '';
    const answer = (await ask(`${message}${hint} `, { secret })).trim();
    return answer === '' ? defaultValue : answer;
  }

  // Enter待ち。非対話時は即通過。
  async function pressEnter(message = '') {
    if (nonInteractive) return;
    await ask(message ? `${message} ` : '');
  }

  // Stage3 の処理中だけ、readline が受けた最初の Ctrl+C / close も中断へ渡す。
  function onInterrupt(handler) {
    const iface = rl;
    iface?.on('SIGINT', handler);
    iface?.on('close', handler);
    return () => {
      iface?.removeListener('SIGINT', handler);
      iface?.removeListener('close', handler);
    };
  }

  function close() {
    closing = true;
    if (rl) { rl.close(); rl = null; }
    for (const restore of restoreWrites) restore();
  }

  return { isInteractive: !nonInteractive, choice, yesNo, number, text, pressEnter, onInterrupt, close };
}
