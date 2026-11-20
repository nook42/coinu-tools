// block-verifier/src/utf8.js
// 公開データのUTF-8デコードは、不正バイトをU+FFFDへ置換せずfail-closedにする。

import { TextDecoder } from 'node:util';

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export class InvalidUtf8Error extends Error {
  constructor(label, cause) {
    super(`${label}: invalid UTF-8`, { cause });
    this.name = 'InvalidUtf8Error';
    this.code = 'INVALID_UTF8';
    this.label = label;
  }
}

export function decodeUtf8(bytes, label) {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch (cause) {
    throw new InvalidUtf8Error(label, cause);
  }
}
