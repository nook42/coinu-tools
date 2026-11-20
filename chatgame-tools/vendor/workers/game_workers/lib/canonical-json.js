// workers/game_workers/lib/canonical-json.js
import { isCanonicalRestrictedJson } from './protocol-v2.js';
// 公開 JSON が「正準（canonical）」か — つまり `JSON.stringify` が出す唯一の書き方か — を検査する。
//
// ─────────────────────────────────────────────────────────────────────────
// なぜ要るか（P-2026-0822・2026-08-07）
//
// JSON では同じ数を複数の書き方で表せる: `100` / `100.0` / `1e2` / `1.0e2` / `1e+2`。
// 読み手によって扱いが違う:
//   ・JS の `JSON.parse` … 4つとも `100` として読む。
//   ・Rust の採点コア（`crates/scoring-core/src/json.rs`）… **整数トークンだけ**を受け付け、
//     `100.0` を見たら summary 全体を `JsonMalformed` として拒否する。
//
// さらに厄介なのが「JS 側の検査を素通りする」書き方:
//   `{"group_id":9007199254740991.4}` を V8 の `JSON.parse` は **9007199254740991 に丸める**。
//   丸まった後は安全整数なので `normalizeGid` の類は通ってしまう。Rust は元のトークンを見て
//   「小数」と判断し、そのグループを NO_GID として請求葉から外す。
//   実測された結末: **JS は 115384615384615000000000 wei を配り、Rust は 0 wei**。
//   同一入力から2つの答えが出る＝証明が通らない（＝ブロックが確定できない）。
//
// `summary.json` を書くのは運営なので、これは「運営も攻撃者でありうる」前提の系では
// 攻撃者の手が届く場所である。ただし攻撃としては弱く（自分のブロックの証明を作れなくするだけ）、
// **事故で踏む方が現実的**。
//
// そして規約はすでにある — CLAUDE.md「全 R2 JSON は minified `JSON.stringify`」。
// `JSON.stringify` は `100.0` も `1e2` も絶対に出さない。つまり正しく作られたファイルなら
// 問題は起きない。**いままで検査していなかっただけ**なので、規約を検査へ格上げする。
//
// ─────────────────────────────────────────────────────────────────────────
// 検査の中身 — **2段ある**（🔴 2026-08-09 訂正: 以前ここは1段目だけを書いて「これだけ。」と
// 締めていたが、2026-08-08 の J-13 案B2 で2段目が入っている）
//
//   1段目  `JSON.stringify(JSON.parse(text)) === text`（往復一致）
//   2段目  `isCanonicalRestrictedJson(text)`（`protocol-v2.js`。Rust の
//          `crates/scoring-core/src/json.rs::check_canonical_json` と**同じ文法**）
//
// 1段目は「`JSON.stringify` が書いた」ことしか言わない。`JSON.stringify` は数値を必ず最短の
// 正準表記で出し、文字列も必要最小限のエスケープしか使わないが、**その出力の一部は
// Rust の採点コアが受け付けない**（数値は安全整数の10進表記のみ）。
// 実測（往復 true / 文法 false）: `{"x":1.5}` `{"x":0.1}` `{"x":1e+21}` `{"x":1e-7}`
// `{"x":9007199254740992}`（2^53）。`JSON.stringify` は `0.5` も `1e+21` も `1e-7` も実際に出す。
// ⚠️ したがって **「正しく `JSON.stringify` で書けば必ず通る」は成り立たない。**
//    通るのは「`JSON.stringify` で書いた **かつ** 数値が安全整数」のとき。
//    `summary.json` に入る数値は blockNum / group_id / points / 各種 ms 時刻 / 0-1 フラグで
//    非整数が入る余地は無い（R2 実物 129 本＋差分テスト fixture 19 本で偽陽性ゼロを実測）。
//
// ⚠️ 検出できないもの（過信しないこと。ここは1段目・2段目とも同じで、**literally 真のまま**）:
//   ・**素の文字列キーの並べ替え**は検出できない。`JSON.parse` はキーの挿入順を保ち、
//     `JSON.stringify` もその順で出すので往復は一致する（実測 2026-08-07）。
//     並べ替えは manifest の sha256 照合と block-verifier の summary バイト比較が受け持つ。
//   ・逆に、**整数に見えるキー**（`"10"` など）を含むオブジェクトは `JSON.parse` の時点で
//     昇順へ並べ替えられるため、往復が一致しない＝この検査に落ちる。これは偽陽性になりうるので、
//     適用先は `summary.json` に限る（`isCanonicalJsonRequiredKey` を参照）。
//
// ─────────────────────────────────────────────────────────────────────────
// この検査を適用する場所
//
//   ・**読む側だけ**。`summary.json` をテキストからオブジェクトにする箇所すべて。
//   ・**書く側（`putR2ObjectOrThrow` など）は検査不要**。`JSON.stringify` で書いているので
//     定義上必ず正準になる。書く側が正準を保証しているからこそ、読む側で
//     「正準でない＝このパイプラインが書いたものではない」と断定できる。

// 正準 JSON を要求するキー。**`games/block{N}/summary.json` だけ**に限る。
//
// 🔴 他の公開 JSON へ広げてはいけない（2026-08-07・実測）:
//   `entries/block{N}/game_groups.json` などは**整数に見えるキー**を持つオブジェクトを含み、
//   `JSON.parse` が仕様どおりそれらを昇順へ並べ替えるため、正しく `JSON.stringify` で
//   書かれたファイルでも往復が一致しない＝**偽陽性**になる。
//   （R2 の実物で確認: `summary.json` は 106/106 一致・他 315 件は上記の理由で不一致になりうる）
const SUMMARY_KEY_RE = /^games\/block(?:0|[1-9][0-9]*)\/summary\.json$/;

export function isCanonicalJsonRequiredKey(key) {
  return typeof key === 'string' && SUMMARY_KEY_RE.test(key);
}

// 二つの文字列が最初に食い違う位置（0-indexed）。同一なら -1。
// 一方が他方の接頭辞なら短い方の長さ（＝そこから先が余分/不足）。
export function canonicalJsonFirstDiff(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return i;
  }
  return a.length === b.length ? -1 : n;
}

// 食い違い位置の周辺を切り出す（運用で「どこが変か」を目視できるように）。
function excerptAround(s, at, radius = 48) {
  if (at < 0) return s.length > radius * 2 ? s.slice(0, radius * 2) + '…' : s;
  const from = Math.max(0, at - radius);
  const to = Math.min(s.length, at + radius);
  return (from > 0 ? '…' : '') + s.slice(from, to) + (to < s.length ? '…' : '');
}

// 「なぜ拒否するのか」を、第三者・運用者の双方が読んで分かる形で1度だけ書く。
const WHY =
  'All R2 JSON in this system is written with minified JSON.stringify, so a published file must '
  + 'survive JSON.parse -> JSON.stringify unchanged. This one does not, which means the bytes were not '
  + 'produced by this pipeline (or were edited afterwards). That matters because independent re-scorers '
  + 'do not read the alternative spellings of a number the same way: JS JSON.parse accepts 100 / 100.0 / '
  + '1e2 alike and even rounds 9007199254740991.4 to an integer, while the Rust scoring core rejects any '
  + 'token that is not an integer. Accepting this file would let the same input produce two different '
  + 'payouts, so it is refused.';

function makeCanonicalJsonError(reason, label, detail, offset) {
  const err = new Error(`[canonical-json] ${label} is not canonical JSON — ${detail}\n${WHY}`);
  err.name = 'CanonicalJsonError';
  // 🔴 `instanceof` は使わない。vendor 済みコピー（block-verifier / chatgame-tools）と正典とでは
  //   別のモジュール実体になるため、クラスの同一性で判定すると片方で必ず外れる。
  err.canonicalJsonError = true;
  err.canonicalJsonReason = reason;   // 'parse' | 'noncanonical'
  err.canonicalJsonLabel = label;
  if (typeof offset === 'number') err.canonicalJsonOffset = offset;
  return err;
}

// 例外が「正準 JSON 検査による拒否」かどうか（握り潰し防止の再 throw 判定に使う）
export function isCanonicalJsonError(e) {
  return !!(e && e.canonicalJsonError === true);
}

/**
 * 生テキストを「正準 JSON である」ことを確かめてからパースする。
 *
 * @param {string} text  - **生のバイト列（UTF-8 文字列）**。パース済みオブジェクトではない。
 * @param {string} label - エラーメッセージに出す名前（R2 キーなど）
 * @returns {*} パース結果
 * @throws {Error} `err.canonicalJsonError === true` が立った Error。
 *                 `canonicalJsonReason` は 'parse'（JSON として読めない）か
 *                 'noncanonical'（読めるが `JSON.stringify` の出力と違う）。
 */
export function parseCanonicalJson(text, label = 'JSON') {
  if (typeof text !== 'string') {
    throw makeCanonicalJsonError('parse', label,
      `expected the raw published text but got ${text === null ? 'null' : typeof text}`);
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw makeCanonicalJsonError('parse', label, `JSON.parse failed: ${e.message}`);
  }

  let canonical;
  try {
    canonical = JSON.stringify(value);
  } catch (e) {
    // 循環参照は JSON.parse の出力では起こりえないが、BigInt 等の再現不能値と同様に
    // 「正準表現が存在しない」＝拒否側へ倒す。
    throw makeCanonicalJsonError('noncanonical', label, `JSON.stringify failed: ${e.message}`);
  }

  if (canonical !== text) {
    const at = canonicalJsonFirstDiff(text, canonical);
    throw makeCanonicalJsonError('noncanonical', label,
      `re-serializing it with JSON.stringify does not reproduce the published bytes `
      + `(first difference at byte offset ${at}; published ${text.length} bytes, canonical ${canonical.length} bytes)\n`
      + `  published: ${excerptAround(text, at)}\n`
      + `  canonical: ${excerptAround(canonical, at)}`,
      at);
  }

  // 🔴 J-13 案B2（2026-08-08・ユーザー確定）: **往復一致だけでは足りない。**
  //
  //   `JSON.stringify(JSON.parse(t)) === t` は「JS が書いた」ことしか言わない。
  //   Rust の採点コア（`crates/scoring-core/src/json.rs`）は数値を**安全整数の10進表記**しか
  //   受け付けないので、`{"x":1.5}` のように往復は一致するが Rust が読めないファイルが残る。
  //   ＝「公開データは JS で読めるのに証明だけ作れない」（可用性の破れ）。
  //   → **文法を仕様として制限**し、両者の受理集合を一致させる。
  //   `summary.json` に入る数値は blockNum / group_id / points / 各種 ms 時刻 / 0-1 フラグで、
  //   非整数が入る余地は無い（R2 実物 129 本＋差分テスト fixture 19 本で**偽陽性ゼロ**を実測）。
  if (!isCanonicalRestrictedJson(text)) {
    throw makeCanonicalJsonError('noncanonical', label,
      'it round-trips through JSON.stringify but is outside the restricted grammar the Rust '
      + 'scoring core accepts (numbers must be safe integers written in plain decimal; strings must '
      + 'use only the escapes JSON.stringify emits). Publishing it would make the block unprovable.');
  }

  return value;
}
