// workers/game_workers/lib/char-counter.js
// 半角/全角文字数カウント（src/utils/tool.js getStringWidth と同じロジック）

export function countHalfWidthChars(str) {
  if (!str) return 0;
  let count = 0;
  for (let i = 0; i < str.length; i++) {
    count += str[i].match(/[^\x01-\x7E\xA1-\xDF]/) ? 2 : 1;
  }
  return count;
}

// ============================================================
// K-S2-003 是正（2026-07-27）: 不可視文字は「発言」として数えない
// ============================================================
// 背景: countHalfWidthChars は ASCII の U+0001〜U+007E と Latin-1 の
// U+00A1〜U+00DF を1、それ以外（半角カナ U+FF71 などを含む）を2と数え、
// **画面に見えるかどうかを考慮していない**。そのため U+200B（ゼロ幅スペース）が
// 2文字として数えられ、13個入りのメッセージを20回送るだけで
// 「500文字以上 + 20発言」の適格条件を満たせた（画面上は空の吹き出しが並ぶだけ）。
// 他メンバーが普通に会話していれば発言が自然に挟まれるため結託も不要で、
// 受領証明も相手クライアントが自動発行する。
//
// 方針（ユーザー決定 2026-07-27）:
//   このゲームは「発言内容が妥当かどうかは他プレイヤーが密告・投票で判断する」設計。
//   したがって取り除くのは **他プレイヤーから見えないもの** に限る。
//     ・空白（半角/全角スペース・改行等）は **数える**。見えるし場所も取る＝表現の一つ。
//       "aaaaa" と "     " は同質であり、内容の適正さは他プレイヤーの判断に委ねる。
//     ・結合記号（Zalgo）も **数える**。汚い表示として可視であり、同上。
//     ・幅ゼロで知覚できない文字だけを除去する（＝隠れて文字数・発言数を稼げるもの）。
//
// 決定論性: Unicode プロパティ正規表現（\p{...}）は実行環境の Unicode バージョンに
// 依存し、検証ツールとの再現性を壊すため使用しない。**明示的なコードポイント表**で固定する。
// 表を変更する場合は manifest rules の visibleCharsRule 版数を上げること。

// 可視文字規則の版数。**INVISIBLE_RANGES を変更したら必ず上げること。**
// manifest.rules.visibleCharsRule として公開され、検証ツールがピン値と照合する
// （第三者が「どの規則で採点されたブロックか」を判別できるようにするため）。
export const VISIBLE_CHARS_RULE_VERSION = 3;

// 不可視（幅ゼロ・知覚不能）コードポイントの範囲表。[start, end] 両端含む。
// TAB(U+0009) / LF(U+000A) / CR(U+000D) は改行・字下げとして**可視**なので除外しない。
//
// 🔴 **v2（2026-08-05・P-2026-0811 #6）: 3,762 コードポイントの取りこぼしを補った。**
//    旧表は Default_Ignorable の一部しか含んでおらず、K-S2-003（不可視文字による
//    文字数の水増し）が**そのまま再現できた**（短く喋っているように見せて500文字条件を満たせた）。
//
// 🔴 **採否の基準（ユーザー確定 2026-08-05）: 「空白すら描かれないものだけを不可視とする」。**
//    画面に**空白として場所を取る**文字は、目で見て分かるので**数える**。
//    → ハングルフィラー **U+115F / U+1160 / U+3164 / U+FFA0 は意図的に除外**している。
//      これらは幅ゼロではなく**空白として描画される**ため、既存の「空白は可視だから数える」
//      方針に従う。表に足さないこと。
export const INVISIBLE_RANGES = [
  [0x0000, 0x0008], [0x000B, 0x000C], [0x000E, 0x001F], // C0 制御（TAB/LF/CR を除く）
  [0x007F, 0x009F],                                     // DEL + C1 制御
  [0x00AD, 0x00AD],                                     // SOFT HYPHEN
  [0x034F, 0x034F],                                     // COMBINING GRAPHEME JOINER
  [0x061C, 0x061C],                                     // ARABIC LETTER MARK
  [0x17B4, 0x17B5],                                     // KHMER VOWEL INHERENT AQ / AA
  [0x180B, 0x180F],                                     // MONGOLIAN FVS 1-4 + VOWEL SEPARATOR
  [0x200B, 0x200F],                                     // ZWSP / ZWNJ / ZWJ / LRM / RLM
  [0x202A, 0x202E],                                     // bidi embedding / override
  [0x2060, 0x206F],                                     // WORD JOINER / invisible operators /
                                                        //   U+2065（未割当だが Default_Ignorable）/
                                                        //   bidi isolates / deprecated format
  [0xFE00, 0xFE0F],                                     // variation selectors
  [0xFEFF, 0xFEFF],                                     // BOM (ZWNBSP)
  [0xFFF0, 0xFFFB],                                     // 未割当 Default_Ignorable + interlinear annotation
  [0x13430, 0x1343F],  // EGYPTIAN HIEROGLYPH 書式制御（quadrat 結合・描画されない）
  [0x1BCA0, 0x1BCA3],                                   // SHORTHAND FORMAT CONTROLS
  [0x1D173, 0x1D17A],                                   // MUSICAL SYMBOL 書式制御
  [0xE0000, 0xE0FFF],                                   // tag characters + variation selectors supplement
                                                        //   （旧 [0xE0000,0xE007F] と [0xE0100,0xE01EF] を統合し
                                                        //     未割当 Default_Ignorable の穴を埋めた）
];

export function isInvisibleCodePoint(cp) {
  for (const [lo, hi] of INVISIBLE_RANGES) {
    if (cp >= lo && cp <= hi) return true;
  }
  return false;
}

/// 不可視文字を除去した文字列を返す（サロゲートペア対応のためコードポイント単位で走査）。
/// 表示・保存される本文は変更しない。**採点の数え方だけ**がこの関数を通る。
export function stripInvisibleChars(str) {
  if (!str) return '';
  let out = '';
  for (const ch of str) { // for...of はコードポイント単位
    if (!isInvisibleCodePoint(ch.codePointAt(0))) out += ch;
  }
  return out;
}

/// 適格条件（最低発言量）用の文字数。不可視文字を除去してから従来規則で数える。
/// 上限（maxChars / maxMsgChars）には使わない — あちらは Evidence バンドルのサイズを
/// 縛るのが目的なので、不可視文字も数える countHalfWidthChars のままでなければならない。
export function countVisibleChars(str) {
  return countHalfWidthChars(stripInvisibleChars(str));
}

/// 「画面に出る内容が1文字でもあるか」。`filterVisibleMessages` の述語を単体で使えるようにしたもの。
///
/// 🔴 J-17（2026-08-08・ユーザー確定）: **クライアントの受信ゲートもこれと同じ判定にする。**
///    `text` を省いた（あるいは `null` の）発言＝**幽霊メッセージ**は、採点側ではここが落とすので
///    文字数にも発言回数にも入らない。しかし受信側が受理してしまうと
///      ・全員の画面に空の吹き出しとして出る
///      ・全員の提出バンドルに載る（`JSON.stringify` が `text: undefined` をキーごと落とす）
///      ・chatHash の原像にだけ入る（`?? ''` で空文字として）
///    という「正典の発言集合には存在しないのに全員が運ぶ発言」が作れた。
///    → 受信段階（`src/hooks/useGameWebSocket.js` の `verifyIncomingMessage`）でここを課す。
///    ⚠️ `?? ''` ではなく `|| ''` のままでよい（`stripInvisibleChars` 自身が `!str` を空文字に潰すので、
///       `undefined` / `null` / `''` / `0` / `false` はいずれも同じ結論になる）。
export function hasVisibleContent(text) {
  return stripInvisibleChars(text || '').length > 0;
}

/// 可視内容がゼロのメッセージ（＝不可視文字だけ／空／`text` 欠落・`null`）を除いた配列を返す。
/// 文字数にも発言回数にも数えないため、採点前にこれで濾す。
/// 副次効果として、不可視メッセージを挟んで他人の「連続発言」を分断し
/// 発言回数を水増しさせる経路も塞がる。
export function filterVisibleMessages(messages) {
  if (!Array.isArray(messages)) return [];
  return messages.filter(m => hasVisibleContent(m?.text));
}

// ============================================================
// 上限・下限の正規化（P-2026-0821・2026-08-07）
// ============================================================
// 🔴 **NaN は自分が現れる比較式を「両方向とも false」にする ＝ 上限がまるごと消える。**
//    この系では同じ形の fail-open が過去に3回見つかっている。流れはいつも同じ:
//      環境変数 → `parseInt` → **検査なし** → 比較演算
//    実測値:
//      `parseInt('１００') = NaN`（全角）／`parseInt(' ') = NaN`
//      `parseInt('100件') = 100`（後続を黙って捨てる）／`parseInt('1e2') = 1`（宣言値とズレる）
//
//    ⚠️ **分割代入のデフォルト（`{maxMessages = 100} = {}`）は `undefined` にしか効かない。**
//       `NaN` が渡ると素通りする。関数のデフォルト引数（`minChars = 500`）も同じ。
//       そのため「デフォルト値を書いてあるから安全」は成り立たない。
//    ⚠️ NaN は**自分が現れる比較式だけ**を false にする。1つの NaN で3つの上限が
//       同時に消えるわけではないので、上限ごとに正規化が要る。
//
// 🔴 これは ZKP の一致性にも直結する。Rust ゲスト（crates/scoring-core）は `Caps` を
//    **ゲスト定数（100 / 10000 / 1000）で焼く**ので、JS 側だけ上限が消えれば
//    同一入力から2つの点数表が出る＝そのブロックの証明は永久に通らない。
//    実測（150発言×4字のフィクスチャ）: `maxMessages=100` → 全員 0pt（min_chars）／
//    `maxMessages=NaN` → `220 / 170 / 50`。
export const DEFAULT_CHAT_CAPS = Object.freeze({
  maxChars: 10000,
  maxMessages: 100,
  maxMsgChars: 1000,
});

// ============================================================
// ZKP ゲスト定数のミラー（P-2026-0822・2026-08-07・ユーザー確定）
// ============================================================
// 🔴 **これは ZKP ゲストの ELF に焼き込まれた値のミラーである。**
//    正典は `crates/scoring-core/src/scoring.rs` の `Rules::default()`
//    （`min_chars` / `min_messages` / `caps.{max_chars, max_messages, max_msg_chars}`）。
//
// なぜ焼き込むのか（2026-08-04 のユーザー決定）:
//    しきい値を manifest の宣言値から読むと、**運営が特定のブロックだけ `min_chars` を
//    下げて仲間を救う**という攻撃面ができる。ゲストが定数として持てば、
//    値を動かすには vkey の差し替え（＝公開・タイムロック）が必要になる。
//
// なぜ JS 側にもミラーを置くのか:
//    サーバー（`game-master-DO.js`）はこの5値を**環境変数から読む**ので、
//    どちらかが動いた瞬間に「同一入力から2つの点数表」が出る。
//    実測（3人が全員ちょうど500字）: `GAME_MIN_CHARS=501` で
//    **サーバー側 全員0点 ／ 回路側 全員200点**。証明が結果と噛み合わず配布不能になる。
//    そこで `assertGuestPinnedRules` を採点の入口で毎回走らせ、食い違いを **throw** で止める。
//    このファイルは `block-verifier/vendor/` と `chatgame-tools/vendor/` の両方へ
//    ベンダリングされるので、第三者の検証ツールも同じ値を見られる。
//
// ⚠️ **この5値を変えるときは必ず4点セットで動かすこと。1つでも欠けると証明が通らない:**
//    ① `crates/scoring-core/src/scoring.rs` の `Rules::default()` を変える
//    ② ZKP ゲストの ELF を再ビルドする（`crates/group-guest`）
//    ③ vkey を更新する（🔴 Stage 5 で vkey を固定した後は **14日のタイムロック**が要る）
//    ④ wrangler vars（`GAME_MIN_*` / `GAME_MAX_*`）と検証ツールの pin
//       （`block-verifier/src/config.js` / `chatgame-tools/config.js`）を揃える
//    ＋ この定数（`GUEST_PINNED_RULES`）も同時に更新し、vendor を再同期する。
//
// ⚠️ **運用上の帰結**: これにより5値は事実上凍結される。
//    「テストランのために一時的に `GAME_MIN_CHARS` を下げる」はもうできない
//    （下げた瞬間に採点が throw する）。閾値を触りたいときは上の4点セットごと動かすこと。
export const GUEST_PINNED_RULES = Object.freeze({
  minChars: 500,
  minMessages: 20,
  maxChars: 10000,
  maxMessages: 100,
  maxMsgChars: 1000,
});

// S3R4-U-PRIORITY: E は自分と他人の各20件、E′ は集約を1枚として40枚。
// 3つの個別上限は manifest に宣言し、和の40件も独立して検査する。
export const PRIORITY_OWN_MESSAGES_MAX = 20;
export const PRIORITY_OTHER_MESSAGES_MAX = 20;
export const PRIORITY_MESSAGES_MAX = 40;
export const PRIORITY_RECEIPTS_MAX = 40;

// submission-limits.js の MAX_GROUP_PLAYERS と同じ本番の人数上限。
export const PRIORITY_RULE_MAX_GROUP_PLAYERS = 5;

export function assertPriorityCapacity(minMessages, maxMessages, players = PRIORITY_RULE_MAX_GROUP_PLAYERS) {
  if (!Number.isSafeInteger(minMessages) || minMessages < 0
    || !Number.isSafeInteger(maxMessages) || maxMessages < 0
    || !Number.isSafeInteger(players) || players < 1
    || PRIORITY_OWN_MESSAGES_MAX + (players - 1) * PRIORITY_OTHER_MESSAGES_MAX > maxMessages
    || minMessages > PRIORITY_OWN_MESSAGES_MAX) {
    throw new Error('[calc] priority exceeds the canonical per-sender message cap');
  }
}

/// `GUEST_PINNED_RULES` の各キー ↔ 環境変数名（エラー文に出すため）。
const GUEST_PINNED_ENV_NAMES = Object.freeze({
  minChars: 'GAME_MIN_CHARS',
  minMessages: 'GAME_MIN_MESSAGES',
  maxChars: 'GAME_MAX_CHARS',
  maxMessages: 'GAME_MAX_MESSAGES',
  maxMsgChars: 'GAME_MAX_MSG_CHARS',
});

/// 実際に採点へ適用するしきい値が、ZKP ゲストに焼かれた値と**完全一致**することを要求する。
/// 1つでも違えば throw する（fail-closed）。
///
/// 🔴 起動時ではなく**採点の入口**で呼ぶこと（ユーザー確定 2026-08-07）。理由は2つ:
///    ① 環境変数は起動後にも変わりうる（長寿命の Durable Object には古い値が残る）
///    ② より本質的に、採点関数はしきい値を**引数で受け取る**ので、
///       env を検査しても「実際に採点で使われた値」を縛れていない。
///       ここで縛れば、どの経路から来た値でもゲストと一致することが保証される。
///
/// @param applied {minChars, minMessages, maxChars, maxMessages, maxMsgChars}
///                — **これから採点関数に渡す値そのもの**（env ではない）
/// @param where   エラー文に出す文脈（例 `block 7`）
export function assertGuestPinnedRules(applied, where = '') {
  const diffs = [];
  for (const key of Object.keys(GUEST_PINNED_RULES)) {
    const got = applied?.[key];
    const want = GUEST_PINNED_RULES[key];
    // `Object.is` を使うのは NaN を「一致」にしないため（`NaN === NaN` は false だが、
    // 「値が揃っているか」を見る比較は Object.is のほうが意図が明確）。
    if (!Object.is(got, want)) {
      diffs.push(`  ・${GUEST_PINNED_ENV_NAMES[key]} (${key}): 適用値=${JSON.stringify(got)} / ゲスト定数=${want}`);
    }
  }
  if (diffs.length === 0) {
    assertPriorityCapacity(applied.minMessages, applied.maxMessages);
    return;
  }
  throw new Error(
    `[calc] scoring thresholds disagree with the ZKP guest constants${where ? ` (${where})` : ''} — ` +
    `採点しきい値が ZKP ゲストの焼き込み値と食い違っています。このまま進めると\n` +
    `同一入力から2つの点数表（サーバー版 / 回路版）が出て、このブロックは**永久に配布できません**。\n` +
    `食い違い:\n${diffs.join('\n')}\n` +
    `適用値は wrangler vars（GAME_MIN_* / GAME_MAX_*）由来です。ゲスト定数の正典は\n` +
    `crates/scoring-core/src/scoring.rs の Rules::default()（ミラー: workers/game_workers/lib/char-counter.js の GUEST_PINNED_RULES）。\n` +
    `対処はどちらか一方:\n` +
    `  (a) 【推奨・即効】wrangler vars を上の「ゲスト定数」の値へ戻して再デプロイする\n` +
    `  (b) しきい値を本当に変えるなら **4点セットで同時に**動かす:\n` +
    `      ① crates/scoring-core/src/scoring.rs の Rules::default()\n` +
    `      ② ZKP ゲスト ELF の再ビルド（crates/group-guest）\n` +
    `      ③ vkey の更新（🔴 Stage 5 以降は 14日のタイムロックが必要）\n` +
    `      ④ wrangler vars ＋ 検証ツールの pin（block-verifier/src/config.js・chatgame-tools/config.js）\n` +
    `      ＋ char-counter.js の GUEST_PINNED_RULES を更新して vendor を再同期する`
  );
}

/// 正の安全整数だけを通し、それ以外（NaN / undefined / null / 非数値 / 小数 / 0 以下）は
/// 既定値に落とす。**`applyChatCaps` と採点エンジンが同じ1つの値を使う**ための共通入口。
/// ⚠️ 「小数を落とす」のは意図的。ZKP ゲストは整数しか表現しないので、
///    `maxMessages = 100.5` のような値をそのまま採用すると両実装が割れる。
export function normalizeChatCaps(caps) {
  const pick = (v, d) => (Number.isSafeInteger(v) && v > 0 ? v : d);
  return {
    maxChars: pick(caps?.maxChars, DEFAULT_CHAT_CAPS.maxChars),
    maxMessages: pick(caps?.maxMessages, DEFAULT_CHAT_CAPS.maxMessages),
    maxMsgChars: pick(caps?.maxMsgChars, DEFAULT_CHAT_CAPS.maxMsgChars),
  };
}

/// 環境変数由来の整数を **fail-closed** で読む（Durable Object のコンストラクタ用）。
/// 未設定（undefined / null / ''）は既定値。設定されているのに整数として読めなければ **throw**。
///
/// 🔴 なぜ既定値へ黙って落とさないのか（ユーザー確定・2026-08-07）:
///    しきい値は ZKP ゲストに焼かれている。運用者が環境変数を打ち間違えたときに
///    黙って既定値へ落とすと「宣言した値」と「適用した値」が食い違ったまま
///    ブロックが1本進み、あとから証明が通らない（＝取り返しがつかない）。
///    **DO が起動しないほうが、上限なしのチャット期間より安全**である。
/// 🔴 `parseInt` ではなく `Number` を使う。`parseInt('100件') = 100` / `parseInt('1e2') = 1` と
///    「宣言値と適用値がズレる」経路をここで塞ぐため（`Number` は両方とも弾く／`1e2` は 100）。
export function requireIntEnv(name, raw, fallback, minValue = 1) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  // 🔴 空白だけの文字列は **fallback にも 0 にもしない**。
  //    `parseInt(' ') = NaN`（旧実装は fail-open）／`Number(' ') = 0`（黙って「上限0／閾値0」）
  //    のどちらも事故なので、ここで明示的に落とす。
  if (typeof raw === 'string' && raw.trim() === '') {
    throw new Error(`[config] ${name} must be an integer >= ${minValue} (got ${JSON.stringify(raw)})`);
  }
  const v = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isSafeInteger(v) || v < minValue) {
    throw new Error(
      `[config] ${name} must be an integer >= ${minValue} (got ${JSON.stringify(raw)})`
    );
  }
  return v;
}

// チャット量キャップ（Evidence計画 §2.1b の決定論規則）。
// 正本メッセージ集合に対する上限強制のバックストップ。サーバー（ChatGameDO）が
// 送信時に同じ上限で拒否するため正常系では発火しないが、提出物への自己注入
// メッセージにも同一規則が適用されることで、上限が敵対的提出に対しても保証される。
// 規則: 呼び出し側が渡す比較器の順に、uidごとに件数・
// 半角換算文字数を累積。
//   ①1メッセージが maxMsgChars 超 → そのメッセージを除外（累積は進めない）
//   ②採用すると件数が maxMessages 超 → 除外
//   ③採用すると文字数が maxChars 超 → 除外（以降の小さいメッセージは採用され得る）
// 検証ツールも同一規則で再現すること（バイト同一の正本集合に到達する必要がある）。
// 採点の規則版15では、最早の既読時刻だけで選び、結果を正準順へ戻す。
// 比較器未指定の歴史的な呼び出しでは id 昇順を保つ。
// 🔴 P-2026-0821（2026-08-07）: **分割代入のデフォルトをやめ、本体で正規化する。**
//    旧 `{ maxChars = 10000, maxMessages = 100, maxMsgChars = 1000 } = {}` は
//    `undefined` にしか効かず、`GAME_MAX_MESSAGES` が `parseInt` で NaN になった caps が
//    そのまま届くと `st.msgs + 1 > NaN` / `st.chars + c > NaN` / `c > NaN` が
//    **すべて false** になり、上限が3本とも消えた（fail-open）。
//    **どこから呼ばれても** fail-open しないよう、入口で `normalizeChatCaps` を通す。
export function applyChatCaps(messages, caps = {}, compareFn = null) {
  const { maxChars, maxMessages, maxMsgChars } = normalizeChatCaps(caps);
  if (!Array.isArray(messages)) return [];
  const sorted = [...messages].sort(compareFn || ((a, b) => (a?.id || 0) - (b?.id || 0)));
// 🔴 P-2026-0819（2026-08-07）: **`Object.create(null)` を使う。**
//    `isCanonicalUid` は ASCII 印字可能を許すので uid に `__proto__` / `constructor` を置ける。
//    素の `{}` だと実測で:
//      uid="__proto__"   → `Object.prototype.msgs = NaN` / `chars = NaN` を書き込み、**プロセス全体を汚染**
//      uid="constructor" → 参照が `Object` 関数を返し、1文字しか喋っていない人の失格理由が
//                          `min_chars` ではなく `vote_fraud` になる
//    さらに `perUid[uid] < minChars` が **NaN 比較で常に false** になり、閾値判定が空振りする。
//    Rust（ZKP ゲスト）は uid を添字に解決するので汚染しない ＝ **同一入力から2つの点数表**。
  const perUid = Object.create(null); // uid -> { chars, msgs }
  const kept = [];
  for (const msg of sorted) {
    if (!msg || msg.uid == null) continue;
    const c = countHalfWidthChars(msg.text || '');
    if (c > maxMsgChars) continue;
    const st = perUid[msg.uid] || (perUid[msg.uid] = { chars: 0, msgs: 0 });
    if (st.msgs + 1 > maxMessages) continue;
    if (st.chars + c > maxChars) continue;
    st.msgs += 1;
    st.chars += c;
    kept.push(msg);
  }
  return kept;
}

// 受理済み・鮮度内の既読の時刻列は呼び出し側が数値昇順に前計算する。
// 上限の鍵は最初の時刻だけ。後の既読の時刻と受け手数は順位に使わない。
export function compareFirstReceiptTimes(a, b) {
  const firstA = a.length ? a[0] : Number.POSITIVE_INFINITY;
  const firstB = b.length ? b[0] : Number.POSITIVE_INFINITY;
  return firstA < firstB ? -1 : firstA > firstB ? 1 : 0;
}

// 上限の選別だけを既読順にし、後続のターン・資格・公開値には正準順を渡す。
export function capMessagesByFirstReceipt(messages, caps, timesOf, compareFn) {
  const kept = applyChatCaps(messages, caps,
    (x, y) => compareFirstReceiptTimes(timesOf(x), timesOf(y)) || compareFn(x, y));
  return kept.sort(compareFn);
}

// 規則版数18: 最優先欄の E の和集合を正準順で先取りし、残りだけを最初の既読の順で選ぶ。
// 件数は両方に掛け、字数の上限は E だけ免除する。累計字数には E も足す。
export function capMessagesWithEvidence(evidence, rest, caps, timesOf, compareFn) {
  if (!evidence.length) return capMessagesByFirstReceipt(rest, caps, timesOf, compareFn);
  const { maxChars, maxMessages, maxMsgChars } = normalizeChatCaps(caps);
  const ordered = [...evidence].sort(compareFn).map(m => ({ m, evidence: true }));
  const remaining = [...rest].sort((a, b) =>
    compareFirstReceiptTimes(timesOf(a), timesOf(b)) || compareFn(a, b));
  for (const m of remaining) ordered.push({ m, evidence: false });
  const perUid = Object.create(null);
  const kept = [];
  for (const { m, evidence: isEvidence } of ordered) {
    if (!m || m.uid == null) continue;
    const chars = countHalfWidthChars(m.text || '');
    if (chars > maxMsgChars) continue;
    const state = perUid[m.uid] || (perUid[m.uid] = { msgs: 0, chars: 0 });
    if (state.msgs + 1 > maxMessages) continue;
    if (!isEvidence && state.chars + chars > maxChars) continue;
    state.msgs += 1;
    state.chars += chars;
    kept.push(m);
  }
  return kept.sort(compareFn);
}

// ライブ表示が数える「この端末から提出できる正典メッセージ集合」。採点と同じ
// applyChatCaps を唯一の選別規則とし、両クライアントが手書きの写しを持たないようにする。
// 戻り値は入力順を保つため、画面の表示順は変えずに進捗値だけを安全側へ揃えられる。
export function capMessagesForScoring(messages, caps = {}, compareFn = null) {
  const list = Array.isArray(messages) ? messages : [];
  const kept = applyChatCaps(list, caps, compareFn);
  if (kept.length === list.length) return list;
  const remaining = new Map();
  for (const message of kept) remaining.set(message, (remaining.get(message) || 0) + 1);
  return list.filter((message) => {
    const count = remaining.get(message) || 0;
    if (count === 0) return false;
    remaining.set(message, count - 1);
    return true;
  });
}

// 各ユーザーの「有効発言回数」を集計する。
// 連続発言（直前のメッセージが同一人物）はカウントせず、
// 他者の発言の後（または最初の発言）のみ +1 する。
// 戻り値: { [uid]: number }
export function countMessageTurns(messages) {
// 🔴 P-2026-0819（2026-08-07）: **`Object.create(null)` を使う。**
//    `isCanonicalUid` は ASCII 印字可能を許すので uid に `__proto__` / `constructor` を置ける。
//    素の `{}` だと実測で:
//      uid="__proto__"   → `Object.prototype.msgs = NaN` / `chars = NaN` を書き込み、**プロセス全体を汚染**
//      uid="constructor" → 参照が `Object` 関数を返し、1文字しか喋っていない人の失格理由が
//                          `min_chars` ではなく `vote_fraud` になる
//    さらに `perUid[uid] < minChars` が **NaN 比較で常に false** になり、閾値判定が空振りする。
//    Rust（ZKP ゲスト）は uid を添字に解決するので汚染しない ＝ **同一入力から2つの点数表**。
  const turns = Object.create(null);
  if (!Array.isArray(messages)) return turns;
  let prevUid = null;
  for (const msg of messages) {
    if (!msg || msg.uid == null) continue;
    if (msg.uid !== prevUid) {
      turns[msg.uid] = (turns[msg.uid] || 0) + 1;
    }
    prevUid = msg.uid;
  }
  return turns;
}
