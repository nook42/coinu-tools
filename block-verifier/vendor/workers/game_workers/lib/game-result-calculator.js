// workers/game_workers/lib/game-result-calculator.js
// ゲーム結果計算ライブラリ（v3.2: タブー全廃・signKey/encryptKey・受領証明正典・不正DQ）
// サーバー側復号・検証、ポイント計算、失格判定、BTCu分配
//
// 正典規則（docs/CHAT_GAME_SIMPLIFICATION_SPEC.md §6 が正典。ここは要約）:
//   - 鍵: signKey（全署名担当・永遠に非公開・登録blockAddress.pubKeyが公開鍵）
//         encryptKey（投票/密告の自己暗号化専用・提出物で公開）
//   - チャット正典 = 有効提出物の最優先欄の E の和集合を先に採り、E′ の既読を先に受理する。
//     残りは登録済みで他メンバーの鮮度内既読がある発言を最早既読順で選ぶ（規則版数18）。
//   - 投票/密告の有効条件 = signKey署名 ∧ チャット窓内 ∧ 他メンバー受領証明≥1件 ∧
//     encryptKeyで復号でき対象が自分以外のメンバー
//     🔴 **条件「本人提出物に含まれる」（SPEC §6.4 条件4）は 2026-08-05 に廃止**
//        （P-2026-0805）。投票／密告の正典も union になった。
//   - 検証⑥（vote_fraud/report_fraud）: **(c) デタラメ発信（復号不能・無効対象）のみ**。
//     🔴 (a) 対象矛盾は 2026-08-05 に全廃（投票・密告とも。クライアントのガードが
//        fail-open なので失格＝全損は重すぎる）。(b) 受領済み発信の未提出／取下げも
//        条件4 の廃止と同時に廃止（union が事後削除を直接塞ぐ）。
//     signKey非公開により共謀でも冤罪不可能
//   - 密告報酬 = floor(失格者デポジットPt / (グループ人数−1)) を各密告者に定額分配
//     （分子は適格帯の上限でクランプ＝決定②-3）

import { verifyMessage, keccak256, toHex } from 'viem';
import { decrypt } from 'eciesjs';
import { countMessageTurns, countHalfWidthChars, countVisibleChars, hasVisibleContent, filterVisibleMessages, capMessagesWithEvidence, normalizeChatCaps } from './char-counter.js';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString, isReceiptTimely,
  msgRefOf, isMsgRef, isActionHash, isCanonicalSignature,
  isCanonicalTimestamp, isCanonicalText, isCanonicalUid, isOpaqueField, isCanonicalDepositIds,
  isCanonicalActionCiphertext,
  receiptMaxActionsPerPair, receiptBundleCap, receiptMaxRefsPerReceipt,
  messageBundleCap, messagePerSenderCap,
  MAX_OBSERVED_ACTIONS_PER_ACTOR,
  buildMsgKeyGetter, canonicalComparatorV2, computeChatHashV2, compareHexAsc, compareStrAsc,
  // P-2026-0829: 入口（ChatGameDO）と採点本体で**同じ**門番を使う（移設・挙動不変）
  canonMetaInt, parseBlockAddress, isRepresentableSignature,
  // J-12 案A3 / J-33 案D（2026-08-08）: ②.6 の原像を1通りに固定する2つの門番
  isCanonicalActionPreimage, actionSectionKeysAreMembers} from './protocol-v2.js';
import { selfReceiptAggregateSignString } from './evidence-compact-v1.js';
import {
  MAX_RECEIPT_FACTS,
  MAX_SELF_AGGREGATE_TARGETS,
  isPlainRecord,
  validateSubmissionStructure,
} from './submission-limits.js';
import { verifyPriorityFields } from './priority-fields.js';

/// 合成キーの区切り。**uid のアルファベット外**の文字を使う。
///
/// 🔴 P-2026-0819（2026-08-07）: `isCanonicalUid` は `/^[\x21-\x7E]+$/`（ASCII 印字可能）なので
///    **`|` も `:` も uid に入れられる**。テンプレート文字列で合成した鍵は衝突する。実測:
///      名簿 = A / A|B / B|C / C のとき
///        `readReceiptTimesByPair`: `"A|B" + "|" + "C"` == `"A" + "|" + "B|C"`
///        → A|B は C の発言を1件も受領していないのに、A が B|C を受領した記録で
///          **§6.9 の5件既読要件をタダで満たし**、C が冤罪失格（JS: C=0(reported) / Rust: C=75）
///        `msgExaminedPairOf`: owner="A" sender="B|C" == owner="A|B" sender="C"
///        → メッセージ署名検証の予算を他人と共有し、C が min_chars+min_messages 失格
///          （JS: C=0 / Rust: C=75）
///    Rust（ZKP ゲスト）は全部**添字のタプル**なので衝突しない ＝ **同一入力から2つの点数表**。
///    ⚠️ 区切りを変えるだけで直る（鍵はすべて内部の Map/Set で、外へは出ない）。
///       `isCanonicalUid` を狭めるのは「将来の匿名エントリー」の余地を削るので採らない。
///    ⚠️ **4箇所を同時に**直すこと。1箇所だけだと残りで同じことが起きる。
const KEY_SEP = '\x1f';   // UNIT SEPARATOR（\x21-\x7E の外＝uid には現れない）

/// 🔴 P-2026-0829（2026-08-07）: `parseBlockAddress` / `canonMetaInt` は
///    `protocol-v2.js` へ**移設**した（挙動不変）。採点本体にしか無かったせいで、
///    ChatGameDO の入口（`handleInit` / 各 WS ハンドラ）が同じ入力を素通しし、
///    採点まで park が遅延していたため。定義は1つ・import で共有する。

/// 発信候補（投票・密告）の正準順序 — **全順序**。
///
/// `(timestamp 昇順 → actionHash 昇順 → signature 昇順)`。
///
/// 🔴 P-2026-0812 F4（2026-08-06）: 末尾の `signature` は**必須**。
///    `actionHashV2` は `(type, blockNum, groupId, uid, encrypted, timestamp)` のハッシュで
///    **署名を含まない**ので、同じ発信に別の有効署名を付けた「双子」は前2キーが同値になる。
///    `Array.prototype.sort` は同値要素間で安定＝**元配列の並び**が採否を決めてしまい、
///    件数上限（`MAX_OBSERVED_ACTIONS_PER_ACTOR`）の境界で本物が押し出された
///    （実測: 双子を先頭に置くだけで投票が消え `no_vote` 失格・250点 → 0点）。
///    `signature` まで一致する2件は**バイト同一**なので、そこから先の順序は結果に影響しない。
/// 署名を**小文字16進**に正規化する。
///
/// これは過去の受理形を念のため同一視する歴史的な正規化。現行の
/// `isCanonicalSignature` / `isRepresentableSignature` は小文字 hex だけを許すため、
/// 正規な入力はこの関数に到達する時点ですでに小文字である。
export const sigLower = (v) => (typeof v === 'string' ? v.toLowerCase() : v);

export const candCanonCmp = (x, y) =>
  (x.a.timestamp - y.a.timestamp)
  || compareHexAsc(x.h, y.h)
  || compareStrAsc(sigLower(x.a.signature), sigLower(y.a.signature));

/// 受領証明の**正準順序**（受理順を決める全順序）。
///
/// 🔴 P-2026-0812 F1/F2/F3（2026-08-06）: **整列してから受理する。**
///    枠（ペア上限・カバー・(受領者,ref) の受領時刻）は先着で消費されるので、
///    提出配列の順がそのまま採点結果になっていた。実測で反転したもの:
///      F1 (受領者,ref) に残る受領時刻が先着 → 密告の受領要件（§6.9）が反転
///         （被密告者 totalPoints 0 ↔ 30・密告者 230 ↔ 250）
///      F2 既読ペア枠が binding なとき、どの発言が正典に入るかが配列順で決まる
///         （min_messages で 250 ↔ 0）
///      F3 行動ペア枠（同一種別で11件）が binding なとき投票先が入れ替わる
///         （100点が p1 ↔ p2 で移動）
///    整列キー: (timestamp 昇順 → 種別 r<a → receiverUid 昇順 → 参照キー昇順 → signature 昇順)。
///    timestamp は全順序を作るための先頭キーであり、結果として最も早い受領時刻が残る。
///    v15 では (受け手, ref) ごとの最早既読が上限の選別に直結する採点要件である。
///    「N件目を受け取った時刻」の旧要請は J-35 の規則版数4で消えた。
///    末尾の signature も全順序にするために必要である
///    （前段のキーが同値になる受領証明が実在する）。
///
/// 🔴 J-40（2026-08-09）: **関数スコープから持ち上げて `export` した（挙動は1バイトも変えない）。**
///    提出物を組み立てるクライアント（`src/components/game/SubmissionPhase.js` と
///    ミラーの `chatgame-tools/src/recovery/bundle.js`）は、同梱する受領証明の重複排除を
///    **生の signature 文字列の昇順**でやっていた。採点は上記の全順序で受理するのに、
///    クライアントは「署名の辞書順で最初の1枚」を残す＝**別の1枚が枠を取る**。
///    最も早い受領時刻は v15 の上限選別にも必要である（J-35 の旧資格要件とは別）。
///    攻撃者は被害者の発言に対して「正しく署名した**不鮮度**な受領証明」を作り、
///    署名が本物より辞書順で小さくなるまで timestamp を振り直して P2P に流すだけで、
///    全クライアントの提出物から**本物の鮮度内受領証明を追い出せた**（実測: 本物を運んだ
///    提出物 4/4 → 0/4・被害者が `min_chars` 失格 70点 → 0点・攻撃者の自損ゼロ）。
///    ⚠️ 定義はここ1箇所だけ。クライアントは**この関数を import する**こと
///       （写経すると同じ穴が静かに戻る）。
///
/// 🔴 J-40b（2026-08-09）: **J-40 の是正は不完全で、しかもこの整列が攻撃を容易にしていた。**
///    J-40 が「枠取りの条件に鮮度を足す ＝ 採点の `carried` と同じ集合にする」と書いたのは
///    **誤り**で、同じ受理ループの `if (!inChatWindow(rc.timestamp)) continue;` を
///    見ていなかった。並びを **timestamp 昇順**にした結果、攻撃者は署名の辞書順を
///    グラインドする必要すら無くなり、**`chatWindow.startMs − 1` と書けば必ず先頭に来る**。
///    実測（4人組・実物のバンドル構築＋vendored 採点）: 既読版で被害者が
///    `min_messages` 失格 70点 → 0点、行動版で被害者が `no_vote` 失格 ＋ 第三者が 150 → 50。
///    是正はクライアント側（`protocol-v2.js` の `receiptCoverClaim` / `selectBundleReceipts`）で、
///    窓外の受領証明に**枠を取らせない**（ただし J-26 のため提出物からは落とさない）。
///    **採点規則は1バイトも変えていない**（`RECEIPT_ACCEPTANCE_RULE_VERSION` も vkey も不変）。
export const receiptCanonCmp = (x, y) => {
  const xr = Array.isArray(x?.msgRefs) && x?.senderUid != null;
  const yr = Array.isArray(y?.msgRefs) && y?.senderUid != null;
  const xt = typeof x?.timestamp === 'number' ? x.timestamp : Number.MAX_SAFE_INTEGER;
  const yt = typeof y?.timestamp === 'number' ? y.timestamp : Number.MAX_SAFE_INTEGER;
  if (xt !== yt) return xt - yt;
  if (xr !== yr) return xr ? -1 : 1;                          // 既読(r) を行動(a) より先に
  const ru = compareStrAsc(String(x?.receiverUid ?? ''), String(y?.receiverUid ?? ''));
  if (ru !== 0) return ru;
  // 参照キー: 既読は senderUid、行動は actionHash（どちらも文字列比較で全順序）
  const xk = xr ? String(x?.senderUid ?? '') : String(x?.actionHash ?? '');
  const yk = yr ? String(y?.senderUid ?? '') : String(y?.actionHash ?? '');
  const kk = compareStrAsc(xk, yk);
  if (kk !== 0) return kk;
  return compareStrAsc(sigLower(String(x?.signature ?? '')), sigLower(String(y?.signature ?? '')));
};

/// 空の候補マップ（検証⑤の第2パスが「第1パスで採られた発信」を引くときの既定値）
const EMPTY_CAND_MAP = new Map();

/// 🔴 J-15 の**計測専用**カウンタ。採点結果には一切影響しない。
///
/// 「密告の第2パスは平常時に一度も走らない」という設計上の主張を、
/// テストが機械的に確かめられるようにするためだけに置いてある
/// （`report-second-pass-test.mjs`）。
/// ⚠️ Rust ゲストには対応物が無い（出力に効かないので差分テストの対象外）。
///    ここを採点の分岐に使ってはいけない — 呼び出し履歴に依存する採点は決定論を壊す。
export const reportSecondPassStats = { runs: 0, examined: 0 };

/// `encryptedActions` の keyed セクション（`votes` / `reports` / `observed.votes` /
/// `observed.reports`）を **中間配列を作らずに** 列挙するための門番。
///
/// 🔴 P-2026-0835（2026-08-08・ラウンド19 判断不要-1）:
///    旧実装は `Object.entries(ea.votes || {})` で回していた。`Object.entries` は
///    **文字列に対して 1文字＝1エントリ**、**配列に対して 1要素＝1ペア**の
///    中間配列を materialize する。`encryptedActions.votes` に 1e6 文字の文字列
///    （raw 1,000,472 B・gzip **1,366 B**）や 1,045,000 要素の配列
///    （raw 2,090,508 B・gzip **2,441 B**）を入れたバンドルは
///    `validateResultBundle` を **valid** で通り、採点時に isolate の heap 上限へ達する。
///    ネイティブスタックは `Builtins_ObjectEntries` → `Runtime_ObjectEntriesSkipFastPath`
///    → `AllocateRawWithRetryOrFailSlowPath` → `FATAL ERROR`。**catch できない**ので
///    `calculateAndStoreResults` の try も走らず、そのブロックの集計・Merkle ルート・
///    報酬配布が永久に完了しない。攻撃コストは calldata 約2.4KB の
///    `Evidence.submitResult` 1回（パーミッションレス）で、攻撃者の自損はゼロ。
///
/// 🔴 これは **JS 正典だけの割れ**だった。Rust ゲスト（`crates/scoring-core/src/json.rs`
///    の `keyed_section`）は同じ入力を O(1) 確保で捌く:
///      ・`{` → キーを1つずつ読む
///      ・`[` → `n.to_string()` をキーにして1要素ずつ読む
///      ・文字列 / 数値 / 真偽 / null → `skip_value()` して `Ok(Vec::new())`
///    回路は点数表を出せるのに正典が1つも出せない、という状態になっていた。
///
/// **受理集合は1ビットも変わらない**:
///   ・文字列 / 数値 / 真偽 / null … 旧実装でも `gather` / `collect` の
///     `!a.encrypted` で全件落ちていた（1文字の文字列に `.encrypted` は無い）
///     → ここで空セクションに畳んでも結論は同じ（Rust の `Ok(Vec::new())` と一致）
///   ・配列 … `for...in` も `Object.entries` と同じ "0","1",… キーを同じ順に返す
///     （Rust の `b'['` 枝と一致）。**通し続けること。**
///   ・オブジェクト … `JSON.parse` 由来なので継承プロパティは無い。それでも
///     Rust が「バイト列上の own キー」しか見ないのに合わせて `hasOwnProperty` を課す
///
/// ⚠️ キー数／要素数そのものの上限は **入れていない**（受理集合が変わり規則版数と
///    vkey が動くため・台帳 J-33 で判断待ち）。ここは確保量だけを O(1) に戻す変更。
const EMPTY_SECTION = Object.freeze(Object.create(null));
const hasOwn = Object.prototype.hasOwnProperty;
export const keyedSection = (v) => ((v !== null && typeof v === 'object') ? v : EMPTY_SECTION);

// 再エクスポート（呼出側・テストがcalculator経由で参照できるように）
export { computeChatHashV2 } from './protocol-v2.js';

// ============================================================
// 🔴 P-2026-0827（2026-08-08）: 検証②.6 のプリイメージを**再帰なしでも作れる**ようにする
// ============================================================
// # 何が起きていたか（park）
//
// `JSON.parse` は 2026-08-07 に非再帰化した（Rust の `json.rs` / `actions.rs`）。
// V8 の `JSON.parse` も深さ 1,000,000 まで通る。**ところが `JSON.stringify` は再帰**で、
// Node v22 は**深さ 6,842 で `RangeError: Maximum call stack size exceeded`**（二分探索の実測値）。
// 検証②.6 の `keccak256(toHex(JSON.stringify({ votes, reports, observed })))` は
// `encryptedDataHash` の**プリイメージ**を作るだけで、`encryptedActions` の形は誰も検査していない。
// ＝ `{"votes":{"a":{"a":{…}}}}` を積むだけで例外が飛び、`calcScoringUnit` /
// `calcEvidenceUnit` の外まで抜けて **ブロック全体が park** する。
// 攻撃コストは **gzip 後 388 バイトの `Evidence.submitResult` 1回**（実測）。
// オンチェーン入力は不変なので、リトライも `/reset-block` も `unpark` も同じ壁に当たり、
// 集計・Merkle ルート・報酬配布は**コードを直さない限り永久に完了しない**。
//
// # なぜ「例外を握って snapshot_mismatch」ではダメか（2026-08-08 訂正）
//
// ZKP ゲスト（`crates/scoring-core/src/submission.rs::verify_snapshot_hash`）は
// **プルーバが渡したプリイメージのバイト列を keccak するだけ**で、深さを一切見ない。
// `parse_action_snapshot`（`json.rs`）の `skip_value` も非再帰なので、
// **正しいハッシュさえ付いていればゲストは深い入れ子を普通に受理する**。
// したがって正典だけが「例外 → snapshot_mismatch」に倒れると、
//   JS: `A=0 B=100 C=200` ／ ゲスト: `A=200 B=200 C=200`
// のように**採点が割れる**（root が summary.json と一致せず配布が止まる）。
// ＝ park は消えても、より静かな食い違いに置き換わるだけ。
//
// # 直し方: **同じバイト列を、深さに依存せずに作る**
//
// `JSON.stringify` を**まず素直に呼ぶ**（＝既存ブロックの結果は1ビットも動かない）。
// V8 の再帰が尽きたときだけ、**同じ規則の非再帰実装**で作り直す。
// 出力がバイト同一である限り、どちらの経路を通っても keccak は同じ ＝
// 「実行環境ごとにスタック上限が違う」ことも結果に影響しない。
//
// ⚠️ **葉（プリミティブ）と例外的な値は `JSON.stringify` に丸投げする**のが要点。
//    文字列のエスケープ（制御文字・孤立サロゲート）・数値表現（`-0` → `0`・
//    非有限 → `null`）を自前で書くと、そこがそのまま食い違いの種になる。
//    自前でやるのは「入れ子を降りる」ところだけ。
// ⚠️ キー順は `Object.keys`（＝整数風キー昇順 → それ以外は挿入順）で、
//    `JSON.stringify` の `EnumerableOwnPropertyNames` と同じ。
//    `Object.create(null)` 由来のオブジェクト（`uidMap`）も同じ扱いになる。

/// `JSON.stringify` と**バイト同一**の出力を、再帰せずに作る。
/// 入力は `JSON.parse` 由来の値（null / boolean / number / string / 配列 / 素のオブジェクト）を想定。
/// それ以外（Date・ボックス化プリミティブ・`toJSON` を持つ値・クラス実体）は
/// **その部分木だけ `JSON.stringify` に委譲**するので、規則の写し間違いが起こらない。
export function iterativeJsonStringify(root) {
  const primitive = (v) => {
    const s = JSON.stringify(v);
    return s === undefined ? 'null' : s;   // 配列中の undefined / function / symbol は "null"
  };
  // 「素直に降りてよい」のは素のオブジェクトと素の配列だけ。
  const walkable = (v) => {
    if (typeof v.toJSON === 'function') return false;
    const proto = Object.getPrototypeOf(v);
    return proto === Object.prototype || proto === null || proto === Array.prototype;
  };
  const out = [];
  const open = new Set();                  // 循環検出（JSON.parse 由来の値では起こり得ない）
  const stack = [{ t: 'v', v: root }];
  while (stack.length > 0) {
    const it = stack.pop();
    if (it.t === 's') { out.push(it.s); continue; }
    if (it.t === 'close') { open.delete(it.v); out.push(it.s); continue; }
    const v = it.v;
    if (v === null || typeof v !== 'object') { out.push(primitive(v)); continue; }
    if (!walkable(v)) { out.push(primitive(v)); continue; }
    if (open.has(v)) throw new TypeError('Converting circular structure to JSON');
    open.add(v);
    const items = [];
    if (Array.isArray(v)) {
      out.push('[');
      for (let i = 0; i < v.length; i++) {
        if (i > 0) items.push({ t: 's', s: ',' });
        items.push({ t: 'v', v: v[i] });
      }
      items.push({ t: 'close', s: ']', v });
    } else {
      out.push('{');
      let first = true;
      for (const k of Object.keys(v)) {
        const val = v[k];
        // 値が undefined / function / symbol のプロパティは**省略**（JSON.stringify と同じ）
        if (val === undefined || typeof val === 'function' || typeof val === 'symbol') continue;
        if (!first) items.push({ t: 's', s: ',' });
        first = false;
        items.push({ t: 's', s: JSON.stringify(k) + ':' });
        items.push({ t: 'v', v: val });
      }
      items.push({ t: 'close', s: '}', v });
    }
    for (let i = items.length - 1; i >= 0; i--) stack.push(items[i]);
  }
  return out.join('');
}

/// 検証②.6 のプリイメージ（正規3フィールド順・v3.2 §6.8）。
/// **例外を投げない**（park させない）。作れなかったときだけ `null` を返す
/// ＝ 呼び出し側は `snapshot_mismatch` に倒す。
/// `null` になるのは循環参照・BigInt など **`JSON.parse` 由来の値では起こり得ない**場合だけ。
export function actionSnapshotPreimage(ea) {
  const v = {
    votes: ea?.votes || {},
    reports: ea?.reports || {},
    observed: ea?.observed || {}
  };
  if (ea && Object.prototype.hasOwnProperty.call(ea, 'priority') && ea.priority !== undefined) v.priority = ea.priority;
  try {
    return JSON.stringify(v);
  } catch {
    // V8 の再帰が尽きた（深さ 6,842〜）→ 同じ規則の非再帰実装で作り直す
    try { return iterativeJsonStringify(v); } catch { return null; }
  }
}

// ============================================================
// ヘルパー関数
// ============================================================

function hexToBytes(hex) {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

function eciesDecrypt(encryptedHex, privKeyHex) {
  const cleanKey = privKeyHex.startsWith('0x') ? privKeyHex.slice(2) : privKeyHex;
  const encryptedBytes = hexToBytes(encryptedHex);
  const decrypted = decrypt(cleanKey, encryptedBytes);
  return new TextDecoder().decode(decrypted);
}

/**
 * 投票・密告のsignKey署名を検証する（A-9: 多層防御）。
 * 署名対象はクライアント・サーバーと同一の §2.6 正準形（type/blockNum/groupId束縛）。
 * 検証側が採点対象の文脈で文字列を構築する＝別ブロック/グループ向け署名は自動的に失敗。
 * 検証アドレス = 登録blockAddress.address（= signKey公開鍵由来・エントリー時に固定）。
 */
async function verifyActionSignature(type, uid, action, members, ctx) {
  // 🔴 P-2026-0822（2026-08-07）: `!action.timestamp` は **`timestamp === 0` を落としていた**。
  //    同じファイルの候補収集（`a.timestamp == null`）・`isCanonicalTimestamp`・
  //    Rust の `crates/scoring-core/src/actions.rs` はいずれも 0 を受理し、
  //    仕様（`docs/CHAT_GAME_SIMPLIFICATION_SPEC.md` §6.4）にも「非ゼロ」の要求は無い。
  //    ＝ **JS だけが過剰に厳しい**。実測（`CHAT_WINDOW=null`・4人組）:
  //      Rust: 投票は採用され非失格 ／ JS: 署名検証で落ち `no_vote` 失格
  //      復号できた投票 Rust 4件 / JS 3件 ＝ 同一入力から2つの正典。
  //    `null` / `undefined` だけを弾く（`isCanonicalTimestamp` が型と範囲を見る）。
  if (!action || !action.encrypted || !action.signature || action.timestamp == null) return false;
  // A-1/A-2（2026-08-05）: 署名は 0x+130桁hex の文字列だけを受理する。
  // オブジェクト署名は viem が受理してしまい、奇数長hexは同一発信に複数の有効署名を作れる。
  if (!isCanonicalSignature(action.signature)) return false;
  // P-2026-0806（2026-08-05）: ZKP ゲストが表現できない型を排除する。
  // `encrypted` が孤立サロゲートを含む／`timestamp` が小数だと Rust 側で再現できず、
  // 「JS は採用・ゲストは不採用」で正典が分裂する（STAGE3C_CANON_TIGHTENING.md §B）。
  if (!isOpaqueField(action.encrypted)) return false;
  // 🔴 P-2026-0842（2026-08-08・ユーザー確定）: `encrypted` は**正準長の hex**だけ。
  //    パディングしない暗号文は長さがそのまま対象 uid の桁数を漏らす
  //    （`protocol-v2.js` の `ACTION_PLAINTEXT_BYTES` 節）。粒度は隣の型検査と同じ
  //    ＝**その1件を採らないだけ**（失格にはしない・予算も消費しない）。
  if (!isCanonicalActionCiphertext(action.encrypted)) return false;
  if (!isCanonicalTimestamp(action.timestamp)) return false;
  if (!isCanonicalUid(uid)) return false;
  const member = members.find(m => m.uid === uid);
  if (!member || !member.bAddr) return false;
  // 🔴 P-2026-0819: 壊れた bAddr で例外を外へ出さない（決定論的 park の原因だった）
  const bAddr = parseBlockAddress(member?.bAddr);
  if (!bAddr) return false;
  const dataString = actionSignStringV2(type, ctx.blockNum, ctx.groupId, uid, action.encrypted, action.timestamp);
  try {
    return await verifyMessage({ address: bAddr.address, message: dataString, signature: action.signature });
  } catch {
    return false;
  }
}

/// `u128::MAX`（= 2^128 − 1）。↔ `crates/group-guest/src/witness.rs` の `MemberIn.deposit_wei: u128`
/// 正準 wei 文字列が表現できる**上限**。この定数を動かすときは Rust の型も一緒に動かすこと。
const U128_MAX = 340282366920938463463374607431768211455n;
const U128_MAX_DIGITS = 39; // U128_MAX.toString().length

/// 正準 wei 文字列か（10進・符号なし・空白なし・先頭0は `'0'` 単独のみ・`u128::MAX` 以下）。
///
/// 🔴 P-2026-0820（2026-08-07）: `BigInt()` は **入力の 1/3 で例外を投げ、残りで黙って 0 になる**。
///    実測（`parseDepositWei` → `calculateDepositPoints`）:
///      `'abc'` `'1e18'` `'1_000'` `'1.5'` `{}` `[1,2]` → **THROW SyntaxError**（採点関数の外へ）
///      `'0x10'` `'  '` `'-1'` `'+1'` `'01'` `''` `[]` `true` → 例外にならず**静かに 0pt**
///    前者は「入力が同じ＝リトライも同じ壁」＝そのブロックが決定論的に park する。
///    後者は Rust（ZKP ゲスト）が `u128` の10進パースしか受け付けないので、
///    `'0x10'`（JS: 0pt）と Rust（受理不能）で**正典が割れる**。
///    ⚠️ 受理を狭めているのではない。**正典が元から10進 wei 文字列しか意味を持たない**
///       （生成側は例外なく `BigInt.toString()`）ので、それ以外は入力の破損である。
///
/// 🔴 P-2026-0823（2026-08-07・ユーザー確定 B-1）: 上限は **`u128::MAX` 以下**。
///    ⚠️ 旧実装の「40桁以下」に**根拠は無かった**（git 履歴のどこにも由来が無く、
///       隣の `isCanonicalDepositIds` の 78＝uint256 の桁数とも無関係）。
///    この値は Rust 側（ZKP ゲスト）で `u128` に入る:
///      `crates/group-guest/src/witness.rs` の `MemberIn.deposit_wei: u128`
///      `u128::MAX = 340282366920938463463374607431768211455`（**39桁**）
///    ＝ 40桁を JS だけが受理すると、**JS は BigInt で完走するのに Rust は witness を
///      組み立てられず、そのブロックの証明が永久に作れない**。
///    点数そのものは割れない（10 ETH 超は両側とも `ineligible_deposit` で最終0点）が、
///    証明に載る中間値 `depositPoints` が割れる（40桁で 9,999,999,999,999 ↔ 1,844,674,407,370）。
///
///    🔴 **桁数だけでは不十分**。39桁でも `u128::MAX` を超える値がある
///       （例: `'9'.repeat(39)` = 999999999999999999999999999999999999999 > u128::MAX）。
///       桁数で粗く弾いてから **`BigInt` で値そのものを比較**する。
///
///    ⚠️ 上限を 20桁（10 ETH）にしてはいけない。この関数が守るのは1件のデポジットではなく
///       **同じ uid の複数デポジットの合計**と権威値で、10 ETH 超過の判定は合計を計算した
///       **後**に `ineligible_deposit`（`calculateGroupResults`）が行う。形式検査で先に
///       落とすと超過を検出する前に意味論が変わる。
export function isCanonicalWei(v) {
  if (typeof v !== 'string' || v.length === 0) return false;
  // 桁数は粗いふるい（`BigInt()` に極端に長い文字列を渡さないため）。
  // `u128::MAX` は39桁なので、40桁以上は値を見るまでもなく範囲外。
  if (v.length > U128_MAX_DIGITS) return false;
  if (!/^(0|[1-9][0-9]*)$/.test(v)) return false;
  // ここまでで10進整数であることは確定＝`BigInt()` は投げない。
  return BigInt(v) <= U128_MAX;
}

// ============================================================
// 適格デポジット帯（1人あたりの**合計**）
// ============================================================
//
// 🔴 J-31（2026-08-08・ユーザー確定）: **モジュール直下に出して export する。**
//    以前は `calculateGroupResults` の関数内ローカルだったため、自動配布経路
//    （`game-master-DO.js` の `autoDistribute`＝応募2名以下）が同じ値を写経するしかなく、
//    実際には写経すらされずに**帯判定が1行も無い**まま運用されていた。
//    その結果「manifest.rules で 10 ETH 上限を宣言しているのに、自動配布ブロックでは
//    20 ETH の応募者が非失格で報酬の93.71%を取り、しかも第三者検証ツールが
//    45項目 FAIL 0 で PASS する」という状態が実測された。
//    問題は金額ではなく **宣言した規則を適用していないブロックが第三者検証で満点を出すこと**。
//
//    値は `workers/entry_workers/lib/entry-validation.js` の
//    `MIN_TOTAL_DEPOSIT_WEI` / `MAX_TOTAL_DEPOSIT_WEI` と一致していなければならない。
//    （あちらは `@noble/curves` に依存するのでベンダリング閉包の都合で直接 import できない。
//      代わりに `workers/entry_workers/test/total-deposit-cap-test.mjs` が
//      「値が一致していること」と「autoDistribute が本当に適用していること」を機械照合する）
//
// 0.01 ETH (wei)
export const MIN_DEPOSIT_WEI = 10n ** 16n;
// K-S4-002（2026-07-31）: 1人あたりの**合計** 10 ETH 上限（製品仕様）。
// EthLock が強制するのは「1口あたり」0.01〜10 ETH で、合計の概念は契約に無い。
// 合計上限はフロント（MiningEntryWizard.js）にしか無く、API を直接叩けば
// 50口 × 10 ETH = 500 ETH の応募が通っていた。エントリー時に拒否するようにしたうえで、
// 採点時も下限と**対称**に検証する（サーバーが後から差し込んだ応募を検証ツールが機械検知できるように）。
export const MAX_DEPOSIT_WEI = 10n ** 19n;

/**
 * 権威（オンチェーン再検証済み）デポジット wei が**適格帯の外**か。
 *
 * これがゲーム経路（`calculateGroupResults`）と自動配布経路（`autoDistribute`）の
 * **唯一の実装**。どちらも `true` なら `ineligible_deposit` で失格させる。
 *
 * 🔴 非正準（`'abc'` / `'0x10'` / `'1e18'` / `null` / オブジェクト …）は **fail-closed で ineligible**。
 *    0 に丸めると「デポジット無し」と区別できず、運営の改竄が結果から見えなくなる。
 *
 * ⚠️ 呼ぶのは**権威表がある場合だけ**。自己申告 depIds へのフォールバック枝には
 *    かけてはならない（Rust の `apply_deposit_eligibility` が
 *    `verified_deposit_wei == None` で早期 return するため。理由は下の呼出側コメント）。
 */
export function isIneligibleDepositWei(rawWei) {
  const s = rawWei == null ? null : (typeof rawWei === 'string' ? rawWei : String(rawWei));
  if (s === null || !isCanonicalWei(s)) return true;
  const w = BigInt(s);
  return w < MIN_DEPOSIT_WEI || w > MAX_DEPOSIT_WEI;
}

/// `BigInt` の整数平方根（Newton 法）。↔ `crates/scoring-core/src/scoring.rs` の `isqrt`
///
/// 🔴 P-2026-0820（2026-08-07・D-2）: 旧実装は `Number(wei / 10^14)` してから `Math.sqrt` で、
///    商が 2^53 を超えると f64 の丸めで Rust の `u128` 整数平方根と割れた。
///    実測: q = 9999999999999999 → JS `100000000` / Rust `99999999`。
///    到達可能域（1人合計 ≤ 10 ETH ＝ q ≤ 100,000）では一致するが、
///    「到達可能域だから安全」という前提そのものを消すために整数演算へ置き換える。
function bigintSqrt(n) {
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

/**
 * デポジットwei文字列からデポジットポイントを計算
 * formula: floor(√(depositWei / 10^14))
 *
 * ⚠️ **例外を投げない**（非正準入力は 0）。fail-closed の判断は呼出側
 *    （`calculateGroupResults` の `ineligible_deposit`）が行う。
 */
export function calculateDepositPoints(depositWei) {
  if (!depositWei || depositWei === '0') return 0;
  const s = typeof depositWei === 'string' ? depositWei : String(depositWei);
  if (!isCanonicalWei(s)) return 0;
  const wei = BigInt(s);
  const divisor = 100000000000000n; // 10^14
  const divided = wei / divisor;
  if (divided <= 0n) return 0;
  return Number(bigintSqrt(divided));
}

/**
 * 密告成立時に、密告者1人あたりへ配る没収ポイント（v3.2 決定⑩: 定額按分）。
 *
 * ⚠️ **これは単なる按分ではなく「均衡条件」である。**（K-S4-005・2026-07-31 に明文化）
 *   n人グループで、ある正直者が自分に投票してくれる確率は 1/(n−1)。
 *   つまり「相手を失格させずに残す」ことの期待価値は P/(n−1)。
 *   密告報酬をこれと**釣り合わせ**、`floor` のぶんだけ下回らせることで、
 *   正直者を虚偽密告して失格させる行為の**期待値を負**にしている。
 *
 *   密告者数で割る式に変えたり、`floor` を `ceil` にしたりすると
 *   **虚偽密告が黒字化し、2体シビルが同組の正直者を確実に失格させる攻撃が成立する**。
 *   `docs/FAIRNESS_AUDIT_FIX_PLAN.md` A4 の受容判断はこの均衡に依存している。
 *   変更するときは `report-vote-equilibrium-test.mjs` を必ず読むこと。
 */
export function reportSharePerReporter(forfeitedPoints, groupSize) {
  return groupSize > 1 ? Math.floor(forfeitedPoints / (groupSize - 1)) : 0;
}

/**
 * メンバーのdepIdsからデポジットwei文字列を取得
 *
 * 🔴 P-2026-0820（2026-08-07・C-3）: **戻り値は必ず正準 wei 文字列**にする。
 *    ここは自己申告（エントリー時のキャッシュ）側なので **fail-soft**（不正なら `'0'`）。
 *    権威側（`verifiedDepositWei`）は逆に fail-closed（`ineligible_deposit`）にしてある。
 *    非対称にする理由: 権威値が壊れているのを 0 に丸めると「デポジット無し」と
 *    区別できず、**運営の改竄が参加者の不作為の陰に隠れる**。
 */
export function parseDepositWei(depIds) {
  if (!depIds) return '0';
  try {
    const parsed = typeof depIds === 'string' ? JSON.parse(depIds) : depIds;
    const v = parsed?.deposit;
    if (v === undefined || v === null) return '0';
    const s = typeof v === 'string' ? v : String(v);
    return isCanonicalWei(s) ? s : '0';
  } catch {
    return '0';
  }
}

/**
 * ブロック報酬（wei）を取得
 * TokenMining.solの報酬テーブルに準拠
 */
export function getBlockRewardWei(blockNum) {
  if (blockNum >= 0 && blockNum <= 90) return 115384615384615000000000n;
  if (blockNum >= 91 && blockNum <= 181) return 57692307692307700000000n;
  if (blockNum >= 182 && blockNum <= 272) return 28846153846153800000000n;
  return 28846153846153800000000n;
}

/**
 * グループ結果を計算（サーバー側復号・検証）
 *
 * @param {Object} groupData - ChatGameDOから取得したグループデータ { members, submissions, meta, verifiedDepositWei }
 * @param {number} minChars - 最低文字数（デフォルト500）
 * @param {number} minMessages - 最低有効発言回数（連続発言を除く、デフォルト20）
 * @param {Object} chatCaps - チャット量キャップ { maxChars, maxMessages, maxMsgChars }
 * @param {Object|null} chatWindow - 宣言タイムライン有効窓 { startMs, endMs }（Evidence契約の
 *   chatWindow ± 時計ずれ許容。窓外タイムスタンプのメッセージ・投票・密告・受領証明は決定論的に不採用。
 *   null = フィルタ無効）
 * @returns {Object} { results, decryptedVotes, decryptedReports, canonicalTimeline }
 *
 * 検証フロー:
 * ① 提出署名検証（新dataString: blockNum/uid/encryptKey束縛・walletSignature廃止） →
 * ②.5 チャット正典（union ∧ signKey署名 ∧ 既読受領証明≥1） →
 * ②.6 snapshot_mismatch（encryptedDataHash ↔ {votes, reports, observed}） →
 * ④ 投票（署名・窓・受領証明・本人提出・復号） → ⑤ 密告（同上・最大2件） →
 * ⑥ 不正判定（vote_fraud / report_fraud） →
 * ⑦ min_chars / min_messages / reported → 多重理由集約 →
 * ⑧ ポイント付与（密告 floor(P/(n−1)) 定額 → 投票ボーナス） → 最終集計
 */
export async function calculateGroupResults(groupData, minChars = 500, minMessages = 20, chatCaps = {}, chatWindow = null) {
  // ============================================================
  // P-2026-0821（2026-08-07）: **閾値は入口で1回だけ確定させる（NaN fail-open の遮断）**
  // ============================================================
  // 🔴 `minChars` / `minMessages` には正規化がどこにも無かった。
  //    `GAME_MIN_CHARS` が `parseInt` で NaN になると
  //      `(effectiveCharCounts[uid] || 0) < NaN` が **常に false**
  //    となり、`min_chars` / `min_messages` の判定8箇所が**丸ごと空振り**する。
  //    実測（150発言×4字のフィクスチャ）: 正常 `0 / 0 / 0`（全員 min_chars 失格）→
  //    `minChars=NaN` で `220 / 170 / 50`。**一言も喋っていない人に報酬が出る。**
  //
  // 🔴 **fail-closed（throw）にする**（ユーザー確定）。既定値へ黙って落とさない:
  //    閾値は ZKP ゲスト（crates/scoring-core）に焼かれているので、
  //    黙って既定値に落とすと「宣言した値」と「適用した値」が食い違ったまま
  //    ブロックが1本進み、あとから証明が通らない（取り返しがつかない）。
  //    ⚠️ 関数のデフォルト引数（`= 500`）は `undefined` にしか効かず NaN を素通しする。
  if (!Number.isSafeInteger(minChars) || minChars < 0
    || !Number.isSafeInteger(minMessages) || minMessages < 0) {
    throw new Error(
      `[calculateGroupResults] minChars/minMessages must be non-negative safe integers `
      + `(got ${JSON.stringify(minChars)} / ${JSON.stringify(minMessages)})`
    );
  }
  // 🔴 chatCaps も**ここで1回だけ**正規化し、以降は `caps` しか触らない。
  //    旧実装は検証②.5 の `maxMessagesCap` だけを `Number.isFinite` で落としており、
  //    正典メッセージ集合を作る `applyChatCaps(canonicalMessages, chatCaps, …)` には
  //    **生の chatCaps** が渡っていた（受け皿が1箇所しか無かった）。
  //    Rust ゲストは `Caps` をゲスト定数で焼くので、ここが割れると必ず食い違う。
  const caps = normalizeChatCaps(chatCaps);
  const inChatWindow = (ts) => !chatWindow
    || (typeof ts === 'number' && ts >= chatWindow.startMs && ts <= chatWindow.endMs);
  // 採点はプレイヤー提出物（submissions）のみから行う。サーバー保存データは採点に一切使わない。
  const { members, meta } = groupData;

  // 🔴 P-2026-0820（2026-08-07・C-1 / C-2）: **外から渡ってくる uid 添字マップを入口で正規化する。**
  //    2026-08-07 の是正は「calculator が自分で作るマップ」だけを `Object.create(null)` にしており、
  //    `groupData.submissions` / `groupData.verifiedDepositWei` は素の `{}` のまま素通りしていた
  //    （本番の出どころは ChatGameDO 応答の `JSON.parse` ＝ **必ず素の `{}`**）。
  //    `isCanonicalUid` は `/^[\x21-\x7E]+$/` を許すので uid に
  //    `__proto__` / `constructor` / `toString` / `valueOf` / `hasOwnProperty` を置ける。実測（3人組・被害者は未提出）:
  //      C-1 `submissions['toString']` が `Object.prototype.toString`（truthy）を返す
  //          → `no_submit` 分岐に入らず検証①で `invalid_signature`
  //          （正常 uid: `0pt [no_submit + vote_undisclosed]` ／ 上記5種: `0pt [invalid_signature]`）
  //          合計点は同じでも `disqualify_reasons` が違い、これは summary.json → resultHash →
  //          ZKP の commit に入る ＝ **そのブロックの証明が永久に通らない**
  //          （Rust ゲストは `sub_of_rank: Vec<Option<usize>>` の添字判定なので必ず `no_submit`）
  //      C-2 `verifiedDepositWei['toString']` の値が `String()` を経て `BigInt()` へ届き
  //          `SyntaxError: Cannot convert function toString() ... to a BigInt` が
  //          **採点関数の外へ出る** ＝ 入力が同じ＝リトライも同じ壁＝ブロック全体が park。
  //          壊れたデータは一切不要（uid が1つ該当するだけ）で C-1 より発火条件が緩い。
  //    ⚠️ `JSON.parse` は `__proto__` を **own property** にするので `Object.assign` で取りこぼさない。
  //    ⚠️ `isCanonicalUid` を狭めて塞ぐのは採らない（将来の匿名エントリー向けの意図的な広さ）。
  const asUidMap = (o) => Object.assign(
    Object.create(null),
    (o && typeof o === 'object' && !Array.isArray(o)) ? o : {}
  );
  const submissions = asUidMap(groupData.submissions);
  const verifiedDepositWei = asUidMap(groupData.verifiedDepositWei);
  // 🔴 P-2026-0822（2026-08-07・ユーザー確定）: 権威表が**渡されたかどうか**は
  //    正規化後の中身では判定できない（`asUidMap` は未指定でも空マップを返す）。
  //    生の値で1回だけ確定させ、以降はこの旗しか見ない。
  const verifiedDepositProvided = groupData.verifiedDepositWei !== undefined
    && groupData.verifiedDepositWei !== null;

  if (!members || members.length === 0) {
    return { results: [], decryptedVotes: {}, decryptedReports: {}, canonicalTimeline: [] };
  }

  const memberUids = members.map(m => m.uid);
  const groupSize = members.length;

  // 🔴 P-2026-0811 #7/#14（2026-08-05）: 名簿を fail-closed で検査する。
  //    ・**重複 uid** は pro-rata の分母を二重計上する（DO 側の集合比較を素通りしていた）
  //    ・**非正準の uid**（非文字列・空・孤立サロゲート）は
  //      `${uid}${KEY_SEP}${ref}` のような複合キーや ZKP ゲストの `String` で再現できない
  //    採点は名簿の並び順の関数なので、ここが緩いと同じ集合から2通りの答えが出る。
  if (new Set(memberUids).size !== memberUids.length || !memberUids.every(isCanonicalUid)) {
    throw new Error('[calc] invalid member roster: duplicate or non-canonical uid');
  }

  // ============================================================
  // 🔴 ②.6 の原像を「ただ1通り」に固定する2つの門番（2026-08-08・ユーザー確定）
  // ============================================================
  //
  // ここで**1回だけ**判定し、以降は `usableEa(uid)` しか触らない。
  // ZKP ゲスト（`crates/scoring-core/src/json.rs` の `parse_action_snapshot`）は
  // ②.6 がハッシュで固定した**バイト列そのもの**を読むので、両者が同じ規則で
  // 「そのバンドルは何も提供しない」と結論できないと採点が割れる。
  //
  //   ① J-12 案A3 … 原像が制限文法（正準 JSON・数値は安全整数のみ）でなければ
  //      **②.6 不一致（`snapshot_mismatch`）** かつ 発信・受領証明を0件にする。
  //      ゲスト側は `verify_snapshot_hash` が同じ検査で落ちる。
  //   ② J-33 案D … uid キー付きセクションに名簿外キーがあれば
  //      **発信・受領証明を0件**にする（②.6 の判定には影響しない＝失格にはしない）。
  //      ゲスト側は `parse_action_snapshot` が `Err(SnapshotForeignKey)` を返す。
  //
  // ⚠️ ②を失格にしないのは、失格は「他人を巻き込む検閲レバー」になりやすいから。
  //    `encryptedActions` は `encryptedDataHash` → ウォレット署名で覆われているので、
  //    他人のバンドルに異物を入れることは誰にもできない＝**自傷にしかならない**。
  const eaGateCache = new Map();   // uid -> { canonical: bool, ea: object|null }
  const eaGate = (uid) => {
    let g = eaGateCache.get(uid);
    if (g) return g;
    const ea = submissions?.[uid]?.encryptedActions;
    if (!ea || typeof ea !== 'object') {
      g = { canonical: false, ea: null };
    } else {
      const pre = actionSnapshotPreimage(ea);
      const canonical = pre !== null && isCanonicalActionPreimage(pre);
      g = {
        canonical,
        ea: (canonical && actionSectionKeysAreMembers(ea, memberUids)) ? ea : null,
      };
    }
    eaGateCache.set(uid, g);
    return g;
  };
  /// 発信・受領証明の**唯一の入口**。使えないバンドルは `null`。
  const usableEa = (uid) => eaGate(uid).ea;

  // 🔴 P-2026-0822（2026-08-07・ユーザー確定 fail-closed）:
  //    **権威表が渡されているなら、名簿の全員がそこに載っていなければならない。**
  //
  //    `calcFilterEligibleDeposits`（game-master-DO）は名簿の全員ぶんの行を必ず作る
  //    （`perUid` は `calcDepIdsUnit` が `data.members` を全員なめて作るので、適格な
  //    デポジットが1件も無い人も `'0'` として載る）。したがって**行が無い＝誰かが消した**。
  //    旧実装はそれを警告もせず自己申告値（D1 由来の depIds）へ切り替えていたので、
  //    運営が表から1行消して D1 に巨額を書くだけでその人が任意の点数を取れた
  //    （実測: `1e12 ETH` → 100,000,000pt）。
  //    パイプライン側の安全装置は「vdep レコードが**丸ごと**無ければ throw」なので、
  //    **1行だけ抜く**攻撃は素通りしていた。
  //
  //    採るのは fail-closed（サーバー保存値で先へ進まない・人を呼ぶ）。
  //    ⚠️ 判定は **`hasOwnProperty`** で行う。`in` や素の添字はプロトタイプ鎖を見るので、
  //       uid が `toString` / `constructor` / `__proto__` の人が「載っている」ことになる。
  //       （`verifiedDepositWei` は上で `Object.create(null)` へ正規化済みなので
  //         いま `in` でも同値だが、正規化を外した瞬間に穴が復活する型なので明示する。）
  //    ⚠️ 値が `null` / `undefined` の行も「載っている」として扱い、権威側の
  //       fail-closed（`ineligible_deposit`）へ落とす。ここで自己申告へ落とすと
  //       「行を消す」代わりに「値を null にする」で同じ迂回ができてしまう。
  if (verifiedDepositProvided) {
    const missing = memberUids.filter(
      (uid) => !Object.prototype.hasOwnProperty.call(verifiedDepositWei, uid)
    );
    if (missing.length > 0) {
      throw new Error(
        '[calc] verified deposit table is incomplete — '
        + `${missing.length}/${memberUids.length} member(s) missing: ${missing.join(', ')} `
        + '(on-chain re-verification writes a row for every roster member, so a missing row '
        + 'means the table was tampered with; refusing to fall back to self-reported deposits)'
      );
    }
  }

  // 署名文脈（§2.6: 署名検証・msgKey・actionHash は採点対象の blockNum/groupId で構築）
  //
  // 🔴 P-2026-0820（2026-08-07・C-4）: **fail-closed で正準性を検査し、Number へ正規化する。**
  //    `chatSignStringV2` / `actionSignStringV2` / `receiptSignString` / `readReceiptSignString` は
  //    いずれも内部で `Number(blockNum)` を通すので、JS は暗黙変換を素通しし
  //    `'0x5'` / `' 5 '` / `[5]` / `'9007199254740993'` が正常値と**同じ点数**で通っていた。
  //    Rust（ZKP ゲスト）の `push_i64` は受け取った値をそのまま10進で書くので
  //    署名対象文字列が割れる ＝ 同一入力から2つの正典メッセージ集合。
  //    これらは回路に焼かれる値なので、黙って通してはならない。
  //    ⚠️ P-2026-0829: 実体は `protocol-v2.js` の `canonMetaInt`（移設・挙動不変）。
  //       ChatGameDO の `handleInit` が**同じ関数**を保存前に呼ぶ（park の前倒し）。
  const ctx = {
    blockNum: canonMetaInt(meta?.blockNum, 'blockNum'),
    groupId: canonMetaInt(meta?.groupId, 'groupId'),
  };

  // 適格帯（`MIN_DEPOSIT_WEI` / `MAX_DEPOSIT_WEI`）と判定（`isIneligibleDepositWei`）は
  // **モジュール直下**にある（J-31・2026-08-08）。関数内ローカルに置いていたせいで
  // 自動配布経路（`game-master-DO.js` の `autoDistribute`）から参照できず、
  // あちらに帯判定が1行も入っていなかった。

  // 🔴 決定②-3（2026-08-08・ユーザー確定・台帳 FINDINGS_LEDGER.md「判断②」）:
  //    適格帯の上限に対応する**デポジットポイント**（= 316）。
  //    密告報酬の分子はここでクランプする（下の ⑧）。定数を直書きせず
  //    `MAX_DEPOSIT_WEI` から `calculateDepositPoints` で導くのは、Rust（ZKP ゲスト）の
  //    `award_points` が **同じ導き方**（`calculate_deposit_points(MAX_DEPOSIT_WEI)`）を
  //    するため。片側だけ 316 を直書きすると、上限を動かしたときに静かに割れる。
  const MAX_ELIGIBLE_DEPOSIT_POINTS = calculateDepositPoints(MAX_DEPOSIT_WEI.toString());

  // メンバー結果オブジェクトを初期化
  // B1（権威的デポジット検証）: groupData.verifiedDepositWei が与えられた場合は権威とする。
  const results = members.map(member => {
    const entryDepositWei = parseDepositWei(member.depIds);
    const verified = verifiedDepositWei[member.uid];
    // 🔴 P-2026-0822（2026-08-07）: 権威表が渡されているなら**行の有無**が権威。
    //    上のゲートで「名簿の全員に own property がある」ことは確定しているので、
    //    ここでは常に true になる（値が `null` でも自己申告へは落ちない）。
    //    値の妥当性は下の `verifiedInvalid`（fail-closed）が見る。
    const hasVerified = verifiedDepositProvided;
    // 🔴 P-2026-0820（2026-08-07・C-3）: 権威値は **fail-closed**。
    //    非正準（`'abc'` / `'0x10'` / `'1e18'` / オブジェクト …）は 0 に丸めず、
    //    下限割れと同じ `ineligible_deposit` で決定論的に失格させる。
    //    0 に丸めると「デポジット無し」と区別できず、運営の改竄が結果から見えなくなる。
    const verifiedRaw = hasVerified
      ? (typeof verified === 'string' ? verified : String(verified))
      : null;
    const verifiedInvalid = hasVerified && !isCanonicalWei(verifiedRaw);
    const depositWei = hasVerified ? (verifiedInvalid ? '0' : verifiedRaw) : entryDepositWei;
    const depositPoints = calculateDepositPoints(depositWei);

    const r = {
      uid: member.uid,
      addr: member.addr,
      depositWei,
      depositPoints,
      originalDepositPoints: depositPoints,
      bonusPoints: 0,
      totalPoints: 0,
      isDisqualified: false,
      disqualifyReason: null,
      // 詳細内訳
      reportGainPoints: 0,
      voteTargetUid: null,
      reportTargetUids: [],
      votedByUids: []
    };

    // B1: 検証済みデポジットが0.01ETH未満（適格デポジット無しを含む）→ 失格
    // K-S4-002: 合計10ETH超も同様に失格（下限と同じ理由コード＝失格理由の集合を増やさない）。
    // エントリー時に拒否しているので、ここに来る＝**エントリー検査を通っていない応募**。
    //
    // ⚠️ **フォールバック枝（権威表が渡されていない）には B1 を一切かけない。**
    //    2026-08-07 に一度「上限だけフォールバック枝にも効かせる」変更（D-2 後半）が
    //    入ったが、ユーザー確定の fail-closed（上のゲート）で取り消した。理由:
    //      ・Rust 側 `apply_deposit_eligibility` は `verified_deposit_wei == None` で
    //        **早期 return**。「オンチェーン再検証の無いブロックで DB の値だけで失格させると、
    //        運営が DB を弄るだけで参加者を落とせる」という意図的な設計判断で、
    //        片側だけ厳しくすると JS と Rust が割れる（＝その ZKP が永久に通らない）。
    //      ・上のゲートを入れた後、この枝を通るのは「表が丸ごと無い」＝テストと
    //        一部ツールの経路だけになった。本番の採点はここへ来ない。
    if (hasVerified) {
      // J-31: 判定そのものは `isIneligibleDepositWei`（モジュール直下）1箇所。
      // 挙動は従来と同一（非正準 → ineligible、帯外 → ineligible）。
      if (isIneligibleDepositWei(verifiedRaw)) {
        r.isDisqualified = true;
        r.disqualifyReason = 'ineligible_deposit';
        // 🔴 P-2026-0811 #14（2026-08-05・ユーザー確定 案A）: これは**他の理由に吸収されない旗**。
        //    検証①は失格済みを飛ばさないので `disqualifyReason` は `no_submit` 等で
        //    上書きされうる。上書きされても失格理由の集約で必ず先頭に現れるよう、
        //    独立フィールドで保持する（「エントリー検査を通っていない応募」という
        //    運営側の異常が、参加者側の不作為の陰に隠れてはならない）。
        r.ineligibleDeposit = true;
      }
    }

    return r;
  });

  // 🔴 P-2026-0812 F5/F6（2026-08-06）: **ここで uid 昇順に固定する。**
  //    以降の全ループ（①〜⑧・受領証明の受理）がこの順で走るので、
  //    入力 `members` 配列の並びが採点結果にもオブジェクトのキー挿入順にも効かなくなる。
  //    直っているもの:
  //      ・受領証明の枠（ペア上限・カバー）の先着消費が名簿順で変わっていた（実測で反転）
  //      ・`decryptedVotes` / `decryptedReports` のキー挿入順が名簿順で変わっていた
  //    ⚠️ **戻り値は最後に名簿順へ戻す**（下の `restoreRosterOrder`）。
  //       `summary.json` の `groups[].members[]` の並びは**グループ分けの正準順序**に
  //       pin されており、block-verifier がグループ分けを独立再現して
  //       `canonicalEqual` で厳密照合している（`grouping.js` の `summaryStructure`）。
  //       uid 昇順にすると、より弱い順序で上書きしてその pin を壊してしまう。
  //    ⚠️ `Object.keys` が「数字に見えるキー」を数値昇順に並べるのは **2³²−1 以下**のときだけ。
  //       本番の uid（X の snowflake・19桁）は上限を超えるので**挿入順**になる。
  //       挿入順を固定しない限り、この配列の並びは決定論にならない。
  results.sort((a, b) => compareStrAsc(a.uid, b.uid));

  /// 採点が終わったら**入力 `members` の並び**へ戻す。
  /// 内部の走査順（uid 昇順）と、公開される行の並び（グループ分けの正準順序）を分離する。
  const restoreRosterOrder = (rows) => {
    const pos = new Map(members.map((m, i) => [m.uid, i]));
    rows.sort((a, b) => (pos.get(a.uid) ?? 0) - (pos.get(b.uid) ?? 0));
    return rows;
  };

  // ============================================================
  // 特殊ケース: 1人グループ → 検証スキップ、全報酬をその1人に
  // ============================================================
  if (members.length === 1) {
    const r = results[0];
    r.totalPoints = r.isDisqualified ? 0 : r.depositPoints;
    r.disqualifyReasons = r.isDisqualified ? [r.disqualifyReason] : [];
    return { results, decryptedVotes: {}, decryptedReports: {}, canonicalTimeline: [] };
  }

  // 🔴 P-2026-0811 #11: 密告が「消える」失格理由（ユーザー確定 2026-08-05）。
  //    ここに載っていない失格理由（min_chars / min_messages / no_vote / reported）では
  //    その人が発信した密告は**生き残る**。判定は検証⑤と reportsByTarget の2箇所で使う。
  const REPORT_VOIDING_DQ_REASONS = [
    'invalid_signature', 'chathash_mismatch', 'snapshot_mismatch',
    'vote_fraud', 'report_fraud', 'ineligible_deposit', 'no_submit',
  ];
  const isReportVoidingDq = (r) =>
    !!r && (r.ineligibleDeposit === true || REPORT_VOIDING_DQ_REASONS.includes(r.disqualifyReason));

  const findResult = (uid) => results.find(r => r.uid === uid);
  const findMember = (uid) => members.find(m => m.uid === uid);
  const bAddrOf = (uid) => parseBlockAddress(findMember(uid)?.bAddr);

  // 検証済みencryptKeyマップ: { uid: encryptKey }
// 🔴 P-2026-0819（2026-08-07）: **`Object.create(null)` を使う。**
//    `isCanonicalUid` は ASCII 印字可能を許すので uid に `__proto__` / `constructor` を置ける。
//    素の `{}` だと実測で:
//      uid="__proto__"   → `Object.prototype.msgs = NaN` / `chars = NaN` を書き込み、**プロセス全体を汚染**
//      uid="constructor" → 参照が `Object` 関数を返し、1文字しか喋っていない人の失格理由が
//                          `min_chars` ではなく `vote_fraud` になる
//    さらに `perUid[uid] < minChars` が **NaN 比較で常に false** になり、閾値判定が空振りする。
//    Rust（ZKP ゲスト）は uid を添字に解決するので汚染しない ＝ **同一入力から2つの点数表**。
  const verifiedEncryptKeys = Object.create(null);
  const priorityOf = new Map();

  // 復号結果格納
  const decryptedVotes = Object.create(null);   // { [uid]: { targetUid } }
  const decryptedReports = Object.create(null); // { [uid]: [{ targetUid }] }
  // 結果表示用の正典アクション。復号結果の公開形は変えず、採用した発信そのものの
  // timestamp / actionHash をここに保持する。最終的に無効化された密告は⑦で同時に消す。
  const canonicalVoteActions = new Map();       // uid -> { actorUid, targetUid, timestamp, actionHash }
  const canonicalReportActions = new Map();     // uid -> [{ actorUid, targetUid, timestamp, actionHash }]

  // ============================================================
  // 検証①: 提出データの署名検証（v3.2 検証②新方式を統合）
  //   walletSignature（旧②のkeccak導出チェーン）は廃止 — masterの素材のため提出物に含めない。
  //   束縛は「外側ウォレット署名が blockNum/uid/encryptKey を内包 ∧ 登録アドレス一致」で行う
  //   （旧walletSignatureメッセージが担っていた文脈束縛を dataString へ明示的に移設）。
  //   encryptKey の束縛 = 本人の投票・密告が復号できること（検証④⑤で自然に検査される）。
  //   signKey の束縛 = 登録blockAddress.pubKeyでの署名検証（チャット・投票・密告・受領証明）。
  // ============================================================
  for (const r of results) {
    const sub = submissions?.[r.uid];

    if (!sub) {
      r.isDisqualified = true;
      r.disqualifyReason = 'no_submit';
      continue;
    }

    const bounded = validateSubmissionStructure(sub, {
      blockNum: ctx.blockNum,
      groupId: ctx.groupId,
      memberUids,
    });
    if (!bounded.ok) {
      r.isDisqualified = true;
      r.disqualifyReason = 'invalid_signature';
      continue;
    }

    // P-2026-0806: 署名対象に入る値が ZKP ゲストで表現できる型であること。
    // ⚠️ ここで弾かないと「JS は通るがゲストは通らない」提出物ができ、
    //    正典メッセージ集合ごと食い違う（§B）。
    //
    // 🔴 P-2026-0832（2026-08-08）: **外側ウォレット署名そのもの**も同じゲートに入れる。
    //   系内の他の署名（発信 `:242` / メッセージ `:898` / 受領証明 `:1225` / 候補収集 `:1563`）は
    //   全部 `isCanonicalSignature` を通っているのに、ここだけが素通しだった。
    //   オブジェクト `{r,s,v}` / high-s の双子 が 200pt で通る（実測）。
    //   ZKP ゲストの `SubmissionIn.sig` は `[u8; 65]` ＝ オブジェクト署名は表現できず、
    //   唯一のデコーダ（`crates/group-host/src/main.rs::sig65()`）は非文字列で panic する。
    //   ⚠️ **述語も順序も `evidence-reconciler.js` の `verifyBundleCore` と同一に保つこと**
    //      （3経路が同じ規則で受理／棄却する — 差分を目で照合できるようにするため）。
    //   ⚠️ 署名は現行の述語どおり小文字 hex のみ。viem が出す正規形と一致する。
    if (!isOpaqueField(sub.encryptKey) || !isOpaqueField(sub.chatHash)
      || !isCanonicalTimestamp(sub.submittedAt)
      || !(sub.encryptedDataHash == null || isOpaqueField(sub.encryptedDataHash))
      || !isCanonicalDepositIds(Array.isArray(sub.depositIds) ? sub.depositIds : null)
      || !isRepresentableSignature(sub.signature)) {
      r.isDisqualified = true;
      r.disqualifyReason = 'invalid_signature';
      continue;
    }

    try {
      const dataString = JSON.stringify({
        blockNum: Number(ctx.blockNum),
        uid: r.uid,
        encryptKey: sub.encryptKey,
        chatHash: sub.chatHash,
        submittedAt: sub.submittedAt,
        encryptedDataHash: sub.encryptedDataHash ?? null,
        depositIds: Array.isArray(sub.depositIds) ? sub.depositIds : null
      });

      const valid = await verifyMessage({
        address: r.addr,
        message: dataString,
        signature: sub.signature
      });

      if (!valid) {
        r.isDisqualified = true;
        r.disqualifyReason = 'invalid_signature';
        continue;
      }
    } catch (e) {
      console.error(`Signature verification failed for ${r.uid}:`, e);
      r.isDisqualified = true;
      r.disqualifyReason = 'invalid_signature';
      continue;
    }

    if (!sub.encryptKey || typeof sub.encryptKey !== 'string') {
      r.isDisqualified = true;
      r.disqualifyReason = 'invalid_signature';
      continue;
    }
    // ①-P: 外側の署名と原像の結合を確かめた束だけから最優先欄を読む。
    if (isPlainRecord(sub.encryptedActions)
      && Object.prototype.hasOwnProperty.call(sub.encryptedActions, 'priority')) {
      if (sub.uid !== r.uid) {
        r.isDisqualified = true;
        r.disqualifyReason = 'invalid_signature';
        continue;
      }
      const gate = eaGate(r.uid);
      if (gate.ea !== null) {
        const preimage = actionSnapshotPreimage(gate.ea);
        if (keccak256(toHex(preimage)) === sub.encryptedDataHash) {
          const verified = await verifyPriorityFields(sub, {
            blockNum: ctx.blockNum, groupId: ctx.groupId, memberUids,
            bAddrOf, chatWindow, verify: verifyMessage,
          });
          if (!verified.ok) {
            r.isDisqualified = true;
            r.disqualifyReason = 'invalid_signature';
            continue;
          }
          priorityOf.set(r.uid, sub.encryptedActions.priority);
        }
      }
    }
    verifiedEncryptKeys[r.uid] = sub.encryptKey;
  }

  // ============================================================
  // K-S6-002 是正（2026-07-29）: 受領証明の「参照整合性」を先に確定する
  // ============================================================
  // 受領証明は「私は〇〇を受け取った」という署名付きのメモだが、**その〇〇が実在するか**を
  // どのレイヤーも見ていなかった。署名は発行者自身の signKey で正しく作れるので、
  // デタラメな参照先を持つ受領証明は「正しい受領証明」として全メンバーのクライアントに
  // 取り込まれ、全員の提出物に同梱されていた（受領証明は運営に消されないよう全員が運ぶ設計）。
  //
  // 実測（本物と同じ乱数バイト・5人×100発言の上限ケース）:
  //   正直な最大ケース                       raw 223KB / gzip  90KB
  //   実在しない actionHash を上限まで        raw 823KB / gzip 333KB
  //   実在しない msgRef を上限まで            raw 5.6MB / gzip 2.6MB
  // → 他メンバーの WS 提出（DO の単一値128KiB）もオンチェーン提出（gzip後128KB）も同時に不能。
  //   攻撃者は自分の提出物にだけ異物を入れなければよいので、**自分だけ提出でき、他の全員が
  //   no_submit 失格**になる（ポイントは全体 pro-rata なので攻撃者の取り分が増える）。
  //
  // Q-S2-001（枚数の上限）では塞がらない: 偽の参照先は毎回ユニークなので「重複だから捨てる」
  // に一度も当たらず、枚数上限（2,200件）の内側で容量を食い尽くせる。
  //
  // 対策は「**実在する対象をカバーしない受領証明は、そもそも数に入れない**」。
  // 捨てても採点結果は変わらない（照合先が無いので元から無視されていた）。
  // そのためにメッセージ union の前半（chatHash 自己整合＋署名検証）をここへ繰り上げる。
  // 🔴 P-2026-0812（2026-08-06）: `??` は **NaN を素通しする**。
  //    `GAME_MAX_MESSAGES` に数値でない値が入ると `parseInt` → NaN になり、
  //    `examined >= NaN` / `msgRefs.length > NaN` / `fresh.length >= NaN` が
  //    すべて false ＝ 受領証明の (b)(c)(d) の CPU 上限が**同時に消える**（実測）。
  //    Q-S2-001 の fail-closed 前提が壊れるので、有限数でなければ既定値に落とす。
  // 🔴 P-2026-0814（2026-08-07）: メッセージ側の予算（②.5(b)）も同じ値から導くので、
  //    受領証明ブロックの内側にあった定義をここへ繰り上げた（両方で1つの値を使う）。
  // 🔴 P-2026-0821（2026-08-07）: 正規化を関数の入口（`caps`）へ集約した。
  //    ここだけが受け皿だったせいで `applyChatCaps` に生の caps が渡っていた。
  const maxMessagesCap = caps.maxMessages;
  const getMsgKey = buildMsgKeyGetter(ctx.blockNum, ctx.groupId);
  const compareCanonical = canonicalComparatorV2(getMsgKey);
  const msgRegistry = new Map();      // msgKey -> msg（署名検証済み・全有効提出物のunion）
  const realReadRefs = new Map();     // `${発信者uid}|${msgRef}` -> 全発信時刻
  // actionHash -> 発信者uid（実在する発信）。
  // 🔴 P-2026-0808（2026-08-05）: Set から Map へ。行動の受領証明の枠を
  //    **(受領者, 発信者) ペア単位**にするために発信者が要る（下の (b) 参照）。
  const realActionHashes = new Map();
  const validSubmitters = [];
  const priorityMsgKeys = new Set();
  const priorityRefTimes = new Map();
  const priorityItems = new Set();
  {
    // (a) chatHash v2 自己整合。本体（messages）未提出は chathash_mismatch 失格
    for (const r of results) {
      // 🔴 P-2026-0812（2026-08-06）: **提出物が有るなら検証する**（失格済みでも）。
      //    ここに来る時点で立っている失格理由は `no_submit`（提出物が無い）と
      //    `invalid_signature`（①で落ちた）と `ineligible_deposit`（初期化時）だけ。
      //    旧実装は `isDisqualified` で飛ばしていたため、`ineligible_deposit` の提出物は
      //    chatHash 自己整合も ②.6 の `encryptedDataHash` 照合も**素通り**した。
      //    その提出物は候補収集・受領証明の運び手としては使われるので、
      //    「運営がエントリー検査を落とした相手の提出物だけ fail-closed のハッシュ束縛が
      //    外れる」という非対称になっていた。
      if (!submissions?.[r.uid]) continue;
      if (r.disqualifyReason === 'invalid_signature') continue;
      const sub = submissions[r.uid];
      let submittedMsgs = Array.isArray(sub?.messages) ? sub.messages : null;
      // 🔴 P-2026-0811 #4/#5（2026-08-05）: **chatHash を計算する前に要素の型を検査する。**
      //    旧実装はここで生の JSON 値をそのまま `computeChatHashV2` へ流していた。
      //    ① `null` やプリミティブが混ざると `WeakMap` / プロパティ参照で**例外が飛び**、
      //       採点ユニットが失敗 → リトライ → park ＝ **ブロック全体の集計が止まる**
      //       （復旧は保存済み提出物の手作業。攻撃者の利得はゼロの純グリーフィング）
      //    ② 型ゲート（isCanonicalUid / isCanonicalText / isCanonicalTimestamp）は
      //       union 側（正規化後）にしか無かったため、`text` 欠落・`timestamp: 1e21` の
      //       ような値のまま chatHash 自己整合を**成立させられた**。
      //       ZKP ゲストは `BundledMessage { uid: String, text: Vec<u16>, timestamp: i64, sig: [u8;65] }`
      //       という型付き構造体で受け取るのでこれらを表現できず、**同じ提出物集合から
      //       2通りの chatHash が出る**（＝root が summary.json と一致せず配布が止まる）。
      //    ⚠️ `typeof m === 'object' && m !== null` を先に置くこと。省くと WeakMap の
      //       TypeError が残る。
      if (submittedMsgs && !submittedMsgs.every((m) =>
        typeof m === 'object' && m !== null && !Array.isArray(m)
        && isCanonicalUid(m.uid)
        && isCanonicalText(m.text ?? '')
        && isCanonicalTimestamp(m.timestamp))) {
        submittedMsgs = null;   // → 直後の分岐で chathash_mismatch
      }
      // chatHash は正準順の (msgKey, 発言署名) から計算（receipts等の添付は影響しない）
      if (!submittedMsgs || computeChatHashV2(submittedMsgs, ctx.blockNum, ctx.groupId) !== sub.chatHash) {
        r.isDisqualified = true;
        r.disqualifyReason = 'chathash_mismatch';
        continue;
      }
      validSubmitters.push(r.uid);
    }

    // (b) メッセージ単位の署名検証＋union登録
    //
    // ============================================================
    // P-2026-0814 是正（2026-08-07）: メッセージ署名検証の CPU 予算
    // ============================================================
    // 🔴 **旧実装には上限が一つも無かった。** 受領証明には Q-S2-001 の (b)(c)(d) が
    //    あるのに、こちらは「提出物に入っていた分だけ全部検証する」ままで、
    //    `chat-game-DO.js` の提出ゲートも `messages` の件数を見ていなかった。
    //    実質の上限は WS フレーム（約1MiB・1件約210B）だけ ＝ 1通あたり約5,000件、
    //    5人組で約25,000回。実測 0.826 ms/回（デタラメ署名）〜1.45 ms/回（本物）なので
    //    **1グループで 20〜36秒**。`calcScoringUnit` の実時間ガードはグループに入る**前**に
    //    しか評価されないため、1ユニットの最悪は「ガード値 ＋ 1グループぶん」＝
    //    約30秒の CPU 予算を決定論的に超え、リトライも同じ壁に当たって **park**（ブロック全停止）。
    //    攻撃コストは「署名すらしないデタラメ署名を並べるだけ」でほぼ無料だった。
    //
    // 予算は受領証明側と**同型**にする（`protocol-v2.js` の導出コメントを参照）:
    //   (b) `${提出者}|${発信者}` ペアごと `messagePerSenderCap`（= maxMessages）件
    //   (c) 提出者ごと `messageBundleCap`（= maxMessages × groupSize）件
    // (b) が要点。合計だけで縛ると、悪意あるメンバーが P2P に大量発言を流したとき
    // **正直な人の提出物でも「他人の氾濫」が先に予算を食い、自分の発言が自分の提出物から
    // 登録されず min_messages 失格**になる（受領証明 (b) がペア単位である理由と同じ）。
    // (c) は (b) の総和と一致するので冗長だが、上限の根拠を明示するために両方置く。
    //
    // 受領証明側で学んだ罠を同じ形で避けている:
    //   ・予算の消費は**重複排除（`msgRegistry.has`）の後**。重複は署名検証しない＝CPU を
    //     使わないので予算を減らす理由が無い。`sigCache` 命中も同様に無料なので消費しない。
    //   ・予算切れの提出物は `break` ではなく `continue`（他の提出物は読み続ける）。
    //   ・走査は**全提出物をまたいだ正準順序**。提出物単位に走らせると、同じ署名済み
    //     メッセージの集合でも「どの提出物が運ぶか」で予算の当たり方が変わる。
    //     ⚠️ `msgRegistry` は msgKey で dedup するので**採用されるメッセージ自体は
    //     運び手に依らない**が、予算が binding になると「どれが検証されるか」が変わる。
    //
    // 🔴 P-2026-0816（2026-08-07 訂正）: 旧コメントの「**正典に入りうるメッセージが
    //    予算切れで落ちることは無い**」は**誤り**だった。
    //    予算は**署名検証を実際に呼ぶたび**に減るので、**検証に失敗する偽メッセージも
    //    同じ枠を食う**。ある提出物が「発信者 V を騙る偽メッセージ」を発信者ごとの上限まで
    //    並べると、**その提出物の中では** V の本物のメッセージが検証に到達しない。
    //    実測（`gen-scoring-fixture.mjs` の `msg-budget-per-sender-binding`）:
    //      4人・各提出物が uid=21000001 を騙る偽署名400件を**本物より前の timestamp**で運ぶ
    //        → 正典メッセージ 48 → 36 件、21000001 が **75pt → 0pt（min_chars+min_messages）**
    //
    //    ⚠️ **到達条件は狭い**（が、ゼロではない）:
    //      ・`msgRegistry` は msgKey で dedup し、登録は**全提出物の union**なので、
    //        予算の残っている提出物が1通でもあれば本物は登録される
    //      ・正規クライアントは受信時に**全メッセージを署名検証して無効なものを破棄する**
    //        （`useGameWebSocket.js` の E-2。履歴・リレーとも）ので、
    //        偽メッセージが正直な提出物に載ることはない
    //      ・したがって成立するのは「**被害者以外の全員が結託して各自の提出物を毒し、
    //        かつ被害者自身が提出しない（または被害者のクライアントも汚染されている）**」場合
    //      ・同一の偽メッセージを全員が運ぶ形では `sigCache` が効いて2通目以降は無料なので、
    //        毒は提出物ごとに**別物**でなければならない
    //
    //    切り詰められるのは細工した提出物**と、その提出物が騙った発信者の枠**である。
    const sigCache = new Map(); // `${msgKey}|${signature}` -> boolean
    const msgBundleCap = messageBundleCap(maxMessagesCap, groupSize);
    const msgSenderCap = messagePerSenderCap(maxMessagesCap);

    // 走査対象を全提出物ぶん集める。ここまでのゲートは**すべて無料**（暗号を使わない）ので
    // 予算は消費しない ＝ 形式不正を並べても他人の枠は減らない。
    const msgCandidates = [];
    for (const submitterUid of validSubmitters) {
      const priority = priorityOf.get(submitterUid);
      for (const raw of [...submissions[submitterUid].messages, ...(priority?.messages ?? [])]) {
        if (!raw || raw.uid == null || !raw.signature) continue;
        if (!isCanonicalSignature(raw.signature)) continue;   // A-1/A-2
        const member = findMember(raw.uid);
        if (!member || !member.bAddr) continue;
        // 正準フィールドのみで正規化（receipts等の輸送フィールドはプロトコル外）
        const m = {
          uid: raw.uid,
          text: raw.text ?? '',
          timestamp: raw.timestamp,
          signature: raw.signature
        };
        // P-2026-0806: 正準フィールドの型。⚠️ 判定は**正規化後の `m`** に対して行う
        //   （`raw.text` が undefined/null なら `''` になり、これはゲストで表現できる。
        //    弾きたいのは `0` / `false` / 数値のように **JS が引用符なしで書く**値）。
        if (!isCanonicalUid(m.uid) || !isCanonicalText(m.text) || !isCanonicalTimestamp(m.timestamp)) continue;
        // 🔴 P-2026-0812（2026-08-06）: **宣言窓（チャット期間）を登録時点で課す。**
        //    旧実装は窓フィルタが union のあと（②.5）にしか無く、`msgRegistry` /
        //    `realReadRefs` には窓外の発言も入っていた。その結果、窓外の発言を指す
        //    既読受領証明が (受領者, 発信者) ペア枠を消費し、**窓内の発言を正典から
        //    押し出せた**（実測: 発信者が min_chars で失格し 220点 → 0点、
        //    その人に投票していたメンバーも 170 → 70）。
        //    発信（投票・密告）側は P-2026-0805 ③ で既に登録時点の `inChatWindow` を
        //    課しており（⑤ と ⑥ の集合を揃えるため）、**メッセージ側だけ漏れていた**。
        //    union の結果は変わらない（どのみち②.5で落ちる）。枠の会計だけが正しくなる。
        if (!inChatWindow(m.timestamp)) continue;
        msgCandidates.push({ m, owner: submitterUid, key: getMsgKey(m) });
      }
    }
    // 正準順序（全順序）: 正典の並び（timestamp → uid → msgKey）→ signature → owner。
    // 🔴 `msgKey` は署名を含まないので、同じ (uid, text, timestamp) に別の有効署名を付けた
    //    「双子」は前3キーが同値になる（`candCanonCmp` の F4 と同じ罠）。`signature` まで
    //    見て全順序にしないと `Array.prototype.sort` の安定性＝入力順が採否を決める。
    //    末尾の owner は、**バイト同一のメッセージが複数の提出物に載ったとき**に
    //    どちらの予算を減らすかを決めるため（結果には効かないが決定論には効く）。
    //    🔴 P-2026-0814: 署名は **`sigLower` で正規化**してから比べる。
    //       ここに到達するのは msgKey が同値な「双子」だけで、`msgRegistry` の dedup により
    //       採用されるメッセージ自体は変わらないが、**どの提出者の予算が減るか**が
    //       大小文字で変わってしまう（Rust はバイト比較なので食い違う）。
    msgCandidates.sort((x, y) =>
      compareCanonical(x.m, y.m)
      || compareStrAsc(sigLower(x.m.signature), sigLower(y.m.signature))
      || compareStrAsc(x.owner, y.owner));

    const msgExaminedOf = new Map();      // 提出者uid          -> 署名検証にかけた件数
    const msgExaminedPairOf = new Map();  // `${提出者}|${発信者}` -> 同上
    for (const { m, owner, key } of msgCandidates) {
      // 重複排除は予算の**前**（同じ msgKey は署名検証しない＝CPU を使わない）
      if (msgRegistry.has(key)) continue;
      const cacheKey = `${key}|${sigLower(m.signature)}`;
      let ok = sigCache.get(cacheKey);
      if (ok === undefined) {
        // ここから先だけが署名検証＝CPU を使う。予算はこの直前に消費する。
        const pairKey = `${owner}${KEY_SEP}${m.uid}`;
        // (b)(c) 予算切れの提出物は読み飛ばすだけ（他の提出物は読み続ける）
        if ((msgExaminedOf.get(owner) || 0) >= msgBundleCap) continue;
        if ((msgExaminedPairOf.get(pairKey) || 0) >= msgSenderCap) continue;
        msgExaminedOf.set(owner, (msgExaminedOf.get(owner) || 0) + 1);
        msgExaminedPairOf.set(pairKey, (msgExaminedPairOf.get(pairKey) || 0) + 1);
        const member = findMember(m.uid);
        // 🔴 P-2026-0819: 壊れた bAddr で例外を外へ出さない（決定論的 park の原因だった）。
        //    ここはループの中なので **`ok = false` に落として次の候補へ進む**
        //    （`return` すると採点関数ごと抜けてしまう）。
        const bAddr = parseBlockAddress(member?.bAddr);
        if (!bAddr) {
          ok = false;
        } else {
          const dataString = chatSignStringV2(ctx.blockNum, ctx.groupId, m.uid, m.text, m.timestamp);
          try {
            ok = await verifyMessage({ address: bAddr.address, message: dataString, signature: m.signature });
          } catch {
            ok = false;
          }
        }
        sigCache.set(cacheKey, ok);
      }
      if (!ok) continue;
      msgRegistry.set(key, m);
      // 既読受領証明が指してよい参照＝**署名検証を通った発言**の msgRef のみ。
      // 発信者 uid で束縛する。msgRef は v12 で16バイト。
      // 🔴 P-2026-0811 #2: 受理時にも鮮度（±10分）を課すため**発信時刻**を持たせる。
      //    旧実装は鮮度が「採用したあと」にしか無く、不鮮度な受領証明が先に
      //    スロットを占有すると、後続の有効なものが署名検証すらされず捨てられた
      //    ＝**発行済みの受領証明を事後に撤回できた**。
      const refKey = `${m.uid}${KEY_SEP}${msgRefOf(key)}`;
      const refTimes = realReadRefs.get(refKey);
      if (refTimes) refTimes.push(m.timestamp);
      else realReadRefs.set(refKey, [m.timestamp]);
    }
    for (const submitterUid of validSubmitters) {
      const priority = priorityOf.get(submitterUid);
      if (priority) for (const m of priority.messages) priorityMsgKeys.add(getMsgKey(m));
    }
    for (const key of priorityMsgKeys) {
      const m = msgRegistry.get(key);
      if (!m) continue;
      const refKey = `${m.uid}${KEY_SEP}${msgRefOf(key)}`;
      const times = priorityRefTimes.get(refKey);
      if (times) times.push(m.timestamp);
      else priorityRefTimes.set(refKey, [m.timestamp]);
    }

    // (c) 実在する発信（投票/密告）の actionHash → 発信者uid。
    //
    // 🔴 **2026-08-05 の作り直し（P-2026-0808）。`addCandidate` と同じ形に揃えた。**
    //    旧実装は ①署名検証をせず ②配列位置で切り詰め ③宣言窓を見ず
    //    ④`__extras` を votes 側でしか剥がしていなかった。
    //    このため「本物と同じ (encrypted, timestamp) で署名だけデタラメ」な偽物で
    //    **架空の actionHash を実在として登録**でき、(提出者,発信者) ペア予算を
    //    埋め尽くして**既にブロードキャストされた受領証明を事後に無効化**できた
    //    （受領証明の (e) 実在ゲートを通らなくなる）。
    //    候補収集（検証④⑤⑥の共通ソース）だけ直しても、この経路が残っていれば
    //    同じ抑圧攻撃が成立する。**必ず両方を同じ規則にすること。**
    const realBuckets = new Map();   // 提出者ごとに actorUid -> type -> [{a, h}]
    for (const r of results) {
      if (r.isDisqualified && ['no_submit', 'invalid_signature', 'chathash_mismatch'].includes(r.disqualifyReason)) {
        continue;
      }
      // 🔴 2026-08-08: 使えるバンドルだけ。非正準な原像（J-12 案A3）／名簿外キー（J-33 案D）は
      //    ここで丸ごと `null` になる ＝ ZKP ゲストの `parse_action_snapshot` が
      //    `Err` を返して `image = None` になるのと同じ結論。
      const ea = usableEa(r.uid);
      if (!ea) continue;
      const buckets = new Map();
      const gather = (actorUidRaw, type, a) => {
        const actorUid = (typeof actorUidRaw === 'string' && actorUidRaw.endsWith('__extras'))
          ? actorUidRaw.slice(0, -'__extras'.length) : actorUidRaw;
        if (!a || !a.encrypted || !a.signature || a.timestamp == null) return;
        if (!memberUids.includes(actorUid)) return;
        if (!isCanonicalSignature(a.signature) || !isOpaqueField(a.encrypted)
          || !isCanonicalActionCiphertext(a.encrypted)                // P-2026-0842
          || !isCanonicalTimestamp(a.timestamp) || !isCanonicalUid(actorUid)) return;
        if (!inChatWindow(a.timestamp)) return;
        let byType = buckets.get(actorUid);
        if (!byType) { byType = new Map(); buckets.set(actorUid, byType); }
        let list = byType.get(type);
        if (!list) { list = []; byType.set(type, list); }
        list.push({ a, h: actionHashV2(type, ctx.blockNum, ctx.groupId, actorUid, a.encrypted, a.timestamp) });
      };
      // 🔴 P-2026-0835: `Object.entries` は使わない（`keyedSection` のコメント参照）。
      //    中間配列を materialize すると 1e6 文字の文字列 / 1,045,000 要素の配列で
      //    isolate が catch 不能の FATAL に落ちる。
      const eaVotes = keyedSection(ea.votes);
      for (const actorUid in eaVotes) {
        if (!hasOwn.call(eaVotes, actorUid)) continue;
        const v = eaVotes[actorUid];
        for (const a of (Array.isArray(v) ? v : [v])) gather(actorUid, 'vote', a);
      }
      const eaReports = keyedSection(ea.reports);
      for (const actorUid in eaReports) {
        if (!hasOwn.call(eaReports, actorUid)) continue;
        const reps = eaReports[actorUid];
        for (const rep of (Array.isArray(reps) ? reps : [reps])) gather(actorUid, 'report', rep);
      }
      const obs = ea.observed;
      if (obs && typeof obs === 'object') {
        const obsVotes = keyedSection(obs.votes);
        for (const rawUid in obsVotes) {
          if (!hasOwn.call(obsVotes, rawUid)) continue;
          const v = obsVotes[rawUid];
          for (const a of (Array.isArray(v) ? v : [v])) gather(rawUid, 'vote', a);
        }
        const obsReports = keyedSection(obs.reports);
        for (const rawUid in obsReports) {
          if (!hasOwn.call(obsReports, rawUid)) continue;
          const reps = obsReports[rawUid];
          for (const rep of (Array.isArray(reps) ? reps : [reps])) gather(rawUid, 'report', rep);
        }
      }
      realBuckets.set(r.uid, buckets);
    }
    // 正準順序（timestamp 昇順 → actionHash 昇順）で切り詰め、**検証してから**登録する
    for (const buckets of realBuckets.values()) {
      for (const [actorUid, byType] of buckets) {
        for (const [type, list] of byType) {
          // 🔴 P-2026-0812 F4: `actionHash` は (type, blockNum, groupId, uid, encrypted,
          //    timestamp) のハッシュで **signature を含まない**。同じ発信に別の有効署名を
          //    付けた「双子」は timestamp も actionHash も一致し、比較関数が 0 を返す＝
          //    `Array.prototype.sort` の安定性で**元配列順**が採否を決めていた。
          //    予算 `used++` は検証の前に消費されるので、双子を先に置くだけで
          //    本物が検証されず `no_vote` 失格にできた（実測 250 → 0）。
          const sorted = [...list].sort(candCanonCmp);
          let used = 0;
          for (const { a, h } of sorted) {
            if (used >= MAX_OBSERVED_ACTIONS_PER_ACTOR) break;
            // 🔴 P-2026-0812: 予算の消費は**重複排除の後**。既に登録済みの actionHash は
            //    署名検証もしないので CPU を使わず、予算を減らす理由が無い。
            //    旧実装は先に消費していたため、同一発信の別バイト署名（high-s 双子）で
            //    予算だけを焼けた（`isCanonicalSignature` の low-s 化と二重に塞ぐ）。
            if (realActionHashes.has(h)) continue;
            used++;                     // 予算は署名検証の前に消費（CPU 有界性）
            if (!(await verifyActionSignature(type, actorUid, a, members, ctx))) continue;
            realActionHashes.set(h, { actorUid, type, timestamp: a.timestamp });
          }
        }
      }
    }
  }

  // ============================================================
  // 受領証明の収集・検証（チャット既読＋アクション受領・v3.2 §6.3）
  //   - 受領証明はグループ全員へブロードキャストされ、各メンバーが観測分を提出物に同梱する。
  //   - 収集元: 有効提出物の messages[].receipts / votes[].receipts / reports[][].receipts /
  //     encryptedActions.observed.receipts
  //   - 有効条件: 発行者がメンバー ∧ 登録pubKeyで署名検証 ∧ チャット窓内。
  //     自己受領（発行者=発信者）は正典条件として無効（検証側で発信者と比較）。
  //   - サーバー受領証明は存在しない（運営バックデートの穴になるため・§6.3）。
  // ============================================================
  // ============================================================
  // Q-S2-001 是正（2026-07-28）: 受領証明の増幅による採点CPUの枯渇を封じる
  // ============================================================
  // 旧実装は「集めた受領証明を1枚残らず署名検証」していた（実測 1.52ms/回・件数上限なし）。
  // グループメンバーは自分の signKey でタイムスタンプを1msずつずらすだけで「本物の署名」を
  // 量産でき、1通の提出物に数千枚を詰めれば採点がCPU上限に達する。K-S2-004 の fail-closed 化に
  // より、これは「自分のグループが消える」から「**ブロック全体が止まる**」に格上げされていた。
  //
  // 対策は4つ。**いずれも失格を伴わない（超過は無視するだけ）** — 通信障害・複数端末・
  // 運営による受領証明履歴の出し渋りで、正直な参加者が巻き込まれないようにするため。
  //
  //  (a) すでに**検証に合格して採用済み**の受領証明でカバー済みの対象しか含まない受領証明は、
  //      **署名検証せずに捨てる**。捨てても結果が変わらないものだけを捨てるので安全。
  //      → 複数端末による二重発行も、水増しも、コストゼロで無効化される。
  //      ⚠️ 「入力の2件目だから捨てる」にしてはならない。攻撃者が偽物を先頭に置いて
  //         本物を押し出し、他人の発言を正典から落として失格させられる（逆向きの攻撃）。
  //  (b) (受領者, 発信者) ペアごとのカバー上限。既読は maxMessages 件・行動は
  //      `receiptMaxActionsPerPair(groupSize)` 件（= 基数10 × groupSize。3人組30 / 4人組40 /
  //      5人組50）。⚠️ 基数 `RECEIPT_MAX_ACTIONS_PER_PAIR_BASE` そのものではない
  //      （P-2026-0812 で groupSize 比例に変わった。旧記述の名残に注意）。
  //      **ペア単位**にするのが要点で、合計で持つと
  //      1人がP2Pに大量発言を流すだけで正直な受領者の枠が埋まり、その人が出した
  //      **他メンバーへの**受領証明が落ちて第三者が min_chars 失格になる。
  //  (c) 提出物1通あたり、署名検証にかける枚数の上限（receiptBundleCap）。
  //      正直な提出物は重複を除いて提出するので必ず収まる＝切り詰められるのは細工した
  //      提出物だけで、その場合も本物は他メンバーの提出物に入っているため失われない。
  //  (d) 1枚に入る msgRef 数の上限（receiptMaxRefsPerReceipt）。
  //
  // 処理は**提出物ごと**に行う（(c) を提出者に帰属させるため）。提出物の順序は results 順
  // ＝メンバー順で決定論的、提出物内の順序は配列順（正規クライアントは署名昇順で整列）。
    // S3R6-G-1-01（凍結の例外 S3R6-U-REPLY2 の2）: 集約の原像を項ごとの同一性の鍵へ写さない。
    // 原像の文字列の中身ごとに番号を振る。同じ中身は同じ番号、違う中身は違う番号になる。
    // 署名の検証には従来どおり原像そのものを使う。Rust の SeenData::segmented と同じ考え。
    const aggregateIdOf = new Map(); // 原像の文字列 -> 番号（この採点の間だけ）
    const aggregateIdFor = (preimage) => {
      let id = aggregateIdOf.get(preimage);
      if (id === undefined) { id = aggregateIdOf.size; aggregateIdOf.set(preimage, id); }
      return id;
    };
    const receiptsOfBundle = (sub, uid) => {
      const out = [];
      // U-7 (B'): 行動の受領証明は発行者本人の提出物から正典へ運ばない。
      // 受理前に除外し、本人の束の examined / pairUsed / accepted を消費させない。
      // msgRefs + senderUid がある形は既読として扱うので従来どおり残す。
      const carry = (rc) => {
        if (rc?.receiverUid === uid && rc.actionHash != null
          && !(Array.isArray(rc.msgRefs) && rc.senderUid != null)) return;
        out.push(rc);
      };
      // 🔴 2026-08-08: 発信と**同じ入口**。非正準な原像（J-12 案A3）／名簿外キー（J-33 案D）の
      //    バンドルは受領証明も1件も提供しない（ZKP ゲストは `image = None` で受領証明0件）。
      const ea = usableEa(uid);
      if (ea && typeof ea === 'object') {
        const ownVote = ea.votes?.[uid];
        if (Array.isArray(ownVote?.receipts)) for (const rc of ownVote.receipts) carry(rc);
        const ownReports = ea.reports?.[uid];
        if (Array.isArray(ownReports)) {
          for (const rep of ownReports) {
            if (Array.isArray(rep?.receipts)) for (const rc of rep.receipts) carry(rc);
          }
        }
        if (Array.isArray(ea.observed?.receipts)) for (const rc of ea.observed.receipts) carry(rc);
        const aggregate = ea.observed?.selfReceiptAggregate;
        if (aggregate && aggregate.version === 1 && aggregate.receiverUid === uid
          && Array.isArray(aggregate.entries) && aggregate.entries.length <= MAX_SELF_AGGREGATE_TARGETS
          && isCanonicalSignature(aggregate.signature)) {
          const aggregatePreimage = selfReceiptAggregateSignString(ctx.blockNum, ctx.groupId, uid, aggregate.entries);
          const aggregateId = aggregateIdFor(aggregatePreimage);
          for (const entry of aggregate.entries) {
            const base = {
              receiverUid: uid,
              timestamp: entry?.timestamp,
              signature: aggregate.signature,
              _selfAggregate: { preimage: aggregatePreimage, signature: aggregate.signature, id: aggregateId },
            };
            if (entry?.targetType === 'read') {
              out.push({ ...base, senderUid: entry.senderUid, msgRefs: [entry.msgRef] });
            }
          }
        }
      }
      // 🔴 P-2026-0812 F1/F2/F3: ここで正準順序に固定する。
      //    同梱位置（自分の投票に付いた分／密告に付いた分／observed）の違いも吸収される。
      return out.sort(receiptCanonCmp);
    };

  const priorityReceiptsOf = (priority, uid) => {
    const out = [...priority.receipts];
    if (Object.prototype.hasOwnProperty.call(priority, 'selfReceiptAggregate')) {
      const agg = priority.selfReceiptAggregate;
      if (agg.receiverUid === uid) {
        const preimage = selfReceiptAggregateSignString(ctx.blockNum, ctx.groupId, uid, agg.entries);
        const aggregateId = aggregateIdFor(preimage);
        for (const entry of agg.entries) {
          out.push({
            receiverUid: uid, timestamp: entry.timestamp, signature: agg.signature,
            _selfAggregate: { preimage, signature: agg.signature, id: aggregateId },
            senderUid: entry.senderUid, msgRefs: [entry.msgRef],
          });
        }
      }
    }
    return out;
  };

  const readReceiptCoverage = new Map();   // msgRef    -> Array<{receiverUid, timestamp}>
  const actionReceiptCoverage = new Map(); // actionHash -> Array<{receiverUid, timestamp}>
  {
    // ⚠️ `maxMessagesCap`（NaN 落とし込み込み）は検証②.5(b) と共有するため関数先頭で定義済み。
    const bundleCap = receiptBundleCap(maxMessagesCap, groupSize);
    const maxRefsPerReceipt = receiptMaxRefsPerReceipt(maxMessagesCap);
    const maxActionsPerPair = receiptMaxActionsPerPair(groupSize);

    const seenSig = new Set();      // 完全同一（署名一致）の多重同梱は無料でスキップ
    const sigCache = new Map();
    // キーの区切りは KEY_SEP（\x1f）。uid のアルファベット（\x21-\x7E）の外なので衝突しない
    const accepted = new Set();     // 採用済みカバー: `受領者␟r␟{msgRef}` / `受領者␟a␟{actionHash}`
    const pairUsed = new Map();     // `受領者␟r␟{発信者}` / `受領者␟a␟{種別}␟{発信者}` -> 採用済み件数

    const usedOf = (key) => pairUsed.get(key) || 0;
    const bumpPair = (key, n) => pairUsed.set(key, usedOf(key) + n);

    //   偽造は不可能（受領者の signKey 署名そのものが要る）ので、
    //   「運んでいないのに運んだと主張する」経路は開かない。
    //   ⚠️ 4つ組で重複排除する＝同じ1枚を何万回同梱しても表は伸びない（DoS 対策）。
    // 1通ぶんの受領証明を、同梱位置の決定論的な順序で並べる
    //
    // 🔴 P-2026-0811 #3（2026-08-05）: **`messages[].receipts` 分岐を削除した。**
    //    提出署名が覆うのは {blockNum,uid,encryptKey,chatHash,submittedAt,encryptedDataHash,
    //    depositIds} だけ、chatHash が覆うのは {uid,text,timestamp,signature} だけなので、
    //    `messages[].receipts` は**誰の署名にも覆われていない**。
    //    ところが旧実装はそこを**最初に**読み、`examined` は署名検証の前に消費されるため、
    //    デタラメ署名を大量に差し込むだけで**本物の受領証明を読む前に予算を焼き切れた**
    //    （提出物は1件も無効化されないまま、狙った1人だけを失格にできた）。
    //    正規クライアント（SubmissionPhase.js）は submittedMessages に receipts を
    //    一度も入れないので、削除して失うものは無い。
    //    運びたくなったら `encryptedDataHash` のプリイメージに入れて署名で覆うこと。
    // 🔴 P-2026-0812 F1/F2/F3（2026-08-06）: **整列してから受理する。**
    //    整列に使う `receiptCanonCmp` はモジュール先頭で `export` している（J-40）。
    //    提出物を組み立てるクライアントが**同じ順序**を使えないと、
    //    採点が採るはずの1枚をクライアントが提出物から落としてしまう。

    // 🔴 P-2026-0827（2026-08-08・修正B）: **`out.push(...配列)` を使わない。**
    //   spread は**引数展開**なので、要素数が多いとスタックが溢れる
    //   （実測 Node v22: **13万要素で `RangeError: Maximum call stack size exceeded`**）。
    //   受領証明は平坦な配列なので `encryptedDataHash` を攻撃者が自分で計算でき、
    //   検証②.6 を**通ってしまう**（深い入れ子ではないので try/catch の側では止まらない）。
    //   プリイメージ 260KB ＝ gzip 後 約1KB なので、`Evidence.submitResult` 1回で載る。
    //   投げた例外は `calcScoringUnit` の外まで抜けて **park（ブロック全停止）**。
    //   1件ずつ `push` すれば引数展開が無いので上限が消える（結果は完全に同一）。
    //   ⚠️ 収集口の**数と順序**は変えないこと（`out.sort` の前段だが、比較器が同値を返す
    //      受領証明では入力順が結果に残る）。


    // 🔴 P-2026-0813（2026-08-07）: **全提出物をまとめて正準順序に並べてから受理する。**
    //
    //    P-2026-0812 では「提出物**内**」でしか整列しておらず、採否を決める状態
    //    （`accepted` / `pairUsed` / カバレッジの受領時刻）は**提出物をまたいで共有**される。
    //    走査は uid 昇順の提出物から先着で消費するので、**同じ署名済み受領証明の集合でも
    //    「どの提出物が運ぶか」で採点が変わった**。実測（Codex 第3回）:
    //
    //      ① 最早受領時刻／5件既読要件
    //         同じ (受領者 p1, 発信者 p4) の受領証明を base+340000 と base+360000 に発行し、
    //         **格納先の提出物だけ**を入れ替える（全体集合は同一）
    //           早い方が先の提出物 → p1=230pt / reportTargetUids=[p4] / p4=0pt(reported)
    //           遅い方が先の提出物 → p1=250pt / reportTargetUids=[]   / p4=30pt
    //         ＝「最も早い受領時刻」が**全体の最小ではなく、最初の提出物内の最小**になっていた
    //
    //      ② applyChatCaps との相互作用
    //         正準順で先に来る1001字×5件と後に来る60字×5件、maxMessages=5・maxMsgChars=1000。
    //         受領証明10件の集合は同一で、先の提出物が運ぶ5件だけ入れ替える
    //           1001字側が先 → p1=0pt（min_chars+min_messages）
    //           60字側が先   → p1=230pt
    //
    //    ⚠️ `examined`（提出物1通あたりの署名検証予算）は**提出者ごとのカウンタとして維持**する。
    //       これは「1人が採点CPUを枯渇させない」ための公平配分なので、全体化してはいけない。
    //    ⚠️ 末尾の owner タイブレーカは、**バイト同一の受領証明が複数の提出物に載ったとき**に
    //       どちらの予算を減らすかを決めるため（結果には効かないが、決定論には効く）。
    const allReceipts = [];
    for (const r of results) {
      // R21-F1: a bundle rejected by the finite/canonical envelope gate must
      // not be expanded again here.  Besides being semantically ineligible as
      // a receipt carrier, walking its rejected giant array would turn a
      // bounded `invalid_signature` verdict back into a block-level throw.
      if (r.isDisqualified && ['no_submit', 'invalid_signature', 'chathash_mismatch', 'snapshot_mismatch']
        .includes(r.disqualifyReason)) continue;
      const sub = submissions?.[r.uid];
      if (!sub) continue;
      for (const rc of receiptsOfBundle(sub, r.uid)) allReceipts.push({ rc, owner: r.uid });
    }
    if (allReceipts.length > MAX_RECEIPT_FACTS * Math.max(1, groupSize)) {
      // Finite-bound derivation (zero slack): validateSubmissionStructure counts every
      // legacy msgRef (or one action receipt) plus every A entry, including duplicates,
      // and allows at most MAX_RECEIPT_FACTS per bundle. Each legacy object contributes
      // at least one counted fact but expands to only one element; each A entry expands
      // to one element. Thus expanded elements <= counted facts <= MAX_RECEIPT_FACTS
      // per bundle, even when receipts overlap. Five bundles yield at most 12,000.
      // The upper bound equals this threshold, so the slack is zero.  If MAX_RECEIPT_FACTS
      // or MAX_GROUP_PLAYERS increases, this throw can park the whole block (H3); changes
      // to any bound input must review all four finite-fact thresholds together.  The fourth
      // is the client-side MAX_SELF_AGGREGATE_TARGETS guard in evidence-compact-v1.js;
      // exceeding it causes no_submit rather than parking the block.
      throw new Error(`[calc] expanded receipt input exceeds finite block limit (${allReceipts.length})`);
    }
    // E′ は通常欄の展開後の上限に数えない（F1）。構造の別上限で総数は有界。
    for (const r of results) {
      if (r.isDisqualified && ['no_submit', 'invalid_signature', 'chathash_mismatch', 'snapshot_mismatch']
        .includes(r.disqualifyReason)) continue;
      const priority = priorityOf.get(r.uid);
      if (!priority) continue;
      for (const rc of priorityReceiptsOf(priority, r.uid)) {
        priorityItems.add(rc);
        allReceipts.push({ rc, owner: r.uid });
      }
    }
    allReceipts.sort((x, y) => receiptCanonCmp(x.rc, y.rc) || compareStrAsc(x.owner, y.owner));

    // ①-P で署名と窓を確かめた E′ のうち、登録済みの E を指す分を先に受理する。
    for (const { rc } of allReceipts) {
      if (!priorityItems.has(rc)) continue;
      for (const ref of rc.msgRefs) {
        const senderTimes = priorityRefTimes.get(`${rc.senderUid}${KEY_SEP}${ref}`);
        if (!senderTimes) continue;
        if (!senderTimes.some((senderTs) => isReceiptTimely(rc.timestamp, senderTs))) continue;
        const coverKey = `${rc.receiverUid}${KEY_SEP}r${KEY_SEP}${ref}`;
        if (accepted.has(coverKey)) continue;
        accepted.add(coverKey);
        let list = readReceiptCoverage.get(ref);
        if (!list) { list = []; readReceiptCoverage.set(ref, list); }
        list.push({ receiverUid: rc.receiverUid, timestamp: rc.timestamp });
        bumpPair(`${rc.receiverUid}${KEY_SEP}r${KEY_SEP}${rc.senderUid}`, 1);
      }
    }

    const examinedOf = new Map(); // 提出者uid -> この提出物から署名検証にかけた枚数
    {
      for (const { rc, owner } of allReceipts) {
        // (c) この提出物の予算が尽きたら、その提出物の残りは読まない
        //     （全体走査なので `break` ではなく `continue`。他の提出物は読み続ける）
        if ((examinedOf.get(owner) || 0) >= bundleCap) continue;
        if (!rc || !rc.signature || !rc.receiverUid || rc.timestamp == null) continue;
        // 🔴 A-1/A-2（2026-08-05）: 署名の形式をここで固定する。
        //    ここが緩いと下の `seenSig`（Set の参照比較）も `sigCache` のキーも壊れ、
        //    **2枚目以降の受領証明が署名検証されずに採用される**（実測で再現）。
        if (!isCanonicalSignature(rc.signature)) continue;
        // P-2026-0806: timestamp と uid の型（小数 ts・孤立サロゲート uid を排除）
        if (!isCanonicalTimestamp(rc.timestamp) || !isCanonicalUid(rc.receiverUid)) continue;
        // 🔴 P-2026-0815（2026-08-07）: **`seenSig` の早期スキップを撤去した。**
        //    旧実装は「署名だけ」を同一性の鍵にしていたが、**同じ ECDSA 署名は
        //    別のメッセージに対して別の公開鍵を復元できる**ので、
        //    「署名が同じ ＝ 同じ受領証明」は成り立たない。実測（Codex 第5回）:
        //      同じ署名を2枚の既読受領証明に付け、それぞれの本文から復元した
        //      別々の blockAddress を名簿に置くと、**両方とも単独では有効**。
        //      先の1枚を採用すると後の「正直者の発言への既読」が重複扱いで捨てられ、
        //      `user0001` が **200点・適格 → 0点・min_chars+min_messages 失格**になった。
        //    `sigCache` は元から `(署名, 種別, 署名対象文字列)` で正しかったのに、
        //    `seenSig` だけが署名単独だった。**同じ鍵に揃える**（下の `seenKey`）。
        //    ⚠️ 同一性の判定に `dataString` が要るので、ここでは早期スキップできない。
        //       `dataString` の構築は署名検証より桁違いに安いので実害は無い。
        if (!memberUids.includes(rc.receiverUid)) continue;
        if (!inChatWindow(rc.timestamp)) continue;
        const bAddr = bAddrOf(rc.receiverUid);
        if (!bAddr) continue;

        // 種別判定: msgRefs配列あり=既読受領証明 / actionHashあり=アクション受領証明
        if (Array.isArray(rc.msgRefs) && rc.senderUid != null) {
          // 🔴 A-3（2026-08-05）: senderUid は**文字列**のみ。数値だと
          //    `realReadRefs` のテンプレート照合（`${rc.senderUid}${KEY_SEP}${ref}`）に一致してしまい、
          //    直下の自己受領検査（`===`）だけが型不一致で素通りする＝自己受領の遮断が破れる。
          if (typeof rc.senderUid !== 'string') continue;
          if (rc.senderUid === rc.receiverUid) continue;              // 自己受領は無効
          if (rc.msgRefs.length === 0 || rc.msgRefs.length > maxRefsPerReceipt) continue; // (d)
          if (!rc.msgRefs.every(isMsgRef)) continue;                  // 形式（旧32バイト形式もここで落ちる）
          const pairKey = `${rc.receiverUid}${KEY_SEP}r${KEY_SEP}${rc.senderUid}`;
          const room = maxMessagesCap - usedOf(pairKey);              // (b) このペアの残り枠
          // (a) 新しく採用できるカバーが1つも無いなら、署名検証せずに捨てる
          // (e) K-S6-002: 参照先が**実在する発言**でないものは数にも入れない。
          //     実在しない参照は照合先が無く元から採点に効かないので、捨てても結果は変わらない。
          // 🔴 P-2026-0811 #10: 署名対象は `[...msgRefs].sort(compareHexAsc)` なのに
          //    採点は提出配列順で走査していた＝運び手が並べ替えるだけで
          //    どの発言を正典に残すか選べた。署名対象と同じ順に揃える。
          // 🔴 J-35（2026-08-09）: `carried` ＝ この1枚が指す「実在かつ鮮度を満たす」参照。
          //    `fresh`（＝新しく採用できるカバー）は従来どおり `carried` を枠で絞ったもの。
          //    分けたのは運び手の記録に使うため。**`fresh` の中身は1バイトも変わらない**
          //    （元の走査は sorted 順で `fresh.length >= room` を先頭に見ていたので、
          //     `carried` を同じ順で辿って同じ位置で break すれば同一集合になる）。
          const carried = [];
          for (const ref of [...rc.msgRefs].sort(compareHexAsc)) {
            const senderTimes = realReadRefs.get(`${rc.senderUid}${KEY_SEP}${ref}`);
            if (!senderTimes) continue;                               // (e) 実在しない参照
            // 🔴 P-2026-0811 #2: 受理の時点で鮮度を課す（旧実装は消費時にしか無かった）。
            //    鮮度を満たさない受領証明は元から採点に効かないので、
            //    枠も accepted も coverage も**一切消費させない**（(e) と同じ論法）。
            if (!senderTimes.some((senderTs) => isReceiptTimely(rc.timestamp, senderTs))) continue;
            if (carried.includes(ref)) continue;
            carried.push(ref);
          }
          const fresh = [];
          for (const ref of carried) {
            if (fresh.length >= room) break;
            const ck = `${rc.receiverUid}${KEY_SEP}r${KEY_SEP}${ref}`;
            if (accepted.has(ck)) continue;
            fresh.push(ref);
          }

          // 🔴 J-35: 採用されない（枠切れ・重複同梱）1枚でも、**検証済みのバイト列と完全同一**なら
          //    「この提出物も同じ1枚を運んでいた」という事実だけは記録する。
          //    署名検証はしない＝ CPU 予算（`examinedOf`）にも `seenSig` にも一切触らない。
          //    ⚠️ 下の `if (fresh.length === 0) continue;` の**前**に置く（採否の会計は1バイトも変えない）。
          if (fresh.length === 0) continue;

          const dataString = rc._selfAggregate?.preimage
            || readReceiptSignString(ctx.blockNum, ctx.groupId, rc.receiverUid, rc.senderUid, rc.msgRefs, rc.timestamp);
          // 🔴 A-1: キーは (署名, 署名対象文字列) の組。集約の項は文字列の中身の番号を使う。
          const aggregateTargetKey = rc._selfAggregate ? `|${rc.senderUid}|${rc.msgRefs.join(',')}|${rc.timestamp}` : '';
          const seenData = rc._selfAggregate ? `agg#${rc._selfAggregate.id}` : dataString;
          const cacheKey = `${sigLower(rc.signature)}|r|${seenData}${aggregateTargetKey}`;
          // 🔴 J-35: この経路（枠が残っているのに完全同一の重複）は実質到達しない
          //    （同一の1枚は先に枠とカバーを埋めるので2枚目の `fresh` は必ず空になる）が、
          //    到達したときに運び手が落ちないよう記録だけしておく。
          // P-2026-0815: 完全同一（同じ署名 ∧ 同じ署名対象）の多重同梱だけを無料でスキップする
          if (seenSig.has(cacheKey)) continue;
          examinedOf.set(owner, (examinedOf.get(owner) || 0) + 1);
          const verifyKey = rc._selfAggregate
            ? `${sigLower(rc.signature)}|aggregate|${dataString}` : cacheKey;
          let ok = sigCache.get(verifyKey);
          if (ok === undefined) {
            try { ok = await verifyMessage({ address: bAddr.address, message: dataString, signature: rc.signature }); }
            catch { ok = false; }
            sigCache.set(verifyKey, ok);
          }
          if (!ok) continue;
          // 🔴 P-2026-0808（2026-08-05）: `seenSig` の記録は**検証に合格してから**行う。
          //    旧実装は検証の前に記録していたため、他人の本物の署名を「中身だけ差し替えた
          //    偽エントリ」で先に焼いておくと、**本物の受領証明が二重同梱として捨てられた**
          //    ＝既にブロードキャストされた受領証明を事後に撤回できた。
          seenSig.add(cacheKey);
          for (const ref of fresh) {
            accepted.add(`${rc.receiverUid}${KEY_SEP}r${KEY_SEP}${ref}`);
            let list = readReceiptCoverage.get(ref);
            if (!list) { list = []; readReceiptCoverage.set(ref, list); }
            list.push({ receiverUid: rc.receiverUid, timestamp: rc.timestamp });
          }
          bumpPair(pairKey, fresh.length);
        } else if (isActionHash(rc.actionHash)) {
          // K-S6-002: 形式（0x+64hex）と実在（提出された発信のいずれかを指すこと）を要求。
          // 旧実装は `typeof === 'string'` だけで、任意長のランダム文字列を受理していた。
          const act = realActionHashes.get(rc.actionHash);
          if (act === undefined) continue;                             // (e) 実在しない発信
          // 🔴 P-2026-0812（2026-08-06）: **自己受領は受理段で弾く。**
          //    既読側は `rc.senderUid === rc.receiverUid` を弾いているのに行動側に無く、
          //    消費側（`actionHasMemberReceipt` の `e.receiverUid !== actorUid`）でしか
          //    落ちていなかった＝受理集合と消費集合が食い違い、枠と `examined` だけを
          //    消費していた（受理側と消費側で条件を揃える・P-2026-0805 ③ と同じ論法）。
          if (rc.receiverUid === act.actorUid) continue;
          // 🔴 P-2026-0811 #2: 受理の時点で鮮度（±10分）を課す。
          //    旧実装は鮮度が「採用したあと」にしか無かったため、不鮮度な受領証明が
          //    先に `accepted` スロットを占有すると、後続の有効なものが署名検証すら
          //    されずに捨てられた ＝ **発行済みの受領証明を事後に撤回できた**。
          //    鮮度を満たさないものは元から採点に効かないので、
          //    枠も accepted も coverage も一切消費させない（(e) と同じ論法）。
          if (!isReceiptTimely(rc.timestamp, act.timestamp)) continue;
          const coverKey = `${rc.receiverUid}${KEY_SEP}a${KEY_SEP}${rc.actionHash}`;
          if (accepted.has(coverKey)) continue;                        // (a)
          // (b) 🔴 P-2026-0808（2026-08-05）: **(受領者, 発信者) ペア単位**に直した。
          //    旧実装は `${rc.receiverUid}|a` の受領者ごと1バケツで、上限も
          //    RECEIPT_MAX_ACTIONS_PER_PAIR × (groupSize−1) と合算だった。
          //    既読側は元からペア単位で、そのコメント自身が
          //    「発信者ごとの合計にすると氾濫者が他人のバケツを埋めて**本物の投票を
          //     押し出し no_vote 冤罪**にできる」と書いているのに、行動側だけ漏れていた。
          //    発信者と種別は `realActionHashes`（actionHash → {actorUid, type, timestamp}）から引く。
          // 🔴 P-2026-0811 #1: 枠キーに **type** を入れる。
          //    候補側 MAX_OBSERVED_ACTIONS_PER_ACTOR は **type ごと**に10件（最大20件）を
          //    許すのに、受領側の枠が type 込みで10件だと**構造的に必ず枠切れが起きる**。
          //    投票1件＋密告10件＝11件で溢れ、どれが落ちるかが入力の並び順で決まっていた
          //    （＝**全員が正直でも事故的に no_vote 失格が起きる**）。
          // 🔴 P-2026-0812: 枠を `10 × groupSize` に。候補側は (提出者, 発信者, 種別) ごと
          //    10件なので、提出者が分担すれば同じ (発信者, 種別) に最大 10×提出者数 件の
          //    実在発信が作れる。固定10件だと**構造的に必ず枠切れ**が起きていた。
          const pairKey = `${rc.receiverUid}${KEY_SEP}a${KEY_SEP}${act.type}${KEY_SEP}${act.actorUid}`;
          if (usedOf(pairKey) >= maxActionsPerPair) continue;

          const dataString = rc._selfAggregate?.preimage
            || receiptSignString(ctx.blockNum, ctx.groupId, rc.receiverUid, rc.actionHash, rc.timestamp);
          // 🔴 A-1: キーは (署名, 署名対象文字列) の組。集約の項は文字列の中身の番号を使う。
          const aggregateTargetKey = rc._selfAggregate ? `|${rc.actionHash}|${rc.timestamp}` : '';
          const seenData = rc._selfAggregate ? `agg#${rc._selfAggregate.id}` : dataString;
          const cacheKey = `${sigLower(rc.signature)}|a|${seenData}${aggregateTargetKey}`;
          // P-2026-0815: 完全同一の多重同梱だけを無料でスキップする（上と同じ理由）
          if (seenSig.has(cacheKey)) continue;
          examinedOf.set(owner, (examinedOf.get(owner) || 0) + 1);
          const verifyKey = rc._selfAggregate
            ? `${sigLower(rc.signature)}|aggregate|${dataString}` : cacheKey;
          let ok = sigCache.get(verifyKey);
          if (ok === undefined) {
            try { ok = await verifyMessage({ address: bAddr.address, message: dataString, signature: rc.signature }); }
            catch { ok = false; }
            sigCache.set(verifyKey, ok);
          }
          if (!ok) continue;
          seenSig.add(cacheKey);   // 🔴 検証に合格してから記録する（上と同じ理由）
          accepted.add(coverKey);
          bumpPair(pairKey, 1);
          let list = actionReceiptCoverage.get(rc.actionHash);
          if (!list) { list = []; actionReceiptCoverage.set(rc.actionHash, list); }
          list.push({ receiverUid: rc.receiverUid, timestamp: rc.timestamp });
        }
      }
    }
    let readFacts = 0;
    for (const list of readReceiptCoverage.values()) readFacts += list.length;
    let actionFacts = 0;
    for (const list of actionReceiptCoverage.values()) actionFacts += list.length;
    // E′ の先の受理も (受け手, 送り手) の枠を使うので各ペアの本番上限は変わらない。
    if (readFacts > 2_000) {
      // Finite-bound derivation (zero slack): `accepted` makes (receiverUid, msgRef)
      // unique, while each (receiverUid, senderUid) pair is capped at caps.maxMessages.
      // A fact can carry only when senderUid matches the roster actor in realReadRefs via
      // `${senderUid}${KEY_SEP}${msgRef}`, and senderUid !== receiverUid.  Therefore the
      // honest maximum is MAX_GROUP_PLAYERS * (MAX_GROUP_PLAYERS - 1) * caps.maxMessages
      // = 5 * 4 * 100 = 2,000.  The upper bound equals this threshold, so the slack is zero.
      // If caps.maxMessages or MAX_GROUP_PLAYERS increases, this throw can park the whole
      // block (H3); changes to any bound input must review all four finite-fact thresholds together.
      // The fourth is the client-side MAX_SELF_AGGREGATE_TARGETS guard in
      // evidence-compact-v1.js; exceeding it causes no_submit rather than parking the block.
      throw new Error(`[calc] accepted chat receipt facts exceed finite limit read=${readFacts}`);
    }
    // Action coverage also retains receipted retry/fraud candidates so that
    // K-S2-006 can see a third distinct report attempt.  The 60-fact protocol
    // bound applies after the one-vote/two-report canonical selection below,
    // not to this deliberately wider defensive candidate pool.
    void actionFacts;
  }

  // アクションの受領証明有無（発信者以外のメンバーによる、発信主張時刻±10分以内の受領≥1件・v3.3）
  const actionHasMemberReceipt = (actorUid, actionHash, claimedTimestamp) => {
    const list = actionReceiptCoverage.get(actionHash);
    if (!list) return false;
    return list.some(e => e.receiverUid !== actorUid && isReceiptTimely(e.timestamp, claimedTimestamp));
  };

  // ============================================================
  // 検証②.5: チャット正典（v3.2 union復活・受領証明フィルタ）
  //   (a) chatHash v2 自己整合: 各提出物の chatHash ↔ messages（不一致は失格）。← 上へ繰り上げ済み
  //   (b) 全提出物のメッセージunion。メッセージ単位でsignKey署名を検証（登録pubKey）。← 同上
  //       ⚠️ (a)(b) は K-S6-002（2026-07-29）で**受領証明の収集より前**へ移した。
  //          受領証明が「実在する発言」を指しているかを判定するには union が先に要るため。
  //          結果は msgRegistry / realReadRefs に入っている（判定順序・失格理由は不変）。
  //   (c) 正典条件 = 「発信者以外のメンバーの有効な既読受領証明≥1件」。
  //       - 偽造挿入: signKey署名は捏造不可能（提出後も永遠に）
  //       - 自己水増し: 正直なメンバーはチャット期間外に受領署名しない
  //       - 事後削除: 本人が提出物から落としても他者の提出物＋受領証明から正典に残る
  //   (d) 規則版数18: 最優先欄の E の和集合を先に採る。件数は E にも掛け、
  //       字数の上限は E に掛けない。残りは最早の既読の順で採る。
  // ============================================================
  let canonicalMessages;
  let effectiveCharCounts;
  {
    const registry = msgRegistry;

    // (c) 受領証明フィルタ: 発信者以外のメンバーの「リアルタイム既読」≥1件のみ正典（v3.3）。
    //     受領timestampが発信主張timestampの±10分以内であることを要求＝バックデート/
    //     ポストデート発信は正直なメンバーから既読を得られず正典外（挟み込みチート遮断）。
    const union = [];
    const receiptTimes = new Map();
    for (const [key, msg] of registry.entries()) {
      // 既読は msgKey の先頭16バイト（msgRef）で参照される（protocol-v2.js）
      const readers = readReceiptCoverage.get(msgRefOf(key));
      const times = (readers || [])
        .filter(e => e.receiverUid !== msg.uid && isReceiptTimely(e.timestamp, msg.timestamp))
        .map(e => e.timestamp).sort((left, right) => left - right);
      if (times.length > 0) {
        union.push(msg);
        receiptTimes.set(msg, times);
      }
    }

    // (d) 正準順序ソート → 窓フィルタ → E を先取り → 残りを最早既読順 → 正準順
    canonicalMessages = union.sort(compareCanonical);
    if (chatWindow) {
      canonicalMessages = canonicalMessages.filter(m => inChatWindow(m.timestamp));
    }
    const evidence = [...priorityMsgKeys].map(key => registry.get(key))
      .filter(m => m && inChatWindow(m.timestamp)).sort(compareCanonical);
    const rest = canonicalMessages.filter(m => !priorityMsgKeys.has(getMsgKey(m)));
    // 🔴 P-2026-0821（2026-08-07）: **正規化済みの `caps` を渡す**（旧: 生の `chatCaps`）。
    //    ここが正典メッセージ集合を確定させる唯一の場所であり、
    //    上限が消えると `summary.json` → `resultHash` → ZKP commit まで全部ずれる。
    canonicalMessages = capMessagesWithEvidence(
      evidence, rest, caps, m => receiptTimes.get(m), compareCanonical);

    // K-S2-003（2026-07-27）: 適格条件の文字数は **不可視文字を除いて**数える。
    // ゼロ幅文字（U+200B 等）は画面に現れず他プレイヤーが判断できないため、
    // 「隠れて文字数を稼ぐ」経路になっていた。空白・結合記号は可視なので従来どおり数える
    // （内容の適正さは密告・投票で他プレイヤーが判断する、という設計に委ねる）。
    // 上限（applyChatCaps）は countHalfWidthChars のまま＝バンドルサイズの縛りは不変。
    effectiveCharCounts = Object.create(null);   // P-2026-0819: uid は `__proto__` になりうる
    for (const msg of canonicalMessages) {
      if (!msg || msg.uid == null) continue;
      effectiveCharCounts[msg.uid] = (effectiveCharCounts[msg.uid] || 0) + countVisibleChars(msg.text || '');
    }

  }

  // ============================================================
  // 検証②.6: encryptedDataHash ↔ 提出スナップショット本体の整合（A-7）
  //   正規スナップショット = {votes, reports, observed}（フィールド順固定・v3.2 §6.8）
  // ============================================================
  for (const r of results) {
    // 🔴 P-2026-0812: 提出物が有れば検証する（(a) と同じ理由）。旧実装は
    //    `isDisqualified` で飛ばしており、`ineligible_deposit` の提出物だけ
    //    `encryptedDataHash` の束縛が外れていた（健全メンバーの提出物なら
    //    `encryptedActions` の差し替えは snapshot_mismatch で検出されるのに、
    //    その相手のものだけ無検出で通った）。
    if (!submissions?.[r.uid]) continue;
    if (r.disqualifyReason === 'invalid_signature' || r.disqualifyReason === 'chathash_mismatch') continue;
    const sub = submissions[r.uid];
    const ea = sub?.encryptedActions;
    if (!ea || typeof ea !== 'object') {
      r.isDisqualified = true;
      r.disqualifyReason = 'snapshot_mismatch';
      continue;
    }
    // 🔴 P-2026-0827（2026-08-08）: プリイメージは `actionSnapshotPreimage` で作る。
    //   `JSON.stringify` は再帰で、Node v22 は**深さ 6,842 で `RangeError`**（実測）。
    //   直に呼ぶと gzip 後 388 バイトのオンチェーン提出1回で**ブロック全体が park** した。
    //   ⚠️ **例外を握って `snapshot_mismatch` に倒すのでは不足**（2026-08-08 訂正）。
    //      ZKP ゲストは `verify_snapshot_hash` で**プルーバが渡したバイト列を keccak するだけ**、
    //      `parse_action_snapshot` の `skip_value` も非再帰なので、正しいハッシュさえ付いていれば
    //      **深い入れ子を普通に受理する**。正典だけ失格に倒すと採点が割れる
    //      （実測 JS `A=0 B=100 C=200` ／ ゲスト `A=200 B=200 C=200`）。
    //      → 同じバイト列を深さに依存せず作り、**同じ結論**へ着地させる。
    //   `null` が返るのは循環参照など JSON 由来では起こり得ない場合だけ（→ snapshot_mismatch）。
    //
    // 🔴 J-12 案A3（2026-08-08・ユーザー確定）: **原像の文法も見る。**
    //   ハッシュは「値」を固定するが「表現」を固定しない。ZKP ゲストは
    //   プルーバが渡したバイト列を keccak するだけなので、原像の文法を制限しないと
    //   同じ宣言ハッシュに対して「正典が作る原像」と「プルーバが選んだ別の書き方」が
    //   併存しうる（実測: 非最短の数値表記1つで JS=259pt / ゲスト=246pt）。
    //   → 制限文法（正準 JSON・数値は安全整数のみ）でなければ `snapshot_mismatch`。
    //   ゲスト側は `verify_snapshot_hash` が同じ検査で落ちる（`crates/scoring-core`）。
    const preimage = actionSnapshotPreimage(ea);
    const recomputed = (preimage === null || !eaGate(r.uid).canonical)
      ? null : keccak256(toHex(preimage));
    // J-37 は未リリースの受理規則版 9 に畳み、RECEIPT_ACCEPTANCE_RULE_VERSION は上げない。
    if (recomputed === null || recomputed !== sub.encryptedDataHash) {
      r.isDisqualified = true;
      r.disqualifyReason = 'snapshot_mismatch';
    }
  }

  // ⚠️ `ownVoteOf` / `ownReportsOf`（本人の提出スナップショットだけを権威とするヘルパー）は
  //    P-2026-0805（2026-08-05）の union 正典化で**削除した**。
  //    「本人の結果提出物に含まれている」（SPEC §6.4 条件4）という要求が無くなったため。

  // アクションの正準ハッシュ（署名対象文字列のkeccak）
  const hashOfAction = (type, uid, a) => actionHashV2(type, ctx.blockNum, ctx.groupId, uid, a.encrypted, a.timestamp);

  // ============================================================
  // 発信（投票／密告）の候補収集 — 検証④⑤⑥の**共通ソース**
  // ============================================================
  // 🔴 P-2026-0805（2026-08-05）: union 正典化に伴い、④⑤ もこの候補集合を見る。
  //    旧実装は ④ が `ownVoteOf`、⑤ が `ownReportsOf` と**本人提出物だけ**を権威にしており、
  //    「本人の結果提出物に含まれている」（SPEC §6.4 条件4）が有効性の条件だった。
  //    条件4 を廃止したので、収集を ④ の**手前**へ巻き上げて3者で共有する。
  const receiptedVoteActors = new Set();
  // 観測セクションから各メンバーの発信候補を収集（有効提出物のみ）
  const validSubUids = results.filter(r => !r.isDisqualified || !['no_submit', 'invalid_signature', 'chathash_mismatch', 'snapshot_mismatch'].includes(r.disqualifyReason))
    // 🔴 2026-08-08: `usableEa` が発信の唯一の入口（J-12 案A3 / J-33 案D）。
    .filter(r => usableEa(r.uid)).map(r => r.uid);

  // actorUid -> Map<actionHash, action>（type別）
  const observedVotesOf = new Map();
  const observedReportsOf = new Map();
  // 🔴 J-15（2026-08-08）: 密告の**第2パス用の控え**。
  //    actorUid -> Map<`${actionHash}|${署名}`, {h, a}>
  //    第1パス（＝下の 10 枠）で採られなかった候補のうち、**受領証明のあるものだけ**を
  //    (提出者, 発信者) ごと最大 MAX_OBSERVED_ACTIONS_PER_ACTOR 件まで控える。
  //    ⚠️ 受領証明のあるものに絞るのは**メモリ上限のため**でもある。全候補を保持すると
  //       1通のバンドルに 10^6 件を詰めるだけで isolate が落ちる（`keyedSection` の注釈参照）。
  //       受領済みの発信は `realActionHashes`（10 × 提出者数 × 種別）に束縛されるので有界。
  //    ⚠️ ここでは署名検証も復号もしない（**平常時のコストを 1 サイクルも増やさない**）。
  //       実際に使うのは検証⑤の第2パスだけで、そこで初めて検証する。
  const extraReportCandsOf = new Map();
  // K-S6-002（2026-07-29）: 候補は1件ずつ署名検証にかかる。
  // 上限が無いと、1人が自分の signKey で正しく署名した発信を数千件流すだけで採点CPUを枯渇させ、
  // かつ全員の提出物を肥大させて提出不能にできた。
  // ⚠️ 予算は **(提出者, 発信者) ペアごと**。発信者ごとの合計にすると、氾濫者が他人のバケツを
  //    埋めて**本物の投票を押し出し no_vote 失格**にできる（受領証明の (b) と同じ理由）。
  //
  // 🔴 **2026-08-05 の作り直し（P-2026-0805 / P-2026-0808）。3点変えた。**
  //
  // ① **署名検証してから登録する**（旧実装は先着で hash スロットを埋め、検証は後だった）
  //    `actionHashV2` は (type, blockNum, groupId, uid, encrypted, timestamp) だけを束ね
  //    **署名を含まない**（`protocol-v2.js`）。旧実装は `if (!m.has(h)) m.set(h, a)` の
  //    先着1件保持で検証が後だったため、**本物と同じ中身で署名だけデタラメな偽物**を
  //    先に置くと hash スロットを先取りでき、後の検証で偽物が捨てられると
  //    **本物も一緒に消えた**。
  //    実測（2026-08-05）: 2対象へ投票した不正者が自分の観測欄に毒を置くだけで
  //    `vote_fraud`(0pt) → `ok`(200pt) に逃げ切れた＝**one-shot 規則の検知バイパス**。
  //    union 正典化すると向きが逆転し「**他人の本物の発信を消して正直者を失格にできる**」
  //    になるため、union 化の前提条件として先に直す。
  //    ⚠️ チャットのメッセージ側（`msgRegistry`）は元から verify→insert の順で正しかった。
  //
  // ② 予算の切り詰めを**配列位置ではなく正準順序**（timestamp 昇順 → actionHash 昇順）で行う。
  //    位置ベースだと、11件以上発信した本人が「提出時にどれを残すか」を配列順で選べる
  //    ＝**提出期間が第二の意思決定点**になり、union 化の眼目（発信した時点で確定・
  //    あとから引っ込められない）が崩れる。正準順序なら全員が同じ N 件を残す。
  //
  // ③ **宣言窓の外の発信は最初から採らない**。⑤（`inChatWindow`）は窓外を無視するのに
  //    ⑥ の `allSentTargets` は数えていたため、時計ずれや再送で3件目が窓外に落ちた
  //    正直なプレイヤーが `report_fraud` で失格しえた。両者を同一集合に揃える。
  //
  // ④ 観測セクションの `__extras` サフィックスを剥がす（`addRealAction` と同形）。
  //    剥がさないと `<uid>__extras` キーで運ばれた2本目が候補に入らず、
  //    one-shot 規則を回避できた。
  const stripExtras = (u) => (typeof u === 'string' && u.endsWith('__extras')
    ? u.slice(0, -'__extras'.length) : u);
  /// 正準順序: timestamp 昇順 → actionHash 昇順
  const canonCmp = candCanonCmp;

  for (const uid of validSubUids) {
    const ea = usableEa(uid);   // 🔴 2026-08-08: 発信の唯一の入口（J-12 案A3 / J-33 案D）
    // この提出者ぶんの候補: actorUid -> type -> [{a, h}]
    const buckets = new Map();
    const collect = (actorUid, type, a) => {
      if (!a || !a.encrypted || !a.signature || a.timestamp == null) return;
      // P-2026-0806: ZKP ゲストが表現できない型を排除
      // P-2026-0842: `encrypted` は正準長の hex のみ（長さチャネルの遮断・規則 v7）
      if (!isCanonicalSignature(a.signature) || !isOpaqueField(a.encrypted)
        || !isCanonicalActionCiphertext(a.encrypted)
        || !isCanonicalTimestamp(a.timestamp) || !isCanonicalUid(actorUid)) return;
      if (!inChatWindow(a.timestamp)) return;                     // ③
      let byType = buckets.get(actorUid);
      if (!byType) { byType = new Map(); buckets.set(actorUid, byType); }
      let list = byType.get(type);
      if (!list) { list = []; byType.set(type, list); }
      list.push({ a, h: hashOfAction(type, actorUid, a) });
    };

    // 本人セクション（自分の分）。正規形は単体だが、改造クライアントが複数投票を
    // 配列で入れてくる場合も候補に取り込む。
    const ownVote = ea.votes?.[uid];
    for (const a of (Array.isArray(ownVote) ? ownVote : [ownVote])) if (a) collect(uid, 'vote', a);
    for (const rep of (Array.isArray(ea.reports?.[uid]) ? ea.reports[uid] : [])) {
      collect(uid, 'report', rep);
    }
    // 観測セクション（他人の発信・単体/配列の両形式を受理）
    const obs = ea.observed;
    if (obs && typeof obs === 'object') {
      // 🔴 P-2026-0835: `Object.entries` は使わない（`keyedSection` のコメント参照）
      const obsVotes = keyedSection(obs.votes);
      for (const rawActor in obsVotes) {
        if (!hasOwn.call(obsVotes, rawActor)) continue;
        const v = obsVotes[rawActor];
        const actorUid = stripExtras(rawActor);                   // ④
        if (!memberUids.includes(actorUid)) continue;
        for (const a of (Array.isArray(v) ? v : [v])) collect(actorUid, 'vote', a);
      }
      const obsReports = keyedSection(obs.reports);
      for (const rawActor in obsReports) {
        if (!hasOwn.call(obsReports, rawActor)) continue;
        const reps = obsReports[rawActor];
        const actorUid = stripExtras(rawActor);                   // ④
        if (!memberUids.includes(actorUid) || !Array.isArray(reps)) continue;
        for (const rep of reps) collect(actorUid, 'report', rep);
      }
    }

    // ② 正準順序で並べ、先頭 MAX_OBSERVED_ACTIONS_PER_ACTOR 件だけを検証して採用
    for (const [actorUid, byType] of buckets) {
      for (const [type, list] of byType) {
        const map = type === 'vote' ? observedVotesOf : observedReportsOf;
        let m = map.get(actorUid);
        if (!m) { m = new Map(); map.set(actorUid, m); }
        const sorted = [...list].sort(canonCmp);
        let used = 0;
        for (const { a, h } of sorted) {
          // ============================================================
          // 🔴 J-15（2026-08-08・ユーザー確定 案A）: **投票は受領証明のあるものだけ**
          // ============================================================
          //   void の投票は**どこでも使われていない**（④も⑥(c)も `receipted` に絞り、
          //   `receiptedVoteActors` も受領済みのみを見る）。にもかかわらず 10 枠を食っていた
          //   ため、古い void が並ぶと**唯一有効な最新の投票が捨てられた**。
          //   実測: 10件（void 9 + 受領 1）→ {200,200,200} ／
          //         11件（void 10 + 受領 1）→ **{0,100,200}**（発信者が `no_vote` 失格・
          //         投票先の無実の第三者もボーナス 100点を失う）。
          //   自損ゼロで狙える（同組の1人が最初の10回だけ受領証明を出さない）うえ、
          //   回線断・タブ休止・再送の繰り返しで**事故でも起きる**。
          //
          //   🔴 判定は切り詰めの**前**にできる。「受領証明の受理」は循環するが、
          //      `actionReceiptCoverage` はこの候補収集より**手前**で確定している
          //      （受理は `realActionHashes` にだけ依存し、候補集合には依存しない）。
          //      ＝ 復号も追加の署名検証も要らない。
          //   ⚠️ **密告（⑤）は同じ扱いにしてはいけない**。密告には「2枠」という奪い合う
          //      資源があり、void も受領済み候補の後で枠を消費しうる。
          //      ここで void を除くと最後の枠が動く。
          //      密告側の救済は検証⑤の**第2パス**（枠を決めたあと）で行う。
          //   ⚠️ 予算 10 を残す理由は**署名検証の回数を抑えるため**。⑥(c) は受領済みを
          //      走査して1件でもデタラメなら即 `vote_fraud` なので、位置は無関係。
          if (type === 'vote' && !actionHasMemberReceipt(actorUid, h, a.timestamp)) continue;
          if (used >= MAX_OBSERVED_ACTIONS_PER_ACTOR) break;
          // 🔴 P-2026-0813（2026-08-07）: **重複排除は予算の消費より前**。
          //    `m` は全提出者で共有される（union）ので、既に別の提出物から登録済みの
          //    発信をもう一度運ぶだけで、後続の提出物の10枠を焼けた。実測:
          //      正規の投票 Y が本人の提出物から欠け、p2 の観測欄から union で救済される形で、
          //      既に登録済みの void 投票 X を p2 の同じ候補列にも入れる。
          //        X が1コピー  → p1 = 230pt / voteTargetUid = p2
          //        X が10コピー → p1 =   0pt / no_vote 失格（集合としては同一）
          //    `realActionHashes` 側（addRealAction）は P-2026-0812 で既に直っていたのに、
          //    **候補側だけ順序が逆のまま残っていた**（同じ穴を2箇所に開けていた）。
          //    ⚠️ 重複は署名検証もしないので CPU を使わず、予算を減らす理由が無い。
          if (m.has(h)) continue;
          used++;                       // 予算は署名検証の前に消費（CPU 有界性を保つ）
          // ① 検証してから登録する
          if (!(await verifyActionSignature(type, actorUid, a, members, ctx))) continue;
          m.set(h, a);
        }

        // ============================================================
        // 🔴 J-15 第2パスの控え（密告のみ・ここでは検証も復号もしない）
        // ============================================================
        //   第1パスで 10 枠から溢れた（または署名検証に落ちた）候補のうち、
        //   **受領証明のあるもの**だけを控える。枠と2標的は第1パスが決め、ここは
        //   触らない。第1パスの順は検証⑤で最初の受領証明時刻へ変える。
        //   正常なゲームでは密告は1〜2件なので `sorted` は 10 件以下 ＝ この控えは常に空で、
        //   検証⑤の第2パスは**一度も走らない**。
        if (type === 'report') {
          let extras = null;
          let taken = 0;
          for (const { a, h } of sorted) {
            if (taken >= MAX_OBSERVED_ACTIONS_PER_ACTOR) break;
            if (m.has(h)) continue;                                    // 第1パスで採用済み
            if (!actionHasMemberReceipt(actorUid, h, a.timestamp)) continue;  // void は救わない
            if (extras === null) {
              extras = extraReportCandsOf.get(actorUid);
              if (!extras) { extras = new Map(); extraReportCandsOf.set(actorUid, extras); }
            }
            // 双子（同じ発信の別署名）は別エントリのまま持つ。第2パスが署名検証するので、
            // ここで1件に畳むと「先に来たデタラメ署名」が本物を隠しうる。
            // 🔴 P-2026-0843（2026-08-09・ラウンド22 根4）: **重複排除は予算の消費より前**。
            //    キーは `(actionHash, 署名)` の組で、`extras` は Map ＝ 完全同一の重複は
            //    どのみち1件に畳まれるのに、旧実装は畳んだあとも `taken++` を回していた。
            //    ＝ **同じ集合を9本同梱するか10本同梱するかで正典の点数表が変わる**
            //      （正典が完全同一の重複に対して冪等でない）。実測（`j15-extra-pool-dup-*`）:
            //        9本  → 控えに本物も入り、密告2名成立で被密告者が `reported` 失格
            //        10本 → 予算が尽きて**本物が控えに入らず**、密告が1名に減って不成立
            //               （攻撃者 52pt → 94pt ＝ 事後削除の復活）
            //    第1パス（`m.has(h)`）と `realActionHashes`（P-2026-0812/0813）は
            //    既にこの順で、**ここだけが残っていた**（同じ穴の3箇所目）。
            //    ⚠️ 重複は署名検証もしないので CPU を使わず、予算を減らす理由が無い。
            //    ⚠️ Rust ゲスト（`crates/scoring-core/src/actions.rs` の
            //       `ExtraReportPool::has` → `continue` → `taken += 1`）は初めから
            //       この順で、割れていたのは JS 側だけ ＝ ZKP を通すと証明不能になる class。
            const ek = `${h}${KEY_SEP}${sigLower(a.signature)}`;
            if (extras.has(ek)) continue;
            extras.set(ek, { h, a });
            taken++;
          }
        }
      }
    }
  }

  // 候補は**すべて署名検証済み**（① の作り直し）。以降は再検証しない。
  /// (actorUid, type) の候補を正準順序（timestamp → actionHash）で並べて返す
  const candsOf = (map, uid) =>
    [...(map.get(uid) || new Map()).entries()].map(([h, a]) => ({ h, a })).sort(canonCmp);

  // 「投票発信が成立していた」発信者を収集（署名検証＋発信者以外のリアルタイム受領証明≥1件）。
  // encryptKey は不要＝未提出者（no_submit）についても判定できる。復号は行わない。
  for (const [actorUid, cands] of observedVotesOf.entries()) {
    for (const [h, a] of cands.entries()) {
      if (!actionHasMemberReceipt(actorUid, h, a.timestamp)) continue; // void は「なかったこと」
      receiptedVoteActors.add(actorUid);
      break;
    }
  }

  // 規則版数5: 受領証明のある投票の最早の自称時刻。復号結果や提出者には依存しない。
  const confirmedVoteTs = new Map();
  for (const [actorUid, cands] of observedVotesOf.entries()) {
    for (const a of cands.values()) {
      const previous = confirmedVoteTs.get(actorUid);
      if (previous === undefined || a.timestamp < previous) confirmedVoteTs.set(actorUid, a.timestamp);
    }
  }
  const reportEligible = (targetUid, reportTimestamp) => {
    const voteTs = confirmedVoteTs.get(targetUid);
    return voteTs !== undefined && voteTs < reportTimestamp;
  };

  // 検証⑤の枠だけに使う鍵。actionHasMemberReceipt と同じ受理済み coverage を見る。
  const firstCountedReceiptTs = (actorUid, actionHash, claimedTs) => {
    let first = null;
    for (const e of actionReceiptCoverage.get(actionHash) || []) {
      if (e.receiverUid === actorUid || !isReceiptTimely(e.timestamp, claimedTs)) continue;
      if (first === null || e.timestamp < first) first = e.timestamp;
    }
    return first;
  };


  // ============================================================
  // 検証④: 投票（union・署名・窓・受領証明・復号）
  // ============================================================
  // 🔴 P-2026-0805（2026-08-05）: 正典を「本人提出物」から **union** へ寄せた。
  //    SPEC §6.4 の条件4「**本人の結果提出物に含まれている**」を廃止。
  //    発端はテストラン block1 の `report_fraud` 冤罪（クライアントが提出物から
  //    密告1件を黙って落とし、⑥(b) の「取下げ」に見えた）。
  //
  // 🔴 **対象矛盾を失格にしない**（2026-08-05・ユーザー確定）。
  //    有効な投票 = 受領証明の付いた発信を**正準順序（timestamp → actionHash）**で
  //    並べた**先頭1件**。void 後に対象を乗り換えても「最初に受領された対象」しか
  //    効かないので、乗り換えの利得はゼロ＝ one-shot の目的は達成される。
  //    🔴 **J-19（2026-08-08・ユーザー確定 案D＝受容）: この「利得ゼロ」は
  //       発信者について正しく、運び手について正しくない。** 発信者は選び直せないが、
  //       **どれが先頭になるかは第三者が受領証明1枚で変えられる**（void だった古い発信に
  //       後から受領証明を付けると投票ボーナスの行き先が変わる・攻撃者の自損ゼロ）。
  //       これは**仕様**（「標的を変更したプレイヤーが悪い」＋「ゲーム期間中に未読でも
  //       提出期間中に既読へ変わりうるのは許容」）であって見落としではない。
  //       正規クライアントを使っている限り標的の変更自体が起きないので、発火するのは
  //       下の fail-open（localStorage 消失／復元クライアント）に当たった参加者だけ。
  //
  //    失格（致死判定）にしない理由: 対象変更を禁じているのはクライアント
  //    `src/components/game/ChatPhase.js` のガードだけで、これは **fail-open**。
  //    自分の投票を ①localStorage ②DO のエコー ③P2P 自己エコー の3経路すべてから
  //    復元できないと全対象のボタンが復活する。**localStorage が消えただけで
  //    悪意ゼロの参加者が2対象ぶんの署名を作れてしまい**、失格＝全損は重すぎる
  //    （復元クライアント `chatgame-tools` は DO/WS 接続を持たないため常にこの状態）。
  for (const r of results) {
    if (r.isDisqualified) continue;
    const encryptKey = verifiedEncryptKeys[r.uid];
    if (!encryptKey) continue;

    // 受領証明のある発信だけが「発信として成立」（void ＝ なかったこと）
    const receipted = candsOf(observedVotesOf, r.uid)
      .filter(({ h, a }) => actionHasMemberReceipt(r.uid, h, a.timestamp));

    let picked = null;
    for (const { h, a } of receipted) {
      try {
        const d = JSON.parse(eciesDecrypt(a.encrypted, encryptKey));
        // 対象が無効な発信は投票として成立しない（受領済みなら⑥(c)で vote_fraud）
        if (!d.targetUid || !memberUids.includes(d.targetUid) || d.targetUid === r.uid) continue;
        picked = { targetUid: d.targetUid };
        canonicalVoteActions.set(r.uid, {
          actorUid: r.uid,
          targetUid: d.targetUid,
          timestamp: a.timestamp,
          actionHash: h,
        });
        break;                         // 正準順序の先頭1件
      } catch { /* 復号不能は⑥(c)で garbled として捕捉 */ }
    }

    if (!picked) {
      r.isDisqualified = true;
      r.disqualifyReason = 'no_vote';
      continue;
    }
    decryptedVotes[r.uid] = picked;
    r.voteTargetUid = picked.targetUid;
  }

  // ============================================================
  // 検証⑤: 密告（union・署名・窓・受領証明・復号・最大2件）
  // ============================================================
  // 🔴 P-2026-0805: 正典を union へ。条件4 を廃止。
  //
  // K-S2-006: 密告の2枠は、最初の受領証明の時刻が早い順の2人で決まる。
  // 受領証明の無い（void の）密告は、その後でだけ枠を取る。
  // 正直な画面は void の対象も2枠に数え、3人目への密告を出させない。
  //
  // 第1パスは最初の数える受領証明の時刻で整列し、同点と void は正準順にする。
  // 旧実装の配列順依存では同じ発信集合でも失格者が入れ替わった（30 ↔ 0）。
  //    この配列は summary.json / D1 に載り resultHash → Merkle → ZKP の入力になるので、
  //    順序が未定義だとバイト厳密性が保証できない。
  //
  // 🔴 P-2026-0811 #11（2026-08-05・ユーザー確定）: **密告が生き残る失格理由**を導入した。
  //    「ゲーム中の必須ミッション未達」と「密告成立」で失格した者の密告は**生き残る**。
  //    それ以外の失格（署名不正・提出物不整合・不正発信・不適格デポジット）では**消える**。
  //      生きる  : min_chars / min_messages / no_vote / reported
  //      消える  : invalid_signature / chathash_mismatch / snapshot_mismatch /
  //                vote_fraud / report_fraud / ineligible_deposit / no_submit
  //    理由: 密告は「AI/Bot を見つけて排除する」というゲームの中核機能であり、
  //    密告した本人が文字数を稼げなかった／投票を出せなかったことと、その密告の
  //    真偽は無関係。逆に「不正な提出物を出した」者の密告を残すと、失格覚悟で
  //    他人を道連れにする経路が開く。密告返し（カウンター）を成立させるため
  //    `reported` も生き残る側に置く。
  //    ⚠️ ここで飛ばすのは「消える」理由だけ。`no_vote` は④で付くのでここに届く。
  //       min_chars / min_messages は⑦で付く＝ここでは未確定なので自然に通る。
  //       実際の除外は reportsByTarget の構築時（＝全理由が確定した後）に行う。
  for (const r of results) {
    if (r.isDisqualified && isReportVoidingDq(r)) continue;
    const encryptKey = verifiedEncryptKeys[r.uid];
    if (!encryptKey) continue;

    // 最大密告数（chat-game-DO の MAX_REPORTS と同値）
    const MAX_REPORTS = 2;
    const consumedTargets = new Set();
    const validReports = [];
    const validReportActions = [];

    const firstPassReports = candsOf(observedReportsOf, r.uid).sort((left, right) => {
      const lt = firstCountedReceiptTs(r.uid, left.h, left.a.timestamp);
      const rt = firstCountedReceiptTs(r.uid, right.h, right.a.timestamp);
      if (lt === null && rt !== null) return 1;
      if (lt !== null && rt === null) return -1;
      if (lt !== null && rt !== null && lt !== rt) return lt - rt;
      return canonCmp(left, right);
    });
    for (const { h, a } of firstPassReports) {
      // 枠の消費判定（受領の有無を問わない）— 対象が復号でき有効な場合のみ
      let slotTarget = null;
      try {
        const d = JSON.parse(eciesDecrypt(a.encrypted, encryptKey));
        if (d?.targetUid && memberUids.includes(d.targetUid) && d.targetUid !== r.uid) slotTarget = d.targetUid;
      } catch { /* 復号不能は枠を消費しない（受領済みなら⑥の garbled で捕捉） */ }
      if (slotTarget === null) continue;

      // 既に2枠を別対象で使い切っている場合、新しい対象は枠外＝有効化しない
      if (!consumedTargets.has(slotTarget) && consumedTargets.size >= MAX_REPORTS) continue;
      consumedTargets.add(slotTarget);

      // 規則版数5: 標的の確定した投票より後の密告だけ有効。作者と運び手に依存しない。
      // **枠の消費は上で済ませてある** — ここで枠を返すと K-S2-006 が再発する。
      if (!reportEligible(slotTarget, a.timestamp)) continue;
      // void は有効な密告にならない（枠は上で消費済み＝戻らない）
      if (!actionHasMemberReceipt(r.uid, h, a.timestamp)) continue;
      // 同一対象への複数発信（void 後の再送）は1件に畳む
      if (validReports.some(vr => vr.targetUid === slotTarget)) continue;

      validReports.push({ targetUid: slotTarget });
      validReportActions.push({
        actorUid: r.uid,
        targetUid: slotTarget,
        timestamp: a.timestamp,
        actionHash: h,
      });
    }

    // ============================================================
    // 🔴 J-15 第2パス（2026-08-08・ユーザー確定）
    // ============================================================
    //   第1パスの枠の順は受領証明時刻へ変更済み。枠を取った標的だけを救う。
    //   ここは「枠を取った標的なのに、有効な密告が1件も残らなかった」場合だけ、
    //   **その標的への**受領証明つきの密告を古い順に探して救う。
    //     救うもの  : 同じ標的への再送が11件目にある場合（第1パスの10枠から溢れた）
    //     救わないもの: 3番目の**新しい**標的（枠外のまま＝仕様どおり・K-S2-006）
    //   🔴 枠は戻さない。戻すと「試し放題」に戻る。
    //   🔴 必要なときだけ走る。控え（`extraReportCandsOf`）は 10 件を超える密告候補が
    //      1通のバンドルに載ったときしか作られないので、正常なゲームでは**空**＝
    //      このブロックは1回も回らない（`reportSecondPassStats` で実測できる）。
    const extraPool = extraReportCandsOf.get(r.uid);
    if (extraPool && extraPool.size > 0 && validReports.length < consumedTargets.size) {
      const registered = observedReportsOf.get(r.uid) || EMPTY_CAND_MAP;
      // 走査順は正準順序（timestamp → actionHash → 署名）。第1パスとは別の順序。
      const extras = [...extraPool.values()].sort(canonCmp);
      for (const slotTarget of consumedTargets) {
        if (validReports.some(vr => vr.targetUid === slotTarget)) continue;
        reportSecondPassStats.runs++;
        let examined = 0;
        for (const { h, a } of extras) {
          // 1標的あたり最大 MAX_OBSERVED_ACTIONS_PER_ACTOR 件だけ検証する（CPU 有界性）
          if (examined >= MAX_OBSERVED_ACTIONS_PER_ACTOR) break;
          if (registered.has(h)) continue;         // 第1パスが既に見た発信
          examined++;
          reportSecondPassStats.examined++;
          // 控えには署名検証を通していない候補も入っている（双子対策）。ここで検証する。
          if (!(await verifyActionSignature('report', r.uid, a, members, ctx))) continue;
          let target = null;
          try {
            const d = JSON.parse(eciesDecrypt(a.encrypted, encryptKey));
            if (d?.targetUid && memberUids.includes(d.targetUid) && d.targetUid !== r.uid) target = d.targetUid;
          } catch { /* 復号不能は救済にならない（⑥は第1パスの集合だけを見る） */ }
          if (target !== slotTarget) continue;
          if (!reportEligible(slotTarget, a.timestamp)) continue;
          // 受領証明があることは控えに入る条件（＝ここでは再確認不要）
          validReports.push({ targetUid: slotTarget });
          validReportActions.push({
            actorUid: r.uid,
            targetUid: slotTarget,
            timestamp: a.timestamp,
            actionHash: h,
          });
          break;
        }
      }
    }

    decryptedReports[r.uid] = validReports;
    canonicalReportActions.set(r.uid, validReportActions);
    r.reportTargetUids = validReports.map(vr => vr.targetUid);
  }

  // Round 21 F1 semantic action bound: five accepted votes plus ten accepted
  // reports, each receipted by at most four other members. Fraud/retry
  // candidates remain available above but do not count as accepted facts.
  {
    const acceptedHashes = new Set();
    for (const action of canonicalVoteActions.values()) acceptedHashes.add(action.actionHash);
    for (const actions of canonicalReportActions.values()) {
      for (const action of actions) acceptedHashes.add(action.actionHash);
    }
    let acceptedActionFacts = 0;
    for (const hash of acceptedHashes) acceptedActionFacts += actionReceiptCoverage.get(hash)?.length || 0;
    if (acceptedActionFacts > 60) {
      // Finite-bound derivation (zero slack): each uid contributes at most
      // MAX_ACCEPTED_VOTES_PER_PLAYER + MAX_ACCEPTED_REPORTS_PER_PLAYER = 1 + 2 accepted
      // hashes, so MAX_GROUP_PLAYERS gives 15 hashes.  Coverage is unique by
      // (receiverUid, actionHash), and a receiver must be a roster member other than the
      // actor, giving at most MAX_GROUP_PLAYERS - 1 = 4 facts per hash: 15 * 4 = 60.
      // The upper bound equals this threshold, so the slack is zero.  If either accepted-
      // action limit or MAX_GROUP_PLAYERS increases, this throw can park the whole block
      // (H3); changes to any bound input must review all four finite-fact thresholds together.
      // The fourth is the client-side MAX_SELF_AGGREGATE_TARGETS guard in
      // evidence-compact-v1.js; exceeding it causes no_submit rather than parking the block.
      throw new Error(`[calc] accepted action receipt facts exceed finite limit action=${acceptedActionFacts}`);
    }
  }

  // ============================================================
  // 検証⑥: 不正判定（vote_fraud / report_fraud）
  // ============================================================
  //   (a) **密告**の対象超過: distinct 対象が3件以上（void を含む・K-S2-006）
  //   (c) デタラメ発信: 正当署名＋受領証明付きなのに「正しい投票/密告データ」でない
  //       ＝復号不能、または復号できたが対象が無効（targetUid 欠落・非メンバー・自分自身）。
  //       正規クライアントでは起こり得ない＝改造クライアントの意図的発信なので不正扱い。
  //
  // 🔴 **(b)（受領済み発信の未提出・取下げ）は 2026-08-05 に廃止**（P-2026-0805）。
  //    条件4 を廃止したので「本人提出物に無い＝取下げ」という概念自体が無くなった。
  //    (b) が守っていた「密告したよフェイク」「反応的プレイ」は union が直接塞ぐ
  //    （発信した時点で全員の提出物に載るので引っ込められない）。
  //    🔴 **2026-08-08 訂正（J-22 1-c）**: この一文が当てはまるのは
  //       **実際にブロードキャストされた発信だけ**である。密告発信を**0通**に置けば
  //       `report_fraud` も付かず `reportTargetUids` も空＝**取下げに罰が無い**。
  //       共謀ペアは「チャット中に密告発信をブロードキャストしない」だけで、
  //       正直な実時刻の ts のまま**提出時に行使できる選択権**を保持できる
  //       （実測 4人組・全員 10 ETH: ペア合計 1264 → 提出時に密告 1684・自損0）。
  //       受容の判断と情報チャネルの限定は `docs/FAIRNESS_AUDIT_FIX_PLAN.md` A4。
  //    ⚠️ `ownVoteOf` / `ownReportsOf` はこれで未使用になったため削除した。
  //       ヘルパーが残っていないことが「(b) が消えている」ことの機械的な確認になる。
  //
  // 🔴 **投票の (a)（対象矛盾）も廃止**。④ が正準順序の先頭1件を採るので乗り換えの
  //    利得がゼロであり、致死判定が守るものが無い。詳細は④のコメント。
  const markFraud = (uid, reason) => {
    const r = findResult(uid);
    if (!r) return;
    r.isDisqualified = true;
    r.disqualifyReason = reason;
    r.fraudReason = reason;
  };

  for (const r of results) {
    // no_submit / 提出物不正の失格者は encryptKey 不明のため判定不能
    const encryptKey = verifiedEncryptKeys[r.uid];
    if (!encryptKey) continue;
    const uid = r.uid;

    // ---- vote: (c) デタラメ発信のみ ----
    {
      const receipted = candsOf(observedVotesOf, uid)
        .filter(({ h, a }) => actionHasMemberReceipt(uid, h, a.timestamp));
      let garbled = false;
      for (const { a } of receipted) {
        try {
          const d = JSON.parse(eciesDecrypt(a.encrypted, encryptKey));
          if (!d.targetUid || !memberUids.includes(d.targetUid) || d.targetUid === uid) { garbled = true; break; }
        } catch {
          garbled = true; break;
        }
      }
      if (garbled) markFraud(uid, 'vote_fraud');
    }

    // ---- report: (a) 対象超過 ＋ (c) デタラメ発信 ----
    // 🔴 J-15（2026-08-08）: ⑥ が見るのは**第1パスの候補集合だけ**（`observedReportsOf`）。
    //    検証⑤の第2パスが拾った控え（`extraReportCandsOf`）は**失格の材料にしない**。
    //    第2パスは「枠を取った標的への有効な密告」を救うだけで、枠も対象数も増やさないので、
    //    そこから新しい不正判定が生まれる余地は無い。逆にここを広げると、
    //    切り詰めで見えていなかった発信が突然 `report_fraud` の根拠になり、
    //    「10件までしか見ない」という CPU 有界性の約束と噛み合わなくなる。
    if (!(findResult(uid)?.fraudReason)) {
      const cands = candsOf(observedReportsOf, uid);

      // (c) は**受領済み発信のみ**で判定する（正典「⑥は void を判定材料にしない」）
      let garbled = false;
      for (const { h, a } of cands) {
        if (!actionHasMemberReceipt(uid, h, a.timestamp)) continue;
        try {
          const d = JSON.parse(eciesDecrypt(a.encrypted, encryptKey));
          if (!d.targetUid || !memberUids.includes(d.targetUid) || d.targetUid === uid) { garbled = true; break; }
        } catch {
          garbled = true; break;
        }
      }

      // 🔴 P-2026-0811 #15（2026-08-05・ユーザー確定 案A）: (a)「対象超過で失格」を**廃止**した。
      //    3人目以降の対象は⑤の枠規則で**単に無効**になるだけ（受領証明時刻順の先頭2対象を採用）。
      //    投票の対象矛盾を失格にしないと決めたのと同じ理由:
      //      ・対象変更を禁じているのはクライアント `ChatPhase.js` のガードだけで **fail-open**。
      //        localStorage が消える／復元クライアント（DO・WS 接続なし）を使うだけで、
      //        悪意ゼロの参加者が3対象ぶんの署名を作れてしまう
      //      ・one-shot の目的（都合の良い2つを選び直せない）は K-S2-006 の枠規則
      //        ＝「void でも distinct 対象枠は解放しない」だけで達成される。
      //        3件目を出しても採用されるのは常に先頭2対象なので、乗り換えの利得はゼロ
      //        🔴 J-19（受容・案D）: ここも「利得ゼロ」は**発信者について**の話。
      //           どの2件が先頭になるかは第三者の受領証明で動きうる（仕様・上の検証④参照）
      //    残る report_fraud は (c) デタラメ発信（受領済みなのに復号不能／対象が無効）のみ。
      if (garbled) { markFraud(uid, 'report_fraud'); }
    }
  }

  // ============================================================
  // ⑦ 全ての失格者を先に判定（ポイント付与の前に確定）
  // ============================================================

  // 有効発言回数（連続発言を除く）を集計（正典messagesから算出）
  // K-S2-003: 可視内容がゼロのメッセージ（不可視文字だけ／空）は発言として数えない。
  // 併せて、不可視メッセージを挟んで他人の「連続発言」を分断し発言回数を
  // 水増しさせる経路も塞がる。
  const messageTurns = countMessageTurns(filterVisibleMessages(canonicalMessages));

  // min_chars / min_messages チェック（どちらも必須ミッション、未達で失格）
  for (const r of results) {
    if (r.isDisqualified) continue;

    if ((effectiveCharCounts[r.uid] || 0) < minChars) {
      r.isDisqualified = true;
      r.disqualifyReason = 'min_chars';
    } else if ((messageTurns[r.uid] || 0) < minMessages) {
      r.isDisqualified = true;
      r.disqualifyReason = 'min_messages';
    }
  }

  // 通報による失格判定
  const reportsByTarget = Object.create(null); // { targetUid: [reporterUid, ...] }

  for (const [reporterUid, reportList] of Object.entries(decryptedReports)) {
    // 🔴 P-2026-0811 #11: 密告が「消える」失格理由の者からの密告は数えない。
    //    ここは⑦の min_chars / min_messages 判定より**後**なので、`reported` 以外の
    //    失格理由はすべて確定している。`reported` は「生きる」側なので、
    //    密告返し（カウンター）の相互成立を妨げない＝循環参照は起きない。
    if (isReportVoidingDq(findResult(reporterUid))) continue;

    for (const report of reportList) {
      if (!report.targetUid) continue;

      if (!reportsByTarget[report.targetUid]) {
        reportsByTarget[report.targetUid] = [];
      }
      if (!reportsByTarget[report.targetUid].includes(reporterUid)) {
        reportsByTarget[report.targetUid].push(reporterUid);
      }
      // 🔴 P-2026-0812 F5: 密告者一覧は uid 昇順に固定する（`Object.entries(decryptedReports)`
      //    の列挙順＝挿入順に依存させない）。`reportThresholdMet` は合計しか見ないので
      //    値は変わらないが、この配列は下流の列挙順に効く。
      reportsByTarget[report.targetUid].sort(compareStrAsc);
    }
  }

  // 🔴 P-2026-0812（2026-08-06）: 集計から外した密告は **結果からも消す**。
  //    ⑤が `reportTargetUids` を書くのは⑥より前なので、⑥で `report_fraud` が付いた人や
  //    「消える」失格理由の人の密告が、数えられていないのに結果に残っていた。
  //    この配列は `games/block{N}/group{g}.json` と `summary.json` に載り、
  //    その sha256 が manifestHash → HashStorage にアンカーされる。第三者が公開データ
  //    だけから密告集計を再構成すると答えが合わなくなる＝検証性が落ちる。
  for (const r of results) {
    if (isReportVoidingDq(r)) {
      r.reportTargetUids = [];
      delete decryptedReports[r.uid];
      canonicalReportActions.delete(r.uid);
    }
  }

  // 密告成立条件（§6.9）: 密告者2人以上 AND 密告者のoriginalDepositPoints合計 > 被密告者のそれ。
  // 注: REPORT_VOIDING_DQ_REASONS に含まれない4理由
  //     （min_chars / min_messages / no_vote / reported）の失格者からの通報は有効。
  // originalDepositPoints（ポイント移動前の値）で判定するため、連鎖・不動点は構造的に発生しない。
  const reportThresholdMet = (targetUid) => {
    const target = findResult(targetUid);
    if (!target) return false;
    const reporterUids = reportsByTarget[targetUid];
    if (!reporterUids || reporterUids.length < 2) return false;
    const reporterPointsSum = reporterUids.reduce((sum, uid) => {
      const r = findResult(uid);
      return sum + (r ? r.originalDepositPoints : 0);
    }, 0);
    return reporterPointsSum > target.originalDepositPoints;
  };

  for (const targetUid of Object.keys(reportsByTarget)) {
    const target = findResult(targetUid);
    if (!target || target.isDisqualified) continue;
    if (!reportThresholdMet(targetUid)) continue;

    // 通報成功: 被通報者失格
    target.isDisqualified = true;
    target.disqualifyReason = 'reported';
  }

  // ============================================================
  // 追加: 失格理由の補足（複数理由の検出）
  // ============================================================
  // K-S2-005 是正（2026-07-28）: `reported` の付与を「他の失格理由に依らず」評価する。
  //
  // 旧実装は、署名/不正提出系（sigReasons）で先に失格した対象を単一理由に固定していたため
  // `reported` が理由配列から落ち、⑧の密告報酬ループ（disqualifyReasons.includes('reported')
  // を要求）が一切支払わなくなっていた。被密告者はどのみち報酬0なので追加の損失が無く、
  // **自分が密告されたと知ってから自爆すれば密告者のご褒美だけを消せる**（自爆攻撃）。
  //
  // 「知ってから」が成立するのは、提出バンドルに encryptKey が平文で入っており、
  // 誰か1人が提出した時点でその人の密告先が全員に読めるため（Evidence 経由なら公開）。
  // 提出期間は長いので、最後まで待って全員の密告先を確認してから自爆できた。
  //
  // ただし「他の理由で失格でも常に再分配する」だけでは逆の問題が生じる:
  // **チャット期間中に失格が見えている相手を全員で密告しておくのが最適解**になり、
  // 「3人で条件を達成してから残り1人を密告し、以後その1人に既読を出さない（＝正典に入らず
  // min_chars 失格）」という結託が儲かる。旧タブー時代に no_taboo 失格者を再分配対象外に
  // した判断（FAIRNESS計画 A1-3）と同じ論点である。
  //
  // そこで失格理由を「密告の締切（チャット期間終了）より前に確定するか・後に確定するか」で分ける:
  //
  //   ① CHAT_PERIOD_DQ_REASONS（再分配なし）
  //      min_chars / min_messages / no_vote / ineligible_deposit
  //      → 自爆に使うには「500字に到達しない」等の**事前コミット**が要り、後から取り消せない。
  //        密告されたと知ってからでは間に合わない＝自爆攻撃として機能しない。
  //        逆に「見えている失格者を密告して稼ぐ」経路はここで塞がる。
  //        また、喋らない Bot は密告が無くても min_chars で自動失格する＝ご褒美は不要。
  //        密告制度が本当に必要なのは「min_chars を満たしてくる喋る Bot」であり、
  //        そこには②側で正しくご褒美が出る。
  //
  //   🔴 J-21（2026-08-08・ユーザー確定）: `ineligible_deposit` を②から①へ移した。
  //      理由: ②の根拠は「**提出バンドルの内容で決まる**＝標的が提出時に自分で発動できる」
  //      だが、デポジット額は**ゲーム開始前に確定するオンチェーンの値**で提出物ではない。
  //      標的が提出時に自分で発動することはできない＝②の根拠が最初から覆っていなかった。
  //      逆に①の根拠（事前コミット済み・後から取り消せない／かつ**見えている**＝
  //      デポジット額は UI でもチェーンでも誰でも見える）にそのまま当てはまる。
  //      放置すると「上限超過の応募を見つけて全員で密告するだけ」で定額が刷れた
  //      （実測・5人組: 50 ETH の標的で密告者1人あたり 176pt、159.5 ETH で 315pt）。
  //      ＝ 分類のミスであり、規則①が塞ぎたかった経路がここから漏れていた。
  //
  //   ② それ以外（再分配あり）
  //      no_submit / vote_undisclosed / invalid_signature / chathash_mismatch /
  //      snapshot_mismatch / vote_fraud / report_fraud
  //      → いずれも**提出バンドルの内容で決まる**＝他人の提出を見てから選べるので、
  //        再分配を消させてはならない。
  //   ⚠️ `no_submit` は①へ動かさない（2026-08-08・ユーザー確定で②に**据え置き**）。
  //      提出しないことは提出期間中に標的が自分で選べる＝②の根拠がそのまま成立する。
  //
  // ⚠️ vote_fraud / report_fraud を②に置くのは必須である。この2つは「チャット期間中の行為」に
  //    見えるが、(b)取下げ判定（受領済み発信を本人提出物に含めない）と (c)garbled（提出時に
  //    食い違う encryptKey を宣言する）という**提出時に自分で発動できる経路**を持つ。
  //    ①に置くと「自分の投票を提出物から省く」だけで本是正が丸ごと迂回される。
  // 🔴 P-2026-0812 以降、**この配列は判定に使われていない**（宣言だけ）。
  //    規則①のゲートは `chatPeriodFailOf`（実際の値から直接判定）へ移した。
  //    ここを残しているのは **SPEC §6.9 の①②分類の記録**としてで、
  //    「①に何が入るか」を読み手が1箇所で確認できるようにするため。
  //    ⚠️ **ゲートの判定に使い直さないこと。** 失格理由の配列は分岐ごとに
  //       集める中身が違うので、それを見ると被密告者が自分の提出物を壊すだけで
  //       ①を迂回できる（実測でグループ合計 390 → 410）。
  //    Rust 側も同じ形（`Reason::is_chat_period` は分類の記録として残し、
  //    ゲートは `chat_period_fail()` が担う）。
  // eslint-disable-next-line no-unused-vars
  const CHAT_PERIOD_DQ_REASONS = ['min_chars', 'min_messages', 'no_vote', 'ineligible_deposit'];
  const SIG_DQ_REASONS = ['invalid_signature', 'chathash_mismatch', 'snapshot_mismatch', 'vote_fraud', 'report_fraud'];

  /// ① チャット期間中に確定する不作為に該当するか（§6.9 の①②分岐）。
  ///
  /// 🔴 P-2026-0812: **失格理由の配列ではなく、実際の値から直接判定する。**
  ///    `disqualifyReasons` は分岐ごとに集める理由が違うので、それを読むと
  ///    「別の失格を上書きさせて①を迂回する」経路ができる（上の実測を参照）。
  /// ⚠️ 投票は `decryptedVotes` ではなく `receiptedVoteActors`（**受領証明つきの
  ///    投票発信を出したか**）で見る。①の趣旨は「チャット期間中の行為」の有無で、
  ///    復号は提出物に依存する後段の話だから。これにより①で先に失格した人
  ///    （④が走らず `decryptedVotes` が空のまま）にも同じ物差しが当たる。
  /// ⚠️ 未提出者の文字数・発言回数を正典 union で評価するのは従来どおり
  ///    （全員未提出なら正典が空＝両方未達。SPEC §6.4 v3.3追補）。
  /// 🔴 J-21（2026-08-08・ユーザー確定）: `ineligibleDeposit` を①に加えた。
  ///    デポジット額はゲーム開始前に確定するオンチェーンの値で、標的が提出時に
  ///    自分で発動できない＝②の根拠（提出バンドルの内容で決まる）が覆っていなかった。
  ///    ⚠️ **`disqualifyReasons` ではなく旗の実値 `r.ineligibleDeposit === true` を読む。**
  ///       理由配列を読むと被密告者が自分の提出物を壊すだけで①を迂回できる
  ///       （上の実測 390 → 410）。旗は採点入力（オンチェーン再検証の結果）から
  ///       直接立つので、標的の提出物では動かせない。
  const chatPeriodFailOf = (r) =>
    r.ineligibleDeposit === true
    || (effectiveCharCounts[r.uid] || 0) < minChars
    || (messageTurns[r.uid] || 0) < minMessages
    || !receiptedVoteActors.has(r.uid);

  for (const r of results) {
    if (!r.isDisqualified) {
      r.disqualifyReasons = [];
      continue;
    }

    // まず `reported` 以外の理由を集める（分岐ごとに従来と同一の規則）
    const reasons = [];

    // 🔴 P-2026-0811 #14: B1 適格デポジット不足（オンチェーン再検証）は**独立の旗**。
    //    以前は `disqualifyReason` の分岐だったため、同じ人が未提出だと `no_submit` に
    //    上書きされて理由ごと消えていた（＝エントリー検査の穴が結果から見えなくなる）。
    //    旗で分岐することで `no_submit` に隠されなくなる。
    //    （単一理由として扱うのは従来どおり。④⑤⑦を最初から飛ばされているので、
    //      併記できる他の理由は「参加しなかった結果」でしかなく実態を表さない）
    if (r.ineligibleDeposit === true) {
      reasons.push('ineligible_deposit');
    } else if (!submissions?.[r.uid]) {
      // 結果未提出: 他の判定可能な失格理由も併記
      reasons.push('no_submit');

      // 投票: 未提出だと encryptKey が公開されないので投票先は永久に復号できない。
      // ただし「投票を発信していた事実」は他メンバーの提出物＋リアルタイム受領証明で確定するので
      // 切り分ける（受領済み発信あり＝vote_undisclosed / 発信の証拠なし＝no_vote）。
      // どちらも投票先が確定しないため投票ボーナスは付かない（＝採点結果は同じ）。
      // K-S2-005: vote_undisclosed は②（提出時の不備）／no_vote は①（チャット期間中の不作為）。
      reasons.push(receiptedVoteActors.has(r.uid) ? 'vote_undisclosed' : 'no_vote');

      // 文字数/会話回数: 正典チャット（全提出物のunion ∧ 受領証明≥1）で判定できる。
      // 他メンバーが提出していれば未提出者の発言も union 経由で正典に入るため、
      // 「未提出だから未達」ではなく実際の正典で評価する（全員未提出なら正典が空＝両方未達）。
      if ((effectiveCharCounts[r.uid] || 0) < minChars) reasons.push('min_chars');
      if ((messageTurns[r.uid] || 0) < minMessages) reasons.push('min_messages');
    } else if (SIG_DQ_REASONS.includes(r.disqualifyReason)) {
      // 署名/不正提出/不正発信関連の失格は（reported を除き）単一理由
      reasons.push(r.disqualifyReason);
    } else {
      // ゲームプレイ関連の失格: 全ての該当理由を収集
      if ((effectiveCharCounts[r.uid] || 0) < minChars) reasons.push('min_chars');
      if ((messageTurns[r.uid] || 0) < minMessages) reasons.push('min_messages');
      if (!decryptedVotes[r.uid]) reasons.push('no_vote');
    }

    // K-S2-005: `reported` は「密告成立条件を満たし、かつ①の理由が1つも無い」場合に付与する。
    // 対象の主失格理由が既に 'reported'（他の理由が無く密告だけで失格）の場合も、
    // reasons は空のままここに来て 'reported' が付く。
    //
    // 🔴 P-2026-0812（2026-08-06）: 判定を **`reasons` から `chatPeriodFailOf` へ移した。**
    //    `reasons` の中身は分岐ごとに違う（SIG 枝は単一理由・ineligible 枝も単一理由）ため、
    //    被密告者が**提出時に自分の chatHash を壊すだけ**で①のゲートを迂回できた。
    //    実測（4人組・p1=100pt/p2=70/p3=50/p4=30・p1+p2 が p4 を密告）:
    //      p4 が min_chars だけ           → p1=100 p2=170 グループ合計 390（規則どおり）
    //      p4 が min_chars + chathash壊し → p1=110 p2=180 グループ合計 410（①が迂回された）
    //    p4 はどのみち0点なので**追加コストがゼロ**＝「身代わりを min_chars で落としつつ
    //    chatHash を壊すだけで共謀密告者に定額を刷れる」＝規則①が防ぎたかった
    //    「見えている失格者を密告するのが常に得」が復活していた。
    //    さらに chatHash / snapshot / vote_fraud は**提出時**に決まるので、
    //    規則①の根拠「事前コミットが要り後から取り消せない」も成立していなかった。
    if (!chatPeriodFailOf(r) && reportThresholdMet(r.uid)) {
      reasons.push('reported');
    }

    r.disqualifyReasons = reasons.length > 0 ? reasons : [r.disqualifyReason];
    r.disqualifyReason = r.disqualifyReasons[0];
  }

  // ============================================================
  // ⑧ ポイント付与（全失格者確定後）
  // ============================================================

  // 通報ポイント付与（v3.2 決定⑩: 定額按分）
  //   各密告者は floor(失格者のoriginalDepositPoints / (グループ人数−1)) を受け取る。
  //   密告者数に依らず1人当たり定額（3人以上でも変わらない）。密告者が n−1 人未満なら
  //   残余は誰にも配られず消滅。投票ボーナスの期待値（n人グループで約1/(n−1)）と釣り合わせ、
  //   「投票されなさそうな相手は密告した方が得」→全員に投票される振る舞いのインセンティブを作る。
  //   REPORT_VOIDING_DQ_REASONS に含まれない4理由（min_chars / min_messages / no_vote / reported）の
  //   失格者もポイントをもらえ、その失格者からの通報も有効（現行踏襲・按分式のみ変更）。
  // 🔴 P-2026-0812 F5: `Object.entries` の列挙順に依存しない。
  //    JS が「数字に見えるキー」を数値昇順に並べるのは **2³²−1 以下**のときだけで、
  //    本番の uid（X の snowflake・19桁）は上限を超えるため**挿入順**になる。
  //    挿入順は提出物の走査順に依存する＝名簿の並びで変わっていた。
  //    ポイント計算自体は加算なので順序で値は変わらないが、`votedByUids` の
  //    **配列の並び**は `games/block{N}/group{g}.json` に載り、その sha256 が
  //    manifestHash → HashStorage としてオンチェーンに焼かれる。
  const reportsByTargetSorted = Object.entries(reportsByTarget)
    .map(([t, us]) => [t, [...us].sort(compareStrAsc)])
    .sort((a, b) => compareStrAsc(a[0], b[0]));
  for (const [targetUid, reporterUids] of reportsByTargetSorted) {
    const target = findResult(targetUid);
    // 通報成功（失格になった）対象のみポイント分配。
    // K-S2-005: `reported` の付与規則は上の補足ループが一元管理する（①なら付かない・
    // ②なら他の失格理由と重なっても付く）。ここは判定を持たず、その結果に従うだけ。
    if (!target || !target.disqualifyReasons?.includes('reported')) continue;

    // 🔴 決定②-3（2026-08-08・ユーザー確定・台帳「判断②」）: **分子を適格帯の上限でクランプする。**
    //    標的の持ち点が適格帯（0.01〜10 ETH）を外れていると分子が 316 を超え、
    //    「10 ETH 上限」が保証するはずの値を報酬経路が踏み越えていた
    //    （実測: 159.5 ETH の標的を4人で密告 → 密告者の持ち点 316 → 631）。
    //    本番経路は `ineligible_deposit` を規則①側へ移した是正で既に塞がっているが、
    //    **権威デポジット表が渡されない経路**（表が丸ごと無い＝テストと一部ツール・
    //    上の `if (hasVerified)` 参照）には B1 が一切かからないので、ここで保険をかける。
    //    適格な標的の持ち点は必ず 316 以下なので、正常系ではクランプは恒等変換
    //    （＝過剰遮断ゼロ。`report-vote-equilibrium-test.mjs` §6/§7 が実測で固定する）。
    const forfeitedPoints = Math.min(target.originalDepositPoints, MAX_ELIGIBLE_DEPOSIT_POINTS);
    const sharePerReporter = reportSharePerReporter(forfeitedPoints, groupSize);

    for (const reporterUid of reporterUids) {
      const reporter = findResult(reporterUid);
      if (reporter) {
        reporter.depositPoints += sharePerReporter;
        reporter.reportGainPoints += sharePerReporter;
      }
    }
  }

  // 投票ボーナス（失格者ももらえるが、失格者からの投票は無効）
  // 🔴 P-2026-0812 F5: 同上。`votedByUids` の並びがオンチェーンに焼かれるので、
  //    投票者 uid の昇順で走査して配列順を固定する。
  const votesSorted = Object.entries(decryptedVotes).sort((a, b) => compareStrAsc(a[0], b[0]));
  for (const [voterUid, vote] of votesSorted) {
    if (!vote?.targetUid) continue;
    const votedForUid = vote.targetUid;

    // 自己投票は無視
    if (voterUid === votedForUid) continue;

    const voter = findResult(voterUid);
    const votedFor = findResult(votedForUid);
    if (!voter || !votedFor) continue;

    // 失格者からの投票は無効（被投票者は失格でもボーナスをもらえる）
    if (voter.isDisqualified) continue;

    // ボーナス = 投票者のoriginalDepositPoints
    votedFor.bonusPoints += voter.originalDepositPoints;
    votedFor.votedByUids.push(voterUid);
  }

  // ============================================================
  // 最終ポイント集計
  // （失格者はポイントをもらっていても合計0、報酬分配から除外）
  // ============================================================
  for (const r of results) {
    if (r.isDisqualified) {
      r.totalPoints = 0;
    } else {
      r.totalPoints = r.depositPoints + r.bonusPoints;
    }
  }

  // ============================================================
  // 結果表示用の正典タイムライン
  // ============================================================
  // 生の ChatGameDO 保存値を画面側で再フィルタすると、提出物 union・署名検証・受領証明の
  // 採否・チャット量キャップ・密告資格／枠／失格による無効化を再現できない。
  // そこで、採点で実際に確定した canonicalMessages と採用済みアクションから、公開用の
  // 最小投影をここで一度だけ作る。暗号文や秘密鍵は含めず、投票／密告は復号済み標的を含む。
  const canonicalTimeline = [];
  for (const msg of canonicalMessages) {
    canonicalTimeline.push({
      kind: 'chat',
      uid: msg.uid,
      text: msg.text,
      timestamp: msg.timestamp,
      msgKey: getMsgKey(msg),
    });
  }
  for (const action of canonicalVoteActions.values()) {
    canonicalTimeline.push({
      kind: 'vote',
      actorUid: action.actorUid,
      targetUid: action.targetUid,
      timestamp: action.timestamp,
      actionHash: action.actionHash,
    });
  }
  for (const actions of canonicalReportActions.values()) {
    actions.forEach((action, index) => {
      canonicalTimeline.push({
        kind: 'report',
        actorUid: action.actorUid,
        targetUid: action.targetUid,
        nth: index + 1,
        timestamp: action.timestamp,
        actionHash: action.actionHash,
      });
    });
  }

  // 異種イベントが同一 timestamp の場合も公開バイト列が一意になるよう、全 tie-break を明示する。
  const kindRank = { chat: 0, vote: 1, report: 2 };
  canonicalTimeline.sort((a, b) => {
    if (a.timestamp !== b.timestamp) return a.timestamp < b.timestamp ? -1 : 1;
    const kr = kindRank[a.kind] - kindRank[b.kind];
    if (kr !== 0) return kr;
    const actorCmp = compareStrAsc(a.uid || a.actorUid, b.uid || b.actorUid);
    if (actorCmp !== 0) return actorCmp;
    const targetCmp = compareStrAsc(a.targetUid || '', b.targetUid || '');
    if (targetCmp !== 0) return targetCmp;
    return compareStrAsc(a.msgKey || a.actionHash, b.msgKey || b.actionHash);
  });

  restoreRosterOrder(results);

  return { results, decryptedVotes, decryptedReports, canonicalTimeline };
}
