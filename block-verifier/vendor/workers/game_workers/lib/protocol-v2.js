// workers/game_workers/lib/protocol-v2.js
// P2P冗長チャネル プロトコルv2 の共有プリミティブ（docs/P2P_REDUNDANT_CHANNEL_PLAN.md §2/§5/§7）。
//
// ⚠️ このファイルは フロントエンド（src/）・ChatGameDO・GameMasterDO・calculator・
// evidence-reconciler・検証ツール の全実装から共有される「バイト厳密一致」の単一実装。
// シリアライズ（キー順・数値正規化・NFC）を変えるとchatHash/署名検証が全実装で分裂する。
// 規則変更時は RECEIPT_ACCEPTANCE_RULE_VERSION と連動 pin を更新する。
//
// 正規シリアライズ規約（EVIDENCE_CENSORSHIP_PLAN §4.3 を継承）:
//   - JSON.stringify のキー順はオブジェクトリテラルの記述順で固定
//   - 数値は 2^53 未満の整数のみ（blockNum, groupId, timestamp）。それ以外は文字列
//   - text は署名前・msgKey計算前に必ず NFC 正規化（C3）
//   - blockNum / groupId は Number に正規化（クエリ文字列由来の "5" と 5 の分裂を防ぐ）

import { keccak256, toBytes } from 'viem';
import { applyChatCaps, capMessagesByFirstReceipt, capMessagesForScoring, countMessageTurns, countVisibleChars, filterVisibleMessages,
  countHalfWidthChars, hasVisibleContent, normalizeChatCaps, GUEST_PINNED_RULES } from './char-counter.js';

// ============================================================
// バージョンゲート（§7）
// ============================================================

// P2P_PROTOCOL_FROM_BLOCK 環境変数のパース。
// ⚠️ 版数ゲートは廃止（2026-07-07・ユーザー確定）: 本プロジェクトは未リリースで v1 ブロックは
// 存在しない前提。v2 はブロック0から常時有効。採点はプレイヤー提出物＋オンチェーンのみから行い、
// サーバー保存データは採点に一切使わない（本体未提出＝失格）。P2P_PROTOCOL_FROM_BLOCK 廃止・
// calculator/reconciler の v1 分岐とサーバーフォールバックは削除済み。

// ============================================================
// テキストは正規化しない（NFC 廃止・2026-08-04・ユーザー確定）
// ============================================================
//
// 🔴 **ここに正規化を戻さないこと。** チャット本文は署名対象文字列にそのまま入る
//    **不透明なバイト列**として扱う。
//
// 廃止の理由:
//  ・`String.prototype.normalize('NFC')` の結果は**ランタイムが積んでいる ICU の
//    Unicode データ版数**で決まる。言語仕様ではなくデータテーブルなので、
//    ブラウザ/Node の版が違えば新しく割り当てられた文字で結果が食い違いうる。
//    つまり **JS 正典の側がそもそも完全には決定的でない**。
//  ・ZKP のゲスト（Rust）はこれを再現できなければならず、ズレたときの症状が最悪
//    ——「証明は通るが正典と違う答え」＝ ZKP が誤った計算にお墨付きを与える。
//  ・`char-counter.js` の不可視文字対策が `\p{...}` を避けて**明示的なコードポイント表**を
//    採用したのと同じ理由（同ファイル冒頭の「決定論性」の項）。NFC はその方針から
//    取り残された最後の1箇所だった。
//
// 廃止で失うものが無いことの確認（2026-08-04）:
//  ・**不可視文字での文字数・発言数の水増し**は `char-counter.js` の `INVISIBLE_RANGES` が
//    防いでいる（K-S2-003）。NFC は不可視文字を1文字も削除しないので**無関係**。
//  ・**タブーの includes 回避**は制度ごと廃止済み（2026-07-23）＝対象が存在しない。
//  ・**msgKey の分裂**は、送信側が WS と Nostr の両方へ同一の文字列を流すので起きない。
//
// 残る差: NFC 形と NFD 形は別メッセージになる。ただし "hello" と "hello " でも同じことが
// でき元から防げていないため、上限（100メッセージ / 10,000字）が実質的な歯止め。

// ============================================================
// 署名ペイロード正準形（§2.6・C6: type/blockNum/groupId束縛）
// ============================================================

// chat（v2）: msgKey の入力もこの文字列そのもの（§2.1）
//
// 🔴 J-17（2026-08-08・ユーザー確定）: **`text` の欠落・`null` は `''` に読み替える。**
//
// `JSON.stringify` は値が `undefined` のキーを**キーごと落とす**ので、
// 正規化前は次の2つが別の文字列＝別の msgKey になっていた:
//   text 欠落 … `{"type":"chat",...,"uid":"…","timestamp":…}`     （text キーが無い）
//   text: ''  … `{"type":"chat",...,"uid":"…","text":"","timestamp":…}`
//
// 一方、採点本体（`game-result-calculator.js` 検証②(b)）は候補を
// `text: raw.text ?? ''` に正規化してから msgKey を作る。つまり**同じ発言が2つの識別子を持ち**、
// 「chatHash の原像」と「採点の原像」が割れていた（[[J-17]]）。
//
// 🔴 ZKP ゲスト（Rust）は `MessageIn::text: Vec<u16>` ＝**空ベクタしか表現できない**ので、
//    `scoring_core::sig::chat_sign_string` は必ず `"text":""` を書く。
//    つまり幽霊メッセージ入りの提出物は **JS=受理 / Rust=`chathash_mismatch`（実測 全員 0/0/0）**
//    に割れていた。ここを揃えることで、Rust 側を1バイトも変えずに（＝**vkey 不変**で）一致する。
//
// ⚠️ 正常な発言（文字列）に対しては `text ?? ''` は恒等なので、**既存の署名は1つも変わらない**。
//    値が変わるのは「正規クライアントが決して作らない」欠落・`null` の場合だけ。
export function chatSignStringV2(blockNum, groupId, uid, text, timestamp) {
  return JSON.stringify({
    type: 'chat',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    text: text ?? '',
    timestamp
  });
}

// vote / report（v2）。v3.2: 署名鍵は signKey（永遠に非公開）— 提出後の偽造・冤罪を構造的に排除。
export function actionSignStringV2(type, blockNum, groupId, uid, encrypted, timestamp) {
  return JSON.stringify({
    type,
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    encrypted,
    timestamp
  });
}

// 署名済みアクションの同一性キー（受領証明の参照先）: actionHash = keccak256(署名対象文字列)
export function actionHashV2(type, blockNum, groupId, uid, encrypted, timestamp) {
  return keccak256(toBytes(actionSignStringV2(type, blockNum, groupId, uid, encrypted, timestamp)));
}

// ============================================================
// 署名の形式検査（A-1 / A-2・2026-08-05）
// ============================================================
//
// 🔴 **署名は必ず `0x` + 130桁hex の文字列**。ここを緩めると2つの穴が同時に開く。
//
// **A-1: `sigCache` のキー衝突で署名検証が素通りする**
//   viem の `recoverPublicKey` は文字列判定より**先に**
//   `typeof signature === 'object' && 'r' in signature` を見るので、
//   `{"r":"0x…","s":"0x…","v":27}` を有効な署名として受理する。
//   一方 `game-result-calculator.js` の受領証明ループはキャッシュキーを
//   テンプレート文字列で作っていたため、**全オブジェクトが `"[object Object]"` に潰れた**。
//   さらに重複排除の `seenSig`（Set）はオブジェクトを参照比較するので効かない。
//   結果、本物のオブジェクト署名を1枚通したあとは
//   **任意の偽受領証明が署名検証されずに採用された**（実測で再現）。
//   偽の既読受領証明が通る＝**バックデートした発言を正典に載せられる**＝
//   受領証明制度が防いでいるはずの挟み込みチートがそのまま成立していた。
//
// **A-2: 奇数長hexを viem が「65バイト」と数える**
//   viem の `size(hex)` は `Math.ceil((length - 2) / 2)` なので `0x` + **129桁**でも 65。
//   `substring(2,130)` が r||s、残りの**1桁**が recovery bit になる。
//   つまり `…891b` の末尾を `…890` にしても検証が通る＝
//   **同一の発信に対しバイト列の違う有効署名が作れる**。
//   `seenSig` による重複排除をすり抜けて枠を食い潰せる。
//
// ⚠️ 正規クライアント（viem の `signMessage`）は常にこの形式を返すので、
//    正直な参加者への影響はゼロ。
export function canonicalizeSignature(v) {
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(v)) return v;
  try {
    const lower = v.toLowerCase();
    const r = lower.slice(2, 66);
    let s = BigInt(`0x${lower.slice(66, 130)}`);
    const rawV = Number.parseInt(lower.slice(130), 16);
    let recovery = rawV === 0 || rawV === 1 ? rawV + 27 : rawV;
    if (s > SECP256K1_HALF_N) {
      s = SECP256K1_N - s;
      recovery = recovery === 27 ? 28 : 27;
    }
    if (recovery !== 27 && recovery !== 28) return v;
    return `0x${r}${s.toString(16).padStart(64, '0')}${recovery.toString(16)}`;
  } catch {
    return v;
  }
}

export function isCanonicalSignature(v) {
  // 🔴 P-2026-0812（2026-08-06）: **low-s に限る。**
  //    secp256k1 は (r, s) と (r, n−s) の両方が同じ鍵・同じ内容で有効になる。
  //    viem の `verifyMessage` は high-s の「双子」も受理する（実測）。
  //    `actionHashV2` は署名を含まないので双子は**同じ actionHash** になり、
  //    件数上限の予算だけを消費して本物を押し出せた（実測 250点 → 0点の no_vote 失格）。
  //    `isLowSSignature` は元から定義されていたのに**採点経路から一度も呼ばれていなかった**。
  //    ⚠️ viem / ethers / MetaMask の `personal_sign` はいずれも low-s しか出さないので、
  //       正規クライアントの署名が弾かれることはない。
  if (typeof v !== 'string' || !/^0x[0-9a-f]{128}(?:1b|1c)$/.test(v)) return false;
  return isLowSSignature(v);
}

/// **表現可能性だけ**の署名検査（low-s を課さない）。
///
/// 🔴 用途は **提出物の外側ウォレット署名** 1箇所だけ。他の署名は必ず
///    `isCanonicalSignature`（＝これ ＋ low-s）を使うこと。
///
/// なぜ分けるのか（P-2026-0832・2026-08-08）:
///   外側署名には元から正準形の検査が無く、**オブジェクト `{r,s,v}` 形式や
///   high-s の双子が満点で通っていた**（実測。系内の他の署名は全部
///   `isCanonicalSignature` を通っているのに、ここだけ取り残されていた）。
///
///   このうち **非文字列・奇数長の排除は今すぐ入れるべき**もので、Rust 側の変更も要らない。
///   ゲストは `SubmissionIn.sig: [u8; 65]` で、ホストの `sig65()` は `as_str()` なので
///   **非文字列署名を正典が受理すると、プルーバが panic してそのブロックの証明が永久に作れない**。
///
///   🔴 J-16（2026-08-08・ユーザー確定）の恒久原則は、署名の出どころで規則を分けること:
///   **制御できるものには厳格に、制御できないものには寛容に**。
///   blockAddress/signKey 系は系内で生成を制御できるので `isCanonicalSignature`
///   （v=27/28＋low-s）だけを受ける。外側 wallet 署名は利用者の wallet 実装に依存するので、
///   `isRepresentableSignature`（v=27/28、high-s も可）を受ける。
///   ⚠️ この2述語は**一本化しない**。外側へ low-s を足しても、内部から low-s を外してもならない。
export function isRepresentableSignature(v) {
  return typeof v === 'string' && /^0x[0-9a-f]{128}(?:1b|1c)$/.test(v);
}

// ============================================================
// 正準な型の検査（P-2026-0806・2026-08-05）
// ============================================================
//
// 🔴 **正典が型を検査していないと、ZKP のゲストが再現できない。**
//
// `JSON.stringify` はどんな型でもそれらしく書くので、`timestamp` が小数でも
// `text` が `0` でも署名検証は通ってしまう。一方ゲスト（Rust）は
// `timestamp: i64` / `text: Vec<u16>` / `uid: String` なので**表現できない**。
//
// ゲスト側だけ厳しくすると「JS が採用した発信をゲストが落とす」＝
// 正典メッセージ集合が変わり、**root が summary.json と一致しなくなる**
// （＝そのブロックの配布が止まる）。だから**正典を締めるしかない**。
//
// 詳細と発見の経緯: `docs/external-audit/STAGE3C_CANON_TIGHTENING.md` §B
//
// ⚠️ **必要最小限に留める**こと。過剰に締めると正直な参加者を弾く。
//    ここで禁じているのは「Rust が表現できない値」だけで、
//    正規クライアント（viem / 通常の JSON）が作る値はすべて通る。

/// 孤立サロゲート（対にならない U+D800〜U+DFFF）を含むか。
///
/// 🔴 Rust の `String` は孤立サロゲートを保持できない。`text` だけは
///    `Vec<u16>` で忠実に扱うので許容するが、**それ以外の文字列フィールドでは禁じる**。
///    （`encryptKey` / `chatHash` / `encryptedDataHash` / `encrypted` は
///     本番では hex か base64 なので実害なく締められる）
export function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const lo = s.charCodeAt(i + 1);
      if (!(lo >= 0xdc00 && lo <= 0xdfff)) return true;
      i++;                       // 正しい対は読み飛ばす
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;               // 対にならない下位サロゲート
    }
  }
  return false;
}

/// タイムスタンプ。**安全整数のみ**（小数・NaN・Infinity・文字列・2^53 超を排除）。
/// ⚠️ 正典は `blockNum`/`groupId` だけ `Number()` を通し、timestamp は素通しだった。
///    小数 timestamp は `isReceiptTimely` も `inChatWindow` も通り抜ける。
export function isCanonicalTimestamp(v) {
  return Number.isSafeInteger(v);
}

/// チャット本文。**文字列であること**だけを要求する。
/// 🔴 孤立サロゲートは**許容する**（`text.rs` が `Vec<u16>` で忠実に扱う設計）。
///    `0` / `false` / 数値は排除する（JS は引用符なしで書くのでゲストが再現できない）。
export function isCanonicalText(v) {
  return typeof v === 'string';
}

/// uid。**文字列で、空でなく、孤立サロゲートを含まないこと**。
/// ⚠️ 数字だけに限定しない —— X の snowflake は数字だが、
///    将来の匿名エントリー（デポジット元アドレス）は `0x…` になりうる
///    （`EVIDENCE_CENSORSHIP_PLAN.md` §8b-2 ④）。過剰に締めない。
export function isCanonicalUid(v) {
  // 🔴 P-2026-0812 F5（2026-08-06）: **ASCII 印字可能文字に限る。**
  //    uid は `canonicalComparatorV2`（チャット正典の並び）と `compareStrAsc`
  //    （密告者一覧・votedByUids・results の並び）のソートキーになる。
  //    JS は **UTF-16 コード単位**、Rust は **UTF-8 バイト**で比較するので、
  //    非 ASCII が混ざると順序が逆転する。実測:
  //      uid A="\u{10000}" / B="\u{FFFD}"（同 timestamp）で
  //      JS は A,B・Rust は B,A → **chatHash が別値**になり ZKP が通らない
  //      （0x223184d7… vs 0xbba420ea…・196ペア中14ペアで反転）。
  //    本番の uid は X の数値 ID（`[0-9]{1,20}`）で、請求葉の鍵は
  //    `claim-data-codec.js` の `playerLeafKey` が既に `[0-9]{1,20}` を強制している。
  //    ここを数字だけに締めないのは、将来の匿名エントリーで別の ID 体系を
  //    使えるようにするため（ASCII なら順序は両実装で一致する）。
  return typeof v === 'string' && v.length > 0 && /^[\x21-\x7E]+$/.test(v);
}

/// 不透明な文字列フィールド（`encryptKey` / `chatHash` / `encryptedDataHash` / `encrypted`）。
/// 中身は解釈しないが、**Rust の `&str` で運べる**ことは要求する。
export function isOpaqueField(v) {
  return typeof v === 'string' && !hasLoneSurrogate(v);
}

// ============================================================
// 投票・密告の暗号文は**固定長**（P-2026-0842・2026-08-08・ユーザー確定）
// ============================================================
//
// 🔴 **暗号文の長さが対象 uid の桁数を漏らしていた。**
//
// `encryptAction`（`src/utils/ecies.js`）は `JSON.stringify(data)` をそのまま ECIES に
// かけていた。ECIES の封筒は固定長（下の `ECIES_ENVELOPE_BYTES`）で AES-GCM は
// ストリーム暗号なので、**暗号文の長さ ＝ 封筒 ＋ 平文の長さ**。平文は
//   投票 `{"targetUid":"<uid>"}` ／ 密告 `{"targetUid":"<uid>","reason":"suspected_bot"}`
// なので、実測（ランダム鍵50本 × 10種の桁数・**揺れゼロ＝鍵非依存**）:
//
//   投票の暗号文 hex 長 = 226 + 2 × len(uid)
//   密告の暗号文 hex 長 = 276 + 2 × len(uid)
//
// 長さ → 桁数は**単射**で、投票と密告の長さ域も重ならない。
// X の数値 ID は登録時期で桁数が分かれる（8〜10 / 18 / 19桁）ため、
// **暗号を1ビットも解かずに票の行き先が絞れる**。
//
// しかも露出は招待制ではない。この暗号文は
//   ① `action_made` でグループ全員へブロードキャストされ、
//   ② `publishLiveSnapshot` が `live/block{N}/group{g}.json` として**無認証で R2 に公開**する
//      （照合用の uid 一覧が**同じ JSON に載っている**）
// ＝ 受動観測だけで成立する。
//
// ⚠️ `docs/P2P_REDUNDANT_CHANNEL_PLAN.md` §5 には「サイズパディングは不要」という
//    明示の決定があったが、その根拠は「ブロードキャストは対象を伏せ**件数のみ**」だった。
//    v3.2 で `action_made` が**署名済み発信本体（＝暗号文）**を配るようになり前提が失効している。
//    同ドキュメントの当該ブロックは失効として訂正済み。
//
// # 直し方
//
// 平文を **`ACTION_PLAINTEXT_BYTES` バイト固定**にパディングする（`padActionPlaintext`）。
// パディングは**正典フォーマットを1バイトも変えない**: 3実装（JS 採点 / Rust ゲスト /
// 復元クライアント）はいずれも余剰フィールドを無視して `targetUid` だけを読む
// （Rust には `crates/scoring-core/src/actions.rs` に明示テストがある）。
// 署名・`actionHash` は `encrypted`（＝暗号文）に対して取るのでプロトコルも不変。
//
// 🔴 **任意にはできない。** パディングしないクライアントが1人でも混じれば
//    その人の票は漏れ続ける。よって**採点正典が長さを強制する**
//    （`isCanonicalActionCiphertext`）＝これは規則変更であり、
//    `RECEIPT_ACCEPTANCE_RULE_VERSION` を上げてある（v7）。

/// ECIES（eciesjs 0.4.17・非圧縮エフェメラル鍵 ＋ AES-256-GCM）の封筒バイト数。
/// 65（エフェメラル公開鍵）＋ 16（nonce）＋ 16（GCM タグ）＝ 97。
/// ⚠️ ここは**依存ライブラリの構成**で決まる値なので、`eciesjs` の設定
///    （圧縮鍵 / ChaCha20-Poly1305）を変えると動く。`test-calculator` の
///    `action-padding-unit.mjs` が実測で固定している。
export const ECIES_ENVELOPE_BYTES = 97;

/// 投票・密告の平文（パディング後）のバイト数。**この値ひとつが暗号文長を決める**。
///
/// # 128 を選んだ根拠
///
/// パディング後の平文は `{"targetUid":"<uid>","reason":"suspected_bot","p":"0…0"}` の形。
/// uid 以外の骨格は密告で 48 バイト（投票は 23 バイト）なので、
/// **収容できる uid の長さ ＝ 128 − 48 ＝ 80 文字**（投票だけなら 105 文字）。実測済み。
///
/// | 想定される uid | 長さ | 128 で収まるか |
/// |---|---|---|
/// | X の数値 ID（snowflake・現行） | ≤ 20 | ✅ 余裕 60 |
/// | 将来の匿名エントリー＝デポジット元アドレス `0x…`（`EVIDENCE_CENSORSHIP_PLAN.md` §8b-2 ④） | 42 | ✅ 余裕 38 |
/// | `0x` ＋ 32バイトハッシュ | 66 | ✅ 余裕 14 |
/// | UUID / base58 公開鍵 / bech32 アドレス | 36 / 44 / 62 | ✅ |
///
/// `isCanonicalUid` は `/^[\x21-\x7E]+$/` で長さ無制限だが、
/// **正典が意味を持つ ID 体系はすべて 80 文字に収まる**。
/// 逆に大きくしすぎると Evidence（gzip 後 128KB＝geth の tx 伝播上限）の予算を食う。
/// 実効コストは 1発信あたり hex で +184〜204 文字。5人組の正規バンドルは
/// 発信15本ぶんなので生で約 +3KB、gzip 後で約 +1.5KB（現行 95KB / 上限 128KB）。
export const ACTION_PLAINTEXT_BYTES = 128;

/// 正準な投票・密告暗号文の hex 長。`encryptAction` の出力はこの長さ**ちょうど**になる。
export const ACTION_CIPHERTEXT_HEX_LEN = 2 * (ECIES_ENVELOPE_BYTES + ACTION_PLAINTEXT_BYTES);

/// パディングに使う JSON キー（1文字＝骨格を最小にするため）と詰め物の文字。
/// 詰め物は ASCII なので「文字数 ＝ バイト数」。
const ACTION_PAD_KEY = 'p';
const ACTION_PAD_CHAR = '0';

/// 正準 JSON（`JSON.stringify(オブジェクト)` の出力）を
/// **`ACTION_PLAINTEXT_BYTES` バイトちょうど**に伸ばす。
///
/// 余剰フィールドを1本足すだけで、既存の読み取り側（`JSON.parse(...).targetUid`）は
/// 1バイトも変えずに済む。
///
/// 🔴 収まらなければ**投げる**（黙って短いまま暗号化しない）。
///    短い暗号文は `isCanonicalActionCiphertext` が落とすので、
///    黙って通すと「送信は成功したのに採点で消える」遅延失敗になる。
/// @param {string} json         `JSON.stringify(オブジェクト)` の出力
/// @param {number} targetBytes  仕上がりのバイト数。**既定以外を渡してよいのはテスト用の
///   フィクスチャ生成だけ**（BOM 3バイトを前置するぶんを引く、など）。
///   正典の経路（`encryptAction`）は必ず既定値を使う。
export function padActionPlaintext(json, targetBytes = ACTION_PLAINTEXT_BYTES) {
  if (typeof json !== 'string' || json.length < 2 || json[0] !== '{' || json[json.length - 1] !== '}') {
    throw new Error('[protocol-v2] padActionPlaintext: input must be a JSON object literal');
  }
  const byteLen = (s) => new TextEncoder().encode(s).length;
  const sep = json === '{}' ? '' : ',';
  const head = `${json.slice(0, -1)}${sep}"${ACTION_PAD_KEY}":"`;
  const padLen = targetBytes - byteLen(head) - 2;   // 末尾の `"` と `}`
  if (padLen < 0) {
    throw new Error(`[protocol-v2] padActionPlaintext: payload exceeds ${targetBytes} bytes`);
  }
  return `${head}${ACTION_PAD_CHAR.repeat(padLen)}"}`;
}

/// 投票・密告の `encrypted`。**長さが正準値ちょうどの hex 文字列**であること。
///
/// 🔴 これは「衛生」ではなく**規則**である。緩めると長さチャネルが復活し、
///    パディングしない改造クライアント1人ぶんだけ票の行き先が公開される。
///
/// ⚠️ hex 文字種まで見るのは2つの理由から:
///    ① 正規の生成側（`ecies.js` の `bytesToHex`）は必ず hex を返すので**過剰遮断ゼロ**
///    ② hex ＝ ASCII なので **JS の `.length`（UTF-16 コード単位）と
///       Rust の `.len()`（UTF-8 バイト）が必ず一致する**。
///       文字種を見ないと Rust 側で UTF-16 の数え直しが要り、そこが割れる余地になる。
/// 表現の一意性も署名対象の一部なので、小文字hexだけを正式形とする。
export function isCanonicalActionCiphertext(v) {
  return typeof v === 'string'
    && v.length === ACTION_CIPHERTEXT_HEX_LEN
    && /^[0-9a-f]+$/.test(v);
}

/// `depositIds`。`null` か、**10進文字列**の配列。
/// 🔴 本番の実体は `canonicalizeDepositId`（`entry_workers/lib/deposit-id.js:36`）が
///    返す `BigInt(x).toString(10)` ＝**文字列**。uint256 は78桁まであり得るので
///    数値では表現しきれない。
export function isCanonicalDepositIds(v) {
  if (v === null || v === undefined) return true;
  return Array.isArray(v) && v.every((x) => typeof x === 'string' && /^[0-9]{1,78}$/.test(x));
}

/// 署名文脈の整数（`meta.blockNum` / `meta.groupId`）を **fail-closed** で検査し、
/// `Number` へ正規化する。
///
/// 🔴 P-2026-0820（2026-08-07・C-4）: `chatSignStringV2` / `actionSignStringV2` /
///    `receiptSignString` / `readReceiptSignString` はいずれも内部で `Number(blockNum)` を
///    通すので、JS は暗黙変換を素通しし `'0x5'` / `' 5 '` / `[5]` / `'9007199254740993'` が
///    正常値と**同じ点数**で通っていた。Rust（ZKP ゲスト）の `push_i64` は受け取った値を
///    そのまま10進で書くので署名対象文字列が割れる ＝ 同一入力から2つの正典メッセージ集合。
///
/// 🔴 P-2026-0829（2026-08-07）: **この門番は採点本体にしかなかった。**
///    `ChatGameDO.handleInit` は `meta` を無検証で `storage.put` していたので、
///    `groupId: '0x5'` / `blockNum: true` などが HTTP 200 で**保存され**、
///    48時間後の採点で初めて throw していた（＝「遅延 fail-closed」）。
///    保存済み入力は不変なのでリトライも効かず、修復の窓（`extendGrace`）も
///    閉じたあとで park する。**入口（`handleInit`）でも同じ規則を課すこと。**
///    ⚠️ 検査は Rust ゲスト（`crates/group-guest/src/witness.rs`）にも同型で在る。
///       ここを緩めると3実装が割れる。
///
/// @param {*} v      検査対象
/// @param {string} label  エラーメッセージ中のフィールド名（`blockNum` / `groupId`）
/// @param {string} prefix エラーメッセージの発生源タグ（既定は採点本体の `[calc]`）
export function canonMetaInt(v, label, prefix = '[calc]') {
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${prefix} invalid meta.${label}: not a safe non-negative integer`);
    return v;
  }
  if (typeof v === 'string' && /^[0-9]+$/.test(v)) {
    const n = Number(v);
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${prefix} invalid meta.${label}: not a safe non-negative integer`);
    return n;
  }
  throw new Error(`${prefix} invalid meta.${label}: must be a non-negative integer (number or decimal string)`);
}

/// 登録 blockAddress を安全に取り出す。壊れていれば `null`（**例外を外へ出さない**）。
///
/// 🔴 P-2026-0819（2026-08-07）: `bAddr` の `JSON.parse` が**3箇所**にあり、
///    ガードされていたのは1箇所（`bAddrOf`）だけだった。実測:
///      member.bAddr = 'not-json' → SyntaxError が `calculateGroupResults` の外へ
///      member.bAddr = '{'        → 同上
///    名簿は ChatGameDO の応答＝運営が掌握しているので、1文字入れるだけで
///    **入力が同じ＝リトライも同じ壁 ＝ 決定論的に park**（ブロック全体が止まる）。
///    P-2026-0811 #4/#5・K-S2-004 と同型（「型検査を通す前に例外が飛ぶ」）。
///    ⚠️ `'[]'` / `'123'` は例外にならず `bAddr.address` が undefined になるだけなので、
///       その1人が静かに全損する。`address` が文字列であることまで見る。
///
/// 🔴 P-2026-0829（2026-08-07）: **この門番も採点本体にしかなかった。**
///    `ChatGameDO` は5箇所で生の `JSON.parse(member.bAddr)` を書いていたため、
///    壊れた `bAddr` が当時の chat / receipt / sendkey / vote / report のハンドラを
///    `Internal error` で落としていた。さらに `handleInit` の roster 公開は
///    map 全体が1つの try だったので、**1人壊れるとグループ全員の
///    `roster/group{X}.json` が publish されない**（＝P2P ブートストラップが無言で消える）。
export function parseBlockAddress(raw) {
  if (!raw) return null;
  let v = raw;
  if (typeof raw === 'string') {
    try { v = JSON.parse(raw); } catch { return null; }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  if (typeof v.address !== 'string' || v.address.length === 0) return null;
  return v;
}

// 形式検査（K-S6-002・2026-07-29）。actionHash は必ず keccak256 の出力＝0x + 64桁の小文字hex。
// 旧実装は `typeof rc.actionHash === 'string'` しか見ておらず、**任意長の文字列**を受理していた
// （4,096文字の乱数を200枚流すだけで他メンバーの提出物が1MBを超え、WS提出もオンチェーン提出も
// 同時に不能になった）。isMsgRef と同じ役割の門番。
export function isActionHash(v) {
  return typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v);
}

// ============================================================
// 🔴 検証②.6 の**原像の制限文法**（J-12 案A3・2026-08-08 ユーザー確定）
// ============================================================
//
// # 何が壊れていたか
//
// 正典 JS は②.6 の原像を**必ず自分で再直列化**して照合する（`actionSnapshotPreimage`）。
// ところが ZKP ゲストは **プルーバが渡したバイト列を keccak するだけ**で、
// それが `JSON.stringify` の出力かどうかを見ていなかった。
// ハッシュは「**値**」を固定するが「**表現**」を固定しない。
// 実測: 非最短の数値表記（`1.700000001248e12`）を1つ混ぜるだけで **JS=259pt / Rust=246pt**
// （攻撃者本人 0pt→52pt・正典では成立していた密告が消えて被密告者 117pt→0pt）。
//
// # なぜ「空白と escape だけ塞ぐ」では足りないのか
//
// 数値の穴が残り、同じ値を表すバイト列は無限に作れる（`1e12` / `1.0e12` / `0.17e13` …）。
// 逆に「回路内で完全な `JSON.stringify` の不動点検査」をやるには、
// 回路へ最短往復の浮動小数点表記（Ryu / Grisu）を持ち込むことになる。
//
// # A3: 文法を**仕様として**制限する
//
// ②.6 の原像に実際に入るのは **タイムスタンプ（安全整数）・暗号文文字列・配列／オブジェクト**
// だけで、非整数が入る余地は現実に無い（実運用アーカイブ6ブロック・17バンドル・
// 生成フィクスチャ込み 475 バンドルで**偽陽性ゼロ**を実測）。
// 文法を制限すれば「同じ値を表すバイト列はただ1通り」になり、
// プルーバは書き方を選び直せなくなる。**署名の計算式は変えないので署名スキーマは不変。**
//
// 🔴 **正典 JS 側にも同じ文法を課すこと**（この関数）。
//    片側だけだと「JS 受理 / 回路拒否」＝そのブロックが永久に証明不能になる。
//    ここで落ちた提出物は②.6 不一致 ＝ `snapshot_mismatch`（自分のバンドルだけの自傷）。
//
// # 受理する文法（↔ `crates/scoring-core/src/json.rs` の `check_canonical_json`）
//
//   ・空白は1文字も許さない（文字列の中を除く）
//   ・数値は `-?(0|[1-9][0-9]*)` のみ。`-0` 不可・`Number.isSafeInteger` を満たすこと
//   ・文字列は `JSON.stringify` の最小エスケープのみ
//     （`\" \\ \b \f \n \r \t` と、短縮形を持たない C0・孤立サロゲートの `\uXXXX` 小文字hex）
//     `\/` は不可（`JSON.stringify` は `/` を escape しない）
//   ・生の文字は U+0020 以上。**生の孤立サロゲートは不可**（`JSON.stringify` は必ず escape する）
//   ・オブジェクトのキーは重複禁止
//   ・配列添字風キー（`0|[1-9][0-9]*` かつ < 2^32−1）は昇順で先頭に並ぶこと
//     （V8 の列挙順 ＝ `JSON.parse` → `JSON.stringify` の並び）

const CANON_ARRAY_INDEX_LIMIT = 4294967295;
const CANON_SHORT_ESCAPE = new Set([0x08, 0x09, 0x0a, 0x0c, 0x0d]);
const CANON_SIMPLE_ESCAPE = new Set(['"', '\\', 'b', 'f', 'n', 'r', 't']);

export function canonArrayIndex(k) {
  if (k.length === 0 || k.length > 10) return null;
  for (let i = 0; i < k.length; i++) {
    const c = k.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return null;
  }
  if (k.length > 1 && k[0] === '0') return null;
  const v = Number(k);
  return v < CANON_ARRAY_INDEX_LIMIT ? v : null;
}

/// 🔴 テキストが**制限文法の正準 JSON**か。↔ Rust `json::check_canonical_json`
///
/// 用途は2つあり、**どちらも根は同じ（原像の未束縛）** なので実装は1本にする:
///   ① 検証②.6 の原像（J-12 案A3）… 別名 `isCanonicalActionPreimage`
///   ② `summary.json`（J-13 案B2）… `lib/canonical-json.js` の `parseCanonicalJson` が使う
///
/// ⚠️ **再帰しない**（深い入れ子でスタックを尽きさせない・P-2026-0827 と同じ理由）。
export function isCanonicalRestrictedJson(text) {
  if (typeof text !== 'string') return false;
  const n = text.length;
  let i = 0;
  // スタックには「開いている入れ子」を積む。オブジェクトはキーの状態も持つ。
  const stack = [];

  // 文字列を1つ読む。返り値は [中身, 次の位置] / 不正なら null
  const readString = () => {
    if (text[i] !== '"') return null;
    const start = ++i;
    for (;;) {
      if (i >= n) return null;
      const c = text.charCodeAt(i);
      if (c === 0x22) { const s = text.slice(start, i); i++; return s; }        // '"'
      if (c === 0x5c) {                                                         // '\'
        const e = text[i + 1];
        if (e === undefined) return null;
        if (e === 'u') {
          const hex = text.slice(i + 2, i + 6);
          if (hex.length !== 4 || !/^[0-9a-f]{4}$/.test(hex)) return null;
          const cp = parseInt(hex, 16);
          const ok = (cp < 0x20 && !CANON_SHORT_ESCAPE.has(cp)) || (cp >= 0xd800 && cp <= 0xdfff);
          if (!ok) return null;
          i += 6; continue;
        }
        if (!CANON_SIMPLE_ESCAPE.has(e)) return null;
        i += 2; continue;
      }
      if (c < 0x20) return null;
      // 生の孤立サロゲートは `JSON.stringify` が出力しえない（必ず `\udXXX` にする）
      if (c >= 0xd800 && c <= 0xdbff) {
        const lo = text.charCodeAt(i + 1);
        if (!(lo >= 0xdc00 && lo <= 0xdfff)) return null;
        i += 2; continue;
      }
      if (c >= 0xdc00 && c <= 0xdfff) return null;
      i++;
    }
  };

  // 数値を1つ読む（安全整数の10進表記のみ）
  const readNumber = () => {
    const st = i;
    if (text[i] === '-') i++;
    const ds = i;
    if (text[i] === '0') i++;
    else if (text[i] >= '1' && text[i] <= '9') { while (text[i] >= '0' && text[i] <= '9') i++; }
    else return false;
    const digits = text.slice(ds, i);
    if (digits.length > 1 && digits[0] === '0') return false;
    if (text[i] === '.' || text[i] === 'e' || text[i] === 'E') return false;
    const tok = text.slice(st, i);
    if (tok === '-0') return false;
    return Number.isSafeInteger(Number(tok));
  };

  // `"key":` を読み、いま開いているオブジェクトへ登録する
  const readMemberKey = (obj) => {
    const k = readString();
    if (k === null) return false;
    const idx = canonArrayIndex(k);
    if (idx === null) { obj.seenPlain = true; }
    else {
      if (obj.seenPlain) return false;
      if (obj.lastIndex !== null && idx <= obj.lastIndex) return false;
      obj.lastIndex = idx;
    }
    if (obj.keys.has(k)) return false;   // キー重複（`JSON.stringify` は出力しえない）
    obj.keys.add(k);
    if (text[i] !== ':') return false;
    i++;
    return true;
  };

  for (;;) {
    // ---- 値の開始 ----
    const c = text[i];
    if (c === undefined) return false;
    if (c === '{') {
      i++;
      if (text[i] === '}') { i++; }
      else {
        const obj = { keys: new Set(), lastIndex: null, seenPlain: false };
        if (!readMemberKey(obj)) return false;
        stack.push(obj);
        continue;
      }
    } else if (c === '[') {
      i++;
      if (text[i] === ']') { i++; }
      else { stack.push(null); continue; }
    } else if (c === '"') {
      if (readString() === null) return false;
    } else if (c === 't') {
      if (text.slice(i, i + 4) !== 'true') return false; i += 4;
    } else if (c === 'f') {
      if (text.slice(i, i + 5) !== 'false') return false; i += 5;
    } else if (c === 'n') {
      if (text.slice(i, i + 4) !== 'null') return false; i += 4;
    } else if (!readNumber()) return false;

    // ---- 値を1つ読み終えた。閉じるか、次の要素へ ----
    for (;;) {
      if (stack.length === 0) return i === n;
      const frame = stack[stack.length - 1];
      const t = text[i];
      if (frame === null) {                     // 配列
        if (t === ',') { i++; break; }
        if (t === ']') { i++; stack.pop(); continue; }
        return false;
      }
      if (t === ',') { i++; if (!readMemberKey(frame)) return false; break; }
      if (t === '}') { i++; stack.pop(); continue; }
      return false;
    }
  }
}

/// 検証②.6 の原像用の別名（呼び出し側の意図が読めるように）。実装は同一。
export const isCanonicalActionPreimage = isCanonicalRestrictedJson;

/// 🔴 J-33 案D（2026-08-08・ユーザー確定）:
/// `encryptedActions` の **uid キー付き全セクション**（`votes` / `reports` /
/// `observed.votes` / `observed.reports`）のキーが、すべてグループ名簿の uid であること。
///
/// ⚠️ **「キー数 ＝ メンバー数」ではない。** 投票／密告していない人はキーごと現れないので
///    メンバー数以下になる。規則は個数ではなく「すべてのキーが名簿の uid であること」。
///
/// 動機: キーの個数がどのゲートでも縛られていなかったため、ZKP ゲストは重複キー検出に
/// FNV-1a 64bit の指紋を使わざるをえず、その指紋が**構成的に破られた**
/// （8,192 個の相異なるキーが同一指紋・実測 43〜49 倍の減速が gzip 25KB で
/// `Evidence.submitResult` 1回に載る）。キーを名簿に限れば1バンドル最大11個になり、
/// 指紋という仕掛けごと不要になる。
///
/// 🔴 名簿照合は **prototype-safe** に書くこと。素の `{}` を辞書にすると
///    `__proto__` / `constructor` / `toString` / `valueOf` / `hasOwnProperty` を uid に持つ
///    メンバーが弾かれ、**その人だけ失格**する（uid の文字集合は `\x21-\x7E` を許す）。
///    ここでは `Array.prototype.includes`（＝ SameValueZero 比較）しか使わない。
///
/// ⚠️ `__extras` は剥がさない。両クライアントが提出直前に基点 uid へ畳むので
///    （`SubmissionPhase.js` ＝ `chatgame-tools/src/recovery/bundle.js`・
///    デプロイ済みビルドでも確認）、`<uid>__extras` は正規の提出物には出現しない。
export function actionSectionKeysAreMembers(ea, memberUids) {
  if (!ea || typeof ea !== 'object') return false;
  const hasOwn = Object.prototype.hasOwnProperty;
  const scan = (sec) => {
    if (sec === null || typeof sec !== 'object') return true;   // 文字列/数値/真偽/null＝キー0個
    for (const k in sec) {
      if (!hasOwn.call(sec, k)) continue;
      if (!memberUids.includes(k)) return false;
    }
    return true;
  };
  const obs = (ea.observed !== null && typeof ea.observed === 'object') ? ea.observed : null;
  return scan(ea.votes) && scan(ea.reports)
    && (obs === null || (scan(obs.votes) && scan(obs.reports)));
}

// 1つの提出物が、1人の発信者について運べる「観測した発信（投票/密告）」の上限（K-S6-002）。
// 正規は投票1・密告2＋void後の再送ぶんで、矛盾の証拠（__extras）に必要なのも数件。
// 上限が無いと、受領証明の参照整合性を入れても「偽の発信＋その受領証明」のペアを量産すれば
// 同じ肥大化が起きる（発信は自分の signKey で正しく署名できるため署名検証では落ちない）。
//
// ⚠️ 数え方は **(提出者, 発信者) ペアごと**。発信者ごとの合計にすると、氾濫者が他人の
// バケツを埋めて**本物の投票を押し出し no_vote 失格にできる**（受領証明の (b) と同じ理由）。
export const MAX_OBSERVED_ACTIONS_PER_ACTOR = 10;

// 受領証明・観測発信の**受理規則**の版数（K-S6-002・2026-07-29）。
// しきい値だけでなく「何を数えるか」を変えたら必ず上げること
// （VISIBLE_CHARS_RULE_VERSION / REPORT_ELIGIBILITY_RULE_VERSION と同趣旨）。
// v1 の内容:
//   ・actionHash は 0x + 64hex に固定（isActionHash）
//   ・受領証明は**実在する対象**（提出されたメッセージ／発信）をカバーするものだけ数える
//   ・観測発信は (提出者, 発信者) ペアごとに MAX_OBSERVED_ACTIONS_PER_ACTOR 件まで
// v3 の変更（2026-08-05・P-2026-0805 / P-2026-0806 / P-2026-0808）:
//   ・**投票／密告の正典を「本人提出物」から union へ**（SPEC §6.4 条件4 の廃止）
//     検証⑥(b)（受領済み発信の未提出＝取下げ）を廃止
//   ・投票の対象矛盾は**失格にせず**、受領済み発信を正準順序で並べた**先頭1件**を採る
//   ・密告の枠消費と候補の切り詰めを**正準順序（timestamp → actionHash）**に固定
//     （旧実装は配列位置依存で、並べ替えるだけで失格者が入れ替わった）
//   ・発信の候補収集を **署名検証してから登録**する順に修正
//     （旧実装は先着で hash スロットを埋め検証は後＝偽物で本物を追い出せた）
//   ・候補収集にも `inChatWindow` を適用（⑤ と ⑥ の集合を揃える）
//   ・観測セクションの `__extras` サフィックスを剥がす
//   ・正典が扱う値の型を検査する（`isCanonicalTimestamp` / `isCanonicalText` /
//     `isCanonicalUid` / `isOpaqueField` / `isCanonicalDepositIds`）
// v2 の変更（2026-08-05・A-1〜A-3 是正）:
//   ・署名は `isCanonicalSignature`（0x + 130桁hex の**文字列**）のみ受理
//     （オブジェクト署名／奇数長hex を排除）
//   ・既読受領証明の `senderUid` は**文字列**のみ受理
//     （数値だとテンプレート文字列照合に一致してしまい、自己受領検査も型不一致で素通りした）
//   ・署名検証キャッシュのキーに**署名対象文字列そのもの**を含める
// v4 の変更（2026-08-06・P-2026-0811 の機械的修正）:
//   ・行動受領証明のペア枠キーに **type** を入れる（`{受領者}|a:{種別}:{発信者}`）
//     — 候補側 MAX_OBSERVED_ACTIONS_PER_ACTOR は type ごとに10件（最大20件）なのに
//       受領側の枠が type 込みで10件だと**構造的に必ず枠切れ**が起き、
//       投票1＋密告10＝11件で「誰が落ちるか」が入力の並び順で決まっていた
//   ・受領証明の**受理時**に鮮度（`isReceiptTimely` ±10分）を課す
//     — 旧実装は鮮度が「採用したあと」にしか無く、不鮮度な受領証明が先に枠を
//       占有すると後続の有効なものが署名検証すらされずに捨てられた（事後撤回）
//   ・`receiptsOfBundle` から `messages[].receipts` 分岐を削除
//     （誰の署名にも覆われていない領域で `examined` 予算を焼けた）
//   ・chatHash 自己整合の**手前**に `messages` 要素の型ゲートを追加
//   ・名簿の fail-closed 検査（重複 uid・非正準 uid）
//   ・既読受領証明の `msgRefs` を署名対象と同じ `compareHexAsc` 順に並べてから走査
//     （運び手が並べ替えるだけでどの発言を正典に残すか選べた）
// manifest.rules.receiptAcceptanceRule として公開し、検証ツールが
// 「どの規則で採点されたブロックか」を判別できるようにする。
// 🔴 上げたら **block-verifier/src/config.js の receiptAcceptanceRule pin も同じ値にする**
//    （忘れると check.stageC.rulesPins で simulation が落ちる。過去に2回踏んでいる）。
export const RECEIPT_ACCEPTANCE_RULE_VERSION = 18;
// S3R4-U-DUPGATE: 提出物内の参照の重複を許し、上限は重複を除かない数で掛ける。
// v18（2026-10-08・S3R4-U-PRIORITY）:
//   ・最優先欄の E の和集合を先に正典へ入れ、E′ の既読を枠と1通の検証予算を通さず先に受理する。
//     E′ は枠の使用には数え、通常欄の有限の上限には数えない（F1）。残りは最初の既読の順。
// v17（2026-10-07・S3R4-U11-V17・未配備・v18 で置き換えた）:
//   ・各有効な提出物の会話の証拠を先に正典へ入れ、残りを最初の既読の順で選ぶ。
//     件数上限は証拠にも掛け、正典の字数上限は証拠に掛けない。
// v16（2026-10-03・S3FIX-E5-01 (d)）:
//   ・密告の第1パスの枠の順を最初の数える受領証明の時刻にした。受領証明なしは最後。
//     同点と受領証明なしの中は timestamp → actionHash → signature の正準順。
// v15（2026-10-01・S3FIX）:
//   ・採点の1人100件・1万字の上限を、受理済み・鮮度内の最も早い既読の時刻順に掛ける。
//     同時刻なら正準順。2枚目以降の既読時刻と受け手数は比べない。
//   ・選んだ後は正準順へ戻す。密告資格・ターン・タイムラインの規則は変えない。
// v14（2026-09-29・S3R2-U-7 (B')）:
//   ・行動の受領証明は発行者本人の提出物にある分を正典へ採らない。
//     発言の既読は全員の提出物の和集合を保つ。
// v13（2026-09-26・Stage 3 持ち越しの判断 D-04・R33-C-2c-01）:
//   ・chatHash の原像に各発言の署名を入れる。正準順の各発言の (msgKey, signature) を
//     `coinu:chat-hash:v3|<msgKey>:<signature>|…` の UTF-8 として keccak256（空集合は '0x'。下の
//     computeChatHashV2）。msgKey そのものは変えない。旧来の1件だけの特例（msgKey の生32バイトを
//     keccak）は廃止。これで各発言の署名も外側ウォレット署名の束縛に入る（束縛の台帳 G → BOUND-7）。
//     同じ msgKey で署名だけ違う提出物は別の chatHash になり受理が変わるので版数を上げる。
// v12（2026-08-20・Stage 3 採点レビュー第5ラウンド）:
//   ・msgRef を msgKey の先頭8バイトから先頭16バイトへ拡張する。
//     受領証明の署名 preimage と、既読カバーを識別する規則が変わるため版数を上げる。
// v11（2026-08-17・Stage 3 採点レビュー第2ラウンド）:
//   ・入口で失格した提出物は、メッセージ／受領証明だけでなく発信候補も運べないよう統一
//   ・既読受領証明1枚の msgRef 上限を compact/入口ゲートと同じ100件へ統一
// v10（2026-08-12・Round 21 F1）: 提出物全体を有限化し、正規クライアントが発行した
// 自己受領を `receipt_aggregate/1` の1署名へまとめる。受理できる事実数を
// チャット2,000件＋行動分を含む上限（現在2,400件）を固定し、compact Evidence の同じ論理像を
// JS正典とRustゲストが検証する。受領署名のプリイメージと「何を数えるか」が変わるため版数を上げる。
// v9（2026-08-08・J-15 案A・ユーザー確定）: **観測発信の切り詰めが「古い順」だった穴**を塞いだ。
//   1人あたり10件の切り詰めが timestamp 昇順だったため、void（受領証明ゼロ）の古い発信が
//   10枠を食い、**唯一有効な最新の投票が捨てられた**。実測:
//     10件（void 9 + 受領 1）→ {200,200,200} ／ **11件（void 10 + 受領 1）→ {0,100,200}**
//   （発信者が `no_vote` 失格・投票先の無実の第三者もボーナス 100点を失う）。
//   同組の1人が最初の10回だけ受領証明を出さなければ**自損ゼロ**で起こせるうえ、
//   回線断・タブ休止・再送の繰り返しで**事故でも起きる**。
//   ① **投票（④）**: 切り詰めの対象を「受領証明のある候補」だけにする。
//      void の投票は④でも⑥(c)でも `receiptedVoteActors` でも使われないので、
//      10枠に入れる意味が無い（除いたぶん有効な候補が入る）。
//      判定は復号も追加の署名検証も要らない（`actionReceiptCoverage` は候補収集より手前で確定）。
//   ② **密告（⑤）**: 2段構え。**第1パス（枠と2標的の決定）は1バイトも変えない**
//      ＝ K-S2-006「void でも distinct 対象枠は解放しない」の均衡は不変。
//      枠を取った標的なのに有効な密告が1件も残らなかった場合だけ、**その標的への**
//      受領証明つきの密告を古い順に探す第2パスを走らせる（1標的あたり最大10件）。
//      救うのは「同じ標的への再送が11件目にある」場合だけで、3番目の**新しい**標的は
//      枠外のまま（仕様どおり）。第2パスは控えが空なら1回も回らない＝平常時のコストは 0。
//   ⚠️ ④と⑤で扱いが**非対称**（④は receipted のみ・⑤は第1パスで全件）。意図的。
//      密告は「2枠」という奪い合う資源があるので void でも枠を消費させる必要がある。
//   🔴 「何を数えるか」が変わる（受理される投票／密告の集合が変わる）ので版数を上げる。
// v8（2026-08-08・J-33 案D ＋ J-12 案A3・ユーザー確定）: **②.6 の原像を1通りに固定した。**
//   ① `encryptedActions` の uid キー付き全セクション（`votes` / `reports` /
//      `observed.votes` / `observed.reports`）のキーは**グループ名簿の uid だけ**。
//      1つでも名簿外があれば、そのバンドルは発信も受領証明も**1件も提供しない**
//      （②.6 の判定には影響しない ＝ 失格にはならない・自傷にしかならない）。
//      旧規則は名簿外キーを**黙って読み飛ばす**だけで、キーの個数がどこでも縛られて
//      いなかった（ZKP ゲストの重複キー検出に使っていた FNV-1a 指紋が構成的に破られた）。
//   ② ②.6 の原像は**制限文法**（正準 JSON・数値は安全整数のみ）でなければならない。
//      満たさない提出物は `snapshot_mismatch`。
//      旧規則は「ハッシュが合えば何でもよい」で、ハッシュは値しか固定しないため
//      非最短の数値表記1つで **JS=259pt / ゲスト=246pt** に割れた。
//   🔴 どちらも「何を数えるか」が変わるので版数を上げる。
//      検証ツールの pin（`block-verifier/src/config.js` の `receiptAcceptanceRule`）は
//      v7 の時点で既に 6 のまま**解放待ち**なので、**追加の待ちは生まれない**
//      （解放時に 6 → 8 を一度に入れる）。
// v7（2026-08-08・P-2026-0842・ユーザー確定）: 投票・密告の `encrypted` に
//   **正準長**（`isCanonicalActionCiphertext`）を課した。`gather` / `collect` の
//   入口 ＝ v3 で `isOpaqueField` などの型検査を足したのと**同じ位置・同じ粒度**
//   （その1件を候補に積まないだけ。予算は消費せず、失格にもしない）。
//   これは衛生ではなく規則である: 長さが正準値でない発信は正典に入らないので、
//   パディングしないクライアントの投票は `no_vote` になる。
//   動機は「暗号文の長さが対象 uid の桁数を漏らす」受動観測攻撃
//   （詳細は下の `ACTION_PLAINTEXT_BYTES` 節）。
// v6（2026-08-07・P-2026-0813・ユーザー確定 2026-08-07）: 整列の**単位**を
//   「提出物**内**」から**全提出物をまとめた1本の正準順序**へ直した。
//   受理の可否を決める状態（ペア枠・カバー・`(受領者, 参照)` に残る受領時刻）は
//   提出物をまたいで共有されるので、提出物内だけで整列しても
//   「**同じ署名済み受領証明の集合を、どの提出物が運ぶか**」で採点が変わっていた。
//   実測（同じ集合のまま格納先の提出物だけを入れ替えた）:
//   p1 の合計が **230pt ↔ 250pt**、p4 に `reported` が**付いたり消えたり**した。
//   整列キーの末尾に**提出者 uid** をタイブレーカとして足してある（全順序にするため）。
//
//   ⚠️ **v5 のまま据え置いていた期間がある**（2026-08-07 の P-2026-0813 で数え方を
//      変えたのに版数を上げ忘れていた＝同じ `rule=5` を名乗るブロックが2種類の規則で
//      採点されうる状態だった）。未リリースで実ブロックはテストランのみ＝実害はゼロだが、
//      「数え方を変えたら版数を上げる」という下のルールを自分で破っていた。
//      本番でこれを繰り返さないため、ユーザー判断で 6 へ引き上げた。
// v5（2026-08-06・P-2026-0812 F1/F2/F3）: 受領証明を**提出物内で正準順序に整列してから**
//   受理するようにした。旧 v4 は提出配列の順に枠（ペア上限・カバー）を先着で消費しており、
//   同じ受領証明の集合でも並べ替えるだけで「どの発言が正典に入るか」「どの発信が
//   受領済みになるか」「(受領者,ref) の受領時刻に何が残るか」が変わっていた（実測で
//   min_messages / no_vote / 密告成立が反転）。整列キーは
//   `(timestamp 昇順 → 種別 r<a → receiverUid 昇順 → 参照キー昇順 → signature 昇順)`。
//   timestamp 昇順なので (受領者, ref) に残るのは**最も早い受領時刻**になる。
// 併せて提出物の走査順を `results` 順（＝名簿順）から **uid 昇順**に固定した。

// ============================================================
// 受領証明（v3.2 §6.3）— 発信者以外のメンバーが signKey で自動署名。
// 「本人のsignKey署名 ∧ 他メンバー受領証明≥1件」が正典条件（チャット/投票/密告で統一）。
//
// v3.3 リアルタイム条件: 受領証明は |受領timestamp − 発信主張timestamp| ≤ 10分 の場合のみ有効。
// クライアントは発信主張時刻から10分以内に受信したものにしか受領証明を発行しない。
// D-02: 投票の2通目以降にはさらに先着から10分より後という条件を課す。
// これにより「タイムスタンプを過去(未来)にずらした発信を後から挟み込み、既読を集めて
// 会話数を水増しする」バックデート/ポストデートを±10分に制限する（サーバー時刻公証は
// 運営チートの穴になるため不採用。10分以内に誰にも読まれなかった発信は無効＝なかったことになる）。
// ============================================================

// 受領証明の有効窓（ms）。クライアント発行ゲートと calculator 検証の共通定数。
export const RECEIPT_FRESH_WINDOW_MS = 10 * 60 * 1000;

// D-02: 投票の受け手は最初に観測した投票を基点にする。2通目以降は基点から
// 10分より後の主張時刻のときだけ受領証明を出す。観測への採用は別に行い、
// 密告にはこの追加条件を適用しない（対象の2枠は採点が守る）。
export function shouldIssueReceiptForObservedAction(type, firstVote, action) {
  if (type !== 'vote' || !firstVote || firstVote.signature === action?.signature) return true;
  return Number.isSafeInteger(firstVote.timestamp)
    && Number.isSafeInteger(action?.timestamp)
    && action.timestamp > firstVote.timestamp + RECEIPT_FRESH_WINDOW_MS;
}

// 在席（アクティブ）判定のしきい値（ms）。クリック/入力/スクロール等の操作がこの時間だけ
// 検知されないクライアントは away（オフライン）になり、その間は受領証明を発行しない。
// 受領証明の有効窓と同値にしてあるのは「1窓ぶん無反応＝その間に届いた発信は結局voidになる」
// を一致させるため（採点には影響しない＝正直なクライアントの振る舞い規約）。
export const IDLE_TIMEOUT_MS = RECEIPT_FRESH_WINDOW_MS;

// ============================================================
// 密告の資格要件（正典 §6.9 追補・規則版数 5）
// ============================================================
// 標的の受領証明付き投票の最早の自称時刻より、密告の自称時刻が厳密に後なら有効。
// 投票は復号しない。標的の提出物が無くても他人が運んだ確定投票を数える。
// 資格を満たさない密告も先に distinct 対象枠を取る。
//
// ⚠️ 定数名は歴史的なもの（`REPORT_MIN_READ_RECEIPTS` / `manifest.rules.reportMinReadReceipts`）。
//    版数5の採点では使わない。manifest.rules の45鍵の形とクライアントとの互換のため残す。
export const REPORT_MIN_READ_RECEIPTS = 5;

// 上記規則の版数。**しきい値や数え方を変えたら必ず上げること**（manifest.rules に公開され、
// 検証ツールが「どの規則で採点されたブロックか」を判別する。VISIBLE_CHARS_RULE_VERSION と同趣旨）
//   1: 密告者が標的から5件受領している（ペア単位・2026-07-28〜2026-08-09）
//   2: 標的の正典メッセージ5件を密告者が提出物で運んでいる（J-35・2026-08-09〜）
//   3: 標的の正典メッセージ5件を union で数える（密告者の運びに依らない）
//   4: 標的の正典メッセージ5件目より密告が後（厳密な時刻順）
//   5: 標的の確定した投票の最早時刻より密告が後（S3FIX-A501-VOTE）
export const REPORT_ELIGIBILITY_RULE_VERSION = 5;

// 受領証明が発信に対してリアルタイム（±10分以内）かの判定（クライアント/採点で共通）
export function isReceiptTimely(receiptTimestamp, claimedTimestamp) {
  return typeof receiptTimestamp === 'number' && typeof claimedTimestamp === 'number'
    && Math.abs(receiptTimestamp - claimedTimestamp) <= RECEIPT_FRESH_WINDOW_MS;
}

// 投票・密告の受領証明: actionHash = actionHashV2(...)（署名済み発信データの同一性キー）
export function receiptSignString(blockNum, groupId, receiverUid, actionHash, timestamp) {
  return JSON.stringify({
    type: 'receipt',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid: receiverUid,
    actionHash,
    timestamp
  });
}

// ============================================================
// msgRef（2026-07-28・オンチェーン容量対策）
// ============================================================
// 既読受領証明が「どの発言を読んだか」を指す参照は、msgKey（32バイト）の**先頭16バイト**を使う。
//
// 動機: Evidence（検閲されたときの自己救済＝オンチェーン提出）の上限は gzip 後 128KB で、
// これは **Ethereum クライアントのトランザクション伝播上限（geth txMaxSize = 128KB）と同じ**。
// つまり契約側の定数を上げても、そのトランザクションは mempool に載らない＝容量を減らすしかない。
// 既読機能を追加した後、この予算は測り直されていなかった。実測（5人×100発言の上限ケース）:
//
//   既読なし（設計時の想定）      gzip後  66KB   ✅
//   32バイト参照（既読追加後）    gzip後 147KB   ❌ 上限の1.15倍 ＝ オンチェーン提出が不可能
//   **16バイト参照（現行）**       compact wire は u16 索引なので8バイト版と完全同一
//
// 支配項は既読の署名ではなく msgKey の羅列（1発言を4人が既読にすると66文字が4回書かれる）。
//
// 旧8バイト参照は、自分の発言同士なら誕生日攻撃 2^32.3 で衝突を作れた。
// 参照から発言時刻を推測する層ごとの差を使い、第三者の発言や密告資格を事後に void 化できたため、
// 16バイトへ拡張した。自己衝突の仕事量は約 2^64.3 となる。
//
// msgKey そのもの（重複排除キー・正準順序のタイブレーカー・chatHash の材料）は32バイトのまま。
// 短縮するのは**既読の中の参照だけ**である。
export const MSG_REF_BYTES = 16;

// msgKey（0x + 64hex）→ msgRef（0x + 32hex）
export function msgRefOf(msgKey) {
  return String(msgKey).slice(0, 2 + MSG_REF_BYTES * 2);
}

// 形式検査（改造クライアント・旧形式の混入を弾く）。この固定長は次の不変条件を支える:
//   (i) `|` を含みうる uid と `${uid}|${ref}` で連結しても、固定長 suffix により単射になる
//   (ii) JS `compareHexAsc`（BigInt 順）と Rust `[u8; 16]`（辞書順）が一致する
//   (iii) 衝突耐性の範囲で msgRef から発信者が推移的に一意に決まり、検証層①③が同じ原像を見る
export function isMsgRef(v) {
  return typeof v === 'string'
    && v.length === 2 + MSG_REF_BYTES * 2
    && /^0x[0-9a-f]+$/.test(v);
}

// ============================================================
// 受領証明の分量上限（Q-S2-001・2026-07-28）
// ============================================================
// 採点は受領証明を1枚ずつ署名検証する（実測 1.52ms/回）。件数に上限が無いと、
// グループメンバーがタイムスタンプを1msずつずらして「本物の署名」を量産するだけで
// CPU を使い切らせ、K-S2-004 の fail-closed 化によりブロック全体を止められる。
//
// 上限は「正当に存在しうる最大」から導く（恣意的な数字を作らない）:
//   ・既読: 1人の発信者につき最大 GAME_MAX_MESSAGES 件（それ以上は applyChatCaps で正典外）
//   ・行動: 投票1・密告2 ＋ void後の再送ぶんの余裕 → 1ペアあたり 10
// 超過はすべて**無視**（失格にはしない。通信障害や複数端末で正直な人を巻き込まないため）。
// 🔴 P-2026-0812（2026-08-06）: **`groupSize` に比例させる。**
//    候補側 `MAX_OBSERVED_ACTIONS_PER_ACTOR` は **(提出者, 発信者, 種別) ごと**に10件なので、
//    提出者が分担して運べば同じ (発信者, 種別) に対して最大 `10 × 提出者数` 件の
//    「実在する発信」が作れる。受領側の枠が固定10件だと**構造的に必ず枠切れが起き**、
//    枠に入れなかった受領証明が採点から落ちる。
//    2026-08-06 に枠キーへ種別を入れて閾値は 11 に上がったが、**構造は変わっていなかった**
//    （実測: 同一種別で11件にすると投票先が入れ替わり100点が移動した）。
//    枠を「起きうる最大件数」に合わせることで、正直な受領証明が落ちる状況そのものを消す。
//    ⚠️ CPU 上限は `receiptBundleCap` が別途縛るので、これを広げても有界性は失われない。
export const RECEIPT_MAX_ACTIONS_PER_PAIR_BASE = 10;
export const receiptMaxActionsPerPair = (groupSize) =>
  RECEIPT_MAX_ACTIONS_PER_PAIR_BASE * Math.max(1, groupSize);
// 1枚の既読受領証明に入れられる msgRef の数（1枚 = 1つの (受領者, 発信者) ペア）
// 行動受領証明は actionHash を持つ別形式なので、行動10件をここへ足してはならない。
export const receiptMaxRefsPerReceipt = (maxMessages) => maxMessages;

// 提出物1通あたり、署名検証にかける受領証明の上限。
// 実行値: 3人組 960 / 4人組 2,160 / 5人組 4,000。
// 正直な提出物は「カバー先が全て他の既読と重複する既読を載せない」ため必ずこの中に収まる
// （SubmissionPhase の重複排除）。したがって切り詰められるのは細工した提出物だけであり、
// その場合も本物の既読は他メンバーの提出物に入っているので失われない。
// 🔴 P-2026-0812（2026-08-06）: 導出を「受理しうる**受領証明の枚数**」から取り直した。
//    旧式 `receiptMaxRefsPerReceipt × groupSize × (groupSize−1)` は 5人組で 2,200 だが、
//    実際に受理しうる枚数は
//      既読  groupSize × (groupSize−1) × maxMessages（1枚1ref の最悪ケース）
//      行動  groupSize × (groupSize−1) × 2種別 × receiptMaxActionsPerPair(groupSize)
//    ＝ 5人組で **既読 2,000 + 行動 2,000 = 4,000** で、**上限のほうが小さかった**
//    🔴 2026-08-07 訂正: 旧コメントの「2,000+800=2,800」は誤り。
//       行動側は 20ペア × 2種別 × receiptMaxActionsPerPair(5)=50 ＝ 2,000。
//    （「正直な提出物は必ず収まる」というコメントの前提が成り立っていなかった）。
/// 1通の提出物が**意味のある形で運べる既読カバーの総数**。
/// = (受領者, 発信者) の組 × 1発信者あたりの発言上限。5人組・100発言で 2,000。
/// 🔴 P-2026-0812（2026-08-06）: `receiptBundleCap`（CPU 上限）とは**別物**。
///    Evidence のバンドルサイズ見積もりはこちらを使うこと。
///    以前は両者がたまたま近い値だったので `receiptBundleCap` が流用されていた。
export const readCoverageCap = (maxMessages, groupSize) =>
  groupSize * Math.max(0, groupSize - 1) * maxMessages;

export const receiptBundleCap = (maxMessages, groupSize) => {
  const pairs = groupSize * Math.max(0, groupSize - 1);
  return pairs * (maxMessages + 2 * receiptMaxActionsPerPair(groupSize));
};

// ============================================================
// メッセージの分量上限（P-2026-0814・2026-08-07）
// ============================================================
// 🔴 **受領証明にだけ上限があり、メッセージには一つも無かった。**
//
// 採点はメッセージも1件ずつ署名検証する（`game-result-calculator.js` 検証②.5(b)）。
// ところが Q-S2-001（受領証明）で入れた (b)(c)(d) に相当するものがメッセージ側には無く、
// `chat-game-DO.js` の提出ゲートも `submittedMessages.length` を一切見ていなかった
// （`depositIds` は10件、`receipts` は `receiptBundleCap` で縛られているのに `messages` だけ素通り）。
// 保存側も `storeSubmissionBundle` が分割するのでサイズで止まらない。
// 実質の上限は Cloudflare の WS フレーム（約1MiB）だけ ＝ 1件約210バイトなので
// **1提出物あたり約5,000件**、5人組で約25,000回の署名検証になる。
//
// 実測（M系 Mac・`verifyMessage`）:
//   形式だけ正しいデタラメ署名 0.826 ms/回 ／ 本物の署名 1.45 ms/回
//   → 20,000件で 16.5秒、25,000件で 20.7秒（本物なら36秒）
// `game-master-DO.js` の CPU 予算は約30秒で、`calcScoringUnit` の実時間ガードは
// **グループに入る前にしか評価されない**ため、1ユニットの最悪は「ガード値 ＋ 1グループぶん」。
// つまり上限が無いと**決定論的に予算を超え → ユニット失敗 → 入力が同じなのでリトライも同じ壁
// → park（ブロック全体が止まる）**。攻撃者の利得はゼロの純グリーフィングで、
// コストは「署名しないデタラメ署名を並べるだけ」＝ほぼ無料である。
//
// 上限は受領証明と同じく「正当に存在しうる最大」から導く（恣意的な数字を作らない）:
//   ・`applyChatCaps`（char-counter.js）は **1人の発信者につき `GAME_MAX_MESSAGES` 件**しか
//     正典に残さない。それを超える発言は誰が運んでも正典外＝運ぶ意味が無い。
//   ・発信者はグループ人数ぶんしかいない。
//   → 1通の提出物が運ぶ意味のあるメッセージは **maxMessages × groupSize**（5人組・100件で 500）。
// これは `chat-game-DO.js` が WS 経路で通す総数（`messageCounts[uid] ≤ maxMessages` を
// 全メンバーぶん）とも一致する。
//
// 超過は受領証明と同じく**無視するだけ**（失格にはしない）。
// ⚠️ **採点側は `messagePerSenderCap` の方（発信者ごと）を先に課すこと。**
//    合計だけで縛ると、悪意あるメンバーが P2P に大量発言を流したとき
//    正直な人の提出物でも「他人の氾濫」が先に予算を食い、
//    **自分の発言が自分の提出物から登録されず min_messages 失格**になる
//    （受領証明 (b) がペア単位である理由とまったく同じ）。
//    発信者ごとに切ると合計は自動的に `messageBundleCap` に収まる。

/// 1通の提出物が、**1人の発信者**について署名検証にかけるメッセージ数の上限。
/// `applyChatCaps` が正典に残す件数そのもの＝これを超える分は運んでも正典に入らない。
export const messagePerSenderCap = (maxMessages) => maxMessages;

/// 1通の提出物が運ぶメッセージ件数の上限（= 発信者ごとの上限 × 発信者数）。
/// `chat-game-DO.js` の提出ゲートと、採点側の提出物ごとの署名検証予算が共有する。
export const messageBundleCap = (maxMessages, groupSize) =>
  Math.max(1, groupSize) * messagePerSenderCap(maxMessages);

// ============================================================
// 受領証明の「消費側」マップ（K-S6-005・2026-07-29）
// ============================================================
// 採点エンジンは受領証明を **±10分（isReceiptTimely）** で篩うが、UI と提出物構築は
// 「他メンバーの受領証明が1件でもあるか」しか見ておらず、時刻を一切見ていなかった。
//
// そのため同じグループの1人が「署名は正しいが時刻を11分ずらした受領証明」を出すだけで、
//   ・被害者の画面は文字数・会話回数が進み、投票に「投票済み」の緑表示が出る
//   ・被害者は条件を満たしたと信じて発言をやめ、投票も再送しない
//   ・採点は ±10分で無効化するので min_chars / min_messages / no_vote で失格
// という「正規UIに従った善良なプレイヤーの冤罪失格」が、**署名1回のコスト**で成立していた。
//
// さらに提出物構築（正式な投票の選択）も同じ判定を使っていたため、
// 攻撃者が無効な方の投票に偽の受領証明を付けると、**本当に有効な投票が観測欄へ回され、
// 無効な方が正式扱いになる**（採点は votes[uid] しか見ない）＝確実に no_vote 失格になった。
//
// 対策: 消費側のマップを**この関数1つに集約**し、採点と同じ ±10分で篩う。
// 参照先（発言・発信）の時刻と突き合わせる必要があるため、呼び出し側が
// 自分の知っているメッセージ・発信を渡す。知らない対象への受領証明は「未読」扱いになる
// ＝安全側（被害者はもっと発言しようとするだけで、失格には向かわない）。
//
// ⚠️ 超過・不正は**無視するだけ**で、警告表示も失格も行わない。
//    「◯◯さんが不正な受領証明を出しています」という表示は、時計のずれでも起きるため
//    それ自体が冤罪の材料になる（ユーザー確定 2026-07-29）。
//
// ============================================================
// J-26（2026-08-08・ユーザー確定「案B＝表示にだけ窓を適用する」）
// ============================================================
// 最優先欄（規則版数18）は例外。確定した宣言窓での検査は priority-fields.js の冒頭を参照。
// 🔴 `isReceiptTimely` は「受領証明の**自称**時刻」と「相手の発言の**自称**時刻」しか比べず、
//    **「いまの時刻」とは一度も比べない**。自称時刻は書式（`isCanonicalTimestamp`）しか
//    検査されないので**未来の値が書ける**。
//
//    チャット中に「相手の発言 ts + 9分」の受領証明を出すと、鮮度 9分 ≤ 10分 なので
//    DO は素通しして配信し、**被害者の画面に「既読」と出る**。しかし採点は
//    宣言窓（チェーンが宣言したチャット終了 + 時計ずれ許容）の外なので**無効**。
//    被害者は「読まれた」と信じて対処の機会を失う（実時刻ではまだチャット期間なので、
//    本来なら別の人に頼み直せた）。露出帯は末尾の
//    `RECEIPT_FRESH_WINDOW_MS(10分) − 時計ずれ許容(2分) = 8分`。
//
// 対策は**表示（消費側）にだけ**宣言窓を課すこと。窓は呼出側が渡す（既定 null＝従来どおり）。
//
// 🔴 **提出物の構築には渡さないこと。** 全員のクライアントが `extendGrace` 前の古い窓を
//    持っていた場合、正当な受領証明が**全員の提出物から同時に消えて正典から失われる**。
//    取り返しがつかない。
// 🔴 **サーバー（`chat-game-DO.js`）にも入れないこと。** `extendGrace` でチャット終了は
//    後ろへ動くので、初期化時の窓を焼き込むと**延長後の正直な受領証明を fail-closed で落とす**。
//
// 間違う方向の非対称性:
//    古い窓で「未読」と誤表示 → 被害者が別の人に頼み直すだけ（無害）
//    古い窓で「拒否」        → 正典から消える（取り返しがつかない）
//    ＝ **表示は安全側・拒否は危険側**。だからここ（表示）にだけ入れる。
//
// 判定は採点本体（`game-result-calculator.js` の `inChatWindow(rc.timestamp)`）と同一:
// 受領証明の timestamp が [startMs, endMs]（両端含む）の内側であること。
export const CHAT_WINDOW_CLOCK_SKEW_MS = 120000;

/// チェーンの宣言タイムライン（ms）→ 採点が使う `chatWindow`（±時計ずれ許容）。
/// 正典は `game-master-DO.js` の `calcEvidenceUnit`（旧 `reconcileEvidence`、`Evidence.chatWindow(N)` ± skew）で、
/// **クライアントはそれと同じ窓を再導出する**（写経しないよう関数をここに1つだけ置く）。
/// @param timeline {chatOpenAt, chatCloseAt}（ms）。どちらかが有限でなければ null（＝窓なし）
export function chatWindowMsFromTimeline(timeline) {
  const open = timeline?.chatOpenAt;
  const close = timeline?.chatCloseAt;
  if (!Number.isFinite(open) || !Number.isFinite(close)) return null;
  return { startMs: open - CHAT_WINDOW_CLOCK_SKEW_MS, endMs: close + CHAT_WINDOW_CLOCK_SKEW_MS };
}

// actions: [{ type: 'vote'|'report', uid, encrypted, timestamp }]
// chatWindow: { startMs, endMs } | null — **表示専用**の宣言窓（J-26）。null は従来どおり窓なし。
// myUid: 自分が発行した既読を ref 単位の自己集約として扱う。未指定なら全件 legacy 扱い。
export function buildReceiptMaps(receipts, { messages = [], actions = [], myUid = null }, blockNum, groupId, chatWindow = null, getClientMsgKey = null) {
  // 採点本体（game-result-calculator.js）の `inChatWindow` と同一式。
  const inChatWindow = (ts) => !chatWindow
    || (typeof ts === 'number' && ts >= chatWindow.startMs && ts <= chatWindow.endMs);
  // senderUid + 参照 → 発信時刻。提出前の filterReceiptsToCarriedTargets と同様、
  // 同じ sender/ref が曖昧なら「この端末から運べる対象」とは扱わない。
  const msgTimeByTarget = new Map();
  const ambiguousTargets = new Set();
  for (const m of (Array.isArray(messages) ? messages : [])) {
    if (!m || m.uid == null || m.timestamp == null) continue;
    const ref = msgRefOf(getClientMsgKey ? getClientMsgKey(m) : computeMsgKeyV2(blockNum, groupId, m));
    const key = `${m.uid}|${ref}`;
    if (msgTimeByTarget.has(key)) ambiguousTargets.add(key);
    else msgTimeByTarget.set(key, m.timestamp);
  }
  for (const key of ambiguousTargets) msgTimeByTarget.delete(key);
  const actionTimeByHash = new Map();
  for (const a of (Array.isArray(actions) ? actions : [])) {
    if (!a || !a.encrypted || a.timestamp == null || a.uid == null) continue;
    actionTimeByHash.set(actionHashV2(a.type, blockNum, groupId, a.uid, a.encrypted, a.timestamp), a.timestamp);
  }

  const readersByMsgKey = {};
  const receiptorsByActionHash = {};
  for (const rc of Object.values(receipts || {})) {
    if (!rc || rc.receiverUid == null || rc.timestamp == null) continue;
    // 🔴 P-2026-0836（2026-08-08・ラウンド19 判断不要-2）: **署名の正準性（形式＋low-s）を課す。**
    //    ここは「画面に『既読 / 受領済み』と出す」判断を一手に握っている消費側で、
    //    旧実装は `rc.signature` を**1行も見ていなかった**。
    //    採点正典（`game-result-calculator.js:1238` の `isCanonicalSignature`）と
    //    Rust（`receipts.rs:186` の `is_low_s`）は high-s の「双子」を落とすので、
    //    双子だけを受け取った利用者は **画面に「投票: 完了」/「既読」と出たまま
    //    採点では void** になり、**再送導線が構造的に出ない**（`ChatPhase.js:99→115→121`／
    //    `game.js:459-468` の `receiptedMessages`）。自己救済も
    //    `game-result-calculator.js:1325` の `receiverUid === actorUid` で塞がっている。
    //    DO 側（`chat-game-DO.js` の6+1箇所）にも同じ述語を入れたが、**P2P（Nostr）経路は
    //    DO を通らない**ので、消費側のここを直さないと迂回される。
    //    ⚠️ ここで課せるのは署名の**形式**まで（ECDSA 検証は非同期で、この関数は同期）。
    //       発行者の同一性は呼出側（`useGameWebSocket.verifyRelayInner` /
    //       `relay-verify.js`）が検証する。high-s 双子はこの形式ゲートだけで閉じる。
    //    ⚠️ 過剰遮断ゼロ: viem `signMessage` 500サンプルで high-s は 0件。
    //       採点も同じ述語なので、ここで落ちるものは採点でも必ず落ちる（表示 ≡ 採点）。
    if (!isCanonicalSignature(rc.signature)) continue;
    // J-26: 宣言窓の外の受領証明は**表示に出さない**（採点は元から無効にしている）。
    // 呼出側が窓を渡さない限り no-op ＝ 提出物構築の呼び出しは従来どおり全件を見る。
    if (!inChatWindow(rc.timestamp)) continue;
    if (Array.isArray(rc.msgRefs)) {
      // 決定1: 提出ゲート／採点と同じく read receipt の senderUid は文字列だけ。
      // 配列等をテンプレート文字列で暗黙変換すると、表示だけが提出可能集合より広くなる。
      if (typeof rc.senderUid !== 'string') continue;
      const carriedTargets = rc.msgRefs.map((ref) => ({
        ref,
        timestamp: msgTimeByTarget.get(`${rc.senderUid}|${ref}`),
      }));
      if (rc.receiverUid === myUid) {
        for (const { ref, timestamp } of carriedTargets) {
          if (timestamp == null || !isReceiptTimely(rc.timestamp, timestamp)) continue;
          (readersByMsgKey[ref] = readersByMsgKey[ref] || new Set()).add(rc.receiverUid);
        }
        continue;
      }
      // 🔴 request7 方針変更: 採点は ref 単位で部分点を与え得るが、署名済み batch は
      // 分割して提出できない。運べない ref が1件でもあれば、この端末が単独で保証できる
      // 既読は0件として表示する（割り当てを超えた発行者の分を除き、表示は提出できるもの）。
      // action map は別枝なので、提出時の受領済み vote 選択には影響しない。
      if (carriedTargets.some((target) => target.timestamp == null
        || !isReceiptTimely(rc.timestamp, target.timestamp))) continue;
      // S3R4-U-DUPGATE: 受け入れた既読は包含・一部重複にかかわらず全部数える。
      for (const ref of rc.msgRefs) {
        (readersByMsgKey[ref] = readersByMsgKey[ref] || new Set()).add(rc.receiverUid);
      }
    } else if (isActionHash(rc.actionHash)) {
      const ts = actionTimeByHash.get(rc.actionHash);
      if (ts == null || !isReceiptTimely(rc.timestamp, ts)) continue;
      (receiptorsByActionHash[rc.actionHash] = receiptorsByActionHash[rc.actionHash] || new Set()).add(rc.receiverUid);
    }
  }
  return { readersByMsgKey, receiptorsByActionHash };
}

// クライアントが保証できる正典発言。採点と同じく窓、既読、最早既読順の上限で絞る。
// 自分の発言は提出時に保持するが、他人の発言は手元に有効な既読がある分だけ運ぶ。
// scoring-core / 入口ゲートからは呼ばないクライアント専用の組み立て関数。
export function clientScoreableMessages(messages, receipts, {
  blockNum, groupId, myUid, chatWindow = null, caps = {}, compare = null, getClientMsgKey = null,
  claimMemo = null,
} = {}) {
  const inWindow = (message) => !chatWindow || (message.timestamp >= chatWindow.startMs
    && message.timestamp <= chatWindow.endMs);
  const windowed = (Array.isArray(messages) ? messages : []).filter(inWindow);
  const targets = buildRealTargets({}, windowed, blockNum, groupId, getClientMsgKey);
  const selectedReceipts = admitReadReceiptsByArrival(receipts, targets, {
    messages: windowed, blockNum, groupId, myUid, selfUid: myUid, chatWindow,
    caps, getClientMsgKey, claimMemo,
  });
  const { readersByMsgKey } = buildReceiptMaps(
    selectedReceipts, { messages: windowed, myUid }, blockNum, groupId, chatWindow, getClientMsgKey,
  );
  const covered = windowed.filter((message) => {
    if (message.uid === myUid) return true;
    const ref = msgRefOf(getClientMsgKey ? getClientMsgKey(message) : computeMsgKeyV2(blockNum, groupId, message));
    const readers = readersByMsgKey[ref];
    return readers && [...readers].some((uid) => uid !== message.uid);
  });
  // 上限の鍵は手元で採用した受領証明だけから作る。自分の発言も同じ鍵で比べ、
  // まだ誰にも読まれていない自分の発言には鍵を与えない。
  const firstTimeByTarget = new Map();
  const maxRefsPerReceipt = receiptMaxRefsPerReceipt(normalizeChatCaps(caps).maxMessages);
  for (const receipt of selectedReceipts) {
    if (!Array.isArray(receipt?.msgRefs)) continue;
    const claimOptions = {
      chatWindow, selfUid: myUid, maxRefsPerReceipt, atomic: true,
    };
    const claim = claimMemo
      ? claimMemo.claim(receipt, targets, claimOptions)
      : receiptCoverClaim(receipt, targets, claimOptions);
    if (!claim.windowed) continue;
    for (const targetKey of claim.targetKeys) {
      const prior = firstTimeByTarget.get(targetKey);
      if (prior === undefined || receipt.timestamp < prior) {
        firstTimeByTarget.set(targetKey, receipt.timestamp);
      }
    }
  }
  const canonical = compare || ((a, b) => (a?.id || 0) - (b?.id || 0));
  const firstTimesByMessage = new Map(covered.map((message) => {
    const ref = msgRefOf(getClientMsgKey ? getClientMsgKey(message)
      : computeMsgKeyV2(blockNum, groupId, message));
    const first = firstTimeByTarget.get(`r:${ref}|${message.uid}`);
    return [message, first === undefined ? [] : [first]];
  }));
  return capMessagesByFirstReceipt(covered, caps,
    (message) => firstTimesByMessage.get(message), canonical);
}

// 自動既読と上限の外の判定が共有する受領の索引（自動既読の元の本体）。
function receiptableIndex(messages, receipts, {
  blockNum, groupId, myUid, chatWindow, caps, getClientMsgKey, memberUids,
}) {
  const inWindow = (message) => !chatWindow || (message.timestamp >= chatWindow.startMs
    && message.timestamp <= chatWindow.endMs);
  const windowed = (Array.isArray(messages) ? messages : []).filter((message) =>
    message?.uid !== myUid && inWindow(message));
  const roster = memberUids == null ? null : new Set(memberUids);
  const byTarget = new Map();
  for (const message of windowed) {
    const ref = msgRefOf(getClientMsgKey ? getClientMsgKey(message)
      : computeMsgKeyV2(blockNum, groupId, message));
    const key = `${message.uid}|${ref}`;
    if (!byTarget.has(key)) byTarget.set(key, message);
    else byTarget.set(key, null); // 衝突した参照に既読を対応付けない。
  }
  const timesByMessage = new Map();
  const ownCovered = new Set();
  const maxRefs = receiptMaxRefsPerReceipt(normalizeChatCaps(caps).maxMessages);
  for (const receipt of Array.isArray(receipts) ? receipts : Object.values(receipts || {})) {
    if (!Array.isArray(receipt?.msgRefs) || !isCanonicalSignature(receipt.signature)
      || !isCanonicalTimestamp(receipt.timestamp)
      || !isCanonicalUid(receipt.receiverUid) || !isCanonicalUid(receipt.senderUid)
      || receipt.msgRefs.length === 0 || receipt.msgRefs.length > maxRefs
      || !receipt.msgRefs.every(isMsgRef)
      || receipt.receiverUid === receipt.senderUid
      || (roster && !roster.has(receipt.receiverUid))
      || (chatWindow && !inWindow({ timestamp: receipt.timestamp }))) continue;
    for (const ref of receipt.msgRefs) {
      const message = byTarget.get(`${receipt.senderUid}|${ref}`);
      if (!message || !isReceiptTimely(receipt.timestamp, message.timestamp)) continue;
      let receivers = timesByMessage.get(message);
      if (!receivers) { receivers = new Map(); timesByMessage.set(message, receivers); }
      const prior = receivers.get(receipt.receiverUid);
      if (prior === undefined || receipt.timestamp < prior) receivers.set(receipt.receiverUid, receipt.timestamp);
      if (receipt.receiverUid === myUid) ownCovered.add(message);
    }
  }
  return { windowed, timesByMessage, ownCovered };
}

// 自動既読の候補。今この端末が鮮度内の既読を発行できる発言も、篩いの段で加える。
// cap の前に鮮度を確かめるため、逆日付の void 発言は正当な候補の枠を使えない。
export function clientReceiptableMessages(messages, receipts, {
  blockNum, groupId, myUid, timestamp, chatWindow = null, caps = {}, compare = null,
  getClientMsgKey = null, memberUids = null,
} = {}) {
  const { windowed, timesByMessage, ownCovered } = receiptableIndex(messages, receipts,
    { blockNum, groupId, myUid, chatWindow, caps, getClientMsgKey, memberUids });
  const eligible = windowed.filter((message) => timesByMessage.has(message)
    || isReceiptTimely(timestamp, message.timestamp));
  const capped = capMessagesByFirstReceipt(eligible, caps, (message) => {
    const known = timesByMessage.get(message);
    return known ? [...known.values()].sort((a, b) => a - b) : [timestamp];
  }, compare);
  return capped.filter((message) => !ownCovered.has(message)
    && isReceiptTimely(timestamp, message.timestamp));
}

// S3R4-U-OVERCAP: 宣言窓の内の他人の発言に、既知の最早既読順で上限を掛ける。時計は読まない。
// 既読の無い発言は最後（+∞）へ並べるため、上限付近の新しい発言を次の既読まで隠しうる。
// 画面・最優先欄の計画・提出に同じ集合を渡す。自分の発言は含めない。
export function clientReceiptCapExcluded(messages, receipts, {
  blockNum, groupId, myUid, chatWindow = null, caps = {}, compare = null,
  getClientMsgKey = null, memberUids = null,
} = {}) {
  const key = getClientMsgKey || buildMsgKeyGetter(blockNum, groupId);
  const cmp = compare || canonicalComparatorV2(key);
  const { windowed, timesByMessage } = receiptableIndex(messages, receipts,
    { blockNum, groupId, myUid, chatWindow, caps, getClientMsgKey, memberUids });
  const kept = new Set(capMessagesByFirstReceipt(windowed, caps, (message) => {
    const known = timesByMessage.get(message);
    return known ? [...known.values()].sort((a, b) => a - b) : [];
  }, cmp));
  const excluded = new Set();
  for (const message of windowed) if (!kept.has(message)) excluded.add(key(message));
  return excluded;
}

// 画面の表示（chatTimeline.js の buildChatTimeline の visible、ChatPhase.js の
// isTimestampVisible、game.js の visibleReadersByMsgKey）を自分以外の発言について
// 数え直す1か所。最優先欄の区切りの池（S3R4-U-MEMPOOL の2）。締切の前は
// 送り手以外の読み手（自分を含む）の既読が付いた発言だけを数える（R18・既読が付くまで数えない）。
// 締切の後は読み手の無い発言を記憶からだけ選ぶ（C-P2B2-1・CORR-03）。時計は読まない。
export function clientShownOtherMessageKeys(messages, receipts, {
  blockNum, groupId, myUid, chatWindow = null, hiddenMessageKeys = null, shownMessageKeys = null,
  atMs = null, closed = false, getClientMsgKey = null,
} = {}) {
  const key = getClientMsgKey || buildMsgKeyGetter(blockNum, groupId);
  const hidden = hiddenMessageKeys instanceof Set ? hiddenMessageKeys : null;
  const shown = shownMessageKeys instanceof Set ? shownMessageKeys : null;
  const list = (Array.isArray(messages) ? messages : []).filter((m) => m && m.uid != null);
  const visible = list.filter((m) => m.uid === myUid || !(hidden?.has(key(m)) && !shown?.has(key(m))));
  const { readersByMsgKey } = buildReceiptMaps(receipts, { messages: visible, myUid },
    blockNum, groupId, chatWindow, getClientMsgKey);
  const at = Number.isSafeInteger(atMs) ? atMs : null;
  const out = new Set();
  for (const m of visible) {
    if (m.uid === myUid) continue;
    if (at !== null && !(m.timestamp < at)) continue;
    const k = key(m);
    const readers = readersByMsgKey[msgRefOf(k)];
    const read = !!readers && [...readers].some((uid) => uid !== m.uid);
    const timely = closed === true && at !== null && isReceiptTimely(at, m.timestamp)
      && !!shown?.has(k);
    if (read || timely) out.add(k);
  }
  return out;
}

// 確定した宣言窓を持つクライアントの提出専用。他人の既読は窓外なら
// 包含差し替え・第2階層・自己集約のどれへも渡さない。null は判定保留。
export function clientWindowedReceipts(receipts, chatWindow, selfUid) {
  const source = Array.isArray(receipts) ? receipts : Object.values(receipts || {});
  if (!chatWindow) return source; // U-12: warn at the UI, keep submission possible
  return source.filter((receipt) => !(
    Array.isArray(receipt?.msgRefs) && receipt.receiverUid !== selfUid
    && (receipt.timestamp < chatWindow.startMs || receipt.timestamp > chatWindow.endMs)
  ));
}

// 上の actions 引数を、クライアントが持つ形（自分の発信＋観測した他人の発信）から組み立てる。
// 本体と復元クライアントで同じ集合になるよう、ここに1つだけ置く。
export function collectKnownActions({ myUid = null, myVote = null, myVotePrev = [], myReports = [], observedActions = {} } = {}) {
  const out = [];
  const push = (type, uid, a) => {
    // 🔴 P-2026-0842（2026-08-08）: **採点が採らない発信は「消費側」でも数えない。**
    //    DO（ライブ層）は同じ述語を課すが、**P2P（Nostr）経路は DO を通らない**ので、
    //    非パディングの発信を中継されると「画面には『〜が投票しました（既読n）』と出るのに
    //    採点では void」という表示≡採点の割れが起きる（K-S6-005 / P-2026-0836 と同型）。
    if (a && a.encrypted && a.timestamp != null && uid != null
      && isCanonicalActionCiphertext(a.encrypted)) {
      out.push({ type, uid, encrypted: a.encrypted, timestamp: a.timestamp });
    }
  };
  if (myUid != null) {
    push('vote', myUid, myVote);
    for (const v of (Array.isArray(myVotePrev) ? myVotePrev : [])) push('vote', myUid, v);
    for (const r of (Array.isArray(myReports) ? myReports : [])) push('report', myUid, r);
  }
  for (const [rawUid, v] of Object.entries(observedActions?.votes || {})) {
    const uid = rawUid.endsWith('__extras') ? rawUid.slice(0, -'__extras'.length) : rawUid;
    for (const a of (Array.isArray(v) ? v : [v])) push('vote', uid, a);
  }
  for (const [uid, arr] of Object.entries(observedActions?.reports || {})) {
    for (const a of (Array.isArray(arr) ? arr : [arr])) push('report', uid, a);
  }
  return out;
}

// 提出物に同梱してよい受領証明の判定材料（K-S6-002・2026-07-29）。
// 「自分のバンドルに実在する対象」の集合を作る。本体（SubmissionPhase.js）と
// 復元クライアント（chatgame-tools）が**同じ判定**をするよう、実装をここに1つだけ置く。
//
//   realRefs         : `${発信者uid}|${msgRef}`（自分が持っているチャットの参照）
//   realActionHashes : 自分のバンドルに入っている発信（投票/密告）の actionHash
//   refTimes         : `${発信者uid}|${msgRef}` -> 発言の**全主張時刻**
//   actionTimes      : actionHash -> 発信の**主張時刻**
//
// 実在しない対象を指す受領証明は採点側でも照合先が無く元から効かないため、
// 落としても結果は変わらない（＝安全に落とせる唯一の基準）。
//
// 🔴 J-40（2026-08-09）: 時刻表（`refTimes` / `actionTimes`）を足した。**引数は変えていない。**
//    採点は受領証明を受理する時点で鮮度（`isReceiptTimely` ±10分）を課す
//    （`game-result-calculator.js` の `carried` / 行動側の `isReceiptTimely(rc.timestamp, act.timestamp)`）
//    のに、提出物を組み立てるクライアントは「実在するか」しか見ていなかった。
//    その差のせいで**不鮮度な受領証明が (受領者, ref) の枠を先取りして本物を追い出す**
//    攻撃が成立していた（詳細は `receiptCanonCmp` のコメント）。
//    クライアントが枠を数えるための判定材料をここで配る。
//    ⚠️ **訂正（J-40b・2026-08-09）**: J-40 のコメントは「これで採点の `carried` と
//       **同じ集合**になる」と書いていたが、**事実として誤りだった**。足したのは
//       ①実在 ②鮮度 の2つだけで、採点が同じ受理ループで課している
//       **宣言窓（`inChatWindow`）を見ていなかった**（実測で冤罪失格が再現した）。
//       枠取りの述語は `receiptCoverClaim` に集約し、取りこぼしは
//       `receipt-slot-predicate-parity-test.mjs` が採点側ソースから機械抽出して検出する。
//       ⚠️ それでも「`carried` と完全に同じ集合」ではない —— 署名検証・予算・ペア枠は
//          意図的に課していない（理由は `receiptCoverClaim` のコメント）。
//    msgRef は msgKey の切り詰めなので、同じ `${uid}|${ref}` に別時刻の発言が理論上は入り得る。
//    v12 で16バイトへ拡張して現実的な衝突生成を封じたうえで、ここでは全時刻を保持し、
//    万一の衝突でも「既に成立した発言を後から void 化する」減る向きへ倒さない。
export function buildRealTargets(snapshot, messages, blockNum, groupId, getClientMsgKey = null) {
  const realRefs = new Set();
  const refTimes = new Map();
  for (const m of (Array.isArray(messages) ? messages : [])) {
    if (!m || m.uid == null) continue;
    const canon = { uid: m.uid, text: m.text ?? '', timestamp: m.timestamp };
    const key = `${m.uid}|${msgRefOf(getClientMsgKey ? getClientMsgKey(m) : computeMsgKeyV2(blockNum, groupId, canon))}`;
    realRefs.add(key);
    const times = refTimes.get(key);
    if (times) times.push(m.timestamp);
    else refTimes.set(key, [m.timestamp]);
  }

  const realActionHashes = new Set();
  const actionTimes = new Map();
  // 🔴 J-40b（2026-08-09）: 発信者 uid も配る。採点の受理段は
  //    `if (rc.receiverUid === act.actorUid) continue;`（行動側の自己受領）を課しており、
  //    その述語をクライアントが再現するには actionHash → 発信者の対応が要る。
  const actionActors = new Map();
  // R3-12: 自己受領集約は (発信者, 種別) ごとに正準先着を選ぶ。
  // actionHash から vote/report を復元できるよう、実在判定と同じ走査で配る。
  const actionTypes = new Map();
  const add = (type, actorUid, a) => {
    if (!a || !a.encrypted || !a.signature || a.timestamp == null) return;
    const h = actionHashV2(type, blockNum, groupId, actorUid, a.encrypted, a.timestamp);
    realActionHashes.add(h);
    actionTimes.set(h, a.timestamp);
    actionActors.set(h, actorUid);
    actionTypes.set(h, type);
  };
  const walk = (type, obj) => {
    for (const [rawUid, v] of Object.entries(obj || {})) {
      // 正規クライアントは __extras を基点uidへ畳んでから提出するが、
      // ローカル保存の形をそのまま渡された場合にも同じ結果になるようにする
      const actorUid = rawUid.endsWith('__extras') ? rawUid.slice(0, -'__extras'.length) : rawUid;
      for (const a of (Array.isArray(v) ? v : [v])) add(type, actorUid, a);
    }
  };
  walk('vote', snapshot?.votes);
  walk('report', snapshot?.reports);
  walk('vote', snapshot?.observed?.votes);
  walk('report', snapshot?.observed?.reports);

  return { realRefs, realActionHashes, refTimes, actionTimes, actionActors, actionTypes };
}

// S3R4-U-MEMPOOL の小問・C-P2B2-2: 他のメンバーの既読の受け入れは公式と復元で共有する。
// 指す先が全部届き、全部窓と鮮度の内にあるときだけ covered。窓外は即拒否し、未着だけなら待つ。
// 自分の既読は先の窓を見ず、従来どおり参照ごとに判定する。
export function clientReadReceiptAdmission(receipt, targets, {
  chatWindow = null, memberUids = null, selfUid = null, maxRefsPerReceipt = Infinity,
} = {}) {
  if (!Array.isArray(receipt?.msgRefs) || typeof receipt.senderUid !== 'string') return { state: 'invalid' };
  const keys = receipt.msgRefs.map((ref) => `${receipt.senderUid}|${ref}`);
  const windowed = chatWindow && Number.isSafeInteger(chatWindow.startMs) && Number.isSafeInteger(chatWindow.endMs);
  if (receipt.receiverUid !== selfUid && windowed && keys.some((key) => {
    if (!targets?.realRefs?.has(key)) return false;
    const times = targets.refTimes?.get(key);
    return (Array.isArray(times) ? times : [times]).some((ts) =>
      !(ts >= chatWindow.startMs && ts <= chatWindow.endMs));
  })) return { state: 'invalid' };
  if (!keys.every((key) => targets?.realRefs?.has(key))) return { state: 'pending' };
  const claim = receiptCoverClaim(receipt, targets, {
    memberUids, chatWindow, maxRefsPerReceipt, atomic: true, selfUid,
  });
  if (!claim.windowed || claim.keys.length === 0) return { state: 'invalid' };
  return { state: 'covered', facts: claim.keys };
}

// ============================================================
// 受領証明の「枠を消費してよいか」判定（J-40b・2026-08-09）
// ============================================================
// 🔴 **なぜ関数が1つ要るのか。**
//
// 提出物を組み立てるクライアント（本体 `SubmissionPhase.js` と そのミラー
// `chatgame-tools/src/recovery/bundle.js`）は、同梱する受領証明を
// `${receiverUid}|r:${ref}` / `${receiverUid}|a:${actionHash}` の**カバー枠**で先着1枚に絞る。
// この「枠を取ってよい受領証明」の集合が、採点（`game-result-calculator.js` の受理ループ）が
// 実際に採る集合より**広い**と、採点に効かない1枚が本物を枠から追い出せる
// ＝ **被害者の発言／投票が void になり、自損ゼロで冤罪失格を作れる**。
//
// この穴は同じ形で2回開いた:
//   K-S6-002 (f) 実在しない参照を見ていなかった → 実在ゲートを足した
//   J-40        鮮度（`isReceiptTimely`）を見ていなかった → 鮮度ゲートを足した
//   J-40b       宣言窓（`inChatWindow`）を見ていなかった → **本関数**
// 3回とも「述語を1つ手で写し忘れた」だけで、原因は**述語の一覧が人手の写経だった**こと。
// J-40 は並びを timestamp 昇順（`receiptCanonCmp`）に揃えたので、窓の取りこぼしは
// **grinding すら不要**にまで悪化していた（`window.startMs − 1` と書けば必ず先頭に来る）。
//
// なので述語を**この関数1つに集める**。クライアントは自前で述語を並べず、これを呼ぶ。
// 取りこぼしは `receipt-slot-predicate-parity-test.mjs` が機械的に検出する
// （採点側の受理ループのソースから `continue` 述語を抽出し、下の分類表と突き合わせる）。
//
// ------------------------------------------------------------
// 戻り値 `{ keys, windowed }` の意味 — **「載せるか」と「枠を取れるか」を分ける**
// ------------------------------------------------------------
//   keys     : この受領証明が主張しうるカバーキー。空 ＝ 採点に一切効かない（載せる意味が無い）
//   windowed : 宣言窓（`chatWindow`）の内側か。**false でも keys は返す**
//
// 🔴 窓を「載せない条件」にしてはいけない（J-26 の決定）。全員のクライアントが
//    `extendGrace` 前の古い窓を持っていた場合、正当な受領証明が**全員の提出物から同時に消えて
//    正典から失われる**。取り返しがつかない。だから呼出側は2階層で使うこと:
//      第1階層（windowed=true）… 枠（`covered`）を取る
//      第2階層（windowed=false）… 第1階層が取らなかったカバーだけを運ぶ（枠は取らない）
//    こうすると
//      ・攻撃（窓外の ts で本物を追い出す）… 本物が第1階層で枠を取るので追い出せない
//      ・J-26 の縮退（窓が古くて正当な受領証明が窓外に見える）… 第2階層が拾うので消えない
//    の両方が同時に満たされる。
//
// 🔴 **窓が読めないとき（`chatWindow = null`）は fail-open**（全件 windowed=true ＝ 従来どおり）。
//    ・fail-closed（全部落とす／全部第2階層）にすると、RPC 障害だけで
//      正直な参加者の受領証明が正典から消える。運営の攻撃より障害の方が起きやすい
//      （K-S6-006 で「一度もチェーンが読めない」縮退モードは既に受容済み）
//    ・**残るリスク（記録）**: チェーンを**一度も**読めなかったクライアントでは、
//      この窓ゲートが no-op になり J-40b の攻撃が復活する。ただし
//      「窓が古い（stale）」だけなら第2階層が本物を拾うので安全側に倒れる。
//      復活条件は「RPC 全滅 ＋ 同組に攻撃者」で、K-S6-006 が受容した縮退モードと同じ帯。
//
// ------------------------------------------------------------
// **意図的に課さない**述語（採点側にはあるが、ここには入れない）
// ------------------------------------------------------------
//   ・ECDSA 署名検証そのもの（`verifyMessage` / `!ok`）
//       … 非同期なのでこの同期関数では課せない。かつ**取り込み時に検証済み**
//         （`useGameWebSocket.verifyRelayInner` / `chatgame-tools` の `relay-verify.js`）。
//         署名が通らない受領証明はそもそも `receipts` に入らない。
//         ⚠️ ここで課さないことの帰結は「偽署名の1枚が枠を取る」ではなく
//            「取り込み層が漏らせば枠を取られる」＝**防御はそちらの層に置いてある**。
//   ・`seenSig` の重複排除／`examinedOf` の予算／ペア枠（`usedOf(pairKey) >= …`）／
//     `accepted` の全体重複／`fresh.length === 0`
//       … これらは**容量の会計**であって受領証明の適格性ではない。クライアントが先回りして
//         切り詰めると、採点が採ったはずの1枚を落としうる（＝過剰遮断）。
//         クライアント側の `covered` が「先着1枚」を実現しているのが対応物。
//
// @param rc       受領証明（`{receiverUid, senderUid, msgRefs, timestamp, signature}` または
//                 `{receiverUid, actionHash, timestamp, signature}`）
// @param targets  `buildRealTargets()` の戻り値
// @param opts     `{ memberUids, chatWindow, maxRefsPerReceipt, atomic, selfUid }`
//                 memberUids 未指定＝名簿検査を省く（採点は必ず課すので、渡せるなら渡すこと）
//                 maxRefsPerReceipt 未指定＝件数上限を課さない
//                 atomic は既定 false。true のとき他人の既読は全参照が実在かつ鮮度内でなければ
//                 丸ごと無効。自己発行分は従来どおり参照ごとに扱う。
export function receiptCoverClaim(rc, targets, opts = {}) {
  const NONE = { keys: [], targetKeys: [], windowed: false };
  const realRefs = targets?.realRefs;
  const refTimes = targets?.refTimes;
  const realActionHashes = targets?.realActionHashes;
  const actionTimes = targets?.actionTimes;
  const actionActors = targets?.actionActors;
  const memberUids = Array.isArray(opts.memberUids) ? opts.memberUids : null;
  const chatWindow = opts.chatWindow || null;
  const maxRefsPerReceipt = Number.isFinite(opts.maxRefsPerReceipt) ? opts.maxRefsPerReceipt : Infinity;

  // --- 共通（採点の受理ループが種別判定より前に課している述語）---
  if (!rc || !rc.signature || !rc.receiverUid || rc.timestamp == null) return NONE;
  if (!isCanonicalSignature(rc.signature)) return NONE;
  if (!isCanonicalTimestamp(rc.timestamp) || !isCanonicalUid(rc.receiverUid)) return NONE;
  // 採点の `!memberUids.includes(rc.receiverUid)` と `!bAddr`（名簿の blockAddress が引けない）
  // に対応する。クライアントが持つ名簿は採点が使う名簿と同一（R2 のロスター）。
  if (memberUids && !memberUids.includes(rc.receiverUid)) return NONE;

  // 採点本体の `inChatWindow` と同一式（両端を含む）。窓が無ければ常に true。
  const windowed = !chatWindow
    || (typeof rc.timestamp === 'number' && rc.timestamp >= chatWindow.startMs && rc.timestamp <= chatWindow.endMs);

  const keys = [];
  const targetKeys = [];
  if (Array.isArray(rc.msgRefs) && rc.senderUid != null) {
    // --- 既読受領証明 ---
    if (typeof rc.senderUid !== 'string') return NONE;
    if (rc.senderUid === rc.receiverUid) return NONE;                       // 自己受領
    // 件数上限は採点では受領証明を丸ごと捨てる述語。ここでも丸ごと捨てる
    // （残すと K-S6-002 が塞いだ**提出物肥大 DoS** がそのまま復活する — msgRefs 配列は
    //  カバーに使われない参照も含めて全部バイト列に載るため）。
    if (rc.msgRefs.length === 0 || rc.msgRefs.length > maxRefsPerReceipt) return NONE;
    if (!rc.msgRefs.every(isMsgRef)) return NONE;
    // 参照の走査順は採点と同じ `compareHexAsc` 昇順（採る集合は順序に依らないが揃えておく）
    for (const ref of [...rc.msgRefs].sort(compareHexAsc)) {
      const rk = `${rc.senderUid}|${ref}`;
      if (!realRefs || !realRefs.has(rk)) {
        if (opts.atomic === true && rc.receiverUid !== opts.selfUid) return NONE;
        continue;                                                             // 実在しない参照
      }
      const claimedTimes = refTimes ? refTimes.get(rk) : undefined;
      const timely = Array.isArray(claimedTimes)
        ? claimedTimes.some((ts) => isReceiptTimely(rc.timestamp, ts))
        : isReceiptTimely(rc.timestamp, claimedTimes); // 旧テスト／外部呼出しの number も受理
      if (!timely) {
        if (opts.atomic === true && rc.receiverUid !== opts.selfUid) return NONE;
        continue;                                                             // 不鮮度
      }
      const k = `${rc.receiverUid}|r:${ref}`;
      if (!keys.includes(k)) keys.push(k);
      const targetKey = `r:${ref}|${rc.senderUid}`;
      if (!targetKeys.includes(targetKey)) targetKeys.push(targetKey);
    }
  } else if (isActionHash(rc.actionHash)) {
    // --- 行動（投票・密告）受領証明 ---
    if (!realActionHashes || !realActionHashes.has(rc.actionHash)) return NONE;   // 実在しない発信
    const actorUid = actionActors ? actionActors.get(rc.actionHash) : undefined;
    if (actorUid !== undefined && rc.receiverUid === actorUid) return NONE;       // 自己受領
    const at = actionTimes ? actionTimes.get(rc.actionHash) : undefined;
    if (!isReceiptTimely(rc.timestamp, at)) return NONE;                          // 不鮮度
    keys.push(`${rc.receiverUid}|a:${rc.actionHash}`);
    targetKeys.push(`a:${rc.actionHash}`);
  } else {
    return NONE;                                                                  // どちらの種別でもない
  }
  if (keys.length === 0) return NONE;
  return { keys, targetKeys, windowed };
}

// 提出物へ同梱する受領証明を選ぶ（J-40b・本体とミラーで**この1本**を共有する）。
//
// 入力の `receipts` は任意順でよい。内部で採点と同じ正準順序（`receiptCanonCmp` — 呼出側が
// 渡す。正典は `game-result-calculator.js` にあり、循環 import を避けるため注入する）に並べ、
//   第1階層: 宣言窓の内側の受領証明が `covered` を先着で取る
//   第2階層: 窓の外の受領証明は、第1階層が取らなかったカバーだけを運ぶ（枠は取らない）
// の順に採る。他人の既読は全参照の有効性を先に検査し、無効な束にはどちらの階層でも
// 枠を与えない。戻り値は**正準順序**の配列（正常系では従来と1バイトも変わらない）。
//
// ⚠️ 出力の白名簿（載せるフィールドの絞り込み）は呼出側が行う（P-2026-0840）。
export function selectBundleReceipts(receipts, targets, opts = {}) {
  const cmp = opts.compare;
  const list = (Array.isArray(receipts) ? receipts : Object.values(receipts || {}))
    .filter((rc) => rc && rc.signature);
  const sorted = typeof cmp === 'function' ? [...list].sort(cmp) : list;
  const claims = sorted.map((rc) => ({ rc, claim: receiptCoverClaim(rc, targets, { ...opts, atomic: opts.atomic !== false }) }));
  const covered = new Set();
  const keep = new Set();
  for (const { rc, claim } of claims) {
    if (!claim.windowed) continue;
    let addsNew = false;
    for (const k of claim.keys) if (!covered.has(k)) { covered.add(k); addsNew = true; }
    if (addsNew) keep.add(rc);
  }
  // 第2階層。`coveredOut` を別に持つのは、窓外どうしでも同じカバーを何千枚も運ばせないため
  // （運ぶ枚数の上限は「カバーキーの数」＝第1階層と同じ有界性）。
  const coveredOut = new Set();
  for (const { rc, claim } of claims) {
    if (claim.windowed) continue;
    let addsNew = false;
    for (const k of claim.keys) {
      if (covered.has(k) || coveredOut.has(k)) continue;
      coveredOut.add(k); addsNew = true;
    }
    if (addsNew) keep.add(rc);
  }
  return sorted.filter((rc) => keep.has(rc));
}

// 行動受領証明の到着順の包含・先着述語。公式の待ち行列で使う。
// rivals は同じ発行者の受理済み候補。真の包含だけが先着を差し替えられる。
export function receiptArrivalContainment(facts, rivals, candidate = null, chatCloseAt = null) {
  const mine = facts instanceof Set ? facts : new Set(facts);
  const conflicts = rivals.filter((rival) => {
    for (const fact of rival.facts) if (mine.has(fact)) return true;
    return false;
  });
  if (conflicts.length === 0) return { admit: true, superseded: [] };
  if (candidate?.actionHash && Number.isSafeInteger(chatCloseAt)) {
    const eligible = (receipt) => mayCarryActionReceipt(receipt, chatCloseAt);
    const stamp = (receipt) => Number.isSafeInteger(receipt?._chainSeenAt)
      ? receipt._chainSeenAt : Number.isSafeInteger(receipt?._deviceSeenAt)
        ? receipt._deviceSeenAt : Infinity;
    const candidateEligible = eligible(candidate);
    const supersede = conflicts.every((rival) => {
      const rivalEligible = eligible(rival.receipt);
      if (candidateEligible !== rivalEligible) return candidateEligible;
      if (candidateEligible && stamp(candidate) !== stamp(rival.receipt)) {
        return stamp(candidate) < stamp(rival.receipt);
      }
      return rival.facts.size < mine.size && [...rival.facts].every((fact) => mine.has(fact));
    });
    return { admit: supersede, superseded: supersede ? conflicts : [] };
  }
  const admit = conflicts.every((rival) => (
    rival.facts.size < mine.size && [...rival.facts].every((fact) => mine.has(fact))
  ));
  return { admit, superseded: admit ? conflicts : [] };
}

export const PARTIAL_READ_RECEIPT_ALERT_THRESHOLD = 5;
// Count distinct signed receipts, across the entire observed game, that have a
// strict partial overlap with another receipt from the same issuer.
export function partialReadReceiptAlerts(receipts) {
  const byIssuer = new Map();
  for (const rc of Array.isArray(receipts) ? receipts : Object.values(receipts || {})) {
    if (!rc?.signature || typeof rc.receiverUid !== 'string' || typeof rc.senderUid !== 'string'
        || !Array.isArray(rc.msgRefs)) continue;
    if (!byIssuer.has(rc.receiverUid)) byIssuer.set(rc.receiverUid, new Map());
    byIssuer.get(rc.receiverUid).set(rc.signature, rc);
  }
  const alerts = {};
  for (const [uid, signed] of byIssuer) {
    const list = [...signed.values()];
    const partial = new Set();
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) {
      const a = list[i], b = list[j];
      if (a.senderUid !== b.senderUid) continue;
      const left = new Set(a.msgRefs), right = new Set(b.msgRefs);
      let shared = false, leftOnly = false, rightOnly = false;
      for (const ref of left) { if (right.has(ref)) shared = true; else leftOnly = true; }
      for (const ref of right) if (!left.has(ref)) { rightOnly = true; break; }
      if (shared && leftOnly && rightOnly) { partial.add(a.signature); partial.add(b.signature); }
    }
    if (partial.size >= PARTIAL_READ_RECEIPT_ALERT_THRESHOLD) alerts[uid] = partial.size;
  }
  return alerts;
}

export class PartialReadReceiptTracker {
  constructor() { this.byIssuer = new Map(); }
  add(rc) {
    if (!rc?.signature || typeof rc.receiverUid !== 'string' || typeof rc.senderUid !== 'string'
        || !Array.isArray(rc.msgRefs)) return 0;
    let group = this.byIssuer.get(rc.receiverUid);
    if (!group) { group = { signed: new Map(), partial: new Set() }; this.byIssuer.set(rc.receiverUid, group); }
    if (group.signed.has(rc.signature)) return group.partial.size;
    const left = new Set(rc.msgRefs);
    for (const other of group.signed.values()) {
      if (other.senderUid !== rc.senderUid) continue;
      const right = new Set(other.msgRefs);
      let shared = false, leftOnly = false, rightOnly = false;
      for (const ref of left) { if (right.has(ref)) shared = true; else leftOnly = true; }
      for (const ref of right) if (!left.has(ref)) { rightOnly = true; break; }
      if (shared && leftOnly && rightOnly) {
        group.partial.add(rc.signature);
        group.partial.add(other.signature);
      }
    }
    group.signed.set(rc.signature, rc);
    return group.partial.size;
  }
}

export function admitReadReceiptsByArrival(receipts, targets, opts = {}) {
  const source = Array.isArray(receipts) ? receipts : Object.values(receipts || {});
  const ordered = source.map((rc, index) => ({ rc, index }))
    .sort((a, b) => (a.rc?._seq ?? a.index) - (b.rc?._seq ?? b.index) || a.index - b.index);
  const accepted = [];
  for (const { rc } of ordered) {
    if (!Array.isArray(rc?.msgRefs) || rc.receiverUid === opts.selfUid) {
      accepted.push(rc);
      continue;
    }
    const claimOptions = { ...opts, atomic: true };
    const claim = opts.claimMemo
      ? opts.claimMemo.claim(rc, targets, claimOptions)
      : receiptCoverClaim(rc, targets, claimOptions);
    if (claim.keys.length === 0) continue;
    // 宣言窓外は既存の第2階層でだけ運ぶ。
    accepted.push(rc);
  }
  return accepted;
}

// チャットの既読受領証明（msgRefバッチ明示列挙・昇順ソート済み配列）。
// 累積プレフィックス方式は不採用（提出物リストへの挿入で検証が壊れない・部分受領に頑健）。
export function readReceiptSignString(blockNum, groupId, receiverUid, senderUid, msgRefs, timestamp) {
  return JSON.stringify({
    type: 'read_receipt',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid: receiverUid,
    senderUid,
    msgRefs: [...msgRefs].sort(compareHexAsc),
    timestamp
  });
}

// 在席通知（v3.3追補・P2P/WS共通）: active / away の状態変化を署名付きで配る。
// 採点には一切使わない（サーバー/他人が在席を証明する材料にはならない）。UI表示専用。
// 署名するのは「他人が勝手に他人をオフラインにできない」ようにするため。
export function presenceSignStringV2(blockNum, groupId, uid, state, timestamp) {
  return JSON.stringify({
    type: 'presence',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    state,
    timestamp
  });
}

// 旧 sendkey（v2）の署名文字列。D-08（S3C15）で P2P の sendkey 配布を削除し、
// 現行の uid と Nostr 鍵は応募時の blockAddress.nostrPubkey と検証済み名簿で束縛する。
// この関数は採点・提出物に無関係で、次の周で整理する。
export function sendkeySignStringV2(blockNum, groupId, uid, nostrPubkey, encryptedFor, timestamp) {
  return JSON.stringify({
    type: 'sendkey',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    nostrPubkey,
    encryptedFor,
    timestamp
  });
}

// 旧 sendkey_reshare 要求（R6: 署名必須＝応答増幅の抑止。wantUid=欲しい鍵の持ち主）。
// D-08（S3C15）で削除した仕組みの関数。採点と提出物に無関係で、次の周で整理する。
export function reshareReqSignStringV2(blockNum, groupId, uid, wantUid, timestamp) {
  return JSON.stringify({
    type: 'sendkey_reshare_req',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    wantUid,
    timestamp
  });
}

// 旧 sendkey_reshare 応答（uid=応答者・forUid=要求者・wantUid=鍵の持ち主）。
// D-08（S3C15）で削除した仕組みの関数。採点と提出物に無関係で、次の周で整理する。
export function reshareSignStringV2(blockNum, groupId, uid, forUid, wantUid, encryptedFor, timestamp) {
  return JSON.stringify({
    type: 'sendkey_reshare',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid,
    forUid,
    wantUid,
    encryptedFor,
    timestamp
  });
}

// ============================================================
// msgKey / 正準順序 / chatHash v2（§2.1〜§2.3）
// ============================================================

// msgKey = keccak256(署名対象文字列)。署名検証合格＝msgKey真正性の保証。
// 重複排除キー・ソート最終タイブレーカー・chatHash構成要素を1つで兼ねる。
export function computeMsgKeyV2(blockNum, groupId, msg) {
  return keccak256(toBytes(chatSignStringV2(blockNum, groupId, msg.uid, msg.text, msg.timestamp)));
}

// メッセージオブジェクト→msgKey のキャッシュ付きゲッター（keccak再計算の抑制）
export function buildMsgKeyGetter(blockNum, groupId) {
  const cache = new WeakMap();
  return (m) => {
    let k = cache.get(m);
    if (k === undefined) {
      k = computeMsgKeyV2(blockNum, groupId, m);
      cache.set(m, k);
    }
    return k;
  };
}

// 正準順序（§2.2）: (timestamp昇順) → (uid昇順・文字列) → (msgKey昇順・BigInt)
export function canonicalComparatorV2(getMsgKey) {
  return (a, b) => {
    const ta = Number(a?.timestamp) || 0;
    const tb = Number(b?.timestamp) || 0;
    if (ta !== tb) return ta - tb;
    const ua = String(a?.uid ?? '');
    const ub = String(b?.uid ?? '');
    if (ua !== ub) return ua < ub ? -1 : 1;
    const ka = BigInt(getMsgKey(a));
    const kb = BigInt(getMsgKey(b));
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  };
}

// 正準順序ソート（元配列は変更しない）
export function sortCanonicalV2(messages, blockNum, groupId) {
  const getKey = buildMsgKeyGetter(blockNum, groupId);
  return [...messages].sort(canonicalComparatorV2(getKey));
}

// chatHash（規則版13）: 正準順 (timestamp, uid, msgKey) の各 (msgKey, 発言署名) を
// ASCII/UTF-8 文字列 `coinu:chat-hash:v3|0x<64小文字hex>:0x<130小文字hex>|...`
// として keccak256。接頭辞が非hexなので1件も viem の hex 復号にはならない。
// `:` と `|` は固定長 hex フィールドの区切り。空集合だけは文字列 '0x'。
// 署名は入口で正準な65バイト小文字hexに制限する。msgKey 自体は署名を含めず維持する。
export function computeChatHashV2(messages, blockNum, groupId) {
  if (!messages || messages.length === 0) return '0x';
  const getKey = buildMsgKeyGetter(blockNum, groupId);
  const sorted = [...messages].sort(canonicalComparatorV2(getKey));
  return keccak256(toBytes(`coinu:chat-hash:v3|${sorted.map(m => `${getKey(m)}:${m.signature}`).join('|')}`));
}

// msgKeyによる重複排除＋正準順序ソート（§2.5 マージ手順の3-4）
export function dedupAndSortV2(messages, blockNum, groupId, getClientMsgKey = null) {
  const getKey = getClientMsgKey || buildMsgKeyGetter(blockNum, groupId);
  const byKey = new Map();
  for (const m of messages) {
    if (!m || m.uid == null) continue;
    const k = getKey(m);
    if (!byKey.has(k)) byKey.set(k, m);
  }
  return [...byKey.values()].sort(canonicalComparatorV2(getKey));
}

// ============================================================
// 汎用ヘルパー
// ============================================================

// U-18: only the chain clock observed when the receipt arrives decides whether
// the arrival was during chat. The device clock is used only while chain time
// cannot be read. This metadata is local and is never signed into a submission.
export function isActionReceiptDuringChat(chatCloseAt, chainTimeMs, deviceTimeMs) {
  if (!Number.isSafeInteger(chatCloseAt)) return true; // U-12: unknown window is fail-open
  if (Number.isSafeInteger(chainTimeMs)) return chainTimeMs <= chatCloseAt;
  return Number.isSafeInteger(deviceTimeMs)
    && deviceTimeMs <= chatCloseAt;
}

export function markActionReceiptSource(receipt, {
  source = 'device', chatCloseAt = null, chainTimeMs = null, nowMs = Date.now(),
} = {}) {
  if (!receipt || typeof receipt.actionHash !== 'string' || Array.isArray(receipt.msgRefs)) return receipt;
  const stored = source === 'storage';
  const chainSeenAt = stored && Number.isSafeInteger(receipt._chainSeenAt) ? receipt._chainSeenAt : null;
  const deviceSeenAt = stored && Number.isSafeInteger(receipt._deviceSeenAt) ? receipt._deviceSeenAt : null;
  const arrivedDuringChat = !stored && isActionReceiptDuringChat(chatCloseAt, chainTimeMs, nowMs);
  const useChain = arrivedDuringChat && Number.isSafeInteger(chainTimeMs);
  const useDevice = arrivedDuringChat && !useChain;
  const { _firstArrivalAt: _arrivalOnly, ...cleanReceipt } = receipt;
  return { ...cleanReceipt,
    _chainSeenAt: useChain ? chainTimeMs : chainSeenAt,
    _deviceSeenAt: useDevice ? nowMs : deviceSeenAt,
    _chatSources: [
      ...(useChain || chainSeenAt !== null ? ['chain'] : []),
      ...(useDevice || deviceSeenAt !== null ? ['device'] : []),
    ],
  };
}

export function mayCarryActionReceipt(receipt, chatCloseAt) {
  if (!receipt?.actionHash) return true;
  if (!Number.isSafeInteger(chatCloseAt)) return true; // U-12
  const chain = Number.isSafeInteger(receipt._chainSeenAt) ? receipt._chainSeenAt : null;
  const device = Number.isSafeInteger(receipt._deviceSeenAt) ? receipt._deviceSeenAt : null;
  return (chain !== null && isActionReceiptDuringChat(chatCloseAt, chain, null))
    || (device !== null && isActionReceiptDuringChat(chatCloseAt, null, device));
}

export function clientChatSourcedReceipts(receipts, chatWindow, chatCloseAt = null) {
  // chatWindow.endMs includes the ±120s scoring allowance; only the separate,
  // declared chatCloseAt may decide provenance. Missing close follows U-12.
  const source = Array.isArray(receipts) ? receipts : Object.values(receipts || {});
  return source.filter((receipt) => mayCarryActionReceipt(receipt, chatCloseAt));
}

export function mergeActionReceiptSources(old, incoming) {
  if (!old?.actionHash) return old;
  const earlier = (a, b) => Number.isSafeInteger(a) && Number.isSafeInteger(b)
    ? Math.min(a, b) : Number.isSafeInteger(a) ? a : Number.isSafeInteger(b) ? b : null;
  const chainSeenAt = earlier(old._chainSeenAt, incoming?._chainSeenAt);
  const deviceSeenAt = earlier(old._deviceSeenAt, incoming?._deviceSeenAt);
  const receivedAt = earlier(old._receivedAt, incoming?._receivedAt);
  return { ...old, _chainSeenAt: chainSeenAt, _deviceSeenAt: deviceSeenAt,
    ...(receivedAt !== null ? { _receivedAt: receivedAt } : {}),
    _chatSources: [...(chainSeenAt !== null ? ['chain'] : []), ...(deviceSeenAt !== null ? ['device'] : [])] };
}

// 0x hex を BigInt として昇順比較（null は最後）
/// uid・senderUid のような**非16進の文字列**を昇順に並べる全順序比較。
///
/// 🔴 `compareHexAsc` は `BigInt()` に食わせるので16進以外では throw する。
///    uid は `[0-9]` の10進文字列だが、将来の ID 体系変更に耐えるよう
///    ここでは**コード単位の辞書順**にしておく。ASCII の範囲では
///    JS（UTF-16 コード単位）と Rust（UTF-8 バイト）の順序が一致する。
/// ⚠️ 非 ASCII が混ざると両者の順序が食い違う。uid は `isCanonicalUid` で
///    孤立サロゲートを弾いているが ASCII 強制ではないので、
///    **オンチェーンに載る配列の並びにこの比較を使う場合は ASCII を別途保証すること**
///    （`claim-data-codec.js` の `playerLeafKey` は `[0-9]{1,20}` を強制している）。
export function compareStrAsc(a, b) {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareHexAsc(a, b) {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  const av = BigInt(a);
  const bv = BigInt(b);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

// ============================================================
// low-s 強制（C4 belt-and-suspenders）
// ============================================================

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

// ECDSA署名（65バイト r||s||v の0x hex）の s が low-s（s <= n/2）であること。
// viem/正規クライアントの署名は常にlow-s。malleabilityで作った双子(n−s)を弾く。
export function isLowSSignature(signature) {
  if (typeof signature !== 'string' || !signature.startsWith('0x') || signature.length < 130) return false;
  try {
    const s = BigInt('0x' + signature.slice(66, 130));
    return s > 0n && s <= SECP256K1_HALF_N;
  } catch (e) {
    return false;
  }
}
