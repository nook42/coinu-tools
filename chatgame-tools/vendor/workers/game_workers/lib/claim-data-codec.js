// claim-data-codec.js — 請求データのオンチェーン公開フォーマット（K-S5-002 / 請求データ自己完結化）
//
// 何のためにあるか:
//   COINU の請求は TokenMining.claim / claimLockReward で行う。
//   オンチェーンには root（32バイト）しか無く、そこから proof は逆算できない。
//   proof を組み立てられるデータが R2（運営のサーバー）にしか無いと、
//   運営が R2 を消した時点で未請求の報酬が永久に請求不能になる。
//   そこで root 提出と同一の手続きで、請求に必要な最小データをチェーンに載せる。
//   仕様書: docs/ONCHAIN_CLAIM_DATA_SPEC.md / docs/CLAIM_LEAF_DEPOSITID_SPEC.md
//
// ★ bitcoinu-claimdata/2（2026-08-01・請求データ自己完結化）で変わったこと:
//   ① depositId を**プレイヤーごと**に持つ（旧版はフラットな全体集合で、所有者を持たなかった）
//   ② デポッターの葉が**プレイヤー単位1枚**になり、受取アドレスと個別配当額が葉から消えた
//   → **葉が blob の純関数**になった。EthLock を1件も読まずに root を再現できる
//      （`claimEntriesFromClaimData` から ledger 引数が消えたのがその証拠＝型で保証される）。
//      受取先と配当額は請求時に契約が EthLock から読む＝運営が差し替えられない。
//
// ★ bitcoinu-claimdata/3（2026-08-01・ZKP Stage 1 のための非圧縮化）で変わったこと:
//   **gzip をやめて生バイト列をそのままチャンク分割する。** 形式そのものは /2 と同一で、
//   変わったのは「圧縮するかどうか」だけ（マジックは BCD2 → BCD3）。
//   理由（`docs/ZKP_HANDOFF_FROM_CLAIM_LEAF.md` §3 の実測 ＋ `docs/ZKP_ROADMAP.md` §6）:
//     ・圧縮率が **6.8〜12.8% しかない**。varint 差分と20バイトのアドレスで情報密度が既に高い
//     ・DEFLATE は**ビット単位の Huffman 復号**で RISC-V に不利（100〜500 cycles/byte）。
//       Stage 1 の回路は keccak 約18,700回 ≒ 19 Mcycle と小さいため、
//       解凍 107 Mcycle を足すと**解凍が回路の主コストになって逆転する**
//     ・ガス増は通常ブロックでほぼゼロ（チャンク数が変わらない。calldata 差 ≒ $7/ブロック）
//   → 回路から DEFLATE が丸ごと消え、「バイト厳密に再現すべき表面積」も1つ減る。
//
// 何を載せ、何を載せないか:
//   載せる   … グループID / プレイヤーの uid・受取アドレス・分割前の報酬 / 適格 depositId の集合
//   載せない … デポッターの受取アドレスと按分の重み（どちらも depositId から EthLock を読めば分かる）
//
// サイズの要（実測で確認済み）:
//   depositId はプレイヤーごとに昇順に並べ、前との差分だけを varint で書く。
//
// ⚠️ このファイルは正典。block-verifier / chatgame-tools の vendor/ へコピーされる。

import { getAddress, keccak256, encodePacked, toHex } from 'viem';

/// フォーマット版数。manifest.rules の claimDataFormat と一致させ、
/// block-verifier の pins でも固定する（ずれたら FAIL する）。
export const CLAIM_DATA_FORMAT = 'bitcoinu-claimdata/3';
/// 先頭マジック（"BCD3"）。取得した bytes が本当にこの形式かを最初に弾く。
/// ⚠️ 版数を上げたらここも必ず上げること。上げないと旧形式の blob を新デコーダが
///    「それっぽく」読んで**別の木**を作る（root は出るが誰も請求できない）。
/// /3 で BCD2 → BCD3。**中身の並びは /2 と同一**だが、gzip をやめたので
/// 旧 blob（gzip 済み）を新デコーダに渡すと必ずマジック不一致で弾かれる＝これが版数ゲート。
const MAGIC = Uint8Array.from([0x42, 0x43, 0x44, 0x33]);
/// blob の上限。/2 までは gunzipBytes の cap（gzip 爆弾対策）だったが、
/// /3 は非圧縮なので **decodeClaimData の入口で直接**効かせる。
/// 実際にはチェーン側が `MAX_CLAIM_DATA_BYTES(98,304) × MAX_CLAIM_DATA_CHUNKS(16) = 1.5MB` に
/// 構造的に制限しているので、ここは多重防御。
export const MAX_DECODED_BYTES = 4 * 1024 * 1024;

/// デポッター葉の `to`。デポッター葉は受取先を持たない（請求時に EthLock から取る）。
/// TokenMining._requireDepositorLeaf が `address(0)` で葉を組むので、ここも 0 でなければならない。
export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/// デポッター葉の形式版数（manifest.rules で公開し、block-verifier の pins で固定する）。
export const DEPOSITOR_LEAF_FORMAT = 'bitcoinu-lock-owner-leaf/3';
/// デポッター按分の端数規則（同上）。全員切り捨て・端数は未配布。
export const DEPOSITOR_ROUNDING = 'floor-truncate';

// ============================================================
// varint（LEB128・protobuf 互換）
// ============================================================

class ByteWriter {
  constructor() { this.buf = []; }
  varint(n) {
    let v = BigInt(n);
    if (v < 0n) throw new Error('[claimdata] varint: negative value');
    // 🔴 エンコード側にも同じ 128 ビット天井を課す（`MAX_U128` の由来は下のコメント）。
    //    デコーダ（`ByteReader.varint` / `decodeClaimData` の depositId 累積）と
    //    Rust の `codec.rs`（u128）は 128 ビット超を **Err** にするので、ここを素通しにすると
    //    **自分のエンコーダが作った blob を自分のデコーダで読めない**状態になる
    //    （`normalizeGid` の P-2026-0820 C-5 と同型の穴。あちらは gid だけを塞いだ）。
    //    それをオンチェーンに publish すると、そのブロックの請求データは
    //    **誰も復元できない**（＝葉が作れず root も再現できない）。
    //    ここで throw すれば「publish 前に大きな音を立てて止まる」に変わる。
    //    ⚠️ 過剰遮断は無い: 実在の depositId は EthLock の連番で 2¹²⁸ には届かず、
    //       仮に届いてもデコーダが既に拒否するので**受理集合は1ビットも変わらない**。
    if (v > MAX_U128) throw new Error('[claimdata] varint exceeds 128 bits');
    for (;;) {
      const b = Number(v & 0x7fn);
      v >>= 7n;
      if (v === 0n) { this.buf.push(b); return this; }
      this.buf.push(b | 0x80);
    }
  }
  bytes(arr) { for (const b of arr) this.buf.push(b); return this; }
  get length() { return this.buf.length; }
  toUint8Array() { return Uint8Array.from(this.buf); }
}

// varint が表現してよい最大値（u128 いっぱい）。
// 🔴 P-2026-0811 A-2（2026-08-06）: 旧実装は shift 上限が 140n で **128ビットを超える値を
//    無制限に読めた**。Rust 側（`crates/scoring-core/src/codec.rs`）は u128 なので、
//    同じバイト列がパニック（debug）または上位ビット切り捨て（release）になり、
//    「JS は読めるのに Rust は別の木を作る」＝ ZKP が通らない/通ってはいけないものが通る、
//    という最悪の食い違いになる。**両方に同じ 128ビット上限**を入れて受理集合を揃えた。
//    ⚠️ この天井は `ByteWriter.varint`（エンコード）にも課してある
//       ＝「エンコード可能な集合 ⊆ デコード可能な集合」を depositId についても保つため。
const MAX_U128 = (1n << 128n) - 1n;

class ByteReader {
  constructor(bytes) { this.b = bytes; this.i = 0; }
  varint() {
    let shift = 0n, out = 0n;
    for (;;) {
      if (this.i >= this.b.length) throw new Error('[claimdata] truncated varint');
      const byte = this.b[this.i++];
      const chunk = BigInt(byte & 0x7f);
      // 桁あふれ（この chunk を shift だけずらすと 128 ビットを超える）は受け付けない
      // ＝ Rust の `chunk.leading_zeros() < shift` と同値
      if ((chunk << shift) > MAX_U128) throw new Error('[claimdata] varint exceeds 128 bits');
      out |= chunk << shift;
      if ((byte & 0x80) === 0) return out;
      shift += 7n;
      if (shift >= 128n) throw new Error('[claimdata] varint too long');
    }
  }
  num() {
    const v = this.varint();
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('[claimdata] varint exceeds safe integer');
    return Number(v);
  }
  bytes(n) {
    if (this.i + n > this.b.length) throw new Error('[claimdata] truncated bytes');
    const out = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return out;
  }
  get done() { return this.i >= this.b.length; }
}

function bytesToHexAddress(b) {
  let s = '0x';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
function hexAddressToBytes(addr) {
  const clean = addr.startsWith('0x') ? addr.slice(2) : addr;
  if (clean.length !== 40) throw new Error(`[claimdata] bad address length: ${addr}`);
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// uid は X（Twitter）のユーザーID＝数値文字列。ただし非数値でも壊れないようにする。
//   len=0 → 数値形式（varint が続く）／len>0 → その長さの生バイト列が続く
const enc = new TextEncoder();
const dec = new TextDecoder();
function writeUid(w, uid) {
  const s = String(uid);
  // ⚠️ len=0 は「数値形式が続く」印なので、生バイト列側で長さ0が現れてはならない。
  //    空 uid を生バイト側に流すと writer は varint(0) を書き、reader は続く
  //    アドレス20バイトの先頭を uid の varint として読む＝**例外を出さずに**
  //    1バイトずれた別の木ができる（fail-open）。ここで確実に潰す。
  if (s.length === 0) throw new Error('[claimdata] empty uid');
  // 🔴 P-2026-0818: **書く側も同じ形を強制する**（JS 自身が Rust で読めない blob を作れないように）。
  //    `encodeClaimData` も葉にするメンバーの uid を検査するのでここに非正準 uid は来ないが、
  //    「読めるが書けない」「書けるが読めない」の非対称を残さない。
  if (!CANONICAL_UID_RE.test(s)) {
    throw new Error(`[claimdata] non-canonical uid: ${JSON.stringify(s.slice(0, 32))} (expected [0-9]{1,20})`);
  }
  if (/^(0|[1-9][0-9]{0,19})$/.test(s) && BigInt(s) <= 0xffffffffffffffffn) {
    w.varint(0).varint(BigInt(s));   // 正準な10進表記（先頭0なし・uint64 内）
  } else {
    const raw = enc.encode(s);
    w.varint(raw.length).bytes(raw);
  }
}
// 🔴 P-2026-0818（2026-08-07）: uid の正準形。**`[0-9]{1,20}`**。
//    請求葉の鍵（`playerLeafKey`）が既にこの形を強制している（P-2026-0811 A-4）。
//    理由は「葉は `key` の**文字列**でソートされるが、その順序が
//    JS＝UTF-16 コード単位・Rust＝UTF-8 バイトで、非 ASCII uid では逆転する」から。
const CANONICAL_UID_RE = /^[0-9]{1,20}$/;

function readUid(r) {
  const len = r.num();
  const uid = (len === 0) ? r.varint().toString() : dec.decode(r.bytes(len));
  // 🔴 P-2026-0818: **デコード時にも正準形を要求する。**
  //    旧実装は無検査で、`uid="abc"` を含む blob を JS は「葉0件」として
  //    **デコード成功**にしていた。一方 Rust（`codec.rs` の `read_uid`）は
  //    報酬を読む前に `[0-9]{1,20}` を検査して `UnclaimableUid` で落とす。
  //    ＝ **公開データは読めるのに証明だけ作れない**（liveness の破れ）。
  //    実測 blob: 42434433000100010361626311111111111111111111111111111111111111110000
  //      JS   → decodedUid="abc", entries=0（成功）
  //      Rust → Err(UnclaimableUid)
  //    `claimEntriesForMember` が `fullReward <= 0` のとき uid の形式検査より**先に**
  //    空配列を返すため、報酬0の行では葉の側の検査に到達しなかったのが原因。
  //    ⚠️ 両実装とも fail-closed に揃える（受理を広げる方向ではない）。
  if (!CANONICAL_UID_RE.test(uid)) {
    throw new Error(`[claimdata] non-canonical uid: ${JSON.stringify(uid.slice(0, 32))} (expected [0-9]{1,20})`);
  }
  return uid;
}

// ============================================================
// 🔒 葉の正準形（契約が確定させたバイト列。SPEC §6-6）
//
// ここが**唯一の実装**。summary 経路・blob 経路・検証ツールが全部ここを通る。
// TokenMining.sol の _depositorLeafKey / _toString / _toHex と1バイトも違ってはならない。
// ズレると「root は一致するのに請求だけ Invalid proof で通らない」という最も気づきにくい壊れ方をする。
// ============================================================

/// 10進・前置ゼロ無し（Solidity `_toString` と同じ）。
function toDec(v) {
  const n = BigInt(v);
  if (n < 0n) throw new Error(`[claimdata] negative value in key: ${v}`);
  return n.toString();
}

/**
 * depositId 集合の正準形: **BigInt 昇順・重複排除・すべて > 0**。
 *
 * ⚠️ 文字列ソートにすると '10' < '9' で静かにずれ、契約の `require(id > prev)` と食い違う。
 * ⚠️ 重複排除は「BigInt の値」で行う（'007' と '7' は同じ ID）。
 * ⚠️ 想定外の値は throw する（fail-closed）。黙って落とすと setHash が契約の要求する
 *    適格集合と食い違い、そのプレイヤーのデポッターが**全員**請求不能になる。
 */
export function canonicalDepositIds(ids) {
  const seen = new Set();
  const out = [];
  for (const raw of (ids || [])) {
    const s = String(raw);
    if (!/^\d+$/.test(s)) throw new Error(`[claimdata] non-numeric depositId: ${JSON.stringify(s)}`);
    const v = BigInt(s);
    if (v <= 0n) throw new Error(`[claimdata] depositId must be > 0 (got ${s})`);
    const k = v.toString();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return out;
}

/**
 * 適格 depositId 集合のコミットメント。
 * Solidity: `keccak256(abi.encodePacked(depositIds))`（uint256[] の packed ＝各32バイト連結）。
 * 全32バイトを使う（16バイトに切る案は「集合を選ぶのは運営自身＝衝突攻撃 2^64 が成立し、
 * しかも検出を回避できる」ため撤回済み。SPEC §5-2）。
 */
export function depositorSetHash(sortedDepositIds) {
  if (!Array.isArray(sortedDepositIds) || sortedDepositIds.length === 0) {
    throw new Error('[claimdata] depositorSetHash: empty deposit set');
  }
  let prev = 0n;
  const ids = sortedDepositIds.map((x) => {
    const v = BigInt(x);
    // 契約の `require(id > prev, "depositIds must be ascending/unique")` と同一条件
    if (v <= prev) throw new Error('[claimdata] depositorSetHash: ids must be strictly ascending and > 0');
    prev = v;
    return v;
  });
  return keccak256(encodePacked(['uint256[]'], [ids]));
}

/**
 * プレイヤー葉の鍵。契約は `claim()` で鍵を verbatim に受けるので**契約側**の uid 形式制約は無い。
 *
 * 🔴 P-2026-0811 A-4（2026-08-06）: それでも uid を **`[0-9]{1,20}`** に狭める（fail-closed）。
 *    葉は `key` の文字列でソートするが、その順序が
 *      JS  … `Array.prototype.sort` ＝ **UTF-16 コード単位**の辞書順
 *      Rust… `str::cmp`             ＝ **UTF-8 バイト**の辞書順
 *    で、**非 ASCII の uid では逆転する**（BMP 外の文字は UTF-16 でサロゲート 0xD800 台、
 *    UTF-8 では 0xF0 台になるため、全角数字などとの大小が入れ替わる）。
 *    葉の並びが変われば Merkle root が変わり、
 *    **JS が提出した root を Rust（ZKP ゲスト）が再現できない**＝証明が永久に通らない。
 *    X の uid は数値文字列なので、正常系でこの検査に引っかかることは無い。
 *    ↔ Rust 側は `crates/scoring-core/src/codec.rs` の `read_uid` と
 *       `crates/scoring-core/src/leaf.rs` の `player_leaf_key` に同じ検査がある。
 */
export function playerLeafKey(blockNum, gid, uid) {
  const s = String(uid);
  if (!/^\d{1,20}$/.test(s)) {
    throw new Error(
      `[claimdata] playerLeafKey: uid must be 1-20 digits (got ${JSON.stringify(s)}) `
      + '— non-ASCII uids sort differently in JS(UTF-16) and Rust(UTF-8) and would break the merkle root'
    );
  }
  return `${toDec(blockNum)}_${toDec(gid)}_player_${s}`;
}

/**
 * デポッター葉に使える uid か（契約 TokenMining._parseUint と**同一条件**）。
 *
 * `_parseUint` は「1〜20桁の数字のみ・結果が 0 でないこと」しか受け付けない。
 * これを外れる uid で葉を作ると、鍵としては正しいのに **請求時に必ず revert する**
 * ＝ そのプレイヤーのデポッター配分が永久に取り出せなくなる。
 * 起きてはいけない状態なので、黙って葉を落とすのではなく throw する（fail-closed）。
 */
export function assertClaimableUid(uid) {
  const s = String(uid);
  if (!/^\d{1,20}$/.test(s) || BigInt(s) === 0n) {
    throw new Error(
      `[claimdata] uid ${JSON.stringify(s)} is not parseable by TokenMining._parseUint `
      + '(1-20 digits, non-zero) — a depositor leaf for it would be permanently unclaimable'
    );
  }
  return s;
}

/**
 * デポッター葉の鍵（プレイヤー単位・複数形 `depositors`）。
 * `setHash` は **0x を除いた小文字 hex 64文字**（Solidity `_toHex`）。
 *
 * ⚠️ `LockRewardClaimed` イベントに載る記帳用の鍵（`..._lock_owner_{lockId}`・**単数形**）とは別物。
 *    証明のための鍵と記帳のための鍵を分けている（SPEC §6-4）。
 */
export function depositorLeafKey(blockNum, gid, uid, setHash) {
  const s = String(setHash);
  const hex = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`[claimdata] depositorLeafKey: setHash must be lowercase hex64 (got ${s})`);
  }
  return `${toDec(blockNum)}_${toDec(gid)}_lock_owners_${assertClaimableUid(uid)}_${hex}`;
}

/** `Claimed` / `LockRewardClaimed` イベントに載る**記帳用**の鍵（ロック単位）。 */
export function depositorLedgerKey(blockNum, gid, depositId) {
  return `${toDec(blockNum)}_${toDec(gid)}_lock_owner_${toDec(depositId)}`;
}

// ============================================================
// 按分（正典の式。契約 TokenMining._payDepositor と一致させること）
// ============================================================

/** プレイヤー 50% / デポッター 50%。端数はデポッター側合計へ（従来どおり・変更なし）。 */
export function splitFullReward(fullReward) {
  const full = BigInt(fullReward);
  const playerShare = full / 2n;
  return { playerShare, depositorShareTotal: full - playerShare };
}

/**
 * デポッター1件の取り分。**全員切り捨て**（順序非依存・SPEC §7）。
 *
 * 旧規則は「最後の1人 = depositorShareTotal − Σ他」で順序依存だった。
 * 契約 `_payDepositor` は `(depositorShareTotal * myAmount) / totalDepWei` を計算するので、
 * 表示値（summary / D1）もこの式でなければ「表示額と実際に届く額が違う」ことになる。
 * 端数（最大 N−1 wei）は誰にも配られず未請求のまま残る。
 */
export function depositorShareOf(depositorShareTotal, amountWei, totalDepWei) {
  const total = BigInt(totalDepWei);
  if (total <= 0n) throw new Error('[claimdata] depositorShareOf: zero denominator');
  const amt = BigInt(amountWei);
  if (amt < 0n) throw new Error('[claimdata] depositorShareOf: negative amount');
  return BigInt(depositorShareTotal) * amt / total;
}

// ============================================================
// 葉の生成（summary 経路と blob 経路が共有する**唯一の実装**）
// ============================================================

/**
 * summary の member 行から「50/50 スプリット前の元報酬」を取り出す。
 * `full_btcu_reward` が無い旧データは player_share + depositor_share から復元する。
 * 壊れた値は null（＝葉にしない）。
 */
export function fullRewardOfMember(m) {
  try {
    if (m?.full_btcu_reward != null) return BigInt(m.full_btcu_reward);
    return BigInt(m?.player_share ?? m?.btcu_reward ?? '0') + BigInt(m?.depositor_share ?? '0');
  } catch { return null; }
}

/**
 * 1プレイヤー分の請求エントリー（＝Merkle の葉の材料）を作る **唯一の実装**。
 *
 * summary.json 経路（game-master-DO.collectClaimEntriesFromSummary）と
 * blob 経路（claimEntriesFromClaimData）がここを共有することで、
 * 「片方だけ直して root が食い違う」という最頻の事故を構造的に消す。
 *
 * 除外規則（両経路で完全に同一でなければならない）:
 *   ・fullReward が壊れている / ≤ 0 → **このプレイヤーは丸ごと葉にしない**（デポッター葉も出さない）
 *   ・受取アドレスが不正           → 同上
 *   ・金額 0 の葉は作らない（契約が amount > 0 を要求する）
 */
function assertPlainAsciiSummaryUid(uid) {
  // Rust json.rs の parse_member → plain_ascii: JSON の生文字列に非 ASCII / escape があれば Err。
  // JSON.stringify で必ず escape になる制御文字・引用符・逆斜線もここで拒む。
  // DEL (0x7f) は Rust の is_ascii と同じく許す。
  for (let i = 0; i < uid.length; i++) {
    const c = uid.charCodeAt(i);
    if (c < 0x20 || c > 0x7f || c === 0x22 || c === 0x5c) {
      throw new Error(`[claimdata] non-ASCII or escaped summary uid: ${JSON.stringify(uid.slice(0, 32))}`);
    }
  }
}

function summaryUidOfMember(member) {
  // Rust は userId 欠落を "undefined" にするが、存在する非文字列は parse_member で拒む。
  const value = member?.userId;
  if (value === undefined) return 'undefined';
  if (typeof value !== 'string') throw new Error('[claimdata] summary uid must be a string');
  assertPlainAsciiSummaryUid(value);
  return value;
}

export function claimEntriesForMember(blockNum, gid, uid, address, fullReward, depositIds) {
  const out = [];
  const u = String(uid);
  // Rust の summary parse_member は報酬を見る前にエスケープなしの ASCII だけを読む。
  // 葉を作るときの数字1〜20桁という制約は別（playerLeafKey / blob の readUid）。
  assertPlainAsciiSummaryUid(u);
  if (u.length === 0) return out;
  const full = (() => { try { return BigInt(fullReward); } catch { return null; } })();
  if (full == null || full <= 0n) return out;
  // 🔴 P-2026-0812（2026-08-06）: **文字列であることを先に要求する。**
  //    viem の `getAddress` は内部 LRU キャッシュをテンプレートリテラルでキーイングするので、
  //    `getAddress(["0x11…11"])` の結果が**同一プロセスで先に同じアドレスを文字列で
  //    checksum したかどうか**で変わる（実測）:
  //      冷えたプロセス            → TypeError → 葉にならない
  //      文字列で1回通した後       → "0x11…11" を返す → 葉ができる
  //    ＝ **正典が純関数でなくなり、同じ公開データから検証者ごとに違う Merkle root が出る**。
  //    JSON で `String(v)` が有効アドレスになりうる非文字列は配列だけなので、
  //    型を先に見るだけで塞がる（正規の summary.json は必ず文字列）。
  if (typeof address !== 'string') return out;
  let to;
  try { to = getAddress(address); } catch { return out; }
  if (!CANONICAL_UID_RE.test(u)) {
    throw new Error(`[claimdata] non-canonical uid: ${JSON.stringify(u.slice(0, 32))} (expected [0-9]{1,20})`);
  }

  const ids = canonicalDepositIds(depositIds);
  if (ids.length === 0) {
    // 適格 deposit なし → プレイヤーが全額
    out.push({ key: playerLeafKey(blockNum, gid, u), to, amount: full.toString() });
    return out;
  }

  const { playerShare, depositorShareTotal } = splitFullReward(full);
  if (playerShare > 0n) {
    out.push({ key: playerLeafKey(blockNum, gid, u), to, amount: playerShare.toString() });
  }
  if (depositorShareTotal > 0n) {
    // ★ gid / uid / depositIds を葉に添える（葉のハッシュには入らない付随情報）。
    //   TokenMining.claimLockReward は setHash ではなく **集合そのもの** を calldata で要求するが、
    //   setHash は一方向なので鍵から復元できない。R2 の leavesMeta / proof ファイルに
    //   ここから流し込んでおかないと、運営以外は請求引数を組み立てられなくなる。
    out.push({
      key: depositorLeafKey(blockNum, gid, u, depositorSetHash(ids)),
      to: ZERO_ADDRESS,
      amount: depositorShareTotal.toString(),
      gid: Number(gid),
      uid: u,
      depositIds: ids.map((v) => v.toString()),
    });
  }
  return out;
}

/** 決定的な順序（再実行で同一 root を得るため key でソート）。 */
function sortEntries(entries) {
  entries.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return entries;
}

/** gid の正準化。整数でない／負の group_id は葉にしない（両経路で同一規則）。
 *
 * 🔴 P-2026-0820（2026-08-07・C-5）: **`Number()` 強制をやめる。**
 *    旧実装は `Number(rawGid)` の暗黙変換で `"7"` / `"0x7"` / `"1e3"` / `null` / `""` /
 *    `[]` / `true` を受理し、さらに `Number.isInteger` なので 2⁵³ 超も通していた。実測:
 *      ・`group_id = "9007199254740993"` → **encode は成功するのに decode が
 *        `varint exceeds safe integer` で THROW** ＝ 自分のエンコーダが作った blob を
 *        自分のデコーダで読めない（`decodeClaimData` は `num()` と累積で安全整数を強制）
 *      ・`group_id = null` / `""` / `[]` / `false` → 黙って gid 0 になり、
 *        本物の group 0 と**葉の鍵が重複**する（`buildMerkleTree` の fail-closed が
 *        救済しているが、そこに頼るべきではない）
 *    デコーダ側（`num()` / 累積の安全整数チェック）は変更不要。ここを締めるだけで
 *    「エンコード可能な集合 ⊆ デコード可能な集合」が回復する。
 */
function normalizeGid(rawGid) {
  // 🔴 J-13 案B2（2026-08-08・ユーザー確定）: **null を返して skip する経路を廃止した。**
  //
  //    旧実装は数値でない `group_id` を `null` にし、呼び出し側が
  //    **そのグループを丸ごと飛ばして完走**していた。飛ばされたグループのメンバーは
  //    葉が作られない ＝ **永久に請求不能**なのに、ZKP の**証明は通る**
  //    （回路は自分のコードどおりに動いただけで、「このルートはこの summary.json から
  //    正しく導かれた」は真）。証明は「ファイルが正しいか」ではなく
  //    「ファイルからルートを正しく計算したか」しか保証しない。
  //    ＝ 運営は `"group_id": 2` を `"group_id": "2"` と書くだけ（引用符1組）で、
  //    証明を通したまま特定グループ全員の請求権を消せた。
  //    消された側からは自分の設定ミスと区別がつかない。
  //
  //    🔴 **skip をやめることが本質**。読めなかったら**ファイル全体を拒否**する。
  //    ⚠️ Rust 側（`crates/scoring-core/src/json.rs` の `parse_group`）も同じ規則。
  //      片側だけだと「JS は完走・Rust は停止」で証明が永久に通らない。
  if (typeof rawGid !== 'number' || !Number.isSafeInteger(rawGid) || rawGid < 0) {
    throw new Error(
      `[claim-data-codec] group_id is not a non-negative safe integer: ${JSON.stringify(rawGid)} `
      + '(summary.json must be canonical; skipping the group would silently make every member '
      + 'of it unclaimable while the ZKP proof still verifies)'
    );
  }
  return rawGid;
}

/**
 * summary.json の1グループから「プレイヤー uid → その適格 depositId 一覧」を作る。
 *
 * ⚠️ **btcuReward で絞ってはいけない。** 切り捨てで 0 wei になった極小デポジットを
 *    集合から落とすと setHash が契約の要求する適格集合と食い違い、
 *    そのプレイヤーのデポッターが**全員**請求不能になる（SPEC §6-2）。
 */
function depositIdsByPlayer(group) {
  const byUid = new Map();
  for (const d of (group?.depositor_results || [])) {
    const uid = String(d.playerUid);
    if (!byUid.has(uid)) byUid.set(uid, []);
    byUid.get(uid).push(d.depositId);
  }
  return byUid;
}

/**
 * 公開データ summary.json から請求エントリーを収集する（＝ツリーの入力を公表データに一致させる）。
 * game-master-DO.collectClaimEntriesFromSummary はこれを呼ぶだけ。
 *
 * @param {object} [stats] 省略可。渡すと {groups, players, skipped} が代入される（診断ログ用）
 */
export function claimEntriesFromSummary(blockNum, summary, stats) {
  const entries = [];
  let groups = 0, players = 0, skipped = 0;
  for (const group of (summary?.groups || [])) {
    // 🔴 J-13 案B2: 読めない `group_id` は throw（skip しない・上の `normalizeGid` 参照）
    const gid = normalizeGid(group?.group_id);
    const byUid = depositIdsByPlayer(group);
    let any = false;
    for (const m of (group.members || [])) {
      const uid = summaryUidOfMember(m);
      const got = claimEntriesForMember(
        blockNum, gid, uid, m?.address, fullRewardOfMember(m), byUid.get(uid) || []
      );
      if (got.length === 0) { skipped++; continue; }
      entries.push(...got);
      players++; any = true;
    }
    if (any) groups++;
  }
  if (stats) Object.assign(stats, { groups, players, skipped });
  return sortEntries(entries);
}

// ============================================================
// エンコード
// ============================================================

/**
 * summary.json から、請求に必要な最小データを組み立てる（gzip 前）。
 *
 * 葉になるのは claimEntriesForMember が拾う行だけなので、
 * **報酬0・アドレス無効のプレイヤーは丸ごと省く**（そのデポジットも葉にならない）。
 * 省く条件は claimEntriesFromSummary と**完全に同一**でなければならない
 * （食い違うと「チェーンから復元した root」と「summary から作った root」がずれる）。
 *
 * @param {number} blockNum
 * @param {object} summary  games/block{N}/summary.json の中身
 * @returns {{bytes: Uint8Array, stats: object}}
 */
export function encodeClaimData(blockNum, summary) {
  const w = new ByteWriter();
  w.bytes(MAGIC).varint(blockNum);

  const groups = [];
  for (const g of (summary?.groups || [])) {
    // 🔴 J-13 案B2: 読めない `group_id` は throw（skip しない）
    const gid = normalizeGid(g?.group_id);
    const byUid = depositIdsByPlayer(g);

    const members = [];
    for (const m of (g.members || [])) {
      // 除外条件は claimEntriesForMember と**同一**でなければならない。
      // 片方だけが落とすと「summary から作った root」と「blob から作った root」がずれる。
      const uid = summaryUidOfMember(m);
      if (uid.length === 0) continue;
      const full = fullRewardOfMember(m);
      if (full == null || full <= 0n) continue;                      // 葉にならない
      // 🔴 P-2026-0812: `claimEntriesForMember` と同じ理由で**型を先に見る**
      //    （viem の getAddress は LRU キャッシュ経由で非文字列に対する結果が
      //      実行順に依存する＝正典が純関数でなくなる）。
      if (typeof m.address !== 'string') continue;
      let addr;
      try { addr = hexAddressToBytes(getAddress(m.address)); } catch { continue; }  // 葉にならない
      if (!CANONICAL_UID_RE.test(uid)) {
        throw new Error(`[claimdata] non-canonical uid: ${JSON.stringify(uid.slice(0, 32))} (expected [0-9]{1,20})`);
      }
      members.push({ uid, addr, full, depositIds: canonicalDepositIds(byUid.get(uid) || []) });
    }
    if (members.length === 0) continue;
    groups.push({ gid, members });
  }

  groups.sort((a, b) => a.gid - b.gid);
  w.varint(groups.length);
  let prevGid = 0;
  let deposits = 0;
  for (const g of groups) {
    w.varint(g.gid - prevGid); prevGid = g.gid;
    w.varint(g.members.length);
    for (const m of g.members) {
      writeUid(w, m.uid);
      w.bytes(m.addr);
      w.varint(m.full);
      // ★ BCD2: そのプレイヤーの適格 depositId 集合（昇順・前との差分 varint）。
      //   差分の起点は**メンバーごとに 0 へリセット**する（プレイヤー間で昇順にはならないため）。
      w.varint(m.depositIds.length);
      let prev = 0n;
      for (const id of m.depositIds) { w.varint(id - prev); prev = id; }
      deposits += m.depositIds.length;
    }
  }

  return {
    bytes: w.toUint8Array(),
    stats: {
      format: CLAIM_DATA_FORMAT,
      groups: groups.length,
      players: groups.reduce((s, g) => s + g.members.length, 0),
      deposits,
      rawBytes: w.length,
    },
  };
}

// ============================================================
// デコード
// ============================================================

/** encodeClaimData の逆。壊れた入力は例外にする（黙って部分復元しない）。 */
export function decodeClaimData(bytes) {
  if (!bytes || bytes.length < 5) throw new Error('[claimdata] too short');
  // /3 で gzip をやめたため、gunzipBytes の cap が効かなくなった分をここで受け持つ。
  if (bytes.length > MAX_DECODED_BYTES) throw new Error('[claimdata] too large');
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new Error(`[claimdata] bad magic (not ${CLAIM_DATA_FORMAT})`);
  }
  const r = new ByteReader(bytes.subarray(MAGIC.length));
  const blockNum = r.num();

  const groupCount = r.num();
  const groups = [];
  const allIds = new Set();
  let gid = 0;
  for (let gi = 0; gi < groupCount; gi++) {
    // 🔴 P-2026-0812（2026-08-06）: **累積値**にも安全整数の上限を課す。
    //    `r.num()` は各デルタを `MAX_SAFE_INTEGER` で縛るが、`gid` は JS Number で
    //    累積するので合計が 2⁵³ を超えると**黙って丸まる**。Rust 側は `u64` なので
    //    丸まらず、**同じ blob から2つの Merkle root が出る**（両方とも「成功」を返す）。
    //    実測（デルタ `9007199254740991, 1, 1`）: 3番目の gid が
    //    JS `9007199254740992` / Rust `9007199254740993` → root `0x3ce8147e…` vs `0x445809d5…`。
    gid += r.num();
    if (!Number.isSafeInteger(gid)) throw new Error('[claimdata] group id exceeds safe integer');
    const memberCount = r.num();
    const members = [];
    for (let mi = 0; mi < memberCount; mi++) {
      const uid = readUid(r);
      const addr = bytesToHexAddress(r.bytes(20));
      const full = r.varint();
      const depCount = r.num();
      const depositIds = [];
      let prev = 0n;
      for (let di = 0; di < depCount; di++) {
        const delta = r.varint();
        // 差分 0 以下は「重複 or 非昇順 or id=0」＝契約が必ず弾く集合。
        // 黙って読むと請求不能な葉を作るので、ここで例外にする（fail-closed）。
        if (delta <= 0n) throw new Error('[claimdata] depositIds must be strictly ascending and > 0');
        prev += delta;
        // 🔴 P-2026-0811 A-2: 累積も 128ビットで打ち止め。Rust 側は u128 の
        //    `checked_add` で Err にするので、ここで通すと受理集合がずれる。
        if (prev > MAX_U128) throw new Error('[claimdata] depositId exceeds 128 bits');
        const s = prev.toString();
        depositIds.push(s);
        allIds.add(s);
      }
      members.push({ uid, address: getAddress(addr), fullReward: full, depositIds });
    }
    groups.push({ gid, members });
  }

  if (!r.done) throw new Error('[claimdata] trailing bytes after payload');

  // 全プレイヤーの適格 depositId の和集合（昇順）。バイト列には持たない**派生値**で、
  // block-verifier が EthLock 台帳を引くときの対象一覧に使う（L1 の検出に必要）。
  const depositIds = [...allIds].map((s) => BigInt(s)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    .map((v) => v.toString());

  return { blockNum, groups, depositIds };
}

// ============================================================
// 葉の復元（★ EthLock を1件も読まない＝葉が blob の純関数であることの証明）
// ============================================================

/**
 * デコード結果だけから請求エントリー（＝Merkle の葉の材料）を復元する。
 *
 * ★ **引数は decoded ひとつだけ。** EthLock の台帳を受け取らないこと自体が
 *   「root は blob の純関数である」という本改修の主目的を型で保証している
 *   （SPEC §10 T3）。ledger を足したくなったら設計が壊れている。
 *
 * @param {{blockNum:number, groups:Array}} decoded
 * @returns {Array<{key:string, to:string, amount:string}>} key 昇順
 */
export function claimEntriesFromClaimData(decoded) {
  if (arguments.length > 1) {
    throw new Error('[claimdata] claimEntriesFromClaimData takes no ledger — leaves are a pure function of the blob');
  }
  const { blockNum, groups } = decoded || {};
  if (!Array.isArray(groups)) throw new Error('[claimdata] decoded.groups missing');
  const entries = [];
  for (const g of groups) {
    for (const m of (g.members || [])) {
      entries.push(...claimEntriesForMember(blockNum, g.gid, m.uid, m.address, m.fullReward, m.depositIds));
    }
  }
  return sortEntries(entries);
}

// ============================================================
// チャンク分割（/3 以降、請求データは gzip しない）
// ============================================================
//
// ⚠️ `gzipBytes` / `gunzipBytes` は **請求データの経路では使わなくなった**（/3 で非圧縮化）。
//    export は残してあるが、これは Evidence の提出バンドル等の別経路が
//    同じ streaming ヘルパを必要としたときのため。
//    **請求データに対して呼び出さないこと**（呼ぶとマジックが合わずデコードで弾かれる）。

async function streamAll(bytes, stream, cap) {
  const piped = new Blob([bytes]).stream().pipeThrough(stream);
  const reader = piped.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (cap && total > cap) { await reader.cancel(); throw new Error('[claimdata] decompressed too large'); }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}

export async function gzipBytes(bytes) {
  return streamAll(bytes, new CompressionStream('gzip'), 0);
}
export async function gunzipBytes(bytes, cap = MAX_DECODED_BYTES) {
  return streamAll(bytes, new DecompressionStream('gzip'), cap);
}

/**
 * 「全体を gzip してからバイト分割」する（各チャンクを個別 gzip しない）。
 * 順に連結すれば元の gzip バイト列に戻る。
 */
export function splitChunks(bytes, maxBytes) {
  if (maxBytes <= 0) throw new Error('[claimdata] bad chunk size');
  const out = [];
  for (let i = 0; i < bytes.length; i += maxBytes) {
    out.push(bytes.subarray(i, Math.min(i + maxBytes, bytes.length)));
  }
  return out.length > 0 ? out : [bytes.subarray(0, 0)];
}

/// チャンク列の**連鎖ハッシュ**（契約 `TokenMining.publishClaimData` が積算するのと同じ規約）:
///   初期値     = bytes32(0)
///   全件       = keccak(acc ‖ keccak(chunk))
///   0件        = bytes32(0)
///
/// 🔴 P-2026-0838（2026-08-08・ラウンド19 判断不要-6）: この計算は
///     ・契約         `TokenMining.publishClaimData`
///     ・Rust         `crates/scoring-core/src/merkle.rs:79-94` の `chunk_chain_hash`
///     ・block-verifier `block-verifier/src/claim-data.js:53-60` の `runningHashOf`
///    の**3本が既にあったのに、正典 DO だけが持っていなかった**。
///    そのため `publishClaimDataOnChain` は「チャンク**本数**が同じか」だけで
///    「既に公開済み」を判定していた（`ref.dataHash` を読んでいるのに一度も比較していない）。
///    チャンク本数はデータ内容の同一性を表さず、正典 `MAX_DEPOSIT_IDS` から導出する
///    サイズ回帰では本番到達可能な入力も複数チャンクになる。したがって本数一致を
///    内容一致の代理にすると、チャンク数が同じまま内容だけ変わる再計算をスキップし得る。
///    結果、`claimDataOf[N].dataHash`（旧 blob）と `blockStates[N].merkleRoot`（新 root）が
///    食い違い、K-S5-002 が保証したはずの
///    「root がある ⟹ その root を再現できる請求データがチェーン上にある」が壊れる。
///    しかも自己修復不能（再実行しても同じ判定でまた `alreadyComplete`）で、
///    検証期間（4日）を過ぎると契約側の `require(block.timestamp < _verificationEndsAt)` で
///    revert ＝ **修復不能**になる。
export function chunkChainHash(chunks) {
  let h = `0x${'00'.repeat(32)}`;
  for (const c of chunks) {
    const leaf = keccak256(toHex(c));
    h = keccak256(encodePacked(['bytes32', 'bytes32'], [h, leaf]));
  }
  return h;
}

export function concatChunks(chunks) {
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}
