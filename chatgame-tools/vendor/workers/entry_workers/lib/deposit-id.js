// workers/entry_workers/lib/deposit-id.js
//
// K-S4-002（外部監査 S4・2026-07-29）: depositId の正準化。
//
// 背景:
//   旧実装は1エントリー内の depositId 重複排除を `String(id)` の**字面**で行っていた。
//   そのため `"123"` `"0123"` `"00123"` … は別IDとして残る一方、RPC calldata は数値化して
//   作るので**全部が同じオンチェーンデポジットを読む**。上限50件まで並べれば、
//   1件のデポジットを50回再計上できた（0.01 ETH なら 10pt → 70pt、
//   10 ETH なら 316pt → 2,236pt）。BTCu 配分はポイント比例なのでそのまま不当報酬になる。
//
// 方針:
//   受付直後に「10進数字のみ・uint256 範囲」を検査し、`BigInt(id).toString(10)` へ
//   正準化してから重複排除・保存する。K-S2-002 で「エントリー時の depIds が権威」に
//   なったため、**入口はここ1箇所**。ここで潰しておけば、集計側や block-verifier が
//   字面で dedup していても別IDに割れない。

export const MAX_UINT256 = (1n << 256n) - 1n;
// uint256 の10進最大桁数（2^256-1 は78桁）
export const MAX_DECIMAL_DIGITS = 78;

/**
 * depositId 1件を正準10進表記へ。不正なら Error を throw する。
 *
 * 受理する型は **文字列 / bigint / 安全整数の number** だけ。
 * 文字列は「10進数字のみ」（前後の空白は許容）。
 * 先頭ゼロは正準化され、16進表記・指数表記・符号・小数点は拒否する。
 *
 * 🔴 外部レビュー（2026-08-07・①③）で実測された穴:
 *   ・旧実装は `String(raw)` で何でも受けたため、`9007199254740993`（2^53+1）を
 *     **number で渡すと 9007199254740992 へ丸められ**、別のデポジットの ID として
 *     正常に受理されていた（実行時値も出力も丸め後の値）。
 *     Number.isSafeInteger を満たさない number は必ず throw する。
 *   ・`[[123]]` のような入れ子配列も `String([123]) === "123"` で正規 ID になっていた。
 *     配列・オブジェクト・null・undefined・boolean・symbol は型の時点で拒否する。
 */
export function canonicalizeDepositId(raw) {
  let str;
  if (typeof raw === 'bigint') {
    if (raw < 0n) throw new Error(`Invalid depositId: ${raw.toString(10).slice(0, 32)}`);
    str = raw.toString(10);
  } else if (typeof raw === 'number') {
    // 非安全整数（既に桁落ちしている可能性がある）・小数・NaN・Infinity は拒否。
    if (!Number.isSafeInteger(raw) || raw < 0) {
      throw new Error(`Invalid depositId: ${String(raw).slice(0, 32)}`);
    }
    str = String(raw);
  } else if (typeof raw === 'string') {
    str = raw.trim();
  } else {
    throw new Error(`Invalid depositId type: ${Object.prototype.toString.call(raw)}`);
  }
  if (!/^[0-9]+$/.test(str) || str.length > MAX_DECIMAL_DIGITS) {
    throw new Error(`Invalid depositId: ${str.slice(0, 32)}`);
  }
  const big = BigInt(str);
  if (big > MAX_UINT256) {
    throw new Error(`depositId out of uint256 range: ${str.slice(0, 32)}`);
  }
  // 🔴 P-2026-0817（2026-08-07）: **0 を拒否する**（契約が発行する ID は必ず 1 以上）。
  //    `EthLock.lockETH` は `lastLockId++` してから代入するので
  //    `depositId == 0` は存在しない。にもかかわらずエントリー側だけが `0` を受理しており、
  //    請求側の正典 `claim-data-codec.js` の `canonicalDepositIds` は
  //    `if (v <= 0n) throw` で**必ず弾く**。
  //    ＝ **受理されるのに永久に請求できないエントリー**が作れる状態だった（fail-open）。
  //    受理する側と請求する側で同じ集合にする。
  if (big === 0n) {
    throw new Error('Invalid depositId: 0 (EthLock issues ids starting at 1)');
  }
  return big.toString(10);
}

/**
 * depositId 配列を正準化し、重複を排除し、**BigInt 昇順**へ整列して返す。
 *
 * 🔴 外部レビュー（2026-08-07・②）: 旧実装は「初出順を保つ」だったため、
 *   `["1","2","3"]` と `["3","2","1"]` が別の結果になった。同じ論理的集合なら
 *   渡す順序によらず結果が一致する（P2 決定論）のが「正準化」の要件。
 *   規則は `workers/game_workers/lib/claim-data-codec.js` の `canonicalDepositIds`
 *   （既に BigInt 昇順）と揃える — 正準化規則が2つあると、どちらかを基準にした
 *   第三者検証が必ずズレる。
 *
 * 🔴 同（③）: 旧実装は `Array.isArray(list) ? list : []` で、`null` も
 *   `{0:"7",length:1}` も **空配列として黙って受理**していた（「送ったのに1件も
 *   数えられない」が無言で起きる）。配列でなければ throw する。
 *   唯一の呼び出し元 entry-worker.js:233 は直前に `Array.isArray` で弾いているので、
 *   正当な経路が新たに落ちることはない（`null` が渡る経路は存在しない）。
 *
 * 不正な要素が1つでもあれば throw（無言で落とすと「送ったのに数えられない」になるため）。
 */
export function canonicalizeDepositIds(list) {
  if (!Array.isArray(list)) {
    throw new Error(`Invalid depositIds: expected an array, got ${Object.prototype.toString.call(list)}`);
  }
  const seen = new Set();
  const out = [];
  for (const raw of list) {
    const id = canonicalizeDepositId(raw);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  // BigInt 昇順（10進文字列の辞書順ではない: "10" < "9" になってしまう）
  out.sort((a, b) => {
    const x = BigInt(a); const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  return out;
}
