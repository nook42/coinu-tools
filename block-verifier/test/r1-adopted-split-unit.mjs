// r1-adopted-split-unit.mjs — R1是正（calc:{N}:adopted 単一キー128KiB超）ユニットテスト
//
// 背景（総点検 R1）: A1パイプラインは採用/無効一覧を calc:{N}:adopted の1キーに丸ごと
// 保存していた。adopted は最大2100件（≈270KB）、invalid はオンチェーン投稿でガス代
// だけで第三者が無制限に積めるため、1値128KiBの上限に抵触して put が例外化し、
// evidence ユニット連続失敗 → park ＝結果集計の恒久停止に至る。
// 是正: Z2と同じ「チャンク→マーカーの順」で calc:{N}:adopted_chunk:* / invalid_chunk:* に
// 500件ずつ分割し、マーカーには meta＋件数＋チャンク数のみを保存する。
//
//  U1: 2100 adopted + 3000 invalid — 全保存キーが128KiB未満・チャンク数が期待どおり
//  U2: 読み出し往復 — 配列・順序ともバイト同一（JSON一致）／withInvalid=false は invalid を読まない
//  U3: 空（resultCount=0）— マーカーのみ・reportPublished保持・空配列復元
//  U4: 旧単一キー形状の後方互換 — そのまま返す
//  U5: 再実行でチャンク数が減った場合 — マーカー宣言分のみ結合（残存キーは無視）
//  U6: calcCleanupKeys が adopted マーカー＋全チャンクを掃除する
//
// 実行: node block-verifier/test/r1-adopted-split-unit.mjs （Node 22）

import { GameMasterDO } from './canonical.mjs';
import { makeState } from './stubs.mjs';

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};

const BLOCK = 9;
const LIMIT = 128 * 1024;

function makeGm() {
  const state = makeState();
  const gm = new GameMasterDO(state, { RELEASE_TIME: '2099-01-01T00:00:00Z' });
  return { gm, store: state.storage._map };
}

// 最悪ケース寄りの実データ形状（uid=19桁snowflake級・txHash=66字・reasonは実スラッグ）
const mkAdopted = (n) => Array.from({ length: n }, (_, i) => ({
  uid: String(1234567890123456000n + BigInt(i)),
  groupId: i % 525,
  seq: i + 1,
  txHash: '0x' + String(i).padStart(64, 'a'),
}));
const mkInvalid = (n) => Array.from({ length: n }, (_, i) => ({
  seq: 100000 + i,
  txHash: '0x' + String(i).padStart(64, 'b'),
  reason: ['json_parse_error', 'invalid_signature', 'not_a_member', 'decompressed_too_large'][i % 4],
}));
const META = { contractAddress: '0x' + 'c'.repeat(40), resultCount: 5100, window: { openAt: 1, closeAt: 2 }, chatWindow: { chatOpenAt: 1, chatCloseAt: 2, clockSkewAllowMs: 120000 }, safeBlock: '123456', confirmations: 64 };

// ---- U1: 2100 adopted + 3000 invalid — 全キー128KiB未満・チャンク構成 ----
{
  const { gm, store } = makeGm();
  const adopted = mkAdopted(2100), invalid = mkInvalid(3000);
  await gm.calcStoreAdopted(BLOCK, { adopted, invalid, meta: META });

  let maxBytes = 0, maxKey = '';
  for (const [k, v] of store) {
    const b = Buffer.byteLength(JSON.stringify(v), 'utf8');
    if (b > maxBytes) { maxBytes = b; maxKey = k; }
  }
  ok(`U1 全保存キーが128KiB未満（最大=${maxBytes}B @ ${maxKey}）`, maxBytes < LIMIT);

  const marker = store.get(`calc:${BLOCK}:adopted`);
  ok('U1b マーカーは件数・チャンク数・metaのみ（配列を持たない）',
    !('adopted' in marker) && !('invalid' in marker) &&
    marker.adoptedCount === 2100 && marker.invalidCount === 3000 &&
    marker.adoptedChunks === 5 && marker.invalidChunks === 6 &&
    JSON.stringify(marker.meta) === JSON.stringify(META));
  ok('U1c チャンクキーが宣言数どおり存在',
    [...store.keys()].filter(k => k.startsWith(`calc:${BLOCK}:adopted_chunk:`)).length === 5 &&
    [...store.keys()].filter(k => k.startsWith(`calc:${BLOCK}:invalid_chunk:`)).length === 6);
}

// ---- U2: 読み出し往復 — バイト同一・withInvalid挙動 ----
{
  const { gm } = makeGm();
  const adopted = mkAdopted(1234), invalid = mkInvalid(777);
  await gm.calcStoreAdopted(BLOCK, { adopted, invalid, meta: META });

  const full = await gm.calcLoadAdopted(BLOCK, { withInvalid: true });
  ok('U2 adopted往復バイト同一（順序含む）', JSON.stringify(full.adopted) === JSON.stringify(adopted));
  ok('U2b invalid往復バイト同一（順序含む）', JSON.stringify(full.invalid) === JSON.stringify(invalid));
  ok('U2c meta/reportPublished/件数を保持',
    JSON.stringify(full.meta) === JSON.stringify(META) && full.reportPublished === false &&
    full.adoptedCount === 1234 && full.invalidCount === 777);

  const lean = await gm.calcLoadAdopted(BLOCK);
  ok('U2d withInvalid=false はadopted全件・invalid空', lean.adopted.length === 1234 && lean.invalid.length === 0);
}

// ---- U3: 空（resultCount=0経路）— マーカーのみ・reportPublished保持 ----
{
  const { gm, store } = makeGm();
  await gm.calcStoreAdopted(BLOCK, { adopted: [], invalid: [], meta: META, reportPublished: true });
  ok('U3 チャンクキーなし（マーカー1キーのみ）',
    [...store.keys()].filter(k => k.startsWith(`calc:${BLOCK}:`)).length === 1);
  const rec = await gm.calcLoadAdopted(BLOCK, { withInvalid: true });
  ok('U3b 空配列復元＋reportPublished=true', rec.adopted.length === 0 && rec.invalid.length === 0 && rec.reportPublished === true);
}

// ---- U4: 旧単一キー形状の後方互換 ----
{
  const { gm } = makeGm();
  const legacy = { adopted: mkAdopted(3), invalid: mkInvalid(2), meta: META };
  await gm.storage.put(`calc:${BLOCK}:adopted`, legacy);
  const rec = await gm.calcLoadAdopted(BLOCK, { withInvalid: true });
  ok('U4 旧形状はそのまま返す', rec === legacy && rec.adopted.length === 3 && rec.invalid.length === 2);
}

// ---- U5: 再実行でチャンク数減 — マーカー宣言分のみ結合 ----
{
  const { gm, store } = makeGm();
  await gm.calcStoreAdopted(BLOCK, { adopted: mkAdopted(1100), invalid: mkInvalid(600), meta: META });
  await gm.calcStoreAdopted(BLOCK, { adopted: mkAdopted(400), invalid: [], meta: META });
  const rec = await gm.calcLoadAdopted(BLOCK, { withInvalid: true });
  ok('U5 マーカー宣言分のみ結合（残存チャンクは無視）',
    rec.adopted.length === 400 && rec.invalid.length === 0,
    `adopted=${rec.adopted.length} invalid=${rec.invalid.length}`);
  ok('U5b 残存チャンクキーは存在してよい（cleanup対象）',
    [...store.keys()].some(k => k === `calc:${BLOCK}:adopted_chunk:1` || k === `calc:${BLOCK}:invalid_chunk:0`));
}

// ---- U6: calcCleanupKeys が全部掃除 ----
{
  const { gm, store } = makeGm();
  await gm.calcStoreAdopted(BLOCK, { adopted: mkAdopted(1500), invalid: mkInvalid(1200), meta: META });
  await gm.calcCleanupKeys(BLOCK);
  ok('U6 cleanup後に calc:{N}:* が残らない',
    [...store.keys()].filter(k => k.startsWith(`calc:${BLOCK}:`)).length === 0,
    [...store.keys()].filter(k => k.startsWith(`calc:${BLOCK}:`)).join(','));
}

console.log(`\nr1-adopted-split-unit: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
