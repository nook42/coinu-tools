// g1-merkle-proofs-unit.mjs — G1/G1b是正（Merkle分割形式＋proof事前生成・フォールバック）ユニットテスト
//
// 背景（総点検G1+G1b）: 旧形式は全葉にproofを埋め込んだ単一JSON（最大10.7万葉で約150MB・
// 生成メモリ約300MB=OOM）を請求のたびに丸読みしていた。是正: O(N)の
// メタ＋leaves/levels/indexチャンク＋「1請求キー1ファイル」のproof事前生成
// （claim-worker /build-proofs レンジ発注・Workersの自動スケールで並列）。
//
// 本物の GameMasterDO.buildMerkleTree/publishMerkleArtifacts と本物の claim-worker.js を
// メモリR2で直結して検証する（葉12,345=パディング16,384・深さ14・葉ページ3・複数レベルページ）:
//  T1: 分割アーティファクトの構造（メタ・葉ページ・レベルページ・索引16分冊・全ファイル有界）
//  T2: /build-proofs レンジ発注 — written合算 == leafCount・全proofファイル生成
//  T3: proof正当性 — 境界含むサンプル葉のproofがrootへ畳める（sorted-pair・パディング込み）
//  T4: 1レンジのR2読取が有界（葉ページ＋レベルページ≒25読取。ツリー丸読みが消えた証明）
//  T5: /claim 通常経路 — proofファイル1発読みで応答（応答形状は旧互換）
//  T6: フォールバック — proofファイル欠落→その場生成で応答＋自己修復書き戻し
//  T7: 存在しないキー→従来どおり failed 応答／メタ欠落→404／/build-proofs 無認証→401
//
// 実行: node block-verifier/test/g1-merkle-proofs-unit.mjs （Node 22）

import { GameMasterDO } from './canonical.mjs';
import { makeState } from './stubs.mjs';
import claimWorker from '../../workers/claim_workers/claim-worker.js';
import { keccak256, concatHex } from 'viem';

let passed = 0, failed = 0;
const realLog = console.log.bind(console), realErr = console.error.bind(console);
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; realLog(`  ok: ${name}`); }
  else { failed++; realErr(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};

const BLOCK = 7;
const SECRET = 'test-secret';
const N_LEAVES = 12345; // パディング後16,384・proofDepth=14・葉ページ3・L0レベルページ4
const ADDR = '0x00000000000000000000000000000000000000A1';

// メモリR2（get/putのみ・読取回数を記録）
function makeMemR2() {
  const map = new Map();
  const stats = { gets: 0, puts: 0 };
  return {
    _map: map, stats,
    async get(key) {
      stats.gets++;
      if (!map.has(key)) return null;
      const body = map.get(key);
      return { text: async () => body, json: async () => JSON.parse(body) };
    },
    async put(key, body, _opts) {
      stats.puts++;
      map.set(key, typeof body === 'string' ? body : JSON.stringify(body));
    },
    async delete(key) { map.delete(key); },
  };
}

// sorted-pairでproofをrootへ畳む（TokenMining._verifyMerkleProofと同一規則）
function foldProof(leaf, proof) {
  let h = leaf;
  for (const sib of proof) {
    h = BigInt(h) < BigInt(sib) ? keccak256(concatHex([h, sib])) : keccak256(concatHex([sib, h]));
  }
  return h;
}

const quiet = async (fn) => {
  console.log = () => {}; console.warn = () => {}; console.error = () => {};
  try { return await fn(); } finally { console.log = realLog; console.warn = realErr; console.error = realErr; }
};

// ---- 世界構築: 本物のbuildMerkleTree＋publishMerkleArtifactsでR2にアーティファクトを敷く ----
const r2 = makeMemR2();
const gm = new GameMasterDO(makeState(), { RELEASE_TIME: '2099-01-01T00:00:00Z', R2_BUCKET: r2 });
const entries = Array.from({ length: N_LEAVES }, (_, i) => ({
  key: `${BLOCK}_${i % 100}_player_${9000000 + i}`,
  to: ADDR,
  amount: String(1000 + i),
}));
const tree = await quiet(() => gm.buildMerkleTree(BLOCK, entries));
const meta = {
  blockNum: BLOCK, root: tree.root, leafCount: tree.leafCount, proofDepth: tree.proofDepth,
  totalAmount: tree.totalAmount, format: 'v2', leafChunkSize: 5000, levelSegSize: 4096, indexFanout: 16,
};
await quiet(async () => {
  await gm.putR2Object(`merkle/block_${BLOCK}.json`, meta);
  await gm.publishMerkleArtifacts(BLOCK, tree);
});

const env = { R2_BUCKET: r2, API_SECRET: SECRET };
const post = (path, body, headers = {}) => claimWorker.fetch(
  new Request(`http://claim.local${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
  }), env, { waitUntil: (p) => pendingWaits.push(p) });
const pendingWaits = [];

// ---- T1: 分割アーティファクトの構造 ----
{
  ok('T1 メタは数百B・rootあり', JSON.parse(r2._map.get(`merkle/block_${BLOCK}.json`)).root === tree.root
    && r2._map.get(`merkle/block_${BLOCK}.json`).length < 1000);
  const leafPages = [...r2._map.keys()].filter(k => k.includes('/leaves/')).length;
  const levelPages = [...r2._map.keys()].filter(k => k.includes('/levels/')).length;
  const indexPages = [...r2._map.keys()].filter(k => k.includes('/index/')).length;
  ok(`T1b 葉ページ3・索引16分冊（levels=${levelPages}）`, leafPages === 3 && indexPages === 16 && levelPages >= 5);
  let maxBytes = 0;
  for (const [k, v] of r2._map) if (k.startsWith('merkle/')) maxBytes = Math.max(maxBytes, v.length);
  ok(`T1c 全アーティファクトが有界（最大=${(maxBytes / 1e6).toFixed(2)}MB < 2MB）`, maxBytes < 2_000_000);
  ok('T1d proofDepth=14（12,345→16,384パディング）', tree.proofDepth === 14);
}

// ---- T2: /build-proofs レンジ発注（500葉×25レンジ） ----
{
  let written = 0;
  await quiet(async () => {
    for (let from = 0; from < N_LEAVES; from += 500) {
      const res = await post('/build-proofs', { block_number: BLOCK, from, to: from + 500 }, { 'X-Api-Secret': SECRET });
      if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
      written += (await res.json()).written;
    }
  });
  const proofFiles = [...r2._map.keys()].filter(k => k.includes('/proofs/')).length;
  ok('T2 written合算 == leafCount', written === N_LEAVES, `written=${written}`);
  ok('T2b proofファイル数 == leafCount', proofFiles === N_LEAVES, `files=${proofFiles}`);
}

// ---- T3: proof正当性（境界＋ランダムサンプル） ----
{
  const sampleIdx = [0, 1, 4999, 5000, 8191, 8192, 12344];
  for (let i = 0; i < 30; i++) sampleIdx.push((i * 397 + 13) % N_LEAVES);
  let allOk = true;
  for (const i of sampleIdx) {
    const item = JSON.parse(r2._map.get(`merkle/block_${BLOCK}/proofs/${entries[i].key}.json`));
    if (item.index !== i || item.amount !== entries[i].amount) { allOk = false; break; }
    if (foldProof(item.leaf, item.proof).toLowerCase() !== tree.root.toLowerCase()) { allOk = false; break; }
  }
  ok(`T3 サンプル${sampleIdx.length}葉のproofが全てrootへ畳める（ページ境界含む）`, allOk);
}

// ---- T4: 1レンジの読取が有界（ツリー丸読みの消滅） ----
{
  const before = r2.stats.gets;
  await quiet(() => post('/build-proofs', { block_number: BLOCK, from: 6000, to: 6500 }, { 'X-Api-Secret': SECRET }));
  const reads = r2.stats.gets - before;
  ok(`T4 1レンジ（500葉）のR2読取=${reads}回 ≦ 40（メタ1＋葉ページ≦2＋レベルページ）`, reads <= 40);
}

// ---- T5: /claim 通常経路（proofファイル1発読み・応答形状は旧互換） ----
{
  const target = entries[7777];
  const before = r2.stats.gets;
  const res = await quiet(() => post('/claim', {
    block_number: BLOCK, group_id: 7777 % 100, user_id: String(9000000 + 7777), role: 'player',
  }));
  const data = await res.json();
  const reads = r2.stats.gets - before;
  ok('T5 応答成功・旧互換形状（address/amount/keys/merkleRoot/items）',
    data.status === 'success' && data.data.address === ADDR && data.data.merkleRoot === tree.root
    && data.data.items[0].key === target.key && Array.isArray(data.data.items[0].proof),
    JSON.stringify(data).slice(0, 200));
  ok('T5b proofがrootへ畳める', foldProof(tree.leavesMeta[7777].leaf, data.data.items[0].proof).toLowerCase() === tree.root.toLowerCase());
  ok(`T5c 読取はメタ＋proofファイルの2回のみ（実測=${reads}）`, reads <= 2);
}

// ---- T6: フォールバック（proofファイル欠落→その場生成＋自己修復） ----
{
  const target = entries[5001]; // 葉ページ1（境界直後）
  const proofKey = `merkle/block_${BLOCK}/proofs/${target.key}.json`;
  r2._map.delete(proofKey);
  const res = await quiet(() => post('/claim', {
    block_number: BLOCK, group_id: 5001 % 100, user_id: String(9000000 + 5001), role: 'player',
  }));
  const data = await res.json();
  ok('T6 欠落時もその場生成で応答成功', data.status === 'success'
    && foldProof(tree.leavesMeta[5001].leaf, data.data.items[0].proof).toLowerCase() === tree.root.toLowerCase(),
    JSON.stringify(data).slice(0, 200));
  await Promise.all(pendingWaits.splice(0));
  ok('T6b 自己修復（proofファイルが書き戻される）', r2._map.has(proofKey));
}

// ---- T7: 異常系 ----
{
  const res = await quiet(() => post('/claim', { block_number: BLOCK, group_id: 0, user_id: 'nonexistent', role: 'player' }));
  const data = await res.json();
  ok('T7 存在しないキーはfailed応答（旧互換メッセージ）',
    data.status === 'failed' && /No claim found/.test(data.message), JSON.stringify(data));

  const res404 = await quiet(() => post('/claim', { block_number: 999, group_id: 0, user_id: '1', role: 'player' }));
  ok('T7b メタ欠落ブロックは404', res404.status === 404);

  const res401 = await quiet(() => post('/build-proofs', { block_number: BLOCK, from: 0, to: 1 }));
  ok('T7c /build-proofs 無認証は401', res401.status === 401);
}

realLog(`\ng1-merkle-proofs-unit: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
