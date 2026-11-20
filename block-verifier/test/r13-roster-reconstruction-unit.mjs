// 周13 C8-01(う): 公開キャッシュが失われたときの名簿再構成に「歯」があることを固定する。
//
// 🔴 なぜ要るか: `rosterKeys` は不在キャッシュを読み飛ばす（`results.js` の `if (!data) continue;`）。
//    したがってキャッシュを消すと名簿のバイト検査は `rosterLiveAnchor` の1本しか残らない。
//    その1本を「読めないから fail」で終わらせると、**消せば検査が消える**状態になる。
//    そこで不在時はアンカー済み sha256 を「運営が後から動かせないデータから再構成した
//    正準バイト列」と突き合わせる。この試験はその再構成が
//    ① writer と同じバイト列を作ること ② どこを1つ変えても別の値になること を固定する。
import { createHash } from 'node:crypto';
import { keccak256, stringToHex } from 'viem';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { frozenEntryKeyFailure, run as runEntries } from '../src/stages/entries.js';
import { ChatGameDO } from '../vendor/workers/game_workers/chat-game-DO.js';
import {
  rosterMembersOf, reconstructedRosterGroupSha256, reconstructedRosterIndexSha256,
  reconstructCanonicalRosterPayloads,
} from '../src/stages/results.js';

let failed = 0;
const ok = (condition, label) => {
  if (condition) console.log(`ok: ${label}`);
  else { console.error(`NG: ${label}`); failed++; }
};
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const VALID_PUB = '0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const VALID_NOSTR = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const validEntry = { bAddr: JSON.stringify({ address: '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
  pubKey: VALID_PUB, nostrPubkey: VALID_NOSTR }) };
ok(frozenEntryKeyFailure(validEntry) === null, '固定応募の正しい3キーは通す');
for (const [label, mutate] of [
  ['欠けた Nostr 鍵', (b) => { delete b.nostrPubkey; }],
  ['曲線外 Nostr 鍵', (b) => { b.nostrPubkey = '00'.repeat(32); }],
  ['address のすり替え', (b) => { b.address = '0x' + '11'.repeat(20); }],
]) {
  const bAddr = JSON.parse(validEntry.bAddr);
  mutate(bAddr);
  ok(frozenEntryKeyFailure({ bAddr: JSON.stringify(bAddr) }) !== null, `固定応募の${label}を入口の鍵検査不適合として検出`);
}
// 検査関数だけでなく Stage A の report 出力を通す。後続の root 計算は番兵で止める。
for (const [label, row, expected] of [
  ['正しい応募', validEntry, 'pass'],
  ['Nostr 鍵欠落', { bAddr: JSON.stringify({
    ...JSON.parse(validEntry.bAddr), nostrPubkey: undefined,
  }) }, 'fail'],
]) {
  const checks = [];
  const stop = new Error('entry-key-check-observed');
  const ctx = {
    blockNum: 4, data: {},
    chain: {
      getApplicantHash: async () => ({ hash: '0x' + '11'.repeat(32), updated: 1 }),
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
    },
    r2: { fetchJson: async (key) => key.includes('/info/')
      ? { data: { entries: key.endsWith('/00_info.json') ? [{ filename: '00_0', number: 1 }] : [] } }
      : { data: [row] }, release() {} },
    report: {
      fact() {},
      check(id, status, params) {
        checks.push({ id, status, params });
        if (id === 'check.stageA.entryKeyIntegrity') throw stop;
      },
    },
    ui: { println() {}, t: (key) => key === 'stageA.entryKeyInvalidReason'
      ? 'frozen entry failed entry validation' : key },
  };
  try { await runEntries(ctx); } catch (error) { if (error !== stop) throw error; }
  const recorded = checks.find((item) => item.id === 'check.stageA.entryKeyIntegrity');
  ok(recorded?.status === expected
    && recorded.params.count === (expected === 'fail' ? 1 : 0)
    && (expected === 'pass' || /00_0.json#0: invalid nostrPubkey/.test(recorded.params.first))
    && recorded.params.reason === (expected === 'fail' ? 'frozen entry failed entry validation' : '-'),
  `Stage A report は${label}を ${expected} として記録`);
}

let nextGlobalIndex = 0;
const member = (uid, addr, blockAddr, pubKey, ids, nostrPubkey = '79'.repeat(32)) => ({
  globalIndex: nextGlobalIndex++,
  data: {
    uid,
    addr,
    bAddr: JSON.stringify({ address: blockAddr, pubKey, nostrPubkey }),
    depIds: JSON.stringify({ ids }),
  },
});

const A = '0x1111111111111111111111111111111111111111';
const B = '0x2222222222222222222222222222222222222222';
const BA = '0x3333333333333333333333333333333333333333';
const BB = '0x4444444444444444444444444444444444444444';
const PA = `04${'aa'.repeat(64)}`;
const PB = `04${'bb'.repeat(64)}`;

const g0 = { groupId: 0, members: [member('21000000', A, BA, PA, ['1', '2']), member('21000100', B, BB, PB, ['3'])] };
const g1 = { groupId: 1, members: [member('21000200', A, BA, PA, [])] };

// ① writer（chat-game-DO.js publishRosterFile）と同じバイト列になること。
const expectedText = JSON.stringify({
  blockNum: 0,
  groupId: 0,
  members: [
    { uid: '21000000', walletAddress: A, blockAddress: BA, pubKey: PA, nostrPubkey: '79'.repeat(32), depositIds: ['1', '2'], lang: 'unknown', globalIndex: g0.members[0].globalIndex, depositWei: '0', depositVerified: false },
    { uid: '21000100', walletAddress: B, blockAddress: BB, pubKey: PB, nostrPubkey: '79'.repeat(32), depositIds: ['3'], lang: 'unknown', globalIndex: g0.members[1].globalIndex, depositWei: '0', depositVerified: false },
  ],
});
ok(reconstructedRosterGroupSha256(0, g0) === sha(expectedText),
  'group 名簿の再構成が writer と同じバイト列になる');
ok(JSON.stringify(rosterMembersOf(g0)) === JSON.stringify(JSON.parse(expectedText).members),
  'rosterMembersOf の欄集合と並びが writer と一致する');

// 索引側（game-master-DO.js buildRosterIndex ＋ JSON.stringify）。
// ⚠️ JSON.stringify のキーが数値順になるのは配列添字（2^32−2 以下）だけ。
// それ以外の uid は、writer と同じ groupId 昇順で挿入した順になる。
ok(reconstructedRosterIndexSha256([g1, g0])
   === sha(JSON.stringify({ 21000000: 0, 21000100: 0, 21000200: 1 })),
'索引の再構成が数値昇順のキー順で writer と一致する');

// ② 歯: どこを1つ変えても sha256 が変わること（＝すり替えを見逃さない）。
const base = reconstructedRosterGroupSha256(0, g0);
const tamper = (label, mutate) => {
  const copy = JSON.parse(JSON.stringify(g0));
  mutate(copy);
  ok(reconstructedRosterGroupSha256(0, copy) !== base, `歯: ${label} を変えると別の sha256 になる`);
};
tamper('pubKey（P2P の信頼の起点）', (g) => {
  g.members[0].data.bAddr = JSON.stringify({ address: BA, pubKey: PB, nostrPubkey: '79'.repeat(32) });
});
tamper('nostrPubkey', (g) => {
  g.members[0].data.bAddr = JSON.stringify({ address: BA, pubKey: PA, nostrPubkey: 'ab'.repeat(32) });
});
tamper('blockAddress', (g) => {
  g.members[0].data.bAddr = JSON.stringify({ address: BB, pubKey: PA, nostrPubkey: '79'.repeat(32) });
});
tamper('walletAddress', (g) => { g.members[0].data.addr = B; });
tamper('uid', (g) => { g.members[0].data.uid = '21000999'; });
tamper('depositIds', (g) => { g.members[0].data.depIds = JSON.stringify({ ids: ['1'] }); });
tamper('lang', (g) => { g.members[0].data.lang = 'ja'; });
tamper('globalIndex', (g) => { g.members[0].globalIndex += 1; });
tamper('depositWei', (g) => { g.members[0].data.depIds = JSON.stringify({ ids: ['1', '2'], deposit: '100' }); });
tamper('depositVerified', (g) => { g.members[0].data.verified = true; });
tamper('メンバーの並び', (g) => { g.members.reverse(); });
tamper('メンバーを1人落とす', (g) => { g.members.pop(); });

ok(reconstructedRosterGroupSha256(1, g0) !== base, '歯: groupId が違えば別の sha256 になる');
ok(reconstructedRosterIndexSha256([g0]) !== reconstructedRosterIndexSha256([g0, g1]),
  '歯: 索引から1グループ落とすと別の sha256 になる');
{
  const moved = JSON.parse(JSON.stringify(g1));
  moved.groupId = 0;
  ok(reconstructedRosterIndexSha256([g0, g1]) !== reconstructedRosterIndexSha256([g0, moved]),
    '歯: uid を別グループへ付け替えると索引の sha256 が変わる');
}

// ③ 壊れた入力で例外にせず、writer と同じ既定値へ倒すこと（writer は catch して [] にする）。
{
  const broken = { groupId: 0, members: [{ globalIndex: 99, data: { uid: '21000000', addr: null, bAddr: 'not-json', depIds: 'not-json' } }] };
  const m = rosterMembersOf(broken)[0];
  ok(m.blockAddress === null && m.pubKey === null && m.nostrPubkey === null && m.walletAddress === null
     && Array.isArray(m.depositIds) && m.depositIds.length === 0,
  '壊れた bAddr / depIds は writer と同じく null / [] になる');
}

// GM と ChatGameDO の vendored 書き手を実行し、12組・D1 行順の乱れ・高位 uid を比べる。
{
  const ids = ['4294967294', '4294967295', '__proto__', 'u-abc'];
  const derived = Array.from({ length: 12 }, (_, groupId) => ({ groupId, members: [
    member(ids[groupId] ?? String(21000000 + groupId), A, BA, PA, [String(groupId)]),
  ] })).reverse();
  const d1Rows = derived.map((group) => ({ group_id: group.groupId,
    members: group.members.map((row) => ({ ...row.data, globalIndex: row.globalIndex })) }));
  const captured = new Map();
  const env = {
    BITCOINU_DATA: { prepare: () => ({ bind: () => ({ all: async () => ({ results: d1Rows }) }) }) }, API_SECRET: 'x',
    R2_BUCKET: {
      put: async (key, value) => { captured.set(key, value); },
      get: async (key) => captured.has(key)
        ? { text: async () => captured.get(key) } : null,
    },
    CHAT_GAME_DO: {
      idFromName: (name) => name,
      get: (id) => ({ fetch: async () => {
        const [block, gid] = String(id).split('-').map(Number);
        const row = d1Rows.find((item) => item.group_id === gid);
        const writer = { env: { R2_BUCKET: env.R2_BUCKET }, storage: { put: async () => {} },
          recordDependencyOutcome: () => {} };
        const rosterSha256 = await ChatGameDO.prototype.publishRosterFile.call(
          writer, block, gid, row.members);
        return new Response(JSON.stringify({ rosterSha256 }), { status: 200 });
      } }),
    },
  };
  const gm = new GameMasterDO({ storage: { get: async () => undefined,
    put: async () => {} } }, env);
  gm.deferGroupObservation = () => {};
  const written = await gm.rebuildAndPublishRosterManifest(7, d1Rows);
  const commitment = await gm.computePublishedRosterCommitment(7, written.manifestText);
  ok(typeof commitment.C === 'string' && commitment.C.startsWith('0x')
    && commitment.members.length === 1, 'GM は公開12組の実バイトと D1 を照合して C を作る');
  const rebuilt = reconstructCanonicalRosterPayloads(7, derived);
  const manifestKey = 'games/block7/roster/manifest.json';
  ok(written.manifestText === rebuilt.manifestText
    && captured.get(manifestKey) === rebuilt.manifestText,
  '12組の GM manifest と再構成 manifest が byte 一致する');
  ok(captured.get('games/block7/roster/index.json') === rebuilt.indexText,
    '高位 uid と __proto__ を含む index が byte 一致する');
  ok(derived.every((group) => captured.get(`games/block7/roster/group${group.groupId}.json`)
    === rebuilt.groupTexts.get(group.groupId)), '12組の ChatGameDO group が byte 一致する');
  // R-4.22: 実書き手の新しい raw SHA が C、名簿 manifest、結果 files、検証の写しへ動的に流れる。
  const rosterManifest = JSON.parse(written.manifestText);
  ok(derived.every((group) => {
    const key = `games/block7/roster/group${group.groupId}.json`;
    const rawSha = sha(captured.get(key));
    return rosterManifest.groups.find((row) => row.groupId === group.groupId)?.sha256 === rawSha
      && reconstructedRosterGroupSha256(7, group) === rawSha;
  }), '実group raw SHAは名簿宣言とverifier再構成へ伝播');
  for (const group of derived) captured.set(`games/block7/group${group.groupId}.json`, '{}');
  captured.set('verification/block7/stage3/manifest.json', '{}');
  captured.set('games/block7/zkp/evidence-segments.json', '{}');
  gm.getR2Object = async () => ({ groups: [] });
  gm.merkleRebuildArtifactKeys = () => [];
  gm.canonicalGroupIdsFromFinalizedSummary = async () => derived.map((group) => group.groupId).sort((a, b) => a - b);
  gm.publishStage3InputManifest = async () => {};
  gm.canonicalResultPageKeys = () => [];
  gm.sha256R2Object = async (obj) => sha(await obj.text());
  gm.clearVerificationAdminTxWait = async () => {};
  const manifests = [];
  gm.finalizeVerificationManifest = async (_block, files) => {
    manifests.push(structuredClone(files));
    return { ok: true };
  };
  const manualManifest = await gm.publishVerificationManifest(7, []);
  const unitProgress = await gm.calcManifestUnit(7, { stage: 'manifest', cursor: 0 });
  ok(manualManifest.ok === true && unitProgress.stage === 'proofs'
    && JSON.stringify(manifests[0]) === JSON.stringify(manifests[1]),
  '手動・unitの結果filesはキー順とSHAが同じ');
  ok(derived.every((group) => {
    const key = `games/block7/roster/group${group.groupId}.json`;
    return manifests.every((files) => files[key] === sha(captured.get(key)));
  }), '実group raw SHAは結果manifest.filesへ伝播');
  const moved = structuredClone(derived);
  moved[0].members[0].data.uid = 'changed';
  ok(keccak256(stringToHex(rebuilt.manifestText))
    !== keccak256(stringToHex(reconstructCanonicalRosterPayloads(7, moved).manifestText)),
  '1人の移動で manifest keccak が変わる');
}

console.log(failed === 0 ? 'r13-roster-reconstruction-unit: ALL PASSED' : `${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
