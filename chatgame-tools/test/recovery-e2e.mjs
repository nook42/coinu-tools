// test/recovery-e2e.mjs — 復元クライアントの Hardhat ローカル E2E（Evidence 直接提出→回収→検証）
//
// ① hardhat node 起動＋一式デプロイ（Evidence 含む）
// ② 検閲シナリオ（scenario.mjs）で p2 の復元バンドルを再構成
// ③ 結果窓の外で提出→revert（窓ガード）／結果窓内で submitResultOnChain 実投稿
// ④ ResultSubmitted イベントを回収→ decodeEvidenceData で解凍→バイト等価＋validateResultBundle
// ⑤ first-write-wins: 2回目の別バイト提出は seq=2 だが採用は seq=1（reconciler の precedence）
//
// 実行: node test/recovery-e2e.mjs   （##CHECK/##RESULT 形式）

import {
  startNode, deployContracts, makeClients, makeChain, TIMING, setNextTimestamp, mineOne, write,
} from '../../block-verifier/test/chain-setup.mjs';
import { createWalletClient, http, parseAbiItem, sha256, stringToHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { buildScenario, fixedWalletKey } from './scenario.mjs';
import { submitResultOnChain, measureOnChainBytes, saveRecoveryRosterProof } from '../src/recovery/submit.js';
import { buildRosterMemberCommitment, createRosterMemberProof } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { rosterAnchorKey } from '../vendor/workers/game_workers/lib/roster-anchor-rule.js';
import { decodeEvidenceData, validateResultBundle, buildMembersIndex } from '../vendor/workers/game_workers/lib/evidence-reconciler.js';

const checks = [];
function check(id, cond) { checks.push({ id, status: cond ? 'pass' : 'fail' }); console.log(`  ${cond ? 'ok' : 'NG'}: ${id}`); }

// scenario は blockNum=5 で鍵/署名を作る。Evidence 窓も block 5 で計算する。
const BLOCK_NUM = 5;

// block N の結果窓 [chatClose(N), chatClose(N)+SUBMIT_PERIOD)
// chatClose = entryEnd + grace + GAME_PERIOD（Evidence.sol の時刻算術）。
function resultWindowSec(t, N) {
  const entryEnd = t.S + (N + 1) * t.BLOCK_TIME;
  const chatClose = entryEnd + t.GRACE + t.GAME_PERIOD; // grace は INITIAL_GRACE=GRACE（未延長）
  return { openAt: chatClose, closeAt: chatClose + t.SUBMIT_PERIOD };
}

async function main() {
  console.log('[recovery-e2e] starting hardhat node…');
  const node = await startNode({ port: 8551 });
  const cleanups = [() => node.stop()];
  try {
    const { evidence, hashStorage } = await deployContracts(node.rpcUrl);
    const chain = makeChain(node.rpcUrl);

    const sc = await buildScenario({ blockNum: BLOCK_NUM });
    const submitter = privateKeyToAccount(fixedWalletKey(101));
    const walletClient = createWalletClient({ chain, transport: http(node.rpcUrl), account: submitter });
    const { publicClient } = makeClients(node.rpcUrl);
    const deployer = makeClients(node.rpcUrl);
    const fundHash = await deployer.walletClient.sendTransaction({ to: submitter.address, value: 10n ** 18n });
    await publicClient.waitForTransactionReceipt({ hash: fundHash });

    const groupText = JSON.stringify({ blockNum: BLOCK_NUM, groupId: 0,
      members: [...sc.players.map((p) => ({ uid: p.uid, walletAddress: p.addr })),
        { uid: 'shared-wallet-alias', walletAddress: submitter.address }] });
    const manifestText = JSON.stringify({ blockNum: BLOCK_NUM, groups: [{ groupId: 0,
      sha256: sha256(stringToHex(groupText)).slice(2) }] });
    const commitment = buildRosterMemberCommitment({ blockNum: BLOCK_NUM, manifestText,
      groupTexts: { 0: groupText } });
    check('u8.shared_wallet_one_tree_member', commitment.members.length === sc.players.length);
    const entryEnd = TIMING.S + (BLOCK_NUM + 1) * TIMING.BLOCK_TIME;
    await setNextTimestamp(node.rpcUrl, entryEnd + 1);
    await mineOne(node.rpcUrl);
    await write(deployer, hashStorage, 'setOtherHash', [rosterAnchorKey(BLOCK_NUM), commitment.C]);
    const storageData = new Map();
    const storage = { setItem: (k, v) => storageData.set(k, v), getItem: (k) => storageData.get(k) || null };
    check('recovery.roster_proof_saved', saveRecoveryRosterProof({ blockNum: BLOCK_NUM, groupId: 0,
      uid: sc.players[1].uid, chainId: 31337, evidenceAddress: evidence.address,
      walletAddress: submitter.address, manifestHash: commitment.manifestHash, C: commitment.C,
      proof: createRosterMemberProof(commitment, submitter.address), sharedWalletUids: 2 }, storage));
    // ② シナリオ
    const payload = sc.p2Recovery.payload;
    const byteLength = await measureOnChainBytes(payload);
    check('recovery.payload_gt_min', byteLength >= 256);
    console.log(`[recovery-e2e] recovery payload data bytes=${byteLength}`);

    const win = resultWindowSec(TIMING, BLOCK_NUM);
    await setNextTimestamp(node.rpcUrl, entryEnd + TIMING.GRACE + 1);
    await mineOne(node.rpcUrl);
    let startedRosterGraceRejected = false;
    try { await write(deployer, evidence, 'extendGrace', [BigInt(BLOCK_NUM), BigInt(TIMING.GRACE + 1)]); }
    catch { startedRosterGraceRejected = true; }
    check('u8.started_roster_grace_rejected', startedRosterGraceRejected);

    // ③-a: 窓の前（chatClose 直前）に提出 → revert
    {
      await setNextTimestamp(node.rpcUrl, win.openAt - 10);
      await mineOne(node.rpcUrl);
      let reverted = false;
      try {
        await submitResultOnChain(walletClient, evidence.address, BLOCK_NUM, payload, { storage });
      } catch { reverted = true; }
      check('recovery.before_window_reverts', reverted);
    }

    // ③-b: 窓内で提出
    await setNextTimestamp(node.rpcUrl, win.openAt + 10);
    await mineOne(node.rpcUrl);
    const res1 = await submitResultOnChain(walletClient, evidence.address, BLOCK_NUM, payload, { storage });
    check('recovery.submit_ok', !!res1.hash);
    await publicClient.waitForTransactionReceipt({ hash: res1.hash });
    const directArgs = (data, manifestHash = commitment.manifestHash,
      proof = createRosterMemberProof(commitment, submitter.address)) =>
      [BigInt(BLOCK_NUM), data, manifestHash, proof];
    const other = makeClients(node.rpcUrl, fixedWalletKey(109));
    const otherFund = await deployer.walletClient.sendTransaction({
      to: other.account.address, value: 10n ** 18n,
    });
    await publicClient.waitForTransactionReceipt({ hash: otherFund });
    let otherRejected = false;
    try { await write(other, evidence, 'submitResult', directArgs('0x' + '11'.repeat(256))); }
    catch { otherRejected = true; }
    check('u8.other_wallet_rejected', otherRejected);
    let wrongRootRejected = false;
    try { await write({ walletClient, publicClient }, evidence, 'submitResult',
      directArgs('0x' + '11'.repeat(256), `0x${'ff'.repeat(32)}`)); }
    catch { wrongRootRejected = true; }
    check('u8.wrong_root_rejected', wrongRootRejected);
    let wrongProofRejected = false;
    try { await write({ walletClient, publicClient }, evidence, 'submitResult',
      directArgs('0x' + '11'.repeat(256), commitment.manifestHash,
        createRosterMemberProof(commitment, sc.players[0].addr))); }
    catch { wrongProofRejected = true; }
    check('u8.other_member_proof_rejected', wrongProofRejected);
    let oversizedRejected = false;
    try { await write({ walletClient, publicClient }, evidence, 'submitResult',
      directArgs('0x' + '11'.repeat(130001))); }
    catch { oversizedRejected = true; }
    check('u8.data_above_max_rejected', oversizedRejected);

    // ④ ResultSubmitted 回収 → decode → バイト等価 + 検証
    const logs = await publicClient.getLogs({
      address: evidence.address,
      event: parseAbiItem('event ResultSubmitted(uint256 indexed blockNum, uint256 indexed seq, address indexed sender, bytes data, uint256 timestamp)'),
      args: { blockNum: BigInt(BLOCK_NUM) },
      fromBlock: 0n, toBlock: 'latest',
    });
    check('recovery.event_present', logs.length === 1 && logs[0].args.seq === 1n);
    const decoded = await decodeEvidenceData(logs[0].args.data); // gzip判別＋解凍 → { ok, raw }
    check('recovery.decoded_byte_identical', decoded.ok && decoded.raw === payload);

    const membersIndex = buildMembersIndex([{ group_id: 0, members: sc.members }]);
    const v = await validateResultBundle(decoded.raw, BLOCK_NUM, membersIndex, logs[0].args.sender);
    check('recovery.onchain_bundle_valid', v.valid && v.uid === sc.players[1].uid);

    // ⑤ first-write-wins: 別バイト（submittedAt 違い）を再提出 → seq=2 だが precedence は seq最小
    {
      const sc2 = await buildScenario({ blockNum: BLOCK_NUM, base: 1750000001000 }); // submittedAt 等が変わる
      const res2 = await submitResultOnChain(walletClient, evidence.address, BLOCK_NUM, sc2.p2Recovery.payload, { storage });
      await publicClient.waitForTransactionReceipt({ hash: res2.hash });
      const logs2 = await publicClient.getLogs({
        address: evidence.address,
        event: parseAbiItem('event ResultSubmitted(uint256 indexed blockNum, uint256 indexed seq, address indexed sender, bytes data, uint256 timestamp)'),
        args: { blockNum: BigInt(BLOCK_NUM) },
        fromBlock: 0n, toBlock: 'latest',
      });
      // reconciler.selectAdoptedResults は seq 昇順で最初の有効を採用（ここではロジック確認のみ）
      const seqs = logs2.map((l) => Number(l.args.seq)).sort((a, b) => a - b);
      check('recovery.two_events_seq', seqs.join(',') === '1,2');
      // 採用は seq=1（最初）＝元の payload
      const first = logs2.find((l) => l.args.seq === 1n);
      const firstDecoded = await decodeEvidenceData(first.args.data);
      check('recovery.first_write_wins', firstDecoded.ok && firstDecoded.raw === payload);
    }
    const maxData = '0x' + 'ab'.repeat(130000);
    await write({ walletClient, publicClient }, evidence, 'submitResult', directArgs(maxData));
    check('u8.max_data_accepted', Number(await publicClient.readContract({ address: evidence.address,
      abi: evidence.abi, functionName: 'resultCountOf', args: [BigInt(BLOCK_NUM), submitter.address] })) === 3);
    let fourthRejected = false;
    try { await write({ walletClient, publicClient }, evidence, 'submitResult',
      directArgs('0x' + '11'.repeat(256))); }
    catch { fourthRejected = true; }
    check('u8.shared_wallet_fourth_rejected', fourthRejected);
    const registeredOther = makeClients(node.rpcUrl, fixedWalletKey(100));
    const registeredOtherFund = await deployer.walletClient.sendTransaction({
      to: registeredOther.account.address, value: 10n ** 18n,
    });
    await publicClient.waitForTransactionReceipt({ hash: registeredOtherFund });
    await write(registeredOther, evidence, 'submitResult',
      directArgs(logs[0].args.data, commitment.manifestHash,
        createRosterMemberProof(commitment, registeredOther.account.address)));
    check('u8.other_member_uses_own_slot', Number(await publicClient.readContract({
      address: evidence.address, abi: evidence.abi, functionName: 'resultCountOf',
      args: [BigInt(BLOCK_NUM), registeredOther.account.address],
    })) === 1);
    const replayByOther = await validateResultBundle(decoded.raw, BLOCK_NUM,
      membersIndex, registeredOther.account.address);
    check('u8.other_member_replay_not_adopted',
      !replayByOther.valid && replayByOther.reason === 'sender_mismatch');
    const noRosterBlock = BLOCK_NUM + 1;
    const noRosterOpen = resultWindowSec(TIMING, noRosterBlock).openAt;
    await setNextTimestamp(node.rpcUrl, noRosterOpen + 10);
    await mineOne(node.rpcUrl);
    let noRosterRejected = false;
    try { await write({ walletClient, publicClient }, evidence, 'submitResult',
      [BigInt(noRosterBlock), '0x' + '11'.repeat(256), commitment.manifestHash,
        createRosterMemberProof(commitment, submitter.address)]); }
    catch { noRosterRejected = true; }
    check('u8.r33_no_roster_rejected', noRosterRejected);
  } finally {
    for (const c of cleanups.reverse()) { try { await c(); } catch { /* noop */ } }
  }

  console.log('');
  for (const c of checks) console.log(`##CHECK ${c.id} ${c.status}`);
  const anyFail = checks.some((c) => c.status === 'fail');
  console.log(`##RESULT ${anyFail ? 'fail' : 'full'}`);
  process.exit(anyFail ? 2 : 0);
}

main().catch((e) => { console.error('[recovery-e2e] fatal:', e); console.log('##RESULT fatal'); process.exit(3); });
