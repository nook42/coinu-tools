// test/self-verify-intent-unit.mjs — A-3 自己検証に渡す intent の扱い（v3.2: vote/reports のみ）
//
// 復元クライアントは「自分が別クライアント(game.js)で行動した」場合、P2P の自己アクション観測で
// myVote/myReports だけを埋め、平文(intent)は持たないことがある。空の入れ物
// {vote:null, reports:[]} は selfVerifyIntent で null に正規化して渡す（未知は「未知」として
// 扱わせ、照合を丸ごとスキップ＝本体の actionIntent_ 不在時と同じ挙動）。
// ここでは①正規化、②intent無しで提出できること、③検証が死んでいないこと
// （vote/report の差し替え・復号不能は依然拒否されること）を確認する。
//
// 実行: node test/self-verify-intent-unit.mjs   （##CHECK/##RESULT 形式）

import { buildScenario } from './scenario.mjs';
import { encryptAction } from '../vendor/src/utils/ecies.js';
import { actionSignStringV2 } from '../vendor/workers/game_workers/lib/protocol-v2.js';
const { buildSubmissionBundle } = await import(process.env.T7_BUNDLE_SOURCE || '../src/recovery/bundle.js');

const checks = [];
function check(id, cond) { checks.push({ id, status: cond ? 'pass' : 'fail' }); console.log(`  ${cond ? 'ok' : 'NG'}: ${id}`); }

// app.js の selfVerifyIntent と同じ規則（空の区画は渡さない・vote/reports のみ）
function selfVerifyIntent(intent) {
  const vote = intent.vote || undefined;
  const reports = intent.reports?.length ? intent.reports : undefined;
  if (!vote && !reports) return null;
  return { vote: vote ?? null, reports: reports ?? [] };
}

async function main() {
  const s = await buildScenario();
  const [p1, p2, p3, p4] = s.players;

  // p2 の密告を1件用意（p3 宛て・encryptKey自己暗号化＋signKey署名）
  const p2Report = await s.makeAction(p2, 'report', { targetUid: p3.uid, reason: 'suspected_bot' }, 1750000000500);

  const build = ({ intent, myVote = s.votes[p2.uid], myReports = [] }) => buildSubmissionBundle({
    blockNum: s.blockNum, groupId: s.groupId, myUid: p2.uid, encryptKey: p2.encryptKey,
    members: s.members, messages: s.sharedMessages, myDepositIds: JSON.parse(p2.depIds).ids,
    myVote, myReports,
    observedActions: { votes: {}, reports: {} }, receipts: s.allReceipts,
    intent, submittedAt: 1750000999999,
    signWallet: async (message) => p2.wallet.signMessage({ message }),
  });

  const codeOf = async (p) => { try { await p; return null; } catch (e) { return e.code || e.message; } };

  // ① 空の入れ物は null に正規化される（平文不明＝照合スキップ）
  {
    const normalized = selfVerifyIntent({ vote: null, reports: [] });
    check('intent.normalized_to_null', normalized === null);
    const built = await build({ intent: normalized });
    check('intent.builds_without_intent', !!built?.payload && !!built?.encryptedDataHash);
    // 観測分（平文不明）の投票もちゃんと提出物に載る（黙って落としていないこと）
    check('intent.observed_vote_kept', built.snapshotData.votes?.[p2.uid]?.signature === s.votes[p2.uid].signature);
  }

  // ② 平文を知っている場合は照合される（vote）
  {
    const ok = selfVerifyIntent({ vote: p1.uid, reports: [] });
    check('intent.correct_vote_passes', !!(await build({ intent: ok }))?.payload);

    const wrong = selfVerifyIntent({ vote: p4.uid, reports: [] });
    check('intent.wrong_vote_refused', await codeOf(build({ intent: wrong })) === 'vote_mismatch');
  }

  // ③ reports の照合（正しい対象集合は通る・違う対象は拒否）
  {
    const ok = selfVerifyIntent({ vote: p1.uid, reports: [p3.uid] });
    const built = await build({ intent: ok, myReports: [p2Report] });
    check('intent.correct_reports_pass', Array.isArray(built.snapshotData.reports?.[p2.uid]) && built.snapshotData.reports[p2.uid].length === 1);

    const wrong = selfVerifyIntent({ vote: p1.uid, reports: [p4.uid] });
    // intent は p4 を密告したと記録しているのに提出物には p4 宛てが無い → report_missing。
    // 「足りない」向きはそのまま出すと採点⑥(b)で report_fraud 失格になるので出す前に止める。
    check('intent.missing_reports_refused', await codeOf(build({ intent: wrong, myReports: [p2Report] })) === 'report_missing');
  }

  // ④ 回帰（2026-08-05 block1 実障害）: intent が実発信より少なくても**捨てない**。
  //    以前は intent.reports に無い対象を黙って除去していたため、実際に送った密告が
  //    提出物から消え、他メンバーの提出物＋受領証明で正典に残った結果
  //    採点⑥(b)が「取下げ」と見なして report_fraud 冤罪失格になった。
  //    発信は全て自分の signKey 署名付き＝他人には捏造できないので、除去する理由が無い。
  {
    const p4Report = await s.makeAction(p2, 'report', { targetUid: p4.uid, reason: 'suspected_bot' }, 1750000000600);
    // 2件送ったが intent には1件しか残っていない（連続クリック・リロード等で起こりうる）
    const partial = selfVerifyIntent({ vote: p1.uid, reports: [p3.uid] });
    const built = await build({ intent: partial, myReports: [p2Report, p4Report] });
    const mine = built.snapshotData.reports?.[p2.uid] || [];
    check('intent.partial_intent_keeps_all_reports', Array.isArray(mine) && mine.length === 2);
    // 署名で照合（対象の平文ではなく発信そのものが2件とも載っていること）
    const sigs = new Set(mine.map((r) => r.signature));
    check('intent.partial_intent_keeps_both_signatures',
      sigs.has(p2Report.signature) && sigs.has(p4Report.signature));
  }

  // ④ 復号不能な自分の投票（別人の encryptKey で暗号化されたもの）は拒否
  {
    const alien = await s.makeAction(p3, 'vote', { targetUid: p1.uid }, 1750000000600); // p3のencryptKey製
    const fake = { encrypted: alien.encrypted, signature: alien.signature, timestamp: alien.timestamp };
    check('intent.undecryptable_vote_refused', await codeOf(build({ intent: null, myVote: fake })) === 'vote_undecryptable');
  }

  // J-19: 別対象への出し直しは両端末から提出できる。A-3 は正規化後の自分の票だけを見る。
  {
    const voteW = s.votes[p2.uid]; // p1 宛て、受領済み
    const voteC = await s.makeAction(p2, 'vote', { targetUid: p3.uid }, s.base + 30);
    const receiptC = await s.makeActionReceipt(p4, p2.uid, 'vote', voteC, s.base + 500030);
    const receipts = [...s.allReceipts, receiptC];
    const make = (myVote, myVotePrev, intent, received = receipts, observedActions = { votes: {}, reports: {} }) => buildSubmissionBundle({
      blockNum: s.blockNum, groupId: s.groupId, myUid: p2.uid, encryptKey: p2.encryptKey,
      members: s.members, messages: s.sharedMessages, myDepositIds: JSON.parse(p2.depIds).ids,
      myVote, myVotePrev, myReports: [], observedActions, receipts: received,
      intent: { vote: intent, reports: [] }, submittedAt: s.base + 999999,
      signWallet: async (message) => p2.wallet.signMessage({ message }),
    });
    const newDevice = await make(voteC, [voteW], p3.uid);
    check('t7.two_receipted_prefers_intent', newDevice.snapshotData.votes[p2.uid].signature === voteC.signature);
    const laterIntent = await make(voteW, [voteC], p3.uid);
    check('t7.two_receipted_later_intent_wins', laterIntent.snapshotData.votes[p2.uid].signature === voteC.signature);
    const oldDevice = await make(voteW, [voteC], p1.uid);
    check('t7.mirror_prefers_intent', oldDevice.snapshotData.votes[p2.uid].signature === voteW.signature);
    const voteWAgain = await s.makeAction(p2, 'vote', { targetUid: p1.uid }, s.base + 31);
    const receiptWAgain = await s.makeActionReceipt(p4, p2.uid, 'vote', voteWAgain, s.base + 500031);
    const sameTarget = await make(voteWAgain, [voteW], p1.uid, [...receipts, receiptWAgain]);
    check('t7.same_target_resend_keeps_first_choice', sameTarget.snapshotData.votes[p2.uid].signature === voteWAgain.signature);
    const newDeviceOneReceipt = await make(voteC, [voteW], p3.uid, s.allReceipts);
    check('t7.new_device_a3_accepts_other_own_vote', newDeviceOneReceipt.snapshotData.votes[p2.uid].signature === voteW.signature);
    const oldDeviceOneReceipt = await make(voteW, [voteC], p1.uid, [receiptC]);
    check('t7.old_device_a3_accepts_other_own_vote', oldDeviceOneReceipt.snapshotData.votes[p2.uid].signature === voteC.signature);
    check('t7.substituted_votes_refused', await codeOf(make(voteW, [voteC], p4.uid)) === 'vote_mismatch');
    const otherEncrypted = encryptAction({ targetUid: p4.uid }, p2.encryptKey);
    const otherTs = s.base + 32;
    const other = { encrypted: otherEncrypted, timestamp: otherTs, signature: await p3.signAccount.signMessage({
      message: actionSignStringV2('vote', s.blockNum, s.groupId, p3.uid, otherEncrypted, otherTs),
    }) };
    check('t7.other_uid_cannot_satisfy_a3', await codeOf(make(voteW, [voteC], p4.uid, receipts,
      { votes: { [p3.uid]: other }, reports: {} })) === 'vote_mismatch');
    const unreadableEncrypted = encryptAction({ targetUid: p4.uid }, p3.encryptKey);
    const unreadableTs = s.base + 33;
    const unreadable = { encrypted: unreadableEncrypted, timestamp: unreadableTs,
      signature: await p2.signAccount.signMessage({
        message: actionSignStringV2('vote', s.blockNum, s.groupId, p2.uid, unreadableEncrypted, unreadableTs),
      }) };
    const unreadableReceipt = await s.makeActionReceipt(p4, p2.uid, 'vote', unreadable, s.base + 500033);
    const skippedUnreadable = await make(unreadable, [voteW], p1.uid, [...s.allReceipts, unreadableReceipt]);
    check('t7.undecryptable_candidate_skipped', skippedUnreadable.snapshotData.votes[p2.uid].signature === voteW.signature);
    const cappedHistory = [];
    for (let i = 0; i < 10; i++) {
      cappedHistory.push(await s.makeAction(p2, 'vote',
        { targetUid: i === 9 ? p3.uid : p4.uid }, s.base + 40 + i));
    }
    check('t7.normalized_away_intent_refused', await codeOf(make(voteW, cappedHistory, p3.uid,
      s.allReceipts)) === 'vote_mismatch');
    const withoutIntent = await s.makeP2Recovery({ intent: null });
    check('t7.honest_bytes_unchanged', withoutIntent.payload === s.p2Recovery.payload);
  }

  console.log('');
  for (const c of checks) console.log(`##CHECK ${c.id} ${c.status}`);
  const failed = checks.filter((c) => c.status !== 'pass').length;
  console.log(`##RESULT ${failed === 0 ? 'full' : 'partial'}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
