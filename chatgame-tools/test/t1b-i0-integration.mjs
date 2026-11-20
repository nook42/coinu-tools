import assert from 'node:assert/strict';
import { buildScenario } from './scenario.mjs';
import { calculateGroupResults } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { buildReceiptMaps, clientScoreableMessages, computeMsgKeyV2, msgRefOf,
  buildMsgKeyGetter, canonicalComparatorV2 } from '../vendor/workers/game_workers/lib/protocol-v2.js';
import { countMessageTurns, countVisibleChars, filterVisibleMessages, GUEST_PINNED_RULES } from '../vendor/workers/game_workers/lib/char-counter.js';
import { ReceiptAdmissionQueue } from '../../src/utils/relay.js';
import { buildRealTargets, receiptCoverClaim } from '../../workers/game_workers/lib/protocol-v2.js';

const sc = await buildScenario();
const [p1,p2] = sc.players;
const mine=sc.sharedMessages.filter((message)=>message.uid===p2.uid);
const X=await sc.makeReadReceipt(p1,p2.uid,mine.slice(0,10),sc.base+550000);
const Y=await sc.makeReadReceipt(p1,p2.uid,mine.slice(0,12),sc.base+550001);
const other=sc.allReceipts.filter((receipt)=>!(receipt.senderUid===p2.uid && receipt.receiverUid===p1.uid)
  && !(receipt.senderUid===p2.uid && Array.isArray(receipt.msgRefs)));
const material=[...other,X,Y];
const views=[];
const flows = [
  ['公式の新セッション', material],
  ['Q の受領証明が先着', [Y,...other,X]],
  ['開き直しで P2P だけ', [X,...other.slice().reverse(),Y]],
  ['復元の新セッション', [...other.slice().reverse(),Y,X]],
  ['復元で live を入れ直し', [Y,X,...other.slice().reverse()]],
];
const rosterUids=sc.members.map((member)=>member.uid);
const targets=buildRealTargets({votes:{},reports:{},observed:{votes:{},reports:{}}},
  sc.sharedMessages,sc.blockNum,sc.groupId);
for(const [flow,receipts] of flows) {
  const queue=new ReceiptAdmissionQueue({
    getRosterUids:()=>rosterUids,verifyReceipt:async()=>true,
    resolveReceipt:(receipt)=>{
      const claim=receiptCoverClaim(receipt,targets,{memberUids:rosterUids,selfUid:p2.uid,atomic:true});
      return claim.keys.length>0?{state:'covered',facts:claim.keys}:{state:'invalid'};
    },
    getChatWindow:()=>null,
    getSelectionContext:()=>({messages:sc.sharedMessages,blockNum:sc.blockNum,
      groupId:sc.groupId,myUid:p2.uid,caps:GUEST_PINNED_RULES}),
  });
  for(const receipt of receipts.filter((item)=>Array.isArray(item.msgRefs)))
    await queue.offer(receipt,{verified:true});
  const officialSelected=queue.getAcceptedReceipts()
    .filter((receipt)=>receipt.receiverUid===p1.uid&&receipt.senderUid===p2.uid)
    .map((receipt)=>receipt.signature).sort();
  queue.dispose();
  const built=await sc.makeP2Recovery({receipts});
  const carried=built.bundle.encryptedActions.observed.receipts;
  const capped=clientScoreableMessages(built.bundle.messages,carried,{
    blockNum:sc.blockNum,groupId:sc.groupId,myUid:p2.uid,caps:GUEST_PINNED_RULES,
    compare:canonicalComparatorV2(buildMsgKeyGetter(sc.blockNum,sc.groupId)),
  });
  const maps=buildReceiptMaps(carried,{messages:capped,myUid:p2.uid},sc.blockNum,sc.groupId);
  const visible=filterVisibleMessages(capped.filter((message)=>{
    const ref=msgRefOf(computeMsgKeyV2(sc.blockNum,sc.groupId,message));
    return [...(maps.readersByMsgKey[ref]||[])].some((uid)=>uid!==message.uid);
  }));
  const turn=countMessageTurns(visible)[p2.uid]||0;
  const chars=visible.filter((message)=>message.uid===p2.uid)
    .reduce((sum,message)=>sum+countVisibleChars(message.text),0);
  const reportButton=visible.filter((message)=>message.uid===p1.uid).length>=5;
  const {results}=await calculateGroupResults({members:sc.members,
    submissions:{[p2.uid]:built.bundle},meta:{blockNum:sc.blockNum,groupId:sc.groupId}},500,10,{},null);
  const selected=carried.filter((receipt)=>receipt.receiverUid===p1.uid&&receipt.senderUid===p2.uid)
    .map((receipt)=>receipt.signature).sort();
  assert.deepEqual(officialSelected,selected,`${flow}: 公式待ち行列と復元の選抜`);
  views.push({flow,turn,chars,reportButton,payload:built.payload,
    selected,
    score:results.find((result)=>result.uid===p2.uid)});
}
for(const view of views.slice(1)) {
  assert.equal(views[0].turn,view.turn,`${view.flow}: I0 画面の会話回数`);
  assert.equal(views[0].chars,view.chars,`${view.flow}: I0 画面の文字数`);
  assert.equal(views[0].reportButton,view.reportButton,`${view.flow}: I0 密告ボタン`);
  assert.deepEqual(views[0].selected,view.selected,`${view.flow}: I0 提出物の既読`);
  assert.equal(views[0].payload,view.payload,`${view.flow}: I0 提出物のバイト列`);
  assert.deepEqual(views[0].score,view.score,`${view.flow}: I0 採点本体の結果`);
}
let arrivedMessages=mine.slice(0,10);
let arrivedTargets=buildRealTargets({votes:{},reports:{},observed:{votes:{},reports:{}}},
  arrivedMessages,sc.blockNum,sc.groupId);
const removed=[];
const sameSession=new ReceiptAdmissionQueue({
  getRosterUids:()=>rosterUids,verifyReceipt:async()=>true,
  resolveReceipt:(receipt)=>{
    const claim=receiptCoverClaim(receipt,arrivedTargets,{memberUids:rosterUids,atomic:true});
    return claim.keys.length>0?{state:'covered',facts:claim.keys}:{state:'pending'};
  },
  getChatWindow:()=>null,
  getSelectionContext:()=>({messages:arrivedMessages,blockNum:sc.blockNum,
    groupId:sc.groupId,myUid:p2.uid,caps:GUEST_PINNED_RULES}),
  onRemove:(receipt)=>removed.push(receipt.signature),
});
await sameSession.offer(X,{verified:true});
await sameSession.offer(Y,{verified:true});
assert.deepEqual(sameSession.getAcceptedReceipts().map((receipt)=>receipt.signature),[X.signature],
  '同じセッション: 既読が先で後続発言が未着なら X を保持');
arrivedMessages=mine;
arrivedTargets=targets;
await sameSession.reevaluate();
assert.deepEqual(sameSession.getAcceptedReceipts().map((receipt)=>receipt.signature),[X.signature,Y.signature],
  '同じセッション: 発言が後から着くと X と Y を両方受け入れる');
assert(!removed.includes(X.signature),'同じセッション: 旧既読を画面から撤回しない');
sameSession.dispose();
console.log(`T1b I0: ALL PASSED; flows=${views.length}; turns=${views[0].turn}; report=${views[0].reportButton}`);

// T1d: 本番の枚数に近い41候補・自分の既読21枚を含む結合盤面。
await import('./t1d-f1-integration.mjs');
