import { registerHooks } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { validateR2MultipartParts } from './stubs.mjs';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ETHERS_ENTRY = pathToFileURL(resolve(root, 'node_modules/ethers/packages/ethers/lib/index.js')).href;
registerHooks({ resolve(s, c, n) { return s === 'ethers' ? { url: ETHERS_ENTRY, shortCircuit: true } : n(s, c); } });
const { GameMasterDO } = await import(pathToFileURL(resolve(root, process.env.T4B_GM_PATH || 'workers/game_workers/game-master-DO.js')).href);
const BLOCK = 9;
const hash = s => createHash('sha256').update(s).digest('hex');
function make(N, rowChange = null) {
  const rows = Array.from({ length: N }, (_, i) => {
    const seq = i + 1; const valid = seq % 17 === 0 ? 1 : 0;
    return { seq, tx_hash: `0x${seq.toString(16).padStart(64, '0')}`, sender: `0x${'11'.repeat(20)}`, valid,
      invalid_reason: valid ? null : (seq % 9 === 0 ? 'invalid_signature' : 'unsupported_format'),
      uid: valid ? (seq % 3 === 0 ? String(seq % 7) : `u${seq % 53}`) : null,
      group_id: valid ? 1 : null };
  });
  rowChange?.(rows);
  const map = new Map();
  const storage = {
    async get(k) { if (Array.isArray(k)) return new Map(k.filter(x => map.has(x)).map(x => [x, map.get(x)])); return map.get(k); },
    async put(k, v) { if (typeof k === 'object') { for (const [x, y] of Object.entries(k)) map.set(x, y); }
      else { if (String(k).startsWith(`calc:${BLOCK}:`)) assert(Buffer.byteLength(JSON.stringify(v))<100000,`${k} exceeds VALUE_SAFE_BYTES`); map.set(k, v); } },
    async delete(k) { if (Array.isArray(k)) k.forEach(x => map.delete(x)); else map.delete(k); },
    async list({prefix,limit} = {}) { return new Map([...map].filter(([k]) => !prefix || k.startsWith(prefix)).slice(0,limit ?? Infinity)); },
  };
  const db = { prepare(sql) { return { bind(...args) { return { async all() {
    if (/SELECT seq, tx_hash, sender, valid, invalid_reason, uid, group_id/.test(sql)) {
      const slice = sql.includes('seq > ?') ? rows.filter(r => r.seq > args[1] && r.seq <= args[2]).slice(0, args[3]) : rows.filter(r => r.seq <= args[1]);
      return { results: JSON.parse(JSON.stringify(slice)) };
    }
    if (/SELECT seq, data_len FROM evidence_events/.test(sql)) {
      return { results: rows.filter(r => r.seq > args[1] && r.seq <= args[2])
        .slice(0, args[3]).map(r => ({ seq: r.seq, data_len: 1 })) };
    }
    throw Error(`SQL ${sql}`);
  } }; } }; } };
  const chain = { async getBlock() { return { number: 1000n, timestamp: 2000000000n }; },
    async readContract({functionName}) { if (functionName === 'resultWindow' || functionName === 'chatWindow') return [1n, 2n]; if (functionName === 'resultCount') return BigInt(N); throw Error(functionName); } };
  let body = null; const segmentObjects = new Map(); const uploads = new Map(); const attempts = new Map(); let completed = false; const ranges = [];
  const r2 = {
    async get(key, opts) { const object = key.endsWith('/evidence-segments.json') ? segmentObjects.get(key) : body; if (object == null) return null; const bytes = Buffer.from(object); if (opts?.range) ranges.push(opts.range); const view = opts?.range ? bytes.subarray(opts.range.offset, opts.range.offset + opts.range.length) : bytes; return { size: bytes.length, async text() { return view.toString(); }, async arrayBuffer() { return Uint8Array.from(view).buffer; } }; },
    async put(key, value) { if (key.endsWith('/evidence-segments.json')) segmentObjects.set(key, String(value)); else body = String(value); return {}; },
    async createMultipartUpload() { uploads.clear(); completed = false; return { uploadId: 'one' }; },
    resumeMultipartUpload() { return { async uploadPart(n, value) { if (completed) throw Error('R2 multipart already completed'); const bytes=Uint8Array.from(typeof value === 'string' ? Buffer.from(value) : value); uploads.set(n,bytes); if (!attempts.has(n)) attempts.set(n,[]); attempts.get(n).push(bytes); return {partNumber:n, etag:`etag${n}`}; },
      async complete(parts) { validateR2MultipartParts(parts, uploads); body = Buffer.concat(parts.map(p=>Buffer.from(uploads.get(p.partNumber)))).toString(); completed = true; },
    }; },
    get body() { return body; }, set body(value) { body = value; }, get uploads() { return uploads; }, get attempts() { return attempts; }, get ranges() { return ranges; },
  };
  const gm = new GameMasterDO({ storage, getWebSockets: () => [], getTags: () => [], acceptWebSocket() {} }, {
    RELEASE_TIME:'2099-01-01T00:00:00Z', EVIDENCE_CONTRACT_ADDRESS:'0x'+'e'.repeat(40), HASH_STORAGE_CONTRACT_ADDRESS:'0x'+'2'.repeat(40), ETHEREUM_MAINNET_RPC_URL:'http://stub', CONFIRMATION_BLOCKS:'0', BITCOINU_DATA:db, R2_BUCKET:r2,
  }); gm.createReadOnlyClient = () => chain;
  return { gm, storage, r2, map, rows };
}
async function run(N, mutation = null, rowChange = null) {
  const {gm,storage,r2,map,rows} = make(N, rowChange);
  let progress = {stage:'evidence',cursor:0,rosterSubmission:{accepted:true,reason:null},evidenceIngest:{segs:[['0','100']],segIdx:1,next:'101',widened:false,done:true,seen:[[1,N]],judgedAtIngest:true}};
  let units = 0;
  while (progress.stage === 'evidence') { progress = await gm.calcEvidenceUnit(BLOCK,progress); if (++units > N + 3) throw Error('loop'); }
  const rec = await gm.calcLoadAdopted(BLOCK);
  rec.invalid=[];
  for(let i=0;i<rec.invalidChunks;i++) rec.invalid.push(...(await storage.get(`calc:${BLOCK}:invalid_chunk:${i}`)||[]));
  mutation?.(map, rec);
  const adoption = Object.create(null);
  for (const a of rec.adopted) adoption[a.uid] = {serverState:'no_submit'};
  await storage.put(`calc:${BLOCK}:score:1`,{adoption});
  const report = {contractAddress:rec.meta.contractAddress,blockNum:BLOCK,resultCount:N,window:rec.meta.window,chatWindow:rec.meta.chatWindow,safeBlock:rec.meta.safeBlock,confirmations:rec.meta.confirmations,
    adopted:rec.adopted.filter(a=>adoption[a.uid]).map(a=>({uid:a.uid,groupId:a.groupId,seq:a.seq,txHash:a.txHash,serverState:adoption[a.uid].serverState})),invalid:rec.invalid};
  if (rec.invalidCount <= 10000) await gm.publishEvidenceReportIdempotent(BLOCK,report);
  else { let p={stage:'summary',summaryPhase:'evidence_report',rosterSubmission:{accepted:true},evidence:{disabled:false}}; while (!(await gm.calcPublishEvidenceReportUnit(BLOCK,p,[{group_id:1}]))) {if(++units>N+20) throw Error('report loop');} }
  return {report:r2.body,adopted:rec.adopted,invalid:rec.invalid,expected:beforeReport(rows,rec.meta),meta:rec.meta,
    partSizes:[...r2.uploads.values()].map(p=>p.byteLength)};
}
// D-06 時点の最終 SELECT 後の選択と旧 publishEvidenceReportIdempotent の
// JSON.stringify 本文を複製した参照。関数の変更と独立に公開バイトを固定する。
function beforeReport(rows, meta) {
  const adoptedByUid = Object.create(null);
  const invalid = [];
  for (const row of rows) {
    if (!row.valid) { invalid.push({seq:row.seq,txHash:row.tx_hash,reason:row.invalid_reason}); continue; }
    if (row.uid == null || adoptedByUid[row.uid]) continue;
    adoptedByUid[row.uid] = {groupId:row.group_id,seq:row.seq,txHash:row.tx_hash,sender:row.sender};
  }
  const adopted = Object.entries(adoptedByUid).map(([uid,a]) => ({uid,groupId:a.groupId,seq:a.seq,txHash:a.txHash,sender:a.sender}));
  const report = {contractAddress:meta.contractAddress,blockNum:BLOCK,resultCount:rows.length,
    window:meta.window,chatWindow:meta.chatWindow,safeBlock:meta.safeBlock,confirmations:meta.confirmations,
    adopted:adopted.map(a=>({uid:a.uid,groupId:a.groupId,seq:a.seq,txHash:a.txHash,serverState:'no_submit'})),invalid};
  return {adopted,invalid,text:JSON.stringify(report)};
}
let sampleMeta;
for (const N of [31,5001,15017,65017,200017,500017]) {
  const current = await run(N);
  if (N===31) sampleMeta=current.meta;
  assert.deepEqual(current.adopted,current.expected.adopted);
  assert.deepEqual(current.invalid,current.expected.invalid);
  assert.equal(current.report,current.expected.text);
  if (current.partSizes.length > 1) {
    assert(current.partSizes.slice(0,-1).every(size=>size===6*1024*1024));
    assert(current.partSizes.at(-1)>0&&current.partSizes.at(-1)<=6*1024*1024);
  }
  console.log(`T4 BYTE_EQUAL N=${N} bytes=${Buffer.byteLength(current.report)} sha256=${hash(current.report)}`);
}
{
  const P = 6*1024*1024;
  const reportOf = N => beforeReport(make(N).rows,{...sampleMeta,resultCount:N}).text;
  let low=100000, high=120000;
  while(low<high){const mid=Math.floor((low+high)/2);if(Buffer.byteLength(reportOf(mid))<2*P)low=mid+1;else high=mid;}
  let exactN=low-1;
  while(exactN%17===0)exactN--;
  const padding=2*P-Buffer.byteLength(reportOf(exactN));
  assert(padding>0&&padding<500);
  const exact=await run(exactN,null,rows=>{rows[exactN-1].invalid_reason+='a'.repeat(padding);});
  assert.equal(Buffer.byteLength(exact.report),2*P);
  assert.equal(exact.report,exact.expected.text);
  console.log(`T4b EXACT_MULTIPLE N=${exactN} padding=${padding} bytes=${2*P} BYTE_EQUAL`);

  const utfN=65017, base=reportOf(utfN);
  const pattern=/"reason":"(?:unsupported_format|invalid_signature)"/g;
  let found, match, invalidIndex=0;
  while((match=pattern.exec(base))){
    const emojiAt=match.index+match[0].length-1;
    const gap=P-1-emojiAt;
    if(gap>=0&&gap<500){found={invalidIndex,gap};break;}
    invalidIndex++;
  }
  assert(found,'no invalid reason near the UTF-8 part boundary');
  const utf=await run(utfN,null,rows=>{
    const row=rows.filter(r=>!r.valid)[found.invalidIndex];
    row.invalid_reason+='a'.repeat(found.gap)+'🦊';
  });
  assert.deepEqual([...Buffer.from(utf.report).subarray(P-1,P+3)],[0xf0,0x9f,0xa6,0x8a]);
  assert.equal(utf.report,utf.expected.text);
  console.log(`T4b UTF8_SPLIT N=${utfN} invalidIndex=${found.invalidIndex} padding=${found.gap} boundary=${P} BYTE_EQUAL`);
}
for (const [name, mutate] of [
  ['boundary_plus_one', map => { const a=map.get('calc:9:invalid_chunk:0'); const b=map.get('calc:9:invalid_chunk:1'); b[0]=a.at(-1); }],
  ['drop_chunk', map => { map.delete('calc:9:invalid_chunk:1'); }],
]) {
  try {
    const changed = await run(15017,mutate);
    assert.equal(changed.report,changed.expected.text);
    throw Error(`mutation unexpectedly green: ${name}`);
  } catch(e) {
    if (/unexpectedly green/.test(String(e))) throw e;
    console.log(`T4 MUTATION_RED ${name}: ${String(e.message).slice(0,90)}`);
  }
}
{
  const w = make(817);
  let p = {stage:'evidence',cursor:0,rosterSubmission:{accepted:true,reason:null},
    evidenceIngest:{segs:[['0','100']],segIdx:1,next:'101',widened:false,done:true,
      seen:[[1,817]],judgedAtIngest:true}};
  const put = w.storage.put.bind(w.storage);
  let fault = true;
  w.storage.put = async (key,value) => {
    await put(key,value);
    if (fault && key === 'calc:9:invalid_chunk:0') { fault=false; throw Error('injected page failure'); }
  };
  await assert.rejects(w.gm.calcEvidenceUnit(BLOCK,p),/injected page failure/);
  assert.equal(p.evidenceFinal,undefined);
  while (p.stage === 'evidence') p = await w.gm.calcEvidenceUnit(BLOCK,p);
  const rec = await w.gm.calcLoadAdopted(BLOCK,{withInvalid:true});
  assert.deepEqual(rec.invalid,beforeReport(w.rows,rec.meta).invalid);
  console.log('T4 RETRY page_failure BYTE_EQUAL');
}
{
  const N=65017; const w=make(N);
  let p={stage:'evidence',cursor:0,rosterSubmission:{accepted:true,reason:null},
    evidenceIngest:{segs:[['0','100']],segIdx:1,next:'101',widened:false,done:true,
      seen:[[1,N]],judgedAtIngest:true}};
  while (p.stage === 'evidence') p=await w.gm.calcEvidenceUnit(BLOCK,p);
  const rec=await w.gm.calcLoadAdopted(BLOCK);
  const adoption=Object.create(null);
  for(const a of rec.adopted) adoption[a.uid]={serverState:'no_submit'};
  await w.storage.put(`calc:${BLOCK}:score:1`,{adoption});
  const resume=w.r2.resumeMultipartUpload.bind(w.r2);
  let fault=true;
  w.r2.resumeMultipartUpload=()=>{
    const upload=resume();
    return {...upload,async uploadPart(n,body){
      if(fault&&n===2){fault=false;throw Error('injected part failure');}
      return upload.uploadPart(n,body);
    }};
  };
  let reportProgress={stage:'summary',summaryPhase:'evidence_report',
    rosterSubmission:{accepted:true},evidence:{disabled:false}};
  let failures=0,done=false;
  for(let i=0;i<20&&!done;i++){
    try{done=await w.gm.calcPublishEvidenceReportUnit(BLOCK,reportProgress,[{group_id:1}]);}
    catch(e){assert.match(String(e),/injected part failure/);failures++;}
  }
  assert.equal(failures,1); assert(done);
  assert.equal(w.r2.body,beforeReport(w.rows,rec.meta).text);
  const original=w.r2.body;
  const marker=await w.storage.get(`calc:${BLOCK}:adopted`);
  marker.meta={...marker.meta,safeBlock:'99999'};
  await w.storage.put(`calc:${BLOCK}:adopted`,marker);
  reportProgress={stage:'summary',summaryPhase:'evidence_report',
    rosterSubmission:{accepted:true},evidence:{disabled:false}};
  done=false;
  for(let i=0;i<20&&!done;i++) done=await w.gm.calcPublishEvidenceReportUnit(BLOCK,reportProgress,[{group_id:1}]);
  assert(done); assert.equal(w.r2.body,original);
  console.log('T4 RETRY part_failure AND safeBlock_idempotency BYTE_EQUAL');
}
{
  const w=make(1);
  for(let i=0;i<2500;i++) await w.storage.put(`calc:${BLOCK}:invalid_chunk:${i}`,[{seq:i}]);
  let largest=0;
  const list=w.storage.list.bind(w.storage);
  w.storage.list=async options=>{const page=await list(options);largest=Math.max(largest,page.size);return page;};
  await w.gm.calcCleanupKeys(BLOCK);
  assert.equal([...w.map.keys()].filter(k=>k.startsWith(`calc:${BLOCK}:`)).length,0);
  assert(largest<=128);
  console.log('T4 CLEANUP 2500_chunks max_page=128');
}
{
  const w=make(1);
  const chunks=[new TextEncoder().encode('前半:é'),new TextEncoder().encode('後半:🦊')];
  const obj={body:new ReadableStream({start(controller){for(const c of chunks)controller.enqueue(c);controller.close();}}),
    async text(){throw Error('full text load forbidden');}};
  const actual=await w.gm.sha256R2Object(obj);
  const expected=createHash('sha256').update(chunks[0]).update(chunks[1]).digest('hex');
  assert.equal(actual,expected);
  console.log('T4 STREAM_SHA256 BYTE_EQUAL');
}
{
  // 新版の途中カーソルで旧版へ戻り、旧500件チャンクのマーカーを旧版が確定した形。
  // 再配備した新版はマーカーの宣言件数だけを読み、途中の200件チャンクを無視する。
  const N=817; const w=make(N);
  let p={stage:'evidence',cursor:0,rosterSubmission:{accepted:true,reason:null},
    evidenceIngest:{segs:[['0','100']],segIdx:1,next:'101',widened:false,done:true,
      seen:[[1,N]],judgedAtIngest:true}};
  p=await w.gm.calcEvidenceUnit(BLOCK,p);
  assert.equal(p.evidenceFinal.cursor,400);
  const meta={contractAddress:'0x'+'e'.repeat(40),resultCount:N,
    window:{openAt:1,closeAt:2},chatWindow:{chatOpenAt:1,chatCloseAt:2,clockSkewAllowMs:120000},
    safeBlock:'1000',confirmations:0};
  const old=beforeReport(w.rows,meta);
  await w.gm.calcStoreAdopted(BLOCK,{adopted:old.adopted,invalid:old.invalid,meta});
  const rec=await w.gm.calcLoadAdopted(BLOCK,{withInvalid:true});
  assert.deepEqual(rec.adopted,old.adopted);
  assert.deepEqual(rec.invalid,old.invalid);
  console.log('T4 LEGACY_MARKER new->old->new BYTE_EQUAL');
}
{
  const w=make(1);
  const status=w.gm.slimCalcProgress({stage:'summary',cursor:321,summaryPhase:'evidence_report',
    evidenceFinal:{cursor:300,invalidCount:280,adoptedCount:2},
    evidenceReport:{mode:'upload',chunk:5,partNumber:3}});
  assert.deepEqual(status.evidenceFinal,{seq:300,invalidCount:280,adoptedCount:2});
  assert.deepEqual(status.evidenceReport,{mode:'upload',invalidChunk:5,partNumber:3,partByteOffset:12582912});
  console.log('T4 STATUS final_seq/report_part visible');
}
{
  const invalid=Array.from({length:200},(_,i)=>({seq:i+1,txHash:`0x${'f'.repeat(64)}`,reason:'unsupported_format'}));
  const adopted=Array.from({length:200},(_,i)=>({uid:`${i}`.padStart(64,'x'),groupId:1,seq:i+1,txHash:`0x${'f'.repeat(64)}`}));
  const invalidBytes=Buffer.byteLength(JSON.stringify(invalid));
  const adoptedBytes=Buffer.byteLength(JSON.stringify(adopted));
  assert(invalidBytes<100000&&adoptedBytes<100000);
  console.log(`T4 STORAGE_CHUNK invalid=${invalidBytes}B adopted=${adoptedBytes}B < VALUE_SAFE_BYTES`);
}
{
  const w=make(1);
  await w.storage.put(`calc:${BLOCK}:adopted`,{invalidCount:10001,adoptedChunks:0,invalidChunks:51});
  await assert.rejects(w.gm.calcLoadAdopted(BLOCK,{withInvalid:true}),/large invalid list/);
  console.log('T4 LARGE_LOAD rejected before joining invalid chunks');
}
{
  // 新版が part 1 を書いたあと、旧版の一括 report が公開され、再び新版へ戻る。
  const N=65017; const w=make(N);
  let p={stage:'evidence',cursor:0,rosterSubmission:{accepted:true,reason:null},
    evidenceIngest:{segs:[['0','100']],segIdx:1,next:'101',widened:false,done:true,
      seen:[[1,N]],judgedAtIngest:true}};
  while(p.stage==='evidence')p=await w.gm.calcEvidenceUnit(BLOCK,p);
  const rec=await w.gm.calcLoadAdopted(BLOCK);
  const adoption=Object.create(null);
  for(const a of rec.adopted)adoption[a.uid]={serverState:'no_submit'};
  await w.storage.put(`calc:${BLOCK}:score:1`,{adoption});
  const rp={stage:'summary',summaryPhase:'evidence_report',rosterSubmission:{accepted:true},evidence:{disabled:false}};
  assert.equal(await w.gm.calcPublishEvidenceReportUnit(BLOCK,rp,[{group_id:1}]),false);
  const oldText=beforeReport(w.rows,rec.meta).text;
  w.r2.body=oldText;
  let done=false;
  for(let i=0;i<20&&!done;i++)done=await w.gm.calcPublishEvidenceReportUnit(BLOCK,rp,[{group_id:1}]);
  assert(done);assert.equal(w.r2.body,oldText);
  console.log('T4 REPORT_VERSION_CYCLE new->old->new BYTE_EQUAL');
}

// T4b: 3 part 以上の盤面で、R2 の書込・storage・complete の両側をそれぞれ落とす。
async function preparedReport(N = 200017) {
  const w = make(N);
  let ep = {stage:'evidence',cursor:0,rosterSubmission:{accepted:true,reason:null},
    evidenceIngest:{segs:[['0','100']],segIdx:1,next:'101',widened:false,done:true,
      seen:[[1,N]],judgedAtIngest:true}};
  while (ep.stage === 'evidence') ep = await w.gm.calcEvidenceUnit(BLOCK,ep);
  const rec = await w.gm.calcLoadAdopted(BLOCK);
  const adoption = Object.create(null);
  for (const a of rec.adopted) adoption[a.uid] = {serverState:'no_submit'};
  await w.storage.put(`calc:${BLOCK}:score:1`,{adoption});
  return { ...w, expected:beforeReport(w.rows,rec.meta).text,
    progress:{stage:'summary',summaryPhase:'evidence_report',rosterSubmission:{accepted:true},evidence:{disabled:false}} };
}
for (const faultAt of ['upload-before','upload-after','storage-before','storage-after','complete-before','complete-after','progress-before','progress-after']) {
  const w = await preparedReport();
  const originalResume = w.r2.resumeMultipartUpload.bind(w.r2);
  const originalPut = w.storage.put.bind(w.storage);
  let injected = false;
  if (faultAt.startsWith('upload') || faultAt.startsWith('complete')) {
    w.r2.resumeMultipartUpload = (...args) => {
      const upload = originalResume(...args);
      return { ...upload,
        async uploadPart(n, data) {
          if (!injected && n === 2 && faultAt === 'upload-before') { injected = true; throw Error('injected upload-before'); }
          const part = await upload.uploadPart(n,data);
          if (!injected && n === 2 && faultAt === 'upload-after') { injected = true; throw Error('injected upload-after'); }
          return part;
        },
        async complete(parts) {
          if (!injected && faultAt === 'complete-before') { injected = true; throw Error('injected complete-before'); }
          await upload.complete(parts);
          if (!injected && faultAt === 'complete-after') { injected = true; throw Error('injected complete-after'); }
        },
      };
    };
  }
  if (faultAt.startsWith('storage')) {
    w.storage.put = async (key, value) => {
      if (!injected && key === `calc:${BLOCK}:report_part:2` && faultAt === 'storage-before') { injected = true; throw Error('injected storage-before'); }
      await originalPut(key,value);
      if (!injected && key === `calc:${BLOCK}:report_part:2` && faultAt === 'storage-after') { injected = true; throw Error('injected storage-after'); }
    };
  }
  let done = false;
  for (let unit = 0; unit < 30 && !done; unit++) {
    const saved = structuredClone(w.progress);
    try {
      done = await w.gm.calcPublishEvidenceReportUnit(BLOCK,w.progress,[{group_id:1}]);
      if (!injected && faultAt.startsWith('progress') && saved.evidenceReport?.partNumber === 2) {
        injected = true;
        if (faultAt === 'progress-before') w.progress = saved;
        throw Error(`injected ${faultAt}`);
      }
    } catch (error) {
      assert.match(String(error),/injected|R2 multipart already completed/);
    }
  }
  assert(injected && done, `${faultAt}: retry did not complete`);
  assert.equal(w.r2.body,w.expected,`${faultAt}: public bytes changed`);
  assert.deepEqual([...w.r2.uploads.keys()],[1,2,3,4],`${faultAt}: part numbering changed`);
  for(const versions of w.r2.attempts.values()) assert(versions.every(v=>Buffer.from(v).equals(Buffer.from(versions[0]))),`${faultAt}: retry changed part bytes`);
  assert(Buffer.byteLength(JSON.stringify(w.progress.evidenceReport))<100000);
  console.log(`T4b RETRY ${faultAt} BYTE_EQUAL`);
}
{
  const w = await preparedReport();
  let done = false, finalCheckpoint;
  for(let i=0;i<20&&!done;i++){
    finalCheckpoint=structuredClone(w.progress);
    done=await w.gm.calcPublishEvidenceReportUnit(BLOCK,w.progress,[{group_id:1}]);
  }
  assert(done);
  const retry=await w.gm.calcPublishEvidenceReportUnit(BLOCK,finalCheckpoint,[{group_id:1}]);
  assert.equal(retry,false);
  let confirmed=false;
  for(let i=0;i<20&&!confirmed;i++) confirmed=await w.gm.calcPublishEvidenceReportUnit(BLOCK,finalCheckpoint,[{group_id:1}]);
  assert(confirmed);
  assert.equal(w.r2.body,w.expected);
  console.log('T4b RETRY complete_published_progress_lost BYTE_EQUAL');
}
{
  const w = await preparedReport();
  let done = false;
  while (!done) done = await w.gm.calcPublishEvidenceReportUnit(BLOCK,w.progress,[{group_id:1}]);
  const original = w.r2.body;
  const marker = await w.storage.get(`calc:${BLOCK}:adopted`);
  marker.meta = {...marker.meta,safeBlock:'99999'};
  await w.storage.put(`calc:${BLOCK}:adopted`,marker);
  w.progress = {stage:'summary',summaryPhase:'evidence_report',rosterSubmission:{accepted:true},evidence:{disabled:false}};
  done = false;
  while (!done) done = await w.gm.calcPublishEvidenceReportUnit(BLOCK,w.progress,[{group_id:1}]);
  assert.equal(w.r2.body,original);
  assert.deepEqual(w.r2.ranges.filter(r=>r.length===6*1024*1024).map(r=>r.offset),[0,6*1024*1024,12*1024*1024]);
  console.log('T4b COMPARE range offsets 0,P,2P BYTE_EQUAL');
}
{
  const P = 6*1024*1024;
  const uploads = new Map([[1,new Uint8Array(P)],[2,new Uint8Array(P)],[3,new Uint8Array(1)]]);
  const parts = [1,2,3].map(partNumber=>({partNumber,etag:`etag${partNumber}`}));
  validateR2MultipartParts(parts,uploads);
  uploads.set(1,new Uint8Array(P+1));
  assert.throws(()=>validateR2MultipartParts(parts,uploads),/non-final parts differ/);
  uploads.set(1,new Uint8Array(P));
  uploads.set(2,new Uint8Array(5*1024*1024-1));
  assert.throws(()=>validateR2MultipartParts(parts,uploads),/below 5MiB/);
  uploads.set(2,new Uint8Array(P));
  const overMax=new Uint8Array(1);
  Object.defineProperty(overMax,'byteLength',{value:5*1024**3+1});
  uploads.set(3,overMax);
  assert.throws(()=>validateR2MultipartParts(parts,uploads),/outside 1B..5GiB/);
  uploads.set(3,new Uint8Array(1));
  uploads.set(3,new Uint8Array(P+1));
  assert.throws(()=>validateR2MultipartParts(parts,uploads),/final part larger/);
  uploads.set(3,new Uint8Array(1));
  assert.throws(()=>validateR2MultipartParts([{partNumber:0,etag:'etag0'}],new Map([[0,new Uint8Array(1)]])),/invalid part number/);
  assert.throws(()=>validateR2MultipartParts([{partNumber:10001,etag:'etag10001'}],new Map([[10001,new Uint8Array(1)]])),/invalid part number/);
  assert.throws(()=>validateR2MultipartParts(Array.from({length:10001},(_,i)=>({partNumber:i+1,etag:`etag${i+1}`})),new Map()),/part count outside/);
  console.log('T4b MUTATION_RED one_byte_shift / below_5MiB / part_numbers');
}
console.log('T4 ALL PASSED');
