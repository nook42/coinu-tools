// ソケットを開けない環境でも同じHardhat EVM/RPCとR2 fixtureを実行する試験用アダプター。
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { EventEmitter } from 'node:events';
const require = createRequire(new URL('../../Hardhat/bitcoinu/package.json', import.meta.url));
let active;
export async function startInProcessNode({ port = 8547 } = {}) {
  const hre = require('hardhat');
  await hre.network.provider.request({ method: 'hardhat_reset', params: [] });
  active = hre.network.provider;
  const rpcUrl = `http://127.0.0.1:${port}`;
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    if (![rpcUrl, rpcUrl.replace('127.0.0.1','localhost')].includes(new URL(url).origin)) return original(input, init);
    const raw = init.body ?? (input instanceof Request ? await input.text() : null);
    const request = JSON.parse(raw);
    const one = async (row) => {
      try { return { jsonrpc: '2.0', id: row.id, result: await active.request({ method: row.method, params: row.params || [] }) }; }
      catch (e) { return { jsonrpc:'2.0',id:row.id,error:{code:e.code || -32000,message:e.message,data:e.data} }; }
    };
    const response = Array.isArray(request) ? await Promise.all(request.map(one)) : await one(request);
    return new Response(JSON.stringify(response), {headers:{'content-type':'application/json'}});
  };
  const proc = new EventEmitter(); proc.stdout = new EventEmitter(); proc.stderr = new EventEmitter();
  proc.exitCode = null; proc.kill = () => { proc.exitCode=0; };
  const stop = () => { globalThis.fetch = original; proc.exitCode = 0; };
  return {proc,rpcUrl,port,stop};
}
export async function runInProcessTool({ configPath, blockNum }) {
  const { readFileSync } = await import('node:fs');
  const { loadConfig } = await import('../src/config.js');
  const { createChain } = await import('../src/chain.js');
  const { verifyOneBlock, emitNonInteractiveOutcome } = await import('../src/index.js');
  const { t } = await import('../src/i18n.js');
  const cfg=loadConfig(['--non-interactive','--lang','en','--block',String(blockNum),'--yes','--config',configPath]);
  JSON.parse(readFileSync(configPath)); // 使用する設定はfixtureがこの試験内で生成したものだけ。
  let stdout='',stderr='';const ui={t:t('en'),println:(s='')=>{stdout+=s+'\n';},warn:(s='')=>{stderr+=s+'\n';},askYesNo:async()=>true,isInteractive:false};
  const chain=createChain(cfg,ui);await chain.probeArchive();
  const outcome=await verifyOneBlock(cfg,chain,ui,blockNum);
  const emitted=emitNonInteractiveOutcome(ui,outcome,null);
  return {code:emitted.exitCode,stdout,stderr};
}
