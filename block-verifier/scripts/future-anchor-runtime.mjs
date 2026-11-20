// Recreate the canonical runtime from the existing Hardhat build-info, without compiling.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const hardhat = path.join(root, 'Hardhat/bitcoinu');
const sourceName = 'contracts/FutureAnchorProvider.sol';
const output = path.join(root, 'block-verifier/src/future-anchor-runtime.json');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

export function canonicalFutureAnchorRuntime() {
  const source = fs.readFileSync(path.join(hardhat, sourceName), 'utf8');
  const config = fs.readFileSync(path.join(hardhat, 'hardhat.config.js'), 'utf8');
  const compiler = /version:\s*['"]0\.8\.24['"]/.exec(config);
  if (!compiler) throw new Error('Hardhat Solidity 0.8.24 compiler missing');
  const compilerTail = config.slice(compiler.index + compiler[0].length);
  const nextSection = compilerTail.search(/\b(?:version|networks):\s*(?:['"]|\{)/);
  const settings = nextSection < 0 ? compilerTail : compilerTail.slice(0, nextSection);
  if (!/optimizer:\s*\{\s*enabled:\s*true,\s*runs:\s*1\s*\}/.test(settings)
      || !/evmVersion:\s*['"]cancun['"]/.test(settings)) throw new Error('Hardhat Solidity settings changed');
  const debug = JSON.parse(fs.readFileSync(path.join(hardhat,
    'artifacts/contracts/FutureAnchorProvider.sol/FutureAnchorProvider.dbg.json'), 'utf8'));
  const info = JSON.parse(fs.readFileSync(path.resolve(hardhat,
    'artifacts/contracts/FutureAnchorProvider.sol', debug.buildInfo), 'utf8'));
  if (info.solcVersion !== '0.8.24'
      || info.input.settings?.optimizer?.enabled !== true
      || info.input.settings?.optimizer?.runs !== 1
      || info.input.settings?.evmVersion !== 'cancun'
      || info.input.sources?.[sourceName]?.content !== source) throw new Error('build-info source/settings do not match current Hardhat');
  const bytecode = info.output.contracts?.[sourceName]?.FutureAnchorProvider?.evm?.deployedBytecode;
  if (!/^(?:0x)?[0-9a-fA-F]+$/.test(bytecode?.object || '')) throw new Error('canonical runtime code missing');
  const refs = Object.values(bytecode.immutableReferences || {}).flat();
  if (refs.length !== 2 || refs.some((ref) => ref.length !== 32)) throw new Error('unexpected immutable references');
  return {
    solcVersion: info.solcVersion,
    settings: { optimizer: info.input.settings.optimizer, evmVersion: info.input.settings.evmVersion },
    sourceSha256: sha256(source),
    object: bytecode.object.startsWith('0x') ? bytecode.object : `0x${bytecode.object}`,
    immutableReferences: refs,
  };
}

export function checkFutureAnchorRuntimeJson(savedPath = output) {
  const expected = canonicalFutureAnchorRuntime();
  const saved = JSON.parse(fs.readFileSync(savedPath, 'utf8'));
  if (JSON.stringify(saved) !== JSON.stringify(expected)) throw new Error('FutureAnchorProvider runtime JSON is stale');
  return saved;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--check')) checkFutureAnchorRuntimeJson();
  else fs.writeFileSync(output, `${JSON.stringify(canonicalFutureAnchorRuntime(), null, 2)}\n`);
  console.log('FutureAnchorProvider runtime JSON OK');
}
