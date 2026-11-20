const encoder = new TextEncoder();

// PV 第15語の値は roster manifest の生テキストhash と全メンバーの根を束縛する C。
// 式は名簿の正本を再利用し、ここに別実装を置かない。
export { buildRosterMemberCommitment, rosterCommitment } from './roster-member-root.js';

export const ZKP_EXPECTED = Object.freeze({
  vkey: '0x00d258b43a015967351e5b67c8d4faa3b5d86795e89c0eb8574a9e2213be6143',
  elfSha256: '0x9140e86851d5e0ba5d6cd25441d86913043ef8dc4c198a0fa6d3456a54e77368',
  selector: '0x4388a21c',
  verifier: '0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2',
  proofBytes: 356,
  publicValuesBytes: 480,
});

// 焼成済み配線 FINAL の固定 pin（WR-BAKE record.json）。
export const ZKP_WIRE_EXPECTED = Object.freeze({
  vkey: '0x00382340c4efdab8b43e1574f19fe2c6a1062723cc15b9f8676cca50b0394801',
  elfSha256: '0x82d67aaaf43d2d8fe89eac9c7a52195acf7f3d0df8e3742f27d6615801141c48',
});

function bytesFromHex(value, bytes, label) {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)) {
    throw new Error(`${label} must be 0x-prefixed ${bytes}-byte hex`);
  }
  return Uint8Array.from(value.slice(2).match(/../g).map((part) => Number.parseInt(part, 16)));
}

function uint256(value, label) {
  let n;
  try { n = BigInt(value); } catch { throw new Error(`${label} must be a nonnegative integer`); }
  if (n < 0n || n >= (1n << 256n)) throw new Error(`${label} is outside uint256`);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function concat(parts) {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function digest(algorithm, data) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto subtle API is unavailable');
  return new Uint8Array(await subtle.digest(algorithm, data));
}

export async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  return `0x${hex(await digest('SHA-256', bytes))}`;
}

// uint256(chainId) || uint256(blockNum) || bytes32(inputHash) || bytes32(vkey)
// [|| bytes32(stage3WitnessManifestHash)]
// の固定長連結。文字列の単純連結による境界の曖昧さを入れない。
// Stage 3 本番jobでは witness manifest も含める。同じ15語入力でも witness pin が変わった
// 再発注を、古いGCS request/jobへ衝突させないためである。
export async function zkpJobId({ chainId, blockNum, inputHash, vkey, stage3WitnessManifestHash = null }) {
  const parts = [
    uint256(chainId, 'chainId'),
    uint256(blockNum, 'blockNum'),
    bytesFromHex(inputHash, 32, 'inputHash'),
    bytesFromHex(vkey, 32, 'vkey'),
  ];
  if (stage3WitnessManifestHash !== null) {
    parts.push(bytesFromHex(stage3WitnessManifestHash, 32, 'stage3WitnessManifestHash'));
  }
  const preimage = concat(parts);
  return hex(await digest('SHA-256', preimage));
}

export function zkpAuthCanonical({ method, pathname, timestamp, nonce, bodyHash }) {
  if (!/^[A-Z]+$/.test(method || '')) throw new Error('method must be uppercase');
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) throw new Error('pathname must start with /');
  if (!/^\d{10}$/.test(String(timestamp))) throw new Error('timestamp must be unix seconds');
  if (!/^[0-9a-f]{32,128}$/i.test(nonce || '')) throw new Error('nonce must be 16-64 bytes of hex');
  bytesFromHex(bodyHash, 32, 'bodyHash');
  return `${method}\n${pathname}\n${timestamp}\n${nonce.toLowerCase()}\n${bodyHash.toLowerCase()}`;
}

async function hmacHex(secret, canonical) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('HMAC secret must be at least 32 characters');
  const key = await globalThis.crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return hex(new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(canonical))));
}

function timingSafeHexEqual(left, right) {
  if (!/^[0-9a-f]{64}$/i.test(left || '') || !/^[0-9a-f]{64}$/i.test(right || '')) return false;
  let different = 0;
  for (let i = 0; i < 64; i += 1) different |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return different === 0;
}

export async function createZkpAuthHeaders({ secret, method, pathname, body = '', now = Date.now(), nonce }) {
  const timestamp = String(Math.floor(now / 1000));
  const actualNonce = nonce || hex(globalThis.crypto.getRandomValues(new Uint8Array(24)));
  const bodyHash = await sha256Hex(encoder.encode(body));
  const canonical = zkpAuthCanonical({ method, pathname, timestamp, nonce: actualNonce, bodyHash });
  const signature = await hmacHex(secret, canonical);
  return {
    'x-zkp-timestamp': timestamp,
    'x-zkp-nonce': actualNonce,
    'x-zkp-content-sha256': bodyHash,
    'x-zkp-signature': signature,
  };
}

export async function verifyZkpAuth({ secret, method, pathname, body = '', headers, now = Date.now(), maxSkewMs = 300_000 }) {
  const get = (name) => headers?.get ? headers.get(name) : headers?.[name] ?? headers?.[name.toLowerCase()];
  const timestamp = get('x-zkp-timestamp');
  const nonce = get('x-zkp-nonce');
  const bodyHash = get('x-zkp-content-sha256');
  const signature = get('x-zkp-signature');
  if (!timestamp || !nonce || !bodyHash || !signature) return { ok: false, reason: 'missing_headers' };
  if (!/^\d{10}$/.test(timestamp)) return { ok: false, reason: 'bad_timestamp' };
  if (Math.abs(now - Number(timestamp) * 1000) > maxSkewMs) return { ok: false, reason: 'timestamp_skew' };
  const actualBodyHash = await sha256Hex(encoder.encode(body));
  if (actualBodyHash.toLowerCase() !== bodyHash.toLowerCase()) return { ok: false, reason: 'body_hash_mismatch' };
  let canonical;
  try { canonical = zkpAuthCanonical({ method, pathname, timestamp, nonce, bodyHash }); }
  catch { return { ok: false, reason: 'malformed_headers' }; }
  const expected = await hmacHex(secret, canonical);
  if (!timingSafeHexEqual(expected, signature.toLowerCase())) return { ok: false, reason: 'signature_mismatch' };
  return { ok: true, timestamp: Number(timestamp), nonce: nonce.toLowerCase(), bodyHash: bodyHash.toLowerCase() };
}

const ZKP_PV_NAMES = Object.freeze([
  'blockNum', 'claimDataHash', 'merkleRoot', 'evidenceAcc', 'entryAcc', 'randaoBlockHash',
  'resultManifestHash', 'prevResultManifestHash', 'applicantHash', 'applicantHashUpdatedBlock',
  'evidenceGraceSec', 'randaoEthBlockNumber', 'deploymentParamsHash', 'futureAnchorsHash',
  'rosterManifestHash',
]);

export function decodeZkpPublicValues(publicValues) {
  if (!/^0x[0-9a-f]+$/i.test(publicValues || '')
    || (publicValues.length - 2) / 2 !== ZKP_EXPECTED.publicValuesBytes) {
    throw new Error(`[zkProof] publicValues must be ${ZKP_EXPECTED.publicValuesBytes} bytes`);
  }
  const words = Object.fromEntries(ZKP_PV_NAMES.map((name, index) => [
    name,
    `0x${publicValues.slice(2 + index * 64, 2 + (index + 1) * 64)}`.toLowerCase(),
  ]));
  return {
    ...words,
    blockNum: BigInt(words.blockNum),
    applicantHashUpdatedBlock: BigInt(words.applicantHashUpdatedBlock),
    evidenceGraceSec: BigInt(words.evidenceGraceSec),
    randaoEthBlockNumber: BigInt(words.randaoEthBlockNumber),
  };
}

export function validateZkpProof(proof, {
  blockNum, root, vkey = ZKP_EXPECTED.vkey, elfSha256 = ZKP_EXPECTED.elfSha256,
} = {}) {
  const fail = (message) => { throw new Error(`[zkProof] ${message}`); };
  if (elfSha256 === null) fail('ELF pin is not configured');
  if (!proof || proof.schemaVersion !== 1 || proof.proofSystem !== 'groth16') fail('invalid proof schema/system');
  if (String(proof.vkey).toLowerCase() !== String(vkey).toLowerCase()) fail(`vkey mismatch: ${proof.vkey}`);
  if (String(proof.verifierSelector).toLowerCase() !== ZKP_EXPECTED.selector) fail(`selector mismatch: ${proof.verifierSelector}`);
  if (String(proof.elfSha256).toLowerCase() !== elfSha256) fail(`ELF mismatch: ${proof.elfSha256}`);
  if (!/^0x[0-9a-f]+$/i.test(proof.proofBytes || '') || (proof.proofBytes.length - 2) / 2 !== ZKP_EXPECTED.proofBytes) {
    fail(`proofBytes must be ${ZKP_EXPECTED.proofBytes} bytes`);
  }
  if (!String(proof.proofBytes).toLowerCase().startsWith(ZKP_EXPECTED.selector)) fail('proof selector prefix mismatch');
  let decoded;
  try { decoded = decodeZkpPublicValues(proof.publicValues); }
  catch (error) { fail(error.message.replace(/^\[zkProof\]\s*/, '')); }
  if (blockNum !== undefined) {
    const pvBlock = decoded.blockNum;
    if (pvBlock !== BigInt(blockNum)) fail(`PV blockNum mismatch: ${pvBlock}`);
  }
  if (root !== undefined) {
    const pvRoot = decoded.merkleRoot;
    if (pvRoot !== String(root).toLowerCase()) fail(`PV root mismatch: ${pvRoot}`);
    if (String(proof.merkleRoot).toLowerCase() !== String(root).toLowerCase()) fail(`output root mismatch: ${proof.merkleRoot}`);
  }
  return proof;
}
