// 応募時とゲーム時に共通の、ブロック単位の Nostr 鍵。
import { keccak256, toBytes } from 'viem';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const salt = toBytes(keccak256(toBytes('bitcoinu/p2p/nostr-key/v2')));

export function deriveNostrKey(signKey, blockNum) {
  const validBlockNum = typeof blockNum === 'number'
    ? Number.isSafeInteger(blockNum) && blockNum >= 0
    : typeof blockNum === 'string' && /^(0|[1-9]\d*)$/.test(blockNum);
  if (typeof signKey !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(signKey)
      || !validBlockNum) {
    throw new Error('invalid Nostr key derivation input');
  }
  const ikm = toBytes(signKey);
  const baseInfo = `blockNum=${blockNum}`;
  for (let ctr = 0; ctr < 256; ctr++) {
    const info = ctr === 0 ? baseInfo : `${baseInfo}|ctr=${ctr}`;
    const sk = hkdf(sha256, ikm, salt, new TextEncoder().encode(info), 32);
    let scalar = 0n;
    for (const byte of sk) scalar = (scalar << 8n) | BigInt(byte);
    if (scalar > 0n && scalar < N) {
      return { sk, pubkey: Array.from(schnorr.getPublicKey(sk), b => b.toString(16).padStart(2, '0')).join('') };
    }
  }
  throw new Error('nostr key derivation failed (256 attempts)');
}

export function isValidNostrPubkey(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) return false;
  try {
    schnorr.utils.lift_x(BigInt(`0x${value}`));
    return true;
  } catch {
    return false;
  }
}
