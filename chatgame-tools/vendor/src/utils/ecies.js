// src/utils/ecies.js
// ECIES (secp256k1) 暗号化/復号ユーティリティ
// 投票・密告の自己暗号化専用。封筒は平文 JSON。

import { encrypt, decrypt, PrivateKey } from 'eciesjs';
import { gcm } from '@noble/ciphers/aes';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
// 🔴 パディング規則は**正典（protocol-v2.js）に1つだけ**置く。ここに数値を写経すると
//    採点側の `isCanonicalActionCiphertext` と静かに割れる（＝全員 no_vote）。
import { padActionPlaintext } from '../../workers/game_workers/lib/protocol-v2.js';

// 密告・投票の自己暗号化（encryptKey由来の公開鍵で暗号化→結果提出時にencryptKey公開で採点者が復号）
//
// 🔴 平文は **必ず固定長にパディングしてから**暗号化する（P-2026-0842・2026-08-08）。
//    ECIES の封筒は固定長・AES-GCM はストリーム暗号なので、パディングしないと
//    **暗号文の長さがそのまま対象 uid の桁数を漏らす**。この暗号文は `action_made` で
//    グループ全員へ配られ、`live/block{N}/group{g}.json` として**無認証で公開**される。
//    根拠と定数の選び方は `protocol-v2.js` の `ACTION_PLAINTEXT_BYTES` 節。
//    ⚠️ 採点正典が長さを強制する（`isCanonicalActionCiphertext`）。ここを外すと
//       その人の投票・密告は**採点で消える**（投票なら `no_vote` 失格）。
export function encryptAction(data, myEncryptKey) {
  const privKeyHex = myEncryptKey.startsWith('0x') ? myEncryptKey.slice(2) : myEncryptKey;
  const sk = new PrivateKey(hexToBytes(privKeyHex));
  const pubKey = sk.publicKey.toBytes();
  const plainBytes = new TextEncoder().encode(padActionPlaintext(JSON.stringify(data)));
  const encrypted = encrypt(pubKey, plainBytes);
  return bytesToHex(encrypted);
}

// 密告・投票の復号（encryptKeyで）
export function decryptAction(encryptedHex, myEncryptKey) {
  const privKeyHex = myEncryptKey.startsWith('0x') ? myEncryptKey.slice(2) : myEncryptKey;
  const encryptedBytes = hexToBytes(encryptedHex);
  const decrypted = decrypt(privKeyHex, encryptedBytes);
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// A report's ciphertext is stable for one issuer, target, block and group.
// Keep this envelope compatible with eciesjs: uncompressed R || nonce || tag || ciphertext.
export function encryptReportDeterministic(targetUid, encryptKey, { blockNum, groupId }) {
  if (typeof targetUid !== 'string' || !targetUid
      || !Number.isSafeInteger(blockNum) || !Number.isSafeInteger(groupId)) {
    throw new TypeError('Invalid report target or context');
  }
  const secretHex = typeof encryptKey === 'string' && encryptKey.startsWith('0x')
    ? encryptKey.slice(2) : encryptKey;
  if (typeof secretHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(secretHex)) {
    throw new TypeError('Invalid encryptKey');
  }
  const secret = hexToBytes(secretHex);
  const plain = new TextEncoder().encode(padActionPlaintext(JSON.stringify({ targetUid, reason: 'suspected_bot' })));
  const label = new TextEncoder().encode(`coinu/action-ecies-det/v1|report|${blockNum}|${groupId}|`);
  const concat = (...parts) => {
    const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  };
  const seed = hmac(sha256, secret, concat(label, sha256(plain)));
  const ephLabel = new TextEncoder().encode('eph');
  let ephemeral;
  for (let ctr = 0; ctr <= 0xffffffff; ctr++) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, ctr);
    try {
      ephemeral = new PrivateKey(hmac(sha256, seed, concat(ephLabel, counter)), 'secp256k1');
      break;
    } catch { /* Reject 0 and values outside the secp256k1 scalar range. */ }
  }
  if (!ephemeral) throw new Error('Could not derive report key');
  const recipient = new PrivateKey(secret, 'secp256k1').publicKey;
  const publicBytes = ephemeral.publicKey.toBytes(false);
  const sharedKey = ephemeral.encapsulate(recipient, false);
  const nonce = hmac(sha256, seed, new TextEncoder().encode('nonce')).subarray(0, 16);
  const cipherAndTag = gcm(sharedKey, nonce).encrypt(plain);
  const tag = cipherAndTag.subarray(cipherAndTag.length - 16);
  const cipher = cipherAndTag.subarray(0, cipherAndTag.length - 16);
  return bytesToHex(concat(publicBytes, nonce, tag, cipher));
}

// hex文字列 → Uint8Array
function hexToBytes(hex) {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Uint8Array → hex文字列
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
