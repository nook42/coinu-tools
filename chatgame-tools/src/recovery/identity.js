// src/recovery/identity.js — ウォレット署名からの鍵導出（byte-exact）
//
// v3.2（設計書 §6.1）: 単一ウォレット署名 → master 経由で signKey / encryptKey を兄弟導出。
//   signKey    … 全署名担当（チャット/投票/密告/受領証明）。★永遠に非公開★
//   encryptKey … 投票/密告の自己暗号化専用。結果提出時に公開（採点復号用）
// 導出は vendored walletTools.generateBlockKeys を verbatim 実行（byte-exact）。
// Nostr鍵は vendored relay.deriveNostrKey（signKey からHKDFドメイン分離）。
// ウォレット供給元（EIP-6963 injected / テストの local account）を問わず同一署名を得るため、
// signMessage(message)→署名 の抽象だけを受け取り、内部で walletClient 形状に包んで正典を呼ぶ。
// ⚠️ ウォレット署名 sig は master の素材のため、戻り値に含めない・保存しない（必要時は再署名）。

import { generateBlockKeys, deriveBlockAddress, isKeySignatureValidFor } from '../../vendor/src/utils/walletTools.js';
import { deriveNostrKey, groupTag } from '../../vendor/src/utils/relay.js';
import { isValidNostrPubkey } from '../../vendor/src/utils/p2pKeys.js';

// signMessage: async (message:string) => signature（EIP-191 personal_sign。ウォレット/local account）
function walletShim(address, signMessage) {
  return { signMessage: async ({ message }) => signMessage(message) };
}

// ブロック単位の身元導出（groupId 不要）。roster が渡されれば bAddr をロスターの pubKey と照合し
// 不一致は throw（EOA限定・別injectedウォレット取り違え検知）。グループ確定後に deriveP2PKeys を呼ぶ。
export async function deriveBlockIdentity({ signMessage, address, blockNum, uid, rosterMember = null }) {
  const wc = walletShim(address, signMessage);
  const { signKey, encryptKey, signature, blockAddress } = await generateBlockKeys(wc, address, blockNum, uid);
  const bAddr = JSON.parse(blockAddress);
  const ok = await isKeySignatureValidFor(signature, signKey, address, blockNum, uid);
  if (!ok) throw new IdentityError('signature_invalid', 'wallet signature did not re-derive the expected signKey (EOA only)');
  if (rosterMember) {
    const rosterBlock = rosterMember.bAddr && (typeof rosterMember.bAddr === 'string' ? JSON.parse(rosterMember.bAddr) : rosterMember.bAddr);
    const rp = rosterMember.pubKey || rosterBlock?.pubKey;
    const ra = rosterMember.blockAddress || rosterBlock?.address;
    if (rp && String(rp).toLowerCase() !== String(bAddr.pubKey).toLowerCase()) {
      throw new IdentityError('roster_mismatch', 'derived blockAddress does not match the roster (wrong wallet or wrong uid)');
    }
    if (ra && String(ra).toLowerCase() !== String(bAddr.address).toLowerCase()) {
      throw new IdentityError('roster_mismatch', 'derived block address does not match the roster');
    }
    if (isValidNostrPubkey(rosterBlock?.nostrPubkey) && rosterBlock.nostrPubkey !== bAddr.nostrPubkey) {
      throw new IdentityError('roster_mismatch', 'derived Nostr pubkey does not match the roster');
    }
  }
  // signature（master素材）はここで捨てる — 提出物・保存に絶対に載せない
  return { signKey, encryptKey, blockAddress, bAddr };
}

// Nostr鍵は応募時と同じ blockNum 単位。group tag は組単位。
export function deriveP2PKeys(signKey, blockNum, groupId) {
  const nostr = deriveNostrKey(signKey, blockNum); // { sk, pubkey }
  const tag = groupTag(blockNum, groupId);
  return { nostrSk: nostr.sk, nostrPubkey: nostr.pubkey, tag };
}

export function canStartRecoveryP2P(rosterMember) {
  let block = rosterMember?.bAddr;
  if (typeof block === 'string') {
    try { block = JSON.parse(block); } catch { block = null; }
  }
  return isValidNostrPubkey(block?.nostrPubkey);
}

// signKey だけからの登録 blockAddress 再導出（別端末・localStorage喪失時。walletTools.deriveBlockAddress）
export function blockAddressFromKey(signKey, blockNum) {
  return deriveBlockAddress(signKey, blockNum); // { blockAddress: JSON string {address, pubKey, nostrPubkey}, signKey }
}

export class IdentityError extends Error {
  constructor(code, msg) { super(msg); this.name = 'IdentityError'; this.code = code; }
}
