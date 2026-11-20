// entry worker は src/ を import できない。src/utils/p2pKeys.js と同じ lift_x 判定。
import { schnorr } from '@noble/curves/secp256k1';

export function isValidNostrPubkey(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) return false;
  try {
    schnorr.utils.lift_x(BigInt(`0x${value}`));
    return true;
  } catch {
    return false;
  }
}
