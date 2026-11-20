import { verifyMessage, keccak256, concat, stringToBytes, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { canonicalizeSignature } from '../../workers/game_workers/lib/protocol-v2.js';
import { deriveNostrKey } from './p2pKeys.js';
export { canonicalizeSignature };

// ============================================================
// 鍵導出（v3.2 正典・設計書 §6.1）
//   sig        = wallet.signMessage("bitcoinu_mining_block{N}_user{uid}_tokenmining{address}")
//                                                          ↑ エントリー時の1回のみ
//   master     = keccak256(sig)            … どこにも保存・送信しない中間値
//   signKey    = keccak256(master ‖ "sign")    … ★永遠に非公開★ 全署名担当（チャット/投票/密告/受領証明）
//   encryptKey = keccak256(master ‖ "encrypt") … 投票/密告の自己暗号化専用・結果提出時に公開
// keccak の一方向性により encryptKey を公開しても master / signKey は導出不能。
// 両鍵とも再署名（personal_sign は RFC6979 決定論）でいつでも復元可能。
// blockAddress = {"address","pubKey","nostrPubkey"} は応募時に固定する公開情報。
// ⚠️ ウォレット署名 sig は master の素材のため【提出物・サーバー送信に絶対に含めない】。
//    localStorage への保存（keySig_*）はエントリー再検証・ポップアップ省略のためのローカル専用キャッシュ。
// UI 文言では signKey/encryptKey をまとめて「ブロックキー」と総称する。
// ============================================================

// TokenMining は本番パラメータの再デプロイでアドレスが変わり、ブロック番号も0から
// 振り直される。テスト版と本番版で同じ鍵を再利用しないよう、鍵導出のウォレット署名に
// TokenMining アドレスを含める。両方とも mainnet 上なので chain ID はドメインに含めない。
// ウォレットと復元クライアントで checksum 表記が違っても同じ鍵になるよう、
// 署名対象へは 0x 付き小文字40桁の形だけを入れる。
export const normalizeTokenMiningAddressForKeyDomain = (tokenMiningAddress) => {
    const normalized = typeof tokenMiningAddress === 'string' ? tokenMiningAddress.trim().toLowerCase() : '';
    if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
        throw new Error('TokenMining address is required for block key generation');
    }
    return normalized;
};

let runtimeTokenMiningAddress;

// 復元クライアントは Next.js env を持たないため、チェーン検証に使った
// config.contracts.tokenMining を導出前に注入する。モジュール内だけに保持し、鍵や署名は保持しない。
export const setBlockKeyTokenMiningAddress = (tokenMiningAddress) => {
    runtimeTokenMiningAddress = normalizeTokenMiningAddressForKeyDomain(tokenMiningAddress);
};

const configuredTokenMiningAddress = (explicitAddress) => {
    if (explicitAddress !== undefined) {
        return normalizeTokenMiningAddressForKeyDomain(explicitAddress);
    }

    let envAddress;
    try {
        envAddress = process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
    } catch {
        // 復元クライアントの browser bundle に process は無い。上の runtime 注入が必須。
    }
    // Next.js 本体では public env を権威とし、runtime 値で上書きさせない。
    if (envAddress !== undefined) return normalizeTokenMiningAddressForKeyDomain(envAddress);
    if (runtimeTokenMiningAddress) return runtimeTokenMiningAddress;
    return normalizeTokenMiningAddressForKeyDomain(undefined);
};

export const blockKeySignatureMessage = (blockNum, userId, tokenMiningAddress) => {
    const domainAddress = configuredTokenMiningAddress(tokenMiningAddress);
    return `bitcoinu_mining_block${blockNum}_user${userId}_tokenmining${domainAddress}`;
};

// ============================================================
// 署名バイト列の正規化（K-S6-007・2026-07-29）
// ============================================================
// 鍵は**署名バイト列そのもの**を種にするため、同じウォレット・同じ文言でも
// バイト表現が違えば別の鍵になる。実測（本物の署名で確認）:
//
//   元の署名        verifyMessage=true  key=0xe99d2196…
//   v を 0/1 表現へ  verifyMessage=true  key=0xa93757ea…  ← 別鍵
//   high-s の双子    verifyMessage=true  key=0x9b89b850…  ← 別鍵
//
// **3通りとも verifyMessage は合格する**ので、旧実装はこれを素通しし、
// 別端末で再生成した利用者が「登録した鍵と違う鍵」を持ってしまい、
// 以後の署名が登録 pubKey で検証できず min_chars / no_vote 失格になっていた。
//
// 表現差の原因は2つあり、どちらもここで吸収する:
//   ① malleability: (r, s) と (r, n−s) はどちらも有効 → low-s へ寄せる（寄せたら v を反転）
//   ② v の表現: 27/28 と 0/1 の実装が両方ある → 27/28 に統一
// 正規化後の署名も verifyMessage に合格する（実測確認済み）。
//
// ⚠️ 署名の乱数（r）自体が違うケース（RFC6979 非準拠の実装）は吸収できない。
//    そのため game.js 側で「導出した pubKey が登録名簿と一致するか」を必ず照合する。
// 純関数: ウォレット署名から signKey / encryptKey / blockAddress を導出
// K-S6-007: 導出の入口で必ず正規化する（キャッシュ済みの旧形式署名も同じ鍵に落ちる）
export const deriveKeysFromSignature = (rawSignature, blockNum) => {
    const signature = canonicalizeSignature(rawSignature);
    const master = keccak256(toBytes(signature));
    const signKey = keccak256(concat([toBytes(master), stringToBytes('sign')]));
    const encryptKey = keccak256(concat([toBytes(master), stringToBytes('encrypt')]));
    const account = privateKeyToAccount(signKey);
    const blockAddress = JSON.stringify({
        address: account.address,
        pubKey: account.publicKey,
        nostrPubkey: deriveNostrKey(signKey, blockNum).pubkey,
    });
    return { blockAddress, signKey, encryptKey };
};

/**
 * Generates block keys (signKey/encryptKey) from a single wallet signature.
 * @param {object} walletClient - The wallet client from wagmi/viem
 * @param {string} address - The user's wallet address
 * @param {number|string} blockNum - The block number
 * @param {string} userId - The user ID
 * @param {string} [tokenMiningAddress] - Explicit TokenMining address (recovery client); Next.js uses public env
 * @returns {Promise<{blockAddress: string, signKey: string, encryptKey: string, signature: string}>}
 *   blockAddress is JSON: {"address":"0x...","pubKey":"0x04...","nostrPubkey":"64hex"}。
 *   signature はローカルキャッシュ（keySig_*）専用 — 提出物・送信に含めてはならない。
 */
export const generateBlockKeys = async (walletClient, address, blockNum, userId, tokenMiningAddress) => {
    if (!walletClient || !address || blockNum == null || !userId) {
        throw new Error('Missing required parameters for block key generation');
    }

    const message = blockKeySignatureMessage(blockNum, userId, tokenMiningAddress);

    try {
        // 1. Sign the message（唯一のウォレットポップアップ）
        const signature = await walletClient.signMessage({
            account: address,
            message: message
        });

        // 2. Verify the signature (sanity check)
        const valid = await verifyMessage({
            address: address,
            message: message,
            signature: signature
        });

        if (!valid) {
            throw new Error('Signature verification failed');
        }

        // 3. master 経由で兄弟導出
        // K-S6-007: 保存・再検証も正規化後の形で統一する（表現差で鍵が割れないように）
        const canonical = canonicalizeSignature(signature);
        return { ...deriveKeysFromSignature(canonical, blockNum), signature: canonical };
    } catch (error) {
        console.error('Error generating block keys:', error);
        throw error;
    }
};

/**
 * Verifies that a cached wallet signature was produced by the given wallet address
 * for the given block/user, and is consistent with the cached signKey.
 * Used to decide whether cached keys can be safely reused at entry time
 * (wrong wallet / wrong block → derived signKey won't match → regenerate).
 * @param {string} signature - The cached wallet signature (keySig_* / ローカル専用)
 * @param {string} signKey - The cached signKey
 * @param {string} address - The wallet address that should have signed (claim address)
 * @param {number|string} blockNum - The block number
 * @param {string} userId - The user ID
 * @param {string} [tokenMiningAddress] - Explicit TokenMining address (recovery client); Next.js uses public env
 * @returns {Promise<boolean>}
 */
export const isKeySignatureValidFor = async (signature, signKey, address, blockNum, userId, tokenMiningAddress) => {
    if (!signature || !signKey || !address || blockNum == null || !userId) return false;

    try {
        const message = blockKeySignatureMessage(blockNum, userId, tokenMiningAddress);

        // 1. 署名が請求先(=接続中)アドレスのものか検証
        const validSigner = await verifyMessage({ address, message, signature });
        if (!validSigner) return false;

        // 2. 署名から導出した signKey と保存値の整合性
        return deriveKeysFromSignature(signature, blockNum).signKey === signKey;
    } catch (error) {
        console.error('Error verifying key signature:', error);
        return false;
    }
};

/**
 * Derives the registered blockAddress JSON from an existing signKey.
 * @param {string} signKey - The signing private key
 * @returns {{blockAddress: string, signKey: string}|null}
 */
export const deriveBlockAddress = (signKey, blockNum) => {
    try {
        const account = privateKeyToAccount(signKey);
        return {
            blockAddress: JSON.stringify({
                address: account.address,
                pubKey: account.publicKey,
                nostrPubkey: deriveNostrKey(signKey, blockNum).pubkey,
            }),
            signKey
        };
    } catch (error) {
        console.error('Error deriving address from key:', error);
        return null;
    }
};
