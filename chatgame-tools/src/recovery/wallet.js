// src/recovery/wallet.js — EIP-6963 マルチウォレット検出＋接続（ブラウザ専用・no wagmi）
//
// DESIGN §2.1: bare window.ethereum は複数injectedウォレットで別プロバイダに解決され得る
// （→別署名→別signKey/encryptKey）。EIP-6963 列挙＋選択でユーザーが元の署名ウォレットを選べるようにする。
// 署名は viem createWalletClient({transport: custom(provider)}) で EIP-191 personal_sign。

import { createWalletClient, custom } from 'viem';
import { mainnet } from 'viem/chains';

// EIP-6963: announce イベントを集めてプロバイダ一覧を返す
export function discoverProviders(timeoutMs = 300) {
  return new Promise((resolve) => {
    const found = [];
    const seen = new Set();
    const onAnnounce = (event) => {
      const d = event.detail;
      if (d?.info?.uuid && !seen.has(d.info.uuid)) { seen.add(d.info.uuid); found.push(d); }
    };
    window.addEventListener('eip6963:announceProvider', onAnnounce);
    window.dispatchEvent(new Event('eip6963:requestProvider'));
    setTimeout(() => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce);
      if (found.length === 0 && window.ethereum) {
        found.push({ info: { uuid: 'legacy', name: 'Injected (window.ethereum)', icon: null }, provider: window.ethereum });
      }
      resolve(found);
    }, timeoutMs);
  });
}

export async function connectProvider(provider) {
  const accounts = await provider.request({ method: 'eth_requestAccounts' });
  if (!accounts || !accounts.length) throw new Error('no accounts');
  const chainIdHex = await provider.request({ method: 'eth_chainId' });
  const chainId = parseInt(chainIdHex, 16);
  return { address: accounts[0], chainId };
}

export async function ensureMainnet(provider) {
  const chainIdHex = await provider.request({ method: 'eth_chainId' });
  if (parseInt(chainIdHex, 16) === 1) return true;
  try {
    await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x1' }] });
    return true;
  } catch {
    return false;
  }
}

// signMessage(message) → 署名（EIP-191 personal_sign）。identity.deriveBlockIdentity に渡す。
export function makeSigner(provider, address) {
  return async (message) => {
    // provider.request personal_sign を直接叩く（viem walletClient と同一の EIP-191 バイト）
    // viem 経由でも同一だが、注入プロバイダを厳密に使うため request を用いる。
    const wc = createWalletClient({ chain: mainnet, transport: custom(provider), account: address });
    return wc.signMessage({ account: address, message });
  };
}

// Evidence 提出用の walletClient（chainId=1 バインド）
export function makeWalletClient(provider, address) {
  return createWalletClient({ chain: mainnet, transport: custom(provider), account: address });
}
