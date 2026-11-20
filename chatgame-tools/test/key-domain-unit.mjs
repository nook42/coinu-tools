// A3-d2: 鍵導出の TokenMining ドメイン分離と復元クライアントの注入経路を固定する。
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import * as walletTools from '../../src/utils/walletTools.js';
import { setBlockKeyTokenMiningAddress as setVendoredTokenMiningAddress } from '../vendor/src/utils/walletTools.js';
import { configureRecoveryBlockKeyDomain } from '../src/recovery/app.js';
import { deriveBlockIdentity, deriveP2PKeys, canStartRecoveryP2P, IdentityError } from '../src/recovery/identity.js';
import { deriveNostrKey } from '../../src/utils/p2pKeys.js';

const wallet = privateKeyToAccount(`0x${'31'.repeat(32)}`);
const tokenMiningA = '0xC12A4c7f846c546D7c74bd7acdFC4187bB690Bf6';
const tokenMiningB = '0x1111111111111111111111111111111111111111';
const blockNum = 7;
const uid = 'user0001';
assert.equal(deriveNostrKey(`0x${'11'.repeat(32)}`, 7).pubkey,
  '95f20e44f3741f1ffaf85ef99f082fd85b3ac9129c440cb54d1d89a92a6e71c3',
  '復元側でも Nostr v2 の既知解を固定する');
const signedMessages = [];
const walletClient = {
  signMessage: async ({ message }) => {
    signedMessages.push(message);
    return wallet.signMessage({ message });
  },
};

const expectedMessage = 'bitcoinu_mining_block7_useruser0001_tokenmining0xc12a4c7f846c546d7c74bd7acdfc4187bb690bf6';
assert.equal(
  walletTools.blockKeySignatureMessage(blockNum, uid, tokenMiningA),
  expectedMessage,
  'TokenMining address must be readable in the signed preimage in canonical lowercase form',
);
assert.equal(expectedMessage.includes('chain'), false, 'chain ID must not be added to the key domain');
assert.throws(
  () => walletTools.blockKeySignatureMessage(blockNum, uid, ''),
  /TokenMining address is required/,
  'missing TokenMining address must fail closed',
);
assert.throws(
  () => walletTools.blockKeySignatureMessage(blockNum, uid, '0x1234'),
  /TokenMining address is required/,
  'malformed TokenMining address must fail closed',
);
const savedPublicAddress = process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
try {
  delete process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
  assert.throws(
    () => walletTools.blockKeySignatureMessage(blockNum, uid),
    /TokenMining address is required/,
    'missing NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS must fail closed',
  );
  process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS = tokenMiningA;
  assert.equal(
    walletTools.blockKeySignatureMessage(blockNum, uid),
    expectedMessage,
    'main client must read the TokenMining domain from NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS',
  );
} finally {
  if (savedPublicAddress === undefined) delete process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
  else process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS = savedPublicAddress;
}

const keysA = await walletTools.generateBlockKeys(walletClient, wallet.address, blockNum, uid, tokenMiningA);
assert.equal(signedMessages.at(-1), expectedMessage, 'generateBlockKeys must sign the domain-separated preimage');
const keysACaseVariant = await walletTools.generateBlockKeys(
  walletClient,
  wallet.address,
  blockNum,
  uid,
  tokenMiningA.toLowerCase(),
);
assert.equal(keysACaseVariant.signKey, keysA.signKey, 'checksum/lowercase address variants must derive the same key');

const keysB = await walletTools.generateBlockKeys(walletClient, wallet.address, blockNum, uid, tokenMiningB);
assert.notEqual(keysB.signKey, keysA.signKey, 'a different TokenMining deployment must derive a different signKey');
assert.notEqual(keysB.encryptKey, keysA.encryptKey, 'a different TokenMining deployment must derive a different encryptKey');
assert.equal(
  await walletTools.isKeySignatureValidFor(keysA.signature, keysA.signKey, wallet.address, blockNum, uid, tokenMiningA),
  true,
  'cached key signature must validate in its TokenMining domain',
);
assert.equal(
  await walletTools.isKeySignatureValidFor(keysA.signature, keysA.signKey, wallet.address, blockNum, uid, tokenMiningB),
  false,
  'cached key signature must not validate in a different TokenMining domain',
);

configureRecoveryBlockKeyDomain(tokenMiningA, walletTools);
const savedRecoveryEnvAddress = process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
try {
  delete process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
  const recoveryKeys = await walletTools.generateBlockKeys(walletClient, wallet.address, blockNum, uid);
  assert.equal(recoveryKeys.signKey, keysA.signKey, 'recovery runtime injection must reproduce the main-client signKey');
  assert.equal(recoveryKeys.encryptKey, keysA.encryptKey, 'recovery runtime injection must reproduce the main-client encryptKey');
  const rosterBlock = JSON.parse(keysA.blockAddress);
  const rosterMember = { bAddr: rosterBlock };
  setVendoredTokenMiningAddress(tokenMiningA);
  const recovered = await deriveBlockIdentity({
    signMessage: (message) => wallet.signMessage({ message }),
    address: wallet.address, blockNum, uid, rosterMember,
  });
  assert.equal(JSON.parse(recovered.blockAddress).nostrPubkey, rosterBlock.nostrPubkey);
  assert.equal(deriveP2PKeys(recovered.signKey, blockNum, 1).nostrPubkey, rosterBlock.nostrPubkey);
  assert.equal(deriveP2PKeys(recovered.signKey, blockNum, 2).nostrPubkey, rosterBlock.nostrPubkey);
  assert.equal(canStartRecoveryP2P(rosterMember), true);
  for (const nostrPubkey of [undefined, 'abc', '00'.repeat(32)]) {
    const missing = { ...rosterMember, bAddr: { ...rosterBlock, nostrPubkey } };
    assert.equal(canStartRecoveryP2P(missing), false, '本人の名簿鍵が無効ならリレーを起動しない');
    const identity = await deriveBlockIdentity({
      signMessage: (message) => wallet.signMessage({ message }),
      address: wallet.address, blockNum, uid, rosterMember: missing,
    });
    assert.equal(identity.signKey, recovered.signKey, '本人の鍵欠落でも WS/Evidence 用の身元を導出');
  }
  await assert.rejects(() => deriveBlockIdentity({
    signMessage: (message) => wallet.signMessage({ message }),
    address: wallet.address, blockNum, uid,
    rosterMember: { ...rosterMember, bAddr: { ...rosterBlock,
      nostrPubkey: deriveNostrKey(`0x${'22'.repeat(32)}`, blockNum).pubkey } },
  }), (error) => error instanceof IdentityError && error.code === 'roster_mismatch');
  const topLevelIgnored = await deriveBlockIdentity({
    signMessage: (message) => wallet.signMessage({ message }),
    address: wallet.address, blockNum, uid,
    rosterMember: { ...rosterMember,
      nostrPubkey: deriveNostrKey(`0x${'22'.repeat(32)}`, blockNum).pubkey },
  });
  assert.equal(topLevelIgnored.signKey, recovered.signKey,
    'WS 最上位の別鍵は復元の blockAddress 照合を変えない');
  assert.equal(canStartRecoveryP2P({ ...rosterMember, nostrPubkey: 'invalid' }), true,
    '復元 P2P は本番名簿の bAddr だけを読む');
} finally {
  if (savedRecoveryEnvAddress === undefined) delete process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS;
  else process.env.NEXT_PUBLIC_TOKEN_MINING_CONTRACT_ADDRESS = savedRecoveryEnvAddress;
}

console.log('key-domain-unit: all tests passed');
