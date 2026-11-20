import { keccak256, sha256, stringToHex, encodeAbiParameters, concatHex } from 'viem';

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
const SHA256_TEXT = /^[0-9a-fA-F]{64}$/;
const abiWords = [{ type: 'bytes32' }, { type: 'bytes32' }];

function blockNumber(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new TypeError('invalid blockNum');
  return number;
}

export function normalizeRosterAddress(address) {
  if (typeof address !== 'string' || !ADDRESS.test(address)) throw new TypeError('invalid walletAddress');
  return address.toLowerCase();
}

function pairHash(a, b) {
  return keccak256(a < b ? concatHex([a, b]) : concatHex([b, a]));
}

export function rosterMemberLeaf(blockNum, address) {
  const addr = normalizeRosterAddress(address);
  const inner = keccak256(encodeAbiParameters(
    [{ type: 'uint256' }, { type: 'address' }], [BigInt(blockNumber(blockNum)), addr],
  ));
  return keccak256(inner);
}

// All callers use this one ordering and tree rule. An unpaired last node is promoted unchanged.
export function buildRosterMemberTree(blockNum, addresses) {
  const number = blockNumber(blockNum);
  if (!Array.isArray(addresses)) throw new TypeError('addresses must be an array');
  const members = [...new Set(addresses.map(normalizeRosterAddress))].sort();
  if (members.length === 0) return { blockNum: number, members, layers: [], memberRoot: null };
  const layers = [members.map((address) => rosterMemberLeaf(number, address))];
  while (layers.at(-1).length > 1) {
    const current = layers.at(-1);
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(i + 1 < current.length ? pairHash(current[i], current[i + 1]) : current[i]);
    }
    layers.push(next);
  }
  return { blockNum: number, members, layers, memberRoot: layers.at(-1)[0] };
}

export function createRosterMemberProof(tree, address) {
  let index = tree.members.indexOf(normalizeRosterAddress(address));
  if (index < 0) throw new TypeError('address is not a roster member');
  const proof = [];
  for (let level = 0; level < tree.layers.length - 1; level++) {
    const sibling = index ^ 1;
    if (sibling < tree.layers[level].length) proof.push(tree.layers[level][sibling]);
    index = Math.floor(index / 2);
  }
  return proof;
}

function proofRoot(blockNum, address, proof) {
  if (!Array.isArray(proof) || proof.length > 12) return null;
  let node = rosterMemberLeaf(blockNum, address);
  for (const sibling of proof) {
    if (typeof sibling !== 'string' || !HASH.test(sibling)) return null;
    node = pairHash(node, sibling.toLowerCase());
  }
  return node;
}

export function verifyRosterMemberProof({ blockNum, address, memberRoot, proof }) {
  return HASH.test(memberRoot || '') && proofRoot(blockNum, address, proof) === memberRoot.toLowerCase();
}

export function rosterCommitment(manifestHash, memberRoot) {
  if (!HASH.test(manifestHash || '') || !HASH.test(memberRoot || '')) throw new TypeError('invalid roster hash');
  return keccak256(encodeAbiParameters(abiWords, [manifestHash, memberRoot]));
}

export function verifyRosterCommitmentProof({ blockNum, address, manifestHash, C, proof }) {
  if (!HASH.test(manifestHash || '') || !HASH.test(C || '')) return false;
  const memberRoot = proofRoot(blockNum, address, proof);
  return memberRoot !== null && rosterCommitment(manifestHash, memberRoot) === C.toLowerCase();
}

// groupTexts contains the exact published text, keyed by groupId (Map or plain object).
// Hashing parsed/re-serialized JSON here would silently accept changed R2 bytes.
export function buildRosterMemberCommitment({ blockNum, manifestText, groupTexts }) {
  const number = blockNumber(blockNum);
  if (typeof manifestText !== 'string') throw new TypeError('manifestText must be a string');
  const manifest = JSON.parse(manifestText);
  if (manifest?.blockNum !== number || !Array.isArray(manifest.groups)) throw new TypeError('invalid roster manifest');
  const addresses = [];
  const ids = new Set();
  for (const group of manifest.groups) {
    const groupId = group?.groupId;
    if (!Number.isSafeInteger(groupId) || groupId < 0 || ids.has(groupId) || !SHA256_TEXT.test(group.sha256 || '')) {
      throw new TypeError('invalid manifest group');
    }
    ids.add(groupId);
    const text = groupTexts instanceof Map ? groupTexts.get(groupId) : groupTexts?.[groupId];
    if (typeof text !== 'string' || sha256(stringToHex(text)).slice(2) !== group.sha256.toLowerCase()) {
      throw new TypeError(`group ${groupId} sha256 mismatch`);
    }
    const roster = JSON.parse(text);
    if (roster?.blockNum !== number || roster?.groupId !== groupId || !Array.isArray(roster.members)) {
      throw new TypeError(`invalid group ${groupId} roster`);
    }
    for (const member of roster.members) addresses.push(normalizeRosterAddress(member?.walletAddress));
  }
  const tree = buildRosterMemberTree(number, addresses);
  const manifestHash = keccak256(stringToHex(manifestText));
  return { ...tree, manifestHash, C: tree.memberRoot ? rosterCommitment(manifestHash, tree.memberRoot) : null };
}
