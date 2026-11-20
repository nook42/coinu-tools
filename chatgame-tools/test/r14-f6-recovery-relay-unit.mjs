#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { saveRelayList } from '../../src/utils/relay.js';

const toolRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(toolRoot, '..');
const originalLocalStorage = globalThis.localStorage;

try {
  const writes = [];
  globalThis.localStorage = {
    setItem: (key, value) => writes.push(['set', key, value]),
    removeItem: (key) => writes.push(['remove', key]),
  };
  assert.equal(saveRelayList(['wss://relay.example']), true, 'setItem 成功時は true');
  assert.equal(saveRelayList(null), true, 'removeItem 成功時は true');
  assert.deepEqual(writes.map(([op]) => op), ['set', 'remove']);

  globalThis.localStorage = {
    setItem: () => { throw new Error('storage denied'); },
    removeItem: () => { throw new Error('storage denied'); },
  };
  assert.equal(saveRelayList(['wss://relay.example']), false, 'setItem 失敗時は false');
  assert.equal(saveRelayList(null), false, 'removeItem 失敗時は false');
} finally {
  if (originalLocalStorage === undefined) delete globalThis.localStorage;
  else globalThis.localStorage = originalLocalStorage;
}

const appSource = readFileSync(resolve(toolRoot, 'src/recovery/app.js'), 'utf8');
const settingsSource = readFileSync(resolve(repoRoot, 'src/components/game/RelaySettings.js'), 'utf8');
const discoverySource = readFileSync(resolve(toolRoot, 'src/recovery/discovery.js'), 'utf8');

function recoveryAppGuardsSuccess(source) {
  return (source.match(/const saved = saveRelayList\(/g) || []).length === 1
    && source.includes("saved ? 'recovery.relay.saved' : 'recovery.relay.saveFailed'");
}

function relaySettingsGuardsSuccess(source) {
  return (source.match(/const saved = saveRelayList\(/g) || []).length === 2
    && (source.match(/text: saved/g) || []).length === 2
    && (source.match(/game\.relay\.saveFailed/g) || []).length === 2;
}

function registrationCountWarnsInsteadOfThrowing(source) {
  const start = source.indexOf('const selectionDiffersFromLatest =');
  const end = source.indexOf('if (anchors.selectionRegistered !== true)', start);
  if (start < 0 || end < 0) return false;
  const branch = source.slice(start, end);
  return branch.includes('anchors.registrationCount !== 1 || selectionDiffersFromLatest')
    && branch.includes('onWarning({')
    && !branch.includes('throw new Error');
}

assert.equal(recoveryAppGuardsSuccess(appSource), true, '復元UIは保存成功を戻り値で分岐する');
assert.equal(relaySettingsGuardsSuccess(settingsSource), true, '本体UIの2呼び出しは保存成功を戻り値で分岐する');
assert.equal(registrationCountWarnsInsteadOfThrowing(discoverySource), true,
  'registrationCount != 1 は throw せず警告する');

const appMutant = appSource.replace('const saved = saveRelayList(', 'saveRelayList(');
const settingsMutant = settingsSource.replace('const saved = saveRelayList(', 'saveRelayList(');
const registrationMutant = discoverySource.replace('      onWarning({', "      throw new Error('mutant');\n      onWarning({");
assert.equal(recoveryAppGuardsSuccess(appMutant), false, 'mutation: 復元UIの無条件成功表示を検出');
assert.equal(relaySettingsGuardsSuccess(settingsMutant), false, 'mutation: 本体UIの無条件成功表示を検出');
assert.equal(registrationCountWarnsInsteadOfThrowing(registrationMutant), false,
  'mutation: 再登録時 throw の復活を検出');

console.log('PASS: F6 registration warning / relay persistence result guards');
console.log('PASS: 3 injected regressions turned the guard red');
