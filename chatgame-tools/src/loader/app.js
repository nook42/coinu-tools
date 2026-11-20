// src/loader/app.js — ローダー UI エントリ（esbuild でバンドル）
import { loadConfig, saveConfig, resolveRpcUrls } from '../../config.js';
import { t, pickLang, SUPPORTED_LANGS } from '../common/i18n.js';
import { runLoaderVerification, launchVerifiedApp } from './loader.js';
import { LoaderStatus } from './verify-core.js';

const $ = (id) => document.getElementById(id);
let cfg = loadConfig();
let lang = pickLang(cfg.lang);
let tr = t(lang);

function statusMessage(res) {
  switch (res.status) {
    case LoaderStatus.OK: return { kind: 'ok', msg: tr('loader.ok', { buildVersion: res.buildVersion }) };
    case LoaderStatus.NO_HASH_REGISTERED: return { kind: 'warn', msg: tr('loader.fail.no_hash') };
    case LoaderStatus.RPC_FAIL: return { kind: 'fail', msg: tr('loader.fail.rpc') };
    case LoaderStatus.FETCH_FAIL: return { kind: 'fail', msg: tr('loader.fail.fetch') };
    case LoaderStatus.MAINTENANCE: return { kind: 'warn', msg: tr('loader.fail.maintenance') };
    case LoaderStatus.MANIFEST_INVALID: return { kind: 'fail', msg: tr('loader.fail.manifest_invalid') };
    case LoaderStatus.MANIFEST_HASH_MISMATCH: return { kind: 'fail', msg: tr('loader.fail.manifest_mismatch') };
    case LoaderStatus.FILE_HASH_MISMATCH: return { kind: 'fail', msg: tr('loader.fail.file_mismatch', { count: res.count }) };
    default: return { kind: 'fail', msg: `${res.status}: ${res.error || ''}` };
  }
}

function render() {
  tr = t(lang);
  $('title').textContent = tr('app.title');
  $('subtitle').textContent = tr('app.subtitle');
  $('h-loader').textContent = tr('entry.loader');
  $('desc-loader').textContent = tr('entry.loader.desc');
  $('rpc-label').textContent = tr('loader.rpc');
  $('verify-btn').textContent = tr('entry.loader');
  $('guarantee').textContent = tr('loader.guarantee');
  $('recovery-link').textContent = tr('entry.recovery');
}

function setStage(stage, extra) {
  const map = {
    reading: tr('loader.reading'),
    fetching: tr('loader.fetching'),
    verifying: tr('loader.verifying', { done: extra?.done ?? 0, total: extra?.total ?? 0 }),
  };
  $('stage').textContent = map[stage] || '';
}

async function onVerify() {
  $('result').textContent = '';
  $('launch-area').innerHTML = '';
  const rpcSel = $('rpc-select').value;
  cfg.rpcUrls = rpcSel === 'all' ? resolveRpcUrls(cfg) : [rpcSel];
  saveConfig({ rpcUrls: cfg.rpcUrls, lang });
  let res;
  try {
    res = await runLoaderVerification(cfg, { onStage: setStage });
  } catch (e) {
    res = { status: 'RPC_FAIL', error: String(e?.message || e) };
  }
  $('stage').textContent = '';
  const { kind, msg } = statusMessage(res);
  const box = $('result');
  box.className = `result ${kind}`;
  box.textContent = msg;
  if (res.status === LoaderStatus.OK) {
    if (res.warns?.some((w) => w.code === 'REREGISTERED')) {
      const w = res.warns.find((x) => x.code === 'REREGISTERED');
      const warnEl = document.createElement('div');
      warnEl.className = 'result warn';
      warnEl.textContent = tr('loader.warn.reregistered', { registrationCount: w.registrationCount });
      box.after(warnEl);
    }
    const btn = document.createElement('button');
    btn.textContent = tr('loader.launch');
    btn.onclick = () => launchVerifiedApp(cfg, res.manifest).catch((e) => { $('result').textContent = String(e?.message || e); });
    $('launch-area').appendChild(btn);
  } else {
    const link = document.createElement('a');
    link.href = './recovery.html';
    link.textContent = tr('loader.togo_recovery');
    link.className = 'togo';
    $('launch-area').appendChild(link);
  }
}

function init() {
  const langSel = $('lang-select');
  for (const l of SUPPORTED_LANGS) {
    const o = document.createElement('option');
    o.value = l; o.textContent = t(l)('lang.name'); if (l === lang) o.selected = true;
    langSel.appendChild(o);
  }
  langSel.onchange = () => { lang = langSel.value; render(); };
  const rpcSel = $('rpc-select');
  for (const p of cfg.rpcPresets) {
    const o = document.createElement('option'); o.value = p.url; o.textContent = `${p.name} (${p.url})`; rpcSel.appendChild(o);
  }
  const all = document.createElement('option'); all.value = 'all'; all.textContent = 'all presets (fallback)'; rpcSel.appendChild(all);
  $('verify-btn').onclick = onVerify;
  render();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}
