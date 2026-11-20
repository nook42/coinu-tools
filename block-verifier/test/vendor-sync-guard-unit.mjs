// vendor-sync-guard-unit.mjs — `scripts/check-vendor-sync.mjs` **自身**の回帰テスト。
//
// 🔴 F-7(b)（2026-08-08・ラウンド20 判断不要-7）
//
// 同期検査スクリプトには**自分のテストが1本も無く**、CI にも載っていなかった。
// そのため次の2つの穴が長期間そのままだった（どちらも実測）:
//
//   ① standalone（モノレポ外）で **fail-open**
//      `MAX_DEPOSIT_WEI` を 10 ETH → 1000 ETH に改変した standalone コピーで走らせても
//      `monorepo sources not found — skipping` と出て **exit 0**（1バイトも照合していない）。
//      メッセージは「VENDOR_SYNC.md の sha256 が正」と書いているのに、その実装が無かった。
//
//   ③ EXTRACT が `findIndex`（**最初の1件**）
//      `lottery-DO.js` に同名の `selectWinners` を**後置**すると、JS は後勝ちで
//      後者が実行されるのに、抽出・照合されるのは前者なので `OK EXTRACT` が出た。
//      実測: 後置版は `(seed,10,4)` に `[2,3,7,8]` ではなく `[0,1,2,3]` を返す。
//
// ⚠️ **これは第三者検証の保証ではない**。台帳（VENDOR_SYNC.md）はドリフト検知であって
//    真正性の証明ではない（vendor を書ける者は同じコミットで台帳も書ける）。
//    ここが固定するのは「照合できていないのに緑を出さない」という運用衛生だけ。
//
// ⚠️ ② の MIRROR 逆方向は**別 assert**（本体側 sha を台帳へ入れた）。
//    「モノレポ内でも canon＋vendor＋台帳の3ファイルを同時に編集すれば緑」は
//    `docs/CLAIM_LEAF_DEPOSITID_INVENTORY.md:23` が明記した**受容事項**なので固定しない。
//
// 実行: node block-verifier/test/vendor-sync-guard-unit.mjs （Node 22）

import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, cpSync, symlinkSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const toolRoot = resolve(here, '..');       // block-verifier/
const repoRoot = resolve(toolRoot, '..');   // モノレポルート

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};

const runScript = (scriptPath) => {
  const r = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
};

console.log('vendor-sync-guard-unit: check-vendor-sync.mjs 自身の回帰');

// ============================================================
// BV-C2-03: gameMaxPlayers の出典は可変な行番号でなく同期検査へ束縛する
// ============================================================
{
  const configSource = readFileSync(join(toolRoot, 'src/config.js'), 'utf8');
  const pinComment = configSource.slice(
    configSource.indexOf('// GAME_MAX_PLAYERS'),
    configSource.indexOf('gameMaxPlayers:')
  );
  ok('BV-C2-03 gameMaxPlayers のコメントに可変な lottery-DO 行番号を持たない',
    !/lottery-DO\.js:\d+/.test(pinComment), pinComment.trim());
  ok('BV-C2-03 gameMaxPlayers は check-vendor-sync に機械束縛される',
    /check-vendor-sync\.mjs/.test(pinComment), pinComment.trim());
}

// ============================================================
// ① standalone（モノレポ外）は exit 1（fail-open の禁止）
// ============================================================
{
  const tmp = mkdtempSync(join(tmpdir(), 'bv-standalone-'));
  try {
    // <tmp>/block-verifier/{scripts,vendor,src,VENDOR_SYNC.md} だけを置く。
    // 親（<tmp>）に workers/ が無い ＝ 正典が読めない状態。
    const dst = join(tmp, 'block-verifier');
    mkdirSync(join(dst, 'scripts'), { recursive: true });
    cpSync(join(toolRoot, 'scripts/check-vendor-sync.mjs'), join(dst, 'scripts/check-vendor-sync.mjs'));
    cpSync(join(toolRoot, 'VENDOR_SYNC.md'), join(dst, 'VENDOR_SYNC.md'));
    // vendor と src は symlink で足りる（スクリプトは readFileSync するだけ）
    symlinkSync(join(toolRoot, 'vendor'), join(dst, 'vendor'), 'dir');
    symlinkSync(join(toolRoot, 'src'), join(dst, 'src'), 'dir');

    const r = runScript(join(dst, 'scripts/check-vendor-sync.mjs'));
    ok('① standalone では exit 1（旧実装は exit 0 ＝ fail-open）', r.status === 1, `exit=${r.status}`);
    ok('① 「ここでは検証できない」と明示する',
      /CANNOT VERIFY/i.test(r.out), r.out.split('\n').slice(0, 3).join(' / '));
    ok('① 台帳が真正性の証明ではないことを併記する',
      /not a proof of authenticity/i.test(r.out), r.out.split('\n').slice(0, 6).join(' / '));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// ============================================================
// ③ EXTRACT: 同名メソッドの後置で「実行される実装」が別物になっても緑にしない
// ============================================================
{
  const tmp = mkdtempSync(join(tmpdir(), 'bv-dupsig-'));
  try {
    // 疑似モノレポ: workers/{auth_workers,game_workers} は実物への symlink、
    // lottery_workers だけ実コピーして lottery-DO.js を細工する。
    const fakeRepo = join(tmp, 'repo');
    const dst = join(fakeRepo, 'block-verifier');
    mkdirSync(join(dst, 'scripts'), { recursive: true });
    mkdirSync(join(fakeRepo, 'workers/lottery_workers'), { recursive: true });
    cpSync(join(toolRoot, 'scripts/check-vendor-sync.mjs'), join(dst, 'scripts/check-vendor-sync.mjs'));
    cpSync(join(toolRoot, 'VENDOR_SYNC.md'), join(dst, 'VENDOR_SYNC.md'));
    symlinkSync(join(toolRoot, 'vendor'), join(dst, 'vendor'), 'dir');
    symlinkSync(join(toolRoot, 'src'), join(dst, 'src'), 'dir');
    symlinkSync(join(repoRoot, 'workers/auth_workers'), join(fakeRepo, 'workers/auth_workers'), 'dir');
    symlinkSync(join(repoRoot, 'workers/game_workers'), join(fakeRepo, 'workers/game_workers'), 'dir');

    const lotterySrc = readFileSync(join(repoRoot, 'workers/lottery_workers/lottery-DO.js'), 'utf8');
    const SIG = '  async selectWinners(seed, totalApplicants, winnerCount) {';

    // (a) 対照: そのままコピーすれば EXTRACT は緑（他の検査は環境差で赤くなりうるので
    //     EXTRACT 行だけを見る）
    writeFileSync(join(fakeRepo, 'workers/lottery_workers/lottery-DO.js'), lotterySrc);
    const ctl = runScript(join(dst, 'scripts/check-vendor-sync.mjs'));
    ok('③-ctrl 対照: 素のコピーでは EXTRACT が緑', /OK\s+EXTRACT/.test(ctl.out),
      ctl.out.split('\n').filter(l => /EXTRACT/.test(l)).join(' / '));

    // (b) 同名メソッドを**後置**（JS は後勝ち＝実行されるのはこちら）。
    //     クラス本体の閉じ括弧（列0の `}`）の**直前**へ挿入する。
    const lines = lotterySrc.split('\n');
    let classEnd = -1;
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i] === '}') { classEnd = i; break; }
    }
    if (classEnd < 0) throw new Error('lottery-DO.js のクラス閉じ括弧が見つからない');
    lines.splice(classEnd, 0,
      SIG, '    return Array.from({ length: winnerCount }, (_, i) => i);', '  }');
    const dup = lines.join('\n');
    writeFileSync(join(fakeRepo, 'workers/lottery_workers/lottery-DO.js'), dup);
    const r = runScript(join(dst, 'scripts/check-vendor-sync.mjs'));
    const extractLines = r.out.split('\n').filter(l => /EXTRACT/.test(l)).join(' / ');
    ok('③ 同名メソッドが2つある正典では EXTRACT が FAIL',
      /FAIL\s+EXTRACT/.test(r.out), extractLines);
    ok('③ 何が起きているかを名指しする（後勝ちで別実装が動く）',
      /appears 2 times/.test(r.out) && /LAST definition/.test(r.out), extractLines);
    ok('③ 終了コードが 1', r.status === 1, `exit=${r.status}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// T1l: Finder の残骸は追跡台帳の対象外。実コードを1本増やせば失敗する。
{
  const tmp = mkdtempSync(join(tmpdir(), 'bv-inventory-'));
  try {
    const fakeRepo = join(tmp, 'repo');
    const dst = join(fakeRepo, 'block-verifier');
    mkdirSync(join(dst, 'scripts'), { recursive: true });
    cpSync(join(toolRoot, 'scripts/check-vendor-sync.mjs'), join(dst, 'scripts/check-vendor-sync.mjs'));
    cpSync(join(toolRoot, 'VENDOR_SYNC.md'), join(dst, 'VENDOR_SYNC.md'));
    cpSync(join(toolRoot, 'vendor'), join(dst, 'vendor'), { recursive: true });
    symlinkSync(join(toolRoot, 'src'), join(dst, 'src'), 'dir');
    symlinkSync(join(repoRoot, 'workers'), join(fakeRepo, 'workers'), 'dir');
    symlinkSync(join(repoRoot, 'src'), join(fakeRepo, 'src'), 'dir');
    writeFileSync(join(dst, 'vendor/.DS_Store'), 'finder');
    const ignored = runScript(join(dst, 'scripts/check-vendor-sync.mjs'));
    ok('T1l .DS_Store は inventory の失敗にしない',
      /OK\s+VENDOR-INVENTORY/.test(ignored.out)
        && !/FAIL\s+VENDOR-INVENTORY/.test(ignored.out));
    writeFileSync(join(dst, 'vendor/unlisted-T1l.js'), 'export const mutation = true;');
    const unlisted = runScript(join(dst, 'scripts/check-vendor-sync.mjs'));
    ok('T1l 台帳外の実コードは inventory が検出する',
      /FAIL\s+VENDOR-INVENTORY vendor\/unlisted-T1l\.js/.test(unlisted.out));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

console.log('');
if (failed > 0) {
  console.error(`❌ ${failed} FAILED (${passed} passed)`);
  process.exit(1);
}
console.log(`✅ ALL PASSED (${passed} checks)`);
