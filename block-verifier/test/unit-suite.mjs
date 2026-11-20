import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const testDir = dirname(fileURLToPath(import.meta.url));
const excluded = new Map([
  // 補助ZKPスイートは、リポジトリに同梱されていない過去Groth16 cold-proof成果物を要求する。
  // 再実行検証のnpm testからは分離し、存在しない証明の生成・再生成を決して行わない。
  ['zkp-unit.mjs', 'historical Groth16 cold-proof fixture is not present'],
]);
const files = readdirSync(testDir)
  .filter((name) => name.endsWith('-unit.mjs'))
  .filter((name) => !excluded.has(name))
  .sort();

for (const [file, reason] of excluded) {
  process.stdout.write(`SKIP ${file}: ${reason}\n`);
}

let failed = 0;
for (const file of files) {
  process.stdout.write(`\n=== ${file} ===\n`);
  const result = spawnSync(process.execPath, [join(testDir, file)], {
    cwd: join(testDir, '..'),
    env: process.env,
    stdio: 'inherit',
  });
  if (result.status !== 0) failed++;
}

if (failed > 0) {
  console.error(`\n${failed}/${files.length} unit test files failed.`);
  process.exit(1);
}
console.log(`\nALL PASSED: ${files.length} unit test files`);
