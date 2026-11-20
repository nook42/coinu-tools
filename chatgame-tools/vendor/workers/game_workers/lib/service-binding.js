// workers/game_workers/lib/service-binding.js
//
// S3-003 ＝ K-S4-001 ＝ K-S5-001（2026-07-29）: DO→Worker の呼び出しを
// **公開 workers.dev URL から Service Binding へ**移すための共通ヘルパー。
//
// なぜ移すのか（4年運用を前提とした判断・2026-07-29 ユーザー決定）:
//   ・現状でも動いている（DO→Worker の公開 URL fetch が 1042 になる実測は無い）。
//     ただし Worker→Worker は既に禁止されており、DO→Worker が今後も許され続ける保証は無い。
//     仕様が変われば収集・抽選・グループ分け・ログイン・シャード書込・proof 生成が同時に止まる。
//   ・内部通信が公開 DNS / 公開ルーティングに依存している状態そのものを無くす。
//   ・`AGENTS.md:89` の運用規約（DO→worker は Service Binding）に実装を一致させる。
//
// ⚠️ Service Binding には**公開 URL には無い上限**がある:
//     「A single request has a maximum of 32 Worker invocations,
//       and each call to a Service binding counts towards this limit.」
//   しかも公式ドキュメントは「32 がワーカーごとか、元リクエストからの合計か」を明記していない。
//   → **どちらの解釈でも安全**になるよう、1回の実行での呼び出しを
//      SB_MAX_CALLS_PER_INVOCATION 以下に抑え、超える分は
//      カーソルを保存して次の実行（アラーム）へ持ち越す（分割送信）。
//   このため呼び出し側は「予算切れ＝resumable」を扱えるようになっている必要がある。

// 1回の実行で行ってよい Service Binding 呼び出しの上限。
// 公式上限は 32。解釈の不確実性とリトライぶんの余裕を見て 30 に置く
// （恣意的な数字ではなく「32 から2回ぶんの余裕を引いた値」）。
export const SB_MAX_CALLS_PER_INVOCATION = 30;

// Worker 全体のサブリクエスト設計上限。契約プランの実上限について
// リポジトリ内に異なる記述があったため、現在の実装が前提にしている保守値を
// ここ1箇所に固定する。他のワーカーは数値を写経せず、必ずこの定数から導出する。
export const WORKER_SUBREQUEST_LIMIT = 1000;

/**
 * バインディングを取り出す。無ければ**理由の分かる例外**を投げる（fail-closed）。
 * 公開 URL への暗黙フォールバックは持たない — 持つと「設定漏れに気づかないまま
 * 公開経路で動き続ける」ことになり、移行した意味が消えるため。
 * 設定漏れは deploy 直後の `/binding-check` で検出する運用にする。
 */
export function requireBinding(env, name) {
  const b = env?.[name];
  if (!b || typeof b.fetch !== 'function') {
    throw new Error(
      `[binding] service binding "${name}" is not configured on this Worker — ` +
      `add it to the wrangler config ([[services]]) and redeploy. ` +
      `(GET /binding-check lists every expected binding and its state)`
    );
  }
  return b;
}

/**
 * Service Binding 経由の内部呼び出し。
 * URL の host 部分は使われないので `http://internal` 固定にする
 * （公開 URL を組み立てないことで、コピペで公開経路へ戻るのを防ぐ）。
 */
export function internalRequest(path, init = {}) {
  return new Request(`http://internal${path}`, init);
}

/**
 * JSON を POST する定型。`X-Api-Secret` は呼び出し側の責務（受け側が検証する）。
 */
export function internalJsonRequest(path, body, apiSecret, extraHeaders = {}) {
  return internalRequest(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(apiSecret ? { 'X-Api-Secret': apiSecret } : {}),
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

/**
 * 期待するバインディング名の一覧に対し、実際に存在するかを返す（監視・デプロイ後検査用）。
 * @returns {{ok: boolean, missing: string[], present: number, expected: number}}
 */
export function checkBindings(env, expectedNames) {
  const missing = [];
  for (const name of expectedNames) {
    const b = env?.[name];
    if (!b || typeof b.fetch !== 'function') missing.push(name);
  }
  return {
    ok: missing.length === 0,
    missing,
    present: expectedNames.length - missing.length,
    expected: expectedNames.length,
  };
}

/** write-worker のバインディング名（既存の命名: WRITE_WORKER_0..39） */
export const writeWorkerBinding = (index) => `WRITE_WORKER_${index}`;
/** auth-worker のバインディング名（auth-worker-0..99 に対応） */
export const authWorkerBinding = (index) => `AUTH_WORKER_${index}`;
/** collect-worker のバインディング名（collect-worker-00..99 に対応・2桁ゼロ埋め） */
export const collectWorkerBinding = (paddedIndex) => `COLLECT_WORKER_${paddedIndex}`;

export const WRITE_WORKER_COUNT = 40;
export const AUTH_WORKER_COUNT = 100;
export const COLLECT_WORKER_COUNT = 100;

/** game_workers（GameMasterDO + ChatGameDO は同一 Worker）が必要とする全バインディング */
export function expectedGameWorkerBindings() {
  const names = ['CLAIM_WORKER', 'ADMIN_TX_COORDINATOR'];
  for (let i = 0; i < WRITE_WORKER_COUNT; i++) names.push(writeWorkerBinding(i));
  for (let i = 0; i < AUTH_WORKER_COUNT; i++) names.push(authWorkerBinding(i));
  return names;
}
