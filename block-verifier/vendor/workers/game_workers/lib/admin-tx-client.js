// private Service Binding経由のAdminTxCoordinatorクライアント。
const COORDINATOR_DEADLINE_MS = 30_000;

async function withCoordinatorDeadline(run) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      run(controller.signal),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error('coordinator_timeout'));
          controller.abort();
        }, COORDINATOR_DEADLINE_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function enqueueAdminTx(env, request) {
  if (!env?.ADMIN_TX_COORDINATOR || typeof env.ADMIN_TX_COORDINATOR.fetch !== 'function') {
    return { accepted: false, submitted: false, status: 'unavailable', reason: 'coordinator_binding_missing' };
  }
  try {
    const { response, body, invalidResponse } = await withCoordinatorDeadline(async (signal) => {
      const response = await env.ADMIN_TX_COORDINATOR.fetch(new Request('https://admin-tx-coordinator/enqueue', {
        method: 'POST', signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }));
      try { return { response, body: await response.json() }; }
      catch { return { invalidResponse: true }; }
    });
    if (invalidResponse) return { accepted: false, submitted: false,
      status: 'unavailable', reason: 'coordinator_invalid_response' };
    if (!response.ok) {
      return {
        accepted: false, submitted: false, status: body.status || 'unavailable',
        reason: body.reason || body.error || `coordinator_http_${response.status}`,
      };
    }
    return body;
  } catch (error) {
    return {
      accepted: false, submitted: false, status: 'unavailable',
      reason: error?.message === 'coordinator_timeout' ? 'coordinator_timeout' : 'coordinator_unavailable',
      error: String(error?.message || error).slice(0, 256),
    };
  }
}

export function adminTxReceiptBlockNumber(result) {
  const raw = result?.receipt?.blockNumber;
  if (raw === null || raw === undefined) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

export function isAdminTxPending(result) {
  return ['queued', 'in_flight', 'unavailable'].includes(result?.status);
}

export async function getAdminTxCoordinatorStatus(env) {
  if (!env?.ADMIN_TX_COORDINATOR || typeof env.ADMIN_TX_COORDINATOR.fetch !== 'function') {
    return { ok: false, reason: 'coordinator_binding_missing', inflight: null, queued: null };
  }
  try {
    const { response, body } = await withCoordinatorDeadline(async (signal) => {
      const response = await env.ADMIN_TX_COORDINATOR.fetch(new Request('https://admin-tx-coordinator/status', { signal }));
      return { response, body: await response.json() };
    });
    return response.ok ? body : { ok: false, reason: body.reason || body.error || `coordinator_http_${response.status}` };
  } catch (error) {
    return { ok: false, reason: error?.message === 'coordinator_timeout' ? 'coordinator_timeout' : 'coordinator_unavailable',
      error: String(error?.message || error).slice(0, 256) };
  }
}
