// 外部HTTP読取の共通上限。fetch の接続だけでなく response body の読取りまで同じ期限で囲う。
export const EXTERNAL_READ_TIMEOUT_MS = 5000;

export class ExternalReadUnavailableError extends Error {
  constructor(message, cause = null) {
    super(message, cause ? { cause } : undefined);
    this.name = 'ExternalReadUnavailableError';
    this.code = 'external_read_unavailable';
  }
}

export async function withExternalReadTimeout(
  operation,
  { timeoutMs = EXTERNAL_READ_TIMEOUT_MS, signal: parentSignal = undefined, label = 'external read' } = {},
) {
  const limit = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
    ? Number(timeoutMs) : EXTERNAL_READ_TIMEOUT_MS;
  const controller = new AbortController();
  const abortFromParent = () => controller.abort(parentSignal?.reason);
  if (parentSignal?.aborted) abortFromParent();
  else parentSignal?.addEventListener?.('abort', abortFromParent, { once: true });

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new ExternalReadUnavailableError(`${label} timed out after ${limit}ms`));
    }, limit);
  });
  try {
    return await Promise.race([operation(controller.signal), timeout]);
  } catch (error) {
    if (error?.code === 'external_read_unavailable') throw error;
    if (controller.signal.aborted && !parentSignal?.aborted) {
      throw new ExternalReadUnavailableError(`${label} timed out after ${limit}ms`, error);
    }
    throw error;
  } finally {
    clearTimeout(timer);
    parentSignal?.removeEventListener?.('abort', abortFromParent);
  }
}

export async function fetchBounded(
  url,
  options = {},
  { timeoutMs = EXTERNAL_READ_TIMEOUT_MS, label = String(url), read = (response) => response } = {},
) {
  const { signal: parentSignal, ...fetchOptions } = options;
  return withExternalReadTimeout(async (signal) => {
    const response = await fetch(url, { ...fetchOptions, signal });
    return read(response);
  }, { timeoutMs, signal: parentSignal, label });
}

export function fetchJsonBounded(url, options = {}, config = {}) {
  return fetchBounded(url, options, { ...config, read: (response) => response.json() });
}

export function fetchTextBounded(url, options = {}, config = {}) {
  return fetchBounded(url, options, { ...config, read: (response) => response.text() });
}

export function fetchArrayBufferBounded(url, options = {}, config = {}) {
  return fetchBounded(url, options, { ...config, read: (response) => response.arrayBuffer() });
}
