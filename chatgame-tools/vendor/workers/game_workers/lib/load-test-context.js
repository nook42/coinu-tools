// 通常運用のrequestには影響させず、E2E runnerが明示するtest mutationだけを
// run専用隔離deploymentへ束縛する追加ガード。headerがあるのにenv不一致ならfail closed。
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;

export function hasLoadTestMutationContext(request) {
  return request.headers.has('X-Test-Deployment-Fingerprint')
    || request.headers.has('X-Test-Namespace');
}

export function verifyLoadTestMutationContext(request, env) {
  if (!hasLoadTestMutationContext(request)) return true;
  const fingerprint = request.headers.get('X-Test-Deployment-Fingerprint');
  const namespace = request.headers.get('X-Test-Namespace');
  return env.LOAD_TEST_MODE === 'isolated'
    && env.ISOLATION_CONFIRMATION === 'dedicated-test-resources'
    && typeof env.TEST_NAMESPACE === 'string'
    && namespace === env.TEST_NAMESPACE
    && FINGERPRINT_RE.test(fingerprint || '')
    && fingerprint === env.DEPLOYMENT_FINGERPRINT;
}
