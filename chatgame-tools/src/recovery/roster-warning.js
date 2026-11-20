// 名簿切替の理由を、事実より強い断定をしない利用者向け文面へ対応づける。
const ANCHORED_REASON_KEYS = Object.freeze({
  previous_summary_anchor_mismatch: 'recovery.warn.anchoredRosterFallback.previousSummaryMismatch',
  previous_summary_anchor_unavailable: 'recovery.warn.anchoredRosterFallback.previousSummaryUnavailable',
  previous_summary_anchor_invalid: 'recovery.warn.anchoredRosterFallback.previousSummaryInvalid',
  published_game_groups_unavailable: 'recovery.warn.anchoredRosterFallback.publishedGroupsUnavailable',
  published_game_groups_mismatch: 'recovery.warn.anchoredRosterFallback.publishedGroupsMismatch',
});
const RECONSTRUCTION_STOP_KEYS = Object.freeze({
  previous_summary_anchor_unavailable: 'recovery.warn.rosterReconstructionStop.previousSummaryUnavailable',
  previous_summary_anchor_mismatch: 'recovery.warn.rosterReconstructionStop.previousSummaryMismatch',
  previous_summary_anchor_invalid: 'recovery.warn.rosterReconstructionStop.previousSummaryInvalid',
});

export const ANCHORED_ROSTER_ERROR_CATEGORIES = Object.freeze(Object.assign(Object.create(null), {
  anchored_roster_config_missing: 'unavailable',
  anchored_roster_manifest_unavailable: 'unavailable',
  anchored_roster_chain_read_failed: 'unavailable',
  anchored_roster_chain_anchor_unavailable: 'unavailable',
  anchored_roster_manifest_invalid: 'invalid',
  anchored_roster_selection_mismatch: 'mismatch',
  anchored_roster_group_unavailable: 'unavailable',
  anchored_roster_commitment_invalid: 'invalid',
  anchored_roster_commitment_mismatch: 'mismatch',
  anchored_roster_index_unavailable: 'unavailable',
  anchored_roster_index_mismatch: 'mismatch',
  anchored_roster_index_invalid: 'invalid',
  anchored_roster_group_mismatch: 'mismatch',
  anchored_roster_group_invalid: 'invalid',
  anchored_roster_proof_invalid: 'invalid',
}));

export function anchoredRosterErrorCode(error) {
  return typeof error?.code === 'string'
    && Object.prototype.hasOwnProperty.call(ANCHORED_ROSTER_ERROR_CATEGORIES, error.code)
    ? error.code : 'unknown';
}

export function rosterFallbackWarningKey(roster) {
  if (roster?.rosterAnchorCheckStatus === 'mismatch') return 'recovery.warn.rosterMismatchStop';
  if (roster?.rosterAnchorCheckStatus === 'absent') return 'recovery.warn.rosterAbsentStop';
  if (roster?.rosterAnchorCheckStatus === 'reconstruction_unavailable') {
    return RECONSTRUCTION_STOP_KEYS[roster.anchoredRosterFallbackReason]
      || 'recovery.warn.rosterReconstructionStop.unknown';
  }
  if (roster?.rosterAnchorStatus === 'legacy') return 'recovery.warn.rosterLegacy';
  if (roster?.anchoredRosterFallback === true) {
    return ANCHORED_REASON_KEYS[roster.anchoredRosterFallbackReason]
      || 'recovery.warn.anchoredRosterFallback.unknown';
  }
  if (roster?.recomputedRosterFallback === true) {
    return 'recovery.warn.recomputedRosterFallback.canonicalMatch';
  }
  return null;
}

export function formatRosterIntegrityWarning(roster, tr) {
  const rawReason = roster?.anchoredRosterFallbackReason
    || roster?.recomputedRosterFallbackReason
    || 'unknown';
  const reason = typeof rawReason === 'string' && (
    Object.prototype.hasOwnProperty.call(ANCHORED_REASON_KEYS, rawReason)
    || Object.prototype.hasOwnProperty.call(RECONSTRUCTION_STOP_KEYS, rawReason)
    || ['canonical_manifest_match', 'roster_reconstruction_unavailable', 'external_read_unavailable'].includes(rawReason)
  ) ? rawReason : 'unknown';
  const key = rosterFallbackWarningKey({ ...roster, anchoredRosterFallbackReason: reason });
  if (!key) return null;
  const anchorCode = roster?.recomputedRosterFallbackAnchorError;
  const anchorError = typeof anchorCode === 'string'
    && Object.prototype.hasOwnProperty.call(ANCHORED_ROSTER_ERROR_CATEGORIES, anchorCode)
    ? `${tr(`recovery.warn.anchorError.${ANCHORED_ROSTER_ERROR_CATEGORIES[anchorCode]}`)} (${anchorCode})`
    : tr('recovery.warn.anchorError.unknown');
  const params = {
    reason, anchorError,
    rosterAnchorHash: typeof roster?.rosterAnchorHash === 'string' && /^0x[0-9a-fA-F]{64}$(?![\s\S])/.test(roster.rosterAnchorHash) ? roster.rosterAnchorHash : '-',
    rosterAnchorIndex: Number.isSafeInteger(roster?.rosterAnchorIndex) && roster.rosterAnchorIndex >= 0 ? roster.rosterAnchorIndex : '-',
    recomputedHash: typeof roster?.recomputedHash === 'string' && /^0x[0-9a-fA-F]{64}$(?![\s\S])/.test(roster.recomputedHash) ? roster.recomputedHash : '-',
  };
  const primary = tr(key, params);
  const evidence = roster?.rosterAnchorHash != null && roster?.rosterAnchorIndex != null
    ? ` ${tr('recovery.warn.rosterAnchorEvidence', params)}` : '';
  const recomputed = roster?.recomputedHash != null
    ? ` ${tr('recovery.warn.rosterRecomputedHash', params)}` : '';
  return `⚠ ${primary}${evidence}${recomputed}${roster?.rosterAnchorStatus === 'legacy'
    && roster?.recomputedRosterFallback === true
    ? ` ${tr('recovery.warn.recomputedRosterFallback.legacyMatch', params)}` : ''}`;
}

export function formatLateRosterWarning(lateCount, tr) {
  return `⚠ ${tr('recovery.warn.rosterLateRegistrations', { count: lateCount })}`;
}
