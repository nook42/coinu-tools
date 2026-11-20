// publicnode選択画面と最終まとめが共有する検証領域。名前はsummary.area.*だけで翻訳する。
// matchesは領域の全検査を拾う。requiredは到達確認の最低条件であり、成否のホワイトリストではない。
export const VERIFICATION_AREAS = [
  { area: 'adminHistory', historical: true,
    matches: /^fact\.system\.(?:adminRotation|superAdminRotation|donateSuperAdminChanges|donateAdminChanges|donateEventUnavailable)/,
    required: [], complete: (report) => {
      const audit = report.getFact?.('system.audit');
      return audit?.adminHistoryChecked === true && !audit.adminChangeError && !audit.donateEventError;
    } },
  { area: 'entries', historical: false, matches: /^check\.stageA\./,
    required: ['check.stageA.rootMatch', 'check.stageA.earlyFreeze'] },
  { area: 'selection', historical: false, matches: /^check\.stage[AB]\./,
    required: ['check.stageB.playersMatch', 'check.stageB.randao'] },
  { area: 'grouping', historical: false, matches: /^check\.stage[AB]\./,
    required: ['check.stageB.groupsMatch'] },
  { area: 'resultFiles', historical: false,
    matches: /^check\.stageC\.(?:downloads|manifest|summaryCanonicalJson)/,
    required: ['check.stageC.manifestAnchor', 'check.stageC.manifestFiles'] },
  { area: 'locks', historical: true,
    matches: /^check\.stageC\.(?:deposit|ethLockWiring)/,
    required: ['check.stageC.depositVerification'] },
  { area: 'scoring', historical: true,
    matches: /^check\.stage(?:[AB]\.|C\.(?:prerequisites|downloads|manifest|rules|roster|group|majorLangs|auto|noGameSummary|timelineNoGame|scoring|summary|merkleRebuild|deposit|ethLockWiring|evidence|archiveChainConsistency|chatWindowDeclared))/,
    required: ['check.stageC.summaryMatch', 'check.stageC.merkleRebuild'] },
  { area: 'publicMerkle', historical: false,
    matches: /^check\.stageC\.(?:merkle(?:Root|Totals)|onchainClaimData|claimDataFormat|summaryCanonicalJson)/,
    required: ['check.stageC.merkleRoot', 'check.stageC.merkleTotals', 'check.stageC.onchainClaimData'] },
  { area: 'evidence', historical: false,
    matches: /^check\.stageC\.(?:evidence|archiveChainConsistency|chatWindowDeclared|timelineNoGameEvidenceEmpty)/,
    required: ['check.stageC.evidenceCompleteness', 'check.stageC.evidenceAcc', 'check.stageC.archiveChainConsistency'] },
  { area: 'timeline', historical: true,
    matches: /^check\.stageC\.(?:timeline|chatWindowDeclared|groupCanonicalTimelineMatch|lifecycle|root|resultReregistration|proofAttachmentEvent)/,
    required: ['check.stageC.timelineWindows', 'check.stageC.lifecycleReplayCurrent'],
    notApplicable: (report, entries) => report.get('check.stageC.timelineWindows')?.params?.reason === 'no_evidence_windows'
      && entries.every((e) => e.status === 'skip') },
  { area: 'proofPublicValues', historical: false,
    matches: /^check\.stageC\.(?:zkCurrentRequirement|zkEpoch|zkVerifierIdentity|zkProofStatus|zkProofFormat|zkPublicValues)$/,
    required: ['check.stageC.zkProofFormat', 'check.stageC.zkPublicValues', 'check.stageC.zkVerifierIdentity'] },
  { area: 'proofHistory', historical: true,
    matches: /^check\.stageC\.(?:zkPrevRegistrationWitness|futureAnchorsHash)$/,
    required: ['check.stageC.futureAnchorsHash'] },
];

export function publicnodeExplanation(translate) {
  const lines = [translate('main.publicnodeIntro')];
  for (const historical of [false, true]) {
    lines.push(translate(historical ? 'main.publicnodeCannot' : 'main.publicnodeCan'));
    for (const row of VERIFICATION_AREAS.filter((row) => row.historical === historical)) {
      lines.push(`  ・${translate(`summary.area.${row.area}`)}`);
    }
  }
  return lines;
}
