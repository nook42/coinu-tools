// チェーン由来の表示名は、name/symbol/nameChanged の組が検証済みの場合だけ採用する。
// FAIL の原因になった未検証文字列を、その後の検査行や結論へ再表示しないための境界。

export function verifiedTokenDisplay(metadata) {
  if (!metadata || metadata.metadataOk !== true) return null;
  const expectedName = metadata.nameChanged ? 'Bitcoin' : 'COINU';
  const expectedSymbol = metadata.nameChanged ? 'BTC' : 'COINU';
  if (metadata.name !== expectedName || metadata.symbol !== expectedSymbol) return null;
  return { tokenName: metadata.name, tokenSymbol: metadata.symbol };
}

export function applyVerifiedTokenDisplay(translate, metadata) {
  const display = verifiedTokenDisplay(metadata);
  if (!display) return false;
  translate?.setDefaults?.(display);
  return true;
}
