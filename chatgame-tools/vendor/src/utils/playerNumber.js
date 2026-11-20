// S3R5-U-R05-PLAYERNO: 確定名簿の位置を使う表示だけの補助。
export const POINTED_NAME_TOKEN = '\uE000';

function safeString(value) {
  try { return String(value ?? ''); } catch { return ''; }
}

export function playerNumberOf(members, uid) {
  try {
    if (!Array.isArray(members) || uid == null || safeString(uid) === '') return null;
    const target = String(uid);
    for (let i = 0; i < members.length; i++) {
      const member = members[i];
      if (member && member.uid != null && String(member.uid) === target) return i + 1;
    }
  } catch { return null; }
  return null;
}

export function isolatePointedName(name) {
  const shown = (typeof name === 'string' ? name : safeString(name))
    .replace(/[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/gu, '')
    .replace(/[\n\r\u001C-\u001E\u0085\u2028\u2029]/gu, ' ');
  return `\u2068${shown}\u2069`;
}

export function pointedNameText(name, label) {
  return `${isolatePointedName(name)}(${safeString(label)})`;
}

export function pointedTemplateText(translate, key, param, shown, label) {
  try {
    if (label == null || label === '') return translate(key, { [param]: shown });
    return String(translate(key, { [param]: POINTED_NAME_TOKEN }))
      .split(POINTED_NAME_TOKEN).join(pointedNameText(shown, label));
  } catch { return ''; }
}

export function pointedTemplateParts(translate, key, param, shown, label) {
  if (label == null || label === '') return null;
  try {
    const pieces = String(translate(key, { [param]: POINTED_NAME_TOKEN })).split(POINTED_NAME_TOKEN);
    const parts = [];
    pieces.forEach((piece, index) => {
      if (index) parts.push({ name: isolatePointedName(shown), tag: `(${safeString(label)})` });
      if (piece) parts.push(piece);
    });
    return parts;
  } catch { return []; }
}
