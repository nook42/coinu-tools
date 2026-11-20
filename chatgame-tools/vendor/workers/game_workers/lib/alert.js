// workers/game_workers/lib/alert.js
//
// S3-008（2026-07-29・ユーザー要望）: 照合できずゲームを開始できない状態を**運用者へ即座に通知**する。
//
// なぜ必要か:
//   S3-008 の対処で「照合できるまでゲームを開始しない」ようにした。その待機には期限があり、
//   `extendGrace` が不可能になる時刻（初期状態なら応募終了+26時間）を過ぎると、
//   そのブロックは「ゲームなし・報酬永久凍結」に倒れる。
//   つまり **運用者がその期限内にトラブルへ気づけるか**が結果を左右する。
//   `/calc-status` を見に行かないと分からない状態では気づけないので、能動的に知らせる。
//
// 送信経路（両方任意・設定されているものを順に試す）:
//   ① Cloudflare Email Service の send_email バインディング
//        wrangler-config:
//          [[send_email]]
//          name = "ALERT_EMAIL"
//          # destination_address は**書かない**。書くと宛先がリポジトリに残るうえ、
//          # Email Sending では宛先を固定する必要がない。
//        env: ALERT_EMAIL_FROM（送信元・オンボード済みゾーンのアドレス。実在しなくてよい）
//             ALERT_EMAIL_TO  （宛先）
//
//        ⚠️ バインディングの呼び出し方は Cloudflare 側で2世代ある（2026-07-30 実機確認）:
//          ・Email Sending（現行 Email Service・public beta 2026-04-16）
//              env.ALERT_EMAIL.send({ from, to, subject, text })   ← 構造化オブジェクト
//          ・Email Routing（旧来の send_email）
//              env.ALERT_EMAIL.send(new EmailMessage(from, to, rawMime))
//        どちらが有効かは環境に依存するため**順に試す**。先に成功した時点で返すので
//        二重送信は起きない（throw しなかった＝送れた、の一手で判定する）。
//   ② 汎用 Webhook（外部のメール送信 API 等）
//        env: ALERT_WEBHOOK_URL / ALERT_WEBHOOK_AUTH（任意・Authorization ヘッダの値）
//
// 設計上の約束:
//   ・**絶対に throw しない。** 通知の失敗がゲームのパイプラインを止めてはならない。
//   ・**宛先をソースに埋め込まない。** env で渡す（リポジトリに個人のアドレスを残さない）。
//   ・送信結果は DO ストレージへ残し、`/status` から «通知できているか» を確認できるようにする。

const ALERT_STATE_KEY = 'alert_last_result';
const ALERT_STATE_PREFIX = `${ALERT_STATE_KEY}:`;

export function alertStateKey(kind) {
  return `${ALERT_STATE_PREFIX}${String(kind || 'unknown')}`;
}

/** 通知先が1つも設定されていなければ false（＝この環境では通知しない） */
export function alertConfigured(env) {
  return !!(env?.ALERT_EMAIL && env?.ALERT_EMAIL_TO && env?.ALERT_EMAIL_FROM) || !!env?.ALERT_WEBHOOK_URL;
}

/** 設定状況（値は出さない）。監視・テスト用 */
export function describeAlertConfig(env) {
  return {
    email: !!(env?.ALERT_EMAIL && env?.ALERT_EMAIL_TO && env?.ALERT_EMAIL_FROM),
    webhook: !!env?.ALERT_WEBHOOK_URL,
    configured: alertConfigured(env),
  };
}

// RFC 5322 の最小メッセージを組み立てる（依存を増やさないため手組み）。
// 件名は非ASCIIを含みうるので RFC 2047 の Base64 エンコードを使う。
export function buildMimeMessage({ from, to, subject, body }) {
  const b64 = (s) => {
    const bytes = new TextEncoder().encode(s);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  };
  const encodedSubject = /^[\x20-\x7E]*$/.test(subject) ? subject : `=?UTF-8?B?${b64(subject)}?=`;
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: base64',
    '',
    b64(body),
  ].join('\r\n');
}

/**
 * 通知を送る。**失敗しても throw しない**（結果を返すだけ）。
 * @returns {Promise<{sent: boolean, via: string|null, error: string|null, skipped?: boolean}>}
 */
export async function sendAlert(env, { subject, body }) {
  if (!alertConfigured(env)) {
    return { sent: false, via: null, error: null, skipped: true };
  }

  // 失敗理由は**全部**残す。1つ目の方式が「API の形が違う」で落ちたのか
  // 「送信自体が拒否された」で落ちたのかは、後から切り分けが必要になる。
  const attempts = [];

  // ① Cloudflare Email Service（send_email バインディング）
  if (env.ALERT_EMAIL && env.ALERT_EMAIL_TO && env.ALERT_EMAIL_FROM) {
    // ①-a Email Sending（現行）: 構造化オブジェクト
    try {
      await env.ALERT_EMAIL.send({
        from: env.ALERT_EMAIL_FROM,
        to: env.ALERT_EMAIL_TO,
        subject,
        text: body,
      });
      return { sent: true, via: 'cloudflare_email_sending', error: null };
    } catch (e) {
      attempts.push(`email_sending: ${e?.message || e}`);
    }

    // ①-b Email Routing（旧）: 生 MIME + EmailMessage
    try {
      // cloudflare:email は Workers ランタイムだけに存在する。
      // ローカルの単体テストから import しても壊れないよう動的 import で囲む。
      const { EmailMessage } = await import('cloudflare:email');
      const raw = buildMimeMessage({
        from: env.ALERT_EMAIL_FROM, to: env.ALERT_EMAIL_TO, subject, body,
      });
      await env.ALERT_EMAIL.send(new EmailMessage(env.ALERT_EMAIL_FROM, env.ALERT_EMAIL_TO, raw));
      return { sent: true, via: 'cloudflare_email_routing', error: null };
    } catch (e) {
      attempts.push(`email_routing: ${e?.message || e}`);
    }
    console.error('[alert] cloudflare email send failed:', attempts.join(' | '));
    // ② へフォールバック
  }

  // ② 汎用 Webhook
  if (env.ALERT_WEBHOOK_URL) {
    try {
      const res = await fetch(env.ALERT_WEBHOOK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(env.ALERT_WEBHOOK_AUTH ? { Authorization: env.ALERT_WEBHOOK_AUTH } : {}),
        },
        body: JSON.stringify({ to: env.ALERT_EMAIL_TO || null, subject, text: body }),
      });
      if (res.ok) return { sent: true, via: 'webhook', error: null };
      attempts.push(`webhook: HTTP ${res.status}`);
    } catch (e) {
      attempts.push(`webhook: ${e?.message || e}`);
    }
    return { sent: false, via: 'webhook', error: attempts.join(' | ') };
  }

  return { sent: false, via: null, error: attempts.length ? attempts.join(' | ') : 'no transport succeeded' };
}

/**
 * 送信し、結果を DO ストレージへ記録する（`/status` から «通知できているか» が見える）。
 * storage は任意（無ければ記録だけ省く）。
 */
export async function sendAlertAndRecord(env, storage, { subject, body, kind }) {
  const result = await sendAlert(env, { subject, body });
  try {
    const record = {
      kind: kind || null,
      subject,
      at: Date.now(),
      ...result,
    };
    if (storage) {
      // `alert_last_result` は既存の監視APIとの後方互換用に最新1件を保つ。
      // 障害の記録は後続の別種アラートで消えないよう、kind別キーにも保存する。
      await storage.put({
        [ALERT_STATE_KEY]: record,
        [alertStateKey(kind)]: record,
      });
    }
  } catch { /* 記録の失敗も無害化する */ }
  return result;
}

export { ALERT_STATE_KEY, ALERT_STATE_PREFIX };
