#!/usr/bin/env node
// check-vendor-sync.mjs — vendor/ と正典（モノレポ）の同期検査（chatgame-tools）
//
//   COPY   … vendor ファイルと正典ファイルのバイト一致
//   MIRROR … 正典の該当行範囲の sha256 が台帳記録値と一致（変わったらミラー再レビューが必要）
//   DIST   … **配信物（dist/）が現在の vendor/・src/・config.js・bundle依存から作られているか**
//              （R-6・R6 B-4・M10-02・周14 T6）
// いずれかが不一致なら exit 1。
// モノレポ外（独立リポジトリ化後）で実行された場合は正典が読めないため skip 扱いで exit 0。

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectBundleInputDigest } from '../build/bundle.mjs';
import { DEFAULTS, PIN_OMISSIONS } from '../config.js';

const here = dirname(fileURLToPath(import.meta.url));
const toolRoot = resolve(here, '..');          // chatgame-tools/
const repoRoot = resolve(toolRoot, '..');      // モノレポルート

// vendor/ ツリー全体の指紋（相対パス昇順の "path sha256" 行を連結して sha256）。
// 🔴 **同じ関数を `build/bundle.mjs` にも置いてある**（片方だけ変えたら
//    突き合わせが必ず失敗するので、変えるときは両方・byte 同一に保つこと）。
export function digestVendorTree(vendorRoot) {
  const rel = [];
  const walk = (dir, prefix) => {
    for (const name of readdirSync(dir).sort()) {
      const abs = join(dir, name);
      const key = prefix ? `${prefix}/${name}` : name;
      if (statSync(abs).isDirectory()) walk(abs, key);
      else rel.push([key, createHash('sha256').update(readFileSync(abs)).digest('hex')]);
    }
  };
  walk(vendorRoot, '');
  const lines = rel.map(([k, h]) => `${k} ${h}`);
  return {
    count: rel.length,
    digest: createHash('sha256').update(lines.join('\n')).digest('hex'),
    files: Object.fromEntries(rel),
  };
}

// COPY 台帳: [vendor相対, 正典相対]（VENDOR_SYNC.md と一致させること）
const COPIES = [
  // P2b-2c: 共有の既読入口。公式 hook の MIRROR 2窓は本体不変を検査する。
  ['vendor/workers/game_workers/lib/protocol-v2.js', 'workers/game_workers/lib/protocol-v2.js'],
  ['vendor/workers/game_workers/lib/submission-limits.js', 'workers/game_workers/lib/submission-limits.js'],
  ['vendor/workers/game_workers/lib/priority-fields.js', 'workers/game_workers/lib/priority-fields.js'],
  ['vendor/workers/game_workers/lib/evidence-compact-v1.js', 'workers/game_workers/lib/evidence-compact-v1.js'],
  ['vendor/workers/game_workers/lib/evidence-trim.js', 'workers/game_workers/lib/evidence-trim.js'],
  ['vendor/workers/game_workers/lib/zkp-protocol.js', 'workers/game_workers/lib/zkp-protocol.js'],
  ['vendor/workers/game_workers/lib/roster-member-root.js', 'workers/game_workers/lib/roster-member-root.js'],
  ['vendor/workers/game_workers/lib/evidence-sender-vectors.json', 'workers/game_workers/lib/evidence-sender-vectors.json'],
  // 周11 P1: game-master-DO.js が Stage 3 の group witness 生成のため import するようになった。
  ['vendor/workers/game_workers/lib/group-witness.js', 'workers/game_workers/lib/group-witness.js'],
  // 同上: group-witness.js が depositId の正準化を entry_workers から取り込む。
  ['vendor/workers/entry_workers/lib/deposit-id.js', 'workers/entry_workers/lib/deposit-id.js'],
  ['vendor/workers/entry_workers/lib/nostr-key.js', 'workers/entry_workers/lib/nostr-key.js'],
  ['vendor/workers/game_workers/lib/char-counter.js', 'workers/game_workers/lib/char-counter.js'],
  ['vendor/workers/game_workers/lib/game-result-calculator.js', 'workers/game_workers/lib/game-result-calculator.js'],
  ['vendor/workers/game_workers/lib/evidence-reconciler.js', 'workers/game_workers/lib/evidence-reconciler.js'],
  ['vendor/workers/game_workers/lib/finality.js', 'workers/game_workers/lib/finality.js'],
  ['vendor/workers/game_workers/lib/evidence-segment-plan.js', 'workers/game_workers/lib/evidence-segment-plan.js'],
  ['vendor/workers/game_workers/lib/getlogs-adaptive.js', 'workers/game_workers/lib/getlogs-adaptive.js'],
  ['vendor/workers/game_workers/lib/timeline-check.js', 'workers/game_workers/lib/timeline-check.js'],
  // 🔴 R15延長: game-master-DO.js が MAX_VERIFICATION_EXTENSION_SEC を import するようになったので追加。
  //    これが無いと esbuild が './lib/block-lifecycle.js' を解決できず bundle が落ちる（要領§8 罠#4）。
  ['vendor/workers/game_workers/lib/block-lifecycle.js', 'workers/game_workers/lib/block-lifecycle.js'],
  // S3-001: game-master-DO.js の新しい依存（選出データ完全性検査 + 決定的抽選）
  ['vendor/workers/game_workers/lib/selection-integrity.js', 'workers/game_workers/lib/selection-integrity.js'],
  ['vendor/workers/game_workers/lib/select-winners.js', 'workers/game_workers/lib/select-winners.js'],
  // P-2026-0816: game-master-DO.js の新しい依存（グループ分け完全性検査）
  ['vendor/workers/game_workers/lib/grouping-integrity.js', 'workers/game_workers/lib/grouping-integrity.js'],
  ['vendor/workers/game_workers/lib/canonical-json.js', 'workers/game_workers/lib/canonical-json.js'],
  // S3-003: DO→Worker を Service Binding へ移した共通ヘルパー（game-master-DO / chat-game-DO が import）
  ['vendor/workers/game_workers/lib/service-binding.js', 'workers/game_workers/lib/service-binding.js'],
  ['vendor/workers/game_workers/lib/admin-tx-client.js', 'workers/game_workers/lib/admin-tx-client.js'],
  // S3-008: RPC 一覧の組み立てと障害通知（game-master-DO が import）
  ['vendor/workers/game_workers/lib/rpc-urls.js', 'workers/game_workers/lib/rpc-urls.js'],
  ['vendor/workers/game_workers/lib/rpc-independence.js', 'workers/game_workers/lib/rpc-independence.js'],
  ['vendor/workers/game_workers/lib/alert.js', 'workers/game_workers/lib/alert.js'],
  ['vendor/workers/game_workers/lib/observation-write-failures.js', 'workers/game_workers/lib/observation-write-failures.js'],
  ['vendor/workers/game_workers/lib/load-test-context.js', 'workers/game_workers/lib/load-test-context.js'],
  // K-S5-002: 請求データのオンチェーン公開フォーマット（正典と1バイトも違ってはならない）
  ['vendor/workers/game_workers/lib/claim-data-codec.js', 'workers/game_workers/lib/claim-data-codec.js'],
  // M10a: 開始関門の変更も正典 GM との byte 一致で検査する。
  ['vendor/workers/game_workers/game-master-DO.js', 'workers/game_workers/game-master-DO.js'],
  ['vendor/workers/game_workers/lib/roster-anchor-rule.js', 'workers/game_workers/lib/roster-anchor-rule.js'],
  ['vendor/workers/game_workers/lib/roster-canonical.js', 'workers/game_workers/lib/roster-canonical.js'],
  // S6 持ち越し課題の解消（2026-07-29）: vendor の chat-game-DO.js は import されないため
  // 台帳に無く、手コピーで静かに古びる状態だった。COPY 台帳に載せて drift を機械検出する。
  ['vendor/workers/game_workers/chat-game-DO.js', 'workers/game_workers/chat-game-DO.js'],
  ['vendor/workers/auth_workers/lib/cors.js', 'workers/auth_workers/lib/cors.js'],
  ['vendor/src/utils/protocol.js', 'src/utils/protocol.js'],
  ['vendor/src/utils/ecies.js', 'src/utils/ecies.js'],
  ['vendor/src/utils/evidence-trim-policy.js', 'src/utils/evidence-trim-policy.js'],
  ['vendor/src/utils/walletTools.js', 'src/utils/walletTools.js'],
  ['vendor/src/utils/p2pKeys.js', 'src/utils/p2pKeys.js'],
  ['vendor/src/utils/relay.js', 'src/utils/relay.js'],
  ['vendor/src/utils/priorityEvidence.js', 'src/utils/priorityEvidence.js'],
  ['vendor/src/utils/receipt-warnings.js', 'src/utils/receipt-warnings.js'],
  ['vendor/src/utils/chainClock.js', 'src/utils/chainClock.js'],
  ['vendor/src/utils/clientClock.js', 'src/utils/clientClock.js'],
  ['vendor/src/utils/read-receipt-batching.js', 'src/utils/read-receipt-batching.js'],
  // S3FIX 便 SYNC3: 便 C2 の共有関数を公式正典へ移し、復元は COPY を読む。
  ['vendor/src/utils/read-receipt-pause.js', 'src/utils/read-receipt-pause.js'],
  ['vendor/src/utils/windowCompare.js', 'src/utils/windowCompare.js'],
  ['vendor/src/utils/chainAgreement.js', 'src/utils/chainAgreement.js'],
  // S3R5 便 PLAYERNO: 旧表示名衝突の写しを置き換え、確定名簿の番号の正典を COPY。
  ['vendor/src/utils/playerNumber.js', 'src/utils/playerNumber.js'],
  // S3R5 便 SELF: 復元が import する密告根拠の正典 COPY。
  ['vendor/src/utils/reportGround.js', 'src/utils/reportGround.js'],
  // S3R6 便 SUBMITVIEW・SUBMITVIEW2: 提出画面と復元の保証の区画の正典 COPY。
  ['vendor/src/utils/submissionGuarantee.js', 'src/utils/submissionGuarantee.js'],
  // S3R6 便 TRIMWARN: 切り詰めの確認の保証の比べを復元も共有する正典 COPY。
  ['vendor/src/utils/trimGuaranteeCheck.js', 'src/utils/trimGuaranteeCheck.js'],
];

// MIRROR 台帳: 正典行範囲（1-indexed 両端含む）の sha256（VENDOR_SYNC.md と一致させること）
// sha256 が null のものは「未実装（実装時に確定）」= 検査スキップ。
const MIRRORS = [
  {
    name: 'vendor/workers/game_workers/game-master-DO.js publishAutoRosterFile',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +120 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +53 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +25 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 16961, endLine: 16970,
    sha256: '9580ed4dc1c7754e1d6c202b63527160393bcf5c84e8c2fef8e6a447888e02cd',
    mirrorFile: 'vendor/workers/game_workers/game-master-DO.js',
    mirrorSignature: '  async publishAutoRosterFile(blockNum, players) {',
    mirrorClosing: '  }',
    mirrorSha256: '9580ed4dc1c7754e1d6c202b63527160393bcf5c84e8c2fef8e6a447888e02cd',
  },
  {
    name: 'src/recovery/bundle.js buildSubmissionBundle',
    declarationText: 'MIRROR: src/components/game/SubmissionPhase.js:742-1485（handleSubmit の本体）。',
    source: 'src/components/game/SubmissionPhase.js',
    // 🔴 2026-08-08: P-2026-0908（`planOnChainTrim` の impossible 時に溢れの原因 uid を
    //    表示する分岐）で、この範囲より前が **+12 行**。区間の中身は byte 一致のまま
    //    （sha256 据え置き・行番号だけ +12）。同じ行数（285行）の窓を全走査して特定した。
    // 🔴 2026-08-08: P-2026-0840（ラウンド19 判断不要-8・`observed.receipts` を
    //    `votes` / `reports` と同じ白名簿に揃える）で**中身が変わった**（+14 行）。
    //    ミラー（`src/recovery/bundle.js` の `kept.push`）にも同じ白名簿を入れたうえで
    //    範囲と sha を更新している。
    // 🔴 2026-08-08: P-2026-0843（判断③・提出物にも `applyChatCaps` を掛ける）で
    //    **中身が変わった**。ミラー（`src/recovery/bundle.js` の `cappedMessages`）にも
    //    同じ規則を入れたうえで範囲と sha を更新している。
    //    範囲の**始点を前へ伸ばした**: 上限適用（`cappedMessages`）と `chatHash` は
    //    handleSubmit の外（useMemo）にあるが、ミラーでは同じ関数の中にあり、
    //    「chatHash と submittedMessages が同一集合であること」が規則の芯なので
    //    両方を1つの窓に入れないと台帳が守る範囲から漏れる。
    // 🔴 2026-08-09: J-40（受領証明の重複排除を採点正典の `receiptCanonCmp` 順にし、
    //    枠取りに鮮度ゲート `isReceiptTimely` を足す）で**中身が変わった**（範囲内 +28 行）。
    //    さらに import が6行増えたので**範囲の始点も +6**（213→219 / 594→628）。
    //    ミラー（`src/recovery/bundle.js` の同名ブロック）にも同じ規則を入れたうえで
    //    範囲と sha を更新している。回帰テストは
    //    `workers/game_workers/script/test-calculator/receipt-displacement-test.mjs`。
    // 🔴 2026-08-09: J-40b（J-40 が**宣言窓 `inChatWindow` を取りこぼしていた**件）で
    //    **中身が変わった**。枠取りの述語を `protocol-v2.js` の `receiptCoverClaim` /
    //    `selectBundleReceipts` へ集約し、本体もミラーもそれを呼ぶだけにしたうえで、
    //    `chatWindow`（Evidence の宣言窓）を渡す引数を両方に足した。
    //    範囲の始点が +4 なのは `chainTimeline` プロパティのコメントが増えたため（219→223）。
    //    回帰テストは `receipt-displacement-test.mjs` §6〜§9 と
    //    `receipt-slot-predicate-parity-test.mjs`（採点側ソースから述語を機械抽出して突き合わせ）。
    // 🔴 2026-08-09: J-36 で**中身が変わった**。本体はサーバー申告 caps を捨てて
    //    `GUEST_PINNED_RULES` を直接使う。復元クライアントにはサーバー申告の入力経路がなく、
    //    利用者が明示した `chatCaps` を正規化する境界なので手書き側の引数形は据え置いた。
    //    関数境界を再確認し、範囲と sha を実内容から取り直した（旧 223-642）。
    // 2026-08-12: Round 21 F1 の有限構造化・自己receipt集約・compact codecを
    // 本体と復元側の両方へ反映。窓の終端も handleSubmit の依存配列まで伸ばし、
    // payload構築とWS送信を漏らさず固定する（旧終端634は途中で切れていた）。
    // 2026-08-14: R26-C7（describeTrimPlan への一本化）でこの範囲より前が -1 行。
    // 同じ466行窓の全走査で旧sha256の唯一一致（215-680）を確認した（中身は不変）。
    // 2026-08-17: request2 A-2 で entryDepositIds を外し、説明コメントも更新。
    // 復元側からも同じ引数を外して再レビューした。
    // 2026-08-17: request3 D-3 で自己 receipt 集約へ actionTypes を渡す1行を追加。
    // 復元側も同じ buildRealTargets の戻り値を渡すことを再レビューした。
    // 2026-08-20: request5 A-6 で buildRealTargets を cappedMessages に限定し、
    // 署名前に filterReceiptsToCarriedTargets を通す不変条件を本体・復元側へ反映した。
    // B-4 のオンチェーン警告文も同じ窓内に追加されたため、範囲の sha を更新した。
    // 2026-08-21: REQUEST8 D-1で、この範囲に混入していた別callback（Evidence救済）の
    // 末尾を除外し、提出上限の節からWS handleSubmitの依存配列までへ境界を張り直した。
    // 2026-08-22: Stage 3 Review 10 便Bで、到着順配管・reportTargetOf・A-3 observed照合を
    // 本体へ追加し、便Cで復元ミラーへ同じ規則を反映して再レビューした。
    // 2026-09-08 周15 T7: 範囲内の表示用 i18n defaultValue をカタログへ移し4行減。
    // 提出バンドル組立規則とミラー本体は不変と再レビューし、正典側 hash のみ更新。
    // 🔴 2026-09-10 周17: 周16 D-AUTH が本体へ identity/窓/wallet の番兵と所有 ref を挿入し、
    //   区間が 261-789 → 409-1000（+63行）へ動いた。統括が
    //   `git diff 123ef745 HEAD -- SubmissionPhase.js` の全追加行を読み、
    //   **提出バンドルの組立規則は1行も変わっていない**ことを確認した:
    //     ・追加はすべて assertSubmissionRunCurrent / assertSubmissionWalletCurrent /
    //       isGameIdentityCallbackCurrent / submitInFlightRef の所有検査
    //     ・唯一の書き換え `async (message) => canonicalizeSignature(...)` は
    //       アロー本体をブロックへ変えて番兵を挟んだだけで、署名の作り方は同一
    //   ⇒ ミラー本体は据え置き（chatgame-tools/test の bundle-unit /
    //      r14-resend-parity-unit / trim-policy-unit はいずれも rc=0）。正典側 hash と行だけ更新。
    // P2b-2a-2: 区切りの判定時刻と記憶を公式・復元の提出に渡し、T9 の注記を現行の上限関数へ揃えた。
    // S3R6 便 SUBMITVIEW・SUBMITVIEW2・SUBMITVIEW3・SV4: 切り出し、自己検証、控えの窓を差分で再レビュー。
    // C3B・TRIMWARN・TRIM2 の前方の行ずれは境界の同じ綴りで取り直した。
    // S3R8 便 R8-POSTSEND（00de73aca）: 窓の前に送信の直後の記録の配線が入り +15 行。窓の中身は byte 不変（同じ長さ738行の全走査で旧 sha256 617175bb… が 580-1317 に唯一一致・便の報告書と Astra の通す側の反証で確かめた）。
    // S3R8 第2波: 便 R8-SVA8（5586ea8be）で窓の前が +9 行、便 R8-MSGKEY（7ddb086dc）で窓の中の cappedMessages の memo が発言の鍵の getter（頁の寿命の使い回し・性能だけ）を使うようになった。鍵の値と提出の集合・並び・バイト列は不変（便の反証で起点と一致を確かめた）＝写し先の本体は据え置き、行と sha だけ取り直した。
    // 2026-11-19（ユーザーの指示・0ae797985 と反証 D-2）: 窓の前に state 2つ・準備中の印の try/finally・再提出の確認の文の
    // 差し替えが入り +11 行、窓の中の handleSubmit に prepareOnly（オンチェーンの準備では署名・保存だけで WS へ送らない・
    // isSubmitting を立てない）と送る直前の setServerSendTried(true) が入った（旧窓との diff は +6 行・1行の置き換えだけ）。
    // 束の組立とバイト列は不変で、写し先は送信も画面の state も写さない＝本体は不変。窓を 742-1485 と sha だけ取り直した。
    startLine: 742,
    endLine: 1485,
    // 2026-08-13: Round 25 C25-01/P25-01/V25-02 で production transport を
    // compact 1形式へ固定し、署名・暗号文・参照順の正準ゲートを再レビューした。
    // 2026-09-27 周33 便 S3C7（D-04 の後の文書の直し）: 正典（chatHash の useMemo の上の見出し）と
    // ミラー（bundle.js の chatHash の見出し）のコメント1行ずつを、規則版13 の chatHash の呼び名へ直しただけ。
    // コメントを除いた差分は両方とも空（TypeScript transpileModule の removeComments で比較）。hash だけ更新。
    // 2026-10-01 S3FIX 便 B1（e4b16e05）: handleSubmit の自己集約に確定した窓を渡す1行を正典と写し先の両方に足した（統括が同じ意味であることを確認）。窓の終わり 1029→1030・sha256 と写し先の本体の sha256 を更新。
    // S3R5 便 SELF（3ca690bc5）: 密告根拠の控えを読み、票と証明を正典と写し先で同じ規則で優先する。根拠なしでは元の束を保つ。
    // S3R5 便 LOCK（2b479a6af）: 組み直しが20未満の時だけ確定を検査する段を正典と写し先へ追加。確定が偽なら組み直しの束を保つ。
    // S3R5 便 DISP5（09b088876）: 窓の中は自己検証の失敗の文言（i18n の既定文）だけが変わった。写し先は文言を写さないので本体は不変。
    // RS-0: optional per-receipt memo changes no submitted bytes.
    // S3R6 便 SV5（d24034360）: 公開選択の印で publicWindowChosen を初期化する1行だけが窓内で変わった。束のバイト列には入らず写し先に相当はない。窓の前は SV5 の +8 行と SV6（e16b31382）の +10 行で動き、SV6 は窓内を変えていない（再レビュー）。
    sha256: '8d3bdc1d69f10f9548716084bf6262102d0b59182150c590081935e85ad8496b',
    mirrorFile: 'src/recovery/bundle.js',
    mirrorSignature: 'export async function buildSubmissionBundle({',
    mirrorSha256: '31e2bc39e85e82d5b40a4ae08557a0fe45ace5f605d2aad66ff6098fcea249e7',
  },
  {
    name: 'src/recovery/relay-verify.js verifyRelayInner',
    source: 'src/hooks/useGameWebSocket.js',
    // 🔴 2026-08-07: P-2026-0829（リレー内側の正準 timestamp 検査）で**中身が変わった**。
    //    ミラー（src/recovery/relay-verify.js）にも同じ検査を入れたうえで sha を更新している。
    //    範囲は `verifyRelayInner` 関数まるごとに張り直した（旧範囲は関数境界と無関係な窓だった）。
    // 🔴 2026-08-08: P-2026-0836（ラウンド19 判断不要-2・リレー内側の署名正準性 low-s）で
    //    **中身が変わった**。ミラー（`src/recovery/relay-verify.js`）にも同じ
    //    `isCanonicalSignature` を入れたうえで範囲と sha を更新している。
    // 🔴 2026-08-08: J-17（幽霊メッセージ）の受信ゲート追加で `useGameWebSocket.js` の
    //    冒頭に import が3行増えたため、**中身は1バイトも変わらないまま行番号だけ**が
    //    326-379 → 329-382 へずれた（sha256 は据え置き＝内容不変の証拠）。
    // 🔴 2026-08-09: J-40b / 沈静化窓のチェーン窓導出（`quiescenceUntil` を useMemo 化）などで
    //    この範囲より**前**が +84 行。区間の中身は byte 一致のまま（sha256 据え置き＝内容不変の証拠）。
    //    当時の関数境界で裏取り済み: 413 = `const verifyRelayInner = useCallback(async (type, inner) => {`、
    //    466 = 対応する `}, [blockNum, groupId]);`（J-36 前の位置）。
    // 🔴 2026-08-09: J-36 で receipt の msgRefs 上限がサーバー申告 ref からゲスト pin
    //    直参照へ変わり、**中身が変わった**。復元側はサーバー申告を受けず既定100／利用者明示値
    //    だけなので引数形を据え置いた。
    // 2026-08-13: Round 25 の正準署名ゲートを含む現在の関数境界 413-468 を再レビューした。
    // 2026-08-17: ライブ名簿 identity 保持を前段へ追加したため、さらに +26 行。
    // 内容は byte 不変。
    // 2026-08-21: REQUEST8 D-3の共有バッチ定数importで前方が差引 -1 行。
    // 56行窓の全走査で旧sha256の唯一一致（481-536）を確認した（中身は不変）。
    // 2026-08-22: 便Bの到着連番配管が前方へ入り +20 行。関数本体は byte 不変。
    // 2026-08-23: Round12 FIX_2 で action/receipt の未来+2分ゲートと
    // read receipt senderUid の文字列＋名簿検査を本体／復元ミラーへ追加して再レビュー。
    // 2026-09-06: 周14 T3 の検証済み／WS未検証名簿分離で、本体は source 付き
    // selectCurrentRoster を読む形へ変更。復元側の getMembers と同じ選択済み集合であることを再確認。
    // 2026-09-07: 周15 T2 の共有名簿selector抽出で前方が -6 行。60行窓のshaは不変。
    // 2026-09-09: 周16 D の接続owner/receipt queue修正がこの関数より前へ +8 行。
    // 2026-09-10 周17: 周16 D-AUTH の続きで更に前方が動き、統括が60行窓を全走査して
    //   旧sha256が **589-648 に唯一一致**することを確認した（関数本体は byte 不変）。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-27 周33 便 S3C11（D-12・R33-F-1-01）: 冒頭に close code の定数（3行）を足して前方 +3 行。
    //   同じ60行窓を全走査し、旧sha256の唯一一致（656-715）を確認（中身は不変）。
    // S3C15: sendkey/reshare を除去し、chat の署名検証を同じ関門へ追加。
    // T1m: 前方の既読期限管理が15行増えた。57行の旧hashは865-921で一意一致。
    // S3FIX 便 SYNC: 便 C の前方削除で 896-950 → 798-852。旧 sha256 の全走査で唯一一致し本体不変。
    // S3FIX 便 SYNC2: MD の前方追加で 798-852 → 821-875。旧 sha256 は同長全走査で唯一一致。
    // S3FIX 便 SYNC3: C2 の前方追加で 821-875 → 823-877。旧 sha256 の同長全走査で唯一一致。
    // S3FIX C3: connection observer gained four lines before this byte-identical window.
    // T6: RPC consent and bounded start-poll wait added lines before this byte-identical body.
    // S3R4 MATURE18: 成熟を60秒の固定の見回りにし、前方が -74 行。本体は byte 不変。
    // S3R5 段4: PHASE +20・STORE +5・SELF +19 の前方追加。旧 sha の55行全走査で唯一一致し本体不変。
    // S3R5 便 LOCK: 前方の import +1。旧55行 sha の同長全走査で 1059-1113 に唯一一致。
    // WR-E2E-S3-ROSTERNAME-FIX1: 前方の表示採用・init 保持のみ変更。55行 sha の唯一一致。
    startLine: 1111,
    endLine: 1165,
    sha256: 'f0a85e6c5ff2edf6c339ce7a5c5e5621dba27b42f8cd11526c195bcfc91736cf',
    mirrorFile: 'src/recovery/relay-verify.js',
    mirrorSignature: 'export function makeVerifyRelayInner(getMembers, blockNum, groupId, maxMessages = 100) {',
    mirrorSha256: 'b6a09ba571fd787d93fb271a2bc42f03d15d8bb2e796049175b0761e8ff2e1f9',
  },
  {
    name: 'src/recovery/app.js hasVisibleConfirmedVote',
    declarationText: 'MIRROR: 本体 `src/components/game/ChatPhase.js` の `hasVisibleConfirmedVote`。',
    source: 'src/components/game/ChatPhase.js',
    // 規則版数5の投票資格とラスト10分の門。復元側の wrapper・門・純粋 helper を連結する。
    // S3R6 便 C3B の import 1行で前方 +1。旧 sha256 の同長全走査で唯一一致。
    // 2026-11-20: 版 7（9804e7aa2）の画面の直しでこの範囲より前が +4 行。旧 sha256 の同長全走査で唯一一致（中身は byte 一致）。
    startLine: 267,
    endLine: 279,
    sha256: 'ee4215ec57745f108e5db9f6ff196ed74f70d9902312ad7e8a0a80041cef9a3e',
    mirrorFile: 'src/recovery/app.js',
    mirrorParts: [
      { signature: 'function hasVisibleConfirmedVote(targetUid, atMs) {' },
      { signature: 'function canReportTarget(targetUid, atMs) {' },
      { signature: 'export function hasTimestampVisibleConfirmedVote({' },
    ],
    mirrorSha256: '1bad2054d6a912050208b44e4125c2a46c4260dbe9bfb56dcd4a5973d1a9ae9f',
  },
  // 🔴 2026-08-09（ラウンド22 タスク2-a）: **未登録だった手写しミラーの登録その1。**
  //
  //   `src/recovery/app.js` は本体 `ChatPhase.js` の入口ゲートを手写ししているのに、
  //   MIRROR 台帳には `bundle.js` と `relay-verify.js` の2本しか載っていなかった。
  //   その結果、正典側にゲートが増えても `check-vendor-sync` が**鳴らない**。
  //   実際に送信側の4ゲートが1つも移植されておらず、1メッセージ上限（半角1,000字）超の
  //   貼り付けが警告ゼロで送信でき、画面 2,142字/20ターン ⇄ 採点 1,140字/**19ターン** で
  //   `min_messages` 失格（実測）という形で表に出た。
  {
    // 名前は VENDOR_SYNC.md の MIRROR 表の第1列と**完全一致**させること（突き合わせの識別キー）。
    // 2026-08-09: ここだけ ` (チャット送信ゲート)` が付いていて MD 側と食い違っていた
    // （新設の LEDGER(MIRROR) 検査が初回実行で検出）。説明は MD の第2列に置く。
    name: 'src/recovery/app.js chatSendBlockReason',
    declarationText: 'MIRROR: 本体 `src/components/game/ChatPhase.js` の `handleSend` の4ゲート。',
    source: 'src/components/game/ChatPhase.js',
    // `handleSend` まるごと（4ゲート＝可視内容 / 1メッセージ上限 / 発言数上限 / 総文字数上限）。
    // ミラー側は `chatSendBlockReason`（判定）＋ `sendChat` / `doSend`（適用）に分かれている。
    // request7 D-3 で props に scoringMessages が1行増えたため、内容不変で +1 行。
    // 2026-08-26: 便W8 が serverError prop を追加し、この範囲より**前**が +1 行。
    //   20行窓の全走査で旧sha256の唯一一致（243-262）を確認した（中身は byte 一致）。
    // S3R6 便 C3B の import 1行で前方 +1。旧 sha256 の同長全走査で唯一一致。
    // 2026-11-20: 版 7（9804e7aa2）の画面の直しでこの範囲より前が +4 行。旧 sha256 の同長全走査で唯一一致（中身は byte 一致）。
    startLine: 326,
    endLine: 345,
    sha256: 'bf087cc2fbcafbdba679cf35c2b8934ec1d6969c2ef1313751e934416011d592',
    mirrorFile: 'src/recovery/app.js',
    mirrorSignature: 'function chatSendBlockReason(text) {',
    mirrorSha256: 'b0efdf815247aeef164a6e976463c02a39e02b35b300c50dbfae9bffcb4f2b05',
  },
  // 🔴 2026-08-09（ラウンド22 タスク2-a）: **未登録だった手写しミラーの登録その2。**
  //
  //   `relay-client.js` の `_verifyChat` は自分で「MIRROR相当: useGameWebSocket.js
  //   verifyIncomingMessage の v2 経路」とコメントしているのに台帳に無かった。
  //   Round 25 で部分集合だった正準性検査（signature / uid / text / timestamp）も
  //   復元側へ移植し、P2P ingress の受理集合を正典と揃えた。
  {
    name: 'src/recovery/relay-client.js _verifyChat',
    source: 'src/hooks/useGameWebSocket.js',
    // 🔴 2026-08-09: 上の `verifyRelayInner` と同じ理由で、この範囲より前が +84 行。
    //    中身は byte 一致のまま（sha256 据え置き）。関数境界で裏取り済み:
    //    J-36 でこの範囲より前が -2 行になったが中身は byte 一致（sha256 据え置き）。
    // 2026-08-13: 現在の関数境界 471-508 を再レビュー。内容の sha256 は不変。
    // 2026-08-17: ライブ名簿 identity 保持を前段へ追加したため、さらに +26 行。
    // 内容は byte 不変。
    // 2026-08-21: 同じ前方差分により -1 行。38行窓の旧sha256唯一一致を確認。
    // 2026-08-22: 同じ前方差分 +20 行。38行窓の旧sha256唯一一致を確認。
    // 2026-08-23: Round12 FIX_2 の未来+2分クライアントゲートを復元ミラーにも追加。
    // 2026-09-06: 周14 T3 の名簿分離により、同じ選択済み名簿を
    // selectCurrentRoster から読む形へ変更して再レビュー。
    // 2026-09-07: 周15 T2 の共有名簿selector抽出で前方が -6 行。39行窓のshaは不変。
    // 2026-09-09: 周16 D の接続owner/receipt queue修正がこの関数より前へ +8 行。
    // 2026-09-10 周17: 統括が39行窓を全走査し、旧sha256が **651-689 に唯一一致**することを
    //   確認した（関数本体は byte 不変）。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-27 周33 便 S3C11（D-12・R33-F-1-01）: 冒頭に close code の定数（3行）を足して前方 +3 行。
    //   同じ39行窓を全走査し、旧sha256の唯一一致（718-756）を確認（中身は不変）。
    // S3C15: 前方の内側署名検証が3行減。関数本体は不変。
    // S3R2-U-14: 正典と復元の両方で1件上限を署名検証より前に適用する。
    // T1m: 同じ前方差分。40行の旧hashは924-963で一意一致。
    // S3FIX 便 SYNC: 便 C の前方削除で 953-992 → 855-894。旧 sha256 の全走査で唯一一致し本体不変。
    // S3FIX 便 SYNC2: MD の前方追加で 855-894 → 878-917。旧 sha256 は同長全走査で唯一一致。
    // S3FIX 便 SYNC3: C2 の前方追加で 878-917 → 880-919。旧 sha256 の同長全走査で唯一一致。
    // S3FIX C3: same four-line shift; body hash remains unchanged.
    // T6: the same preceding shift; body bytes and hash are unchanged.
    // S3R4 MATURE18: 成熟を60秒の固定の見回りにし、前方が -74 行。本体は byte 不変。
    // S3R5 段4: 同じ前方追加 +44。旧 sha の44行全走査で唯一一致し本体不変。
    // S3R5 便 LOCK: 前方の import +1。旧44行 sha の同長全走査で 1116-1159 に唯一一致。
    // WR-E2E-S3-ROSTERNAME-FIX1: 前方の表示採用・init 保持のみ変更。44行 sha の唯一一致。
    startLine: 1168,
    endLine: 1211,
    sha256: 'd09af814385d5ddb7d8e2cdb580dc1e7f42b16d18edcbc8faee5048597cb76ad',
    mirrorFile: 'src/recovery/relay-client.js',
    mirrorSignature: '  async _verifyChat(msg) {',
    mirrorClosing: '  }',
    mirrorSha256: '7768aa31554cc580fa9dfe5317163bdb4573c63f6122a1c214a4de140b7928f2',
  },
  {
    name: 'src/recovery/discovery.js verifyLiveRosterAnchor',
    source: 'src/utils/roster-verification.js',
    // 2026-09-24 M10b: 双方の selector を同一固定ブロックの履歴・grace・timestamp へ揃え、
    // 開始前を provisional に保つ。公開JSONの raw hash/group sha 照合も人手で再レビュー。
    startLine: 204,
    endLine: 423,
    sha256: '3e6c955b73d1db93ffb84567f6ed27062536c8cba815a5a66758cd144e0b01e0',
    mirrorFile: 'src/recovery/discovery.js',
    mirrorSignature: 'export async function verifyLiveRosterAnchor({',
    mirrorSha256: 'd3dbe0069e0d39f710867813434474dbd2a6d3378a629745e215408f954a6f1c',
  },
  {
    name: 'src/recovery/app.js isTimestampVisible',
    source: 'src/components/game/ChatPhase.js',
    // 2026-08-24: 便A-2。A-1で本体に追加された未来時刻の表示述語を復元側へ追加。
    // 2026-08-26: 便W8 の serverError 表示ブロックでこの範囲より**前**が +9 行。
    //   4行窓の全走査で旧sha256の唯一一致（678-681）を確認した（中身は byte 一致）。
    // S3R6 便 C3B の import 1行で前方 +1。旧 sha256 の同長全走査で唯一一致。
    // 2026-11-20: 版 7（9804e7aa2）の画面の直しでこの範囲より前が +7 行。旧 sha256 の同長全走査で唯一一致（中身は byte 一致）。
    startLine: 945,
    endLine: 948,
    sha256: 'd094f4d3dc282229ddf76e8c5066c511304d97544e83cad26ec2bff7afb16473',
    mirrorFile: 'src/recovery/app.js',
    mirrorSignature: 'export function isTimestampVisible(timestamp, nowMs) {',
    mirrorSha256: '6a1ccbdc7629c20aa8d70feeefe4c6adaf8ecb64bc020559c0ef2efdd0b72310',
  },
];

// config.js の数値をここへ写さず、正典ソースから毎回抽出して比較する。
// path は DEFAULTS.pins の数値 leaf と完全一致しなければならない（追加 pin の黙殺を禁止）。
const PIN_BINDINGS = [
  {
    path: 'gameMaxPlayers',
    sources: [
      { file: 'workers/game_workers/game-master-DO.js', kind: 'const', name: 'GAME_MAX_PLAYERS' },
      { file: 'workers/lottery_workers/lottery-DO.js', kind: 'const', name: 'GAME_MAX_PLAYERS' },
    ],
    consumer: { file: 'src/recovery/app.js', pattern: /state\.cfg\.pins\.gameMaxPlayers/ },
  },
  {
    path: 'minChars',
    sources: [{ file: 'workers/game_workers/lib/char-counter.js', kind: 'guest-rule', name: 'minChars' }],
    consumer: { file: 'src/recovery/app.js', pattern: /const \{ minChars, minMessages[^}]*\} = state\.cfg\.pins/ },
  },
  {
    path: 'minMessages',
    sources: [{ file: 'workers/game_workers/lib/char-counter.js', kind: 'guest-rule', name: 'minMessages' }],
    consumer: { file: 'src/recovery/app.js', pattern: /const \{ minChars, minMessages[^}]*\} = state\.cfg\.pins/ },
  },
  ...['maxChars', 'maxMessages', 'maxMsgChars'].map((name) => ({
    path: `chatCaps.${name}`,
    sources: [{ file: 'workers/game_workers/lib/char-counter.js', kind: 'guest-rule', name }],
    consumer: { file: 'src/recovery/app.js', pattern: new RegExp(`\\bcaps\\.${name}\\b|\\bchatCaps\\.${name}\\b`) },
  })),
  {
    path: 'maxReports',
    sources: [{ file: 'workers/game_workers/lib/submission-limits.js', kind: 'const', name: 'MAX_ACCEPTED_REPORTS_PER_PLAYER' }],
    consumer: { file: 'src/recovery/app.js', pattern: /state\.cfg\.pins\.maxReports/ },
  },
  {
    path: 'confirmationBlocks',
    sources: [{ file: 'workers/lottery_workers/lottery-DO.js', kind: 'const', name: 'CONFIRMATION_BLOCKS_DEFAULT' }],
    consumer: { file: 'src/recovery/app.js', pattern: /state\.cfg\.pins\.confirmationBlocks/ },
  },
];

const sha256 = (bufOrStr) => createHash('sha256').update(bufOrStr).digest('hex');

function numericLeaves(value, prefix = '') {
  const out = [];
  for (const [key, child] of Object.entries(value || {})) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof child === 'number') out.push(path);
    else if (child && typeof child === 'object' && !Array.isArray(child)) out.push(...numericLeaves(child, path));
    else throw new Error(`pin ${path} は数値または数値だけの object でなければなりません`);
  }
  return out.sort();
}

function valueAtPath(value, dotted) {
  return dotted.split('.').reduce((current, key) => current?.[key], value);
}

function canonicalPinValue(source) {
  const text = readFileSync(resolve(repoRoot, source.file), 'utf8');
  let pattern;
  if (source.kind === 'const') {
    pattern = new RegExp(`(?:export\\s+)?const\\s+${source.name}\\s*=\\s*(\\d+)\\s*;`, 'g');
  } else if (source.kind === 'guest-rule') {
    const body = text.match(/export const GUEST_PINNED_RULES\s*=\s*Object\.freeze\(\{([\s\S]*?)\}\);/)?.[1];
    if (body == null) throw new Error(`${source.file} の GUEST_PINNED_RULES を抽出できません`);
    pattern = new RegExp(`\\b${source.name}\\s*:\\s*(\\d+)\\s*,?`, 'g');
    const hits = [...body.matchAll(pattern)];
    if (hits.length !== 1) throw new Error(`${source.file} の GUEST_PINNED_RULES.${source.name} は ${hits.length} 件です`);
    return Number(hits[0][1]);
  } else {
    throw new Error(`未知の pin source kind: ${source.kind}`);
  }
  const hits = [...text.matchAll(pattern)];
  if (hits.length !== 1) throw new Error(`${source.file} の ${source.name} は ${hits.length} 件です`);
  return Number(hits[0][1]);
}

function mirrorDeclarationKey(file, text) {
  return `${file}\u0000${text.replace(/^\/\/\s*/, '').trim()}`;
}

function mirrorDeclarationRange(text) {
  const match = text.replace(/^\/\/\s*/, '').trim()
    .match(/^MIRROR:\s+([^:]+):(\d+)-(\d+)(?:\s|（|。|$)/);
  if (!match) return null;
  return { source: match[1], startLine: Number(match[2]), endLine: Number(match[3]) };
}

function collectMirrorDeclarations(dir, prefix = 'src') {
  const found = [];
  const walk = (current, rel) => {
    for (const name of readdirSync(current).sort()) {
      const absolute = join(current, name);
      const childRel = `${rel}/${name}`;
      if (statSync(absolute).isDirectory()) {
        walk(absolute, childRel);
        continue;
      }
      if (!/\.m?js$/.test(name)) continue;
      readFileSync(absolute, 'utf8').split('\n').forEach((line, index) => {
        if (/^\/\/\s*MIRROR:/.test(line.trim())) {
          found.push({ file: childRel, line: index + 1, text: line.trim() });
        }
      });
    }
  };
  walk(dir, prefix);
  return found;
}

function readJavaScriptTree(dir) {
  let text = '';
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const absolute = join(current, name);
      if (statSync(absolute).isDirectory()) walk(absolute);
      else if (/\.m?js$/.test(name)) text += `\n${readFileSync(absolute, 'utf8')}`;
    }
  };
  walk(dir);
  return text;
}

function mirrorBodyPart(lines, file, name, part) {
  const hits = [];
  lines.forEach((line, index) => { if (line === part.signature) hits.push(index); });
  if (hits.length !== 1) {
    throw new Error(`${name} — mirror signature found ${hits.length} time(s) in ${file}: ${part.signature}`);
  }
  const start = hits[0];
  const closing = part.closing || '}';
  const end = lines.findIndex((line, index) => index > start && line === closing);
  if (end === -1) throw new Error(`${name} — mirror function body is not closed in ${file}`);
  return { start: start + 1, end: end + 1, text: lines.slice(start, end + 1).join('\n') };
}

let failed = 0;
const ok = (msg) => console.log(`  OK   ${msg}`);
const ng = (msg) => { failed++; console.error(`  FAIL ${msg}`); };

{
  const keys = COPIES.map(([vendor, source]) => `${vendor}\u0000${source}`);
  if (new Set(keys).size !== keys.length) {
    ng(`COPY-LEDGER COPIES に重複行がある (rows=${keys.length} unique=${new Set(keys).size})`);
  } else {
    ok(`COPY-LEDGER COPIES ${keys.length}行はすべて一意`);
  }
}

// 🔴 F-7(b)（2026-08-08・ラウンド20 判断不要-7）: **fail-open（exit 0）をやめる。**
//
//   旧実装は正典が読めなければ「skip」として **exit 0** で終わっていた。
//   実測: standalone コピーで `MAX_DEPOSIT_WEI` を 10 ETH → 1000 ETH に改変しても
//   `monorepo sources not found — skipping` と出て **exit 0**（1バイトも照合していない）。
//   しかもメッセージは「In standalone mode, VENDOR_SYNC.md sha256 values are the source of truth」
//   と書いているのに、**その実装が存在しない**。
//
//   ⚠️ **これは第三者検証の保証ではない**（台帳照合を実装しても対運営の保証は増えない＝自己参照ガード。
//     実測: 台帳照合を足しても `VENDOR_SYNC.md` の64桁を1行書き換えるだけで exit 0 に戻る）。
//     ここで直すのは**運用衛生**＝「照合できていないのに緑を出す」ことをやめる、それだけ。
//     コピーの真正性が要るなら `HashStorage.buildHashes` への登録（別項目）が必要。
if (!existsSync(resolve(repoRoot, 'workers/game_workers/game-master-DO.js'))) {
  console.error('check-vendor-sync: monorepo sources not found — CANNOT VERIFY here (standalone checkout).');
  console.error('  This script compares vendor/ against the canonical sources in the monorepo.');
  console.error('  Outside the monorepo there is nothing to compare against, so it exits 1 instead of');
  console.error('  reporting a green it did not earn. Run it from a monorepo checkout.');
  console.error('  NOTE: VENDOR_SYNC.md is a drift ledger, not a proof of authenticity — anyone who can');
  console.error('        edit vendor/ can edit the ledger in the same commit.');
  process.exit(1);
}

console.log('check-vendor-sync: comparing chatgame-tools/vendor against monorepo canon');

// --- COPY: バイト一致 ---
for (const [v, s] of COPIES) {
  const vp = resolve(toolRoot, v);
  const sp = resolve(repoRoot, s);
  if (!existsSync(vp)) { ng(`${v} — vendor file missing`); continue; }
  if (!existsSync(sp)) { ng(`${v} — canonical source ${s} missing`); continue; }
  const vb = readFileSync(vp);
  const sb = readFileSync(sp);
  if (vb.equals(sb)) ok(`COPY    ${v}`);
  else ng(`COPY    ${v} — bytes differ from ${s} (vendor sha256=${sha256(vb)}, source sha256=${sha256(sb)})`);
}

// --- PIN: 復元クライアント設定 ⇔ 正典値。未使用 pin と無言の除外も失敗にする ---
{
  let pinBad = 0;
  let configuredPaths;
  try {
    configuredPaths = numericLeaves(DEFAULTS.pins);
  } catch (error) {
    ng(`PIN      ${error.message}`);
    pinBad++;
    configuredPaths = [];
  }
  const bindingPaths = PIN_BINDINGS.map(({ path }) => path).sort();
  if (new Set(bindingPaths).size !== bindingPaths.length) {
    ng('PIN      PIN_BINDINGS に重複 path がある');
    pinBad++;
  }
  if (JSON.stringify(configuredPaths) !== JSON.stringify(bindingPaths)) {
    ng(`PIN      DEFAULTS.pins の leaf と PIN_BINDINGS が不一致 (config=${configuredPaths.join(', ')} bindings=${bindingPaths.join(', ')})`);
    pinBad++;
  }

  for (const binding of PIN_BINDINGS) {
    const configured = valueAtPath(DEFAULTS.pins, binding.path);
    const labels = [];
    let allCanonicalValuesMatch = true;
    try {
      for (const source of binding.sources) {
        const canonical = canonicalPinValue(source);
        const label = `${source.file}#${source.name}`;
        labels.push(label);
        if (configured !== canonical) {
          ng(`PIN      ${binding.path}=${configured} != ${label}=${canonical}`);
          pinBad++;
          allCanonicalValuesMatch = false;
        }
      }
    } catch (error) {
      ng(`PIN      ${binding.path} — ${error.message}`);
      pinBad++;
      allCanonicalValuesMatch = false;
    }
    const consumerText = readFileSync(resolve(toolRoot, binding.consumer.file), 'utf8');
    if (!binding.consumer.pattern.test(consumerText)) {
      ng(`PIN      ${binding.path} — runtime consumer が見つからない (${binding.consumer.file})`);
      pinBad++;
    } else if (labels.length && allCanonicalValuesMatch) {
      ok(`PIN      ${binding.path}=${configured} ⇔ ${labels.join(' + ')}`);
    }
  }

  const runtimeSource = readJavaScriptTree(resolve(toolRoot, 'src'));
  for (const [path, omission] of Object.entries(PIN_OMISSIONS)) {
    if (valueAtPath(DEFAULTS.pins, path) !== undefined) {
      ng(`PIN      omission ${path} が DEFAULTS.pins にも存在する`);
      pinBad++;
    }
    if (!['canonical-direct', 'no-canonical-counterpart'].includes(omission?.status)
        || typeof omission?.reason !== 'string' || omission.reason.trim() === '') {
      ng(`PIN      omission ${path} に status / reason が無い`);
      pinBad++;
    } else if (new RegExp(`\\b${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(runtimeSource)) {
      ng(`PIN      omission ${path} が chatgame-tools/src から参照されている（pin へ戻して正典と結ぶこと）`);
      pinBad++;
    } else {
      ok(`PIN      omission ${path} = ${omission.status} (${omission.reason})`);
    }
  }
  if (pinBad === 0) ok(`PIN      config ⇔ canon (${PIN_BINDINGS.length}/${configuredPaths.length} numeric leaves) 一致`);
}

// --- MIRROR: 正典行範囲の sha256 が台帳値のまま ---
{
  const declared = collectMirrorDeclarations(resolve(toolRoot, 'src'));
  const registered = MIRRORS.filter(({ declarationText }) => declarationText)
    .map(({ mirrorFile, declarationText, source, startLine, endLine }) => ({
      file: mirrorFile,
      text: declarationText,
      key: mirrorDeclarationKey(mirrorFile, declarationText),
      source,
      startLine,
      endLine,
    }));
  const declaredKeys = new Set(declared.map(({ file, text }) => mirrorDeclarationKey(file, text)));
  const registeredKeys = new Set(registered.map(({ key }) => key));
  let declarationBad = 0;
  if (declared.length !== declaredKeys.size) {
    ng(`MIRROR-DECL 同じ宣言が重複している (宣言=${declared.length} unique=${declaredKeys.size})`);
    declarationBad++;
  }
  if (registered.length !== registeredKeys.size) {
    ng(`MIRROR-DECL 同じ登録が重複している (登録=${registered.length} unique=${registeredKeys.size})`);
    declarationBad++;
  }
  for (const declaration of declared) {
    const key = mirrorDeclarationKey(declaration.file, declaration.text);
    if (!registeredKeys.has(key)) {
      ng(`MIRROR-DECL ${declaration.file}:${declaration.line} が MIRRORS 台帳に未登録: ${declaration.text}`);
      declarationBad++;
    }
  }
  for (const registration of registered) {
    if (!declaredKeys.has(registration.key)) {
      ng(`MIRROR-DECL 台帳にだけ存在: ${registration.file} ${registration.text}`);
      declarationBad++;
    }
    const declaredRange = mirrorDeclarationRange(registration.text);
    if (declaredRange) {
      const declaredValue = `${declaredRange.source}:${declaredRange.startLine}-${declaredRange.endLine}`;
      const registeredValue = `${registration.source}:${registration.startLine}-${registration.endLine}`;
      if (declaredValue !== registeredValue) {
        ng(`MIRROR-DECL ${registration.file} の宣言範囲が登録値と不一致 `
          + `(declaration=${declaredValue} registration=${registeredValue})`);
        declarationBad++;
      }
    }
  }
  if (declarationBad === 0 && declared.length === registered.length && declaredKeys.size === registeredKeys.size
      && declared.every(({ file, text }) => registeredKeys.has(mirrorDeclarationKey(file, text)))) {
    ok(`MIRROR-DECL 宣言 ${declared.length}件 / 登録 ${registered.length}件`);
  }
}

for (const m of MIRRORS) {
  if (m.sha256 == null) { console.log(`  SKIP MIRROR  ${m.name} (not implemented yet)`); continue; }
  const sp = resolve(repoRoot, m.source);
  if (!existsSync(sp)) { ng(`MIRROR  ${m.name} — canonical source ${m.source} missing`); continue; }
  const lines = readFileSync(sp, 'utf8').split('\n');
  const seg = lines.slice(m.startLine - 1, m.endLine).join('\n');
  const h = sha256(seg);
  if (h === m.sha256) {
    ok(`MIRROR  ${m.name} (source ${m.source}:${m.startLine}-${m.endLine} unchanged)`);
  } else {
    ng(`MIRROR  ${m.name} — ${m.source}:${m.startLine}-${m.endLine} changed (sha256=${h}); re-review the mirror and update VENDOR_SYNC.md + this script`);
  }

  // block-verifier と同じく、正典側だけでなく手書きミラー側の関数本体も固定する。
  if (m.mirrorFile && m.mirrorSha256) {
    const mp = resolve(toolRoot, m.mirrorFile);
    if (!existsSync(mp)) { ng(`MIRROR  ${m.name} — mirror file ${m.mirrorFile} missing`); continue; }
    const mlines = readFileSync(mp, 'utf8').split('\n');
    let parts;
    try {
      const specs = m.mirrorParts || [{ signature: m.mirrorSignature, closing: m.mirrorClosing }];
      parts = specs.map((part) => mirrorBodyPart(mlines, m.mirrorFile, m.name, part));
    } catch (error) {
      ng(`MIRROR  ${error.message}`);
      continue;
    }
    const mh = sha256(parts.map((part) => part.text).join('\n'));
    const ranges = parts.map((part) => `${part.start}-${part.end}`).join('+');
    if (mh === m.mirrorSha256) {
      ok(`MIRROR  ${m.name} (mirror body ${m.mirrorFile}:${ranges} unchanged)`);
    } else {
      ng(`MIRROR  ${m.name} — mirror body in ${m.mirrorFile}:${ranges} changed (sha256=${mh}); `
        + 're-review it against the canon and update VENDOR_SYNC.md + this script');
    }
  }
}

// --- LEDGER: VENDOR_SYNC.md に書いてある sha256 が正典と一致しているか ---
//
// 2026-07-31 追加。**これが無かったせいで台帳が静かに古びていた**（発見時 9/15 行がズレ）。
// COPY 検査は vendor と正典を直接比べるだけなので、両方を更新すれば通ってしまい、
// VENDOR_SYNC.md に書いた sha256 が古いままでも誰も気づかない。
//
// ところがこのツールを**モノレポ外へ配って単体で使う**とき（＝第三者検証という本来の用途）、
// 正典が手元に無いので照合の基準は **VENDOR_SYNC.md の sha256 だけ**になる（上の skip メッセージ参照）。
// つまり古い台帳は「第三者が正しいコピーを不正と判定する／古いコピーを正しいと判定する」に直結する。
// 台帳は飾りではなく検証の土台なので、機械で固定する。
{
  const mdPath = resolve(toolRoot, 'VENDOR_SYNC.md');
  if (!existsSync(mdPath)) {
    ng('LEDGER  VENDOR_SYNC.md not found');
  } else {
    const md = readFileSync(mdPath, 'utf8');
    const rowRe = /^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{64})`\s*\|\s*(COPY|MIRROR|EXTRACT)\s*\|/gm;
    const recorded = new Map();
    let m;
    while ((m = rowRe.exec(md)) !== null) {
      const [, , srcRel, sha, kind] = m;
      if (kind === 'COPY') recorded.set(srcRel, sha);
    }
    let ledgerBad = 0;
    for (const [, s] of COPIES) {
      const rec = recorded.get(s);
      if (!rec) { ng(`LEDGER  ${s} — VENDOR_SYNC.md に COPY 行が無い（台帳に追加すること）`); ledgerBad++; continue; }
      const sp = resolve(repoRoot, s);
      if (!existsSync(sp)) continue; // COPY 検査側で既に報告済み
      const actual = sha256(readFileSync(sp));
      if (actual !== rec) {
        ng(`LEDGER  ${s} — VENDOR_SYNC.md の sha256 が古い（recorded=${rec} actual=${actual}）`);
        ledgerBad++;
      }
    }
    if (ledgerBad === 0) ok(`LEDGER  VENDOR_SYNC.md sha256 (${COPIES.length} COPY rows) up to date`);

    // --- LEDGER(MIRROR): このスクリプトの MIRRORS と VENDOR_SYNC.md の MIRROR 表を突き合わせる ---
    //
    // 🔴 2026-08-09（ラウンド23）追加。**この検査が無かったせいで両者が静かに食い違っていた。**
    //   実測: `relay-verify.js verifyRelayInner` がスクリプト 329-382 / MD 326-379、
    //   `relay-client.js _verifyChat` がスクリプト 385-422 / MD 385-422 と、
    //   **同じ台帳を名乗る2つの記録が別々の行範囲を指していた**。
    //   MIRROR の判定は「行範囲を切って sha256」なので、行範囲は sha256 と同格の台帳データ。
    //   ところが上の COPY 照合は `kind === 'COPY'` の行しか見ておらず、
    //   MIRROR 行は sha256 すら誰とも突き合わされていなかった（＝MD 側は書き放題）。
    //
    //   ⚠️ これは「孤立した不変量」パターンそのもの: ミラーの台帳が2箇所に在るのに、
    //     それを突き合わせる者がいない。COPY 側と違い MIRROR は正典との照合が
    //     スクリプト側の数値だけで完結してしまうため、MD が古びても誰も気づけない。
    //
    //   なお本検査が守るのは**2つの記録の一致**であって真正性ではない（冒頭の警告と同じ）。
    //   両方を同じコミットで書き換えれば通る。狙いは「片方だけ直して満足する」事故の遮断。
    const mirrorRowRe =
      /^\|\s*`([^`]+)`\s*\|\s*`([^`:]+):(\d+)-(\d+)`[^|]*\|\s*`([0-9a-f]{64})`\s*\|\s*MIRROR\s*\|/gm;
    const bodyRowRe =
      /^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`[^|]*\|\s*`([0-9a-f]{64})`\s*\|\s*MIRROR-BODY\s*\|/gm;
    const mdMirrors = new Map();
    const mdBodies = new Map();
    let mm;
    while ((mm = mirrorRowRe.exec(md)) !== null) {
      const [, name, src, s0, s1, sha] = mm;
      mdMirrors.set(name, { source: src, startLine: Number(s0), endLine: Number(s1), sha256: sha });
    }
    while ((mm = bodyRowRe.exec(md)) !== null) {
      const [, name, file, sha] = mm;
      mdBodies.set(name, { mirrorFile: file, sha256: sha });
    }
    // 空振り防止: MD の MIRROR 行の総数と、パースできた件数が一致すること。
    // （説明文に `|` が入る等で行がパースから漏れると、突き合わせが黙って素通りする）
    const mdMirrorRowCount = (md.match(/^\|.*\|\s*MIRROR\s*\|\s*$/gm) || []).length;
    const mdBodyRowCount = (md.match(/^\|.*\|\s*MIRROR-BODY\s*\|\s*$/gm) || []).length;
    let mirrorLedgerBad = 0;
    if (mdMirrorRowCount !== mdMirrors.size) {
      ng(`LEDGER  VENDOR_SYNC.md の MIRROR 行 ${mdMirrorRowCount} 本のうち ${mdMirrors.size} 本しかパースできない` +
         `（"source:開始-終了" の形になっていない行がある＝突き合わせが素通りする）`);
      mirrorLedgerBad++;
    }
    if (mdBodyRowCount !== mdBodies.size) {
      ng(`LEDGER  VENDOR_SYNC.md の MIRROR-BODY 行 ${mdBodyRowCount} 本のうち ${mdBodies.size} 本しかパースできない`);
      mirrorLedgerBad++;
    }
    const expectedBodies = new Set();
    for (const s of MIRRORS) {
      const rec = mdMirrors.get(s.name);
      if (!rec) {
        ng(`LEDGER  MIRROR ${s.name} — VENDOR_SYNC.md に MIRROR 行が無い（台帳に追加すること）`);
        mirrorLedgerBad++;
      } else {
        const want = `${s.source}:${s.startLine}-${s.endLine}`;
        const got = `${rec.source}:${rec.startLine}-${rec.endLine}`;
        if (want !== got) {
          ng(`LEDGER  MIRROR ${s.name} — 行範囲がスクリプトと VENDOR_SYNC.md で食い違う（script=${want} md=${got}）`);
          mirrorLedgerBad++;
        }
        if (s.sha256 != null && s.sha256 !== rec.sha256) {
          ng(`LEDGER  MIRROR ${s.name} — sha256 がスクリプトと VENDOR_SYNC.md で食い違う（script=${s.sha256} md=${rec.sha256}）`);
          mirrorLedgerBad++;
        }
      }
      if (s.mirrorSha256 != null) {
        expectedBodies.add(s.name);
        const brec = mdBodies.get(s.name);
        if (!brec) {
          ng(`LEDGER  MIRROR-BODY ${s.name} — VENDOR_SYNC.md に MIRROR-BODY 行が無い（ミラー本体の pin が台帳に無い）`);
          mirrorLedgerBad++;
        } else {
          if (brec.mirrorFile !== s.mirrorFile) {
            ng(`LEDGER  MIRROR-BODY ${s.name} — ミラーファイルが食い違う（script=${s.mirrorFile} md=${brec.mirrorFile}）`);
            mirrorLedgerBad++;
          }
          if (brec.sha256 !== s.mirrorSha256) {
            ng(`LEDGER  MIRROR-BODY ${s.name} — sha256 が食い違う（script=${s.mirrorSha256} md=${brec.sha256}）`);
            mirrorLedgerBad++;
          }
        }
      }
    }
    // 逆方向: MD にだけ在る幽霊行（スクリプトから消したのに台帳に残っている）も赤にする。
    const scriptNames = new Set(MIRRORS.map((s) => s.name));
    for (const name of mdMirrors.keys()) {
      if (!scriptNames.has(name)) {
        ng(`LEDGER  MIRROR ${name} — VENDOR_SYNC.md にだけ在る（このスクリプトの MIRRORS に無い＝検査されていない）`);
        mirrorLedgerBad++;
      }
    }
    for (const name of mdBodies.keys()) {
      if (!expectedBodies.has(name)) {
        ng(`LEDGER  MIRROR-BODY ${name} — VENDOR_SYNC.md にだけ在る（対応する mirrorSha256 がスクリプトに無い）`);
        mirrorLedgerBad++;
      }
    }
    if (mirrorLedgerBad === 0) {
      ok(`LEDGER  VENDOR_SYNC.md ⇔ check-vendor-sync.mjs MIRROR 台帳 (${MIRRORS.length} rows + ${expectedBodies.size} body) 一致`);
    }
  }
}

// --- DIST: 配信物（dist/）が **現在の vendor/・src/・bundle依存** から作られているか ---
//
// 🔴 これが無かったせいで「ソースは新しいがビルドが古い」を誰も検知できなかった。
//    実例: P-2026-0842（投票・密告の平文を固定長パディング）で `vendor/src/utils/ecies.js` は
//    更新されたが `dist/recovery.bundle.js` は 2026-08-06 15:14 のまま＝パディング無しの
//    暗号文を作る。採点正典が長さ（450 hex）を強制した瞬間、そのクライアントで投票した人は
//    `no_vote` 相当で無言に落ち、その人に投票していた第三者も投票ボーナスを巻き添えで失う
//    （実測・3人組: user0001=0 / user0002=100 / user0003=200・合計 300／正常時 600）。
//    エラーも警告も出ない。
//
// ⚠️ `build-info.json` の `files` を dist 実体と突き合わせるだけでは**不足**。
//    ソースを更新してもビルドしなければ dist も build-info も動かないので、
//    「両方とも古いまま整合」になって素通りする。基準は必ず**現在の vendor/ と src/**。
//
// 直し方: `cd chatgame-tools && npm run bundle`（＋配信先の再ホスティング）。
// 契約バッチ再デプロイ手順（`docs/OPS_TASKS.md §5` → `setParam.js` の
// `rebuildRecoveryBundle()`）がこれを無条件で実行する。
{
  const distDir = resolve(toolRoot, 'dist');
  const infoPath = join(distDir, 'build-info.json');
  if (!existsSync(distDir) || !existsSync(infoPath)) {
    // dist を配らない使い方（モノレポ内の開発だけ）もあるので、無いこと自体は問わない。
    ok('DIST    dist/ が無い（配布物を作っていない）— 検査対象外');
  } else {
    const vendorRoot = resolve(toolRoot, 'vendor');
    const now = digestVendorTree(vendorRoot);
    const sourceNow = digestVendorTree(resolve(toolRoot, 'src'));
    // esbuild の metafile.inputs から同じ2エントリを write:false で解決する。
    // package.json の直接依存だけでなく、実際に inline される推移依存の実体が母集団になる。
    const bundleInputsNow = await collectBundleInputDigest();
    let info = null;
    try { info = JSON.parse(readFileSync(infoPath, 'utf8')); } catch { /* 下で NG */ }
    const rec = info && info.vendor;
    const sourceRec = info && info.source;
    const configRec = info && info.config && info.config['config.js'];
    const bundleInputsRec = info && info.bundleInputs;
    const recordedDistFiles = info && info.files;
    if (!recordedDistFiles || typeof recordedDistFiles !== 'object' || Array.isArray(recordedDistFiles)) {
      ng('DIST    dist/build-info.json に dist 実体の files 指紋が無い');
    } else {
      const actualNames = readdirSync(distDir)
        .filter((name) => name !== 'build-info.json' && statSync(join(distDir, name)).isFile())
        .sort();
      const recordedNames = Object.keys(recordedDistFiles).sort();
      const drift = [];
      for (const name of actualNames) {
        const actual = createHash('sha256').update(readFileSync(join(distDir, name))).digest('hex');
        if (recordedDistFiles[name] !== actual) {
          drift.push(recordedDistFiles[name] === undefined ? `+${name}` : `~${name}`);
        }
      }
      for (const name of recordedNames) if (!actualNames.includes(name)) drift.push(`-${name}`);
      if (drift.length) {
        ng(`DIST    dist/build-info.json の files と dist 実体が違う — ${drift.join(', ')}`);
      } else {
        ok(`DIST    dist 実体 ${actualNames.length} file(s) の sha256 が build-info.json と一致`);
      }
    }
    if (!rec || typeof rec.digest !== 'string') {
      ng('DIST    dist/build-info.json に vendor 指紋が無い＝この検査より前にビルドされた配布物。'
        + ` 現在の vendor/ は ${now.count} file(s) digest=${now.digest.slice(0, 12)}。`
        + ' `npm run bundle` で作り直すこと（古い配布物が現行の採点規則と食い違っていないことを'
        + '機械的に示せない）');
    } else if (rec.digest !== now.digest) {
      // どのファイルがズレたかまで出す（「何を直せばよいか」が分かる形で落とす）
      const drift = [];
      const recFiles = rec.files || {};
      for (const [k, h] of Object.entries(now.files)) {
        if (recFiles[k] !== h) drift.push(recFiles[k] === undefined ? `+${k}` : `~${k}`);
      }
      for (const k of Object.keys(recFiles)) if (now.files[k] === undefined) drift.push(`-${k}`);
      ng(`DIST    dist/ がビルドされた時点の vendor/ と現在の vendor/ が違う`
        + `（built=${rec.digest.slice(0, 12)} now=${now.digest.slice(0, 12)}）`
        + ` — 差分 ${drift.length} 件: ${drift.slice(0, 6).join(', ')}${drift.length > 6 ? ' …' : ''}`
        + '。`npm run bundle` で作り直すこと');
    } else {
      ok(`DIST    dist/ は現在の vendor/ から作られている（${now.count} file(s) digest=${now.digest.slice(0, 12)}）`);
    }
    if (!sourceRec || typeof sourceRec.digest !== 'string') {
      ng('DIST    dist/build-info.json に src 指紋が無い＝chatgame-tools/src を検査できない。'
        + ` 現在の src/ は ${sourceNow.count} file(s) digest=${sourceNow.digest.slice(0, 12)}。`
        + ' `npm run bundle` で作り直すこと');
    } else if (sourceRec.digest !== sourceNow.digest) {
      const drift = [];
      const recFiles = sourceRec.files || {};
      for (const [k, h] of Object.entries(sourceNow.files)) {
        if (recFiles[k] !== h) drift.push(recFiles[k] === undefined ? `+${k}` : `~${k}`);
      }
      for (const k of Object.keys(recFiles)) if (sourceNow.files[k] === undefined) drift.push(`-${k}`);
      ng(`DIST    dist/ がビルドされた時点の src/ と現在の src/ が違う`
        + `（built=${sourceRec.digest.slice(0, 12)} now=${sourceNow.digest.slice(0, 12)}）`
        + ` — 差分 ${drift.length} 件: ${drift.slice(0, 6).join(', ')}${drift.length > 6 ? ' …' : ''}`
        + '。`npm run bundle` で作り直すこと');
    } else {
      ok(`DIST    dist/ は現在の src/ から作られている（${sourceNow.count} file(s) digest=${sourceNow.digest.slice(0, 12)}）`);
    }
    const configNow = createHash('sha256').update(readFileSync(resolve(toolRoot, 'config.js'))).digest('hex');
    if (typeof configRec !== 'string') {
      ng('DIST    dist/build-info.json に config.js 指紋が無い。契約アドレスを含む設定を検査できない。'
        + ' `npm run bundle` で作り直すこと');
    } else if (configRec !== configNow) {
      ng(`DIST    dist/ がビルドされた時点の config.js と現在の config.js が違う`
        + `（built=${configRec.slice(0, 12)} now=${configNow.slice(0, 12)}）。`
        + '`npm run bundle` で作り直すこと');
    } else {
      ok('DIST    dist/ は現在の config.js から作られている');
    }
    if (!bundleInputsRec || typeof bundleInputsRec.digest !== 'string') {
      ng('DIST    dist/build-info.json に esbuild bundle 入力の指紋が無い。'
        + ` 現在の入力は ${bundleInputsNow.count} file(s) digest=${bundleInputsNow.digest.slice(0, 12)}。`
        + '推移依存を含む配信物の再現性を検査できないため `npm run bundle` で作り直すこと');
    } else if (bundleInputsRec.digest !== bundleInputsNow.digest) {
      const drift = [];
      const recFiles = bundleInputsRec.files || {};
      for (const [key, hash] of Object.entries(bundleInputsNow.files)) {
        if (recFiles[key] !== hash) drift.push(recFiles[key] === undefined ? `+${key}` : `~${key}`);
      }
      for (const key of Object.keys(recFiles)) {
        if (bundleInputsNow.files[key] === undefined) drift.push(`-${key}`);
      }
      ng(`DIST    dist/ がビルドされた時点の esbuild bundle 入力と現在の入力が違う`
        + `（built=${bundleInputsRec.digest.slice(0, 12)} now=${bundleInputsNow.digest.slice(0, 12)}）`
        + ` — 差分 ${drift.length} 件: ${drift.slice(0, 6).join(', ')}${drift.length > 6 ? ' …' : ''}`
        + '。`npm run bundle` で作り直すこと');
    } else {
      ok(`DIST    dist/ は現在の esbuild bundle 入力から作られている`
        + `（${bundleInputsNow.count} file(s) digest=${bundleInputsNow.digest.slice(0, 12)}）`);
    }
  }
}

if (failed > 0) {
  console.error(`check-vendor-sync: ${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('check-vendor-sync: all checks passed');
