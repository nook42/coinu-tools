// SOURCE: workers/lottery_workers/lottery-DO.js lines 2508-2595 (verbatim body)
// 抽出理由: lottery-DO.js はモジュールトップで ethers（GitHubフォーク）に依存するため丸ごとベンダー不可。
// selectWinners は this 非依存の純関数（決定的抽選）。本体は下記マーカー間に一切改変なしで転記されている。
// 同期検査: block-verifier/scripts/check-vendor-sync.mjs が正典の本体と行単位一致を検証する。
export async function selectWinners(seed, totalApplicants, winnerCount) {
// ===== BEGIN VERBATIM BODY (lottery-DO.js:2509-2594) =====
    console.log(`Selecting winners: totalApplicants=${totalApplicants}, winnerCount=${winnerCount}`);

    // 入力検証
    if (!Number.isSafeInteger(totalApplicants) || !Number.isSafeInteger(winnerCount)) {
      throw new Error('応募者数と当選者数は安全な整数である必要があります');
    }
    if (!seed || typeof seed !== 'string') {
      throw new Error('シードは文字列である必要があります');
    }

    // 応募者数または当選者数が0の場合は空配列を返す
    if (totalApplicants <= 0 || winnerCount <= 0) {
      console.log(`No selection needed: totalApplicants=${totalApplicants}, winnerCount=${winnerCount}`);
      return [];
    }

    if (winnerCount > totalApplicants) {
      throw new Error('当選者数は応募者数以下である必要があります');
    }

    // 全員当選の短絡: 抽選不要
    if (winnerCount >= totalApplicants) {
      console.log(`All applicants win (winnerCount ${winnerCount} >= totalApplicants ${totalApplicants}), skip drawing`);
      return Array.from({ length: totalApplicants }, (_, i) => i);
    }

    // シードから0xプレフィックスを除去
    const cleanSeed = seed.replace(/^0x/i, '');
    console.log(`Using selection seed: ${cleanSeed.substring(0, 16)}...`);

    // シードから乱数を生成する関数
    async function generateRandom(input) {
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = new Uint8Array(hashBuffer);

      // 8バイトをBigIntに変換
      let randomValue = 0n;
      for (let i = 0; i < 8; i++) {
        randomValue = randomValue * 256n + BigInt(hashArray[i]);
      }

      return randomValue;
    }

    // 小さい方を抽選する（当選者 or 落選者）
    const loserCount = totalApplicants - winnerCount;
    const drawLosers = loserCount < winnerCount;
    const drawCount = drawLosers ? loserCount : winnerCount;
    console.log(`Drawing ${drawCount} ${drawLosers ? 'losers' : 'winners'} out of ${totalApplicants}`);

    const drawn = new Set();
    let seedCounter = 0;
    const maxIterations = totalApplicants * 1000; // 極大上限（異常時は明示エラー）

    while (drawn.size < drawCount) {
      if (seedCounter > maxIterations) {
        // サイレントに人数を減らして続行することは絶対にしない
        throw new Error(`selectWinners exceeded max iterations (${maxIterations}): drawn=${drawn.size}/${drawCount}, N=${totalApplicants}`);
      }
      const randomValue = await generateRandom(cleanSeed + seedCounter);
      const candidate = Number(randomValue % BigInt(totalApplicants));
      drawn.add(candidate);
      seedCounter++;
    }

    let result;
    if (drawLosers) {
      // 落選者の補集合が当選者
      result = [];
      for (let i = 0; i < totalApplicants; i++) {
        if (!drawn.has(i)) result.push(i);
      }
    } else {
      result = Array.from(drawn).sort((a, b) => a - b);
    }

    if (result.length !== winnerCount) {
      throw new Error(`selectWinners result size mismatch: got ${result.length}, expected ${winnerCount}`);
    }

    console.log(`Selected ${result.length} winners. First 10: [${result.slice(0, 10).join(', ')}]`);
    console.log(`Selected ${result.length} winners. Last 10: [${result.slice(-10).join(', ')}]`);

    return result;
// ===== END VERBATIM BODY =====
}
