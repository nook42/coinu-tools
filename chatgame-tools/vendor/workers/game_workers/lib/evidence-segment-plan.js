// Versioned capacity prices; old entries remain available for in-flight block resumes.
const PRICES = Object.freeze({
  'pre-g7-placeholder-1': Object.freeze({
    coefficients: Object.freeze({ a: '1000', b: '100', c: '1000', sig: '82' }),
    budget: Object.freeze({ cycles: '15000000', sigRecoveries: '1000' }),
    invalidCosts: Object.freeze({
      unsupported_format: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      compact_decode_error: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      not_a_member: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      sender_mismatch: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      compact_context_mismatch: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      invalid_signature: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      chathash_mismatch: Object.freeze({ b: '100', c: '1000', sig: '82' }),
      snapshot_mismatch: Object.freeze({ b: '100', c: '1000', sig: '82' }),
    }),
  }),
  'g7-1': Object.freeze({
    coefficients: Object.freeze({ a: '45000000', b: '0', c: '170000000', sig: '82' }),
    budget: Object.freeze({ cycles: '2085000000', sigRecoveries: '984' }),
    invalidCosts: Object.freeze({
      unsupported_format: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      compact_decode_error: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      not_a_member: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      sender_mismatch: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      compact_context_mismatch: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      invalid_signature: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      chathash_mismatch: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
      snapshot_mismatch: Object.freeze({ b: '0', c: '170000000', sig: '82' }),
    }),
  }),
});

export const CURRENT_EVIDENCE_SEGMENT_PIN_VERSION = 'g7-1';
export const EVIDENCE_SEGMENT_PIN_VERSIONS = Object.freeze(Object.keys(PRICES));

const decimal = (value, label) => {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new Error(`[evidence-segments] unsafe ${label}: ${value}`);
  }
  const text = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`[evidence-segments] invalid ${label}: ${text}`);
  return BigInt(text);
};

export function evidenceSegmentPrice(version = CURRENT_EVIDENCE_SEGMENT_PIN_VERSION) {
  const price = Object.hasOwn(PRICES, version) ? PRICES[version] : null;
  if (!price) throw new Error(`[evidence-segments] unknown pinVersion: ${version}`);
  return price;
}

// Each axis uses the maximum over every possible path, without decoding a frame.
// g7-1 has b=0, so every frame pays the same worst-frame cost.
export function planEvidenceSegmentsWithPrice(frames, price, version) {
  if (!Array.isArray(frames)) throw new Error('[evidence-segments] frames must be an array');
  // Direct callers may supply a price-file copy with no version. Only the
  // historical price contents retain their original uncapped planner behavior.
  const historicalPrice = (version === undefined || version === 'pre-g7-placeholder-1')
    && JSON.stringify(price) === JSON.stringify(PRICES['pre-g7-placeholder-1']);
  const costs = [price.coefficients, ...Object.values(price.invalidCosts)];
  const fixed = decimal(price.coefficients.a, 'a');
  const maxCycles = decimal(price.budget.cycles, 'cycles budget');
  const maxSig = decimal(price.budget.sigRecoveries, 'sig budget');
  const segments = [];
  let firstSeq = 1n;
  let count = 0n;
  let cycles = fixed;
  let signatures = 0n;
  for (const frame of frames) {
    const seq = decimal(frame.seq, 'seq');
    if (seq !== firstSeq + count) {
      throw new Error(`[evidence-segments] missing or duplicate seq ${firstSeq + count} (got ${seq})`);
    }
    const bytes = decimal(frame.rawBytes ?? frame.data_len, 'rawBytes');
    if (!historicalPrice && bytes > 130_000n) {
      throw new Error(`[evidence-segments] frame rawBytes exceeds 130000 at seq ${seq}`);
    }
    const frameCycles = costs.reduce((max, item) => {
      const amount = decimal(item.b, 'b') * bytes + decimal(item.c, 'c');
      return amount > max ? amount : max;
    }, 0n);
    const frameSig = costs.reduce((max, item) => {
      const amount = decimal(item.sig, 'sig');
      return amount > max ? amount : max;
    }, 0n);
    if (fixed + frameCycles > maxCycles || frameSig > maxSig) {
      throw new Error(`[evidence-segments] one frame exceeds budget at seq ${seq}`);
    }
    if (count > 0n && (cycles + frameCycles > maxCycles || signatures + frameSig > maxSig)) {
      segments.push({ index: String(segments.length), firstSeq: String(firstSeq), frameCount: String(count) });
      firstSeq = seq;
      count = 0n;
      cycles = fixed;
      signatures = 0n;
    }
    cycles += frameCycles;
    signatures += frameSig;
    count++;
  }
  if (count > 0n) {
    segments.push({ index: String(segments.length), firstSeq: String(firstSeq), frameCount: String(count) });
  }
  return segments;
}

export function evidenceSegmentArtifact(frames, version = CURRENT_EVIDENCE_SEGMENT_PIN_VERSION) {
  const price = evidenceSegmentPrice(version);
  return {
    schemaVersion: 1,
    pinVersion: version,
    coefficients: price.coefficients,
    budget: price.budget,
    invalidCosts: price.invalidCosts,
    segments: planEvidenceSegmentsWithPrice(frames, price, version),
  };
}
