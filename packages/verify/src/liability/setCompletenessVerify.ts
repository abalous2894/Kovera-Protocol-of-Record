import { createHash } from 'node:crypto';
import { stableStringify } from '../core/stableStringify.js';
import { isRecord } from '../core/isRecord.js';
import { verifyPartialPathCommitment, PARTIAL_PATH_SCHEMA } from '../core/partialPath.js';
import { verifyReceiptDigestMatch } from './digest.js';

export const SET_COMPLETENESS_SCHEMA = 'aevesa.set-completeness/v1' as const;
export const SET_COMPLETENESS_SKU = 'aevesa-set-completeness-v1' as const;

export interface SetCompletenessMember {
  step_index: number;
  receipt_digest: string;
  entry_hash?: string | null;
}

export interface SetCompletenessManifest {
  schema: typeof SET_COMPLETENESS_SCHEMA;
  session_id: string;
  declared_count: number;
  members: SetCompletenessMember[];
  set_root: string;
  terminal_receipt_digest?: string | null;
}

export interface SetCompletenessVerifyChecks {
  schemaValid: boolean;
  memberCountMatches: boolean;
  stepIndicesContiguous: boolean;
  setRootMatches: boolean;
  terminalDigestMatches: boolean;
  partialPathStepAligned: boolean;
  memberDigestsValid: boolean;
  setComplete: boolean;
}

export interface SetCompletenessVerifyOptions {
  /** Terminal liability receipt for partial_path / terminal digest binding */
  terminalReceipt?: unknown;
  /** When true (default), require step_index 0..n-1 with no gaps */
  requireContiguousSteps?: boolean;
  /** When true (default), recompute and match set_root */
  requireSetRootMatch?: boolean;
  /** When terminal receipt provided, require partial_path.step_index + 1 === declared_count */
  requirePartialPathAlignment?: boolean;
  /** When true, verify each member receipt_digest format (64 hex) */
  requireMemberDigestFormat?: boolean;
}

export interface SetCompletenessVerifyResult {
  schema: typeof SET_COMPLETENESS_SCHEMA;
  sku: typeof SET_COMPLETENESS_SKU;
  ok: boolean;
  checks: SetCompletenessVerifyChecks;
  computedSetRoot: string | null;
  gtmLine: string;
  note: string | null;
}

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

/**
 * Canonical set_root — sorted members, lower-case digests, stable JSON preimage.
 */
export function computeSetCompletenessRoot(input: {
  session_id: string;
  declared_count: number;
  members: SetCompletenessMember[];
}): string {
  const sorted = [...input.members].sort((a, b) => a.step_index - b.step_index);
  const preimage = stableStringify({
    schema: SET_COMPLETENESS_SCHEMA,
    session_id: String(input.session_id || '').trim(),
    declared_count: input.declared_count,
    members: sorted.map((m) => {
      const row: Record<string, unknown> = {
        step_index: m.step_index,
        receipt_digest: normalizeHex64(m.receipt_digest) || String(m.receipt_digest),
      };
      const eh = normalizeHex64(m.entry_hash);
      if (eh) row.entry_hash = eh;
      return row;
    }),
  });
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
}

function parseManifest(data: unknown): SetCompletenessManifest | null {
  if (!isRecord(data)) return null;
  if (data.schema !== SET_COMPLETENESS_SCHEMA) return null;
  const session_id = String(data.session_id || '').trim();
  const declared_count = Number(data.declared_count);
  if (!session_id || !Number.isInteger(declared_count) || declared_count < 1) return null;
  if (!Array.isArray(data.members)) return null;

  const members: SetCompletenessMember[] = [];
  for (const raw of data.members) {
    if (!isRecord(raw)) return null;
    const step_index = Number(raw.step_index);
    const receipt_digest = normalizeHex64(raw.receipt_digest);
    if (!Number.isInteger(step_index) || step_index < 0 || !receipt_digest) return null;
    const entry_hash = normalizeHex64(raw.entry_hash);
    members.push({
      step_index,
      receipt_digest,
      ...(entry_hash ? { entry_hash } : {}),
    });
  }

  const set_root = normalizeHex64(data.set_root);
  if (!set_root) return null;

  const terminal = data.terminal_receipt_digest != null ? normalizeHex64(data.terminal_receipt_digest) : null;

  return {
    schema: SET_COMPLETENESS_SCHEMA,
    session_id,
    declared_count,
    members,
    set_root,
    ...(terminal ? { terminal_receipt_digest: terminal } : {}),
  };
}

function checkContiguousSteps(members: SetCompletenessMember[], declared_count: number): boolean {
  if (members.length !== declared_count) return false;
  const indices = members.map((m) => m.step_index).sort((a, b) => a - b);
  for (let i = 0; i < declared_count; i += 1) {
    if (indices[i] !== i) return false;
  }
  return true;
}

/**
 * Set-completeness profile — prove a declared session receipt set is complete (no tail truncation).
 *
 * Offline: manifest structure, contiguous step indices, set_root recomputation,
 * optional terminal receipt partial_path alignment.
 */
export function verifySetCompletenessBundle(
  manifestData: unknown,
  options: SetCompletenessVerifyOptions = {},
): SetCompletenessVerifyResult {
  const requireContiguous = options.requireContiguousSteps !== false;
  const requireRoot = options.requireSetRootMatch !== false;
  const requirePartialPath = options.requirePartialPathAlignment !== false;
  const requireDigestFormat = options.requireMemberDigestFormat !== false;

  const manifest = parseManifest(manifestData);
  const schemaValid = manifest != null;

  if (!manifest) {
    return {
      schema: SET_COMPLETENESS_SCHEMA,
      sku: SET_COMPLETENESS_SKU,
      ok: false,
      checks: {
        schemaValid: false,
        memberCountMatches: false,
        stepIndicesContiguous: false,
        setRootMatches: false,
        terminalDigestMatches: false,
        partialPathStepAligned: false,
        memberDigestsValid: false,
        setComplete: false,
      },
      computedSetRoot: null,
      gtmLine:
        'Receipt protocols truncate tails. Aevesa set-completeness binds every hop — auditors verify the full session set offline.',
      note: 'Invalid aevesa.set-completeness/v1 manifest',
    };
  }

  const memberCountMatches = manifest.members.length === manifest.declared_count;
  const stepIndicesContiguous = !requireContiguous || checkContiguousSteps(manifest.members, manifest.declared_count);

  const memberDigestsValid =
    !requireDigestFormat ||
    manifest.members.every((m) => HEX64.test(normalizeHex64(m.receipt_digest) || ''));

  const computedSetRoot = computeSetCompletenessRoot({
    session_id: manifest.session_id,
    declared_count: manifest.declared_count,
    members: manifest.members,
  });
  const setRootMatches = !requireRoot || computedSetRoot === manifest.set_root;

  let terminalDigestMatches = true;
  let partialPathStepAligned = true;

  const terminalReceipt = options.terminalReceipt;
  if (terminalReceipt != null && isRecord(terminalReceipt)) {
    const terminalDigest = normalizeHex64(
      (terminalReceipt.integrity as { receipt_digest?: unknown } | undefined)?.receipt_digest,
    );
    const expectedTerminal =
      manifest.terminal_receipt_digest ||
      manifest.members.find((m) => m.step_index === manifest.declared_count - 1)?.receipt_digest ||
      null;

    if (expectedTerminal && terminalDigest) {
      terminalDigestMatches = terminalDigest === normalizeHex64(expectedTerminal);
    }

    if (requirePartialPath && isRecord(terminalReceipt.partial_path)) {
      const pp = terminalReceipt.partial_path;
      if (pp.schema === PARTIAL_PATH_SCHEMA) {
        const stepIndex = Number(pp.step_index);
        partialPathStepAligned =
          Number.isInteger(stepIndex) && stepIndex + 1 === manifest.declared_count;
        const ppVerify = verifyPartialPathCommitment(pp);
        partialPathStepAligned = partialPathStepAligned && ppVerify.ok === true;
      } else {
        partialPathStepAligned = false;
      }
    }

    if (terminalDigest && requireDigestFormat) {
      const digestCheck = verifyReceiptDigestMatch(terminalReceipt);
      if (!digestCheck.ok) {
        terminalDigestMatches = false;
      }
    }
  } else if (manifest.terminal_receipt_digest) {
    terminalDigestMatches = manifest.members.some(
      (m) => normalizeHex64(m.receipt_digest) === normalizeHex64(manifest.terminal_receipt_digest),
    );
  }

  const setComplete =
    schemaValid &&
    memberCountMatches &&
    stepIndicesContiguous &&
    setRootMatches &&
    memberDigestsValid &&
    terminalDigestMatches &&
    partialPathStepAligned;

  let note: string | null = null;
  if (setComplete) {
    note = `Set complete — ${manifest.declared_count} receipt digests bound under set_root ${manifest.set_root.slice(0, 12)}… Intermediate members require independent receipt verification.`;
  } else if (!memberCountMatches) {
    note = `Member count ${manifest.members.length} does not match declared_count ${manifest.declared_count}`;
  } else if (!stepIndicesContiguous) {
    note = 'Step indices must be contiguous 0..declared_count-1 (no tail truncation gap)';
  } else if (!setRootMatches) {
    note = 'set_root mismatch — manifest may have been tampered or members reordered';
  } else if (!terminalDigestMatches) {
    note = 'Terminal receipt_digest does not match manifest terminal member';
  } else if (!partialPathStepAligned) {
    note = 'Terminal partial_path.step_index must equal declared_count - 1';
  } else {
    note = 'Set-completeness verification failed';
  }

  return {
    schema: SET_COMPLETENESS_SCHEMA,
    sku: SET_COMPLETENESS_SKU,
    ok: setComplete,
    checks: {
      schemaValid,
      memberCountMatches,
      stepIndicesContiguous,
      setRootMatches,
      terminalDigestMatches,
      partialPathStepAligned,
      memberDigestsValid,
      setComplete,
    },
    computedSetRoot,
    gtmLine:
      'Receipt protocols truncate tails. Aevesa set-completeness binds every hop — auditors verify the full session set offline.',
    note,
  };
}
