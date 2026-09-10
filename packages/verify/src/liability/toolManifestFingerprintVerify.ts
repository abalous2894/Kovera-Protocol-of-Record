import { sha256HexUtf8 } from '../core/sha256.js';
import { TOOL_MANIFEST_FINGERPRINT_SCHEMA, buildToolManifestFingerprintPreimage, type ToolManifestFingerprintInput } from '../core/toolManifestFingerprint.js';
import { stableStringify } from '../core/stableStringify.js';

export interface ToolManifestFingerprintVerifyResult {
  ok: boolean;
  code: string;
  expected?: string;
  got?: string;
  present?: boolean;
  manifestFingerprint?: string | null;
  toolCompositeHash?: string | null;
}

export function verifyToolManifestFingerprint(
  block: unknown,
): ToolManifestFingerprintVerifyResult {
  if (!block || typeof block !== 'object' || Array.isArray(block)) {
    return { ok: false, code: 'INVALID_TOOL_MANIFEST_FINGERPRINT' };
  }

  const bind = block as Record<string, unknown>;
  if (bind.schema !== TOOL_MANIFEST_FINGERPRINT_SCHEMA) {
    return { ok: false, code: 'INVALID_TOOL_MANIFEST_FINGERPRINT_SCHEMA' };
  }

  const stored = String(bind.bind_digest || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(stored)) {
    return { ok: false, code: 'MISSING_BIND_DIGEST' };
  }

  const present = bind.present === true;
  const preimage = buildToolManifestFingerprintPreimage(bind as unknown as ToolManifestFingerprintInput);
  const expected = sha256HexUtf8(stableStringify(preimage));
  if (expected !== stored) {
    return {
      ok: false,
      code: 'TOOL_MANIFEST_BIND_DIGEST_MISMATCH',
      expected,
      got: stored,
      present,
      manifestFingerprint: present ? String(bind.manifest_fingerprint || '').toLowerCase() : null,
      toolCompositeHash: present ? String(bind.tool_composite_hash || '').toLowerCase() : null,
    };
  }

  if (present) {
    const manifestFingerprint = String(bind.manifest_fingerprint || '').toLowerCase();
    const toolCompositeHash = String(bind.tool_composite_hash || '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(manifestFingerprint)) {
      return { ok: false, code: 'MISSING_MANIFEST_FINGERPRINT', present: true };
    }
    if (!/^[a-f0-9]{64}$/.test(toolCompositeHash)) {
      return { ok: false, code: 'MISSING_TOOL_COMPOSITE_HASH', present: true };
    }
    return {
      ok: true,
      code: 'TOOL_MANIFEST_FINGERPRINT_VERIFIED',
      present: true,
      manifestFingerprint,
      toolCompositeHash,
    };
  }

  if (bind.absent_reason == null || String(bind.absent_reason).trim() === '') {
    return { ok: false, code: 'MISSING_ABSENT_REASON', present: false };
  }

  return {
    ok: true,
    code: 'TOOL_MANIFEST_FINGERPRINT_ABSENT_MARKED',
    present: false,
    manifestFingerprint: null,
    toolCompositeHash: null,
  };
}

export function buildToolManifestFingerprintProofSteps(receipt: {
  tool_manifest_fingerprint?: unknown;
  side_effects?: { action?: { tool_name?: string } };
}) {
  const bind = receipt?.tool_manifest_fingerprint;
  const verify = verifyToolManifestFingerprint(bind);
  const present = (bind as { present?: boolean } | undefined)?.present === true;

  return [
    {
      key: 'tool_manifest_fingerprint_schema',
      label: 'MCP manifest bind extension (aevesa.tool-manifest-fingerprint/v1)',
      ok: Boolean(bind && typeof bind === 'object'),
      detail: (bind as { schema?: string } | undefined)?.schema || 'missing',
    },
    {
      key: 'tool_manifest_bind_digest',
      label: 'Bind digest seals manifest fingerprint + tool composite hash',
      ok: verify.ok === true,
      detail: verify.ok ? verify.code : verify.code,
    },
    {
      key: 'manifest_fingerprint',
      label: present
        ? 'Session manifest fingerprint (AttestMCP tools/list hash)'
        : 'Honest absent marker (AttestMCP disabled or manifest unpinned)',
      ok: present ? verify.ok === true && Boolean(verify.manifestFingerprint) : verify.ok === true,
      detail: present
        ? verify.manifestFingerprint || 'missing'
        : String((bind as { absent_reason?: string } | undefined)?.absent_reason || 'absent'),
    },
    {
      key: 'tool_composite_hash',
      label: present ? 'Pinned tool definition composite hash at invoke' : 'Not bound',
      ok: present ? verify.ok === true && Boolean(verify.toolCompositeHash) : verify.ok === true,
      detail: present
        ? verify.toolCompositeHash || 'missing'
        : receipt?.side_effects?.action?.tool_name || 'n/a',
    },
  ];
}
