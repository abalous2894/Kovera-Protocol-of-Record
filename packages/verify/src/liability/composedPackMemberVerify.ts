import { isRecord } from '../core/isRecord.js';
import { verifyMemberVerifyAttestation } from './memberVerifyAttestationVerify.js';

const HEX64 = /^[a-f0-9]{64}$/;

export type ComposedMemberVerifySource = 'member_document' | 'witness_attestation' | 'none';

export interface ComposedMemberRef {
  member_schema?: string;
  member_digest?: string;
  verify_ok?: boolean;
  label?: string;
  entry_count?: number | null;
}

export interface ResolvedComposedMember {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  verify_source: ComposedMemberVerifySource;
  label: string;
  entry_count: number | null;
}

export interface ResolveComposedMemberVerifyOptions {
  members: ComposedMemberRef[];
  member_documents?: Record<string, unknown> | null;
  member_verify_attestations?: Record<string, unknown> | null;
  resolveMemberDocument: (memberDocs: Record<string, unknown>, memberSchema: string) => unknown;
  recomputeMemberVerifyOk: (memberSchema: string, embedded: unknown) => boolean;
  /** When true, attestations must include witness cosign (default true for PC-09 path). */
  requireWitnessCosignOnAttestation?: boolean;
}

export interface ResolveComposedMemberVerifyResult {
  members: ResolvedComposedMember[];
  memberArtifactsBundled: boolean;
  memberAttestationsPresent: boolean;
  memberAttestationsWitnessed: boolean;
  memberProofPresent: boolean;
  memberVerifyRecomputed: boolean;
  selfAssertedVerifyIgnored: boolean;
}

function asAttestationMap(raw: unknown): Record<string, unknown> {
  if (!isRecord(raw)) return {};
  return raw;
}

function attestationForSchema(
  attestations: Record<string, unknown>,
  memberSchema: string,
): unknown {
  return attestations[memberSchema] ?? null;
}

/**
 * Resolve per-member verify_ok from co-pasted member_documents OR witness-bound attestations (PC-09).
 */
export function resolveComposedMemberVerifyState(
  options: ResolveComposedMemberVerifyOptions,
): ResolveComposedMemberVerifyResult {
  const memberDocs = isRecord(options.member_documents) ? options.member_documents : {};
  const attestations = asAttestationMap(options.member_verify_attestations);
  const requireWitness = options.requireWitnessCosignOnAttestation !== false;

  const memberArtifactsBundled = Object.keys(memberDocs).length > 0;
  const memberAttestationsPresent = Object.keys(attestations).length > 0;

  let memberAttestationsWitnessed = false;
  if (memberAttestationsPresent) {
    memberAttestationsWitnessed = Object.values(attestations).every((att) => {
      const result = verifyMemberVerifyAttestation(att, { requireWitnessCosign: requireWitness });
      return result.checks.witnessCosignProvided && result.checks.witnessCosignStructureValid === true;
    });
  }

  const resolved: ResolvedComposedMember[] = options.members.map((member) => {
    const member_schema = String(member.member_schema || '').trim();
    const member_digest = String(member.member_digest || '').trim().toLowerCase();
    const embedded = options.resolveMemberDocument(memberDocs, member_schema);

    if (embedded != null) {
      return {
        member_schema,
        member_digest,
        verify_ok: options.recomputeMemberVerifyOk(member_schema, embedded),
        verify_source: 'member_document',
        label: String(member.label || ''),
        entry_count: member.entry_count ?? null,
      };
    }

    const attestation = attestationForSchema(attestations, member_schema);
    if (attestation != null) {
      const attResult = verifyMemberVerifyAttestation(attestation, {
        expected_member_schema: member_schema,
        expected_member_digest: member_digest,
        requireWitnessCosign: requireWitness,
      });
      return {
        member_schema,
        member_digest,
        verify_ok: attResult.ok === true,
        verify_source: 'witness_attestation',
        label: String(member.label || ''),
        entry_count: member.entry_count ?? null,
      };
    }

    return {
      member_schema,
      member_digest,
      verify_ok: false,
      verify_source: 'none',
      label: String(member.label || ''),
      entry_count: member.entry_count ?? null,
    };
  });

  const memberVerifyRecomputed = resolved.length > 0 && resolved.every((m) => m.verify_ok === true);
  const selfAssertedVerifyIgnored =
    options.members.some((m) => m.verify_ok === true) && !resolved.some((m) => m.verify_ok === true);

  const assertedMembers = options.members.filter((m) => m.verify_ok === true);
  const attestationProofComplete =
    memberAttestationsPresent &&
    memberAttestationsWitnessed &&
    assertedMembers.length > 0 &&
    assertedMembers.every((member) => {
      const row = resolved.find((r) => r.member_schema === String(member.member_schema || '').trim());
      return row?.verify_source === 'witness_attestation' && row.verify_ok === true;
    });

  const memberProofPresent = memberArtifactsBundled || attestationProofComplete;

  return {
    members: resolved,
    memberArtifactsBundled,
    memberAttestationsPresent,
    memberAttestationsWitnessed,
    memberProofPresent,
    memberVerifyRecomputed,
    selfAssertedVerifyIgnored,
  };
}

export function composedMemberDigestsValid(members: ComposedMemberRef[]): boolean {
  return (
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m.member_digest || '').trim().toLowerCase()))
  );
}

export function extractComposedPackProofLayers(docInput: unknown): {
  memberDocs: Record<string, unknown>;
  memberAttestations: Record<string, unknown>;
} {
  const doc = isRecord(docInput) ? docInput : {};
  return {
    memberDocs: isRecord(doc.member_documents) ? doc.member_documents : {},
    memberAttestations: isRecord(doc.member_verify_attestations) ? doc.member_verify_attestations : {},
  };
}

export function hashOnlyComposedPackSurface(
  docInput: unknown,
  hasForbiddenKeys: (value: unknown, depth?: number) => boolean,
): boolean {
  const doc = isRecord(docInput) ? docInput : {};
  const { member_documents: _md, member_verify_attestations: _mva, ...hashOnlyDoc } = doc;
  return !hasForbiddenKeys(hashOnlyDoc);
}

export function pc09MemberProofNote(result: ResolveComposedMemberVerifyResult): string | null {
  if (!result.memberProofPresent) {
    return 'member_documents or member_verify_attestations with witness cosign required (PC-09)';
  }
  if (result.selfAssertedVerifyIgnored) {
    return 'composed_members.verify_ok is exporter self-asserted; bundle member_documents or witness attestations for offline re-verify';
  }
  if (result.memberAttestationsPresent && !result.memberAttestationsWitnessed) {
    return 'member_verify_attestations present but witness cosign invalid or missing (PC-09)';
  }
  return null;
}
