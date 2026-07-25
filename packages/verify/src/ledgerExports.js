export { ExitCode } from './exitCodes.js';

export {
  AEGIS_LEDGER_PREIMAGE_SPEC,
  AEGIS_ENTRY_HASH_INPUT_KEYS,
  AEGIS_CONTEXT_LINKAGE_KEYS,
} from './core/aegisPreimageSpec.js';

export { canonicalize } from './core/canonicalize.js';
export { stableStringify } from './core/stableStringify.js';
export { sha256Utf8, sha256Buffer } from './core/sha256.js';
export { resolveGovernanceBinding } from './core/governanceBinding.js';

export {
  serializeIntentContext,
  canonicalizeIntentContextForBinding,
  computeIntentContextDigest,
  buildIntentContextFromSources,
  intentContextIsPresent,
  INTENT_CONTEXT_MAX_REASONING,
  INTENT_CONTEXT_MAX_MODEL,
} from './core/intentContext.js';

export {
  evaluateIntentAlignment,
  normalizeStructuralPayload,
  intentAlignmentLevelFromScore,
  INTENT_ALIGNMENT_LEVEL,
  MAX_INTENT_ALIGNMENT_SIGNALS,
  canonicalizeIntentAlignmentForDigest,
} from './core/intentAlignment.js';

export {
  extractCausalLineageFromPayload,
  canonicalizeCausalLineageForDigest,
  causalLineageToProofBinding,
} from './core/causalLineage.js';

export {
  formatAegisLedgerTimestampIso,
  buildGovernanceBindingFromStoredDoc,
  buildContextLinkageFromStoredDoc,
  buildEntryHashPreimageFromStoredDoc,
  serializeEntryHashInput,
  serializeContextLinkage,
  computeEntryHashFromPreimage,
  computeContextHashFromLinkage,
  sealAegisLedgerRow,
  verifyLedgerEntryPreimage,
} from './core/ledgerPreimage.js';

export {
  digestReasoningText,
  buildReasoningPath,
  buildConstraintsApplied,
  buildModelFingerprint,
  buildCausalBinding,
  computeProofOfIntent,
  buildProofOfIntentFromSpecInput,
  verifyProofOfIntentForStoredRow,
  NO_REASONING_DIGEST,
} from './core/proofOfIntent.js';

export {
  COMPLIANCE_PACK_SIGNING_KEY_ID,
  SPEC_TEST_VECTOR_SIGNING_SECRET,
  getCompliancePackSigningSecret,
  manifestPayloadForSigning,
  hashManifestForSigning,
  signConformityPackManifest,
  verifyConformityPackManifestSignature,
} from './core/art12Manifest.js';

export { verifyArt12PackPath, verifyArt12PackFiles, verifyArt12PackDirectory } from './core/art12PackVerify.js';

export { verifyPolicyPromotionProof } from './offlinePromotionVerifier.js';

export {
  normalizeSessionId,
  extractSessionIdFromPayload,
  buildSwarmDelegationTreeFromRows,
} from './core/swarmDelegationTree.js';

export {
  DELEGATION_CHAIN_SCHEMA,
  DELEGATION_CHAIN_DEMO_SIGNING_SECRET,
  verifyDelegationChain,
  verifyHdpHopChain,
  verifyHdpHopReceipt,
  buildDelegationChainProofTrace,
  scopeHashFromEffectiveAccess,
} from './core/delegationChainVerify.js';

export {
  RECEIPT_PROFILE_DENIED,
  RECEIPT_PROFILE_PERMITTED,
  SCITT_REFUSAL_PROFILE,
  isDeniedReceiptProfile,
  validateDeniedReceiptProfile,
  validateScittRefusalAlignment,
  buildDeniedReceiptProofSteps,
} from './liability/deniedReceiptProfile.js';

export { validateIncidentCustodyPackManifest } from './compliance/incidentCustodyPackVerify.js';
export { validateConformanceLabManifest } from './compliance/conformanceLabVerify.js';
export { validateCrossVendorIntegrationManifest } from './compliance/crossVendorIntegrationVerify.js';

export { runSpecVectors } from './spec/runSpecVectors.js';
export { GOLDEN_VECTORS } from './spec/goldenVectors.js';
