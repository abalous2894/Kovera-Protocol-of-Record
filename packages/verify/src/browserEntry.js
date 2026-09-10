/**
 * Browser bundle entry — generated from browser-manifest.json.
 * Import subpaths directly (not dist/index.js) so esbuild never pulls node-only CLI/offline exports.
 * Regenerate: npm run generate:browser-entry --workspace=@aevesa/verify
 */

export { verifyReceipt } from '../dist/liability/verifyReceipt.js';

export { parseLiabilityReceiptStructure } from '../dist/liability/schema.js';

export {
  computeReceiptDigest,
  computeCanonicalReceiptDigest,
  receiptDigestPreimage,
  verifyReceiptDigestMatch,
  RECEIPT_DIGEST_PROFILE_ORDER,
} from '../dist/liability/digest.js';

export {
  evaluateIntentAlignment,
  normalizeStructuralPayload,
} from '../dist/core/intentAlignment.js';

export {
  verifySetCompletenessBundle,
  computeSetCompletenessRoot,
  SET_COMPLETENESS_SCHEMA,
  SET_COMPLETENESS_SKU,
} from '../dist/liability/setCompletenessVerify.js';

export {
  verifySessionProof,
  computeSessionProofDigest,
  SESSION_PROOF_SCHEMA,
  SESSION_PROOF_SKU,
  SESSION_PROOF_VERIFY_SCHEMA,
} from '../dist/liability/sessionProofVerify.js';

export {
  verifyProvableExecutionBoundaryBundle,
  PROVABLE_EXECUTION_BOUNDARY_SKU,
} from '../dist/liability/provableExecutionBoundaryVerify.js';

export { PROVABLE_EXECUTION_BOUNDARY_SCHEMA } from '../dist/core/provableExecutionBoundary.js';

export {
  verifyConformityClosureBundle,
  CONFORMITY_CLOSURE_SKU,
} from '../dist/liability/conformityClosureVerify.js';

export { CONFORMITY_CLOSURE_SCHEMA } from '../dist/core/conformityClosure.js';

export { verifyDeclaredAdaptationEnvelopeBundle } from '../dist/liability/declaredAdaptationEnvelopeVerify.js';

export {
  DECLARED_ADAPTATION_ENVELOPE_SCHEMA,
  DECLARED_ADAPTATION_ENVELOPE_SKU,
  buildDeclaredAdaptationEnvelopeDocument,
  evaluateAdaptationEnvelopeDrift,
} from '../dist/core/declaredAdaptationEnvelope.js';

export { verifySubstantialModificationSignalBundle } from '../dist/liability/substantialModificationSignalVerify.js';

export { verifyAdaptationLifecycleExportBundle } from '../dist/liability/adaptationLifecycleExportVerify.js';

export {
  ADAPTATION_LIFECYCLE_EXPORT_SCHEMA,
  buildAdaptationLifecycleExportDocument,
} from '../dist/core/adaptationLifecycleExport.js';

export {
  SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA,
  SUBSTANTIAL_MODIFICATION_SIGNAL_SKU,
  buildSubstantialModificationSignalDocument,
  buildSubstantialModificationSignalFraming,
} from '../dist/core/substantialModificationSignal.js';

export {
  verifyQuarterlyReviewExport,
  QUARTERLY_REVIEW_EXPORT_SKU,
} from '../dist/liability/quarterlyReviewExportVerify.js';

export { QUARTERLY_REVIEW_EXPORT_SCHEMA } from '../dist/core/quarterlyReviewExport.js';

export {
  verifyInsuranceSignalDigest,
  INSURANCE_SIGNAL_DIGEST_SKU,
} from '../dist/liability/insuranceSignalDigestVerify.js';

export { INSURANCE_SIGNAL_DIGEST_SCHEMA } from '../dist/core/insuranceSignalDigest.js';

export {
  verifyIndependentGuardianBundle,
  INDEPENDENT_GUARDIAN_BUNDLE_SKU,
} from '../dist/liability/independentGuardianBundleVerify.js';

export { INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA } from '../dist/core/independentGuardianBundle.js';

export {
  verifyAp2ConductReceipt,
  AP2_CONDUCT_RECEIPT_SKU,
} from '../dist/liability/ap2ConductReceiptVerify.js';

export { AP2_CONDUCT_RECEIPT_SCHEMA } from '../dist/core/ap2ConductReceipt.js';

export {
  verifyShutdownDrillBundle,
  SHUTDOWN_DRILL_BUNDLE_SKU,
} from '../dist/liability/shutdownDrillBundleVerify.js';

export { SHUTDOWN_DRILL_BUNDLE_SCHEMA } from '../dist/core/shutdownDrillBundle.js';

export {
  verifyFlightRecorderExport,
  FLIGHT_RECORDER_EXPORT_SKU,
} from '../dist/liability/flightRecorderExportVerify.js';

export { FLIGHT_RECORDER_EXPORT_SCHEMA } from '../dist/core/flightRecorderExport.js';

export {
  verifyRogueContainmentPack,
  ROGUE_CONTAINMENT_PACK_SKU,
} from '../dist/liability/rogueContainmentPackVerify.js';

export { ROGUE_CONTAINMENT_PACK_SCHEMA } from '../dist/core/rogueContainmentPack.js';

export {
  verifyReasoningBaselineReceipt,
  REASONING_BASELINE_RECEIPT_SKU,
} from '../dist/liability/reasoningBaselineReceiptVerify.js';

export { REASONING_BASELINE_RECEIPT_SCHEMA } from '../dist/core/reasoningBaselineReceipt.js';

export {
  verifyClusterCustodyGraph,
  CLUSTER_CUSTODY_GRAPH_SKU,
} from '../dist/liability/clusterCustodyGraphVerify.js';

export { CLUSTER_CUSTODY_GRAPH_SCHEMA } from '../dist/core/clusterCustodyGraph.js';

export {
  verifyMemoryCommitment,
  buildMemoryCommitmentProofSteps,
} from '../dist/liability/memoryCommitmentVerify.js';

export {
  MEMORY_COMMITMENT_SCHEMA,
  MEMORY_COMMITMENT_SKU,
  computeMemoryRootFromContentHashes,
  buildMemoryCommitmentDocument,
} from '../dist/core/memoryCommitment.js';

export {
  verifyToolManifestFingerprint,
  buildToolManifestFingerprintProofSteps,
} from '../dist/liability/toolManifestFingerprintVerify.js';

export {
  TOOL_MANIFEST_FINGERPRINT_SCHEMA,
  TOOL_MANIFEST_FINGERPRINT_SKU,
  buildToolManifestFingerprintDocument,
} from '../dist/core/toolManifestFingerprint.js';

export { verifyDelegationChain } from '../dist/core/delegationChainVerify.js';

export {
  verifyVerifiableDenialEvidencePack,
  VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU,
} from '../dist/liability/verifiableDenialEvidencePackVerify.js';

export { VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA } from '../dist/core/verifiableDenialEvidencePack.js';

export {
  verifyLicenseSurvivableCustodyPack,
  LICENSE_SURVIVABLE_CUSTODY_PACK_SKU,
} from '../dist/liability/licenseSurvivableCustodyPackVerify.js';

export { LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA } from '../dist/core/licenseSurvivableCustodyPack.js';

export {
  verifyCarrierMgaAcceptanceKit,
  CARRIER_MGA_ACCEPTANCE_KIT_SKU,
} from '../dist/liability/carrierMgaAcceptanceKitVerify.js';

export { CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA } from '../dist/core/carrierMgaAcceptanceKit.js';

export {
  verifyIndependenceWitnessPack,
  INDEPENDENCE_WITNESS_PACK_SKU,
} from '../dist/liability/independenceWitnessPackVerify.js';

export { INDEPENDENCE_WITNESS_PACK_SCHEMA } from '../dist/core/independenceWitnessPack.js';

export {
  verifyAgtConductReceipt,
  AGT_CONDUCT_RECEIPT_SKU,
} from '../dist/liability/agtConductReceiptVerify.js';

export { AGT_CONDUCT_RECEIPT_SCHEMA } from '../dist/core/agtConductReceipt.js';

export {
  verifyCrossPlatformConductPack,
  CROSS_PLATFORM_CONDUCT_PACK_SKU,
} from '../dist/liability/crossPlatformConductPackVerify.js';

export { CROSS_PLATFORM_CONDUCT_PACK_SCHEMA } from '../dist/core/crossPlatformConductPack.js';

export {
  verifyDeclaredAgentRoster,
  DECLARED_AGENT_ROSTER_SKU,
} from '../dist/liability/declaredAgentRosterVerify.js';

export { DECLARED_AGENT_ROSTER_SCHEMA } from '../dist/core/declaredAgentRoster.js';

export {
  verifyObservedAgentConductSet,
  OBSERVED_AGENT_CONDUCT_SET_SKU,
} from '../dist/liability/observedAgentConductSetVerify.js';

export { OBSERVED_AGENT_CONDUCT_SET_SCHEMA } from '../dist/core/observedAgentConductSet.js';

export {
  verifyAgentCensusCompletenessPack,
  AGENT_CENSUS_COMPLETENESS_PACK_SKU,
} from '../dist/liability/agentCensusCompletenessPackVerify.js';

export { AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA } from '../dist/core/agentCensusCompletenessPack.js';

export {
  verifyAttestedEvidenceSet,
  ATTESTED_EVIDENCE_SET_SKU,
} from '../dist/liability/attestedEvidenceSetVerify.js';

export { ATTESTED_EVIDENCE_SET_SCHEMA } from '../dist/core/attestedEvidenceSet.js';

export {
  verifyExecutiveAttestationBindingPack,
  EXECUTIVE_ATTESTATION_BINDING_PACK_SKU,
} from '../dist/liability/executiveAttestationBindingPackVerify.js';

export { EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA } from '../dist/core/executiveAttestationBindingPack.js';

export {
  verifyIncidentNotificationTimeline,
  INCIDENT_NOTIFICATION_TIMELINE_SKU,
} from '../dist/liability/incidentNotificationTimelineVerify.js';

export { INCIDENT_NOTIFICATION_TIMELINE_SCHEMA } from '../dist/core/incidentNotificationTimeline.js';

export {
  verifyIncidentNotificationTimelinePack,
  INCIDENT_NOTIFICATION_TIMELINE_PACK_SKU,
} from '../dist/liability/incidentNotificationTimelinePackVerify.js';

export { INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA } from '../dist/core/incidentNotificationTimelinePack.js';

export {
  verifyPostMarketMonitoringSnapshot,
  POST_MARKET_MONITORING_SNAPSHOT_SKU,
} from '../dist/liability/postMarketMonitoringSnapshotVerify.js';

export { POST_MARKET_MONITORING_SNAPSHOT_SCHEMA } from '../dist/core/postMarketMonitoringSnapshot.js';

export {
  verifyPostMarketMonitoringExportPack,
  POST_MARKET_MONITORING_EXPORT_PACK_SKU,
} from '../dist/liability/postMarketMonitoringExportPackVerify.js';

export { POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA } from '../dist/core/postMarketMonitoringExportPack.js';

export {
  verifyVendorModelChange,
  VENDOR_MODEL_CHANGE_SKU,
} from '../dist/liability/vendorModelChangeVerify.js';

export { VENDOR_MODEL_CHANGE_SCHEMA } from '../dist/core/vendorModelChange.js';

export {
  verifyPolicyAtChangeSnapshot,
  POLICY_AT_CHANGE_SNAPSHOT_SKU,
} from '../dist/liability/policyAtChangeSnapshotVerify.js';

export { POLICY_AT_CHANGE_SNAPSHOT_SCHEMA } from '../dist/core/vendorModelChange.js';

export {
  verifyModelChangeNotificationPack,
  MODEL_CHANGE_NOTIFICATION_PACK_SKU,
} from '../dist/liability/modelChangeNotificationPackVerify.js';

export { MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA } from '../dist/core/modelChangeNotificationPack.js';

export {
  verifyDelegationStepReceipt,
  DELEGATION_STEP_RECEIPT_SKU,
} from '../dist/liability/delegationStepReceiptVerify.js';

export { DELEGATION_STEP_RECEIPT_SCHEMA } from '../dist/core/delegationStepReceipt.js';

export {
  verifyCrossOrgDelegationChainPack,
  CROSS_ORG_DELEGATION_CHAIN_PACK_SKU,
} from '../dist/liability/crossOrgDelegationChainPackVerify.js';

export { CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA } from '../dist/core/crossOrgDelegationChainPack.js';

export {
  verifyMcpSepAttestationBind,
  MCP_SEP_ATTESTATION_BIND_SKU,
} from '../dist/liability/mcpSepAttestationBindVerify.js';

export { MCP_SEP_ATTESTATION_BIND_SCHEMA } from '../dist/core/mcpSepAttestationBind.js';

export {
  verifyInterceptDecisionAttestation,
  INTERCEPT_DECISION_ATTESTATION_SKU,
} from '../dist/liability/interceptDecisionAttestationVerify.js';

export { INTERCEPT_DECISION_ATTESTATION_SCHEMA } from '../dist/core/interceptDecisionAttestation.js';

export {
  verifyAddonVettingProvenance,
  ADDON_VETTING_PROVENANCE_SKU,
} from '../dist/liability/addonVettingProvenanceVerify.js';

export { ADDON_VETTING_PROVENANCE_SCHEMA } from '../dist/core/addonVettingProvenance.js';

export {
  verifyHostConformanceBind,
  HOST_CONFORMANCE_BIND_SKU,
} from '../dist/liability/hostConformanceBindVerify.js';

export { HOST_CONFORMANCE_BIND_SCHEMA } from '../dist/core/hostConformanceBind.js';

export {
  verifyEvidencePortabilityDrill,
  EVIDENCE_PORTABILITY_DRILL_SKU,
} from '../dist/liability/evidencePortabilityDrillVerify.js';

export { EVIDENCE_PORTABILITY_DRILL_SCHEMA } from '../dist/core/evidencePortabilityDrill.js';

export {
  verifyWitnessDiversityBlock,
  WITNESS_DIVERSITY_SKU,
} from '../dist/liability/witnessDiversityVerify.js';

export {
  WITNESS_DIVERSITY_BLOCK_SCHEMA,
  buildWitnessDiversityBlock,
} from '../dist/core/witnessDiversity.js';

export {
  verifyHitlApprovalReceipt,
  HITL_APPROVAL_RECEIPT_SKU,
} from '../dist/liability/hitlApprovalReceiptVerify.js';

export { HITL_APPROVAL_RECEIPT_SCHEMA } from '../dist/core/hitlApprovalReceipt.js';

export {
  verifyTraceableConductPackage,
  TRACEABLE_CONDUCT_PACKAGE_SKU,
} from '../dist/liability/traceableConductPackageVerify.js';

export { TRACEABLE_CONDUCT_PACKAGE_SCHEMA } from '../dist/core/traceableConductPackage.js';

export {
  verifyQuarterlyRetestReceipt,
  QUARTERLY_RETEST_RECEIPT_SKU,
} from '../dist/liability/quarterlyRetestReceiptVerify.js';

export { QUARTERLY_RETEST_RECEIPT_SCHEMA } from '../dist/core/quarterlyRetestReceipt.js';

export {
  verifyAdversarialTestEvidencePack,
  ADVERSARIAL_TEST_EVIDENCE_PACK_SKU,
} from '../dist/liability/adversarialTestEvidencePackVerify.js';

export { ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA } from '../dist/core/adversarialTestEvidencePack.js';
