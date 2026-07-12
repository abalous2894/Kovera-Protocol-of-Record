/**
 * Golden test vectors — canonical JSON equivalent of kovera-sovereign-ledger-spec.md §3.6, §4.7, §5.5, §6.6.
 * verify-spec-vectors runs these; parseSpecMarkdown cross-checks hashes appear in the spec document.
 */

export const SPEC_TEST_VECTOR_SIGNING_SECRET = 'spec-test-vector-secret-v1';

/** @type {import('./runSpecVectors.js').SpecVectorSuite} */
export const GOLDEN_VECTORS = {
  aegis: {
    golden: {
      id: '3.6.1',
      preimage: {
        agentId: 'agent-spec-golden',
        eventType: 'PERMISSION_REQUESTED',
        severity: 'HIGH',
        payload: {
          aegisSessionId: 'spec-session-golden-001',
          sessionId: 'spec-session-golden-001',
          toolName: 'payments.transfer',
          model: 'gpt-4.1',
          sovereigntyPolicySeal: {
            policyVersionHash: 'pol_v1_abc123',
            policyVersion: '2026.05.1',
          },
        },
        timestamp: '2026-05-19T12:00:00.000Z',
        prevHash: 'GENESIS',
        contextHash: null,
        governanceBinding: {
          cost: null,
          approverId: null,
          policyId: null,
          forensicSnapshot: null,
          proofOfIntent: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
      },
      expected: {
        entryHash: '5b87a7ba72e3d27913d4501c5bc78dbaad2dc7bf4a21f6c64936202ab48be2ee',
        contextHash_from_GENESIS: '157483306fd23435e7d4bb7d0754570f30c1afb53f66e722790edf8a6bb6caef',
      },
    },
    tampered: {
      id: '3.6.2',
      storedEntryHash: '5b87a7ba72e3d27913d4501c5bc78dbaad2dc7bf4a21f6c64936202ab48be2ee',
      recomputedEntryHash: 'd7975d2c4b3d469278bd837f1665342b3bb50be8aae57b372138ebdc5a4b4c81',
    },
    legacy: {
      id: '3.6.3',
      governanceBinding: {
        cost: null,
        approverId: null,
        policyId: null,
        forensicSnapshot: null,
      },
      mustNotContainKey: 'proofOfIntent',
    },
  },
  proofOfIntent: {
    golden: {
      id: '4.7.1',
      input: {
        reasoningFromContext: 'Transfer funds to vendor per approved invoice',
        eventType: 'PERMISSION_REQUESTED',
        payload: {
          toolName: 'payments.transfer',
          model: 'gpt-4.1',
          requestedPermission: 'MANUAL_APPROVAL',
          sovereigntyPolicySeal: { policyVersionHash: 'pol_v1_abc123' },
        },
      },
      expectedHash: '7081d4d326abc0e248db4e52a1ee1ea1c61b6c0780948e0c269c94acfbe64ca2',
      expectedReasoningDigest: '4364f13955f49c3300e5f002ba98d47fb9f5bf10e123db3f79f0b9e538f1a8f9',
    },
    causal: {
      id: '4.7.2',
      input: {
        eventType: 'A2A_DELEGATION',
        swarmFirstAction: true,
        reasoningFromContext: 'Execute delegated subtask per manager mandate',
        payload: {
          toolName: 'delegate.worker',
          model: 'gpt-4.1',
          parentEntryHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          parentSessionId: 'manager-session-001',
          rootSessionId: 'root-swarm-001',
          sovereigntyPolicySeal: { policyVersionHash: 'pol_v1_abc123' },
        },
      },
      expectedHash: '4cf835e91719451a394ac02ecbf75a3ef4d44d5d0a567c936ea74c0ed24ac3b4',
    },
    tampered: {
      id: '4.7.3',
      storedProofOfIntent: '4cf835e91719451a394ac02ecbf75a3ef4d44d5d0a567c936ea74c0ed24ac3b4',
      recomputedAfterTamper: 'fb05bc4c0f4f38277c7de90680caaa6e28cefee8a2fff37f876fcb944e958505',
    },
  },
  swarm: {
    golden: {
      id: '5.5.1',
      rootSessionId: 'root-swarm-001',
      rows: [
        {
          agentId: 'agent-root',
          eventType: 'PERMISSION_REQUESTED',
          timestamp: '2026-05-19T12:00:00.000Z',
          payload: {
            aegisSessionId: 'root-swarm-001',
            sessionId: 'root-swarm-001',
            rootSessionId: 'root-swarm-001',
          },
          entryHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
        {
          agentId: 'agent-worker',
          eventType: 'A2A_DELEGATION',
          timestamp: '2026-05-19T12:01:00.000Z',
          payload: {
            aegisSessionId: 'worker-session-001',
            sessionId: 'worker-session-001',
            parentSessionId: 'root-swarm-001',
            rootSessionId: 'root-swarm-001',
            parentEntryHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
            swarmFirstAction: true,
          },
        },
      ],
      expected: {
        schema: 'aevesa.swarm.delegation-tree/v1',
        rootSessionId: 'root-swarm-001',
        nodeCount: 2,
        edgeCount: 1,
        edges: [{ from: 'root-swarm-001', to: 'worker-session-001', type: 'A2A_DELEGATION' }],
      },
    },
  },
  art12: {
    golden: {
      id: '6.6.1',
      manifest: {
        art12_conformity_pack_format_version: '1.0',
        session_id: 'spec-session-golden-001',
        file_integrity: {
          'session/summary.json': 'deadbeef',
        },
      },
      expectedManifestSha256: '7764b4adf41f6a470637fc1dd7d7bc6173e9129ec0c4ea59c769428904aa8ee3',
      expectedSignature: 'G/X6toUT7XFIXsyaKsQOrjBA2NXAx1tCsHRseQK7nS8=',
    },
    tamperedManifest: {
      id: '6.6.2',
      reason: 'MANIFEST_HASH_MISMATCH',
    },
  },
  intentAlignment: {
    aligned: {
      id: '7.1.1',
      intentContext: {
        reasoning_summary: 'Formatting a backup log for archival compliance',
        model_fingerprint: 'gpt-4.1-2025-04-14',
      },
      payload: {
        tool: 'backup_log_format',
        path: '/var/log/backup/app.log',
        host: 'logs.internal.example.com',
        method: 'GET',
        amount: 0,
        scopes: [],
      },
      expected: { score: 0, level: 'ALIGNED', signals: [] },
    },
    elevated: {
      id: '7.1.2',
      intentContext: {
        reasoning_summary: 'Verifying item availability in catalog',
        model_fingerprint: 'gpt-4.1-2025-04-14',
      },
      payload: {
        tool: 'check_inventory',
        path: '/api/v1/catalog/items',
        host: 'catalog.internal.example.com',
        method: 'GET',
        amount: 250,
        scopes: ['read'],
      },
      expected: { score: 0.5, level: 'ELEVATED', signals: ['QUANTITATIVE_VOLATILITY_ELEVATED'] },
    },
    critical: {
      id: '7.1.3',
      intentContext: {
        reasoning_summary: 'Formatting a backup log for archival compliance',
        model_fingerprint: 'gpt-4.1-2025-04-14',
      },
      payload: {
        tool: 'read_file',
        path: '/proc/self/environ',
        host: 'localhost',
        method: 'GET',
        amount: 0,
        scopes: ['read'],
        exfilTarget: 's3://attacker-bucket/env-dump',
      },
      expected: {
        score: 1,
        level: 'CRITICAL',
        signals: ['PATH_PROC_OR_ENV_ACCESS', 'PAYLOAD_EXFIL_TARGET_FIELD', 'TOOL_EXFIL_VECTOR_MISMATCH'],
      },
    },
    performanceBudgetMs: 2,
  },
};

/**
 * Extract lowercase hex hashes from spec markdown for drift detection.
 * @param {string} markdown
 */
export function extractSpecDocumentHashes(markdown) {
  const re = /\b[a-f0-9]{64}\b/gi;
  return new Set([...markdown.matchAll(re)].map((m) => m[0].toLowerCase()));
}

/**
 * Parse JSON code blocks tagged with **Input** / **Output** near test vector headers.
 * @param {string} markdown
 * @param {string} sectionId — e.g. "3.6.1"
 */
export function findSpecJsonBlocksForSection(markdown, sectionId) {
  const header = `#### ${sectionId}`;
  const start = markdown.indexOf(header);
  if (start < 0) return [];
  const searchFrom = start + header.length;
  const nextMatch = markdown.slice(searchFrom).search(/\r?\n#### /);
  const nextHeaderPos = nextMatch >= 0 ? searchFrom + nextMatch : -1;
  const slice = nextHeaderPos >= 0 ? markdown.slice(start, nextHeaderPos) : markdown.slice(start);
  const blocks = [];
  const re = /```json\r?\n([\s\S]*?)```/g;
  let match;
  while ((match = re.exec(slice)) !== null) {
    try {
      blocks.push(JSON.parse(match[1]));
    } catch {
      /* partial / illustrative blocks skipped */
    }
  }
  return blocks;
}
