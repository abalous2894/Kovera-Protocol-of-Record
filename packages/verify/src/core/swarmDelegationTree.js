/**
 * Swarm delegation tree builder — pure function extracted from swarmAccountabilityService.js.
 */

const SWARM_SESSION_ID_MAX = 256;

/**
 * @param {string} sessionId
 */
export function normalizeSessionId(sessionId) {
  const s = String(sessionId || '').trim();
  if (!s || s.length > SWARM_SESSION_ID_MAX) return null;
  return s;
}

/**
 * @param {object} payload
 */
export function extractSessionIdFromPayload(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const p = /** @type {Record<string, unknown>} */ (payload);
  return normalizeSessionId(p.aegisSessionId ?? p.aegis_session_id ?? p.sessionId ?? null);
}

/**
 * Build delegation tree from in-memory ledger rows (no Mongo).
 * @param {string} rootSessionId
 * @param {Array<object>} rows
 */
export function buildSwarmDelegationTreeFromRows(rootSessionId, rows) {
  const root = normalizeSessionId(rootSessionId);
  if (!root) {
    return { ok: false, error: 'INVALID_ROOT_SESSION_ID', rootSessionId: '', nodes: [], edges: [] };
  }

  /** @type {Map<string, object>} */
  const nodes = new Map();
  /** @type {Array<{ from: string, to: string, type: string }>} */
  const edges = [];

  const ensureNode = (sessionId, seed = {}) => {
    const sid = normalizeSessionId(sessionId);
    if (!sid) return null;
    if (!nodes.has(sid)) {
      nodes.set(sid, {
        sessionId: sid,
        parentSessionId: null,
        rootSessionId: root,
        agentIds: new Set(),
        passportJtis: new Set(),
        entryCount: 0,
        firstSeen: null,
        lastSeen: null,
        anchorEntryHash: null,
        isRoot: sid === root,
        ...seed,
      });
    }
    return nodes.get(sid);
  };

  ensureNode(root, { isRoot: true, rootSessionId: root });

  for (const row of rows) {
    const payload = row.payload && typeof row.payload === 'object' ? row.payload : {};
    const sid = extractSessionIdFromPayload(payload);
    if (!sid) continue;

    const node = ensureNode(sid);
    if (!node) continue;

    node.entryCount += 1;
    node.agentIds.add(String(row.agentId || ''));
    const ts =
      row.timestamp instanceof Date
        ? row.timestamp.toISOString()
        : String(row.timestamp || row.entryHash ? '' : '');
    const tsVal = ts || (payload.parentEntryHash ? '1970-01-01T00:00:00.000Z' : '');
    if (tsVal && (!node.firstSeen || tsVal < node.firstSeen)) {
      node.firstSeen = tsVal;
      if (payload.parentEntryHash) node.anchorEntryHash = String(payload.parentEntryHash);
    }
    if (tsVal && (!node.lastSeen || tsVal > node.lastSeen)) {
      node.lastSeen = tsVal;
    }

    const pw = payload.passportWitness;
    if (pw && typeof pw === 'object' && pw.jti) {
      node.passportJtis.add(String(pw.jti));
    }

    const parentSid = normalizeSessionId(payload.parentSessionId);
    if (parentSid && parentSid !== sid) {
      node.parentSessionId = parentSid;
      ensureNode(parentSid);
      const edgeKey = `${parentSid}->${sid}`;
      if (!edges.some((e) => `${e.from}->${e.to}` === edgeKey)) {
        edges.push({ from: parentSid, to: sid, type: 'A2A_DELEGATION' });
      }
    }
  }

  const serializedNodes = [...nodes.values()].map((n) => ({
    sessionId: n.sessionId,
    parentSessionId: n.parentSessionId,
    rootSessionId: n.rootSessionId || root,
    agentIds: [...n.agentIds].filter(Boolean).sort(),
    passportJtis: [...n.passportJtis].sort(),
    entryCount: n.entryCount,
    firstSeen: n.firstSeen,
    lastSeen: n.lastSeen,
    anchorEntryHash: n.anchorEntryHash,
    isRoot: n.isRoot === true,
  }));

  return {
    ok: true,
    schema: 'aevesa.swarm.delegation-tree/v1',
    rootSessionId: root,
    nodeCount: serializedNodes.length,
    edgeCount: edges.length,
    nodes: serializedNodes,
    edges,
  };
}
