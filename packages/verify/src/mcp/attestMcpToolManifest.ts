import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalizeJcs } from '../core/jcs.js';
import { assertNoForbiddenKeys, normalizeUnicodeNfkc } from '../core/jcsSafeObject.js';

function sha256Utf8(input: string): string {
  return createHash('sha256').update(String(input), 'utf8').digest('hex');
}

export const ATTEST_MCP_MANIFEST_SCHEMA = 'attestmcp/tool-manifest/v1';

export class AttestMcpManifestViolation extends Error {
  readonly code = 'ATTEST_MCP_MANIFEST_VIOLATION';
  readonly serverId: string;
  readonly expectedHash: string;
  readonly observedHash: string;
  readonly toolName?: string;

  constructor(params: {
    message: string;
    serverId: string;
    expectedHash: string;
    observedHash: string;
    toolName?: string;
  }) {
    super(params.message);
    this.name = 'AttestMcpManifestViolation';
    this.serverId = params.serverId;
    this.expectedHash = params.expectedHash;
    this.observedHash = params.observedHash;
    this.toolName = params.toolName;
  }
}

export interface McpToolDefinitionLike {
  name: string;
  description?: string;
  inputSchema?: unknown;
  [key: string]: unknown;
}

export interface PinnedMcpToolEntry {
  name: string;
  descriptionHash: string;
  inputSchemaHash: string;
  compositeHash: string;
}

export interface AttestMcpToolManifest {
  schema: typeof ATTEST_MCP_MANIFEST_SCHEMA;
  serverId: string;
  version: number;
  pinnedAt: string;
  toolsListHash: string;
  tools: PinnedMcpToolEntry[];
}

function normalizeToolDescription(description: unknown): string {
  return normalizeUnicodeNfkc(String(description ?? ''));
}

function normalizeInputSchema(inputSchema: unknown): unknown {
  if (inputSchema == null) return {};
  if (typeof inputSchema !== 'object') return { _scalar: String(inputSchema) };
  return inputSchema;
}

/**
 * Canonical MCP tool definition for hash pinning (description + schema only).
 */
export function normalizeMcpToolForManifest(tool: McpToolDefinitionLike): Record<string, unknown> {
  assertNoForbiddenKeys(tool);
  const name = normalizeUnicodeNfkc(String(tool.name ?? ''));
  if (!name) throw new TypeError('MCP tool name is required');
  return {
    name,
    description: normalizeToolDescription(tool.description),
    inputSchema: normalizeInputSchema(tool.inputSchema),
  };
}

export function hashMcpToolDefinition(tool: McpToolDefinitionLike): string {
  return sha256Utf8(canonicalizeJcs(normalizeMcpToolForManifest(tool)));
}

export function buildPinnedToolEntry(tool: McpToolDefinitionLike): PinnedMcpToolEntry {
  const normalized = normalizeMcpToolForManifest(tool);
  const descriptionHash = sha256Utf8(canonicalizeJcs({ description: normalized.description }));
  const inputSchemaHash = sha256Utf8(canonicalizeJcs({ inputSchema: normalized.inputSchema }));
  const compositeHash = hashMcpToolDefinition(tool);
  return {
    name: normalized.name as string,
    descriptionHash,
    inputSchemaHash,
    compositeHash,
  };
}

/**
 * Deterministic hash over the full tools/list response (sorted by tool name).
 */
export function hashMcpToolsList(tools: McpToolDefinitionLike[]): string {
  const entries = tools
    .map((t) => buildPinnedToolEntry(t))
    .sort((a, b) => a.name.localeCompare(b.name));
  return sha256Utf8(
    canonicalizeJcs({
      schema: ATTEST_MCP_MANIFEST_SCHEMA,
      tools: entries,
    }),
  );
}

export function buildAttestMcpManifest(
  serverId: string,
  tools: McpToolDefinitionLike[],
  options: { version?: number; pinnedAt?: string } = {},
): AttestMcpToolManifest {
  const sid = String(serverId ?? '').trim();
  if (!sid) throw new TypeError('serverId is required');
  const pinnedTools = tools
    .map((t) => buildPinnedToolEntry(t))
    .sort((a, b) => a.name.localeCompare(b.name));
  return {
    schema: ATTEST_MCP_MANIFEST_SCHEMA,
    serverId: sid,
    version: options.version ?? 1,
    pinnedAt: options.pinnedAt ?? new Date().toISOString(),
    toolsListHash: hashMcpToolsList(tools),
    tools: pinnedTools,
  };
}

export function findPinnedTool(
  manifest: AttestMcpToolManifest,
  toolName: string,
): PinnedMcpToolEntry | null {
  const name = String(toolName ?? '').trim();
  return manifest.tools.find((t) => t.name === name) ?? null;
}

export interface AttestMcpVerifyResult {
  ok: boolean;
  pinned: boolean;
  manifest?: AttestMcpToolManifest;
  violation?: AttestMcpManifestViolation;
}

/**
 * TOFU: pin on first authorization; fail-closed on subsequent drift.
 */
export function verifyOrPinToolsList(
  serverId: string,
  tools: McpToolDefinitionLike[],
  existing: AttestMcpToolManifest | null | undefined,
): AttestMcpVerifyResult {
  const observedHash = hashMcpToolsList(tools);
  if (!existing) {
    return {
      ok: true,
      pinned: true,
      manifest: buildAttestMcpManifest(serverId, tools),
    };
  }
  if (existing.toolsListHash !== observedHash) {
    return {
      ok: false,
      pinned: false,
      manifest: existing,
      violation: new AttestMcpManifestViolation({
        message: `MCP tools/list hash drift detected for server "${serverId}" (possible tool rug-pull)`,
        serverId,
        expectedHash: existing.toolsListHash,
        observedHash,
      }),
    };
  }
  return { ok: true, pinned: false, manifest: existing };
}

/**
 * Pre-execution check: tool definition must match pinned composite hash.
 */
export function verifyToolAgainstManifest(
  manifest: AttestMcpToolManifest,
  tool: McpToolDefinitionLike,
): AttestMcpVerifyResult {
  const pinned = findPinnedTool(manifest, tool.name);
  const observed = hashMcpToolDefinition(tool);
  if (!pinned) {
    return {
      ok: false,
      pinned: false,
      manifest,
      violation: new AttestMcpManifestViolation({
        message: `Unknown MCP tool "${tool.name}" — not in pinned manifest`,
        serverId: manifest.serverId,
        expectedHash: manifest.toolsListHash,
        observedHash: observed,
        toolName: tool.name,
      }),
    };
  }
  if (pinned.compositeHash !== observed) {
    return {
      ok: false,
      pinned: false,
      manifest,
      violation: new AttestMcpManifestViolation({
        message: `MCP tool "${tool.name}" description/schema drift (rug-pull)`,
        serverId: manifest.serverId,
        expectedHash: pinned.compositeHash,
        observedHash: observed,
        toolName: tool.name,
      }),
    };
  }
  return { ok: true, pinned: false, manifest };
}

export function defaultAttestMcpRegistryDir(): string {
  const base =
    process.env.KOVERA_MCP_DATA_DIR ||
    process.env.KOVERA_ATTEST_MCP_REGISTRY_DIR ||
    path.join(process.env.HOME || process.env.USERPROFILE || '/tmp', '.config', 'sentinul');
  return path.join(base, 'attestmcp-manifests');
}

function manifestFilePath(registryDir: string, serverId: string): string {
  const safe = String(serverId).replace(/[^a-zA-Z0-9._-]/g, '_');
  return path.join(registryDir, `${safe}.json`);
}

export class AttestMcpManifestRegistry {
  readonly registryDir: string;

  constructor(registryDir?: string) {
    this.registryDir = registryDir ?? defaultAttestMcpRegistryDir();
  }

  load(serverId: string): AttestMcpToolManifest | null {
    const file = manifestFilePath(this.registryDir, serverId);
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const parsed = JSON.parse(raw) as AttestMcpToolManifest;
      if (parsed?.schema !== ATTEST_MCP_MANIFEST_SCHEMA) return null;
      return parsed;
    } catch (e: unknown) {
      const err = e as NodeJS.ErrnoException;
      if (err?.code === 'ENOENT') return null;
      throw e;
    }
  }

  save(manifest: AttestMcpToolManifest): void {
    fs.mkdirSync(this.registryDir, { recursive: true });
    const file = manifestFilePath(this.registryDir, manifest.serverId);
    fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  }

  /**
   * TOFU pin or verify tools/list — throws AttestMcpManifestViolation on drift.
   */
  assertToolsList(serverId: string, tools: McpToolDefinitionLike[]): AttestMcpToolManifest {
    const existing = this.load(serverId);
    const result = verifyOrPinToolsList(serverId, tools, existing);
    if (!result.ok || !result.manifest) {
      throw result.violation ?? new AttestMcpManifestViolation({
        message: 'AttestMCP tools/list verification failed',
        serverId,
        expectedHash: existing?.toolsListHash ?? '',
        observedHash: hashMcpToolsList(tools),
      });
    }
    if (result.pinned) {
      this.save(result.manifest);
    }
    return result.manifest;
  }

  /**
   * Pre-execution gate for tools/call (full tool definition).
   */
  assertToolCall(serverId: string, tool: McpToolDefinitionLike): void {
    const manifest = this.load(serverId);
    if (!manifest) {
      throw new AttestMcpManifestViolation({
        message: `No AttestMCP manifest pinned for server "${serverId}" — authorize tools/list first`,
        serverId,
        expectedHash: '',
        observedHash: hashMcpToolDefinition(tool),
        toolName: tool.name,
      });
    }
    const result = verifyToolAgainstManifest(manifest, tool);
    if (!result.ok) {
      throw result.violation!;
    }
  }

  /**
   * Pre-execution gate: tool name must exist in pinned manifest.
   */
  assertToolNameAllowed(serverId: string, toolName: string): void {
    const manifest = this.load(serverId);
    if (!manifest) {
      throw new AttestMcpManifestViolation({
        message: `No AttestMCP manifest pinned for server "${serverId}"`,
        serverId,
        expectedHash: '',
        observedHash: '',
        toolName,
      });
    }
    if (!findPinnedTool(manifest, toolName)) {
      throw new AttestMcpManifestViolation({
        message: `MCP tool "${toolName}" is not in the pinned manifest (possible tool laundering)`,
        serverId,
        expectedHash: manifest.toolsListHash,
        observedHash: '',
        toolName,
      });
    }
  }
}
