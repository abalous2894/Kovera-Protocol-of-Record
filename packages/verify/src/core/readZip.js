/**
 * Minimal read-only ZIP extractor (STORE + DEFLATE) — node:fs + node:zlib only.
 */

import { inflateRawSync } from 'node:zlib';

/**
 * @param {Buffer} buf
 * @returns {Map<string, Buffer>}
 */
export function readZipEntriesFromBuffer(buf) {
  const eocdOffset = findEndOfCentralDirectory(buf);
  if (eocdOffset < 0) {
    throw new Error('Invalid ZIP: end of central directory not found');
  }

  const entryCount = buf.readUInt16LE(eocdOffset + 10);
  const centralDirOffset = buf.readUInt32LE(eocdOffset + 16);
  /** @type {Map<string, Buffer>} */
  const entries = new Map();

  let offset = centralDirOffset;
  for (let i = 0; i < entryCount; i += 1) {
    if (buf.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error('Invalid ZIP: bad central directory header');
    }
    const compression = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const uncompressedSize = buf.readUInt32LE(offset + 24);
    const nameLength = buf.readUInt16LE(offset + 28);
    const extraLength = buf.readUInt16LE(offset + 30);
    const commentLength = buf.readUInt16LE(offset + 32);
    const localHeaderOffset = buf.readUInt32LE(offset + 42);
    const name = buf.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');
    offset += 46 + nameLength + extraLength + commentLength;

    if (name.endsWith('/')) continue;

    const localNameLength = buf.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = buf.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const compressed = buf.subarray(dataStart, dataStart + compressedSize);
    const data = decompressZipEntry(compression, compressed, uncompressedSize);
    entries.set(normalizeZipPath(name), data);
  }

  return entries;
}

/**
 * @param {string} zipPath
 * @param {import('node:fs').readFileSync} readFileSync
 */
export function readZipEntriesFromFile(zipPath, readFileSync) {
  const buf = readFileSync(zipPath);
  const entries = readZipEntriesFromBuffer(buf);
  const prefix = detectArt12PackPrefix([...entries.keys()]);
  if (!prefix) return entries;

  /** @type {Map<string, Buffer>} */
  const stripped = new Map();
  for (const [name, data] of entries) {
    if (name.startsWith(prefix)) {
      stripped.set(name.slice(prefix.length), data);
    } else {
      stripped.set(name, data);
    }
  }
  return stripped;
}

/**
 * Art. 12 exports nest files under art12-conformity-pack/.
 * @param {string[]} paths
 */
function detectArt12PackPrefix(paths) {
  if (paths.includes('manifest.json')) return '';
  const candidate = 'art12-conformity-pack/';
  if (paths.some((p) => p.startsWith(candidate))) return candidate;
  return '';
}

/**
 * @param {string} name
 */
function normalizeZipPath(name) {
  return name.replace(/\\/g, '/');
}

/**
 * @param {Buffer} buf
 */
function findEndOfCentralDirectory(buf) {
  const minOffset = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= minOffset; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      return i;
    }
  }
  return -1;
}

/**
 * @param {number} compression
 * @param {Buffer} compressed
 * @param {number} uncompressedSize
 */
function decompressZipEntry(compression, compressed, uncompressedSize) {
  if (compression === 0) {
    return Buffer.from(compressed);
  }
  if (compression === 8) {
    return inflateRawSync(compressed, { maxOutputLength: Math.max(uncompressedSize, compressed.length * 20) });
  }
  throw new Error(`Unsupported ZIP compression method: ${compression}`);
}
