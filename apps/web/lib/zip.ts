import { inflateRawSync } from "node:zlib";

/**
 * Minimal, defensive ZIP reader for scanning uploaded plugin and theme
 * packages. Reads the central directory only, refuses ZIP64, encrypted
 * entries, symbolic links and unsafe paths, and caps how much is inflated.
 */

export type ZipEntry = { name: string; compressedSize: number; size: number; method: number; offset: number; directory: boolean };
export class ZipError extends Error {}

const MAX_ENTRIES = 30_000;
const MAX_TOTAL_SIZE = 400 * 1024 * 1024;

export function unsafeZipPath(name: string) {
  return !name || name.includes("\0") || name.includes("\\") || name.startsWith("/") || /^[A-Za-z]:/.test(name) || name.split("/").some((part) => part === "..");
}

export function listZip(buffer: Buffer): ZipEntry[] {
  const searchFrom = Math.max(0, buffer.length - 65_557);
  let eocd = -1;
  for (let index = buffer.length - 22; index >= searchFrom; index -= 1) {
    if (buffer.readUInt32LE(index) === 0x06054b50) { eocd = index; break; }
  }
  if (eocd < 0) throw new ZipError("This is not a ZIP file (or it is damaged).");
  const count = buffer.readUInt16LE(eocd + 10);
  const cdSize = buffer.readUInt32LE(eocd + 12);
  const cdOffset = buffer.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) throw new ZipError("ZIP64 archives are not supported; re-create the zip with a standard tool.");
  if (count > MAX_ENTRIES) throw new ZipError(`The package has more than ${MAX_ENTRIES} files.`);
  if (cdOffset + cdSize > buffer.length) throw new ZipError("The ZIP directory is damaged.");
  const entries: ZipEntry[] = [];
  let pointer = cdOffset;
  let total = 0;
  for (let index = 0; index < count; index += 1) {
    if (pointer + 46 > buffer.length || buffer.readUInt32LE(pointer) !== 0x02014b50) throw new ZipError("The ZIP directory is damaged.");
    const flags = buffer.readUInt16LE(pointer + 8);
    const method = buffer.readUInt16LE(pointer + 10);
    const compressedSize = buffer.readUInt32LE(pointer + 20);
    const size = buffer.readUInt32LE(pointer + 24);
    const nameLength = buffer.readUInt16LE(pointer + 28);
    const extraLength = buffer.readUInt16LE(pointer + 30);
    const commentLength = buffer.readUInt16LE(pointer + 32);
    const external = buffer.readUInt32LE(pointer + 38);
    const offset = buffer.readUInt32LE(pointer + 42);
    const name = buffer.subarray(pointer + 46, pointer + 46 + nameLength).toString("utf8");
    pointer += 46 + nameLength + extraLength + commentLength;
    if (flags & 0x1) throw new ZipError(`${name} is encrypted; upload an unencrypted package.`);
    if (((external >>> 16) & 0o170000) === 0o120000) throw new ZipError(`${name} is a symbolic link, which is not allowed in a package.`);
    if (unsafeZipPath(name)) throw new ZipError(`The package contains an unsafe path: ${name.slice(0, 120)}`);
    if (method !== 0 && method !== 8) throw new ZipError(`${name} uses an unsupported compression method.`);
    total += size;
    if (total > MAX_TOTAL_SIZE) throw new ZipError("The package unpacks to more than 400 MB.");
    entries.push({ name, compressedSize, size, method, offset, directory: name.endsWith("/") });
  }
  return entries;
}

/** Inflate one entry (at most maxBytes; larger entries throw). */
export function readZipEntry(buffer: Buffer, entry: ZipEntry, maxBytes = 8 * 1024 * 1024): Buffer {
  if (entry.size > maxBytes) throw new ZipError(`${entry.name} is larger than ${Math.round(maxBytes / 1024 / 1024)} MB.`);
  const local = entry.offset;
  if (local + 30 > buffer.length || buffer.readUInt32LE(local) !== 0x04034b50) throw new ZipError(`${entry.name} is damaged.`);
  const start = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
  const data = buffer.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(data);
  return inflateRawSync(data, { maxOutputLength: Math.max(entry.size, 1) });
}
