import { createConnection } from "node:net";
import { posix } from "node:path";
import { timingSafeEqual } from "node:crypto";
import { Client, type SFTPWrapper, type Stats } from "ssh2";
import { resolvePublicAddresses } from "./monitor.ts";
import { isValidHostingHostname, validateHostingOperationTarget } from "./hosting.ts";

type SftpPathOperations = Pick<SFTPWrapper, "realpath" | "lstat">;
type SftpInspectionOperations = Pick<SFTPWrapper, "realpath" | "lstat" | "opendir" | "readdir" | "close">;

function getSftpStats(operations: SftpPathOperations, path: string): Promise<Stats> {
  return new Promise((resolve, reject) => {
    operations.lstat(path, (error, stats) => error ? reject(error) : resolve(stats));
  });
}

function getSftpRealpath(operations: SftpPathOperations, path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    operations.realpath(path, (error, resolved) => error ? reject(error) : resolve(resolved));
  });
}

function expectedFingerprintBytes(value: string): Buffer {
  const normalized = value.trim();
  if (!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(normalized)) {
    throw new Error("Provide the server's SHA256 SSH host-key fingerprint.");
  }
  const bytes = Buffer.from(normalized.slice("SHA256:".length), "base64");
  if (bytes.length !== 32) throw new Error("The SSH host-key fingerprint is malformed.");
  return bytes;
}

export function matchesSshHostFingerprint(actualHex: string, expected: string): boolean {
  let expectedBytes: Buffer;
  try {
    expectedBytes = expectedFingerprintBytes(expected);
  } catch {
    return false;
  }
  if (!/^[a-f0-9]{64}$/i.test(actualHex)) return false;
  return timingSafeEqual(Buffer.from(actualHex, "hex"), expectedBytes);
}

async function assertNoSymlinkPath(operations: SftpPathOperations, path: string, expectDirectory: boolean): Promise<void> {
  const normalized = posix.normalize(path);
  if (normalized !== path || !normalized.startsWith("/") || normalized === "/") {
    throw new Error("The remote site root must be a normalized absolute path other than filesystem root.");
  }
  let current = "/";
  const segments = normalized.split("/").filter(Boolean);
  for (const [index, segment] of segments.entries()) {
    current = posix.join(current, segment);
    const stats = await getSftpStats(operations, current);
    if (stats.isSymbolicLink()) throw new Error("The configured site root contains a symbolic link.");
    if (index < segments.length - 1 && !stats.isDirectory()) {
      throw new Error("The configured site root contains a non-directory path component.");
    }
    if (index === segments.length - 1 && expectDirectory && !stats.isDirectory()) {
      throw new Error("The configured site root is not a directory.");
    }
  }
}

export async function verifySftpDocumentRoot(
  operations: SftpPathOperations,
  configuredRoot: string,
): Promise<string> {
  const validation = validateHostingOperationTarget(configuredRoot, configuredRoot);
  if (!validation.ok || validation.normalized !== configuredRoot) {
    throw new Error(validation.message ?? "The configured site root is not a canonical absolute path.");
  }
  await assertNoSymlinkPath(operations, configuredRoot, true);
  const resolvedRoot = await getSftpRealpath(operations, configuredRoot);
  if (resolvedRoot !== configuredRoot) {
    throw new Error("The remote server resolved the configured site root to a different path.");
  }
  return resolvedRoot;
}

export async function inspectSftpTargetPath(
  operations: SftpPathOperations,
  configuredRoot: string,
  target: string,
): Promise<{ path: string; exists: boolean; stats: Stats | null }> {
  const validation = validateHostingOperationTarget(target, configuredRoot);
  if (!validation.ok || !validation.normalized) {
    throw new Error(validation.message ?? "The target path is outside the configured website root.");
  }
  const path = validation.normalized;
  const relative = posix.relative(configuredRoot, path);
  let current = configuredRoot;
  const segments = relative ? relative.split("/") : [];
  for (const [index, segment] of segments.entries()) {
    current = posix.join(current, segment);
    try {
      const stats = await getSftpStats(operations, current);
      if (stats.isSymbolicLink()) throw new Error("The target path contains a symbolic link.");
      if (index < segments.length - 1 && !stats.isDirectory()) {
        throw new Error("The target path contains a non-directory path component.");
      }
      if (index === segments.length - 1) return { path, exists: true, stats };
    } catch (error) {
      if (index !== segments.length - 1 || !(error instanceof Error) || !/no such file|not found/i.test(error.message)) {
        throw error;
      }
      return { path, exists: false, stats: null };
    }
  }
  return { path, exists: true, stats: await getSftpStats(operations, configuredRoot) };
}

export async function inspectSftpTarget(
  sftp: SftpInspectionOperations,
  configuredRoot: string,
  target: string,
  operation: "inspect_directory_structure" | "inspect_file_permissions",
): Promise<Record<string, unknown>> {
  const inspected = await inspectSftpTargetPath(sftp, configuredRoot, target);
  if (!inspected.exists || !inspected.stats) throw new Error("The requested remote target does not exist.");

  if (operation === "inspect_file_permissions") {
    return {
      path: inspected.path,
      mode: `0${(inspected.stats.mode & 0o7777).toString(8)}`,
      kind: inspected.stats.isDirectory() ? "directory" : inspected.stats.isFile() ? "file" : "other",
    };
  }
  if (!inspected.stats.isDirectory()) throw new Error("Directory inspection requires a directory target.");
  const { entries, truncated } = await readDirectoryEntries(sftp, inspected.path);
  return {
    path: inspected.path,
    entries: entries
      .map(({ filename, attrs }) => ({
        name: filename,
        kind: attrs.isSymbolicLink() ? "symlink" : attrs.isDirectory() ? "directory" : attrs.isFile() ? "file" : "other",
        mode: `0${(attrs.mode & 0o7777).toString(8)}`,
      })),
    truncated,
  };
}

function openDirectory(sftp: SftpInspectionOperations, path: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    sftp.opendir(path, (error, handle) => error ? reject(error) : resolve(handle));
  });
}

function readDirectoryChunk(sftp: SftpInspectionOperations, handle: Buffer): Promise<Array<{ filename: string; attrs: Stats }>> {
  return new Promise((resolve, reject) => {
    sftp.readdir(handle, (error, entries) => error ? reject(error) : resolve(entries));
  });
}

function closeDirectory(sftp: SftpInspectionOperations, handle: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.close(handle, (error) => error ? reject(error) : resolve());
  });
}

function isSftpEndOfDirectory(error: unknown): boolean {
  return error instanceof Error
    && "code" in error
    && error.code === "EOF";
}

async function readDirectoryEntries(
  sftp: SftpInspectionOperations,
  path: string,
): Promise<{ entries: Array<{ filename: string; attrs: Stats }>; truncated: boolean }> {
  const handle = await openDirectory(sftp, path);
  const entries: Array<{ filename: string; attrs: Stats }> = [];
  let truncated = false;
  try {
    while (entries.length <= 200) {
      let chunk: Array<{ filename: string; attrs: Stats }>;
      try {
        chunk = await readDirectoryChunk(sftp, handle);
      } catch (error) {
        if (isSftpEndOfDirectory(error)) break;
        throw error;
      }
      if (chunk.length === 0) break;
      const remaining = 201 - entries.length;
      entries.push(...chunk.slice(0, remaining));
      if (entries.length > 200) {
        truncated = true;
        entries.length = 200;
        break;
      }
    }
  } catch (error) {
    await closeDirectory(sftp, handle);
    throw error;
  }
  await closeDirectory(sftp, handle);
  return {
    entries: entries.filter(({ filename }) => filename !== "." && filename !== ".."),
    truncated,
  };
}

function connectClient(input: {
  hostname: string;
  port: number;
  username: string;
  authMethod: "key" | "password";
  secret: string;
  hostKeyFingerprint: string;
  address: string;
}): Promise<Client> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: input.address, port: input.port });
    const client = new Client();
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      client.destroy();
      reject(error);
    };
    const timer = setTimeout(() => fail(new Error("SFTP connection timed out.")), 12_000);
    socket.once("error", fail);
    client.once("error", fail);
    client.once("ready", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(client);
    });
    socket.once("connect", () => {
      client.connect({
        sock: socket,
        host: input.hostname,
        port: input.port,
        username: input.username,
        ...(input.authMethod === "key" ? { privateKey: input.secret } : { password: input.secret }),
        hostHash: "sha256",
        hostVerifier: (fingerprint: string) => matchesSshHostFingerprint(fingerprint, input.hostKeyFingerprint),
        readyTimeout: 10_000,
        keepaliveInterval: 5_000,
        keepaliveCountMax: 2,
      });
    });
  });
}

function openSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((error, sftp) => error ? reject(error) : resolve(sftp));
  });
}

function closeSftp(client: Client): void {
  client.end();
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<T>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    }),
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

type PinnedSftpInput = {
  hostname: string;
  port: number;
  username: string;
  authMethod: "key" | "password";
  secret: string;
  hostKeyFingerprint: string;
  documentRoot: string;
};

async function openVerifiedSftp(input: PinnedSftpInput): Promise<{ client: Client; sftp: SFTPWrapper; root: string }> {
  if (!isValidHostingHostname(input.hostname)) throw new Error("Enter a public IP address or valid public hostname.");
  if (!input.secret.trim()) throw new Error("An SFTP credential is required.");
  expectedFingerprintBytes(input.hostKeyFingerprint);
  if (!input.username.trim()) throw new Error("An SFTP username is required.");

  const addresses = await resolvePublicAddresses(input.hostname);
  let lastError: Error | null = null;
  for (const address of addresses) {
    let client: Client;
    try {
      client = await connectClient({
        ...input,
        hostname: input.hostname.trim(),
        port: input.port,
        username: input.username.trim(),
        authMethod: input.authMethod,
        address: address.address,
      });
    } catch (error) {
      lastError = error instanceof Error ? error : new Error("SFTP connection failed.");
      continue;
    }
    try {
      const sftp = await withTimeout(openSftp(client), 10_000, "SFTP subsystem startup timed out.");
      const root = await withTimeout(
        verifySftpDocumentRoot(sftp, input.documentRoot),
        10_000,
        "Remote document-root verification timed out.",
      );
      return { client, sftp, root };
    } catch (error) {
      closeSftp(client);
      throw error;
    }
  }
  throw lastError ?? new Error("The SFTP host could not be reached.");
}

export async function testPinnedSftpConnection(input: PinnedSftpInput): Promise<{ root: string; hostKeyFingerprint: string }> {
  const connected = await openVerifiedSftp(input);
  closeSftp(connected.client);
  return { root: connected.root, hostKeyFingerprint: input.hostKeyFingerprint.trim() };
}

export async function inspectPinnedSftpTarget(input: PinnedSftpInput & {
  target: string;
  operation: "inspect_directory_structure" | "inspect_file_permissions";
}): Promise<Record<string, unknown>> {
  const connected = await openVerifiedSftp(input);
  try {
    return await withTimeout(
      inspectSftpTarget(connected.sftp, connected.root, input.target, input.operation),
      15_000,
      "SFTP inspection timed out.",
    );
  } finally {
    closeSftp(connected.client);
  }
}
