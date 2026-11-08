import { createHash } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { compareVersions } from "./cleanup-plan.ts";
import { CleanupError, startCleanup, type CleanupActor } from "./cleanup-service.ts";
import { db } from "./db.ts";
import { scanPackage, type PackageScan } from "./package-scan.ts";
import { loadVulnerabilityIndex } from "./vulnerabilities.ts";

/**
 * Owner-uploaded plugin/theme packages (premium plugins, vendor-patched
 * versions). Uploads arrive in 3 MB pieces (hosting caps request bodies at
 * 4.5 MB), are assembled and scanned once, and only a package that passed the
 * scan can be installed. The site downloads it piece by piece with its signed
 * credentials, checks size and SHA-256, scans it again, and installs it with
 * the previous version kept in the quarantine for automatic rollback.
 */

export const PACKAGE_CHUNK_BYTES = 3 * 1024 * 1024;
export const PACKAGE_MAX_BYTES = 80 * 1024 * 1024;
const ORG_QUOTA_BYTES = 400 * 1024 * 1024;
const KEEP_DAYS = 14;
type Json = Record<string, unknown>;
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};

export function installedSoftware(diagnostics: unknown, kind: "plugin" | "theme", target: string) {
  const data = record(diagnostics);
  if (kind === "plugin") {
    const plugin = (Array.isArray(data.plugins) ? data.plugins.map(record) : []).find((item) => item.file === target);
    return plugin ? { name: String(plugin.name ?? target), version: String(plugin.version ?? ""), source: String(plugin.source ?? "") } : null;
  }
  const theme = (Array.isArray(data.themes) ? data.themes.map(record) : []).find((item) => item.stylesheet === target);
  return theme ? { name: String(theme.name ?? target), version: String(theme.version ?? ""), source: String(theme.source ?? "") } : null;
}

export async function createPackage(input: { websiteId: string; organizationId: string; userId: string; kind: "plugin" | "theme"; target: string; fileName: string; size: number; sha256: string }) {
  if (input.size > PACKAGE_MAX_BYTES) throw new CleanupError(`Packages can be at most ${PACKAGE_MAX_BYTES / 1024 / 1024} MB.`, 413);
  await purgeOldPackages(input.organizationId);
  const used = await db.softwarePackage.aggregate({ where: { organizationId: input.organizationId, status: { in: ["uploading", "ready", "blocked", "installing"] } }, _sum: { size: true } });
  if ((used._sum.size ?? 0) + input.size > ORG_QUOTA_BYTES) throw new CleanupError("Uploaded packages use the 400 MB storage limit; delete packages you no longer need first.", 409);
  const agent = await db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true } });
  if (!installedSoftware(agent?.diagnostics, input.kind, input.target)) throw new CleanupError(`That ${input.kind} is not installed on this site (according to the latest sync).`, 404);
  const slug = input.kind === "plugin" ? input.target.split("/")[0] : input.target;
  return db.softwarePackage.create({
    data: { organizationId: input.organizationId, websiteId: input.websiteId, kind: input.kind, slug, target: input.target, fileName: input.fileName.slice(0, 200), size: input.size, sha256: input.sha256, chunkCount: Math.ceil(input.size / PACKAGE_CHUNK_BYTES), uploadedById: input.userId },
    select: { id: true, chunkCount: true },
  });
}

export async function storeChunk(packageId: string, index: number, data: Buffer) {
  const pkg = await db.softwarePackage.findUnique({ where: { id: packageId }, select: { status: true, chunkCount: true, size: true } });
  if (!pkg) throw new CleanupError("Package not found.", 404);
  if (pkg.status !== "uploading") throw new CleanupError("This package is already complete.", 409);
  if (!Number.isInteger(index) || index < 0 || index >= pkg.chunkCount) throw new CleanupError("Invalid piece number.", 400);
  const expected = index === pkg.chunkCount - 1 ? pkg.size - index * PACKAGE_CHUNK_BYTES : PACKAGE_CHUNK_BYTES;
  if (data.length !== expected) throw new CleanupError(`Piece ${index + 1} has the wrong size (${data.length} bytes, expected ${expected}).`, 400);
  const sha256 = createHash("sha256").update(data).digest("hex");
  await db.softwarePackageChunk.upsert({ where: { packageId_index: { packageId, index } }, create: { packageId, index, data: new Uint8Array(data), sha256 }, update: { data: new Uint8Array(data), sha256 } });
}

async function assemble(packageId: string) {
  const chunks = await db.softwarePackageChunk.findMany({ where: { packageId }, orderBy: { index: "asc" }, select: { index: true, data: true } });
  return { buffer: Buffer.concat(chunks.map((chunk) => Buffer.from(chunk.data))), count: chunks.length };
}

/** Check the upload is complete and intact, then scan it. */
export async function finalizePackage(packageId: string) {
  const pkg = await db.softwarePackage.findUnique({ where: { id: packageId }, include: { website: { select: { wordpressAgent: { select: { diagnostics: true } } } } } });
  if (!pkg) throw new CleanupError("Package not found.", 404);
  if (pkg.status !== "uploading") return { status: pkg.status, scan: pkg.scan as PackageScan | null };
  const { buffer, count } = await assemble(packageId);
  if (count !== pkg.chunkCount || buffer.length !== pkg.size) throw new CleanupError(`The upload is incomplete (${count} of ${pkg.chunkCount} pieces).`, 409);
  if (createHash("sha256").update(buffer).digest("hex") !== pkg.sha256) {
    await db.softwarePackage.update({ where: { id: packageId }, data: { status: "blocked", scan: { status: "blocked", blockers: ["The uploaded file is corrupted (checksum mismatch); upload it again."] } as Prisma.InputJsonValue } });
    throw new CleanupError("The uploaded file is corrupted (checksum mismatch); upload it again.", 400);
  }
  const installed = installedSoftware(pkg.website.wordpressAgent?.diagnostics, pkg.kind as "plugin" | "theme", pkg.target);
  const openVuln = await db.issue.findMany({ where: { websiteId: pkg.websiteId, source: "vulnerability_feed", status: { in: ["open", "acknowledged"] }, fingerprint: { startsWith: `vuln:${pkg.kind}-${pkg.slug}:` } }, select: { evidence: true } });
  const fixedIn = openVuln.map((issue) => record(issue.evidence).fixedIn).filter((value): value is string => typeof value === "string").sort(compareVersions).at(-1) ?? null;
  const scan = scanPackage(buffer, { kind: pkg.kind as "plugin" | "theme", target: pkg.target, installedVersion: installed?.version ?? null, fixedIn }, await loadVulnerabilityIndex());
  await db.softwarePackage.update({ where: { id: packageId }, data: { status: scan.status, scan: scan as unknown as Prisma.InputJsonValue, name: scan.name, version: scan.version } });
  return { status: scan.status, scan };
}

export async function startPackageInstall(input: { packageId: string; websiteId: string; organizationId: string; actor: CleanupActor; issueId?: string | null }) {
  const pkg = await db.softwarePackage.findFirst({ where: { id: input.packageId, websiteId: input.websiteId } });
  if (!pkg) throw new CleanupError("Package not found.", 404);
  // "installing" is allowed again when that run ended without a report (the site refuses overlapping runs anyway).
  if (!["ready", "failed", "installing"].includes(pkg.status)) throw new CleanupError(pkg.status === "blocked" ? "This package did not pass the scan, so it cannot be installed." : pkg.status === "installed" ? "This package is already installed." : "This package is not ready to install.", 409);
  const agent = await db.wordPressAgent.findFirst({ where: { websiteId: input.websiteId, revokedAt: null }, select: { diagnostics: true, lastSeenAt: true } });
  if (!agent || agent.lastSeenAt.getTime() < Date.now() - 15 * 60_000) throw new CleanupError("The WordPress plugin must be connected and online to install a package.", 409);
  const pluginVersion = String(record(record(agent.diagnostics).site).pluginVersion ?? "0");
  if (compareVersions(pluginVersion, "0.8.0") < 0) throw new CleanupError(`Installing uploaded packages needs AI Website Doctor 0.8.0 or later on the site (it reports ${pluginVersion}).`, 409);
  const installed = installedSoftware(agent.diagnostics, pkg.kind as "plugin" | "theme", pkg.target);
  if (!installed) throw new CleanupError(`The ${pkg.kind} is no longer installed on the site.`, 409);
  const name = pkg.name ?? installed.name;
  const step = {
    description: `Install the uploaded ${name} ${pkg.version} (replacing ${installed.version || "the installed version"}); the previous version is kept for rollback.`,
    operation: "install_package" as const,
    parameters: { packageId: pkg.id, kind: pkg.kind, target: pkg.target, expectedVersion: installed.version || "none", version: String(pkg.version), sha256: pkg.sha256, size: String(pkg.size), chunks: String(pkg.chunkCount) },
  };
  const started = await startCleanup({ websiteId: input.websiteId, organizationId: input.organizationId, planDigest: "package", include: [], actor: input.actor, explicit: { steps: [step], title: `Install uploaded ${name} ${pkg.version}`, issueId: input.issueId ?? undefined, mode: "maintenance" } });
  await db.softwarePackage.update({ where: { id: pkg.id }, data: { status: "installing" } });
  return started;
}

/** One piece for the site (signed agent request). */
export async function chunkForAgent(websiteId: string, packageId: string, index: number) {
  const pkg = await db.softwarePackage.findFirst({ where: { id: packageId, websiteId, status: { in: ["installing", "ready"] } }, select: { id: true } });
  if (!pkg) return null;
  return db.softwarePackageChunk.findUnique({ where: { packageId_index: { packageId, index } }, select: { data: true, sha256: true } });
}

/** Free storage: pieces of packages installed or abandoned more than two weeks ago. */
export async function purgeOldPackages(organizationId: string) {
  const cutoff = new Date(Date.now() - KEEP_DAYS * 24 * 60 * 60_000);
  const old = await db.softwarePackage.findMany({ where: { organizationId, updatedAt: { lt: cutoff }, status: { in: ["installed", "blocked", "uploading", "failed"] } }, select: { id: true } });
  if (old.length) {
    await db.softwarePackageChunk.deleteMany({ where: { packageId: { in: old.map((item) => item.id) } } });
    await db.softwarePackage.updateMany({ where: { id: { in: old.map((item) => item.id) }, status: "uploading" }, data: { status: "expired" } });
  }
}

export function describePackage(pkg: { id: string; kind: string; slug: string; target: string; name: string | null; version: string | null; fileName: string; size: number; status: string; scan: unknown; createdAt: Date }) {
  return { id: pkg.id, kind: pkg.kind, slug: pkg.slug, target: pkg.target, name: pkg.name, version: pkg.version, fileName: pkg.fileName, size: pkg.size, status: pkg.status, scan: pkg.scan ?? null, createdAt: pkg.createdAt.toISOString() };
}
