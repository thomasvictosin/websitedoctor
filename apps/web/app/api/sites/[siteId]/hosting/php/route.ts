import { NextResponse } from "next/server";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { decryptHostingSecret } from "@/lib/hosting";
import {
  checkPhpCompatibility,
  cpanelClient,
  CpanelError,
  matchVhost,
  phpId,
  phpLabel,
  pluginConfirmation,
  readPhpState,
  switchPhpVersion,
  type PhpSwitchResult,
  type PluginReport,
} from "@/lib/hosting-php";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { requestSourceHash } from "@/lib/rate-limit";
import { readBoundedJson } from "@/lib/request-json";
import { fetchPageAsBrowser } from "@/lib/security-probe";

export const runtime = "nodejs";
export const maxDuration = 180;

/** One switch per connection at a time in this process; the stored "running" marker covers other processes. */
const running = new Set<string>();
const RUNNING_MARKER_MS = 5 * 60_000;

type StoredChange = Omit<PhpSwitchResult, "baseline" | "after"> & { baseline?: unknown; after?: unknown };
type Metadata = Record<string, unknown> & { cpanel?: { vhost?: string }; phpChange?: StoredChange | { status: "running"; startedAt: string; to: { id: string; label: string } } };

async function loadSite(request: Request, siteId: string, sameOrigin: boolean) {
  const authorization = await authorizeOwnerRequest(request, sameOrigin);
  if ("response" in authorization) return { response: authorization.response } as const;
  const website = await db.website.findFirst({
    where: ownedWebsiteWhere(authorization.ownerId, siteId),
    select: { id: true, url: true, organizationId: true, wordpressAgent: { select: { diagnostics: true, revokedAt: true } } },
  });
  if (!website) return { response: NextResponse.json({ error: "Website not found." }, { status: 404 }) } as const;
  const connections = await db.hostingConnection.findMany({
    where: { websiteId: website.id, ownerId: authorization.ownerId, connectionMethod: "cpanel_uapi", status: "connected" },
    select: { id: true, hostname: true, port: true, username: true, connectionMetadata: true, credential: { select: { encryptedValue: true } } },
    orderBy: { createdAt: "desc" },
  });
  const agent = website.wordpressAgent && !website.wordpressAgent.revokedAt ? website.wordpressAgent.diagnostics as PluginReport : null;
  return { website, connections, report: agent ?? null, ownerId: authorization.ownerId } as const;
}

function clientFor(connection: { hostname: string; port: number | null; username: string | null; credential: { encryptedValue: string } | null }) {
  if (!connection.credential?.encryptedValue || !connection.username) throw new CpanelError("This cPanel connection has no stored token; add the connection again.", 409);
  return cpanelClient({ hostname: connection.hostname, port: connection.port ?? 2083, username: connection.username, token: decryptHostingSecret(connection.credential.encryptedValue) });
}

function metadataOf(value: unknown): Metadata {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Metadata : {};
}

function errorResponse(error: unknown) {
  if (error instanceof CpanelError) return NextResponse.json({ error: error.message }, { status: error.status });
  throw error;
}

export async function GET(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const loaded = await loadSite(request, siteId, false);
  if ("response" in loaded) return loaded.response;
  const wanted = new URL(request.url).searchParams.get("connectionId");
  const connections = loaded.connections.filter((connection) => !wanted || connection.id === wanted);
  const plugin = loaded.report?.site?.phpVersion ? { phpVersion: loaded.report.site.phpVersion, reportedAt: loaded.report.collectedAt ?? null } : null;
  if (!connections.length) {
    return NextResponse.json({ connections: [], plugin, hint: "Add a cPanel hosting connection (Settings → Hosting connection) to switch PHP from here." }, { headers: { "cache-control": "no-store" } });
  }
  const results = await Promise.all(connections.map(async (connection) => {
    const metadata = metadataOf(connection.connectionMetadata);
    const lastChange = metadata.phpChange && metadata.phpChange.status !== "running" ? metadata.phpChange as StoredChange : null;
    const base = {
      connectionId: connection.id,
      hostname: connection.hostname,
      running: running.has(connection.id) || (metadata.phpChange?.status === "running" && Date.now() - Date.parse(metadata.phpChange.startedAt) < RUNNING_MARKER_MS),
      lastChange: lastChange ? { ...lastChange, baseline: undefined, after: undefined } : null,
      confirmation: pluginConfirmation(lastChange, loaded.report),
    };
    try {
      const state = await readPhpState(clientFor(connection));
      const vhost = state.vhosts.find((entry) => entry.vhost === metadata.cpanel?.vhost) ?? matchVhost(state.vhosts, loaded.website.url);
      if (!vhost) return { ...base, error: "This cPanel account no longer lists the website's domain." };
      const installedLabels = state.installed.map((option) => option.label);
      return {
        ...base,
        vhost: vhost.vhost,
        current: { id: vhost.id, label: vhost.label, inherited: vhost.inherited, phpFpm: vhost.phpFpm },
        systemDefault: phpLabel(state.systemDefault),
        installed: state.installed.map((option) => ({
          ...option,
          current: option.id === vhost.id,
          ...checkPhpCompatibility({ current: vhost.label, target: option.label, installed: installedLabels, report: loaded.report }),
        })),
      };
    } catch (error) {
      if (error instanceof CpanelError) return { ...base, error: error.message };
      throw error;
    }
  }));
  return NextResponse.json({ connections: results, plugin }, { headers: { "cache-control": "no-store" } });
}

const switchSchema = z.object({
  connectionId: z.string().min(1).max(128).optional(),
  version: z.string().trim().min(3).max(12),
  expectedCurrent: z.string().trim().max(12).optional(),
  confirm: z.literal(true),
}).strict();

async function saveChange(connectionId: string, change: Metadata["phpChange"]) {
  const current = await db.hostingConnection.findUnique({ where: { id: connectionId }, select: { connectionMetadata: true } });
  await db.hostingConnection.update({
    where: { id: connectionId },
    data: { connectionMetadata: { ...metadataOf(current?.connectionMetadata), phpChange: change } as Prisma.InputJsonValue },
  });
}

export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await params;
  const loaded = await loadSite(request, siteId, true);
  if ("response" in loaded) return loaded.response;
  const parsed = switchSchema.safeParse(await readBoundedJson(request, 2048));
  if (!parsed.success) return NextResponse.json({ error: "Send version (for example \"8.2\"), confirm: true, and connectionId when the site has several cPanel connections." }, { status: 400 });
  const targetId = phpId(parsed.data.version);
  if (!targetId) return NextResponse.json({ error: "Use a PHP version such as 8.2 (or cPanel's ea-php82)." }, { status: 400 });
  const expectedCurrent = parsed.data.expectedCurrent ? phpId(parsed.data.expectedCurrent) : null;

  const candidates = loaded.connections.filter((connection) => !parsed.data.connectionId || connection.id === parsed.data.connectionId);
  if (!candidates.length) return NextResponse.json({ error: "Connect this site's cPanel account first (Settings → Hosting connection)." }, { status: 409 });
  if (candidates.length > 1) return NextResponse.json({ error: "This site has several cPanel connections; pass connectionId." }, { status: 400 });
  const connection = candidates[0];
  const metadata = metadataOf(connection.connectionMetadata);
  if (running.has(connection.id) || (metadata.phpChange?.status === "running" && Date.now() - Date.parse(metadata.phpChange.startedAt) < RUNNING_MARKER_MS)) {
    return NextResponse.json({ error: "A PHP switch is already running for this site." }, { status: 409 });
  }

  running.add(connection.id);
  try {
    const call = clientFor(connection);
    const state = await readPhpState(call);
    const vhost = state.vhosts.find((entry) => entry.vhost === metadata.cpanel?.vhost) ?? matchVhost(state.vhosts, loaded.website.url);
    if (!vhost) return NextResponse.json({ error: "This cPanel account no longer lists the website's domain." }, { status: 404 });
    const target = phpLabel(targetId)!;
    const compatibility = checkPhpCompatibility({ current: vhost.label, target, installed: state.installed.map((option) => option.label), report: loaded.report });
    if (compatibility.blockers.length) {
      return NextResponse.json({ error: `PHP ${target} cannot be used yet: ${compatibility.blockers.join(" ")}`, blockers: compatibility.blockers, warnings: compatibility.warnings }, { status: 409 });
    }

    const audit = (action: string, details: Record<string, unknown>) => db.auditLog.create({
      data: {
        action,
        actorType: "admin",
        actorId: loaded.ownerId,
        actorUserId: loaded.ownerId,
        organizationId: loaded.website.organizationId,
        resourceType: "hosting_connection",
        resourceId: connection.id,
        sourceHash: requestSourceHash(request),
        details: { websiteId: loaded.website.id, vhost: vhost.vhost, ...details } as Prisma.InputJsonValue,
      },
    });
    await saveChange(connection.id, { status: "running", startedAt: new Date().toISOString(), to: { id: targetId, label: target } });
    await audit("hosting_php_switch_started", { from: vhost.label, to: target, warnings: compatibility.warnings });

    let result: PhpSwitchResult;
    try {
      result = await switchPhpVersion({
        call,
        vhost: vhost.vhost,
        siteUrl: loaded.website.url,
        targetId,
        expectedCurrentId: expectedCurrent,
        fetchPage: async (url) => {
          const page = await fetchPageAsBrowser(url);
          return { statusCode: page.statusCode, text: page.text, headers: page.headers as Record<string, unknown> };
        },
      });
    } catch (error) {
      await saveChange(connection.id, undefined);
      await audit("hosting_php_switch_finished", { status: "failed", error: error instanceof Error ? error.message : "unknown error" });
      throw error;
    }
    await saveChange(connection.id, { ...result, baseline: result.baseline, after: result.after });
    await audit("hosting_php_switch_finished", { status: result.status, from: result.from?.label ?? null, to: result.to.label, steps: result.steps });
    if (result.status === "verified") {
      await db.hostingConnection.update({ where: { id: connection.id }, data: { lastSuccessfulConnection: new Date() } });
    }
    return NextResponse.json({ ...result, warnings: compatibility.warnings }, { status: result.status === "blocked" ? 409 : 200 });
  } catch (error) {
    return errorResponse(error);
  } finally {
    running.delete(connection.id);
  }
}
