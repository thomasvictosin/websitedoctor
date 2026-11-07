import { NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { agentDiagnosticSchema } from "@/lib/agent-diagnostics";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";
import { deriveEvidenceSignals, selectRelevantTools } from "@/lib/ai/tool-registry";
import { proposeStandingEligibleRepair } from "@/lib/repair-authorization";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> },
) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const body = await readBoundedJson(request, 120_000);
  if (body === null) return NextResponse.json({ error: "Diagnostic payload is invalid or too large." }, { status: 413 });
  const parsed = agentDiagnosticSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Diagnostic payload is invalid." }, { status: 400 });

  const website = await db.website.findUnique({
    where: { id: auth.agent.websiteId },
    select: {
      name: true,
      url: true,
      checks: { orderBy: { checkedAt: "desc" }, take: 1 },
    },
  });
  if (!website) return NextResponse.json({ error: "Registered website not found." }, { status: 404 });

  const scanSession = await db.scanSession.create({
    data: { websiteId: auth.agent.websiteId, scanType: "wordpress", initiatedBy: "wordpress_agent" },
  });
  const diagnosticResult = await db.diagnosticResult.create({
    data: {
      scanSessionId: scanSession.id,
      category: "wordpress",
      status: "completed",
      summary: {
        collectedAt: parsed.data.collectedAt,
        site: parsed.data.site,
        pluginCount: parsed.data.plugins.length,
        issueCount: parsed.data.issues.length,
      },
    },
  });
  await db.wordPressAgent.update({
    where: { id: agentId },
    data: {
      diagnostics: parsed.data,
      wpVersion: parsed.data.site.wpVersion,
      phpVersion: parsed.data.site.phpVersion,
      ...(parsed.data.site.pluginVersion ? { pluginVersion: parsed.data.site.pluginVersion } : {}),
      lastSeenAt: new Date(),
    },
  });

  const centralCheck = website.checks[0];
  const centralAvailability = centralCheck ? {
    checkedAt: centralCheck.checkedAt.toISOString(),
    available: centralCheck.available,
    statusCode: centralCheck.statusCode,
    responseTime: centralCheck.responseTime,
    error: centralCheck.error,
  } : null;
  for (const issue of parsed.data.issues) {
    const fingerprint = `wp:${issue.fingerprint}`;
    const evidence = {
      collectedAt: parsed.data.collectedAt,
      finding: issue,
      site: parsed.data.site,
      centralAvailability,
      ...( /plugin|theme|conflict|update|extension/i.test(`${issue.fingerprint} ${issue.title} ${issue.description}`)
        ? { plugins: parsed.data.plugins.slice(0, 100) }
        : {}),
      ...( /cron|scheduled|schedule|event/i.test(`${issue.fingerprint} ${issue.title} ${issue.description}`)
        ? { cron: {
          cronDisabled: parsed.data.site.cronDisabled,
          overdueCronCount: parsed.data.site.overdueCronCount,
          scheduledTasks: parsed.data.scheduledTasks ?? [],
          history: parsed.data.cronHistory ?? [],
        } }
        : {}),
      ...(issue.fingerprint.startsWith("php-fatal:") ? { fatalErrors: parsed.data.fatalErrors ?? [], plugins: parsed.data.plugins.slice(0, 100) } : {}),
      ...(issue.fingerprint.startsWith("php-log:") ? { phpErrors: parsed.data.phpErrors ?? [], phpErrorLog: parsed.data.phpErrorLog ?? null } : {}),
      ...(issue.fingerprint.startsWith("integrity:") ? { integrity: parsed.data.integrity ?? null } : {}),
      ...(issue.fingerprint.startsWith("cron-failed:") ? { failedTasks: (parsed.data.cronHistory ?? []).filter((task) => task.status === "failed") } : {}),
      ...( /plugin|theme|conflict/i.test(`${issue.fingerprint} ${issue.title} ${issue.description}`)
        ? { conflictTesting: parsed.data.conflictTesting ?? null }
        : {}),
      ...(parsed.data.authorizedLogExcerpt && /error|fatal|exception|warning|stack|log/i.test(`${issue.fingerprint} ${issue.title} ${issue.description}`)
        ? { authorizedLogExcerpt: parsed.data.authorizedLogExcerpt }
        : {}),
    };
    const tools = selectRelevantTools(deriveEvidenceSignals("wordpress_agent", evidence, issue));
    const toolIds = tools.map((tool) => tool.id);
    const storedIssue = await db.issue.upsert({
      where: { websiteId_fingerprint: { websiteId: auth.agent.websiteId, fingerprint } },
      create: {
        websiteId: auth.agent.websiteId,
        fingerprint,
        title: issue.title,
        description: issue.description,
        severity: issue.severity,
        source: "wordpress_plugin",
        evidence,
        toolIds,
      },
      update: {
        title: issue.title,
        description: issue.description,
        severity: issue.severity,
        lastSeenAt: new Date(),
        evidence,
        toolIds,
      },
      select: { id: true },
    });
    await db.evidenceRecord.create({
      data: {
        diagnosticResultId: diagnosticResult.id,
        issueId: storedIssue.id,
        kind: "wordpress_finding",
        source: "wordpress_agent",
        sensitivity: evidence.authorizedLogExcerpt ? "sensitive" : "normal",
        payload: evidence,
        collectedAt: new Date(parsed.data.collectedAt),
      },
    });
    await db.issue.updateMany({
      where: {
        websiteId: auth.agent.websiteId,
        fingerprint,
        status: "resolved",
      },
      data: { status: "open", resolvedAt: null },
    });
    await proposeStandingEligibleRepair(auth.agent.websiteId, storedIssue.id);
  }
  const activeFingerprints = parsed.data.issues.map((issue) => `wp:${issue.fingerprint}`);
  const logEvidenceUnavailable = parsed.data.phpErrorLog?.status !== "readable";
  await db.issue.updateMany({
    where: {
      websiteId: auth.agent.websiteId,
      source: "wordpress_plugin",
      status: { in: ["open", "acknowledged"] },
      ...(logEvidenceUnavailable ? { NOT: { fingerprint: { startsWith: "wp:php-log:" } } } : {}),
      ...(activeFingerprints.length > 0 ? { fingerprint: { notIn: activeFingerprints } } : {}),
    },
    data: { status: "resolved", resolvedAt: new Date() },
  });
  await db.scanSession.update({
    where: { id: scanSession.id },
    data: { status: "completed", completedAt: new Date() },
  });
  return NextResponse.json({
    ok: true,
    issueCount: parsed.data.issues.length,
    selectedTools: [...new Set(parsed.data.issues.flatMap((issue) =>
      selectRelevantTools(deriveEvidenceSignals("wordpress_agent", {
        site: parsed.data.site,
        plugins: parsed.data.plugins,
        cron: {
          cronDisabled: parsed.data.site.cronDisabled,
          overdueCronCount: parsed.data.site.overdueCronCount,
          scheduledTasks: parsed.data.scheduledTasks ?? [],
          history: parsed.data.cronHistory ?? [],
        },
        authorizedLogExcerpt: parsed.data.authorizedLogExcerpt,
      }, issue)).map((tool) => tool.id)))],
    aiAnalysis: "run by the central application when requested; plugin does not run an AI model",
  });
}
