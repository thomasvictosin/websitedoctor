import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { ownedWebsiteWhere } from "@/lib/ownership";
import { boundedRepairPlan, deterministicIssueRecommendation, requiresRecoveryPoint } from "@/lib/repair-policy";
import { determineRepairRisk } from "@/lib/ai/orchestrator";
import { applyStandingRepairAuthorization, authorizeExplicitPromptRepair } from "@/lib/repair-authorization";
import { checkWebsite } from "@/lib/monitor";
import { enforceRateLimit, requestSourceHash } from "@/lib/rate-limit";
import { readBoundedJson } from "@/lib/request-json";
import { redactApiValue } from "@/lib/redaction";
import { getAiEngine } from "@/lib/ai";
import { isDiagnosisOnlyPrompt, promptExplicitlyAuthorizesRepair, promptNamesPage, validateIssueCategoryScope, validateRepairRequestScope } from "@/lib/repair-request-scope";

export const runtime = "nodejs";
const inputSchema = z.object({ prompt: z.string().trim().min(3).max(1000), issueId: z.string().min(1).max(64).optional() }).strict();
const stopWords = new Set(["please", "could", "would", "should", "can", "you", "the", "and", "for", "with", "from", "this", "that", "site", "website", "fix", "repair", "handle", "take", "care", "of", "issue", "issues", "it", "my", "on", "in", "to", "a", "an", "do", "whatever", "safely", "all", "every"]);
function tokens(value: string) { return new Set(value.toLowerCase().replace(/https?:\/\/\S+/g, " ").replace(/[^a-z0-9]+/g, " ").split(/\s+/).filter((item) => item.length > 2 && !stopWords.has(item))); }
function issuePage(issue: { diagnosis: unknown; evidence: unknown }) {
  const diagnosis = issue.diagnosis && typeof issue.diagnosis === "object" && !Array.isArray(issue.diagnosis) ? issue.diagnosis as Record<string, unknown> : {};
  const nested = diagnosis.diagnosis && typeof diagnosis.diagnosis === "object" && !Array.isArray(diagnosis.diagnosis) ? diagnosis.diagnosis as Record<string, unknown> : {};
  if (typeof nested.affectedPage === "string") return nested.affectedPage;
  const evidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence) ? issue.evidence as Record<string, unknown> : {};
  const browser = evidence.browser && typeof evidence.browser === "object" && !Array.isArray(evidence.browser) ? evidence.browser as Record<string, unknown> : {};
  const finding = browser.finding && typeof browser.finding === "object" && !Array.isArray(browser.finding) ? browser.finding as Record<string, unknown> : {};
  return typeof finding.sourcePage === "string" ? finding.sourcePage : null;
}

export async function POST(request: Request, { params }: { params: Promise<{ siteId: string }> }) {
  const authorization = await authorizeOwnerRequest(request, true);
  if ("response" in authorization) return authorization.response;
  const limited = await enforceRateLimit({ namespace: "repair-request", subject: authorization.ownerId, limit: 20, windowMs: 15 * 60_000 });
  if (limited) return limited;
  const parsed = inputSchema.safeParse(await readBoundedJson(request, 4096));
  if (!parsed.success) return NextResponse.json({ error: "Enter a repair request up to 1,000 characters." }, { status: 400 });
  const { siteId } = await params;
  const website = await db.website.findFirst({ where: ownedWebsiteWhere(authorization.ownerId, siteId), select: { id: true, name: true, url: true, organizationId: true, wordpressAgent: { select: { id: true, diagnostics: true, revokedAt: true } } } });
  if (!website) return NextResponse.json({ error: "Website not found." }, { status: 404 });
  const issues = await db.issue.findMany({ where: { websiteId: siteId, status: { in: ["open", "acknowledged"] } }, orderBy: { lastSeenAt: "desc" }, take: 100 });
  const pageList = [...new Set(issues.map((issue) => issuePage(issue)).filter((page): page is string => Boolean(page)))];
  const evidenceIssues = issues.map((issue) => ({ id: issue.id, title: issue.title, description: issue.description, fingerprint: issue.fingerprint, severity: issue.severity, page: issuePage(issue) }));
  let intent: { requestKind: "diagnose" | "recommend" | "repair_one" | "repair_multiple" | "routine_maintenance"; issueIds: string[]; scopePage: string | null; requestedOutcome: string } | null = null;
  let interpretationMode: "local_ai" | "deterministic_fallback" = "local_ai";
  if (parsed.data.issueId) {
    if (!issues.some((issue) => issue.id === parsed.data.issueId)) return NextResponse.json({ error: "The selected issue is not active on this website." }, { status: 404 });
    intent = { requestKind: /\b(diagnos|scan|check|inspect|what|why)\b/i.test(parsed.data.prompt) && !/\b(fix|repair|resolve|correct|change)\b/i.test(parsed.data.prompt) ? "diagnose" : /\b(recommend|suggest|how do i|what should)\b/i.test(parsed.data.prompt) ? "recommend" : "repair_one", issueIds: [parsed.data.issueId], scopePage: null, requestedOutcome: parsed.data.prompt };
  } else {
    try {
      intent = await getAiEngine(website.organizationId).interpretRepairRequest(parsed.data.prompt, { website: { name: website.name, url: website.url }, issues: evidenceIssues, pages: pageList });
    } catch {
      interpretationMode = "deterministic_fallback";
      const promptTokens = tokens(parsed.data.prompt);
      const ranked = issues.map((candidate) => ({ candidate, score: [...promptTokens].filter((token) => tokens(`${candidate.title} ${candidate.description} ${candidate.fingerprint.replaceAll(/[-_:]/g, " ")}`).has(token)).length }))
        .filter((item) => item.score > 0).sort((a, b) => b.score - a.score);
      const bulk = /\b(all|every|routine|maintenance|across|throughout)\b/i.test(parsed.data.prompt);
      const tied = ranked.length > 1 && ranked[0].score === ranked[1].score;
      if ((!ranked.length || (tied && !bulk)) && !/\b(diagnos|scan|check|inspect)\b/i.test(parsed.data.prompt)) {
        return NextResponse.json({ status: "needs_issue_selection", message: "The AI could not interpret the request safely. Select the issue or run diagnosis; no repair was created.", candidates: ranked.slice(0, 8).map(({ candidate }) => ({ id: candidate.id, title: candidate.title, severity: candidate.severity })) }, { status: 200, headers: { "cache-control": "no-store" } });
      }
      const selected = bulk ? ranked.slice(0, 25).map(({ candidate }) => candidate) : ranked.slice(0, 1).map(({ candidate }) => candidate);
      intent = {
        requestKind: /\b(diagnos|scan|check|inspect)\b/i.test(parsed.data.prompt) && !/\b(fix|repair|resolve|correct|change)\b/i.test(parsed.data.prompt) ? "diagnose" : /\b(recommend|suggest|how do i|what should)\b/i.test(parsed.data.prompt) ? "recommend" : bulk ? "repair_multiple" : "repair_one",
        issueIds: selected.map((issue) => issue.id),
        scopePage: pageList.find((page) => parsed.data.prompt.toLowerCase().includes(page.toLowerCase())) ?? null,
        requestedOutcome: parsed.data.prompt,
      };
    }
  }
  if (intent?.requestKind === "diagnose" && intent.issueIds.length === 0) return NextResponse.json({ status: "diagnosis_results", interpretationMode, requestKind: intent.requestKind, issues: issues.map((issue) => ({ id: issue.id, title: issue.title, description: issue.description, severity: issue.severity, page: issuePage(issue), evidence: issue.evidence, diagnosis: issue.diagnosis })) }, { headers: { "cache-control": "no-store" } });
  if (!intent || !intent.issueIds.length) return NextResponse.json({ status: "needs_issue_selection", message: "No matching active issue was identified. Run a scan or select an issue; no repair was created.", candidates: evidenceIssues.slice(0, 8) }, { status: 200, headers: { "cache-control": "no-store" } });
  if (isDiagnosisOnlyPrompt(parsed.data.prompt)) intent.requestKind = "diagnose";
  const scopeError = validateRepairRequestScope(parsed.data.prompt, intent.requestKind, intent.issueIds);
  if (scopeError) return NextResponse.json({ status: "needs_scope_clarification", message: `${scopeError} Clarify the issue or category and submit a new request.`, candidates: evidenceIssues.slice(0, 8) }, { status: 200, headers: { "cache-control": "no-store" } });
  if (!validateIssueCategoryScope(parsed.data.prompt, intent.issueIds, evidenceIssues)) return NextResponse.json({ status: "needs_scope_clarification", message: "The interpreted issue list included findings outside the category you named. No repair was created; select the relevant issues and retry.", candidates: evidenceIssues.slice(0, 8) }, { status: 200, headers: { "cache-control": "no-store" } });
  if (intent.scopePage && !promptNamesPage(parsed.data.prompt, intent.scopePage)) return NextResponse.json({ status: "needs_scope_clarification", message: "The interpreted page was not clearly named in your request. No repair was created; specify the affected page or choose the issue directly.", page: intent.scopePage }, { status: 200, headers: { "cache-control": "no-store" } });
  const selectedIssues = intent.issueIds.flatMap((id) => issues.filter((issue) => issue.id === id));
  if (selectedIssues.length !== intent.issueIds.length) return NextResponse.json({ error: "The interpreted request did not match current issues on this website." }, { status: 409 });
  const scopedIssues = intent.scopePage ? selectedIssues.filter((issue) => issuePage(issue) === intent!.scopePage) : selectedIssues;
  if (!scopedIssues.length) return NextResponse.json({ status: "needs_scope_clarification", message: "The requested page does not match the affected page in the stored evidence. No repair was created.", page: intent.scopePage }, { status: 200, headers: { "cache-control": "no-store" } });
  if (intent.requestKind === "diagnose") return NextResponse.json({ status: "diagnosis_results", interpretationMode, requestKind: intent.requestKind, issues: scopedIssues.map((issue) => ({ id: issue.id, title: issue.title, description: issue.description, severity: issue.severity, page: issuePage(issue), evidence: issue.evidence, diagnosis: issue.diagnosis })) }, { headers: { "cache-control": "no-store" } });
  if (intent.requestKind === "recommend") return NextResponse.json({ status: "recommendations", interpretationMode, requestKind: intent.requestKind, scopePage: intent.scopePage, issues: scopedIssues.map((issue) => {
    const stored = issue.diagnosis && typeof issue.diagnosis === "object" && !Array.isArray(issue.diagnosis) ? issue.diagnosis as Record<string, unknown> : {};
    const diagnosis = stored.diagnosis && typeof stored.diagnosis === "object" && !Array.isArray(stored.diagnosis) ? stored.diagnosis as Record<string, unknown> : {};
    const fix = diagnosis.recommendedFix && typeof diagnosis.recommendedFix === "object" && !Array.isArray(diagnosis.recommendedFix) ? diagnosis.recommendedFix as Record<string, unknown> : {};
    const deterministic = deterministicIssueRecommendation({ fingerprint: issue.fingerprint, title: issue.title, description: issue.description }, issue.evidence);
    return { id: issue.id, title: issue.title, severity: issue.severity, description: issue.description, recommendation: typeof fix.description === "string" ? fix.description : deterministic, recommendationSource: typeof fix.description === "string" ? "stored_ai_diagnosis" : "deterministic_evidence_rules" };
  }) }, { headers: { "cache-control": "no-store" } });
  const explicitRepairRequest = promptExplicitlyAuthorizesRepair(parsed.data.prompt);
  const replacementUrl = parsed.data.prompt.match(/https?:\/\/[^\s"'<>]+/i)?.[0]?.replace(/[),.;]+$/, "");
  if (replacementUrl) {
    try {
      const target = new URL(replacementUrl);
      if (target.origin !== new URL(website.url).origin || target.username || target.password || target.hash || target.search) throw new Error("A link replacement must be a clean URL on the same site.");
      const check = await checkWebsite(target.toString());
      if (!check.available || check.statusCode === null || check.statusCode < 200 || check.statusCode >= 300 || check.finalUrl !== target.toString()) throw new Error("The requested replacement URL did not pass the direct availability check.");
    } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Replacement URL could not be verified." }, { status: 400 }); }
  }
  const agent = website.wordpressAgent && !website.wordpressAgent.revokedAt ? website.wordpressAgent : null;
  const diagnostics = agent?.diagnostics && typeof agent.diagnostics === "object" && !Array.isArray(agent.diagnostics) ? agent.diagnostics as Prisma.JsonObject : {};
  const diagnosticSite = diagnostics.site && typeof diagnostics.site === "object" && !Array.isArray(diagnostics.site)
    ? diagnostics.site as Prisma.JsonObject
    : {};
  const candidates = scopedIssues.map((issue) => {
    const issueEvidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence)
      ? { ...(issue.evidence as Prisma.JsonObject), editablePages: Array.isArray(diagnostics.editablePages) ? diagnostics.editablePages : [], environmentType: diagnosticSite.environmentType, ...(replacementUrl ? { requestedReplacementUrl: replacementUrl } : {}) }
      : issue.evidence;
    const plan = boundedRepairPlan({ fingerprint: issue.fingerprint, title: issue.title, description: issue.description }, issueEvidence);
    const instructions = agent ? plan.instructions : { steps: [], rollbackPlan: [], requiresApproval: true as const };
    const operationIds = instructions.steps.map((step) => step.operation);
    const risk = operationIds.length ? determineRepairRisk(operationIds) : "high";
    return { issue, plan, instructions, operationIds, risk, issueEvidence };
  });
  const conflicts = new Set<string>();
  const mappedTargets = new Map<string, string>();
  for (const candidate of candidates) {
    const step = candidate.instructions.steps[0];
    if (!step) continue;
    const target = step.operation === "replace_post_link"
      ? `post:${step.parameters.postId}`
      : step.operation === "add_scoped_css_rule"
        ? `css:${step.parameters.selector}`
        : `${step.operation}:${step.parameters.plugin ?? step.parameters.stylesheet ?? "site"}`;
    const previous = mappedTargets.get(target);
    if (previous) { conflicts.add(previous); conflicts.add(candidate.issue.id); }
    else mappedTargets.set(target, candidate.issue.id);
  }
  const executableCandidates = candidates.filter((candidate) => candidate.operationIds.length > 0);
  if (executableCandidates.some((candidate) => candidate.operationIds.some((operation) => operation === "disable_plugin" || operation === "switch_theme")) && executableCandidates.length > 1) {
    for (const candidate of executableCandidates) conflicts.add(candidate.issue.id);
  }
  const uniqueCandidates = candidates.filter((candidate) => !conflicts.has(candidate.issue.id));
  const skipped = candidates.filter((candidate) => conflicts.has(candidate.issue.id)).map(({ issue }) => ({ issueId: issue.id, status: "skipped_conflict", reason: "Another selected repair overlaps the same target." }));
  const results = [];
  for (const candidate of uniqueCandidates.slice(0, 25)) {
    const { issue, plan, instructions, operationIds, risk } = candidate;
    const activeProposal = await db.repairProposal.findFirst({ where: { issueId: issue.id, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true } });
    if (activeProposal) { skipped.push({ issueId: issue.id, status: "skipped_active_repair", reason: "An active proposal already exists." }); continue; }
    const proposal = !agent && plan.candidate ? { ...plan.proposal, manualGuidance: ["The WordPress agent is disconnected, so the app cannot execute or verify this repair. Reconnect the plugin before requesting execution.", plan.candidate.description] } : plan.proposal;
    const repair = await db.$transaction(async (tx) => {
      await tx.$queryRaw`WITH advisory_lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(hashtext(${siteId}))) SELECT 1 FROM advisory_lock`;
      const existing = await tx.repairProposal.findFirst({ where: { issueId: issue.id, status: { in: ["pending_approval", "approved", "executing", "in_progress"] } }, select: { id: true } });
      if (existing) return null;
      const created = await tx.repairProposal.create({ data: { websiteId: siteId, issueId: issue.id, risk, initiatingInterface: "prompt_request", operationIds, requiredPermissions: ["manage_options"], approvalStatus: "pending", backupStatus: requiresRecoveryPoint(operationIds) ? "not_started" : "not_required", executionStatus: "not_started", verificationStatus: "not_started", rollbackStatus: "not_requested", proposal: { ...proposal, risk, instructions, executionAvailable: Boolean(agent && instructions.steps.length > 0), relevantTools: issue.toolIds, evidenceBacked: true, request: { prompt: parsed.data.prompt, requestKind: intent!.requestKind, matchedIssueId: issue.id, scopePage: intent!.scopePage, interpretationMode } } as Prisma.InputJsonValue } });
      await tx.repairEvent.create({ data: { repairId: created.id, eventType: "prompt_repair_proposed", actor: authorization.ownerId, details: { issueId: issue.id, operationIds, risk, requestKind: intent!.requestKind, interpretationMode } } });
      await tx.auditLog.create({ data: { action: "prompt_repair_proposed", actorType: "admin", actorId: authorization.ownerId, actorUserId: authorization.ownerId, organizationId: website.organizationId, resourceType: "repair", resourceId: created.id, sourceHash: requestSourceHash(request), details: { websiteId: siteId, issueId: issue.id, operationIds, requestKind: intent!.requestKind, interpretationMode } } });
      return created;
    });
    if (!repair) { skipped.push({ issueId: issue.id, status: "skipped_active_repair", reason: "Another request created an active proposal for this issue first." }); continue; }
    let autoApproved = explicitRepairRequest && await applyStandingRepairAuthorization({ repairId: repair.id, websiteId: siteId, organizationId: website.organizationId, operationIds, risk, agentId: agent?.id });
    if (!autoApproved && explicitRepairRequest && ["repair_one", "repair_multiple", "routine_maintenance"].includes(intent.requestKind)) {
      autoApproved = await authorizeExplicitPromptRepair({ repairId: repair.id, websiteId: siteId, organizationId: website.organizationId, userId: authorization.ownerId, scopePage: intent.scopePage });
    }
    const finalRepair = autoApproved ? await db.repairProposal.findUnique({ where: { id: repair.id } }) : repair;
    results.push({ issueId: issue.id, title: issue.title, repairId: repair.id, operationIds, risk, status: autoApproved ? "queued" : operationIds.length ? "requires_approval" : "guidance_only", repair: finalRepair });
  }
  return NextResponse.json(redactApiValue({ status: results.some((item) => item.status === "queued") ? "queued" : "plan_ready", interpretationMode, requestKind: intent.requestKind, scopePage: intent.scopePage, requestedOutcome: intent.requestedOutcome, results, skipped }), { status: 201, headers: { "cache-control": "no-store" } });
}
