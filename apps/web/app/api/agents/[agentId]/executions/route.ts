import { NextResponse } from "next/server";
import { z } from "zod";
import { authenticateAgent } from "@/lib/agent-auth";
import { db } from "@/lib/db";
import { readBoundedJson } from "@/lib/request-json";
import { reviewRepairOutcome } from "@/lib/ai/orchestrator";
import { Prisma } from "@prisma/client";
import { requiresRecoveryPoint, deriveRepairStatus } from "@/lib/repair-policy";
import { verifyBrowserConflictRepair, verifyBrowserLayoutRepair, verifyBrowserLinkRepair, verifyFatalPluginContainment, verifyRecoveryState, verifyRepairEvidence } from "@/lib/repair-verification";
import { checkWebsite } from "@/lib/monitor";
import { requestSourceHash } from "@/lib/rate-limit";
import { authorizeRepairExecution } from "@/lib/repair-authorization";

export const runtime = "nodejs";

// The browser scanner loads Playwright, which is not available in every
// deployment (it is not in the Vercel function bundle). A static import made
// this whole route fail to load, so the plugin could not report any execution.
// Load it only when a browser rescan is needed; if it is unavailable, return
// null so verification is recorded as inconclusive, never as success.
async function runBrowserRetest(url: string) {
  try {
    const { scanBrowserSite } = await import("@/lib/browser-monitor");
    return await scanBrowserSite(url);
  } catch (error) {
    console.error("Central browser rescan unavailable", error instanceof Error ? error.message : "Unknown error");
    return null;
  }
}

function repairOperations(proposal: unknown): Array<{ operation: unknown; parameters: unknown }> {
  if (!proposal || typeof proposal !== "object" || Array.isArray(proposal)) return [];
  const instructions = (proposal as Record<string, unknown>).instructions;
  if (!instructions || typeof instructions !== "object" || Array.isArray(instructions)) return [];
  const steps = (instructions as Record<string, unknown>).steps;
  return Array.isArray(steps) ? steps.flatMap((step) => step && typeof step === "object" && !Array.isArray(step)
    ? [{ operation: (step as Record<string, unknown>).operation, parameters: (step as Record<string, unknown>).parameters }]
    : []) : [];
}
const resultSchema = z.object({
  repairId: z.string().min(1).max(64),
  authorizationGrantId: z.string().min(1).max(64).optional(),
  status: z.enum(["completed", "failed", "rolled_back", "rollback_failed", "verification_failed", "inconclusive"]),
  result: z.object({
    message: z.string().max(2000),
    startedAt: z.string().datetime(),
    backupId: z.string().max(100).optional(),
    backupStatus: z.enum(["created", "not_required", "failed", "unavailable"]),
    localStateRestoreApplied: z.boolean().optional(),
    executionStatus: z.enum(["completed", "failed"]),
    verificationStatus: z.enum(["passed", "failed", "inconclusive"]),
    verificationReason: z.string().max(2000),
    verified: z.boolean(),
    rollbackApplied: z.boolean().optional(),
    beforeEvidence: z.record(z.string(), z.json()).optional(),
    afterEvidence: z.record(z.string(), z.json()).optional(),
  }),
});

export async function POST(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> },
) {
  const { agentId } = await params;
  const auth = await authenticateAgent(request, agentId);
  if ("response" in auth) return auth.response;
  if (auth.agent.id !== agentId) return NextResponse.json({ error: "Agent identity mismatch." }, { status: 403 });
  const body = await readBoundedJson(request, 100_000);
  if (body === null) return NextResponse.json({ error: "Execution result is invalid or too large." }, { status: 413 });
  const parsed = resultSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Execution result is invalid." }, { status: 400 });

  const isCentralRollback = ["rolled_back", "rollback_failed"].includes(parsed.data.status);
  const repair = await db.repairProposal.findFirst({
    where: {
      id: parsed.data.repairId,
      websiteId: auth.agent.websiteId,
      status: isCentralRollback ? "rollback_required" : "approved",
    },
    include: {
      issue: { select: { evidence: true, fingerprint: true } },
      website: { select: { organizationId: true, url: true } },
    },
  });
  if (!repair) {
    return NextResponse.json({
      error: parsed.data.status === "rolled_back"
        ? "A centrally requested rollback was not found."
        : "Approved repair proposal not found.",
    }, { status: 404 });
  }

  const existing = await db.agentExecution.findUnique({
    where: { agentId_repairId: { agentId, repairId: repair.id } },
  });
  if (isCentralRollback) {
    if (!existing || existing.status !== "rollback_required") {
      return NextResponse.json({ error: "Rollback is not currently awaiting execution." }, { status: 409 });
    }
    const previousResult = existing.result && typeof existing.result === "object" && !Array.isArray(existing.result)
      ? existing.result as Prisma.JsonObject
      : {};
    const rollbackVerification = verifyRecoveryState({
      beforeEvidence: previousResult.beforeDiagnostics ?? null,
      afterEvidence: parsed.data.result.afterEvidence ?? null,
      operations: repairOperations(repair.proposal),
    });
    const rollbackVerified = parsed.data.status === "rolled_back"
      && parsed.data.result.executionStatus === "completed"
      && parsed.data.result.backupStatus === "created"
      && rollbackVerification.status === "passed";
    const finalStatus = rollbackVerified ? "rolled_back" : "failed";
    const execution = await db.$transaction(async (transaction) => {
      const claimed = await transaction.repairProposal.updateMany({
        where: { id: repair.id, status: "rollback_required" },
        data: { status: finalStatus },
      });
      if (claimed.count !== 1) return null;
      const rollbackResult = {
        ...parsed.data.result,
        verified: rollbackVerified,
        verification: rollbackVerification,
      } as Prisma.InputJsonObject;
      const updatedExecution = await transaction.agentExecution.update({
        where: { id: existing.id, status: "rollback_required" },
        data: {
          status: finalStatus,
          result: rollbackResult,
          completedAt: new Date(),
        },
      });
      await transaction.repairProposal.update({
        where: { id: repair.id },
        data: {
          rollbackStatus: finalStatus === "rolled_back" ? "completed" : "failed",
          verificationStatus: rollbackVerification.status,
        },
      });
      await transaction.verificationResult.create({
        data: {
          repairId: repair.id,
          executionId: existing.id,
          status: rollbackVerification.status,
          method: "central_recovery_state_comparison",
          result: rollbackVerification,
        },
      });
      await transaction.repairEvent.create({
        data: {
          repairId: repair.id,
          eventType: finalStatus === "rolled_back" ? "rollback_completed" : "rollback_failed",
          actor: "wordpress_plugin",
          details: rollbackResult,
        },
      });
      await transaction.auditLog.create({
        data: {
          action: finalStatus === "rolled_back" ? "repair_rollback_verified" : "repair_rollback_failed",
          actorType: "wordpress_agent",
          actorId: agentId,
          organizationId: repair.website.organizationId,
          resourceType: "repair",
          resourceId: repair.id,
          sourceHash: requestSourceHash(request),
          details: { verificationStatus: rollbackVerification.status },
        },
      });
      return updatedExecution;
    });
    if (!execution) return NextResponse.json({ error: "Rollback is already being recorded." }, { status: 409 });
    return NextResponse.json({
      ok: rollbackVerified,
      executionId: execution.id,
      status: finalStatus,
      verification: rollbackVerification,
    });
  }
  if (existing) return NextResponse.json({ error: "An execution result has already been recorded." }, { status: 409 });

  const handedGrant = parsed.data.authorizationGrantId ? await db.repairApproval.findFirst({ where: { id: parsed.data.authorizationGrantId, repairId: repair.id, operationDigest: { not: null }, expiresAt: { gt: new Date() }, consumedAt: { not: null }, executionResult: "task_dispatched" }, select: { id: true, repairId: true, operationDigest: true, expiresAt: true, consumedAt: true, executionResult: true, executionWebsiteId: true, executionIssueId: true, executionProposalId: true, decision: true, authorizationMethod: true } }) : null;
  const authorizationDecision = await authorizeRepairExecution({ repairId: repair.id, websiteId: auth.agent.websiteId, mode: "executor", grantId: parsed.data.authorizationGrantId });
  if (authorizationDecision.outcome !== "AUTHORIZED" || !authorizationDecision.grantId || !handedGrant
    || parsed.data.authorizationGrantId !== authorizationDecision.grantId) {
    return NextResponse.json({ error: `${authorizationDecision.outcome}: ${authorizationDecision.reason}` }, { status: 403 });
  }

  const agent = await db.wordPressAgent.findUnique({
    where: { id: agentId },
    select: { diagnostics: true },
  });
  const proposal = repair.proposal;
  const recoveryRequired = requiresRecoveryPoint(repair.operationIds);
  const driveConnection = recoveryRequired
    ? await db.googleDriveConnection.findUnique({
        where: { organizationId: repair.website.organizationId },
        select: { id: true },
      })
    : null;
  const uploadedBackup = recoveryRequired && parsed.data.result.backupId
    ? await db.backup.findUnique({
        where: { repairId_externalId: { repairId: repair.id, externalId: parsed.data.result.backupId } },
        select: { status: true, storageProvider: true, storageFileId: true, storageFolderId: true },
      })
    : null;
  const backupValid = (!recoveryRequired
    ? parsed.data.result.backupStatus === "created" || parsed.data.result.backupStatus === "not_required" || parsed.data.result.backupStatus === "unavailable"
    : parsed.data.result.backupStatus === "created"
      && Boolean(parsed.data.result.backupId)
      && (!driveConnection || (uploadedBackup?.status === "created"
        && uploadedBackup.storageProvider === "google_drive"
        && Boolean(uploadedBackup.storageFileId)
        && Boolean(uploadedBackup.storageFolderId))));
  const recoveryPointAvailable = parsed.data.result.backupStatus === "created" && Boolean(parsed.data.result.backupId);
  const executionStatus = backupValid ? parsed.data.result.executionStatus : "failed";
  const proposalData = proposal && typeof proposal === "object" && !Array.isArray(proposal) ? proposal as Prisma.JsonObject : {};
  const instructions = proposalData.instructions && typeof proposalData.instructions === "object" && !Array.isArray(proposalData.instructions)
    ? proposalData.instructions as Prisma.JsonObject
    : {};
  const steps = Array.isArray(instructions.steps) ? instructions.steps : [];
  const isBrowserConflict = (repair.issue?.fingerprint ?? "").startsWith("wp:staging-conflict:");
  const isBrowserLayoutRepair = (repair.issue?.fingerprint ?? "").startsWith("browser:horizontal-overflow:")
    && steps.some((step) => step && typeof step === "object" && !Array.isArray(step) && (step as Prisma.JsonObject).operation === "add_scoped_css_rule");
  const isLinkRepair = (repair.issue?.fingerprint ?? "").startsWith("browser:link-redirect:")
    || (repair.issue?.fingerprint ?? "").startsWith("browser:broken-link:");
  const browserRetest = (isBrowserConflict || isBrowserLayoutRepair || isLinkRepair) && executionStatus === "completed"
    ? await runBrowserRetest(repair.website.url)
    : null;
  const siteAvailabilityCheck = isLinkRepair && executionStatus === "completed"
    ? await checkWebsite(repair.website.url)
    : null;
  const fatalPluginStep = steps.map((step) => step && typeof step === "object" && !Array.isArray(step) ? step as Prisma.JsonObject : {})
    .find((step) => step.operation === "disable_plugin" && step.parameters && typeof step.parameters === "object" && !Array.isArray(step.parameters));
  const fatalPluginFile = fatalPluginStep?.parameters && typeof fatalPluginStep.parameters === "object" && !Array.isArray(fatalPluginStep.parameters)
    ? (fatalPluginStep.parameters as Prisma.JsonObject).plugin
    : null;
  const linkRepairStep = steps.map((step) => step && typeof step === "object" && !Array.isArray(step) ? step as Prisma.JsonObject : {})
    .find((step) => step.operation === "replace_post_link");
  const linkRepairParameters = linkRepairStep?.parameters && typeof linkRepairStep.parameters === "object" && !Array.isArray(linkRepairStep.parameters)
    ? linkRepairStep.parameters as Prisma.JsonObject
    : {};
  const isBrokenLinkRepair = (repair.issue?.fingerprint ?? "").startsWith("browser:broken-link:");
  const replacementUrl = isBrokenLinkRepair ? linkRepairParameters.replacementUrl : (() => {
    const evidence = repair.issue?.evidence && typeof repair.issue.evidence === "object" && !Array.isArray(repair.issue.evidence)
      ? repair.issue.evidence as Prisma.JsonObject
      : {};
    const browser = evidence.browser && typeof evidence.browser === "object" && !Array.isArray(evidence.browser)
      ? evidence.browser as Prisma.JsonObject
      : {};
    const finding = browser.finding && typeof browser.finding === "object" && !Array.isArray(browser.finding)
      ? browser.finding as Prisma.JsonObject
      : {};
    return finding.replacementUrl;
  })();
  const replacementCheck = isLinkRepair && executionStatus === "completed" && typeof replacementUrl === "string"
    ? await checkWebsite(replacementUrl)
    : null;
  const linkVerification = isLinkRepair
    ? browserRetest
      ? verifyBrowserLinkRepair({
          issueFingerprint: repair.issue?.fingerprint ?? "",
          issueEvidence: isBrokenLinkRepair
            ? { ...(repair.issue?.evidence && typeof repair.issue.evidence === "object" && !Array.isArray(repair.issue.evidence) ? repair.issue.evidence as Prisma.JsonObject : {}), requestedReplacementUrl: linkRepairParameters.replacementUrl ?? null }
            : repair.issue?.evidence ?? null,
          scan: browserRetest,
          siteAvailability: siteAvailabilityCheck,
          destinationAvailability: replacementCheck,
        })
      : { status: "inconclusive" as const, reason: "The central browser scan did not run after the link update.", regressions: [] }
    : null;
  const verification = linkVerification
    ? linkVerification
    : isBrowserLayoutRepair
      ? browserRetest
        ? verifyBrowserLayoutRepair({ issueFingerprint: repair.issue?.fingerprint ?? "", scan: browserRetest })
        : { status: "inconclusive" as const, reason: "The staging browser scan did not run after the CSS change.", regressions: [] }
    : !isBrowserConflict && (repair.issue?.fingerprint ?? "").startsWith("wp:php-fatal:") && typeof fatalPluginFile === "string"
    ? verifyFatalPluginContainment({
      issueFingerprint: repair.issue?.fingerprint ?? null,
      pluginFile: fatalPluginFile,
      startedAt: parsed.data.result.startedAt,
      baselineEvidence: agent?.diagnostics ?? null,
      afterEvidence: parsed.data.result.afterEvidence ?? null,
    })
    : isBrowserConflict
    ? browserRetest
      ? verifyBrowserConflictRepair({
          issueFingerprint: repair.issue?.fingerprint ?? "",
          issueEvidence: repair.issue?.evidence ?? null,
          scan: browserRetest,
        })
      : { status: "inconclusive" as const, reason: "The repair did not complete, so browser verification was not run.", regressions: [] }
    : verifyRepairEvidence({
        issueFingerprint: repair.issue?.fingerprint ?? null,
        baselineEvidence: agent?.diagnostics ?? null,
        afterEvidence: parsed.data.result.afterEvidence ?? null,
      });
  const afterEvidence = browserRetest
    ? { wordpress: parsed.data.result.afterEvidence ?? agent?.diagnostics ?? null, browserRetest, siteAvailabilityCheck, replacementCheck }
    : parsed.data.result.afterEvidence ?? agent?.diagnostics ?? null;
  const verified = executionStatus === "completed" && verification.status === "passed";
  const review = await reviewRepairOutcome({
    proposal,
    result: {
      status: executionStatus,
      verified,
      message: parsed.data.result.message,
      backupId: parsed.data.result.backupId,
    },
    beforeEvidence: repair.issue?.evidence ?? null,
    afterEvidence,
  });
  const rollbackClaimed = parsed.data.result.rollbackApplied === true;
  const rollbackVerification = rollbackClaimed
      ? parsed.data.result.backupId && recoveryPointAvailable
      ? verifyRecoveryState({
          beforeEvidence: parsed.data.result.beforeEvidence ?? agent?.diagnostics ?? null,
          afterEvidence: parsed.data.result.afterEvidence ?? null,
          operations: repairOperations(repair.proposal),
        })
      : { status: "inconclusive" as const, reason: "The claimed rollback has no valid recovery point." }
    : null;
  const rollbackApplied = rollbackVerification?.status === "passed";
  const rollbackRequired = Boolean(parsed.data.result.backupId) && !rollbackApplied
    && (rollbackClaimed || verification.status !== "passed" || review.rollbackRecommended);
  const nextStatus = deriveRepairStatus({
    executionStatus,
    verificationStatus: verification.status,
    rollbackApplied,
    rollbackRequired,
  });
  const proposalRecord = proposal && typeof proposal === "object" && !Array.isArray(proposal)
    ? proposal as Prisma.JsonObject
    : {};
  const reviewRecord = {
    review: review.review,
    comparison: review.comparison,
    rollbackRecommended: rollbackRequired,
    aiStatus: review.aiStatus,
    aiErrors: review.aiErrors,
    reviewedAt: new Date().toISOString(),
  } satisfies Prisma.InputJsonObject;
  const resultRecord = {
    ...parsed.data.result,
    afterEvidence,
    browserRetest,
    beforeDiagnostics: parsed.data.result.beforeEvidence ?? agent?.diagnostics ?? null,
    rollbackApplied,
    rollbackClaimed,
    localStateRestoreApplied: parsed.data.result.localStateRestoreApplied === true,
    recoveryScope: "wordpress_state_snapshot",
    providerRestoreAvailable: false,
    rollbackVerification,
    verified,
    verification: {
      status: verification.status,
      reason: verification.reason,
      regressions: verification.regressions,
      claimedStatus: parsed.data.result.verificationStatus,
    },
    review: reviewRecord,
  } as Prisma.InputJsonObject;
  let execution;
  try {
    execution = await db.$transaction(async (transaction) => {
      const claimed = await transaction.repairProposal.updateMany({
        where: { id: repair.id, status: "approved" },
        data: {
          status: nextStatus,
          proposal: { ...proposalRecord, executionReview: reviewRecord } as Prisma.InputJsonValue,
        },
      });
      if (claimed.count !== 1) return null;
      await transaction.repairProposal.update({
        where: { id: repair.id },
        data: {
          backupStatus: backupValid ? parsed.data.result.backupStatus : "failed",
          executionStatus,
          verificationStatus: verification.status,
          rollbackStatus: parsed.data.result.rollbackApplied
            ? rollbackApplied ? "completed" : rollbackRequired ? "required" : "failed"
            : rollbackRequired ? "required" : review.rollbackRecommended ? "unavailable" : "not_required",
        },
      });
      await transaction.repairApproval.update({ where: { id: authorizationDecision.grantId }, data: { executionResult: nextStatus } });
      const execution = await transaction.agentExecution.create({
        data: {
          agentId,
          repairId: repair.id,
          status: nextStatus,
          result: resultRecord,
          startedAt: new Date(parsed.data.result.startedAt),
          completedAt: new Date(),
        },
      });
      if (parsed.data.result.backupId) {
        const backup = await transaction.backup.findUnique({
          where: { repairId_externalId: { repairId: repair.id, externalId: parsed.data.result.backupId } },
          select: { id: true, metadata: true, storageProvider: true },
        });
        const metadata = backup?.metadata && typeof backup.metadata === "object" && !Array.isArray(backup.metadata)
          ? backup.metadata as Prisma.JsonObject
          : {};
        const backupData = {
          status: backupValid ? "created" : "failed",
          metadata: {
            ...metadata,
            reportedStatus: parsed.data.result.backupStatus,
            pluginRecoveryScope: "wordpress_state_snapshot",
            providerVerified: Boolean(backupValid && backup?.storageProvider === "google_drive"),
          } satisfies Prisma.InputJsonObject,
        };
        if (backup) {
          await transaction.backup.update({ where: { id: backup.id }, data: backupData });
        } else {
          await transaction.backup.create({
            data: {
              websiteId: repair.websiteId,
              repairId: repair.id,
              agentId,
              externalId: parsed.data.result.backupId,
              backupType: "wordpress_recovery_point",
              ...backupData,
            },
          });
        }
      }
      await transaction.verificationResult.create({
        data: {
          repairId: repair.id,
          executionId: execution.id,
          status: verification.status,
          method: isLinkRepair ? "central_link_retest_and_http_availability" : isBrowserLayoutRepair ? "central_staging_responsive_layout_retest" : browserRetest ? "central_wordpress_browser_retest" : "central_wordpress_diagnostic_comparison",
          result: {
            reason: verification.reason,
            regressions: verification.regressions,
            rollbackStatus: rollbackVerification?.status ?? null,
            ...(isLinkRepair ? {
              siteAvailabilityCheck,
              replacementCheck,
              browserRetest: browserRetest ? {
                status: browserRetest.status,
                pages: browserRetest.pages.length,
                findingFingerprints: browserRetest.findings.map((finding) => finding.fingerprint),
                crawlIncomplete: browserRetest.crawlIncomplete,
                errors: browserRetest.errors,
              } : null,
            } : { browserRetest: browserRetest ? {
              status: browserRetest.status,
              pages: browserRetest.pages.length,
              findingFingerprints: browserRetest.findings.map((finding) => finding.fingerprint),
              crawlIncomplete: browserRetest.crawlIncomplete,
              errors: browserRetest.errors,
            } : null }),
          },
        },
      });
      await transaction.repairEvent.createMany({
        data: [
          {
            repairId: repair.id,
            eventType: "execution_reported",
            actor: "wordpress_plugin",
            details: {
              backupStatus: backupValid ? parsed.data.result.backupStatus : "failed",
              executionStatus,
              startedAt: parsed.data.result.startedAt,
              backupId: parsed.data.result.backupId ?? null,
              recoveryScope: "wordpress_state_snapshot",
              providerVerified: false,
              rollbackApplied,
              rollbackClaimed,
            },
          },
          {
            repairId: repair.id,
            eventType: "verification_completed",
            actor: "central_orchestrator",
            details: {
              status: verification.status,
              reason: verification.reason,
              regressions: verification.regressions,
            },
          },
          ...(rollbackApplied ? [{
            repairId: repair.id,
            eventType: "rollback_completed",
            actor: "wordpress_plugin",
            details: { backupId: parsed.data.result.backupId, automatic: true },
          }] : rollbackClaimed ? [{
            repairId: repair.id,
            eventType: "rollback_verification_failed",
            actor: "central_orchestrator",
            details: rollbackVerification ?? {
              status: "inconclusive",
              reason: "Rollback was claimed but no rollback verification result was available.",
            },
          }] : []),
          ...(rollbackRequired ? [{
            repairId: repair.id,
            eventType: "rollback_requested",
            actor: "central_orchestrator",
            details: { backupId: parsed.data.result.backupId, reason: verification.reason },
          }] : []),
        ],
      });
      await transaction.auditLog.create({
        data: {
          action: "repair_execution_reported",
          actorType: "wordpress_agent",
          actorId: agentId,
          organizationId: repair.website.organizationId,
          resourceType: "repair",
          resourceId: repair.id,
          sourceHash: requestSourceHash(request),
          details: {
            executionStatus,
            verificationStatus: verification.status,
            rollbackStatus: rollbackApplied ? "completed" : rollbackRequired ? "required" : "not_required",
          },
        },
      });
      return execution;
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      return NextResponse.json({ error: "An execution result has already been recorded." }, { status: 409 });
    }
    throw error;
  }
  if (!execution) return NextResponse.json({ error: "Repair execution is already being recorded." }, { status: 409 });
  return NextResponse.json({
    ok: true,
    executionId: execution.id,
    status: nextStatus,
    rollbackRequired: nextStatus === "rollback_required",
    verification,
    review,
  });
}
