import { db } from "./db.ts";
import type { Prisma } from "@prisma/client";
import { browserPageKey, scanBrowserSite } from "./browser-monitor.ts";
import { checkWebsite } from "./monitor.ts";
import { proposeStandingEligibleRepair } from "./repair-authorization.ts";

export async function runAndStoreCheck(
  website: { id: string; name: string; url: string },
  initiatedBy = "manual",
  dependencies: { checkWebsite?: typeof checkWebsite; scanBrowserSite?: typeof scanBrowserSite } = {},
  sessionId?: string,
) {
  const checkSite: typeof checkWebsite = dependencies.checkWebsite ?? checkWebsite;
  const scanSite: typeof scanBrowserSite = dependencies.scanBrowserSite ?? scanBrowserSite;
  const session = sessionId ? { id: sessionId } : await db.scanSession.create({
    data: { websiteId: website.id, scanType: "availability_and_browser", initiatedBy },
  });
  try {
    const result = await checkSite(website.url);
    const checkedAt = new Date();
    const check = await db.siteCheck.create({
      data: { websiteId: website.id, scanSessionId: session.id, ...result, checkedAt },
    });

    let browser: Awaited<ReturnType<typeof scanBrowserSite>> | null = null;
    if (result.available) {
      browser = await scanSite(website.url);
      const browserDiagnostic = await db.diagnosticResult.create({
        data: {
          scanSessionId: session.id,
          category: "browser",
          status: browser.status,
          summary: {
            scannedUrl: browser.scannedUrl,
            checkedAt: browser.checkedAt,
            viewports: browser.viewports,
            pages: browser.pages,
            pageLimit: browser.pageLimit,
            pageLimitReached: browser.pageLimitReached,
            crawlIncomplete: browser.crawlIncomplete,
            metrics: browser.metrics,
            errors: browser.errors,
            findingCount: browser.findings.length,
          },
        },
      });
      for (const finding of browser.findings) {
        const evidence = {
          browser: {
            scannedUrl: browser.scannedUrl,
            checkedAt: browser.checkedAt,
            viewports: browser.viewports,
            metrics: browser.metrics,
            finding: finding.evidence,
          },
          collectedAt: browser.checkedAt,
        };
        const issue = await db.issue.upsert({
          where: { websiteId_fingerprint: { websiteId: website.id, fingerprint: finding.fingerprint } },
          create: {
            websiteId: website.id,
            fingerprint: finding.fingerprint,
            title: finding.title,
            description: finding.description,
            severity: finding.severity,
            source: "browser_monitor",
            evidence: evidence as Prisma.InputJsonValue,
          },
          update: {
            title: finding.title,
            description: finding.description,
            severity: finding.severity,
            source: "browser_monitor",
            status: "open",
            lastSeenAt: checkedAt,
            resolvedAt: null,
            evidence: evidence as Prisma.InputJsonValue,
          },
          select: { id: true },
        });
        await proposeStandingEligibleRepair(website.id, issue.id);
        await db.evidenceRecord.create({
          data: {
            diagnosticResultId: browserDiagnostic.id,
            issueId: issue.id,
            kind: finding.fingerprint,
            source: "browser_monitor",
            payload: evidence as Prisma.InputJsonValue,
            collectedAt: checkedAt,
          },
        });
      }
      const browserIssueIds = browser.findings.map(({ fingerprint }) => ({ websiteId: website.id, fingerprint }));
      if (browserIssueIds.length) {
        const storedIssues = await db.issue.findMany({ where: { OR: browserIssueIds }, select: { id: true, fingerprint: true } });
        for (const issue of storedIssues) {
          await db.evidenceRecord.create({
            data: {
              diagnosticResultId: browserDiagnostic.id,
              issueId: issue.id,
              kind: "browser-finding",
              source: "browser_monitor",
              payload: { scanStatus: browser.status, crawlIncomplete: browser.crawlIncomplete, pageLimitReached: browser.pageLimitReached } as Prisma.InputJsonValue,
              collectedAt: checkedAt,
            },
          });
        }
      }
      const scannedPageKeys = new Set(browser.pages.filter((page) => page.complete).map((page) => page.pageKey));
      if (scannedPageKeys.size > 0) {
        const existingFindings = await db.issue.findMany({
          where: { websiteId: website.id, source: "browser_monitor", status: "open", fingerprint: { startsWith: "browser:" } },
          select: { id: true, fingerprint: true },
        });
        const observedFingerprints = new Set(browser.findings.map((finding) => finding.fingerprint));
        const resolvedIds = existingFindings
          .filter((issue) => {
            const pageKey = issue.fingerprint.split(":").at(-1);
            return pageKey && scannedPageKeys.has(pageKey) && !observedFingerprints.has(issue.fingerprint);
          })
          .map((issue) => issue.id);
        if (resolvedIds.length) {
          await db.issue.updateMany({
            where: { id: { in: resolvedIds }, websiteId: website.id },
            data: { status: "resolved", resolvedAt: checkedAt, lastSeenAt: checkedAt },
          });
        }
      }
    }

    let issueId: string | null = null;
    if (!result.available) {
      const description = result.error ?? `Website returned HTTP ${result.statusCode}.`;
      const issue = await db.issue.upsert({
        where: { websiteId_fingerprint: { websiteId: website.id, fingerprint: "availability" } },
        create: {
          websiteId: website.id,
          fingerprint: "availability",
          title: `${website.name} is unavailable`,
          description,
          severity: result.statusCode && result.statusCode >= 500 ? "high" : "critical",
          source: "availability_check",
          evidence: { ...result, checkedAt: checkedAt.toISOString() },
        },
        update: {
          description,
          severity: result.statusCode && result.statusCode >= 500 ? "high" : "critical",
          status: "open",
          lastSeenAt: checkedAt,
          resolvedAt: null,
          evidence: { ...result, checkedAt: checkedAt.toISOString() },
        },
        select: { id: true },
      });
      issueId = issue.id;
    } else {
      await db.issue.updateMany({
        where: { websiteId: website.id, fingerprint: "availability", status: "open" },
        data: { status: "resolved", resolvedAt: checkedAt, lastSeenAt: checkedAt },
      });
      issueId = (await db.issue.findUnique({
        where: { websiteId_fingerprint: { websiteId: website.id, fingerprint: "availability" } },
        select: { id: true },
      }))?.id ?? null;
    }

    const diagnostic = await db.diagnosticResult.create({
      data: {
        scanSessionId: session.id,
        issueId,
        category: "availability",
        status: result.available ? "passed" : "failed",
        summary: result,
      },
    });
    await db.evidenceRecord.create({
      data: {
        diagnosticResultId: diagnostic.id,
        issueId,
        kind: "http_head_check",
        source: "central_monitor",
        payload: { ...result, checkedAt: checkedAt.toISOString() },
        collectedAt: checkedAt,
      },
    });
    await db.scanSession.update({
      where: { id: session.id },
      data: { status: "completed", completedAt: checkedAt },
    });
    return { ...check, browser };
  } catch (error) {
    await db.scanSession.update({
      where: { id: session.id },
      data: { status: "failed", completedAt: new Date() },
    });
    throw error;
  }
}
