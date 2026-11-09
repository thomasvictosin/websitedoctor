import { db } from "./db.ts";
import type { Prisma } from "@prisma/client";
import type { scanBrowserSite } from "./browser-monitor.ts";
import { isLegacyPerPageFingerprint, siteWideFindingCleared, SITE_WIDE_SUFFIX } from "./browser-findings.ts";
import { checkWebsite } from "./monitor.ts";
import { proposeStandingEligibleRepair } from "./repair-authorization.ts";
import { runSecurityProbe, type SecurityProbeResult } from "./security-probe.ts";

type BrowserScanner = typeof scanBrowserSite;

// Playwright is not part of the serverless (Vercel) bundle. Load the browser
// scanner only when a scan needs it, so availability and security checks keep
// working where no browser runtime exists.
async function loadBrowserScanner(): Promise<BrowserScanner | null> {
  try {
    return (await import("./browser-monitor.ts")).scanBrowserSite;
  } catch (error) {
    console.error("Browser scanner unavailable:", error instanceof Error ? error.message : "unknown error");
    return null;
  }
}

/**
 * Store the probe's findings as issues and resolve earlier security findings
 * that a completed check no longer observes. A check that failed to fetch its
 * evidence never resolves its findings.
 */
export async function storeSecurityProbe(websiteId: string, scanSessionId: string, probe: SecurityProbeResult) {
  const checkedAt = new Date(probe.checkedAt);
  const diagnostic = await db.diagnosticResult.create({
    data: {
      scanSessionId,
      category: "security",
      status: probe.findings.length ? "failed" : probe.completedChecks.length ? "passed" : "inconclusive",
      summary: {
        url: probe.url,
        checkedAt: probe.checkedAt,
        completedChecks: probe.completedChecks,
        findingCount: probe.findings.length,
        samples: probe.samples,
        robots: probe.robots,
        sitemap: probe.sitemap,
        errors: probe.errors,
        limitations: probe.limitations,
      } as Prisma.InputJsonValue,
    },
  });
  const issueIds: string[] = [];
  const alreadyOpen = new Set((await db.issue.findMany({ where: { websiteId, source: "security_probe", status: { in: ["open", "acknowledged"] } }, select: { fingerprint: true } })).map((issue) => issue.fingerprint));
  for (const finding of probe.findings) {
    const evidence = { security: { checkedAt: probe.checkedAt, url: probe.url, check: finding.check, ...finding.evidence, limitations: probe.limitations }, collectedAt: probe.checkedAt };
    const issue = await db.issue.upsert({
      where: { websiteId_fingerprint: { websiteId, fingerprint: finding.fingerprint } },
      create: { websiteId, fingerprint: finding.fingerprint, title: finding.title, description: finding.description, severity: finding.severity, source: "security_probe", evidence: evidence as Prisma.InputJsonValue },
      update: { title: finding.title, description: finding.description, severity: finding.severity, source: "security_probe", status: "open", lastSeenAt: checkedAt, resolvedAt: null, evidence: evidence as Prisma.InputJsonValue },
      select: { id: true },
    });
    issueIds.push(issue.id);
    await db.evidenceRecord.create({
      data: { diagnosticResultId: diagnostic.id, issueId: issue.id, kind: finding.fingerprint, source: "security_probe", payload: evidence as Prisma.InputJsonValue, collectedAt: checkedAt },
    });
    await proposeStandingEligibleRepair(websiteId, issue.id);
  }
  const observed = new Set(probe.findings.map((finding) => finding.fingerprint));
  const open = await db.issue.findMany({
    where: { websiteId, source: "security_probe", status: { in: ["open", "acknowledged"] } },
    select: { id: true, fingerprint: true, evidence: true },
  });
  const resolvedIds = open.filter((issue) => {
    if (observed.has(issue.fingerprint)) return false;
    const check = (issue.evidence as { security?: { check?: string } } | null)?.security?.check;
    return typeof check === "string" && probe.completedChecks.includes(check as never);
  }).map((issue) => issue.id);
  if (resolvedIds.length) {
    await db.issue.updateMany({ where: { id: { in: resolvedIds }, websiteId }, data: { status: "resolved", resolvedAt: checkedAt, lastSeenAt: checkedAt } });
  }
  const newlyObserved = probe.findings.filter((finding) => !alreadyOpen.has(finding.fingerprint));
  if (newlyObserved.length) {
    try {
      const { notifyNewSecurityFindings, runAutomaticProtection } = await import("./protection.ts");
      await notifyNewSecurityFindings(websiteId, newlyObserved);
      await runAutomaticProtection(websiteId);
    } catch (error) {
      console.error(`Security alerting failed for ${websiteId}:`, error instanceof Error ? error.message : error);
    }
  }
  return { diagnosticId: diagnostic.id, issueIds, resolvedCount: resolvedIds.length };
}

/** Run only the plain-HTTP security probe and store it (works without a browser runtime). */
export async function runAndStoreSecurityCheck(website: { id: string; url: string }, initiatedBy = "manual", probe: typeof runSecurityProbe = runSecurityProbe) {
  const session = await db.scanSession.create({ data: { websiteId: website.id, scanType: "security", initiatedBy } });
  try {
    const result = await probe(website.url);
    const stored = await storeSecurityProbe(website.id, session.id, result);
    await db.scanSession.update({ where: { id: session.id }, data: { status: "completed", completedAt: new Date() } });
    return { scanSessionId: session.id, probe: result, ...stored };
  } catch (error) {
    await db.scanSession.update({ where: { id: session.id }, data: { status: "failed", completedAt: new Date() } });
    throw error;
  }
}

export async function runAndStoreCheck(
  website: { id: string; name: string; url: string },
  initiatedBy = "manual",
  dependencies: { checkWebsite?: typeof checkWebsite; scanBrowserSite?: BrowserScanner; runSecurityProbe?: typeof runSecurityProbe } = {},
  sessionId?: string,
) {
  const checkSite: typeof checkWebsite = dependencies.checkWebsite ?? checkWebsite;
  const session = sessionId ? { id: sessionId } : await db.scanSession.create({
    data: { websiteId: website.id, scanType: "availability_and_browser", initiatedBy },
  });
  try {
    let result = await checkSite(website.url);
    // One slow response (a shared host under load, a cache rebuild) is not an outage: ask once more
    // before recording the site as down and raising a critical alert.
    if (!result.available && result.statusCode === null) {
      await new Promise((resolve) => setTimeout(resolve, dependencies.checkWebsite ? 0 : 5_000));
      result = await checkSite(website.url);
    }
    const checkedAt = new Date();
    // SiteCheck has no finalUrl column; the final URL is kept in the evidence record below.
    const { finalUrl: _finalUrl, ...checkColumns } = result;
    const check = await db.siteCheck.create({
      data: { websiteId: website.id, scanSessionId: session.id, ...checkColumns, checkedAt },
    });

    let browser: Awaited<ReturnType<BrowserScanner>> | null = null;
    let security: SecurityProbeResult | null = null;
    if (result.available) {
      try {
        security = await (dependencies.runSecurityProbe ?? runSecurityProbe)(website.url);
        await storeSecurityProbe(website.id, session.id, security);
      } catch (error) {
        console.error(`Security probe failed for ${website.id}:`, error instanceof Error ? error.message : "unknown error");
      }
    }
    // A browser result collected elsewhere (the GitHub runner) already proves the pages loaded moments
    // ago; keep it even if this server's own request just timed out.
    const externalResult = Boolean(dependencies.scanBrowserSite) && initiatedBy === "scheduled_browser";
    const scanSite = result.available || externalResult ? dependencies.scanBrowserSite ?? await loadBrowserScanner() : null;
    if (result.available && !scanSite) {
      await db.diagnosticResult.create({
        data: { scanSessionId: session.id, category: "browser", status: "unavailable", summary: { reason: "The browser runtime is not available on this deployment; availability and security checks still ran." } },
      });
    }
    if ((result.available || externalResult) && scanSite) {
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
      // Before site-wide grouping, every page had its own copy of rules such as
      // contrast or console errors. Those copies are now covered by one grouped issue.
      const legacy = await db.issue.findMany({
        where: { websiteId: website.id, source: "browser_monitor", fingerprint: { startsWith: "browser:" }, repairs: { none: {} } },
        select: { id: true, fingerprint: true },
      });
      const legacyIds = legacy.filter((issue) => isLegacyPerPageFingerprint(issue.fingerprint)).map((issue) => issue.id);
      if (legacyIds.length) await db.issue.deleteMany({ where: { id: { in: legacyIds }, websiteId: website.id } });
      const scannedPageKeys = new Set(browser.pages.filter((page) => page.complete).map((page) => page.pageKey));
      if (scannedPageKeys.size > 0) {
        const existingFindings = await db.issue.findMany({
          where: { websiteId: website.id, source: "browser_monitor", status: "open", fingerprint: { startsWith: "browser:" } },
          select: { id: true, fingerprint: true, evidence: true },
        });
        const observedFingerprints = new Set(browser.findings.map((finding) => finding.fingerprint));
        const resolvedIds = existingFindings
          .filter((issue) => {
            if (observedFingerprints.has(issue.fingerprint)) return false;
            const pageKey = issue.fingerprint.split(":").at(-1);
            // A site-wide issue is fixed once most pages it was seen on were rescanned without it.
            if (pageKey === SITE_WIDE_SUFFIX) {
              const evidence = issue.evidence as { browser?: { finding?: { pageKeys?: unknown } } } | null;
              return siteWideFindingCleared(evidence?.browser?.finding?.pageKeys, scannedPageKeys);
            }
            return Boolean(pageKey) && scannedPageKeys.has(pageKey!);
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
    return { ...check, browser, security };
  } catch (error) {
    await db.scanSession.update({
      where: { id: session.id },
      data: { status: "failed", completedAt: new Date() },
    });
    throw error;
  }
}
