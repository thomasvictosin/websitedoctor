// Groups browser findings that describe one site-wide problem (a theme's
// contrast, a header's unlabeled button, a script error on every page) into a
// single issue per rule, so ten crawled pages do not become ten issues.
// Findings that are repaired page by page keep their per-page fingerprint:
// horizontal overflow (a scoped CSS rule for that page), broken and
// redirecting links (the link is edited in that post), and HTTP errors.

export type GroupableFinding = {
  fingerprint: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  evidence: Record<string, unknown>;
};

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 } as const;
const PER_PAGE_KINDS = /^(horizontal-overflow|broken-link:|link-redirect:|page-http-error)/;
const PAGE_KEY = /^[0-9a-f]{12}$/;
export const SITE_WIDE_SUFFIX = "site";
const MAX_LISTED_PAGES = 50;
const MAX_OBSERVED_PAGES = 5;

/** The rule a per-page browser fingerprint belongs to, when that rule is grouped site-wide. */
export function siteWideBrowserKind(fingerprint: string): string | null {
  if (!fingerprint.startsWith("browser:")) return null;
  const rest = fingerprint.slice("browser:".length);
  const cut = rest.lastIndexOf(":");
  if (cut <= 0) return null;
  const kind = rest.slice(0, cut);
  const suffix = rest.slice(cut + 1);
  if (PER_PAGE_KINDS.test(kind)) return null;
  if (suffix !== SITE_WIDE_SUFFIX && !PAGE_KEY.test(suffix)) return null;
  return kind;
}

/**
 * Whether a scan that did not observe a site-wide finding shows it is fixed. Requiring every page
 * it was seen on to be rescanned kept fixed issues open forever when one page timed out in one
 * viewport on every scan. Site-wide findings come from shared templates, so a clean rescan of most
 * of those pages is the evidence; if a missed page still has it, the next scan reopens the issue.
 */
export const SITE_WIDE_RESOLVE_SHARE = 0.8;

export function siteWideFindingCleared(pageKeys: unknown, scannedPageKeys: ReadonlySet<string>) {
  if (!Array.isArray(pageKeys)) return false;
  const keys = pageKeys.filter((key): key is string => typeof key === "string");
  if (!keys.length) return false;
  const rescanned = keys.filter((key) => scannedPageKeys.has(key)).length;
  return rescanned >= Math.ceil(keys.length * SITE_WIDE_RESOLVE_SHARE);
}

/** True for a fingerprint written before grouping (one issue per page for a grouped rule). */
export function isLegacyPerPageFingerprint(fingerprint: string) {
  return siteWideBrowserKind(fingerprint) !== null && !fingerprint.endsWith(`:${SITE_WIDE_SUFFIX}`);
}

export function groupSiteWideFindings<T extends GroupableFinding>(findings: T[]): T[] {
  const grouped = new Map<string, T[]>();
  const result: T[] = [];
  for (const finding of findings) {
    const kind = siteWideBrowserKind(finding.fingerprint);
    if (!kind) {
      result.push(finding);
      continue;
    }
    if (!grouped.has(kind)) grouped.set(kind, []);
    grouped.get(kind)!.push(finding);
  }
  for (const [kind, items] of grouped) {
    const worst = items.reduce((best, item) => SEVERITY_RANK[item.severity] > SEVERITY_RANK[best.severity] ? item : best, items[0]);
    const pages = [...new Set(items.map((item) => String(item.evidence.pageUrl ?? "")).filter(Boolean))];
    const pageKeys = [...new Set(items.map((item) => item.fingerprint.slice(item.fingerprint.lastIndexOf(":") + 1)))];
    const listed = pages.slice(0, 10).map((url) => `- ${url}`).join("\n");
    const more = pages.length > 10 ? `\n- and ${pages.length - 10} more page(s)` : "";
    const where = pages.length > 1 ? `Seen on ${pages.length} pages:\n${listed}${more}` : pages.length === 1 ? `Seen on ${pages[0]}.` : "";
    result.push({
      ...worst,
      fingerprint: `browser:${kind}:${SITE_WIDE_SUFFIX}`,
      title: pages.length > 1 ? `${worst.title} (${pages.length} pages)`.slice(0, 300) : worst.title,
      description: [worst.description, where].filter(Boolean).join("\n").slice(0, 4000),
      evidence: {
        ...worst.evidence,
        pageUrl: pages[0] ?? worst.evidence.pageUrl,
        pageCount: pages.length,
        pages: pages.slice(0, MAX_LISTED_PAGES),
        pageKeys,
        examples: items.slice(0, MAX_OBSERVED_PAGES).map((item) => item.evidence),
      },
    });
  }
  return result;
}
