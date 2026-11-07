import { z } from "zod";

const relativePath = z.string().max(300);
const pathList = z.array(relativePath).max(50);

export const integrityReportSchema = z.object({
  scannedAt: z.string().datetime({ offset: true }),
  status: z.enum(["complete", "partial", "checksums_unavailable"]),
  durationMs: z.number().int().min(0).max(600_000),
  core: z.object({
    version: z.string().max(40).optional(),
    locale: z.string().max(20).optional(),
    checksumsAvailable: z.boolean(),
    checkedFiles: z.number().int().min(0).max(100_000),
    modified: pathList,
    missing: pathList,
    unknownPhp: pathList,
  }),
  rootUnknownFiles: pathList,
  uploadsPhp: pathList,
  muPlugins: pathList,
  contentRootPhp: pathList,
  suspiciousFiles: z.array(z.object({ path: relativePath, signatures: z.array(z.string().max(60)).max(20) })).max(50),
  htaccess: z.object({
    present: z.boolean(),
    bytes: z.number().int().min(0).optional(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    hasWordPressBlock: z.boolean().optional(),
    suspiciousLines: z.array(z.object({ line: z.number().int().min(1), reason: z.string().max(60), text: z.string().max(200) })).max(10).optional(),
  }),
  robotsFile: z.object({ present: z.boolean(), bytes: z.number().int().min(0).optional(), sitemapEntries: z.number().int().min(0).optional() }),
  admins: z.object({
    count: z.number().int().min(0).max(100_000),
    recent: z.array(z.object({ login: z.string().max(60), registeredAt: z.string().datetime({ offset: true }) })).max(20),
  }),
  pluginIntegrity: z.array(z.object({
    plugin: z.string().max(200),
    version: z.string().max(40),
    status: z.enum(["verified", "modified", "no_checksums", "not_checked"]),
    modified: z.array(relativePath).max(10),
    addedPhp: z.array(relativePath).max(10),
    missing: z.number().int().min(0).max(100_000),
    checkedAt: z.string().datetime({ offset: true }),
  })).max(60).optional(),
  fileHashes: z.record(relativePath, z.string().regex(/^[a-f0-9]{64}$/)).refine((value) => Object.keys(value).length <= 150, "Too many file hashes.").optional(),
  truncated: z.boolean(),
});

export type IntegrityReport = z.infer<typeof integrityReportSchema>;

export const agentDiagnosticSchema = z.object({
  collectedAt: z.string().datetime({ offset: true }),
  site: z.object({
    wpVersion: z.string().max(40),
    phpVersion: z.string().max(40),
    memoryLimit: z.string().max(40),
    environmentType: z.enum(["production", "staging", "development", "local"]).optional(),
    pluginVersion: z.string().regex(/^\d+(\.\d+){1,3}$/).optional(),
    customCssSha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    debugMode: z.boolean(),
    cronDisabled: z.boolean(),
    overdueCronCount: z.number().int().min(0).max(1000),
    scheduledTaskCount: z.number().int().min(0).max(1000).optional(),
    activeTheme: z.object({ name: z.string().max(200), version: z.string().max(40), stylesheet: z.string().max(100) }),
  }),
  plugins: z.array(z.object({
    name: z.string().max(200),
    version: z.string().max(40),
    file: z.string().max(200),
    active: z.boolean(),
    updateAvailable: z.boolean(),
    source: z.enum(["wordpress.org", "other"]).optional(),
    newVersion: z.string().regex(/^[0-9A-Za-z.+-]{1,40}$/).optional(),
  })).max(500),
  editablePages: z.array(z.object({
    id: z.number().int().positive(),
    url: z.string().url().max(2000),
    postType: z.string().max(40),
    contentSha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
  })).max(100).optional(),
  fatalErrors: z.array(z.object({
    id: z.string().max(64), observedAt: z.string().datetime({ offset: true }), type: z.string().max(40),
    message: z.string().max(500), file: z.string().max(200), plugin: z.string().max(200).nullable().optional(), line: z.number().int().min(0),
  })).max(20).optional(),
  phpErrors: z.array(z.object({
    id: z.string().regex(/^[a-f0-9]{32}$/i),
    level: z.enum(["warning", "notice", "deprecated", "fatal", "parse_error", "uncaught_exception"]),
    message: z.string().max(500),
    file: z.string().max(200),
    plugin: z.string().max(200).nullable().optional(),
    line: z.number().int().min(0).max(2_147_483_647),
  })).max(20).optional(),
  phpErrorLog: z.object({
    collectionEnabled: z.boolean(),
    status: z.enum(["disabled", "readable", "not_found", "unreadable", "empty", "unavailable"]),
    observedCount: z.number().int().min(0).max(20),
    limit: z.literal(20),
  }).optional(),
  scheduledTasks: z.array(z.object({
    id: z.string().max(64), hook: z.string().max(200), scheduledAt: z.string().datetime({ offset: true }), overdue: z.boolean(),
    status: z.enum(["pending", "running", "completed", "failed"]),
    lastStartedAt: z.string().datetime({ offset: true }).nullable(), lastCompletedAt: z.string().datetime({ offset: true }).nullable(),
    failure: z.object({ type: z.string().max(40), message: z.string().max(500), source: z.enum(["fatal_error", "application_report"]).optional() }).nullable(),
  })).max(100).optional(),
  cronHistory: z.array(z.object({
    id: z.string().max(64), hook: z.string().max(200), scheduledAt: z.string().datetime({ offset: true }),
    status: z.enum(["running", "completed", "failed"]), startedAt: z.string().datetime({ offset: true }).optional(),
    completedAt: z.string().datetime({ offset: true }).optional(),
    failure: z.object({ type: z.string().max(40), message: z.string().max(500), source: z.enum(["fatal_error", "application_report"]).optional() }).optional(),
  })).max(100).optional(),
  conflictTesting: z.object({
    status: z.enum(["not_run", "completed", "failed"]),
    environment: z.enum(["live_site_observation", "disposable_staging"]),
    stagingRequired: z.boolean(), liveDeactivationPerformed: z.boolean(), testedAt: z.string().datetime({ offset: true }).nullable(),
    activePlugins: z.array(z.string().max(200)).max(100), activeTheme: z.string().max(100),
    findings: z.array(z.object({
      components: z.array(z.string().max(200)).min(1).max(3),
      result: z.enum(["conflict", "no_conflict", "inconclusive"]),
      evidence: z.string().max(1000),
      baselineFindings: z.array(z.object({ fingerprint: z.string().max(160), severity: z.enum(["low", "medium", "high"]) })).max(100).optional(),
      probeFindings: z.array(z.object({ fingerprint: z.string().max(160), severity: z.enum(["low", "medium", "high"]) })).max(100).optional(),
    })).max(100),
  }).superRefine((report, context) => {
    if (report.environment === "live_site_observation" && report.liveDeactivationPerformed) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "Live conflict diagnostics cannot deactivate components." });
    }
    if (report.environment === "disposable_staging" && report.status === "completed" && report.testedAt === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "Completed staging tests require a timestamp." });
    }
  }).optional(),
  integrity: integrityReportSchema.optional(),
  hardening: z.array(z.object({
    id: z.string().max(60),
    enabled: z.boolean(),
    verified: z.boolean().nullable(),
    detail: z.string().max(300),
    changedAt: z.string().nullable(),
  })).max(20).optional(),
  settings: z.object({
    blogname: z.string().max(500),
    blogdescription: z.string().max(2000),
  }).optional(),
  issues: z.array(z.object({
    fingerprint: z.string().regex(/^[a-z0-9:_-]{1,100}$/i),
    title: z.string().min(1).max(200),
    description: z.string().max(2000),
    severity: z.enum(["low", "medium", "high", "critical"]),
  })).max(50),
  authorizedLogExcerpt: z.string().max(16_384).optional(),
});
