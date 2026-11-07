export type DiagnosticEvidenceSource = "availability_check" | "wordpress_agent" | "browser_test" | "browser_monitor";

export type RelevantTool = {
  id: string;
  description: string;
  available: boolean;
  reason: string;
};

export type EvidenceSignals = {
  source: DiagnosticEvidenceSource;
  finding?: { fingerprint?: string; title?: string; description?: string };
  hasAvailabilityResult?: boolean;
  hasWordPressSiteInfo?: boolean;
  hasPluginInventory?: boolean;
  hasCronInfo?: boolean;
  hasAuthorizedLogs?: boolean;
  hasBrowserResult?: boolean;
};

const toolCatalog = [
  {
    id: "http_availability",
    description: "DNS-pinned HTTP(S) availability and response-time check",
    matches: (evidence: EvidenceSignals) => evidence.hasAvailabilityResult === true || evidence.source === "availability_check",
    reason: "Independent check from the central application; does not depend on WordPress.",
  },
  {
    id: "wordpress_configuration",
    description: "WordPress/PHP version, memory, debug configuration, and active theme inspection",
    matches: (evidence: EvidenceSignals) => evidence.hasWordPressSiteInfo === true,
    reason: "WordPress agent supplied local configuration evidence.",
  },
  {
    id: "wordpress_plugin_inventory",
    description: "Installed/active plugin inventory and update status",
    matches: (evidence: EvidenceSignals) => evidence.hasPluginInventory === true
      && /plugin|theme|conflict|update|extension/i.test(
        `${evidence.finding?.fingerprint ?? ""} ${evidence.finding?.title ?? ""} ${evidence.finding?.description ?? ""}`,
      )
      && !/php[-_ ]?(?:log|warning|error|fatal)|php (?:warning|error|fatal)|debug log/i.test(
        `${evidence.finding?.fingerprint ?? ""} ${evidence.finding?.title ?? ""} ${evidence.finding?.description ?? ""}`,
      ),
    reason: "WordPress agent supplied plugin inventory evidence.",
  },
  {
    id: "wordpress_cron",
    description: "WP-Cron configuration and overdue event count",
    matches: (evidence: EvidenceSignals) => evidence.hasCronInfo === true
      && /cron|scheduled|schedule|event/i.test(
        `${evidence.finding?.fingerprint ?? ""} ${evidence.finding?.title ?? ""} ${evidence.finding?.description ?? ""}`,
      ),
    reason: "WordPress agent supplied scheduling evidence.",
  },
  {
    id: "wordpress_authorized_logs",
    description: "Administrator-authorized WordPress debug-log excerpt and bounded parsed PHP errors",
    matches: (evidence: EvidenceSignals) => evidence.hasAuthorizedLogs === true
      && /error|fatal|exception|warning|stack|log/i.test(
        `${evidence.finding?.fingerprint ?? ""} ${evidence.finding?.title ?? ""} ${evidence.finding?.description ?? ""}`,
      ),
    reason: "An explicitly authorized log excerpt is available for analysis.",
  },
  {
    id: "browser_diagnostics",
    description: "Browser console, responsive layout, and resource diagnostics",
    matches: (evidence: EvidenceSignals) => evidence.hasBrowserResult === true || evidence.source === "browser_test" || evidence.source === "browser_monitor",
    reason: "Browser diagnostics are selected only when browser evidence is supplied.",
  },
];

export function selectRelevantTools(evidence: EvidenceSignals): RelevantTool[] {
  return toolCatalog
    .filter((tool) => tool.matches(evidence))
    .map((tool) => ({
      id: tool.id,
      description: tool.description,
      available: true,
      reason: tool.reason,
    }));
}

export function deriveEvidenceSignals(
  source: DiagnosticEvidenceSource,
  evidence: Record<string, unknown>,
  finding?: EvidenceSignals["finding"],
): EvidenceSignals {
  const site = evidence.site && typeof evidence.site === "object"
    ? evidence.site as Record<string, unknown>
    : null;
  return {
    source,
    finding,
    hasAvailabilityResult: source === "availability_check"
      || Boolean(evidence.centralAvailability && typeof evidence.centralAvailability === "object"),
    hasWordPressSiteInfo: site !== null,
    hasPluginInventory: Array.isArray(evidence.plugins),
    hasCronInfo: Boolean(site && ("cronDisabled" in site || "overdueCronCount" in site)),
    hasAuthorizedLogs: (typeof evidence.authorizedLogExcerpt === "string" && evidence.authorizedLogExcerpt.length > 0)
      || (Array.isArray(evidence.phpErrors) && evidence.phpErrors.length > 0),
    hasBrowserResult: (source === "browser_test" || source === "browser_monitor") && evidence.browser !== undefined,
  };
}

export function selectEvidenceForAnalysis(
  source: DiagnosticEvidenceSource,
  evidence: Record<string, unknown>,
  toolIds: string[],
  finding: EvidenceSignals["finding"],
): Record<string, unknown> {
  if (source === "availability_check") {
    const selected: Record<string, unknown> = {};
    for (const key of ["available", "statusCode", "responseTime", "error", "checkedAt"]) {
      if (evidence[key] !== undefined) selected[key] = evidence[key];
    }
    return selected;
  }

  const selected: Record<string, unknown> = {
    finding,
    collectedAt: evidence.collectedAt,
  };
  if (toolIds.includes("wordpress_configuration")) selected.site = evidence.site;
  if (toolIds.includes("wordpress_plugin_inventory")) {
    selected.plugins = Array.isArray(evidence.plugins) ? evidence.plugins.slice(0, 100) : [];
  }
  if (toolIds.includes("wordpress_cron") && evidence.site && typeof evidence.site === "object") {
    const site = evidence.site as Record<string, unknown>;
    selected.cron = {
      cronDisabled: site.cronDisabled,
      overdueCronCount: site.overdueCronCount,
    };
  }
  if (toolIds.includes("wordpress_authorized_logs")) {
    if (typeof evidence.authorizedLogExcerpt === "string") selected.authorizedLogExcerpt = evidence.authorizedLogExcerpt;
    if (Array.isArray(evidence.phpErrors)) selected.phpErrors = evidence.phpErrors.slice(0, 20);
    if (evidence.phpErrorLog && typeof evidence.phpErrorLog === "object") selected.phpErrorLog = evidence.phpErrorLog;
  }
  if (toolIds.includes("http_availability")) selected.centralAvailability = evidence.centralAvailability;
  if (toolIds.includes("browser_diagnostics")) selected.browser = evidence.browser;
  return selected;
}
