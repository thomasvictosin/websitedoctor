import { z } from "zod";
import { isAllowedAgentOperation } from "./agent-operations.ts";
import { createHash } from "node:crypto";

export const repairStepSchema = z.object({
  description: z.string().trim().min(1).max(500),
  operation: z.enum(["disable_plugin", "switch_theme", "update_setting", "replace_post_link", "add_scoped_css_rule"]),
  parameters: z.record(z.string(), z.string().max(2000)),
}).strict().refine(isAllowedAgentOperation, "Operation parameters are not allowed.");

export const repairInstructionsSchema = z.object({
  steps: z.array(repairStepSchema).length(1),
  rollbackPlan: z.array(z.string().trim().min(1).max(500)).max(10),
  requiresApproval: z.literal(true),
}).strict();

export function repairRiskForOperations(operations: string[]): "low" | "medium" | "high" {
  if (operations.length === 0 || operations.some((operation) => ![
    "disable_plugin",
    "switch_theme",
    "update_setting",
    "replace_post_link",
    "add_scoped_css_rule",
  ].includes(operation))) return "high";
  if (operations.some((operation) => operation === "disable_plugin" || operation === "switch_theme" || operation === "add_scoped_css_rule")) return "high";
  if (operations.includes("update_setting")) return "medium";
  return "low";
}

export function requiresRecoveryPoint(operations: string[]): boolean {
  return operations.length > 0;
}

export type EvidenceBackedRepair = {
  operation: "disable_plugin" | "switch_theme" | "replace_post_link" | "add_scoped_css_rule";
  parameters: Record<string, string>;
  description: string;
  verificationFingerprints: string[];
  baselineHighFingerprints: string[];
};

export function boundedRepairPlan(issue: { fingerprint: string; title: string; description: string }, evidence: unknown) {
  const candidate = evidenceBackedRepairs(issue.fingerprint, evidence)[0];
  const manualGuidance = candidate ? [] : manualRemediationGuidance(issue.fingerprint, issue.description, evidence);
  const instructions = candidate ? {
    steps: [{ description: candidate.description, operation: candidate.operation, parameters: candidate.parameters }],
    rollbackPlan: ["Before applying, the plugin saves the exact operation target and prior value. If verification fails, it restores only that target when it still matches the operation's expected after-value. Your existing site backup remains the broader recovery option."],
    requiresApproval: true as const,
  } : {
    steps: [],
    rollbackPlan: [],
    requiresApproval: true as const,
  };
  const proposal = candidate ? {
    issue: issue.title,
    rationale: issue.fingerprint.startsWith("wp:php-fatal:")
      ? `Recent fatal-error evidence maps to the exact active plugin file shown below. Deactivation is a temporary containment step and may disable site features: ${candidate.description}`.slice(0, 1000)
      : candidate.operation === "add_scoped_css_rule"
        ? `A complete browser scan measured a specific element wider than its parent on the connected staging site. This single max-width rule is a bounded candidate, not a confirmed fix until the staging rescan passes: ${candidate.description}`.slice(0, 1000)
      : candidate.operation === "replace_post_link"
        ? `The browser confirmed the old same-origin URL is broken, the replacement was explicitly supplied and verified, and the connected WordPress agent mapped the source URL to a published editable post or page. The plugin still requires the exact old link to be present before changing it: ${candidate.description}`.slice(0, 1000)
        : `Disposable staging evidence recorded a browser finding change for this component. This is a bounded candidate for review, not proof of a root cause: ${candidate.description}`.slice(0, 1000),
    proposedChanges: [candidate.description],
    expectedImpact: candidate.operation === "replace_post_link"
      ? "Visitors and crawlers should follow the corrected URL; only this exact link in the mapped post is changed."
      : candidate.operation === "add_scoped_css_rule"
        ? "A page-scoped CSS rule limits the measured overflowing element to its parent width on the staging site."
        : candidate.operation === "disable_plugin"
        ? "The implicated plugin becomes inactive; any features it provides may stop working."
        : candidate.operation === "switch_theme"
          ? "The site uses the verified alternative theme; visible layout and styling may change."
          : "Only the identified WordPress setting is changed to the displayed value.",
    recoveryAvailability: "The plugin records the exact prior target and attempts a guarded restore if verification fails.",
    risk: "high" as const,
    requiresApproval: true as const,
    verificationPlan: [
      "Apply only after an administrator approves the exact operation.",
      candidate.operation === "replace_post_link"
        ? "After applying, the plugin confirms the exact post content update; the central browser rescan confirms the source page is complete and the old link finding is gone; independent HTTP checks confirm the site and selected destination respond successfully without an unexpected redirect."
        : candidate.operation === "add_scoped_css_rule"
          ? "After applying on staging, rerun the central browser scan at mobile and desktop widths; the original horizontal-overflow finding must be absent. Review any other reported findings before deployment."
        : issue.fingerprint.startsWith("wp:php-fatal:")
        ? "Collect fresh WordPress diagnostics; verify the implicated plugin is inactive and the same fatal event has not recurred, then check site availability and critical features."
        : "Rerun the central browser scan and confirm the recorded findings are absent with no new high severity findings.",
      "If verification fails or is inconclusive, the plugin restores the operation-specific saved target when it still matches the expected after-value. Otherwise, use your existing site recovery process.",
    ],
  } : {
    issue: issue.title,
    rationale: "No executable change is attached because the evidence does not identify a specific operation with a reliable recovery point and comparable verification. Use the manual remediation steps below.",
    proposedChanges: ["No automatic change is supported for this finding. Manual remediation only; no website changes will be executed from this proposal."],
    manualGuidance,
    risk: "high" as const,
    requiresApproval: true as const,
    verificationPlan: ["Repeat the relevant scan and confirm the original finding is gone without new availability or high-severity findings."],
  };
  return { proposal, instructions, candidate };
}

/** Deterministic, evidence-based guidance for issue review when no model is configured or available. */
export function deterministicIssueRecommendation(issue: { fingerprint: string; title: string; description: string }, evidence: unknown) {
  const plan = boundedRepairPlan(issue, evidence);
  return {
    kind: plan.candidate ? "supported_candidate" as const : "manual_guidance" as const,
    summary: plan.proposal.rationale,
    proposedChanges: plan.proposal.proposedChanges,
    manualGuidance: plan.proposal.manualGuidance ?? [],
    risk: plan.proposal.risk,
    verificationPlan: plan.proposal.verificationPlan,
    executableOperation: plan.candidate?.operation ?? null,
    requiresApproval: true as const,
  };
}

/** Deterministic diagnosis keeps observed facts separate from unconfirmed causes. */
export function deterministicIssueDiagnosis(input: {
  website: { name: string; url: string };
  fingerprint: string;
  title: string;
  description: string;
  severity: string;
  evidence: unknown;
}) {
  const root = objectRecord(input.evidence);
  const browser = objectRecord(root?.browser);
  const finding = objectRecord(browser?.finding);
  const pageUrl = typeof finding?.pageUrl === "string" ? finding.pageUrl
    : typeof finding?.sourcePage === "string" ? finding.sourcePage : null;
  const fact = input.description.trim() || input.title;
  const recommendation = deterministicIssueRecommendation({ fingerprint: input.fingerprint, title: input.title, description: input.description }, input.evidence);
  return {
    kind: "deterministic" as const,
    issueTitle: input.title,
    category: categoryForFingerprint(input.fingerprint),
    description: input.description,
    affectedWebsite: input.website.url,
    affectedPage: pageUrl,
    affectedComponent: typeof finding?.selector === "string" ? finding.selector
      : typeof finding?.plugin === "string" ? finding.plugin : null,
    severity: ["low", "medium", "high", "critical"].includes(input.severity) ? input.severity : "medium",
    confidence: null,
    facts: [{ claim: fact, basis: "directly recorded finding" }],
    hypotheses: [],
    probableRootCause: { claim: "Not established by deterministic evidence rules.", status: "insufficient_evidence" as const },
    alternativeExplanations: [],
    recommendedFix: {
      description: recommendation.proposedChanges[0] ?? "Review the recorded evidence and follow the manual guidance.",
      risk: recommendation.risk,
      approvalRequired: true as const,
      verificationProcedure: recommendation.verificationPlan,
    },
    recommendation,
  };
}

function categoryForFingerprint(fingerprint: string) {
  if (/^(?:wp:)?(?:security|integrity):/.test(fingerprint)) return "security";
  if (/accessibility|missing-image-alt|missing-form-label/.test(fingerprint)) return "accessibility";
  if (/slow|lcp|cls|resource/.test(fingerprint)) return "performance";
  if (/overflow|responsive|mobile-navigation/.test(fingerprint)) return "responsive";
  if (/php-|plugin|theme|wp:/.test(fingerprint)) return "wordpress";
  if (/availability/.test(fingerprint)) return "availability";
  if (/security|ssl|tls|certificate/.test(fingerprint)) return "security";
  if (/link|javascript|console|request|http/.test(fingerprint)) return "functionality";
  return "unknown";
}

// Shared order of work for any compromise finding: preserve evidence, contain,
// clean, close the entry point, then prove the fix from outside the site.
const COMPROMISE_CLEANUP_STEPS = [
  "Take a full files-and-database backup from the hosting panel before changing anything; it is both evidence and a fallback.",
  "In the WordPress plugin, select Collect and sync diagnostics to refresh the integrity scan: it lists modified core files, unknown PHP files, malware code patterns, injected .htaccess rules and recently created administrators.",
  "Replace WordPress core (wp-admin, wp-includes and root files) with a fresh copy of the same version from wordpress.org, keeping wp-config.php and wp-content. Remove every file the integrity scan lists as unknown or as matching malware patterns, after confirming it is not part of a known plugin.",
  "Restore .htaccess to the standard WordPress block and delete any physical robots.txt or sitemap files the site did not create on purpose.",
  "Reinstall every plugin and theme from its official source, delete unused ones (WP File Manager-style tools are common entry points), and remove unknown administrator accounts.",
  "Rotate all administrator, hosting, SFTP and database passwords and generate new WordPress salts in wp-config.php, which signs every session out.",
  "Run a Security check in Website Doctor and confirm Googlebot and visitors now receive the same page, then in Google Search Console review Security issues, resubmit the real sitemap and request removal of the spam URLs.",
];

function manualRemediationGuidance(issueFingerprint: string, description: string, rawEvidence: unknown): string[] {
  const fingerprint = issueFingerprint.replace(/^wp:/, "");
  if (fingerprint === "security:blank-homepage") return [
    "Load the home page in a private window and compare it with the Googlebot sample in the evidence; a blank page together with full content for crawlers means malware, not a theme error.",
    "If no cloaking finding accompanies this, check the plugin's fatal-error and PHP-log findings and the host's PHP error log for the request time; a suppressed fatal in the theme or a plugin is the usual cause.",
    "If index.php is listed as a modified core file in the integrity scan, follow the compromise cleanup for the site instead of debugging the theme.",
    "After the fix, run a Security check and confirm the browser sample returns the real page.",
  ];
  if (fingerprint.startsWith("security:") || fingerprint.startsWith("integrity:")) {
    const specific: Record<string, string> = {
      "security:cloaking": "The evidence shows the exact responses: compare the browser and Googlebot samples (status, size, title, language). The injection point is usually a modified index.php, an .htaccess rule matching crawler user agents, or a PHP file included early in wp-config.php or a must-use plugin.",
      "security:search-redirect": "Visitors arriving from search are sent to another domain; check .htaccess for HTTP_REFERER conditions and the integrity scan for files matching search_referrer_check or crawler_cloaking.",
      "security:sitemap-spam": "The spam URLs are generated by injected code, not stored as WordPress posts; deleting posts will not remove them. Find the generator through the integrity scan (modified index.php or unknown root PHP files).",
      "security:robots-sitemaps": "robots.txt is usually a physical file written by the malware; the integrity scan reports whether a physical robots.txt exists and how many sitemaps it lists.",
      "integrity:malware-signatures": "Each listed file matched code patterns used by backdoors and spam loaders. Review each one; matches in a file you recognize from a reputable plugin can be false positives.",
      "integrity:core-modified": "Core files must match the official release byte for byte; restore exactly the listed files from the same WordPress version.",
      "integrity:htaccess": "The listed lines sit outside the # BEGIN/END WordPress block; remove them and keep only the WordPress block plus rules you added deliberately (for example security-plugin rules).",
      "integrity:unknown-core-php": "WordPress never adds files to these directories on its own; anything not in the official checksum list was placed there by a person or by malware.",
      "integrity:uploads-php": "Executable files in uploads are almost never legitimate; also add a rule preventing PHP execution in wp-content/uploads.",
      "integrity:content-root-php": "Confirm each file belongs to a known plugin or the host (some caching plugins add drop-ins); remove the rest.",
      "integrity:robots-file": "A physical robots.txt overrides the one WordPress generates; delete it unless you created it on purpose.",
      "integrity:recent-admin": "Confirm with your team who created each listed account; delete unknown ones and review their posts and settings changes.",
    };
    return [specific[fingerprint] ?? description.slice(0, 300), ...COMPROMISE_CLEANUP_STEPS];
  }
  if (fingerprint.startsWith("browser:broken-link:")) return [
    "Open the recorded source page and confirm the destination as a visitor and while signed in; the scan confirms only same-origin HTTP 404/410 responses or missing same-page anchors.",
    "If the destination moved, update the source link or add a deliberate permanent redirect. Avoid redirecting every missing URL to the home page.",
    "Check the CMS/editor, navigation menu, template, or shortcode that owns the link, then rerun the link scan.",
  ];
  if (/browser:(slow-page-load|poor-lcp|poor-cls|large-resource|slow-resource|resource-heavy-page):/.test(fingerprint)) return [
    "Use the recorded page, viewport, resource URL, and timing/size observation to identify the responsible image, script, stylesheet, font, or server response.",
    "Reproduce with a cold and a warm browser load; compare the same page and viewport before changing caching, compression, media, or third-party integrations.",
    "Apply one change at a time in staging and repeat the browser scan. These browser samples are triage measurements, not field Core Web Vitals.",
  ];
  if (fingerprint.startsWith("browser:accessibility-color-contrast:")) return [
    "Open the finding's evidence: each listed element shows its text colour, background colour and measured contrast (for example \"contrast of 2.9 … expected 4.5:1\").",
    "Darken the text colour or lighten the background until normal text reaches at least 4.5:1 and large text (24px, or 19px bold) at least 3:1. Change it where the colour is defined once: Elementor → Site Settings → Global Colors, the theme Customizer, or the block's style. That fixes every page that uses it.",
    "This is a design change, so it is never made automatically. The next daily browser check confirms the fix.",
  ];
  if (fingerprint.startsWith("browser:accessibility-target-size:")) return [
    "Open the finding's evidence to see the small links or icons (usually social icons, pagination dots or footer links).",
    "Make each one at least 24×24 pixels, or leave at least 24 pixels between neighbouring targets: increase the icon size or padding in the widget's style settings, or the spacing between items.",
    "This changes the layout, so it is never made automatically. The next daily browser check confirms the fix.",
  ];
  if (/browser:accessibility-(?:link-name|button-name|label|select-name|meta-viewport):|browser:missing-form-label:/.test(fingerprint)) return [
    "Use the Fix button: AI Website Doctor 0.9.0+ adds the missing names and labels (or removes the zoom block) to every page as it is sent, without editing the theme. It can be switched off under Accessibility.",
    "For a permanent fix in the source, add the text in the widget or block settings (for example the icon's \"Aria label\" or \"Title\" field in Elementor, or a label for the form field).",
    "The next daily browser check confirms the finding is gone.",
  ];
  if (/browser:(accessibility-|missing-image-alt|missing-form-label)/.test(fingerprint)) return [
    "Inspect the recorded axe-core rule and affected DOM nodes; verify the issue with keyboard and assistive-technology behavior.",
    "Update the owning block, theme template, or plugin markup (for example, provide meaningful image alternative text or an associated form label). Do not hide the affected element to silence the rule.",
    "Rerun the accessibility scan and manually review the changed interaction; automated checks do not establish WCAG conformance.",
  ];
  if (/browser:(horizontal-overflow|mobile-navigation)/.test(fingerprint)) return [
    "Reproduce at the recorded viewport and inspect the identified page/component and its computed dimensions or navigation state.",
    "Adjust the owning theme/block CSS or menu behavior in staging, checking content, keyboard operation, and nearby breakpoints.",
    "Rerun responsive scans at the tested widths and inspect the affected page manually before deploying.",
  ];
  if (/browser:(javascript-error|console-error|failed-request|page-http-error)/.test(fingerprint)) return [
    "Inspect the recorded URL, HTTP status or browser error, request initiator, and timestamp; distinguish first-party failures from extensions, consent blockers, and third-party services.",
    "Correlate the browser observation with the hosting/PHP/application logs and reproduce the affected user flow before changing code or configuration.",
    "Make the smallest source-specific change in staging, then repeat the browser scan and the affected interaction.",
  ];
  if (/php-fatal:|php-log:/.test(fingerprint)) return [
    `Use the recorded PHP error message and basename/line (${description.slice(0, 240)}) to locate the owning plugin, theme, or custom code; correlate it with the event time and the site's full protected logs.`,
    "Check the component's compatibility and recent deployment/update history, then reproduce on staging with the same PHP and WordPress versions.",
    "Use the host's normal backup and rollback process before changing code, disabling a component, changing PHP settings, or clearing logs. The plugin does not have a full filesystem/database recovery point.",
    "After the manual fix, sync fresh WordPress diagnostics and rerun the browser/availability scan; confirm the new error does not recur.",
  ];
  if (/plugin-update:/.test(fingerprint)) return [
    "Review the plugin vendor's release notes and compatibility requirements, then update a backed-up staging copy first.",
    "Exercise the site's critical forms, checkout, login, and scheduled tasks on staging before applying the update in production.",
    "Keep a host-level database and files backup available, and rerun WordPress and browser diagnostics after deployment.",
  ];
  if (/wp-debug-enabled/.test(fingerprint)) return [
    "Confirm whether troubleshooting is still in progress and ensure debug output is not displayed to visitors.",
    "If disabling debug mode, edit the site's protected wp-config.php or deployment configuration through the host's normal change process; the plugin cannot back up or edit that file.",
    "Keep authorized log collection disabled unless needed, protect and rotate existing logs, and verify the public site no longer displays diagnostics.",
  ];
  if (/wp-cron-disabled|overdue-wp-cron|cron-failed:/.test(fingerprint)) return [
    "Inspect the scheduled hook, its last run/failure, site traffic, and the hosting provider's system-cron configuration.",
    "For disabled WP-Cron, configure and verify a host-level scheduler before relying on it; for failed hooks, diagnose the owning plugin/theme callback and avoid deleting queued events blindly.",
    "Run the affected scheduled task safely on staging, then verify its next execution and sync fresh task history.",
  ];
  if (/php-version-low/.test(fingerprint)) return [
    "Check the host's supported PHP versions and the compatibility of WordPress core, the active theme, and all required plugins.",
    "Upgrade PHP on a backed-up staging site first and exercise critical site workflows; coordinate the production version switch with the host.",
    "Rerun WordPress diagnostics and browser checks after the host applies the change.",
  ];
  if (/availability/.test(fingerprint)) return [
    "Check the hosting/provider status, DNS, TLS certificate, origin health, and recent deployment or traffic changes.",
    "Compare the central HTTP result with protected web-server/PHP logs and the site's own monitoring; the central scan cannot inspect host-level logs.",
    "Restore service through the hosting or deployment process, then rerun availability and browser scans.",
  ];
  const root = objectRecord(rawEvidence);
  if (issueFingerprint.startsWith("wp:staging-conflict:") && root?.conflictTesting) return [
    "Review the disposable-staging component comparison and confirm it matches the current production plugin/theme versions.",
    "If the implicated component is still exact and the central proposal contains an allowlisted operation, review its recovery scope and verification plan before approval; otherwise perform the change manually on staging.",
    "Do not deactivate components on production solely from a live-site observation. Re-run central browser verification after any approved change.",
  ];
  return [
    "Review the recorded finding and evidence references, then reproduce the behavior on the site before changing anything.",
    "Use the owning WordPress component's supported settings or the host/deployment process; back up the database and files before a manual change.",
    "Rerun the relevant WordPress, availability, or browser scan and compare the new evidence with this finding.",
  ];
}

/** Only offer executable WordPress repairs backed by an isolated staging comparison. */
export function evidenceBackedRepairs(issueFingerprint: string, rawEvidence: unknown): EvidenceBackedRepair[] {
  const root = objectRecord(rawEvidence);
  if (issueFingerprint.startsWith("browser:horizontal-overflow:") && root?.environmentType === "staging") {
    const browser = objectRecord(root.browser);
    const finding = objectRecord(browser?.finding);
    const pageUrl = typeof finding?.pageUrl === "string" ? finding.pageUrl : "";
    const observations = Array.isArray(finding?.observations) ? finding.observations.map(objectRecord) : [finding];
    const candidates = observations.flatMap((observation) => Array.isArray(observation?.overflowingElements)
      ? observation.overflowingElements.map(objectRecord)
      : []);
    const pages = Array.isArray(root.editablePages) ? root.editablePages.map(objectRecord) : [];
    let scannedPage: URL | null = null;
    try { scannedPage = new URL(pageUrl); } catch { /* Invalid evidence cannot authorize a CSS change. */ }
    if (!scannedPage || scannedPage.search || scannedPage.hash) return [];
    const page = pages.find((item) => {
      if (typeof item?.url !== "string" || !Number.isSafeInteger(item.id) || Number(item.id) < 1 || Number(item.id) > 9_999_999_999
        || typeof item.postType !== "string" || !/^[a-z0-9_-]{1,40}$/i.test(item.postType)) return false;
      try {
        const editableUrl = new URL(item.url);
        return editableUrl.origin === scannedPage!.origin
          && editableUrl.pathname.replace(/\/+$/, "") === scannedPage!.pathname.replace(/\/+$/, "");
      } catch { return false; }
    });
    const element = candidates.find((item) => item
      && typeof item.selector === "string"
      && item.selector.length <= 160
      && /^(?:#[A-Za-z_][A-Za-z0-9_-]*|\.[A-Za-z_][A-Za-z0-9_-]*)$/.test(item.selector)
      && typeof item.width === "number" && Number.isFinite(item.width)
      && typeof item.parentWidth === "number" && Number.isFinite(item.parentWidth)
      && item.parentWidth > 0 && item.width >= item.parentWidth + 8
      && item.width <= 20_000);
    if (!page || !element) return [];
    const pageClass = page.postType === "page" ? "page-id" : "postid";
    const selector = `body.${pageClass}-${page.id} ${element.selector}`;
    return [{
      operation: "add_scoped_css_rule",
      parameters: { selector },
      description: `On the staging site, add max-width: 100% to ${selector}; the browser measured this element at ${element.width}px inside a ${element.parentWidth}px parent on ${pageUrl}.`,
      verificationFingerprints: [issueFingerprint],
      baselineHighFingerprints: [],
    }];
  }
  if (issueFingerprint.startsWith("browser:broken-link:")) {
    const browser = objectRecord(root?.browser);
    const finding = objectRecord(browser?.finding);
    const pageUrl = typeof finding?.sourcePage === "string" ? finding.sourcePage : "";
    const linkUrl = typeof finding?.href === "string" ? finding.href : "";
    const replacementUrl = typeof root?.requestedReplacementUrl === "string" ? root.requestedReplacementUrl : "";
    const postId = (Array.isArray(root?.editablePages) ? root.editablePages : []).map(objectRecord)
      .find((page) => page?.url === pageUrl && Number.isSafeInteger(page.id) && Number(page.id) > 0)?.id;
    let source: URL | null = null;
    let oldLink: URL | null = null;
    let destination: URL | null = null;
    try {
      source = new URL(pageUrl);
      oldLink = new URL(linkUrl);
      destination = new URL(replacementUrl);
    } catch { /* Invalid or absent user selection cannot authorize an operation. */ }
    if (finding?.kind === "missing_page" && [404, 410].includes(Number(finding.statusCode))
      && typeof postId === "number" && source && oldLink && destination
      && source.origin === oldLink.origin && source.origin === destination.origin
      && !source.search && !source.hash && !oldLink.hash && !oldLink.search
      && !destination.search && !destination.hash && replacementUrl !== linkUrl) {
      return [{
        operation: "replace_post_link",
        parameters: { postId: String(postId), pageUrl, linkUrl, replacementUrl },
        description: `In published WordPress post ${postId}, replace exactly ${linkUrl} (confirmed HTTP ${Number(finding.statusCode)}) with the explicitly selected, reachable URL ${replacementUrl}.`,
        verificationFingerprints: [issueFingerprint],
        baselineHighFingerprints: [],
      }];
    }
    return [];
  }
  if (issueFingerprint.startsWith("browser:link-redirect:")) {
    const browser = objectRecord(root?.browser);
    const finding = objectRecord(browser?.finding);
    const pageUrl = typeof finding?.sourcePage === "string" ? finding.sourcePage : "";
    const linkUrl = typeof finding?.href === "string" ? finding.href : "";
    const replacementUrl = typeof finding?.replacementUrl === "string" ? finding.replacementUrl : "";
    const postId = (Array.isArray(root?.editablePages) ? root.editablePages : []).map(objectRecord)
      .find((page) => page?.url === pageUrl && Number.isSafeInteger(page.id) && Number(page.id) > 0)?.id;
    const chain = Array.isArray(finding?.redirectChain) ? finding.redirectChain.map(objectRecord) : [];
    let source: URL | null = null;
    let oldLink: URL | null = null;
    let destination: URL | null = null;
    try {
      source = new URL(pageUrl);
      oldLink = new URL(linkUrl);
      destination = new URL(replacementUrl);
    } catch { /* Invalid evidence cannot authorize an operation. */ }
    if (finding?.kind === "permanent_redirect" && typeof postId === "number" && source && oldLink && destination
      && source.origin === oldLink.origin && source.origin === destination.origin
      && !source.search && !source.hash && !oldLink.hash && !destination.search && !destination.hash
      && Number(finding.statusCode) >= 200 && Number(finding.statusCode) < 300
      && chain.length > 0 && chain.every((hop) => hop && [301, 308].includes(Number(hop.status)))) {
      return [{
        operation: "replace_post_link",
        parameters: { postId: String(postId), pageUrl, linkUrl, replacementUrl },
        description: `Update the permanent-redirecting link in published WordPress post ${postId} from ${linkUrl} to its verified same-origin destination ${replacementUrl}.`,
        verificationFingerprints: [issueFingerprint],
        baselineHighFingerprints: [],
      }];
    }
    return [];
  }
  if (issueFingerprint.startsWith("wp:php-fatal:")) {
    const fatalId = issueFingerprint.slice("wp:php-fatal:".length);
    const recentFatalEvents = (Array.isArray(root?.fatalErrors) ? root.fatalErrors : [])
      .map(objectRecord)
      .filter((item) => item?.id === fatalId && typeof item.observedAt === "string"
        && Number.isFinite(Date.parse(item.observedAt))
        && Date.parse(String(root?.collectedAt ?? "")) - Date.parse(item.observedAt) <= 24 * 60 * 60 * 1000
        && Date.parse(String(root?.collectedAt ?? "")) >= Date.parse(item.observedAt));
    const implicatedPlugins = [...new Set(recentFatalEvents.flatMap((item) => typeof item?.plugin === "string" ? [item.plugin] : []))];
    const pluginFile = implicatedPlugins.length === 1 ? implicatedPlugins[0] : "";
    const installedPlugins = Array.isArray(root?.plugins) ? root.plugins.map(objectRecord) : [];
    const matched = installedPlugins.find((plugin) => plugin?.file === pluginFile && plugin.active === true);
    if (!matched || !/^(?!\/)(?!.*(?:^|\/)\.\.?\/)[a-z0-9._/-]+\.php$/i.test(pluginFile)) return [];
    return [{
      operation: "disable_plugin",
      parameters: { plugin: pluginFile },
      description: `Deactivate ${pluginFile}, the active plugin whose code path produced this recent PHP fatal error. This is a temporary containment step; it may disable features provided by that plugin.`,
      verificationFingerprints: [issueFingerprint.slice(3)],
      baselineHighFingerprints: [],
    }];
  }
  if (!issueFingerprint.startsWith("wp:staging-conflict:")) return [];
  const report = objectRecord(root?.conflictTesting);
  if (report?.environment !== "disposable_staging" || report.status !== "completed" || report.liveDeactivationPerformed !== false) return [];
  const expected = issueFingerprint.slice("wp:".length);
  const activePlugins = new Set(Array.isArray(report.activePlugins) ? report.activePlugins.filter((item): item is string => typeof item === "string") : []);
  const installedPlugins = new Set(Array.isArray(root?.plugins)
    ? root.plugins.flatMap((item) => {
      const plugin = objectRecord(item);
      return plugin?.active === true && typeof plugin.file === "string" ? [plugin.file] : [];
    })
    : []);
  const availableRepairs: EvidenceBackedRepair[] = [];
  for (const rawFinding of Array.isArray(report.findings) ? report.findings : []) {
    const finding = objectRecord(rawFinding);
    const components = Array.isArray(finding?.components) ? finding.components.filter((item): item is string => typeof item === "string") : [];
    if (finding?.result !== "conflict" || components.length === 0) continue;
    const fingerprint = `staging-conflict:${createHash("sha256").update(components.join("|")).digest("hex").slice(0, 32)}`;
    if (fingerprint !== expected) continue;
    const baseline = readFindingFingerprints(finding.baselineFindings);
    const probe = readFindingFingerprints(finding.probeFindings);
    if (!baseline.length || !baseline.some((item) => !probe.some((seen) => seen.fingerprint === item.fingerprint))) continue;
    const backup = baseline.filter((item) => item.severity === "high" || item.severity === "critical").map((item) => item.fingerprint);
    if (components.length === 1 && activePlugins.has(components[0]) && installedPlugins.has(components[0])) {
      availableRepairs.push({
        operation: "disable_plugin",
        parameters: { plugin: components[0] },
        description: `Disable ${components[0]}, which was isolated as a contributor in disposable staging.`,
        verificationFingerprints: baseline.map((item) => item.fingerprint),
        baselineHighFingerprints: backup,
      });
    } else if (components.length === 2
      && components[0] === `theme:${String(report.activeTheme ?? "")}`
      && components[1].startsWith("theme:")
      && /^[a-z0-9_-]+$/i.test(components[1].slice("theme:".length))) {
      availableRepairs.push({
        operation: "switch_theme",
        parameters: { stylesheet: components[1].slice("theme:".length) },
        description: `Switch to ${components[1].slice("theme:".length)}, which removed the recorded browser findings in disposable staging.`,
        verificationFingerprints: baseline.map((item) => item.fingerprint),
        baselineHighFingerprints: backup,
      });
    }
  }
  return availableRepairs.slice(0, 1);
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function readFindingFingerprints(value: unknown): Array<{ fingerprint: string; severity: string }> {
  if (!Array.isArray(value) || value.length > 100) return [];
  return value.flatMap((item) => {
    const finding = objectRecord(item);
    return typeof finding?.fingerprint === "string" && typeof finding.severity === "string"
      ? [{ fingerprint: finding.fingerprint, severity: finding.severity }]
      : [];
  });
}

export function deriveRepairStatus(input: {
  executionStatus: "completed" | "failed";
  verificationStatus: "passed" | "failed" | "inconclusive";
  rollbackApplied: boolean;
  rollbackRequired: boolean;
}): string {
  if (input.rollbackApplied) return "rolled_back";
  if (input.rollbackRequired) return "rollback_required";
  if (input.executionStatus === "failed") return "failed";
  if (input.verificationStatus === "passed") return "verified";
  if (input.verificationStatus === "failed") return "verification_failed";
  return "inconclusive";
}
