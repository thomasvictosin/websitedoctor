"use client";

import { FormEvent, useCallback, useEffect, useState, type ReactNode } from "react";
import { HostingManager } from "./hosting-manager";
import { BackupsManager } from "./backups-manager";
import { CleanupManager } from "./cleanup-manager";
import { useConfirm } from "./confirm-dialog";
import { IssueBoard, isOpenIssue } from "./issue-board";
import { CloudflarePanel, ProtectionManager } from "./protection-manager";
import { RepairCentre, type LegacyRepairRow } from "./repair-centre";
import { McpAccessManager } from "./mcp-access-manager";
import { IntegrationsSettings } from "./integrations-settings";
import { AccessibilityFixes, PerformancePanel } from "./performance-panel";
import { RenewalsPanel, UpcomingRenewals } from "./renewals-panel";
import { PackageUploadDialog, SoftwarePanel, type UploadTarget } from "./software-panel";
import { parseAssistantRepairPermissionCommand } from "@/lib/repair-assistant-intent";

type Check = {
  id: string;
  checkedAt: string;
  available: boolean;
  statusCode: number | null;
  responseTime: number | null;
  error: string | null;
};

type Website = {
  id: string;
  name: string;
  url: string;
  environmentType: "production" | "staging";
  relatedWebsiteId: string | null;
  relatedWebsite?: { id: string; name: string; url: string; environmentType: "production" | "staging" } | null;
  monitoringEnabled: boolean;
  intervalMinutes: number;
  checks: Check[];
  _count: { issues: number };
  wordpressAgent: null | {
    id: string;
    siteName: string;
    siteUrl: string;
    wpVersion: string | null;
    phpVersion: string | null;
    pluginVersion: string;
    diagnostics: {
      site?: { activeTheme?: { name?: string }; overdueCronCount?: number };
      plugins?: Array<{ active: boolean; updateAvailable: boolean }>;
      phpErrors?: Array<{ level: string; message: string; file: string; line: number }>;
      phpErrorLog?: { collectionEnabled: boolean; status: string; observedCount: number; limit: number };
      issues?: Array<{ title: string; severity: string }>;
      settings?: { blogname?: string; blogdescription?: string };
    } | null;
    lastSeenAt: string;
    revokedAt: string | null;
    executions: Array<{
      id: string;
      status: string;
      createdAt: string;
      repair: { issue: { title: string } | null };
    }>;
  };
};

// Issue.diagnosis.diagnosis holds either an AI diagnosis (lib/ai/engine.ts) or
// a deterministic one (deterministicIssueDiagnosis in lib/repair-policy.ts,
// stored by "Diagnose Without AI" and when AI is unavailable). Deterministic
// diagnoses have no evidence-reference arrays and a null confidence, so those
// fields are optional here and must be read defensively when rendering.
type StructuredDiagnosis = {
  kind?: "deterministic";
  issueTitle: string;
  issueTitleEvidenceRefs?: string[];
  category: string;
  description: string;
  descriptionEvidenceRefs?: string[];
  affectedWebsite: string;
  affectedPage: string | null;
  affectedComponent: string | null;
  severity: string;
  confidence: number | null;
  facts?: Array<{ claim: string; evidenceRefs?: string[]; basis?: string }>;
  hypotheses?: Array<{ claim: string; evidenceRefs?: string[] }>;
  probableRootCause?: {
    claim: string;
    status: "hypothesis" | "insufficient_evidence";
    evidenceRefs?: string[];
  };
  alternativeExplanations?: Array<{ explanation: string; evidenceRefs?: string[] }>;
  recommendedFix?: {
    description: string;
    evidenceRefs?: string[];
    risk: string;
    approvalRequired: true;
    verificationProcedure?: string[];
  };
  evidenceReferences?: Array<{ id: string; path: string; value: unknown }>;
};

function diagnosisConfidenceLabel(confidence: number | null | undefined) {
  return typeof confidence === "number" && Number.isFinite(confidence)
    ? `${Math.round(confidence * 100)}% confidence`
    : "deterministic rules, no AI confidence score";
}

type Issue = {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  confidence: number | null;
  toolIds: string[];
  evidence: unknown;
  diagnosis: {
    status?: string;
    error?: string | null;
    diagnosis?: StructuredDiagnosis | null;
  } | null;
  lastSeenAt: string;
  resolvedAt?: string | null;
  website: { id: string; name: string; url: string };
  repairs: Array<{
    id: string;
    status: string;
    risk: string;
    initiatingInterface: string;
    operationIds: string[];
    requiredPermissions: string[];
    approvalStatus: string;
    backupStatus: string;
    executionStatus: string;
    verificationStatus: string;
    rollbackStatus: string;
    createdAt: string;
    proposal: {
      issue: string;
      rationale: string;
      proposedChanges: string[];
      expectedImpact?: string;
      recoveryAvailability?: string;
      requiresApproval: boolean;
      verificationPlan: string[];
      manualGuidance?: string[];
      executionAvailable?: boolean;
      hostingRequest?: { executionEnabled: boolean };
      instructions?: {
        steps?: Array<{ description: string; operation: string; parameters: Record<string, string> }>;
        rollbackPlan?: string[];
      };
    };
    events: Array<{ id: string; eventType: string; actor: string; createdAt: string }>;
    approvals?: Array<{ id: string; decision: string; comment: string | null; createdAt: string }>;
    verificationResults?: Array<{ id: string; status: string; method: string; result: unknown; createdAt: string }>;
  }>;
};

function RepairApprovalDetails({ repair }: { repair: Issue["repairs"][number] }) {
  const steps = repair.proposal.instructions?.steps ?? [];
  if (steps.length === 0) return null;
  return <section className="repair-approval-details" aria-label="Exact proposed change and verification plan">
    <h4>Exact change and scope</h4>
    <ol>{steps.map((step, index) => <li key={`${step.operation}-${index}`}>
      <strong>{step.operation.replaceAll("_", " ")}</strong> — {step.description}
      <dl>{Object.entries(step.parameters).map(([key, value]) => <div key={key}><dt>{key.replaceAll(/([A-Z])/g, " $1").replaceAll("_", " ")}</dt><dd>{value}</dd></div>)}</dl>
    </li>)}</ol>
    <p>Scope is limited to the target and current value shown above. No additional posts, links, or settings are included.</p>
    <h4>Verification before success</h4>
    <ul>{repair.proposal.verificationPlan.map((step, index) => <li key={index}>{step}</li>)}</ul>
    <p>If verification fails or cannot complete, the plugin attempts to restore this operation’s saved prior value before reporting the outcome.</p>
  </section>;
}

type Settings = {
  aiProvider: string;
  aiConfigured: boolean;
  scheduledMonitoring: boolean;
  authentication: string;
};

type DashboardView = "dashboard" | "websites" | "issues" | "repairs" | "assistant" | "team" | "settings";
type RepairAuthorizationPolicy = { mode: "manual" | "auto_eligible"; allowedOperations: string[]; maxRisk: "low" | "medium" | "high"; maxRepairsPerBatch: number; requireRecoveryPoint: true; requireVerification: true; paused: boolean };
const repairOperationDescriptions = [
  ["replace_post_link", "Replace one exact broken or redirecting URL in one mapped published post."],
  ["update_setting", "Change one explicitly identified site name or description setting."],
  ["disable_plugin", "Temporarily deactivate one plugin isolated by staging or mapped to a recent fatal error."],
  ["switch_theme", "Switch to one verified installed theme based on disposable staging evidence."],
] as const;
type TeamMember = { id: string; email: string; name: string; role: string; disabledAt: string | null; createdAt: string };
type AssistantMessage = {
  role: "user" | "assistant";
  content: string;
  evidenceReferences?: Array<{ id: string; path: string; value: unknown }>;
};
type DeterministicRecommendation = { kind: "supported_candidate" | "manual_guidance"; summary: string; proposedChanges: string[]; manualGuidance: string[]; risk: string; verificationPlan: string[]; executableOperation: string | null; requiresApproval: true };

const textList = (value: unknown) => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

/**
 * Give every repair proposal the fields the UI renders. Proposals come from
 * several generations of the app (repairs, manual guidance, cleanup and
 * maintenance runs); one record missing a list must never break the page.
 */
function normalizeIssues(issues: Issue[]): Issue[] {
  return (Array.isArray(issues) ? issues : []).map((issue) => ({
    ...issue,
    toolIds: textList(issue.toolIds),
    repairs: (Array.isArray(issue.repairs) ? issue.repairs : []).map((repair) => {
      const proposal = (repair.proposal && typeof repair.proposal === "object" ? repair.proposal : {}) as Issue["repairs"][number]["proposal"];
      return {
        ...repair,
        operationIds: textList(repair.operationIds),
        events: Array.isArray(repair.events) ? repair.events : [],
        proposal: {
          ...proposal,
          issue: typeof proposal.issue === "string" ? proposal.issue : issue.title,
          rationale: typeof proposal.rationale === "string" ? proposal.rationale : "",
          proposedChanges: textList(proposal.proposedChanges),
          verificationPlan: textList(proposal.verificationPlan),
          manualGuidance: proposal.manualGuidance === undefined ? undefined : textList(proposal.manualGuidance),
        },
      };
    }),
  }));
}

export default function Home() {
  const [websites, setWebsites] = useState<Website[]>([]);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [memberEmail, setMemberEmail] = useState("");
  const [memberName, setMemberName] = useState("");
  const [memberPassword, setMemberPassword] = useState("");
  const [memberRole, setMemberRole] = useState<"member" | "admin">("member");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [environmentType, setEnvironmentType] = useState<"production" | "staging">("production");
  const [relatedWebsiteId, setRelatedWebsiteId] = useState("");
  const [monitoringEnabled, setMonitoringEnabled] = useState(false);
  const [intervalMinutes, setIntervalMinutes] = useState(60);
  const [busy, setBusy] = useState<string | null>(null);
  const dialogs = useConfirm();
  const [fixInProgress, setFixInProgress] = useState(false);
  const [siteQuery, setSiteQuery] = useState("");
  const [siteFilter, setSiteFilter] = useState<"all" | "attention" | "healthy" | "disconnected">("all");
  const [siteSort, setSiteSort] = useState<"worst" | "name" | "checked">("worst");
  const [message, setMessage] = useState("");
  const [scanProgress, setScanProgress] = useState<Record<string, { scanId: string; status: string; withAi: boolean }>>({});
  const [history, setHistory] = useState<Record<string, Check[]>>({});
  const [pairingCodes, setPairingCodes] = useState<Record<string, { code: string; expiresAt: string }>>({});
  const [activeView, setActiveView] = useState<DashboardView>("dashboard");
  const [uploadTarget, setUploadTarget] = useState<UploadTarget | null>(null);
  const [selectedWebsiteId, setSelectedWebsiteId] = useState<string | null>(null);
  const [websiteDetailTab, setWebsiteDetailTab] = useState<"overview" | "software" | "performance" | "renewals" | "diagnostics" | "accessibility" | "responsive" | "repair-history" | "cleanup" | "protection" | "backups" | "history" | "settings">("overview");
  const [assistantWebsiteId, setAssistantWebsiteId] = useState("");
  const [assistantQuestion, setAssistantQuestion] = useState("");
  const [assistantBusy, setAssistantBusy] = useState(false);
  const [assistantMessages, setAssistantMessages] = useState<AssistantMessage[]>([]);
  const [recommendations, setRecommendations] = useState<Record<string, DeterministicRecommendation>>({});
  const [repairPolicy, setRepairPolicy] = useState<RepairAuthorizationPolicy>({ mode: "manual", allowedOperations: [], maxRisk: "low", maxRepairsPerBatch: 10, requireRecoveryPoint: true, requireVerification: true, paused: false });
  const [repairPolicyBusy, setRepairPolicyBusy] = useState(false);
  const [repairPrompt, setRepairPrompt] = useState("");
  const [repairPromptIssueId, setRepairPromptIssueId] = useState("");
  const [selectedBatchRepairs, setSelectedBatchRepairs] = useState<string[]>([]);
  const [repairWebsiteFilter, setRepairWebsiteFilter] = useState("all");
  const [repairRiskFilter, setRepairRiskFilter] = useState("all");
  const [repairFromDate, setRepairFromDate] = useState("");
  const [repairToDate, setRepairToDate] = useState("");

  const refresh = useCallback(async () => {
    const [sitesResponse, issuesResponse, settingsResponse, membersResponse] = await Promise.all([
      fetch("/api/sites"),
      fetch("/api/issues"),
      fetch("/api/settings"),
      fetch("/api/members"),
    ]);
    const failedResponse = ([
      ["/api/sites", sitesResponse],
      ["/api/issues", issuesResponse],
      ["/api/settings", settingsResponse],
      ["/api/members", membersResponse],
    ] as const).find(([, response]) => !response.ok);
    if (failedResponse) {
      const [endpoint, response] = failedResponse;
      throw new Error(`Could not load dashboard data: ${endpoint} returned HTTP ${response.status}.`);
    }
    const [sites, currentIssues, currentSettings, memberData] = await Promise.all([
      sitesResponse.json() as Promise<Website[]>,
      issuesResponse.json() as Promise<Issue[]>,
      settingsResponse.json() as Promise<Settings>,
      membersResponse.json() as Promise<{ members: Array<{ user: TeamMember; role: string }> }>,
    ]);
    setWebsites(sites);
    setIssues(normalizeIssues(currentIssues));
    setSettings(currentSettings);
    setMembers(memberData.members.map(({ user, role }: { user: TeamMember; role: string }) => ({ ...user, role })));
    setAssistantWebsiteId((current) => current || sites[0]?.id || "");
    setSelectedWebsiteId((current) => current || sites[0]?.id || null);
  }, []);

  useEffect(() => {
    let active = true;
    const load = () => refresh().catch((error: unknown) => {
      if (active) setMessage(error instanceof Error ? error.message : "Could not load dashboard data.");
    });
    void load();
    const timer = window.setInterval(() => { void load(); }, fixInProgress ? 5_000 : 15_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [refresh, fixInProgress]);

  useEffect(() => {
    if (!selectedWebsiteId) return;
    fetch(`/api/sites/${selectedWebsiteId}/repair-authorization`).then(async (response) => {
      const result = await response.json();
      if (response.ok) setRepairPolicy(result);
    }).catch(() => setRepairPolicy({ mode: "manual", allowedOperations: [], maxRisk: "low", maxRepairsPerBatch: 10, requireRecoveryPoint: true, requireVerification: true, paused: false }));
  }, [selectedWebsiteId]);

  async function saveRepairPolicy() {
    if (!selectedWebsiteId) return;
    setRepairPolicyBusy(true);
    try {
      const response = await fetch(`/api/sites/${selectedWebsiteId}/repair-authorization`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(repairPolicy) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not save repair authorization.");
      setRepairPolicy(result);
      const enabled = result.mode === "auto_eligible" ? result.allowedOperations as string[] : [];
      const disabled = repairOperationDescriptions.map(([operation]) => operation).filter((operation) => !enabled.includes(operation));
      setMessage(`Permissions updated for ${websites.find((site) => site.id === selectedWebsiteId)?.name ?? "website"}. Automatic execution ${result.mode === "auto_eligible" && !result.paused ? "enabled" : "disabled"}. Enabled operations: ${enabled.length ? enabled.join(", ") : "none"}. Disabled operations: ${disabled.length ? disabled.join(", ") : "none"}.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not save repair authorization."); }
    finally { setRepairPolicyBusy(false); }
  }

  async function pauseAutomaticRepairs() {
    if (!selectedWebsiteId) return;
    setRepairPolicyBusy(true);
    try {
      const pausedPolicy = { ...repairPolicy, paused: true };
      const response = await fetch(`/api/sites/${selectedWebsiteId}/repair-authorization`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(pausedPolicy) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not pause automatic repairs.");
      setRepairPolicy(result);
      setMessage("Automatic repair authorization is paused. Queued standing-policy repairs were returned to approval.");
      await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not pause automatic repairs."); }
    finally { setRepairPolicyBusy(false); }
  }



  async function submitPromptRepair(targetSiteId = selectedWebsiteId, requestText = repairPrompt, selectedIssueId = repairPromptIssueId) {
    if (!targetSiteId || requestText.trim().length < 3) return;
    setRepairPolicyBusy(true);
    try {
      const response = await fetch(`/api/sites/${targetSiteId}/repair-requests`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ prompt: requestText, ...(selectedIssueId ? { issueId: selectedIssueId } : {}) }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not process repair request.");
      if (result.status === "needs_issue_selection") {
        setMessage(`${result.message} Candidates: ${(result.candidates ?? []).map((item: { title: string }) => item.title).join("; ") || "No active issues matched."}`);
        if (targetSiteId === assistantWebsiteId) setAssistantMessages((current) => [...current, { role: "assistant", content: result.message }]);
      } else if (result.status === "needs_scope_clarification") {
        setMessage(result.message);
        if (targetSiteId === assistantWebsiteId) setAssistantMessages((current) => [...current, { role: "assistant", content: result.message }]);
      } else if (result.status === "diagnosis_results") {
        setMessage(`Diagnosis request matched ${result.issues?.length ?? 0} stored issue(s). No repairs were proposed or executed.`);
        if (targetSiteId === assistantWebsiteId) setAssistantMessages((current) => [...current, { role: "assistant", content: (result.issues ?? []).map((issue: { title: string; severity: string; description: string }) => `${issue.severity}: ${issue.title} — ${issue.description}`).join("\n") || "No matching stored issues were found." }]);
      } else {
        const queued = (result.results ?? []).filter((item: { status: string }) => item.status === "queued").length;
        const approval = (result.results ?? []).filter((item: { status: string }) => item.status === "requires_approval").length;
        const guidance = (result.results ?? []).filter((item: { status: string }) => item.status === "guidance_only").length;
        setMessage(`${result.interpretationMode === "deterministic_fallback" ? "The AI was unavailable; a conservative rule-based issue match was used. " : ""}${queued} queued, ${approval} awaiting your approval, ${guidance} guidance-only, ${(result.skipped ?? []).length} skipped.`);
        if (targetSiteId === assistantWebsiteId) setAssistantMessages((current) => [...current, { role: "assistant", content: (result.results ?? []).map((item: { title: string; status: string; risk: string; repair?: { proposal?: { proposedChanges?: string[] } } }) => `${item.status} · ${item.risk} risk · ${item.title}: ${item.repair?.proposal?.proposedChanges?.join("; ") ?? "No executable operation; review guidance."}`).join("\n") || "No repair plan was produced." }]);
        if (requestText === repairPrompt) setRepairPrompt("");
        if (requestText === assistantQuestion) setAssistantQuestion("");
        await refresh();
      }
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not process repair request."); }
    finally { setRepairPolicyBusy(false); }
  }

  async function approveRepairBatch() {
    if (!selectedBatchRepairs.length) return;
    setRepairPolicyBusy(true);
    try {
      const response = await fetch("/api/repairs/batch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repairIds: selectedBatchRepairs }) });
      const result = await response.json();
      if (!response.ok) throw new Error([result.error, ...(result.conflicts ?? [])].filter(Boolean).join(" ") || "Could not approve selected repairs.");
      setSelectedBatchRepairs([]);
      setMessage(`${result.approved} repair${result.approved === 1 ? "" : "s"} approved and queued. Each will run only on its connected site's next plugin poll.`);
      await refresh();
      void monitorBatchResults(result.repairIds as string[]);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not approve selected repairs."); }
    finally { setRepairPolicyBusy(false); }
  }

  async function monitorBatchResults(repairIds: string[]) {
    const terminal = new Set(["verified", "failed", "verification_failed", "inconclusive", "rolled_back", "rollback_required", "rejected"]);
    for (let attempt = 0; attempt < 12; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 5000));
      try {
        const response = await fetch("/api/issues");
        if (!response.ok) return;
        const currentIssues = await response.json() as Issue[];
        setIssues(currentIssues);
        const rows = currentIssues.flatMap((issue) => issue.repairs).filter((repair) => repairIds.includes(repair.id));
        if (rows.length === repairIds.length && rows.every((repair) => terminal.has(repair.status))) {
          const passed = rows.filter((repair) => repair.status === "verified").length;
          const recovered = rows.filter((repair) => repair.status === "rolled_back").length;
          const needsHelp = rows.filter((repair) => ["rollback_required", "failed", "verification_failed", "inconclusive"].includes(repair.status)).length;
          setMessage(`Batch complete: ${passed} verified, ${recovered} rolled back, ${needsHelp} need review. Each repair has its own verification and recovery result.`);
          return;
        }
      } catch { return; }
    }
  }

  async function addMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("member:add"); setMessage("");
    try {
      const response = await fetch("/api/members", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: memberEmail, name: memberName, temporaryPassword: memberPassword, role: memberRole }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not add member.");
      setMemberEmail(""); setMemberName(""); setMemberPassword("");
      await refresh();
      setMessage("Account created. Share its temporary password securely; the user signs in with that password.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not add member."); }
    finally { setBusy(null); }
  }

  async function removeMember(member: TeamMember) {
    if (!await dialogs.confirm({ title: `Remove ${member.email}?`, body: "They lose access to this organization immediately.", confirmLabel: "Remove member", danger: true })) return;
    setBusy(`member:remove:${member.id}`);
    try {
      const response = await fetch("/api/members", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ userId: member.id }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not remove member.");
      await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not remove member."); }
    finally { setBusy(null); }
  }

  async function addWebsite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("add");
    setMessage("");
    try {
      const response = await fetch("/api/sites", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, url, monitoringEnabled, intervalMinutes, environmentType, relatedWebsiteId: relatedWebsiteId || null }),
      });
      const responseText = await response.text();
      let result: { error?: string } = {};
      if (responseText) {
        try { result = JSON.parse(responseText) as { error?: string }; }
        catch { throw new Error(`Could not add website (server returned HTTP ${response.status} with an invalid response).`); }
      }
      if (!responseText && !response.ok) throw new Error(`Could not add website (server returned HTTP ${response.status} without a response).`);
      if (!response.ok) throw new Error(result.error ?? "Could not add website.");
      setName("");
      setUrl("");
      setEnvironmentType("production");
      setRelatedWebsiteId("");
      setMonitoringEnabled(false);
      try {
        await refresh();
      } catch {
        setMessage("Website was added, but the dashboard could not refresh. Check that the database is running, then refresh the page. Do not submit the form again.");
        return;
      }
      setMessage("Website added. Run a check to see its current status.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not add website. Check the server and database connection, then try again.");
    } finally {
      setBusy(null);
    }
  }

  async function runSecurityCheck(site: Website) {
    setBusy(`security:${site.id}`);
    setMessage(`${site.name}: checking what visitors, Googlebot and search visitors receive…`);
    try {
      const response = await fetch(`/api/sites/${site.id}/security-check`, { method: "POST" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not run the security check.");
      await refresh();
      const findings = Array.isArray(result.findings) ? result.findings as Array<{ title: string; severity: string }> : [];
      setMessage(findings.length
        ? `${site.name}: ${findings.length} security finding(s): ${findings.map((finding) => `${finding.severity.toUpperCase()} ${finding.title}`).join("; ")}. See Issues for evidence and cleanup steps.`
        : `${site.name}: no cloaking, conditional redirect, blank page or sitemap spam observed (${(result.completedChecks ?? []).join(", ") || "no checks completed"}).`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not run the security check.");
    } finally {
      setBusy(null);
    }
  }

  async function runScanWorkflow(site: Website, withAi: boolean) {
    setBusy(`scan:${site.id}`);
    setMessage("");
    try {
      const response = await fetch(`/api/sites/${site.id}/check`, { method: "POST" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not queue the automated scan.");
      if (response.status !== 202 || !result.scanSessionId) throw new Error("The scan request did not return a queued scan ID.");
      setScanProgress((current) => ({ ...current, [site.id]: { scanId: result.scanSessionId, status: "queued", withAi } }));
      setMessage(withAi
        ? `${site.name}: automated scan queued. AI will analyze findings from this scan when collection finishes.`
        : `${site.name}: automated scan queued. AI analysis is off.`);
      void completeScanWorkflow(site, result.scanSessionId, withAi);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not queue the automated scan.");
    } finally {
      setBusy(null);
    }
  }

  async function completeScanWorkflow(site: Website, scanId: string, withAi: boolean) {
    const siteId = site.id;
    for (let attempt = 0; attempt < 900; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      try {
        const response = await fetch(`/api/sites/${siteId}/scans/${scanId}`);
        const scan = await response.json();
        if (!response.ok) throw new Error(scan.error ?? "Could not retrieve scan progress.");
        setScanProgress((current) => ({ ...current, [siteId]: { scanId, status: scan.status, withAi } }));
        if (["completed", "failed", "cancelled"].includes(scan.status)) {
          await refresh();
          if (scan.status !== "completed") {
            setMessage(`${site.name}: automated scan ${scan.status}${scan.job?.lastError ? `: ${scan.job.lastError}` : "."}`);
            return;
          }
          if (!withAi) {
            setMessage("Automated scan completed. HTTP, browser, and accessibility evidence is available; AI analysis was not run.");
            return;
          }
          setBusy(`scan-ai:${siteId}`);
          setMessage("Scan completed. AI is analyzing findings recorded by this scan…");
          const issueResponse = await fetch("/api/issues");
          const siteIssues = await issueResponse.json() as Issue[];
          if (!issueResponse.ok) throw new Error("Scan completed, but its findings could not be loaded for AI analysis.");
          const scanStartedAt = new Date(scan.startedAt).getTime();
          const findings = siteIssues.filter((issue) => issue.website.id === siteId
            && issue.status !== "resolved"
            && new Date(issue.lastSeenAt).getTime() >= scanStartedAt).slice(0, 10);
          let analyzed = 0;
          let unavailable = 0;
          for (const issue of findings) {
            const analysisResponse = await fetch(`/api/issues/${issue.id}/diagnose`, { method: "POST" });
            const analysis = await analysisResponse.json();
            if (!analysisResponse.ok || analysis.aiStatus === "unavailable") {
              unavailable += 1;
              continue;
            }
            analyzed += 1;
          }
          await refresh();
          setMessage(findings.length === 0
            ? "Scan completed with no active findings to analyze. AI analysis was not needed."
            : `Scan completed for ${site.name}. AI analysis completed for ${analyzed} of ${findings.length} findings${unavailable ? `; AI was unavailable for ${unavailable}` : ""}${siteIssues.filter((issue) => issue.website.id === siteId && issue.status !== "resolved" && new Date(issue.lastSeenAt).getTime() >= scanStartedAt).length > 10 ? "; the remaining findings can be analyzed individually from Issues" : ""}.`);
          setBusy(null);
          return;
        }
      } catch (error) {
        setMessage(error instanceof Error ? error.message : "Could not complete the scan workflow.");
        setBusy(null);
        return;
      }
    }
    setMessage("The scan is still running. You can review this site again shortly.");
  }

  async function updateWebsite(site: Website, updates: Partial<Pick<Website, "monitoringEnabled" | "intervalMinutes" | "environmentType" | "relatedWebsiteId">>) {
    setBusy(`update:${site.id}`);
    try {
      const response = await fetch(`/api/sites/${site.id}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: site.name,
          url: site.url,
          environmentType: updates.environmentType ?? site.environmentType,
          relatedWebsiteId: updates.relatedWebsiteId ?? site.relatedWebsiteId,
          monitoringEnabled: updates.monitoringEnabled ?? site.monitoringEnabled,
          intervalMinutes: updates.intervalMinutes ?? site.intervalMinutes,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not update website.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not update website.");
    } finally {
      setBusy(null);
    }
  }

  async function deleteWebsite(site: Website) {
    if (!await dialogs.confirm({ title: `Remove ${site.name}?`, body: "Its monitoring history, issues and repair records are deleted from this app. The website itself is not changed.", confirmLabel: "Remove website", danger: true })) return;
    setBusy(`delete:${site.id}`);
    try {
      const response = await fetch(`/api/sites/${site.id}`, { method: "DELETE" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not remove website.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not remove website.");
    } finally {
      setBusy(null);
    }
  }

  async function loadHistory(site: Website) {
    try {
      const response = await fetch(`/api/sites/${site.id}/history`);
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not load check history.");
      setHistory((current) => ({ ...current, [site.id]: result as Check[] }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load check history.");
    }
  }

  async function toggleHistory(site: Website) {
    if (history[site.id]) {
      setHistory((current) => {
        const next = { ...current };
        delete next[site.id];
        return next;
      });
      return;
    }
    await loadHistory(site);
  }

  async function createPairing(site: Website) {
    setBusy(`pair:${site.id}`);
    setMessage("");
    try {
      const response = await fetch("/api/agents/pairings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ websiteId: site.id }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not create pairing code.");
      setPairingCodes((current) => ({ ...current, [site.id]: { code: result.code, expiresAt: result.expiresAt } }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not create pairing code.");
    } finally { setBusy(null);
    }
  }

  async function disconnectAgent(agentId: string) {
    if (!await dialogs.confirm({ title: "Revoke the WordPress agent connection?", body: "The plugin can no longer sync or run approved repairs until it is paired again.", confirmLabel: "Revoke connection", danger: true })) return;
    try {
      const response = await fetch(`/api/agents/${agentId}/disconnect`, { method: "POST" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not revoke agent.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not revoke agent.");
    }
  }

  async function copyPairingCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      setMessage("One-time pairing code copied. Treat it as a secret.");
    } catch {
      setMessage("Clipboard access failed. Select and copy the pairing code manually.");
    }
  }

  async function updateIssue(issue: Issue, status: "acknowledged" | "resolved") {
    try {
      const response = await fetch(`/api/issues/${issue.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ status }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not update issue.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not update issue.");
    }
  }

  useEffect(() => {
    setFixInProgress(issues.some((issue) => issue.repairs.some((repair) => (repair.proposal as { kind?: string }).kind === "compromise_cleanup" && ["approved", "executing"].includes(repair.status))));
  }, [issues]);

  /** A one-click run that is queued or running on this website, if any (the site runs one at a time). */
  function activeRunForSite(siteId: string) {
    for (const candidate of issues) {
      if (candidate.website.id !== siteId) continue;
      const run = candidate.repairs.find((repair) => (repair.proposal as { kind?: string }).kind === "compromise_cleanup" && ["approved", "executing"].includes(repair.status));
      if (run) return run;
    }
    return null;
  }

  /** Status line for an issue's most recent one-click fix. */
  function fixProgress(issue: Issue) {
    const run = issue.repairs.find((repair) => (repair.proposal as { kind?: string }).kind === "compromise_cleanup");
    if (!run) return null;
    if (run.status === "approved") return { active: true, text: "Waiting for the site to pick up the fix…" };
    if (run.status === "executing") return { active: true, text: "Applying the fix on the site…" };
    const age = Date.now() - new Date(run.createdAt).getTime();
    if (age > 60 * 60_000) return null;
    if (run.status === "verified") return { active: false, text: "Fixed and verified. The finding clears with the next sync." };
    if (run.status === "rolled_back") return { active: false, text: "The fix was restored." };
    return { active: false, text: "The fix did not verify; open View Repair Details below for what remains." };
  }

  /** Primary action shown on a compact issue card: the one-click fix and its progress. */
  function renderIssuePrimary(issue: Issue) {
    return <>
                  {oneClickFix(issue) && (
                    <button className="button primary" onClick={() => fixIssue(issue)} disabled={busy !== null || Boolean(activeRunForSite(issue.website.id) && oneClickFix(issue)!.confirm)}
                      title={activeRunForSite(issue.website.id) ? `The site is working on “${activeRunForSite(issue.website.id)!.proposal.issue}”; it handles one change at a time.` : undefined}>
                      {busy === `fix:${issue.id}` ? "Approving…" : issue.repairs.some((repair) => (repair.proposal as { kind?: string }).kind === "compromise_cleanup" && ["approved", "executing"].includes(repair.status)) ? "Fix in progress…" : activeRunForSite(issue.website.id) && oneClickFix(issue)!.confirm ? "Site busy…" : oneClickFix(issue)!.label}
                    </button>
                  )}
                  {issue.status !== "resolved" && /^vuln:plugin-/.test(issue.fingerprint) && oneClickFix(issue)?.label !== "Remove until fixed" && (
                    <button className="button ghost issue-secondary" disabled={busy !== null || Boolean(activeRunForSite(issue.website.id))} onClick={() => removeUntilFixed(issue)}>Remove until fixed</button>
                  )}
                  {(() => {
                    const progress = fixProgress(issue);
                    return progress ? <span className="fix-progress" role="status">{progress.active && <span className="spinner" aria-hidden="true" />}{progress.text}</span> : null;
                  })()}
    </>;
  }

  /** Everything else about an issue, shown under "Details & more actions". */
  function renderIssueDetails(issue: Issue) {
    return <div className="issue-detail-body">
                <small className="issue-page">Affected page: {issue.diagnosis?.diagnosis?.affectedPage ?? "Not identified from available evidence"}</small>
                {issue.evidence !== null && issue.evidence !== undefined && (
                  <details className="issue-evidence">
                    <summary>Diagnostic evidence</summary>
                    <pre>{JSON.stringify(issue.evidence, null, 2)}</pre>
                  </details>
                )}
                {issue.diagnosis?.diagnosis && (
                  <div className="issue-ai-diagnosis">
                    <strong>Central diagnosis · {issue.diagnosis.diagnosis.severity} · {diagnosisConfidenceLabel(issue.diagnosis.diagnosis.confidence)}</strong>
                    <DiagnosisDetails diagnosis={issue.diagnosis.diagnosis} />
                  </div>
                )}
                {recommendations[issue.id] && <div className="issue-ai-diagnosis">
                  <strong>Evidence-based recommendation · {recommendations[issue.id].kind === "supported_candidate" ? "supported change candidate" : "manual steps"} · {recommendations[issue.id].risk} risk</strong>
                  <p>{recommendations[issue.id].summary}</p>
                  <small>How this was generated: fixed rules matched this finding’s detector/fingerprint to the recorded browser or WordPress evidence. It is a bounded checklist, not an AI inference or a guaranteed root cause. If no exact safe rule matched, it returns general manual guidance.</small>
                  <ul>{recommendations[issue.id].proposedChanges.map((change, index) => <li key={index}>{change}</li>)}</ul>
                  {recommendations[issue.id].manualGuidance.length > 0 && <ol>{recommendations[issue.id].manualGuidance.map((step, index) => <li key={index}>{step}</li>)}</ol>}
                  <p><strong>Verify:</strong> {recommendations[issue.id].verificationPlan.join(" ")}</p>
                  <small>This recommendation is generated from stored evidence without AI. Any app-executed change still requires an eligible operation, recovery point, and your approval.</small>
                </div>}
                <small className="repair-availability">Repair availability: {issue.repairs.some((repair) => repair.operationIds.length > 0 && repair.proposal.executionAvailable)
                  ? "A supported operation is available for review."
                  : issue.repairs.length > 0
                    ? "No automatic operation is supported for the current proposal; manual guidance is available below."
                    : "Not assessed yet. Review a repair plan to check for a supported, evidence backed operation."}</small>
                {issue.toolIds.length > 0 && <small className="tool-evidence">Relevant evidence: {issue.toolIds.join(", ")}</small>}
                <div className="issue-actions">
                  <button className="button ghost" onClick={() => loadRecommendation(issue)} disabled={busy !== null}>
                    {busy === `recommend:${issue.id}` ? "Preparing…" : recommendations[issue.id] ? "Refresh Recommendation" : "Get Recommendation (No AI)"}
                  </button>
                  <button className="button ghost" onClick={() => diagnoseIssue(issue, false)} disabled={busy !== null}>
                    {busy === `issue-diagnose:${issue.id}` ? "Diagnosing…" : "Diagnose Without AI"}
                  </button>
                  <button className="button ghost" onClick={() => diagnoseIssue(issue, true)} disabled={busy !== null}>
                    {busy === `issue-diagnose:${issue.id}` ? "Analyzing…" : "Analyze with AI (Optional)"}
                  </button>
                  {issue.status === "open" && <button className="button ghost" onClick={() => updateIssue(issue, "acknowledged")}>Acknowledge</button>}
                  {issue.status !== "resolved" && <button className="button ghost" onClick={() => updateIssue(issue, "resolved")}>Resolve</button>}
                  <button className="button secondary" onClick={() => proposeRepair(issue)} disabled={busy !== null || issue.repairs.some((repair) => ["pending_approval", "approved", "executing", "in_progress"].includes(repair.status))}>
                    {busy === `repair:${issue.id}` ? "Preparing…" : "Review repair plan"}
                  </button>
                </div>
                {issue.repairs.map((repair) => (
                  <details className="repair-card issue-repair-details" key={repair.id}>
                    <summary>View Repair Details · {repair.risk} risk · {repair.status.replaceAll("_", " ")}</summary>
                    <p>{repair.proposal.rationale}</p>
                    {repair.proposal.expectedImpact && <p><strong>Expected impact:</strong> {repair.proposal.expectedImpact}</p>}
                    {repair.proposal.recoveryAvailability && <p><strong>Undo:</strong> {repair.proposal.recoveryAvailability}</p>}
                    {repair.status === "rollback_required" && <p className="repair-limitation"><strong>Recovery needed:</strong> The plugin could not confirm its operation-specific undo. Review the execution and verification evidence below; use your existing site recovery process if manual recovery is needed.</p>}
                    <ul>{repair.proposal.proposedChanges.map((change, index) => <li key={index}>{change}</li>)}</ul>
                    {repair.proposal.manualGuidance && repair.proposal.manualGuidance.length > 0 && <div><strong>Manual remediation guidance · no changes will be executed</strong><ol>{repair.proposal.manualGuidance.map((step, index) => <li key={index}>{step}</li>)}</ol></div>}
                    <RepairApprovalDetails repair={repair} />
                    <small>Operations: {repair.operationIds.length > 0 ? repair.operationIds.join(", ") : "No executable allowlisted operation"}</small>
                    <small>Permissions: {repair.requiredPermissions.join(", ")} · Initiated from {repair.initiatingInterface}</small>
                    <small>Approval: {repair.approvalStatus} · Backup: {repair.backupStatus} · Execution: {repair.executionStatus} · Verification: {repair.verificationStatus} · Rollback: {repair.rollbackStatus}</small>
                    {!repair.proposal.hostingRequest && <small>Queued repairs execute on the connected site’s next WordPress poll. WP-Cron polling is traffic-triggered, so low-traffic sites may take longer.</small>}
                    {repair.events.length > 0 && (
                      <details>
                        <summary>Repair history ({repair.events.length} events)</summary>
                        <ol>{repair.events.map((event) => (
                          <li key={event.id}>{event.eventType.replaceAll("_", " ")} · {event.actor} · {new Date(event.createdAt).toLocaleString()}</li>
                        ))}</ol>
                      </details>
                    )}
                    {(repair.approvals?.length || repair.verificationResults?.length) ? <details><summary>Approvals and verification evidence</summary>
                      {repair.approvals?.map((approval) => <p key={approval.id}>Approval: {approval.decision} · {new Date(approval.createdAt).toLocaleString()}{approval.comment ? ` · ${approval.comment}` : ""}</p>)}
                      {repair.verificationResults?.map((verification) => <div key={verification.id}><p>Verification: {verification.status} via {verification.method} · {new Date(verification.createdAt).toLocaleString()}</p><pre>{JSON.stringify(verification.result, null, 2)}</pre></div>)}
                    </details> : null}
                    {repair.status === "pending_approval" && (
                      <div className="issue-actions">
                        {repair.operationIds.length > 0 && repair.proposal.executionAvailable
                          ? <button className="button primary" onClick={() => decideRepair(repair.id, "approve_and_apply")} disabled={busy !== null}>Fix This Issue</button>
                          : <button className="button secondary" onClick={() => decideRepair(repair.id, "approve")} disabled={busy !== null}>{repair.proposal.hostingRequest ? "Acknowledge review only" : "Acknowledge manual plan"}</button>}
                        {repair.operationIds.length > 0 && repair.proposal.executionAvailable && <button className="button secondary" onClick={() => {
                          setSelectedBatchRepairs((current) => current.includes(repair.id) ? current.filter((id) => id !== repair.id) : [...current, repair.id]);
                          setMessage(selectedBatchRepairs.includes(repair.id) ? "Repair removed from the batch." : "Repair added to the batch. Open Repairs to review and authorize the selected batch.");
                        }}>{selectedBatchRepairs.includes(repair.id) ? "Remove from Repair Batch" : "Add to Repair Batch"}</button>}
                        <button className="button ghost" onClick={() => decideRepair(repair.id, "reject")} disabled={busy !== null}>Reject</button>
                      </div>
                    )}
                  </details>
                ))}
    </div>;
  }

  async function updateAllPlugins(siteId: string) {
    if (!await dialogs.confirm({ title: "Update all plugins on this website?", body: "Each WordPress.org plugin with an update is downloaded, checked against the official checksums, and rolled back automatically if the site breaks. Premium plugins are left for their vendors.", confirmLabel: "Update all" })) return;
    setBusy(`updates:${siteId}`);
    try {
      const response = await fetch(`/api/sites/${siteId}/cleanup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "update_plugins", confirm: true }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The updates could not be approved.");
      setMessage(`${result.stepCount} plugin update(s) approved. ${result.message}`);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The updates could not be approved.");
    } finally {
      setBusy(null);
    }
  }

  /** Open a website's detail view on a tab from any page and bring it into view. */
  function openWebsiteDetail(siteId: string, tab: typeof websiteDetailTab = "overview") {
    setSelectedWebsiteId(siteId);
    setWebsiteDetailTab(tab);
    setActiveView("websites");
    setTimeout(() => document.getElementById("website-detail")?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
  }

  /** Open critical/high compromise findings (outside check or integrity scan) for a website. */
  function compromiseFindings(siteId: string) {
    return issues.filter((issue) => issue.website.id === siteId && issue.status !== "resolved"
      && /^(?:wp:)?(?:security|integrity):/.test(issue.fingerprint) && (issue.severity === "critical" || issue.severity === "high"));
  }

  function oneClickFix(issue: Issue) {
    if (issue.status === "resolved") return null;
    if (issue.fingerprint.startsWith("wp:plugin-update:")) return { label: "Fix: update plugin", confirm: "Update this plugin on the live site now? It is downloaded from WordPress.org, checked against the official checksums, and the previous version is put back automatically if the site breaks." };
    if (issue.fingerprint.startsWith("wp:integrity:plugin-modified:")) return { label: "Fix: reinstall plugin", confirm: "Reinstall this plugin from WordPress.org? Its current, modified files are kept in the quarantine and can be restored." };
    if (issue.fingerprint.startsWith("wp:theme-update:")) return { label: "Fix: update theme", confirm: "Update this theme on the live site now? It is downloaded from WordPress.org, compared with the official package, and the previous version is put back automatically if the site breaks." };
    if (issue.fingerprint.startsWith("wp:integrity:theme-modified:")) return { label: "Fix: reinstall theme", confirm: "Reinstall this theme from WordPress.org? Its current, modified files are kept in the quarantine and can be restored." };
    if (issue.fingerprint.startsWith("vuln:")) {
      const evidence = (issue.evidence ?? {}) as { fixedIn?: string | null; updateFixes?: boolean };
      if (evidence.updateFixes) return { label: "Fix: install fixed version", confirm: "Install the fixed version on the live site? It is downloaded from WordPress.org and verified, and the old version is put back automatically if the site breaks." };
      if (evidence.fixedIn && uploadTargetFor(issue)) return { label: "Upload fixed version", confirm: null, action: "upload" as const };
      if (issue.fingerprint.startsWith("vuln:theme-")) return { label: "Fix vulnerability", confirm: "Fix this vulnerable theme? An unused theme with no fix yet is moved to the quarantine (restorable). An active theme without a fix is never removed automatically." };
      return { label: "Remove until fixed", confirm: "No fixed version exists yet. Deactivate this plugin and move it to the quarantine? It can be restored from the quarantine at any time." };
    }
    if (/^wp:(?:plugin|theme)-update:/.test(issue.fingerprint) && uploadTargetFor(issue)) return { label: "Upload new version", confirm: null, action: "upload" as const };
    if (issue.fingerprint.startsWith("perf:")) return { label: "See speed fixes", confirm: null, action: "performance" as const };
    // Accessibility findings the plugin can fix on every page as it is sent (0.9.0+).
    const a11yMeasure = /^browser:accessibility-meta-viewport:/.test(issue.fingerprint) ? "a11y_zoom"
      : /^browser:accessibility-(?:link-name|button-name):/.test(issue.fingerprint) ? "a11y_names"
      : /^browser:(?:accessibility-(?:label|select-name):|missing-form-label:)/.test(issue.fingerprint) ? "a11y_form_labels" : null;
    if (a11yMeasure) return {
      label: a11yMeasure === "a11y_zoom" ? "Fix: allow zooming" : a11yMeasure === "a11y_names" ? "Fix: name icon links" : "Fix: label form fields",
      confirm: a11yMeasure === "a11y_zoom"
        ? "Allow visitors to pinch-zoom on every page? The plugin removes the zoom block from the page header as pages are sent; theme files are not edited and you can switch it off under Accessibility."
        : a11yMeasure === "a11y_names"
          ? "Give icon-only links and buttons a spoken name on every page? Names come from where the link points (Facebook, email, a page of this site) or the icon (menu, search, close). Nothing visible changes and theme files are not edited."
          : "Give unlabeled form fields a spoken label on every page? The label comes from the field's placeholder or name. Nothing visible changes and theme files are not edited.",
      action: "a11y" as const,
      measure: a11yMeasure,
    };
    if (/^browser:(?:accessibility-|missing-image-alt:)/.test(issue.fingerprint)) return { label: "How to fix", confirm: null, action: "accessibility" as const };
    if (issue.fingerprint.startsWith("renewal:")) return { label: "Open renewals", confirm: null, action: "renewals" as const };
    if (/^(?:wp:)?(?:security|integrity):/.test(issue.fingerprint)) return { label: "Fix: open cleanup", confirm: null };
    return null;
  }

  /**
   * Premium plugins and themes (not on WordPress.org) are fixed by uploading
   * the vendor's zip; works for vulnerability and update findings.
   */
  function uploadTargetFor(issue: Issue): UploadTarget | null {
    const site = websites.find((item) => item.id === issue.website.id);
    const diagnostics = (site?.wordpressAgent?.diagnostics ?? {}) as { plugins?: Array<Record<string, unknown>>; themes?: Array<Record<string, unknown>> };
    const evidence = (issue.evidence ?? {}) as { fixedIn?: string | null };
    const vuln = /^vuln:(plugin|theme)-([a-z0-9_-]+):/.exec(issue.fingerprint);
    if (vuln) {
      if (vuln[1] === "plugin") {
        const plugin = (diagnostics.plugins ?? []).find((item) => typeof item.file === "string" && String(item.file).split("/")[0] === vuln[2]);
        return plugin && plugin.source !== "wordpress.org" ? { websiteId: issue.website.id, kind: "plugin", target: String(plugin.file), name: String(plugin.name ?? plugin.file), installedVersion: String(plugin.version ?? ""), fixedIn: evidence.fixedIn ?? null, issueId: issue.id } : null;
      }
      const theme = (diagnostics.themes ?? []).find((item) => item.stylesheet === vuln[2]);
      return theme && theme.source !== "wordpress.org" ? { websiteId: issue.website.id, kind: "theme", target: String(theme.stylesheet), name: String(theme.name ?? theme.stylesheet), installedVersion: String(theme.version ?? ""), fixedIn: evidence.fixedIn ?? null, issueId: issue.id } : null;
    }
    const update = /^(Plugin|Theme) update available:\s*(.+)$/.exec(issue.title);
    if (!update) return null;
    if (update[1] === "Plugin") {
      const plugin = (diagnostics.plugins ?? []).find((item) => item.name === update[2]);
      return plugin && plugin.source !== "wordpress.org" && typeof plugin.file === "string" ? { websiteId: issue.website.id, kind: "plugin", target: plugin.file, name: String(plugin.name), installedVersion: String(plugin.version ?? ""), fixedIn: null, issueId: issue.id } : null;
    }
    const theme = (diagnostics.themes ?? []).find((item) => item.name === update[2]);
    return theme && theme.source !== "wordpress.org" ? { websiteId: issue.website.id, kind: "theme", target: String(theme.stylesheet), name: String(theme.name), installedVersion: String(theme.version ?? ""), fixedIn: null, issueId: issue.id } : null;
  }

  /** Deactivate a vulnerable plugin (or remove an unused theme) until a fixed version is installed. */
  async function removeUntilFixed(issue: Issue) {
    if (!await dialogs.confirm({ title: "Remove until fixed?", body: "The plugin is deactivated and moved to the quarantine (an unused theme is moved there too). Anything it provides on the site stops working until you install a fixed version or restore it from the quarantine.", confirmLabel: "Remove until fixed", danger: true })) return;
    setBusy(`fix:${issue.id}`);
    try {
      const response = await fetch(`/api/issues/${issue.id}/fix`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirm: true, mode: "remove" }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The removal could not be approved.");
      setMessage(`${result.steps?.join(" ") ?? "Approved."} It is restorable from the quarantine.`);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The removal could not be approved.");
    } finally {
      setBusy(null);
    }
  }

  async function fixIssue(issue: Issue) {
    const fix = oneClickFix(issue);
    if (!fix) return;
    if ("action" in fix && fix.action === "upload") { const target = uploadTargetFor(issue); if (target) setUploadTarget(target); return; }
    if ("action" in fix && fix.action === "performance") { openWebsiteDetail(issue.website.id, "performance"); return; }
    if ("action" in fix && fix.action === "accessibility") { openWebsiteDetail(issue.website.id, "accessibility"); return; }
    if ("action" in fix && fix.action === "a11y" && "measure" in fix) {
      if (!await dialogs.confirm({ title: fix.label.replace(/^Fix: /, "").replace(/^./, (letter) => letter.toUpperCase()) + "?", body: fix.confirm ?? "", confirmLabel: "Turn on" })) return;
      const response = await fetch(`/api/sites/${issue.website.id}/performance`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "fix", changes: [{ measure: fix.measure, state: "on" }] }) });
      const result = await response.json().catch(() => ({}));
      setMessage(response.ok ? "Approved and sent to the site. It usually runs within a few seconds; the next daily browser check confirms the finding is gone." : result.error ?? "The fix could not be started.");
      return;
    }
    if ("action" in fix && fix.action === "renewals") { openWebsiteDetail(issue.website.id, "renewals"); return; }
    if (!fix.confirm) {
      openWebsiteDetail(issue.website.id, "cleanup");
      setMessage("Compromise findings are fixed together: review the cleanup plan below and approve it once.");
      return;
    }
    if (!await dialogs.confirm({ title: fix.label, body: fix.confirm, confirmLabel: "Approve fix" })) return;
    setBusy(`fix:${issue.id}`);
    try {
      const response = await fetch(`/api/issues/${issue.id}/fix`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirm: true }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The fix could not be approved.");
      setMessage(`${result.steps?.join(" ") ?? "Fix approved."} ${result.message}`);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The fix could not be approved.");
    } finally {
      setBusy(null);
    }
  }

  async function proposeRepair(issue: Issue): Promise<Record<string, unknown> | null> {
    setBusy(`repair:${issue.id}`);
    try {
      const issueEvidence = issue.evidence && typeof issue.evidence === "object" && !Array.isArray(issue.evidence)
        ? issue.evidence as Record<string, unknown>
        : {};
      const browserEvidence = issueEvidence.browser && typeof issueEvidence.browser === "object" && !Array.isArray(issueEvidence.browser)
        ? issueEvidence.browser as Record<string, unknown>
        : {};
      const findingEvidence = browserEvidence.finding && typeof browserEvidence.finding === "object" && !Array.isArray(browserEvidence.finding)
        ? browserEvidence.finding as Record<string, unknown>
        : {};
      const replaceBrokenLink = issue.fingerprint.startsWith("browser:broken-link:")
        && findingEvidence.kind === "missing_page" && [404, 410].includes(Number(findingEvidence.statusCode));
      const replacementUrl = replaceBrokenLink
        ? (await dialogs.prompt({ title: "Replacement link", body: "Enter the exact same-site URL that should replace the confirmed broken link. It must be a reachable page on this website.", confirmLabel: "Use this URL", input: { label: "Replacement URL", placeholder: "https://example.com/new-page/" } }))?.trim()
        : undefined;
      if (replaceBrokenLink && !replacementUrl) return null;
      const response = await fetch(`/api/issues/${issue.id}/repairs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(replacementUrl ? { replacementUrl } : {}),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not create repair proposal.");
      await refresh();
      return result as Record<string, unknown>;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not create repair proposal.");
      return null;
    } finally {
      setBusy(null);
    }
  }

  async function diagnoseIssue(issue: Issue, withAi: boolean) {
    setBusy(`issue-diagnose:${issue.id}`);
    try {
      const response = await fetch(`/api/issues/${issue.id}/diagnose`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ withAi }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not analyze issue.");
      if (result.aiStatus === "unavailable") setMessage(result.aiError ?? "AI is unavailable; deterministic diagnosis and recommendations remain available.");
      else if (result.aiStatus === "not_requested") setMessage("Deterministic diagnosis saved. No AI model was called.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not analyze issue.");
    } finally {
      setBusy(null);
    }
  }

  async function loadRecommendation(issue: Issue) {
    setBusy(`recommend:${issue.id}`);
    try {
      const response = await fetch(`/api/issues/${issue.id}/recommend`);
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not prepare recommendation.");
      setRecommendations((current) => ({ ...current, [issue.id]: result.recommendation }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not prepare recommendation.");
    } finally { setBusy(null); }
  }

  async function decideRepair(repairId: string, decision: "approve" | "approve_and_apply" | "reject") {
    setBusy(`decision:${repairId}`);
    try {
      const response = await fetch(`/api/repairs/${repairId}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not record approval.");
      setMessage(result.message);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not record approval.");
    } finally {
      setBusy(null);
    }
  }

  async function logout() {
    const response = await fetch("/api/auth/logout", { method: "POST" });
    if (!response.ok) {
      setMessage("Sign out failed.");
      return;
    }
    window.location.reload();
  }

  async function askAssistant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!assistantWebsiteId || !assistantQuestion.trim()) return;
    const question = assistantQuestion.trim();
    setAssistantMessages((current) => [...current, { role: "user", content: question }]);
    setAssistantQuestion("");
    setAssistantBusy(true);
    try {
      const permissionCommand = parseAssistantRepairPermissionCommand(question);
      const enableLinkAutomation = permissionCommand === "enable_broken_link_automation";
      const disableLinkAutomation = permissionCommand === "disable_broken_link_automation";
      const asksAutomaticPermissions = /\b(automatic|automatically|automation)\b/i.test(question)
        && /\b(what|which|can|allowed|permission|permissions)\b/i.test(question);
      const asksApprovalPermissions = /\b(approval|approval required|require approval|need approval)\b/i.test(question);
      const asksRepairHistory = /\b(previous|past|history|review|show)\b/i.test(question) && /\brepairs?\b/i.test(question);
      if (enableLinkAutomation || disableLinkAutomation) {
        const policyResponse = await fetch(`/api/sites/${assistantWebsiteId}/repair-authorization`);
        const policy = await policyResponse.json();
        if (!policyResponse.ok) throw new Error(policy.error ?? "Could not read this website’s repair permissions.");
        const allowedOperations = new Set<string>(policy.allowedOperations ?? []);
        if (enableLinkAutomation) allowedOperations.add("replace_post_link");
        else allowedOperations.delete("replace_post_link");
        const operations = [...allowedOperations];
        const next = {
          ...policy,
          mode: enableLinkAutomation || (policy.mode === "auto_eligible" && operations.length > 0) ? "auto_eligible" : "manual",
          allowedOperations: operations,
        };
        const response = await fetch(`/api/sites/${assistantWebsiteId}/repair-authorization`, {
          method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(next),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error ?? "Could not update this website’s repair permissions.");
        if (selectedWebsiteId === assistantWebsiteId) setRepairPolicy(result);
        const confirmation = enableLinkAutomation
          ? result.paused
            ? "Confirmed: permission for automatic broken or redirecting internal-link repairs is enabled, but automatic repairs remain paused for this website. Other operations are unchanged. Each repair still needs a supported proposal, fresh evidence, recovery point, and verification."
            : "Confirmed: automatic repair permission is enabled for verified broken or redirecting internal links on this website. Other operations are unchanged. Each repair still needs a supported proposal, fresh evidence, recovery point, and verification."
          : "Confirmed: automatic repair permission for broken or redirecting internal links is disabled on this website. Other operations are unchanged. Queued standing repairs were returned for approval; individual manual approvals remain available.";
        setAssistantMessages((current) => [...current, { role: "assistant", content: confirmation }]);
        setMessage(confirmation);
        return;
      }
      if (asksAutomaticPermissions || asksApprovalPermissions) {
        const response = await fetch(`/api/sites/${assistantWebsiteId}/repair-authorization`);
        const policy = await response.json();
        if (!response.ok) throw new Error(policy.error ?? "Could not read this website’s repair permissions.");
        const descriptions = new Map<string, string>(repairOperationDescriptions);
        const configured = (policy.allowedOperations as string[]).map((operation) => descriptions.get(operation) ?? operation);
        const canRunAutomatically = policy.mode === "auto_eligible" && !policy.paused ? configured : [];
        const approval = repairOperationDescriptions.map(([operation, description]) => ({ operation, description }))
          .filter(({ operation }) => !canRunAutomatically.includes(descriptions.get(operation) ?? operation) || operation === "disable_plugin" || operation === "switch_theme");
        const answer = asksAutomaticPermissions
          ? `For ${websites.find((site) => site.id === assistantWebsiteId)?.name ?? "this website"}, automatic execution is ${policy.mode === "auto_eligible" && !policy.paused ? "active" : policy.paused ? "paused" : "disabled"}. ${canRunAutomatically.length ? `Configured operations: ${canRunAutomatically.join("; ")}.` : "No operation is currently eligible for automatic execution."} Every operation still needs matching evidence, a fresh site connection, an exact allowlisted proposal, recovery support, and verification. Plugin deactivation and theme switching always require case-by-case approval.`
          : `Operations requiring case-by-case approval on ${websites.find((site) => site.id === assistantWebsiteId)?.name ?? "this website"}: ${approval.map(({ description }) => description).join("; ")}. High-impact plugin and theme changes always require approval. Current automatic permissions: ${canRunAutomatically.length ? canRunAutomatically.join("; ") : "none"}.`;
        setAssistantMessages((current) => [...current, { role: "assistant", content: answer }]);
        return;
      }
      if (asksRepairHistory) {
        const rows = issues.filter((issue) => issue.website.id === assistantWebsiteId)
          .flatMap((issue) => issue.repairs.map((repair) => ({ issue, repair })))
          .sort((a, b) => Date.parse(b.repair.events.at(-1)?.createdAt ?? "") - Date.parse(a.repair.events.at(-1)?.createdAt ?? ""))
          .slice(0, 12);
        const answer = rows.length
          ? rows.map(({ issue, repair }) => `${issue.title}: ${repair.status.replaceAll("_", " ")} · ${repair.risk} risk · operations ${repair.operationIds.join(", ") || "none"} · verification ${repair.verificationStatus} · ${repair.events.at(-1)?.createdAt ? new Date(repair.events.at(-1)!.createdAt).toLocaleString() : "date unavailable"}`).join("\n")
          : "There are no recorded repairs for this website yet.";
        setAssistantMessages((current) => [...current, { role: "assistant", content: answer }]);
        return;
      }
      const response = await fetch(`/api/sites/${assistantWebsiteId}/assistant`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ question }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The assistant could not answer.");
      setAssistantMessages((current) => [...current, {
        role: "assistant",
        content: result.answer,
        evidenceReferences: result.evidenceReferences,
      }]);
    } catch (error) {
      setAssistantMessages((current) => [...current, {
        role: "assistant",
        content: error instanceof Error ? error.message : "The assistant could not answer.",
      }]);
    } finally {
      setAssistantBusy(false);
    }
  }

  const allChecks = websites.flatMap((site) => site.checks);
  // Each website is counted once, using the same rules as the website list.
  const healthyCount = websites.filter((site) => siteHealth(site).key === "healthy" && siteHealth(site).open === 0).length;
  const warningCount = websites.filter((site) => siteHealth(site).key === "healthy" && siteHealth(site).open > 0).length;
  const criticalCount = websites.filter((site) => siteHealth(site).rank >= 2).length;
  const uptimeChecks = allChecks.filter((check) => check.statusCode !== null);
  const uptime = uptimeChecks.length > 0
    ? `${((uptimeChecks.filter((check) => check.available).length / uptimeChecks.length) * 100).toFixed(2)}%`
    : "—";
  const recentChecks = websites.flatMap((site) => site.checks.map((check) => ({ site, check })))
    .sort((a, b) => Date.parse(b.check.checkedAt) - Date.parse(a.check.checkedAt))
    .slice(0, 6);
  const repairRows = issues.flatMap((issue) => issue.repairs.map((repair) => ({ issue, repair })))
    .sort((a, b) => Date.parse(b.repair.events.at(-1)?.createdAt ?? "") - Date.parse(a.repair.events.at(-1)?.createdAt ?? ""));
  const filteredRepairRows = repairRows.filter(({ issue, repair }) => {
    const eventDate = repair.events.at(-1)?.createdAt ?? repair.approvals?.at(-1)?.createdAt ?? "";
    const date = eventDate ? new Date(eventDate) : null;
    return (repairWebsiteFilter === "all" || issue.website.id === repairWebsiteFilter)
      && (repairRiskFilter === "all" || repair.risk === repairRiskFilter)
      && (!repairFromDate || (date && date >= new Date(`${repairFromDate}T00:00:00`)))
      && (!repairToDate || (date && date < new Date(`${repairToDate}T23:59:59.999`)));
  });
  const selectedWebsite = websites.find((site) => site.id === selectedWebsiteId) ?? null;
  /** Overall state of a website, worst first: hacked, offline, needs attention, not checked, healthy. */
  function siteHealth(site: Website) {
    const open = issues.filter((issue) => issue.website.id === site.id && isOpenIssue(issue));
    const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
    for (const issue of open) counts[issue.severity] = (counts[issue.severity] ?? 0) + 1;
    const check = site.checks[0];
    if (compromiseFindings(site.id).length) return { key: "hacked", label: "Hacked", tone: "danger", rank: 4, counts, open: open.length };
    if (check && !check.available) return { key: "offline", label: "Offline", tone: "danger", rank: 3, counts, open: open.length };
    if (counts.critical + counts.high > 0) return { key: "attention", label: "Needs attention", tone: "warn", rank: 2, counts, open: open.length };
    if (!check) return { key: "unchecked", label: "Not checked yet", tone: "off", rank: 1, counts, open: open.length };
    return { key: "healthy", label: open.length ? "Minor issues" : "Healthy", tone: "on", rank: 0, counts, open: open.length };
  }

  function sortSites(list: Website[], order: "worst" | "name" | "checked") {
    return [...list].sort((a, b) => order === "name" ? a.name.localeCompare(b.name)
      : order === "checked" ? Date.parse(b.checks[0]?.checkedAt ?? "0") - Date.parse(a.checks[0]?.checkedAt ?? "0")
      : siteHealth(b).rank - siteHealth(a).rank || siteHealth(b).open - siteHealth(a).open || a.name.localeCompare(b.name));
  }

  function pluginState(site: Website) {
    const agent = site.wordpressAgent;
    if (!agent || agent.revokedAt) return { text: "Plugin not connected", tone: "off" };
    const minutes = Math.round((Date.now() - Date.parse(agent.lastSeenAt)) / 60_000);
    const version = (agent.diagnostics as { site?: { pluginVersion?: string } } | null)?.site?.pluginVersion ?? agent.pluginVersion;
    return { text: `Plugin ${version} · synced ${minutes < 1 ? "just now" : minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} h ago`}`, tone: minutes > 30 ? "warn" : "on" };
  }

  /** One compact, scannable row per website; actions beyond Open live in the More menu. */
  function renderSiteRow(site: Website, compact: boolean) {
    const check = site.checks[0];
    const health = siteHealth(site);
    const plugin = pluginState(site);
    const currentScan = scanProgress[site.id];
    return (
      <article className={`site-row site-row-${health.key}`} key={site.id}>
        <span className={`site-status ${check ? check.available ? "online" : "offline" : "unchecked"}`}>{check ? check.available ? "✓" : "!" : "·"}</span>
        <div className="site-info">
          <div className="site-title-line"><strong>{site.name}</strong><span className={`pill pill-${health.tone === "danger" ? "danger" : health.tone}`}>{health.label}</span></div>
          <span>{site.url}</span>
          <small>
            {site.environmentType === "staging" ? "Staging" : "Production"}
            {" · "}<span className={`plugin-state plugin-state-${plugin.tone}`}>{plugin.text}</span>
            {check && ` · ${check.available ? `HTTP ${check.statusCode}` : check.error ?? "Unavailable"} · checked ${new Date(check.checkedAt).toLocaleString()}`}
          </small>
          {health.open > 0 && (
            <div className="site-counts" aria-label="Open issues by severity">
              {(["critical", "high", "medium", "low"] as const).filter((level) => health.counts[level]).map((level) => <span key={level} className={`severity severity-${level}`}>{health.counts[level]} {level}</span>)}
            </div>
          )}
        </div>
        <div className="site-actions">
          {health.key === "hacked" && <button className="button danger" onClick={() => openWebsiteDetail(site.id, "cleanup")}>Clean up</button>}
          <button className="button primary" onClick={() => openWebsiteDetail(site.id, health.open ? "overview" : "overview")}>Open</button>
          {!compact && (
            <details className="row-menu">
              <summary className="button ghost">More</summary>
              <div className="row-menu-items" role="menu">
                <button role="menuitem" onClick={() => runScanWorkflow(site, false)} disabled={busy !== null}>{busy === `scan:${site.id}` ? "Queueing…" : "Scan now"}</button>
                <button role="menuitem" onClick={() => runScanWorkflow(site, true)} disabled={busy !== null}>Scan + AI analysis</button>
                <button role="menuitem" onClick={() => runSecurityCheck(site)} disabled={busy !== null}>{busy === `security:${site.id}` ? "Checking…" : "Security check"}</button>
                <button role="menuitem" onClick={() => openWebsiteDetail(site.id, "cleanup")}>Clean up &amp; fixes</button>
                <button role="menuitem" onClick={() => openWebsiteDetail(site.id, "protection")}>Protection</button>
                <button role="menuitem" onClick={() => openWebsiteDetail(site.id, "performance")}>Speed &amp; performance</button>
                <button role="menuitem" onClick={() => openWebsiteDetail(site.id, "settings")}>Settings &amp; connection</button>
                <button role="menuitem" onClick={() => toggleHistory(site)}>{history[site.id] ? "Hide check history" : "Check history"}</button>
                <button role="menuitem" className="danger-text" onClick={() => deleteWebsite(site)} disabled={busy !== null}>Remove website</button>
              </div>
            </details>
          )}
        </div>
        {currentScan && <small className="diagnostic-limit">Latest scan: {currentScan.status.replaceAll("_", " ")}{currentScan.withAi ? " · AI analysis selected" : " · automated evidence only"}</small>}
                    {history[site.id] && (
          <div className="check-history">
            <strong>Recent checks (up to 100)</strong>
            {history[site.id].length === 0 ? <p>No checks have run yet.</p> : (
              <ul>{history[site.id].map((item) => (
                <li key={item.id}>
                  <span className={item.available ? "history-good" : "history-bad"}>{item.available ? "Available" : "Unavailable"}</span>
                  {item.statusCode ? ` · HTTP ${item.statusCode}` : ""}
                  {item.responseTime !== null ? ` · ${item.responseTime} ms` : ""}
                  {` · ${new Date(item.checkedAt).toLocaleString()}`}
                  {item.error ? ` · ${item.error}` : ""}
                </li>
              ))}</ul>
            )}
          </div>
        )}
      </article>
    );
  }

  /** Hosting connection and WordPress plugin pairing, shown in the website's Settings tab. */
  function renderSiteConnection(site: Website) {
    return <>
                    <div className="wordpress-agent">
                      <div className="wordpress-agent-heading">
                        <strong>WordPress agent</strong>
                        {site.wordpressAgent && !site.wordpressAgent.revokedAt
                          ? <span className="agent-connected">Connected</span>
                          : <span className="agent-disconnected">Not connected</span>}
                      </div>
                      {site.wordpressAgent && !site.wordpressAgent.revokedAt ? (
                        <>
                          <p>{site.wordpressAgent.siteName} · WordPress {site.wordpressAgent.wpVersion ?? "unknown"} · PHP {site.wordpressAgent.phpVersion ?? "unknown"}</p>
                          <small>Last sync: {new Date(site.wordpressAgent.lastSeenAt).toLocaleString()}</small>
                          {site.wordpressAgent.diagnostics && (
                            <small>
                              {site.wordpressAgent.diagnostics.plugins?.length ?? 0} plugins inspected ·
                              {" "}{site.wordpressAgent.diagnostics.issues?.length ?? 0} detected issues ·
                              {" "}{site.wordpressAgent.diagnostics.site?.overdueCronCount ?? 0} overdue cron events
                            </small>
                          )}
                          {site.wordpressAgent.executions.map((execution) => (
                            <small key={execution.id}>
                              Recent repair: {execution.repair.issue?.title ?? "Approved repair"} · {execution.status} · {new Date(execution.createdAt).toLocaleString()}
                            </small>
                          ))}
                          <button className="button ghost danger-text" onClick={() => disconnectAgent(site.wordpressAgent!.id)}>Revoke connection</button>
                        </>
                      ) : (
                        <>
                          <p>Pair a WordPress installation on this registered site.</p>
                          <button className="button secondary" onClick={() => createPairing(site)} disabled={busy !== null}>
                            {busy === `pair:${site.id}` ? "Creating…" : "Create one-time pairing code"}
                          </button>
                          {pairingCodes[site.id] && (
                            <div className="pairing-code">
                              <code>{pairingCodes[site.id].code}</code>
                              <button className="button ghost" onClick={() => copyPairingCode(pairingCodes[site.id].code)}>Copy</button>
                              <small>Expires {new Date(pairingCodes[site.id].expiresAt).toLocaleTimeString()}. Enter it in the WordPress plugin once.</small>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                    <details className="hosting-details">
                      <summary>Hosting connection (optional, advanced)</summary>
                    <div className="site-hosting-panel">
                      <HostingManager
                        websiteId={site.id}
                        websiteName={site.name}
                        issues={issues
                          .filter((issue) => issue.website.id === site.id && issue.status !== "resolved")
                          .map(({ id, title }) => ({ id, title }))}
                        onNotice={setMessage}
                        onProposalCreated={refresh}
                      />
                    </div>
                    </details>
    </>;
  }

  const visibleSites = sortSites(websites.filter((site) => {
    const needle = siteQuery.trim().toLowerCase();
    if (needle && !`${site.name} ${site.url}`.toLowerCase().includes(needle)) return false;
    const health = siteHealth(site);
    if (siteFilter === "attention") return health.rank >= 2;
    if (siteFilter === "healthy") return health.key === "healthy";
    if (siteFilter === "disconnected") return !site.wordpressAgent || Boolean(site.wordpressAgent.revokedAt);
    return true;
  }), siteSort);


  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="AI Website Doctor home">
          <span className="brand-mark">+</span>
          <span>website<span className="brand-accent">doctor</span></span>
        </a>
        <div className="header-actions">
          <a className="button ghost" href="/api/reports">Export report</a>
          <button className="button ghost" onClick={logout}>Sign out</button>
          <span className="local-badge"><span className="pulse" /> MONITORING ON</span>
        </div>
      </header>

      <nav className="main-nav" aria-label="Main navigation">
        {([
          ["dashboard", "Overview"],
          ["websites", "Websites"],
          ["issues", "Issues"],
          ["repairs", "Repairs"],
          ["assistant", "AI assistant"],
          ["team", "Team"],
          ["settings", "Settings"],
        ] as Array<[DashboardView, string]>).map(([view, label]) => (
          <button
            key={view}
            className={`nav-item ${activeView === view ? "active" : ""}`}
            onClick={() => setActiveView(view)}
            aria-current={activeView === view ? "page" : undefined}
          >
            {label}
          </button>
        ))}
      </nav>

      <section className="intro">
        <p className="eyebrow">{activeView === "dashboard" ? "YOUR WEBSITE HEALTH, AT A GLANCE" : "AI WEBSITE DOCTOR"}</p>
        <h1>{activeView === "dashboard" ? "A healthier web starts here." : {
          websites: "Your websites",
          issues: "Issue centre",
          repairs: "Repairs & automation",
          assistant: "Ask about your website health",
          team: "Organization members",
          settings: "Settings",
          dashboard: "Overview",
        }[activeView]}</h1>
        <p className="subtitle">{activeView === "assistant"
          ? "Answers use stored scan and issue evidence. If the evidence is missing, the assistant will say so."
          : activeView === "repairs"
            ? "Everything the app can fix, what is running now, what waits for you, what runs automatically, and what happened."
            : activeView === "settings"
              ? "Connect the free services behind vulnerability checks, PageSpeed scores and email reminders."
              : "Monitor availability, review evidence, and get AI guidance from the evidence."}</p>
      </section>

      {activeView === "dashboard" && websites.filter((site) => compromiseFindings(site.id).length > 0).map((site) => (
        <section className="compromise-alert" role="alert" key={`compromise-${site.id}`}>
          <div>
            <strong>{site.name} shows signs of being hacked</strong>
            <p>{compromiseFindings(site.id).length} critical or high security finding(s), for example: {compromiseFindings(site.id).slice(0, 2).map((issue) => issue.title).join("; ")}.</p>
          </div>
          <button className="button primary" onClick={() => openWebsiteDetail(site.id, "cleanup")}>Review cleanup plan</button>
        </section>
      ))}
      {activeView === "dashboard" && <section className="summary-grid" aria-label="Monitoring summary">
        <article className="summary-card">
          <span className="summary-icon icon-purple">◎</span>
          <span className="summary-label">WEBSITES</span>
          <strong>{websites.length}</strong>
          <span className="summary-foot">in your watchlist</span>
        </article>
        <article className="summary-card">
          <span className="summary-icon icon-green">✓</span>
          <span className="summary-label">HEALTHY</span>
          <strong>{healthyCount}</strong>
          <span className="summary-foot">online with no open issues</span>
        </article>
        <article className="summary-card">
          <span className="summary-icon icon-amber">◷</span>
          <span className="summary-label">WARNINGS</span>
          <strong>{warningCount}</strong>
          <span className="summary-foot">online, only low or medium issues</span>
        </article>
        <article className="summary-card">
          <span className="summary-icon icon-red">!</span>
          <span className="summary-label">CRITICAL</span>
          <strong>{criticalCount}</strong>
          <span className="summary-foot">hacked, down or high severity</span>
        </article>
        <article className="summary-card">
          <span className="summary-icon icon-blue">↗</span>
          <span className="summary-label">OBSERVED UPTIME</span>
          <strong>{uptime}</strong>
          <span className="summary-foot">{uptimeChecks.length} recorded checks across loaded history</span>
        </article>
        <article className="summary-card">
          <span className="summary-icon icon-purple">◷</span>
          <span className="summary-label">PENDING APPROVALS</span>
          <strong>{repairRows.filter(({ repair }) => repair.status === "pending_approval").length}</strong>
          <span className="summary-foot">repair proposals awaiting your review</span>
        </article>
      </section>}

      {activeView === "dashboard" && websites.length > 0 && (
        <section className="panel sites-panel attention-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">MONITORING</p><h2>Websites that need attention</h2></div>
            <span className="count-pill">{websites.filter((site) => siteHealth(site).rank >= 2).length} OF {websites.length}</span>
          </div>
          {websites.filter((site) => siteHealth(site).rank >= 2).length === 0
            ? <p className="activity-empty">All {websites.length} website(s) look healthy. Nothing needs your attention right now.</p>
            : <div className="site-list">{sortSites(websites.filter((site) => siteHealth(site).rank >= 2), "worst").slice(0, 6).map((site) => renderSiteRow(site, true))}</div>}
          <div className="board-footer"><button className="button secondary" onClick={() => setActiveView("websites")}>View all {websites.length} website(s)</button></div>
        </section>
      )}

      {(activeView === "websites" || (activeView === "dashboard" && websites.length === 0)) && <div className="content-grid">
        <section className="panel sites-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">MONITORING</p>
              <h2>Your websites</h2>
            </div>
            <span className="count-pill">{websites.length} TOTAL</span>
          </div>
          {websites.length > 0 && (
            <div className="board-toolbar site-toolbar" role="search">
              <input type="search" placeholder="Search websites" value={siteQuery} onChange={(event) => setSiteQuery(event.target.value)} aria-label="Search websites" />
              <select value={siteFilter} onChange={(event) => setSiteFilter(event.target.value as typeof siteFilter)} aria-label="Filter websites">
                <option value="all">All websites</option>
                <option value="attention">Needs attention</option>
                <option value="healthy">Healthy</option>
                <option value="disconnected">Plugin not connected</option>
              </select>
              <select value={siteSort} onChange={(event) => setSiteSort(event.target.value as typeof siteSort)} aria-label="Sort websites">
                <option value="worst">Needs attention first</option>
                <option value="name">Name</option>
                <option value="checked">Recently checked</option>
              </select>
            </div>
          )}
          {websites.length === 0 ? (
            <div className="empty-state">
              <div className="empty-orbit">◎</div>
          <h3>Your watchlist is ready</h3>
          <p>Add a production site on its own, or optionally link it to staging. Checks run only when you request them.</p>
            </div>
          ) : visibleSites.length === 0 ? <p className="activity-empty">No websites match these filters.</p> : (
            <div className="site-list">{visibleSites.map((site) => renderSiteRow(site, false))}</div>
          )}
        </section>

        <aside className="panel add-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">GET STARTED</p>
              <h2>Add a website</h2>
            </div>
            <span className="add-icon">↗</span>
          </div>
          <p className="form-intro">Choose on-demand checks or enable local periodic monitoring.</p>
          <form onSubmit={addWebsite}>
            <label htmlFor="website-name">WEBSITE NAME</label>
            <input id="website-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="My portfolio" maxLength={80} required />
            <label htmlFor="website-url">WEBSITE URL</label>
            <input id="website-url" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" required />
            <label htmlFor="website-environment">ENVIRONMENT</label>
            <select id="website-environment" value={environmentType} onChange={(event) => { setEnvironmentType(event.target.value as "production" | "staging"); setRelatedWebsiteId(""); }}>
              <option value="production">Production website</option>
              <option value="staging">Staging website</option>
            </select>
            <label htmlFor="website-related">LINK TO OTHER ENVIRONMENT (OPTIONAL)</label>
            <select id="website-related" value={relatedWebsiteId} onChange={(event) => setRelatedWebsiteId(event.target.value)}>
              <option value="">No paired website</option>
              {websites.filter((site) => site.environmentType !== environmentType).map((site) => <option key={site.id} value={site.id}>{site.name} · {site.environmentType}</option>)}
            </select>
            <label htmlFor="monitor-interval">CHECK FREQUENCY</label>
            <select id="monitor-interval" value={intervalMinutes} onChange={(event) => setIntervalMinutes(Number(event.target.value))}>
              <option value={5}>Every 5 minutes</option>
              <option value={15}>Every 15 minutes</option>
              <option value={60}>Every hour</option>
              <option value={360}>Every 6 hours</option>
              <option value={1440}>Every day</option>
            </select>
            <label className="checkbox-label">
              <input type="checkbox" checked={monitoringEnabled} onChange={(event) => setMonitoringEnabled(event.target.checked)} />
              Enable scheduled monitoring
            </label>
            <button className="button primary full-width" type="submit" disabled={busy !== null}>
              {busy === "add" ? "Adding…" : "Add to watchlist"} <span>→</span>
            </button>
          </form>
          <div className="privacy-note"><span>◇</span><p><strong>Private by design</strong><br />Your website list and check history stay in your local database. No external AI API is used.</p></div>
        </aside>
      </div>}

      {activeView === "websites" && selectedWebsite && (
        <section className="panel detail-panel" id="website-detail">
          <div className="panel-heading">
            <div><p className="eyebrow">WEBSITE DETAIL</p><h2>{selectedWebsite.name}</h2></div>
            <button className="button ghost" onClick={() => setSelectedWebsiteId(null)}>Close details</button>
          </div>
          <div className="detail-tabs" role="tablist" aria-label="Website detail sections">
            {([
              ["overview", "Overview"], ["software", "Plugins & themes"], ["performance", "Speed & performance"], ["renewals", "Renewals"], ["cleanup", "Clean up & fixes"], ["protection", "Protection"],
              ["backups", "Backups"], ["diagnostics", "Diagnostics"], ["accessibility", "Accessibility"], ["responsive", "Responsive"], ["repair-history", "Repair history"], ["history", "Scan history"], ["settings", "Settings"],
            ] as const).map(([tab, label]) => (
              <button key={tab} role="tab" aria-selected={websiteDetailTab === tab} className={websiteDetailTab === tab ? "active" : ""}
                onClick={() => setWebsiteDetailTab(tab)}>{label}</button>
            ))}
          </div>
          <WebsiteDetail
            site={selectedWebsite}
            issues={issues.filter((issue) => issue.website.id === selectedWebsite.id)}
            history={history[selectedWebsite.id] ?? null}
            tab={websiteDetailTab}
            repairs={repairRows.filter(({ issue }) => issue.website.id === selectedWebsite.id)}
            busy={busy}
            onHistory={() => loadHistory(selectedWebsite)}
            onUpdate={(updates) => updateWebsite(selectedWebsite, updates)}
            onScan={(withAi) => runScanWorkflow(selectedWebsite, withAi)}
            onSecurityCheck={() => runSecurityCheck(selectedWebsite)}
            onNotice={setMessage}
            connection={renderSiteConnection(selectedWebsite)}
            scanStatus={scanProgress[selectedWebsite.id] ?? null}
            websites={websites}
            onUpload={setUploadTarget}
            onFixIssue={(issueId) => { const target = issues.find((item) => item.id === issueId); if (target) void fixIssue(target); }}
          />
        </section>
      )}

      {activeView === "dashboard" && websites.length > 0 && <UpcomingRenewals onOpenSite={(siteId) => openWebsiteDetail(siteId, "renewals")} />}

      {activeView === "dashboard" && (
        <section className="recent-grid" aria-label="Recent activity">
          <article className="panel">
            <div className="panel-heading"><div><p className="eyebrow">MONITORING</p><h2>Recent scans</h2></div></div>
            {recentChecks.length === 0 ? <p className="activity-empty">No scans recorded yet.</p> : (
              <ul className="activity-list">{recentChecks.map(({ site, check }) => (
                <li key={check.id}>
                  <span className={`activity-dot ${check.available ? "good" : "bad"}`} />
                  <div><strong>{site.name}</strong><small>{check.available ? `HTTP ${check.statusCode ?? "—"}` : check.error ?? "Unavailable"} · {new Date(check.checkedAt).toLocaleString()}</small></div>
                </li>
              ))}</ul>
            )}
          </article>
          <article className="panel">
            <div className="panel-heading"><div><p className="eyebrow">INCIDENTS</p><h2>Most important open issues</h2></div></div>
            <IssueBoard issues={issues} mode="summary" renderDetails={renderIssueDetails} renderPrimary={renderIssuePrimary}
              onOpenSite={(siteId) => openWebsiteDetail(siteId, "overview")} onViewAll={() => setActiveView("issues")} />
          </article>
          <article className="panel">
            <div className="panel-heading"><div><p className="eyebrow">REPAIR HISTORY</p><h2>Recent successful repairs</h2></div></div>
            {repairRows.filter(({ repair }) => repair.status === "verified").slice(0, 5).length === 0
              ? <p className="activity-empty">No repairs have been verified yet.</p>
              : <ul className="activity-list">{repairRows.filter(({ repair }) => repair.status === "verified").slice(0, 5).map(({ issue, repair }) => (
                <li key={repair.id}><span className="activity-dot good">✓</span>
                  <div><strong>{issue.title}</strong><small>{issue.website.name} · Verified</small></div>
                </li>
              ))}</ul>}
          </article>
        </section>
      )}

      {activeView === "issues" && <section className="panel issues-panel">
        <div className="panel-heading">
          <div><p className="eyebrow">ISSUE MANAGEMENT</p><h2>Issues across your websites</h2></div>
          <span className="count-pill">{issues.filter(isOpenIssue).length} OPEN</span>
        </div>
        {issues.length === 0
          ? <div className="issue-empty">No issues recorded yet. Failed availability checks and AI diagnoses will appear here.</div>
          : <IssueBoard issues={issues} mode="full" renderDetails={renderIssueDetails} renderPrimary={renderIssuePrimary}
              onOpenSite={(siteId) => openWebsiteDetail(siteId, "overview")} onUpdateAll={updateAllPlugins} updateAllBusySiteId={busy?.startsWith("updates:") ? busy.slice(8) : null} />}
      </section>}

      {activeView === "repairs" && (
        <RepairCentre
          legacy={repairRows.filter(({ repair }) => (repair.proposal as { kind?: string }).kind !== "compromise_cleanup").map(({ issue, repair }): LegacyRepairRow => ({
            id: repair.id, siteId: issue.website.id, siteName: issue.website.name, title: repair.proposal.issue || issue.title, status: repair.status, risk: repair.risk,
            createdAt: repair.createdAt, rationale: repair.proposal.rationale, changes: repair.proposal.proposedChanges,
            executable: repair.operationIds.length > 0 && Boolean(repair.proposal.executionAvailable),
          }))}
          onOpenSite={(siteId, tab) => openWebsiteDetail(siteId, tab)}
          onNotice={setMessage}
          decisionSlot={(() => {
            const pending = filteredRepairRows.filter(({ repair }) => repair.status === "pending_approval" && (repair.proposal as { kind?: string }).kind !== "compromise_cleanup");
            return (
              <section className="panel">
                <div className="panel-heading"><div><p className="eyebrow">YOUR DECISION</p><h2>Waiting for your approval</h2></div><span className="count-pill">{pending.length}</span></div>
                {pending.length === 0 ? <p className="activity-empty">Nothing is waiting for you. Fixes you start from Issues or a website&apos;s Clean up tab run straight away and appear under In progress.</p> : (
                  <div className="board-cards decision-list">
                    {pending.map(({ issue, repair }) => {
                      const executable = repair.operationIds.length > 0 && Boolean(repair.proposal.executionAvailable);
                      return (
                        <article className={`board-card severity-edge-${issue.severity}`} key={repair.id}>
                          <div className="board-card-head">
                            <span className={`severity severity-${issue.severity}`}>{issue.severity}</span>
                            <div className="board-card-title"><strong>{repair.proposal.issue || issue.title}</strong><small>{issue.website.name} · {executable ? `automatic repair · ${repair.risk} risk` : "manual plan (the app will not change the site)"}</small></div>
                          </div>
                          {repair.proposal.rationale && <p className="board-card-description">{repair.proposal.rationale}</p>}
                          <div className="board-card-actions">
                            {executable
                              ? <button className="button primary" onClick={() => decideRepair(repair.id, "approve_and_apply")} disabled={busy !== null}>Approve &amp; fix</button>
                              : <button className="button secondary" onClick={() => decideRepair(repair.id, "approve")} disabled={busy !== null}>Mark plan as read</button>}
                            <button className="button ghost" onClick={() => decideRepair(repair.id, "reject")} disabled={busy !== null}>Reject</button>
                            {executable && <label className="batch-repair-select"><input type="checkbox" checked={selectedBatchRepairs.includes(repair.id)} onChange={(event) => setSelectedBatchRepairs((current) => event.target.checked ? [...current, repair.id] : current.filter((id) => id !== repair.id))} /> Select for batch</label>}
                          </div>
                          <details className="issue-evidence"><summary>What exactly changes</summary>
                            {repair.proposal.proposedChanges.length > 0 && <ul className="plain-list">{repair.proposal.proposedChanges.map((change, index) => <li key={index}>{change}</li>)}</ul>}
                            {repair.proposal.manualGuidance && repair.proposal.manualGuidance.length > 0 && <ol className="plain-list">{repair.proposal.manualGuidance.map((step, index) => <li key={index}>{step}</li>)}</ol>}
                            <RepairApprovalDetails repair={repair} />
                          </details>
                        </article>
                      );
                    })}
                  </div>
                )}
                {selectedBatchRepairs.length > 0 && (
                  <div className="batch-bar">
                    <span><strong>{selectedBatchRepairs.length} selected.</strong> Each is re-checked before it runs.</span>
                    <button className="button primary" onClick={approveRepairBatch} disabled={repairPolicyBusy}>Approve &amp; fix {selectedBatchRepairs.length}</button>
                  </div>
                )}
              </section>
            );
          })()}
          advancedSlot={(
            <details className="panel advanced-panel">
              <summary><span className="eyebrow">ADVANCED</span><strong>Repair permissions and requests in your own words</strong></summary>
          <section className="repair-authorization-panel">
            <p className="advanced-intro">Fine-grained settings for the original scan-based repairs. Most people only need the switches under <strong>What runs without you</strong>. Plugin isolation and theme switching are high risk and always need your approval, so they cannot be made automatic.</p>
            <label>Website<select value={selectedWebsiteId ?? ""} onChange={(event) => { setSelectedWebsiteId(event.target.value || null); setRepairPromptIssueId(""); }}>
              {websites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
            </select></label>
            <p>When automatic mode is on, a scan finding that maps to exactly one of the permitted repairs below is queued without asking you, applied with an undo copy and verified. Nothing else is ever automatic here.</p>
            <label className="repair-policy-toggle"><input type="checkbox" checked={repairPolicy.mode === "auto_eligible"} onChange={(event) => setRepairPolicy((current) => ({ ...current, mode: event.target.checked ? "auto_eligible" : "manual" }))} /> Automatically queue eligible repairs under this policy</label>
            <fieldset><legend>Permitted operations</legend>
              {repairOperationDescriptions.filter(([operation]) => operation === "replace_post_link" || operation === "update_setting").map(([operation, description]) => <label key={operation} className="repair-policy-toggle"><input type="checkbox" checked={repairPolicy.allowedOperations.includes(operation)} onChange={(event) => setRepairPolicy((current) => ({ ...current, allowedOperations: event.target.checked ? [...current.allowedOperations, operation] : current.allowedOperations.filter((item) => item !== operation) }))} /><span><strong>{operation === "replace_post_link" ? "Update links that permanently redirect" : "Change the site title or tagline (from a typed request)"}</strong><small>{description}</small></span></label>)}
            </fieldset>
            <label>Maximum risk<select value={repairPolicy.maxRisk} onChange={(event) => setRepairPolicy((current) => ({ ...current, maxRisk: event.target.value as RepairAuthorizationPolicy["maxRisk"] }))}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label>
            <label>Maximum automatic repairs queued at once<input type="number" min={1} max={25} value={repairPolicy.maxRepairsPerBatch} onChange={(event) => setRepairPolicy((current) => ({ ...current, maxRepairsPerBatch: Math.max(1, Math.min(25, Number(event.target.value) || 1)) }))} /></label>
            <label className="repair-policy-toggle"><input type="checkbox" checked={repairPolicy.paused} onChange={(event) => setRepairPolicy((current) => ({ ...current, paused: event.target.checked }))} /> Pause automatic repairs now</label>
            {!repairPolicy.paused && <button className="button danger" onClick={pauseAutomaticRepairs} disabled={repairPolicyBusy || !selectedWebsiteId}>Pause automatic repairs immediately</button>}
            <p className="repair-limitation">Every supported operation requires an operation-specific recovery record and post-change verification. These safety checks cannot be disabled; the WordPress recovery record is separate from your full-site backup.</p>
            <button className="button primary" onClick={saveRepairPolicy} disabled={repairPolicyBusy || !selectedWebsiteId}>{repairPolicyBusy ? "Saving…" : "Save repair permissions"}</button>
            <div className="prompt-repair-box"><h3>Request a repair in your words</h3>
              <label>Issue (optional when your request identifies one clearly)<select value={repairPromptIssueId} onChange={(event) => setRepairPromptIssueId(event.target.value)}><option value="">Match from request</option>{issues.filter((issue) => issue.website.id === selectedWebsiteId && issue.status !== "resolved").map((issue) => <option key={issue.id} value={issue.id}>{issue.title}</option>)}</select></label>
              <textarea value={repairPrompt} onChange={(event) => setRepairPrompt(event.target.value)} maxLength={1000} placeholder="For example: Replace the broken link on the pricing page with https://example.com/plans" />
              <button className="button secondary" onClick={() => submitPromptRepair()} disabled={repairPolicyBusy || !selectedWebsiteId || repairPrompt.trim().length < 3}>Create bounded repair request</button>
              <small>Requests can only map to stored issues and existing allowlisted operations. Ambiguous matches ask you to select an issue; unsupported requests produce guidance only.</small>
            </div>
          </section>
            </details>
          )}
        />
      )}

      {activeView === "assistant" && (
        <section className="panel assistant-panel">
          <div className="panel-heading"><div><p className="eyebrow">EVIDENCE-GROUNDED</p><h2>Website health assistant</h2></div>
            <span className={`assistant-status ${settings?.aiConfigured ? "ready" : "offline"}`}>{settings?.aiConfigured ? "Local model configured" : "Local model unavailable"}</span>
          </div>
          {websites.length === 0 ? <p className="activity-empty">Add a website and collect diagnostic evidence before asking questions.</p> : <>
            <label className="assistant-site-label" htmlFor="assistant-site">WEBSITE</label>
            <select id="assistant-site" value={assistantWebsiteId} disabled={assistantBusy} onChange={(event) => {
              setAssistantWebsiteId(event.target.value);
              setAssistantMessages([]);
            }}>
              {websites.map((site) => <option key={site.id} value={site.id}>{site.name} · {site.url}</option>)}
            </select>
            <div className="assistant-messages" aria-live="polite">
              {assistantMessages.length === 0
                ? <p className="assistant-empty">Ask about recorded checks, issues, or WordPress diagnostics. The assistant cites stored evidence and does not run new tools from chat.</p>
                : assistantMessages.map((entry, index) => (
                  <article className={`assistant-message ${entry.role}`} key={`${entry.role}-${index}`}>
                    <strong>{entry.role === "user" ? "You" : "AI Website Doctor"}</strong>
                    <p>{entry.content}</p>
                    {entry.evidenceReferences && entry.evidenceReferences.length > 0 && (
                      <details><summary>Evidence used ({entry.evidenceReferences.length})</summary>
                        <ul>{entry.evidenceReferences.map((reference) => <li key={reference.id}><code>{reference.id}</code> {reference.path}: {JSON.stringify(reference.value)}</li>)}</ul>
                      </details>
                    )}
                  </article>
                ))}
              {assistantBusy && <p className="assistant-empty">Checking stored evidence…</p>}
            </div>
            <form className="assistant-form" onSubmit={askAssistant}>
              <label className="sr-only" htmlFor="assistant-question">Ask about this website</label>
              <textarea id="assistant-question" value={assistantQuestion} onChange={(event) => setAssistantQuestion(event.target.value)}
                maxLength={1000} placeholder="What are the most serious issues found?" required />
              <button className="button primary" type="submit" disabled={assistantBusy || !assistantQuestion.trim()}>
                {assistantBusy ? "Thinking…" : "Ask"}
              </button>
            </form>
            <button className="button secondary" onClick={() => submitPromptRepair(assistantWebsiteId, assistantQuestion, "")} disabled={repairPolicyBusy || !assistantWebsiteId || assistantQuestion.trim().length < 3}>Plan or perform a bounded repair request</button>
            <small className="assistant-disclaimer">Answers are based only on stored diagnostics. Missing or invalid evidence will be reported, not guessed.</small>
          </>}
        </section>
      )}

      {activeView === "team" && <section className="panel team-panel">
        <div className="panel-heading"><div><p className="eyebrow">ACCESS MANAGEMENT</p><h2>Organization members</h2></div></div>
        <p>Accounts share this organization’s website and diagnostic data. Give each person a unique temporary password and deliver it securely.</p>
        <form className="team-form" onSubmit={addMember}>
          <label>Name<input value={memberName} onChange={(event) => setMemberName(event.target.value)} autoComplete="name" required maxLength={200} /></label>
          <label>Email<input type="email" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} autoComplete="email" required maxLength={254} /></label>
          <label>Temporary password<input type="password" value={memberPassword} onChange={(event) => setMemberPassword(event.target.value)} autoComplete="new-password" minLength={12} maxLength={128} required /></label>
          <label>Role<select value={memberRole} onChange={(event) => setMemberRole(event.target.value as "member" | "admin")}><option value="member">Member</option><option value="admin">Administrator</option></select></label>
          <button className="button primary" type="submit" disabled={busy !== null}>{busy === "member:add" ? "Adding…" : "Add member"}</button>
        </form>
        <div className="team-list">{members.map((member) => <article key={member.id}>
          <div><strong>{member.name}</strong><small>{member.email} · {member.role}{member.disabledAt ? " · disabled" : ""}</small></div>
          <button className="button ghost" onClick={() => removeMember(member)} disabled={busy !== null || member.disabledAt !== null}>Remove</button>
        </article>)}</div>
        <small className="diagnostic-limit">Self-service invitations, password reset, and membership across multiple organizations are not configured.</small>
      </section>}

      {activeView === "team" && <McpAccessManager onNotice={setMessage} />}

      {activeView === "settings" && <IntegrationsSettings onNotice={setMessage} />}

      <PackageUploadDialog target={uploadTarget} onClose={() => setUploadTarget(null)} onDone={(text) => { setUploadTarget(null); setMessage(text); void refresh(); }} />

      {activeView === "dashboard" && <section className="system-settings">
        <div><span className="eyebrow">SYSTEM SETTINGS</span><strong>Organization accounts</strong><small>Database-backed sessions and membership-based access</small></div>
        <div><span className="eyebrow">AI PROVIDER</span><strong>{settings?.aiProvider ?? "Loading…"}</strong><small>{settings?.aiConfigured ? "Server-side model configured" : "AI environment config required"} · Optional. Current model provider integration: Ollama only.</small></div>
        <div><span className="eyebrow">MONITORING</span><strong>{settings?.scheduledMonitoring ? "Scheduler enabled" : "On demand"}</strong><small>Availability and outside security checks run on a schedule</small></div>
      </section>}

      {message && <div className="toast" role="status">{message}<button aria-label="Dismiss message" onClick={() => setMessage("")}>×</button></div>}

      <footer className="footer">
        <span>AI WEBSITE DOCTOR <span className="footer-dot">•</span> MONITORING &amp; REPAIR</span>
        <span>Every repair keeps a recovery point and is verified afterwards.</span>
      </footer>
    </main>
  );
}

function DiagnosisDetails({ diagnosis }: { diagnosis: StructuredDiagnosis }) {
  const formatValue = (value: unknown) =>
    typeof value === "string" ? value : JSON.stringify(value);
  const references = (ids: string[] | undefined) => Array.isArray(ids) && ids.length > 0 ? ` [${ids.join(", ")}]` : "";
  const facts = Array.isArray(diagnosis.facts) ? diagnosis.facts : [];
  const hypotheses = Array.isArray(diagnosis.hypotheses) ? diagnosis.hypotheses : [];
  const alternativeExplanations = Array.isArray(diagnosis.alternativeExplanations) ? diagnosis.alternativeExplanations : [];
  const verificationProcedure = Array.isArray(diagnosis.recommendedFix?.verificationProcedure) ? diagnosis.recommendedFix.verificationProcedure : [];
  const evidenceReferences = Array.isArray(diagnosis.evidenceReferences) ? diagnosis.evidenceReferences : [];
  const rootCause = diagnosis.probableRootCause;

  return (
    <div className="structured-diagnosis">
      <strong>{diagnosis.issueTitle}{references(diagnosis.issueTitleEvidenceRefs)} · {diagnosis.category}</strong>
      <p>{diagnosis.description}{references(diagnosis.descriptionEvidenceRefs)}</p>
      <small>
        Website: {diagnosis.affectedWebsite}
        {diagnosis.affectedPage ? ` · Page: ${diagnosis.affectedPage}` : " · Page: not identified by available evidence"}
        {diagnosis.affectedComponent ? ` · Component: ${diagnosis.affectedComponent}` : ""}
      </small>
      <h4>Observed facts</h4>
      <ul>{facts.map((fact, index) => <li key={index}>{fact.claim}{references(fact.evidenceRefs)}</li>)}</ul>
      <h4>Hypotheses</h4>
      <p>{!rootCause || rootCause.status === "insufficient_evidence" ? "Insufficient evidence to identify a probable cause." : rootCause.claim}{references(rootCause?.evidenceRefs)}</p>
      {hypotheses.length > 0 && (
        <ul>{hypotheses.map((item, index) => <li key={index}>{item.claim}{references(item.evidenceRefs)}</li>)}</ul>
      )}
      {alternativeExplanations.length > 0 && (
        <>
          <h4>Alternative explanations</h4>
          <ul>{alternativeExplanations.map((item, index) => <li key={index}>{item.explanation}{references(item.evidenceRefs)}</li>)}</ul>
        </>
      )}
      {diagnosis.recommendedFix && <>
        <h4>Recommended fix · {diagnosis.recommendedFix.risk} risk · approval required</h4>
        <p>{diagnosis.recommendedFix.description}{references(diagnosis.recommendedFix.evidenceRefs)}</p>
        {verificationProcedure.length > 0 && <ul>{verificationProcedure.map((step, index) => <li key={index}>{step}</li>)}</ul>}
      </>}
      {evidenceReferences.length > 0 && <details>
        <summary>Evidence references ({evidenceReferences.length})</summary>
        <ul>{evidenceReferences.map((reference) => (
          <li key={reference.id}><code>{reference.id}</code> {reference.path}: {formatValue(reference.value)}</li>
        ))}</ul>
      </details>}
      <small>{diagnosis.kind === "deterministic" ? "Generated by deterministic rules from stored evidence; no AI model was called." : `Model ${diagnosisConfidenceLabel(diagnosis.confidence)}`}</small>
    </div>
  );
}

function WebsiteDetail({
  site,
  websites,
  issues,
  history,
  tab,
  repairs,
  busy,
  onHistory,
  onUpdate,
  onScan,
  onSecurityCheck,
  onNotice,
  connection,
  scanStatus,
  onUpload,
  onFixIssue,
}: {
  site: Website;
  websites: Website[];
  issues: Issue[];
  history: Check[] | null;
  tab: "overview" | "software" | "performance" | "renewals" | "diagnostics" | "accessibility" | "responsive" | "repair-history" | "cleanup" | "protection" | "backups" | "history" | "settings";
  repairs: Array<{ issue: Issue; repair: Issue["repairs"][number] }>;
  busy: string | null;
  onHistory: () => void;
  onUpdate: (updates: Partial<Pick<Website, "monitoringEnabled" | "intervalMinutes" | "environmentType" | "relatedWebsiteId">>) => void;
  onScan: (withAi: boolean) => void;
  onSecurityCheck: () => void;
  onNotice: (message: string) => void;
  connection: ReactNode;
  scanStatus: { scanId: string; status: string; withAi: boolean } | null;
  onUpload: (target: UploadTarget) => void;
  onFixIssue: (issueId: string) => void;
}) {
  const check = site.checks[0] ?? null;
  const openIssues = issues.filter((issue) => issue.status !== "resolved");
  const browserIssues = issues.filter((issue) => issue.source === "browser_monitor" || issue.source === "browser" || issue.toolIds.some((id) => id.includes("browser")));
  const issueEvidence = (issue: Issue) => issue.evidence && typeof issue.evidence === "object" ? issue.evidence as Record<string, unknown> : {};
  const browserFinding = (issue: Issue) => {
    const evidence = issueEvidence(issue);
    const browser = evidence.browser && typeof evidence.browser === "object" ? evidence.browser as Record<string, unknown> : {};
    return browser.finding && typeof browser.finding === "object" ? browser.finding as Record<string, unknown> : {};
  };
  if (tab === "backups") return <BackupsManager websiteId={site.id} />;
  if (tab === "cleanup") return <CleanupManager websiteId={site.id} onNotice={onNotice} />;
  if (tab === "renewals") return <RenewalsPanel websiteId={site.id} onNotice={onNotice} />;
  if (tab === "software") return <SoftwarePanel websiteId={site.id} diagnostics={site.wordpressAgent?.diagnostics} issues={issues} onUpload={onUpload} onFix={onFixIssue} />;
  if (tab === "protection") return <><ProtectionManager websiteId={site.id} onNotice={onNotice} /><CloudflarePanel websiteId={site.id} onNotice={onNotice} /></>;
  if (tab === "overview") {
    return <div className="detail-content">
      <div className="detail-metrics">
        <div><small>HEALTH SCORE</small><strong>{check ? check.available
          ? `${Math.max(0, 100 - openIssues.reduce((score, issue) => score + (issue.severity === "critical" ? 40 : issue.severity === "high" ? 25 : issue.severity === "medium" ? 10 : 3), 0))}%`
          : "0%" : "—"}</strong></div>
        <div><small>STATUS</small><strong>{check ? check.available ? "Online" : "Unavailable" : "Not checked"}</strong></div>
        <div><small>LATEST RESPONSE</small><strong>{check?.responseTime !== null && check?.responseTime !== undefined ? `${check.responseTime} ms` : "—"}</strong></div>
        <div><small>OPEN ISSUES</small><strong>{openIssues.length}</strong></div>
        <div><small>MONITORING</small><strong>{site.monitoringEnabled ? `Every ${site.intervalMinutes} min` : "Paused"}</strong></div>
      </div>
      <p className="detail-url">{site.url}</p>
      <p className="diagnostic-limit">Environment: <strong>{site.environmentType === "staging" ? "Staging" : "Production"}</strong>{site.relatedWebsite ? ` · Paired with ${site.relatedWebsite.name} (${site.relatedWebsite.environmentType})` : " · No paired environment is required"}</p>
      <div className="site-settings">
        <label>Environment<select value={site.environmentType} onChange={(event) => onUpdate({ environmentType: event.target.value as "production" | "staging" })} disabled={busy !== null}><option value="production">Production</option><option value="staging">Staging</option></select></label>
        <label>Paired environment<select value={site.relatedWebsiteId ?? ""} onChange={(event) => onUpdate({ relatedWebsiteId: event.target.value || null })} disabled={busy !== null}><option value="">None</option>{websites.filter((candidate) => candidate.id !== site.id && candidate.environmentType !== site.environmentType).map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name} · {candidate.environmentType}</option>)}</select></label>
      </div>
      {check && <small>Last check: {new Date(check.checkedAt).toLocaleString()} · HTTP {check.statusCode ?? "—"}</small>}
      {openIssues.length > 0 && <div className="detail-issue-list">{openIssues.map((issue) => (
        <article className="repair-card" key={issue.id}>
          <div className="issue-heading"><span className={`severity severity-${issue.severity}`}>{issue.severity}</span><div><strong>{issue.title}</strong><small>{issue.source} · {new Date(issue.lastSeenAt).toLocaleString()}</small></div></div>
          <p>{issue.description}</p>
          {issue.diagnosis?.diagnosis && <DiagnosisDetails diagnosis={issue.diagnosis.diagnosis} />}
        </article>
      ))}</div>}
      <small className="score-note">Health score is a local summary of the latest availability check and open issue severity. It is not a full quality or security audit.</small>
      {!check && <p className="activity-empty">Run an availability check to establish a baseline.</p>}
    </div>;
  }
  if (tab === "diagnostics") {
    const wp = site.wordpressAgent;
    return <div className="detail-content">
      <h3>Availability</h3>
      {check ? <p>{check.available ? "The latest HTTP check succeeded." : check.error ?? "The latest HTTP check failed."} {check.statusCode ? `HTTP ${check.statusCode}` : ""} {check.responseTime !== null ? `· ${check.responseTime} ms` : ""}</p> : <p>No availability check has been recorded.</p>}
      <h3>WordPress diagnostics</h3>
      {wp && !wp.revokedAt ? <>
        <p>WordPress {wp.wpVersion ?? "unknown"} · PHP {wp.phpVersion ?? "unknown"} · Last sync {new Date(wp.lastSeenAt).toLocaleString()}</p>
        <p>Active theme: {wp.diagnostics?.site?.activeTheme?.name ?? "Not reported"} · Plugins inspected: {wp.diagnostics?.plugins?.length ?? 0}</p>
        <p>Overdue scheduled events: {wp.diagnostics?.site?.overdueCronCount ?? "Not reported"}</p>
        <p>PHP debug.log evidence: {wp.diagnostics?.phpErrorLog?.status ?? "not reported"} · {wp.diagnostics?.phpErrors?.length ?? 0} parsed entries (up to 20). Collection requires the plugin’s explicit log opt-in.</p>
        {wp.diagnostics?.issues?.length ? <ul>{wp.diagnostics.issues.map((item, index) => <li key={`${item.title}-${index}`}>{item.severity}: {item.title}</li>)}</ul> : <p>No WordPress findings in the last synced diagnostics.</p>}
      </> : <p>WordPress agent is not connected. Plugin/theme diagnostics are unavailable.</p>}
      <h3>Browser findings</h3>
      {browserIssues.length ? <ul>{browserIssues.map((issue) => <li key={issue.id}><strong>{issue.title}</strong> · {issue.severity} · {issue.diagnosis?.diagnosis?.affectedPage ?? "Page is not recorded"}</li>)}</ul> : <p>No browser findings are stored yet. The daily <p>No browser findings are stored yet. The daily &quot;Browser checks&quot; GitHub Actions workflow opens each site in a real browser; start it by hand from the repository&apos;s Actions tab to check now.</p>quot;Browser checks<p>No browser findings are stored yet. The daily &quot;Browser checks&quot; GitHub Actions workflow opens each site in a real browser; start it by hand from the repository&apos;s Actions tab to check now.</p>quot; GitHub Actions workflow opens each site in a real browser; start it by hand from the repository<p>No browser findings are stored yet. The daily &quot;Browser checks&quot; GitHub Actions workflow opens each site in a real browser; start it by hand from the repository&apos;s Actions tab to check now.</p>apos;s Actions tab to check now.</p>}
      <p className="diagnostic-limit">Broken-link checks confirm same-origin 404/410 destinations or missing in-page anchors; external and 401/403 links are excluded. Browser observations cover only pages reached within crawl bounds. Server logs and application-level failures are not inferred from browser evidence.</p>
    </div>;
  }
  if (tab === "performance") {
    const samples = site.checks.filter((item) => item.responseTime !== null);
    const average = samples.length ? Math.round(samples.reduce((sum, item) => sum + (item.responseTime ?? 0), 0) / samples.length) : null;
    return <><PerformancePanel websiteId={site.id} onNotice={onNotice} /><details className="detail-content legacy-timing"><summary>Browser scan timings</summary>
      <h3>Availability response timing</h3><p>{average === null ? "No response-time samples are available." : `Average HTTP HEAD response: ${average} ms across ${samples.length} stored checks.`}</p>
      <p className="diagnostic-limit">Crawl resource count and transfer size are unique-resource totals across the scan. Timing summaries use valid page and viewport samples: median, 75th percentile, and maximum are reported separately; each page retains viewport-specific values. Transfer size is what the browser exposes through Resource Timing and can be understated for cross-origin resources without timing permission.</p>
      {browserIssues.length ? <div className="issue-list">{browserIssues.map((issue) => {
        const finding = browserFinding(issue);
        const metrics = issueEvidence(issue).browser && typeof issueEvidence(issue).browser === "object" ? (issueEvidence(issue).browser as Record<string, unknown>).metrics as Record<string, unknown> | undefined : undefined;
        const summary = metrics?.viewportMetricSummary && typeof metrics.viewportMetricSummary === "object" ? metrics.viewportMetricSummary as Record<string, { sampleCount?: number; median?: number | null; p75?: number | null; max?: number | null }> : {};
        const timing = Object.entries(summary).map(([key, value]) => `${key}: median ${value.median ?? "—"}, p75 ${value.p75 ?? "—"}, max ${value.max ?? "—"} (${value.sampleCount ?? 0} samples)`);
        return <article className="repair-card" key={issue.id}><strong>{issue.title}</strong><p>{issue.description}</p>{metrics && <small>{Object.entries(metrics).filter(([, value]) => typeof value === "number").map(([key, value]) => `${key}: ${value}`).join(" · ")} {timing.join(" · ")}</small>}{Object.keys(finding).length > 0 && <details><summary>Browser evidence</summary><pre>{JSON.stringify(finding, null, 2)}</pre></details>}</article>;
      })}</div> : <p>No browser performance measurements are stored yet.</p>}
      <p className="diagnostic-limit">Browser timing and paint metrics are diagnostic observations, not a Lighthouse score or field Core Web Vitals measurement. Interaction to Next Paint requires real user interaction.</p>
    </details></>;
  }
  if (tab === "accessibility" || tab === "responsive") {
    return <>{tab === "accessibility" && <AccessibilityFixes websiteId={site.id} onNotice={onNotice} />}<div className="detail-content">
      {(() => {
        const selected = browserIssues.filter((issue) => tab === "accessibility"
          ? /^browser:(?:accessibility-|missing-image-alt:|missing-form-label:)/.test(issue.fingerprint) || issue.title.toLowerCase().includes("accessibility")
          : issue.title.toLowerCase().includes("overflow") || issue.title.toLowerCase().includes("navigation") || issue.title.toLowerCase().includes("mobile") || issue.toolIds.some((id) => id.includes("browser")));
        return <>
          <h3>{tab === "accessibility" ? "Automated accessibility findings" : "Responsive browser findings"}</h3>
          {selected.length ? <div className="issue-list">{selected.map((issue) => <article className="repair-card" key={issue.id}><div className="issue-heading"><span className={`severity severity-${issue.severity}`}>{issue.severity}</span><strong>{issue.title}</strong></div><p>{issue.description}</p><small>{issue.diagnosis?.diagnosis?.affectedPage ?? "Affected page not identified"}</small><details><summary>Observed evidence</summary><pre>{JSON.stringify(browserFinding(issue), null, 2)}</pre></details></article>)}</div> : <p>No browser findings are stored for this site yet. These checks open the site in a real browser at desktop, tablet and phone widths once a day (the &quot;Browser checks&quot; GitHub Actions workflow); you can also start that workflow by hand.</p>}
          <p className="diagnostic-limit">{tab === "accessibility" ? "axe-core automated rule results are not a complete accessibility audit or WCAG conformance claim; manual review is still needed." : "Responsive observations reflect tested viewports and discovered pages within crawl limits; they do not guarantee every device layout."}</p>
        </>;
      })()}
    </div></>;
  }
  if (tab === "history") {
    return <div className="detail-content">
      <div className="panel-heading detail-inner-heading"><div><h3>Scan history</h3><small>Availability checks stored for this website</small></div>
        <button className="button secondary" onClick={onHistory}>{history ? "Refresh history" : "Load history"}</button></div>
      {history === null ? <p className="activity-empty">Load recent scan history.</p> : history.length === 0 ? <p className="activity-empty">No scans recorded.</p> : (
        <ul className="history-list">{history.map((item) => <li key={item.id}>
          <span className={`activity-dot ${item.available ? "good" : "bad"}`} />
          <strong>{item.available ? "Available" : "Unavailable"}</strong>
          <span>{item.statusCode ? `HTTP ${item.statusCode}` : item.error}</span>
          <span>{item.responseTime !== null ? `${item.responseTime} ms` : "—"}</span>
          <time>{new Date(item.checkedAt).toLocaleString()}</time>
        </li>)}</ul>
      )}
    </div>;
  }
  if (tab === "repair-history") {
    return <div className="detail-content">
      <h3>Repair history</h3>
      {repairs.length === 0 ? <p className="activity-empty">No repair proposals have been recorded for this website.</p> : <div className="issue-list">
        {repairs.map(({ issue, repair }) => <article className="repair-card repair-centre-card" key={repair.id}>
          <div className="issue-heading"><span className={`severity severity-${issue.severity}`}>{issue.severity}</span><div><strong>{repair.proposal.issue || issue.title}</strong><small>{repair.status.replaceAll("_", " ")} · {repair.risk} risk · {new Date(repair.events.at(-1)?.createdAt ?? "").toLocaleString()}</small></div></div>
          <p>{repair.proposal.rationale}</p>
          {repair.proposal.proposedChanges.length > 0 && <ul>{repair.proposal.proposedChanges.map((change, index) => <li key={index}>{change}</li>)}</ul>}
          {repair.proposal.manualGuidance && repair.proposal.manualGuidance.length > 0 && <div><strong>Manual remediation guidance · no changes will be executed</strong><ol>{repair.proposal.manualGuidance.map((step, index) => <li key={index}>{step}</li>)}</ol></div>}
          <RepairApprovalDetails repair={repair} />
          <div className="repair-state-grid"><span>Approval <strong>{repair.approvalStatus}</strong></span><span>Execution <strong>{repair.executionStatus}</strong></span><span>Verification <strong>{repair.verificationStatus}</strong></span><span>Rollback <strong>{repair.rollbackStatus}</strong></span></div>
        </article>)}
      </div>}
    </div>;
  }
  return <div className="detail-content settings-detail">
    <h3>Connection</h3>
    <div className="settings-connection">{connection}</div>
    <h3>Monitoring settings</h3>
    <label className="monitor-toggle"><input type="checkbox" checked={site.monitoringEnabled} disabled={busy !== null}
      onChange={(event) => onUpdate({ monitoringEnabled: event.target.checked })} /> Scheduled monitoring</label>
    <label className="interval-control">Check frequency
      <select value={site.intervalMinutes} disabled={busy !== null} onChange={(event) => onUpdate({ intervalMinutes: Number(event.target.value) })}>
        <option value={5}>Every 5 minutes</option><option value={15}>Every 15 minutes</option><option value={60}>Every hour</option>
        <option value={360}>Every 6 hours</option><option value={1440}>Every day</option>
      </select>
    </label>
    <div className="site-actions">
      <button className="button secondary" onClick={() => onScan(false)} disabled={busy !== null}>{busy === `scan:${site.id}` ? "Queueing…" : "Scan only"}</button>
      <button className="button ghost" onClick={() => onScan(true)} disabled={busy !== null}>{busy === `scan:${site.id}` ? "Queueing…" : "Scan + AI"}</button>
      <button className="button ghost" onClick={onSecurityCheck} disabled={busy !== null}>{busy === `security:${site.id}` ? "Checking…" : "Security check"}</button>
    </div>
    {scanStatus && <p className="diagnostic-limit">Latest scan: {scanStatus.status.replaceAll("_", " ")} · {scanStatus.withAi ? "AI analysis selected" : "automated evidence only"}</p>}
      <p>Automated scans collect HTTP availability, bounded same-origin Playwright browser evidence, broken-link checks, responsive observations, resource-performance signals, and axe-core accessibility findings. Link checks inspect at most 1,000 candidates and probe at most 200 unvisited same-origin targets. Performance flags use lab-sample thresholds: load over 5 seconds, LCP over 2.5 seconds, CLS over 0.1, resources over 1 MB or 3 seconds, and more than 100 resources on a page. “Scan only” stops after evidence collection. “Scan + AI” then analyzes up to ten active findings from that scan with the configured local model. WordPress/PHP errors, plugin inventory, and scheduled-task evidence come from the connected plugin; debug.log parsing requires the plugin’s explicit opt-in and is limited to a 16 KB read, 12 KB excerpt, and 20 structured PHP errors.</p>
  </div>;
}
