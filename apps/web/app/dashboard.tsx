"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { HostingManager } from "./hosting-manager";
import { BackupsManager } from "./backups-manager";
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

type StructuredDiagnosis = {
  issueTitle: string;
  issueTitleEvidenceRefs: string[];
  category: string;
  description: string;
  descriptionEvidenceRefs: string[];
  affectedWebsite: string;
  affectedPage: string | null;
  affectedComponent: string | null;
  severity: string;
  confidence: number;
  facts: Array<{ claim: string; evidenceRefs: string[] }>;
  hypotheses: Array<{ claim: string; evidenceRefs: string[] }>;
  probableRootCause: {
    claim: string;
    status: "hypothesis" | "insufficient_evidence";
    evidenceRefs: string[];
  };
  alternativeExplanations: Array<{ explanation: string; evidenceRefs: string[] }>;
  recommendedFix: {
    description: string;
    evidenceRefs: string[];
    risk: string;
    approvalRequired: true;
    verificationProcedure: string[];
  };
  evidenceReferences: Array<{ id: string; path: string; value: unknown }>;
};

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

type DashboardView = "dashboard" | "websites" | "issues" | "repairs" | "assistant" | "team";
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
  const [message, setMessage] = useState("");
  const [scanProgress, setScanProgress] = useState<Record<string, { scanId: string; status: string; withAi: boolean }>>({});
  const [history, setHistory] = useState<Record<string, Check[]>>({});
  const [pairingCodes, setPairingCodes] = useState<Record<string, { code: string; expiresAt: string }>>({});
  const [activeView, setActiveView] = useState<DashboardView>("dashboard");
  const [selectedWebsiteId, setSelectedWebsiteId] = useState<string | null>(null);
  const [websiteDetailTab, setWebsiteDetailTab] = useState<"overview" | "diagnostics" | "performance" | "accessibility" | "responsive" | "repair-history" | "backups" | "history" | "settings">("overview");
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
    if (!sitesResponse.ok || !issuesResponse.ok || !settingsResponse.ok || !membersResponse.ok) {
      throw new Error("Could not load dashboard data.");
    }
    const [sites, currentIssues, currentSettings, memberData] = await Promise.all([
      sitesResponse.json(),
      issuesResponse.json(),
      settingsResponse.json(),
      membersResponse.json(),
    ]);
    setWebsites(sites);
    setIssues(currentIssues);
    setSettings(currentSettings);
    setMembers(memberData.members.map(({ user, role }: { user: TeamMember; role: string }) => ({ ...user, role })));
    setAssistantWebsiteId((current) => current || sites[0]?.id || "");
    setSelectedWebsiteId((current) => current || sites[0]?.id || null);
  }, []);

  useEffect(() => {
    refresh().catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Could not load websites."));
  }, [refresh]);

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

  async function pauseAllAutomaticRepairs() {
    const automaticSites = websites;
    if (automaticSites.length === 0) return;
    setRepairPolicyBusy(true);
    try {
      const outcomes = await Promise.all(automaticSites.map(async (site) => {
        try {
        const currentResponse = await fetch(`/api/sites/${site.id}/repair-authorization`);
        const current = await currentResponse.json();
        if (!currentResponse.ok) throw new Error(`${site.name}: ${current.error ?? "Could not read permissions."}`);
        if (current.mode !== "auto_eligible" || current.paused) return { site: site.name, changed: false, error: "" };
        const response = await fetch(`/api/sites/${site.id}/repair-authorization`, {
          method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...current, paused: true }),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(`${site.name}: ${result.error ?? "Could not pause automatic repairs."}`);
        return { site: site.name, changed: true, error: "" };
        } catch (error) {
          return { site: site.name, changed: false, error: error instanceof Error ? error.message : "Could not pause automatic repairs." };
        }
      }));
      const changed = outcomes.filter((item) => item.changed).map((item) => item.site);
      setMessage(changed.length ? `Automatic repairs paused for: ${changed.join(", ")}. Manual Fix This Issue approvals remain available.` : "Automatic repairs were already paused or disabled on every website. Manual approvals remain available.");
      const failed = outcomes.filter((item) => item.error);
      if (selectedWebsiteId) {
        const response = await fetch(`/api/sites/${selectedWebsiteId}/repair-authorization`);
        if (response.ok) setRepairPolicy(await response.json());
      }
      await refresh();
      if (failed.length) setMessage((current) => `${current} Could not update: ${failed.map((item) => item.error).join("; ")}`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not pause automatic repairs across websites."); }
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
        setMessage(`${result.interpretationMode === "deterministic_fallback" ? "Local AI was unavailable; a conservative deterministic issue match was used. " : ""}${queued} queued, ${approval} awaiting your approval, ${guidance} guidance-only, ${(result.skipped ?? []).length} skipped.`);
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
    if (!window.confirm(`Remove ${member.email} from this organization?`)) return;
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
      await refresh();
      setMessage("Website added. Run a check to see its current status.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not add website. Check the server and database connection, then try again.");
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
    if (!window.confirm(`Remove ${site.name} and its monitoring history?`)) return;
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
    if (!window.confirm("Revoke this WordPress agent connection?")) return;
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
        ? window.prompt("Enter the exact same-site URL to replace the confirmed broken link. It must be a reachable page on this website.")?.trim()
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
  const latestCheckFor = (site: Website) => site.checks[0] ?? null;
  const openIssuesFor = (site: Website) => issues.filter((issue) => issue.website.id === site.id && issue.status !== "resolved");
  const healthyCount = websites.filter((site) =>
    latestCheckFor(site)?.available && openIssuesFor(site).length === 0,
  ).length;
  const warningCount = websites.filter((site) =>
    latestCheckFor(site)?.available && openIssuesFor(site).some((issue) => ["low", "medium"].includes(issue.severity)),
  ).length;
  const criticalCount = websites.filter((site) =>
    latestCheckFor(site)?.available === false
      || openIssuesFor(site).some((issue) => ["high", "critical"].includes(issue.severity)),
  ).length;
  const uptimeChecks = allChecks.filter((check) => check.statusCode !== null);
  const uptime = uptimeChecks.length > 0
    ? `${((uptimeChecks.filter((check) => check.available).length / uptimeChecks.length) * 100).toFixed(2)}%`
    : "—";
  const recentChecks = websites.flatMap((site) => site.checks.map((check) => ({ site, check })))
    .sort((a, b) => Date.parse(b.check.checkedAt) - Date.parse(a.check.checkedAt))
    .slice(0, 6);
  const recentIncidents = issues.filter((issue) => issue.status !== "resolved").slice(0, 5);
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
          <span className="local-badge"><span className="pulse" /> LOCAL MONITORING</span>
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
          repairs: "Repair centre",
          assistant: "Ask about your website health",
          team: "Organization members",
          dashboard: "Overview",
        }[activeView]}</h1>
        <p className="subtitle">{activeView === "assistant"
          ? "Answers use stored scan and issue evidence. If the evidence is missing, the assistant will say so."
          : "Monitor availability, review evidence, and get local AI guidance — all from your own machine."}</p>
      </section>

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
          <span className="summary-foot">sites with low or medium issues</span>
        </article>
        <article className="summary-card">
          <span className="summary-icon icon-red">!</span>
          <span className="summary-label">CRITICAL</span>
          <strong>{criticalCount}</strong>
          <span className="summary-foot">sites down or high severity</span>
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

      {(activeView === "dashboard" || activeView === "websites") && <div className="content-grid">
        <section className="panel sites-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">MONITORING</p>
              <h2>Your websites</h2>
            </div>
            <span className="count-pill">{websites.length} TOTAL</span>
          </div>

          {websites.length === 0 ? (
            <div className="empty-state">
              <div className="empty-orbit">◎</div>
          <h3>Your watchlist is ready</h3>
          <p>Add a production site on its own, or optionally link it to staging. Checks run only when you request them.</p>
            </div>
          ) : (
            <div className="site-list">
              {websites.map((site) => {
                const check = site.checks[0];
                const currentScan = scanProgress[site.id];
                return (
                  <article className="site-row" key={site.id}>
                    <span className={`site-status ${check ? check.available ? "online" : "offline" : "unchecked"}`}>
                      {check ? check.available ? "✓" : "!" : "·"}
                    </span>
                    <div className="site-info">
                      <strong>{site.name}</strong>
                      <small>{site.environmentType === "staging" ? "Staging" : "Production"}{site.relatedWebsite ? ` · linked to ${site.relatedWebsite.name}` : " · no paired environment"}</small>
                      <span>{site.url}</span>
                      {check && (
                        <small>
                          {check.available ? `HTTP ${check.statusCode}` : check.error}
                          {check.responseTime !== null && ` · ${check.responseTime} ms`}
                          {` · ${new Date(check.checkedAt).toLocaleString()}`}
                        </small>
                      )}
                    </div>
                    <div className="site-actions">
                      <button className="button secondary" onClick={() => runScanWorkflow(site, false)} disabled={busy !== null}>
                        {busy === `scan:${site.id}` ? "Queueing…" : "Scan only"}
                      </button>
                      <button className="button ghost" onClick={() => runScanWorkflow(site, true)} disabled={busy !== null} title="Collect automated evidence, then ask local AI to analyze findings from that scan.">
                        {busy === `scan:${site.id}` ? "Queueing…" : "Scan + AI"}
                      </button>
                      <button className="button ghost" onClick={() => toggleHistory(site)}>
                        {history[site.id] ? "Hide history" : "History"}
                      </button>
                      <button className="button ghost" onClick={() => {
                        setSelectedWebsiteId(site.id);
                        setWebsiteDetailTab("overview");
                      }}>Details</button>
                      <button className="button ghost danger-text" onClick={() => deleteWebsite(site)} disabled={busy !== null}>Remove</button>
                    </div>
                    {currentScan && <small className="diagnostic-limit">Latest scan: {currentScan.status.replaceAll("_", " ")}{currentScan.withAi ? " · AI analysis selected" : " · automated evidence only"}</small>}
                    <div className="site-settings">
                      <label className="monitor-toggle">
                        <input
                          type="checkbox"
                          checked={site.monitoringEnabled}
                          onChange={(event) => updateWebsite(site, { monitoringEnabled: event.target.checked })}
                          disabled={busy !== null}
                        />
                        Scheduled monitoring
                      </label>
                      <label className="interval-control">
                        Every
                        <select
                          value={site.intervalMinutes}
                          onChange={(event) => updateWebsite(site, { intervalMinutes: Number(event.target.value) })}
                          disabled={busy !== null}
                          aria-label={`Check frequency for ${site.name}`}
                        >
                          <option value={5}>5 min</option>
                          <option value={15}>15 min</option>
                          <option value={60}>1 hour</option>
                          <option value={360}>6 hours</option>
                          <option value={1440}>1 day</option>
                        </select>
                      </label>
                    </div>
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
                  </article>
                );
              })}
            </div>
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
        <section className="panel detail-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">WEBSITE DETAIL</p><h2>{selectedWebsite.name}</h2></div>
            <button className="button ghost" onClick={() => setSelectedWebsiteId(null)}>Close details</button>
          </div>
          <div className="detail-tabs" role="tablist" aria-label="Website detail sections">
            {(["overview", "diagnostics", "performance", "accessibility", "responsive", "repair-history", "backups", "history", "settings"] as const).map((tab) => (
              <button key={tab} role="tab" aria-selected={websiteDetailTab === tab} className={websiteDetailTab === tab ? "active" : ""}
                onClick={() => setWebsiteDetailTab(tab)}>{tab}</button>
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
            scanStatus={scanProgress[selectedWebsite.id] ?? null}
            websites={websites}
          />
        </section>
      )}

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
            <div className="panel-heading"><div><p className="eyebrow">INCIDENTS</p><h2>Recent issues</h2></div></div>
            {recentIncidents.length === 0 ? <p className="activity-empty">No open incidents.</p> : (
              <ul className="activity-list">{recentIncidents.map((issue) => (
                <li key={issue.id}><span className={`severity severity-${issue.severity}`}>{issue.severity}</span>
                  <div><strong>{issue.title}</strong><small>{issue.website.name} · {new Date(issue.lastSeenAt).toLocaleString()}</small></div>
                </li>
              ))}</ul>
            )}
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

      {(activeView === "dashboard" || activeView === "issues") && <section className="panel issues-panel">
        <div className="panel-heading">
          <div><p className="eyebrow">ISSUE MANAGEMENT</p><h2>{activeView === "issues" ? "All issues" : "Recent issues"}</h2></div>
          <span className="count-pill">{issues.filter((issue) => issue.status === "open").length} OPEN</span>
        </div>
        {issues.length === 0 ? (
          <div className="issue-empty">No issues recorded yet. Failed availability checks and AI diagnoses will appear here.</div>
        ) : (
          <div className="issue-list">
            {(activeView === "dashboard" ? issues.slice(0, 4) : issues).map((issue) => (
              <article className="issue-card" key={issue.id}>
                <div className="issue-heading">
                  <span className={`severity severity-${issue.severity}`}>{issue.severity}</span>
                  <div><strong>{issue.title}</strong><small>{issue.website.name} · {issue.diagnosis?.diagnosis?.category ?? issue.source} · {new Date(issue.lastSeenAt).toLocaleString()}</small></div>
                  <span className={`issue-state state-${issue.status}`}>{issue.status.replace("_", " ")}</span>
                </div>
                <p className="issue-description">{issue.description}</p>
                <small className="issue-page">Affected page: {issue.diagnosis?.diagnosis?.affectedPage ?? "Not identified from available evidence"}</small>
                {issue.evidence !== null && issue.evidence !== undefined && (
                  <details className="issue-evidence">
                    <summary>Diagnostic evidence</summary>
                    <pre>{JSON.stringify(issue.evidence, null, 2)}</pre>
                  </details>
                )}
                {issue.diagnosis?.diagnosis && (
                  <div className="issue-ai-diagnosis">
                    <strong>Central diagnosis · {issue.diagnosis.diagnosis.severity} · {Math.round(issue.diagnosis.diagnosis.confidence * 100)}% confidence</strong>
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
              </article>
            ))}
          </div>
        )}
      </section>}

      {activeView === "repairs" && (
        <section className="repair-centre">
          <section className="panel global-repair-pause">
            <div><p className="eyebrow">IMMEDIATE CONTROL</p><h2>Automatic repair controls</h2><p>Pausing stops new standing-policy authorizations across every website. Individual manual approvals remain available.</p></div>
            <button className="button danger" onClick={pauseAllAutomaticRepairs} disabled={repairPolicyBusy || websites.length === 0}>{repairPolicyBusy ? "Pausing…" : "Pause All Automatic Repairs"}</button>
          </section>
          <section className="panel repair-authorization-panel">
            <div className="panel-heading"><div><p className="eyebrow">CONTROLLED AUTONOMY</p><h2>Repair authorization</h2></div></div>
            <label>Website<select value={selectedWebsiteId ?? ""} onChange={(event) => { setSelectedWebsiteId(event.target.value || null); setRepairPromptIssueId(""); }}>
              {websites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
            </select></label>
            <p>Automatic mode only queues one allowlisted operation when it matches your selected permissions and risk ceiling. Diagnosis never grants permission to invent code or run arbitrary commands.</p>
            <label className="repair-policy-toggle"><input type="checkbox" checked={repairPolicy.mode === "auto_eligible"} onChange={(event) => setRepairPolicy((current) => ({ ...current, mode: event.target.checked ? "auto_eligible" : "manual" }))} /> Automatically queue eligible repairs under this policy</label>
            <fieldset><legend>Permitted operations</legend>
              {repairOperationDescriptions.map(([operation, description]) => <label key={operation} className="repair-policy-toggle"><input type="checkbox" checked={repairPolicy.allowedOperations.includes(operation)} onChange={(event) => setRepairPolicy((current) => ({ ...current, allowedOperations: event.target.checked ? [...current.allowedOperations, operation] : current.allowedOperations.filter((item) => item !== operation) }))} /><span><strong>{operation.replaceAll("_", " ")}</strong><small>{description}</small></span></label>)}
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
          <section className="panel batch-approval-bar">
            <div><strong>Batch approval · {selectedBatchRepairs.length} selected</strong><small>Selected proposals are revalidated for ownership, freshness, executor connection, exact allowlisted scope, and overlap.</small>
              {selectedBatchRepairs.length > 0 && <ul>{selectedBatchRepairs.map((id) => {
                const selected = repairRows.find(({ repair }) => repair.id === id);
                return selected ? <li key={id}>{selected.issue.website.name} · {selected.issue.title} · {selected.repair.risk} risk · {selected.repair.proposal.proposedChanges.join("; ")}</li> : null;
              })}</ul>}
            </div>
            <button className="button secondary" onClick={approveRepairBatch} disabled={repairPolicyBusy || selectedBatchRepairs.length === 0}>Approve and queue {selectedBatchRepairs.length || "selected"}</button>
          </section>
          <section className="panel" aria-label="Repair filters">
            <div className="panel-heading"><div><p className="eyebrow">REPAIR HISTORY</p><h2>Filter repairs</h2></div></div>
            <div className="repair-filter-row">
              <label>Website<select value={repairWebsiteFilter} onChange={(event) => setRepairWebsiteFilter(event.target.value)}>
                <option value="all">All websites</option>{websites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
              </select></label>
              <label>Risk<select value={repairRiskFilter} onChange={(event) => setRepairRiskFilter(event.target.value)}><option value="all">All risk levels</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label>
              <label>From<input type="date" value={repairFromDate} onChange={(event) => setRepairFromDate(event.target.value)} /></label>
              <label>To<input type="date" value={repairToDate} onChange={(event) => setRepairToDate(event.target.value)} /></label>
            </div>
          </section>
          {([
            ["Pending approval", ["pending_approval"]],
            ["Approved / executing", ["approved", "executing", "in_progress"]],
            ["Successful", ["verified"]],
            ["Failed", ["failed", "verification_failed", "inconclusive"]],
            ["Rollback needed", ["rollback_required"]],
            ["Rolled back", ["rolled_back"]],
            ["Rejected", ["rejected"]],
          ] as Array<[string, string[]]>).map(([title, statuses]) => {
            const rows = filteredRepairRows.filter(({ repair }) => statuses.includes(repair.status));
            return (
              <section className="panel repair-group" key={title}>
                <div className="panel-heading"><div><p className="eyebrow">REPAIR WORKFLOW</p><h2>{title}</h2></div><span className="count-pill">{rows.length}</span></div>
                {rows.length === 0 ? <p className="activity-empty">No repairs in this stage.</p> : (
                  <div className="issue-list">{rows.map(({ issue, repair }) => (
                    <article className="repair-card repair-centre-card" key={repair.id}>
                      {repair.status === "pending_approval" && repair.operationIds.length > 0 && repair.proposal.executionAvailable && <label className="batch-repair-select"><input type="checkbox" checked={selectedBatchRepairs.includes(repair.id)} onChange={(event) => setSelectedBatchRepairs((current) => event.target.checked ? [...current, repair.id] : current.filter((id) => id !== repair.id))} /> Include in batch approval</label>}
                      <div className="issue-heading">
                        <span className={`severity severity-${issue.severity}`}>{issue.severity}</span>
                        <div><strong>{repair.proposal.issue || issue.title}</strong><small>{issue.website.name} · {repair.risk} risk · {repair.status.replaceAll("_", " ")}</small></div>
                      </div>
                      <p>{repair.proposal.rationale}</p>
                      {repair.proposal.expectedImpact && <p><strong>Expected impact:</strong> {repair.proposal.expectedImpact}</p>}
                      {repair.proposal.recoveryAvailability && <p><strong>Undo:</strong> {repair.proposal.recoveryAvailability}</p>}
                      {repair.status === "rollback_required" && <p className="repair-limitation"><strong>Recovery needed:</strong> The plugin could not confirm its operation-specific undo. Review the execution and verification evidence below; use your existing site recovery process if manual recovery is needed.</p>}
                      {repair.proposal.proposedChanges.length > 0 && <ul>{repair.proposal.proposedChanges.map((change, index) => <li key={index}>{change}</li>)}</ul>}
                      {repair.proposal.manualGuidance && repair.proposal.manualGuidance.length > 0 && <div><strong>Manual remediation guidance · no changes will be executed</strong><ol>{repair.proposal.manualGuidance.map((step, index) => <li key={index}>{step}</li>)}</ol></div>}
                      <RepairApprovalDetails repair={repair} />
                      <div className="repair-state-grid">
                        <span>Approval <strong>{repair.approvalStatus}</strong></span>
                        <span>Backup <strong>{repair.backupStatus}</strong></span>
                        <span>Execution <strong>{repair.executionStatus}</strong></span>
                        <span>Verification <strong>{repair.verificationStatus}</strong></span>
                        <span>Rollback <strong>{repair.rollbackStatus}</strong></span>
                      </div>
                      {repair.status === "pending_approval" && (
                        <div className="issue-actions">
                          {repair.operationIds.length > 0 && repair.proposal.executionAvailable
                            ? <button className="button primary" onClick={() => decideRepair(repair.id, "approve_and_apply")} disabled={busy !== null}>Fix This Issue</button>
                            : <button className="button secondary" onClick={() => decideRepair(repair.id, "approve")} disabled={busy !== null}>{repair.proposal.hostingRequest ? "Acknowledge review only" : "Acknowledge manual plan"}</button>}
                          <button className="button ghost" onClick={() => decideRepair(repair.id, "reject")} disabled={busy !== null}>Reject</button>
                        </div>
                      )}
                      {repair.events.length > 0 && <details><summary>Lifecycle history ({repair.events.length})</summary>
                        <ol>{repair.events.map((event) => <li key={event.id}>{event.eventType.replaceAll("_", " ")} · {event.actor} · {new Date(event.createdAt).toLocaleString()}</li>)}</ol>
                      </details>}
                      {(repair.approvals?.length || repair.verificationResults?.length) ? <details><summary>Approvals and verification evidence</summary>
                        {repair.approvals?.map((approval) => <p key={approval.id}>Approval: {approval.decision} · {new Date(approval.createdAt).toLocaleString()}{approval.comment ? ` · ${approval.comment}` : ""}</p>)}
                        {repair.verificationResults?.map((verification) => <div key={verification.id}><p>Verification: {verification.status} via {verification.method} · {new Date(verification.createdAt).toLocaleString()}</p><pre>{JSON.stringify(verification.result, null, 2)}</pre></div>)}
                      </details> : null}
                    </article>
                  ))}</div>
                )}
              </section>
            );
          })}
          <p className="repair-limitation">Queued repairs are delivered to the connected WordPress plugin on its next traffic-triggered WP-Cron poll. Sites with no incoming traffic may not poll promptly.</p>
        </section>
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

      {activeView === "dashboard" && <section className="system-settings">
        <div><span className="eyebrow">SYSTEM SETTINGS</span><strong>Organization accounts</strong><small>Database-backed sessions and membership-based access</small></div>
        <div><span className="eyebrow">AI PROVIDER</span><strong>{settings?.aiProvider ?? "Loading…"}</strong><small>{settings?.aiConfigured ? "Server-side model configured" : "AI environment config required"} · Optional. Current model provider integration: Ollama only.</small></div>
        <div><span className="eyebrow">MONITORING</span><strong>{settings?.scheduledMonitoring ? "Scheduler enabled" : "On demand"}</strong><small>Checks run locally; no external monitor</small></div>
      </section>}

      {message && <div className="toast" role="status">{message}<button aria-label="Dismiss message" onClick={() => setMessage("")}>×</button></div>}

      <footer className="footer">
        <span>AI WEBSITE DOCTOR <span className="footer-dot">•</span> LOCAL-FIRST MONITORING</span>
        <span>Scheduled checks are local. Approved repair proposals are not executed.</span>
      </footer>
    </main>
  );
}

function DiagnosisDetails({ diagnosis }: { diagnosis: StructuredDiagnosis }) {
  const formatValue = (value: unknown) =>
    typeof value === "string" ? value : JSON.stringify(value);
  const references = (ids: string[]) => ids.length > 0 ? ` [${ids.join(", ")}]` : "";

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
      <ul>{diagnosis.facts.map((fact, index) => <li key={index}>{fact.claim}{references(fact.evidenceRefs)}</li>)}</ul>
      <h4>Hypotheses</h4>
      <p>{diagnosis.probableRootCause.status === "insufficient_evidence" ? "Insufficient evidence to identify a probable cause." : diagnosis.probableRootCause.claim}{references(diagnosis.probableRootCause.evidenceRefs)}</p>
      {diagnosis.hypotheses.length > 0 && (
        <ul>{diagnosis.hypotheses.map((item, index) => <li key={index}>{item.claim}{references(item.evidenceRefs)}</li>)}</ul>
      )}
      {diagnosis.alternativeExplanations.length > 0 && (
        <>
          <h4>Alternative explanations</h4>
          <ul>{diagnosis.alternativeExplanations.map((item, index) => <li key={index}>{item.explanation}{references(item.evidenceRefs)}</li>)}</ul>
        </>
      )}
      <h4>Recommended fix · {diagnosis.recommendedFix.risk} risk · approval required</h4>
      <p>{diagnosis.recommendedFix.description}{references(diagnosis.recommendedFix.evidenceRefs)}</p>
      <ul>{diagnosis.recommendedFix.verificationProcedure.map((step, index) => <li key={index}>{step}</li>)}</ul>
      <details>
        <summary>Evidence references ({diagnosis.evidenceReferences.length})</summary>
        <ul>{diagnosis.evidenceReferences.map((reference) => (
          <li key={reference.id}><code>{reference.id}</code> {reference.path}: {formatValue(reference.value)}</li>
        ))}</ul>
      </details>
      <small>Model confidence: {Math.round(diagnosis.confidence * 100)}%</small>
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
  scanStatus,
}: {
  site: Website;
  websites: Website[];
  issues: Issue[];
  history: Check[] | null;
  tab: "overview" | "diagnostics" | "performance" | "accessibility" | "responsive" | "repair-history" | "backups" | "history" | "settings";
  repairs: Array<{ issue: Issue; repair: Issue["repairs"][number] }>;
  busy: string | null;
  onHistory: () => void;
  onUpdate: (updates: Partial<Pick<Website, "monitoringEnabled" | "intervalMinutes" | "environmentType" | "relatedWebsiteId">>) => void;
  onScan: (withAi: boolean) => void;
  scanStatus: { scanId: string; status: string; withAi: boolean } | null;
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
      {browserIssues.length ? <ul>{browserIssues.map((issue) => <li key={issue.id}><strong>{issue.title}</strong> · {issue.severity} · {issue.diagnosis?.diagnosis?.affectedPage ?? "Page is not recorded"}</li>)}</ul> : <p>No browser findings are stored yet. Run a browser scan from the monitoring API or scheduled scan runner.</p>}
      <p className="diagnostic-limit">Broken-link checks confirm same-origin 404/410 destinations or missing in-page anchors; external and 401/403 links are excluded. Browser observations cover only pages reached within crawl bounds. Server logs and application-level failures are not inferred from browser evidence.</p>
    </div>;
  }
  if (tab === "performance") {
    const samples = site.checks.filter((item) => item.responseTime !== null);
    const average = samples.length ? Math.round(samples.reduce((sum, item) => sum + (item.responseTime ?? 0), 0) / samples.length) : null;
    return <div className="detail-content">
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
    </div>;
  }
  if (tab === "accessibility" || tab === "responsive") {
    return <div className="detail-content">
      {(() => {
        const selected = browserIssues.filter((issue) => tab === "accessibility"
          ? issue.title.toLowerCase().includes("accessibility") || issue.title.toLowerCase().includes("alt text") || issue.title.toLowerCase().includes("label") || issue.title.toLowerCase().includes("contrast") || String(browserFinding(issue).fingerprint ?? "").startsWith("accessibility-")
          : issue.title.toLowerCase().includes("overflow") || issue.title.toLowerCase().includes("navigation") || issue.title.toLowerCase().includes("mobile") || issue.toolIds.some((id) => id.includes("browser")));
        return <>
          <h3>{tab === "accessibility" ? "Automated accessibility findings" : "Responsive browser findings"}</h3>
          {selected.length ? <div className="issue-list">{selected.map((issue) => <article className="repair-card" key={issue.id}><div className="issue-heading"><span className={`severity severity-${issue.severity}`}>{issue.severity}</span><strong>{issue.title}</strong></div><p>{issue.description}</p><small>{issue.diagnosis?.diagnosis?.affectedPage ?? "Affected page not identified"}</small><details><summary>Observed evidence</summary><pre>{JSON.stringify(browserFinding(issue), null, 2)}</pre></details></article>)}</div> : <p>No matching browser findings are stored for this site yet.</p>}
          <p className="diagnostic-limit">{tab === "accessibility" ? "axe-core automated rule results are not a complete accessibility audit or WCAG conformance claim; manual review is still needed." : "Responsive observations reflect tested viewports and discovered pages within crawl limits; they do not guarantee every device layout."}</p>
        </>;
      })()}
    </div>;
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
    </div>
    {scanStatus && <p className="diagnostic-limit">Latest scan: {scanStatus.status.replaceAll("_", " ")} · {scanStatus.withAi ? "AI analysis selected" : "automated evidence only"}</p>}
      <p>Automated scans collect HTTP availability, bounded same-origin Playwright browser evidence, broken-link checks, responsive observations, resource-performance signals, and axe-core accessibility findings. Link checks inspect at most 1,000 candidates and probe at most 200 unvisited same-origin targets. Performance flags use lab-sample thresholds: load over 5 seconds, LCP over 2.5 seconds, CLS over 0.1, resources over 1 MB or 3 seconds, and more than 100 resources on a page. “Scan only” stops after evidence collection. “Scan + AI” then analyzes up to ten active findings from that scan with the configured local model. WordPress/PHP errors, plugin inventory, and scheduled-task evidence come from the connected plugin; debug.log parsing requires the plugin’s explicit opt-in and is limited to a 16 KB read, 12 KB excerpt, and 20 structured PHP errors.</p>
  </div>;
}
