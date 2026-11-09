"use client";

import { FormEvent, useEffect, useState } from "react";
import { PhpVersionPanel } from "./php-version-panel";

type HostingCapability = {
  capability: string;
  supported: boolean;
  details?: string | null;
};

type HostingConnection = {
  id: string;
  websiteId: string;
  provider: string;
  connectionMethod: string;
  hostname: string;
  port: number | null;
  username: string | null;
  authMethod: string;
  documentRoot: string | null;
  status: string;
  lastSuccessfulConnection: string | null;
  lastConnectionTest: string | null;
  discoveredCapabilities: HostingCapability[];
};

type HostingOperation = {
  operation: string;
  kind: "diagnostic" | "repair";
  risk: string;
  description: string;
  requiresApproval: boolean;
  requiresRecoveryPoint: boolean;
  requiresVerification: boolean;
};

type HostingOperationGroup = {
  connectionId: string;
  provider: string;
  connectionMethod: string;
  availableOperations: HostingOperation[];
};

type HostingRepairIssue = { id: string; title: string };

const hostingRepairOperations = [
  "correct_file_permissions",
  "restore_htaccess",
  "regenerate_htaccess",
  "restore_configuration_file",
  "move_faulty_file",
] as const;

export function HostingManager({
  websiteId,
  websiteName,
  issues,
  onNotice,
  onProposalCreated,
}: {
  websiteId: string;
  websiteName: string;
  issues: HostingRepairIssue[];
  onNotice?: (message: string) => void;
  onProposalCreated: () => Promise<void>;
}) {
  const [connections, setConnections] = useState<HostingConnection[]>([]);
  const [operationsByConnection, setOperationsByConnection] = useState<Record<string, HostingOperation[]>>({});
  const [targetsByConnection, setTargetsByConnection] = useState<Record<string, string>>({});
  const [selectedOperationByConnection, setSelectedOperationByConnection] = useState<Record<string, string>>({});
  const [diagnosticResults, setDiagnosticResults] = useState<Record<string, unknown>>({});
  const [proposalTargetsByConnection, setProposalTargetsByConnection] = useState<Record<string, string>>({});
  const [proposalIssuesByConnection, setProposalIssuesByConnection] = useState<Record<string, string>>({});
  const [proposalOperationsByConnection, setProposalOperationsByConnection] = useState<Record<string, string>>({});
  const [inspectingConnectionId, setInspectingConnectionId] = useState<string | null>(null);
  const [proposingConnectionId, setProposingConnectionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [provider, setProvider] = useState("generic");
  const [method, setMethod] = useState("sftp");
  const [hostname, setHostname] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("");
  const [authMethod, setAuthMethod] = useState("key");
  const [documentRoot, setDocumentRoot] = useState("");
  const [hostKeyFingerprint, setHostKeyFingerprint] = useState("");
  const [secret, setSecret] = useState("");

  const loadConnections = async () => {
    setLoading(true);
    try {
      const [connectionsResponse, operationsResponse] = await Promise.all([
        fetch(`/api/sites/${websiteId}/hosting`),
        fetch(`/api/sites/${websiteId}/hosting/operations`),
      ]);
      const connectionsResult = await connectionsResponse.json();
      const operationsResult = await operationsResponse.json();
      if (!connectionsResponse.ok) throw new Error(connectionsResult.error ?? "Could not load hosting connections.");
      if (!operationsResponse.ok) throw new Error(operationsResult.error ?? "Could not load hosting operations.");
      setConnections(Array.isArray(connectionsResult) ? connectionsResult : []);
      setOperationsByConnection(Object.fromEntries(
        (Array.isArray(operationsResult) ? operationsResult as HostingOperationGroup[] : [])
          .map(({ connectionId, availableOperations }) => [
            connectionId,
            availableOperations.filter(({ kind, operation }) => kind === "diagnostic"
              && ["inspect_directory_structure", "inspect_file_permissions"].includes(operation)),
          ]),
      ));
    } catch (error) {
      onNotice?.(error instanceof Error ? error.message : "Hosting connections could not be loaded.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadConnections();
  }, [websiteId]);

  async function submit(testOnly: boolean) {
    setSaving(true);
    try {
      const response = await fetch(`/api/sites/${websiteId}/hosting`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          provider,
          method,
          hostname,
          port: Number(port),
          username,
          authMethod,
          documentRoot: method === "cpanel_uapi" ? "" : documentRoot,
          hostKeyFingerprint: method === "sftp" ? hostKeyFingerprint : "",
          secret,
          testConnection: testOnly,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not save the hosting connection.");
      await loadConnections();
      onNotice?.(testOnly ? "Hosting connection test succeeded." : `Saved hosting connection for ${websiteName}.`);
      setSecret("");
    } catch (error) {
      onNotice?.(error instanceof Error ? error.message : "Could not validate the hosting connection.");
    } finally {
      setSaving(false);
    }
  }

  async function inspect(connection: HostingConnection) {
    const operation = selectedOperationByConnection[connection.id] ?? operationsByConnection[connection.id]?.[0]?.operation;
    const target = targetsByConnection[connection.id]?.trim();
    if (!operation || !target) {
      onNotice?.("Choose an inspection and enter a target path inside the configured document root.");
      return;
    }
    setInspectingConnectionId(connection.id);
    setDiagnosticResults((current) => ({ ...current, [connection.id]: undefined }));
    try {
      const response = await fetch(`/api/sites/${websiteId}/hosting/operations`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ connectionId: connection.id, operation, target }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "The hosting inspection failed.");
      setDiagnosticResults((current) => ({ ...current, [connection.id]: result.result }));
    } catch (error) {
      onNotice?.(error instanceof Error ? error.message : "The hosting inspection failed.");
    } finally {
      setInspectingConnectionId(null);
    }
  }

  async function requestRepairReview(connection: HostingConnection) {
    const issueId = proposalIssuesByConnection[connection.id] ?? issues[0]?.id;
    const operation = proposalOperationsByConnection[connection.id] ?? hostingRepairOperations[0];
    const target = proposalTargetsByConnection[connection.id]?.trim();
    if (!issueId || !target) {
      onNotice?.("Choose an open issue and enter the exact target path for this hosting repair review.");
      return;
    }
    setProposingConnectionId(connection.id);
    try {
      const response = await fetch(`/api/sites/${websiteId}/hosting/repairs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ connectionId: connection.id, issueId, operation, target }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not record the hosting repair proposal.");
      await onProposalCreated();
      onNotice?.("Hosting repair proposal recorded for review. Approval will not change remote files.");
    } catch (error) {
      onNotice?.(error instanceof Error ? error.message : "Could not record the hosting repair proposal.");
    } finally {
      setProposingConnectionId(null);
    }
  }

  return (
    <div className="hosting-manager">
      <div className="wordpress-agent-heading">
        <strong>Hosting connections</strong>
        <span className={connections.length ? "agent-connected" : "agent-disconnected"}>{connections.length ? `${connections.length} configured` : "None"}</span>
      </div>
      <p>Connect through the protocol your hosting account supports. Hosting providers vary by client; enter a provider label and select an available connection method. Secrets are encrypted before they are stored.</p>
      <p>With a cPanel account (API token), you can switch the site&apos;s PHP version from here: the app checks compatibility first, verifies the site from outside after switching, and switches back automatically if the site breaks.</p>
      <p>Over SFTP this build can inspect files. Remote file changes are not implemented yet. When available, writing or overwriting will be optional and require your confirmation after a warning that names the exact target and recovery plan.</p>
      <p>Hosting-side PHP/server log reading is not implemented in this connection yet. WordPress PHP error evidence, when enabled in the paired plugin, comes from the site itself and is separate from hosting account logs.</p>

      {connections.length > 0 && (
        <div className="check-history">
          <strong>Registered connections</strong>
          <ul>
            {connections.map((connection) => (
              <li key={connection.id}>
                <span>{connection.provider}</span>
                <span> · {connection.connectionMethod}</span>
                <span> · {connection.hostname}:{connection.port ?? "default"}</span>
                <span> · {connection.status}</span>
                {connection.discoveredCapabilities.length > 0 && (
                  <small>Capabilities: {connection.discoveredCapabilities.map((capability) => capability.capability).join(", ")}</small>
                )}
                {(operationsByConnection[connection.id]?.length ?? 0) > 0 && (
                  <div className="hosting-inspection">
                    <label>
                      Inspect hosting connection
                      <select
                        value={selectedOperationByConnection[connection.id] ?? operationsByConnection[connection.id][0].operation}
                        onChange={(event) => setSelectedOperationByConnection((current) => ({ ...current, [connection.id]: event.target.value }))}
                      >
                        {operationsByConnection[connection.id].map((operation) => (
                          <option key={operation.operation} value={operation.operation}>
                            {operation.operation.replaceAll("_", " ")}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Target path
                      <input
                        value={targetsByConnection[connection.id] ?? ""}
                        onChange={(event) => setTargetsByConnection((current) => ({ ...current, [connection.id]: event.target.value }))}
                        placeholder={connection.documentRoot ?? "/configured/site/root"}
                      />
                    </label>
                    <button
                      type="button"
                      className="button ghost"
                      disabled={loading || saving || inspectingConnectionId !== null || connection.status !== "connected"}
                      onClick={() => void inspect(connection)}
                    >
                      {inspectingConnectionId === connection.id ? "Inspecting…" : "Inspect"}
                    </button>
                    {diagnosticResults[connection.id] !== undefined && (
                      <pre className="hosting-inspection-result">{JSON.stringify(diagnosticResults[connection.id], null, 2)}</pre>
                    )}
                  </div>
                )}
                {connection.status === "connected" && connection.connectionMethod === "cpanel_uapi" && (
                  <PhpVersionPanel websiteId={websiteId} connectionId={connection.id} onNotice={onNotice} />
                )}
                {connection.status === "connected" && connection.connectionMethod === "sftp" && (
                  <div className="hosting-inspection">
                    <strong>Request hosting repair review</strong>
                    <p>This creates an issue-linked review record only. It does not create a backup or make remote changes, even if approved.</p>
                    {issues.length === 0 ? <p>There are no open issues for this website to attach the review to.</p> : <>
                      <label>
                        Related issue
                        <select
                          value={proposalIssuesByConnection[connection.id] ?? issues[0].id}
                          onChange={(event) => setProposalIssuesByConnection((current) => ({ ...current, [connection.id]: event.target.value }))}
                        >
                          {issues.map((issue) => <option key={issue.id} value={issue.id}>{issue.title}</option>)}
                        </select>
                      </label>
                      <label>
                        Proposed operation
                        <select
                          value={proposalOperationsByConnection[connection.id] ?? hostingRepairOperations[0]}
                          onChange={(event) => setProposalOperationsByConnection((current) => ({ ...current, [connection.id]: event.target.value }))}
                        >
                          {hostingRepairOperations.map((operation) => (
                            <option key={operation} value={operation}>{operation.replaceAll("_", " ")}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Exact target path
                        <input
                          value={proposalTargetsByConnection[connection.id] ?? ""}
                          onChange={(event) => setProposalTargetsByConnection((current) => ({ ...current, [connection.id]: event.target.value }))}
                          placeholder={connection.documentRoot ?? "/configured/site/root"}
                          required
                        />
                      </label>
                      <button
                        type="button"
                        className="button ghost"
                        disabled={loading || saving || proposingConnectionId !== null || !connection.documentRoot}
                        onClick={() => void requestRepairReview(connection)}
                      >
                        {proposingConnectionId === connection.id ? "Recording…" : "Record review proposal"}
                      </button>
                    </>}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <form className="hosting-connection-form" onSubmit={(event) => {
        event.preventDefault();
        void submit(false);
      }}>
        <label className="hosting-field">
          Provider
          <input value={provider} onChange={(event) => setProvider(event.target.value)} placeholder="generic" />
        </label>
        <label className="hosting-field">
          Connection method
          <select value={method} onChange={(event) => {
            const next = event.target.value;
            setMethod(next);
            if (next === "cpanel_uapi") { setPort(2083); setAuthMethod("token"); }
            if (next === "sftp") { setPort(22); setAuthMethod("key"); }
          }}>
            <option value="ssh" disabled>SSH (not available yet)</option>
            <option value="sftp">SFTP</option>
            <option value="cpanel_uapi">cPanel (API token)</option>
            <option value="plesk_api" disabled>Plesk-compatible API (not available yet)</option>
            <option value="provider_api" disabled>Hosting provider API (not available yet)</option>
            <option value="server_agent" disabled>Server agent (not available yet)</option>
          </select>
        </label>
        <label className="hosting-field">
          Hostname / IP
          <input value={hostname} onChange={(event) => setHostname(event.target.value)} placeholder="example.com or 203.0.113.10" required />
        </label>
        <label className="hosting-field">
          Port
          <input type="number" min={1} max={65535} value={port} onChange={(event) => setPort(Number(event.target.value || 22))} />
        </label>
        <label className="hosting-field">
          Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="user or admin" />
        </label>
        <label className="hosting-field">
          Authentication method
          <select value={authMethod} onChange={(event) => setAuthMethod(event.target.value)}>
            <option value="key">SSH private key</option>
            <option value="password">Password</option>
            <option value="token">API token</option>
            <option value="none">None / not required</option>
          </select>
        </label>
        {method !== "cpanel_uapi" && <label className="hosting-field">
          Document root
          <input value={documentRoot} onChange={(event) => setDocumentRoot(event.target.value)} placeholder="/home/user/public_html" />
        </label>}
        {method === "cpanel_uapi" && <p className="hosting-field-help hosting-field-wide">
          Hostname: your server&apos;s hostname from cPanel → Server Information (port 2083), or cpanel.yourdomain on port 443. Username: the cPanel account name.
          Token: cPanel → Security → Manage API Tokens → Create. The site&apos;s domain and folder are found automatically; the host must have MultiPHP Manager enabled.
        </p>}
        {method === "sftp" && <label className="hosting-field hosting-field-wide">
          SSH host-key fingerprint (SHA256)
          <input value={hostKeyFingerprint} onChange={(event) => setHostKeyFingerprint(event.target.value)} placeholder="SHA256:..." required />
          <small className="hosting-field-help">Get this fingerprint from your hosting provider through a separate trusted channel.</small>
        </label>}
        <label className="hosting-field hosting-field-wide">
          Secret / token / private key
          <textarea value={secret} onChange={(event) => setSecret(event.target.value)} rows={3} placeholder="Paste a key, password, or API token. It is stored encrypted server-side." />
        </label>
        <div className="hosting-form-actions">
          <button type="submit" className="button secondary" disabled={saving || loading}>
            {saving ? "Saving…" : "Save connection"}
          </button>
          <button type="button" className="button ghost" disabled={saving || loading} onClick={() => void submit(true)}>
            Test connection
          </button>
        </div>
      </form>
    </div>
  );
}
