"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type McpToken = {
  id: string;
  name: string;
  prefix: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  createdAt: string;
};

type Expiry = "30" | "90" | "365" | "none";

function tokenState(token: McpToken) {
  if (token.revokedAt) return "revoked";
  if (token.expiresAt && Date.parse(token.expiresAt) <= Date.now()) return "expired";
  return "active";
}

export function McpAccessManager({ onNotice }: { onNotice: (message: string) => void }) {
  const [tokens, setTokens] = useState<McpToken[]>([]);
  const [name, setName] = useState("Claude Code");
  const [expiry, setExpiry] = useState<Expiry>("90");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);
  const [origin, setOrigin] = useState("");

  const load = useCallback(async () => {
    const response = await fetch("/api/mcp-tokens");
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "Could not load MCP tokens.");
    setTokens(result.tokens as McpToken[]);
  }, []);

  useEffect(() => {
    setOrigin(window.location.origin);
    load().catch((error: unknown) => onNotice(error instanceof Error ? error.message : "Could not load MCP tokens."));
  }, [load, onNotice]);

  async function createToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const response = await fetch("/api/mcp-tokens", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, expiresInDays: expiry === "none" ? null : Number(expiry) }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not create the MCP token.");
      setCreated({ name: result.name, token: result.token });
      await load();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "Could not create the MCP token.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(token: McpToken) {
    if (!window.confirm(`Revoke "${token.name}"? Claude clients using it will lose access immediately.`)) return;
    try {
      const response = await fetch("/api/mcp-tokens", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ tokenId: token.id }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not revoke the MCP token.");
      await load();
      onNotice(`MCP token "${token.name}" revoked.`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "Could not revoke the MCP token.");
    }
  }

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      onNotice("Copied. Treat it as a password.");
    } catch {
      onNotice("Clipboard access failed. Select and copy the text manually.");
    }
  }

  const endpoint = `${origin}/api/mcp`;
  const claudeCodeCommand = created
    ? `claude mcp add --transport http website-doctor ${endpoint} --header "Authorization: Bearer ${created.token}"`
    : "";
  const desktopConfig = created
    ? JSON.stringify({ mcpServers: { "website-doctor": { command: "npx", args: ["-y", "mcp-remote", endpoint, "--header", `Authorization: Bearer ${created.token}`] } } }, null, 2)
    : "";

  return (
    <section className="panel team-panel" aria-labelledby="mcp-access-heading">
      <div className="panel-heading"><div><p className="eyebrow">AI ASSISTANT ACCESS</p><h2 id="mcp-access-heading">Claude MCP access</h2></div></div>
      <p>
        Connect Claude Code or Claude Desktop to this app so Claude can read your websites, WordPress plugin diagnostics, and issues,
        create repair proposals, and queue approved repairs for the plugin. A token acts as you, with your role. Claude can run only
        the app&apos;s allowlisted repair operations, each with a recovery point and central verification. It cannot change standing
        repair permissions, members, hosting credentials, or tokens.
      </p>
      <form className="team-form" onSubmit={createToken}>
        <label>Token name<input value={name} onChange={(event) => setName(event.target.value)} maxLength={80} required /></label>
        <label>Expires<select value={expiry} onChange={(event) => setExpiry(event.target.value as Expiry)}>
          <option value="30">In 30 days</option>
          <option value="90">In 90 days</option>
          <option value="365">In 1 year</option>
          <option value="none">Never</option>
        </select></label>
        <button className="button primary" type="submit" disabled={busy}>{busy ? "Creating…" : "Create MCP token"}</button>
      </form>

      {created && (
        <div className="pairing-code" role="status">
          <strong>Token for “{created.name}”. It is shown only once.</strong>
          <code>{created.token}</code>
          <button className="button ghost" type="button" onClick={() => copy(created.token)}>Copy token</button>
          <small>Claude Code: run this in a terminal.</small>
          <code>{claudeCodeCommand}</code>
          <button className="button ghost" type="button" onClick={() => copy(claudeCodeCommand)}>Copy command</button>
          <small>Claude Desktop: add this to claude_desktop_config.json, then restart Claude Desktop (requires Node.js).</small>
          <pre>{desktopConfig}</pre>
          <button className="button ghost" type="button" onClick={() => copy(desktopConfig)}>Copy config</button>
          <button className="button secondary" type="button" onClick={() => setCreated(null)}>I saved it, hide token</button>
        </div>
      )}

      <div className="team-list">
        {tokens.length === 0 ? <small>No MCP tokens yet.</small> : tokens.map((token) => {
          const state = tokenState(token);
          return (
            <article key={token.id}>
              <div>
                <strong>{token.name}</strong>
                <small>
                  {token.prefix}… · {state}
                  {` · created ${new Date(token.createdAt).toLocaleDateString()}`}
                  {` · last used ${token.lastUsedAt ? new Date(token.lastUsedAt).toLocaleString() : "never"}`}
                  {token.expiresAt && state === "active" ? ` · expires ${new Date(token.expiresAt).toLocaleDateString()}` : ""}
                </small>
              </div>
              {state === "active" && <button className="button ghost danger-text" type="button" onClick={() => revoke(token)}>Revoke</button>}
            </article>
          );
        })}
      </div>
      <small className="diagnostic-limit">Every MCP tool call is recorded in the audit log with the token that made it.</small>
    </section>
  );
}
