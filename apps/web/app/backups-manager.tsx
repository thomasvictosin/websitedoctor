"use client";

import { useCallback, useEffect, useState } from "react";
import { useConfirm } from "./confirm-dialog";

type BackupRow = {
  id: string;
  repairId: string | null;
  backupId: string | null;
  status: string;
  storageProvider: string | null;
  metadata: unknown;
  createdAt: string;
  restorable: boolean;
  restoreStatus: string;
  restoreCompletedAt: string | null;
  restoreResult: unknown;
};

type BackupResponse = {
  website: { id: string; name: string };
  drive: { connected: boolean; accountEmail: string | null };
  backups: BackupRow[];
};

function backupDetails(value: unknown): { operation: string; target: string } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { operation: "Repair recovery point", target: "" };
  const record = value as Record<string, unknown>;
  return {
    operation: typeof record.operation === "string" ? record.operation.replaceAll("_", " ") : "Repair recovery point",
    target: typeof record.target === "string" ? record.target : "",
  };
}

function restoreMessage(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const message = (value as Record<string, unknown>).message;
  return typeof message === "string" ? message : null;
}

export function BackupsManager({ websiteId }: { websiteId: string }) {
  const dialogs = useConfirm();
  const [data, setData] = useState<BackupResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [restoringId, setRestoringId] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/sites/${websiteId}/backups`, { cache: "no-store" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not load recovery points.");
      setData(result as BackupResponse);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not load recovery points.");
    } finally {
      setLoading(false);
    }
  }, [websiteId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!data?.backups.some((backup) => backup.restoreStatus === "requested")) return;
    const timer = window.setInterval(() => { void load(); }, 5000);
    return () => window.clearInterval(timer);
  }, [data?.backups, load]);

  async function requestRestore(backup: BackupRow) {
    if (!await dialogs.confirm({ title: "Restore this repair's saved state?", body: "Only this repair's saved WordPress state is restored. The paired plugin asks a local administrator to confirm, and stops if the target has changed since.", confirmLabel: "Request restore" })) return;
    setRestoringId(backup.id);
    setNotice("");
    try {
      const response = await fetch(`/api/backups/${backup.id}/restore`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error ?? "Could not request the recovery.");
      setNotice(result.message ?? "Restore request queued for the paired WordPress plugin.");
      await load();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not request the recovery.");
    } finally {
      setRestoringId(null);
    }
  }

  return (
    <section className="panel backup-manager">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">WEBSITE RECOVERY</p>
          <h2>{data?.website.name ?? "Website"} backups</h2>
        </div>
        {data?.drive.connected
          ? <span className="agent-connected">Google Drive connected</span>
          : <span className="agent-disconnected">Google Drive not connected</span>}
      </div>
      <p>These are repair-specific WordPress snapshots for this website only, not a full-site or database backup.</p>
      {data?.drive.connected ? (
        <p>Drive account: <strong>{data.drive.accountEmail}</strong>. Snapshots are encrypted by this app before upload.</p>
      ) : (
        <p>Connect the dedicated Google account to sync future repair snapshots. Existing local-only recovery points are not uploaded automatically.</p>
      )}
      {!data?.drive.connected && (
        <a className="button secondary" href={`/api/integrations/google-drive/connect?siteId=${encodeURIComponent(websiteId)}`}>
          Connect Google Drive
        </a>
      )}
      {notice && <p role="status" className="notice">{notice}</p>}
      {loading && !data ? <p>Loading recovery points…</p> : data?.backups.length ? (
        <div className="check-history">
          {data.backups.some((backup) => backup.restoreStatus === "requested") && <p role="status">Waiting for the paired WordPress administrator to confirm the restore…</p>}
          <ul>
            {data.backups.map((backup) => {
              const details = backupDetails(backup.metadata);
              const resultMessage = restoreMessage(backup.restoreResult);
              return <li key={backup.id}>
                <strong>{details.operation}</strong>
                {details.target && <span> · {details.target}</span>}
                <small>{new Date(backup.createdAt).toLocaleString()} · {backup.storageProvider === "google_drive" ? "Encrypted Google Drive snapshot" : "WordPress-local recovery point"} · {backup.status}</small>
                <small>Restore status: {backup.restoreStatus.replaceAll("_", " ")}</small>
                {backup.restoreStatus === "requested" && <small>Waiting for confirmation in the paired WordPress plugin.</small>}
                {backup.restoreStatus === "restored" && <small>Restored {backup.restoreCompletedAt ? new Date(backup.restoreCompletedAt).toLocaleString() : ""}.</small>}
                {backup.restoreStatus === "failed" && resultMessage && <small role="status">Restore failed: {resultMessage}</small>}
                {backup.restorable && backup.restoreStatus !== "requested" && backup.restoreStatus !== "restored" && (
                  <button
                    type="button"
                    className="button ghost"
                    disabled={restoringId !== null}
                    onClick={() => void requestRestore(backup)}
                  >
                    {restoringId === backup.id ? "Requesting…" : "Request restore"}
                  </button>
                )}
              </li>;
            })}
          </ul>
        </div>
      ) : <p>{data ? "No repair snapshots have been created for this website yet." : null}</p>}
      <small>A restore changes only the saved operation target, requires confirmation in WordPress, and is refused if its current value no longer matches the recorded repair state.</small>
    </section>
  );
}
