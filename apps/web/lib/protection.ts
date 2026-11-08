import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { db } from "./db.ts";

/**
 * Per-site protection settings and the automatic responses they enable:
 *
 * - selfHealing: when a new compromise finding appears, the app starts a
 *   cleanup limited to the safe, verified operations (quarantine dropped
 *   files, restore core files, remove injected .htaccess rules, reinstall
 *   tampered WordPress.org plugins, purge the cache). Salts, users and plugin
 *   removal always wait for a person. At most three automatic runs per day;
 *   more means something keeps reinfecting the site, which is reported.
 * - autoUpdates: once a day, update WordPress.org plugins with the verified,
 *   auto-rollback updater, but never while compromise findings are open.
 *
 * Every automatic action and every new critical/high security finding is
 * recorded as a notification, which the plugin emails to the site admin.
 */

export const PROTECTION_KEY = "protection";
export const SELF_HEAL_OPERATIONS = ["quarantine_file", "restore_core_file", "remove_htaccess_rules", "reinstall_plugin", "purge_page_cache"] as const;
const SELF_HEAL_DAILY_LIMIT = 3;
const AUTO_UPDATE_INTERVAL_MS = 24 * 60 * 60_000;

export const protectionSettingsSchema = z.object({
  selfHealing: z.boolean().default(false),
  autoUpdates: z.boolean().default(false),
  /** Pause all automation for the site without forgetting which responses are switched on. */
  paused: z.boolean().default(false),
  updatedAt: z.string().optional(),
  updatedBy: z.string().nullable().optional(),
});
export type ProtectionSettings = z.infer<typeof protectionSettingsSchema>;

export async function getProtectionSettings(websiteId: string): Promise<ProtectionSettings> {
  const setting = await db.systemSetting.findFirst({ where: { scope: "site", scopeId: websiteId, key: PROTECTION_KEY }, select: { value: true } });
  const parsed = protectionSettingsSchema.safeParse(setting?.value ?? {});
  return parsed.success ? parsed.data : { selfHealing: false, autoUpdates: false, paused: false };
}

export async function saveProtectionSettings(websiteId: string, organizationId: string, changes: Partial<Pick<ProtectionSettings, "selfHealing" | "autoUpdates" | "paused">>, userId: string | null) {
  const current = await getProtectionSettings(websiteId);
  const value = { ...current, ...changes, updatedAt: new Date().toISOString(), updatedBy: userId };
  await db.systemSetting.upsert({
    where: { organizationId_scope_scopeId_key: { organizationId, scope: "site", scopeId: websiteId, key: PROTECTION_KEY } },
    create: { organizationId, scope: "site", scopeId: websiteId, key: PROTECTION_KEY, value: value as Prisma.InputJsonValue },
    update: { value: value as Prisma.InputJsonValue },
  });
  await db.auditLog.create({ data: { action: "protection_settings_changed", actorType: "admin", actorId: userId ?? "unknown", actorUserId: userId, organizationId, resourceType: "website", resourceId: websiteId, details: changes as Prisma.InputJsonValue } });
  return value;
}

/** Notifications are scoped to a site through their category ("<kind>:<websiteId>"). */
export async function notifySite(websiteId: string, kind: "security" | "self_healing" | "maintenance", title: string, body: string) {
  const website = await db.website.findUnique({ where: { id: websiteId }, select: { organizationId: true, name: true } });
  if (!website) return null;
  return db.notification.create({ data: { organizationId: website.organizationId, category: `${kind}:${websiteId}`, title: `${website.name}: ${title}`.slice(0, 200), body: body.slice(0, 4000) } });
}

export async function recentSiteAlerts(websiteId: string, since: Date) {
  return db.notification.findMany({
    where: { category: { in: [`security:${websiteId}`, `self_healing:${websiteId}`, `maintenance:${websiteId}`, `renewal:${websiteId}`] }, createdAt: { gte: since } },
    orderBy: { createdAt: "desc" }, take: 20,
    select: { id: true, category: true, title: true, body: true, createdAt: true },
  });
}

/** Record a notification for compromise findings that are new or came back. */
export async function notifyNewSecurityFindings(websiteId: string, findings: Array<{ fingerprint: string; severity: string; title: string; description: string }>) {
  const severe = findings.filter((finding) => finding.severity === "critical" || finding.severity === "high");
  if (!severe.length) return;
  const since = new Date(Date.now() - 24 * 60 * 60_000);
  const recent = await db.notification.findMany({ where: { category: `security:${websiteId}`, createdAt: { gte: since } }, select: { body: true } });
  const fresh = severe.filter((finding) => !recent.some((note) => note.body.includes(`[${finding.fingerprint}]`)));
  if (!fresh.length) return;
  await notifySite(websiteId, "security", `${fresh.length} new security finding(s)`, fresh.map((finding) => `${finding.severity.toUpperCase()}: ${finding.title} [${finding.fingerprint}]\n${finding.description.slice(0, 500)}`).join("\n\n"));
}

type Actor = { kind: "standing"; userId: null; interface: "self_healing" | "auto_update" };

/** Start a safe automatic cleanup when self-healing is on and compromise evidence is open. */
export async function maybeSelfHeal(websiteId: string) {
  const settings = await getProtectionSettings(websiteId);
  if (!settings.selfHealing) return { started: false, reason: "self-healing is off" };
  if (settings.paused) return { started: false, reason: "automation is paused" };
  const evidence = await db.issue.count({ where: { websiteId, status: { in: ["open", "acknowledged"] }, severity: { in: ["critical", "high"] }, OR: [{ fingerprint: { startsWith: "security:" } }, { fingerprint: { startsWith: "wp:integrity:" } }] } });
  if (!evidence) return { started: false, reason: "no open compromise findings" };
  const { loadCleanupPlan, startCleanup, CleanupError } = await import("./cleanup-service.ts");
  const active = await db.repairProposal.findFirst({ where: { websiteId, status: { in: ["approved", "executing"] }, proposal: { path: ["kind"], equals: "compromise_cleanup" } }, select: { id: true } });
  if (active) return { started: false, reason: "a run is already active" };
  const since = new Date(Date.now() - 24 * 60 * 60_000);
  const recentRuns = await db.repairProposal.count({ where: { websiteId, initiatingInterface: "self_healing", createdAt: { gte: since } } });
  const { plan } = await loadCleanupPlan(websiteId);
  const steps = plan.steps.filter((step) => (SELF_HEAL_OPERATIONS as readonly string[]).includes(step.operation));
  if (!steps.some((step) => step.operation !== "purge_page_cache")) return { started: false, reason: "nothing safe to repair automatically" };
  // Blockers about scan age are tolerated: every step re-checks its target digest on the site.
  const hardBlockers = plan.blockers.filter((blocker) => !/30 minutes old/.test(blocker));
  if (hardBlockers.length) return { started: false, reason: hardBlockers.join(" ") };
  if (recentRuns >= SELF_HEAL_DAILY_LIMIT) {
    const warned = await db.notification.findFirst({ where: { category: `self_healing:${websiteId}`, title: { contains: "keeps coming back" }, createdAt: { gte: since } }, select: { id: true } });
    if (!warned) await notifySite(websiteId, "self_healing", "Malware keeps coming back", `Self-healing has repaired this site ${recentRuns} times in 24 hours and the problem returned each time. Something not covered by automatic repair (a backdoor in a plugin or theme, a scheduled task, or stolen credentials) is reinstalling it. Review the cleanup plan, rotate salts and passwords, and reinstall premium plugins and the theme.`);
    return { started: false, reason: "daily self-healing limit reached" };
  }
  try {
    const actor: Actor = { kind: "standing", userId: null, interface: "self_healing" };
    const started = await startCleanup({ websiteId, organizationId: "", planDigest: "self_healing", include: [], actor, explicit: { steps, title: "Automatic repair (self-healing)", mode: "compromise" } });
    await notifySite(websiteId, "self_healing", "Automatic repair started", `Self-healing queued ${steps.length} safe repair step(s):\n${steps.map((step) => `- ${step.description}`).join("\n")}\n\nThe plugin applies them on its next check-in and the app verifies the result from outside. Salts, users and plugin removal still need your approval in the cleanup plan.`);
    return { started: true, repairId: started.repairId };
  } catch (error) {
    if (error instanceof CleanupError) return { started: false, reason: error.message };
    throw error;
  }
}

/** Daily verified plugin updates, never while the site has open compromise findings. */
export async function maybeAutoUpdate(websiteId: string) {
  const settings = await getProtectionSettings(websiteId);
  if (!settings.autoUpdates) return { started: false, reason: "automatic updates are off" };
  if (settings.paused) return { started: false, reason: "automation is paused" };
  const compromised = await db.issue.count({ where: { websiteId, status: { in: ["open", "acknowledged"] }, severity: { in: ["critical", "high"] }, OR: [{ fingerprint: { startsWith: "security:" } }, { fingerprint: { startsWith: "wp:integrity:" } }] } });
  if (compromised) return { started: false, reason: "clean up the open security findings first" };
  const last = await db.repairProposal.findFirst({ where: { websiteId, initiatingInterface: "auto_update" }, orderBy: { createdAt: "desc" }, select: { createdAt: true } });
  if (last && Date.now() - last.createdAt.getTime() < AUTO_UPDATE_INTERVAL_MS) return { started: false, reason: "updated within the last day" };
  const active = await db.repairProposal.findFirst({ where: { websiteId, status: { in: ["approved", "executing"] }, proposal: { path: ["kind"], equals: "compromise_cleanup" } }, select: { id: true } });
  if (active) return { started: false, reason: "a run is already active" };
  const { startPluginUpdates, CleanupError } = await import("./cleanup-service.ts");
  try {
    const actor: Actor = { kind: "standing", userId: null, interface: "auto_update" };
    const started = await startPluginUpdates({ websiteId, organizationId: "", actor });
    await notifySite(websiteId, "maintenance", "Automatic plugin updates started", `${started.steps.length} WordPress.org plugin update(s) were queued:\n${started.steps.map((step) => `- ${step.description}`).join("\n")}${started.skipped.length ? `\n\nNot updated automatically:\n${started.skipped.map((item) => `- ${item}`).join("\n")}` : ""}`);
    return { started: true, repairId: started.repairId };
  } catch (error) {
    if (error instanceof CleanupError) return { started: false, reason: error.message };
    throw error;
  }
}

/** Run the automatic responses after new evidence arrives; failures never break ingestion. */
export async function runAutomaticProtection(websiteId: string) {
  try {
    const heal = await maybeSelfHeal(websiteId);
    if (!heal.started) await maybeAutoUpdate(websiteId);
  } catch (error) {
    console.error(`Automatic protection failed for ${websiteId}:`, error instanceof Error ? error.message : error);
  }
}
