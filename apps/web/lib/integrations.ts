import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { db } from "./db.ts";

/**
 * Organization integrations the owner pastes into Settings instead of the
 * hosting dashboard: the Wordfence Intelligence key (known vulnerabilities),
 * the Google PageSpeed Insights key (Core Web Vitals and performance score),
 * and Resend (reminder and alert email). Keys are stored encrypted
 * (AES-256-GCM, key derived from SESSION_SECRET) and never returned; the API
 * only reports whether each one is set. Environment variables still work and
 * take effect when nothing is stored.
 */

const SETTING_KEY = "integrations";
type Stored = { wordfenceKey?: string; pagespeedKey?: string; resendKey?: string; emailFrom?: string; reminderEmails?: string[]; updatedAt?: string };
export type IntegrationSecrets = { wordfenceKey: string | null; pagespeedKey: string | null; resendKey: string | null; emailFrom: string | null; reminderEmails: string[] };

function key(): Buffer {
  const secret = process.env.SESSION_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) throw new Error("SESSION_SECRET must be at least 32 bytes before integration keys can be stored.");
  return createHmac("sha256", secret).update("ai-website-doctor:integration-secret:v1").digest();
}

export function sealSecret(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${data.toString("base64url")}`;
}

export function openSecret(payload: string | undefined): string | null {
  if (!payload) return null;
  try {
    const [iv, tag, data] = payload.split(".");
    const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64url"));
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

async function storedRow(organizationId: string) {
  return db.systemSetting.findFirst({ where: { organizationId, scope: "organization", scopeId: organizationId, key: SETTING_KEY }, select: { id: true, value: true } });
}

export async function getIntegrations(organizationId: string): Promise<IntegrationSecrets> {
  const value = ((await storedRow(organizationId))?.value ?? {}) as Stored;
  return {
    wordfenceKey: openSecret(value.wordfenceKey) ?? process.env.WORDFENCE_INTELLIGENCE_API_KEY ?? null,
    pagespeedKey: openSecret(value.pagespeedKey) ?? process.env.PAGESPEED_API_KEY ?? null,
    resendKey: openSecret(value.resendKey) ?? process.env.RESEND_API_KEY ?? null,
    emailFrom: value.emailFrom ?? process.env.EMAIL_FROM ?? null,
    reminderEmails: Array.isArray(value.reminderEmails) ? value.reminderEmails : [],
  };
}

/** What the Settings page may see: never the keys themselves. */
export async function integrationStatus(organizationId: string) {
  const value = ((await storedRow(organizationId))?.value ?? {}) as Stored;
  const secrets = await getIntegrations(organizationId);
  const source = (stored: string | undefined, env: string | undefined) => stored ? "settings" : env ? "environment" : null;
  return {
    wordfence: { configured: Boolean(secrets.wordfenceKey), source: source(value.wordfenceKey, process.env.WORDFENCE_INTELLIGENCE_API_KEY) },
    pagespeed: { configured: Boolean(secrets.pagespeedKey), source: source(value.pagespeedKey, process.env.PAGESPEED_API_KEY) },
    email: { configured: Boolean(secrets.resendKey), source: source(value.resendKey, process.env.RESEND_API_KEY), from: secrets.emailFrom, reminderEmails: secrets.reminderEmails },
  };
}

export type IntegrationUpdate = { wordfenceKey?: string | null; pagespeedKey?: string | null; resendKey?: string | null; emailFrom?: string | null; reminderEmails?: string[] };

/** Set (string), clear (null) or keep (undefined) each value. */
export async function saveIntegrations(organizationId: string, update: IntegrationUpdate) {
  const row = await storedRow(organizationId);
  const next: Stored = { ...((row?.value ?? {}) as Stored) };
  for (const field of ["wordfenceKey", "pagespeedKey", "resendKey"] as const) {
    if (update[field] === null) delete next[field];
    else if (typeof update[field] === "string" && update[field]) next[field] = sealSecret(update[field]);
  }
  if (update.emailFrom === null) delete next.emailFrom;
  else if (typeof update.emailFrom === "string") next.emailFrom = update.emailFrom;
  if (update.reminderEmails) next.reminderEmails = update.reminderEmails;
  next.updatedAt = new Date().toISOString();
  if (row) await db.systemSetting.update({ where: { id: row.id }, data: { value: next as Prisma.InputJsonValue, isSecret: true } });
  else await db.systemSetting.create({ data: { organizationId, scope: "organization", scopeId: organizationId, key: SETTING_KEY, value: next as Prisma.InputJsonValue, isSecret: true } });
}

/** The first Wordfence key available in any organization (the vulnerability index is shared). */
export async function anyWordfenceKey(): Promise<string | null> {
  const rows = await db.systemSetting.findMany({ where: { scope: "organization", key: SETTING_KEY }, select: { value: true } });
  for (const row of rows) {
    const opened = openSecret((row.value as Stored).wordfenceKey);
    if (opened) return opened;
  }
  return process.env.WORDFENCE_INTELLIGENCE_API_KEY ?? null;
}
