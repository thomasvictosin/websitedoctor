import { after, NextResponse } from "next/server";
import { z } from "zod";
import { authorizeOwnerRequest } from "@/lib/auth-api";
import { db } from "@/lib/db";
import { sendEmail } from "@/lib/email";
import { integrationStatus, saveIntegrations } from "@/lib/integrations";
import { readBoundedJson } from "@/lib/request-json";
import { refreshAllVulnerabilities, vulnerabilityStatus } from "@/lib/vulnerabilities";

export const runtime = "nodejs";
export const maxDuration = 120;

async function organization(request: Request, write: boolean) {
  const authorization = await authorizeOwnerRequest(request, write);
  if ("response" in authorization) return { response: authorization.response } as const;
  const membership = await db.organizationMember.findFirst({
    where: { userId: authorization.ownerId, ...(write ? { role: { in: ["owner", "admin"] } } : {}) },
    orderBy: { createdAt: "asc" },
    select: { organizationId: true, user: { select: { email: true } } },
  });
  if (!membership) return { response: NextResponse.json({ error: write ? "Only organization owners and administrators can change integrations." : "No organization." }, { status: 403 }) } as const;
  return { organizationId: membership.organizationId, email: membership.user.email } as const;
}

export async function GET(request: Request) {
  const org = await organization(request, false);
  if ("response" in org) return org.response;
  return NextResponse.json({ ...(await integrationStatus(org.organizationId)), vulnerabilities: await vulnerabilityStatus(), accountEmail: org.email }, { headers: { "cache-control": "no-store" } });
}

const secret = z.string().trim().min(8).max(400).regex(/^[\x21-\x7e]+$/, "Keys contain no spaces.").nullable().optional();
const updateSchema = z.object({
  wordfenceKey: secret,
  pagespeedKey: secret,
  resendKey: secret,
  emailFrom: z.string().trim().max(200).regex(/^(?:[^<>@\n]{0,80}<)?[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+>?$/, "Use an address like Website Doctor <alerts@yourdomain.com>.").nullable().optional(),
  reminderEmails: z.array(z.string().trim().email().max(254)).max(10).optional(),
}).strict();

export async function PUT(request: Request) {
  const org = await organization(request, true);
  if ("response" in org) return org.response;
  const parsed = updateSchema.safeParse(await readBoundedJson(request, 8_000));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid settings." }, { status: 400 });
  await saveIntegrations(org.organizationId, parsed.data);
  // A new Wordfence key downloads the vulnerability database right away instead of waiting for tomorrow.
  if (typeof parsed.data.wordfenceKey === "string") after(async () => { try { await refreshAllVulnerabilities(); } catch (error) { console.error("Vulnerability refresh failed:", error instanceof Error ? error.message : error); } });
  return NextResponse.json({ ...(await integrationStatus(org.organizationId)), vulnerabilities: await vulnerabilityStatus(), refreshing: typeof parsed.data.wordfenceKey === "string" });
}

/** Actions: send a test email, or refresh the vulnerability database now. */
export async function POST(request: Request) {
  const org = await organization(request, true);
  if ("response" in org) return org.response;
  const body = z.object({ action: z.enum(["test_email", "refresh_vulnerabilities"]) }).safeParse(await readBoundedJson(request, 1_000));
  if (!body.success) return NextResponse.json({ error: "Unknown action." }, { status: 400 });
  if (body.data.action === "test_email") {
    const status = await integrationStatus(org.organizationId);
    const to = status.email.reminderEmails.length ? status.email.reminderEmails : [org.email];
    const result = await sendEmail(org.organizationId, { to, subject: "Website Doctor test email", text: "This is a test from Website Doctor. Renewal reminders and alerts will arrive like this." });
    return NextResponse.json(result.sent ? { message: `Test email sent to ${to.join(", ")}.` } : { error: result.reason }, { status: result.sent ? 200 : 400 });
  }
  const result = await refreshAllVulnerabilities();
  return NextResponse.json({ result, vulnerabilities: await vulnerabilityStatus() });
}
