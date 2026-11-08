import { getIntegrations } from "./integrations.ts";

/**
 * Outgoing email through Resend's HTTP API (free tier is enough for
 * reminders). Without a Resend key the caller falls back to the site's own
 * WordPress plugin, which mails its administrator with wp_mail.
 */
export async function sendEmail(organizationId: string, message: { to: string[]; subject: string; text: string }, fetcher: typeof fetch = fetch) {
  const { resendKey, emailFrom } = await getIntegrations(organizationId);
  const to = message.to.filter((address) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)).slice(0, 10);
  if (!resendKey) return { sent: false as const, reason: "No email provider is configured." };
  if (!to.length) return { sent: false as const, reason: "No reminder email address is set." };
  const response = await fetcher("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${resendKey}`, "content-type": "application/json" },
    body: JSON.stringify({ from: emailFrom || "Website Doctor <onboarding@resend.dev>", to, subject: message.subject.slice(0, 200), text: message.text.slice(0, 20_000) }),
    signal: AbortSignal.timeout(15_000),
  }).catch((error: unknown) => ({ ok: false, status: 0, text: async () => String(error) }) as unknown as Response);
  if (!response.ok) return { sent: false as const, reason: `The email provider returned HTTP ${response.status}: ${(await response.text()).slice(0, 200)}` };
  return { sent: true as const };
}
