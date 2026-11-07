import { z } from "zod";
import { isValidHostingHostname, validateHostingOperationTarget } from "./hosting.ts";

export const websiteInputSchema = z.object({
  name: z.string().trim().min(1).max(80),
  environmentType: z.enum(["production", "staging"]).default("production"),
  relatedWebsiteId: z.string().trim().min(1).optional().nullable(),
  url: z.string().trim().url().max(2048)
    .superRefine((value, context) => {
      const url = new URL(value);
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        context.addIssue({ code: "custom", message: "Only HTTP and HTTPS websites are supported." });
      }
      if (url.username || url.password) {
        context.addIssue({ code: "custom", message: "Website URLs must not contain credentials." });
      }
      if (url.search || url.hash) {
        context.addIssue({ code: "custom", message: "Register a website URL without query parameters or fragments." });
      }
    })
    .transform((value) => new URL(value).toString()),
  monitoringEnabled: z.boolean().default(false),
  intervalMinutes: z.number().int().min(5).max(1440).default(60),
});

export const websiteUpdateSchema = z.object({
  name: z.string().trim().min(1).max(80),
  environmentType: z.enum(["production", "staging"]).default("production"),
  relatedWebsiteId: z.string().trim().min(1).optional().nullable(),
  url: websiteInputSchema.shape.url,
  monitoringEnabled: z.boolean(),
  intervalMinutes: z.number().int().min(5).max(1440),
});

export const hostingConnectionInputSchema = z.object({
  provider: z.string().trim().min(1).max(80).default("generic"),
  method: z.enum(["ssh", "sftp", "cpanel_uapi", "plesk_api", "provider_api", "server_agent"]),
  hostname: z.string().trim().min(1).max(255).refine(isValidHostingHostname, "Enter a public IP address or a valid public hostname."),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().trim().max(128).optional().or(z.literal("")),
  authMethod: z.enum(["key", "password", "token", "none"]).default("key"),
  documentRoot: z.string().trim().max(512).optional().or(z.literal(""))
    .refine((value) => !value || validateHostingOperationTarget(value, value).ok, "Document root must be a safe absolute path other than filesystem root."),
  hostKeyFingerprint: z.string().trim().max(52).optional().or(z.literal(""))
    .refine((value) => !value || /^SHA256:[A-Za-z0-9+/]{43}=?$/.test(value), "Use the SSH SHA256 host-key fingerprint."),
  secret: z.string().trim().max(8192).optional().or(z.literal("")),
  testConnection: z.boolean().optional().default(false),
}).superRefine((value, context) => {
  if (value.method !== "sftp") return;
  if (!value.username) context.addIssue({ code: "custom", path: ["username"], message: "An SFTP username is required." });
  if (!value.documentRoot) context.addIssue({ code: "custom", path: ["documentRoot"], message: "An SFTP document root is required." });
  if (!value.secret) context.addIssue({ code: "custom", path: ["secret"], message: "An SFTP credential is required." });
  if (value.authMethod !== "key" && value.authMethod !== "password") {
    context.addIssue({ code: "custom", path: ["authMethod"], message: "SFTP supports SSH keys or passwords." });
  }
  if (!value.hostKeyFingerprint) {
    context.addIssue({ code: "custom", path: ["hostKeyFingerprint"], message: "Pin the SSH SHA256 host-key fingerprint before connecting." });
  }
});
