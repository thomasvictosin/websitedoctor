import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { posix } from "node:path";
import { testPinnedSftpConnection } from "./hosting-sftp.ts";
import { isPublicAddress } from "./monitor.ts";

export type HostingConnectionMethod =
  | "ssh"
  | "sftp"
  | "cpanel_uapi"
  | "plesk_api"
  | "provider_api"
  | "server_agent";

const hostingConnectionMethods = new Set<HostingConnectionMethod>([
  "ssh",
  "sftp",
  "cpanel_uapi",
  "plesk_api",
  "provider_api",
  "server_agent",
]);

export function isHostingConnectionMethod(value: string): value is HostingConnectionMethod {
  return hostingConnectionMethods.has(value as HostingConnectionMethod);
}

export type HostingAuthMethod = "key" | "password" | "token" | "none";

export type HostingCapability = {
  capability: string;
  supported: boolean;
  details?: string | null;
};

export type HostingOperationKind = "diagnostic" | "repair";

export type HostingOperationDefinition = {
  operation: string;
  kind: HostingOperationKind;
  description: string;
  risk: "low" | "medium" | "high";
  requiresApproval: boolean;
  requiresRecoveryPoint: boolean;
  requiresVerification: boolean;
  requiredCapabilities: string[];
};

export const HOSTING_OPERATION_REGISTRY: Record<string, HostingOperationDefinition> = {
  inspect_account_environment: {
    operation: "inspect_account_environment",
    kind: "diagnostic",
    description: "Identify the connected account, hosting environment, and basic account resources.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["ssh_connection", "cpanel_api_connection", "account_information"],
  },
  inspect_directory_structure: {
    operation: "inspect_directory_structure",
    kind: "diagnostic",
    description: "Inspect the website directory structure without writing files.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["inspect_directory_structure", "file_information"],
  },
  inspect_file_permissions: {
    operation: "inspect_file_permissions",
    kind: "diagnostic",
    description: "Read file and directory permissions for the website and relevant config files.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["inspect_file_permissions", "file_information"],
  },
  read_php_config: {
    operation: "read_php_config",
    kind: "diagnostic",
    description: "Read accessible PHP configuration and relevant version metadata.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["read_php_config", "php_settings"],
  },
  read_php_error_logs: {
    operation: "read_php_error_logs",
    kind: "diagnostic",
    description: "Inspect PHP error logs and fatal entries that are explicitly readable by the account.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["read_php_error_logs", "account_information"],
  },
  inspect_htaccess: {
    operation: "inspect_htaccess",
    kind: "diagnostic",
    description: "Review .htaccess or equivalent site configuration rules that are relevant to the issue.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["read_wordpress_files", "file_information"],
  },
  check_disk_usage: {
    operation: "check_disk_usage",
    kind: "diagnostic",
    description: "Check account and site disk usage and available resources.",
    risk: "low",
    requiresApproval: false,
    requiresRecoveryPoint: false,
    requiresVerification: false,
    requiredCapabilities: ["disk_usage", "resource_checks"],
  },
  correct_file_permissions: {
    operation: "correct_file_permissions",
    kind: "repair",
    description: "Correct verified permissions on a specific file or directory within the website root.",
    risk: "medium",
    requiresApproval: true,
    requiresRecoveryPoint: true,
    requiresVerification: true,
    requiredCapabilities: ["inspect_file_permissions", "upload_file"],
  },
  restore_htaccess: {
    operation: "restore_htaccess",
    kind: "repair",
    description: "Restore an approved backup of a site .htaccess file.",
    risk: "medium",
    requiresApproval: true,
    requiresRecoveryPoint: true,
    requiresVerification: true,
    requiredCapabilities: ["restore_file", "read_wordpress_files"],
  },
  regenerate_htaccess: {
    operation: "regenerate_htaccess",
    kind: "repair",
    description: "Regenerate a supported .htaccess configuration for the registered site after verification.",
    risk: "medium",
    requiresApproval: true,
    requiresRecoveryPoint: true,
    requiresVerification: true,
    requiredCapabilities: ["read_wordpress_files", "upload_file"],
  },
  restore_configuration_file: {
    operation: "restore_configuration_file",
    kind: "repair",
    description: "Restore a verified configuration file that was replaced or corrupted.",
    risk: "medium",
    requiresApproval: true,
    requiresRecoveryPoint: true,
    requiresVerification: true,
    requiredCapabilities: ["restore_file", "file_information"],
  },
  move_faulty_file: {
    operation: "move_faulty_file",
    kind: "repair",
    description: "Move or isolate a confirmed faulty file while preserving the rest of the site.",
    risk: "high",
    requiresApproval: true,
    requiresRecoveryPoint: true,
    requiresVerification: true,
    requiredCapabilities: ["backup_file", "inspect_file_metadata"],
  },
};

export const HOSTING_METHOD_CAPABILITIES: Record<HostingConnectionMethod, string[]> = {
  ssh: [
    "ssh_connection",
    "inspect_directory_structure",
    "inspect_file_permissions",
    "read_php_config",
    "read_php_error_logs",
    "read_wordpress_files",
  ],
  sftp: [
    "sftp_connection",
    "inspect_directory_structure",
    "inspect_file_permissions",
    "file_information",
  ],
  cpanel_uapi: [
    "cpanel_api_connection",
    "domain_discovery",
    "account_information",
    "disk_usage",
    "php_settings",
    "file_information",
  ],
  plesk_api: [
    "plesk_api_connection",
    "site_information",
    "file_information",
    "php_settings",
  ],
  provider_api: [
    "provider_api_connection",
    "account_status",
    "resource_checks",
    "site_metadata",
  ],
  server_agent: [
    "server_agent_connection",
    "host_read_only_checks",
    "host_repair_execution",
  ],
};

export function normalizeHostingMethod(value: string): HostingConnectionMethod {
  const normalized = value.trim().toLowerCase();
  if (normalized === "ssh") return "ssh";
  if (normalized === "sftp") return "sftp";
  if (normalized === "cpanel" || normalized === "cpanel_uapi") return "cpanel_uapi";
  if (normalized === "plesk" || normalized === "plesk_api") return "plesk_api";
  if (normalized === "provider" || normalized === "provider_api") return "provider_api";
  if (normalized === "server_agent" || normalized === "agent") return "server_agent";
  throw new Error(`Unsupported hosting connection method: ${value}`);
}

export function normalizeHostingAuthMethod(value: string): HostingAuthMethod {
  const normalized = value.trim().toLowerCase();
  if (normalized === "password") return "password";
  if (normalized === "token") return "token";
  if (normalized === "none") return "none";
  if (normalized === "key") return "key";
  throw new Error(`Unsupported hosting authentication method: ${value}`);
}

export function getRepresentativeCapabilities(method: HostingConnectionMethod): HostingCapability[] {
  return HOSTING_METHOD_CAPABILITIES[method].map((capability) => ({
    capability,
    supported: true,
    details: `Confirmed by the ${method} adapter contract while the actual host is being validated.`,
  }));
}

export function resolveHostingOperations(method: HostingConnectionMethod, capabilities: Array<{ capability: string; supported?: boolean } | string>): HostingOperationDefinition[] {
  const capabilitySet = new Set(
    capabilities
      .filter((item) => typeof item === "string" || item.supported === true)
      .map((item) => (typeof item === "string" ? item : item.capability))
      .filter(Boolean),
  );

  return Object.values(HOSTING_OPERATION_REGISTRY).filter((definition) => {
    const required = definition.requiredCapabilities;
    return required.every((capability) => capabilitySet.has(capability));
  }).filter((definition) => {
    const methodSet = new Set(HOSTING_METHOD_CAPABILITIES[method]);
    return definition.requiredCapabilities.some((capability) => methodSet.has(capability));
  });
}

export function validateHostingOperationTarget(target: string, root?: string | null): { ok: boolean; message?: string; normalized?: string } {
  const candidate = target.trim();
  if (!candidate) return { ok: false, message: "A hosting operation requires a target path." };
  if (!root?.trim()) return { ok: false, message: "A configured website root is required before validating a hosting target." };

  const unsafePath = (value: string) => (
    value.includes("\\")
    || value.includes("%")
    || /[\0-\x1f\x7f?#]/.test(value)
    || value.startsWith("//")
    || /^[a-zA-Z]:/.test(value)
    || value.split("/").some((segment) => segment === "." || segment === "..")
  );
  const rootCandidate = root.trim();
  if (!rootCandidate.startsWith("/") || unsafePath(rootCandidate)) {
    return { ok: false, message: "The configured website root must be a safe absolute POSIX path." };
  }
  if (unsafePath(candidate)) {
    return { ok: false, message: "Target paths must be explicit POSIX paths without traversal or encoded segments." };
  }

  const normalizedRoot = posix.normalize(rootCandidate);
  if (normalizedRoot === "/") {
    return { ok: false, message: "The filesystem root cannot be used as a website root." };
  }
  const normalizedTarget = posix.normalize(
    candidate.startsWith("/") ? candidate : posix.join(normalizedRoot, candidate),
  );
  const relative = posix.relative(normalizedRoot, normalizedTarget);
  if (relative === ".." || relative.startsWith("../") || posix.isAbsolute(relative)) {
    return { ok: false, message: "The requested path is outside the configured website root." };
  }

  return { ok: true, normalized: normalizedTarget };
}

export function validateHostingRepairProposal(
  operationName: string,
  targetPath: string,
  documentRoot: string | null | undefined,
): { ok: true; operation: HostingOperationDefinition; target: string } | { ok: false; message: string } {
  const operation = Object.hasOwn(HOSTING_OPERATION_REGISTRY, operationName)
    ? HOSTING_OPERATION_REGISTRY[operationName]
    : null;
  if (!operation || operation.kind !== "repair") {
    return { ok: false, message: "Choose a registered hosting repair operation." };
  }
  if (!documentRoot) {
    return { ok: false, message: "The SFTP connection has no configured document root." };
  }
  const target = validateHostingOperationTarget(targetPath, documentRoot);
  if (!target.ok || !target.normalized) {
    return { ok: false, message: target.message ?? "The target is not inside the configured website root." };
  }
  if (["restore_htaccess", "regenerate_htaccess"].includes(operation.operation)) {
    const rootHtaccess = validateHostingOperationTarget(".htaccess", documentRoot);
    if (!rootHtaccess.ok || target.normalized !== rootHtaccess.normalized) {
      return { ok: false, message: "This operation is limited to the .htaccess file at the website root." };
    }
  }
  return { ok: true, operation, target: target.normalized };
}

export function isValidHostingHostname(value: string): boolean {
  const hostname = value.trim().toLowerCase().replace(/\.$/, "");
  if (!hostname || hostname.length > 253 || /[/:@?#\s]/.test(hostname)) return false;
  if (isIP(hostname)) return isPublicAddress(hostname);
  if (
    hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname.endsWith(".internal")
    || hostname.endsWith(".home.arpa")
    || hostname.endsWith(".test")
    || hostname.endsWith(".invalid")
  ) return false;
  return hostname.includes(".") && hostname.split(".").every((label) => (
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ));
}

export function encryptHostingSecret(plaintext: string): string {
  const secret = process.env.HOSTING_CREDENTIALS_KEY ?? process.env.SESSION_SECRET ?? "ai-website-doctor-hosting-credentials-dev";
  const key = createHash("sha256").update(secret).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

export function decryptHostingSecret(payload: string): string {
  const parts = payload.split(":");
  if (parts.length !== 3) {
    throw new Error("Stored hosting credential is not in the expected encrypted format.");
  }
  const secret = process.env.HOSTING_CREDENTIALS_KEY ?? process.env.SESSION_SECRET ?? "ai-website-doctor-hosting-credentials-dev";
  const key = createHash("sha256").update(secret).digest();
  const iv = Buffer.from(parts[0], "base64");
  const tag = Buffer.from(parts[1], "base64");
  const encrypted = Buffer.from(parts[2], "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

export function fingerprintHostingCredential(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

export function buildHostingConnectionRecord(input: {
  provider: string;
  method: string;
  hostname: string;
  username?: string | null;
  port?: number | null;
  authMethod?: string;
  documentRoot?: string | null;
  secret?: string;
}) {
  const method = normalizeHostingMethod(input.method);
  const authMethod = normalizeHostingAuthMethod(input.authMethod ?? "key");
  const port = typeof input.port === "number" && Number.isFinite(input.port) ? input.port : undefined;
  const result = {
    provider: input.provider?.trim() || "generic",
    connectionMethod: method,
    hostname: input.hostname.trim(),
    port,
    username: input.username?.trim() || null,
    authMethod,
    documentRoot: input.documentRoot?.trim() || null,
    capabilities: getRepresentativeCapabilities(method),
    status: "connected",
    message: `Hosting connection registered for ${method}. Its connection test must pass before capabilities are enabled.`,
  } satisfies {
    provider: string;
    connectionMethod: HostingConnectionMethod;
    hostname: string;
    port?: number;
    username: string | null;
    authMethod: HostingAuthMethod;
    documentRoot: string | null;
    capabilities: HostingCapability[];
    status: string;
    message: string;
  };

  if (input.secret && input.secret.trim().length > 0) {
    result.message = `${result.message} A stored credential was encrypted and associated with this connection.`;
  }

  return result;
}

export async function discoverHostingCapabilities(input: {
  method: string;
  hostname: string;
  username?: string | null;
  port?: number | null;
  authMethod?: string;
  secret?: string;
  hostKeyFingerprint?: string;
  documentRoot?: string | null;
  provider?: string;
}): Promise<{
  ok: boolean;
  status: "success" | "error";
  message: string;
  capabilities: HostingCapability[];
  metadata?: Record<string, unknown>;
}> {
  const method = normalizeHostingMethod(input.method);
  const hostname = input.hostname?.trim() ?? "";
  const port = typeof input.port === "number" && Number.isFinite(input.port) ? input.port : (method === "ssh" || method === "sftp" ? 22 : method === "cpanel_uapi" ? 2083 : 443);

  if (!hostname) {
    return {
      ok: false,
      status: "error",
      message: "A hostname or IP address is required to test the hosting connection.",
      capabilities: [],
    };
  }

  if (port < 1 || port > 65535) {
    return {
      ok: false,
      status: "error",
      message: "The configured port must be between 1 and 65535.",
      capabilities: [],
    };
  }

  if (method === "ssh" || method === "sftp") {
    if (method === "ssh") {
      return {
        ok: false,
        status: "error",
        message: "No connection was attempted because the SSH command adapter is not implemented.",
        capabilities: getRepresentativeCapabilities(method).map((capability) => ({ ...capability, supported: false })),
      };
    }
    try {
      if (!input.documentRoot) throw new Error("A configured website document root is required for SFTP validation.");
      const authMethod = normalizeHostingAuthMethod(input.authMethod ?? "key");
      if (authMethod !== "key" && authMethod !== "password") {
        throw new Error("SFTP supports only private-key or password authentication.");
      }
      const verified = await testPinnedSftpConnection({
        hostname,
        port,
        username: input.username ?? "",
        authMethod,
        secret: input.secret ?? "",
        hostKeyFingerprint: input.hostKeyFingerprint ?? "",
        documentRoot: input.documentRoot,
      });
      const capabilities = getRepresentativeCapabilities(method).map((capability) => ({
        ...capability,
        supported: ["sftp_connection", "inspect_directory_structure", "inspect_file_permissions", "file_information"].includes(capability.capability),
        details: "Verified through a host-key-pinned SFTP session; remote writes are not enabled.",
      }));
      return {
        ok: true,
        status: "success",
        message: "The SSH host key matched the configured pin, and the document root resolved without symlinked path components. Read-only inspection capabilities are enabled.",
        capabilities,
        metadata: { port, documentRoot: verified.root, hostKeyFingerprint: verified.hostKeyFingerprint },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Connection test failed.";
      return {
        ok: false,
        status: "error",
        message: `SFTP host or document-root verification failed: ${message}`,
        capabilities: getRepresentativeCapabilities(method).map((capability) => ({ ...capability, supported: false })),
      };
    }
  }

  if (method === "cpanel_uapi") {
    return {
      ok: false,
      status: "error",
      message: "The cPanel UAPI adapter is not implemented yet; no network request was made.",
      capabilities: getRepresentativeCapabilities(method).map((capability) => ({ ...capability, supported: false })),
    };
  }

  if (method === "plesk_api" || method === "provider_api" || method === "server_agent") {
    return {
      ok: false,
      status: "error",
      message: `The ${method} adapter is not implemented yet; no network request was made.`,
      capabilities: getRepresentativeCapabilities(method).map((capability) => ({ ...capability, supported: false })),
    };
  }

  const capabilities = getRepresentativeCapabilities(method).map((capability) => ({ ...capability, supported: false }));
  return {
    ok: false,
    status: "error",
    message: `Unsupported hosting method: ${method}.`,
    capabilities,
  };
}

export async function testHostingConnection(input: {
  method: string;
  hostname: string;
  username?: string | null;
  port?: number | null;
  authMethod?: string;
  secret?: string;
  hostKeyFingerprint?: string;
  documentRoot?: string | null;
  provider?: string;
}) {
  return discoverHostingCapabilities(input);
}
