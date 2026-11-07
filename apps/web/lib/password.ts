import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export function hashPassword(candidate: string): string {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString("base64url")}$${scryptSync(candidate, salt, 64).toString("base64url")}`;
}

export function verifyPassword(candidate: unknown, encoded: unknown): boolean {
  if (typeof candidate !== "string" || Buffer.byteLength(candidate) < 12 || typeof encoded !== "string") return false;
  const normalized = encoded.replaceAll("\\$", "$");
  const [algorithm, salt, expected, extra] = normalized.split("$");
  if (algorithm !== "scrypt" || !salt || !expected || extra !== undefined) return false;
  try {
    const saltBytes = Buffer.from(salt, "base64url");
    const expectedBytes = Buffer.from(expected, "base64url");
    if (saltBytes.length < 16 || expectedBytes.length !== 64) return false;
    return timingSafeEqual(scryptSync(candidate, saltBytes, expectedBytes.length), expectedBytes);
  } catch {
    return false;
  }
}

export function validAdminPassword(candidate: unknown): boolean {
  const configured = process.env.ADMIN_PASSWORD_HASH;
  return verifyPassword(candidate, configured);
}

export function authIsConfigured(): boolean {
  const passwordHash = (process.env.ADMIN_PASSWORD_HASH ?? "").replaceAll("\\$", "$");
  const validPasswordHash = /^scrypt\$[A-Za-z0-9_-]{22,}\$[A-Za-z0-9_-]{86}$/.test(passwordHash);
  const secureOriginConfigured = process.env.NODE_ENV !== "production"
    || isSecureApplicationOrigin(process.env.APP_ORIGIN);
  return validPasswordHash
    && Boolean(process.env.SESSION_SECRET && Buffer.byteLength(process.env.SESSION_SECRET) >= 32)
    && secureOriginConfigured;
}

function isSecureApplicationOrigin(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const origin = new URL(value);
    return origin.protocol === "https:" && origin.origin === value;
  } catch {
    return false;
  }
}
