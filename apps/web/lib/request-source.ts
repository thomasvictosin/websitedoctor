import { createHash } from "node:crypto";

export function requestSourceKey(request?: Request): string {
  const forwarded = process.env.TRUST_PROXY === "true"
    ? request?.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || request?.headers.get("x-real-ip")?.trim()
    : undefined;
  const source = forwarded || "local";
  return createHash("sha256").update(source).digest("hex");
}

export const requestSourceHash = requestSourceKey;
