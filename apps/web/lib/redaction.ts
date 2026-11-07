const sensitiveKey = /(?:authorization|password|passwd|secret|token|api[_-]?key|cookie|authorizedlogexcerpt|credential|private[_-]?key|database[_-]?url)/i;
const preservedAuthorizationKeys = /^(?:authorization(?:GrantId|ExpiresAt|Method|Scope)|authorization)$/i;
const sensitiveValue = /\b(authorization|password|passwd|secret|token|api[_-]?key|cookie)\s*[:=]\s*[^;\s,]+/gi;

export function redactApiValue(value: unknown): unknown {
  if (value instanceof Date) return value;
  if (typeof value === "string") {
    return value
      .replace(sensitiveValue, "$1=[REDACTED]")
      .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
      .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_KEY]")
      .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/gi, "[REDACTED_GITHUB_TOKEN]")
      .replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED_API_KEY]")
      .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_API_KEY]")
      .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[REDACTED_JWT]")
      .replace(/\b[A-Za-z0-9+/_-]{40,}={0,2}\b/g, "[REDACTED_TOKEN]");
  }
  if (Array.isArray(value)) return value.map(redactApiValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .flatMap(([key, child]) => {
        if (key === "authorization") return [[key, "******"]];
        if (!sensitiveKey.test(key) || preservedAuthorizationKeys.test(key)) return [[key, redactApiValue(child)]];
        return [];
      }),
  );
}
