export function isSecureRequest(request: Request): boolean {
  if (process.env.NODE_ENV !== "production") return true;
  const forwardedProtocol = process.env.TRUST_PROXY === "true"
    ? request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim()
    : undefined;
  const protocol = forwardedProtocol ?? new URL(request.url).protocol.replace(/:$/, "");
  return protocol === "https";
}

export async function isSameOrigin(request: Request): Promise<boolean> {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host || !isSecureRequest(request)) return false;
  try {
    const actual = new URL(origin);
    const configured = process.env.APP_ORIGIN;
    const expected = configured ? new URL(configured) : new URL(request.url);
    return actual.origin.toLowerCase() === expected.origin.toLowerCase()
      && actual.host.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}
