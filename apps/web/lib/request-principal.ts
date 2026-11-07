import { AsyncLocalStorage } from "node:async_hooks";

/**
 * A user authenticated by something other than the browser session cookie.
 *
 * Only /api/mcp sets this, and only after verifying a hashed MCP access token
 * (lib/mcp-tokens.ts). Route handlers invoked inside `runAsPrincipal` then go
 * through the normal authorizeRequest gate, so every ownership, role, rate
 * limit, audit, and repair-safety check applies exactly as for the dashboard.
 */
export type RequestPrincipal = {
  userId: string;
  via: "mcp_token";
  tokenId: string;
};

const storage = new AsyncLocalStorage<RequestPrincipal>();

export function runAsPrincipal<T>(principal: RequestPrincipal, callback: () => Promise<T>): Promise<T> {
  return storage.run(principal, callback);
}

export function currentPrincipal(): RequestPrincipal | undefined {
  return storage.getStore();
}
