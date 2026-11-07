import { createHmac } from "node:crypto";

export function signAgentRequest(input: {
  token: string;
  method: string;
  target: string;
  timestamp: string;
  nonce: string;
  bodyHash: string;
}): string {
  const canonical = [
    input.method.toUpperCase(),
    input.target,
    input.timestamp,
    input.nonce,
    input.bodyHash,
  ].join("\n");
  return createHmac("sha256", input.token).update(canonical).digest("hex");
}
