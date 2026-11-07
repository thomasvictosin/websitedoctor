import test from "node:test";
import assert from "node:assert/strict";
import { currentPrincipal, runAsPrincipal } from "../lib/request-principal.ts";

const principal = { userId: "user-a", via: "mcp_token", tokenId: "token-a" };

test("an MCP principal exists only inside runAsPrincipal", async () => {
  assert.equal(currentPrincipal(), undefined);
  const seen = await runAsPrincipal(principal, async () => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    return currentPrincipal();
  });
  assert.deepEqual(seen, principal);
  assert.equal(currentPrincipal(), undefined);
});

test("concurrent MCP requests never see each other's principal", async () => {
  const other = { userId: "user-b", via: "mcp_token", tokenId: "token-b" };
  const [first, second, outside] = await Promise.all([
    runAsPrincipal(principal, async () => { await new Promise((resolve) => setTimeout(resolve, 10)); return currentPrincipal()?.userId; }),
    runAsPrincipal(other, async () => { await new Promise((resolve) => setTimeout(resolve, 1)); return currentPrincipal()?.userId; }),
    (async () => { await new Promise((resolve) => setTimeout(resolve, 5)); return currentPrincipal(); })(),
  ]);
  assert.equal(first, "user-a");
  assert.equal(second, "user-b");
  assert.equal(outside, undefined);
});
