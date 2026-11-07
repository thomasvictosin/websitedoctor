import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, scryptSync } from "node:crypto";
import { isSameOrigin, isSecureRequest } from "../lib/origin.ts";
import { validAdminPassword } from "../lib/password.ts";
import { signAgentRequest } from "../lib/agent-signature.ts";
import { checkWebsite, isPublicAddress } from "../lib/monitor.ts";
import { requestSourceKey } from "../lib/request-source.ts";
import { redactApiValue } from "../lib/redaction.ts";
import { websiteInputSchema } from "../lib/validation.ts";
import { isAgentCredentialActive } from "../lib/agent-credential-policy.ts";
import { loginSchema } from "../lib/login-input.ts";

test("login accepts the bootstrap local email and validates normal email addresses", () => {
  assert.equal(loginSchema.safeParse({ email: "admin@localhost", password: "a valid password" }).success, true);
  assert.equal(loginSchema.safeParse({ email: "ADMIN@LOCALHOST", password: "a valid password" }).success, true);
  assert.equal(loginSchema.safeParse({ email: "not-an-email", password: "a valid password" }).success, false);
  assert.equal(loginSchema.safeParse({ password: "a valid password" }).success, true);
});

test("admin authentication uses a scrypt verifier and never compares plaintext configuration", () => {
  const previous = process.env.ADMIN_PASSWORD_HASH;
  const salt = randomBytes(16);
  const password = "correct horse battery staple";
  const derived = scryptSync(password, salt, 64);
  process.env.ADMIN_PASSWORD_HASH = `scrypt$${salt.toString("base64url")}$${derived.toString("base64url")}`;
  assert.equal(validAdminPassword(password), true);
  assert.equal(validAdminPassword("wrong password"), false);
  process.env.ADMIN_PASSWORD_HASH = password;
  assert.equal(validAdminPassword(password), false);
  if (previous === undefined) delete process.env.ADMIN_PASSWORD_HASH;
  else process.env.ADMIN_PASSWORD_HASH = previous;
});

test("state-changing origin validation compares scheme and host", async () => {
  const previous = process.env.APP_ORIGIN;
  delete process.env.APP_ORIGIN;
  assert.equal(await isSameOrigin(new Request("https://doctor.example/api", {
    headers: { host: "doctor.example", origin: "https://doctor.example" },
  })), true);
  assert.equal(await isSameOrigin(new Request("https://doctor.example/api", {
    headers: { host: "doctor.example", origin: "http://doctor.example" },
  })), false);
  if (previous === undefined) delete process.env.APP_ORIGIN;
  else process.env.APP_ORIGIN = previous;
});

test("production requests require HTTPS as seen by the app or trusted proxy", () => {
  const previous = {
    nodeEnv: process.env.NODE_ENV,
    trustProxy: process.env.TRUST_PROXY,
  };
  process.env.NODE_ENV = "production";
  delete process.env.TRUST_PROXY;
  assert.equal(isSecureRequest(new Request("http://doctor.example/api")), false);
  assert.equal(isSecureRequest(new Request("https://doctor.example/api")), true);
  process.env.TRUST_PROXY = "true";
  assert.equal(isSecureRequest(new Request("http://internal/api", {
    headers: { "x-forwarded-proto": "https" },
  })), true);
  if (previous.nodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previous.nodeEnv;
  if (previous.trustProxy === undefined) delete process.env.TRUST_PROXY;
  else process.env.TRUST_PROXY = previous.trustProxy;
});

test("agent request signatures bind method, target, timestamp, nonce, and body digest", () => {
  const bodyHash = createHash("sha256").update('{"ok":true}').digest("hex");
  assert.equal(signAgentRequest({
    token: "per-installation-secret",
    method: "POST",
    target: "/api/agents/agent-1/diagnostics",
    timestamp: "1793640000",
    nonce: "0123456789abcdef0123456789abcdef",
    bodyHash,
  }), "204aeb006ba4dda7c697614ea8839f6b58ed85bf2f39fb714f8e490210d5ff25");
  const request = {
    token: "per-installation-secret",
    method: "post",
    target: "/api/agents/agent-1/diagnostics",
    timestamp: "1793640000",
    nonce: "0123456789abcdef0123456789abcdef",
    bodyHash: "a".repeat(64),
  };
  const signature = signAgentRequest(request);
  assert.match(signature, /^[a-f0-9]{64}$/);
  assert.equal(signAgentRequest(request), signature);
  assert.notEqual(signAgentRequest({ ...request, target: "/api/agents/agent-2/diagnostics" }), signature);
  assert.notEqual(signAgentRequest({ ...request, bodyHash: "b".repeat(64) }), signature);
});

test("revoked and expired WordPress installation credentials are rejected", () => {
  const now = new Date("2026-11-03T10:00:00.000Z");
  assert.equal(isAgentCredentialActive({ agentRevokedAt: null, credentialRevokedAt: null, expiresAt: null }, now), true);
  assert.equal(isAgentCredentialActive({ agentRevokedAt: null, credentialRevokedAt: null, expiresAt: new Date(now.getTime() + 1000) }, now), true);
  assert.equal(isAgentCredentialActive({ agentRevokedAt: null, credentialRevokedAt: null, expiresAt: new Date(now.getTime() - 1) }, now), false);
  assert.equal(isAgentCredentialActive({ agentRevokedAt: null, credentialRevokedAt: now, expiresAt: null }, now), false);
  assert.equal(isAgentCredentialActive({ agentRevokedAt: now, credentialRevokedAt: null, expiresAt: null }, now), false);
});

test("monitoring blocks private, reserved, mapped, and metadata-network IPs", () => {
  for (const address of [
    "127.0.0.1",
    "10.0.0.1",
    "100.100.100.200",
    "169.254.169.254",
    "192.0.2.1",
    "::ffff:127.0.0.1",
    "fc00::1",
    "fe80::1",
  ]) {
    assert.equal(isPublicAddress(address), false, `${address} must be blocked`);
  }
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2001:4860:4860::8888"), true);
});

test("monitor requests refuse local targets before making network connections", async () => {
  for (const url of ["http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/"]) {
    const result = await checkWebsite(url);
    assert.equal(result.available, false);
    assert.match(result.error ?? "", /Local network|public IP/i);
  }
});

test("website registration rejects credentials, queries, and unsupported schemes", () => {
  const valid = { name: "Example", url: "https://example.com/", monitoringEnabled: false, intervalMinutes: 60 };
  assert.equal(websiteInputSchema.safeParse(valid).success, true);
  assert.equal(websiteInputSchema.safeParse({ ...valid, url: "https://user:pass@example.com/" }).success, false);
  assert.equal(websiteInputSchema.safeParse({ ...valid, url: "https://example.com/?token=secret" }).success, false);
  assert.equal(websiteInputSchema.safeParse({ ...valid, url: "file:///etc/passwd" }).success, false);
});

test("API redaction removes credential fields and scrubs leaked values", () => {
  assert.deepEqual(redactApiValue({
    authorizedLogExcerpt: "sensitive",
    nested: {
      accessToken: "secret",
      message: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
    },
  }), {
    nested: { message: "Authorization=[REDACTED] [REDACTED_TOKEN]" },
  });
});

test("rate-limit source keys are opaque and trusted-proxy gated", () => {
  const previous = process.env.TRUST_PROXY;
  process.env.TRUST_PROXY = "true";
  const key = requestSourceKey(new Request("https://doctor.example", {
    headers: { "x-forwarded-for": "203.0.113.8, 10.0.0.2" },
  }));
  assert.match(key, /^[a-f0-9]{64}$/);
  assert.notEqual(key, "203.0.113.8");
  if (previous === undefined) delete process.env.TRUST_PROXY;
  else process.env.TRUST_PROXY = previous;
});
