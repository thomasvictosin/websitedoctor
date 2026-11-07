import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes, scryptSync } from "node:crypto";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import http from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
import { scanBrowserSite } from "../lib/browser-monitor.ts";
import { checkWebsite } from "../lib/monitor.ts";
import { agentDiagnosticSchema } from "../lib/agent-diagnostics.ts";

const root = new URL("../../../", import.meta.url).pathname.replace(/\/$/, "");
const appDir = root + "/apps/web";
const nextBin = [root + "/node_modules/next/dist/bin/next", appDir + "/node_modules/next/dist/bin/next"].find(existsSync);
if (!nextBin) throw new Error("Next.js CLI was not found. Install workspace dependencies before running the WordPress E2E workflow.");
const composeArgs = ["compose", "-f", root + "/docker-compose.e2e.yml"];
const wpUrl = "http://127.0.0.1:8081/";
const registeredWpUrl = "http://verification-does-not-resolve.invalid/";
const registeredWordPressOrigin = new URL(registeredWpUrl).origin;
const wordpressHosts = new Set([new URL(wpUrl).hostname, new URL(registeredWpUrl).hostname]);
const missingWordPressFixturePaths = new Set(["/awd-e2e-missing-image.png", "/awd-e2e-repair-target-b-missing.js"]);
const appUrl = "http://127.0.0.1:3000";
const adminPassword = "e2e-supervisor-password";
const adminHash = ["scrypt", Buffer.from("aiwd-e2e-fixed-salt").toString("base64url"), scryptSync(adminPassword, "aiwd-e2e-fixed-salt", 64).toString("base64url")].join("$");
const testSecret = "e2e-session-secret-with-more-than-32-bytes";
const env = {
  ...process.env,
  DATABASE_URL: "postgresql://doctor:e2e-only-password@127.0.0.1:55432/website_doctor_e2e?schema=public",
  APP_ORIGIN: appUrl,
  TRUST_PROXY: "true",
  ADMIN_PASSWORD_HASH: adminHash,
  SESSION_SECRET: testSecret,
  AI_PROVIDER: "fixture",
  AIWD_ALLOW_FIXTURE_AI: "true",
  AIWD_FIXTURE_AI_FAILURE_TITLE: "Fixture AI unavailable control",
  AIWD_FIXTURE_AI_MALFORMED_TITLE: "Fixture AI malformed control",
};
process.env.DATABASE_URL = env.DATABASE_URL;
const { runAndStoreCheck } = await import("../lib/monitoring-service.ts");
const { authorizeRepairExecution } = await import("../lib/repair-authorization.ts");
const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: env.DATABASE_URL }) });
const childProcesses = [];
let wpSiteUrl = wpUrl;

function rewriteWordPressUrls(value) {
  return value.replace(/(?:https?:)?\/\/([^/:?#]+)(?::\d+)?(?=\/|[?#]|$)/gi, (match, hostname) => (
    wordpressHosts.has(hostname.toLowerCase()) ? registeredWordPressOrigin : match
  ));
}

function rewriteWordPressLocation(value) {
  return rewriteWordPressUrls(value);
}

function spawnCapture(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => code === 0
      ? resolve(stdout.trim())
      : reject(new Error([command, args.join(" "), "failed", String(code), stderr.slice(-5000)].join(" "))));
  });
}

async function compose(...args) {
  return spawnCapture("docker", [...composeArgs, ...args], { cwd: root, env });
}

async function waitFor(url, timeout = 120_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await delay(1000);
  }
  throw new Error("Timed out waiting for " + url);
}

async function wp(...args) {
  return compose("exec", "-T", "wpcli", "wp", ...args);
}

async function jsonWpEval(code, extraEnv = {}) {
  const output = await new Promise((resolve, reject) => {
    const child = spawn("docker", [...composeArgs, "exec", "-T", ...Object.entries(extraEnv).flatMap(([key, value]) => ["-e", key + "=" + value]), "wpcli", "wp", "eval", code], {
      cwd: root,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => status === 0 ? resolve(stdout.trim()) : reject(new Error(["wp eval failed", String(status), stderr.slice(-3000)].join(": "))));
  });
  return JSON.parse(output);
}

async function wpEvalFile(file, extraEnv = {}) {
  const output = await new Promise((resolve, reject) => {
    const args = [...composeArgs, "exec", "-T", ...Object.entries(extraEnv).flatMap(([key, value]) => ["-e", key + "=" + value]), "wpcli", "wp", "eval-file", file];
    const child = spawn("docker", args, { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => status === 0 ? resolve(stdout.trim()) : reject(new Error(["wp eval-file failed", String(status), stderr.slice(-3000)].join(": "))));
  });
  return JSON.parse(output);
}

function appHeaders(cookie, write = false) {
  return {
    ...(cookie ? { cookie } : {}),
    ...(write ? { origin: appUrl } : {}),
    ...(write ? { "content-type": "application/json" } : {}),
  };
}

async function ownerRequest(path, { method = "GET", body, cookie } = {}) {
  const response = await fetch(appUrl + path, {
    method,
    headers: { ...appHeaders(cookie, method !== "GET"), ...(method !== "GET" ? { "x-forwarded-proto": "https" } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { response, body: await response.json().catch(() => null) };
}

async function agentRequest(agentId, token, method, path, body, options = {}) {
  const payload = body === undefined ? "" : JSON.stringify(body);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString("hex");
  const target = new URL(path, appUrl).pathname + new URL(path, appUrl).search;
  const bodyHash = createHash("sha256").update(payload).digest("hex");
  const canonical = [method.toUpperCase(), target, timestamp, nonce, bodyHash].join("\n");
  const signature = createHmac("sha256", token).update(canonical).digest("hex");
  const response = await fetch(appUrl + path, {
    method,
    headers: {
      authorization: "Bearer " + token,
      "x-awd-timestamp": timestamp,
      "x-awd-nonce": nonce,
      "x-awd-signature": signature,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(options.headers ?? {}),
      "x-forwarded-proto": "https",
    },
    ...(body === undefined ? {} : { body: payload }),
  });
  return { response, body: await response.json().catch(() => null) };
}

async function login(url = appUrl) {
  const response = await fetch(url + "/api/auth/login", {
    method: "POST",
    headers: { origin: url, "content-type": "application/json" },
    body: JSON.stringify({ password: adminPassword }),
  });
  assert.equal(response.status, 200, await response.text());
  return response.headers.get("set-cookie")?.split(";")[0] ?? "";
}

async function browserScanThroughLocalWordPress() {
  return scanBrowserSite(wpSiteUrl, {
    resolve: async () => [{ address: "93.184.216.34", family: 4 }],
    request: async (url, method) => {
      if (missingWordPressFixturePaths.has(url.pathname)) {
        return { status: 404, headers: { "content-type": "text/plain" }, body: Buffer.from("Missing E2E fixture resource.") };
      }
      const target = new URL(url.pathname + url.search, wpUrl);
      const response = await new Promise((resolve, reject) => {
        const request = http.request(target, { method, headers: { host: url.host } }, (incoming) => {
          const chunks = [];
          incoming.on("data", (chunk) => chunks.push(chunk));
          incoming.on("end", () => resolve({
            status: incoming.statusCode ?? 502,
            headers: Object.fromEntries(Object.entries(incoming.headers)
              .filter(([, value]) => value !== undefined)
              .map(([key, value]) => [key, Array.isArray(value) ? value.join(", ") : String(value)])),
            body: Buffer.concat(chunks),
          }));
          incoming.on("error", reject);
        });
        request.on("error", reject);
        request.end();
      });
      const headers = response.headers;
      for (const [key, value] of Object.entries(headers)) {
        headers[key] = key.toLowerCase() === "location" ? rewriteWordPressLocation(value) : rewriteWordPressUrls(value);
      }
      let body = response.body;
      const type = headers["content-type"] ?? "";
      if (/text|javascript|json|svg/i.test(type)) {
        body = Buffer.from(rewriteWordPressUrls(body.toString("utf8")));
      }
      return { status: response.status, headers, body };
    },
  });
}

async function startApp() {
  const child = spawn(process.execPath, [nextBin, "dev", "--hostname", "127.0.0.1", "--port", "3000"], {
    cwd: appDir,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  childProcesses.push(child);
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  await waitFor(appUrl + "/");
}

async function run() {
  await compose("up", "-d", "--wait");
  await waitFor(wpUrl);
  await spawnCapture("npm", ["run", "db:push", "--workspace", "apps/web"], { cwd: root, env });
  await startApp();
  await wp("core", "install", "--url=" + wpUrl, "--title=AIWD E2E", "--admin_user=e2e-admin", "--admin_password=e2e-admin-password", "--admin_email=e2e@example.invalid").catch((error) => {
    if (!/already installed/i.test(error.message)) throw error;
  });
  await wp("plugin", "activate", "ai-website-doctor");
  await wp("plugin", "activate", "repair-target-a");
  await wp("plugin", "activate", "repair-target-b");
  await wp("option", "update", "home", registeredWpUrl.replace(/\/$/, ""));
  await wp("option", "update", "siteurl", registeredWpUrl.replace(/\/$/, ""));
  wpSiteUrl = registeredWpUrl;
  const healthyDiagnostics = await jsonWpEval("echo wp_json_encode(awd_collect_diagnostics(array()));");
  await wp("eval", "delete_option('ai_website_doctor_staging_conflict_report');");
  const baselineBrowser = await browserScanThroughLocalWordPress();
  assert.equal(baselineBrowser.status, "issues_found", JSON.stringify(baselineBrowser.errors));
  const fingerprints = new Set(baselineBrowser.findings.map((finding) => finding.fingerprint));
  const observedFindings = [...fingerprints].join(", ") || "none";
  const scanErrors = baselineBrowser.errors.join("; ") || "none";
  const hasFinding = (kind) => [...fingerprints].some((item) => item.startsWith("browser:" + kind + ":"));
  for (const detector of ["horizontal-overflow", "mobile-navigation", "missing-image-alt", "missing-form-label", "accessibility-color-contrast", "javascript-error", "failed-request"]) {
    assert.ok(hasFinding(detector), `disposable WordPress broken fixture did not trigger ${detector}. Observed findings: ${observedFindings}. Scan errors: ${scanErrors}`);
  }

  const pluginPaths = ["repair-target-a/repair-target-a.php", "repair-target-b/repair-target-b.php"];
  const conflictFindings = [];
  for (const plugin of pluginPaths) {
    await wp("plugin", "deactivate", plugin);
    const probe = await browserScanThroughLocalWordPress();
    await wp("plugin", "activate", plugin);
    const removed = baselineBrowser.findings.filter((finding) => !probe.findings.some((item) => item.fingerprint === finding.fingerprint));
    assert.ok(removed.length > 0, `staging isolation did not attribute browser findings to ${plugin}. Baseline: ${baselineBrowser.findings.map(({ fingerprint }) => fingerprint).join(", ")}. Probe: ${probe.findings.map(({ fingerprint }) => fingerprint).join(", ")}`);
    conflictFindings.push({
      components: [plugin],
      result: "conflict",
      evidence: "Disposable WordPress staging browser scan removed " + removed.length + " findings when this plugin was deactivated.",
      baselineFindings: baselineBrowser.findings.map(({ fingerprint, severity }) => ({ fingerprint, severity })),
      probeFindings: probe.findings.map(({ fingerprint, severity }) => ({ fingerprint, severity })),
    });
  }
  for (const plugin of pluginPaths) await wp("plugin", "deactivate", plugin);
  const healthyBrowser = await browserScanThroughLocalWordPress();
  for (const plugin of pluginPaths) await wp("plugin", "activate", plugin);
  const attributedFingerprints = new Set(conflictFindings.flatMap(({ baselineFindings, probeFindings }) => (
    baselineFindings.filter(({ fingerprint }) => !probeFindings.some((item) => item.fingerprint === fingerprint)).map(({ fingerprint }) => fingerprint)
  )));
  const retainedFixtureFindings = healthyBrowser.findings.filter(({ fingerprint }) => attributedFingerprints.has(fingerprint));
  assert.equal(retainedFixtureFindings.length, 0, "healthy WordPress control retained broken fixture findings: " + retainedFixtureFindings.map(({ fingerprint }) => fingerprint).join(", "));

  const pairingIssues = conflictFindings.map((finding, index) => {
    const hash = createHash("sha256").update(finding.components.join("|")).digest("hex").slice(0, 32);
    return {
      fingerprint: "staging-conflict:" + hash,
      title: "Staging browser conflict control " + (index + 1),
      description: finding.evidence,
      severity: "medium",
    };
  });
  const issueUnavailable = { fingerprint: "test-ai-unavailable", title: env.AIWD_FIXTURE_AI_FAILURE_TITLE, description: "AI failure test finding.", severity: "medium" };
  const issueMalformed = { fingerprint: "test-ai-malformed", title: env.AIWD_FIXTURE_AI_MALFORMED_TITLE, description: "Malformed AI test finding.", severity: "medium" };
  const diagnostics = {
    ...healthyDiagnostics,
    collectedAt: new Date().toISOString(),
    conflictTesting: {
      status: "completed", environment: "disposable_staging", stagingRequired: true,
      liveDeactivationPerformed: false, testedAt: new Date().toISOString(),
      activePlugins: pluginPaths, activeTheme: healthyDiagnostics.site.activeTheme.stylesheet,
      findings: conflictFindings,
    },
    issues: [...pairingIssues, issueUnavailable, issueMalformed],
  };
  const parsedDiagnostics = agentDiagnosticSchema.safeParse(diagnostics);
  if (!parsedDiagnostics.success) throw new Error("E2E diagnostics are invalid: " + JSON.stringify(parsedDiagnostics.error.issues));

  const cookie = await login();
  const websiteResult = await ownerRequest("/api/sites", {
    method: "POST", cookie,
    body: { name: "Disposable WordPress", url: registeredWpUrl.replace(/\/$/, ""), monitoringEnabled: false, intervalMinutes: 60 },
  });
  assert.equal(websiteResult.response.status, 201, JSON.stringify(websiteResult.body));
  const website = websiteResult.body;
  const browserFindingRecords = baselineBrowser.findings.map((finding) => ({
    ...finding,
    evidence: { browser: { scannedUrl: registeredWpUrl, checkedAt: baselineBrowser.checkedAt, viewports: baselineBrowser.viewports, metrics: baselineBrowser.metrics, finding: finding.evidence }, collectedAt: baselineBrowser.checkedAt },
  }));
  const browserScanResult = await runAndStoreCheck(website, "e2e", {
    checkWebsite: async () => ({ available: true, statusCode: 200, responseTime: 12, error: null }),
    scanBrowserSite: async () => baselineBrowser,
  });
  assert.equal(browserScanResult.browser.findings.length, browserFindingRecords.length);
  const storedBrowserEvidence = await prisma.evidenceRecord.findMany({ where: { diagnosticResult: { scanSession: { websiteId: website.id } }, source: "browser_monitor" } });
  assert.ok(storedBrowserEvidence.length >= browserFindingRecords.length, "browser detector evidence must be persisted with the scan");
  const storedBrowserIssues = await prisma.issue.findMany({ where: { websiteId: website.id, source: "browser_monitor" } });
  assert.ok(browserFindingRecords.every((finding) => storedBrowserIssues.some((issue) => issue.fingerprint === finding.fingerprint)), "browser findings must become central issues");
  const expiredPairing = await ownerRequest("/api/agents/pairings", { method: "POST", cookie, body: { websiteId: website.id } });
  assert.equal(expiredPairing.response.status, 200);
  await prisma.agentPairing.updateMany({ where: { websiteId: website.id, consumedAt: null }, data: { expiresAt: new Date(Date.now() - 1000) } });
  const expiredRegistration = await fetch(appUrl + "/api/agents/register", {
    method: "POST", headers: { "content-type": "application/json", "x-forwarded-proto": "https" },
    body: JSON.stringify({ code: expiredPairing.body.code, siteUrl: registeredWpUrl, siteName: "Expired", wpVersion: "6.8", phpVersion: "8.2", pluginVersion: "0.1.0" }),
  });
  assert.equal(expiredRegistration.status, 401, "expired pairing credentials must be rejected");
  await prisma.agentPairing.updateMany({ where: { websiteId: website.id, consumedAt: null }, data: { expiresAt: new Date(Date.now() + 10 * 60_000) } });
  const pairing = await ownerRequest("/api/agents/pairings", { method: "POST", cookie, body: { websiteId: website.id } });
  assert.equal(pairing.response.status, 200);
  const registration = await fetch(appUrl + "/api/agents/register", {
    method: "POST", headers: { "content-type": "application/json", "x-forwarded-proto": "https" },
    body: JSON.stringify({ code: pairing.body.code, siteUrl: registeredWpUrl, siteName: "Disposable WordPress", wpVersion: diagnostics.site.wpVersion, phpVersion: diagnostics.site.phpVersion, pluginVersion: "0.1.0" }),
  });
  assert.equal(registration.status, 201);
  const { agentId, token } = await registration.json();

  const unauthenticated = await fetch(appUrl + "/api/agents/" + agentId + "/dashboard", { headers: { "x-forwarded-proto": "https" } });
  assert.equal(unauthenticated.status, 401, "unsigned agent requests must be rejected");
  const malformed = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/diagnostics", { collectedAt: "not-a-date" });
  assert.equal(malformed.response.status, 400, "malformed diagnostic data must be rejected");
  const stored = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/diagnostics", diagnostics);
  assert.equal(stored.response.status, 200, JSON.stringify(stored.body));
  assert.equal(stored.body.issueCount, 4);

  const issues = await prisma.issue.findMany({ where: { websiteId: website.id }, orderBy: { firstSeenAt: "asc" } });
  const conflictIssueA = issues.find((issue) => issue.fingerprint === "wp:" + pairingIssues[0].fingerprint);
  const conflictIssueB = issues.find((issue) => issue.fingerprint === "wp:" + pairingIssues[1].fingerprint);
  assert.ok(conflictIssueA && conflictIssueB, "detector reports must become persisted central issues");
  const diagnosis = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/analysis", { issueId: conflictIssueA.id });
  assert.equal(diagnosis.response.status, 200);
  assert.equal(diagnosis.body.aiStatus, "completed");
  assert.ok(diagnosis.body.diagnosis.facts[0].evidenceRefs.length > 0);
  const diagnosisRecord = await prisma.issue.findUnique({ where: { id: conflictIssueA.id } });
  assert.ok(diagnosisRecord.diagnosis.diagnosis.facts[0].evidenceRefs.length > 0);

  const aiUnavailable = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/analysis", { issueId: issues.find((issue) => issue.fingerprint === "wp:test-ai-unavailable").id });
  assert.equal(aiUnavailable.body.aiStatus, "unavailable");
  const aiMalformed = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/analysis", { issueId: issues.find((issue) => issue.fingerprint === "wp:test-ai-malformed").id });
  assert.equal(aiMalformed.body.aiStatus, "unavailable");

  const localRepair = await ownerRequest("/api/issues/" + conflictIssueA.id + "/repairs", { method: "POST", cookie });
  assert.equal(localRepair.response.status, 201, JSON.stringify(localRepair.body));
  assert.deepEqual(localRepair.body.proposal.instructions.steps[0], {
    description: "Disable repair-target-a/repair-target-a.php, which was isolated as a contributor in disposable staging.",
    operation: "disable_plugin",
    parameters: { plugin: "repair-target-a/repair-target-a.php" },
  });
  const browserIssuePlan = await ownerRequest("/api/issues/" + issues.find((issue) => issue.fingerprint === "wp:test-ai-unavailable").id + "/repairs", { method: "POST", cookie });
  assert.equal(browserIssuePlan.body.proposal.executionAvailable, false, "an unsupported diagnostic must not imply an executable automatic repair");

  const customApproval = await ownerRequest("/api/repairs/" + localRepair.body.id, { method: "PATCH", cookie, body: { decision: "approve_and_apply" } });
  assert.equal(customApproval.response.status, 200, JSON.stringify(customApproval.body));

  const privateTarget = await scanBrowserSite("http://127.0.0.1:8081/", {
    resolve: async () => [{ address: "127.0.0.1", family: 4 }],
    launch: async () => { throw new Error("Private targets must be blocked before browser launch."); },
  });
  assert.equal(privateTarget.status, "unavailable", "malicious/private scan targets must remain blocked");

  await executeAndRollback(agentId, token, localRepair.body.id, "repair-target-a/repair-target-a.php");

  const wpRepair = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/repairs", { issueId: conflictIssueB.id });
  assert.equal(wpRepair.response.status, 201, JSON.stringify(wpRepair.body));
  const wpApproval = await agentRequest(agentId, token, "PATCH", "/api/agents/" + agentId + "/repairs/" + wpRepair.body.id, { decision: "approve" });
  assert.equal(wpApproval.response.status, 200, JSON.stringify(wpApproval.body));
  await executeAndRollback(agentId, token, wpRepair.body.id, "repair-target-b/repair-target-b.php");

  const foreignUser = await prisma.user.create({ data: { id: "e2e-foreign-owner", email: "foreign@example.invalid", name: "Foreign owner" } });
  const foreignOrganization = await prisma.organization.create({ data: { id: "e2e-foreign-organization", name: "Foreign tenant" } });
  await prisma.organizationMember.create({ data: { organizationId: foreignOrganization.id, userId: foreignUser.id, role: "owner" } });
  const foreignWebsite = await prisma.website.create({ data: { ownerId: "local-admin", organizationId: foreignOrganization.id, name: "Foreign", url: "https://example.org" } });
  const foreignIssue = await prisma.issue.create({ data: { websiteId: foreignWebsite.id, fingerprint: "tenant-secret", title: "Foreign issue", description: "Tenant isolation fixture", source: "browser_test" } });
  const crossTenant = await ownerRequest("/api/issues/" + foreignIssue.id + "/repairs", { method: "POST", cookie });
  assert.equal(crossTenant.response.status, 404, "cross-tenant issue records must remain inaccessible");

  await prisma.installationCredential.updateMany({ where: { agentId }, data: { expiresAt: new Date(Date.now() - 1000) } });
  const expiredCredential = await agentRequest(agentId, token, "GET", "/api/agents/" + agentId + "/dashboard");
  assert.equal(expiredCredential.response.status, 401, "expired installation credentials must be rejected");

  await jsonWpEval("$settings = awd_settings(); $settings['central_url'] = 'http://127.0.0.1:3999'; $settings['agent_id'] = 'e2e-agent'; $settings['agent_token'] = '" + token + "'; update_option(AWD_OPTION, $settings, false); awd_send_diagnostics(); echo wp_json_encode(array('queued' => is_array(get_option('ai_website_doctor_diagnostic_queue'))));");
  const queued = await jsonWpEval("echo wp_json_encode(array('queued' => is_array(get_option('ai_website_doctor_diagnostic_queue'))));");
  assert.equal(queued.queued, true, "disconnected WordPress diagnostics must remain queued locally");
  process.stdout.write("Disposable WordPress end-to-end workflow passed (both approval interfaces, browser evidence, central diagnosis, execution, failed verification, automatic rollback, and security cases).\n");
}

async function executeAndRollback(agentId, token, repairId, pluginPath) {
  const tasks = await agentRequest(agentId, token, "GET", "/api/agents/" + agentId + "/tasks");
  assert.equal(tasks.response.status, 200);
  const task = tasks.body.tasks.find((item) => item.repairId === repairId);
  if (!task) {
    const repair = await prisma.repairProposal.findUnique({
      where: { id: repairId },
      include: { issue: { select: { fingerprint: true } }, approvals: { select: { decision: true, authorizationMethod: true, expiresAt: true, consumedAt: true, executionResult: true } }, website: { include: { wordpressAgent: { select: { diagnostics: true, lastSeenAt: true } } } } },
    });
    const authorization = repair ? await authorizeRepairExecution({ repairId, websiteId: repair.websiteId, mode: "executor" }) : null;
    const diagnostics = repair?.website.wordpressAgent?.diagnostics;
    const baselineFingerprints = diagnostics && typeof diagnostics === "object" && Array.isArray(diagnostics.issues)
      ? diagnostics.issues.map((issue) => issue && typeof issue === "object" ? issue.fingerprint : null)
      : null;
    assert.ok(task, `approved task must be delivered to the connected WordPress executor; state: ${JSON.stringify({
      response: tasks.body,
      authorization,
      proposal: repair && {
        status: repair.status,
        operationIds: repair.operationIds,
        instructions: (repair.proposal && typeof repair.proposal === "object" ? repair.proposal.instructions : null),
        issueFingerprint: repair.issue?.fingerprint,
        approvals: repair.approvals,
        baselineFingerprints,
        agentLastSeenAt: repair.website.wordpressAgent?.lastSeenAt,
      },
    })}`);
  }
  assert.deepEqual(task.steps[0].parameters, { plugin: pluginPath });
  const execution = await wpEvalFile("/opt/aiwd/e2e-wordpress-execute.php", { AIWD_E2E_EXECUTION: JSON.stringify({ steps: task.steps }) });
  assert.equal(execution.executionStatus, "completed", execution.message);
  const report = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/executions", {
    repairId,
    authorizationGrantId: task.authorizationGrantId,
    status: "completed",
    result: {
      message: execution.message,
      startedAt: new Date().toISOString(),
      backupId: execution.backupId,
      backupStatus: "created",
      executionStatus: "completed",
      verificationStatus: "inconclusive",
      verificationReason: "The central app must run its browser verification step.",
      verified: false,
      rollbackApplied: false,
      afterEvidence: execution.diagnostics,
    },
  });
  assert.equal(report.response.status, 200, JSON.stringify(report.body));
  assert.equal(report.body.status, "rollback_required", "an inconclusive browser retest must not mark a repair complete");
  const restored = await wpEvalFile("/opt/aiwd/e2e-wordpress-rollback.php", { AIWD_E2E_BACKUP_ID: execution.backupId });
  assert.equal(restored.executionStatus, "completed", restored.message);
  const rollbackReport = await agentRequest(agentId, token, "POST", "/api/agents/" + agentId + "/executions", {
    repairId,
    authorizationGrantId: task.authorizationGrantId,
    status: "rolled_back",
    result: {
      message: restored.message,
      startedAt: new Date().toISOString(),
      backupId: execution.backupId,
      backupStatus: "created",
      executionStatus: "completed",
      verificationStatus: "passed",
      verificationReason: "The disposable WordPress recovery point was restored.",
      verified: true,
      rollbackApplied: true,
      afterEvidence: restored.diagnostics,
    },
  });
  assert.equal(rollbackReport.response.status, 200, JSON.stringify(rollbackReport.body));
  assert.equal(rollbackReport.body.status, "rolled_back");
}

try {
  await run();
} catch (error) {
  process.stderr.write(`WordPress E2E workflow failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
} finally {
  for (const child of childProcesses) child.kill("SIGTERM");
  await prisma.$disconnect();
  await new Promise((resolve) => setTimeout(resolve, 1000));
  await spawnCapture("docker", [...composeArgs, "down", "-v", "--remove-orphans"], { cwd: root, env }).catch(() => undefined);
}
