import test from "node:test";
import assert from "node:assert/strict";
import { executeHostingRepair } from "../lib/hosting-execution.ts";
import {
  discoverHostingCapabilities,
  fingerprintHostingCredential,
  normalizeHostingMethod,
  resolveHostingOperations,
  validateHostingRepairProposal,
  validateHostingOperationTarget,
} from "../lib/hosting.ts";
import { isHostingRepairProposal } from "../lib/hosting-proposal-policy.ts";
import { createHash } from "node:crypto";
import { inspectSftpTarget, inspectSftpTargetPath, matchesSshHostFingerprint, verifySftpDocumentRoot } from "../lib/hosting-sftp.ts";
import { hostingConnectionInputSchema } from "../lib/validation.ts";

const root = "/home/example/public_html";

test("hosting targets must remain inside a configured POSIX website root", () => {
  assert.deepEqual(validateHostingOperationTarget("wp-content/plugins/example.php", root), {
    ok: true,
    normalized: `${root}/wp-content/plugins/example.php`,
  });
  assert.deepEqual(validateHostingOperationTarget(`${root}/index.php`, root), {
    ok: true,
    normalized: `${root}/index.php`,
  });
  for (const target of [
    "../outside.php",
    `${root}/../outside.php`,
    "/home/example/public_html-evil/file.php",
    "wp-content\\plugins\\example.php",
    "wp-content/%2e%2e/outside.php",
    "C:/site/file.php",
    "//server/share/file.php",
    "wp-content/\0file.php",
  ]) {
    assert.equal(validateHostingOperationTarget(target, root).ok, false, target);
  }
  assert.equal(validateHostingOperationTarget("index.php", null).ok, false);
  assert.equal(validateHostingOperationTarget("index.php", "/").ok, false);
  assert.equal(validateHostingOperationTarget("../public_html", "../public_html").ok, false);
});

test("hosting inputs reject malformed or local host targets and unsafe document roots", () => {
  const valid = {
    provider: "generic",
    method: "sftp",
    hostname: "hosting.example.com",
    port: 22,
    username: "site-user",
    authMethod: "key",
    documentRoot: root,
    hostKeyFingerprint: `SHA256:${Buffer.alloc(32, 7).toString("base64").replace(/=+$/, "")}`,
    secret: "test-private-key",
    testConnection: false,
  };
  assert.equal(hostingConnectionInputSchema.safeParse(valid).success, true);
  for (const hostname of [
    "https://hosting.example.com",
    "user@hosting.example.com",
    "localhost",
    "server.local",
    "127.0.0.1",
    "hosting",
  ]) {
    assert.equal(hostingConnectionInputSchema.safeParse({ ...valid, hostname }).success, false, hostname);
  }
  for (const documentRoot of ["relative/path", "/", "/home/site/../other"]) {
    assert.equal(hostingConnectionInputSchema.safeParse({ ...valid, documentRoot }).success, false, documentRoot);
  }
});

test("hosting methods reject unknown values and operations require confirmed capabilities", () => {
  assert.throws(() => normalizeHostingMethod("mystery-provider"), /Unsupported hosting connection method/);
  const capabilities = [
    { capability: "restore_file", supported: true },
    { capability: "file_information", supported: true },
  ];
  assert.deepEqual(
    resolveHostingOperations("sftp", capabilities).map(({ operation }) => operation),
    ["restore_configuration_file"],
  );
  assert.deepEqual(
    resolveHostingOperations("sftp", capabilities.map((item) => ({ ...item, supported: false }))),
    [],
  );
});

test("hosting repair review proposals accept only registered repairs and exact safe targets", () => {
  const accepted = validateHostingRepairProposal("correct_file_permissions", "wp-content/uploads", root);
  assert.equal(accepted.ok, true);
  if (accepted.ok) {
    assert.equal(accepted.operation.kind, "repair");
    assert.equal(accepted.target, `${root}/wp-content/uploads`);
  }

  assert.deepEqual(validateHostingRepairProposal("inspect_directory_structure", root, root), {
    ok: false,
    message: "Choose a registered hosting repair operation.",
  });
  assert.equal(validateHostingRepairProposal("unknown_operation", root, root).ok, false);
  assert.equal(validateHostingRepairProposal("correct_file_permissions", "../outside.php", root).ok, false);
  assert.equal(validateHostingRepairProposal("restore_htaccess", "wp-config.php", root).ok, false);
  const htaccess = validateHostingRepairProposal("restore_htaccess", `${root}/.htaccess`, root);
  assert.equal(htaccess.ok, true);
  assert.equal(validateHostingRepairProposal("restore_htaccess", `${root}/.htaccess`, `${root}/`).ok, true);
  assert.equal(isHostingRepairProposal({ hostingRequest: {} }), true);
  assert.equal(isHostingRepairProposal({ hostingRequest: null }), true);
  assert.equal(isHostingRepairProposal({ executionAvailable: true }), false);
  assert.equal(isHostingRepairProposal(null), false);
});

test("stored credential fingerprints do not reveal credential prefixes", () => {
  const first = fingerprintHostingCredential("private-key-material-a");
  const second = fingerprintHostingCredential("private-key-material-b");
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.notEqual(first, second);
  assert.equal(first.includes("private-key"), false);
});

test("unimplemented adapters and unsupported credential modes never claim operations", async () => {
  const cpanel = await discoverHostingCapabilities({
    method: "cpanel_uapi",
    hostname: "hosting.example.com",
    username: "site-user",
    authMethod: "token",
    secret: "not-a-real-token",
  });
  assert.equal(cpanel.ok, false);
  assert.equal(cpanel.capabilities.every(({ supported }) => !supported), true);

  const sshPassword = await discoverHostingCapabilities({
    method: "ssh",
    hostname: "hosting.example.com",
    username: "site-user",
    authMethod: "password",
    secret: "not-a-real-password",
  });
  assert.equal(sshPassword.ok, false);
  assert.match(sshPassword.message, /No connection was attempted/);
  assert.equal(sshPassword.capabilities.every(({ supported }) => !supported), true);
});

test("SFTP pins the exact SSH host key and refuses a symlinked site root", async () => {
  const expected = `SHA256:${createHash("sha256").update("known host key").digest("base64").replace(/=+$/, "")}`;
  const digest = createHash("sha256").update("known host key").digest("hex");
  assert.equal(matchesSshHostFingerprint(digest, expected), true);
  assert.equal(matchesSshHostFingerprint("0".repeat(64), expected), false);
  assert.equal(matchesSshHostFingerprint(digest, "SHA256:not-a-fingerprint"), false);

  const operations = {
    realpath(path, callback) { callback(undefined, path); },
    lstat(path, callback) {
      callback(undefined, {
        isSymbolicLink: () => path === "/home/example",
        isDirectory: () => true,
      });
    },
  };
  await assert.rejects(verifySftpDocumentRoot(operations, root), /symbolic link/);
});

test("SFTP refuses target traversal through a symbolic-link component", async () => {
  const operations = {
    lstat(path, callback) {
      callback(undefined, {
        isSymbolicLink: () => path.endsWith("/wp-content"),
        isDirectory: () => true,
      });
    },
  };
  await assert.rejects(
    inspectSftpTargetPath(operations, root, "wp-content/plugins/plugin.php"),
    /symbolic link/,
  );
});

test("SFTP read-only inspection returns bounded names and permission metadata", async () => {
  const directoryStats = {
    mode: 0o40755,
    isSymbolicLink: () => false,
    isDirectory: () => true,
    isFile: () => false,
  };
  const fileStats = {
    mode: 0o100640,
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true,
  };
  let directoryRead = false;
  const sftp = {
    lstat(path, callback) {
      callback(undefined, path.endsWith("/wp-content") ? directoryStats : fileStats);
    },
    opendir(_path, callback) {
      callback(undefined, Buffer.from("directory-handle"));
    },
    readdir(_handle, callback) {
      if (directoryRead) {
        callback(Object.assign(new Error("End of file"), { code: "EOF" }), []);
        return;
      }
      directoryRead = true;
      callback(undefined, [
        { filename: ".", attrs: directoryStats },
        { filename: "plugin.php", attrs: fileStats },
      ]);
    },
    close(_handle, callback) {
      callback(undefined);
    },
  };
  assert.deepEqual(await inspectSftpTarget(sftp, root, "wp-content", "inspect_directory_structure"), {
    path: `${root}/wp-content`,
    entries: [{ name: "plugin.php", kind: "file", mode: "0640" }],
    truncated: false,
  });
  assert.deepEqual(await inspectSftpTarget(sftp, root, "wp-content/plugin.php", "inspect_file_permissions"), {
    path: `${root}/wp-content/plugin.php`,
    mode: "0640",
    kind: "file",
  });
});

test("SFTP directory inspection stops after 200 entries and closes the remote handle", async () => {
  const directoryStats = {
    mode: 0o40755,
    isSymbolicLink: () => false,
    isDirectory: () => true,
    isFile: () => false,
  };
  let reads = 0;
  let closes = 0;
  const sftp = {
    lstat(_path, callback) { callback(undefined, directoryStats); },
    opendir(_path, callback) { callback(undefined, Buffer.from("directory-handle")); },
    readdir(_handle, callback) {
      reads += 1;
      callback(undefined, Array.from({ length: 100 }, (_, index) => ({
        filename: `entry-${reads}-${index}`,
        attrs: directoryStats,
      })));
    },
    close(_handle, callback) {
      closes += 1;
      callback(undefined);
    },
  };
  const result = await inspectSftpTarget(sftp, root, root, "inspect_directory_structure");
  assert.equal(result.entries.length, 200);
  assert.equal(result.truncated, true);
  assert.equal(reads, 3);
  assert.equal(closes, 1);
});

test("hosting repairs require approval and a recovery point, then roll back failed verification", async () => {
  const calls = [];
  const adapter = {
    async createRecoveryPoint(input) {
      calls.push(["backup", input]);
      return { contents: "before" };
    },
    async apply(input) {
      calls.push(["apply", input]);
    },
    async verify(input) {
      calls.push(["verify", input]);
      return { verified: false, message: "Expected file state was not observed." };
    },
    async restore(input) {
      calls.push(["restore", input]);
    },
  };
  const result = await executeHostingRepair({
    operation: "restore_configuration_file",
    target: "wp-config.php",
    root,
    approved: false,
    adapter,
  });
  assert.equal(result.status, "blocked");
  assert.equal(calls.length, 0);

  const failedVerification = await executeHostingRepair({
    operation: "restore_configuration_file",
    target: "wp-config.php",
    root,
    approved: true,
    adapter,
  });
  assert.equal(failedVerification.status, "rolled_back");
  assert.deepEqual(calls.map(([name]) => name), ["backup", "apply", "verify", "restore"]);
  assert.equal(calls[3][1].recoveryPoint.contents, "before");
  assert.equal(calls[0][1].target, `${root}/wp-config.php`);
});

test("hosting repairs refuse incomplete recovery points and report rollback failures", async () => {
  const noRecoveryPoint = await executeHostingRepair({
    operation: "restore_configuration_file",
    target: "wp-config.php",
    root,
    approved: true,
    adapter: {
      async createRecoveryPoint() { return null; },
      async apply() { assert.fail("must not apply without a recovery point"); },
      async verify() { return { verified: true }; },
      async restore() { assert.fail("must not restore without a recovery point"); },
    },
  });
  assert.equal(noRecoveryPoint.status, "blocked");

  const rollbackFailure = await executeHostingRepair({
    operation: "restore_configuration_file",
    target: "wp-config.php",
    root,
    approved: true,
    adapter: {
      async createRecoveryPoint() { return { contents: "before" }; },
      async apply() {},
      async verify() { return { verified: false, message: "Verification failed." }; },
      async restore() { throw new Error("Remote restore failed."); },
    },
  });
  assert.equal(rollbackFailure.status, "rollback_failed");
  assert.equal(rollbackFailure.message, "Verification failed.");
  assert.equal(rollbackFailure.rollbackError, "Remote restore failed.");
});

test("hosting repair registry lookup rejects prototype properties", async () => {
  const result = await executeHostingRepair({
    operation: "toString",
    target: "file.php",
    root,
    approved: true,
    adapter: {
      async createRecoveryPoint() { return { contents: "before" }; },
      async apply() {},
      async verify() { return { verified: true }; },
      async restore() {},
    },
  });
  assert.equal(result.status, "blocked");
});
