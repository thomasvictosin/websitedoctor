import test from "node:test";
import assert from "node:assert/strict";

process.env.DATABASE_URL ??= "postgresql://test:test@127.0.0.1:5432/test";
process.env.SESSION_SECRET = "test-session-secret-with-more-than-thirty-two-bytes";
const { decryptGoogleDriveBackup, decryptGoogleDriveValue, encryptGoogleDriveBackup, encryptGoogleDriveValue } =
  await import("../lib/google-drive.ts");

test("Google Drive refresh tokens are encrypted and authenticated", () => {
  const encrypted = encryptGoogleDriveValue("refresh-token-value");
  assert.notEqual(encrypted, "refresh-token-value");
  assert.equal(decryptGoogleDriveValue(encrypted), "refresh-token-value");

  const originalSecret = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = "different-session-secret-with-more-than-thirty-two-bytes";
  assert.throws(() => decryptGoogleDriveValue(encrypted));
  process.env.SESSION_SECRET = originalSecret;
});

test("Google Drive repair snapshots round-trip encrypted and compressed with integrity validation", () => {
  const snapshot = {
    id: "backup-123",
    complete: true,
    operations: [{ operation: "update_setting", target: "blogname", before: "Old", after: "New" }],
  };
  const encrypted = encryptGoogleDriveBackup(snapshot);
  assert.deepEqual(decryptGoogleDriveBackup(encrypted.data, encrypted.sha256), snapshot);

  const corrupted = Buffer.from(encrypted.data);
  corrupted[corrupted.length - 1] ^= 1;
  assert.throws(() => decryptGoogleDriveBackup(corrupted, encrypted.sha256), /integrity check/);
});
