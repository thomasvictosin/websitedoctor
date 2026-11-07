import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import { db } from "./db.ts";

const DRIVE_API = "https://www.googleapis.com/drive/v3";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo";
const DRIVE_SCOPE = "openid email https://www.googleapis.com/auth/drive.file";
const BACKUP_MAGIC = Buffer.from("AWDGBK01");
const MAX_SNAPSHOT_BYTES = 512_000;

function googleOAuthConfiguration() {
  const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;
  const appOrigin = process.env.APP_ORIGIN;
  if (!clientId || !clientSecret || !appOrigin) {
    throw new Error("Google Drive is not configured. Set GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET, and APP_ORIGIN.");
  }
  const origin = new URL(appOrigin);
  if (origin.protocol !== "https:" && process.env.NODE_ENV === "production") {
    throw new Error("Google Drive OAuth requires an HTTPS APP_ORIGIN in production.");
  }
  return {
    clientId,
    clientSecret,
    redirectUri: new URL("/api/integrations/google-drive/callback", origin).toString(),
  };
}

function encryptionKey(purpose: string): Buffer {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
    throw new Error("SESSION_SECRET must be set to at least 32 bytes before Google Drive credentials or backups can be stored.");
  }
  return createHmac("sha256", sessionSecret).update(`ai-website-doctor:${purpose}:v1`).digest();
}

export function encryptGoogleDriveValue(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey("drive-oauth-token"), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${encrypted.toString("base64url")}`;
}

export function decryptGoogleDriveValue(payload: string): string {
  const [encodedIv, encodedTag, encodedData, extra] = payload.split(".");
  if (!encodedIv || !encodedTag || !encodedData || extra !== undefined) {
    throw new Error("Stored Google Drive credential is malformed.");
  }
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey("drive-oauth-token"), Buffer.from(encodedIv, "base64url"));
  decipher.setAuthTag(Buffer.from(encodedTag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encodedData, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export function encryptGoogleDriveBackup(snapshot: unknown): { data: Buffer; sha256: string } {
  const json = Buffer.from(JSON.stringify(snapshot), "utf8");
  if (json.length > MAX_SNAPSHOT_BYTES) throw new Error("The repair snapshot exceeds the 512 KB backup limit.");
  const compressed = gzipSync(json, { level: 9 });
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey("drive-backup-content"), iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const data = Buffer.concat([BACKUP_MAGIC, iv, cipher.getAuthTag(), ciphertext]);
  return { data, sha256: createHash("sha256").update(data).digest("hex") };
}

export function decryptGoogleDriveBackup(data: Buffer, expectedSha256: string): unknown {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)
    || createHash("sha256").update(data).digest("hex") !== expectedSha256) {
    throw new Error("The stored Google Drive backup failed its integrity check.");
  }
  if (data.length < BACKUP_MAGIC.length + 28 || !data.subarray(0, BACKUP_MAGIC.length).equals(BACKUP_MAGIC)) {
    throw new Error("The stored Google Drive backup has an unsupported format.");
  }
  const ivStart = BACKUP_MAGIC.length;
  const tagStart = ivStart + 12;
  const contentStart = tagStart + 16;
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey("drive-backup-content"), data.subarray(ivStart, tagStart));
  decipher.setAuthTag(data.subarray(tagStart, contentStart));
  const compressed = Buffer.concat([decipher.update(data.subarray(contentStart)), decipher.final()]);
  const json = gunzipSync(compressed, { maxOutputLength: MAX_SNAPSHOT_BYTES });
  return JSON.parse(json.toString("utf8")) as unknown;
}

export function createGoogleDriveAuthorizationUrl(state: string): string {
  const { clientId, redirectUri } = googleOAuthConfiguration();
  const url = new URL(GOOGLE_AUTH_ENDPOINT);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", DRIVE_SCOPE);
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("include_granted_scopes", "true");
  url.searchParams.set("state", state);
  return url.toString();
}

async function postForm(url: string, values: Record<string, string>): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(values),
    signal: AbortSignal.timeout(20_000),
    redirect: "error",
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok || !body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error(`Google OAuth request failed with HTTP ${response.status}.`);
  }
  return body as Record<string, unknown>;
}

export async function exchangeGoogleDriveAuthorizationCode(code: string): Promise<{
  refreshToken: string;
  accountEmail: string;
}> {
  const { clientId, clientSecret, redirectUri } = googleOAuthConfiguration();
  const tokens = await postForm(GOOGLE_TOKEN_ENDPOINT, {
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });
  if (typeof tokens.refresh_token !== "string" || typeof tokens.access_token !== "string") {
    throw new Error("Google did not return an offline refresh token. Reconnect and approve Drive access.");
  }
  const profileResponse = await fetch(GOOGLE_USERINFO_ENDPOINT, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
    signal: AbortSignal.timeout(15_000),
    redirect: "error",
  });
  const profile: unknown = await profileResponse.json().catch(() => null);
  if (!profileResponse.ok || !profile || typeof profile !== "object" || Array.isArray(profile)
    || typeof (profile as Record<string, unknown>).email !== "string") {
    throw new Error("Google did not return the connected account email.");
  }
  return { refreshToken: tokens.refresh_token, accountEmail: (profile as Record<string, string>).email };
}

async function getAccessToken(encryptedRefreshToken: string): Promise<string> {
  const { clientId, clientSecret } = googleOAuthConfiguration();
  const tokens = await postForm(GOOGLE_TOKEN_ENDPOINT, {
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: decryptGoogleDriveValue(encryptedRefreshToken),
    grant_type: "refresh_token",
  });
  if (typeof tokens.access_token !== "string") throw new Error("Google Drive did not return an access token.");
  return tokens.access_token;
}

async function driveRequest(
  encryptedRefreshToken: string,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const accessToken = await getAccessToken(encryptedRefreshToken);
  const response = await fetch(`${DRIVE_API}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      authorization: `Bearer ${accessToken}`,
    },
    signal: init.signal ?? AbortSignal.timeout(30_000),
    redirect: "error",
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`Google Drive request failed with HTTP ${response.status}.`);
  }
  return response;
}

async function createFolder(
  encryptedRefreshToken: string,
  name: string,
  parentId?: string,
): Promise<string> {
  const response = await driveRequest(encryptedRefreshToken, "/files?fields=id", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name,
      mimeType: "application/vnd.google-apps.folder",
      ...(parentId ? { parents: [parentId] } : {}),
    }),
  });
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || Array.isArray(result) || typeof (result as Record<string, unknown>).id !== "string") {
    throw new Error("Google Drive created a folder without returning its identifier.");
  }
  return (result as Record<string, string>).id;
}

export async function createGoogleDriveRootFolder(encryptedRefreshToken: string): Promise<string> {
  return createFolder(encryptedRefreshToken, "AI Website Doctor Backups");
}

async function ensureWebsiteFolder(input: {
  organizationId: string;
  websiteId: string;
  websiteName: string;
  rootFolderId: string;
  encryptedRefreshToken: string;
}): Promise<string> {
  const existing = await db.googleDriveSiteFolder.findFirst({
    where: { organizationId: input.organizationId, websiteId: input.websiteId },
    select: { driveFolderId: true },
  });
  if (existing) return existing.driveFolderId;
  const safeName = input.websiteName.replace(/[\u0000-\u001f/\\]/g, " ").trim().slice(0, 80) || "Website";
  const driveFolderId = await createFolder(
    input.encryptedRefreshToken,
    `${safeName} (${input.websiteId})`,
    input.rootFolderId,
  );
  const folder = await db.googleDriveSiteFolder.upsert({
    where: { websiteId: input.websiteId },
    create: {
      organizationId: input.organizationId,
      websiteId: input.websiteId,
      driveFolderId,
    },
    update: { driveFolderId },
    select: { driveFolderId: true },
  });
  return folder.driveFolderId;
}

function multipartRelated(metadata: Record<string, unknown>, binary: Buffer): { body: Buffer; contentType: string } {
  const boundary = `awd_${randomBytes(18).toString("hex")}`;
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`),
    binary,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return { body, contentType: `multipart/related; boundary=${boundary}` };
}

async function uploadDriveFile(
  encryptedRefreshToken: string,
  folderId: string,
  name: string,
  metadata: Record<string, unknown>,
  binary: Buffer,
): Promise<string> {
  const multipart = multipartRelated({
    name,
    mimeType: "application/octet-stream",
    parents: [folderId],
    appProperties: metadata,
  }, binary);
  const body = new ArrayBuffer(multipart.body.byteLength);
  new Uint8Array(body).set(multipart.body);
  const response = await driveRequest(encryptedRefreshToken, "/files?uploadType=multipart&fields=id", {
    method: "POST",
    headers: { "content-type": multipart.contentType },
    body,
  });
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || Array.isArray(result) || typeof (result as Record<string, unknown>).id !== "string") {
    throw new Error("Google Drive uploaded the backup without returning its file identifier.");
  }
  return (result as Record<string, string>).id;
}

export async function uploadRepairSnapshotToDrive(input: {
  organizationId: string;
  websiteId: string;
  websiteName: string;
  repairId: string;
  pluginBackupId: string;
  snapshot: unknown;
}): Promise<{ fileId: string; folderId: string; sha256: string }> {
  const connection = await db.googleDriveConnection.findUnique({
    where: { organizationId: input.organizationId },
    select: { rootFolderId: true, encryptedRefreshToken: true },
  });
  if (!connection) throw new Error("Connect Google Drive before syncing repair recovery points.");
  const siteFolderId = await ensureWebsiteFolder({
    ...input,
    rootFolderId: connection.rootFolderId,
    encryptedRefreshToken: connection.encryptedRefreshToken,
  });
  const backupFolderId = await createFolder(
    connection.encryptedRefreshToken,
    `Repair ${input.repairId} - ${input.pluginBackupId}`,
    siteFolderId,
  );
  const encrypted = encryptGoogleDriveBackup(input.snapshot);
  const fileId = await uploadDriveFile(
    connection.encryptedRefreshToken,
    backupFolderId,
    "recovery-point.awd",
    { backupId: input.pluginBackupId, websiteId: input.websiteId, repairId: input.repairId },
    encrypted.data,
  );
  return { fileId, folderId: backupFolderId, sha256: encrypted.sha256 };
}

export async function downloadRepairSnapshotFromDrive(input: {
  organizationId: string;
  backupId: string;
}): Promise<unknown> {
  const backup = await db.backup.findFirst({
    where: { id: input.backupId, website: { organizationId: input.organizationId }, status: "created", storageProvider: "google_drive" },
    select: { storageFileId: true, sha256: true },
  });
  if (!backup?.storageFileId || !backup.sha256) throw new Error("The website's Google Drive recovery point was not found or is incomplete.");
  const connection = await db.googleDriveConnection.findUnique({
    where: { organizationId: input.organizationId },
    select: { encryptedRefreshToken: true },
  });
  if (!connection) throw new Error("Google Drive is not connected for this organization.");
  const response = await driveRequest(
    connection.encryptedRefreshToken,
    `/files/${encodeURIComponent(backup.storageFileId)}?alt=media`,
    { headers: { accept: "application/octet-stream" } },
  );
  const data = Buffer.from(await response.arrayBuffer());
  if (data.length > MAX_SNAPSHOT_BYTES + 1024) throw new Error("The Google Drive recovery point exceeds the allowed size.");
  return decryptGoogleDriveBackup(data, backup.sha256);
}
