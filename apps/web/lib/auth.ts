import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { db } from "@/lib/db";
export { authIsConfigured, validAdminPassword } from "./password";
export { isSameOrigin } from "./origin";

const COOKIE_NAME = process.env.NODE_ENV === "production"
  ? "__Host-website-doctor-session"
  : "website-doctor-session";
const SESSION_LIFETIME_SECONDS = 60 * 60 * 12;

function getSecret(): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("SESSION_SECRET must be set to at least 32 bytes.");
  }
  return secret;
}

function sign(payload: string): string {
  return createHmac("sha256", getSecret()).update(payload).digest("base64url");
}

function equal(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export async function getSessionUserId(): Promise<string | null> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get(COOKIE_NAME)?.value;
    if (!token) return null;
    const [userId, expiresAt, nonce, signature, extra] = token.split(".");
    if (!userId || !expiresAt || !nonce || !signature || extra !== undefined) return null;
    const expiry = Number(expiresAt);
    if (!Number.isSafeInteger(expiry) || expiry <= Math.floor(Date.now() / 1000)) return null;
    if (!equal(signature, sign(`${userId}.${expiresAt}.${nonce}`))) return null;
    const user = await db.user.findFirst({ where: { id: userId, disabledAt: null }, select: { id: true } });
    return user?.id ?? null;
  } catch {
    return null;
  }
}

export async function hasValidSession(): Promise<boolean> {
  return (await getSessionUserId()) !== null;
}

export async function createSession(userId: string): Promise<void> {
  const cookieStore = await cookies();
  const expiresAt = String(Math.floor(Date.now() / 1000) + SESSION_LIFETIME_SECONDS);
  const payload = `${userId}.${expiresAt}.${randomBytes(24).toString("base64url")}`;
  cookieStore.set(COOKIE_NAME, `${payload}.${sign(payload)}`, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_LIFETIME_SECONDS,
  });
}

export async function destroySession(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE_NAME);
}
