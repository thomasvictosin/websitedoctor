import { lookup } from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import { isIP } from "node:net";
import http, { type RequestOptions } from "node:http";
import https from "node:https";
import ipaddr from "ipaddr.js";

type ResolvedAddress = LookupAddress;

export type CheckResult = {
  available: boolean;
  statusCode: number | null;
  responseTime: number | null;
  error: string | null;
  finalUrl: string | null;
};

export function isPublicAddress(address: string): boolean {
  try {
    return ipaddr.process(address).range() === "unicast";
  } catch {
    return false;
  }
}

export function assertSafeTarget(target: URL): void {
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS websites can be monitored.");
  }
  if (target.username || target.password) {
    throw new Error("Website URLs must not contain credentials.");
  }
  const hostname = target.hostname.toLowerCase().replace(/\.$/, "");
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".home.arpa")
  ) {
    throw new Error("Local network addresses cannot be monitored.");
  }
}

export async function resolvePublicAddresses(hostname: string): Promise<ResolvedAddress[]> {
  const normalizedHostname = hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(normalizedHostname)
    ? [{ address: normalizedHostname, family: isIP(normalizedHostname) as 4 | 6 }]
    : await lookup(normalizedHostname, { all: true, verbatim: true });

  if (
    addresses.length === 0 ||
    addresses.some(({ address }) => !isPublicAddress(address))
  ) {
    throw new Error("Website must resolve only to public IP addresses.");
  }
  return addresses;
}

export function pinnedLookup(addresses: ResolvedAddress[]): NonNullable<RequestOptions["lookup"]> {
  return ((_hostname, options, callback) => {
    if (typeof options === "object" && options.all) {
      callback(null, addresses);
    } else {
      const address = addresses[0];
      callback(null, address.address, address.family);
    }
  }) as NonNullable<RequestOptions["lookup"]>;
}

async function requestHead(target: URL): Promise<{ statusCode: number; location: string | null }> {
  assertSafeTarget(target);
  const addresses = await resolvePublicAddresses(target.hostname);
  const transport = target.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const request = transport.request(
      target,
      {
        method: "HEAD",
        headers: { "user-agent": "AI-Website-Doctor/0.1 (availability check)" },
        timeout: 10_000,
        lookup: pinnedLookup(addresses),
      },
      (response) => {
        const statusCode = response.statusCode ?? 0;
        const location = response.headers.location ?? null;
        response.destroy();
        resolve({ statusCode, location });
      },
    );

    request.on("timeout", () => request.destroy(new Error("Request timed out.")));
    request.on("error", reject);
    request.end();
  });
}

export async function checkWebsite(rawUrl: string): Promise<CheckResult> {
  const startedAt = Date.now();
  try {
    let target = new URL(rawUrl);
    assertSafeTarget(target);
    for (let redirects = 0; redirects <= 5; redirects += 1) {
      const response = await requestHead(target);
      if (response.statusCode >= 300 && response.statusCode < 400 && response.location) {
        if (redirects === 5) throw new Error("Too many redirects.");
        target = new URL(response.location, target);
        assertSafeTarget(target);
        continue;
      }

      return {
        available: response.statusCode >= 200 && response.statusCode < 500,
        statusCode: response.statusCode,
        responseTime: Date.now() - startedAt,
        error: response.statusCode >= 500 ? `Server returned HTTP ${response.statusCode}.` : null,
        finalUrl: target.toString(),
      };
    }
    throw new Error("Too many redirects.");
  } catch (error) {
    return {
      available: false,
      statusCode: null,
      responseTime: Date.now() - startedAt,
      error: error instanceof Error ? error.message : "Website check failed.",
      finalUrl: null,
    };
  }
}
