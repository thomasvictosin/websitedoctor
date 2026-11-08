import test from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import { scanPackage } from "../lib/package-scan.ts";
import { parsePageSpeed, measuresFor, scoreBand } from "../lib/pagespeed.ts";
import { checkDomain, reminderDue, reminderStage, renewalStatus } from "../lib/renewals.ts";
import { matchClosedPlugins, parseFeed } from "../lib/vulnerabilities.ts";
import { isAllowedCleanupStep } from "../lib/cleanup-plan.ts";

const DAY = 24 * 60 * 60_000;

function crc32(buffer) {
  let crc = ~0;
  for (const byte of buffer) { crc ^= byte; for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1)); }
  return ~crc >>> 0;
}

/** Build a small ZIP (deflate) from {name: content}. */
function zip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const packed = deflateRawSync(data);
    const nameBytes = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc32(data), 14); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc32(data), 16); central.writeUInt32LE(packed.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(nameBytes.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, packed);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + packed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(Object.keys(files).length, 8); end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

const header = (version) => `<?php\n/**\n * Plugin Name: Slider Revolution\n * Version: ${version}\n */\n`;
const target = { kind: "plugin", target: "revslider/revslider.php", installedVersion: "6.8.1" };

test("a clean package for the installed plugin is ready to install", () => {
  const scan = scanPackage(zip({ "revslider/revslider.php": header("6.8.2"), "revslider/includes/a.php": "<?php echo 1;" }), { ...target, fixedIn: "6.8.2" }, { bySlug: {} });
  assert.equal(scan.status, "ready", scan.blockers.join(" "));
  assert.equal(scan.version, "6.8.2");
  assert.equal(scan.name, "Slider Revolution");
  assert.equal(scan.phpFiles, 2);
});

test("packages with malware, the wrong folder, unsafe paths or a still-vulnerable version are blocked", () => {
  const malware = scanPackage(zip({ "revslider/revslider.php": header("6.8.2"), "revslider/x.php": "<?php eval(base64_decode($_POST['c']));" }), target, { bySlug: {} });
  assert.equal(malware.status, "blocked");
  assert.ok(malware.malware.some((item) => item.file === "revslider/x.php" && item.strong));
  assert.equal(scanPackage(zip({ "other/revslider.php": header("6.8.2") }), target, null).status, "blocked");
  const traversal = scanPackage(zip({ "revslider/revslider.php": header("6.8.2"), "../evil.php": "<?php" }), target, null);
  assert.equal(traversal.status, "blocked");
  assert.match(traversal.blockers[0], /unsafe path/);
  assert.equal(scanPackage(zip({ "revslider/revslider.php": header("6.8.1") }), { ...target, fixedIn: "6.8.2" }, null).status, "blocked");
  const index = parseFeed({ v1: { id: "v1", title: "RCE", software: [{ type: "plugin", slug: "revslider", affected_versions: { a: { from_version: "*", to_version: "6.8.2", to_inclusive: true } }, patched_versions: ["6.8.3"] }] } }, new Set(["plugin:revslider"]));
  const vulnerable = scanPackage(zip({ "revslider/revslider.php": header("6.8.2") }), target, index);
  assert.equal(vulnerable.status, "blocked");
  assert.equal(vulnerable.vulnerabilities.length, 1);
  assert.equal(scanPackage(Buffer.from("not a zip at all"), target, null).status, "blocked");
});

test("install_package and set_performance steps are allowlisted only with safe parameters", () => {
  const params = { packageId: "cmw7abcdefghijklmnopqrstu", kind: "plugin", target: "revslider/revslider.php", expectedVersion: "6.8.1", version: "6.8.2", sha256: "b".repeat(64), size: "1234567", chunks: "1" };
  assert.ok(isAllowedCleanupStep({ operation: "install_package", parameters: params }));
  assert.ok(!isAllowedCleanupStep({ operation: "install_package", parameters: { ...params, target: "ai-website-doctor/ai-website-doctor.php" } }));
  assert.ok(!isAllowedCleanupStep({ operation: "install_package", parameters: { ...params, kind: "theme", target: "../x" } }));
  assert.ok(isAllowedCleanupStep({ operation: "install_package", parameters: { ...params, kind: "theme", target: "bauen" } }));
  assert.ok(isAllowedCleanupStep({ operation: "set_performance", parameters: { measure: "defer_scripts", state: "on" } }));
  assert.ok(!isAllowedCleanupStep({ operation: "set_performance", parameters: { measure: "run_php", state: "on" } }));
});

test("PageSpeed results become scores, Core Web Vitals and explained, attributed fixes", () => {
  const body = {
    id: "https://avantgardian.com/",
    lighthouseResult: {
      finalDisplayedUrl: "https://avantgardian.com/",
      categories: { performance: { score: 0.34 } },
      audits: {
        "largest-contentful-paint": { numericValue: 6200, displayValue: "6.2 s", score: 0.1 },
        "total-blocking-time": { numericValue: 900, displayValue: "900 ms", score: 0.2 },
        "cumulative-layout-shift": { numericValue: 0.02, displayValue: "0.02", score: 1 },
        "server-response-time": { title: "Reduce initial server response time", numericValue: 1800, displayValue: "Root document took 1,800 ms", score: 0, scoreDisplayMode: "metricSavings", details: { overallSavingsMs: 1700, items: [{ url: "https://avantgardian.com/", responseTime: 1800 }] } },
        "unused-javascript": { title: "Reduce unused JavaScript", score: 0.3, scoreDisplayMode: "metricSavings", details: { overallSavingsMs: 900, items: [{ url: "https://avantgardian.com/wp-content/plugins/revslider/public/js/rs6.min.js", wastedBytes: 300000 }, { url: "https://www.googletagmanager.com/gtag/js", wastedBytes: 80000 }] } },
        "uses-text-compression": { title: "Enable text compression", score: 1, scoreDisplayMode: "metricSavings" },
      },
    },
    loadingExperience: { overall_category: "SLOW", metrics: { INTERACTION_TO_NEXT_PAINT: { percentile: 640, category: "SLOW" }, CUMULATIVE_LAYOUT_SHIFT_SCORE: { percentile: 5, category: "FAST" } } },
  };
  const parsed = parsePageSpeed(body, { plugins: [{ file: "revslider/revslider.php", name: "Slider Revolution" }] });
  assert.equal(parsed.score, 34);
  assert.equal(scoreBand(parsed.score), "poor");
  assert.equal(parsed.metrics.lcp.display, "6.2 s");
  assert.equal(parsed.field.metrics.inp.p75, 640);
  assert.equal(parsed.field.metrics.cls.p75, 0.05);
  assert.deepEqual(parsed.opportunities.map((item) => item.id), ["server-response-time", "unused-javascript"]);
  const js = parsed.opportunities.find((item) => item.id === "unused-javascript");
  assert.equal(js.sources[0].name, "Slider Revolution");
  assert.equal(js.sources[0].kind, "plugin");
  assert.equal(js.sources[1].kind, "third-party");
  assert.deepEqual(measuresFor(parsed.opportunities), ["page_cache"]);
});

test("renewal reminders go out 30 days before, 10 days before and on expiry, once each", () => {
  const now = Date.parse("2026-11-08T12:00:00Z");
  assert.equal(reminderStage(new Date(now + 45 * DAY), now), null);
  assert.equal(reminderStage(new Date(now + 29 * DAY), now), "30");
  assert.equal(reminderStage(new Date(now + 9 * DAY), now), "10");
  assert.equal(reminderStage(new Date(now - DAY), now), "expired");
  const expiry = new Date(now + 9 * DAY);
  assert.equal(reminderDue({ remindedStage: null, remindedFor: null }, expiry, now), "10");
  assert.equal(reminderDue({ remindedStage: "10", remindedFor: expiry }, expiry, now), null);
  assert.equal(reminderDue({ remindedStage: "30", remindedFor: expiry }, expiry, now), "10");
  // Renewed: a new date far away needs no reminder; a new date that is close starts again.
  assert.equal(reminderDue({ remindedStage: "expired", remindedFor: new Date(now - DAY) }, new Date(now + 365 * DAY), now), null);
  assert.equal(renewalStatus(new Date(now + 20 * DAY), now).status, "expiring");
  assert.equal(renewalStatus(new Date(now - 1000), now).status, "expired");
  assert.equal(renewalStatus(null).status, "unknown");
});

test("domain expiry comes from the registry's RDAP record", async () => {
  const fetcher = async (url) => {
    if (String(url).includes("iana.org")) return new Response(JSON.stringify({ services: [[["com"], ["https://rdap.example.test/com/v1/"]]] }));
    if (String(url).endsWith("/domain/avantgardian.com")) return new Response(JSON.stringify({ events: [{ eventAction: "expiration", eventDate: "2026-12-29T11:06:30Z" }], entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "HOSTINGER operations, UAB"]]] }] }));
    return new Response("{}", { status: 404 });
  };
  const result = await checkDomain("www.avantgardian.com", fetcher);
  assert.equal(result.domain, "avantgardian.com");
  assert.equal(result.expiresAt.toISOString(), "2026-12-29T11:06:30.000Z");
  assert.equal(result.registrar, "HOSTINGER operations, UAB");
});

test("plugins closed on WordPress.org are reported without any API key", () => {
  const index = { checked: { "wp-file-manager": { checkedAt: "2026-11-08", closed: { slug: "wp-file-manager", name: "File Manager", closedDate: "2026-10-01", reason: "security-issue", reasonText: "Security Issue", checkedAt: "2026-11-08" } }, elementor: { checkedAt: "2026-11-08", closed: null } } };
  const findings = matchClosedPlugins(index, { plugins: [{ file: "wp-file-manager/file_folder_manager.php", name: "WP File Manager", version: "7.2" }, { file: "elementor/elementor.php", name: "Elementor", version: "4.3.6" }] });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].fingerprint, "vuln:plugin-wp-file-manager:wporg-closed");
  assert.equal(findings[0].severity, "high");
});
