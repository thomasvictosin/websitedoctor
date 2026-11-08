import { compareVersions } from "./cleanup-plan.ts";
import { matchVulnerabilities, type VulnerabilityIndex } from "./vulnerabilities.ts";
import { listZip, readZipEntry, ZipError } from "./zip.ts";

/**
 * Scan an uploaded plugin/theme zip before it may be installed:
 * - structure: one top-level folder named like the installed plugin/theme,
 *   with the same main file (plugin) or style.css (theme) and a version;
 * - malware: the same code signatures the WordPress plugin's integrity scan
 *   uses (one strong match blocks; two weak ones are a warning, because
 *   commercial code is sometimes obfuscated for licensing);
 * - known vulnerabilities: the uploaded version must not be affected;
 * - signs of a "nulled" (cracked) copy and other risky contents.
 */

const STRONG: Record<string, RegExp> = {
  eval_encoded_payload: /\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\(/i,
  request_code_execution: /\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open|create_function)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b/i,
  request_value_called_as_function: /\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,80}\]\s*\(/i,
  request_file_write: /\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\([^;]{0,300}\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b/i,
  preg_replace_eval_modifier: /preg_replace\s*\(\s*(['"])[^'"]{1,200}\/[a-z]*e[a-z]*\1\s*,/i,
  remote_code_include: /\b(?:include|require)(?:_once)?\s*\(?\s*['"](?:https?|ftp|php|data):/i,
};
const WEAK: Record<string, RegExp> = {
  crawler_cloaking: /HTTP_USER_AGENT[\s\S]{0,600}(?:googlebot|bingbot|baiduspider|yandex|slurp)|(?:googlebot|bingbot|baiduspider|yandex)[\s\S]{0,600}HTTP_USER_AGENT/i,
  search_referrer_check: /HTTP_REFERER[\s\S]{0,300}(?:google\.|bing\.|yahoo\.)/i,
  long_encoded_blob: /['"][A-Za-z0-9+/=]{4000,}['"]/,
  hex_escaped_code: /(?:\\x[0-9a-f]{2}){40,}/i,
  variable_function_obfuscation: /\$\w+\s*=\s*['"](?:ba|bas|base)['"]\s*\.\s*['"]/i,
};
const NULLED = /\b(?:nulled\s+by|wplocker|babiato|gpldl|null24|codelist\.cc|wpnull|gplvault)\b/i;
const EXECUTABLE = /\.(?:php\d?|phtml|pht|phar|inc)$/i;
const RISKY_BINARY = /\.(?:exe|dll|so|sh|bat|cmd|phar)$/i;
const HEADER_BYTES = 8192;

export type PackageScan = {
  status: "ready" | "blocked";
  kind: "plugin" | "theme";
  slug: string | null;
  name: string | null;
  version: string | null;
  files: number;
  phpFiles: number;
  unpackedBytes: number;
  blockers: string[];
  warnings: string[];
  malware: Array<{ file: string; signatures: string[]; strong: boolean }>;
  vulnerabilities: Array<{ title: string; fixedIn: string | null }>;
  scannedAt: string;
};

function header(content: string, field: string) {
  const match = new RegExp(`^[ \\t/*#@]*${field}\\s*:(.*)$`, "mi").exec(content);
  return match ? match[1].replace(/\s*(?:\*\/|\?>).*$/, "").trim().slice(0, 200) || null : null;
}

export function scanPackage(zip: Buffer, expected: { kind: "plugin" | "theme"; target: string; installedVersion: string | null; fixedIn?: string | null }, index: Pick<VulnerabilityIndex, "bySlug"> | null): PackageScan {
  const result: PackageScan = { status: "blocked", kind: expected.kind, slug: null, name: null, version: null, files: 0, phpFiles: 0, unpackedBytes: 0, blockers: [], warnings: [], malware: [], vulnerabilities: [], scannedAt: new Date().toISOString() };
  let entries;
  try {
    entries = listZip(zip).filter((entry) => !entry.name.startsWith("__MACOSX/") && !/(^|\/)\.DS_Store$/.test(entry.name));
  } catch (error) {
    result.blockers.push(error instanceof ZipError ? error.message : "The file could not be read as a ZIP archive.");
    return result;
  }
  const files = entries.filter((entry) => !entry.directory);
  result.files = files.length;
  result.unpackedBytes = files.reduce((sum, entry) => sum + entry.size, 0);
  const tops = new Set(entries.map((entry) => entry.name.split("/")[0]));
  const expectedSlug = expected.kind === "plugin" ? expected.target.split("/")[0] : expected.target;
  if (tops.size !== 1 || !entries.some((entry) => entry.name.includes("/"))) {
    result.blockers.push(`The zip must contain one folder named "${expectedSlug}" (the way WordPress packages plugins and themes). Download the installable zip from the vendor, not the full download bundle.`);
    return result;
  }
  const slug = [...tops][0];
  result.slug = slug;
  if (slug !== expectedSlug) result.blockers.push(`The package folder is "${slug}", but the installed ${expected.kind} is in "${expectedSlug}". Upload the package for the same ${expected.kind}.`);

  const mainName = expected.kind === "plugin" ? `${slug}/${expected.target.split("/").slice(1).join("/")}` : `${slug}/style.css`;
  const main = files.find((entry) => entry.name === mainName);
  if (!main) {
    result.blockers.push(`${mainName} is missing, so WordPress would not recognise this as the same ${expected.kind}.`);
  } else {
    try {
      const content = readZipEntry(zip, main, 4 * 1024 * 1024).subarray(0, HEADER_BYTES).toString("utf8");
      result.name = header(content, expected.kind === "plugin" ? "Plugin Name" : "Theme Name");
      result.version = header(content, "Version");
      if (!result.name) result.blockers.push(`${mainName} has no "${expected.kind === "plugin" ? "Plugin" : "Theme"} Name" header.`);
      if (!result.version || !/^[0-9A-Za-z.+-]{1,40}$/.test(result.version)) result.blockers.push("The package does not declare a usable version number.");
    } catch (error) {
      result.blockers.push(error instanceof Error ? error.message : "The main file could not be read.");
    }
  }

  if (result.version && expected.installedVersion) {
    const order = compareVersions(result.version, expected.installedVersion);
    if (order < 0) result.warnings.push(`This is an older version (${result.version}) than the one installed (${expected.installedVersion}).`);
    if (order === 0) result.warnings.push(`This is the same version that is installed (${result.version}); installing it replaces the files with a clean copy.`);
  }
  if (result.version && expected.fixedIn && compareVersions(result.version, expected.fixedIn) < 0) result.blockers.push(`Version ${result.version} is still vulnerable; the fix is in ${expected.fixedIn} or later.`);

  for (const entry of files) {
    if (RISKY_BINARY.test(entry.name) && !EXECUTABLE.test(entry.name)) result.warnings.push(`Contains an executable file: ${entry.name}`);
    if (/(^|\/)\.htaccess$/.test(entry.name)) result.warnings.push(`Contains server rules: ${entry.name}`);
    if (!EXECUTABLE.test(entry.name) && !/\.(?:js|txt)$/i.test(entry.name)) continue;
    const php = EXECUTABLE.test(entry.name);
    if (php) result.phpFiles += 1;
    let content: string;
    try {
      content = readZipEntry(zip, entry, 16 * 1024 * 1024).subarray(0, 1024 * 1024).toString("latin1");
    } catch {
      result.warnings.push(`${entry.name} could not be unpacked for scanning.`);
      continue;
    }
    if (NULLED.test(content)) result.warnings.push(`${entry.name} mentions a site that distributes cracked ("nulled") software. Cracked copies often contain backdoors; use the vendor's original download.`);
    if (!php) continue;
    if (/ionCube Loader|sg_load\(|SourceGuardian/.test(content)) result.warnings.push(`${entry.name} is encoded (ionCube/SourceGuardian), so its code cannot be inspected.`);
    const strong = Object.entries(STRONG).filter(([, pattern]) => pattern.test(content)).map(([name]) => name);
    const weak = Object.entries(WEAK).filter(([, pattern]) => pattern.test(content)).map(([name]) => name);
    if (strong.length) result.malware.push({ file: entry.name, signatures: [...strong, ...weak], strong: true });
    else if (weak.length >= 2) result.malware.push({ file: entry.name, signatures: weak, strong: false });
  }
  const strongHits = result.malware.filter((item) => item.strong);
  if (strongHits.length) result.blockers.push(`${strongHits.length} file(s) contain code patterns used by malware (${strongHits.slice(0, 3).map((item) => item.file).join(", ")}). Do not install this copy; download a fresh one from the vendor.`);
  const weakHits = result.malware.filter((item) => !item.strong);
  if (weakHits.length) result.warnings.push(`${weakHits.length} file(s) are obfuscated in ways malware also uses (${weakHits.slice(0, 3).map((item) => item.file).join(", ")}). Commercial plugins sometimes do this for licensing; only continue if the file came from the vendor.`);

  if (index && result.version) {
    const fake = expected.kind === "plugin" ? { plugins: [{ file: expected.target, name: result.name ?? slug, version: result.version }] } : { themes: [{ stylesheet: slug, name: result.name ?? slug, version: result.version }] };
    for (const finding of matchVulnerabilities(index, fake)) {
      for (const vulnerability of (finding.evidence.vulnerabilities as Array<{ title?: string; fixedIn?: string | null }> | undefined) ?? []) {
        result.vulnerabilities.push({ title: String(vulnerability.title ?? finding.title), fixedIn: typeof vulnerability.fixedIn === "string" ? vulnerability.fixedIn : null });
      }
    }
    if (result.vulnerabilities.length) result.blockers.push(`Version ${result.version} still has ${result.vulnerabilities.length} known vulnerabilit${result.vulnerabilities.length === 1 ? "y" : "ies"}: ${result.vulnerabilities.slice(0, 2).map((item) => item.title).join("; ")}.`);
  } else if (!index) {
    result.warnings.push("The vulnerability database is not connected, so this version was not checked against known vulnerabilities.");
  }
  result.warnings = [...new Set(result.warnings)].slice(0, 25);
  result.status = result.blockers.length ? "blocked" : "ready";
  return result;
}
