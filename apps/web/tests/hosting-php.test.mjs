import test from "node:test";
import assert from "node:assert/strict";
import {
  checkPhpCompatibility,
  compareSiteHealth,
  compareVersions,
  cpanelClient,
  CpanelError,
  matchVhost,
  parseVhosts,
  phpId,
  phpLabel,
  pluginConfirmation,
  readPhpState,
  sampleSiteHealth,
  switchPhpVersion,
} from "../lib/hosting-php.ts";
import { discoverHostingCapabilities } from "../lib/hosting.ts";
import { hostingConnectionInputSchema } from "../lib/validation.ts";

const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
const target = { hostname: "server.examplehost.com", port: 2083, username: "shopuser", token };

/** A cPanel account with one site whose version can be switched. */
function fakeCpanel({ version = "ea-php74", installed = ["ea-php74", "ea-php81", "ea-php82"], failSet = () => false, inherited = false, wrap = false } = {}) {
  const state = { version, sets: [], requests: [] };
  const transport = async (url, headers) => {
    state.requests.push({ url: url.toString(), headers });
    const [, , module, func] = url.pathname.split("/");
    let result;
    if (module !== "LangPHP") result = { status: 0, errors: ["unknown module"] };
    else if (func === "php_get_installed_versions") result = { status: 1, data: { versions: installed } };
    else if (func === "php_get_system_default_version") result = { status: 1, data: { version: "ea-php81" } };
    else if (func === "php_get_vhost_versions") {
      result = { status: 1, data: [
        { vhost: "shop.example", version: state.version, documentroot: "/home/shopuser/public_html", php_fpm: 1, phpversion_source: inherited ? { system_default: 1 } : { domain: "shop.example" } },
        { vhost: "other.example", version: "ea-php81", documentroot: "/home/shopuser/other" },
      ] };
    } else if (func === "php_set_vhost_versions") {
      const requested = url.searchParams.get("version");
      state.sets.push(requested);
      if (failSet(requested, state.sets.length)) result = { status: 0, errors: ["Could not update the PHP-FPM pool."] };
      else { state.version = requested; result = { status: 1, data: null }; }
    } else result = { status: 0, errors: ["unknown function"] };
    return { status: 200, body: JSON.stringify(wrap ? { result } : result) };
  };
  return { state, transport, call: cpanelClient(target, transport) };
}

/** A website whose pages depend on the PHP version currently set in the fake cPanel. */
function fakeSite(cpanel, { brokenOn = [], homeError = null, flakyFirst = 0 } = {}) {
  let calls = 0;
  return async (url) => {
    const { pathname } = new URL(url);
    if (homeError && pathname === "/") throw new Error(homeError);
    if (brokenOn.includes(cpanel.state.version)) {
      return { statusCode: 500, text: "<p>There has been a critical error on this website.</p>", headers: {} };
    }
    if (pathname === "/" && flakyFirst > 0 && calls++ < flakyFirst) return { statusCode: 503, text: "restarting", headers: {} };
    const label = phpLabel(cpanel.state.version);
    if (pathname === "/") return { statusCode: 200, text: `<html>${"content ".repeat(200)}</html>`, headers: { "x-powered-by": `PHP/${label}.3` } };
    if (pathname === "/wp-admin/admin-ajax.php") return { statusCode: 400, text: "0", headers: {} };
    return { statusCode: 200, text: "ok", headers: {} };
  };
}

const noSleep = async () => {};

test("PHP version ids and labels convert both ways and compare numerically", () => {
  assert.equal(phpLabel("ea-php81"), "8.1");
  assert.equal(phpLabel("ea-php74"), "7.4");
  assert.equal(phpLabel("alt-php81"), null);
  assert.equal(phpLabel("inherit"), null);
  assert.equal(phpId("8.2"), "ea-php82");
  assert.equal(phpId("ea-php74"), "ea-php74");
  assert.equal(phpId("8"), null);
  assert.equal(phpId("8.2; rm"), null);
  assert.ok(compareVersions("8.10", "8.9") > 0);
  assert.ok(compareVersions("7.4", "8.0") < 0);
  assert.equal(compareVersions("8.1", "8.1.0"), 0);
});

test("cPanel requests use the API token header and parse flat and wrapped answers", async () => {
  for (const wrap of [false, true]) {
    const cpanel = fakeCpanel({ wrap });
    const state = await readPhpState(cpanel.call);
    assert.deepEqual(state.installed.map((option) => option.label), ["7.4", "8.1", "8.2"]);
    assert.equal(state.systemDefault, "ea-php81");
    assert.equal(state.vhosts[0].label, "7.4");
    const request = cpanel.state.requests[0];
    assert.equal(request.headers.authorization, `cpanel shopuser:${token}`);
    assert.match(request.url, /^https:\/\/server\.examplehost\.com:2083\/execute\/LangPHP\//);
  }
});

test("cPanel errors become clear messages and bad inputs are refused before any request", async () => {
  const reject = async () => ({ status: 401, body: "" });
  await assert.rejects(cpanelClient(target, reject)("LangPHP", "php_get_installed_versions"), /rejected the username or API token/);
  const html = async () => ({ status: 200, body: "<html>login</html>" });
  await assert.rejects(cpanelClient(target, html)("LangPHP", "php_get_installed_versions"), /did not return an API response/);
  const feature = async () => ({ status: 200, body: JSON.stringify({ status: 0, errors: ["This feature requires the “multiphp_manager” feature."] }) });
  await assert.rejects(cpanelClient(target, feature)("LangPHP", "php_get_installed_versions"), (error) => error instanceof CpanelError && /MultiPHP Manager/.test(error.message) && error.status === 403);
  const tls = async () => { throw Object.assign(new Error("self signed"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" }); };
  await assert.rejects(cpanelClient(target, tls)("LangPHP", "php_get_installed_versions"), /TLS certificate is not valid/);

  assert.throws(() => cpanelClient({ ...target, username: "user:evil" }), /username/);
  assert.throws(() => cpanelClient({ ...target, token: "short" }), /API token/);
  assert.throws(() => cpanelClient({ ...target, token: `${token}\r\nx: y` }), /API token/);
  assert.throws(() => cpanelClient({ ...target, port: 22 }), /port 2083/);
});

test("the website is matched to its cPanel domain, with www as an alias", () => {
  const vhosts = parseVhosts([
    { vhost: "shop.example", version: "ea-php74", phpversion_source: { system_default: 1 } },
    { vhost: "blog.shop.example", version: "ea-php82" },
  ]);
  assert.equal(matchVhost(vhosts, "https://www.shop.example/").vhost, "shop.example");
  assert.equal(matchVhost(vhosts, "https://shop.example/blog/").vhost, "shop.example");
  assert.equal(matchVhost(vhosts, "https://blog.shop.example").vhost, "blog.shop.example");
  assert.equal(matchVhost(vhosts, "https://unrelated.example"), null);
  assert.equal(vhosts[0].inherited, true);
  assert.equal(vhosts[1].inherited, false);
  // cPanel documents phpversion_source as an array, and answers with one object when a vhost is named.
  assert.equal(parseVhosts([{ vhost: "a.example", version: "ea-php81", phpversion_source: [{ system_default: 1 }] }])[0].inherited, true);
  assert.equal(parseVhosts([{ vhost: "a.example", version: "ea-php81", phpversion_source: [{ domain: "a.example" }] }])[0].inherited, false);
  assert.equal(parseVhosts({ vhost: "One.Example", version: "ea-php82" })[0].vhost, "one.example");
  assert.equal(parseVhosts({ vhost: "custom.example", version: "my-custom-php" })[0].label, null, "custom PHP packages are listed without a version label");
});

test("compatibility blocks unsafe targets and warns about likely trouble", () => {
  const report = {
    collectedAt: new Date().toISOString(),
    site: { wpVersion: "6.0", phpVersion: "7.4.33" },
    plugins: [
      { name: "Shop", active: true, updateAvailable: true, source: "wordpress.org" },
      { name: "Premium Forms", active: true, updateAvailable: false, source: "other" },
      { name: "Needs 8", active: true, updateAvailable: false, source: "wordpress.org", requiresPhp: "8.0" },
      { name: "Inactive needs 8.3", active: false, updateAvailable: false, requiresPhp: "8.3" },
    ],
    themes: [{ name: "Child", active: true, requiresPhp: "7.4" }, { name: "Parent", parentOfActive: true, requiresPhp: "8.1" }],
  };
  const installed = ["7.2", "7.4", "8.0", "8.1", "8.2"];

  const toOld = checkPhpCompatibility({ current: "8.1", target: "7.4", installed, report });
  assert.ok(toOld.blockers.some((line) => /plugin Needs 8 requires PHP 8.0/.test(line)));
  assert.ok(toOld.blockers.some((line) => /theme Parent requires PHP 8.1/.test(line)));
  assert.ok(!toOld.blockers.some((line) => /Inactive/.test(line)), "inactive plugins are not loaded, so they do not block");

  const tooNewForWordPress = checkPhpCompatibility({ current: "8.1", target: "8.2", installed, report });
  assert.ok(tooNewForWordPress.blockers.some((line) => /WordPress 6.0 does not support PHP 8.2.*6.1/.test(line)));

  const upgrade = checkPhpCompatibility({ current: "7.4", target: "8.1", installed, report });
  assert.deepEqual(upgrade.blockers, []);
  assert.ok(upgrade.warnings.some((line) => /Update these plugins first.*Shop/.test(line)));
  assert.ok(upgrade.warnings.some((line) => /1 active premium or custom plugin/.test(line)));
  assert.ok(upgrade.warnings.some((line) => /PHP 8 removed features/.test(line)));

  assert.ok(checkPhpCompatibility({ current: "7.4", target: "8.3", installed, report }).blockers.some((line) => /not installed/.test(line)));
  assert.ok(checkPhpCompatibility({ current: "7.4", target: "7.4", installed, report }).blockers.some((line) => /already runs/.test(line)));
  assert.ok(checkPhpCompatibility({ current: "7.4", target: "7.1", installed: [...installed, "7.1"], report }).blockers.some((line) => /minimum for the AI Website Doctor plugin/.test(line)));

  const unknown = checkPhpCompatibility({ current: "7.4", target: "8.1", installed, report: null });
  assert.deepEqual(unknown.blockers, []);
  assert.ok(unknown.warnings.some((line) => /has not reported yet/.test(line)));
  const stale = checkPhpCompatibility({ current: "7.4", target: "8.1", installed, report: { ...report, collectedAt: "2026-01-01T00:00:00Z" }, now: new Date("2026-11-09T12:00:00Z") });
  assert.ok(stale.warnings.some((line) => /more than an hour old/.test(line)));
});

test("site health: the home page must work afterwards, other pages must keep working if they did", () => {
  const sample = (path, statusCode, extra = {}) => ({ path, statusCode, bytes: 5000, fatal: false, poweredBy: null, error: null, ...extra });
  const before = [sample("/", 200), sample("/wp-login.php", 200), sample("/wp-json/", 403), sample("/wp-admin/admin-ajax.php", 500)];
  assert.deepEqual(compareSiteHealth(before, before), []);
  assert.match(compareSiteHealth(before, [sample("/", 500), ...before.slice(1)]).join(), /\/ now fails \(HTTP 500\)/);
  assert.match(compareSiteHealth(before, [before[0], sample("/wp-login.php", 502), ...before.slice(2)]).join(), /wp-login.php now fails/);
  assert.deepEqual(compareSiteHealth(before, [...before.slice(0, 3), sample("/wp-admin/admin-ajax.php", 500)]), [], "a page that already failed does not count");
  assert.match(compareSiteHealth(before, [sample("/", 200, { fatal: true }), ...before.slice(1)]).join(), /now shows a PHP error/);
  assert.deepEqual(compareSiteHealth([sample("/", 200, { fatal: true })], [sample("/", 200, { fatal: true })]), [], "an article that mentions PHP errors is not a new failure");
  assert.match(compareSiteHealth(before, [sample("/", 200, { bytes: 20 }), ...before.slice(1)]).join(), /blank/);
  assert.match(compareSiteHealth([sample("/", 500)], [sample("/", 500)]).join(), /\/ now fails/, "a broken home page must be fixed by the switch, or it is undone");
});

test("site health samples are taken inside a subdirectory install and bypass page caches", async () => {
  const seen = [];
  const samples = await sampleSiteHealth("https://shop.example/blog", async (url) => {
    seen.push(url);
    return { statusCode: 200, text: "Fatal error: Uncaught Error: Call to undefined function", headers: { "x-powered-by": "PHP/8.2.12" } };
  });
  assert.ok(seen.some((url) => /^https:\/\/shop\.example\/blog\/\?awd-php-check=[a-z0-9]+$/.test(url)), seen.join());
  assert.ok(seen.includes("https://shop.example/blog/wp-login.php"));
  assert.ok(seen.includes("https://shop.example/blog/wp-admin/admin-ajax.php"));
  assert.equal(samples[0].fatal, true);
  assert.equal(samples[0].poweredBy, "PHP/8.2.12");
});

test("a switch that keeps the site working is verified", async () => {
  const cpanel = fakeCpanel();
  const result = await switchPhpVersion({ call: cpanel.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php82", expectedCurrentId: "ea-php74", fetchPage: fakeSite(cpanel), sleep: noSleep });
  assert.equal(result.status, "verified", result.message);
  assert.deepEqual(cpanel.state.sets, ["ea-php82"]);
  assert.equal(cpanel.state.version, "ea-php82");
  assert.equal(result.from.label, "7.4");
  assert.equal(result.to.label, "8.2");
  assert.equal(result.after[0].poweredBy, "PHP/8.2.3");
  const setRequest = cpanel.state.requests.find((request) => request.url.includes("php_set_vhost_versions"));
  assert.match(setRequest.url, /version=ea-php82/);
  assert.match(setRequest.url, /vhost=shop\.example/);
});

test("a switch that breaks the site is undone automatically", async () => {
  const cpanel = fakeCpanel();
  const result = await switchPhpVersion({ call: cpanel.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php82", fetchPage: fakeSite(cpanel, { brokenOn: ["ea-php82"] }), sleep: noSleep, attempts: 2 });
  assert.equal(result.status, "rolled_back");
  assert.deepEqual(cpanel.state.sets, ["ea-php82", "ea-php74"]);
  assert.equal(cpanel.state.version, "ea-php74");
  assert.match(result.message, /broke the site.*switched back to PHP 7\.4/);
  assert.ok(result.steps.some((step) => step.step === "Switch back to PHP 7.4" && step.ok && /answers as before/.test(step.detail)));
});

test("a failed switch-back is reported as urgent with the manual fix", async () => {
  const cpanel = fakeCpanel({ failSet: (_version, count) => count === 2 });
  const result = await switchPhpVersion({ call: cpanel.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php82", fetchPage: fakeSite(cpanel, { brokenOn: ["ea-php82"] }), sleep: noSleep, attempts: 1 });
  assert.equal(result.status, "rollback_failed");
  assert.match(result.message, /MultiPHP Manager/);
  assert.match(result.message, /PHP 7\.4/);
});

test("a short outage while PHP restarts is retried before judging the switch", async () => {
  const cpanel = fakeCpanel();
  const result = await switchPhpVersion({ call: cpanel.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php81", fetchPage: fakeSite(cpanel, { flakyFirst: 2 }), sleep: noSleep });
  // The baseline sees the first 503 (a broken home page does not stop the switch) and the first check the second; the retry passes.
  assert.equal(result.status, "verified", result.message);
  assert.deepEqual(cpanel.state.sets, ["ea-php81"]);
});

test("nothing is changed when the version moved since review or the site cannot be checked", async () => {
  const moved = fakeCpanel({ version: "ea-php81" });
  const stale = await switchPhpVersion({ call: moved.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php82", expectedCurrentId: "ea-php74", fetchPage: fakeSite(moved), sleep: noSleep });
  assert.equal(stale.status, "blocked");
  assert.deepEqual(moved.state.sets, []);

  const unreachable = fakeCpanel();
  const blind = await switchPhpVersion({ call: unreachable.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php82", fetchPage: fakeSite(unreachable, { homeError: "blocked by an edge challenge (HTTP 403)" }), sleep: noSleep });
  assert.equal(blind.status, "blocked");
  assert.match(blind.message, /Nothing was changed/);
  assert.deepEqual(unreachable.state.sets, []);

  const refused = fakeCpanel({ failSet: () => true });
  const failed = await switchPhpVersion({ call: refused.call, vhost: "shop.example", siteUrl: "https://shop.example/", targetId: "ea-php82", fetchPage: fakeSite(refused), sleep: noSleep });
  assert.equal(failed.status, "failed");
  assert.equal(refused.state.version, "ea-php74");
});

test("the plugin's next report confirms the version WordPress really runs", () => {
  const change = { status: "verified", to: { id: "ea-php82", label: "8.2" }, finishedAt: "2026-11-09T10:00:00Z" };
  const now = new Date("2026-11-09T10:04:00Z");
  assert.equal(pluginConfirmation(change, null, now).state, "unavailable");
  assert.equal(pluginConfirmation(change, { collectedAt: "2026-11-09T09:58:00Z", site: { phpVersion: "7.4.33" } }, now).state, "waiting");
  assert.equal(pluginConfirmation(change, { collectedAt: "2026-11-09T10:03:00Z", site: { phpVersion: "8.2.12" } }, now).state, "confirmed");
  const mismatch = pluginConfirmation(change, { collectedAt: "2026-11-09T10:03:00Z", site: { phpVersion: "7.4.33" } }, now);
  assert.equal(mismatch.state, "mismatch");
  assert.match(mismatch.detail, /Select PHP Version/);
  assert.equal(pluginConfirmation({ ...change, to: { id: "ea-php82", label: "8.2" } }, { collectedAt: "2026-11-09T10:03:00Z", site: { phpVersion: "8.20.1" } }, now).state, "mismatch", "8.20 is not 8.2");
  assert.equal(pluginConfirmation({ ...change, status: "rolled_back" }, null, now), null);
});

test("a cPanel hosting connection is tested against the real account and finds the site", async () => {
  const cpanel = fakeCpanel();
  const ok = await discoverHostingCapabilities({ method: "cpanel_uapi", hostname: target.hostname, port: 2083, username: "shopuser", authMethod: "token", secret: token, siteUrl: "https://www.shop.example/", cpanelTransport: cpanel.transport });
  assert.equal(ok.ok, true, ok.message);
  assert.match(ok.message, /shop\.example runs PHP 7\.4/);
  assert.deepEqual(ok.metadata.cpanel.vhost, "shop.example");
  assert.equal(ok.metadata.documentRoot, "/home/shopuser/public_html");
  assert.deepEqual(ok.capabilities.filter((capability) => capability.supported).map((capability) => capability.capability).sort(), ["cpanel_api_connection", "domain_discovery", "php_settings"]);

  const missing = await discoverHostingCapabilities({ method: "cpanel_uapi", hostname: target.hostname, port: 2083, username: "shopuser", authMethod: "token", secret: token, siteUrl: "https://elsewhere.example/", cpanelTransport: cpanel.transport });
  assert.equal(missing.ok, false);
  assert.match(missing.message, /no domain matching elsewhere\.example.*shop\.example/);

  const wrongPort = await discoverHostingCapabilities({ method: "cpanel_uapi", hostname: target.hostname, port: 2087, username: "shopuser", authMethod: "token", secret: token, siteUrl: "https://shop.example/", cpanelTransport: cpanel.transport });
  assert.equal(wrongPort.ok, false);
  assert.match(wrongPort.message, /port 2083/);
});

test("cPanel connection input requires a username, an API token and a cPanel port", () => {
  const base = { method: "cpanel_uapi", hostname: "server.examplehost.com", username: "shopuser", authMethod: "token", secret: token };
  assert.equal(hostingConnectionInputSchema.safeParse(base).success, true);
  assert.equal(hostingConnectionInputSchema.safeParse({ ...base, port: 2083 }).success, true);
  assert.equal(hostingConnectionInputSchema.safeParse({ ...base, port: 2087 }).success, false);
  assert.equal(hostingConnectionInputSchema.safeParse({ ...base, username: "" }).success, false);
  assert.equal(hostingConnectionInputSchema.safeParse({ ...base, secret: "" }).success, false);
  assert.equal(hostingConnectionInputSchema.safeParse({ ...base, authMethod: "password" }).success, false);
});
