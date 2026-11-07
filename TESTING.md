# Testing and detector completion gates

## Local checks

```sh
npm ci
npm run typecheck
npm run test:web
npm run test:repair-db
npm run plugin:lint
npm run plugin:test
npm run browser:install --workspace apps/web
npm run test:e2e:wordpress
```

The WordPress end-to-end command creates disposable PostgreSQL, MariaDB, WordPress, and app services using `docker-compose.e2e.yml`. It installs the plugin and deliberately broken fixture plugins, uses the app's real browser scanner against the disposable WordPress site, and tears down the containers and database volumes afterward. Do not point this fixture at a customer installation.

`npm run test:repair-db` creates a separate disposable PostgreSQL container, applies the Prisma schema, runs database-backed repair authorization tests, then removes the container and its volume. It races concurrent one-time grant claims and injects a mid-transaction batch grant failure to verify the whole batch rolls back. Docker is required.

## Completion gate

A detector is complete only after CI exercises all of these against both a known-broken fixture and a healthy control:

1. It records the expected evidence and issue in the shared store.
2. The central diagnosis cites stored evidence and does not assert unobserved facts.
3. Any executable proposal is bounded to an allowlisted reversible operation supported by evidence. Browser-only layout findings have no automatic CSS repair.
4. Approval is required and shared across the WordPress and web interfaces.
5. Execution is recorded, relevant checks are rerun, and verification failure or regression triggers rollback with the outcome recorded.

The detector-level web tests cover browser overflow, mobile navigation, image alt text, form labels, contrast heuristics, axe-core violations, browser paint/timing metrics, sitemap crawling, JavaScript errors, and failed requests, with healthy controls. The real WordPress E2E workflow exercises two staged plugin conflicts, both approval interfaces, central evidence-grounded diagnosis, executor recovery, inconclusive browser verification, rollback, AI unavailable/malformed responses, pairing and installation credential expiry, unauthenticated requests, tenant isolation, malformed diagnostics, a private-target URL block, and offline diagnostic queuing.

Hosting tests cover public host validation, SSH host-key pinning, DNS-pinned SFTP connections, remote document-root verification, symlink/traversal rejection, bounded read-only directory and permission inspection, capability allowlisting, safe hosting-proposal target validation, and the generic repair lifecycle. Dashboard SFTP inspections are audited and bounded by time and entry count. Hosting repair requests can be linked to an open issue and reviewed through the shared repair history, but approval is review-only: no recovery point or remote write is performed, and approve-and-apply, batch authorization, and WordPress-agent execution are blocked. SFTP path checks are not a race-safe write boundary; the requirements for any future write adapter are documented in [the hosting write-safety contract](./docs/hosting-write-safety.md).

The Linux hosting write-safety feasibility probe is separate from application tests and uses only a disposable container `/tmp` fixture: `./spikes/hosting-write-safety/run-linux-spike.sh`. It confirms confined path resolution on the tested kernel and reproduces why ordinary rename plus advisory locking can overwrite a concurrent change; it is not a write adapter or a release gate substitute.

## Limits and status

Playwright browser tests require Chromium; they skip locally when Chromium is absent. CI installs Chromium before running them. The full app + WordPress E2E needs Docker Compose. If Docker is absent, the unit suites can pass while the real integration remains unrun.

The browser crawl discovers page links and sitemap URLs but is bounded to 250 pages, depth 8, 10 minutes, 3000 requests, and 100 MB total responses; query links and external destinations are excluded. Axe-core checks WCAG tagged rules automatically, but does not establish full conformance or replace manual accessibility review. Mobile navigation and contrast heuristics remain review signals. Browser evidence alone does not create an executable layout or CSS repair. Plugin/theme conflicts are probed only in an explicitly disposable staging environment; live components are never deactivated for diagnosis. Scheduled-task overdue status can be detected, but generic callback failures require callbacks to report outcomes through the plugin reporting API. PHP fatal evidence depends on the available shutdown/error-log signals.

Organization accounts support admin-provisioned temporary passwords, membership-based scoping, and member removal. Password reset, invitation delivery, and multi-organization switching remain incomplete.

Do not mark a detector complete based on the dashboard or a passing unit test alone. Record the broken-control and healthy-control results and full repair-lifecycle evidence in CI before claiming completion.
