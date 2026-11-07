# Supabase setup checklist

The app uses PostgreSQL through Prisma, so Supabase can host the application database without an ORM rewrite. The repository is prepared to use `DATABASE_URL` for the app and optional `DIRECT_URL` for Prisma CLI schema changes. No Supabase project has been created or connected yet.

## Create and connect a project

1. Create a new Supabase project in the region nearest the application server. Choose a plan and database password; store the password in a password manager.
2. Open **Connect** in the project dashboard and copy the **Session pooler** URL to the server's `DATABASE_URL` environment variable.
3. Copy **Direct connection** to `DIRECT_URL` for Prisma schema commands when the runner can reach that address. Direct connections require IPv6 or the Supabase IPv4 add-on. If direct connectivity is unavailable, set `DIRECT_URL` to the session-pooler URL.
4. Keep `DATABASE_URL` in session mode (port 5432) for the current long-running Node app. The application uses PostgreSQL advisory locks while serializing repair permissions and dispatch. Transaction pool mode (port 6543) does not preserve session-level advisory locks between statements.
5. Configure these variables only on the application server/CI environment. Never expose database credentials or Supabase secret/service-role keys to browser code.

For the local Supabase development project, keep Docker Compose PostgreSQL as the default, or set both URLs to the Supabase project explicitly. Do not reuse a production URL in a local `.env` file.

## Initialize an empty project

The repository currently has a Prisma schema but no checked-in migration history. For a brand-new, empty Supabase project only:

```sh
npm run db:generate
npm run db:push --workspace apps/web
```

`db:push` bootstraps the local-admin user and organization, synchronizes the schema, and migrates legacy WordPress agent hashes. It is an initialization/development workflow, not a reviewed production migration pipeline. Inspect Prisma's proposed changes before applying it, and do not run it against a database containing data you need to preserve without a verified backup.

Before production use, establish and review a Prisma migration baseline so future schema changes are versioned and deployed deliberately. Avoid `db push` as the recurring production schema process.

## Move existing local records

1. Pause the local app's scheduler and avoid writes during the database copy.
2. Create a PostgreSQL dump of the local database and keep the original unchanged.
3. Restore into a separate, empty Supabase project first; do not test a restore against the source or live production project.
4. Validate table counts, accounts/memberships, websites, scans/issues, repair history, and encrypted credentials/backups. Confirm `SESSION_SECRET` remains the same because stored encrypted secrets depend on it.
5. Run app-level smoke checks against the separate restored project, then schedule the production cutover and retain a rollback path to the original database.

No local data has been copied by this setup preparation.

## Production app requirements

Supabase hosts the PostgreSQL database, not the Next.js app or its Playwright browser runtime. Deploy the app to a Node-compatible host and configure `APP_ORIGIN`, `SESSION_SECRET`, `ADMIN_PASSWORD_HASH`, `DATABASE_URL`, and `DIRECT_URL`. Preserve an always-running worker/scheduler process for durable scans and scheduled checks; the current due-site scheduler is in-process and is not a distributed high-availability scheduler.

Select a Supabase compute/storage plan, region, backup/retention policy, and network connection mode after estimating load and cost. Supabase connection options, IPv4 reachability, plan limits, and Prisma pooling guidance can change; verify them in the project dashboard before cutover.

## Current decision/status

- [x] Prisma can select `DIRECT_URL` for CLI schema operations and `DATABASE_URL` at app runtime.
- [x] Supabase connection and risk checklist documented.
- [ ] Choose/create Supabase project and region.
- [ ] Configure real connection URLs in the selected app host's secrets.
- [ ] Establish versioned migrations before production schema changes.
- [ ] Decide whether and when local data should be copied.
- [ ] Select the application hosting provider and production backup/restore policy.
