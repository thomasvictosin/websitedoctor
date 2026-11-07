import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

const root = new URL("../../../", import.meta.url).pathname.replace(/\/$/, "");
const project = `aiwd-repair-test-${randomUUID().slice(0, 8)}`;
const composeFile = `${root}/docker-compose.repair-tests.yml`;
const databaseUrl = "postgresql://repair_test:repair_test_only@127.0.0.1:55433/repair_authorization_test?schema=public";
const env = { ...process.env, DATABASE_URL: databaseUrl, REPAIR_TEST_DATABASE_URL: databaseUrl };

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, env, stdio: "inherit", ...options });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve() : reject(new Error(`${command} ${args.join(" ")} exited with ${code}`)));
  });
}

let failed = false;
try {
  await run("docker", ["compose", "-p", project, "-f", composeFile, "up", "-d", "--wait"]);
  await run("npx", ["prisma", "generate"], { cwd: `${root}/apps/web` });
  await run("npx", ["prisma", "db", "push"], { cwd: `${root}/apps/web` });
  await run("node", ["--experimental-strip-types", "--test", "tests/repair-authorization.db.test.mjs"], { cwd: `${root}/apps/web` });
} catch (error) {
  failed = true;
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
} finally {
  try { await run("docker", ["compose", "-p", project, "-f", composeFile, "down", "-v", "--remove-orphans"]); }
  catch (error) { failed = true; process.stderr.write(`Test database cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`); }
}
if (failed) process.exitCode = 1;
