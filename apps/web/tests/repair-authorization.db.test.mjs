import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
import { consumeRepairGrant, createRepairAuthorizationGrant } from "../lib/repair-grant-policy.ts";
import { commitRepairBatch } from "../lib/repair-batch-transaction.ts";

const connectionString = process.env.REPAIR_TEST_DATABASE_URL;
const testDatabase = connectionString ? new PrismaClient({ adapter: new PrismaPg({ connectionString }) }) : null;

test("Postgres enforces single-use grant consumption and atomic batch approval", { skip: !testDatabase }, async (t) => {
  const db = testDatabase;
  const suffix = randomUUID();
  const owner = await db.user.create({ data: { id: `owner-${suffix}`, email: `${suffix}@example.test`, name: "Repair test owner" } });
  const organization = await db.organization.create({ data: { id: `org-${suffix}`, name: "Repair test organization" } });
  const website = await db.website.create({ data: { id: `site-${suffix}`, ownerId: owner.id, organizationId: organization.id, name: "Repair test site", url: "https://example.test/" } });
  const agent = await db.wordPressAgent.create({ data: { websiteId: website.id, siteUrl: website.url, siteName: website.name, pluginVersion: "test", lastSeenAt: new Date() } });
  const issues = await Promise.all(["a", "b"].map((suffix) => db.issue.create({ data: {
    websiteId: website.id, fingerprint: `wp:test-${suffix}`, title: `Test issue ${suffix}`, description: "Disposable authorization fixture", source: "wordpress",
  } })));
  const operationIds = ["replace_post_link"];
  const makeProposal = (postId) => ({
    issue: `Test issue ${postId}`,
    executionAvailable: true,
    instructions: {
      steps: [{ description: "Update a test link", operation: "replace_post_link", parameters: {
        postId: String(postId), pageUrl: "https://example.test/page/", linkUrl: "https://example.test/old/", replacementUrl: "https://example.test/new/",
      } }],
      rollbackPlan: ["Restore the exact prior link"], requiresApproval: true,
    },
  });
  const repairs = await Promise.all(issues.map((issue, index) => db.repairProposal.create({ data: {
    websiteId: website.id, issueId: issue.id, risk: "low", operationIds, proposal: makeProposal(index + 10),
  } })));

  t.after(async () => {
    await db.organization.delete({ where: { id: organization.id } }).catch(() => {});
    await db.user.delete({ where: { id: owner.id } }).catch(() => {});
  });

  await t.test("concurrent claims consume exactly one matching grant", async () => {
    const repair = repairs[0];
    const finalProposal = { ...repair.proposal, executionRequest: { mode: "apply_on_site_poll", batchId: "concurrent-test" } };
    const grant = await db.$transaction((tx) => createRepairAuthorizationGrant(tx, {
      repairId: repair.id, proposal: finalProposal, operationIds, websiteId: website.id, issueId: repair.issueId,
      method: "individual", scope: { kind: "test" },
    }));
    const now = new Date();
    const results = await Promise.all(Array.from({ length: 12 }, () => consumeRepairGrant(db.repairApproval, {
      id: grant.id, digest: grant.operationDigest, now,
    })));
    assert.equal(results.reduce((count, result) => count + result.count, 0), 1);
    const stored = await db.repairApproval.findUnique({ where: { id: grant.id } });
    assert.ok(stored.consumedAt);
    assert.equal(stored.decision, "consumed");
  });

  await t.test("a failure during batch commit rolls back every selected approval and grant", async () => {
    const batchId = `batch-${suffix}`;
    const [first, second] = repairs;
    await db.$executeRawUnsafe(`CREATE OR REPLACE FUNCTION fail_repair_test_grant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.repairId = '${second.id}' THEN RAISE EXCEPTION 'injected batch failure'; END IF; RETURN NEW; END $$`);
    await db.$executeRawUnsafe("CREATE TRIGGER fail_repair_test_grant BEFORE INSERT ON \"RepairApproval\" FOR EACH ROW EXECUTE FUNCTION fail_repair_test_grant()");
    try {
      await assert.rejects(db.$transaction((tx) => commitRepairBatch(tx, {
        repairs: repairs.map((repair) => ({ ...repair, organizationId: organization.id })),
        userId: owner.id,
        batchId,
        now: new Date(),
        sourceHash: "database-integration-test",
        findConflict: async () => null,
      })));
    } finally {
      await db.$executeRawUnsafe("DROP TRIGGER IF EXISTS fail_repair_test_grant ON \"RepairApproval\"");
      await db.$executeRawUnsafe("DROP FUNCTION IF EXISTS fail_repair_test_grant()");
    }
    const persisted = await db.repairProposal.findMany({ where: { id: { in: [first.id, second.id] } }, orderBy: { id: "asc" } });
    assert.equal(persisted.length, 2);
    assert.ok(persisted.every((repair) => repair.status === "pending_approval"));
    assert.equal(await db.repairApproval.count({ where: { batchId } }), 0);
    assert.equal(await db.repairEvent.count({ where: { eventType: "batch_execution_queued", repairId: { in: [first.id, second.id] } } }), 0);
  });
});

test.after(async () => { await testDatabase?.$disconnect(); });
