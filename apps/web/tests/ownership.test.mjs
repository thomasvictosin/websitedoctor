import test from "node:test";
import assert from "node:assert/strict";
import {
  ownedIssueWhere,
  ownedRepairWhere,
  ownedWebsiteWhere,
} from "../lib/ownership-filters.ts";

test("website queries are constrained to the authenticated owner", () => {
  const membershipScope = { organization: { members: { some: { userId: "owner-a" } } } };
  assert.deepEqual(ownedWebsiteWhere("owner-a"), membershipScope);
  assert.deepEqual(ownedWebsiteWhere("owner-a", "site-a"), {
    ...membershipScope,
    id: "site-a",
  });
});

test("issue and repair lookups enforce ownership through their website relation", () => {
  assert.deepEqual(ownedIssueWhere("owner-a", "issue-a"), {
    id: "issue-a",
    website: { organization: { members: { some: { userId: "owner-a" } } } },
  });
  assert.deepEqual(ownedRepairWhere("owner-a", "repair-a"), {
    id: "repair-a",
    website: { organization: { members: { some: { userId: "owner-a" } } } },
  });
});

test("owner-scoped records do not match a different owner", () => {
  const requestedOwner = "owner-a";
  const storedOwner = "owner-b";
  assert.notEqual(ownedWebsiteWhere(requestedOwner).organization.members.some.userId, storedOwner);
  assert.notEqual(ownedIssueWhere(requestedOwner).website.organization.members.some.userId, storedOwner);
  assert.notEqual(ownedRepairWhere(requestedOwner).website.organization.members.some.userId, storedOwner);
});
