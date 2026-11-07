import "dotenv/config";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL must be set before migrating installation credentials.");

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString }),
});

try {
  const agents = await prisma.wordPressAgent.findMany({
    where: { legacySecretHash: { not: null } },
    select: { id: true, legacySecretHash: true },
  });
  for (const agent of agents) {
    if (!agent.legacySecretHash) continue;
    await prisma.$transaction(async (transaction) => {
      const credential = await transaction.installationCredential.findFirst({
        where: { agentId: agent.id, tokenHash: agent.legacySecretHash },
        select: { id: true },
      });
      if (!credential) {
        await transaction.installationCredential.create({
          data: { agentId: agent.id, tokenHash: agent.legacySecretHash },
        });
      }
      await transaction.wordPressAgent.updateMany({
        where: { id: agent.id, legacySecretHash: agent.legacySecretHash },
        data: { legacySecretHash: null },
      });
    });
  }
} finally {
  await prisma.$disconnect();
}
