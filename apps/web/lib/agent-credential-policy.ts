export function isAgentCredentialActive(input: {
  agentRevokedAt: Date | null;
  credentialRevokedAt: Date | null;
  expiresAt: Date | null;
}, now = new Date()): boolean {
  return input.agentRevokedAt === null
    && input.credentialRevokedAt === null
    && (input.expiresAt === null || input.expiresAt.getTime() > now.getTime());
}
