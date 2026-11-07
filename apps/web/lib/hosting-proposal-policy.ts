export function isHostingRepairProposal(value: unknown): boolean {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.hasOwn(value, "hostingRequest");
}
