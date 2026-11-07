export type AssistantRepairPermissionCommand = "enable_broken_link_automation" | "disable_broken_link_automation";

/** Parse only explicit instructions for the single low-risk operation category. */
export function parseAssistantRepairPermissionCommand(input: string): AssistantRepairPermissionCommand | null {
  const question = input.trim();
  const mentionsAutomation = /\b(automatic|automatically|automation)\b/i.test(question);
  const mentionsLinkCategory = /\b(broken|redirecting|internal)[ -]?links?\b/i.test(question);
  if (!mentionsAutomation || !mentionsLinkCategory) return null;
  if (/\b(enable|allow|turn on|start)\b/i.test(question)) return "enable_broken_link_automation";
  if (/\b(disable|revoke|turn off|stop)\b/i.test(question)) return "disable_broken_link_automation";
  return null;
}
