export type RepairRequestKind = "diagnose" | "recommend" | "repair_one" | "repair_multiple" | "routine_maintenance";

export function promptExplicitlyAuthorizesRepair(prompt: string) {
  return /\b(fix|repair|resolve|correct|apply|take care of|perform routine maintenance|run routine maintenance)\b/i.test(prompt)
    && !/\b(recommend|suggest|how can i|what should|check only)\b/i.test(prompt);
}

export function isDiagnosisOnlyPrompt(prompt: string) {
  return /\b(diagnos\w*|scan|check|inspect|what is wrong|why is)\b/i.test(prompt)
    && !promptExplicitlyAuthorizesRepair(prompt);
}

export function hasExplicitBroadRepairScope(prompt: string) {
  return /\b(all|every|batch|routine|maintenance|across|throughout|category)\b/i.test(prompt)
    || /\b(broken|redirecting|internal) links\b/i.test(prompt)
    || /\b(accessibility|performance|security|seo) issues\b/i.test(prompt);
}

export function categoryIssueIds(prompt: string, issues: Array<{ id: string; fingerprint: string; title: string; description: string }>) {
  const patterns: Array<[RegExp, RegExp]> = [
    [/\b(broken|redirecting|internal) links?\b/i, /broken-link|link-redirect|\blink\b/i],
    [/\b(accessibility|alt text|form labels?|contrast|keyboard|wcag)\b/i, /accessibility|missing-image-alt|missing-form-label|contrast|keyboard/i],
    [/\b(performance|slow pages?|slow loading|lcp|cls|large resources?)\b/i, /slow-|poor-lcp|poor-cls|large-resource|resource-heavy|performance/i],
    [/\b(seo|search engine)\b/i, /\bseo\b|search-engine/i],
  ];
  const category = patterns.find(([promptPattern]) => promptPattern.test(prompt));
  if (!category) return null;
  const issuePattern = category[1];
  return new Set(issues.filter((issue) => issuePattern.test(`${issue.fingerprint} ${issue.title} ${issue.description}`)).map((issue) => issue.id));
}

export function validateIssueCategoryScope(prompt: string, issueIds: string[], issues: Array<{ id: string; fingerprint: string; title: string; description: string }>) {
  const allowedIds = categoryIssueIds(prompt, issues);
  return !allowedIds || issueIds.every((id) => allowedIds.has(id));
}

export function promptNamesPage(prompt: string, page: string) {
  const normalizedPrompt = prompt.toLowerCase();
  if (normalizedPrompt.includes(page.toLowerCase())) return true;
  try {
    const url = new URL(page);
    const path = url.pathname.toLowerCase().replace(/\/$/, "");
    if (path && path !== "/" && normalizedPrompt.includes(path)) return true;
    const slug = path.split("/").filter(Boolean).at(-1)?.replaceAll(/[-_]+/g, " ");
    return Boolean(slug && slug.length > 2 && normalizedPrompt.includes(slug));
  } catch { return false; }
}

export function validateRepairRequestScope(prompt: string, requestKind: RepairRequestKind, issueIds: string[]) {
  if (new Set(issueIds).size !== issueIds.length) return "The repair plan selected the same issue more than once.";
  if (isDiagnosisOnlyPrompt(prompt) && requestKind !== "diagnose") return "This wording asks for diagnosis only. No repair plan was created.";
  if (requestKind === "repair_one" && issueIds.length !== 1) return "A single-issue repair request must identify exactly one issue.";
  if (requestKind === "repair_multiple" && !hasExplicitBroadRepairScope(prompt)) return "A multi-issue request needs an explicit category, batch, or all/every scope.";
  if (requestKind === "routine_maintenance" && !/\b(routine|maintenance)\b/i.test(prompt)) return "Routine maintenance requires an explicit maintenance request.";
  if (requestKind === "routine_maintenance" && !hasExplicitBroadRepairScope(prompt)) return "Routine maintenance needs an explicit scope.";
  return null;
}
