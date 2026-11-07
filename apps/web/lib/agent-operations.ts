export function isAllowedAgentOperation(
  step: { operation?: unknown; parameters?: unknown },
): step is {
  operation: "disable_plugin" | "update_setting" | "switch_theme" | "replace_post_link" | "add_scoped_css_rule";
  parameters: Record<string, string>;
} {
  if (!step || typeof step.operation !== "string" || !step.parameters || typeof step.parameters !== "object" || Array.isArray(step.parameters)) return false;
  const params = step.parameters as Record<string, unknown>;
  if (Object.values(params).some((value) => typeof value !== "string")) return false;
  if (step.operation === "replace_post_link") {
    if (Object.values(params).some((value) => (value as string).length > 2000)) return false;
  } else if (Object.values(params).some((value) => (value as string).length > 500)) return false;
  switch (step.operation) {
    case "disable_plugin":
      return Object.keys(params).length === 1
        && typeof params.plugin === "string"
        && /^(?!\/)(?!.*(?:^|\/)\.\.?\/)[a-z0-9._/-]+\.php$/i.test(params.plugin);
    case "update_setting":
      return Object.keys(params).length === 3
        && ["blogname", "blogdescription"].includes(String(params.option))
        && typeof params.value === "string"
        && typeof params.expectedCurrentValue === "string";
    case "switch_theme":
      return Object.keys(params).length === 1 && typeof params.stylesheet === "string" && /^[a-z0-9_-]+$/i.test(params.stylesheet);
    case "replace_post_link": {
      if (Object.keys(params).length !== 4 || !/^\d{1,10}$/.test(String(params.postId))) return false;
      const values = [params.pageUrl, params.linkUrl, params.replacementUrl];
      if (!values.every((value) => typeof value === "string")) return false;
      try {
        const [page, link, replacement] = values.map((value) => new URL(value as string));
        return [page, link, replacement].every((url) => ["http:", "https:"].includes(url.protocol) && !url.username && !url.password && !url.hash)
          && page.origin === link.origin && page.origin === replacement.origin;
      } catch { return false; }
    }
    case "add_scoped_css_rule":
      return Object.keys(params).length === 1
        && typeof params.selector === "string"
        && /^body\.(?:page-id|postid)-[1-9][0-9]{0,9}\s+(?:#[A-Za-z_][A-Za-z0-9_-]*|\.[A-Za-z_][A-Za-z0-9_-]*)$/.test(params.selector);
    default:
      return false;
  }
}
