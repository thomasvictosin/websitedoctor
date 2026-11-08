import { createAiEngine } from "./engine";
import { OllamaProvider } from "./ollama";
import { FixtureAiProvider } from "./fixture-provider";
import { ClaudeProvider } from "./claude";
import type { AiProvider } from "./provider";
import { claudeSettings } from "../integrations";

function environmentProvider(): AiProvider {
  const providerName = process.env.AI_PROVIDER ?? "ollama";
  if (providerName === "ollama") return new OllamaProvider();
  if (providerName === "fixture" && process.env.NODE_ENV !== "production" && process.env.AIWD_ALLOW_FIXTURE_AI === "true") {
    return new FixtureAiProvider();
  }
  throw new Error(`Unsupported AI_PROVIDER "${providerName}". Supported providers: ollama.`);
}

/**
 * Claude when an Anthropic key is set (Settings → Integrations, or ANTHROPIC_API_KEY),
 * otherwise the AI_PROVIDER from the environment (a self-hosted Ollama server).
 * The key is looked up on first use, so creating the engine stays synchronous.
 */
class ConfiguredProvider implements AiProvider {
  private resolved: Promise<AiProvider> | null = null;

  constructor(private readonly organizationId?: string | null) {}

  private provider() {
    this.resolved ??= (async () => {
      // The CI fixture always wins, so tests never call a real model.
      if (process.env.AI_PROVIDER === "fixture") return environmentProvider();
      const claude = await claudeSettings(this.organizationId);
      return claude ? new ClaudeProvider(claude.apiKey, claude.model) : environmentProvider();
    })();
    return this.resolved;
  }

  async generateJson(prompt: string, evidence: unknown) {
    return (await this.provider()).generateJson(prompt, evidence);
  }
}

export function getAiEngine(organizationId?: string | null) {
  return createAiEngine(new ConfiguredProvider(organizationId));
}
