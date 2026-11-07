import { createAiEngine } from "./engine";
import { OllamaProvider } from "./ollama";
import { FixtureAiProvider } from "./fixture-provider";
import type { AiProvider } from "./provider";

function createProvider(): AiProvider {
  const providerName = process.env.AI_PROVIDER ?? "ollama";
  if (providerName === "ollama") return new OllamaProvider();
  if (providerName === "fixture" && process.env.NODE_ENV !== "production" && process.env.AIWD_ALLOW_FIXTURE_AI === "true") {
    return new FixtureAiProvider();
  }
  throw new Error(`Unsupported AI_PROVIDER "${providerName}". Supported providers: ollama.`);
}

export function getAiEngine() {
  return createAiEngine(createProvider());
}
