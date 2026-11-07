import { z } from "zod";
import type { AiProvider } from "./provider";

const ollamaResponseSchema = z.object({ response: z.string() });

export class OllamaProvider implements AiProvider {
  constructor(
    private readonly baseUrl = process.env.OLLAMA_BASE_URL ?? "http://localhost:11434",
    private readonly model = process.env.OLLAMA_MODEL ?? "qwen2.5:3b",
  ) {}

  async generateJson(prompt: string, evidence: unknown): Promise<unknown> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/api/generate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        redirect: "error",
        cache: "no-store",
        body: JSON.stringify({
          model: this.model,
          stream: false,
          format: "json",
          prompt: `${prompt}\n\nEvidence JSON:\n${JSON.stringify(evidence)}`,
        }),
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      throw new Error("Local AI is unavailable. Check the server-side Ollama configuration and service status.");
    }

    if (!response.ok) {
      throw new Error(
        `Local AI returned HTTP ${response.status}. Check that Ollama is running and the configured model is available.`,
      );
    }

    const envelope = ollamaResponseSchema.parse(await response.json());
    try {
      return JSON.parse(envelope.response) as unknown;
    } catch {
      throw new Error("Local AI returned invalid JSON. Retry the request or select another model.");
    }
  }
}
