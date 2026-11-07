export interface AiProvider {
  generateJson(prompt: string, evidence: unknown): Promise<unknown>;
}
