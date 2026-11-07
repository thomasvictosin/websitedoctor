export async function readBoundedJson(request: Request, maximumBytes: number): Promise<unknown | null> {
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > maximumBytes) return null;
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > maximumBytes) return null;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return null;
  }
}
