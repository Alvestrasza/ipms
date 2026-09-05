/** Browser write authorization must not trust proxy/request host headers. */
export function isTrustedPortalOrigin(
  origin: string | null,
  configured: string | undefined,
): boolean {
  if (!origin || !configured || origin !== configured) return false;
  try {
    const parsed = new URL(configured);
    if (parsed.origin !== configured) return false;
    return (
      parsed.protocol === "https:" ||
      (parsed.protocol === "http:" &&
        ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname))
    );
  } catch {
    return false;
  }
}
