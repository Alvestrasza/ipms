import "server-only";

export const CONTROL_PLANE_URL = (
  process.env.IPMS_CONTROL_PLANE_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

export function controlPlaneHeaders(
  headers: Record<string, string> = {},
): Record<string, string> {
  return {
    "X-Forwarded-Proto": "https",
    ...headers,
  };
}
