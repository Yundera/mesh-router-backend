/**
 * Returns the SERVER_DOMAIN from environment.
 * This is the domain suffix used for all user domains (e.g., "nsl.sh", "inojob.com").
 * @throws Error if SERVER_DOMAIN is not configured
 */
export function getServerDomain(): string {
  const serverDomain = process.env.SERVER_DOMAIN;
  if (!serverDomain) {
    throw new Error("SERVER_DOMAIN environment variable is not configured");
  }
  return serverDomain;
}

/**
 * Default TTL for route entries in seconds.
 */
const DEFAULT_ROUTES_TTL_SECONDS = 600; // 10 minutes

/**
 * Returns the TTL for route entries from environment or default.
 * Routes expire if not refreshed within this time.
 * @returns TTL in seconds
 */
export function getRoutesTtl(): number {
  const envValue = process.env.ROUTES_TTL_SECONDS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_ROUTES_TTL_SECONDS;
}
