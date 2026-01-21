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
