import { getRedisClient } from "../redis/redisClient.js";

/**
 * Health check configuration for a route.
 */
export interface RouteHealthCheck {
  path: string;        // HTTP path to probe (e.g., "/.well-known/health")
  host?: string;       // Optional Host header override (defaults to user's domain)
}

/**
 * A single route entry for reaching a PCS.
 */
export interface Route {
  ip: string;                      // IP address of the route endpoint
  port: number;                    // Port number
  priority: number;                // Lower number = higher priority (1 = direct, 2 = tunnel)
  healthCheck?: RouteHealthCheck;  // Optional health check configuration
}

/**
 * TTL for route entries in seconds.
 * Routes expire if not refreshed within this time.
 */
const ROUTES_TTL_SECONDS = 600; // 10 minutes

/**
 * Get the Redis key for a user's routes.
 */
function getRoutesKey(userId: string): string {
  return `routes:${userId}`;
}

/**
 * Register or update routes for a user.
 * Stores the routes in Redis with a TTL.
 *
 * @param userId - The user ID
 * @param routes - Array of routes to register
 */
export async function registerRoutes(userId: string, routes: Route[]): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  if (!routes || routes.length === 0) {
    throw new Error("At least one route is required.");
  }

  // Validate routes
  for (const route of routes) {
    if (!route.ip) {
      throw new Error("Route IP is required.");
    }
    if (!route.port || route.port < 1 || route.port > 65535) {
      throw new Error("Route port must be between 1 and 65535.");
    }
    if (typeof route.priority !== "number") {
      throw new Error("Route priority is required.");
    }
  }

  const redis = getRedisClient();
  const key = getRoutesKey(userId);
  const value = JSON.stringify(routes);

  await redis.setex(key, ROUTES_TTL_SECONDS, value);
}

/**
 * Get routes for a user.
 *
 * @param userId - The user ID
 * @returns Array of routes, or null if not found/expired
 */
export async function getRoutes(userId: string): Promise<Route[] | null> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const key = getRoutesKey(userId);
  const value = await redis.get(key);

  if (!value) {
    return null;
  }

  try {
    return JSON.parse(value) as Route[];
  } catch {
    console.error(`Invalid routes data for user ${userId}`);
    return null;
  }
}

/**
 * Delete routes for a user.
 *
 * @param userId - The user ID
 */
export async function deleteRoutes(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const key = getRoutesKey(userId);
  await redis.del(key);
}

/**
 * Check if a user has any routes registered.
 *
 * @param userId - The user ID
 * @returns true if routes exist, false otherwise
 */
export async function hasRoutes(userId: string): Promise<boolean> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const key = getRoutesKey(userId);
  const exists = await redis.exists(key);

  return exists === 1;
}

/**
 * Get the TTL (time to live) for a user's routes.
 *
 * @param userId - The user ID
 * @returns TTL in seconds, -1 if key exists but has no TTL, -2 if key doesn't exist
 */
export async function getRoutesTTL(userId: string): Promise<number> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const key = getRoutesKey(userId);

  return redis.ttl(key);
}
