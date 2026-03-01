import { getRedisClient } from "../redis/redisClient.js";
import { getRoutesTtl, getInactiveDomainDays } from "../configuration/config.js";

/**
 * Redis key for domain activity tracking sorted set.
 * Stores userId -> timestamp (score) mapping for fast activity queries.
 */
const ACTIVITY_KEY = "domains:activity";

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
  scheme?: "http" | "https";       // Protocol scheme (default: "https" for backward compat)
  healthCheck?: RouteHealthCheck;  // Optional health check configuration
  source: string;                  // Source identifier (e.g., "agent", "tunnel") - routes from same source replace each other
  type?: "ip" | "domain";          // Route type: "ip" for direct IP, "domain" for pre-validated domain routes (default: "ip")
  domain?: string;                 // Domain hostname (required when type="domain", e.g., "88-187-147-189.sslip.io")
  verify?: boolean;                // Whether to validate the route before storing (default: true)
}

/**
 * Get the Redis key for a user's routes.
 */
function getRoutesKey(userId: string): string {
  return `routes:${userId}`;
}

/**
 * Generate a unique key for a route based on ip:port:scheme:type:domain.
 * The scheme is included to allow separate routes for http/https on the same ip:port.
 * The type and domain are included to differentiate between IP and domain routes.
 */
function getRouteKey(route: Route): string {
  const scheme = route.scheme || 'https';
  const type = route.type || 'ip';
  const domain = route.domain || '';
  return `${route.ip}:${route.port}:${scheme}:${type}:${domain}`;
}

/**
 * Register or update routes for a user.
 * Merges new routes with existing routes based on ip:port as unique identifier.
 * This allows multiple sources (agent, tunnel) to register routes independently.
 *
 * @param userId - The user ID
 * @param routes - Array of routes to register/update
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

  // Get existing routes to merge with
  const existingValue = await redis.get(key);
  let existingRoutes: Route[] = [];

  if (existingValue) {
    try {
      existingRoutes = JSON.parse(existingValue) as Route[];
    } catch {
      // Invalid data, start fresh
      existingRoutes = [];
    }
  }

  // Filter out existing routes that have the same source as incoming routes
  // This ensures routes from the same source replace each other entirely
  const incomingSources = new Set(routes.map(r => r.source));
  existingRoutes = existingRoutes.filter(r => !incomingSources.has(r.source));

  // Create a map of existing routes by ip:port
  const routeMap = new Map<string, Route>();
  for (const route of existingRoutes) {
    routeMap.set(getRouteKey(route), route);
  }

  // Merge/update with new routes
  for (const route of routes) {
    routeMap.set(getRouteKey(route), route);
  }

  // Convert back to array
  const mergedRoutes = Array.from(routeMap.values());
  const value = JSON.stringify(mergedRoutes);

  await redis.setex(key, getRoutesTtl(), value);

  // Update activity tracking in Redis
  await updateActivityTracking(userId);
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

// ============================================================================
// Domain Activity Tracking
// ============================================================================

/**
 * Update activity tracking for a user.
 * Called when routes are registered to track the last activity time.
 *
 * @param userId - The user ID
 */
export async function updateActivityTracking(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  await redis.zadd(ACTIVITY_KEY, Date.now(), userId);
}

/**
 * Get user IDs that have been active within the specified number of days.
 *
 * @param inactiveDays - Number of days to consider active (default: from config)
 * @returns Array of user IDs that are active
 */
export async function getActiveUserIds(inactiveDays?: number): Promise<string[]> {
  const days = inactiveDays ?? getInactiveDomainDays();
  const threshold = Date.now() - (days * 24 * 60 * 60 * 1000);

  const redis = getRedisClient();
  return redis.zrangebyscore(ACTIVITY_KEY, threshold, '+inf');
}

/**
 * Get user IDs that have been inactive for more than the specified number of days.
 *
 * @param inactiveDays - Number of days of inactivity (default: from config)
 * @returns Array of user IDs that are inactive
 */
export async function getInactiveUserIds(inactiveDays?: number): Promise<string[]> {
  const days = inactiveDays ?? getInactiveDomainDays();
  const threshold = Date.now() - (days * 24 * 60 * 60 * 1000);

  const redis = getRedisClient();
  return redis.zrangebyscore(ACTIVITY_KEY, 0, threshold);
}

/**
 * Remove a user from activity tracking.
 * Called during domain cleanup.
 *
 * @param userId - The user ID to remove
 */
export async function removeFromActivityTracking(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  await redis.zrem(ACTIVITY_KEY, userId);
}

/**
 * Get the last activity timestamp for a user.
 *
 * @param userId - The user ID
 * @returns Timestamp in milliseconds, or null if not found
 */
export async function getActivityTimestamp(userId: string): Promise<number | null> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const score = await redis.zscore(ACTIVITY_KEY, userId);

  return score !== null ? parseInt(score, 10) : null;
}
