import { generateKeyPair, sign } from "../library/KeyLib.js";
import { getFirestore } from "firebase-admin/firestore";
import { NSL_ROUTER_COLLECTION, NSLRouterData } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { getRedisClient } from "../redis/redisClient.js";
import { deleteRoutes, getRoutes, getRoutesTTL, Route } from "../services/Routes.js";

// Test user prefix to identify test data (alphanumeric only for domain validation)
export const TEST_USER_PREFIX = "testuser";
// Test server domain - must match SERVER_DOMAIN env var set in test-app.ts
// The API returns SERVER_DOMAIN from env, not from database (DB value is informational only)
export const TEST_SERVER_DOMAIN = "test.example.com";

/**
 * Generate a unique test user ID (alphanumeric only to pass domain validation)
 */
export function generateTestUserId(): string {
  const timestamp = Date.now().toString(36); // Convert to base36 for shorter string
  const random = Math.random().toString(36).substring(2, 8);
  return `${TEST_USER_PREFIX}${timestamp}${random}`;
}

/**
 * Create a test user with keypair in Firebase
 * The domainName is the userId itself (alphanumeric, valid for domain)
 */
export async function createTestUser(userId: string): Promise<{ publicKey: string; privateKey: string }> {
  const keyPair = await generateKeyPair();

  const userData: NSLRouterData = {
    domainName: userId, // userId is now alphanumeric and valid as domain
    serverDomain: TEST_SERVER_DOMAIN,
    publicKey: keyPair.pub,
  };

  await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId).set(userData);

  return {
    publicKey: keyPair.pub,
    privateKey: keyPair.priv,
  };
}

/**
 * Sign a message with a private key
 */
export async function signMessage(privateKey: string, message: string): Promise<string> {
  return sign(privateKey, message);
}

/**
 * Delete a test user from Firebase
 */
export async function deleteTestUser(userId: string): Promise<void> {
  await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId).delete();
}

/**
 * Clean up all test users (those with TEST_USER_PREFIX)
 */
export async function cleanupAllTestUsers(): Promise<void> {
  const snapshot = await getFirestore()
    .collection(NSL_ROUTER_COLLECTION)
    .where("domainName", ">=", "")
    .get();

  const batch = getFirestore().batch();
  let count = 0;

  snapshot.docs.forEach((doc) => {
    if (doc.id.startsWith(TEST_USER_PREFIX)) {
      batch.delete(doc.ref);
      count++;
    }
  });

  if (count > 0) {
    await batch.commit();
    console.log(`[Test Cleanup] Deleted ${count} test users`);
  }
}

/**
 * Get test user data from Firebase
 */
export async function getTestUserData(userId: string): Promise<NSLRouterData | null> {
  const doc = await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId).get();
  return doc.exists ? (doc.data() as NSLRouterData) : null;
}

/**
 * Get routes from Redis for a test user
 */
export async function getTestUserRoutes(userId: string): Promise<Route[] | null> {
  return getRoutes(userId);
}

/**
 * Delete routes from Redis for a test user
 */
export async function deleteTestUserRoutes(userId: string): Promise<void> {
  try {
    await deleteRoutes(userId);
  } catch {
    // Ignore if routes don't exist
  }
}

/**
 * Clean up all test routes from Redis (those with TEST_USER_PREFIX)
 */
export async function cleanupAllTestRoutes(): Promise<void> {
  const redis = getRedisClient();
  const keys = await redis.keys(`routes:${TEST_USER_PREFIX}*`);

  if (keys.length > 0) {
    await redis.del(...keys);
    console.log(`[Test Cleanup] Deleted ${keys.length} test route entries from Redis`);
  }
}

/**
 * Get TTL for routes from Redis for a test user
 * @returns TTL in seconds, -1 if no TTL, -2 if key doesn't exist
 */
export async function getTestUserRoutesTTL(userId: string): Promise<number> {
  return getRoutesTTL(userId);
}

/**
 * Get TTL for a specific source's routes in Redis
 * @returns TTL in seconds, -1 if no TTL, -2 if key doesn't exist
 */
export async function getTestUserSourceTTL(userId: string, source: string): Promise<number> {
  const redis = getRedisClient();
  return redis.ttl(`routes:${userId}:${source}`);
}

/**
 * Clean up usage (DAU) keys for a specific test app/uid/date.
 * Targeted so it never touches real usage data: removes the per-app DAU set and
 * per-user set entirely, and prunes the test entries from the shared daily sets.
 */
export async function cleanupTestUsage(app: string, uid: string, date: string): Promise<void> {
  const redis = getRedisClient();
  await redis.del(`usage:dau:${app}:${date}`, `usage:user:${uid}:${date}`);
  await redis.srem(`usage:apps:${date}`, app);
  await redis.srem(`usage:active:${date}`, uid);
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
