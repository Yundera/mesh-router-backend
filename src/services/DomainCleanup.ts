import { getInactiveDomainDays } from "../configuration/config.js";
import { getInactiveUserIds, removeFromActivityTracking, getActivityTimestamp } from "./Routes.js";
import { getUserDomain, clearDomainAssignment } from "./Domain.js";
import { logDomainReleased } from "./DomainLogger.js";

export interface CleanupResult {
  releasedCount: number;
  domains: string[];
}

/**
 * Runs the domain cleanup process.
 * Identifies inactive domains and releases them.
 *
 * Steps:
 * 1. Get inactive userIds from Redis (sorted set)
 * 2. For each userId:
 *    a. Fetch domain from Firestore
 *    b. Log RELEASED event
 *    c. Clear domain fields (domainName, publicKey)
 *    d. Remove from Redis activity set
 * 3. Return summary
 */
export async function runCleanup(): Promise<CleanupResult> {
  const inactiveDays = getInactiveDomainDays();
  const releasedDomains: string[] = [];

  console.log(`Starting domain cleanup (inactivity threshold: ${inactiveDays} days)`);

  // Get inactive user IDs from Redis
  const inactiveUserIds = await getInactiveUserIds(inactiveDays);

  console.log(`Found ${inactiveUserIds.length} potentially inactive users`);

  for (const userId of inactiveUserIds) {
    try {
      // Fetch domain info from Firestore
      const userData = await getUserDomain(userId);

      if (!userData || !userData.domainName) {
        // User doesn't have a domain, just clean up Redis
        await removeFromActivityTracking(userId);
        continue;
      }

      const domainName = userData.domainName;

      // Calculate actual inactive days for logging
      const activityTimestamp = await getActivityTimestamp(userId);
      const actualInactiveDays = activityTimestamp
        ? Math.floor((Date.now() - activityTimestamp) / (24 * 60 * 60 * 1000))
        : inactiveDays;

      // Log the release event
      logDomainReleased(domainName, userId, actualInactiveDays);

      // Clear domain assignment in Firestore (keeps user doc)
      await clearDomainAssignment(userId);

      // Remove from Redis activity tracking
      await removeFromActivityTracking(userId);

      releasedDomains.push(domainName);
      console.log(`Released domain: ${domainName} (user: ${userId}, inactive: ${actualInactiveDays} days)`);

    } catch (error) {
      console.error(`Error processing user ${userId} during cleanup:`, error);
      // Continue with other users even if one fails
    }
  }

  console.log(`Domain cleanup complete: ${releasedDomains.length} domains released`);

  return {
    releasedCount: releasedDomains.length,
    domains: releasedDomains,
  };
}
