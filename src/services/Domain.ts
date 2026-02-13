import {NSL_ROUTER_COLLECTION, NSLRouterData} from "../DataBaseDTO/DataBaseNSLRouter.js";
import admin from "firebase-admin";

//https://www.nic.ad.jp/timeline/en/20th/appendix1.html#:~:text=Format%20of%20a%20domain%20name,a%20maximum%20of%20253%20characters.

/**
 * Validates a domain name according to standard naming conventions.
 * Rules:
 * - Must start with a letter or number
 * - Can contain only lower case letters and numbers
 * - Must be between 1 and 63 characters long
 * @param domain - The domain name to validate
 * @returns An object containing validation result and error message if any
 */
function validateDomainName(domain: string): { isValid: boolean; message: string } {
  if (!domain) {
    return { isValid: false, message: "Domain name cannot be empty." };
  }

  if (domain.length > 63) {
    return { isValid: false, message: "Domain name cannot be longer than 63 characters." };
  }

  // Check if domain contains only valid characters (lowercase letters and numbers)
  // This regex implicitly ensures the first character is also a letter or number
  const validCharRegex = /^[a-z0-9]+$/;
  if (!validCharRegex.test(domain)) {
    return {
      isValid: false,
      message: "Domain name can only contain lowercase letters and numbers."
    };
  }

  return { isValid: true, message: "Domain name is valid." };
}

/**
 * Checks the availability of a given domain name.
 * @param domain - The domain name to check. (just the subdomain part of the domain xxx.domain.com
 * @returns A promise that resolves to true if available, false otherwise.
 */
export async function getDomain(domain: string): Promise<{ uid: string, domain: NSLRouterData }> {
  if (!domain) {
    throw new Error("Domain name is required for availability check.");
  }

  const validation = validateDomainName(domain);
  if (!validation.isValid) {
    throw new Error(validation.message);
  }

  const nslRouterCollection = admin.firestore().collection(NSL_ROUTER_COLLECTION);
  const querySnapshot = await nslRouterCollection.where('domainName', '==', domain).get();

  if (querySnapshot.empty) {
    return null;
  } else {
    return {
      uid: querySnapshot.docs[0].id,
      domain: querySnapshot.docs[0].data() as NSLRouterData
    };
  }
}

const RESERVED_DOMAINS = ["root", "app", "www"];

/**
 * Checks if a domain name is available.
 * @param domain - The domain name to check
 * @returns Promise<{ available: boolean, message: string }>
 */
export async function checkDomainAvailability(domain: string): Promise<{ available: boolean, message: string }> {
  if (!domain) {
    throw new Error("Domain name is required.");
  }

  const validation = validateDomainName(domain);
  if (!validation.isValid) {
    return { available: false, message: validation.message };
  }

  if (RESERVED_DOMAINS.includes(domain)) {
    return { available: false, message: "Domain name is not available." };
  }

  const existingDomain = await getDomain(domain);
  return {
    available: existingDomain === null,
    message: existingDomain === null ? "Domain name is available." : "Domain name is not available."
  };
}

/**
 * Gets domain information for a specific user.
 * @param userId - The user ID
 * @returns Promise<NSLRouterData>
 */
export async function getUserDomain(userId: string): Promise<NSLRouterData | null> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const userDoc = await admin.firestore().collection(NSL_ROUTER_COLLECTION).doc(userId).get();
  return userDoc.exists ? userDoc.data() as NSLRouterData : null;
}

/**
 * Updates or creates domain information for a user.
 * @param userId - The user ID
 * @param domainData - The domain data to update
 */
export async function updateUserDomain(
  userId: string,
  domainData: Partial<NSLRouterData>
): Promise<void> {
  const { domainName } = domainData;

  // 2 possibility for domain update/create
  // 1. domain creation => domain must be available
  // 2. domain update => domain must be owned by the user (check with uid)
  // note that 1 user = 0-1 domain (no multiple domain per user)
  if (domainName) {
    const validation = validateDomainName(domainName);
    if (!validation.isValid) {
      throw new Error(validation.message);
    }

    const domain = await getDomain(domainName);
    const isAvailable = domain === null;
    const isOwned = domain?.uid === userId;

    if (!isAvailable && !isOwned) {
      throw new Error(domain ? "Domain name is not owned by you." : "Domain name is already in use.");
    }
  }

  // Clean the data by removing undefined values before sending to Firestore
  const cleanedData = Object.fromEntries(
    Object.entries(domainData).filter(([_, value]) => value !== undefined)
  );

  // Additional validation to ensure required fields are present
  if (Object.keys(cleanedData).length === 0) {
    throw new Error("No valid data provided for update");
  }

  const userDocRef = admin.firestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
  await userDocRef.set(cleanedData, { merge: true });
}

/**
 * Deletes domain information for a user.
 * @param userId - The user ID
 */
export async function deleteUserDomain(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  await admin.firestore().collection(NSL_ROUTER_COLLECTION).doc(userId).delete();
}

/**
 * Updates the lastRouteRegistration timestamp for a user.
 * Called when routes are registered via POST /routes.
 * @param userId - The user ID
 * @returns The updated timestamp
 */
export async function updateLastRouteRegistration(userId: string): Promise<string> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const lastRouteRegistration = new Date().toISOString();
  const userDocRef = admin.firestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
  await userDocRef.update({ lastRouteRegistration });

  return lastRouteRegistration;
}

/**
 * Clears domain assignment fields (domainName, publicKey) for a user.
 * Used during domain cleanup to release inactive domains.
 * Keeps the user document but removes domain assignment.
 * @param userId - The user ID
 */
export async function clearDomainAssignment(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const userDocRef = admin.firestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
  await userDocRef.update({
    domainName: admin.firestore.FieldValue.delete(),
    publicKey: admin.firestore.FieldValue.delete(),
  });
}

/**
 * Gets all user domains from Firestore.
 * Used for listing active domains.
 * @returns Array of user documents with their IDs
 */
export async function getAllUserDomains(): Promise<Array<{ userId: string; data: NSLRouterData }>> {
  const snapshot = await admin.firestore().collection(NSL_ROUTER_COLLECTION).get();
  return snapshot.docs
    .filter(doc => doc.data().domainName) // Only return docs with a domain
    .map(doc => ({
      userId: doc.id,
      data: doc.data() as NSLRouterData,
    }));
}

/**
 * Validates an IPv4 address.
 * @param ip - The IP address to validate
 * @returns true if valid IPv4, false otherwise
 */
function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

/**
 * Validates an IPv6 address.
 * Handles full, compressed (::), and mixed IPv4 formats.
 * @param ip - The IP address to validate
 * @returns true if valid IPv6, false otherwise
 */
function isValidIPv6(ip: string): boolean {
  // Check for valid hex characters and colons only
  if (!/^[0-9a-fA-F:]+$/.test(ip) && !/^[0-9a-fA-F:.]+$/.test(ip)) {
    return false;
  }

  // Handle :: compression - can only appear once
  const doubleColonCount = (ip.match(/::/g) || []).length;
  if (doubleColonCount > 1) {
    return false;
  }

  // Split by :: to handle compressed format
  if (ip.includes('::')) {
    const parts = ip.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];

    // Total groups must be <= 8
    if (left.length + right.length > 7) {
      return false;
    }

    // Validate each group
    const allGroups = [...left, ...right];
    return allGroups.every(group =>
      group === '' || (/^[0-9a-fA-F]{1,4}$/.test(group))
    );
  }

  // No compression - must have exactly 8 groups
  const groups = ip.split(':');
  if (groups.length !== 8) {
    return false;
  }

  return groups.every(group => /^[0-9a-fA-F]{1,4}$/.test(group));
}

/**
 * Validates an IP address (IPv4 or IPv6).
 * @param ip - The IP address to validate
 * @returns true if valid, false otherwise
 */
function isValidIpAddress(ip: string): boolean {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

/**
 * Updates the lastSeenOnline timestamp for a user (heartbeat).
 * @param userId - The user ID
 * @returns The updated timestamp
 */
export async function updateHeartbeat(userId: string): Promise<string> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const userData = await getUserDomain(userId);
  if (!userData) {
    throw new Error("User not found. Register a domain first.");
  }

  const lastSeenOnline = new Date().toISOString();
  const userDocRef = admin.firestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
  await userDocRef.update({ lastSeenOnline });

  return lastSeenOnline;
}

/**
 * Default threshold in seconds to consider a user offline.
 * If no heartbeat received within this time, user is considered offline.
 */
const DEFAULT_OFFLINE_THRESHOLD_SECONDS = 120; // 2 minutes

/**
 * Checks if a user is currently online based on their lastSeenOnline timestamp.
 * @param userId - The user ID
 * @param thresholdSeconds - Optional threshold in seconds (default: 120 seconds / 2 minutes)
 * @returns Online status with lastSeenOnline timestamp
 */
export async function checkOnlineStatus(
  userId: string,
  thresholdSeconds: number = DEFAULT_OFFLINE_THRESHOLD_SECONDS
): Promise<{ online: boolean; lastSeenOnline: string | null }> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const userData = await getUserDomain(userId);
  if (!userData) {
    throw new Error("User not found.");
  }

  const lastSeenOnline = userData.lastSeenOnline ?? null;

  if (!lastSeenOnline) {
    return { online: false, lastSeenOnline: null };
  }

  const lastSeenDate = new Date(lastSeenOnline);
  const now = new Date();
  const diffSeconds = (now.getTime() - lastSeenDate.getTime()) / 1000;

  return {
    online: diffSeconds <= thresholdSeconds,
    lastSeenOnline
  };
}