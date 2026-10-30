import {NSL_ROUTER_COLLECTION, NSLRouterData} from "../DataBaseDTO/DataBaseNSLRouter.js";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { dropUserZone, isUserZonesEnabled } from "./DnsZones.js";

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

  const nslRouterCollection = getFirestore().collection(NSL_ROUTER_COLLECTION);
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

// Labels the zone itself needs (nameservers, ip.<zone>, gateway, mail, ACME, …).
// Only names that pass validateDomainName are listed: dashed ones can't be users anyway.
// Static-zone labels from the Cloudflare export get added here when the zone file exists.
const RESERVED_DOMAINS = [
  "root", "app", "www",
  "ip", "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "ns7", "ns8", "ns9",
  "gw", "gateway", "mail", "acme", "router", "s1", "s2", "dns", "entrypoint",
  // The zone's mail aliases (doc/USER_MAIL.md §2.1): <user>@<zone> must never be one of them.
  "contact", "admin", "abuse", "postmaster", "dmarc",
];

export function isReservedDomain(domain: string): boolean {
  return RESERVED_DOMAINS.includes(domain);
}

/** Why a name is not available, so clients don't have to parse `message`. */
export type DomainUnavailableReason = "invalid" | "reserved" | "taken";

/**
 * Checks if a domain name is available.
 * @param domain - The domain name to check
 * @returns Promise<{ available: boolean, message: string, reason?: DomainUnavailableReason }> - `reason` is set only when unavailable
 */
export async function checkDomainAvailability(domain: string): Promise<{ available: boolean, message: string, reason?: DomainUnavailableReason }> {
  if (!domain) {
    throw new Error("Domain name is required.");
  }

  const validation = validateDomainName(domain);
  if (!validation.isValid) {
    return { available: false, message: validation.message, reason: "invalid" };
  }

  if (isReservedDomain(domain)) {
    return { available: false, message: "Domain name is not available.", reason: "reserved" };
  }

  const existingDomain = await getDomain(domain);
  if (existingDomain !== null) {
    return { available: false, message: "Domain name is not available.", reason: "taken" };
  }
  return { available: true, message: "Domain name is available." };
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

  const userDoc = await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId).get();
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
  let previous: string | undefined; // the name a renaming user had: its zone goes
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

    // A holder of a name reserved after the fact keeps it (key rotation re-posts it)
    if (!isOwned && isReservedDomain(domainName)) {
      throw new Error("Domain name is not available.");
    }
    if (isAvailable) previous = (await getUserDomain(userId))?.domainName;
  }

  // Clean the data by removing undefined values before sending to Firestore
  const cleanedData = Object.fromEntries(
    Object.entries(domainData).filter(([_, value]) => value !== undefined)
  );

  // Additional validation to ensure required fields are present
  if (Object.keys(cleanedData).length === 0) {
    throw new Error("No valid data provided for update");
  }

  const userDocRef = getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
  await userDocRef.set(cleanedData, { merge: true });
  if (previous && previous.toLowerCase() !== domainName.toLowerCase()) {
    // the new name is not delegated yet: dormant until the live check says otherwise
    await userDocRef.update({ "dns.live": FieldValue.delete() });
    releaseZone(previous);
  }
}

/** Drop the zone of a label that is gone (fire and forget: never fails the caller). */
function releaseZone(label: string | undefined): void {
  if (!label || !isUserZonesEnabled()) return;
  dropUserZone(label).catch((e) => console.error(`[dns] ${label}: zone removal failed: ${e.message ?? e}`));
}

/**
 * Deletes domain information for a user.
 * @param userId - The user ID
 */
export async function deleteUserDomain(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const label = (await getUserDomain(userId))?.domainName;
  await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId).delete();
  releaseZone(label);
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
  const userDocRef = getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
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

  const label = (await getUserDomain(userId))?.domainName;
  const userDocRef = getFirestore().collection(NSL_ROUTER_COLLECTION).doc(userId);
  await userDocRef.update({
    domainName: FieldValue.delete(),
    publicKey: FieldValue.delete(),
    "dns.live": FieldValue.delete(),
  });
  releaseZone(label);
}

/**
 * Gets all user domains from Firestore.
 * Used for listing active domains.
 * @returns Array of user documents with their IDs
 */
export async function getAllUserDomains(): Promise<Array<{ userId: string; data: NSLRouterData }>> {
  const snapshot = await getFirestore().collection(NSL_ROUTER_COLLECTION).get();
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
 * Default threshold in seconds to consider a user offline.
 * Routes refresh every ~300s (agent + tunnel), so 660s gives margin for one missed refresh.
 */
const DEFAULT_OFFLINE_THRESHOLD_SECONDS = 660;

/**
 * Checks if a user is currently online based on their lastRouteRegistration timestamp.
 * A user is online if routes were registered within the threshold period.
 * @param userId - The user ID
 * @param thresholdSeconds - Optional threshold in seconds (default: 660 seconds)
 * @returns Online status with lastSeenOnline timestamp (uses lastRouteRegistration as source)
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

  const lastSeenOnline = userData.lastRouteRegistration ?? null;

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