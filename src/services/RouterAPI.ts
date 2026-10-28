import express, { Request } from "express";
import {verifySignature} from "../library/KeyLib.js";
import {authenticate, authenticateService, AuthUserRequest} from "./ExpressAuthenticateMiddleWare.js";
import {checkDomainAvailability, deleteUserDomain, getUserDomain, updateUserDomain, checkOnlineStatus, getDomain, updateLastRouteRegistration, getAllUserDomains} from "./Domain.js";
import {getServerDomain, getInactiveDomainDays, getDnsIpZone, getDnsGatewayIps, getTunnelProviders} from "../configuration/config.js";
import {registerRoutes, getRoutes, deleteRoutes, Route, getRoutesTTL, getActiveUserIds, getActivityTimestamp} from "./Routes.js";
import {validateRoutes, normalizeRoute} from "./RouteValidator.js";
import {getCACertificate, signCSR, isCAInitialized} from "./CertificateAuthority.js";
import {logDomainAssigned} from "./DomainLogger.js";
import {runCleanup} from "./DomainCleanup.js";
import {probeCandidates, checkRateLimit, PROBE_LIMITS} from "./Probe.js";
import {recordUsage, UsageEvent, MAX_USAGE_EVENTS_PER_REQUEST} from "./Usage.js";
import {noteRoutes, onRegistration, isUserZonesEnabled, viewUser, isInScope, isLive, resyncUser, setForce, setCaaAccounts, isAcmeAccountUri, MAX_CAA_ACCOUNTS} from "./DnsZones.js";
import {hopName, acceptsProxyProtocol, setProxyProtocol} from "./HopNames.js";
import {getDnsHealth, httpStatusFor} from "./DnsHealth.js";
import {NSLRouterData} from "../DataBaseDTO/DataBaseNSLRouter.js";
import {acmeLabelFromFqdn, addAcmeTxt, isAcmeTxtValue, removeAcmeTxt, takeAcmeUpdate} from "./AcmeDns.js";
import {verifyEmailCredential, sendUserEmail, EmailError, EmailSendRequest} from "./Email.js";
import { getAuth } from "firebase-admin/auth";

/**
 * Logs authentication failures with relevant context for security monitoring.
 */
function logAuthFailure(req: Request, reason: string, context: Record<string, unknown> = {}): void {
  const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || 'unknown';

  console.warn('AUTH_FAILURE', {
    reason,
    clientIp,
    userAgent,
    method: req.method,
    path: req.path,
    ...context,
  });
}

/**
 * What our nameservers do for a user (the `dns` block of /resolve/v2 and /domains/active),
 * or undefined when user zones are off. `live` = the parent zone delegates to us.
 */
async function dnsSummary(uid: string, data: NSLRouterData, routes: Route[] | null) {
  if (!isUserZonesEnabled()) return undefined;
  const view = await viewUser({ uid, label: data.domainName, dns: data.dns }, routes);
  return {
    delegated: !!data.dns?.delegated,
    live: !!data.dns?.delegated && await isLive(data.domainName),
    force: data.dns?.force ?? "auto",
    hostForce: data.dns?.hostForce ?? {},
    answer: view.answer.kind,
    reason: view.answer.reason,
    certNotAfter: view.probe?.cert === "trusted" ? view.probe.notAfter ?? null : null,
  };
}

/**
 * lego's httpreq client only sends Basic auth: accept the service key as its password,
 * beside the usual `Bearer <SERVICE_API_KEY>`.
 */
function authenticateServiceOrBasic(req: Request, res: express.Response, next: express.NextFunction) {
  const header = req.get('Authorization') || '';
  const key = process.env.SERVICE_API_KEY;
  if (key && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString();
    if (decoded.slice(decoded.indexOf(':') + 1) === key) return next();
  }
  return authenticateService(req, res, next);
}

/*
full domain = domainName+"."+serverDomain
model
nsl-router/%uid%
- domainName:string // eg foo
- serverDomain:string // informational only - API returns SERVER_DOMAIN env var
- publicKey:string

Note: serverDomain is returned from SERVER_DOMAIN environment variable, not from database.
The database field is kept for informational/audit purposes only.
*/

export function routerAPI(expressApp: express.Application) {
  let router = express.Router();

  /**
   * GET /version
   * Returns API version information for client compatibility checks.
   * Clients should check this endpoint before connecting to ensure compatibility.
   * ipZone is the zone a box's IP names live in (<ip-dashed>.<ipZone>): the agent
   * registers its routes there and the box template routes apps on it. Absent when
   * the deployment runs no nameserver, which leaves boxes with no direct route.
   * gatewayIps are the gateways' public IPv4s (DNS_GATEWAY_IPS): the box's Caddy accepts a
   * PROXY header only from them. Absent when unset.
   * tunnelProviders are the tunnel providers' registration URLs (TUNNEL_PROVIDERS): a box's
   * tunnel connects to each of them besides its own PROVIDER, so a NAT box stays reachable
   * through every gateway's host. Absent when unset.
   */
  router.get('/version', (req, res) => {
    const ipZone = getDnsIpZone();
    const gatewayIps = getDnsGatewayIps();
    const tunnelProviders = getTunnelProviders();
    return res.status(200).json({
      version: 2,
      minClientVersion: 2,
      serverDomain: process.env.SERVER_DOMAIN || 'unknown',
      ...(ipZone ? { ipZone } : {}),
      ...(gatewayIps.length ? { gatewayIps } : {}),
      ...(tunnelProviders.length ? { tunnelProviders } : {}),
    });
  });

  /**
   * GET /available/:domain
   * Checks if a domain name is available.
   */
  router.get('/available/:domain', async (req, res) => {
    try {
      const domain = req.params.domain.trim();
      const availability = await checkDomainAvailability(domain);
      return res.status(availability.available ? 200 : 209).json(availability);
    } catch (error) {
      console.error("Error in /available/:domain:", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  //used by mesh router
  router.get('/verify/:userid/:sig', async (req, res) => {
    const {userid, sig} = req.params;
    try {
      const userData = await getUserDomain(userid);

      if (userData) {
        let isValid = false;
        try {
          isValid = await verifySignature(userData.publicKey, sig, userid);
        } catch (e) {
          // Invalid signature format (e.g., non-base36 characters)
          console.log('Invalid signature format for verify', { userid, error: e.message });
          return res.json({ valid: false });
        }
        console.log('Verifying signature for', req.params, isValid);

        if (isValid) {
          res.json({
            serverDomain: getServerDomain(),
            domainName: userData.domainName
          });
        } else {
          res.json({ valid: false });
        }
      } else {
        res.json({ error: "unknown user" });
      }
    } catch (error) {
      res.json({ error: error.toString() });
    }
  });

  /**
   * GET /user/email/:userid/:sig
   * Returns the account email for the user, read live from Firebase Auth.
   * Authenticated by the same Ed25519 signature scheme as route registration
   * (sign(userid) with the private key whose public key is stored for the user).
   * Used by the PCS self-check (ensure-email-synced.sh) to expose the real
   * account email to installed apps via ${APP_EMAIL}.
   */
  router.get('/user/email/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    try {
      const userData = await getUserDomain(userid);
      if (!userData) {
        return res.status(404).json({ error: "User not found." });
      }

      let isValid = false;
      try {
        isValid = await verifySignature(userData.publicKey, sig, userid);
      } catch (e) {
        console.log('Invalid signature format for user email lookup', { userid, error: e.message });
        return res.status(401).json({ error: "Invalid signature." });
      }
      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'user_email' });
        return res.status(401).json({ error: "Invalid signature." });
      }

      // Firebase Auth is the authoritative source of the account email.
      let email: string | undefined;
      try {
        const userRecord = await getAuth().getUser(userid);
        email = userRecord.email;
      } catch (e) {
        return res.status(404).json({ error: "No Firebase user for this id." });
      }
      if (!email) {
        return res.status(404).json({ error: "No email on file for this user." });
      }

      return res.status(200).json({ email });
    } catch (error) {
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * GET /domain/:userid
   * Retrieves the domain information for the specified user.
   */
  router.get('/domain/:userid', async (req, res) => {
    try {
      const userData = await getUserDomain(req.params.userid);

      if (!userData) {
        return res.status(280).json({ error: "User not found." });
      }

      return res.status(200).json({
        domainName: userData.domainName,
        serverDomain: getServerDomain(),
        publicKey: userData.publicKey
      });
    } catch (error) {
      console.error(error.toString());
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * POST /domain/:userid
   * Updates or sets the domain information for the specified user.
   * Requires authentication.
   */
  router.post('/domain', authenticate, async (req: AuthUserRequest, res) => {
    const { domainName, serverDomain, publicKey } = req.body ?? {};

    try {
      if (!domainName && !publicKey) {
        return res.status(400).json({ error: "At least 'domainName' or 'publicKey' must be provided." });
      }

      await updateUserDomain(req.user.uid, {
        domainName,
        serverDomain,
        publicKey
      });

      // Log domain assignment if a new domain name was set
      if (domainName) {
        logDomainAssigned(domainName, req.user.uid);
      }

      return res.status(200).json({ message: "Domain information updated successfully." });
    } catch (error) {
      console.error("Error in POST /domain", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  router.delete('/domain', authenticate, async (req: AuthUserRequest, res) => {
    try {
      await deleteUserDomain(req.user.uid);
      return res.status(200).json({ message: "Domain information deleted successfully." });
    } catch (error) {
      console.error("Error in DELETE /domain", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * GET /status/:userid
   * Checks if a user is online based on their lastSeenOnline timestamp.
   * Returns online status and the lastSeenOnline timestamp.
   */
  router.get('/status/:userid', async (req, res) => {
    const { userid } = req.params;

    try {
      const status = await checkOnlineStatus(userid);

      return res.status(200).json(status);
    } catch (error) {
      if (error.message === "User not found.") {
        return res.status(404).json({ error: error.message });
      }
      console.error("Error in GET /status/:userid", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // Routes v2 API - Multi-route support with Redis storage
  // ============================================================================

  /**
   * POST /routes/:userid/:sig
   * Register or update routes for a user.
   * Routes are stored in Redis with a TTL (refreshed on each call).
   *
   * Body: { routes: [{ ip, port, priority, source, scheme?, type?, domain?, tunnelIp? }] }
   *   - ip: string - IP address of the route endpoint
   *   - port: number - Port number (1-65535)
   *   - priority: number - Lower = higher priority (1 = direct, 2 = tunnel)
   *   - source: string - Source identifier (e.g., "agent", "tunnel")
   *   - scheme: "http" | "https" - Protocol scheme (optional, default: "https")
   *   - type: "ip" | "domain" - Route type (optional, default: "ip")
   *   - domain: string - Domain hostname (required when type="domain")
   *
   * The signature must be a valid Ed25519 signature of the userid.
   */
  router.post('/routes/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    const { routes } = req.body;

    try {
      if (!routes || !Array.isArray(routes) || routes.length === 0) {
        return res.status(400).json({ error: "routes array is required in request body." });
      }

      const userData = await getUserDomain(userid);

      if (!userData) {
        return res.status(404).json({ error: "User not found. Register a domain first." });
      }

      // Verify signature using stored public key
      let isValid = false;
      try {
        isValid = await verifySignature(userData.publicKey, sig, userid);
      } catch (e) {
        console.log('Invalid signature format for routes registration', { userid, error: e.message });
        return res.status(401).json({ error: "Invalid signature." });
      }

      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'routes_registration' });
        return res.status(401).json({ error: "Invalid signature." });
      }

      // Validate and normalize routes
      const validatedRoutes: Route[] = routes.map((r: any, index: number) => normalizeRoute(r, index));

      // Validate routes - all routes are validated for connectivity
      const { accepted, rejected } = await validateRoutes(validatedRoutes);

      // One-line summary for successful registrations
      if (accepted.length > 0) {
        const summary = accepted.map(({ route }) => {
          const host = route.type === 'domain' ? route.domain : route.ip;
          return `${route.scheme || 'https'}://${host}:${route.port}`;
        }).join(', ');
        console.log(`[${userid}] ✓ ${accepted.length}/${accepted.length + rejected.length} routes accepted: ${summary}`);
      }
      // One line per failure with detail
      for (const { route, error, url } of rejected) {
        const routeDesc = route.type === 'domain' ? route.domain : `${route.ip}:${route.port}`;
        console.log(`[${userid}] ✗ REJECT ${route.source}/${route.scheme || 'https'} ${routeDesc} - ${error} ${url || ''}`);
      }

      if (accepted.length === 0) {
        return res.status(400).json({
          error: "All routes failed validation",
          rejected: rejected.map(r => ({
            ip: r.route.ip,
            port: r.route.port,
            type: r.route.type,
            domain: r.route.domain,
            error: r.error,
          })),
        });
      }

      // Extract just the routes for storage
      const routesToStore = accepted.map(a => a.route);
      await registerRoutes(userid, routesToStore);

      // Update lastRouteRegistration in Firestore
      await updateLastRouteRegistration(userid);

      // ip.<zone> allowlist: a failing nameserver primary must not fail the registration
      noteRoutes(routesToStore).catch((e) => console.error(`[dns] [${userid}] allowlist update failed: ${e.message ?? e}`));
      // the user's own zone, when our nameservers serve it (delegated, or shadow mode)
      onRegistration(userid, userData).catch((e) => console.error(`[dns] [${userid}] zone update failed: ${e.message ?? e}`));

      return res.status(200).json({
        message: "Routes registered successfully.",
        routes: routesToStore,
        rejected: rejected.length > 0 ? rejected.map(r => ({
          ip: r.route.ip,
          port: r.route.port,
          type: r.route.type,
          domain: r.route.domain,
          error: r.error,
        })) : undefined,
        domain: `${userData.domainName}.${getServerDomain()}`
      });
    } catch (error) {
      console.error("Error in POST /routes/:userid/:sig", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * DELETE /routes/:userid/:sig
   * Delete all routes for a user.
   *
   * The signature must be a valid Ed25519 signature of the userid.
   */
  router.delete('/routes/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;

    try {
      const userData = await getUserDomain(userid);

      if (!userData) {
        return res.status(404).json({ error: "User not found." });
      }

      // Verify signature using stored public key
      let isValid = false;
      try {
        isValid = await verifySignature(userData.publicKey, sig, userid);
      } catch (e) {
        console.log('Invalid signature format for routes deletion', { userid, error: e.message });
        return res.status(401).json({ error: "Invalid signature." });
      }

      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'routes_deletion' });
        return res.status(401).json({ error: "Invalid signature." });
      }

      await deleteRoutes(userid);

      console.log('Routes deleted', { userid });

      return res.status(200).json({
        message: "Routes deleted successfully."
      });
    } catch (error) {
      console.error("Error in DELETE /routes/:userid/:sig", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * GET /routes/:userid
   * Get the current routes for a user (public, no auth required).
   * Useful for debugging and monitoring.
   */
  router.get('/routes/:userid', async (req, res) => {
    const { userid } = req.params;

    try {
      const routes = await getRoutes(userid);

      if (!routes) {
        return res.status(404).json({ error: "No routes registered for this user." });
      }

      return res.status(200).json({ routes });
    } catch (error) {
      console.error("Error in GET /routes/:userid", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * GET /resolve/v2/:domain
   * Resolve a domain to its routes (v2 API using Redis).
   * Returns identity info from Firestore + routes from Redis.
   *
   * :domain is the subdomain part (e.g., "alice" for alice.nsl.sh)
   *
   * Response includes:
   * - routesTtl: seconds until routes expire (from Redis TTL), -2 if no routes
   * - lastSeenOnline: user's last heartbeat timestamp (informational)
   */
  router.get('/resolve/v2/:domain', async (req, res) => {
    try {
      const domain = req.params.domain.trim().toLowerCase();

      // Get identity from Firestore
      const domainData = await getDomain(domain);

      if (!domainData) {
        return res.status(404).json({ error: "Domain not found." });
      }

      // Get routes from Redis
      const routes = await getRoutes(domainData.uid);

      // Get routes TTL from Redis
      const routesTtl = await getRoutesTTL(domainData.uid);

      // What our nameservers answer for the user's names (only when user zones are on)
      const dns = await dnsSummary(domainData.uid, domainData.domain, routes);

      // the box takes a PROXY v2 header from the gateway (passthrough keeps the client IP)
      const proxyProtocol = await acceptsProxyProtocol(domainData.uid);

      return res.status(200).json({
        userId: domainData.uid,
        domainName: domainData.domain.domainName,
        serverDomain: getServerDomain(),
        routes: routes || [],  // Empty array if no routes registered
        routesTtl,  // Seconds until routes expire (-2 if no routes)
        lastSeenOnline: domainData.domain.lastRouteRegistration || null,  // Updated on route registration
        ...(proxyProtocol ? { proxyProtocol: true } : {}),
        ...(dns ? { dns } : {}),
      });
    } catch (error) {
      console.error("Error in GET /resolve/v2/:domain", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // Domain Activity API
  // ============================================================================

  /**
   * GET /domains/active
   * List all active domains (domains with route activity within INACTIVE_DOMAIN_DAYS).
   * Returns full domain info: online status, routes, time remaining before release.
   */
  router.get('/domains/active', async (req, res) => {
    try {
      const inactiveDays = getInactiveDomainDays();
      const onlineThresholdSeconds = 660; // matches checkOnlineStatus threshold
      const now = Date.now();
      const releaseCutoffMs = inactiveDays * 24 * 60 * 60 * 1000;

      // Get active user IDs from Redis
      const activeUserIds = await getActiveUserIds(inactiveDays);

      const online: Array<Record<string, unknown>> = [];
      const offline: Array<Record<string, unknown>> = [];

      for (const userId of activeUserIds) {
        try {
          const userData = await getUserDomain(userId);
          if (!userData || !userData.domainName) continue;

          const activityTs = await getActivityTimestamp(userId);
          const lastRouteRegistration = activityTs
            ? new Date(activityTs).toISOString()
            : userData.lastRouteRegistration || null;

          const routes = await getRoutes(userId);
          const routesTtl = await getRoutesTTL(userId);

          // Online = route registration within threshold
          const lastRegMs = lastRouteRegistration ? new Date(lastRouteRegistration).getTime() : 0;
          const secondsSinceLastReg = (now - lastRegMs) / 1000;
          const isOnline = lastRouteRegistration !== null && secondsSinceLastReg <= onlineThresholdSeconds;

          // Time remaining before domain release (based on inactiveDays from last activity)
          const activityAgeMs = lastRegMs > 0 ? now - lastRegMs : releaseCutoffMs;
          const remainingMs = Math.max(0, releaseCutoffMs - activityAgeMs);
          const remainingDays = Math.floor(remainingMs / (24 * 60 * 60 * 1000));
          const remainingHours = Math.floor((remainingMs % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));

          const entry = {
            userId,
            domainName: userData.domainName,
            domain: `${userData.domainName}.${getServerDomain()}`,
            online: isOnline,
            lastRouteRegistration,
            routesTtl,
            routeCount: routes?.length || 0,
            routes: routes || [],
            releaseIn: remainingDays > 0
              ? `${remainingDays}d ${remainingHours}h`
              : `${remainingHours}h`,
            releaseInMs: remainingMs,
            ...(isUserZonesEnabled() ? { dns: await dnsSummary(userId, userData, routes) } : {}),
          };

          if (isOnline) {
            online.push(entry);
          } else {
            offline.push(entry);
          }
        } catch (error) {
          console.error(`Error fetching domain for user ${userId}:`, error);
        }
      }

      // Sort: online by domain name, offline by release time (soonest first)
      online.sort((a, b) => String(a.domainName).localeCompare(String(b.domainName)));
      offline.sort((a, b) => Number(a.releaseInMs) - Number(b.releaseInMs));

      return res.status(200).json({
        online,
        offline,
        summary: {
          total: online.length + offline.length,
          online: online.length,
          offline: offline.length,
          inactiveDays,
        },
      });
    } catch (error) {
      console.error("Error in GET /domains/active", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // Admin API - Manual operations (for testing/maintenance)
  // Requires SERVICE_API_KEY authentication: Bearer SERVICE_API_KEY;admin
  // ============================================================================

  /**
   * POST /admin/cleanup
   * Manually trigger domain cleanup.
   * Useful for testing the cleanup logic without waiting for cron.
   *
   * Auth: Bearer SERVICE_API_KEY;admin (or any uid)
   *
   * Query params:
   *   - dryRun=true: Only report what would be cleaned, don't actually clean
   */
  router.post('/admin/cleanup', authenticate, async (req: AuthUserRequest, res) => {
    try {
      const dryRun = req.query.dryRun === 'true';

      if (dryRun) {
        // Import inline to avoid circular deps for dry run
        const { getInactiveUserIds } = await import("./Routes.js");
        const inactiveDays = getInactiveDomainDays();
        const inactiveUserIds = await getInactiveUserIds(inactiveDays);

        const wouldRelease: Array<{ userId: string; domainName: string }> = [];
        for (const userId of inactiveUserIds) {
          const userData = await getUserDomain(userId);
          if (userData?.domainName) {
            wouldRelease.push({ userId, domainName: userData.domainName });
          }
        }

        return res.status(200).json({
          dryRun: true,
          wouldRelease,
          count: wouldRelease.length,
          inactiveDays,
        });
      }

      console.log('Manual cleanup triggered via admin endpoint');
      const result = await runCleanup();

      return res.status(200).json({
        message: "Cleanup completed",
        ...result,
      });
    } catch (error) {
      console.error("Error in POST /admin/cleanup", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // Usage (DAU) ingest API
  // ============================================================================

  /**
   * POST /internal/usage/ingest
   * Fire-and-forget usage notifications from the gateways (CF Worker / OpenResty).
   * Records distinct (uid, app, day) tuples for the Daily Active Users KPI.
   *
   * Auth: Bearer SERVICE_API_KEY (service-only; uid is in the payload, not the caller).
   *
   * Body: { "events": [ { "uid": "abc", "app": "nextcloud" } ] }
   * Responds 204 on success (callers do not read the body).
   */
  router.post('/internal/usage/ingest', authenticateService, async (req, res) => {
    try {
      const body = req.body as { events?: unknown };
      if (!body || !Array.isArray(body.events)) {
        return res.status(400).json({ error: "Body must contain an 'events' array" });
      }

      if (body.events.length > MAX_USAGE_EVENTS_PER_REQUEST) {
        return res.status(413).json({ error: `Too many events (max ${MAX_USAGE_EVENTS_PER_REQUEST})` });
      }

      // Keep only well-formed entries; malformed ones are ignored, not rejected.
      const events: UsageEvent[] = [];
      for (const e of body.events) {
        if (
          e && typeof e === 'object' &&
          typeof (e as UsageEvent).uid === 'string' && (e as UsageEvent).uid.length > 0 &&
          typeof (e as UsageEvent).app === 'string' && (e as UsageEvent).app.length > 0
        ) {
          events.push({ uid: (e as UsageEvent).uid, app: (e as UsageEvent).app });
        }
      }

      await recordUsage(events);
      return res.status(204).end();
    } catch (error) {
      console.error("Error in POST /internal/usage/ingest", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // Per-user mail relay API
  // ============================================================================

  /**
   * POST /email/send
   * Sends a transactional email on behalf of a user. Called by the mail-gateway
   * running on each PCS, which forwards app emails (Vaultwarden, Nextcloud, ...).
   *
   * Auth: Authorization: Bearer <userid>:<signature>
   *   - signature is an Ed25519 signature of the userid (same primitive as route
   *     registration). The userid is only trusted after the signature is verified.
   *
   * Body: { to, subject, text, html?, appName, attachments? }
   *
   * The From address is enforced server-side as <app>.<user-domain>@<server-domain>
   * (e.g. vaultwarden.john@nsl.sh) — the caller cannot influence the identity part,
   * so a user can never send mail as another user.
   */
  router.post('/email/send', async (req, res) => {
    try {
      const authHeader = req.get('authorization') || '';
      const match = authHeader.match(/^Bearer\s+(.+)$/i);
      if (!match) {
        return res.status(401).json({ error: "Missing or malformed Authorization header." });
      }
      const credential = match[1].trim();

      const body = req.body as EmailSendRequest;
      if (!body || !body.to || !body.subject || !body.text || !body.appName) {
        return res.status(400).json({ error: "Missing required fields: to, subject, text, appName." });
      }

      // Establish identity at the verification step (never trust a caller-supplied userid).
      let identity;
      try {
        identity = await verifyEmailCredential(credential);
      } catch (e) {
        if (e instanceof EmailError) {
          logAuthFailure(req, 'invalid_email_credential', { endpoint: 'email_send' });
          return res.status(e.status).json({ error: e.message });
        }
        throw e;
      }

      try {
        const { from, skipped } = await sendUserEmail(identity, body);
        return res.status(200).json({ success: true, from, skipped });
      } catch (e) {
        if (e instanceof EmailError) {
          return res.status(e.status).json({ error: e.message });
        }
        throw e;
      }
    } catch (error) {
      console.error("Error in POST /email/send", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // Certificate Authority API - Private PKI for mesh-router
  // ============================================================================

  /**
   * GET /ca-cert
   * Returns the CA public certificate in PEM format.
   * Public endpoint - no authentication required.
   */
  router.get('/ca-cert', (req, res) => {
    try {
      if (!isCAInitialized()) {
        return res.status(503).json({ error: "Certificate Authority not initialized" });
      }

      const caCert = getCACertificate();
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(caCert);
    } catch (error) {
      console.error("Error in GET /ca-cert", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * POST /cert/:userid/:sig
   * Issues a signed certificate for the user.
   *
   * Request body:
   * {
   *   csr: "-----BEGIN CERTIFICATE REQUEST-----\n...",
   *   publicIp?: "192.168.1.1"  // Optional: adds an IP SAN
   * }
   *
   * Response:
   * {
   *   certificate: "-----BEGIN CERTIFICATE-----\n...",
   *   expiresAt: "2026-01-30T12:00:00.000Z",
   *   caCertificate: "-----BEGIN CERTIFICATE-----\n..."
   * }
   *
   * The signature must be a valid Ed25519 signature of the userid.
   * The CSR Common Name (CN) must match the userid.
   *
   * The certificate carries CERT_EXTRA_SANS, the box's hop name (<label>.box.<zone>, the
   * SNI gateways use) and, if publicIp is provided, an IP SAN. No IP-encoded name.
   */
  router.post('/cert/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    const { csr, publicIp } = req.body;

    try {
      if (!isCAInitialized()) {
        return res.status(503).json({ error: "Certificate Authority not initialized" });
      }

      if (!csr) {
        return res.status(400).json({ error: "CSR is required in request body" });
      }

      const userData = await getUserDomain(userid);

      if (!userData) {
        return res.status(404).json({ error: "User not found. Register a domain first." });
      }

      // Verify signature using stored public key
      let isValid = false;
      try {
        isValid = await verifySignature(userData.publicKey, sig, userid);
      } catch (e) {
        console.log('Invalid signature format for cert request', { userid, error: e.message });
        return res.status(401).json({ error: "Invalid signature." });
      }

      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'cert_request' });
        return res.status(401).json({ error: "Invalid signature." });
      }

      // Sign the CSR (the box's hop name, and an IP SAN when publicIp is given)
      const { certificate, expiresAt } = await signCSR(csr, userid, publicIp, hopName(userData.domainName));
      const caCertificate = getCACertificate();

      console.log('Certificate issued', { userid, expiresAt: expiresAt.toISOString(), publicIp: publicIp || 'none' });

      return res.status(200).json({
        certificate,
        expiresAt: expiresAt.toISOString(),
        caCertificate,
      });
    } catch (error) {
      console.error("Error in POST /cert/:userid/:sig", error);

      // Return specific error messages for known error types
      if (error.message?.includes('CSR Common Name')) {
        return res.status(400).json({ error: error.message });
      }
      if (error.message?.includes('Invalid CSR')) {
        return res.status(400).json({ error: error.message });
      }
      if (error.message?.includes('CSR signature verification')) {
        return res.status(400).json({ error: error.message });
      }

      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * POST /probe
   * Probes candidate public IPs from the backend's vantage point using ICMP.
   * Used by the PCS ensure-script at bootstrap to verify which of the
   * locally-detected IPs are actually reachable from the public internet,
   * before any agent identity exists.
   *
   * Body: { candidates: string[] }
   *   - Up to 4 candidates per call.
   *   - LAN / reserved ranges are rejected without probing.
   *
   * Response: { results: ProbeResult[] } where each result has
   *   { ip, family, reachable, reason? }
   *
   * Unauthenticated by design (the caller has no identity at bootstrap),
   * rate-limited per source IP to prevent abuse as a distributed pinger.
   */
  router.post('/probe', async (req, res) => {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';

    const rate = checkRateLimit(clientIp);
    if (!rate.allowed) {
      if (rate.retryAfterSeconds !== undefined) {
        res.setHeader('Retry-After', String(rate.retryAfterSeconds));
      }
      return res.status(429).json({
        error: `Rate limit exceeded (max ${PROBE_LIMITS.RATE_LIMIT_MAX_REQUESTS} probes per ${PROBE_LIMITS.RATE_LIMIT_WINDOW_MS / 1000}s per source IP).`,
      });
    }

    const { candidates } = req.body ?? {};
    if (!Array.isArray(candidates) || candidates.length === 0) {
      return res.status(400).json({ error: "candidates must be a non-empty array of IP strings." });
    }
    if (candidates.some((c) => typeof c !== 'string')) {
      return res.status(400).json({ error: "every candidate must be a string." });
    }
    if (candidates.length > PROBE_LIMITS.MAX_CANDIDATES_PER_REQUEST) {
      return res.status(400).json({
        error: `at most ${PROBE_LIMITS.MAX_CANDIDATES_PER_REQUEST} candidates per request.`,
      });
    }

    try {
      const results = await probeCandidates(candidates);
      return res.status(200).json({ results });
    } catch (error) {
      console.error("Error in POST /probe", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  // ============================================================================
  // DNS-01 challenges and DNS settings (mesh-router-nameserver architecture §7.2)
  // ============================================================================

  /**
   * POST /acme-dns/update
   * The acme-dns API, so Caddy (caddy-dns/acmedns), lego, certbot and acme.sh work as is
   * with server_url = <backend>/router/api/acme-dns. Credential: X-Api-User = user id,
   * X-Api-Key = the box's Ed25519 signature over it (same as POST /routes). Body
   * {subdomain, txt}: subdomain must be the user's own domain label. Sets
   * _acme-challenge.<label>.<zone> TXT (at most 2 values, 10 min) on the hidden primary
   * before answering. No /register: every box is registered by its user id.
   */
  router.post('/acme-dns/update', async (req, res) => {
    const userid = req.get('X-Api-User');
    const sig = req.get('X-Api-Key');
    const { subdomain, txt } = req.body ?? {};
    try {
      if (!userid || !sig) {
        logAuthFailure(req, 'missing_credentials', { endpoint: 'acme_dns_update' });
        return res.status(401).json({ error: "X-Api-User and X-Api-Key are required." });
      }
      const userData = await getUserDomain(userid);
      let isValid = false;
      try {
        isValid = !!userData && await verifySignature(userData.publicKey, sig, userid);
      } catch {
        isValid = false;
      }
      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'acme_dns_update' });
        return res.status(401).json({ error: "Invalid credentials." });
      }
      if (typeof subdomain !== 'string' || subdomain.toLowerCase() !== userData.domainName.toLowerCase()) {
        logAuthFailure(req, 'acme_foreign_subdomain', { userid, subdomain });
        return res.status(403).json({ error: "subdomain must be your own domain label." });
      }
      if (!isAcmeTxtValue(txt)) {
        return res.status(400).json({ error: "txt must be a 43-character DNS-01 challenge value." });
      }
      if (!isUserZonesEnabled() || !isInScope(userData)) {
        return res.status(409).json({ error: "Your domain is not served by our nameservers." });
      }
      if (!(await takeAcmeUpdate(userid))) {
        return res.status(429).json({ error: "Too many challenge updates, try again within the hour." });
      }
      await addAcmeTxt(userData.domainName, txt);
      await resyncUser(userid, userData);
      console.log(`[acme-dns] ${userData.domainName}: challenge TXT set`);
      return res.status(200).json({ txt });
    } catch (error) {
      console.error("Error in POST /acme-dns/update", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * POST /acme-dns/present, /acme-dns/cleanup
   * lego's httpreq protocol for the gateway (Traefik): {fqdn, value} with
   * Authorization: Bearer SERVICE_API_KEY. Only _acme-challenge.<label>.<zone>. of a
   * delegated user: the gateway needs certs only for names our nameservers really serve.
   */
  const httpreq = (action: 'present' | 'cleanup') => async (req: Request, res: express.Response) => {
    const { fqdn, value } = req.body ?? {};
    try {
      const label = acmeLabelFromFqdn(fqdn);
      if (!label) {
        return res.status(400).json({ error: "fqdn must be _acme-challenge.<user>.<zone>." });
      }
      if (!isAcmeTxtValue(value)) {
        return res.status(400).json({ error: "value must be a 43-character DNS-01 challenge value." });
      }
      const found = await getDomain(label);
      if (!found || !found.domain.dns?.delegated || !isUserZonesEnabled()) {
        return res.status(403).json({ error: `${label} is not delegated to our nameservers.` });
      }
      if (action === 'present') await addAcmeTxt(label, value);
      else await removeAcmeTxt(label, value);
      await resyncUser(found.uid, found.domain);
      console.log(`[acme-dns] ${label}: gateway ${action}`);
      return res.status(200).json({});
    } catch (error) {
      console.error(`Error in POST /acme-dns/${action}`, error);
      return res.status(500).json({ error: error.toString() });
    }
  };
  router.post('/acme-dns/present', authenticateServiceOrBasic, httpreq('present'));
  router.post('/acme-dns/cleanup', authenticateServiceOrBasic, httpreq('cleanup'));

  /**
   * GET /dns/health
   * Public nameservers' health for an external monitor (UptimeRobot): 200 ok/off,
   * 500 degraded (a nameserver down or behind the primary), 503 down (none answers).
   * Recomputed at most once a minute; user zones are counted, never named.
   */
  router.get('/dns/health', async (req, res) => {
    try {
      const health = await getDnsHealth();
      return res.status(httpStatusFor(health.status)).json(health);
    } catch (error) {
      console.error("Error in GET /dns/health", error);
      return res.status(500).json({ status: "degraded", problems: [String(error)] });
    }
  });

  /**
   * PUT /dns/v1/force/:userid
   * The owner's own toggle: route their names (or one host with `host`) through the
   * gateway, or back to auto. Body {force: "gateway"|"auto", host?}. "direct" and
   * delegation are admin actions (mesh-cli dns).
   */
  const setOwnerForce = async (req: Request, res: express.Response) => {
    const { userid } = req.params as { userid: string };
    const { force, host } = req.body ?? {};
    try {
      if (force !== 'gateway' && force !== 'auto') {
        return res.status(400).json({ error: 'force must be "gateway" or "auto".' });
      }
      if (host !== undefined && (typeof host !== 'string' || !/^[a-z0-9-]+$/.test(host.toLowerCase()))) {
        return res.status(400).json({ error: "host must be one DNS label." });
      }
      if (!(await getUserDomain(userid))) {
        return res.status(404).json({ error: "User not found." });
      }
      const { result } = await setForce(userid, force, host?.toLowerCase());
      return res.status(200).json({
        force,
        ...(host ? { host: host.toLowerCase() } : {}),
        answer: result ? { kind: result.answer.kind, reason: result.answer.reason } : null,
      });
    } catch (error) {
      console.error("Error in PUT /dns/v1/force", error);
      return res.status(500).json({ error: error.toString() });
    }
  };
  router.put('/dns/v1/force/:userid', authenticate, (req: AuthUserRequest, res) => {
    if (req.user?.uid !== req.params.userid) {
      logAuthFailure(req, 'uid_mismatch', { userid: req.params.userid, endpoint: 'dns_force' });
      return res.status(403).json({ error: "You can only change your own DNS settings." });
    }
    return setOwnerForce(req, res);
  });

  /**
   * PUT /dns/v1/force/:userid/:sig
   * The same toggle with the box's credential (signature over the user id), for the
   * box's own console, which holds no Firebase token.
   */
  router.put('/dns/v1/force/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    try {
      const userData = await getUserDomain(userid);
      let isValid = false;
      try {
        isValid = !!userData && await verifySignature(userData.publicKey, sig, userid);
      } catch {
        isValid = false;
      }
      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'dns_force' });
        return res.status(401).json({ error: "Invalid signature." });
      }
    } catch (error) {
      console.error("Error in PUT /dns/v1/force/:userid/:sig", error);
      return res.status(500).json({ error: error.toString() });
    }
    return setOwnerForce(req, res);
  });

  /**
   * PUT /dns/v1/caa/:userid/:sig
   * The box reports the Let's Encrypt accounts it holds keys for (body {accounts: [uri]});
   * the user zone then carries CAA issue/issuewild for those accounts only
   * (phase-1.1-gateway-tls.md §7). [] removes the CAA. Credential: the box's signature
   * over the user id. Unchanged list = no write.
   */
  router.put('/dns/v1/caa/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    const accounts = req.body?.accounts;
    try {
      const userData = await getUserDomain(userid);
      let isValid = false;
      try {
        isValid = !!userData && await verifySignature(userData.publicKey, sig, userid);
      } catch {
        isValid = false;
      }
      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'dns_caa' });
        return res.status(401).json({ error: "Invalid signature." });
      }
      if (!Array.isArray(accounts) || accounts.length > MAX_CAA_ACCOUNTS || !accounts.every(isAcmeAccountUri)) {
        return res.status(400).json({ error: `accounts must be at most ${MAX_CAA_ACCOUNTS} Let's Encrypt account URIs.` });
      }
      const { changed, accounts: stored, result } = await setCaaAccounts(userid, accounts);
      return res.status(200).json({ accounts: stored, changed, published: !!result });
    } catch (error) {
      console.error("Error in PUT /dns/v1/caa/:userid/:sig", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * PUT /hop/v1/proxy-protocol/:userid/:sig
   * The box reports whether its running Caddy accepts a PROXY v2 header from the gateways
   * (body {enabled: boolean}); /resolve/v2 then says `proxyProtocol: true` until the report
   * expires (HopNames.ts). Credential: the box's signature over the user id.
   */
  router.put('/hop/v1/proxy-protocol/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    const enabled = req.body?.enabled;
    try {
      const userData = await getUserDomain(userid);
      let isValid = false;
      try {
        isValid = !!userData && await verifySignature(userData.publicKey, sig, userid);
      } catch {
        isValid = false;
      }
      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'hop_proxy_protocol' });
        return res.status(401).json({ error: "Invalid signature." });
      }
      if (typeof enabled !== "boolean") {
        return res.status(400).json({ error: "enabled must be a boolean." });
      }
      await setProxyProtocol(userid, enabled);
      return res.status(200).json({ enabled });
    } catch (error) {
      console.error("Error in PUT /hop/v1/proxy-protocol/:userid/:sig", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  expressApp.use('/', router);
}