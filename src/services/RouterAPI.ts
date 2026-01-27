import express, { Request } from "express";
import {verifySignature} from "../library/KeyLib.js";
import {authenticate, AuthUserRequest} from "./ExpressAuthenticateMiddleWare.js";
import {checkDomainAvailability, deleteUserDomain, getUserDomain, updateUserDomain, updateHeartbeat, checkOnlineStatus, getDomain} from "./Domain.js";
import {getServerDomain} from "../configuration/config.js";
import {registerRoutes, getRoutes, deleteRoutes, Route, getRoutesTTL} from "./Routes.js";
import {getCACertificate, signCSR, isCAInitialized} from "./CertificateAuthority.js";

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
   * POST /heartbeat/:userid/:sig
   * Updates the lastSeenOnline timestamp for a user (heartbeat/keep-alive).
   * The signature must be a valid Ed25519 signature of the userid using the user's registered public key.
   */
  router.post('/heartbeat/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;

    try {
      const userData = await getUserDomain(userid);

      if (!userData) {
        return res.status(404).json({ error: "User not found. Register a domain first." });
      }

      // Verify signature using stored public key
      let isValid = false;
      try {
        isValid = await verifySignature(userData.publicKey, sig, userid);
      } catch (e) {
        console.log('Invalid signature format for heartbeat', { userid, error: e.message });
        return res.status(401).json({ error: "Invalid signature." });
      }

      if (!isValid) {
        logAuthFailure(req, 'invalid_signature', { userid, endpoint: 'heartbeat' });
        return res.status(401).json({ error: "Invalid signature." });
      }

      const lastSeenOnline = await updateHeartbeat(userid);
      console.log('Heartbeat received', { userid, lastSeenOnline });

      return res.status(200).json({
        message: "Heartbeat received.",
        lastSeenOnline
      });
    } catch (error) {
      console.error("Error in POST /heartbeat/:userid/:sig", error);
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
   * Body: { routes: [{ ip, port, priority, healthCheck? }] }
   *   - ip: string - IP address of the route endpoint
   *   - port: number - Port number (1-65535)
   *   - priority: number - Lower = higher priority (1 = direct, 2 = tunnel)
   *   - healthCheck: { path: string, host?: string } - Optional health check config
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
      const validatedRoutes: Route[] = routes.map((r: any, index: number) => {
        if (!r.ip) {
          throw new Error(`Route ${index}: ip is required.`);
        }
        if (!r.port || r.port < 1 || r.port > 65535) {
          throw new Error(`Route ${index}: port must be between 1 and 65535.`);
        }
        if (typeof r.priority !== 'number') {
          throw new Error(`Route ${index}: priority is required.`);
        }

        const route: Route = {
          ip: r.ip,
          port: r.port,
          priority: r.priority,
        };

        // Add health check if provided
        if (r.healthCheck && r.healthCheck.path) {
          route.healthCheck = {
            path: r.healthCheck.path,
            ...(r.healthCheck.host && { host: r.healthCheck.host }),
          };
        }

        return route;
      });

      await registerRoutes(userid, validatedRoutes);

      console.log('Routes registered', { userid, routeCount: validatedRoutes.length });

      return res.status(200).json({
        message: "Routes registered successfully.",
        routes: validatedRoutes,
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

      return res.status(200).json({
        userId: domainData.uid,
        domainName: domainData.domain.domainName,
        serverDomain: getServerDomain(),
        routes: routes || [],  // Empty array if no routes registered
        routesTtl,  // Seconds until routes expire (-2 if no routes)
        lastSeenOnline: domainData.domain.lastSeenOnline || null,  // Informational
      });
    } catch (error) {
      console.error("Error in GET /resolve/v2/:domain", error);
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
   * Request body: { csr: "-----BEGIN CERTIFICATE REQUEST-----\n..." }
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
   */
  router.post('/cert/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    const { csr } = req.body;

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

      // Sign the CSR
      const { certificate, expiresAt } = await signCSR(csr, userid);
      const caCertificate = getCACertificate();

      console.log('Certificate issued', { userid, expiresAt: expiresAt.toISOString() });

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

  expressApp.use('/', router);
}