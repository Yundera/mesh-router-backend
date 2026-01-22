import express from "express";
import {verifySignature} from "../library/KeyLib.js";
import {authenticate, AuthUserRequest} from "./ExpressAuthenticateMiddleWare.js";
import {checkDomainAvailability, deleteUserDomain, getUserDomain, updateUserDomain, registerHostIp, resolveDomainToIp, updateHeartbeat} from "./Domain.js";
import {getServerDomain} from "../configuration/config.js";

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
   * POST /ip/:userid/:sig
   * Registers the host IP and optional target port for a user, authenticated via signature.
   * Body: { hostIp: string, targetPort?: number }
   * The signature must be a valid Ed25519 signature of the userid using the user's registered public key.
   */
  router.post('/ip/:userid/:sig', async (req, res) => {
    const { userid, sig } = req.params;
    const { hostIp, targetPort } = req.body;

    try {
      if (!hostIp) {
        return res.status(400).json({ error: "hostIp is required in request body." });
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
        // Invalid signature format (e.g., non-base36 characters)
        console.log('Invalid signature format', { userid, error: e.message });
        return res.status(401).json({ error: "Invalid signature." });
      }
      const resolvedTargetPort = targetPort ?? 443;
      console.log('Verifying signature for IP registration', { userid, hostIp, targetPort: resolvedTargetPort, isValid });

      if (!isValid) {
        return res.status(401).json({ error: "Invalid signature." });
      }

      await registerHostIp(userid, hostIp, resolvedTargetPort);
      return res.status(200).json({
        message: "Host IP registered successfully.",
        hostIp,
        targetPort: resolvedTargetPort,
        domain: `${userData.domainName}.${getServerDomain()}`
      });
    } catch (error) {
      console.error("Error in POST /ip/:userid/:sig", error);
      return res.status(500).json({ error: error.toString() });
    }
  });

  /**
   * GET /resolve/:domain
   * Public endpoint - resolves a domain name to its host IP (like DNS).
   * :domain is the subdomain part (e.g., "alice" for alice.nsl.sh)
   */
  router.get('/resolve/:domain', async (req, res) => {
    try {
      const domain = req.params.domain.trim().toLowerCase();
      const result = await resolveDomainToIp(domain);

      if (!result) {
        return res.status(404).json({ error: "Domain not found or no IP registered." });
      }

      return res.status(200).json(result);
    } catch (error) {
      console.error("Error in GET /resolve/:domain", error);
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

  expressApp.use('/', router);
}