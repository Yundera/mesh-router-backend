import { describe, it, before, after, beforeEach, afterEach } from "mocha";
import { expect } from "chai";
import request from "supertest";
import { createTestApp } from "./test-app.js";
import {
  generateTestUserId,
  createTestUser,
  deleteTestUser,
  signMessage,
  cleanupAllTestUsers,
  cleanupAllTestRoutes,
  getTestUserRoutes,
  deleteTestUserRoutes,
  getTestUserRoutesTTL,
  sleep,
  TEST_SERVER_DOMAIN,
} from "./test-helpers.js";
import type { Application } from "express";

describe("Domain API", () => {
  let app: Application;
  let testUserId: string;
  let testKeys: { publicKey: string; privateKey: string };

  before(async () => {
    app = createTestApp();
    // Clean up any leftover test data
    await cleanupAllTestUsers();
  });

  after(async () => {
    // Final cleanup
    await cleanupAllTestUsers();
  });

  beforeEach(async () => {
    // Create a fresh test user for each test
    testUserId = generateTestUserId();
    testKeys = await createTestUser(testUserId);
  });

  afterEach(async () => {
    // Clean up the test user
    try {
      await deleteTestUser(testUserId);
    } catch (e) {
      // Ignore if already deleted
    }
  });

  describe("GET /available/:domain", () => {
    it("should return available for unused domain", async () => {
      const unusedDomain = "unuseddomain12345";

      const response = await request(app)
        .get(`/available/${unusedDomain}`)
        .expect(200);

      expect(response.body.available).to.equal(true);
      expect(response.body.message).to.equal("Domain name is available.");
    });

    it("should return unavailable for existing domain", async () => {
      // testUserId is also the domainName
      const domainName = testUserId;

      const response = await request(app)
        .get(`/available/${domainName}`)
        .expect(209); // Note: Using existing status code behavior

      expect(response.body.available).to.equal(false);
    });

    it("should return unavailable for reserved domains", async () => {
      const response = await request(app)
        .get("/available/root")
        .expect(209);

      expect(response.body.available).to.equal(false);
      expect(response.body.message).to.equal("Domain name is not available.");
    });

    it("should return unavailable for www reserved domain", async () => {
      const response = await request(app)
        .get("/available/www")
        .expect(209);

      expect(response.body.available).to.equal(false);
    });

    it("should reject invalid domain names", async () => {
      const response = await request(app)
        .get("/available/invalid-domain")
        .expect(209);

      expect(response.body.available).to.equal(false);
      expect(response.body.message).to.include("lowercase letters and numbers");
    });

    it("should reject domains with uppercase", async () => {
      const response = await request(app)
        .get("/available/InvalidDomain")
        .expect(209);

      expect(response.body.available).to.equal(false);
    });

    it("should reject domains longer than 63 characters", async () => {
      const longDomain = "a".repeat(64);

      const response = await request(app)
        .get(`/available/${longDomain}`)
        .expect(209);

      expect(response.body.available).to.equal(false);
      expect(response.body.message).to.include("63 characters");
    });
  });

  describe("GET /domain/:userid", () => {
    it("should return domain info for existing user", async () => {
      const response = await request(app)
        .get(`/domain/${testUserId}`)
        .expect(200);

      expect(response.body.domainName).to.equal(testUserId);
      expect(response.body.serverDomain).to.equal(TEST_SERVER_DOMAIN);
      expect(response.body.publicKey).to.equal(testKeys.publicKey);
    });

    it("should return 280 for non-existent user", async () => {
      // Note: Using existing status code behavior (280 is non-standard)
      const response = await request(app)
        .get("/domain/nonexistentuser12345")
        .expect(280);

      expect(response.body.error).to.equal("User not found.");
    });
  });

  describe("GET /verify/:userid/:sig", () => {
    it("should return domain info for valid signature", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .get(`/verify/${testUserId}/${signature}`)
        .expect(200);

      expect(response.body.domainName).to.equal(testUserId);
      expect(response.body.serverDomain).to.equal(TEST_SERVER_DOMAIN);
    });

    it("should return valid: false for invalid signature", async () => {
      const invalidSignature = "k1234567890invalidSignature";

      const response = await request(app)
        .get(`/verify/${testUserId}/${invalidSignature}`)
        .expect(200);

      expect(response.body.valid).to.equal(false);
    });

    it("should return error for unknown user", async () => {
      const signature = await signMessage(testKeys.privateKey, "unknownuser12345");

      const response = await request(app)
        .get(`/verify/unknownuser12345/${signature}`)
        .expect(200);

      expect(response.body.error).to.equal("unknown user");
    });
  });
});

// ============================================================================
// Routes v2 API Tests
// ============================================================================

describe("Routes v2 API", () => {
  let app: Application;
  let testUserId: string;
  let testKeys: { publicKey: string; privateKey: string };

  before(async () => {
    app = createTestApp();
    await cleanupAllTestUsers();
    await cleanupAllTestRoutes();
  });

  after(async () => {
    await cleanupAllTestUsers();
    await cleanupAllTestRoutes();
  });

  beforeEach(async () => {
    testUserId = generateTestUserId();
    testKeys = await createTestUser(testUserId);
  });

  afterEach(async () => {
    try {
      await deleteTestUser(testUserId);
      await deleteTestUserRoutes(testUserId);
    } catch {
      // Ignore if already deleted
    }
  });

  describe("POST /routes/:userid/:sig", () => {
    it("should register a single route with valid signature", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const routes = [
        { ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }
      ];

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes })
        .expect(200);

      expect(response.body.message).to.equal("Routes registered successfully.");
      expect(response.body.routes).to.have.lengthOf(1);
      expect(response.body.routes[0].ip).to.equal("10.77.0.100");
      expect(response.body.routes[0].port).to.equal(443);
      expect(response.body.routes[0].priority).to.equal(1);
      expect(response.body.routes[0].source).to.equal("agent");

      // Verify in Redis
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(1);
      expect(storedRoutes![0].ip).to.equal("10.77.0.100");
      expect(storedRoutes![0].source).to.equal("agent");
    });

    it("should register multiple routes (direct + tunnel)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const routes = [
        { ip: "203.0.113.5", port: 443, priority: 1, source: "agent" },   // Direct
        { ip: "10.77.0.100", port: 80, priority: 2, source: "tunnel" }     // Tunnel
      ];

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes })
        .expect(200);

      expect(response.body.routes).to.have.lengthOf(2);

      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(2);
    });

    it("should register route with health check", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const routes = [
        {
          ip: "10.77.0.100",
          port: 443,
          priority: 1,
          source: "agent",
          healthCheck: {
            path: "/.well-known/health",
            host: "alice.nsl.sh"
          }
        }
      ];

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes })
        .expect(200);

      expect(response.body.routes[0].healthCheck).to.deep.equal({
        path: "/.well-known/health",
        host: "alice.nsl.sh"
      });

      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes![0].healthCheck?.path).to.equal("/.well-known/health");
      expect(storedRoutes![0].healthCheck?.host).to.equal("alice.nsl.sh");
    });

    it("should register route with health check path only (no host)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const routes = [
        {
          ip: "10.77.0.100",
          port: 443,
          priority: 1,
          source: "agent",
          healthCheck: {
            path: "/health"
          }
        }
      ];

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes })
        .expect(200);

      expect(response.body.routes[0].healthCheck.path).to.equal("/health");
      expect(response.body.routes[0].healthCheck.host).to.be.undefined;
    });

    it("should update existing route with same ip:port (refresh TTL)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register first route
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      // Refresh same route with updated priority (same ip:port, same source)
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 2, source: "agent" }] })
        .expect(200);

      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(1);
      expect(storedRoutes![0].ip).to.equal("10.77.0.100");
      expect(storedRoutes![0].port).to.equal(443);
      expect(storedRoutes![0].priority).to.equal(2); // Updated priority
    });

    it("should merge routes from different sources (agent + tunnel)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register first route from agent
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      // Register second route from tunnel - different source
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.200", port: 8443, priority: 2, source: "tunnel" }] })
        .expect(200);

      // Both routes should exist (merged - different sources)
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(2);
    });

    it("should replace route when same source registers different IP", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register first route from agent with IP 1.1.1.1
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "1.1.1.1", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      // Register from same source (agent) with different IP 2.2.2.2
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "2.2.2.2", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      // Should only have ONE route (old replaced by new, not appended)
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(1);
      expect(storedRoutes![0].ip).to.equal("2.2.2.2");
      expect(storedRoutes![0].source).to.equal("agent");
    });

    it("should replace only routes from same source, keeping others", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register routes from both agent and tunnel
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [
          { ip: "1.1.1.1", port: 443, priority: 1, source: "agent" },
          { ip: "10.77.0.1", port: 443, priority: 2, source: "tunnel" }
        ]})
        .expect(200);

      // Agent's IP changes - register new IP from agent
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "2.2.2.2", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      // Should have 2 routes: new agent route + unchanged tunnel route
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(2);

      const agentRoute = storedRoutes!.find(r => r.source === "agent");
      const tunnelRoute = storedRoutes!.find(r => r.source === "tunnel");

      expect(agentRoute?.ip).to.equal("2.2.2.2");
      expect(tunnelRoute?.ip).to.equal("10.77.0.1");
    });

    it("should reject route without source field", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
        .expect(500);

      expect(response.body.error).to.include("source is required");
    });

    it("should reject invalid signature", async () => {
      const invalidSignature = "k1234567890invalidSignature";

      const response = await request(app)
        .post(`/routes/${testUserId}/${invalidSignature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(401);

      expect(response.body.error).to.equal("Invalid signature.");
    });

    it("should reject missing routes in body", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({})
        .expect(400);

      expect(response.body.error).to.equal("routes array is required in request body.");
    });

    it("should reject empty routes array", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [] })
        .expect(400);

      expect(response.body.error).to.equal("routes array is required in request body.");
    });

    it("should reject route with missing IP", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ port: 443, priority: 1, source: "agent" }] })
        .expect(500);

      expect(response.body.error).to.include("ip is required");
    });

    it("should reject route with invalid port", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 99999, priority: 1, source: "agent" }] })
        .expect(500);

      expect(response.body.error).to.include("port must be between 1 and 65535");
    });

    it("should reject non-existent user", async () => {
      const fakeUserId = "nonexistentuser12345";
      const signature = await signMessage(testKeys.privateKey, fakeUserId);

      const response = await request(app)
        .post(`/routes/${fakeUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(404);

      expect(response.body.error).to.equal("User not found. Register a domain first.");
    });
  });

  describe("DELETE /routes/:userid/:sig", () => {
    it("should delete routes with valid signature", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // First register routes
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      // Then delete them
      const response = await request(app)
        .delete(`/routes/${testUserId}/${signature}`)
        .expect(200);

      expect(response.body.message).to.equal("Routes deleted successfully.");

      // Verify deleted from Redis
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.be.null;
    });

    it("should reject invalid signature", async () => {
      const invalidSignature = "k1234567890invalidSignature";

      const response = await request(app)
        .delete(`/routes/${testUserId}/${invalidSignature}`)
        .expect(401);

      expect(response.body.error).to.equal("Invalid signature.");
    });

    it("should succeed even if no routes exist", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .delete(`/routes/${testUserId}/${signature}`)
        .expect(200);

      expect(response.body.message).to.equal("Routes deleted successfully.");
    });
  });

  describe("GET /routes/:userid", () => {
    it("should return routes for user with registered routes", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register routes first
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [
          { ip: "10.77.0.100", port: 443, priority: 1, source: "agent" },
          { ip: "10.77.0.200", port: 80, priority: 2, source: "tunnel" }
        ]})
        .expect(200);

      // Get routes
      const response = await request(app)
        .get(`/routes/${testUserId}`)
        .expect(200);

      expect(response.body.routes).to.have.lengthOf(2);
      expect(response.body.routes[0].ip).to.equal("10.77.0.100");
      expect(response.body.routes[1].ip).to.equal("10.77.0.200");
    });

    it("should return 404 for user with no routes", async () => {
      const response = await request(app)
        .get(`/routes/${testUserId}`)
        .expect(404);

      expect(response.body.error).to.equal("No routes registered for this user.");
    });
  });

  describe("GET /resolve/v2/:domain", () => {
    it("should resolve domain to routes with TTL info", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const domainName = testUserId; // domainName equals userId in tests

      // Register routes
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [
          { ip: "203.0.113.5", port: 443, priority: 1, source: "agent" },
          { ip: "10.77.0.100", port: 80, priority: 2, source: "tunnel" }
        ]})
        .expect(200);

      // Resolve
      const response = await request(app)
        .get(`/resolve/v2/${domainName}`)
        .expect(200);

      expect(response.body.userId).to.equal(testUserId);
      expect(response.body.domainName).to.equal(domainName);
      expect(response.body.serverDomain).to.equal(TEST_SERVER_DOMAIN);
      expect(response.body.routes).to.have.lengthOf(2);
      expect(response.body.routes[0].ip).to.equal("203.0.113.5");
      expect(response.body.routes[1].ip).to.equal("10.77.0.100");
      // Verify TTL info is included
      expect(response.body.routesTtl).to.be.a("number");
      expect(response.body.routesTtl).to.be.greaterThan(0);
      expect(response.body).to.have.property("lastSeenOnline");
    });

    it("should return routesTtl as -2 for domain without routes", async () => {
      const domainName = testUserId;

      const response = await request(app)
        .get(`/resolve/v2/${domainName}`)
        .expect(200);

      expect(response.body.userId).to.equal(testUserId);
      expect(response.body.routes).to.be.an("array").that.is.empty;
      // routesTtl is -2 when key doesn't exist (Redis TTL behavior)
      expect(response.body.routesTtl).to.equal(-2);
      expect(response.body.lastSeenOnline).to.be.null;
    });

    it("should return 404 for unknown domain", async () => {
      const response = await request(app)
        .get("/resolve/v2/nonexistentdomain12345")
        .expect(404);

      expect(response.body.error).to.equal("Domain not found.");
    });

    it("should handle case-insensitive domain lookup", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const domainName = testUserId;

      // Register routes
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }]})
        .expect(200);

      // Resolve with uppercase
      const response = await request(app)
        .get(`/resolve/v2/${domainName.toUpperCase()}`)
        .expect(200);

      expect(response.body.routes).to.have.lengthOf(1);
      expect(response.body.routesTtl).to.be.a("number");
    });
  });
});

// ============================================================================
// Routes TTL Tests
// ============================================================================

describe("Routes TTL", () => {
  let app: Application;
  let testUserId: string;
  let testKeys: { publicKey: string; privateKey: string };

  before(async () => {
    app = createTestApp();
    await cleanupAllTestUsers();
    await cleanupAllTestRoutes();
  });

  after(async () => {
    await cleanupAllTestUsers();
    await cleanupAllTestRoutes();
  });

  beforeEach(async () => {
    testUserId = generateTestUserId();
    testKeys = await createTestUser(testUserId);
  });

  afterEach(async () => {
    try {
      await deleteTestUser(testUserId);
      await deleteTestUserRoutes(testUserId);
    } catch {
      // Ignore if already deleted
    }
  });

  describe("TTL behavior", () => {
    it("should set TTL when registering routes", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      const ttl = await getTestUserRoutesTTL(testUserId);
      // TTL should be positive (default is 600 seconds, but test env may differ)
      expect(ttl).to.be.greaterThan(0);
    });

    it("should refresh TTL when re-registering routes", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register route
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      const ttl1 = await getTestUserRoutesTTL(testUserId);

      // Wait a bit
      await sleep(1100);

      // Re-register (refresh)
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      const ttl2 = await getTestUserRoutesTTL(testUserId);

      // TTL should be refreshed (ttl2 >= ttl1 because it was reset)
      expect(ttl2).to.be.at.least(ttl1);
    });

    it("should return routesTtl in resolve response", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
        .expect(200);

      const response = await request(app)
        .get(`/resolve/v2/${testUserId}`)
        .expect(200);

      expect(response.body.routesTtl).to.be.a("number");
      expect(response.body.routesTtl).to.be.greaterThan(0);
    });

    it("should return -2 for routesTtl when no routes exist", async () => {
      const response = await request(app)
        .get(`/resolve/v2/${testUserId}`)
        .expect(200);

      expect(response.body.routesTtl).to.equal(-2);
    });

    it("should expire routes after TTL (requires ROUTES_TTL_SECONDS=2 in test env)", async function() {
      // Skip this test in normal runs - only run with short TTL configured
      // Set ROUTES_TTL_SECONDS=2 in test environment to run this test
      const currentTtl = await getTestUserRoutesTTL(testUserId);
      if (currentTtl === -2) {
        // No routes yet, register one to check TTL
        const signature = await signMessage(testKeys.privateKey, testUserId);
        await request(app)
          .post(`/routes/${testUserId}/${signature}`)
          .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1, source: "agent" }] })
          .expect(200);

        const ttl = await getTestUserRoutesTTL(testUserId);

        // Only run expiration test if TTL is short (2-5 seconds)
        if (ttl > 5) {
          this.skip();
          return;
        }

        // Wait for TTL to expire
        await sleep((ttl + 1) * 1000);

        // Routes should be gone
        const routes = await getTestUserRoutes(testUserId);
        expect(routes).to.be.null;
      } else {
        this.skip();
      }
    });
  });
});
