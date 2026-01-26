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
        { ip: "10.77.0.100", port: 443, priority: 1 }
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

      // Verify in Redis
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(1);
      expect(storedRoutes![0].ip).to.equal("10.77.0.100");
    });

    it("should register multiple routes (direct + tunnel)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const routes = [
        { ip: "203.0.113.5", port: 443, priority: 1 },   // Direct
        { ip: "10.77.0.100", port: 80, priority: 2 }     // Tunnel
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
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
        .expect(200);

      // Refresh same route with updated priority (same ip:port)
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 2 }] })
        .expect(200);

      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(1);
      expect(storedRoutes![0].ip).to.equal("10.77.0.100");
      expect(storedRoutes![0].port).to.equal(443);
      expect(storedRoutes![0].priority).to.equal(2); // Updated priority
    });

    it("should merge routes from different ip:port (multi-source)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register first route (e.g., from agent)
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
        .expect(200);

      // Register second route (e.g., from tunnel) - different ip:port
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.200", port: 8443, priority: 2 }] })
        .expect(200);

      // Both routes should exist (merged)
      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(2);
    });

    it("should reject invalid signature", async () => {
      const invalidSignature = "k1234567890invalidSignature";

      const response = await request(app)
        .post(`/routes/${testUserId}/${invalidSignature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
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
        .send({ routes: [{ port: 443, priority: 1 }] })
        .expect(500);

      expect(response.body.error).to.include("ip is required");
    });

    it("should reject route with invalid port", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 99999, priority: 1 }] })
        .expect(500);

      expect(response.body.error).to.include("port must be between 1 and 65535");
    });

    it("should reject non-existent user", async () => {
      const fakeUserId = "nonexistentuser12345";
      const signature = await signMessage(testKeys.privateKey, fakeUserId);

      const response = await request(app)
        .post(`/routes/${fakeUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
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
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
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
          { ip: "10.77.0.100", port: 443, priority: 1 },
          { ip: "10.77.0.200", port: 80, priority: 2 }
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
          { ip: "203.0.113.5", port: 443, priority: 1 },
          { ip: "10.77.0.100", port: 80, priority: 2 }
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
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }]})
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
