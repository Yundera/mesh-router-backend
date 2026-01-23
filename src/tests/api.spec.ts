import { describe, it, before, after, beforeEach, afterEach } from "mocha";
import { expect } from "chai";
import request from "supertest";
import { createTestApp } from "./test-app.js";
import {
  generateTestUserId,
  createTestUser,
  deleteTestUser,
  signMessage,
  getTestUserData,
  cleanupAllTestUsers,
  cleanupAllTestRoutes,
  getTestUserRoutes,
  deleteTestUserRoutes,
  TEST_SERVER_DOMAIN,
} from "./test-helpers.js";
import type { Application } from "express";

describe("IP Registration API", () => {
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

  describe("POST /ip/:userid/:sig", () => {
    it("should register Host IP with valid signature", async () => {
      const hostIp = "10.77.0.100";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp })
        .expect(200);

      expect(response.body.message).to.equal("Host IP registered successfully.");
      expect(response.body.hostIp).to.equal(hostIp);
      expect(response.body.targetPort).to.equal(443); // Default port

      // Verify in database
      const userData = await getTestUserData(testUserId);
      expect(userData?.hostIp).to.equal(hostIp);
      expect(userData?.hostIpUpdatedAt).to.be.a("string");
      expect(userData?.targetPort).to.equal(443);
    });

    it("should register Host IP with custom targetPort", async () => {
      const hostIp = "10.77.0.100";
      const targetPort = 8443;
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp, targetPort })
        .expect(200);

      expect(response.body.message).to.equal("Host IP registered successfully.");
      expect(response.body.hostIp).to.equal(hostIp);
      expect(response.body.targetPort).to.equal(targetPort);

      // Verify in database
      const userData = await getTestUserData(testUserId);
      expect(userData?.hostIp).to.equal(hostIp);
      expect(userData?.targetPort).to.equal(targetPort);
    });

    it("should reject invalid signature", async () => {
      const hostIp = "10.77.0.100";
      const invalidSignature = "k1234567890invalidSignature";

      const response = await request(app)
        .post(`/ip/${testUserId}/${invalidSignature}`)
        .send({ hostIp })
        .expect(401);

      expect(response.body.error).to.equal("Invalid signature.");
    });

    it("should reject missing hostIp in body", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({})
        .expect(400);

      expect(response.body.error).to.equal("hostIp is required in request body.");
    });

    it("should reject invalid IP format", async () => {
      const invalidIp = "not.an.ip.address";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: invalidIp })
        .expect(500); // Domain.ts throws error which results in 500

      expect(response.body.error).to.include("Invalid IP address format");
    });

    it("should reject non-existent user", async () => {
      const fakeUserId = "nonexistentuser12345";
      const signature = await signMessage(testKeys.privateKey, fakeUserId);

      const response = await request(app)
        .post(`/ip/${fakeUserId}/${signature}`)
        .send({ hostIp: "10.77.0.100" })
        .expect(404);

      expect(response.body.error).to.equal("User not found. Register a domain first.");
    });

    it("should accept valid full IPv6 address", async () => {
      const hostIpv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: hostIpv6 })
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIpv6);
    });

    it("should accept compressed IPv6 address (::1)", async () => {
      const hostIpv6 = "::1";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: hostIpv6 })
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIpv6);
    });

    it("should accept compressed IPv6 address (fe80::1)", async () => {
      const hostIpv6 = "fe80::1";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: hostIpv6 })
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIpv6);
    });

    it("should accept compressed IPv6 address (2001:db8::)", async () => {
      const hostIpv6 = "2001:db8::";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: hostIpv6 })
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIpv6);
    });

    it("should reject invalid IPv6 with multiple ::", async () => {
      const invalidIpv6 = "2001::db8::1";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      const response = await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: invalidIpv6 })
        .expect(500);

      expect(response.body.error).to.include("Invalid IP address format");
    });

    it("should update existing IP with new value", async () => {
      const firstIp = "10.77.0.100";
      const secondIp = "10.77.0.200";
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register first IP
      await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: firstIp })
        .expect(200);

      // Update with second IP
      await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp: secondIp })
        .expect(200);

      // Verify updated
      const userData = await getTestUserData(testUserId);
      expect(userData?.hostIp).to.equal(secondIp);
    });
  });

  describe("GET /resolve/:domain", () => {
    it("should resolve domain to IP with default targetPort", async () => {
      const hostIp = "10.77.0.150";
      const signature = await signMessage(testKeys.privateKey, testUserId);
      // domainName is the same as testUserId (alphanumeric)
      const domainName = testUserId;

      // First register the IP
      await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp })
        .expect(200);

      // Then resolve it
      const response = await request(app)
        .get(`/resolve/${domainName}`)
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIp);
      expect(response.body.targetPort).to.equal(443);
      expect(response.body.domainName).to.equal(domainName);
      expect(response.body.serverDomain).to.equal(TEST_SERVER_DOMAIN);
    });

    it("should resolve domain to IP with custom targetPort", async () => {
      const hostIp = "10.77.0.151";
      const targetPort = 8443;
      const signature = await signMessage(testKeys.privateKey, testUserId);
      const domainName = testUserId;

      // First register the IP with custom port
      await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp, targetPort })
        .expect(200);

      // Then resolve it
      const response = await request(app)
        .get(`/resolve/${domainName}`)
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIp);
      expect(response.body.targetPort).to.equal(targetPort);
      expect(response.body.domainName).to.equal(domainName);
    });

    it("should return 404 for unknown domain", async () => {
      const response = await request(app)
        .get("/resolve/nonexistentdomain12345")
        .expect(404);

      expect(response.body.error).to.equal("Domain not found or no IP registered.");
    });

    it("should return 404 for domain without IP registered", async () => {
      // User exists but has no IP registered yet
      // domainName is the same as testUserId
      const domainName = testUserId;

      const response = await request(app)
        .get(`/resolve/${domainName}`)
        .expect(404);

      expect(response.body.error).to.equal("Domain not found or no IP registered.");
    });

    it("should handle case-insensitive domain lookup", async () => {
      const hostIp = "10.77.0.160";
      const signature = await signMessage(testKeys.privateKey, testUserId);
      // domainName is the same as testUserId
      const domainName = testUserId;

      // Register IP
      await request(app)
        .post(`/ip/${testUserId}/${signature}`)
        .send({ hostIp })
        .expect(200);

      // Resolve with uppercase (should be normalized to lowercase)
      const response = await request(app)
        .get(`/resolve/${domainName.toUpperCase()}`)
        .expect(200);

      expect(response.body.hostIp).to.equal(hostIp);
    });
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

    it("should update existing routes (refresh)", async () => {
      const signature = await signMessage(testKeys.privateKey, testUserId);

      // Register first route
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.100", port: 443, priority: 1 }] })
        .expect(200);

      // Update with new route
      await request(app)
        .post(`/routes/${testUserId}/${signature}`)
        .send({ routes: [{ ip: "10.77.0.200", port: 8443, priority: 1 }] })
        .expect(200);

      const storedRoutes = await getTestUserRoutes(testUserId);
      expect(storedRoutes).to.have.lengthOf(1);
      expect(storedRoutes![0].ip).to.equal("10.77.0.200");
      expect(storedRoutes![0].port).to.equal(8443);
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
    it("should resolve domain to routes", async () => {
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
    });

    it("should return empty routes array for domain without routes", async () => {
      const domainName = testUserId;

      const response = await request(app)
        .get(`/resolve/v2/${domainName}`)
        .expect(200);

      expect(response.body.userId).to.equal(testUserId);
      expect(response.body.routes).to.be.an("array").that.is.empty;
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
    });
  });
});
