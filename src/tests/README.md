# mesh-router-backend Tests

API integration tests for mesh-router-backend using Mocha, Chai, and Supertest.

## Files

| File | Description |
|------|-------------|
| `api.spec.ts` | Main test suite for all API endpoints |
| `test-app.ts` | Express app factory for testing (initializes Firebase, sets up routes) |
| `test-helpers.ts` | Utility functions for test data management |

## Running Tests

Tests must be run inside Docker (requires Redis and Firebase credentials):

```bash
cd mesh-router-backend/dev
docker compose run --rm mesh-router-backend pnpm test
```

Or if the container is already running:

```bash
docker compose exec mesh-router-backend pnpm test
```

## Test Suites

### Domain API (12 tests)

| Endpoint | Tests |
|----------|-------|
| `GET /available/:domain` | Domain availability, reserved names, validation rules, length limits |
| `GET /domain/:userid` | Retrieve domain info, handle non-existent users |
| `GET /verify/:userid/:sig` | Ed25519 signature verification, invalid signatures, unknown users |

### Routes v2 API (21 tests)

| Endpoint | Tests |
|----------|-------|
| `POST /routes/:userid/:sig` | Register routes (single, multiple, with health checks), TTL refresh, signature rejection, validation errors |
| `DELETE /routes/:userid/:sig` | Delete routes, signature verification |
| `GET /routes/:userid` | Retrieve routes, handle missing routes |
| `GET /resolve/v2/:domain` | Domain resolution, TTL info, case-insensitive lookup |

## Test Helpers

### User Management

```typescript
// Generate unique test user ID (alphanumeric, valid as domain)
const userId = generateTestUserId();
// => "testusermkwtms4wddyy87"

// Create user with Ed25519 keypair in Firestore
const { publicKey, privateKey } = await createTestUser(userId);

// Sign a message for authenticated requests
const signature = await signMessage(privateKey, userId);

// Cleanup
await deleteTestUser(userId);
await cleanupAllTestUsers();  // Deletes all users with "testuser" prefix
```

### Route Management

```typescript
// Get routes from Redis
const routes = await getTestUserRoutes(userId);

// Delete routes
await deleteTestUserRoutes(userId);
await cleanupAllTestRoutes();  // Deletes all test routes from Redis
```

## Environment

Tests use these environment variables (set in `test-app.ts`):

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_DOMAIN` | `test.example.com` | Domain suffix for tests |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection (use `redis://redis:6379` in Docker) |
| `GOOGLE_APPLICATION_CREDENTIALS` | - | Path to Firebase service account JSON |

## Test Data Isolation

- All test users are prefixed with `testuser` for easy identification and cleanup
- `beforeEach` creates fresh test data, `afterEach` cleans up
- `before`/`after` hooks handle global cleanup of any leftover test data
- Routes are stored in Redis with keys like `routes:testuser...`

## Adding New Tests

1. Import helpers from `test-helpers.ts`
2. Use `beforeEach`/`afterEach` for test isolation
3. Use `signMessage()` for authenticated endpoints
4. Verify both API response and underlying storage (Firestore/Redis)

Example:

```typescript
import { generateTestUserId, createTestUser, signMessage, deleteTestUser } from "./test-helpers.js";

describe("My New Endpoint", () => {
  let testUserId: string;
  let testKeys: { publicKey: string; privateKey: string };

  beforeEach(async () => {
    testUserId = generateTestUserId();
    testKeys = await createTestUser(testUserId);
  });

  afterEach(async () => {
    await deleteTestUser(testUserId);
  });

  it("should do something", async () => {
    const signature = await signMessage(testKeys.privateKey, testUserId);

    const response = await request(app)
      .post(`/my-endpoint/${testUserId}/${signature}`)
      .send({ data: "test" })
      .expect(200);

    expect(response.body.success).to.be.true;
  });
});
```
