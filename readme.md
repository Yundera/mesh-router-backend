# mesh-router-backend

Express.js API for Mesh Router domain management and route resolution. Handles user domain registration, verification, and multi-route management for the mesh network.

## API Endpoints

### Domain Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/available/:domain` | Public | Check if domain name is available |
| GET | `/domain/:userid` | Public | Get user's domain info |
| POST | `/domain` | Firebase | Register or update domain |
| DELETE | `/domain` | Firebase | Delete user's domain |
| GET | `/verify/:userid/:sig` | Public | Verify domain ownership via Ed25519 signature |

### Routes v2 API (Redis-backed)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/routes/:userid/:sig` | Ed25519 Signature | Register routes (with validation) |
| DELETE | `/routes/:userid/:sig` | Ed25519 Signature | Delete all routes for a user |
| GET | `/routes/:userid` | Public | Get routes for a user |
| GET | `/resolve/v2/:domain` | Public | Resolve domain to routes with TTL info |

#### Route Types

Routes have a `type` field that determines how they're used:

| Type | Used By | Example |
|------|---------|---------|
| `ip` | OpenResty Gateway | `{type: "ip", ip: "88.187.147.189", port: 443}` |
| `domain` | CF Worker | `{type: "domain", domain: "88-187-147-189.sslip.io", port: 443}` |

#### Route Validation at Registration

When routes are submitted via `POST /routes/:userid/:sig`, the backend validates each route before storing:

1. **Connectivity Test**: Attempts to connect to the route (5 second timeout)
2. **SSL Verification**: For HTTPS routes, verifies the certificate is valid
3. **Only Healthy Routes Stored**: Routes that fail validation are rejected

Response includes both accepted and rejected routes:
```json
{
  "message": "Routes registered successfully.",
  "accepted": [
    {"type": "domain", "domain": "88-187-147-189.sslip.io", "port": 443}
  ],
  "rejected": [
    {"type": "domain", "domain": "88-187-147-189.nip.io", "port": 443, "reason": "Connection timeout"}
  ],
  "domain": "myname.nsl.sh"
}
```

### Heartbeat & Status

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/heartbeat/:userid/:sig` | Ed25519 Signature | Update online status |
| GET | `/status/:userid` | Public | Check if user is online |

### Domain Activity & Cleanup

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/domains/active` | Public | List all active domains (with recent route activity) |
| POST | `/admin/cleanup` | SERVICE_API_KEY | Manually trigger inactive domain cleanup |

### Certificate Authority (Private PKI)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/ca-cert` | Public | Get CA public certificate (PEM format) |
| POST | `/cert/:userid/:sig` | Ed25519 Signature | Sign a CSR and get certificate (with optional nip.io SAN) |

### Example Usage

```bash
# Check domain availability
curl http://localhost:8192/available/myname
# Response: {"available":true,"message":"Domain name is available."}

# Resolve domain to routes (v2 API)
curl http://localhost:8192/resolve/v2/myname
# Response: {"userId":"abc123","domainName":"myname","serverDomain":"nsl.sh","routes":[{"ip":"10.77.0.5","port":443,"priority":1}],"routesTtl":580,"lastSeenOnline":"2024-01-15T10:30:00Z"}

# Register routes with validation (requires Ed25519 signature of userid)
curl -X POST http://localhost:8192/routes/{userid}/{signature} \
  -H "Content-Type: application/json" \
  -d '{
    "routes": [
      {"type": "ip", "ip": "88.187.147.189", "port": 443, "priority": 1, "scheme": "https"},
      {"type": "domain", "domain": "88-187-147-189.sslip.io", "port": 443, "priority": 2, "scheme": "https"},
      {"type": "domain", "domain": "88-187-147-189.nip.io", "port": 443, "priority": 3, "scheme": "https"}
    ]
  }'
# Response: {"message":"Routes registered successfully.","accepted":[...],"rejected":[...],"domain":"myname.nsl.sh"}

# Verify domain ownership
curl http://localhost:8192/verify/{userid}/{signature}
# Response: {"serverDomain":"nsl.sh","domainName":"myname"}

# Get CA certificate (for Cloudflare COTS or client trust)
curl http://localhost:8192/ca-cert
# Response: -----BEGIN CERTIFICATE-----\n...(PEM format)

# Request certificate with nip.io SAN (for HTTPS via Cloudflare Workers)
curl -X POST http://localhost:8192/cert/{userid}/{signature} \
  -H "Content-Type: application/json" \
  -d '{"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "publicIp": "2001:bc8:3021::1"}'
# Response: {"certificate":"-----BEGIN CERTIFICATE-----\n...","expiresAt":"2026-01-30T12:00:00.000Z","caCertificate":"..."}
# Certificate will include SAN: 2001-bc8-3021--1.nip.io
```

## Getting Started

### Installation

```bash
pnpm install
```

### Configuration

**Environment Variables**:
| Variable | Required | Description |
|----------|----------|-------------|
| `SERVER_DOMAIN` | Yes | The server domain suffix for all user domains (e.g., `nsl.sh`) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Yes | Path to Firebase service account JSON |
| `REDIS_URL` | Yes | Redis connection URL (e.g., `redis://localhost:6379`) |
| `ROUTES_TTL_SECONDS` | No | TTL for route entries in seconds (default: 600) |
| `SERVICE_API_KEY` | No | API key for service-to-service authentication |
| `CA_CERT_PATH` | No | Path to CA certificate for PKI (default: `config/ca-cert.pem`) |
| `CA_KEY_PATH` | No | Path to CA private key for PKI (default: `config/ca-key.pem`) |
| `CERT_VALIDITY_HOURS` | No | Certificate validity in hours (default: 72) |
| `INACTIVE_DOMAIN_DAYS` | No | Days of inactivity before domain cleanup (default: 30) |
| `DOMAIN_LOG_PATH` | No | Path for domain event audit log (default: `logs/domain-events.log`) |
| `CLEANUP_CRON_SCHEDULE` | No | Cron schedule for cleanup job (default: `0 3 * * *` - 3 AM daily) |

**Service Account** (required):
- Path: `./config/serviceAccount.json`
- Documentation: [serviceAccount.json documentation](./config/serviceAccount.json.md)

### Development

#### Option 1: Docker (Recommended)

See [backend-dev/README.md](./backend-dev/README.md) for the Docker-based development environment with hot reload.

```bash
cd backend-dev
./start.sh      # Linux/Mac
.\start.ps1     # Windows
```

#### Option 2: Local

```bash
pnpm start      # Development with hot reload
pnpm build      # Build TypeScript
pnpm exec       # Build and run
```

### Testing

```bash
# Using Docker dev environment
cd backend-dev
./test.sh       # Linux/Mac
.\test.ps1      # Windows

# Or run directly
pnpm test
```

## Deployment

Build and publish using Dockflow:

```bash
npx dockflow build
npx dockflow publish
```

## Architecture

```
src/
├── index.ts                    # Express app entry point
├── configuration/
│   └── config.ts               # Environment configuration (SERVER_DOMAIN, ROUTES_TTL)
├── services/
│   ├── RouterAPI.ts            # API endpoint definitions
│   ├── Domain.ts               # Domain business logic
│   ├── Routes.ts               # Redis-backed route management
│   ├── DomainCleanup.ts        # Inactive domain cleanup logic
│   ├── DomainLogger.ts         # Domain event audit logging
│   ├── CertificateAuthority.ts # Private PKI certificate signing
│   └── ExpressAuthenticateMiddleWare.ts
├── firebase/
│   └── firebaseIntegration.ts  # Firebase Admin SDK setup
├── redis/
│   └── redisClient.ts          # Redis client configuration
├── library/
│   └── KeyLib.ts               # Ed25519 signature utilities
├── DataBaseDTO/
│   └── DataBaseNSLRouter.ts    # Firestore data models
└── tests/
    ├── api.spec.ts             # Integration tests
    ├── test-app.ts             # Test app factory
    └── test-helpers.ts         # Test utilities
```

## Route System

Routes are stored in Redis with automatic TTL expiration:
- Routes expire after `ROUTES_TTL_SECONDS` (default: 600 seconds / 10 minutes)
- Agents refresh their routes every ~300 seconds (implicit heartbeat)
- Routes are merged by `ip:port` or `domain:port` key, allowing multiple sources
- `/resolve/v2/:domain` returns `routesTtl` showing seconds until expiration

### Route Types

| Type | Field | Used By | Example |
|------|-------|---------|---------|
| `ip` | `ip` | OpenResty Gateway | `88.187.147.189` |
| `domain` | `domain` | CF Worker | `88-187-147-189.sslip.io` |

CF Workers cannot fetch IP addresses directly (Cloudflare error 1003), so they use domain routes with wildcard DNS services (sslip.io, nip.io) that resolve to the embedded IP.

### Route Validation

Routes are validated at registration time:
1. Backend tests connectivity to each route (5 second timeout)
2. For HTTPS routes, SSL certificate is verified
3. Only routes that pass validation are stored in Redis
4. Agent receives feedback on which routes were accepted/rejected

This ensures the CF Worker and Gateway only receive routes that are known to be reachable.

## Domain Activity Tracking & Cleanup

The system tracks domain activity and automatically cleans up inactive domains:

- **Activity Tracking**: When routes are registered (`POST /routes`), the user's activity is recorded in Redis (sorted set `domains:activity`) with a timestamp.
- **Active Domains**: `GET /domains/active` returns domains with activity within `INACTIVE_DOMAIN_DAYS` (default: 30 days).
- **Automatic Cleanup**: A cron job runs on `CLEANUP_CRON_SCHEDULE` (default: 3 AM daily) to release inactive domains.
- **Manual Cleanup**: `POST /admin/cleanup` triggers cleanup manually (requires `SERVICE_API_KEY` auth).
- **Audit Log**: Domain assignments and releases are logged to `DOMAIN_LOG_PATH`.

**Cleanup Process:**
1. Finds users with no route activity for > `INACTIVE_DOMAIN_DAYS`
2. Clears their `domainName` and `publicKey` in Firestore (releases the domain)
3. Removes them from Redis activity tracking
4. Logs the release event

**Manual Testing:** See [test/MANUAL_TEST.md](./test/MANUAL_TEST.md) for testing instructions.

## Domain Configuration

The `serverDomain` returned by all API endpoints comes from the `SERVER_DOMAIN` environment variable, not from the database. This allows the same backend to serve different domains (e.g., `nsl.sh` for production, `domain.com` for staging) without database changes.

The `serverDomain` field stored in Firestore is informational/audit only - it records what the client originally sent but is not used in API responses.

## References

- [Firebase Admin SDK](https://github.com/firebase/firebase-admin-node)
- [libsodium (Ed25519 signatures)](https://github.com/jedisct1/libsodium.js)
- [ioredis](https://github.com/redis/ioredis)
