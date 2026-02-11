# Data Schema

## Firestore Collections

### users/%uid%
User profile data managed by Firebase Auth.

### permissions/%uid%
User permission flags.

### nsl-router/%uid%
Domain registration data.
- `domainName`: string - User's chosen subdomain
- `serverDomain`: string - Server domain suffix (e.g., nsl.sh) - informational only
- `publicKey`: string - Ed25519 public key for signature verification
- `targetPort`: number (optional) - Port where Caddy listens (default: 443)
- `lastSeenOnline`: string (optional) - ISO timestamp of last heartbeat
- `createdate`: string - Creation timestamp
- `createdby`: string - Creator user ID
- `lastupdate`: string - Last update timestamp
- `updatedby`: string - Last updater user ID

## Redis Keys

### routes:{userId}
Route entries for a user.
- **TTL**: 600 seconds (configurable via ROUTES_TTL_SECONDS)
- **Value**: JSON array of routes
```json
[
  {"ip": "203.0.113.5", "port": 443, "priority": 1, "source": "agent"},
  {"ip": "10.77.0.5", "port": 443, "priority": 2, "source": "tunnel"}
]
```

Route fields:
- `ip`: string - Target IP address
- `port`: number - Target port (1-65535)
- `priority`: number - Route priority (lower = higher priority, 1 = direct, 2 = tunnel)
- `source`: string - Route source identifier (e.g., "agent", "tunnel")
- `healthCheck`: object (optional) - Health check configuration
  - `path`: string - HTTP path for health checks
  - `host`: string (optional) - Host header override

### health:{userId}:{routeHash}
Health check status for a specific route (optional).
- **TTL**: 300 seconds
- **Value**: JSON object
```json
{
  "healthy": true,
  "checkedAt": "2024-01-15T10:30:00Z",
  "failures": 0
}
```

### domain:{domainName} (cache, optional)
Cached domain-to-userId mapping.
- **TTL**: 3600 seconds
- **Value**: userId string
