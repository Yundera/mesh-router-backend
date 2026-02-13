# Manual Testing: Domain Activity Tracking & Cleanup

This document describes how to manually test the domain activity tracking and cleanup mechanism.

## Overview

The cleanup system:
1. Tracks domain activity when routes are registered (Redis sorted set `domains:activity`)
2. Lists active domains via `GET /domains/active`
3. Cleans up inactive domains via `POST /admin/cleanup` (protected endpoint)
4. Logs domain events to `logs/domain-events.log`

## Prerequisites

- Docker and Docker Compose installed
- Access to the `mesh-router-backend/backend-dev` directory

## Setup

### 1. Configure Environment

```bash
cd mesh-router-backend/backend-dev

# Create .env from example if it doesn't exist
cp .env.example .env
```

Edit `.env` and ensure these are set:
```
SERVER_DOMAIN=test.example.com
SERVICE_API_KEY=test-secret-key
```

### 2. Start the Dev Stack

```bash
docker-compose up -d
```

Verify services are running:
```bash
docker-compose ps
```

Expected output should show `mesh-router-backend-dev` and `mesh-router-redis` running.

### 3. Check Backend Health

```bash
curl http://localhost:8192/version
```

Expected response:
```json
{"version":2,"minClientVersion":2,"serverDomain":"test.example.com"}
```

---

## Test Cases

### Test 1: List Active Domains (Empty)

**Purpose:** Verify the `/domains/active` endpoint works with no active domains.

```bash
curl -s http://localhost:8192/domains/active | jq .
```

**Expected Response:**
```json
{
  "domains": [],
  "count": 0,
  "inactiveDays": 30
}
```

---

### Test 2: Admin Endpoint Authentication

**Purpose:** Verify the admin endpoint requires authentication.

**Without auth (should fail):**
```bash
curl -s -X POST http://localhost:8192/admin/cleanup
```

**Expected Response:**
```json
{"error":"Unauthorized"}
```

**With auth (should succeed):**
```bash
curl -s -X POST "http://localhost:8192/admin/cleanup?dryRun=true" \
  -H "Authorization: Bearer test-secret-key;admin" | jq .
```

**Expected Response:**
```json
{
  "dryRun": true,
  "wouldRelease": [],
  "count": 0,
  "inactiveDays": 30
}
```

---

### Test 3: Simulate Inactive Domain in Redis

**Purpose:** Test that the cleanup mechanism correctly identifies inactive domains.

**Step 1: Add a simulated inactive user to Redis (31 days old)**

```bash
# Calculate timestamp for 31 days ago (in milliseconds)
OLD_TIMESTAMP=$(( $(date +%s%3N) - 31*24*60*60*1000 ))

# Add to Redis activity tracking
docker exec mesh-router-redis redis-cli ZADD domains:activity $OLD_TIMESTAMP "test-inactive-user"
```

**Step 2: Verify it was added**

```bash
docker exec mesh-router-redis redis-cli ZRANGE domains:activity 0 -1 WITHSCORES
```

**Expected Output:**
```
1) "test-inactive-user"
2) "<timestamp>"
```

**Step 3: Dry-run cleanup to see it would be detected**

```bash
curl -s -X POST "http://localhost:8192/admin/cleanup?dryRun=true" \
  -H "Authorization: Bearer test-secret-key;admin" | jq .
```

**Expected Response:**
```json
{
  "dryRun": true,
  "wouldRelease": [],
  "count": 0,
  "inactiveDays": 30
}
```

Note: The user won't appear in `wouldRelease` because they don't have a domain in Firestore. The cleanup will still remove them from Redis tracking.

**Step 4: Run actual cleanup**

```bash
curl -s -X POST http://localhost:8192/admin/cleanup \
  -H "Authorization: Bearer test-secret-key;admin" | jq .
```

**Expected Response:**
```json
{
  "message": "Cleanup completed",
  "releasedCount": 0,
  "domains": []
}
```

**Step 5: Verify Redis was cleaned**

```bash
docker exec mesh-router-redis redis-cli ZRANGE domains:activity 0 -1 WITHSCORES
```

**Expected Output:** Empty (the inactive user was removed)

---

### Test 4: Simulate Active Domain in Redis

**Purpose:** Verify that recently active domains are NOT cleaned up.

**Step 1: Add a simulated active user to Redis (now)**

```bash
docker exec mesh-router-redis redis-cli ZADD domains:activity $(date +%s%3N) "test-active-user"
```

**Step 2: Verify it was added**

```bash
docker exec mesh-router-redis redis-cli ZRANGE domains:activity 0 -1 WITHSCORES
```

**Step 3: Dry-run cleanup**

```bash
curl -s -X POST "http://localhost:8192/admin/cleanup?dryRun=true" \
  -H "Authorization: Bearer test-secret-key;admin" | jq .
```

**Expected Response:**
```json
{
  "dryRun": true,
  "wouldRelease": [],
  "count": 0,
  "inactiveDays": 30
}
```

The active user should NOT be in the cleanup list.

**Step 4: Verify user still exists in Redis**

```bash
docker exec mesh-router-redis redis-cli ZRANGE domains:activity 0 -1 WITHSCORES
```

**Expected:** The `test-active-user` should still be present.

**Cleanup:** Remove test data

```bash
docker exec mesh-router-redis redis-cli ZREM domains:activity "test-active-user"
```

---

### Test 5: Check Active Domains List

**Purpose:** Verify `/domains/active` returns domains with recent activity.

**Step 1: Add an active user to Redis**

```bash
docker exec mesh-router-redis redis-cli ZADD domains:activity $(date +%s%3N) "test-list-user"
```

**Step 2: Query active domains**

```bash
curl -s http://localhost:8192/domains/active | jq .
```

**Expected Response:**
```json
{
  "domains": [],
  "count": 0,
  "inactiveDays": 30
}
```

Note: The user appears in Redis but won't appear in the domains list because they don't have a domain registered in Firestore. With a real registered domain, the user would appear here.

**Cleanup:**

```bash
docker exec mesh-router-redis redis-cli ZREM domains:activity "test-list-user"
```

---

## Cleanup

After testing, stop the dev stack:

```bash
cd mesh-router-backend/backend-dev
docker-compose down
```

To also remove volumes (Redis data):

```bash
docker-compose down -v
```

---

## Troubleshooting

### Backend won't start

Check logs:
```bash
docker-compose logs mesh-router-backend
```

Common issues:
- Missing `serviceAccount.json` for Firebase
- Invalid environment variables

### Redis connection issues

Check Redis is running:
```bash
docker exec mesh-router-redis redis-cli PING
```

Expected: `PONG`

### Check backend logs for cleanup activity

```bash
docker-compose logs mesh-router-backend | grep -i cleanup
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `INACTIVE_DOMAIN_DAYS` | 30 | Days of inactivity before domain release |
| `DOMAIN_LOG_PATH` | `logs/domain-events.log` | Path to audit log |
| `CLEANUP_CRON_SCHEDULE` | `0 3 * * *` | Cron schedule (default: 3 AM daily) |
| `SERVICE_API_KEY` | (required) | API key for admin endpoints |
