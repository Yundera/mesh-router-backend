import cors from "cors";
import express from "express";
import { initializeFb } from "../firebase/firebaseIntegration.js";
import { routerAPI } from "../services/RouterAPI.js";

// Set test environment variables
process.env.SERVER_DOMAIN = "test.example.com"; // unconditional: the dev .env sets a real zone, and specs share one process
process.env.REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

let initialized = false;

/**
 * Create and configure the Express app for testing
 */
export function createTestApp(): express.Application {
  // Initialize Firebase only once
  if (!initialized) {
    initializeFb();
    initialized = true;
  }

  const app = express();
  app.use(express.json());
  app.use(cors());

  // The test routes point at unreachable IPs: accept them without the live probe
  // (RouteValidator has its own tests in route-input.spec.ts).
  routerAPI(app, async (routes) => ({ accepted: routes.map((route) => ({ route })), rejected: [] }));

  return app;
}
