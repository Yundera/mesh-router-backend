import cors from "cors";
import express from "express";
import { initializeFb } from "../firebase/firebaseIntegration.js";
import { routerAPI } from "../services/RouterAPI.js";

// Set test environment variables
process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";

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

  routerAPI(app);

  return app;
}
