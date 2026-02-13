import * as fs from "fs";
import * as path from "path";
import { getDomainLogPath } from "../configuration/config.js";

/**
 * Ensures the log directory exists.
 */
function ensureLogDirectory(): void {
  const logPath = getDomainLogPath();
  const logDir = path.dirname(logPath);
  if (logDir && !fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
}

/**
 * Appends a log entry to the domain events log file.
 */
function appendLogEntry(entry: string): void {
  try {
    ensureLogDirectory();
    const timestamp = new Date().toISOString();
    const logLine = `${timestamp} ${entry}\n`;
    fs.appendFileSync(getDomainLogPath(), logLine);
  } catch (error) {
    console.error("Failed to write domain event log:", error);
  }
}

/**
 * Logs a domain assignment event.
 * @param domainName - The domain name that was assigned
 * @param userId - The user ID that owns the domain
 */
export function logDomainAssigned(domainName: string, userId: string): void {
  appendLogEntry(`ASSIGNED ${domainName} to ${userId}`);
}

/**
 * Logs a domain release event due to inactivity.
 * @param domainName - The domain name that was released
 * @param userId - The user ID that owned the domain
 * @param inactiveDays - Number of days the domain was inactive
 */
export function logDomainReleased(domainName: string, userId: string, inactiveDays: number): void {
  appendLogEntry(`RELEASED ${domainName} from ${userId} (inactive ${inactiveDays} days)`);
}
