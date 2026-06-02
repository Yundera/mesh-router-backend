/**
 * mesh-usage summary [--date YYYY-MM-DD] [--days N] [--json]
 *
 * Global headline: distinct active users + the top apps for the window
 * (default: 1 day = DAU).
 */
import { getGlobalActiveUsers, getTopApps, dateWindow, utcDateString } from "../services/Usage.js";
import { hasFlag, intFlag, dateFlag, renderTable, MISSING } from "../cli/format.js";

const TOP_APPS_IN_SUMMARY = 5;

export async function main(argv: string[]): Promise<void> {
  const endDate = dateFlag(argv, "date", utcDateString());
  const end = new Date(`${endDate}T00:00:00Z`);
  const days = intFlag(argv, "days", 1);
  const json = hasFlag(argv, "json");

  const window = dateWindow(days, end);
  const [activeUsers, topApps] = await Promise.all([
    getGlobalActiveUsers(window),
    getTopApps(window, TOP_APPS_IN_SUMMARY),
  ]);

  if (json) {
    console.log(JSON.stringify({ endDate, days, activeUsers, topApps }, null, 2));
    return;
  }

  console.log("─── usage summary ─────────────────────────────────────");
  console.log(`  window:        ${days}d ending ${endDate} UTC`);
  console.log(`  active users:  ${activeUsers}`);
  console.log(`  apps used:     ${topApps.length === 0 ? MISSING : topApps.length + (topApps.length === TOP_APPS_IN_SUMMARY ? "+" : "")}`);
  console.log("");
  if (topApps.length === 0) {
    console.log("  (no usage recorded for this window)");
    return;
  }
  renderTable(
    ["app", "active users"],
    topApps.map((a) => [a.app || MISSING, String(a.activeUsers)])
  );
}
