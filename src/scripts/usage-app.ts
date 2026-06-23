/**
 * mesh-cli app <app> [--days N] [--date YYYY-MM-DD] [--json]
 *
 * Distinct active users for one app. Default shows the DAU/WAU/MAU trio ending
 * at --date (today UTC). With --days N, shows active users over that single window.
 */
import { getAppActiveUsers, dateWindow, utcDateString } from "../services/Usage.js";
import { positionals, flagValue, hasFlag, intFlag, dateFlag, renderTable } from "../cli/format.js";

export async function main(argv: string[]): Promise<void> {
  const [app] = positionals(argv);
  if (!app) {
    throw new Error("Usage: mesh-cli app <app> [--days N] [--date YYYY-MM-DD] [--json]");
  }

  const endDate = dateFlag(argv, "date", utcDateString());
  const end = new Date(`${endDate}T00:00:00Z`);
  const json = hasFlag(argv, "json");
  const customDays = flagValue(argv, "days") !== undefined ? intFlag(argv, "days", 1) : undefined;

  if (customDays !== undefined) {
    const users = await getAppActiveUsers(app, dateWindow(customDays, end));
    if (json) {
      console.log(JSON.stringify({ app, endDate, days: customDays, activeUsers: users }, null, 2));
      return;
    }
    console.log(`${app}: ${users} active user${users === 1 ? "" : "s"} over ${customDays} day${customDays === 1 ? "" : "s"} ending ${endDate}`);
    return;
  }

  const [dau, wau, mau] = await Promise.all([
    getAppActiveUsers(app, dateWindow(1, end)),
    getAppActiveUsers(app, dateWindow(7, end)),
    getAppActiveUsers(app, dateWindow(30, end)),
  ]);

  if (json) {
    console.log(JSON.stringify({ app, endDate, dau, wau, mau }, null, 2));
    return;
  }

  console.log(`app: ${app}   (ending ${endDate} UTC)\n`);
  renderTable(
    ["metric", "window", "active users"],
    [
      ["DAU", "1d", String(dau)],
      ["WAU", "7d", String(wau)],
      ["MAU", "30d", String(mau)],
    ]
  );
}
