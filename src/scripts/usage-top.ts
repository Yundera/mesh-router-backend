/**
 * mesh-usage top [--date YYYY-MM-DD] [--days N] [--top N] [--json]
 *
 * Apps ranked by distinct active users over a window (default: 1 day = DAU).
 */
import { getTopApps, dateWindow, utcDateString } from "../services/Usage.js";
import { hasFlag, intFlag, dateFlag, renderTable, MISSING } from "../cli/format.js";

export async function main(argv: string[]): Promise<void> {
  const endDate = dateFlag(argv, "date", utcDateString());
  const end = new Date(`${endDate}T00:00:00Z`);
  const days = intFlag(argv, "days", 1);
  const top = intFlag(argv, "top", 20);
  const json = hasFlag(argv, "json");

  const ranked = await getTopApps(dateWindow(days, end), top);

  if (json) {
    console.log(JSON.stringify({ endDate, days, top, apps: ranked }, null, 2));
    return;
  }

  console.log(`top apps by active users   (${days}d window ending ${endDate} UTC)\n`);
  if (ranked.length === 0) {
    console.log("(no usage recorded for this window)");
    return;
  }
  renderTable(
    ["rank", "app", "active users"],
    ranked.map((a, i) => [String(i + 1), a.app || MISSING, String(a.activeUsers)])
  );
}
