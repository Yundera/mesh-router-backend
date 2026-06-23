/**
 * mesh-cli CLI entrypoint — wired up at /usr/local/bin/mesh-cli in the image
 * (see Dockerfile). Each subcommand is implemented in src/scripts/usage-*.ts and
 * exports an async `main(argv)`. Reads the usage:* daily buckets directly from
 * Redis (same REDIS_URL the backend uses), so it must run inside the container:
 *
 *   docker compose exec mesh-router-backend mesh-cli            # help
 *   docker compose exec mesh-router-backend mesh-cli summary
 *   docker compose exec mesh-router-backend mesh-cli app nextcloud --days 7
 *   docker compose exec mesh-router-backend mesh-cli top --top 10 --json
 */

import { main as usageApp } from "../scripts/usage-app.js";
import { main as usageTop } from "../scripts/usage-top.js";
import { main as usageSummary } from "../scripts/usage-summary.js";
import { main as resetLink } from "../scripts/reset-link.js";

type Command = {
  name: string;
  description: string;
  run: (argv: string[]) => Promise<void>;
};

const COMMANDS: Command[] = [
  {
    name: "summary",
    description: "Global headline: distinct active users + top apps. [--date YYYY-MM-DD] [--days N] [--json].",
    run: usageSummary,
  },
  {
    name: "app",
    description: "Active users for one app (DAU/WAU/MAU by default): <app> [--days N] [--date YYYY-MM-DD] [--json].",
    run: usageApp,
  },
  {
    name: "top",
    description: "Apps ranked by active users: [--date YYYY-MM-DD] [--days N] [--top N] [--json].",
    run: usageTop,
  },
  {
    name: "reset-link",
    description: "Generate a Firebase password-reset link (does not send mail): <email> [--json].",
    run: resetLink,
  },
];

function printHelp(): void {
  console.log("Usage: mesh-cli <command> [args...]");
  console.log("");
  console.log("App-usage (DAU) KPIs for mesh-router. Run inside the container,");
  console.log("e.g. `docker compose exec mesh-router-backend mesh-cli summary`.");
  console.log("");
  console.log("Commands:");
  const width = Math.max(...COMMANDS.map((c) => c.name.length));
  for (const c of COMMANDS) {
    console.log(`  ${c.name.padEnd(width)}  ${c.description}`);
  }
  console.log("");
  console.log("Data is a rolling ~90-day window of distinct (user, app, day) tuples.");
}

async function dispatch(argv: string[]): Promise<number> {
  const [head, ...rest] = argv;
  if (!head || head === "--help" || head === "-h" || head === "help") {
    printHelp();
    return 0;
  }
  const cmd = COMMANDS.find((c) => c.name === head);
  if (!cmd) {
    console.error(`mesh-cli: unknown command '${head}'\n`);
    printHelp();
    return 1;
  }
  await cmd.run(rest);
  return 0;
}

dispatch(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }
);
