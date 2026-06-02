/**
 * Shared CLI helpers for the mesh-usage commands.
 * Mirrors the hand-rolled parsing / table style of the pcs-orchestrator CLI
 * (no argument-parsing library, padEnd columns, "—" for missing values).
 */

export const MISSING = "—";

/** Positional arguments (everything that is not a --flag or its value). */
export function positionals(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      // Skip the value that follows a --key (unless it's a bare boolean flag at the end).
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

/** Value following `--name`, or undefined. */
export function flagValue(argv: string[], name: string): string | undefined {
  const idx = argv.indexOf(`--${name}`);
  return idx >= 0 ? argv[idx + 1] : undefined;
}

/** Presence of a boolean `--name` flag. */
export function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(`--${name}`);
}

/** Integer value for `--name`, falling back to `def`. Throws on a non-integer value. */
export function intFlag(argv: string[], name: string, def: number): number {
  const raw = flagValue(argv, name);
  if (raw === undefined) return def;
  const parsed = parseInt(raw, 10);
  if (isNaN(parsed) || parsed < 1) {
    throw new Error(`--${name} must be a positive integer (got '${raw}')`);
  }
  return parsed;
}

/** Validate and return a YYYY-MM-DD date string, or throw. */
export function dateFlag(argv: string[], name: string, def: string): string {
  const raw = flagValue(argv, name);
  if (raw === undefined) return def;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new Error(`--${name} must be YYYY-MM-DD (got '${raw}')`);
  }
  return raw;
}

/**
 * Print a left-aligned, double-space-separated table with a dashed header rule.
 * Numeric-looking cells are still left-aligned to match the pcs CLI style.
 */
export function renderTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length))
  );
  const fmt = (cells: string[]) =>
    cells.map((c, i) => (c ?? "").padEnd(widths[i])).join("  ");
  console.log(fmt(headers));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const r of rows) console.log(fmt(r));
}
