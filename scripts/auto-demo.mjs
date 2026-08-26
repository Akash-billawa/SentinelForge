/**
 * CLI wrapper: run the auto-demo loop standalone (prefer the in-process
 * serve-ui endpoint POST /api/auto-demo - it survives shell exits).
 *
 *   OPENROUTER_KEY=sk-or-... node scripts/auto-demo.mjs
 */

import { AutoDemo } from "../app/lib/auto-demo.mjs";

const key = process.env.OPENROUTER_KEY;
if (!key) {
  console.error("Set OPENROUTER_KEY in the environment first.");
  process.exit(1);
}
AutoDemo.start(key);
