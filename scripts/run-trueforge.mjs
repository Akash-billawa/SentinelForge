#!/usr/bin/env node
/**
 * Run TrueForge locally on ANY OS - including native Windows.
 *
 * TrueForge v0.1.4 fails to start on Windows because kysely 0.29.5's
 * FileMigrationProvider calls `await import(absolutePath)` and Node's ESM
 * loader rejects `C:\...` paths (ERR_UNSUPPORTED_ESM_URL_SCHEME). The fix is
 * to import via pathToFileURL().href - correct on every platform.
 *
 * This script:
 *   1. installs @truefoundry/trueforge locally if missing (pinned version),
 *   2. applies the idempotent one-line patch to the bundled kysely copy,
 *   3. starts the TrueForge server, forwarding arguments/stdio.
 *
 * Usage:
 *   node scripts/run-trueforge.mjs [-- --port 8790]
 */

import { spawnSync, spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PINNED = process.env.TRUEFORGE_VERSION || "0.1.4";

function findKyselyProvider() {
  const require = createRequire(path.join(REPO_ROOT, "package.json"));
  const candidates = [];
  try {
    candidates.push(path.join(require.resolve("kysely/package.json"), "..", "migration", "file-migration-provider.js"));
  } catch {
    /* not hoisted */
  }
  candidates.push(
    path.join(REPO_ROOT, "node_modules", "kysely", "dist", "migration", "file-migration-provider.js"),
    path.join(
      REPO_ROOT,
      "node_modules",
      "@truefoundry",
      "trueforge",
      "node_modules",
      "kysely",
      "dist",
      "migration",
      "file-migration-provider.js",
    ),
  );
  return candidates.find((p) => existsSync(p));
}

function ensurePackage() {
  const pkgDir = path.join(REPO_ROOT, "node_modules", "@truefoundry", "trueforge");
  if (existsSync(pkgDir)) return;
  console.log(`[run-trueforge] installing @truefoundry/trueforge@${PINNED}...`);
  // Invoke npm's CLI via node directly - "npm" is npm.cmd on Windows and
  // spawnSync without a shell cannot execute .cmd files.
  const npmCli = path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  const cmd = existsSync(npmCli)
    ? [process.execPath, npmCli]
    : ["npm"];
  const res = spawnSync(cmd[0], [...cmd.slice(1), "i", `@truefoundry/trueforge@${PINNED}`, "--no-audit", "--no-fund"], {
    cwd: REPO_ROOT,
    stdio: "inherit",
    shell: !existsSync(npmCli),
  });
  if (res.status !== 0) throw new Error("npm install failed");
}

function patchKysely() {
  const file = findKyselyProvider();
  if (!file) throw new Error("kysely file-migration-provider.js not found under node_modules");
  let src = readFileSync(file, "utf8");
  if (src.includes("pathToFileURL")) {
    console.log("[run-trueforge] kysely already patched - skipping");
    return;
  }
  src = src.replace(
    /((?:import|from)[^\n]*util\/object-utils\.js[\"'];)/,
    "$1\nimport { pathToFileURL } from 'node:url';",
  );
  if (!src.includes("pathToFileURL")) {
    // fallback: prepend import after first line
    const lines = src.split("\n");
    lines.splice(1, 0, "import { pathToFileURL } from 'node:url';");
    src = lines.join("\n");
  }
  src = src.replace("await import(/* webpackIgnore: true */ filePath)", "await import(/* webpackIgnore: true */ pathToFileURL(filePath).href)");
  src = src.replace("await this.#props.import(filePath)\n                : await import(filePath)", "await this.#props.import(filePath)\n                : await import(pathToFileURL(filePath).href)");
  if (!src.includes("pathToFileURL(filePath).href")) {
    throw new Error("could not apply patch - upstream format changed; please file an issue");
  }
  writeFileSync(file, src);
  console.log(`[run-trueforge] patched ${path.relative(REPO_ROOT, file)} (Windows ESM URL scheme fix)`);
}

function main() {
  ensurePackage();
  patchKysely();

  const cli = path.join(REPO_ROOT, "node_modules", "@truefoundry", "trueforge", "dist", "cli.js");
  const args = process.argv.slice(2);
  console.log("[run-trueforge] starting TrueForge...");
  const child = spawn(process.execPath, [cli, ...args], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 0));
}

main();
