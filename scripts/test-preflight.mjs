// Verify preflightModel() against stubbed /api/v1/models responses.
import http from "node:http";
import assert from "node:assert/strict";
import { preflightModel } from "../app/lib/config.mjs";

const cases = [
  { status: 200, body: { data: [] }, model: "google/gemini-3.6-flash", expectFail: "No model providers" },
  {
    status: 200,
    body: { data: [{ name: "google/gemini-3.1-pro-preview" }] },
    model: "google/gemini-3.6-flash",
    expectFail: "was not found",
  },
  {
    status: 200,
    body: { data: [{ name: "google/gemini-3.6-flash" }, { name: "openai/gpt-5.4-mini" }] },
    model: "google/gemini-3.6-flash",
    expectFail: null,
  },
];

const server = http.createServer((req, res) => {
  const c = cases.shift() ?? cases[cases.length - 1];
  res.writeHead(c.status, { "content-type": "application/json" });
  res.end(JSON.stringify(c.body));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

// refill case queue since handler consumed one per request
cases.unshift();

const run = async () => {
  // case 1: no providers
  let r = await preflightModel(base, "google/gemini-3.6-flash");
  assert.equal(r.ok, false);
  assert.match(r.reason, /No model providers/);
  console.log("case1 ok:", r.reason.slice(0, 60) + "...");

  // case 2: pro-only configured, flash requested -> actionable mismatch
  r = await preflightModel(base, "google/gemini-3.6-flash");
  assert.equal(r.ok, false);
  assert.match(r.reason, /gemini-3\.6-flash/);
  console.log("case2 ok:", r.reason.slice(0, 80) + "...");

  // case 3: matching model -> pass
  r = await preflightModel(base, "google/gemini-3.6-flash");
  assert.equal(r.ok, true);
  console.log("case3 ok:", JSON.stringify(r.models));

  // case 4: unreachable server
  r = await preflightModel("http://127.0.0.1:9", "x");
  assert.equal(r.ok, false);
  assert.match(r.reason, /not reachable/);
  console.log("case4 ok:", r.reason.slice(0, 60) + "...");

  server.close();
};
await run();
console.log("PREFLIGHT TESTS PASS");
