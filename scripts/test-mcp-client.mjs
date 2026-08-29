// Regression tests for McpHttpClient against a stub that reproduces the real
// SentinelForge MCP server's three response shapes.
//
// The 202-with-empty-body case is what broke every demo run: the client called
// res.json() unconditionally and died with "Unexpected end of JSON input".
import http from "node:http";
import assert from "node:assert/strict";
import { McpHttpClient } from "../app/lib/mcp-client.mjs";

let sawInitializedNotification = false;

const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  const reply = (result) => ({ jsonrpc: "2.0", id: body.id, result });

  // Notifications: 202 Accepted, ZERO bytes, exactly like the Python server.
  if (body.method === "notifications/initialized") {
    sawInitializedNotification = true;
    res.writeHead(202, { "content-type": "application/json" });
    return res.end();
  }

  if (body.method === "initialize") {
    res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "sess-1" });
    return res.end(JSON.stringify(reply({ protocolVersion: "2025-03-26" })));
  }

  const tool = body.params?.name;

  // Streamable-http servers wrap tool replies in SSE data frames.
  if (tool === "reset_demo") {
    assert.equal(req.headers["mcp-session-id"], "sess-1", "session id must be forwarded");
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write(": ping\n\n");
    res.write(
      `data: ${JSON.stringify(
        reply({ content: [{ type: "text", text: JSON.stringify({ reset: true, existed: false }) }] }),
      )}\n\n`,
    );
    return res.end();
  }

  // Tool-level failure: isError + PLAIN TEXT (not JSON).
  if (tool === "boom") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(
      JSON.stringify(
        reply({ isError: true, content: [{ type: "text", text: "Error executing tool boom: refused" }] }),
      ),
    );
  }

  res.writeHead(404);
  res.end();
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/mcp`;

const client = new McpHttpClient(url);

// case 1: handshake survives the bodiless 202 acknowledgement
await client.init();
assert.equal(client.sessionId, "sess-1");
assert.ok(sawInitializedNotification, "initialized notification must be sent");
console.log("case1 ok: init() tolerates 202 + empty body, captured session", client.sessionId);

// case 2: SSE-framed tool result is parsed
const reset = await client.call("reset_demo", { incident_id: "INC-2026-0042" });
assert.deepEqual(reset, { reset: true, existed: false });
console.log("case2 ok: SSE tool result parsed ->", JSON.stringify(reset));

// case 3: tool errors surface their real message, not a JSON SyntaxError
await assert.rejects(() => client.call("boom"), /boom failed: Error executing tool boom: refused/);
console.log("case3 ok: tool error surfaced verbatim");

server.close();
console.log("MCP CLIENT TESTS PASS");
