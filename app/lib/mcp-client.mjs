/**
 * Minimal MCP streamable-http client (JSON-RPC over POST /mcp).
 * Used by the incident console to read demo state directly from the
 * SentinelForge MCP server - no LLM involved.
 */

export class McpHttpClient {
  constructor(url) {
    this.url = url;
    this.nextId = 1;
  }

  async #post(body, sessionId) {
    const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };
    if (sessionId) headers["mcp-session-id"] = sessionId;
    const res = await fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`MCP HTTP ${res.status}: ${await res.text()}`);
    const ct = res.headers.get("content-type") ?? "";
    if (ct.includes("text/event-stream")) {
      const text = await res.text();
      for (const line of text.split("\n")) {
        if (line.startsWith("data:")) return JSON.parse(line.slice(5).trim());
      }
      throw new Error("empty SSE body from MCP server");
    }
    const sessionIdOut = res.headers.get("mcp-session-id");
    return { json: await res.json(), sessionId: sessionIdOut };
  }

  async init() {
    const result = await this.#post({
      jsonrpc: "2.0",
      id: this.nextId++,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "sentinelforge-console", version: "0.1.0" },
      },
    });
    this.sessionId = result.sessionId ?? undefined;
    await this.#post({ jsonrpc: "2.0", method: "notifications/initialized" }, this.sessionId);
    return true;
  }

  async call(name, args = {}) {
    const payload = {
      jsonrpc: "2.0",
      id: this.nextId++,
      method: "tools/call",
      params: { name, arguments: args },
    };
    let res;
    try {
      res = await this.#post(payload, this.sessionId);
    } catch (err) {
      // Session may have expired server-side; re-handshake once and retry.
      await this.init();
      res = await this.#post(payload, this.sessionId);
    }
    const json = res.json ?? res;
    if (json.error) throw new Error(`MCP error: ${json.error.message}`);
    const out = json.result;
    const textItem = (out.content ?? []).find((c) => c.type === "text");
    return textItem ? JSON.parse(textItem.text) : out;
  }
}
