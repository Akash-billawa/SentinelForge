/**
 * Minimal MCP streamable-http client (JSON-RPC over POST /mcp).
 * Used by the incident console to read investigation state directly from the
 * SentinelForge MCP server - no LLM involved.
 */

export class McpHttpClient {
  constructor(url) {
    this.url = url;
    this.nextId = 1;
    this.sessionId = undefined;
  }

  /**
   * POST one JSON-RPC message. Always returns { json, sessionId }, where json
   * is null for bodiless acknowledgements.
   *
   * Three response shapes have to be tolerated, because the Python MCP server
   * uses all three:
   *   - 202 Accepted + EMPTY body      -> notifications (no reply is owed)
   *   - application/json               -> plain JSON-RPC reply
   *   - text/event-stream             -> reply wrapped in SSE data: frames
   * Parsing unconditionally is what produced "Unexpected end of JSON input"
   * and aborted every investigation before it started.
   */
  async #post(body, sessionId) {
    const headers = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    };
    if (sessionId) headers["mcp-session-id"] = sessionId;
    const res = await fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`MCP HTTP ${res.status}: ${await res.text()}`);

    const outSession = res.headers.get("mcp-session-id") ?? undefined;
    const text = await res.text();
    if (!text.trim()) return { json: null, sessionId: outSession };

    const ct = res.headers.get("content-type") ?? "";
    if (ct.includes("text/event-stream")) {
      for (const line of text.split("\n")) {
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (!data) continue; // keepalive frame
        try {
          return { json: JSON.parse(data), sessionId: outSession };
        } catch {
          /* partial frame - keep scanning */
        }
      }
      throw new Error("empty SSE body from MCP server");
    }
    return { json: JSON.parse(text), sessionId: outSession };
  }

  async init() {
    const { sessionId } = await this.#post({
      jsonrpc: "2.0",
      id: this.nextId++,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "sentinelforge-console", version: "0.1.0" },
      },
    });
    this.sessionId = sessionId;
    // Acknowledged with 202 and no body; nothing to parse.
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
    let res = null;
    let firstError = null;
    try {
      res = await this.#post(payload, this.sessionId);
    } catch (err) {
      firstError = err;
    }
    if (!res?.json) {
      // Session may have expired server-side; re-handshake once and retry.
      // Keep the original failure: reporting only the retry's error is how a
      // genuine fault (500, refused connection) gets misattributed to init().
      try {
        await this.init();
        res = await this.#post({ ...payload, id: this.nextId++ }, this.sessionId);
      } catch (retryError) {
        throw firstError ?? retryError;
      }
    }

    const json = res.json;
    if (!json) throw new Error(`MCP tool ${name} returned an empty response`);
    if (json.error) throw new Error(`MCP error: ${json.error.message}`);

    const out = json.result ?? {};
    const text = (out.content ?? []).find((c) => c.type === "text")?.text;
    // Tool-level failures arrive as isError + a PLAIN TEXT message. Parsing it
    // as JSON used to raise an opaque SyntaxError instead of the real reason.
    if (out.isError) throw new Error(`MCP tool ${name} failed: ${text ?? "unknown error"}`);
    if (text === undefined) return out;
    try {
      return JSON.parse(text);
    } catch {
      return { text };
    }
  }
}
