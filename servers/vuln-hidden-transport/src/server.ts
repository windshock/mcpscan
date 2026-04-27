/**
 * Vuln-Hidden-Transport MCP Server — clean UI tools, but hidden stdio transport endpoint
 */
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const app = express();
app.use(express.json());

const server = new Server(
  { name: "vuln-hidden-transport", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// Clean, safe-looking tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_status",
      description: "Returns the current server status.",
      inputSchema: { type: "object" as const, properties: {} },
    },
    {
      name: "get_version",
      description: "Returns the server version.",
      inputSchema: { type: "object" as const, properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name } = request.params;
  switch (name) {
    case "get_status":
      return { content: [{ type: "text", text: "Status: OK" }] };
    case "get_version":
      return { content: [{ type: "text", text: "v1.0.0" }] };
    default:
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  }
});

// SSE endpoint — the "public" MCP interface
app.get("/sse", async (req: any, res: any) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});

app.post("/messages", async (req: any, res: any) => {});

// HIDDEN: Transport configuration endpoint — accepts stdio transport config
// This is not visible in the tool list but allows arbitrary transport injection
app.post("/api/transport", async (req: any, res: any) => {
  const { type, command, args, url } = req.body || {};

  if (type === "stdio" && command) {
    // VULNERABILITY: accepts arbitrary stdio transport configuration
    // This allows injecting a new MCP server via transport config
    res.json({
      status: "accepted",
      transport: { type: "stdio", command, args: args || [] },
      message: `Transport configured: ${command} ${(args || []).join(" ")}`,
    });
  } else if (type === "sse" && url) {
    res.json({
      status: "accepted",
      transport: { type: "sse", url },
      message: `SSE transport configured: ${url}`,
    });
  } else {
    res.status(400).json({ error: "Invalid transport configuration" });
  }
});

// HIDDEN: Connector metadata — exposes internal connection details
app.get("/api/connectors", (_req: any, res: any) => {
  res.json({
    connectors: [
      {
        name: "internal-db",
        type: "stdio",
        command: "postgres-proxy",
        args: ["--host", "db.internal", "--port", "5432"],
        env: { PGPASSWORD: "internal-db-password-123" },
      },
      {
        name: "file-server",
        type: "stdio",
        command: "file-access",
        args: ["--root", "/"],
      },
    ],
  });
});

// HIDDEN: Config injection endpoint
app.put("/api/config", (req: any, res: any) => {
  const config = req.body;
  // VULNERABILITY: accepts arbitrary MCP config that gets applied
  res.json({
    status: "applied",
    config,
    message: "Configuration has been applied to the server",
  });
});

app.get("/health", (_req: any, res: any) => {
  res.json({ status: "ok", server: "vuln-hidden-transport" });
});

const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`vuln-hidden-transport MCP server listening on port ${PORT}`);
});
