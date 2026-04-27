/**
 * Vuln-Network MCP Server — SSRF, CORS *, debug info exposure
 */
import express from "express";
import cors from "cors";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const app = express();
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

const server = new Server(
  { name: "vuln-network", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch_url",
      description:
        "Fetches content from any URL. Supports internal URLs, localhost, and private networks.",
      inputSchema: {
        type: "object" as const,
        properties: {
          url: { type: "string", description: "The URL to fetch" },
        },
        required: ["url"],
      },
    },
    {
      name: "debug_info",
      description:
        "Returns internal service metadata including network configuration and service endpoints.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "send_webhook",
      description:
        "Sends a POST request to any URL with custom headers and body. Useful for integrations.",
      inputSchema: {
        type: "object" as const,
        properties: {
          url: { type: "string", description: "Webhook URL" },
          body: { type: "string", description: "Request body" },
        },
        required: ["url"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "fetch_url": {
      const url = (args as any)?.url as string;
      try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(30000) });
        const text = await resp.text();
        return { content: [{ type: "text", text: text.slice(0, 10000) }] };
      } catch (e: any) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }

    case "debug_info": {
      const info = {
        hostname: process.env.HOSTNAME || "unknown",
        node_version: process.version,
        pid: process.pid,
        env_keys: Object.keys(process.env),
        internal_services: [
          "http://normal-strict:8000",
          "http://normal-realistic:8000",
          "http://vuln-exec:8000",
          "http://vuln-filesystem:8000",
          "http://config-elevator:8000",
        ],
        network: {
          docker_network: "mcp-lab",
          exposed_ports: [3201],
        },
      };
      return { content: [{ type: "text", text: JSON.stringify(info, null, 2) }] };
    }

    case "send_webhook": {
      const url = (args as any)?.url as string;
      const body = (args as any)?.body as string;
      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: body || "{}",
          signal: AbortSignal.timeout(30000),
        });
        const text = await resp.text();
        return { content: [{ type: "text", text: text.slice(0, 5000) }] };
      } catch (e: any) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }

    default:
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  }
});

// SSE endpoint
app.get("/sse", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  // SSE transport handles this
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", server: "vuln-network" });
});

const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`vuln-network MCP server listening on port ${PORT}`);
});
