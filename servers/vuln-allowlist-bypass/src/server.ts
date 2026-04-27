/**
 * Vuln-Allowlist-Bypass MCP Server — allowlist on name, no validation on args
 */
import express from "express";
import { exec } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const app = express();
app.use(express.json());

const server = new Server(
  { name: "vuln-allowlist-bypass", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const ALLOWED_COMMANDS = ["git", "npm", "node", "python3", "docker", "ls", "cat", "echo"];

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "execute",
      description:
        "Executes an allowed command with arguments. The command name must be in the allowlist. Arguments are passed directly.",
      inputSchema: {
        type: "object" as const,
        properties: {
          command: { type: "string", description: "Command name (must be in allowlist)" },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Command arguments (passed directly without validation)",
          },
        },
        required: ["command"],
      },
    },
    {
      name: "run_git",
      description:
        "Runs git commands. Any git subcommand and arguments are accepted.",
      inputSchema: {
        type: "object" as const,
        properties: {
          args: {
            type: "array",
            items: { type: "string" },
            description: "Git arguments (e.g., ['-c', 'arbitrary_command'])",
          },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "execute": {
      const cmd = (args as any)?.command as string;
      const cmdArgs = ((args as any)?.args as string[]) || [];

      if (!ALLOWED_COMMANDS.includes(cmd)) {
        return {
          content: [{ type: "text", text: `Error: command '${cmd}' not in allowlist: ${ALLOWED_COMMANDS.join(", ")}` }],
        };
      }

      // VULNERABILITY: args are not validated — e.g. git -c arbitrary_command
      const fullCmd = `${cmd} ${cmdArgs.join(" ")}`;
      try {
        const result = await new Promise<string>((resolve, reject) => {
          exec(fullCmd, { timeout: 30000 }, (err, stdout, stderr) => {
            if (err) reject(err);
            else resolve(stdout + (stderr ? "\n" + stderr : ""));
          });
        });
        return { content: [{ type: "text", text: result.slice(0, 10000) }] };
      } catch (e: any) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }

    case "run_git": {
      const gitArgs = ((args as any)?.args as string[]) || [];
      // VULNERABILITY: arbitrary git args like -c to execute commands
      const fullCmd = `git ${gitArgs.join(" ")}`;
      try {
        const result = await new Promise<string>((resolve, reject) => {
          exec(fullCmd, { timeout: 30000 }, (err, stdout, stderr) => {
            if (err) reject(err);
            else resolve(stdout + (stderr ? "\n" + stderr : ""));
          });
        });
        return { content: [{ type: "text", text: result.slice(0, 10000) }] };
      } catch (e: any) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }

    default:
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  }
});

app.get("/sse", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {});

app.get("/health", (_req: any, res: any) => {
  res.json({ status: "ok", server: "vuln-allowlist-bypass" });
});

const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`vuln-allowlist-bypass MCP server listening on port ${PORT}`);
});
