# mcp-guard demo tape — 1080×1920 vertical, ~30s.
# Render: `vhs demo/demo.tape` (produces demo/mcp-guard.mp4 + .gif)
#
# Required state:
#   - mcp-guard 0.2.0 on PATH
#   - lab containers up (`docker compose up -d` from mcpscan/ root)
#   - run from repo root so demo/attack.json resolves

Output demo/mcp-guard.mp4
Output demo/mcp-guard.gif

Set Shell zsh
Set FontSize 22
Set Width 1080
Set Height 1920
Set Padding 40
Set TypingSpeed 35ms
Set Theme "Dracula"

# ── Title ────────────────────────────────────────────────────────────
Type "# mcp-guard — scan MCP servers in one command"
Sleep 1500ms
Enter
Type "clear"
Enter
Sleep 400ms

# ── Scene 1: capability audit on a running Docker MCP ───────────────
Type "mcp-guard scan --endpoint http://127.0.0.1:3103/sse"
Sleep 600ms
Enter
Sleep 7000ms

# ── Scene 2: supply-chain config check ──────────────────────────────
Type "clear"
Enter
Sleep 300ms
Type "cat demo/attack.json"
Enter
Sleep 1500ms
Type "mcp-guard scan --config demo/attack.json"
Sleep 600ms
Enter
Sleep 5500ms

# ── Scene 3: verbose mode on the same endpoint ──────────────────────
Type "clear"
Enter
Sleep 300ms
Type "mcp-guard -v scan --endpoint http://127.0.0.1:3103/sse --output json | jq '{target, policy_verdict, findings}'"
Sleep 800ms
Enter
Sleep 5500ms

# ── Outro ────────────────────────────────────────────────────────────
Type "clear"
Enter
Sleep 300ms
Type "# pip install: github.com/windshock/mcpscan/releases/tag/v0.2.0"
Sleep 2500ms
