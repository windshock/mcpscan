# mcp-guard demo tape — 1080×1350 (4:5) for LinkedIn feed.
# Renders demo/mcp-guard-4x5.{mp4,gif}.

Output demo/mcp-guard-4x5.mp4
Output demo/mcp-guard-4x5.gif

Set Shell zsh
Set FontSize 20
Set Width 1080
Set Height 1350
Set Padding 32
Set TypingSpeed 30ms
Set Theme "Dracula"

# Scene 1: capability audit on running Docker MCP
Type "mcp-guard scan --endpoint http://127.0.0.1:3103/sse"
Sleep 400ms
Enter
Sleep 6500ms

# Scene 2: supply-chain config check
Type "clear"
Enter
Sleep 200ms
Type "mcp-guard scan --config demo/attack.json"
Sleep 400ms
Enter
Sleep 5500ms

# Scene 3: outro
Type "clear"
Enter
Sleep 200ms
Type "# pip install · github.com/windshock/mcpscan"
Sleep 2500ms
