# mcp-guard demo tape — 1080×1080 (1:1) safe-everywhere LinkedIn cut.
# Renders demo/mcp-guard-1x1.{mp4,gif}.

Output demo/mcp-guard-1x1.mp4
Output demo/mcp-guard-1x1.gif

Set Shell zsh
Set FontSize 18
Set Width 1080
Set Height 1080
Set Padding 28
Set TypingSpeed 30ms
Set Theme "Dracula"

# Scene 1
Type "mcp-guard scan --endpoint http://127.0.0.1:3103/sse"
Sleep 400ms
Enter
Sleep 6500ms

# Scene 2
Type "clear"
Enter
Sleep 200ms
Type "mcp-guard scan --config demo/attack.json"
Sleep 400ms
Enter
Sleep 5500ms

# Scene 3
Type "clear"
Enter
Sleep 200ms
Type "# pip install · github.com/windshock/mcpscan"
Sleep 2500ms
