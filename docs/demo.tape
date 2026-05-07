# Critikal TUI demo tape — run with `vhs docs/demo.tape`
# Outputs docs/demo.gif. Re-record after UI changes; commit both files.

Output docs/demo.gif

Set FontSize 14
Set Width 1280
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

# Launch the TUI. Adjust the command to whatever shows the prettiest 15s of UI:
#   - `critikal` (interactive prompt)
#   - `critikal --repo <URL>` (jump straight into a run)
Type "critikal"
Sleep 500ms
Enter

# Give the TUI time to paint
Sleep 4s

# Type a prompt the agent will react to (replace with whatever shows best)
Type "Audit https://github.com/theredguild/damn-vulnerable-defi for reentrancy"
Sleep 800ms
Enter

# Let the agent stream its thinking + first tool calls
Sleep 25s

# Quit cleanly so the GIF doesn't end on a frozen frame
Ctrl+C
Sleep 1s
