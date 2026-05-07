# Critikal TUI demo tape — run with `vhs docs/demo.tape`
# Outputs docs/demo.gif. Re-record after UI changes; commit both files.

Output docs/demo.gif

Set FontSize 14
Set Width 1280
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 60ms
Set PlaybackSpeed 2.0
Set Framerate 24

# vhs spawns a fresh shell — the poetry venv isn't activated, so call the
# binary by its in-repo path. Run vhs from the repo root (cd /path/to/critikal).
Type ".venv/bin/critikal"
Sleep 500ms
Enter

# Give the TUI time to paint
Sleep 4s

# Lightweight prompt — produces visible streaming within seconds rather than
# waiting on full repo ingestion. Swap for a real `--repo` audit later if you
# want to show the pipeline; that needs ~60-90s before output appears.
Type "Audit damn vulnerable defi and write POC"
Sleep 800ms
Enter

# Let the agent stream its reply. PlaybackSpeed 2.0 above means the GIF
# will replay this at 2x — so 60s of real time becomes 30s of GIF.
Sleep 90s

# Quit cleanly so the GIF doesn't end on a frozen frame
Ctrl+C
Sleep 1s
