# dent8 demo tape — a short README story.
#
# Record with https://github.com/charmbracelet/vhs:
#     vhs demo.tape        # -> demo.gif
#
# Tweak Theme / FontSize / Sleep timings to taste.

Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1440
Set Height 760
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 25ms

# --- Setup (hidden): build the CLI and make the maintained walkthrough use it. ---
Hide
Type "cargo build -q -p dent8; export DENT8=$PWD/target/debug/dent8; clear" Enter
Show

Type "# dent8 — a memory firewall for agents"
Sleep 900ms
Enter
Sleep 700ms

Type "# trusted fact in, low-authority overwrite out, receipt replayed"
Enter
Sleep 900ms

Type "./examples/firewall/demo.sh"
Enter
Sleep 7s

Type "# provenance + authority + replay + hash-chain verification"
Enter
Sleep 2s
