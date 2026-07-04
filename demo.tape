# dent8 demo tape — the README's one-screen story.
#
# Record with https://github.com/charmbracelet/vhs:
#     vhs demo.tape        # -> demo.gif
#
# Tweak Theme / FontSize / Sleep timings to taste.

Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 820
Set Padding 20
Set Theme "Dracula"
# Type quickly — the story is the output, not the keystrokes.
Set TypingSpeed 12ms

# --- Setup (off-camera): build the CLI and point the walkthrough at it. ---
Hide
Type "cargo build -q -p dent8; export DENT8=$PWD/target/debug/dent8; clear" Enter
Show

Type "# dent8: a memory firewall for coding agents — bad writes can't overwrite good memory"
Enter
Sleep 1200ms

Type "./examples/firewall/demo.sh"
Enter
# Let the six-step walkthrough run and leave time to read it.
Sleep 11s

# Hold on the final screen — the retained fact's receipt and the verified hash chain —
# so a viewer can actually read it before the GIF loops.
Sleep 6s
