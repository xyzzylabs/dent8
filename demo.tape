# dent8 demo tape — the README's one-screen story.
#
# Record with https://github.com/charmbracelet/vhs:
#     cargo build -q -p dent8
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
Set TypingSpeed 16ms

Type "DENT8_DEMO_PAUSE=0.8 DENT8=$PWD/target/debug/dent8 ./examples/firewall/demo.sh"
Enter
# Let the six-step walkthrough run and leave time to read the receipt.
Sleep 16s

# Hold on the final screen — the retained fact's receipt and the verified hash chain —
# so a viewer can actually read it before the GIF loops.
Sleep 6s
