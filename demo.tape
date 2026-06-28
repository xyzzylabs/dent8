# dent8 demo tape — a 25-second story for the README.
#
# Prereq: build the CLI first so recording is snappy:
#     cargo build -p dent8-cli
# Then record (https://github.com/charmbracelet/vhs):
#     vhs demo.tape        # -> demo.gif
#
# Tweak Theme / FontSize / Sleep timings to taste.

Output demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1180
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 35ms

# --- Setup (hidden): put the freshly-built CLI on PATH, use a throwaway log ---
Hide
Type "export PATH=$PWD/target/debug:$PATH; export DENT8_LOG=$(mktemp); clear" Enter
Show

Type "# dent8 — a memory firewall for coding agents"
Sleep 900ms
Enter
Sleep 1s

Type "# 1. The owner asserts a trusted project fact (high authority)"
Enter
Type "dent8 assert repo myproj database postgres high owner"
Sleep 500ms
Enter
Sleep 2200ms

Type "# 2. A low-authority web scrape tries to overwrite it..."
Enter
Type "dent8 supersede repo myproj database mysql low web-scraper"
Sleep 500ms
Enter
Sleep 2200ms
Type "#    -> blocked by the firewall. Trust is not overwritten."
Enter
Sleep 1800ms

Type "# 3. Why do we believe what we believe? An auditable receipt."
Enter
Type "dent8 explain repo myproj database"
Sleep 500ms
Enter
Sleep 3500ms

Type "# Provenance, authority, freshness, contradictions -- replayable + hash-chained."
Enter
Sleep 3s
