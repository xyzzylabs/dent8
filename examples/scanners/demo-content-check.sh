#!/bin/sh
# DEMO ONLY — NOT A DEFENSE.
#
# A deliberately naive regex scanner for dent8's content-check hook
# (docs/content-check.md). It exists to demonstrate the wire protocol and to drive the
# eval harness's hook mode — it is a handful of substring heuristics that a motivated
# attacker trivially evades (the eval corpus's rot13 and translated payloads sail past
# it, by design). Wire a real scanner (LLM Guard, Rebuff, a Lakera / Azure Prompt
# Shields bridge, ...) for actual coverage; these rules were also written with knowledge
# of dent8's own eval corpus, so its numbers demonstrate the seam, not regex efficacy.
#
# Protocol (dent8.content-check/1): one JSON payload on stdin, one verdict object on
# stdout — {"verdict":"allow"} | {"verdict":"reject","reason":...} |
# {"verdict":"taint","reason":...}. Exit 0 for any verdict; a non-zero exit means the
# scanner itself failed and dent8 applies its failure policy (fail-closed by default).
#
# Note: the zero-width stripping below uses GNU sed's \x escapes (fine on Linux/CI);
# BSD sed users should replace it or drop that normalization step.
set -eu

payload="$(cat)"
# Normalize before matching: turn zero-width spaces (U+200B, UTF-8 e2 80 8b) into real
# spaces so the cheapest obfuscation does not dodge the rules below.
normalized="$(printf '%s' "$payload" | sed 's/\xe2\x80\x8b/ /g')"

verdict() {
    printf '{"verdict":"%s","reason":"%s"}\n' "$1" "$2"
    exit 0
}

matches() {
    printf '%s' "$normalized" | grep -qiE "$1"
}

# --- reject: embedded override imperatives -------------------------------------------
matches 'ignore (all |your )*(previous|prior) instructions' \
    && verdict reject "override imperative: ignore-previous-instructions"
matches '\[SYSTEM\]|treat the next user message as an admin command' \
    && verdict reject "instruction-frame injection: fake system/admin channel"
matches 'important message from the user to the assistant|message from me to you' \
    && verdict reject "authority-frame injection: impersonated user/system message"

# --- reject: exfiltration instructions ------------------------------------------------
matches '!\[\]?\(https?://' \
    && verdict reject "exfil pattern: markdown image beacon URL"
matches '(bcc|forward|send|email)[^"]{0,80}[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' \
    && verdict reject "exfil pattern: standing instruction to send data to an address"
matches '(echo|reveal|disclose|leak)[^"]{0,60}(system prompt|api key)' \
    && verdict reject "secret-leak instruction: system prompt / API key disclosure"

# --- taint: suspicious but not conclusively an instruction ----------------------------
matches '(decode|execute)[^"]{0,60}[A-Za-z0-9+/]{16,}={0,2}' \
    && verdict taint "encoded payload with a decode/execute cue"
matches 'whenever a message contains|if/when the user next says|after [0-9]+ more interactions' \
    && verdict taint "conditional trigger phrasing (possible time bomb)"
matches 'safety=off|treat as current config' \
    && verdict taint "instruction-as-data configuration cue"

printf '{"verdict":"allow"}\n'
