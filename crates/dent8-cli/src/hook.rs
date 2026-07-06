//! The `dent8 hook native-memory-guard` helper for provider hook systems: block or audit
//! direct writes to agent-native memory/rules files (`CLAUDE.md`, `AGENTS.md`,
//! `.cursor/rules/*`, …) so durable facts flow through the firewall instead. Best-effort by
//! design — the MCP/CLI write path is the integrity boundary; this is the seatbelt (see
//! `examples/agent-hooks/`).

use crate::{env_flag, log_path, native::native_memory_paths_in_payload, verify_log};

/// Built-in helper for provider hook systems. It intentionally does not write native memory
/// files; it only runs `verify` or blocks writes that would bypass the fact-event firewall.
pub(crate) fn cmd_hook_native_memory_guard() -> i32 {
    let mode = std::env::var("DENT8_HOOK_MODE")
        .unwrap_or_else(|_| "guard-native-memory-write".to_string());

    if mode == "session-start" {
        return hook_verify("session start");
    }

    if mode != "guard-native-memory-write" && mode != "post-write-audit" {
        eprintln!("dent8 hook: unknown DENT8_HOOK_MODE={mode}");
        return 2;
    }

    // The payload could not be read or parsed, so we cannot tell whether a native memory file is
    // being written. The blocking guard fails closed under enforcement; the post-write audit
    // re-verifies the chain rather than assume nothing changed.
    let Some(payload) = read_hook_payload() else {
        return match mode.as_str() {
            "post-write-audit" => hook_verify("unreadable post-write hook payload"),
            _ if hook_enforced() => {
                eprintln!(
                    "dent8 hook: unreadable payload under DENT8_HOOK_ENFORCE — blocking (fail closed)."
                );
                2
            }
            _ => 0,
        };
    };

    let touched = native_memory_paths_in_payload(&payload);
    if mode == "post-write-audit" {
        if touched.is_empty() {
            return 0;
        }
        return hook_verify(&format!(
            "native memory/rules changed: {}",
            touched.join(", ")
        ));
    }

    // guard-native-memory-write
    if touched.is_empty() {
        return 0;
    }

    eprintln!(
        "dent8 native memory/rules guard: direct writes to {} bypass the fact-event firewall. \
         Use dent8 MCP tools or an explicit reviewed export from dent8. Set \
         DENT8_ALLOW_NATIVE_MEMORY_WRITE=1 to bypass this local guard.",
        touched.join(", ")
    );

    if hook_allow_bypass() {
        return 0;
    }
    if hook_enforced() { 2 } else { 0 }
}

/// `DENT8_HOOK_ENFORCE` turns a guard hit (or an unreadable payload) into a blocking exit 2.
/// Parsed like every dent8 boolean (`1`/`true`/`yes`/`on`); a malformed value **fails closed**
/// (treated as enforcing) so a typo cannot silently disable enforcement.
fn hook_enforced() -> bool {
    match env_flag("DENT8_HOOK_ENFORCE") {
        Ok(value) => value,
        Err(message) => {
            eprintln!("dent8 hook: {message}");
            true
        }
    }
}

/// `DENT8_ALLOW_NATIVE_MEMORY_WRITE` is the explicit local bypass. A malformed value never grants
/// a bypass (treated as unset), so a typo cannot accidentally open the guard.
fn hook_allow_bypass() -> bool {
    match env_flag("DENT8_ALLOW_NATIVE_MEMORY_WRITE") {
        Ok(value) => value,
        Err(message) => {
            eprintln!("dent8 hook: {message}");
            false
        }
    }
}

/// Read the hook JSON from stdin. `Some(Null)` is an empty payload (nothing to guard); `None`
/// means stdin could not be read or did not parse as JSON, so callers can fail closed.
fn read_hook_payload() -> Option<serde_json::Value> {
    let mut raw = String::new();
    let mut stdin = std::io::stdin();
    if let Err(error) = std::io::Read::read_to_string(&mut stdin, &mut raw) {
        eprintln!("dent8 hook: could not read hook JSON: {error}");
        return None;
    }
    if raw.trim().is_empty() {
        return Some(serde_json::Value::Null);
    }
    match serde_json::from_str(&raw) {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("dent8 hook: could not parse hook JSON: {error}");
            None
        }
    }
}

fn hook_verify(reason: &str) -> i32 {
    eprintln!("dent8 hook: verify ({reason})");
    match verify_log(&log_path()) {
        Ok(report) => {
            eprintln!("{report}");
            0
        }
        Err(message) => {
            eprintln!("{message}");
            1
        }
    }
}
