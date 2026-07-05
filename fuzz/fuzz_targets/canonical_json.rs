//! Fuzz `CanonicalJson` — the one place arbitrary *user* JSON (`FactValue::Json`) enters the
//! hashed payload. Its contract: canonical **by construction** (sorted keys, compact) and
//! **idempotent** (re-canonicalizing the canonical form is the identity), for any JSON text —
//! including non-ASCII keys, deep nesting, and pathological numbers. A violation would let two
//! logically-equal values hash differently, breaking the bytes invariant under the chain.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(canonical) = dent8_core::CanonicalJson::new(text) else {
        return;
    };
    let again = dent8_core::CanonicalJson::new(canonical.as_str())
        .expect("canonical output must re-canonicalize");
    assert_eq!(
        canonical.as_str(),
        again.as_str(),
        "canonicalization is not idempotent"
    );
});
