# Security Policy

dent8 is a **memory-integrity firewall for coding agents** — a security tool — so we take
reports about its own integrity seriously.

## Status and scope

dent8 is **pre-1.0 (v0.x)**: the API, the on-disk event encoding (`CANON_VERSION`), and the
storage schema may change between minor versions. Treat it as experimental.

What dent8 does and does **not** defend against is documented precisely in
[`docs/threat-model.md`](docs/threat-model.md). In particular, note the stated assumptions:

- The hash chain is tamper-**evident**; tamper-**resistance** holds only under an external
  **witness deployment** (an anchor issued at write time, key held off the writer's machine).
  The `anchor` / `verify_signed_head` functions are that *primitive*, not a hosted service.
- The firewall governs **provenance, authority, freshness, and contradiction** — it does not
  judge truth, and a compromised high-authority actor is out of scope.

A report that a documented assumption does not hold — or that an *undocumented* bypass exists
(e.g. an un-arbitrated write path, a way to launder authority past `arbitrate_events`, a
canonicalization collision, or a chain/anchor forgery) — is a security issue we want to hear
about.

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability.

- Preferred: open a private report via GitHub's **"Report a vulnerability"**
  (Security → Advisories) on <https://github.com/xyzzylabs/dent8>.
- We aim to acknowledge a report within **5 business days** and to agree on a disclosure
  timeline with the reporter.

When you report, please include: the version/commit, a minimal reproduction (ideally a failing
test or a sequence of `dent8` commands / events), and which threat-model assumption you believe
is violated.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ (latest `0.1` only) |
| < 0.1   | ❌ |
