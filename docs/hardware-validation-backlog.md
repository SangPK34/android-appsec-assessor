# Hardware validation backlog

Current status: `BLOCKED_NO_DEVICE`

All items below are `UNVERIFIED_ON_PHYSICAL_DEVICE`. Fixture and fake-backend results verify software behavior only; they are not Android experiment results and must not be reported as physical PASS.

| Test group | Physical evidence required before PASS |
| --- | --- |
| ADB and capability | Authorized device state, model, Android/SDK/ABI/patch, SELinux, shell identity, root identity, Magisk, Zygisk, and client/server versions parsed from real output. |
| Root wrapper | Real `uid=0`, denied prompt, timeout, missing `su`, stderr handling, and safe path behavior. |
| Frida lifecycle | ABI asset hash, push/chmod, exact process identity, connectivity, attach, spawn, observer handshake/runtime event, owned cleanup, and preservation of a pre-existing server. |
| Private storage | Allowlisted lab UID/data directory, bounded canary-only inventory, metadata/hash/redaction, logout residue, and ownership-safe cleanup. |
| Runtime observers | Real events for preferences, SQLite, files, logging, WebView, TLS, crypto, and root checks with package/session attribution. |
| TLS/proxy/CA | Initial proxy/reverse/CA snapshots, listen readiness, trust outcome, target-attributed traffic, conflict handling, and restoration on normal/interrupted runs. |
| Crypto | Real transformation/key-length/IV metadata and canary-boundary observations without storing key material. |
| Root detection | Real checks executed and observable app response; any lab instrumentation remains `instrumented_validation`. |
| Recovery | Ctrl+C, process crash, USB loss, stale-session recovery, idempotent cleanup, and no deletion of pre-existing resources. |

Physical status values are limited to `NOT_REQUIRED`, `BLOCKED_NO_DEVICE`, `UNVERIFIED`, `PASSED`, and `FAILED`. Until hardware testing resumes, every hardware-dependent row remains `BLOCKED_NO_DEVICE` or `UNVERIFIED`.
