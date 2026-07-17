# Rooted Android device validation plan

Target branch: `test/android-device-validation`

Primary testbed: rooted Google Pixel 4 XL with Magisk. Non-root behavior remains the baseline and fallback. A result is never marked PASS without captured device output and an observable result.

## Safety and evidence rules

- Require device and package allowlisting before every modifying action.
- Hold the device lock for the full modifying workflow.
- Store device serials, APKs, logs, traffic, private data, and session evidence only under ignored local paths.
- Use canary data only. Do not bulk-dump private storage.
- Separate `raw/` and `redacted/`; hash every registered artifact.
- Record ownership immediately after each mutation and run idempotent cleanup.
- Preserve pre-existing proxy, reverse mappings, CA, Frida Server, apps, and files.

## Execution order and acceptance gates

1. **Connection and capability** — parse and retain real output for ADB authorization, model, Android/SDK/ABI/patch, SELinux, shell identity, root identity, Magisk, Zygisk, and Frida client/server compatibility.
2. **Root wrapper** — verify success, denial, timeout, stderr capture, safe quoting, and rejection of unvalidated input. Windows elevation is not Android root.
3. **Frida lifecycle** — verify selected ABI asset and SHA-256, push/chmod/start identity, connectivity, attach/spawn, observer handshake and runtime event, then ownership-safe shutdown.
4. **Private storage** — on an allowlisted lab package, identify UID/data directory and inspect only declared canary files with backup/snapshot and redacted evidence. Root readability alone is a post-compromise observation, not a finding.
5. **TLS/proxy** — snapshot proxy/reverse/CA state, verify listen and trust behavior, distinguish accepted/rejected/pinning/no-traffic/inconclusive, then restore only owned resources.
6. **Cleanup/recovery** — test normal, repeated, interrupted, USB-loss, and stale-session cleanup without overwriting external changes.

## Result classification

Every validation uses exactly one of:

- `natural_validation`
- `adb_assisted_validation`
- `root_assisted_validation`
- `instrumented_validation`
- `post_compromise_observation`

Each test record includes root/Frida requirements and actual use, non-root/rooted result, status, confidence, duration, evidence references, and cleanup outcome.

## Stop conditions

Stop modifying tests when scope is missing, snapshot fails, the device is busy, USB is lost, process identity cannot be verified, or owned-resource cleanup fails. Fix only the blocking device-validation defect before continuing.
