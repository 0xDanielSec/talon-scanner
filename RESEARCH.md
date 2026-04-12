# Security Research — 0xDanielSec

Vulnerability research powered by the [Glasswing Scanner](https://github.com/0xDanielSec/glasswing-scanner) pipeline.

---

## Methodology

Glasswing is a five-phase agentic pipeline built on the Anthropic API. Each phase produces a structured JSON report that feeds the next. All findings go through at least two independent LLM passes before being recorded here, and every report is hash-timestamped at generation time.

**Phase 1 — Intelligence.**
Before touching a repository, the pipeline queries the GitHub Advisory Database, OSV.dev, and recent commit history to build a threat model. This produces a target score and a prioritised list of subsystems worth auditing, avoiding wasted effort on well-patched or low-value code paths.

**Phase 2 — Surface Mapping.**
The surface mapper performs static enumeration of entry points, trust boundaries, and dangerous sinks across the codebase. It uses Claude to trace the top data flows between them, producing a ranked attack surface map that drives file selection for the deep scan.

**Phase 3 — Vulnerability Scan.**
The scanner ranks every file by attack-surface likelihood, then sends the top-N files to Claude for white-box code review. Each raw finding is passed to a second independent LLM call for validation and confidence scoring. Findings below a configurable confidence threshold are automatically discarded. No finding reaches the active research table without passing both passes.

**Phase 4 — Impact Chaining.**
Confirmed findings are correlated by CWE escalation pairs and code co-location to identify multi-step attack chains. Each candidate chain is sent to Claude for logical validation — it must demonstrate a clear causal link between vulnerabilities. Chains that fail the causal check are recorded in the false positive log.

**Phase 5 — PoC Generation.**
For each confirmed HIGH or CRITICAL finding, the pipeline selects a CWE-appropriate strategy and generates a minimal reproduction. A second LLM call validates the PoC for consistency and trigger confidence. PoCs are hard-constrained: no shellcode, no reverse shells, no destructive payloads. Risk ceiling is MEDIUM (local files or resources).

---

## Active Research

| Target | Vulnerability | CWE | CVSS | Status | Disclosure Hash |
|--------|--------------|-----|------|--------|----------------|
| [cilium/tetragon](https://github.com/cilium/tetragon) | Null Pointer Dereference in Process Exit Handler | CWE-476 | 5.5 | Disclosed 2026-04-09 · acknowledged · awaiting patch | `24d15def769592f0` |
| [google/kafel](https://github.com/google/kafel) | Path Traversal in File Include Resolution | CWE-22 | 7.5 | [PR open](https://github.com/0xDanielSec/kafel/tree/fix/path-traversal-include-resolution) | `3a8c8b36a55ecbc7` |

### Finding Details

#### cilium/tetragon — Null Pointer Dereference in Process Exit Handler

- **File:** `bpf/windows/process_monitor.c`
- **CWE:** CWE-476 (NULL Pointer Dereference)
- **CVSS:** 5.5 (Medium)
- **Validation confidence:** 0.95
- **Description:** On the process exit path, `pid` is declared as `uint32_t *` and initialised to `NULL`. The code then dereferences it unconditionally with `*pid = ctx->process_id` without allocating memory or assigning a valid pointer address. The guard `if ((ctx) && ctx->process_id)` validates the source data but does not resolve the null pointer. The result is a guaranteed segmentation fault on any process exit event reaching this handler.
- **Full disclosure hash:** `24d15def769592f077b97d2d38aa89544c0d076627aa026d9a91448a1d235476`
- **Reported:** 2026-04-09

#### google/kafel — Path Traversal in File Include Resolution

- **File:** `src/includes.c:111-128`
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **CVSS:** 7.5 (High)
- **Validation confidence:** 0.90
- **Description:** `includes_resolve()` accepts a caller-controlled filename, joins it to each configured search path with `path_join()`, and opens the result with `fopen()` without any path canonicalisation or boundary check. An attacker who controls the filename argument — for example through a policy file passed to the kafel compiler — can use `../` sequences to open arbitrary files outside the intended include directories. On a Linux system this is sufficient to read `/etc/shadow`, `/proc/self/environ`, or other sensitive paths.
- **Fix:** Canonicalise the joined path with `realpath(3)` and verify the result shares a prefix with the configured search directory before calling `fopen()`. Reject any filename containing `..` or an absolute path component before the join.
- **Full disclosure hash:** `3a8c8b36a55ecbc70274b3a56e0105f4c7ccfbafc2fb5b70c0c09e4b73b8f523`
- **Reported:** 2026-04-10

---

## Responsible Disclosure Policy

1. **Private first.** Findings are reported privately to the maintainer before any public disclosure. The initial report includes the full finding, reproduction steps, and suggested fix.

2. **90-day window.** Maintainers have 90 days from the date of private notification to release a patch. If no response is received within 14 days, a follow-up is sent. Public disclosure proceeds at day 90 regardless of patch status, with reasonable extensions granted for complex fixes.

3. **Hash timestamping.** Every finding is assigned a SHA3-256 disclosure hash at the time the scanner report is generated. The hash covers the finding title, file path, CWE, vulnerable code snippet, and PoC approach. This creates an auditable timestamp that predates any public disclosure.

4. **Coordinated release.** Where possible, public disclosure is coordinated with the maintainer's patch release so that users can upgrade before technical details are public. CVE assignment is requested for findings that meet the threshold.

5. **No weaponisation.** PoCs demonstrate the bug in a controlled, local environment. They are not published in a form that enables trivial exploitation against production systems.

---

## False Positive Log

The validation pipeline dismissed the following findings after review. Recording dismissed findings is part of the methodology — it demonstrates that confirmed results have survived a filter, not that the scanner reports everything it sees.

| Target | Finding | CWE | Reason Dismissed |
|--------|---------|-----|-----------------|
| mitmproxy | Unsafe `yaml.safe_load` usage | CWE-502 | `safe_load` is explicitly not vulnerable to arbitrary object deserialisation; finding was based on filename pattern, not code path |
| mitmproxy | Hardcoded test credentials in test fixtures | CWE-798 | Test-only fixtures, not reachable from production code paths; no deployment risk |
| mitmproxy | Unvalidated redirect in proxy handler | CWE-601 | The proxy's function is to forward arbitrary URLs; flagging all redirects would produce only noise for this class of software |
| runc | Integer overflow in rlimit conversion | CWE-190 | Values are sourced from the OCI spec and clamped by the kernel before use; no exploitable path identified |
| runc | TOCTOU on cgroup path check | CWE-367 | The race window requires attacker control of the cgroup filesystem, which implies privilege already exceeding the impact of the bug |
| kafel | Format string in error message | CWE-134 | Format string is a compile-time constant; the user-controlled value is passed as an argument, not as the format specifier |
| kafel | Unchecked malloc in expression evaluator | CWE-476 | Confirmed null deref possibility but no attacker-controlled trigger path; treated as a quality issue, not a security finding |
| kafel | Integer overflow in syscall number range check | CWE-190 | Range is bounded by the syscall table size, which is a compile-time constant on the target architectures |

---

## Contact

Security disclosures: open a private security advisory on the relevant repository, or reach out via GitHub.

**GitHub:** [github.com/0xDanielSec](https://github.com/0xDanielSec)
