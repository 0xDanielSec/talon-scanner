# Talon Scanner

**Agentic offensive security research pipeline**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Anthropic API](https://img.shields.io/badge/powered%20by-Anthropic%20API-orange.svg)](https://anthropic.com)

An AI-driven research pipeline that finds real vulnerabilities in open source projects — from initial target qualification through coordinated disclosure.

---

## What It Is

Talon Scanner is an agentic pipeline for vulnerability research in open source software. It uses the Claude API as its AI backbone to perform tasks that traditionally require manual expert review: mapping attack surfaces, tracing data flows from entry points to dangerous sinks, correlating findings into exploit chains, and generating minimal proofs of concept. Every phase produces structured JSON reports that feed the next phase in the pipeline.

This is not a traditional scanner that runs a fixed set of checks and exits. It is a research assistant that reasons about code — reading source files, asking targeted questions, and synthesizing answers into actionable findings. The signal-to-noise ratio reflects that: findings are validated by a second model pass before they appear in any report.

---

## Pipeline

```
intel ──► surface ──► scan ──► chain ──► poc ──► disclose ──► detect ──► monitor
  │           │          │        │        │          │            │          │
  └── Target  └── Entry  └── Deep └── Attack└── PoC   └── Report   └── YARA/  └── Continuous
      scoring     points     audit   chains   generation  drafting     Sigma     watch
```

| Phase | Command | Description |
|-------|---------|-------------|
| **1. Intel** | `intel` | Queries NVD, OSV.dev, and GitHub Advisory DB — plus commit history — to score and qualify a target before full audit |
| **2. Surface** | `surface` | Regex-scans source for entry points, trust boundaries, and dangerous sinks; LLM traces the top data flows |
| **3. Scan** | `scan` | Ranks files by attack-surface likelihood; deep-analyses the top-N with Claude for exploitable vulnerabilities |
| **4. Chain** | `chain` | Correlates findings by CWE escalation pairs and co-location; LLM validates multi-step attack paths |
| **5. PoC** | `poc` | Generates minimal, safe proofs of concept for confirmed HIGH/CRITICAL findings; second model pass validates each |
| **6. Disclose** | `disclose` | Produces structured coordinated-disclosure reports with SHA3-256 timestamps and 90-day window tracking |
| **7. Detect** | `detect` | Generates YARA rules and Sigma signatures from confirmed findings so defenders can detect exploitation attempts |
| **Monitor** | `monitor` | Polls target repositories for security-relevant commits; auto-qualifies CRITICAL findings via intel |

---

## Real World Results

Findings produced by this pipeline and reported through coordinated disclosure:

### cilium/tetragon — NULL Pointer Dereference
- **CWE:** CWE-476 (NULL Pointer Dereference)
- **Status:** Patched
- **Fix:** [github.com/cilium/tetragon/pull/4880](https://github.com/cilium/tetragon/pull/4880)
- **Credit:** `Reported-by: 0xDanielSec`

### cilium/cilium — CEL Expression Denial of Service
- **CWE:** CWE-94 (Improper Control of Code Generation) + CWE-770 (Allocation of Resources Without Limits)
- **Status:** Under coordinated disclosure

### google/kafel — Path Traversal
- **CWE:** CWE-22 (Path Traversal)
- **Status:** PR open with fix

---

## Research

Findings and methodology from this pipeline are documented in a published preprint:

**DUEL Framework: Adversarial LLM Security Research**
https://doi.org/10.5281/zenodo.20098146

---

## Output Example

Terminal summary produced by the scan → chain → poc phases on `cilium/tetragon`:

```
[SCAN] cilium/tetragon — 2024-11-08T14:22:10Z
Target: ./tetragon  Lang: go  Top files: 20

[HIGH] pkg/sensors/tracing/kprobe.go:312
  CWE-476: NULL Pointer Dereference
  Entry:  handleKprobeEvent() — untrusted BPF kernel event data
  Sink:   kprobe.Args[idx].Value (no nil guard before dereference)
  Flow:   handleKprobeEvent → getKprobeArgs → Args[idx].Value
  Confidence: 0.89

[CHAIN] Validated attack path
  CWE-476 → kernel NULL deref via malformed BPF event payload
  Steps:  crafted event missing argument field → kprobe handler
          → unguarded nil dereference → kernel panic / DoS
  Exploitability: HIGH  Validated: yes

[POC] Generating proof of concept...
  Method: synthesised BPF event with truncated argument list
  Safe:   yes — triggers controlled panic in isolated test kernel
  File:   reports/tetragon_poc_20241108T142210Z.md

Disclosure hash: sha3-256:a3f9c271e84b...
Report: reports/talon_tetragon_20241108T142210Z.json

[DISCLOSE] Draft report written — 90-day window starts 2024-11-08
```

Fix merged upstream: [cilium/tetragon#4880](https://github.com/cilium/tetragon/pull/4880)

---

## Setup

**Requirements:** Python 3.10+, Anthropic API key

### Linux / macOS

```bash
chmod +x setup.sh
./setup.sh
```

### Windows

```bat
setup.bat
```

### Manual

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Environment

Create a `.env` file in the project root:

```
ANTHROPIC_API_KEY=sk-ant-...
```

The pipeline reads this file automatically. You can also set `ANTHROPIC_API_KEY` directly in your environment.

---

## Usage

```bash
# Phase 1 — qualify a target before committing to a full audit
python glasswing.py intel --target https://github.com/org/repo

# Phase 2 — map the attack surface of a cloned repository
python glasswing.py surface --target ./repo --lang c

# Phase 3 — deep vulnerability scan, top 15 files by risk score
python glasswing.py scan --target ./repo --lang go --top 15

# Phase 4 — correlate findings into attack chains
python glasswing.py chain --reports ./reports --target name

# Phase 5 — generate proofs of concept for confirmed findings
python glasswing.py poc --reports ./reports --target name

# Phase 6 — produce a coordinated-disclosure report for a confirmed finding
python glasswing.py disclose --reports ./reports --target name

# Phase 7 — generate YARA/Sigma detection rules from confirmed findings
python glasswing.py detect --reports ./reports --target name

# Monitor — single sweep of all monitored repositories
python glasswing.py monitor --run-once

# Render any saved report in the terminal
python glasswing.py report --input reports/talon_20240115T103000Z.json
```

Supported languages for `--lang`: `c`, `cpp`, `go`, `python`, `rust`, `javascript`, `typescript`, `java`, `kotlin`, `csharp`, `ruby`, `php`, `swift`, `shell`, `sql`, `terraform`.

---

## Project Structure

```
talon-scanner/
├── glasswing.py           # CLI entry point — all subcommands
├── src/
│   ├── intel.py                # Phase 1: NVD + OSV + GitHub advisory intel
│   ├── surface_mapper.py       # Phase 2: entry points, boundaries, sinks, flows
│   ├── scanner.py              # Phase 3: ranked file scan + LLM deep analysis
│   ├── impact_chainer.py       # Phase 4: CWE escalation chains + LLM validation
│   ├── poc_generator.py        # Phase 5: PoC generation + second-pass validation
│   ├── disclosure_generator.py # Phase 6: coordinated disclosure report engine
│   ├── detection_generator.py  # Phase 7: YARA/Sigma rule generation
│   └── monitor.py              # Monitor: continuous commit monitoring
├── configs/
│   └── targets.json       # Monitor target list with check intervals
├── reports/               # Scan output (gitignored)
├── requirements.txt
├── setup.sh
├── setup.bat
└── .env                   # ANTHROPIC_API_KEY (gitignored)
```

---

## Responsible Disclosure

All findings produced by this pipeline follow a structured disclosure process:

- **Timestamping:** Each finding is assigned a SHA3-256 disclosure hash at generation time, creating an immutable timestamp for priority disputes.
- **90-day window:** Maintainers receive a minimum 90-day remediation window from initial private report before any public disclosure.
- **Private first:** Findings are reported privately to maintainers through official security channels (security advisories, security.txt, or direct contact) before any public communication.

Coordinated disclosure reports are produced automatically by the `poc` phase as Markdown documents ready for submission.

---

## Disclaimer

This tool is designed for authorized security research on targets where you have explicit permission to test. Using it against systems you do not own or have written authorization to test is illegal in most jurisdictions.

All proofs of concept generated by this pipeline are constrained to safe, non-destructive demonstrations. No weaponized payloads, reverse shells, or destructive commands are generated at any stage.

This project is intended for security researchers, bug bounty hunters, and defensive teams auditing software they are responsible for. Educational and research use only.
