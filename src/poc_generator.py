#!/usr/bin/env python
"""
Glasswing PoC Generator — Phase 4: Proof of Concept Generation.

Pipeline
--------
1. Load HIGH and CRITICAL confirmed findings from glasswing-scanner reports
   matching the target.
2. Select the appropriate PoC strategy based on each finding's CWE.
3. Ask Claude to generate a minimal, safe proof-of-concept:
   reproduction steps · PoC code · expected outputs · suggested fix · risk rating.
4. Validate the generated PoC with a second LLM call (consistency, trigger
   confidence, minimality).
5. Save a timestamped JSON report and a ready-to-paste Markdown disclosure
   document (reports/poc_<target>_<date>.md).

PoCs are constrained to SAFE / LOW / MEDIUM risk — no destructive payloads,
no reverse shells, no RCE weaponisation.

Only stdlib + anthropic are used.

Usage
-----
    python glasswing.py poc --reports ./reports --target kafel
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-20250514"
MIN_SEVERITY  = {"high", "critical"}      # findings below this threshold are skipped
_SCANNER_IDS  = {"glasswing-scanner"}

# ---------------------------------------------------------------------------
# CWE → strategy mapping
# ---------------------------------------------------------------------------

CWE_STRATEGY: dict[str, str] = {
    "CWE-22":  "path_traversal",
    "CWE-476": "null_deref",
    "CWE-78":  "cmd_injection",
    "CWE-120": "buffer_overflow",
    "CWE-121": "buffer_overflow",
    "CWE-134": "format_string",
    "CWE-401": "memory_leak",
    "CWE-732": "bad_permissions",
    "CWE-252": "unchecked_return",
    "CWE-416": "use_after_free",
    "CWE-125": "out_of_bounds_read",
    "CWE-89":  "sql_injection",
    "CWE-77":  "cmd_injection",
}
DEFAULT_STRATEGY = "generic_fuzz"

# Per-strategy guidance injected into the generation prompt
STRATEGY_HINTS: dict[str, str] = {
    "path_traversal": (
        "Craft a malicious file path payload using ../ sequences or absolute paths "
        "to escape the intended directory. Target a benign, always-present file "
        "(e.g. /etc/hostname) to demonstrate the traversal without destructive side effects."
    ),
    "null_deref": (
        "Identify the allocation or lookup that can return NULL and craft an input "
        "or environment condition (empty config, missing argument, OOM via ulimit) "
        "that forces that path. The PoC should produce a crash, SIGSEGV, or an "
        "informative error without permanently modifying state."
    ),
    "cmd_injection": (
        "Craft a payload using benign command separators (;echo PWNED, $(id), "
        "`whoami`) to demonstrate command execution. Write only to /tmp or print "
        "to stdout — no destructive commands, no network connections."
    ),
    "buffer_overflow": (
        "Craft an oversized input (Python bytes literal or a C string) that "
        "exceeds the fixed-size buffer. Target the exact buffer size found in the "
        "code. The PoC should crash the binary or trigger AddressSanitizer / "
        "Valgrind output — not exploit the overflow to gain control."
    ),
    "format_string": (
        "Craft a payload containing printf format specifiers (%s, %x, %p) to read "
        "adjacent stack/heap memory or cause a SIGSEGV. Do not include %n — avoid "
        "any write primitives in the PoC."
    ),
    "memory_leak": (
        "Write a short loop that triggers the allocation path without freeing. "
        "Demonstrate the leak with valgrind --leak-check=full or by monitoring "
        "RSS growth via /proc/self/status. Keep the loop bounded (≤10 000 iterations)."
    ),
    "bad_permissions": (
        "Document the insecure permission bits and the exact shell commands an "
        "unprivileged user must run to read, write, or execute the affected path. "
        "This is a documentation-only PoC — no exploitation needed."
    ),
    "unchecked_return": (
        "Simulate the failure condition via ulimit -v (for OOM), a small "
        "LD_PRELOAD library that returns NULL from malloc, or by filling a tmpfs. "
        "Show the crash or incorrect behaviour that results from the unchecked return."
    ),
    "use_after_free": (
        "Demonstrate the sequence: allocate object → free object → access freed "
        "object. Run under AddressSanitizer (-fsanitize=address) or Valgrind to "
        "capture the use-after-free report. Do not attempt to exploit the condition."
    ),
    "out_of_bounds_read": (
        "Craft an input that causes the program to read past the end of a buffer. "
        "Run under AddressSanitizer or Valgrind. The PoC should show the ASAN "
        "report or a crash — not attempt to leak sensitive data beyond the demo."
    ),
    "sql_injection": (
        "Craft a payload with a single-quote or SQL meta-character that breaks "
        "out of the intended query context (e.g. ' OR '1'='1). Demonstrate the "
        "injection with a benign tautology that changes the result set; do not "
        "include DROP, DELETE, or UPDATE payloads."
    ),
    "generic_fuzz": (
        "Generate representative boundary-condition inputs: empty string, very long "
        "string (>4096 bytes), null bytes, format characters, path separators. "
        "Document exactly which input triggers the bug and what the observable "
        "symptom is (crash, wrong output, error message)."
    ),
}

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

_POC_GEN_TOOL: dict[str, Any] = {
    "name": "generate_poc",
    "description": (
        "Generate a minimal, safe, reproducible proof-of-concept for a confirmed "
        "security vulnerability. The PoC MUST NOT be destructive, weaponisable, or "
        "cause unrecoverable side effects. It must be the smallest artifact that "
        "clearly demonstrates the bug."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Numbered reproduction steps in plain English, one action per item. "
                    "Include environment setup, compilation if needed, and how to observe "
                    "the vulnerability."
                ),
            },
            "code": {
                "type": "string",
                "description": (
                    "Minimal code or command sequence that triggers the bug. "
                    "Must be self-contained and runnable. For documentation-only PoCs "
                    "this may be a shell observation command (ls -la, stat, etc.)."
                ),
            },
            "language": {
                "type": "string",
                "enum": ["bash", "python", "c", "text"],
                "description": (
                    "Language of the PoC. Use 'text' for pure-documentation PoCs "
                    "(e.g. bad_permissions)."
                ),
            },
            "expected_vulnerable": {
                "type": "string",
                "description": (
                    "Exact output, error message, crash log, or observable symptom "
                    "when the vulnerability is present and the PoC succeeds."
                ),
            },
            "expected_patched": {
                "type": "string",
                "description": (
                    "Output or behaviour after a correct fix is applied — shows how "
                    "the PoC fails cleanly once the bug is resolved."
                ),
            },
            "suggested_fix": {
                "type": "string",
                "description": (
                    "One concrete paragraph describing how to fix the vulnerability: "
                    "which function or check to add, which API to use instead, "
                    "or which invariant to enforce."
                ),
            },
            "risk": {
                "type": "string",
                "enum": ["SAFE", "LOW", "MEDIUM"],
                "description": (
                    "SAFE: documentation only, zero code to execute. "
                    "LOW: runs locally, produces output, no persistent side effects. "
                    "MEDIUM: creates temporary files or consumes significant local resources."
                ),
            },
        },
        "required": [
            "steps", "code", "language",
            "expected_vulnerable", "expected_patched",
            "suggested_fix", "risk",
        ],
    },
}

_POC_VALIDATE_TOOL: dict[str, Any] = {
    "name": "validate_poc",
    "description": (
        "Review a generated proof-of-concept against the original finding. "
        "Assess whether it is logically consistent with the bug, would actually "
        "exercise the vulnerable code path, and is as minimal as possible."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "is_consistent": {
                "type": "boolean",
                "description": (
                    "True if the PoC correctly targets the described vulnerability "
                    "and not some unrelated code path."
                ),
            },
            "triggers_bug": {
                "type": "boolean",
                "description": (
                    "True if executing the PoC as written would exercise the "
                    "vulnerable code path and produce the described symptom."
                ),
            },
            "is_minimal": {
                "type": "boolean",
                "description": "True if the PoC has no unnecessary complexity or steps.",
            },
            "confidence": {
                "type": "string",
                "enum": ["HIGH", "MEDIUM", "LOW"],
                "description": (
                    "HIGH: PoC is solid — directly triggers the bug, no speculative steps. "
                    "MEDIUM: PoC likely works but has one or two unverified assumptions. "
                    "LOW: PoC is speculative or relies on conditions not confirmed by the code."
                ),
            },
            "notes": {
                "type": "string",
                "description": (
                    "2–3 sentence review: what is strong about the PoC, what assumptions "
                    "it makes, and any refinements that would improve confidence."
                ),
            },
        },
        "required": [
            "is_consistent", "triggers_bug", "is_minimal", "confidence", "notes",
        ],
    },
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LoadedFinding:
    """A HIGH/CRITICAL scanner finding ready for PoC generation."""
    title:           str
    vuln_type:       str
    cwe:             str
    severity:        str
    cvss:            float | None
    file:            str
    line_start:      int | None
    line_end:        int | None
    impact:          str
    poc_idea:        str
    code_snippet:    str
    disclosure_hash: str
    source_report:   str
    strategy:        str = ""     # filled by select_strategy()


@dataclass
class PocResult:
    """One generated-and-validated PoC paired with its finding."""
    finding:          LoadedFinding
    steps:            list[str]  = field(default_factory=list)
    code:             str        = ""
    language:         str        = "text"
    expected_vuln:    str        = ""
    expected_patched: str        = ""
    suggested_fix:    str        = ""
    risk:             str        = "SAFE"
    generated:        bool       = False
    # Validator output
    confidence:       str        = "LOW"
    needs_review:     bool       = True
    validator_notes:  str        = ""
    validated:        bool       = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_cwe(cwe_str: str) -> str:
    """Extract the CWE-NNN token from a verbose CWE string."""
    m = re.match(r"(CWE-\d+)", cwe_str.strip(), re.IGNORECASE)
    return m.group(1).upper() if m else cwe_str.strip()


def _loc(f: LoadedFinding) -> str:
    """Return a 'file:start-end' location string for a finding."""
    s = f.file
    if f.line_start:
        s += f":{f.line_start}"
        if f.line_end and f.line_end != f.line_start:
            s += f"-{f.line_end}"
    return s


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class PocGenerator:
    """
    Orchestrates the full PoC generation pipeline:
    load → select strategy → generate → validate → report.
    """

    def __init__(
        self,
        reports_dir: str | Path,
        target: str,
        model: str = DEFAULT_MODEL,
        verbose: bool = False,
        output_dir: str | Path | None = None,
    ) -> None:
        self.reports_dir = Path(reports_dir).resolve()
        self.target      = target.strip().lower()
        self.model       = model
        self.verbose     = verbose
        self.output_dir  = (
            Path(output_dir).resolve() if output_dir else self.reports_dir
        )
        self.client      = anthropic.Anthropic()

        if not self.reports_dir.is_dir():
            raise ValueError(f"Reports directory not found: {self.reports_dir}")
        if not self.target:
            raise ValueError("Target name must not be empty.")

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        print(msg, flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}", flush=True)

    # ------------------------------------------------------------------
    # Step 1 — Load findings
    # ------------------------------------------------------------------

    def _matches_target(self, path: Path, report: dict[str, Any]) -> bool:
        if self.target in path.name.lower():
            return True
        for key in ("repo", "target", "target_url"):
            val = report.get(key, "")
            if val and self.target in str(val).lower():
                return True
        return False

    def load_findings(self) -> tuple[list[LoadedFinding], list[str]]:
        """
        Walk reports_dir, load all glasswing-scanner reports matching the target,
        and return (HIGH/CRITICAL findings, source report paths).
        """
        findings: list[LoadedFinding] = []
        sources:  list[str]           = []
        seen:     set[str]            = set()

        for rpt_path in sorted(self.reports_dir.glob("*.json")):
            try:
                report: dict[str, Any] = json.loads(
                    rpt_path.read_text(encoding="utf-8", errors="replace")
                )
            except (OSError, json.JSONDecodeError) as exc:
                self._vlog(f"skipping {rpt_path.name}: {exc}")
                continue

            if report.get("scanner") not in _SCANNER_IDS:
                self._vlog(f"skipping {rpt_path.name}: not a scanner report")
                continue

            if not self._matches_target(rpt_path, report):
                self._vlog(f"skipping {rpt_path.name}: no target match")
                continue

            raw = report.get("findings", [])
            self._vlog(f"checking {rpt_path.name} — {len(raw)} total finding(s)")

            added = 0
            for f in raw:
                sev = f.get("severity", "").lower()
                if sev not in MIN_SEVERITY:
                    self._vlog(f"  skip [{sev}] {f.get('title', '?')}")
                    continue
                dhash = f.get("disclosure_hash", "")
                if dhash in seen:
                    continue
                seen.add(dhash)

                cwe_raw = f.get("cwe", "")
                findings.append(LoadedFinding(
                    title=f.get("title", "Untitled"),
                    vuln_type=f.get("type", ""),
                    cwe=_normalize_cwe(cwe_raw) if cwe_raw else "",
                    severity=sev,
                    cvss=f.get("cvss_estimate"),
                    file=f.get("file", ""),
                    line_start=f.get("line_start"),
                    line_end=f.get("line_end"),
                    impact=f.get("impact", ""),
                    poc_idea=f.get("poc_idea", ""),
                    code_snippet=f.get("code_snippet", ""),
                    disclosure_hash=dhash,
                    source_report=str(rpt_path),
                ))
                added += 1

            if added:
                sources.append(str(rpt_path))
                self._vlog(f"  -> {added} HIGH/CRITICAL finding(s) accepted")

        return findings, sources

    # ------------------------------------------------------------------
    # Step 2 — Strategy selection
    # ------------------------------------------------------------------

    def select_strategy(self, finding: LoadedFinding) -> str:
        """Return the PoC strategy name for this finding's CWE."""
        return CWE_STRATEGY.get(finding.cwe.upper(), DEFAULT_STRATEGY)

    # ------------------------------------------------------------------
    # Step 3 — PoC generation
    # ------------------------------------------------------------------

    def generate_poc(self, finding: LoadedFinding) -> PocResult:
        """
        Ask Claude to produce a minimal, safe PoC for the finding.
        Returns a PocResult (generated=True on success).
        """
        result   = PocResult(finding=finding)
        strategy = finding.strategy
        hint     = STRATEGY_HINTS.get(strategy, STRATEGY_HINTS[DEFAULT_STRATEGY])
        location = _loc(finding)

        snippet_block = ""
        if finding.code_snippet:
            snippet_block = (
                f"\n**Vulnerable code (`{location}`):**\n"
                f"```\n{finding.code_snippet[:1800]}\n```\n"
            )

        prompt = (
            "You are a security researcher writing a minimal, safe, responsible "
            "proof-of-concept for a confirmed vulnerability.\n\n"
            "━━ HARD CONSTRAINTS ━━\n"
            "• The PoC MUST be safe to run in a local, isolated test environment.\n"
            "• Do NOT generate shellcode, reverse shells, rootkits, or any payload "
            "that could damage a system, exfiltrate real data, or escalate privileges "
            "beyond demonstrating the bug.\n"
            "• Command injection payloads must only echo output or write to /tmp.\n"
            "• Buffer overflow PoCs must only crash the binary — no shell spawning.\n"
            "• Format string PoCs must only read memory — no %n write primitives.\n"
            "• Keep the PoC as minimal as possible: fewest lines that prove the bug.\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"**Finding:** {finding.title}\n"
            f"**CWE:** {finding.cwe}  |  **Severity:** {finding.severity.upper()}  "
            f"|  **CVSS:** {finding.cvss if finding.cvss is not None else 'N/A'}\n"
            f"**File:** {location}\n"
            f"**Impact:** {finding.impact}\n"
            f"**Scanner's PoC idea:** {finding.poc_idea}\n"
            f"{snippet_block}\n"
            f"**Strategy:** {strategy}\n"
            f"**Guidance:** {hint}\n\n"
            "Call `generate_poc` with:\n"
            "• Clear numbered reproduction steps\n"
            "• Minimal, runnable code (bash / python / c as appropriate)\n"
            "• Exact expected output when vulnerable\n"
            "• Exact expected output when patched\n"
            "• One concrete paragraph describing the fix\n"
            "• Risk rating: SAFE (docs only) / LOW (no side effects) / "
            "MEDIUM (local files or resources)"
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                tools=[_POC_GEN_TOOL],
                tool_choice={"type": "tool", "name": "generate_poc"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] API error generating PoC for '{finding.title}': {exc}")
            return result

        for block in response.content:
            if block.type == "tool_use" and block.name == "generate_poc":
                inp = block.input
                result.steps            = list(inp.get("steps", []))
                result.code             = inp.get("code", "")
                result.language         = inp.get("language", "text")
                result.expected_vuln    = inp.get("expected_vulnerable", "")
                result.expected_patched = inp.get("expected_patched", "")
                result.suggested_fix    = inp.get("suggested_fix", "")
                result.risk             = inp.get("risk", "SAFE")
                result.generated        = True

        return result

    # ------------------------------------------------------------------
    # Step 4 — PoC validation
    # ------------------------------------------------------------------

    def validate_poc(self, result: PocResult) -> PocResult:
        """
        Second-pass LLM call: critically review the generated PoC for
        consistency, trigger confidence, and minimality.
        Mutates *result* in-place and returns it.
        """
        if not result.generated:
            return result

        f          = result.finding
        steps_text = "\n".join(
            f"{i + 1}. {s}" for i, s in enumerate(result.steps)
        )

        prompt = (
            "You are a senior security engineer providing a second opinion on a "
            "generated proof-of-concept.\n\n"
            f"**Finding:** {f.title}  ({f.cwe})\n"
            f"**Severity:** {f.severity.upper()}  "
            f"|  **CVSS:** {f.cvss if f.cvss is not None else 'N/A'}\n"
            f"**File:** {_loc(f)}\n"
            f"**Impact:** {f.impact}\n\n"
            f"**Generated PoC ({result.language}):**\n"
            f"```{result.language if result.language != 'text' else ''}\n"
            f"{result.code}\n"
            "```\n\n"
            f"**Reproduction steps:**\n{steps_text}\n\n"
            f"**Expected output — vulnerable:** {result.expected_vuln}\n"
            f"**Expected output — patched:**    {result.expected_patched}\n\n"
            "Call `validate_poc` to assess:\n"
            "• Is the PoC consistent with the described vulnerability?\n"
            "• Would it actually exercise the vulnerable code path?\n"
            "• Is it as minimal as it can be?\n"
            "• Rate confidence: HIGH / MEDIUM / LOW"
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                tools=[_POC_VALIDATE_TOOL],
                tool_choice={"type": "tool", "name": "validate_poc"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] API error validating PoC for '{f.title}': {exc}")
            return result

        for block in response.content:
            if block.type == "tool_use" and block.name == "validate_poc":
                inp = block.input
                result.confidence     = inp.get("confidence", "LOW")
                result.validator_notes = inp.get("notes", "")
                result.validated      = True
                result.needs_review   = result.confidence == "LOW"

        return result

    # ------------------------------------------------------------------
    # Step 5 — Report assembly
    # ------------------------------------------------------------------

    def _build_report(
        self,
        results: list[PocResult],
        source_reports: list[str],
        total_loaded: int,
    ) -> dict[str, Any]:
        generated = [r for r in results if r.generated]
        by_conf: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_risk: dict[str, int] = {"SAFE": 0, "LOW": 0, "MEDIUM": 0}
        needs_review = 0
        for r in generated:
            by_conf[r.confidence] = by_conf.get(r.confidence, 0) + 1
            by_risk[r.risk]       = by_risk.get(r.risk, 0) + 1
            if r.needs_review:
                needs_review += 1

        return {
            "scanner":        "glasswing-poc-generator",
            "version":        "1.0.0",
            "model":          self.model,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "target":         self.target,
            "reports_dir":    str(self.reports_dir),
            "source_reports": source_reports,
            "summary": {
                "findings_loaded":     total_loaded,
                "pocs_generated":      len(generated),
                "needs_manual_review": needs_review,
                "by_confidence":       by_conf,
                "by_risk":             by_risk,
            },
            "pocs": [
                {
                    "finding": {
                        "title":           r.finding.title,
                        "type":            r.finding.vuln_type,
                        "cwe":             r.finding.cwe,
                        "severity":        r.finding.severity,
                        "cvss":            r.finding.cvss,
                        "file":            r.finding.file,
                        "line_start":      r.finding.line_start,
                        "line_end":        r.finding.line_end,
                        "impact":          r.finding.impact,
                        "disclosure_hash": r.finding.disclosure_hash,
                        "source_report":   r.finding.source_report,
                    },
                    "strategy":            r.finding.strategy,
                    "steps":               r.steps,
                    "code":                r.code,
                    "language":            r.language,
                    "expected_vulnerable": r.expected_vuln,
                    "expected_patched":    r.expected_patched,
                    "suggested_fix":       r.suggested_fix,
                    "risk":                r.risk,
                    "validation": {
                        "confidence":    r.confidence,
                        "needs_review":  r.needs_review,
                        "notes":         r.validator_notes,
                    },
                }
                for r in generated
            ],
        }

    def _build_markdown(self, results: list[PocResult]) -> str:
        """Build a ready-to-paste Markdown disclosure document."""
        generated = [r for r in results if r.generated]
        ts        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines: list[str] = [
            f"# Glasswing PoC Report — {self.target}",
            "",
            f"**Generated:** {ts}  ",
            f"**Model:** {self.model}  ",
            f"**PoCs generated:** {len(generated)}",
            "",
            "---",
            "",
        ]

        for i, r in enumerate(generated, 1):
            f        = r.finding
            cvss_str = f"{f.cvss:.1f}" if f.cvss is not None else "N/A"
            location = _loc(f)
            review   = "  ⚠️ NEEDS MANUAL REVIEW" if r.needs_review else ""

            lines += [
                f"## {i}. {f.title}",
                "",
                "| | |",
                "|---|---|",
                f"| **CWE** | {f.cwe} |",
                f"| **Severity** | {f.severity.upper()} |",
                f"| **CVSS** | {cvss_str} |",
                f"| **File** | `{location}` |",
                f"| **Strategy** | {f.strategy} |",
                f"| **PoC Confidence** | {r.confidence}{review} |",
                f"| **Risk to Run** | {r.risk} |",
                f"| **Disclosure Hash** | `{f.disclosure_hash}` |",
                "",
                "### Impact",
                "",
                f.impact,
                "",
            ]

            if r.steps:
                lines += ["### Reproduction Steps", ""]
                for j, step in enumerate(r.steps, 1):
                    lines.append(f"{j}. {step}")
                lines.append("")

            if r.code:
                lang_tag = r.language if r.language != "text" else ""
                lines += [
                    f"### PoC ({r.language})",
                    "",
                    f"```{lang_tag}",
                    r.code,
                    "```",
                    "",
                ]

            if r.expected_vuln:
                lines += [
                    "### Expected Output — Vulnerable",
                    "",
                    "```",
                    r.expected_vuln,
                    "```",
                    "",
                ]

            if r.expected_patched:
                lines += [
                    "### Expected Output — Patched",
                    "",
                    "```",
                    r.expected_patched,
                    "```",
                    "",
                ]

            if r.suggested_fix:
                lines += [
                    "### Suggested Fix",
                    "",
                    r.suggested_fix,
                    "",
                ]

            if r.validator_notes:
                lines += [
                    "### Reviewer Notes",
                    "",
                    f"*{r.validator_notes}*",
                    "",
                ]

            lines += ["---", ""]

        return "\n".join(lines)

    def save_report(
        self,
        report: dict[str, Any],
        markdown: str,
    ) -> tuple[Path, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        json_out = self.output_dir / f"poc_{self.target}_{ts}.json"
        md_out   = self.output_dir / f"poc_{self.target}_{ts}.md"

        json_out.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        md_out.write_text(markdown, encoding="utf-8")

        return json_out, md_out

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """Execute the full pipeline and return the completed report dict."""

        # ── 1. Load ──────────────────────────────────────────────────────
        self._log(
            f"[*] Loading HIGH/CRITICAL findings for target '{self.target}' "
            f"from {self.reports_dir} …"
        )
        findings, sources = self.load_findings()
        self._log(f"    {len(findings)} qualifying finding(s) loaded.")

        if not findings:
            self._log("[!] No HIGH or CRITICAL findings found — nothing to generate.")
            report   = self._build_report([], sources, 0)
            markdown = self._build_markdown([])
            jp, mp   = self.save_report(report, markdown)
            self._log(f"[+] Empty PoC report saved -> {jp}")
            return report

        # ── 2. Select strategies ─────────────────────────────────────────
        self._log("[*] Selecting PoC strategies …")
        for f in findings:
            f.strategy = self.select_strategy(f)
            self._vlog(f"{f.title}  ({f.cwe})  ->  {f.strategy}")

        # ── 3. Generate ──────────────────────────────────────────────────
        self._log(f"[*] Generating PoCs for {len(findings)} finding(s) …")
        results: list[PocResult] = []
        for idx, finding in enumerate(findings, 1):
            self._log(
                f"    [{idx}/{len(findings)}] {finding.title}  "
                f"({finding.cwe}, {finding.strategy}) …"
            )
            result = self.generate_poc(finding)
            if result.generated:
                self._log(
                    f"        -> generated  "
                    f"language={result.language}  risk={result.risk}"
                )
            else:
                self._log("        -> generation failed")
            results.append(result)

        # ── 4. Validate ──────────────────────────────────────────────────
        generated = [r for r in results if r.generated]
        self._log(f"[*] Validating {len(generated)} generated PoC(s) …")
        for idx, result in enumerate(generated, 1):
            self._log(
                f"    [{idx}/{len(generated)}] "
                f"validating '{result.finding.title}' …"
            )
            self.validate_poc(result)
            review_tag = "  ⚠ NEEDS_MANUAL_REVIEW" if result.needs_review else ""
            self._log(f"        -> confidence={result.confidence}{review_tag}")

        # ── 5. Save ───────────────────────────────────────────────────────
        report   = self._build_report(results, sources, len(findings))
        markdown = self._build_markdown(results)
        jp, mp   = self.save_report(report, markdown)

        self._log("")
        gen_n = len(generated)
        rev_n = sum(1 for r in generated if r.needs_review)
        self._log(f"[+] PoC generation complete.  {gen_n} PoC(s) generated.")
        if rev_n:
            self._log(f"    ⚠ {rev_n} PoC(s) flagged for manual review.")
        self._log(f"[+] JSON   -> {jp}")
        self._log(f"[+] Markdown -> {mp}")

        return report


# ---------------------------------------------------------------------------
# Console report printer  (called by glasswing.py report subcommand)
# ---------------------------------------------------------------------------


def print_poc_report(report: dict[str, Any]) -> None:
    """Print a colour-coded PoC report summary to stdout."""
    try:
        from glasswing import (  # type: ignore
            _c, _hr, _wrap,
            _BOLD, _RED, _YELLOW, _CYAN, _GREEN, _DIM,
        )
    except ImportError:
        def _c(t: str, *_: str) -> str:    return t        # type: ignore[misc]
        def _hr(w: int = 72) -> str:        return "─" * w  # type: ignore[misc]
        def _wrap(t: str, **_: Any) -> str: return t        # type: ignore[misc]
        _BOLD = _RED = _YELLOW = _CYAN = _GREEN = _DIM = ""

    _SEV_COLOR  = {
        "critical": _RED + _BOLD, "high": _RED,
        "medium":   _YELLOW,      "low":  _CYAN,
    }
    _CONF_COLOR = {"HIGH": _GREEN, "MEDIUM": _YELLOW, "LOW": _RED}
    _RISK_COLOR = {"SAFE": _GREEN, "LOW": _CYAN,       "MEDIUM": _YELLOW}

    pocs    = report.get("pocs", [])
    summary = report.get("summary", {})
    target  = report.get("target", "?")
    ts      = report.get("timestamp", "?")
    model   = report.get("model", "?")
    gen_n   = summary.get("pocs_generated", 0)
    rev_n   = summary.get("needs_manual_review", 0)

    print(_hr())
    print(_c(" GLASSWING POC REPORT", _BOLD))
    print(_hr())
    print(f"  {'Target':<14}{target}")
    print(f"  {'Scanned':<14}{ts}")
    print(f"  {'Model':<14}{model}")
    print(
        f"  {'Findings in':<14}"
        f"{summary.get('findings_loaded', '?')} HIGH/CRITICAL loaded"
    )
    review_note = f"  ·  ⚠ {rev_n} need review" if rev_n else ""
    print(f"  {'PoCs':<14}{gen_n} generated{review_note}")
    print(_hr())

    # Breakdown bars
    by_conf = summary.get("by_confidence", {})
    by_risk = summary.get("by_risk", {})
    if gen_n:
        print(_c(" CONFIDENCE BREAKDOWN", _BOLD))
        for lvl in ("HIGH", "MEDIUM", "LOW"):
            n = by_conf.get(lvl, 0)
            if n:
                print(
                    f"  {_c(f'{lvl:<10}', _CONF_COLOR.get(lvl, ''))}  {n}"
                )
        print(_hr())
        print(_c(" RISK BREAKDOWN", _BOLD))
        for lvl in ("SAFE", "LOW", "MEDIUM"):
            n = by_risk.get(lvl, 0)
            if n:
                print(
                    f"  {_c(f'{lvl:<10}', _RISK_COLOR.get(lvl, ''))}  {n}"
                )
        print(_hr())

    if not pocs:
        print(_c("  No PoCs generated.", _GREEN))
        print(_hr())
        return

    print(_c(" PROOF OF CONCEPTS", _BOLD))
    print(_hr())

    for poc in pocs:
        f        = poc.get("finding", {})
        sev      = f.get("severity", "")
        title    = f.get("title", "?")
        cwe      = f.get("cwe", "")
        cvss     = f.get("cvss")
        ffile    = f.get("file", "")
        dhash    = f.get("disclosure_hash", "")
        strategy = poc.get("strategy", "")
        lang     = poc.get("language", "text")
        risk     = poc.get("risk", "SAFE")
        steps    = poc.get("steps", [])
        code     = poc.get("code", "")
        ev       = poc.get("expected_vulnerable", "")
        fix      = poc.get("suggested_fix", "")
        val      = poc.get("validation", {})
        conf     = val.get("confidence", "LOW")
        vn       = val.get("notes", "")
        review   = val.get("needs_review", False)

        cvss_str  = f"{cvss:.1f}" if cvss is not None else "?"
        s_color   = _SEV_COLOR.get(sev, "")
        c_color   = _CONF_COLOR.get(conf, "")
        r_color   = _RISK_COLOR.get(risk, "")
        rev_flag  = _c("  ⚠ NEEDS REVIEW", _RED + _BOLD) if review else ""

        print(
            f"\n  {_c(f'[{sev.upper()}]', s_color)}  "
            f"{_c(title, _BOLD)}{rev_flag}"
        )
        meta = "  ·  ".join(filter(None, [
            cwe,
            f"CVSS {cvss_str}" if cvss_str != "?" else None,
            strategy,
        ]))
        if meta:
            print(f"  {'':12}{_c(meta, _DIM)}")
        if ffile:
            print(f"  {'File':<12}{ffile}")
        print(
            f"  {'Confidence':<12}{_c(conf, c_color)}  "
            f"·  Risk: {_c(risk, r_color)}  "
            f"·  Lang: {lang}"
        )
        if dhash:
            print(f"  {'Hash':<12}{_c(dhash[:16] + '…', _DIM)}")

        if steps:
            print(f"  {'Steps':<12}")
            for j, step in enumerate(steps[:4], 1):
                print(f"               {j}. {step[:70]}")
            if len(steps) > 4:
                print(f"               … {len(steps) - 4} more step(s)")

        if code:
            first_line = code.splitlines()[0][:80].strip()
            print(f"  {'PoC':<12}{_c(first_line, _DIM)}")

        if ev:
            ev_short = ev.splitlines()[0][:70]
            print(f"  {'Vuln output':<12}{_c(ev_short, _DIM)}")

        if fix:
            print(f"  {'Fix':<12}{_wrap(fix[:180], indent=14)}")

        if vn:
            print(f"  {'Review':<12}{_c(vn[:120], _DIM)}")

    print(f"\n{_hr()}")


# ---------------------------------------------------------------------------
# CLI  (standalone; main entry is glasswing.py)
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glasswing-poc-generator",
        description=(
            "Generate minimal, safe PoCs for confirmed HIGH/CRITICAL findings."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/poc_generator.py --reports ./reports --target kafel\n"
            "  python src/poc_generator.py --reports ./reports --target myapp -v\n"
        ),
    )
    parser.add_argument(
        "--reports", "-r",
        default="reports",
        metavar="DIR",
        help="Directory containing glasswing JSON reports (default: reports/).",
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="NAME",
        help="Target name used to filter reports (e.g. 'kafel').",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        metavar="DIR",
        help="Output directory (default: same as --reports).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Claude model to use (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args   = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 1

    try:
        gen = PocGenerator(
            reports_dir=args.reports,
            target=args.target,
            model=args.model,
            verbose=args.verbose,
            output_dir=args.output_dir,
        )
        gen.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
