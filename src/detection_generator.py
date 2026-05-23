#!/usr/bin/env python
"""
Talon Scanner — Detection Generator (Phase 7).

For each confirmed HIGH/CRITICAL finding, automatically generates detection
rules that a Blue Team can deploy to catch exploitation attempts.

Pipeline
--------
1. Load HIGH/CRITICAL findings from glasswing-scanner reports matching target.
2. Map each finding's CWE to a detection strategy (network, process, file,
   crash, auth-anomaly, or generic).
3. Ask Claude to generate three rule formats per finding:
     KQL   — Microsoft Sentinel / Defender XDR query
     Sigma — universal SIEM YAML rule (logsource + detection + condition)
     YARA  — file/memory pattern (only for findings with binary/file angle)
4. Validate each ruleset with a second LLM pass: syntax quality, false-positive
   risk, and a readiness rating (PRODUCTION_READY / NEEDS_TUNING / DRAFT).
5. Save rules to reports/detections_{target}_{YYYYMMDD}/ and write a Markdown
   summary combining all findings.

Only stdlib + anthropic are used.

Usage
-----
    python glasswing.py detect --reports ./reports --target cilium
    python glasswing.py detect --reports ./reports --target cilium --finding 1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-20250514"
MIN_SEVERITY  = {"high", "critical"}
_SCANNER_IDS  = {"glasswing-scanner"}

# ---------------------------------------------------------------------------
# CWE → detection strategy
# ---------------------------------------------------------------------------

# strategy → (label, tables_hint, yara_applicable)
_STRATEGY_META: dict[str, tuple[str, str, bool]] = {
    "network_sqli": (
        "Network + Query Pattern Signatures",
        "CommonSecurityLog, AuditLogs, Syslog",
        False,
    ),
    "process_cmdinj": (
        "Process Creation + Command-Line Rules",
        "DeviceProcessEvents, SecurityEvent, Syslog",
        False,
    ),
    "runtime_codeinj": (
        "Runtime Behaviour + Resource Spike",
        "DeviceProcessEvents, Syslog, SecurityEvent",
        True,
    ),
    "file_traversal": (
        "File-Access Pattern Detection",
        "DeviceFileEvents, Syslog, CommonSecurityLog",
        True,
    ),
    "crash_signal": (
        "Crash / Signal Detection",
        "Syslog, SecurityEvent, DeviceProcessEvents",
        False,
    ),
    "process_spawn": (
        "Unexpected Process Spawn (Deserialization)",
        "DeviceProcessEvents, SecurityEvent",
        True,
    ),
    "auth_anomaly": (
        "Auth Anomaly Pattern",
        "SigninLogs, AuditLogs, SecurityEvent",
        False,
    ),
    "generic_anomaly": (
        "Generic Anomaly Detection",
        "SecurityEvent, Syslog, CommonSecurityLog",
        False,
    ),
}

CWE_TO_STRATEGY: dict[str, str] = {
    "CWE-89":  "network_sqli",
    "CWE-564": "network_sqli",       # SQL injection via HQL
    "CWE-78":  "process_cmdinj",
    "CWE-77":  "process_cmdinj",
    "CWE-88":  "process_cmdinj",
    "CWE-94":  "runtime_codeinj",
    "CWE-95":  "runtime_codeinj",
    "CWE-96":  "runtime_codeinj",
    "CWE-770": "runtime_codeinj",    # Allocation without limits (resource spike)
    "CWE-22":  "file_traversal",
    "CWE-23":  "file_traversal",
    "CWE-36":  "file_traversal",
    "CWE-73":  "file_traversal",
    "CWE-476": "crash_signal",
    "CWE-119": "crash_signal",
    "CWE-120": "crash_signal",
    "CWE-121": "crash_signal",
    "CWE-122": "crash_signal",
    "CWE-125": "crash_signal",
    "CWE-416": "crash_signal",
    "CWE-415": "crash_signal",
    "CWE-502": "process_spawn",
    "CWE-915": "process_spawn",
    "CWE-347": "auth_anomaly",
    "CWE-306": "auth_anomaly",
    "CWE-287": "auth_anomaly",
    "CWE-384": "auth_anomaly",
}
DEFAULT_STRATEGY = "generic_anomaly"

# Strategy-specific guidance injected into the generation prompt
_STRATEGY_HINTS: dict[str, str] = {
    "network_sqli": (
        "Focus on detecting SQL meta-characters (' \" ; -- /* */) and common "
        "SQLi payloads in HTTP parameters, headers, and query strings logged to "
        "CommonSecurityLog or Syslog. Include threshold-based rules to catch "
        "high request rates to the same endpoint. For Sigma use webserver or "
        "proxy logsource. YARA is not applicable."
    ),
    "process_cmdinj": (
        "Target process creation events where a web or service process spawns "
        "unexpected children (sh, bash, cmd, powershell). Look for shell "
        "meta-characters in command-line fields (;, &&, |, $(), backtick). "
        "Use DeviceProcessEvents (KQL) and process_creation logsource (Sigma)."
    ),
    "runtime_codeinj": (
        "Detect abnormal CPU/memory spikes, unexpected interpreter processes "
        "(python, node, ruby) spawned by service accounts, and new DLL/SO "
        "loads in long-running processes. For YARA scan for eval/exec strings "
        "or shellcode NOP sleds in process memory dumps."
    ),
    "file_traversal": (
        "Look for path strings containing '../', '%2e%2e', or absolute paths "
        "in file-open audit events (auditd, Sysmon EventID 11). Alert when "
        "files outside expected directories are accessed by a service process. "
        "YARA should detect traversal sequences in uploaded or cached files."
    ),
    "crash_signal": (
        "Query for kernel logs containing 'segfault', 'general protection fault', "
        "SIGSEGV, or core dump events originating from the target process. "
        "Correlate with preceding unusual input events. YARA is not applicable "
        "for this pattern — crash detection is purely log-based."
    ),
    "process_spawn": (
        "Detect the target service spawning shell interpreters or compilers "
        "as child processes, which is the hallmark of unsafe deserialization. "
        "Include parent-child process chain checks. YARA should scan for Java "
        "serialized-object magic bytes (0xACED0005) or Python pickle opcodes "
        "in network captures or uploaded files."
    ),
    "auth_anomaly": (
        "Detect authentication failures from unusual IPs, forged/expired JWT "
        "tokens (algorithm=none, far-future exp), or auth bypass attempts "
        "reflected in 401/403 spikes followed by a 200. Use SigninLogs and "
        "AuditLogs. YARA is not applicable."
    ),
    "generic_anomaly": (
        "Generate a broad anomaly rule: unexpected error rates, new IP ranges "
        "accessing sensitive endpoints, or sudden spikes in failed operations. "
        "Combine with entity mapping (IP, user, host) to enable investigation."
    ),
}

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

_GEN_TOOL: dict[str, Any] = {
    "name": "generate_detection_rules",
    "description": (
        "Generate KQL, Sigma, and (optionally) YARA detection rules for a "
        "confirmed security vulnerability. Rules must be syntactically correct, "
        "operationally realistic, and tuned to minimize false positives."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "kql": {
                "type": "string",
                "description": (
                    "A complete, runnable KQL query for Microsoft Sentinel or "
                    "Defender XDR. Must query one of the standard tables "
                    "(SecurityEvent, Syslog, CommonSecurityLog, AuditLogs, "
                    "SigninLogs, DeviceProcessEvents, DeviceFileEvents). "
                    "Include: time window (last 24h default), where/filter "
                    "clauses targeting the attack pattern, summarize for "
                    "threshold logic, extend for entity mapping (IP, User, "
                    "Host), and a comment block at the top with the finding "
                    "title, CWE, MITRE ATT&CK technique, and author."
                ),
            },
            "kql_mitre": {
                "type": "string",
                "description": (
                    "MITRE ATT&CK technique ID(s) this KQL rule covers, "
                    "e.g. 'T1190 - Exploit Public-Facing Application'."
                ),
            },
            "sigma": {
                "type": "string",
                "description": (
                    "A complete, valid Sigma rule in YAML format. Must include: "
                    "title, id (UUID v4), status (experimental/test/stable), "
                    "description, author ('0xDanielSec / Talon Scanner'), "
                    "date (today), tags (attack.* MITRE), logsource "
                    "(category + product), detection (keywords/field-value + "
                    "condition), falsepositives list, and level "
                    "(informational/low/medium/high/critical)."
                ),
            },
            "yara": {
                "type": "string",
                "description": (
                    "A YARA rule for file or memory scanning. Include: "
                    "rule name (snake_case), meta block with description/author/"
                    "date/reference, strings block with named patterns "
                    "($hex_* for byte patterns, $str_* for text strings), "
                    "and a condition. Return an empty string if YARA is not "
                    "applicable to this vulnerability class."
                ),
            },
            "yara_applicable": {
                "type": "boolean",
                "description": (
                    "True if a meaningful YARA rule was generated; false if "
                    "the vulnerability has no file/memory artifact to scan."
                ),
            },
            "fp_notes": {
                "type": "string",
                "description": (
                    "2-3 sentences on the main false-positive sources for "
                    "these rules and how an analyst should triage them."
                ),
            },
        },
        "required": [
            "kql", "kql_mitre", "sigma",
            "yara", "yara_applicable", "fp_notes",
        ],
    },
}

_VAL_TOOL: dict[str, Any] = {
    "name": "validate_detection_rules",
    "description": (
        "Review generated detection rules for syntax correctness, operational "
        "quality, and false-positive risk. Provide a readiness rating for each."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "kql_valid": {
                "type": "boolean",
                "description": "True if the KQL is syntactically correct and would parse in Sentinel.",
            },
            "kql_fp_risk": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH"],
                "description": "False-positive risk of the KQL rule in a typical enterprise environment.",
            },
            "kql_rating": {
                "type": "string",
                "enum": ["PRODUCTION_READY", "NEEDS_TUNING", "DRAFT"],
                "description": (
                    "PRODUCTION_READY: can be deployed as-is. "
                    "NEEDS_TUNING: logic is sound but thresholds or allowlists "
                    "need environment-specific adjustment. "
                    "DRAFT: requires significant rework."
                ),
            },
            "sigma_valid": {
                "type": "boolean",
                "description": "True if the Sigma YAML is well-formed and would pass sigma-cli validation.",
            },
            "sigma_fp_risk": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH"],
                "description": "False-positive risk of the Sigma rule.",
            },
            "sigma_rating": {
                "type": "string",
                "enum": ["PRODUCTION_READY", "NEEDS_TUNING", "DRAFT"],
            },
            "yara_valid": {
                "type": "boolean",
                "description": "True if the YARA rule compiles without errors (or N/A if not generated).",
            },
            "yara_rating": {
                "type": "string",
                "enum": ["PRODUCTION_READY", "NEEDS_TUNING", "DRAFT", "N/A"],
            },
            "notes": {
                "type": "string",
                "description": (
                    "2-3 sentences summarising the overall quality of the ruleset "
                    "and the most important tuning action before deployment."
                ),
            },
        },
        "required": [
            "kql_valid", "kql_fp_risk", "kql_rating",
            "sigma_valid", "sigma_fp_risk", "sigma_rating",
            "yara_valid", "yara_rating", "notes",
        ],
    },
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LoadedFinding:
    """A HIGH/CRITICAL scanner finding ready for detection generation."""
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
    repo:            str
    strategy:        str = ""   # filled by select_strategy()


@dataclass
class RuleSet:
    """Generated (and optionally validated) detection rules for one finding."""
    finding:          LoadedFinding

    # Generation output
    kql:              str  = ""
    kql_mitre:        str  = ""
    sigma:            str  = ""
    yara:             str  = ""
    yara_applicable:  bool = False
    fp_notes:         str  = ""
    generated:        bool = False

    # Validation output
    kql_valid:        bool = False
    kql_fp_risk:      str  = "HIGH"
    kql_rating:       str  = "DRAFT"
    sigma_valid:      bool = False
    sigma_fp_risk:    str  = "HIGH"
    sigma_rating:     str  = "DRAFT"
    yara_valid:       bool = False
    yara_rating:      str  = "N/A"
    val_notes:        str  = ""
    validated:        bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_cwe(raw: str) -> str:
    m = re.match(r"(CWE-\d+)", raw.strip(), re.IGNORECASE)
    return m.group(1).upper() if m else raw.strip()


def _loc(f: LoadedFinding) -> str:
    s = f.file
    if f.line_start:
        s += f":{f.line_start}"
        if f.line_end and f.line_end != f.line_start:
            s += f"-{f.line_end}"
    return s


def _slug(text: str, max_len: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", text.lower())
    return s[:max_len].strip("_")


def _rating_color(rating: str) -> str:
    return {"PRODUCTION_READY": "✓", "NEEDS_TUNING": "~", "DRAFT": "!", "N/A": "-"}.get(
        rating, "?"
    )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class DetectionGenerator:
    """
    Orchestrates the full detection generation pipeline:
    load → strategy → generate → validate → save.
    """

    def __init__(
        self,
        reports_dir:  str | Path,
        target:       str,
        model:        str = DEFAULT_MODEL,
        verbose:      bool = False,
        output_dir:   str | Path | None = None,
        finding_idx:  int | None = None,
    ) -> None:
        self.reports_dir = Path(reports_dir).resolve()
        self.target      = target.strip().lower()
        self.model       = model
        self.verbose     = verbose
        self.output_dir  = (
            Path(output_dir).resolve() if output_dir else self.reports_dir
        )
        self.finding_idx = finding_idx
        self.client      = anthropic.Anthropic()

        if not self.reports_dir.is_dir():
            raise ValueError(f"Reports directory not found: {self.reports_dir}")
        if not self.target:
            raise ValueError("Target name must not be empty.")
        if finding_idx is not None and finding_idx < 1:
            raise ValueError("--finding index must be >= 1.")

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
        Walk reports_dir, load glasswing-scanner reports matching the target,
        return (HIGH/CRITICAL findings, list of matched report paths).
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

            if not isinstance(report, dict):
                continue
            if report.get("scanner") not in _SCANNER_IDS:
                self._vlog(f"skipping {rpt_path.name}: not a scanner report")
                continue
            if not self._matches_target(rpt_path, report):
                self._vlog(f"skipping {rpt_path.name}: no target match")
                continue

            repo_val = (
                report.get("repo")
                or report.get("target_url")
                or report.get("target")
                or ""
            )
            raw = report.get("findings", [])
            self._vlog(f"checking {rpt_path.name} — {len(raw)} finding(s)")

            added = 0
            for f in raw:
                sev = f.get("severity", "").lower()
                if sev not in MIN_SEVERITY:
                    self._vlog(f"  skip [{sev}] {f.get('title','?')}")
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
                    repo=str(repo_val),
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
        """Map CWE to a detection strategy key."""
        return CWE_TO_STRATEGY.get(finding.cwe.upper(), DEFAULT_STRATEGY)

    # ------------------------------------------------------------------
    # Step 3 — Generate rules
    # ------------------------------------------------------------------

    def generate_rules(self, finding: LoadedFinding) -> RuleSet:
        """Ask Claude to produce KQL, Sigma, and YARA rules for this finding."""
        rs       = RuleSet(finding=finding)
        strategy = finding.strategy
        meta     = _STRATEGY_META.get(strategy, _STRATEGY_META["generic_anomaly"])
        label, tables_hint, yara_hint = meta
        hint     = _STRATEGY_HINTS.get(strategy, _STRATEGY_HINTS["generic_anomaly"])
        location = _loc(finding)
        cvss_str = f"{finding.cvss:.1f}" if finding.cvss is not None else "N/A"
        today    = datetime.now(timezone.utc).strftime("%Y/%m/%d")

        snippet_block = ""
        if finding.code_snippet:
            snippet_block = (
                f"\n\nVulnerable code ({location}):\n"
                f"```\n{finding.code_snippet[:1500]}\n```"
            )

        prompt = (
            "You are a senior detection engineer writing SIEM and endpoint "
            "detection rules for a confirmed security vulnerability.\n\n"
            "━━ FINDING ━━\n"
            f"Title     : {finding.title}\n"
            f"CWE       : {finding.cwe}\n"
            f"Severity  : {finding.severity.upper()}  CVSS: {cvss_str}\n"
            f"File      : {location}\n"
            f"Repository: {finding.repo or 'not specified'}\n"
            f"Impact    : {finding.impact}\n"
            f"PoC note  : {finding.poc_idea}"
            f"{snippet_block}\n\n"
            "━━ DETECTION STRATEGY ━━\n"
            f"Strategy  : {label}\n"
            f"Hint tables: {tables_hint}\n"
            f"Guidance  : {hint}\n\n"
            "━━ RULES TO GENERATE ━━\n"
            f"Today's date: {today}\n\n"
            "KQL (Microsoft Sentinel / Defender XDR)\n"
            "  • Query one of the hint tables.\n"
            "  • Start with a comment block: finding title, CWE, MITRE ATT&CK technique.\n"
            "  • Include: time-window filter (last 24h), attack-pattern where/filter,\n"
            "    summarize for threshold logic, extend with entity mapping.\n"
            "  • Be specific enough to be actionable, broad enough to catch variants.\n\n"
            "Sigma (universal SIEM YAML)\n"
            "  • Valid Sigma rule — include all required fields.\n"
            "  • id: generate a UUID v4.\n"
            "  • author: '0xDanielSec / Talon Scanner'\n"
            "  • tags: MITRE ATT&CK technique(s) in attack.t* format.\n"
            "  • level: calibrated to the finding severity.\n\n"
            "YARA (file / memory scanning)\n"
            f"  • YARA applicable for this strategy: {yara_hint}\n"
            "  • If applicable: write a rule with hex patterns and/or ASCII strings\n"
            "    that would match an exploit artefact or payload in a file or memory dump.\n"
            "  • If not applicable: return an empty string and set yara_applicable=false.\n\n"
            "Call `generate_detection_rules` with all fields."
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=6000,
                tools=[_GEN_TOOL],
                tool_choice={"type": "tool", "name": "generate_detection_rules"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] API error generating rules for '{finding.title}': {exc}")
            return rs

        for block in response.content:
            if block.type == "tool_use" and block.name == "generate_detection_rules":
                inp = block.input
                rs.kql             = inp.get("kql", "")
                rs.kql_mitre       = inp.get("kql_mitre", "")
                rs.sigma           = inp.get("sigma", "")
                rs.yara            = inp.get("yara", "")
                rs.yara_applicable = bool(inp.get("yara_applicable", False))
                rs.fp_notes        = inp.get("fp_notes", "")
                rs.generated       = True

        return rs

    # ------------------------------------------------------------------
    # Step 4 — Validate rules
    # ------------------------------------------------------------------

    def validate_rules(self, rs: RuleSet) -> RuleSet:
        """
        Second-pass LLM call: critically review the generated ruleset for
        syntax, FP risk, and deployment readiness.
        Mutates rs in-place and returns it.
        """
        if not rs.generated:
            return rs

        f = rs.finding
        prompt = (
            "You are a senior SIEM engineer reviewing detection rules before "
            "production deployment. Assess each rule strictly.\n\n"
            f"Finding: {f.title}  ({f.cwe}, {f.severity.upper()})\n"
            f"Strategy: {f.strategy}\n\n"
            "━━ KQL ━━\n"
            f"```kql\n{rs.kql}\n```\n"
            f"MITRE: {rs.kql_mitre}\n\n"
            "━━ SIGMA ━━\n"
            f"```yaml\n{rs.sigma}\n```\n\n"
        )
        if rs.yara_applicable and rs.yara:
            prompt += (
                "━━ YARA ━━\n"
                f"```yara\n{rs.yara}\n```\n\n"
            )
        else:
            prompt += "━━ YARA ━━\nNot applicable.\n\n"

        prompt += (
            "Review criteria:\n"
            "• KQL: valid syntax, realistic table/field names, appropriate time window.\n"
            "• Sigma: all required fields present, valid logsource, condition logic.\n"
            "• YARA: compiles without errors, patterns would match real artefacts.\n"
            "• FP risk: LOW = specific enough for direct alerting; "
            "MEDIUM = needs allowlist; HIGH = too broad.\n"
            "• Rating: PRODUCTION_READY / NEEDS_TUNING / DRAFT.\n\n"
            "Call `validate_detection_rules` with your assessment."
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                tools=[_VAL_TOOL],
                tool_choice={"type": "tool", "name": "validate_detection_rules"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] API error validating rules for '{f.title}': {exc}")
            return rs

        for block in response.content:
            if block.type == "tool_use" and block.name == "validate_detection_rules":
                inp = block.input
                rs.kql_valid    = bool(inp.get("kql_valid", False))
                rs.kql_fp_risk  = inp.get("kql_fp_risk", "HIGH")
                rs.kql_rating   = inp.get("kql_rating", "DRAFT")
                rs.sigma_valid  = bool(inp.get("sigma_valid", False))
                rs.sigma_fp_risk = inp.get("sigma_fp_risk", "HIGH")
                rs.sigma_rating = inp.get("sigma_rating", "DRAFT")
                rs.yara_valid   = bool(inp.get("yara_valid", False))
                rs.yara_rating  = inp.get("yara_rating", "N/A")
                rs.val_notes    = inp.get("notes", "")
                rs.validated    = True

        return rs

    # ------------------------------------------------------------------
    # Step 5 — Save outputs
    # ------------------------------------------------------------------

    def save_ruleset(self, out_dir: Path, idx: int, rs: RuleSet) -> dict[str, Path]:
        """Write .kql, .sigma.yml, and optionally .yar files. Return paths dict."""
        out_dir.mkdir(parents=True, exist_ok=True)
        prefix = f"{idx:02d}_{_slug(rs.finding.title)}"
        saved: dict[str, Path] = {}

        kql_p = out_dir / f"{prefix}.kql"
        kql_p.write_text(rs.kql, encoding="utf-8")
        saved["kql"] = kql_p

        sigma_p = out_dir / f"{prefix}.sigma.yml"
        sigma_p.write_text(rs.sigma, encoding="utf-8")
        saved["sigma"] = sigma_p

        if rs.yara_applicable and rs.yara.strip():
            yara_p = out_dir / f"{prefix}.yar"
            yara_p.write_text(rs.yara, encoding="utf-8")
            saved["yara"] = yara_p

        return saved

    def _build_summary_md(
        self,
        rulesets: list[RuleSet],
        target: str,
        ts: str,
    ) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        generated = [rs for rs in rulesets if rs.generated]

        lines: list[str] = [
            f"# Talon Scanner — Detection Rules: {target}",
            "",
            f"**Generated:** {now}  ",
            f"**Model:** {self.model}  ",
            f"**Findings processed:** {len(rulesets)}  ",
            f"**Rule sets generated:** {len(generated)}",
            "",
            "---",
            "",
        ]

        for rs in generated:
            f         = rs.finding
            cvss_str  = f"{f.cvss:.1f}" if f.cvss is not None else "N/A"
            kql_r     = _rating_color(rs.kql_rating)
            sig_r     = _rating_color(rs.sigma_rating)
            yar_r     = _rating_color(rs.yara_rating)

            lines += [
                f"## {f.title}",
                "",
                "| | |",
                "|---|---|",
                f"| **CWE** | {f.cwe} |",
                f"| **Severity** | {f.severity.upper()} |",
                f"| **CVSS** | {cvss_str} |",
                f"| **File** | `{_loc(f)}` |",
                f"| **Strategy** | {f.strategy} |",
                f"| **MITRE** | {rs.kql_mitre} |",
                "",
                "### Rule Readiness",
                "",
                "| Rule | Valid | FP Risk | Rating |",
                "|---|---|---|---|",
                f"| KQL | {'✓' if rs.kql_valid else '✗'} | "
                f"{rs.kql_fp_risk} | {kql_r} {rs.kql_rating} |",
                f"| Sigma | {'✓' if rs.sigma_valid else '✗'} | "
                f"{rs.sigma_fp_risk} | {sig_r} {rs.sigma_rating} |",
                f"| YARA | {'✓' if rs.yara_valid else '–'} | "
                f"{'N/A' if not rs.yara_applicable else '–'} | {yar_r} {rs.yara_rating} |",
                "",
            ]

            if rs.fp_notes:
                lines += [
                    "### False-Positive Notes",
                    "",
                    rs.fp_notes,
                    "",
                ]

            if rs.val_notes:
                lines += [
                    "### Reviewer Notes",
                    "",
                    f"*{rs.val_notes}*",
                    "",
                ]

            lines += ["---", ""]

        return "\n".join(lines)

    def save_summary(
        self,
        out_dir: Path,
        rulesets: list[RuleSet],
        target: str,
        ts: str,
    ) -> Path:
        md   = self._build_summary_md(rulesets, target, ts)
        path = out_dir / "detection_summary.md"
        path.write_text(md, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Terminal summary per finding
    # ------------------------------------------------------------------

    def _print_finding_summary(
        self,
        idx: int,
        total: int,
        rs: RuleSet,
        saved: dict[str, Path],
    ) -> None:
        f = rs.finding
        self._log(f"\n  [{idx:02d}/{total:02d}] {f.title}")
        self._log(f"          CWE      : {f.cwe}  |  {f.severity.upper()}")
        self._log(f"          Strategy : {f.strategy}")
        self._log(f"          MITRE    : {rs.kql_mitre or 'see rule'}")
        kv = f"{'✓' if rs.kql_valid else '✗'} {rs.kql_rating:<18} FP:{rs.kql_fp_risk}"
        sv = f"{'✓' if rs.sigma_valid else '✗'} {rs.sigma_rating:<18} FP:{rs.sigma_fp_risk}"
        yv = f"{'✓' if rs.yara_valid else '–'} {rs.yara_rating}"
        self._log(f"          KQL      : {kv}")
        self._log(f"          Sigma    : {sv}")
        self._log(f"          YARA     : {yv}")
        for fmt, path in saved.items():
            self._log(f"          {fmt.upper():<9}: {path}")

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute the full detection generation pipeline."""
        ts      = datetime.now(timezone.utc).strftime("%Y%m%d")
        out_dir = self.output_dir / f"detections_{self.target}_{ts}"

        # ── 1. Load ──────────────────────────────────────────────────────
        self._log(
            f"[*] Loading HIGH/CRITICAL findings for '{self.target}' "
            f"from {self.reports_dir} …"
        )
        findings, _sources = self.load_findings()
        self._log(f"    {len(findings)} qualifying finding(s) loaded.")

        if not findings:
            self._log("[!] No HIGH or CRITICAL findings found — nothing to detect.")
            return

        # ── 2. Filter by --finding ────────────────────────────────────────
        if self.finding_idx is not None:
            if self.finding_idx > len(findings):
                self._log(
                    f"[!] --finding {self.finding_idx} out of range "
                    f"({len(findings)} finding(s) available)."
                )
                return
            targets: list[tuple[int, LoadedFinding]] = [
                (self.finding_idx, findings[self.finding_idx - 1])
            ]
        else:
            targets = list(enumerate(findings, 1))

        self._log(f"[*] Generating detection rules for {len(targets)} finding(s) …")
        self._log(f"    Output: {out_dir}")

        rulesets: list[RuleSet] = []

        for idx, finding in targets:
            # ── Strategy ─────────────────────────────────────────────────
            finding.strategy = self.select_strategy(finding)
            self._log(
                f"\n[{idx}/{len(findings)}] {finding.title}"
                f"  ({finding.cwe} → {finding.strategy})"
            )

            # ── Generate ──────────────────────────────────────────────────
            self._log("    Generating rules via Claude …")
            rs = self.generate_rules(finding)
            if not rs.generated:
                self._log("    [!] Generation failed — skipping.")
                rulesets.append(rs)
                continue
            self._log(
                f"    Generated: KQL ✓  Sigma ✓  "
                f"YARA {'✓' if rs.yara_applicable else '–'}"
            )

            # ── Validate ──────────────────────────────────────────────────
            self._log("    Validating rules …")
            rs = self.validate_rules(rs)
            if rs.validated:
                self._log(
                    f"    KQL:{rs.kql_rating}  "
                    f"Sigma:{rs.sigma_rating}  "
                    f"YARA:{rs.yara_rating}"
                )

            # ── Save rules ────────────────────────────────────────────────
            saved = self.save_ruleset(out_dir, idx, rs)
            rulesets.append(rs)
            self._print_finding_summary(idx, len(findings), rs, saved)

        # ── Summary doc ───────────────────────────────────────────────────
        summary_p = self.save_summary(out_dir, rulesets, self.target, ts)

        gen_n    = sum(1 for rs in rulesets if rs.generated)
        ready_n  = sum(
            1 for rs in rulesets
            if rs.generated and "PRODUCTION_READY" in (rs.kql_rating, rs.sigma_rating)
        )
        tuning_n = sum(
            1 for rs in rulesets
            if rs.generated and "NEEDS_TUNING" in (rs.kql_rating, rs.sigma_rating)
        )
        yara_n   = sum(1 for rs in rulesets if rs.generated and rs.yara_applicable)

        self._log("")
        self._log(f"[+] Detection generation complete.")
        self._log(f"    Rule sets generated : {gen_n}")
        self._log(f"    PRODUCTION_READY    : {ready_n}")
        self._log(f"    NEEDS_TUNING        : {tuning_n}")
        self._log(f"    YARA rules          : {yara_n}")
        self._log(f"[+] Summary -> {summary_p}")
        self._log(f"[+] Output  -> {out_dir}")


# ---------------------------------------------------------------------------
# Standalone CLI  (main entry via glasswing.py detect)
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glasswing-detect",
        description="Generate KQL, Sigma, and YARA detection rules for confirmed findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/detection_generator.py --reports ./reports --target cilium\n"
            "  python src/detection_generator.py --reports ./reports --target cilium"
            " --finding 1\n"
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
        help="Target name used to filter reports (e.g. 'cilium').",
    )
    parser.add_argument(
        "--finding", "-f",
        type=int,
        default=None,
        metavar="N",
        help="Generate rules for the Nth finding only (1-based; default: all HIGH/CRITICAL).",
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
        help=f"Claude model (default: {DEFAULT_MODEL}).",
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
        gen = DetectionGenerator(
            reports_dir=args.reports,
            target=args.target,
            model=args.model,
            verbose=args.verbose,
            output_dir=args.output_dir,
            finding_idx=args.finding,
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
