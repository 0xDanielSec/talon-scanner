#!/usr/bin/env python
"""
Glasswing CVE Hunter — Dependency vulnerability scanner using OSV.dev + Claude.

Pipeline
--------
1. Auto-detect and parse requirements.txt / package.json / go.mod -> package list.
2. Query OSV.dev batch API (https://api.osv.dev/v1/querybatch) for all packages
   in a single HTTP call (batched at 500 if needed — no auth required).
3. Feed every raw finding to Claude claude-sonnet-4-20250514 for prioritization:
       patch_now | patch_planned | accept_risk | investigate
4. Save a structured JSON report to reports/cve_report.json.

Only stdlib + anthropic are used.

Usage
-----
    python src/cve_hunter.py requirements.txt
    python src/cve_hunter.py package.json --model claude-opus-4-6
    python src/cve_hunter.py go.mod --verbose
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MODEL     = "claude-sonnet-4-20250514"
OSV_BATCH_URL     = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_LIMIT   = 500   # conservative limit per request
OSV_TIMEOUT       = 30    # seconds
REPORT_PATH       = Path(__file__).resolve().parent.parent / "reports" / "cve_report.json"

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class Package:
    name:          str
    version:       str | None   # None -> unresolved / wildcard
    ecosystem:     str          # "PyPI" | "npm" | "Go"
    raw:           str = ""     # original line from manifest, for debugging
    is_dev:        bool = False  # devDependencies / test deps


@dataclass
class Vulnerability:
    vuln_id:     str               # OSV / GHSA / CVE id
    aliases:     list[str]         # e.g. ["CVE-2023-1234"]
    summary:     str
    details:     str
    severity:    str               # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    cvss_score:  float | None      # numeric CVSS v3 base score if extractable
    cvss_vector: str               # raw CVSS vector string
    fixed_in:    list[str]         # versions that fix this vuln
    references:  list[str]         # URLs


@dataclass
class Finding:
    package:     Package
    vuln:        Vulnerability
    # Filled in by Claude
    priority:    str = ""          # patch_now | patch_planned | accept_risk | investigate
    reasoning:   str = ""
    recommended_version: str = ""
    risk_score:  int = 0           # 1-10, Claude's holistic risk assessment


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------


def _strip_version_prefix(ver: str) -> str:
    """Remove semver range operators, leaving only the version string."""
    # Remove npm range operators: ^, ~, >=, <=, >, <, =
    ver = re.sub(r"^[~^><=!]+\s*", "", ver.strip())
    # Handle "1.2.3 - 2.3.4" ranges -> take lower bound
    if " - " in ver:
        ver = ver.split(" - ")[0].strip()
    # Handle "||" -> take first option
    if " || " in ver:
        ver = ver.split(" || ")[0].strip()
        ver = re.sub(r"^[~^><=!]+\s*", "", ver)
    # Handle "x", "*", "latest", empty
    if not ver or ver in {"*", "x", "X", "latest", "next", "canary"}:
        return ""
    # "1.x", "1.2.x" -> strip trailing .x
    ver = re.sub(r"\.[xX*]$", ".0", ver)
    return ver


def parse_requirements_txt(content: str) -> list[Package]:
    """Parse a pip requirements.txt file."""
    packages: list[Package] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip blank lines, comments, options, URLs, VCS refs
        if (not line
                or line.startswith("#")
                or line.startswith("-")
                or line.startswith("http")
                or "@" in line):
            continue
        # Strip inline comments and environment markers
        line = re.split(r"\s*[;#]", line)[0].strip()
        # Handle extras: package[extra]==version
        line = re.sub(r"\[.*?\]", "", line)

        # Extract name and version
        match = re.match(
            r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
            r"\s*([><=!~^]+\s*[^\s,]+)?",                      # optional version spec
            line,
        )
        if not match:
            continue

        name     = match.group(1).strip()
        ver_spec = (match.group(3) or "").strip()

        version: str | None = None
        if ver_spec:
            raw_ver = re.sub(r"^[><=!~^]+\s*", "", ver_spec)
            cleaned = _strip_version_prefix(raw_ver)
            version = cleaned or None

        packages.append(Package(
            name=name,
            version=version,
            ecosystem="PyPI",
            raw=raw_line,
        ))
    return packages


def parse_package_json(content: str) -> list[Package]:
    """Parse npm package.json (dependencies + devDependencies)."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid package.json: {exc}") from exc

    packages: list[Package] = []
    dep_groups = [
        (data.get("dependencies", {}),    False),
        (data.get("devDependencies", {}),  True),
        (data.get("peerDependencies", {}), False),
    ]
    for dep_dict, is_dev in dep_groups:
        for name, ver_range in dep_dict.items():
            if not isinstance(ver_range, str):
                continue
            version = _strip_version_prefix(ver_range) or None
            packages.append(Package(
                name=name,
                version=version,
                ecosystem="npm",
                raw=f"{name}: {ver_range}",
                is_dev=is_dev,
            ))
    return packages


def parse_go_mod(content: str) -> list[Package]:
    """Parse a Go go.mod file."""
    packages: list[Package] = []
    in_require_block = False

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if line.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue

        # Single-line require: require module/path v1.2.3
        single = re.match(r"^require\s+(\S+)\s+(v[\w.\-+]+)", line)
        # Inside require block: module/path v1.2.3 [// indirect]
        block  = re.match(r"^(\S+)\s+(v[\w.\-+]+)", line) if in_require_block else None

        m = single or block
        if not m:
            continue

        module_path = m.group(1)
        raw_ver     = m.group(2).lstrip("v")

        # Skip pseudo-versions (0.0.0-20231001000000-abcdef123456)
        if re.match(r"0\.0\.0-\d{14}-[0-9a-f]{12}", raw_ver):
            continue

        packages.append(Package(
            name=module_path,
            version=raw_ver,
            ecosystem="Go",
            raw=raw_line.strip(),
        ))
    return packages


_PARSERS = {
    "requirements.txt": ("PyPI",  parse_requirements_txt),
    "package.json":     ("npm",   parse_package_json),
    "go.mod":           ("Go",    parse_go_mod),
}


def detect_and_parse(manifest_path: Path) -> tuple[list[Package], str]:
    """
    Auto-detect manifest type from filename and parse it.
    Returns (packages, ecosystem).
    """
    name = manifest_path.name
    if name not in _PARSERS:
        # Try to match by suffix / pattern
        if name.endswith(".txt") or name == "requirements.txt":
            name = "requirements.txt"
        else:
            raise ValueError(
                f"Unsupported manifest file '{name}'. "
                "Supported: requirements.txt, package.json, go.mod"
            )

    ecosystem, parser = _PARSERS[name]
    content = manifest_path.read_text(encoding="utf-8", errors="replace")
    packages = parser(content)
    return packages, ecosystem


# ---------------------------------------------------------------------------
# OSV.dev query
# ---------------------------------------------------------------------------


def _extract_cvss(severity_list: list[dict]) -> tuple[float | None, str]:
    """
    Extract the best available CVSS score and vector from an OSV severity array.
    Prefers CVSS_V3 over CVSS_V2.
    """
    vector = ""
    score: float | None = None

    for entry in severity_list:
        s_type  = entry.get("type", "")
        s_score = entry.get("score", "")

        if s_type in ("CVSS_V3", "CVSS_V31"):
            vector = s_score
            # Vector format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # Parse base score from vector components
            score = _cvss_v3_base_score(s_score)
            break  # prefer V3
        if s_type == "CVSS_V2" and not vector:
            vector = s_score

    return score, vector


def _cvss_v3_base_score(vector: str) -> float | None:
    """
    Approximate CVSS v3 base score from the vector string using the
    official formula — no external lib required.
    Returns None if the vector can't be parsed.
    """
    try:
        parts = dict(
            p.split(":", 1)
            for p in vector.split("/")
            if ":" in p
        )
        # Metric weights per CVSS v3.1 spec
        AV   = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
        AC   = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
        PR_S = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
        PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # scope changed
        S    = parts.get("S", "U")
        PR   = (PR_C if S == "C" else PR_S).get(parts.get("PR", "N"), 0.85)
        UI   = {"N": 0.85, "R": 0.62}.get(parts.get("UI", "N"), 0.85)
        C    = {"H": 0.56, "L": 0.22, "N": 0.00}.get(parts.get("C", "N"), 0.0)
        I_   = {"H": 0.56, "L": 0.22, "N": 0.00}.get(parts.get("I", "N"), 0.0)
        A    = {"H": 0.56, "L": 0.22, "N": 0.00}.get(parts.get("A", "N"), 0.0)

        ISS = 1 - (1 - C) * (1 - I_) * (1 - A)
        if ISS == 0:
            return 0.0

        if S == "U":
            impact = 6.42 * ISS
        else:
            impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15

        exploitability = 8.22 * AV * AC * PR * UI

        if impact <= 0:
            return 0.0

        if S == "U":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal
        import math
        return math.ceil(base * 10) / 10

    except Exception:
        return None


def _severity_label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_fixed_versions(affected: list[dict], ecosystem: str) -> list[str]:
    """Pull 'fixed' versions out of the OSV affected[].ranges array."""
    fixed: list[str] = []
    for aff in affected:
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return fixed


def _parse_vuln(osv_vuln: dict, ecosystem: str) -> Vulnerability:
    """Convert one OSV vulnerability object into a Vulnerability dataclass."""
    vuln_id  = osv_vuln.get("id", "UNKNOWN")
    aliases  = osv_vuln.get("aliases", [])
    summary  = osv_vuln.get("summary", "")
    details  = (osv_vuln.get("details", "") or "")[:500]  # cap for prompt brevity

    cvss_score, cvss_vector = _extract_cvss(osv_vuln.get("severity", []))
    severity = _severity_label(cvss_score)

    fixed_in = _extract_fixed_versions(osv_vuln.get("affected", []), ecosystem)
    refs     = [r.get("url", "") for r in osv_vuln.get("references", []) if r.get("url")][:5]

    return Vulnerability(
        vuln_id=vuln_id,
        aliases=aliases,
        summary=summary,
        details=details,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        fixed_in=sorted(set(fixed_in)),
        references=refs,
    )


def query_osv_batch(packages: list[Package]) -> list[Finding]:
    """
    Query OSV.dev batch API for all packages.
    Batches automatically at OSV_BATCH_LIMIT queries per request.
    Returns a flat list of Finding objects (one per package×vulnerability).
    """
    # Build index: position -> Package (only packages with a version)
    queryable  = [p for p in packages if p.version]
    no_version = [p for p in packages if not p.version]

    if not queryable:
        return []

    findings: list[Finding] = []

    for batch_start in range(0, len(queryable), OSV_BATCH_LIMIT):
        batch = queryable[batch_start: batch_start + OSV_BATCH_LIMIT]

        payload = {
            "queries": [
                {
                    "version": pkg.version,
                    "package": {
                        "name":      pkg.name,
                        "ecosystem": pkg.ecosystem,
                    },
                }
                for pkg in batch
            ]
        }

        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            OSV_BATCH_URL,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"OSV API HTTP error {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OSV API network error: {exc.reason}") from exc

        results = data.get("results", [])
        for pkg, result in zip(batch, results):
            for raw_vuln in result.get("vulns", []):
                vuln = _parse_vuln(raw_vuln, pkg.ecosystem)
                findings.append(Finding(package=pkg, vuln=vuln))

    return findings, no_version


# ---------------------------------------------------------------------------
# Claude prioritization tool
# ---------------------------------------------------------------------------

_PRIORITIZE_TOOL: dict[str, Any] = {
    "name": "prioritize_findings",
    "description": (
        "Analyze a set of CVE findings across project dependencies and output a "
        "prioritized action plan for each finding. Consider: CVSS score, exploitability, "
        "availability of a fix, whether this is a transitive/dev dependency, and "
        "real-world exploit prevalence."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "priorities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "package": {
                            "type": "string",
                            "description": "Package name",
                        },
                        "vuln_id": {
                            "type": "string",
                            "description": "OSV/CVE/GHSA identifier",
                        },
                        "priority": {
                            "type": "string",
                            "enum": ["patch_now", "patch_planned", "accept_risk", "investigate"],
                            "description": (
                                "patch_now: Critical/High, fix immediately. "
                                "patch_planned: Medium/High, schedule fix. "
                                "accept_risk: Low severity or mitigated, document and accept. "
                                "investigate: Unclear impact, needs manual triage."
                            ),
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "1-2 sentence justification for the priority.",
                        },
                        "recommended_version": {
                            "type": "string",
                            "description": "Minimum safe version to upgrade to; empty if unknown.",
                        },
                        "risk_score": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10,
                            "description": "Holistic risk score (1=negligible, 10=catastrophic).",
                        },
                    },
                    "required": ["package", "vuln_id", "priority", "reasoning", "risk_score"],
                },
            },
            "executive_summary": {
                "type": "string",
                "description": (
                    "2-4 sentence overall assessment of the dependency security posture."
                ),
            },
        },
        "required": ["priorities", "executive_summary"],
    },
}


def analyze_with_claude(
    findings: list[Finding],
    packages: list[Package],
    ecosystem: str,
    model: str,
) -> tuple[list[Finding], str]:
    """
    Ask Claude to prioritize all findings at once.
    Mutates each Finding in-place with priority/reasoning/recommended_version/risk_score.
    Returns (updated_findings, executive_summary).
    """
    client = anthropic.Anthropic()

    if not findings:
        prompt = (
            f"I scanned {len(packages)} {ecosystem} dependencies against the OSV.dev "
            "vulnerability database and found zero known CVEs. "
            "Call `prioritize_findings` with an empty priorities array and write a "
            "brief executive summary."
        )
    else:
        rows: list[str] = []
        for i, f in enumerate(findings, 1):
            cve_ids = ", ".join(f.vuln.aliases) or "none"
            rows.append(
                f"{i}. {f.package.name}@{f.package.version or '?'}  "
                f"[{f.vuln.vuln_id} / {cve_ids}]  "
                f"severity={f.vuln.severity}  "
                f"cvss={f.vuln.cvss_score or '?'}  "
                f"fixed_in={f.vuln.fixed_in or ['no fix yet']}  "
                f"dev={f.package.is_dev}  "
                f"summary={f.vuln.summary!r}"
            )

        prompt = (
            f"I scanned {len(packages)} {ecosystem} package(s) with OSV.dev and found "
            f"{len(findings)} CVE finding(s). Prioritize every finding below using "
            "`prioritize_findings`. Apply these tiers:\n"
            "  * patch_now       -> CVSS ≥7 OR active exploitation OR RCE/auth bypass\n"
            "  * patch_planned   -> CVSS 4-6.9, exploitable but not immediate-risk\n"
            "  * accept_risk     -> CVSS <4, dev-only, or no realistic exploit path\n"
            "  * investigate     -> ambiguous impact, missing CVSS, or unusual context\n\n"
            "Findings:\n" + "\n".join(rows)
        )

    response = client.messages.create(
        model=model,
        max_tokens=8192,
        tools=[_PRIORITIZE_TOOL],
        tool_choice={"type": "tool", "name": "prioritize_findings"},
        messages=[{"role": "user", "content": prompt}],
    )

    # Build lookup: (package_name, vuln_id) -> Finding
    index: dict[tuple[str, str], Finding] = {
        (f.package.name, f.vuln.vuln_id): f for f in findings
    }

    executive_summary = ""
    for block in response.content:
        if block.type == "tool_use" and block.name == "prioritize_findings":
            executive_summary = block.input.get("executive_summary", "")
            for entry in block.input.get("priorities", []):
                key = (entry.get("package", ""), entry.get("vuln_id", ""))
                target = index.get(key)
                if target is None:
                    # Fuzzy match: find by vuln_id alone (package name may differ slightly)
                    for f in findings:
                        if f.vuln.vuln_id == entry.get("vuln_id"):
                            target = f
                            break
                if target:
                    target.priority            = entry.get("priority", "investigate")
                    target.reasoning           = entry.get("reasoning", "")
                    target.recommended_version = entry.get("recommended_version", "")
                    target.risk_score          = int(entry.get("risk_score", 0))

    # Fill defaults for any findings Claude didn't cover
    for f in findings:
        if not f.priority:
            f.priority  = "investigate"
            f.reasoning = "Not evaluated by Claude."

    return findings, executive_summary


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_PRIORITY_ORDER = {
    "patch_now": 0,
    "patch_planned": 1,
    "investigate": 2,
    "accept_risk": 3,
}


def build_report(
    manifest_path: Path,
    packages: list[Package],
    findings: list[Finding],
    no_version: list[Package],
    executive_summary: str,
    model: str,
) -> dict[str, Any]:
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _PRIORITY_ORDER.get(f.priority, 99),
            -(f.vuln.cvss_score or 0),
        ),
    )

    priority_counts = {k: 0 for k in _PRIORITY_ORDER}
    for f in findings:
        priority_counts[f.priority] = priority_counts.get(f.priority, 0) + 1

    return {
        "scanner":            "glasswing-cve-hunter",
        "version":            "1.0.0",
        "model":              model,
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "manifest":           str(manifest_path),
        "ecosystem":          packages[0].ecosystem if packages else "unknown",
        "packages_scanned":   len(packages),
        "packages_skipped":   len(no_version),  # no pinned version
        "vulnerabilities_found": len(findings),
        "executive_summary":  executive_summary,
        "summary": {
            "by_priority": priority_counts,
            "by_severity": {
                sev: sum(1 for f in findings if f.vuln.severity == sev)
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            },
        },
        "findings": [
            {
                "package":             f.package.name,
                "version":             f.package.version,
                "is_dev_dependency":   f.package.is_dev,
                "vuln_id":             f.vuln.vuln_id,
                "aliases":             f.vuln.aliases,
                "summary":             f.vuln.summary,
                "details":             f.vuln.details,
                "severity":            f.vuln.severity,
                "cvss_score":          f.vuln.cvss_score,
                "cvss_vector":         f.vuln.cvss_vector,
                "fixed_in":            f.vuln.fixed_in,
                "references":          f.vuln.references,
                "priority":            f.priority,
                "reasoning":           f.reasoning,
                "recommended_version": f.recommended_version,
                "risk_score":          f.risk_score,
            }
            for f in sorted_findings
        ],
        "skipped_packages": [
            {"name": p.name, "reason": "no pinned version", "raw": p.raw}
            for p in no_version
        ],
    }


def save_report(report: dict[str, Any], out_path: Path = REPORT_PATH) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


class CVEHunter:
    def __init__(
        self,
        manifest_path: str | Path,
        model: str = DEFAULT_MODEL,
        verbose: bool = False,
        output_path: Path = REPORT_PATH,
    ) -> None:
        self.manifest_path = Path(manifest_path).resolve()
        self.model         = model
        self.verbose       = verbose
        self.output_path   = output_path

        if not self.manifest_path.is_file():
            raise ValueError(f"Manifest not found: {self.manifest_path}")

    def _log(self, msg: str) -> None:
        print(msg, flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}", flush=True)

    def run(self) -> dict[str, Any]:
        # ── 1. Parse manifest ──────────────────────────────────────────
        self._log(f"[*] Parsing {self.manifest_path.name} …")
        packages, ecosystem = detect_and_parse(self.manifest_path)
        pinned    = [p for p in packages if p.version]
        unpinned  = [p for p in packages if not p.version]
        self._log(
            f"    {len(packages)} package(s) found — "
            f"{len(pinned)} pinned, {len(unpinned)} without version."
        )
        if self.verbose:
            for p in packages[:10]:
                self._vlog(f"{p.name}@{p.version or '?'}  [{p.ecosystem}]")
            if len(packages) > 10:
                self._vlog(f"… and {len(packages) - 10} more")

        # ── 2. OSV batch query ─────────────────────────────────────────
        self._log(f"[*] Querying OSV.dev for {len(pinned)} pinned package(s) …")
        try:
            findings, no_version = query_osv_batch(packages)
        except RuntimeError as exc:
            self._log(f"[!] OSV query failed: {exc}")
            raise

        self._log(f"    {len(findings)} vulnerability finding(s) returned.")
        if findings and self.verbose:
            for f in findings:
                self._vlog(
                    f"{f.package.name}@{f.package.version}  "
                    f"{f.vuln.vuln_id}  {f.vuln.severity}  "
                    f"cvss={f.vuln.cvss_score}"
                )

        # ── 3. Claude analysis ─────────────────────────────────────────
        self._log(f"[*] Asking Claude to prioritize findings …")
        findings, executive_summary = analyze_with_claude(
            findings, packages, ecosystem, self.model
        )

        # Print prioritized summary
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.priority] = counts.get(f.priority, 0) + 1
        for tier in ("patch_now", "patch_planned", "investigate", "accept_risk"):
            n = counts.get(tier, 0)
            if n:
                self._log(f"    [{tier}] {n} finding(s)")

        # ── 4. Save report ─────────────────────────────────────────────
        report = build_report(
            manifest_path=self.manifest_path,
            packages=packages,
            findings=findings,
            no_version=no_version,
            executive_summary=executive_summary,
            model=self.model,
        )
        out_path = save_report(report, self.output_path)
        self._log(f"\n[+] Report saved -> {out_path}")
        if executive_summary:
            self._log(f"\n    {executive_summary}")

        return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glasswing-cve-hunter",
        description="Scan dependency manifests for known CVEs via OSV.dev + Claude.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/cve_hunter.py requirements.txt\n"
            "  python src/cve_hunter.py package.json --verbose\n"
            "  python src/cve_hunter.py go.mod --model claude-opus-4-6\n"
            "  python src/cve_hunter.py requirements.txt --output reports/my_report.json\n"
        ),
    )
    parser.add_argument(
        "manifest",
        help="Path to requirements.txt, package.json, or go.mod.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Claude model to use (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--output",
        default=str(REPORT_PATH),
        help=f"Output JSON path (default: {REPORT_PATH}).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    import os
    parser = _build_arg_parser()
    args   = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 1

    try:
        hunter = CVEHunter(
            manifest_path=args.manifest,
            model=args.model,
            verbose=args.verbose,
            output_path=Path(args.output),
        )
        hunter.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
