#!/usr/bin/env python
"""
Glasswing Scanner – Agentic vulnerability scanner using the Anthropic Python SDK.

Pipeline
--------
1. Collect all scannable source files from the target repository.
2. Rank every file by attack-surface likelihood (score 1-5) via Claude.
3. Deep-analyse the top-N highest-scored files for security vulnerabilities.
4. Validate each raw finding with a second LLM call to filter false positives.
5. Emit a timestamped JSON report to reports/ with a SHA3-256 disclosure hash
   per finding.

Usage
-----
    python src/scanner.py /path/to/repo [--top-n 10] [--model <model-id>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_TOP_N = 10
DEFAULT_MIN_CONFIDENCE = 0.55   # below this the validation rejects a finding

# ---------------------------------------------------------------------------
# File-collection constants
# ---------------------------------------------------------------------------

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    # Web / scripting
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    # Systems
    ".c", ".cpp", ".h", ".hpp", ".cc", ".cxx",
    ".rs", ".go", ".zig",
    # JVM / CLR
    ".java", ".kt", ".cs", ".scala", ".groovy",
    # Ruby / PHP / other interpreted
    ".rb", ".php", ".swift", ".m",
    # Shell
    ".sh", ".bash", ".zsh", ".fish", ".ps1",
    # Config / IaC (often contain secrets or misconfigs)
    ".yaml", ".yml", ".json", ".toml", ".xml",
    ".tf", ".hcl", ".bicep",
    # Database
    ".sql",
})

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "dist", "build", "target", "out",
    ".tox", "htmlcov", ".mypy_cache", ".eggs",
    ".idea", ".vscode",
})

MAX_FILE_BYTES   = 150_000   # skip files larger than this
MAX_SNIPPET_CHARS = 12_000   # chars forwarded to the analysis prompt per file
RANK_BATCH_SIZE  = 80        # files per ranking API call (keeps prompts manageable)
PREVIEW_CHARS    = 500       # per-file preview sent during ranking

# ---------------------------------------------------------------------------
# Tool schemas (used as structured-output contracts with Claude)
# ---------------------------------------------------------------------------

_RANK_TOOL: dict[str, Any] = {
    "name": "rank_files",
    "description": (
        "Return an attack-surface score (1-5) for every file in the provided list. "
        "5 = almost certainly contains exploitable security-sensitive code; "
        "1 = very unlikely to contain exploitable issues."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "rankings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path":   {"type": "string"},
                        "score":  {"type": "integer", "minimum": 1, "maximum": 5},
                        "reason": {"type": "string"},
                    },
                    "required": ["path", "score", "reason"],
                },
            }
        },
        "required": ["rankings"],
    },
}

_VULN_TOOL: dict[str, Any] = {
    "name": "report_vulnerability",
    "description": (
        "Report one concrete security vulnerability found in the source file. "
        "Call this once per distinct finding; do NOT call it if there are no real issues."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short, descriptive title of the vulnerability.",
            },
            "type": {
                "type": "string",
                "description": "Vulnerability class, e.g. 'SQL Injection', 'Path Traversal'.",
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "cwe": {
                "type": "string",
                "description": "Primary CWE identifier, e.g. 'CWE-89'.",
            },
            "cvss_estimate": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 10.0,
                "description": "CVSS v3 base score estimate.",
            },
            "impact": {
                "type": "string",
                "description": "What an attacker could achieve by exploiting this.",
            },
            "poc_idea": {
                "type": "string",
                "description": "High-level proof-of-concept approach (no working exploit needed).",
            },
            "line_start":   {"type": "integer"},
            "line_end":     {"type": "integer"},
            "code_snippet": {
                "type": "string",
                "description": "The vulnerable lines of code (verbatim).",
            },
        },
        "required": [
            "title", "type", "severity", "cwe",
            "cvss_estimate", "impact", "poc_idea",
        ],
    },
}

_VALIDATE_TOOL: dict[str, Any] = {
    "name": "validate_finding",
    "description": (
        "Decide whether a reported vulnerability is a genuine security issue "
        "or a false positive, given the actual source code context."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "is_valid": {
                "type": "boolean",
                "description": "True if this is a real vulnerability, False if false positive.",
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "How confident you are in the is_valid verdict (0-1).",
            },
            "reasoning": {
                "type": "string",
                "description": "Concise explanation of the verdict.",
            },
            "revised_severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "Adjusted severity after re-review; omit if unchanged.",
            },
        },
        "required": ["is_valid", "confidence", "reasoning"],
    },
}

# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class GlasswingScanner:
    """
    Orchestrates the full agentic scanning pipeline:
    collect -> rank -> analyse -> validate -> report.
    """

    def __init__(
        self,
        repo_path: str | Path,
        top_n: int = DEFAULT_TOP_N,
        model: str = DEFAULT_MODEL,
        min_validation_confidence: float = DEFAULT_MIN_CONFIDENCE,
        verbose: bool = False,
        extensions: frozenset[str] | None = None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.top_n = top_n
        self.model = model
        self.min_confidence = min_validation_confidence
        self.verbose = verbose
        self.client = anthropic.Anthropic()
        # Allow callers to narrow the extension set (e.g. for --lang filtering)
        self._extensions = extensions if extensions is not None else SCANNABLE_EXTENSIONS

        if not self.repo_path.is_dir():
            raise ValueError(f"repo_path is not a directory: {self.repo_path}")

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        print(msg, flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}", flush=True)

    # ------------------------------------------------------------------
    # Step 1 – File collection
    # ------------------------------------------------------------------

    def collect_files(self) -> list[dict[str, Any]]:
        """
        Recursively walk repo_path and return metadata dicts for all
        scannable, size-within-limit files.
        """
        files: list[dict[str, Any]] = []
        for root, dirs, filenames in os.walk(self.repo_path):
            # Prune in-place so os.walk never descends into irrelevant dirs
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]
            for name in filenames:
                full_path = Path(root) / name
                if full_path.suffix.lower() not in self._extensions:
                    continue
                try:
                    size = full_path.stat().st_size
                except OSError:
                    continue
                if size > MAX_FILE_BYTES:
                    self._vlog(f"skipping oversized file: {full_path.name} ({size} B)")
                    continue
                files.append({
                    "path":     full_path,
                    "rel_path": str(full_path.relative_to(self.repo_path)),
                    "size":     size,
                })
        return files

    def _read_file(self, path: Path) -> str:
        """Read a text file, returning an empty string on any error."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._vlog(f"cannot read {path}: {exc}")
            return ""

    # ------------------------------------------------------------------
    # Step 2 – Ranking
    # ------------------------------------------------------------------

    def rank_files(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Score every file 1-5 for attack-surface likelihood using Claude.
        Returns the full file list sorted descending by score.
        """
        scores:  dict[str, int] = {}
        reasons: dict[str, str] = {}

        total_batches = (len(files) + RANK_BATCH_SIZE - 1) // RANK_BATCH_SIZE
        for batch_idx in range(total_batches):
            batch = files[batch_idx * RANK_BATCH_SIZE: (batch_idx + 1) * RANK_BATCH_SIZE]
            self._vlog(
                f"ranking batch {batch_idx + 1}/{total_batches} "
                f"({len(batch)} files) …"
            )
            self._rank_batch(batch, scores, reasons)

        ranked: list[dict[str, Any]] = []
        for f in files:
            rp = f["rel_path"]
            ranked.append({
                **f,
                "score":  scores.get(rp, 1),
                "reason": reasons.get(rp, "not ranked"),
            })

        ranked.sort(key=lambda x: x["score"], reverse=True)
        return ranked

    def _rank_batch(
        self,
        batch: list[dict[str, Any]],
        scores:  dict[str, int],
        reasons: dict[str, str],
    ) -> None:
        """Send one batch to Claude and merge results into the shared dicts."""
        entries: list[str] = []
        for f in batch:
            content = self._read_file(f["path"])
            preview = content[:PREVIEW_CHARS].replace("\n", " ").strip()
            entries.append(
                f"* {f['rel_path']}  [{f['size']} B]  preview: {preview!r}"
            )

        prompt = (
            "You are a senior application-security engineer performing a triage of a repository.\n"
            "For each file listed below, assign an attack-surface score:\n"
            "  5 – highly likely to contain exploitable vulnerabilities (auth, SQL, shell exec, "
            "      deser, network I/O, crypto, file ops, secrets)\n"
            "  4 – probable security-sensitive code worth deep review\n"
            "  3 – moderate sensitivity\n"
            "  2 – unlikely but possible\n"
            "  1 – minimal attack surface (tests, docs, build scripts, etc.)\n\n"
            "Files to rank:\n"
            + "\n".join(entries)
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                tools=[_RANK_TOOL],
                tool_choice={"type": "tool", "name": "rank_files"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] Ranking API error: {exc}")
            return

        for block in response.content:
            if block.type == "tool_use" and block.name == "rank_files":
                for entry in block.input.get("rankings", []):
                    path = entry.get("path", "")
                    scores[path]  = max(1, min(5, int(entry.get("score", 1))))
                    reasons[path] = entry.get("reason", "")

    # ------------------------------------------------------------------
    # Step 3 – Vulnerability analysis
    # ------------------------------------------------------------------

    def analyze_file(self, file_info: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Ask Claude to audit a single file for security vulnerabilities.
        Returns a list of raw finding dicts (unvalidated).
        """
        content = self._read_file(file_info["path"])
        if not content.strip():
            return []

        snippet = content[:MAX_SNIPPET_CHARS]
        if len(content) > MAX_SNIPPET_CHARS:
            snippet += (
                f"\n\n… [{len(content) - MAX_SNIPPET_CHARS:,} additional chars truncated]"
            )

        prompt = (
            "You are an expert security researcher conducting a white-box code review.\n\n"
            f"**File:** `{file_info['rel_path']}`  "
            f"(attack-surface score: {file_info['score']}/5 — {file_info['reason']})\n\n"
            "Carefully audit the code for security vulnerabilities, including but not limited to:\n"
            "- Injection flaws: SQL, OS command, LDAP, XPath, Server-Side Template\n"
            "- Buffer / heap overflows and memory-safety issues\n"
            "- Insecure deserialisation (pickle, yaml.load, eval, exec)\n"
            "- Authentication and authorisation bypasses\n"
            "- Path / directory traversal\n"
            "- Sensitive data exposure and hard-coded secrets/credentials\n"
            "- Cryptographic weaknesses (weak algos, broken RNG, key misuse)\n"
            "- Race conditions and TOCTOU issues\n"
            "- Logic bugs with a concrete security impact\n\n"
            "Call `report_vulnerability` **once per distinct finding**. "
            "Do NOT call it for theoretical or out-of-scope issues. "
            "If no real vulnerabilities exist, respond with plain text only.\n\n"
            f"```\n{snippet}\n```"
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=8192,
                tools=[_VULN_TOOL],
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] Analysis API error for {file_info['rel_path']}: {exc}")
            return []

        findings: list[dict[str, Any]] = []
        for block in response.content:
            if block.type == "tool_use" and block.name == "report_vulnerability":
                finding = dict(block.input)
                finding["file"] = file_info["rel_path"]
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Step 4 – Validation
    # ------------------------------------------------------------------

    def validate_finding(
        self,
        finding: dict[str, Any],
        file_info: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Second-pass LLM call: confirm the finding is a genuine vulnerability
        and optionally revise its severity.

        Returns the (possibly severity-adjusted) finding dict, or None if the
        finding is rejected as a false positive or inconclusive.
        """
        content = self._read_file(file_info["path"])
        snippet = content[:MAX_SNIPPET_CHARS]

        finding_summary = json.dumps(
            {k: v for k, v in finding.items() if k != "file"},
            indent=2,
        )

        prompt = (
            "You are a senior security engineer providing a second opinion on a reported finding.\n"
            "Critically assess whether the vulnerability described below is a genuine, "
            "exploitable security issue given the actual source code, or whether it is a "
            "false positive, theoretical concern, or already mitigated.\n\n"
            f"### Reported Finding\n```json\n{finding_summary}\n```\n\n"
            f"### Source Code  (`{finding['file']}`)\n```\n{snippet}\n```\n\n"
            "Call `validate_finding` with your verdict."
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                tools=[_VALIDATE_TOOL],
                tool_choice={"type": "tool", "name": "validate_finding"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] Validation API error: {exc}")
            return None

        for block in response.content:
            if block.type == "tool_use" and block.name == "validate_finding":
                v = block.input

                if not v.get("is_valid", False):
                    self._vlog(
                        f"rejected '{finding.get('title')}' — "
                        f"{v.get('reasoning', 'no reason given')}"
                    )
                    return None

                confidence = float(v.get("confidence", 0.0))
                if confidence < self.min_confidence:
                    self._vlog(
                        f"low-confidence ({confidence:.2f}) rejection: "
                        f"'{finding.get('title')}'"
                    )
                    return None

                # Merge validation metadata back into the finding
                validated = dict(finding)
                if v.get("revised_severity"):
                    validated["severity"] = v["revised_severity"]
                validated["_validation"] = {
                    "confidence": confidence,
                    "reasoning":  v.get("reasoning", ""),
                }
                return validated

        # No tool_use block returned -> inconclusive; discard
        return None

    # ------------------------------------------------------------------
    # Step 5 – Report assembly
    # ------------------------------------------------------------------

    @staticmethod
    def _disclosure_hash(finding: dict[str, Any]) -> str:
        """
        Deterministic SHA3-256 hash of key finding fields for
        responsible-disclosure tracking and deduplication.
        """
        fields = "|".join([
            finding.get("title", ""),
            finding.get("file", ""),
            finding.get("cwe", ""),
            finding.get("code_snippet", ""),
            finding.get("poc_idea", ""),
        ])
        return hashlib.sha3_256(fields.encode("utf-8")).hexdigest()

    def _build_report_entry(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Normalize a validated finding into the canonical report schema."""
        return {
            "title":           finding.get("title", ""),
            "type":            finding.get("type", ""),
            "severity":        finding.get("severity", ""),
            "cwe":             finding.get("cwe", ""),
            "cvss_estimate":   finding.get("cvss_estimate"),
            "impact":          finding.get("impact", ""),
            "poc_idea":        finding.get("poc_idea", ""),
            "file":            finding.get("file", ""),
            "line_start":      finding.get("line_start"),
            "line_end":        finding.get("line_end"),
            "code_snippet":    finding.get("code_snippet", ""),
            "validation": {
                "confidence": finding.get("_validation", {}).get("confidence"),
                "reasoning":  finding.get("_validation", {}).get("reasoning", ""),
            },
            "disclosure_hash": self._disclosure_hash(finding),
        }

    def _severity_order(self, entry: dict[str, Any]) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            entry.get("severity", "info"), 99
        )

    def _build_report(
        self,
        ranked: list[dict[str, Any]],
        confirmed: list[dict[str, Any]],
    ) -> dict[str, Any]:
        confirmed_sorted = sorted(confirmed, key=self._severity_order)
        severity_counts = {
            sev: sum(1 for f in confirmed_sorted if f.get("severity") == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        }
        return {
            "scanner":   "glasswing-scanner",
            "version":   "1.0.0",
            "model":     self.model,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo":      str(self.repo_path),
            "summary": {
                "files_collected":    len(ranked),
                "files_deep_scanned": min(self.top_n, len(ranked)),
                "total_findings":     len(confirmed_sorted),
                "by_severity":        severity_counts,
            },
            "file_rankings": [
                {
                    "path":   f["rel_path"],
                    "score":  f["score"],
                    "reason": f["reason"],
                }
                for f in ranked
            ],
            "findings": confirmed_sorted,
        }

    def save_report(self, report: dict[str, Any]) -> Path:
        """Write the report JSON to reports/<timestamp>.json."""
        reports_dir = Path(__file__).resolve().parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = reports_dir / f"glasswing_{ts}.json"
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_path

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """
        Execute the full pipeline and return the completed report dict.
        Also saves the report to disk automatically.
        """
        # ── 1. Collect ──────────────────────────────────────────────────
        self._log(f"[*] Collecting files from {self.repo_path} …")
        all_files = self.collect_files()
        self._log(f"    {len(all_files)} scannable file(s) found.")

        if not all_files:
            self._log("[!] No scannable files found. Exiting.")
            report = self._build_report([], [])
            path = self.save_report(report)
            self._log(f"[+] Empty report saved -> {path}")
            return report

        # ── 2. Rank ──────────────────────────────────────────────────────
        self._log(f"[*] Ranking {len(all_files)} file(s) by attack-surface likelihood …")
        ranked = self.rank_files(all_files)

        top_files = ranked[: self.top_n]
        self._log(
            f"    Top {len(top_files)} file(s) selected for deep analysis "
            f"(scores: {[f['score'] for f in top_files]})."
        )

        # ── 3. Analyse ───────────────────────────────────────────────────
        raw_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for idx, finfo in enumerate(top_files, 1):
            self._log(
                f"[*] Analysing [{idx}/{len(top_files)}] "
                f"{finfo['rel_path']}  (score={finfo['score']}) …"
            )
            findings = self.analyze_file(finfo)
            self._log(f"    {len(findings)} potential finding(s) identified.")
            for f in findings:
                raw_pairs.append((f, finfo))

        # ── 4. Validate ──────────────────────────────────────────────────
        self._log(f"[*] Validating {len(raw_pairs)} raw finding(s) …")
        confirmed: list[dict[str, Any]] = []
        for raw_finding, finfo in raw_pairs:
            title = raw_finding.get("title", "?")
            result = self.validate_finding(raw_finding, finfo)
            if result is not None:
                entry = self._build_report_entry(result)
                confirmed.append(entry)
                self._log(
                    f"    [+] CONFIRMED  {entry['severity'].upper():8s}  "
                    f"{title}  [{entry['cwe']}]  {entry['disclosure_hash'][:12]}…"
                )
            else:
                self._log(f"    [-] dismissed  {title}")

        # ── 5. Report ────────────────────────────────────────────────────
        report   = self._build_report(ranked, confirmed)
        out_path = self.save_report(report)

        self._log("")
        self._log(f"[+] Scan complete. {len(confirmed)} confirmed finding(s).")
        summary = report["summary"]["by_severity"]
        self._log(
            f"    critical={summary['critical']}  high={summary['high']}  "
            f"medium={summary['medium']}  low={summary['low']}  info={summary['info']}"
        )
        self._log(f"[+] Report saved -> {out_path}")

        return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glasswing-scanner",
        description="Agentic security vulnerability scanner powered by Claude.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/scanner.py .\n"
            "  python src/scanner.py /path/to/repo --top-n 15 --verbose\n"
            "  python src/scanner.py /path/to/repo --model claude-opus-4-6 --top-n 5\n"
        ),
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to the repository to scan (default: current directory).",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_TOP_N,
        metavar="N",
        help=f"Number of highest-scored files to deep-analyse (default: {DEFAULT_TOP_N}).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Anthropic model to use (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        metavar="FLOAT",
        help=(
            f"Minimum validation confidence [0-1] to accept a finding "
            f"(default: {DEFAULT_MIN_CONFIDENCE})."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress information.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "Error: ANTHROPIC_API_KEY environment variable is not set.",
            file=sys.stderr,
        )
        return 1

    try:
        scanner = GlasswingScanner(
            repo_path=args.repo,
            top_n=args.top_n,
            model=args.model,
            min_validation_confidence=args.min_confidence,
            verbose=args.verbose,
        )
        scanner.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
