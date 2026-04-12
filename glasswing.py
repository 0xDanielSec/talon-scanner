#!/usr/bin/env python
"""
Glasswing Scanner — Main CLI entry point.

Subcommands
-----------
  scan    Rank and analyse source files for security vulnerabilities.
  cve     Query OSV.dev for known CVEs across project dependencies.
  report  Print a formatted summary of a saved report JSON.

Environment
-----------
  ANTHROPIC_API_KEY is loaded automatically from a .env file in the
  current directory (falls back to the real environment variable).

Examples
--------
  python glasswing.py scan --target ./repo --lang python --top 20
  python glasswing.py cve  --requirements requirements.txt
  python glasswing.py report --input reports/glasswing_20240115T103000Z.json
  python glasswing.py report --input reports/cve_report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

# Force UTF-8 output on Windows (cp1252 cannot encode many Unicode characters)
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ---------------------------------------------------------------------------
# .env loader  (stdlib only — no python-dotenv)
# ---------------------------------------------------------------------------

def _load_dotenv(env_file: str = ".env") -> None:
    """
    Parse KEY=VALUE lines from *env_file* and inject them into os.environ.
    Existing environment variables are NOT overwritten.
    Supports:
      - Blank lines and # comments
      - Optional 'export ' prefix
      - Values quoted with ' or " (outer quotes are stripped)
      - Inline comments after an unquoted value
    """
    path = Path(env_file)
    if not path.is_file():
        return

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Strip optional 'export ' prefix
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip()

        # Strip matching outer quotes
        if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
            value = value[1:-1]
        else:
            # Strip inline comment (only for unquoted values)
            value = value.split(" #")[0].strip()

        if key and key not in os.environ:
            os.environ[key] = value


# ---------------------------------------------------------------------------
# ANSI colour helpers  (disabled when stdout is not a tty)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty() and os.name != "nt" or (
    os.name == "nt" and os.environ.get("TERM") not in (None, "")
)

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_WHITE  = "\033[97m"
_ORANGE = "\033[38;5;208m"


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOR:
        return text
    return "".join(codes) + text + _RESET


_SEVERITY_COLOR: dict[str, str] = {
    "critical": _RED + _BOLD,
    "high":     _RED,
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "medium":   _YELLOW,
    "MEDIUM":   _YELLOW,
    "low":      _CYAN,
    "LOW":      _CYAN,
    "info":     _DIM,
    "INFO":     _DIM,
    "UNKNOWN":  _DIM,
}

_PRIORITY_COLOR: dict[str, str] = {
    "patch_now":     _RED + _BOLD,
    "patch_planned": _YELLOW,
    "investigate":   _CYAN,
    "accept_risk":   _GREEN,
}

_SEVERITY_ORDER  = ["critical", "high", "medium", "low", "info",
                    "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO"]
_PRIORITY_ORDER  = ["patch_now", "patch_planned", "investigate", "accept_risk"]

# Bar-chart settings
_BAR_WIDTH = 28
_BAR_CHAR  = "█"


def _bar(count: int, total: int) -> str:
    if total == 0 or count == 0:
        return ""
    filled = max(1, round((count / total) * _BAR_WIDTH))
    return _BAR_CHAR * filled


def _hr(width: int = 72) -> str:
    return "─" * width


def _header(title: str, width: int = 72) -> str:
    pad = max(0, width - len(title) - 2)
    return f" {_c(title, _BOLD)}{'─' * pad}"


def _wrap(text: str, indent: int = 14, width: int = 72) -> str:
    """Word-wrap *text* at *width*, indenting continuation lines."""
    lines = textwrap.wrap(text, width=width - indent)
    prefix = " " * indent
    return ("\n" + prefix).join(lines)


# ---------------------------------------------------------------------------
# Language -> extension mapping  (for --lang filter)
# ---------------------------------------------------------------------------

_LANG_EXTENSIONS: dict[str, frozenset[str]] = {
    "python":     frozenset({".py"}),
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs"}),
    "typescript": frozenset({".ts", ".tsx"}),
    "go":         frozenset({".go"}),
    "rust":       frozenset({".rs"}),
    "java":       frozenset({".java"}),
    "kotlin":     frozenset({".kt"}),
    "csharp":     frozenset({".cs"}),
    "c":          frozenset({".c", ".h"}),
    "cpp":        frozenset({".cpp", ".cc", ".cxx", ".hpp", ".h"}),
    "ruby":       frozenset({".rb"}),
    "php":        frozenset({".php"}),
    "swift":      frozenset({".swift"}),
    "shell":      frozenset({".sh", ".bash", ".zsh", ".fish", ".ps1"}),
    "sql":        frozenset({".sql"}),
    "terraform":  frozenset({".tf", ".hcl"}),
}


def _resolve_lang_extensions(lang: str | None) -> frozenset[str] | None:
    """Return the extension set for a language name, or None for 'all'."""
    if lang is None or lang.lower() == "all":
        return None
    key = lang.lower().replace("-", "").replace("_", "").replace(" ", "")
    if key not in _LANG_EXTENSIONS:
        known = ", ".join(sorted(_LANG_EXTENSIONS))
        raise ValueError(
            f"Unknown language '{lang}'. Known values: {known}, all"
        )
    return _LANG_EXTENSIONS[key]


# ---------------------------------------------------------------------------
# subcommand: scan
# ---------------------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    from src.scanner import GlasswingScanner

    extensions = None
    if args.lang:
        try:
            extensions = _resolve_lang_extensions(args.lang)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"[*] Language filter: {args.lang} "
              f"({', '.join(sorted(extensions))})")

    try:
        scanner = GlasswingScanner(
            repo_path=args.target,
            top_n=args.top,
            model=args.model,
            verbose=args.verbose,
            extensions=extensions,
        )
        scanner.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.", file=sys.stderr)
        return 130

    return 0


# ---------------------------------------------------------------------------
# subcommand: cve
# ---------------------------------------------------------------------------

def _cmd_cve(args: argparse.Namespace) -> int:
    from src.cve_hunter import CVEHunter, REPORT_PATH

    out_path = Path(args.output) if args.output else REPORT_PATH

    try:
        hunter = CVEHunter(
            manifest_path=args.requirements,
            model=args.model,
            verbose=args.verbose,
            output_path=out_path,
        )
        hunter.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] CVE scan interrupted.", file=sys.stderr)
        return 130

    return 0


# ---------------------------------------------------------------------------
# subcommand: intel
# ---------------------------------------------------------------------------

def _cmd_intel(args: argparse.Namespace) -> int:
    from src.intel import IntelGatherer

    try:
        gatherer = IntelGatherer(
            target_url = args.target,
            model      = args.model,
            verbose    = args.verbose,
            output_dir = Path(args.output_dir),
        )
        gatherer.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Intel gathering interrupted.", file=sys.stderr)
        return 130

    return 0


# ---------------------------------------------------------------------------
# subcommand: surface
# ---------------------------------------------------------------------------

def _cmd_chain(args: argparse.Namespace) -> int:
    from src.impact_chainer import ImpactChainer

    try:
        chainer = ImpactChainer(
            reports_dir=args.reports,
            target=args.target,
            model=args.model,
            verbose=args.verbose,
            output_dir=args.output_dir if args.output_dir else None,
        )
        chainer.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Impact chaining interrupted.", file=sys.stderr)
        return 130

    return 0


def _cmd_surface(args: argparse.Namespace) -> int:
    from src.surface_mapper import SurfaceMapper

    extensions = None
    if args.lang:
        # Validate early so the error message comes from glasswing, not the module
        from src.surface_mapper import _LANG_EXTENSIONS
        key = args.lang.lower().replace("-", "").replace("_", "")
        if key not in _LANG_EXTENSIONS and key != "all":
            known = ", ".join(sorted(_LANG_EXTENSIONS))
            print(f"Error: Unknown language '{args.lang}'. Known: {known}, all",
                  file=sys.stderr)
            return 1

    try:
        mapper = SurfaceMapper(
            repo_path  = args.target,
            lang       = args.lang if args.lang and args.lang.lower() != "all" else None,
            model      = args.model,
            verbose    = args.verbose,
            output_dir = Path(args.output_dir),
        )
        mapper.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Surface mapping interrupted.", file=sys.stderr)
        return 130

    return 0


# ---------------------------------------------------------------------------
# subcommand: report  —  formatted console output
# ---------------------------------------------------------------------------

def _load_report(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Report not found: {path}")
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)


# ── Scanner report formatter ─────────────────────────────────────────────

def _print_scan_report(report: dict[str, Any]) -> None:
    summary  = report.get("summary", {})
    findings = report.get("findings", [])
    by_sev   = summary.get("by_severity", {})
    total    = summary.get("total_findings", len(findings))

    print(_hr())
    print(_c(" GLASSWING SECURITY SCAN REPORT", _BOLD))
    print(_hr())
    print(f"  {'Repo':<12}{report.get('repo', '—')}")
    print(f"  {'Scanned':<12}{report.get('timestamp', '—')}")
    print(f"  {'Model':<12}{report.get('model', '—')}")
    files_col = (
        f"{summary.get('files_collected', '?')} collected"
        f"  ·  {summary.get('files_deep_scanned', '?')} deep-scanned"
    )
    print(f"  {'Files':<12}{files_col}")
    print(_hr())

    print(f" {_c('SEVERITY BREAKDOWN', _BOLD)}"
          f"{'':>38}{_c(str(total) + ' finding(s)', _BOLD)}")
    print(_hr())

    sev_keys = ["critical", "high", "medium", "low", "info"]
    max_count = max((by_sev.get(s, 0) for s in sev_keys), default=1) or 1
    for sev in sev_keys:
        count = by_sev.get(sev, 0)
        bar   = _bar(count, max_count)
        label = sev.upper()
        color = _SEVERITY_COLOR.get(sev, "")
        print(
            f"  {_c(f'{label:<10}', color)}"
            f"{_c(bar, color):<{_BAR_WIDTH + 20}}"
            f"  {count}"
        )

    if not findings:
        print(_hr())
        print(_c("  No findings.", _GREEN))
        print(_hr())
        return

    print(_hr())
    print(_c(" FINDINGS", _BOLD))
    print(_hr())

    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "?").upper()
        color = _SEVERITY_COLOR.get(f.get("severity", ""), "")
        title = f.get("title", "Untitled")
        cwe   = f.get("cwe", "")
        cvss  = f.get("cvss_estimate")
        ftype = f.get("type", "")
        ffile = f.get("file", "")
        ls    = f.get("line_start")
        le    = f.get("line_end")
        impact   = f.get("impact", "")
        poc      = f.get("poc_idea", "")
        dhash    = f.get("disclosure_hash", "")
        snippet  = f.get("code_snippet", "").strip()

        loc = ffile
        if ls:
            loc += f":{ls}"
            if le and le != ls:
                loc += f"-{le}"

        cvss_str = f"{cvss:.1f}" if cvss is not None else "?"
        meta = "  ·  ".join(filter(None, [ftype, cwe, f"CVSS {cvss_str}" if cvss_str != "?" else None]))

        print(f"\n  {_c(f'[{sev}]', color)}  {_c(title, _BOLD)}")
        if meta:
            print(f"  {'':12}{_c(meta, _DIM)}")
        if loc:
            print(f"  {'File':<12}{loc}")
        if impact:
            print(f"  {'Impact':<12}{_wrap(impact)}")
        if poc:
            print(f"  {'PoC':<12}{_wrap(poc)}")
        if snippet:
            first_line = snippet.splitlines()[0][:80]
            print(f"  {'Snippet':<12}{_c(first_line, _DIM)}")
        if dhash:
            print(f"  {'Hash':<12}{_c(dhash[:16] + '…', _DIM)}")

        conf = f.get("validation", {}).get("confidence")
        if conf is not None:
            print(f"  {'Confidence':<12}{conf:.0%}")

    print(f"\n{_hr()}")


# ── CVE report formatter ─────────────────────────────────────────────────

def _print_cve_report(report: dict[str, Any]) -> None:
    summary  = report.get("summary", {})
    findings = report.get("findings", [])
    by_pri   = summary.get("by_priority", {})
    by_sev   = summary.get("by_severity", {})
    total    = summary.get("vulnerabilities_found", len(findings))
    exec_sum = report.get("executive_summary", "")

    print(_hr())
    print(_c(" GLASSWING CVE REPORT", _BOLD))
    print(_hr())
    print(f"  {'Manifest':<12}{report.get('manifest', '—')}")
    print(f"  {'Ecosystem':<12}{report.get('ecosystem', '—')}")
    print(f"  {'Scanned':<12}{report.get('timestamp', '—')}")
    print(f"  {'Model':<12}{report.get('model', '—')}")
    pkg_col = (
        f"{report.get('packages_scanned', '?')} scanned"
        f"  ·  {report.get('packages_skipped', 0)} skipped (no version)"
    )
    print(f"  {'Packages':<12}{pkg_col}")
    print(_hr())

    if exec_sum:
        print(_c(" EXECUTIVE SUMMARY", _BOLD))
        print(_hr())
        for line in textwrap.wrap(exec_sum, width=68):
            print(f"  {line}")
        print(_hr())

    print(f" {_c('PRIORITY BREAKDOWN', _BOLD)}"
          f"{'':>38}{_c(str(total) + ' CVE(s)', _BOLD)}")
    print(_hr())
    max_pri = max((by_pri.get(p, 0) for p in _PRIORITY_ORDER), default=1) or 1
    for pri in _PRIORITY_ORDER:
        count = by_pri.get(pri, 0)
        bar   = _bar(count, max_pri)
        color = _PRIORITY_COLOR.get(pri, "")
        print(
            f"  {_c(f'{pri:<16}', color)}"
            f"{_c(bar, color):<{_BAR_WIDTH + 20}}"
            f"  {count}"
        )

    print(_hr())
    sev_keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    print(_c(" SEVERITY BREAKDOWN", _BOLD))
    max_sev = max((by_sev.get(s, 0) for s in sev_keys), default=1) or 1
    for sev in sev_keys:
        count = by_sev.get(sev, 0)
        if count == 0:
            continue
        bar   = _bar(count, max_sev)
        color = _SEVERITY_COLOR.get(sev, "")
        print(
            f"  {_c(f'{sev:<12}', color)}"
            f"{_c(bar, color):<{_BAR_WIDTH + 20}}"
            f"  {count}"
        )

    if not findings:
        print(_hr())
        print(_c("  No CVE findings.", _GREEN))
        print(_hr())
        return

    print(_hr())
    print(_c(" FINDINGS", _BOLD))
    print(_hr())

    for f in findings:
        pri      = f.get("priority", "investigate")
        sev      = f.get("severity", "UNKNOWN")
        pkg      = f.get("package", "?")
        ver      = f.get("version") or "?"
        vuln_id  = f.get("vuln_id", "")
        aliases  = f.get("aliases", [])
        summary_ = f.get("summary", "")
        cvss     = f.get("cvss_score")
        fixed    = f.get("fixed_in", [])
        rec_ver  = f.get("recommended_version", "")
        reason   = f.get("reasoning", "")
        risk     = f.get("risk_score")
        refs     = f.get("references", [])[:2]
        is_dev   = f.get("is_dev_dependency", False)

        pri_color = _PRIORITY_COLOR.get(pri, "")
        sev_color = _SEVERITY_COLOR.get(sev, "")

        cve_ids = ", ".join(a for a in aliases if a.startswith("CVE-")) or vuln_id
        fix_str = rec_ver or (f"≥ {fixed[0]}" if fixed else "no fix available")
        cvss_str = f"{cvss:.1f}" if cvss is not None else "?"
        dev_tag  = _c("  [dev]", _DIM) if is_dev else ""

        print(
            f"\n  {_c(f'[{pri}]', pri_color)}"
            f"  {_c(f'[{sev}]', sev_color)}"
            f"  {_c(pkg + '@' + ver, _BOLD)}{dev_tag}"
        )
        print(f"  {'CVE':<12}{cve_ids}  {_c('CVSS ' + cvss_str, sev_color)}")
        if summary_:
            print(f"  {'Summary':<12}{_wrap(summary_)}")
        if reason:
            print(f"  {'Reasoning':<12}{_wrap(reason)}")
        print(f"  {'Fix':<12}{fix_str}")
        if risk is not None:
            risk_bar = _BAR_CHAR * risk + _c("░" * (10 - risk), _DIM)
            print(f"  {'Risk':<12}{risk_bar}  {risk}/10")
        for ref in refs:
            print(f"  {'Ref':<12}{_c(ref, _DIM)}")

    print(f"\n{_hr()}")


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        report = _load_report(args.input)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    scanner_id = report.get("scanner", "")
    if scanner_id == "glasswing-scanner":
        _print_scan_report(report)
    elif scanner_id == "glasswing-cve-hunter":
        _print_cve_report(report)
    elif scanner_id == "glasswing-intel":
        from src.intel import print_intel_report
        print_intel_report(report)
    elif scanner_id == "glasswing-surface":
        from src.surface_mapper import print_surface_report
        print_surface_report(report)
    elif scanner_id == "glasswing-impact-chainer":
        from src.impact_chainer import print_chain_report
        print_chain_report(report)
    else:
        # Unknown type — attempt generic pretty-print
        print(f"[!] Unrecognised report type '{scanner_id}'. Dumping raw JSON.")
        print(json.dumps(report, indent=2))

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    default_model = "claude-sonnet-4-20250514"

    root = argparse.ArgumentParser(
        prog="glasswing",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument(
        "--env-file",
        default=".env",
        metavar="FILE",
        help="Path to .env file (default: .env).",
    )

    sub = root.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    sub.required = True

    # ── scan ──────────────────────────────────────────────────────────────
    p_scan = sub.add_parser(
        "scan",
        help="Analyse source files for security vulnerabilities.",
        description=(
            "Rank all source files by attack-surface likelihood, then deep-analyse "
            "the top-N files using Claude."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python glasswing.py scan --target ./repo\n"
            "  python glasswing.py scan --target . --lang python --top 20\n"
            "  python glasswing.py scan --target ./api --lang go --top 5 --verbose\n"
        ),
    )
    p_scan.add_argument(
        "--target", "-t",
        default=".",
        metavar="PATH",
        help="Repository path to scan (default: current directory).",
    )
    p_scan.add_argument(
        "--lang", "-l",
        default=None,
        metavar="LANG",
        help=(
            "Restrict scan to one language. Choices: "
            + ", ".join(sorted(_LANG_EXTENSIONS)) + ", all. "
            "Default: all languages."
        ),
    )
    p_scan.add_argument(
        "--top", "-n",
        type=int,
        default=10,
        metavar="N",
        help="Number of highest-scored files to deep-analyse (default: 10).",
    )
    p_scan.add_argument(
        "--model",
        default=default_model,
        help=f"Claude model (default: {default_model}).",
    )
    p_scan.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )

    # ── cve ───────────────────────────────────────────────────────────────
    p_cve = sub.add_parser(
        "cve",
        help="Scan dependencies for known CVEs via OSV.dev.",
        description=(
            "Parse a dependency manifest, query OSV.dev for known CVEs, then use "
            "Claude to prioritize every finding."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python glasswing.py cve --requirements requirements.txt\n"
            "  python glasswing.py cve --requirements package.json --verbose\n"
            "  python glasswing.py cve --requirements go.mod --output reports/go_cves.json\n"
        ),
    )
    p_cve.add_argument(
        "--requirements", "-r",
        required=True,
        metavar="FILE",
        help="Manifest file: requirements.txt, package.json, or go.mod.",
    )
    p_cve.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Output JSON path (default: reports/cve_report.json).",
    )
    p_cve.add_argument(
        "--model",
        default=default_model,
        help=f"Claude model (default: {default_model}).",
    )
    p_cve.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )

    # ── intel ─────────────────────────────────────────────────────────────
    p_intel = sub.add_parser(
        "intel",
        help="Gather pre-scan intelligence on a GitHub repository.",
        description=(
            "Phase 1 of the offensive research pipeline. Queries OSV.dev, the GitHub "
            "Advisory Database, recent commits, and dependency manifests to score a target "
            "before committing to a full audit."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python glasswing.py intel --target https://github.com/google/kafel\n"
            "  python glasswing.py intel --target openssl/openssl --verbose\n"
        ),
    )
    p_intel.add_argument(
        "--target", "-t",
        required=True,
        metavar="URL",
        help="GitHub repository URL or owner/repo shorthand.",
    )
    p_intel.add_argument(
        "--output-dir",
        default="reports",
        metavar="DIR",
        help="Directory to save the intel report (default: reports/).",
    )
    p_intel.add_argument(
        "--model",
        default=default_model,
        help=f"Claude model (default: {default_model}).",
    )
    p_intel.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )

    # ── surface ───────────────────────────────────────────────────────────
    p_surface = sub.add_parser(
        "surface",
        help="Map the attack surface of a local repository.",
        description=(
            "Phase 2 of the offensive research pipeline. Scans source files for "
            "entry points, trust boundaries, and dangerous sinks, then uses Claude "
            "to trace the top data flows between them."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python glasswing.py surface --target ./kafel --lang c\n"
            "  python glasswing.py surface --target ./myapp --lang python --verbose\n"
        ),
    )
    p_surface.add_argument(
        "--target", "-t",
        required=True,
        metavar="PATH",
        help="Local repository path to map.",
    )
    p_surface.add_argument(
        "--lang", "-l",
        default=None,
        metavar="LANG",
        help=(
            "Restrict scan to one language. Choices: "
            + ", ".join(sorted(_LANG_EXTENSIONS)) + ", all. "
            "Default: all languages."
        ),
    )
    p_surface.add_argument(
        "--output-dir",
        default="reports",
        metavar="DIR",
        help="Directory to save the surface report (default: reports/).",
    )
    p_surface.add_argument(
        "--model",
        default=default_model,
        help=f"Claude model (default: {default_model}).",
    )
    p_surface.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )

    # ── chain ─────────────────────────────────────────────────────────────
    p_chain = sub.add_parser(
        "chain",
        help="Chain scanner findings into higher-impact attack paths (Phase 3).",
        description=(
            "Phase 3 of the offensive research pipeline. Loads glasswing-scanner "
            "reports matching the target, correlates findings by CWE escalation pairs "
            "and same-file co-location, then uses Claude to validate and rank each "
            "candidate attack chain by impact and exploitability."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python glasswing.py chain --reports ./reports --target kafel\n"
            "  python glasswing.py chain --reports ./reports --target myapp --verbose\n"
        ),
    )
    p_chain.add_argument(
        "--reports", "-r",
        default="reports",
        metavar="DIR",
        help="Directory containing glasswing JSON reports (default: reports/).",
    )
    p_chain.add_argument(
        "--target", "-t",
        required=True,
        metavar="NAME",
        help="Target name used to filter reports (e.g. 'kafel').",
    )
    p_chain.add_argument(
        "--output-dir",
        default=None,
        metavar="DIR",
        help="Directory to write the chain report (default: same as --reports).",
    )
    p_chain.add_argument(
        "--model",
        default=default_model,
        help=f"Claude model (default: {default_model}).",
    )
    p_chain.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress.",
    )

    # ── report ────────────────────────────────────────────────────────────
    p_report = sub.add_parser(
        "report",
        help="Print a formatted summary of a saved report JSON.",
        description=(
            "Reads a report produced by the 'scan' or 'cve' subcommand and prints "
            "a colour-coded summary with severity/priority breakdown and all findings."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python glasswing.py report --input reports/glasswing_20240115T103000Z.json\n"
            "  python glasswing.py report --input reports/cve_report.json\n"
        ),
    )
    p_report.add_argument(
        "--input", "-i",
        required=True,
        metavar="FILE",
        help="Path to a glasswing JSON report.",
    )

    return root


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # Load .env before touching ANTHROPIC_API_KEY
    _load_dotenv(args.env_file)

    # API key is required for subcommands that call Claude
    if args.subcommand in ("scan", "cve", "intel", "surface", "chain"):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print(
                "Error: ANTHROPIC_API_KEY is not set.\n"
                "Set it in your environment or add it to a .env file:\n"
                "  echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env",
                file=sys.stderr,
            )
            return 1

    dispatch = {
        "scan":    _cmd_scan,
        "cve":     _cmd_cve,
        "intel":   _cmd_intel,
        "surface": _cmd_surface,
        "chain":   _cmd_chain,
        "report":  _cmd_report,
    }
    return dispatch[args.subcommand](args)


if __name__ == "__main__":
    sys.exit(main())
