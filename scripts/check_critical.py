"""
Security gate script — called by .github/workflows/security-scan.yml.

Reads every JSON report under REPORTS_DIR (default: all-reports), checks for
CRITICAL severity findings, writes a Markdown summary to GITHUB_STEP_SUMMARY,
and exits 1 if any CRITICAL finding is found (blocking the PR).

Environment variables (injected by the workflow):
  REPORTS_DIR       Directory containing downloaded report artifacts.
  CVE_SCAN_RESULT   Result string of the cve-scan job (success/failure/skipped).
  CODE_SCAN_RESULT  Result string of the code-scan job (success/failure/skipped).
  GITHUB_STEP_SUMMARY  Path to the GitHub Actions step-summary file (set by runner).
"""

from __future__ import annotations

import json
import os
import pathlib
import sys


def main() -> int:
    reports_dir  = pathlib.Path(os.environ.get("REPORTS_DIR", "all-reports"))
    cve_result   = os.environ.get("CVE_SCAN_RESULT",  "unknown")
    code_result  = os.environ.get("CODE_SCAN_RESULT", "unknown")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")

    critical:    list[dict] = []
    scan_errors: list[str]  = []
    reports_read = 0

    # Flag upstream job failures (but do not block on them alone)
    if cve_result not in ("success", "skipped"):
        scan_errors.append(f"cve-scan ended with status: {cve_result}")
    if code_result not in ("success", "skipped"):
        scan_errors.append(f"code-scan ended with status: {code_result}")

    # ------------------------------------------------------------------
    # Parse every downloaded report
    # ------------------------------------------------------------------
    for report_file in sorted(reports_dir.rglob("*.json")):
        try:
            data = json.loads(report_file.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[!] Could not parse {report_file}: {exc}")
            continue

        reports_read += 1
        scanner  = data.get("scanner", "unknown")
        findings = data.get("findings", [])

        print(f"\n--- {report_file.name}  ({scanner}) ---")

        if scanner == "glasswing-scanner":
            counts: dict[str, int] = {}
            for finding in findings:
                sev = (finding.get("severity") or "unknown").lower()
                counts[sev] = counts.get(sev, 0) + 1
                if sev == "critical":
                    critical.append({
                        "kind":  "CODE",
                        "title": finding.get("title", "?"),
                        "cwe":   finding.get("cwe", ""),
                        "cvss":  finding.get("cvss_estimate"),
                        "file":  finding.get("file", ""),
                        "hash":  (finding.get("disclosure_hash") or "")[:16],
                    })
            for sev in ("critical", "high", "medium", "low", "info"):
                n = counts.get(sev, 0)
                if n:
                    tag = "  <<< CRITICAL" if sev == "critical" else ""
                    print(f"  {sev.upper():<10} {n}{tag}")

        elif scanner == "glasswing-cve-hunter":
            summ = data.get("summary", {})
            print(f"  Packages scanned: {data.get('packages_scanned', '?')}")
            for sev, n in (summ.get("by_severity") or {}).items():
                if n:
                    tag = "  <<< CRITICAL" if sev.upper() == "CRITICAL" else ""
                    print(f"  {sev:<12} {n}{tag}")
            for finding in findings:
                sev = (finding.get("severity") or "UNKNOWN").upper()
                if sev == "CRITICAL":
                    fixed_in = finding.get("fixed_in") or []
                    fix = (
                        finding.get("recommended_version")
                        or (fixed_in[0] if fixed_in else "no fix available")
                    )
                    critical.append({
                        "kind":    "CVE",
                        "package": f"{finding.get('package', '?')}@{finding.get('version', '?')}",
                        "vuln_id": finding.get("vuln_id", "?"),
                        "cvss":    finding.get("cvss_score"),
                        "priority":finding.get("priority", "?"),
                        "fix":     fix,
                    })

    # ------------------------------------------------------------------
    # Write GitHub step summary (Markdown)
    # ------------------------------------------------------------------
    md_lines: list[str] = ["## Glasswing Security Gate\n\n"]

    if scan_errors:
        md_lines.append("### Scan Errors\n\n")
        for err in scan_errors:
            md_lines.append(f"- `{err}`\n")
        md_lines.append("\n")

    md_lines.append(
        "| Metric | Value |\n"
        "|--------|-------|\n"
        f"| Reports evaluated | {reports_read} |\n"
        f"| Critical findings | {len(critical)} |\n"
        f"| CVE scan result | `{cve_result}` |\n"
        f"| Code scan result | `{code_result}` |\n\n"
    )

    if critical:
        md_lines.append(
            f"### [BLOCKED] {len(critical)} Critical Vulnerability(ies) Found\n\n"
            "| Kind | Details | CVSS | Remediation |\n"
            "|------|---------|------|-------------|\n"
        )
        for c in critical:
            cvss_str = f"{c['cvss']:.1f}" if c.get("cvss") is not None else "?"
            if c["kind"] == "CODE":
                details = f"`{c['file']}` - **{c['title']}** ({c['cwe']})"
                action  = f"Fix in source (`{c['hash']}...`)"
            else:
                details = f"`{c['package']}` - **{c['vuln_id']}**"
                action  = f"Upgrade to `{c['fix']}`"
            md_lines.append(f"| {c['kind']} | {details} | {cvss_str} | {action} |\n")
        md_lines.append(
            "\n> **This PR is blocked until all CRITICAL findings are resolved.**\n"
        )
    else:
        md_lines.append("### [PASSED] No Critical Vulnerabilities Detected\n\n")
        md_lines.append(
            "All scanned dependencies and source files are clear of "
            "CRITICAL severity issues.\n"
        )

    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.writelines(md_lines)
        except OSError as exc:
            print(f"[!] Could not write step summary: {exc}")

    # ------------------------------------------------------------------
    # Exit decision
    # ------------------------------------------------------------------
    if critical:
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"SECURITY GATE FAILED -- {len(critical)} CRITICAL finding(s)")
        print(sep)
        for c in critical:
            cvss_str = str(c.get("cvss") or "?")
            if c["kind"] == "CODE":
                print(
                    f"  [CODE]  {c['title']}"
                    f"  cwe={c['cwe']}"
                    f"  file={c['file']}"
                    f"  cvss={cvss_str}"
                    f"  hash={c['hash']}..."
                )
            else:
                print(
                    f"  [CVE ]  {c['package']}"
                    f"  {c['vuln_id']}"
                    f"  cvss={cvss_str}"
                    f"  priority={c['priority']}"
                    f"  fix={c['fix']}"
                )
        print("\nResolve all CRITICAL findings before merging this PR.")
        return 1

    if reports_read == 0:
        print("No reports found. Scans may have been skipped or produced no output.")
    else:
        print(f"\nSECURITY GATE PASSED -- no critical findings in {reports_read} report(s).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
