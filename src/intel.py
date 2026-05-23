#!/usr/bin/env python
"""
Glasswing Intel — Pre-scan intelligence gathering for offensive research.

Pipeline
--------
1. Historical CVE lookup via OSV.dev + GitHub Advisory API
2. Recent commit analysis — security-sensitive pattern detection
3. Dependency fingerprint — detect manifests, cross-ref with OSV.dev
4. Attack surface score (1-10): HUNT / INVESTIGATE / SKIP
5. Intel report saved to reports/intel_{owner}_{repo}_{date}.json

Uses only stdlib + anthropic.

Usage
-----
    python glasswing.py intel --target https://github.com/org/repo
    python src/intel.py --target https://github.com/org/repo
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL      = "claude-sonnet-4-20250514"
GITHUB_API         = "https://api.github.com"
OSV_QUERY_URL      = "https://api.osv.dev/v1/query"
OSV_BATCH_URL      = "https://api.osv.dev/v1/querybatch"
NVD_BASE_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT        = 10
NVD_RATE_LIMIT     = 5
NVD_RATE_WINDOW    = 30.0
HTTP_TIMEOUT       = 20
COMMIT_LIMIT       = 50
DETAIL_FETCH_LIMIT = 5     # max per-commit detail fetches (files changed)
ADVISORY_PAGE_SIZE = 100
REPORTS_DIR        = Path(__file__).resolve().parent.parent / "reports"

# Regex: security-sensitive keywords in commit messages
_SECURITY_RE = re.compile(
    r"\b(?:auth(?:entic(?:at)?|oriz)?|crypto|crypt|hash|sign|cert|tls|ssl|"
    r"(?:api|secret|access)[_\-]?key|token|password|passwd|credential|"
    r"jwt|oauth|saml|ldap|"
    r"pars(?:e|er|ing)|deserializ|unmarshal|decode|"
    r"buffer|overflow|underflow|heap|alloc|malloc|free|"
    r"use[_\-]?after|double[_\-]?free|"
    r"exec|shell|cmdi|sqli|inject|xss|xxe|ssrf|csrf|rce|"
    r"permiss|privilege|privesc|sandbox|escap|bypass|"
    r"race[_\-]?condition|concurren|mutex|"
    r"path[_\-]?travers|upload)\b",
    re.IGNORECASE,
)

# Language -> (primary OSV ecosystem, attack surface score bonus)
_LANG_SCORES: dict[str, tuple[str, int]] = {
    "C":          ("OSS-Fuzz",  3),
    "C++":        ("OSS-Fuzz",  3),
    "Go":         ("Go",        2),
    "Python":     ("PyPI",      1),
    "JavaScript": ("npm",       1),
    "TypeScript": ("npm",       1),
    "Java":       ("Maven",     1),
    "Kotlin":     ("Maven",     1),
    "Rust":       ("crates.io", 0),
    "Ruby":       ("RubyGems",  1),
    "PHP":        ("Packagist", 1),
    "Swift":      ("SwiftURL",  1),
}


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class _IntelState:
    target_url:  str
    owner:       str
    repo:        str
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    repo_info:   dict[str, Any]  = field(default_factory=dict)
    cve_summary: dict[str, Any]  = field(default_factory=dict)
    advisories:  list[dict]      = field(default_factory=list)
    osv_vulns:   list[dict]      = field(default_factory=list)
    nvd_vulns:   list[dict]      = field(default_factory=list)
    commits_analyzed:   int      = 0
    suspicious_commits: list[dict] = field(default_factory=list)
    manifests_found:    list[str]  = field(default_factory=list)
    dependencies:       list[dict] = field(default_factory=list)
    dep_vulns:          list[dict] = field(default_factory=list)
    score:           int  = 0
    score_breakdown: dict = field(default_factory=dict)
    recommendation:  str  = "SKIP"
    threat_narrative:        str       = ""
    key_findings:            list[str] = field(default_factory=list)
    recommended_focus_areas: list[str] = field(default_factory=list)
    attack_vectors:          list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

def parse_github_url(url: str) -> tuple[str, str]:
    """
    Extract (owner, repo) from a GitHub URL.
    Accepts: https://github.com/owner/repo, github.com/owner/repo, owner/repo
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    m = re.search(r"github\.com[:/]([^/\s]+)/([^/\s#?]+)", url)
    if m:
        return m.group(1), m.group(2)
    parts = url.split("/")
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    raise ValueError(
        f"Cannot parse GitHub URL: {url!r}\n"
        "Expected: https://github.com/owner/repo"
    )


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _github_get(path: str, params: dict | None = None) -> Any:
    """GET from GitHub API. Returns parsed JSON or None on any error."""
    url = f"{GITHUB_API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "glasswing-scanner/1.0")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def _osv_post(payload: dict) -> dict:
    """POST to OSV.dev /v1/query. Returns {} on failure."""
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        OSV_QUERY_URL, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _osv_batch(queries: list[dict]) -> list[dict]:
    """POST to OSV.dev /v1/querybatch. Returns list of result objects or []."""
    if not queries:
        return []
    body = json.dumps({"queries": queries}).encode("utf-8")
    req  = urllib.request.Request(
        OSV_BATCH_URL, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace")).get("results", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# NVD helpers
# ---------------------------------------------------------------------------

_nvd_request_times: list[float] = []


def _nvd_throttle() -> None:
    """Enforce 5 requests per 30-second window (no-auth NVD rate limit)."""
    now = time.monotonic()
    while _nvd_request_times and now - _nvd_request_times[0] > NVD_RATE_WINDOW:
        _nvd_request_times.pop(0)
    if len(_nvd_request_times) >= NVD_RATE_LIMIT:
        wait = NVD_RATE_WINDOW - (now - _nvd_request_times[0]) + 0.1
        if wait > 0:
            time.sleep(wait)
    _nvd_request_times.append(time.monotonic())


def _nvd_get(params: dict) -> dict:
    """GET from NVD CVE 2.0 API. Returns parsed JSON or {} on any error."""
    _nvd_throttle()
    url = NVD_BASE_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "glasswing-scanner/1.0")
    try:
        with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _parse_nvd_response(data: dict) -> list[dict]:
    """Extract normalized CVE list from an NVD CVE 2.0 API response."""
    results: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        desc = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        cvss_score: float | None = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_score = entries[0].get("cvssData", {}).get("baseScore")
                break
        results.append({
            "id":            cve_id,
            "cvss_score":    cvss_score,
            "description":   desc,
            "published":     cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        })
    return results


def _nvd_cvss_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def query_nvd(owner: str, repo: str) -> list[dict]:
    """
    Query NVD CVE 2.0 API for CVEs related to a GitHub owner/repo.

    Tries CPE search first; falls back to keyword search.
    Returns list of dicts: id, cvss_score, description, published, last_modified.
    """
    vendor  = re.sub(r"[^a-z0-9]", "", owner.lower())
    product = repo.lower()

    data    = _nvd_get({"cpeName": f"cpe:2.3:*:{vendor}:{product}:*"})
    results = _parse_nvd_response(data)

    if not results:
        data    = _nvd_get({"keywordSearch": product})
        results = _parse_nvd_response(data)

    return results


# ---------------------------------------------------------------------------
# Manifest parsers  (lightweight, returns [(name, version|None)])
# ---------------------------------------------------------------------------

def _strip_ver(ver: str) -> str:
    ver = re.sub(r"^[~^><=!*\s]+", "", ver.strip())
    if " - " in ver:
        ver = ver.split(" - ")[0].strip()
    if " || " in ver:
        ver = re.sub(r"^[~^><=!]+", "", ver.split(" || ")[0].strip())
    if not ver or ver in {"*", "x", "X", "latest"}:
        return ""
    return re.sub(r"\.[xX*]$", ".0", ver)


def _parse_requirements(content: str) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http")):
            continue
        line = re.split(r"\s*[;#]", line)[0].strip()
        line = re.sub(r"\[.*?\]", "", line)
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*[><=!~^]+\s*([^\s,]+))?", line)
        if m:
            raw = re.sub(r"^[><=!~^]+\s*", "", (m.group(2) or ""))
            pkgs.append((m.group(1), _strip_ver(raw) or None))
    return pkgs


def _parse_package_json(content: str) -> list[tuple[str, str | None]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    pkgs: list[tuple[str, str | None]] = []
    for deps in (data.get("dependencies", {}), data.get("devDependencies", {})):
        for name, ver_range in deps.items():
            if isinstance(ver_range, str):
                pkgs.append((name, _strip_ver(ver_range) or None))
    return pkgs


def _parse_go_mod(content: str) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    in_req = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_req = True
            continue
        if in_req and line == ")":
            in_req = False
            continue
        m = re.match(r"^require\s+(\S+)\s+(v[\w.\-+]+)", line) or (
            re.match(r"^(\S+)\s+(v[\w.\-+]+)", line) if in_req else None
        )
        if m:
            ver = m.group(2).lstrip("v")
            if not re.match(r"0\.0\.0-\d{14}-[0-9a-f]{12}", ver):
                pkgs.append((m.group(1), ver))
    return pkgs


def _parse_cargo_toml(content: str) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if re.match(r"^\[(?:dev-|build-)?dependencies\]$", line, re.IGNORECASE):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
            continue
        if not in_deps:
            continue
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9_-]*)\s*=\s*"([^"]+)"', line)
        if m:
            pkgs.append((m.group(1), _strip_ver(m.group(2)) or None))
            continue
        m2 = re.match(r'^([A-Za-z0-9][A-Za-z0-9_-]*)\s*=\s*\{.*?version\s*=\s*"([^"]+)"', line)
        if m2:
            pkgs.append((m2.group(1), _strip_ver(m2.group(2)) or None))
    return pkgs


def _parse_pom_xml(content: str) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    try:
        content_clean = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', "", content)
        root = ET.fromstring(content_clean)
    except ET.ParseError:
        return []
    for dep in root.iter("dependency"):
        group    = (dep.findtext("groupId") or "").strip()
        artifact = (dep.findtext("artifactId") or "").strip()
        version  = (dep.findtext("version") or "").strip()
        if group and artifact:
            ver = version if (version and not version.startswith("$")) else None
            pkgs.append((f"{group}:{artifact}", ver))
    return pkgs


_MANIFEST_PARSERS: dict[str, tuple[str, Any]] = {
    "requirements.txt": ("PyPI",      _parse_requirements),
    "package.json":     ("npm",       _parse_package_json),
    "go.mod":           ("Go",        _parse_go_mod),
    "Cargo.toml":       ("crates.io", _parse_cargo_toml),
    "pom.xml":          ("Maven",     _parse_pom_xml),
}


# ---------------------------------------------------------------------------
# OSV severity helper
# ---------------------------------------------------------------------------

def _osv_severity(vuln: dict) -> str:
    """Extract a severity label from an OSV vulnerability object."""
    # database_specific.severity (GHSA, OSS-Fuzz entries)
    sev = (vuln.get("database_specific") or {}).get("severity", "")
    if sev:
        return sev.upper()
    # ecosystem_specific.severity inside affected[]
    for aff in vuln.get("affected", []):
        sev = (aff.get("ecosystem_specific") or {}).get("severity", "")
        if sev:
            return sev.upper()
    # Presence of a CVSS vector -> conservative HIGH
    for s in vuln.get("severity", []):
        if s.get("type", "") in ("CVSS_V3", "CVSS_V31", "CVSS_V2"):
            return "HIGH"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Phase 1 — Repo info + historical CVEs
# ---------------------------------------------------------------------------

def _fetch_repo_info(owner: str, repo: str) -> dict[str, Any]:
    data = _github_get(f"/repos/{owner}/{repo}")
    if not isinstance(data, dict):
        return {}
    return {
        "full_name":      data.get("full_name", f"{owner}/{repo}"),
        "description":    data.get("description", ""),
        "language":       data.get("language") or "",
        "stargazers":     data.get("stargazers_count", 0),
        "forks":          data.get("forks_count", 0),
        "open_issues":    data.get("open_issues_count", 0),
        "created_at":     data.get("created_at", ""),
        "pushed_at":      data.get("pushed_at", ""),
        "default_branch": data.get("default_branch", "main"),
        "topics":         data.get("topics", []),
        "license":        (data.get("license") or {}).get("spdx_id", ""),
    }


def _fetch_github_advisories(owner: str, repo: str, language: str) -> list[dict]:
    """Query GitHub Advisory Database. Tries owner/repo and repo-name strategies."""
    seen: set[str] = set()
    result: list[dict] = []

    def _ingest(raw: Any) -> None:
        if not isinstance(raw, list):
            return
        for adv in raw:
            ghsa_id = adv.get("ghsa_id", "")
            if not ghsa_id or ghsa_id in seen:
                continue
            seen.add(ghsa_id)
            sev = adv.get("severity", "unknown").upper()
            cvss_v3 = ((adv.get("cvss_severities") or {}).get("cvss_v3") or {}).get("score")
            result.append({
                "ghsa_id":    ghsa_id,
                "cve_id":     adv.get("cve_id", ""),
                "summary":    adv.get("summary", ""),
                "severity":   sev,
                "cvss_score": cvss_v3,
                "published":  adv.get("published_at", ""),
                "url":        adv.get("html_url", ""),
            })

    _ingest(_github_get("/advisories", {"affects": f"{owner}/{repo}", "per_page": str(ADVISORY_PAGE_SIZE)}))
    if not result:
        _ingest(_github_get("/advisories", {"affects": repo, "per_page": str(ADVISORY_PAGE_SIZE)}))
    return result


def _fetch_osv_cves(owner: str, repo: str, language: str, latest_sha: str) -> list[dict]:
    """Query OSV.dev via commit hash, Go module path, and ecosystem package name."""
    seen: set[str] = set()
    result: list[dict] = []

    def _ingest(vulns: list[dict]) -> None:
        for v in vulns:
            vid = v.get("id", "")
            if vid and vid not in seen:
                seen.add(vid)
                result.append({
                    "id":        vid,
                    "aliases":   v.get("aliases", []),
                    "summary":   v.get("summary", ""),
                    "severity":  _osv_severity(v),
                    "published": v.get("published", ""),
                    "modified":  v.get("modified", ""),
                })

    # Strategy 1: git commit hash
    if latest_sha:
        _ingest(_osv_post({"commit": latest_sha}).get("vulns", []))

    # Strategy 2: Go module path (works for Go repos)
    _ingest(_osv_post({
        "package": {"name": f"github.com/{owner}/{repo}", "ecosystem": "Go"}
    }).get("vulns", []))

    # Strategy 3: package name in detected ecosystem
    ecosystem, _ = _LANG_SCORES.get(language, ("", 0))
    if ecosystem and ecosystem not in ("OSS-Fuzz", "Go", ""):
        _ingest(_osv_post({"package": {"name": repo, "ecosystem": ecosystem}}).get("vulns", []))

    return result


def _build_cve_summary(
    github_advisories: list[dict],
    osv_vulns: list[dict],
    nvd_vulns: list[dict],
) -> dict[str, Any]:
    sev_dist: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    dates: list[str] = []

    for item in github_advisories:
        key = item.get("severity", "UNKNOWN")
        sev_dist[key if key in sev_dist else "UNKNOWN"] += 1
        if item.get("published"):
            dates.append(item["published"])

    for item in osv_vulns:
        key = item.get("severity", "UNKNOWN")
        sev_dist[key if key in sev_dist else "UNKNOWN"] += 1
        if item.get("published"):
            dates.append(item["published"])

    for item in nvd_vulns:
        key = _nvd_cvss_severity(item.get("cvss_score"))
        sev_dist[key if key in sev_dist else "UNKNOWN"] += 1
        if item.get("published"):
            dates.append(item["published"])

    last_cve_date = max(dates) if dates else None
    is_cold = False
    if last_cve_date:
        try:
            dt = datetime.fromisoformat(last_cve_date.replace("Z", "+00:00"))
            is_cold = (datetime.now(timezone.utc) - dt).days > 730
        except Exception:
            pass

    return {
        "total":          len(github_advisories) + len(osv_vulns) + len(nvd_vulns),
        "github_count":   len(github_advisories),
        "osv_count":      len(osv_vulns),
        "nvd_count":      len(nvd_vulns),
        "severity_dist":  sev_dist,
        "last_cve_date":  last_cve_date,
        "is_cold_target": is_cold,
    }


# ---------------------------------------------------------------------------
# Phase 2 — Commit analysis
# ---------------------------------------------------------------------------

def _fetch_commits(owner: str, repo: str) -> list[dict]:
    raw = _github_get(f"/repos/{owner}/{repo}/commits", {"per_page": str(COMMIT_LIMIT)})
    if not isinstance(raw, list):
        return []
    commits = []
    for c in raw:
        cd = c.get("commit", {})
        commits.append({
            "sha":      c.get("sha", "")[:12],
            "sha_full": c.get("sha", ""),
            "message":  (cd.get("message") or "").splitlines()[0][:200],
            "author":   (cd.get("author") or {}).get("name", ""),
            "date":     (cd.get("author") or {}).get("date", ""),
            "url":      c.get("html_url", ""),
        })
    return commits


def _fetch_commit_files(owner: str, repo: str, sha: str) -> list[str]:
    data = _github_get(f"/repos/{owner}/{repo}/commits/{sha}")
    if not isinstance(data, dict):
        return []
    return [f["filename"] for f in data.get("files", []) if "filename" in f]


def _analyze_commits(owner: str, repo: str, commits: list[dict]) -> list[dict]:
    """Flag security-sensitive commits; fetch file details for top N."""
    flagged = []
    for c in commits:
        keywords = list(set(m.group(0).lower() for m in _SECURITY_RE.finditer(c["message"])))
        if keywords:
            entry = dict(c)
            entry["security_keywords"] = sorted(keywords)
            entry["files"] = []
            flagged.append(entry)

    for entry in flagged[:DETAIL_FETCH_LIMIT]:
        entry["files"] = _fetch_commit_files(owner, repo, entry["sha_full"])

    # Remove sha_full from output
    for entry in flagged:
        entry.pop("sha_full", None)

    return flagged


# ---------------------------------------------------------------------------
# Phase 3 — Dependency fingerprint
# ---------------------------------------------------------------------------

def _fetch_manifest_files(owner: str, repo: str, branch: str) -> dict[str, str]:
    """Return {filename: content} for any recognised manifests in the repo root."""
    root = _github_get(f"/repos/{owner}/{repo}/contents/", {"ref": branch})
    if not isinstance(root, list):
        return {}
    root_names = {item["name"] for item in root if item.get("type") == "file"}

    manifests: dict[str, str] = {}
    for fname in _MANIFEST_PARSERS:
        if fname not in root_names:
            continue
        file_data = _github_get(f"/repos/{owner}/{repo}/contents/{fname}", {"ref": branch})
        if not isinstance(file_data, dict):
            continue
        encoded = file_data.get("content", "")
        if not encoded:
            continue
        try:
            manifests[fname] = base64.b64decode(encoded.replace("\n", "")).decode("utf-8", errors="replace")
        except Exception:
            pass
    return manifests


def _fingerprint_dependencies(manifests: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Parse manifests, query OSV, return (all_deps, vuln_findings)."""
    all_deps: list[dict] = []
    osv_queries: list[dict] = []
    dep_meta: list[dict] = []

    for fname, content in manifests.items():
        ecosystem, parser_fn = _MANIFEST_PARSERS[fname]
        for name, ver in parser_fn(content):
            all_deps.append({"name": name, "version": ver, "ecosystem": ecosystem, "manifest": fname})
            if ver:
                osv_queries.append({"version": ver, "package": {"name": name, "ecosystem": ecosystem}})
                dep_meta.append({"name": name, "version": ver, "ecosystem": ecosystem, "manifest": fname})

    vuln_findings: list[dict] = []
    if osv_queries:
        results = _osv_batch(osv_queries)
        for dep, result in zip(dep_meta, results):
            for v in result.get("vulns", []):
                vuln_findings.append({
                    "package":   dep["name"],
                    "version":   dep["version"],
                    "ecosystem": dep["ecosystem"],
                    "manifest":  dep["manifest"],
                    "vuln_id":   v.get("id", ""),
                    "summary":   v.get("summary", ""),
                    "severity":  _osv_severity(v),
                })

    return all_deps, vuln_findings


# ---------------------------------------------------------------------------
# Phase 4 — Attack surface score
# ---------------------------------------------------------------------------

def _compute_score(
    language:           str,
    cve_summary:        dict,
    suspicious_commits: list[dict],
    dep_vulns:          list[dict],
    last_push:          str,
    nvd_vulns:          list[dict] | None = None,
) -> tuple[int, dict[str, int], str]:
    breakdown: dict[str, int] = {}

    _, lang_bonus = _LANG_SCORES.get(language, ("", 0))
    if lang_bonus:
        breakdown[f"Language ({language})"] = lang_bonus

    if cve_summary.get("total", 0) > 0:
        breakdown["CVE history (has CVEs)"] = 2
        if not cve_summary.get("is_cold_target", True):
            breakdown["Recent CVEs (< 2 years)"] = 3

    susp_bonus = min(len(suspicious_commits), 3)
    if susp_bonus:
        breakdown[f"Suspicious commits ({len(suspicious_commits)} flagged)"] = susp_bonus

    if dep_vulns:
        breakdown["Vulnerable dependencies"] = 1

    if nvd_vulns:
        now = datetime.now(timezone.utc)
        cutoff = now.replace(year=now.year - 1)
        recent = [
            v for v in nvd_vulns
            if v.get("published") and
            datetime.fromisoformat(v["published"].replace("Z", "+00:00")) > cutoff
        ]
        if recent:
            breakdown["NVD CVEs (last 12 months)"] = 2

    if last_push:
        try:
            dt = datetime.fromisoformat(last_push.replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - dt).days < 180:
                breakdown["Active project (last push < 6 months)"] = 1
        except Exception:
            pass

    score = max(1, min(sum(breakdown.values()), 10))
    recommendation = "HUNT" if score >= 8 else ("INVESTIGATE" if score >= 5 else "SKIP")
    return score, breakdown, recommendation


# ---------------------------------------------------------------------------
# Phase 5 — Claude threat assessment
# ---------------------------------------------------------------------------

_INTEL_TOOL: dict[str, Any] = {
    "name": "intel_assessment",
    "description": (
        "Analyze gathered intelligence about a GitHub repository and produce "
        "a structured threat assessment for offensive security research."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "threat_narrative": {
                "type": "string",
                "description": (
                    "2-4 sentence executive summary of the repository's attack potential, "
                    "considering CVE history, technology stack, and recent commit activity."
                ),
            },
            "key_findings": {
                "type": "array",
                "items": {"type": "string"},
                "description": "3-5 specific observations that make this target notable to a security researcher.",
            },
            "recommended_focus_areas": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific components, subsystems, or code paths to prioritize during a security audit, "
                    "inferred from CVE patterns, suspicious commit activity, and the technology stack."
                ),
            },
            "attack_vectors": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Most likely attack vectors based on language, CVE history, and commit patterns.",
            },
        },
        "required": ["threat_narrative", "key_findings", "recommended_focus_areas", "attack_vectors"],
    },
}


def _claude_analyze(
    client:    anthropic.Anthropic,
    model:     str,
    state:     _IntelState,
) -> dict[str, Any]:
    ri  = state.repo_info
    cs  = state.cve_summary

    lines: list[str] = [
        f"Repository:   {state.owner}/{state.repo}",
        f"Language:     {ri.get('language', 'unknown')}",
        f"Stars:        {ri.get('stargazers', 0)}",
        f"Description:  {ri.get('description', 'N/A')}",
        f"Topics:       {', '.join(ri.get('topics', [])) or 'none'}",
        "",
        "== CVE History ==",
        f"Total advisories/CVEs: {cs.get('total', 0)}",
        f"Severity breakdown:    {cs.get('severity_dist', {})}",
        f"Last CVE date:         {cs.get('last_cve_date', 'none')}",
        f"Cold target (>2y):     {cs.get('is_cold_target', False)}",
    ]

    if state.advisories:
        lines.append("\nRecent advisories:")
        for adv in state.advisories[:5]:
            lines.append(
                f"  [{adv.get('severity','?')}] {adv.get('ghsa_id','')} / "
                f"{adv.get('cve_id','')} — {adv.get('summary','')[:120]}"
            )

    if state.osv_vulns:
        lines.append("\nOSV vulnerabilities:")
        for v in state.osv_vulns[:5]:
            lines.append(f"  [{v.get('severity','?')}] {v.get('id','')} — {v.get('summary','')[:100]}")

    if state.suspicious_commits:
        lines.append(f"\nSuspicious commits ({len(state.suspicious_commits)} flagged):")
        for c in state.suspicious_commits[:5]:
            kw    = ", ".join(c.get("security_keywords", [])[:5])
            files = ", ".join(c.get("files", [])[:3])
            lines.append(f"  [{c.get('date','')[:10]}] {c.get('message','')[:80]}")
            lines.append(f"    keywords: {kw}" + (f"  |  files: {files}" if files else ""))

    if state.dep_vulns:
        lines.append(f"\nVulnerable dependencies ({len(state.dep_vulns)}):")
        for dv in state.dep_vulns[:5]:
            lines.append(
                f"  [{dv.get('severity','?')}] {dv['package']}@{dv['version']}  "
                f"{dv.get('vuln_id','')} — {dv.get('summary','')[:80]}"
            )

    lines += [
        "",
        f"Attack surface score: {state.score}/10  →  {state.recommendation}",
        f"Score breakdown: {state.score_breakdown}",
    ]

    prompt = (
        "You are a senior offensive security researcher evaluating a target for a legitimate "
        "authorized security audit. Based on the intelligence data below, call `intel_assessment` "
        "with your threat analysis.\n\n" + "\n".join(lines)
    )

    response = client.messages.create(
        model=model,
        max_tokens=2048,
        tools=[_INTEL_TOOL],
        tool_choice={"type": "tool", "name": "intel_assessment"},
        messages=[{"role": "user", "content": prompt}],
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "intel_assessment":
            return block.input  # type: ignore[return-value]
    return {}


# ---------------------------------------------------------------------------
# Report building + saving
# ---------------------------------------------------------------------------

def _build_report(s: _IntelState) -> dict[str, Any]:
    return {
        "scanner":   "glasswing-intel",
        "version":   "1.0.0",
        "timestamp": s.timestamp,
        "target":    s.target_url,
        "owner":     s.owner,
        "repo":      s.repo,
        "repo_info": s.repo_info,
        "phase1_historical_cves": {
            "summary":    s.cve_summary,
            "advisories": s.advisories,
            "osv_vulns":  s.osv_vulns,
            "nvd_vulns":  s.nvd_vulns,
        },
        "phase2_commit_analysis": {
            "commits_analyzed":  s.commits_analyzed,
            "suspicious_count":  len(s.suspicious_commits),
            "suspicious_commits": s.suspicious_commits,
        },
        "phase3_dependency_fingerprint": {
            "manifests_found":        s.manifests_found,
            "total_dependencies":     len(s.dependencies),
            "vulnerable_count":       len(s.dep_vulns),
            "dep_vulnerabilities":    s.dep_vulns,
        },
        "phase4_attack_surface": {
            "score":          s.score,
            "breakdown":      s.score_breakdown,
            "recommendation": s.recommendation,
        },
        "phase5_intel": {
            "threat_narrative":        s.threat_narrative,
            "key_findings":            s.key_findings,
            "recommended_focus_areas": s.recommended_focus_areas,
            "attack_vectors":          s.attack_vectors,
        },
    }


def _save_report(report: dict, owner: str, repo: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = output_dir / f"intel_{owner}_{repo}_{date_str}.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty() and (os.name != "nt" or os.environ.get("TERM") not in (None, ""))

_R    = "\033[0m"
_BOLD = "\033[1m"
_DIM  = "\033[2m"
_RED  = "\033[91m"
_YEL  = "\033[93m"
_CYN  = "\033[96m"
_GRN  = "\033[92m"


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOR:
        return text
    return "".join(codes) + text + _R


_SEV_COLOR = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "MEDIUM":   _YEL,
    "LOW":      _CYN,
    "UNKNOWN":  _DIM,
}

_REC_COLOR = {
    "HUNT":        _RED + _BOLD,
    "INVESTIGATE": _YEL,
    "SKIP":        _GRN,
}

_HR_WIDTH = 72


def _hr() -> str:
    return "─" * _HR_WIDTH


def _bar(n: int, max_n: int, width: int = 20) -> str:
    if max_n == 0 or n == 0:
        return ""
    return "█" * max(1, round(n / max_n * width))


def print_intel_report(report: dict[str, Any]) -> None:
    """Render an intel report dict to stdout."""
    ri  = report.get("repo_info", {})
    p1  = report.get("phase1_historical_cves", {})
    p2  = report.get("phase2_commit_analysis", {})
    p3  = report.get("phase3_dependency_fingerprint", {})
    p4  = report.get("phase4_attack_surface", {})
    p5  = report.get("phase5_intel", {})
    cs  = p1.get("summary", {})

    # ── Header ──────────────────────────────────────────────────────────
    print(_hr())
    target_label = f"{report.get('owner','')}/{report.get('repo','')}"
    print(_c(f" GLASSWING INTEL — {target_label}", _BOLD))
    print(_hr())
    print(f"  {'Target':<14}{report.get('target','—')}")
    lang_bonus = _LANG_SCORES.get(ri.get("language", ""), ("", 0))[1]
    lang_str   = ri.get("language", "?")
    if lang_bonus:
        lang_str += f"  (attack surface +{lang_bonus})"
    print(f"  {'Language':<14}{lang_str}")
    print(f"  {'Activity':<14}{ri.get('stargazers',0):,} stars  ·  {ri.get('forks',0):,} forks  ·  {ri.get('open_issues',0)} open issues")
    if ri.get("description"):
        print(f"  {'Description':<14}{ri['description'][:68]}")
    print(f"  {'Last push':<14}{(ri.get('pushed_at') or '?')[:10]}")

    # ── Phase 1: CVE History ─────────────────────────────────────────────
    total_cves = cs.get("total", 0)
    print(_hr())
    print(_c(" CVE HISTORY", _BOLD) + f"{'':>56}" + _c(f"{total_cves} found", _BOLD))
    print(_hr())

    sev_dist = cs.get("severity_dist", {})
    max_sev  = max(sev_dist.values(), default=1) or 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sev_dist.get(sev, 0)
        if count == 0:
            continue
        bar = _bar(count, max_sev)
        col = _SEV_COLOR.get(sev, "")
        print(f"  {_c(f'{sev:<10}', col)}{_c(bar, col):<30}  {count}")

    if cs.get("last_cve_date"):
        cold_tag = "  (cold — lower priority)" if cs.get("is_cold_target") else "  (active attack surface)"
        print(f"  {'Last CVE':<14}{cs['last_cve_date'][:10]}{_c(cold_tag, _DIM)}")
    elif total_cves == 0:
        print(f"  {_c('No CVEs found in OSV.dev or GitHub Advisory Database.', _DIM)}")

    for adv in (p1.get("advisories") or [])[:3]:
        col = _SEV_COLOR.get(adv.get("severity", ""), "")
        print(
            f"  {_c('[' + adv.get('severity','?') + ']', col):<20}"
            f"  {adv.get('ghsa_id','')}  {adv.get('summary','')[:52]}"
        )

    # NVD sub-section
    nvd_vulns = p1.get("nvd_vulns", [])
    nvd_count = cs.get("nvd_count", 0)
    if nvd_count or nvd_vulns:
        n_crit = sum(1 for v in nvd_vulns if _nvd_cvss_severity(v.get("cvss_score")) == "CRITICAL")
        n_high = sum(1 for v in nvd_vulns if _nvd_cvss_severity(v.get("cvss_score")) == "HIGH")
        sev_tag = ""
        if n_crit or n_high:
            parts = []
            if n_crit:
                parts.append(_c(f"{n_crit} critical", _RED + _BOLD))
            if n_high:
                parts.append(_c(f"{n_high} high", _RED))
            sev_tag = "  (" + ", ".join(parts) + ")"
        print(f"  {'NVD CVEs':<14}{nvd_count} found{sev_tag}")
        if nvd_vulns:
            most_recent = max(nvd_vulns, key=lambda v: v.get("published", ""), default=None)
            if most_recent:
                score_str = (
                    f"CVSS {most_recent['cvss_score']:.1f}"
                    if most_recent.get("cvss_score") is not None
                    else "no CVSS"
                )
                pub = (most_recent.get("published") or "")[:10]
                print(
                    f"  {'Most recent':<14}"
                    f"{_c(most_recent['id'], _BOLD)}  "
                    f"({score_str}, {pub})"
                )

    # ── Phase 2: Suspicious Commits ──────────────────────────────────────
    suspicious = p2.get("suspicious_commits", [])
    analyzed   = p2.get("commits_analyzed", 0)
    print(_hr())
    print(
        _c(" RECENT COMMITS", _BOLD)
        + f"{'':>42}"
        + _c(f"{analyzed} analyzed, {len(suspicious)} flagged", _BOLD)
    )
    print(_hr())

    if suspicious:
        for c in suspicious[:5]:
            kw_str = ", ".join((c.get("security_keywords") or [])[:5])
            print(f"  {_c((c.get('date') or '')[:10], _DIM)}  {c.get('message','')[:62]}")
            print(f"  {'':>14}{_c('keywords: ' + kw_str, _YEL)}")
            if c.get("files"):
                print(f"  {'':>14}{_c('files: ' + ', '.join(c['files'][:3]), _DIM)}")
    else:
        print(f"  {_c('No security-sensitive commits detected.', _DIM)}")

    # ── Phase 3: Dependencies ────────────────────────────────────────────
    dep_vuln_count = p3.get("vulnerable_count", 0)
    total_deps     = p3.get("total_dependencies", 0)
    manifests      = p3.get("manifests_found", [])
    print(_hr())
    print(
        _c(" DEPENDENCY FINGERPRINT", _BOLD)
        + f"{'':>34}"
        + _c(f"{total_deps} deps, {dep_vuln_count} vulns", _BOLD)
    )
    print(_hr())

    if manifests:
        print(f"  {'Manifests':<14}{', '.join(manifests)}")
        print(f"  {'Total deps':<14}{total_deps}")
        if dep_vuln_count:
            print(f"  {'Vulns':<14}{_c(str(dep_vuln_count) + ' found', _YEL)}")
            for dv in (p3.get("dep_vulnerabilities") or [])[:4]:
                col = _SEV_COLOR.get(dv.get("severity", ""), "")
                print(
                    f"    {_c('[' + dv.get('severity','?') + ']', col):<20}"
                    f"  {dv['package']}@{dv.get('version','?')}  "
                    f"{_c(dv.get('vuln_id',''), _DIM)}"
                )
        else:
            print(f"  {_c('No vulnerable dependencies found.', _GRN)}")
    else:
        print(f"  {_c('No supported manifest files found in repo root.', _DIM)}")

    # ── Phase 4: Attack Surface Score ────────────────────────────────────
    score       = p4.get("score", 0)
    rec         = p4.get("recommendation", "SKIP")
    rec_col     = _REC_COLOR.get(rec, "")
    breakdown   = p4.get("breakdown", {})
    print(_hr())
    print(_c(" ATTACK SURFACE SCORE", _BOLD))
    print(_hr())

    for label, val in breakdown.items():
        print(f"  {label:<42}  +{val}")
    print(f"  {'─' * 46}")
    score_bar = "█" * score + _c("░" * (10 - score), _DIM)
    print(f"  {'TOTAL':<42}  {score}/10  {score_bar}  {_c(rec, rec_col)}")

    # ── Phase 5: Claude Threat Assessment ───────────────────────────────
    if p5.get("threat_narrative"):
        print(_hr())
        print(_c(" THREAT ASSESSMENT", _BOLD))
        print(_hr())
        for line in textwrap.wrap(p5["threat_narrative"], width=68):
            print(f"  {line}")
        if p5.get("key_findings"):
            print(f"\n  {_c('Key Findings:', _BOLD)}")
            for kf in p5["key_findings"]:
                print(f"  • {kf}")
        if p5.get("recommended_focus_areas"):
            print(f"\n  {_c('Focus Areas:', _BOLD)}")
            for fa in p5["recommended_focus_areas"]:
                print(f"  • {fa}")
        if p5.get("attack_vectors"):
            print(f"\n  {_c('Attack Vectors:', _BOLD)}")
            for av in p5["attack_vectors"]:
                print(f"  • {av}")

    print(_hr())


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class IntelGatherer:
    def __init__(
        self,
        target_url: str,
        model:      str  = DEFAULT_MODEL,
        verbose:    bool = False,
        output_dir: Path = REPORTS_DIR,
    ) -> None:
        self.owner, self.repo = parse_github_url(target_url)
        self.target_url = f"https://github.com/{self.owner}/{self.repo}"
        self.model      = model
        self.verbose    = verbose
        self.output_dir = output_dir

    def _log(self, msg: str) -> None:
        print(msg, flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}", flush=True)

    def run(self) -> dict[str, Any]:
        s      = _IntelState(target_url=self.target_url, owner=self.owner, repo=self.repo)
        client = anthropic.Anthropic()

        # ── Phase 1: Repo info + historical CVEs ─────────────────────────
        self._log(f"[*] Fetching repo metadata: {self.owner}/{self.repo} …")
        s.repo_info = _fetch_repo_info(self.owner, self.repo)
        language = s.repo_info.get("language", "")
        branch   = s.repo_info.get("default_branch", "main")
        self._vlog(f"Language={language}  Branch={branch}  Stars={s.repo_info.get('stargazers',0)}")

        # Get latest commit SHA for OSV commit-based query
        raw_head = _github_get(f"/repos/{self.owner}/{self.repo}/commits", {"per_page": "1"})
        latest_sha = (raw_head[0].get("sha", "") if isinstance(raw_head, list) and raw_head else "")

        self._log("[*] Querying GitHub Advisory Database …")
        s.advisories = _fetch_github_advisories(self.owner, self.repo, language)
        self._vlog(f"{len(s.advisories)} GitHub advisory(s)")

        self._log("[*] Querying OSV.dev …")
        s.osv_vulns  = _fetch_osv_cves(self.owner, self.repo, language, latest_sha)
        self._vlog(f"{len(s.osv_vulns)} OSV vulnerability(s)")

        self._log("[*] Querying NVD …")
        raw_nvd = query_nvd(self.owner, self.repo)
        # Deduplicate: drop NVD entries already covered by OSV/GitHub advisories
        known_cve_ids: set[str] = set()
        for v in s.osv_vulns:
            if v["id"].startswith("CVE-"):
                known_cve_ids.add(v["id"])
            known_cve_ids.update(a for a in v.get("aliases", []) if a.startswith("CVE-"))
        for adv in s.advisories:
            if adv.get("cve_id"):
                known_cve_ids.add(adv["cve_id"])
        s.nvd_vulns = [v for v in raw_nvd if v["id"] not in known_cve_ids]
        self._vlog(f"{len(raw_nvd)} NVD result(s), {len(s.nvd_vulns)} new after dedup")

        s.cve_summary = _build_cve_summary(s.advisories, s.osv_vulns, s.nvd_vulns)
        cs = s.cve_summary
        sev = cs["severity_dist"]
        self._log(
            f"    {cs['total']} CVE(s)  "
            f"CRIT={sev.get('CRITICAL',0)}  HIGH={sev.get('HIGH',0)}  "
            f"MED={sev.get('MEDIUM',0)}  LOW={sev.get('LOW',0)}  "
            f"(NVD: {cs.get('nvd_count', 0)})"
        )
        if cs.get("is_cold_target"):
            self._log("    [!] Cold target — last CVE > 2 years ago, lower priority")

        # ── Phase 2: Commit analysis ──────────────────────────────────────
        self._log(f"[*] Fetching last {COMMIT_LIMIT} commits …")
        commits = _fetch_commits(self.owner, self.repo)
        s.commits_analyzed = len(commits)
        self._vlog(f"{len(commits)} commits fetched")

        self._log("[*] Scanning commits for security-sensitive patterns …")
        s.suspicious_commits = _analyze_commits(self.owner, self.repo, commits)
        self._log(f"    {len(s.suspicious_commits)} suspicious commit(s) flagged")
        for c in s.suspicious_commits[:3]:
            self._vlog(f"  [{c.get('date','')[:10]}] {c.get('message','')[:60]}")

        # ── Phase 3: Dependency fingerprint ──────────────────────────────
        self._log("[*] Detecting dependency manifests …")
        manifests = _fetch_manifest_files(self.owner, self.repo, branch)
        s.manifests_found = list(manifests.keys())
        self._vlog(f"Found: {s.manifests_found or 'none'}")

        if manifests:
            self._log(f"[*] Parsing {len(manifests)} manifest(s) + querying OSV.dev …")
            s.dependencies, s.dep_vulns = _fingerprint_dependencies(manifests)
            self._log(
                f"    {len(s.dependencies)} dep(s) parsed, "
                f"{len(s.dep_vulns)} vulnerable"
            )
        else:
            self._log("    No supported manifest files in repo root.")

        # ── Phase 4: Score ────────────────────────────────────────────────
        self._log("[*] Computing attack surface score …")
        s.score, s.score_breakdown, s.recommendation = _compute_score(
            language           = language,
            cve_summary        = s.cve_summary,
            suspicious_commits = s.suspicious_commits,
            dep_vulns          = s.dep_vulns,
            last_push          = s.repo_info.get("pushed_at", ""),
            nvd_vulns          = s.nvd_vulns,
        )
        self._log(f"    Score: {s.score}/10  →  {s.recommendation}")

        # ── Phase 5: Claude ───────────────────────────────────────────────
        self._log("[*] Requesting Claude threat assessment …")
        claude_out = _claude_analyze(client, self.model, s)
        s.threat_narrative        = claude_out.get("threat_narrative", "")
        s.key_findings            = claude_out.get("key_findings", [])
        s.recommended_focus_areas = claude_out.get("recommended_focus_areas", [])
        s.attack_vectors          = claude_out.get("attack_vectors", [])

        # ── Save + print ──────────────────────────────────────────────────
        report_dict = _build_report(s)
        out_path    = _save_report(report_dict, self.owner, self.repo, self.output_dir)
        self._log(f"\n[+] Report saved → {out_path}\n")
        print_intel_report(report_dict)

        return report_dict


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> "argparse.ArgumentParser":
    import argparse
    parser = argparse.ArgumentParser(
        prog="glasswing-intel",
        description="Pre-scan intelligence gathering for GitHub repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/intel.py --target https://github.com/google/kafel\n"
            "  python src/intel.py --target google/kafel --verbose\n"
        ),
    )
    parser.add_argument("--target", "-t", required=True, metavar="URL",
                        help="GitHub repository URL or owner/repo.")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Claude model (default: {DEFAULT_MODEL}).")
    parser.add_argument("--output-dir", default=str(REPORTS_DIR), metavar="DIR",
                        help=f"Directory for reports (default: {REPORTS_DIR}).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print detailed progress.")
    return parser


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = _build_arg_parser()
    args   = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 1

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
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
