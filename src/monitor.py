#!/usr/bin/env python
"""
Glasswing Continuous Monitor — watches repositories for security-relevant commits.

Pipeline (one sweep)
--------------------
1. Load target database from configs/targets.json (created on first run).
2. For each active target, fetch commits since last_commit_seen via GitHub API.
3. Score each commit CRITICAL / HIGH / MEDIUM / LOW based on message keywords
   and touched file patterns.
4. Fire alerts for CRITICAL and HIGH commits: print to terminal, append to
   reports/alerts_YYYY-MM-DD.json.
5. For CRITICAL commits (when --auto-qualify is set), run intel gathering and
   prompt the operator to escalate to a full scan.
6. Persist updated last_commit_seen and save a daily summary report.

GitHub API is used without authentication (60 req/hour public limit).
Rate spend per sweep: 1 request per target for commit list + up to
DETAIL_LIMIT requests per target for file lists.

Only stdlib + anthropic are used.

Usage
-----
    python glasswing.py monitor --run-once
    python glasswing.py monitor --watch
    python glasswing.py monitor --status
    python glasswing.py monitor --add-target https://github.com/org/repo \\
                                --lang c --priority high
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_API     = "https://api.github.com"
HTTP_TIMEOUT   = 20
COMMIT_LIMIT   = 20    # max commits fetched per target per sweep
DETAIL_LIMIT   = 5     # max commit-detail requests per target per sweep
DEFAULT_MODEL  = "claude-sonnet-4-20250514"
DEFAULT_INTERVAL_HOURS = 6
STALE_SCAN_DAYS        = 30    # flag targets not full-scanned within this window
ALERT_SCORES           = {"CRITICAL", "HIGH"}

# ---------------------------------------------------------------------------
# Default target database
# ---------------------------------------------------------------------------

DEFAULT_TARGETS: list[dict[str, Any]] = [
    {
        "repo":             "cilium/cilium",
        "lang":             "go",
        "priority":         "critical",
        "last_commit_seen": None,
        "last_scan":        None,
        "findings_count":   0,
        "status":           "active",
    },
    {
        "repo":             "openssh/openssh-portable",
        "lang":             "c",
        "priority":         "critical",
        "last_commit_seen": None,
        "last_scan":        None,
        "findings_count":   0,
        "status":           "active",
    },
    {
        "repo":             "opencontainers/runc",
        "lang":             "go",
        "priority":         "critical",
        "last_commit_seen": None,
        "last_scan":        None,
        "findings_count":   0,
        "status":           "active",
    },
    {
        "repo":             "systemd/systemd",
        "lang":             "c",
        "priority":         "high",
        "last_commit_seen": None,
        "last_scan":        None,
        "findings_count":   0,
        "status":           "active",
    },
    {
        "repo":             "haproxy/haproxy",
        "lang":             "c",
        "priority":         "high",
        "last_commit_seen": None,
        "last_scan":        None,
        "findings_count":   0,
        "status":           "active",
    },
]

# ---------------------------------------------------------------------------
# Commit-scoring patterns
# ---------------------------------------------------------------------------

# Explicit high-severity signals in the commit message
_MSG_CRITICAL_RE = re.compile(
    r"\bCVE-\d{4}-\d+\b"
    r"|\b(?:RCE|remote[- ]code[- ]exec(?:ution)?|arbitrary[- ]code"
    r"|privilege[- ]escalat|privesc"
    r"|sandbox[- ]escap|container[- ]escap|namespace[- ]escap"
    r"|auth(?:entication)?[- ]bypass"
    r"|zero[- ]day|0day"
    r"|heap[- ]overflow|stack[- ]overflow"
    r"|use[- ]after[- ]free|double[- ]free)\b",
    re.IGNORECASE,
)

# Broader security signals (trigger MEDIUM, escalate to HIGH with files)
_MSG_SECURITY_RE = re.compile(
    r"\b(?:vuln|exploit|overflow|inject|bypass|escalat"
    r"|secur|fix(?:es|ed)?\s+(?:bug|issue|flaw|crash)"
    r"|patch|sanitize|sanitise|harden"
    r"|out[- ]of[- ]bound|oob|uaf|heap"
    r"|path[- ]travers|buffer|alloc|parse"
    r"|auth(?:entic|oriz)|crypto|cipher|tls|ssl|cert"
    r"|permission|privilege|capability|setuid|setgid"
    r"|namespace|seccomp|ebpf|bpf|syscall)\b",
    re.IGNORECASE,
)

# Filename / path component patterns indicating security-sensitive code
_FILE_NAME_RE = re.compile(
    r"(?:^|[/_\-\.])(?:"
    r"auth(?:entic|oriz)?|cred(?:ential)?|"
    r"crypto|cipher|hash|sign|cert|tls|ssl|hmac|"
    r"pars(?:e|er|ing)|"
    r"buffer|overflow|alloc|malloc|heap|mem(?:ory)?|"
    r"exec|shell|command|spawn|"
    r"priv(?:ilege)?|capability|cap_|setuid|setgid|"
    r"sandbox|escape|bypass|"
    r"kernel|syscall|seccomp|ebpf|bpf|"
    r"token|secret|key(?:s|ring)?|passw(?:ord|d)|"
    r"acl|rbac|policy|permiss|"
    r"inject|filter|sanitize|"
    r"namespace|container|"
    r"mutex|lock|race"
    r")(?:[_\-\.\s/]|$)",
    re.IGNORECASE,
)

# Directory path patterns
_DIR_PATH_RE = re.compile(
    r"(?:^|/)(?:"
    r"security|auth|crypto|tls|ssl"
    r"|kern(?:el)?|bpf|ebpf|syscall"
    r"|privilege|sandbox|escape"
    r"|credential|token|secret"
    r"|policy|acl|permission"
    r")/",
    re.IGNORECASE,
)

# File extensions where security bugs have high impact
_SEC_EXTENSIONS = {".c", ".h", ".S", ".go", ".rs", ".cpp", ".cc", ".hpp", ".cxx"}

# Languages where memory-safety bugs are most critical
_HIGH_IMPACT_LANGS = {"c", "cpp", "c++", "rust", "asm"}

_SCORE_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ---------------------------------------------------------------------------
# GitHub API helper (module-level, mirrors intel.py)
# ---------------------------------------------------------------------------


def _gh_get(path: str, params: dict | None = None) -> Any:
    """GET from the GitHub API. Returns parsed JSON or None on any error."""
    url = f"{GITHUB_API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "glasswing-scanner/1.0")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return {"_rate_limited": True}
        return None
    except Exception:
        return None


def _parse_repo(raw: str) -> tuple[str, str]:
    """
    Extract (owner, repo) from a GitHub URL or 'owner/repo' shorthand.
    Raises ValueError if the format is not recognised.
    """
    raw = raw.strip().rstrip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    m = re.search(r"github\.com[:/]([^/\s]+)/([^/\s#?]+)", raw)
    if m:
        return m.group(1), m.group(2)
    parts = [p for p in raw.split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    raise ValueError(
        f"Cannot parse repository from {raw!r}. "
        "Expected 'owner/repo' or 'https://github.com/owner/repo'."
    )


# ---------------------------------------------------------------------------
# Commit scoring (pure function, easily testable)
# ---------------------------------------------------------------------------


def score_commit(
    message: str,
    files: list[str],
    lang: str,
) -> tuple[str, list[str]]:
    """
    Return (score, reasons) for a single commit.

    Score is one of CRITICAL / HIGH / MEDIUM / LOW.
    Reasons is a list of human-readable strings explaining the score.
    ``files`` may be empty when commit details could not be fetched —
    in that case scoring is based on the message alone.
    """
    score   = "LOW"
    reasons: list[str] = []

    has_cve      = bool(re.search(r"\bCVE-\d{4}-\d+\b", message, re.IGNORECASE))
    crit_match   = _MSG_CRITICAL_RE.search(message)
    sec_match    = _MSG_SECURITY_RE.search(message)

    # ── Message-level scoring ────────────────────────────────────────────
    if crit_match:
        score = "HIGH"
        reasons.append(f"critical keyword in message: {crit_match.group(0)!r}")
    elif sec_match:
        score = "MEDIUM"
        reasons.append(f"security keyword in message: {sec_match.group(0)!r}")

    if not files:
        # Without file data we cap at HIGH regardless of keywords
        return score, reasons

    # ── File-level scoring ───────────────────────────────────────────────
    sec_files  = [f for f in files if _FILE_NAME_RE.search(f) or _DIR_PATH_RE.search(f)]
    lang_files = [f for f in files if Path(f).suffix.lower() in _SEC_EXTENSIONS]
    is_sys     = lang.lower() in _HIGH_IMPACT_LANGS

    if sec_files:
        reasons.append(
            "touches security-sensitive files: "
            + ", ".join(sec_files[:3])
            + (f" (+{len(sec_files)-3} more)" if len(sec_files) > 3 else "")
        )
        if is_sys and lang_files:
            score = "CRITICAL"
            reasons.append(f"security-sensitive {lang.upper()} code modified")
        elif _SCORE_ORDER.get(score, 99) > _SCORE_ORDER["HIGH"]:
            score = "HIGH"

    elif lang_files and is_sys and score in ("MEDIUM", "HIGH"):
        # Systems-language files changed + security keyword in message
        score = "HIGH"
        reasons.append(
            f"modified {lang.upper()} files: " + ", ".join(lang_files[:3])
        )

    # CVE reference + any file evidence → CRITICAL
    if has_cve and (sec_files or lang_files):
        score = "CRITICAL"
        if not any("CVE" in r for r in reasons):
            reasons.insert(0, "CVE reference combined with security file changes")

    return score, reasons


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class ContinuousMonitor:
    """
    Watches a set of GitHub repositories for security-relevant commits,
    scores them, fires alerts, and optionally escalates to intel gathering.
    """

    def __init__(
        self,
        configs_dir: str | Path = "configs",
        reports_dir: str | Path = "reports",
        model: str = DEFAULT_MODEL,
        verbose: bool = False,
        auto_qualify: bool = False,
    ) -> None:
        self.configs_dir  = Path(configs_dir).resolve()
        self.reports_dir  = Path(reports_dir).resolve()
        self.db_path      = self.configs_dir / "targets.json"
        self.model        = model
        self.verbose      = verbose
        self.auto_qualify = auto_qualify

        self.configs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        print(msg, flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}", flush=True)

    def _err(self, msg: str) -> None:
        print(f"[!] {msg}", flush=True, file=sys.stderr)

    # ------------------------------------------------------------------
    # Target database
    # ------------------------------------------------------------------

    def _default_db(self) -> dict[str, Any]:
        return {
            "check_interval_hours": DEFAULT_INTERVAL_HOURS,
            "last_run": None,
            "targets": DEFAULT_TARGETS,
        }

    def load_db(self) -> dict[str, Any]:
        """Load targets.json, creating it with defaults if absent."""
        if not self.db_path.is_file():
            db = self._default_db()
            self._save_db_atomic(db)
            self._log(f"[*] Created target database at {self.db_path}")
            self._log(f"    Pre-populated with {len(db['targets'])} default target(s).")
            return db
        try:
            return json.loads(self.db_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self._err(f"Could not load {self.db_path}: {exc} — using defaults.")
            return self._default_db()

    def _save_db_atomic(self, db: dict[str, Any]) -> None:
        """Write targets.json atomically via a temp file."""
        tmp = self.db_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.db_path)

    def save_db(self, db: dict[str, Any]) -> None:
        """Persist the database to disk."""
        db["last_run"] = datetime.now(timezone.utc).isoformat()
        self._save_db_atomic(db)

    # ------------------------------------------------------------------
    # Commit fetching
    # ------------------------------------------------------------------

    def _fetch_commits(self, owner: str, repo: str, last_sha: str | None) -> list[dict]:
        """
        Return commits newer than last_sha (newest first, up to COMMIT_LIMIT).
        If last_sha is None, returns the latest COMMIT_LIMIT commits for bootstrap.
        """
        data = _gh_get(
            f"/repos/{owner}/{repo}/commits",
            params={"per_page": COMMIT_LIMIT},
        )
        if not data or not isinstance(data, list):
            if isinstance(data, dict) and data.get("_rate_limited"):
                self._err(f"GitHub API rate limit reached — skipping {owner}/{repo}")
            return []

        commits: list[dict] = []
        for c in data:
            sha = c.get("sha", "")
            if sha == last_sha:
                break   # reached the last-seen boundary
            commit_obj = c.get("commit", {})
            author_obj = commit_obj.get("author", {})
            commits.append({
                "sha":     sha,
                "message": commit_obj.get("message", "").splitlines()[0][:250],
                "author":  author_obj.get("name", "unknown"),
                "date":    author_obj.get("date", ""),
                "url":     c.get("html_url", ""),
            })

        return commits   # newest first

    def _fetch_files(self, owner: str, repo: str, sha: str) -> list[str]:
        """Return the list of filenames touched by a commit."""
        data = _gh_get(f"/repos/{owner}/{repo}/commits/{sha}")
        if not data or not isinstance(data, dict):
            return []
        return [f.get("filename", "") for f in data.get("files", []) if f.get("filename")]

    # ------------------------------------------------------------------
    # Alert output
    # ------------------------------------------------------------------

    def _alert_line(self, width: int = 72) -> str:
        return "━" * width

    def _print_alert(
        self,
        target: dict,
        commit: dict,
        score: str,
        reasons: list[str],
        files: list[str],
    ) -> None:
        """Print a formatted alert to the terminal."""
        try:
            from glasswing import _c, _BOLD, _RED, _YELLOW, _CYAN, _DIM  # type: ignore
        except ImportError:
            def _c(t: str, *_: str) -> str: return t  # type: ignore[misc]
            _BOLD = _RED = _YELLOW = _CYAN = _DIM = ""

        _SCORE_COLOR = {
            "CRITICAL": _RED + _BOLD,
            "HIGH":     _RED,
            "MEDIUM":   _YELLOW,
            "LOW":      _CYAN,
        }
        color = _SCORE_COLOR.get(score, "")

        print("")
        print(_c(self._alert_line(), color))
        print(_c(f" [{score} ALERT]  {target['repo']}", color + _BOLD))
        print(_c(self._alert_line(), color))
        sha_short = commit["sha"][:12]
        date_str  = commit.get("date", "")[:19].replace("T", " ")
        print(f"  {'Repo':<12}{target['repo']}")
        print(f"  {'Commit':<12}{sha_short}  ({date_str} UTC)")
        print(f"  {'Author':<12}{commit['author']}")
        print(f"  {'Message':<12}{commit['message'][:80]}")
        if files:
            shown = files[:5]
            extra = len(files) - len(shown)
            print(f"  {'Files':<12}{', '.join(shown)}" +
                  (f"  (+{extra} more)" if extra else ""))
        print(f"  {'Score':<12}{_c(score, color)}")
        for r in reasons:
            print(f"  {'Reason':<12}{r}")
        print(f"\n  {'Next action':<12}"
              f"python glasswing.py intel --target {target['repo']}")
        print(_c(self._alert_line(), color))

    def _build_alert_record(
        self,
        target: dict,
        commit: dict,
        score: str,
        reasons: list[str],
        files: list[str],
    ) -> dict[str, Any]:
        return {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "repo":       target["repo"],
            "lang":       target["lang"],
            "priority":   target["priority"],
            "commit_sha": commit["sha"],
            "commit_msg": commit["message"],
            "author":     commit["author"],
            "commit_date": commit.get("date", ""),
            "commit_url": commit.get("url", ""),
            "files":      files,
            "score":      score,
            "reasons":    reasons,
            "next_action": f"python glasswing.py intel --target {target['repo']}",
        }

    def _append_alerts(self, new_alerts: list[dict]) -> Path:
        """Load today's alerts file, append new_alerts, save, and return path."""
        date_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        alert_path = self.reports_dir / f"alerts_{date_str}.json"

        existing: list[dict] = []
        if alert_path.is_file():
            try:
                existing = json.loads(alert_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

        all_alerts = existing + new_alerts
        alert_path.write_text(
            json.dumps(all_alerts, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return alert_path

    # ------------------------------------------------------------------
    # Auto-qualify (Intel escalation)
    # ------------------------------------------------------------------

    def _auto_qualify(self, target: dict) -> None:
        """
        Run intel gathering for a CRITICAL commit's repository.
        If the intel score is >= 7, prompt to escalate to a full scan.
        """
        if not os.environ.get("ANTHROPIC_API_KEY"):
            self._err("ANTHROPIC_API_KEY not set — skipping auto-qualify.")
            return

        repo = target["repo"]
        self._log(f"\n[*] Auto-qualifying {repo} via intel gathering …")
        try:
            from src.intel import IntelGatherer  # type: ignore
            gatherer = IntelGatherer(
                target_url=f"https://github.com/{repo}",
                model=self.model,
                verbose=self.verbose,
                output_dir=self.reports_dir,
            )
            report = gatherer.run()
            intel_score = report.get("score", 0)
            rec         = report.get("recommendation", "SKIP")
            self._log(
                f"\n    Intel score: {intel_score}/10  ({rec})"
            )

            if intel_score >= 7:
                self._log(
                    f"    Intel score is {intel_score}/10 — this target is in HUNT territory."
                )
                try:
                    answer = input(
                        f"\n    Run full scan on {repo}? (y/n): "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"

                if answer == "y":
                    self._log(
                        f"    Run: python glasswing.py scan --target ./{repo.split('/')[-1]}"
                    )
                else:
                    self._log("    Skipping full scan.")
        except Exception as exc:
            self._err(f"Auto-qualify failed for {repo}: {exc}")

    # ------------------------------------------------------------------
    # Per-target sweep
    # ------------------------------------------------------------------

    def check_target(self, target: dict) -> tuple[list[dict], int]:
        """
        Process one target for new commits.
        Returns (alert_records, commits_processed).
        """
        repo = target.get("repo", "")
        if not repo or target.get("status") != "active":
            return [], 0

        try:
            owner, repo_name = _parse_repo(repo)
        except ValueError as exc:
            self._err(str(exc))
            return [], 0

        last_sha = target.get("last_commit_seen")

        # Bootstrap: first time we see this target
        if last_sha is None:
            self._vlog(f"bootstrapping {repo} …")
            commits = self._fetch_commits(owner, repo_name, last_sha=None)
            if commits:
                target["last_commit_seen"] = commits[0]["sha"]
                self._log(
                    f"    [bootstrap] {repo}: pinned at "
                    f"{commits[0]['sha'][:12]} — no alerts on first run."
                )
            return [], 0

        # Normal run: fetch commits newer than last_sha
        self._vlog(f"checking {repo} since {last_sha[:12]} …")
        commits = self._fetch_commits(owner, repo_name, last_sha)

        if not commits:
            self._vlog(f"  no new commits.")
            return [], 0

        self._vlog(f"  {len(commits)} new commit(s).")

        alert_records: list[dict] = []
        detail_fetches = 0

        for commit in commits:
            files: list[str] = []

            # Fetch file list for high-signal commits (rate-limit-aware)
            if detail_fetches < DETAIL_LIMIT:
                # Always fetch if message has any security signal (cheap pre-filter)
                if _MSG_SECURITY_RE.search(commit["message"]) or \
                   _MSG_CRITICAL_RE.search(commit["message"]):
                    files = self._fetch_files(owner, repo_name, commit["sha"])
                    detail_fetches += 1
                elif detail_fetches < 2:
                    # Also sample a couple non-signal commits for file-level check
                    files = self._fetch_files(owner, repo_name, commit["sha"])
                    detail_fetches += 1

            commit_score, reasons = score_commit(
                commit["message"], files, target.get("lang", "c")
            )
            self._vlog(
                f"  {commit['sha'][:10]}  [{commit_score}]  {commit['message'][:60]}"
            )

            if commit_score in ALERT_SCORES:
                self._print_alert(target, commit, commit_score, reasons, files)
                alert_records.append(
                    self._build_alert_record(
                        target, commit, commit_score, reasons, files
                    )
                )

                if commit_score == "CRITICAL" and self.auto_qualify:
                    self._auto_qualify(target)

        # Advance the pointer to the newest commit
        target["last_commit_seen"] = commits[0]["sha"]

        return alert_records, len(commits)

    # ------------------------------------------------------------------
    # Full sweep
    # ------------------------------------------------------------------

    def check_all(self) -> dict[str, Any]:
        """
        Sweep every active target once. Returns a run-summary dict.
        Also saves alerts and the daily monitor report.
        """
        db      = self.load_db()
        targets = db.get("targets", [])
        active  = [t for t in targets if t.get("status") == "active"]

        self._log(
            f"[*] Checking {len(active)} active target(s)  "
            f"({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"
        )

        all_alerts:      list[dict] = []
        total_commits    = 0

        for t in active:
            self._log(f"\n[*] {t['repo']}  [{t['lang']}  {t['priority']}]")
            alerts, n = self.check_target(t)
            all_alerts.extend(alerts)
            total_commits += n

        # Identify stale targets (not full-scanned in STALE_SCAN_DAYS)
        stale: list[str] = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_SCAN_DAYS)
        for t in active:
            ls = t.get("last_scan")
            if ls is None:
                stale.append(t["repo"])
            else:
                try:
                    last_dt = datetime.fromisoformat(ls.replace("Z", "+00:00"))
                    if last_dt < cutoff:
                        stale.append(t["repo"])
                except ValueError:
                    stale.append(t["repo"])

        summary = {
            "scanner":            "glasswing-monitor",
            "version":            "1.0.0",
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "targets_watched":    len(active),
            "commits_processed":  total_commits,
            "alerts_fired":       len(all_alerts),
            "stale_targets":      stale,
        }

        # Persist
        self.save_db(db)

        if all_alerts:
            alert_path = self._append_alerts(all_alerts)
            self._log(f"\n[+] {len(all_alerts)} alert(s) saved -> {alert_path}")
        else:
            self._log("\n    No alerts this sweep.")

        summary_path = self._save_summary(summary)
        self._log(f"[+] Summary saved -> {summary_path}")

        if stale:
            self._log(
                f"\n    ⚠ {len(stale)} target(s) overdue for a full scan "
                f"(not scanned in {STALE_SCAN_DAYS}+ days):"
            )
            for r in stale:
                self._log(f"      • {r}")

        return summary

    # ------------------------------------------------------------------
    # Report saving
    # ------------------------------------------------------------------

    def _save_summary(self, summary: dict[str, Any]) -> Path:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path     = self.reports_dir / f"monitor_{date_str}.json"
        path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return path

    # ------------------------------------------------------------------
    # CLI actions
    # ------------------------------------------------------------------

    def run_once(self) -> None:
        """Single sweep of all targets."""
        self.check_all()

    def run_watch(self) -> None:
        """
        Continuous loop: sweep all targets, sleep, repeat.
        Interval is read from targets.json (check_interval_hours).
        """
        self._log("[*] Entering watch mode. Press Ctrl+C to stop.")
        try:
            while True:
                db       = self.load_db()
                interval = int(db.get("check_interval_hours", DEFAULT_INTERVAL_HOURS))

                self.check_all()

                next_run = datetime.now(timezone.utc) + timedelta(hours=interval)
                self._log(
                    f"\n[*] Next check at {next_run.strftime('%Y-%m-%d %H:%M UTC')} "
                    f"(in {interval}h). Sleeping …"
                )
                time.sleep(interval * 3600)
        except KeyboardInterrupt:
            self._log("\n[!] Watch mode stopped by user.")

    def show_status(self) -> None:
        """Print the current target database to the terminal."""
        try:
            from glasswing import _c, _hr, _BOLD, _RED, _YELLOW, _CYAN, _GREEN, _DIM  # type: ignore
        except ImportError:
            def _c(t: str, *_: str) -> str: return t       # type: ignore[misc]
            def _hr(w: int = 72) -> str:    return "─" * w # type: ignore[misc]
            _BOLD = _RED = _YELLOW = _CYAN = _GREEN = _DIM = ""

        _PRI_COLOR = {"critical": _RED + _BOLD, "high": _RED, "medium": _YELLOW, "low": _CYAN}

        db      = self.load_db()
        targets = db.get("targets", [])
        active  = [t for t in targets if t.get("status") == "active"]
        pause   = [t for t in targets if t.get("status") != "active"]
        iv      = db.get("check_interval_hours", DEFAULT_INTERVAL_HOURS)
        last    = db.get("last_run") or "never"

        print(_hr())
        print(_c(" GLASSWING MONITOR — TARGET DATABASE", _BOLD))
        print(_hr())
        print(f"  {'Targets':<16}{len(active)} active"
              + (f"  ·  {len(pause)} paused" if pause else ""))
        print(f"  {'Check interval':<16}{iv}h")
        print(f"  {'Last run':<16}{last}")
        print(_hr())

        sorted_targets = sorted(
            targets,
            key=lambda t: (_PRIORITY_ORDER.get(t.get("priority", "low"), 99),
                           t.get("repo", "")),
        )

        header = f"  {'#':<4}{'Repo':<36}{'Lang':<6}{'Priority':<10}{'Findings':<10}{'Last Scan'}"
        print(_c(header, _DIM))
        print(_c("  " + "─" * 70, _DIM))

        cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_SCAN_DAYS)
        for i, t in enumerate(sorted_targets, 1):
            pri    = t.get("priority", "?")
            color  = _PRI_COLOR.get(pri, "")
            ls     = t.get("last_scan") or "never"
            stale  = ""
            if ls != "never":
                try:
                    if datetime.fromisoformat(ls.replace("Z", "+00:00")) < cutoff:
                        stale = _c("  ⚠ stale", _YELLOW)
                except ValueError:
                    pass
            elif t.get("status") == "active":
                stale = _c("  ⚠ never scanned", _YELLOW)

            status_tag = "" if t.get("status") == "active" else _c("  [paused]", _DIM)
            print(
                f"  {i:<4}{t.get('repo','?'):<36}"
                f"{t.get('lang','?'):<6}"
                f"{_c(pri.upper(), color):<{10 + len(color) + len(_RED) if color else 10}}"  # pad for ANSI
                f"{t.get('findings_count', 0):<10}"
                f"{ls[:10]}{stale}{status_tag}"
            )

        print(_hr())

    def add_target(self, repo_url: str, lang: str, priority: str) -> None:
        """Add a new target to the database, or reactivate an existing one."""
        try:
            owner, repo_name = _parse_repo(repo_url)
        except ValueError as exc:
            self._err(str(exc))
            return

        canonical = f"{owner}/{repo_name}"
        db        = self.load_db()
        targets   = db.setdefault("targets", [])

        # Check for existing entry
        for t in targets:
            if t.get("repo", "").lower() == canonical.lower():
                if t.get("status") == "active":
                    self._log(f"[!] {canonical} is already an active target.")
                else:
                    t["status"] = "active"
                    self.save_db(db)
                    self._log(f"[+] Reactivated target: {canonical}")
                return

        new_target: dict[str, Any] = {
            "repo":             canonical,
            "lang":             lang.lower(),
            "priority":         priority.lower(),
            "last_commit_seen": None,
            "last_scan":        None,
            "findings_count":   0,
            "status":           "active",
        }
        targets.append(new_target)
        self.save_db(db)
        self._log(
            f"[+] Added target: {canonical}  "
            f"(lang={lang}, priority={priority})"
        )
        self._log(
            f"    First run will bootstrap the commit pointer "
            f"(no alerts until the second sweep)."
        )


# ---------------------------------------------------------------------------
# Console report printer  (called by glasswing.py report subcommand)
# ---------------------------------------------------------------------------


def print_monitor_report(report: dict[str, Any]) -> None:
    """Print a formatted daily summary report."""
    try:
        from glasswing import _c, _hr, _BOLD, _RED, _YELLOW, _GREEN, _DIM  # type: ignore
    except ImportError:
        def _c(t: str, *_: str) -> str: return t       # type: ignore[misc]
        def _hr(w: int = 72) -> str:    return "─" * w # type: ignore[misc]
        _BOLD = _RED = _YELLOW = _GREEN = _DIM = ""

    ts      = report.get("timestamp", "?")
    watched = report.get("targets_watched", 0)
    commits = report.get("commits_processed", 0)
    alerts  = report.get("alerts_fired", 0)
    stale   = report.get("stale_targets", [])

    print(_hr())
    print(_c(" GLASSWING MONITOR — DAILY SUMMARY", _BOLD))
    print(_hr())
    print(f"  {'Timestamp':<20}{ts}")
    print(f"  {'Targets watched':<20}{watched}")
    print(f"  {'Commits processed':<20}{commits}")
    alert_color = _RED if alerts else _GREEN
    print(f"  {'Alerts fired':<20}{_c(str(alerts), alert_color)}")
    print(_hr())

    if stale:
        print(_c(" OVERDUE FOR FULL SCAN", _YELLOW + _BOLD))
        for r in stale:
            print(f"  • {r}")
        print(_hr())
    else:
        print(_c("  All targets scanned within the last "
                 f"{STALE_SCAN_DAYS} days.", _GREEN))
        print(_hr())


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glasswing-monitor",
        description="Continuously watch repositories for security-relevant commits.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/monitor.py --run-once\n"
            "  python src/monitor.py --watch\n"
            "  python src/monitor.py --status\n"
            "  python src/monitor.py --add-target https://github.com/org/repo "
            "--lang c --priority high\n"
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--run-once",
        action="store_true",
        help="Run a single sweep of all targets and exit.",
    )
    mode.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously on the configured interval.",
    )
    mode.add_argument(
        "--status",
        action="store_true",
        help="Print the target database and exit.",
    )
    mode.add_argument(
        "--add-target",
        metavar="URL",
        help="Add a repository to the target database.",
    )
    parser.add_argument(
        "--lang",
        default="c",
        metavar="LANG",
        help="Language for a new target (default: c).",
    )
    parser.add_argument(
        "--priority",
        default="high",
        choices=["critical", "high", "medium", "low"],
        help="Priority for a new target (default: high).",
    )
    parser.add_argument(
        "--auto-qualify",
        action="store_true",
        help="Automatically run intel on CRITICAL commits and prompt to escalate.",
    )
    parser.add_argument(
        "--configs-dir",
        default="configs",
        metavar="DIR",
        help="Directory containing targets.json (default: configs/).",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        metavar="DIR",
        help="Directory for alert and summary reports (default: reports/).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Claude model for auto-qualify intel (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-commit detail.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args   = parser.parse_args(argv)

    mon = ContinuousMonitor(
        configs_dir  = args.configs_dir,
        reports_dir  = args.reports_dir,
        model        = args.model,
        verbose      = args.verbose,
        auto_qualify = args.auto_qualify,
    )

    if args.add_target:
        mon.add_target(args.add_target, args.lang, args.priority)
    elif args.status:
        mon.show_status()
    elif args.watch:
        mon.run_watch()
    else:
        mon.run_once()

    return 0


if __name__ == "__main__":
    sys.exit(main())
