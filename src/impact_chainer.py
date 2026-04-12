#!/usr/bin/env python
"""
Glasswing Impact Chainer — Phase 3: Impact Escalation.

Pipeline
--------
1. Load all glasswing-scanner JSON reports from reports/ that match the target.
2. Correlate findings by known CWE escalation pairs and co-located file exposure.
3. Build candidate attack chains: entry point → pivot → final impact.
4. Ask Claude to validate each chain, identify required assumptions, suggest
   simpler paths, and rate exploitability (EASY / MODERATE / HARD / THEORETICAL).
5. Save a timestamped chain report and print chains ranked by impact.

Only stdlib + anthropic are used.

Usage
-----
    python glasswing.py chain --reports ./reports --target kafel
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Report types whose findings we mine for chains
_SCANNER_IDS = {"glasswing-scanner"}

# ---------------------------------------------------------------------------
# CWE escalation pair table
# (cwe_a, cwe_b) -> (chain_type, rating, cvss_delta)
#
# Order: cwe_a enables or amplifies cwe_b.
# Both orderings are resolved at lookup time.
# ---------------------------------------------------------------------------

CWE_ESCALATION_PAIRS: dict[tuple[str, str], tuple[str, str, float]] = {
    ("CWE-476", "CWE-416"): ("memory corruption chain",    "CRITICAL", 2.5),
    ("CWE-22",  "CWE-732"): ("file overwrite chain",       "HIGH",     1.5),
    ("CWE-78",  "CWE-269"): ("privilege escalation chain", "CRITICAL", 2.0),
    ("CWE-120", "CWE-134"): ("code execution chain",       "CRITICAL", 3.0),
    ("CWE-252", "CWE-476"): ("crash chain",                "MEDIUM",   1.0),
    # Path traversal lets an attacker supply a crafted file whose content
    # triggers a null pointer deref in the consuming parser/evaluator.
    ("CWE-22",  "CWE-476"): ("file-triggered crash chain", "HIGH",     1.5),
}

# Flat lookup including reversed pairs
_CWE_PAIR_LOOKUP: dict[tuple[str, str], tuple[str, str, float]] = {}
for (_a, _b), _v in CWE_ESCALATION_PAIRS.items():
    _CWE_PAIR_LOOKUP[(_a, _b)] = _v
    _CWE_PAIR_LOOKUP[(_b, _a)] = _v

_RATING_ORDER       = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_EXPLOIT_ORDER      = {"EASY": 0, "MODERATE": 1, "HARD": 2, "THEORETICAL": 3}
_SEVERITY_ORDER     = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# Tool schema
# ---------------------------------------------------------------------------

_CHAIN_ANALYSIS_TOOL: dict[str, Any] = {
    "name": "analyze_attack_chain",
    "description": (
        "Validate a proposed multi-vulnerability attack chain and rate its "
        "exploitability. Decide whether bug A genuinely enables or amplifies bug B, "
        "enumerate the conditions required, and judge how easy the chain is to execute."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "valid": {
                "type": "boolean",
                "description": (
                    "True if the chain is logically coherent — bug A materially enables "
                    "or amplifies bug B under plausible attacker conditions."
                ),
            },
            "assumptions": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Conditions that must hold for the chain to work, e.g. "
                    "'attacker controls argv[1]', 'ASLR is disabled', "
                    "'file is world-writable'."
                ),
            },
            "simpler_path": {
                "type": "string",
                "description": (
                    "Describe a shorter path to the same final impact if one exists. "
                    "Empty string if this chain is already the most direct route."
                ),
            },
            "exploitability": {
                "type": "string",
                "enum": ["EASY", "MODERATE", "HARD", "THEORETICAL"],
                "description": (
                    "EASY: standard public techniques, no special conditions. "
                    "MODERATE: some preconditions or non-trivial timing required. "
                    "HARD: significant attacker skill or rare environmental conditions. "
                    "THEORETICAL: logically possible but practically infeasible."
                ),
            },
            "revised_rating": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "description": (
                    "Adjusted severity rating for the full chain. "
                    "Omit if the initial estimate is already correct."
                ),
            },
            "revised_cvss_delta": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 4.0,
                "description": (
                    "How much chaining these bugs raises the effective CVSS score "
                    "beyond the highest individual finding score (0.0–4.0). "
                    "Omit if the initial estimate is reasonable."
                ),
            },
            "notes": {
                "type": "string",
                "description": "Key observations about this chain (2–4 sentences).",
            },
        },
        "required": ["valid", "assumptions", "exploitability", "notes"],
    },
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ChainFinding:
    """Slim representation of one scanner finding used inside a chain."""
    title:            str
    cwe:              str     # normalized, e.g. "CWE-476"
    severity:         str
    cvss:             float | None
    file:             str
    impact:           str
    poc_idea:         str
    disclosure_hash:  str


@dataclass
class AttackChain:
    """One candidate multi-vulnerability attack chain."""
    chain_id:    str
    chain_type:  str   # e.g. "memory corruption chain"
    rating:      str   # CRITICAL / HIGH / MEDIUM / LOW
    cvss_delta:  float
    findings:    list[ChainFinding]

    # Synthesised attack narrative (pre-Claude)
    entry_point: str
    pivot:       str
    impact:      str

    # Filled by Claude analysis
    valid:           bool      = False
    assumptions:     list[str] = field(default_factory=list)
    simpler_path:    str       = ""
    exploitability:  str       = "THEORETICAL"
    notes:           str       = ""
    analyzed:        bool      = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_cwe(cwe_str: str) -> str:
    """Extract just the CWE-NNN token from a potentially verbose CWE string."""
    m = re.match(r"(CWE-\d+)", cwe_str.strip(), re.IGNORECASE)
    return m.group(1).upper() if m else cwe_str.strip()


def _short(text: str, n: int = 120) -> str:
    """Truncate a string for use in a narrative sentence."""
    text = text.strip()
    if len(text) <= n:
        return text
    return text[:n].rstrip() + "…"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class ImpactChainer:
    """
    Orchestrates the full impact-chaining pipeline:
    load -> correlate -> build chains -> LLM validation -> report.
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
    # Step 1 — Load findings from matching reports
    # ------------------------------------------------------------------

    def _matches_target(self, path: Path, report: dict[str, Any]) -> bool:
        """Return True if this report is relevant to self.target."""
        if self.target in path.name.lower():
            return True
        for key in ("repo", "target", "target_url"):
            val = report.get(key, "")
            if val and self.target in str(val).lower():
                return True
        return False

    def load_findings(self) -> tuple[list[ChainFinding], list[str]]:
        """
        Walk reports_dir, load all scanner reports that match the target,
        and return (deduplicated findings, list of source report paths).
        """
        findings: list[ChainFinding] = []
        sources:  list[str]          = []
        seen:     set[str]           = set()

        for rpt_path in sorted(self.reports_dir.glob("*.json")):
            try:
                report: dict[str, Any] = json.loads(
                    rpt_path.read_text(encoding="utf-8", errors="replace")
                )
            except (OSError, json.JSONDecodeError) as exc:
                self._vlog(f"skipping {rpt_path.name}: {exc}")
                continue

            if report.get("scanner") not in _SCANNER_IDS:
                self._vlog(f"skipping {rpt_path.name}: scanner type not relevant")
                continue

            if not self._matches_target(rpt_path, report):
                self._vlog(f"skipping {rpt_path.name}: does not match target '{self.target}'")
                continue

            raw = report.get("findings", [])
            self._vlog(f"loading {rpt_path.name} — {len(raw)} finding(s)")
            sources.append(str(rpt_path))

            for f in raw:
                dhash = f.get("disclosure_hash", "")
                if dhash in seen:
                    continue
                seen.add(dhash)

                cwe_raw = f.get("cwe", "")
                findings.append(ChainFinding(
                    title=f.get("title", "Untitled"),
                    cwe=_normalize_cwe(cwe_raw) if cwe_raw else "",
                    severity=f.get("severity", "info"),
                    cvss=f.get("cvss_estimate"),
                    file=f.get("file", ""),
                    impact=f.get("impact", ""),
                    poc_idea=f.get("poc_idea", ""),
                    disclosure_hash=dhash,
                ))

        return findings, sources

    # ------------------------------------------------------------------
    # Step 2 — Correlate findings into candidate chains
    # ------------------------------------------------------------------

    def correlate(self, findings: list[ChainFinding]) -> list[AttackChain]:
        """
        Produce candidate AttackChains by matching:
        1. Known CWE escalation pairs (cross-file or same-file).
        2. Same-file pairs where at least one finding is high/critical severity
           and no CWE pair already covered the combination.
        """
        chains: list[AttackChain] = []
        seen_pairs: set[frozenset[str]] = set()

        # ── CWE escalation pairs ──────────────────────────────────────────
        for i, fa in enumerate(findings):
            for j, fb in enumerate(findings):
                if j <= i:
                    continue
                if not fa.cwe or not fb.cwe:
                    continue

                pair_key = frozenset({fa.disclosure_hash, fb.disclosure_hash})
                if pair_key in seen_pairs:
                    continue

                # Try (fa.cwe, fb.cwe) then swap
                meta = _CWE_PAIR_LOOKUP.get((fa.cwe, fb.cwe))
                if meta is None:
                    meta = _CWE_PAIR_LOOKUP.get((fb.cwe, fa.cwe))
                    if meta:
                        fa, fb = fb, fa  # ensure fa->fb ordering matches the pair

                if meta:
                    chain_type, rating, cvss_delta = meta
                    seen_pairs.add(pair_key)
                    chains.append(
                        self._build_cwe_chain(fa, fb, chain_type, rating, cvss_delta, len(chains))
                    )

        # ── Same-file compound exposure ───────────────────────────────────
        file_groups: dict[str, list[ChainFinding]] = defaultdict(list)
        for f in findings:
            if f.file:
                file_groups[f.file].append(f)

        for file_path, group in file_groups.items():
            if len(group) < 2:
                continue
            high_plus = [f for f in group if f.severity in ("high", "critical")]
            if not high_plus:
                continue

            # All high/critical pairs not already covered
            for i, fa in enumerate(high_plus):
                for j, fb in enumerate(high_plus):
                    if j <= i:
                        continue
                    pair_key = frozenset({fa.disclosure_hash, fb.disclosure_hash})
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    chains.append(
                        self._build_file_chain(fa, fb, file_path, len(chains))
                    )

        # ── Same-CWE cross-file compound chain ───────────────────────────
        # Multiple instances of the same vulnerability class across different
        # components can compound: one instance weakens invariants relied upon
        # by the other, or an attacker can trigger both in sequence.
        # Require at least one finding to be high/critical to avoid noise.
        cwe_groups: dict[str, list[ChainFinding]] = defaultdict(list)
        for f in findings:
            if f.cwe:
                cwe_groups[f.cwe].append(f)

        for cwe, group in cwe_groups.items():
            if len(group) < 2:
                continue
            for i, fa in enumerate(group):
                for j, fb in enumerate(group):
                    if j <= i:
                        continue
                    if fa.file == fb.file:
                        continue  # already covered by same-file logic
                    if fa.severity not in ("high", "critical") and \
                       fb.severity not in ("high", "critical"):
                        continue
                    pair_key = frozenset({fa.disclosure_hash, fb.disclosure_hash})
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    chains.append(
                        self._build_same_cwe_chain(fa, fb, cwe, len(chains))
                    )

        return chains

    # ── Chain builders ────────────────────────────────────────────────────

    def _build_cwe_chain(
        self,
        fa: ChainFinding,
        fb: ChainFinding,
        chain_type: str,
        rating: str,
        cvss_delta: float,
        idx: int,
    ) -> AttackChain:
        poc = _short(fa.poc_idea) if fa.poc_idea else "an exploitable interface"
        entry_point = (
            f"Attacker reaches {fa.file or 'the target module'} via {poc}."
        )
        pivot = (
            f"{fa.title} ({fa.cwe}) creates conditions that enable "
            f"{fb.title} ({fb.cwe}), completing a {chain_type}."
        )
        impact = _short(
            " ".join(filter(None, [fa.impact, fb.impact])), n=350
        )
        return AttackChain(
            chain_id=f"chain-{idx + 1:03d}",
            chain_type=chain_type,
            rating=rating,
            cvss_delta=cvss_delta,
            findings=[fa, fb],
            entry_point=entry_point,
            pivot=pivot,
            impact=impact,
        )

    def _build_same_cwe_chain(
        self,
        fa: ChainFinding,
        fb: ChainFinding,
        cwe: str,
        idx: int,
    ) -> AttackChain:
        max_sev   = fa.severity if _SEVERITY_ORDER.get(fa.severity, 99) <= \
                    _SEVERITY_ORDER.get(fb.severity, 99) else fb.severity
        rating    = "CRITICAL" if max_sev == "critical" else "HIGH"
        entry_point = (
            f"Attacker reaches {fa.file or 'a target module'} containing {cwe} "
            f"and separately {fb.file or 'another module'} with the same class of flaw."
        )
        pivot = (
            f"Both '{fa.title}' and '{fb.title}' share {cwe}: triggering one "
            "weakens safety invariants relied upon by the other, or an attacker "
            "can sequence both for compound effect."
        )
        impact = _short(
            " ".join(filter(None, [fa.impact, fb.impact])), n=350
        )
        return AttackChain(
            chain_id=f"chain-{idx + 1:03d}",
            chain_type=f"compound {cwe} chain",
            rating=rating,
            cvss_delta=1.0,
            findings=[fa, fb],
            entry_point=entry_point,
            pivot=pivot,
            impact=impact,
        )

    def _build_file_chain(
        self,
        fa: ChainFinding,
        fb: ChainFinding,
        file_path: str,
        idx: int,
    ) -> AttackChain:
        rating = (
            "CRITICAL"
            if any(f.severity == "critical" for f in (fa, fb))
            else "HIGH"
        )
        entry_point = (
            f"Attacker targets {file_path}, which contains multiple "
            "co-located high-severity vulnerabilities."
        )
        pivot = (
            f"Exploitation of '{fa.title}' ({fa.cwe or fa.severity}) within the "
            f"same code unit provides a foothold to trigger '{fb.title}' "
            f"({fb.cwe or fb.severity})."
        )
        impact = _short(
            " ".join(filter(None, [fa.impact, fb.impact])), n=350
        )
        return AttackChain(
            chain_id=f"chain-{idx + 1:03d}",
            chain_type="compound file exposure",
            rating=rating,
            cvss_delta=1.0,
            findings=[fa, fb],
            entry_point=entry_point,
            pivot=pivot,
            impact=impact,
        )

    # ------------------------------------------------------------------
    # Step 3 — LLM chain analysis
    # ------------------------------------------------------------------

    def analyze_chain(self, chain: AttackChain) -> AttackChain:
        """
        Call Claude to validate the chain's logic, list required assumptions,
        suggest simpler paths, and rate exploitability.
        Mutates *chain* in-place and returns it.
        """
        findings_text = "\n".join(
            f"  Finding {i + 1}: [{f.severity.upper()}] {f.title}  ({f.cwe or 'no CWE'})\n"
            f"    File   : {f.file or '(unknown)'}\n"
            f"    CVSS   : {f.cvss if f.cvss is not None else '?'}\n"
            f"    Impact : {_short(f.impact)}\n"
            f"    PoC    : {_short(f.poc_idea)}"
            for i, f in enumerate(chain.findings)
        )

        prompt = (
            "You are an expert offensive security researcher reviewing a candidate "
            "multi-vulnerability attack chain.\n\n"
            f"**Chain type:** {chain.chain_type}\n"
            f"**Initial rating:** {chain.rating}  "
            f"**Estimated CVSS delta:** +{chain.cvss_delta:.1f}\n\n"
            "**Proposed attack steps:**\n"
            f"  Step 1 — Entry point : {chain.entry_point}\n"
            f"  Step 2 — Pivot       : {chain.pivot}\n"
            f"  Step 3 — Final impact: {chain.impact}\n\n"
            "**Contributing findings:**\n"
            f"{findings_text}\n\n"
            "Call `analyze_attack_chain` to answer:\n"
            "• Is the chain logically sound — does bug A genuinely enable/amplify bug B?\n"
            "• What assumptions must hold for the chain to succeed?\n"
            "• Is there a simpler path to the same final impact?\n"
            "• Rate exploitability: EASY / MODERATE / HARD / THEORETICAL.\n"
            "• Only revise the rating or CVSS delta if you have clear reason to.\n"
            "• Write 2–4 sentences of notes."
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                tools=[_CHAIN_ANALYSIS_TOOL],
                tool_choice={"type": "tool", "name": "analyze_attack_chain"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            self._log(f"[!] API error analyzing {chain.chain_id}: {exc}")
            return chain

        for block in response.content:
            if block.type == "tool_use" and block.name == "analyze_attack_chain":
                inp = block.input
                chain.valid          = bool(inp.get("valid", False))
                chain.assumptions    = list(inp.get("assumptions", []))
                chain.simpler_path   = inp.get("simpler_path", "")
                chain.exploitability = inp.get("exploitability", "THEORETICAL")
                chain.notes          = inp.get("notes", "")
                chain.analyzed       = True

                if inp.get("revised_rating"):
                    chain.rating = inp["revised_rating"]
                if inp.get("revised_cvss_delta") is not None:
                    chain.cvss_delta = float(inp["revised_cvss_delta"])

        return chain

    # ------------------------------------------------------------------
    # Step 4 — Report
    # ------------------------------------------------------------------

    def _sort_key(self, c: AttackChain) -> tuple:
        return (
            _RATING_ORDER.get(c.rating, 99),
            _EXPLOIT_ORDER.get(c.exploitability, 99),
            -c.cvss_delta,
        )

    def _build_report(
        self,
        chains: list[AttackChain],
        source_reports: list[str],
        total_findings: int,
    ) -> dict[str, Any]:
        valid = sorted([c for c in chains if c.valid], key=self._sort_key)

        by_rating: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_exploit: dict[str, int] = {
            "EASY": 0, "MODERATE": 0, "HARD": 0, "THEORETICAL": 0
        }
        for c in valid:
            by_rating[c.rating]          = by_rating.get(c.rating, 0) + 1
            by_exploit[c.exploitability] = by_exploit.get(c.exploitability, 0) + 1

        return {
            "scanner":        "glasswing-impact-chainer",
            "version":        "1.0.0",
            "model":          self.model,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "target":         self.target,
            "reports_dir":    str(self.reports_dir),
            "source_reports": source_reports,
            "summary": {
                "findings_loaded":   total_findings,
                "candidate_chains":  len(chains),
                "validated_chains":  len(valid),
                "by_rating":         by_rating,
                "by_exploitability": by_exploit,
            },
            "chains": [
                {
                    "chain_id":       c.chain_id,
                    "chain_type":     c.chain_type,
                    "rating":         c.rating,
                    "exploitability": c.exploitability,
                    "cvss_delta":     round(c.cvss_delta, 1),
                    "valid":          c.valid,
                    "steps": {
                        "entry_point": c.entry_point,
                        "pivot":       c.pivot,
                        "impact":      c.impact,
                    },
                    "findings": [
                        {
                            "title":    f.title,
                            "cwe":      f.cwe,
                            "severity": f.severity,
                            "cvss":     f.cvss,
                            "file":     f.file,
                        }
                        for f in c.findings
                    ],
                    "assumptions":  c.assumptions,
                    "simpler_path": c.simpler_path,
                    "notes":        c.notes,
                }
                for c in valid
            ],
        }

    def save_report(self, report: dict[str, Any]) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = self.output_dir / f"chains_{self.target}_{ts}.json"
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return out_path

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """Execute the full pipeline and return the completed report dict."""

        # ── 1. Load ──────────────────────────────────────────────────────
        self._log(
            f"[*] Loading findings for target '{self.target}' "
            f"from {self.reports_dir} …"
        )
        findings, sources = self.load_findings()
        self._log(
            f"    {len(findings)} unique finding(s) loaded "
            f"from {len(sources)} report(s)."
        )

        if len(findings) < 2:
            self._log("[!] Fewer than 2 findings found — no chains possible.")
            report   = self._build_report([], sources, len(findings))
            out_path = self.save_report(report)
            self._log(f"[+] Empty chain report saved -> {out_path}")
            return report

        # ── 2. Correlate ─────────────────────────────────────────────────
        self._log("[*] Correlating findings into candidate chains …")
        candidates = self.correlate(findings)
        self._log(f"    {len(candidates)} candidate chain(s) identified.")

        if not candidates:
            self._log("[!] No correlatable chain candidates found.")
            report   = self._build_report([], sources, len(findings))
            out_path = self.save_report(report)
            self._log(f"[+] Empty chain report saved -> {out_path}")
            return report

        # ── 3. Analyze ───────────────────────────────────────────────────
        self._log(
            f"[*] Asking Claude to validate {len(candidates)} "
            "candidate chain(s) …"
        )
        for idx, chain in enumerate(candidates, 1):
            self._log(
                f"    [{idx}/{len(candidates)}] {chain.chain_id}  "
                f"({chain.chain_type}) …"
            )
            self.analyze_chain(chain)
            verdict = "VALID  " if chain.valid else "invalid"
            self._log(
                f"        -> {verdict}  rating={chain.rating}  "
                f"exploit={chain.exploitability}  "
                f"cvss_delta=+{chain.cvss_delta:.1f}"
            )

        # ── 4. Report ────────────────────────────────────────────────────
        valid    = [c for c in candidates if c.valid]
        report   = self._build_report(candidates, sources, len(findings))
        out_path = self.save_report(report)

        self._log("")
        self._log(
            f"[+] Impact chaining complete.  "
            f"{len(valid)} valid chain(s) from {len(candidates)} candidate(s)."
        )
        for c in sorted(valid, key=self._sort_key):
            self._log(
                f"    [{c.rating}] {c.chain_id}  {c.chain_type}  "
                f"exploit={c.exploitability}  cvss_delta=+{c.cvss_delta:.1f}"
            )
        self._log(f"[+] Chain report saved -> {out_path}")

        return report


# ---------------------------------------------------------------------------
# Console report printer (called by glasswing.py report subcommand)
# ---------------------------------------------------------------------------


def print_chain_report(report: dict[str, Any]) -> None:
    """Print a colour-coded chain report to stdout."""
    # Reuse the colour helpers from glasswing.py if available, else plain text
    try:
        from glasswing import _c, _hr, _wrap, _BOLD, _RED, _YELLOW, _CYAN, _GREEN, _DIM, _ORANGE, _USE_COLOR  # type: ignore
    except ImportError:
        def _c(t: str, *_: str) -> str:     # type: ignore[misc]
            return t
        def _hr(w: int = 72) -> str:         # type: ignore[misc]
            return "─" * w
        def _wrap(t: str, **_: Any) -> str:  # type: ignore[misc]
            return t
        _BOLD = _RED = _YELLOW = _CYAN = _GREEN = _DIM = _ORANGE = ""

    _RATING_COLOR = {
        "CRITICAL": _RED + _BOLD,
        "HIGH":     _RED,
        "MEDIUM":   _YELLOW,
        "LOW":      _CYAN,
    }
    _EXPLOIT_COLOR = {
        "EASY":        _RED,
        "MODERATE":    _YELLOW,
        "HARD":        _CYAN,
        "THEORETICAL": _DIM,
    }

    chains  = report.get("chains", [])
    summary = report.get("summary", {})
    target  = report.get("target", "?")
    ts      = report.get("timestamp", "?")
    model   = report.get("model", "?")

    print(_hr())
    print(_c(" GLASSWING IMPACT CHAIN REPORT", _BOLD))
    print(_hr())
    print(f"  {'Target':<14}{target}")
    print(f"  {'Scanned':<14}{ts}")
    print(f"  {'Model':<14}{model}")
    print(f"  {'Findings in':<14}{summary.get('findings_loaded', '?')} loaded")
    print(
        f"  {'Chains':<14}"
        f"{summary.get('validated_chains', 0)} valid  ·  "
        f"{summary.get('candidate_chains', 0)} candidate(s)"
    )
    print(_hr())

    # Summary breakdown
    by_rating  = summary.get("by_rating", {})
    by_exploit = summary.get("by_exploitability", {})
    total      = summary.get("validated_chains", 0)

    if total:
        print(_c(" RATING BREAKDOWN", _BOLD))
        for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = by_rating.get(r, 0)
            if n:
                print(
                    f"  {_c(f'{r:<12}', _RATING_COLOR.get(r, ''))}  {n}"
                )
        print(_hr())
        print(_c(" EXPLOITABILITY BREAKDOWN", _BOLD))
        for e in ("EASY", "MODERATE", "HARD", "THEORETICAL"):
            n = by_exploit.get(e, 0)
            if n:
                print(
                    f"  {_c(f'{e:<12}', _EXPLOIT_COLOR.get(e, ''))}  {n}"
                )
        print(_hr())

    if not chains:
        print(_c("  No validated chains.", _GREEN))
        print(_hr())
        return

    print(_c(" ATTACK CHAINS  (ranked by impact)", _BOLD))
    print(_hr())

    for c in chains:
        rating  = c.get("rating", "?")
        exploit = c.get("exploitability", "?")
        ctype   = c.get("chain_type", "?")
        cid     = c.get("chain_id", "?")
        delta   = c.get("cvss_delta", 0)
        steps   = c.get("steps", {})
        assump  = c.get("assumptions", [])
        simpler = c.get("simpler_path", "")
        notes   = c.get("notes", "")
        flist   = c.get("findings", [])

        r_color = _RATING_COLOR.get(rating, "")
        e_color = _EXPLOIT_COLOR.get(exploit, "")

        print(
            f"\n  {_c(f'[{rating}]', r_color)}"
            f"  {_c(cid, _BOLD)}"
            f"  {_c(ctype, _BOLD)}"
            f"  {_c(f'[{exploit}]', e_color)}"
            f"  {_c(f'CVSS +{delta:.1f}', r_color)}"
        )

        # Findings summary
        for i, f in enumerate(flist, 1):
            sev   = f.get("severity", "?").upper()
            title = f.get("title", "?")
            cwe   = f.get("cwe", "")
            ffile = f.get("file", "")
            line  = f"  {i}. [{sev}] {title}"
            if cwe:
                line += f"  {_c(cwe, _DIM)}"
            print(line)
            if ffile:
                print(f"       {_c(ffile, _DIM)}")

        # Steps
        print(f"\n  {'Entry':<12}{_wrap(steps.get('entry_point', ''), indent=14)}")
        print(f"  {'Pivot':<12}{_wrap(steps.get('pivot', ''), indent=14)}")
        print(f"  {'Impact':<12}{_wrap(steps.get('impact', ''), indent=14)}")

        # Assumptions
        if assump:
            print(f"  {'Assumes':<12}")
            for a in assump:
                print(f"               • {a}")

        # Simpler path
        if simpler:
            print(f"  {'Simpler':<12}{_wrap(simpler, indent=14)}")

        # Notes
        if notes:
            print(f"  {'Notes':<12}{_wrap(notes, indent=14)}")

    print(f"\n{_hr()}")


# ---------------------------------------------------------------------------
# CLI (standalone, invoked directly — not via glasswing.py)
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glasswing-impact-chainer",
        description="Chain scanner findings into higher-impact attack paths.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/impact_chainer.py --reports ./reports --target kafel\n"
            "  python src/impact_chainer.py --reports ./reports --target myapp --verbose\n"
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
        help="Directory to save the chain report (default: same as --reports).",
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
        chainer = ImpactChainer(
            reports_dir=args.reports,
            target=args.target,
            model=args.model,
            verbose=args.verbose,
            output_dir=args.output_dir,
        )
        chainer.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
