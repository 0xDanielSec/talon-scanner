#!/usr/bin/env python
"""
Glasswing Surface Mapper — Attack surface mapping for local repositories.

Phase 2 of the offensive research pipeline. Run after `intel` qualifies
the target, before `scan` for deep vulnerability analysis.

Pipeline
--------
1. Entry Point Detection   — regex scan for where external/untrusted data enters
2. Trust Boundary Mapping  — where data crosses privilege or trust levels
3. Dangerous Sink Detection — where tainted data could cause harm
4. Flow Analysis           — LLM-assisted tracing of entry→sink paths (top 5)
5. Surface Report          — JSON + terminal attack surface map

Uses only stdlib + anthropic.

Usage
-----
    python glasswing.py surface --target ./repo --lang c
    python glasswing.py surface --target ./repo
    python src/surface_mapper.py --target ./repo --lang python
"""

from __future__ import annotations

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
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL      = "claude-sonnet-4-20250514"
REPORTS_DIR        = Path(__file__).resolve().parent.parent / "reports"

MAX_FILE_BYTES     = 150_000   # skip files larger than this
MAX_SNIPPET_CHARS  = 10_000    # chars sent to Claude per file for flow analysis
CONTEXT_LINES      = 3         # source lines before/after each match
MAX_PER_CATEGORY   = 40        # cap findings per category to avoid report bloat
MAX_FLOW_FILES     = 5         # files sent to Claude for flow analysis

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "dist", "build", "target", "out",
    ".tox", "htmlcov", ".mypy_cache", ".eggs",
    ".idea", ".vscode",
})

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".c", ".cpp", ".h", ".hpp", ".cc", ".cxx",
    ".rs", ".go", ".zig",
    ".java", ".kt", ".cs", ".scala", ".groovy",
    ".rb", ".php", ".swift", ".m",
    ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".yaml", ".yml", ".toml", ".xml",
    ".tf", ".hcl", ".sql",
})

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
}

# Risk ordering for sorting
_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

# ---------------------------------------------------------------------------
# Pattern definitions
# Each tuple: (regex_string, risk_level, human_description)
# ---------------------------------------------------------------------------

# Entry Points — where untrusted data enters the program
_ENTRY_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    "NETWORK": [
        (r"\b(?:socket|bind|listen|accept|recv|recvfrom|recvmsg)\s*\(", "CRITICAL", "Raw socket I/O"),
        (r"\bnet\.(?:Listen|Dial|DialTCP|DialUDP|DialUnix)\b",          "HIGH",     "Go network I/O"),
        (r"\bhttp\.(?:ListenAndServe|Handle|HandleFunc|ServeMux)\b",    "HIGH",     "Go HTTP server"),
        (r"\b(?:ServerSocket|DatagramSocket)\b",                        "HIGH",     "Java socket"),
        (r"\bgrpc\.\w+Server\b|\.NewServer\s*\(",                       "HIGH",     "gRPC server"),
        (r"\bRequest\.(?:body|form|args|json|data|files|cookies)\b",    "HIGH",     "HTTP request data (Python/JS)"),
        (r"\br\.(?:Body|Form|PostForm|URL)\b",                         "HIGH",     "Go HTTP request"),
        (r"\bExpress\(\)|app\.(?:get|post|put|delete|use)\b",          "HIGH",     "Express.js route handler"),
        (r"\b(?:Flask|FastAPI|Django)\b.*route|@app\.route\b",         "HIGH",     "Python web framework route"),
        (r"\bAsyncIO|asyncio\.start_server\b",                         "HIGH",     "Python async server"),
    ],
    "FILE": [
        (r"\bfopen\s*\([^)]*(?:argv|arg|path|name|file|input)",        "CRITICAL", "fopen with user-controlled path"),
        (r"\bopen\s*\([^)]*(?:argv|arg|path|name|fname|filename)",     "CRITICAL", "open() with user-controlled path"),
        (r"\bfopen\s*\(",                                               "HIGH",     "fopen"),
        (r"\b(?:read_file|load_config|parse_file|load_yaml|load_json|from_file)\b", "HIGH", "File loader function"),
        (r"\bos\.(?:Open|ReadFile)\b|ioutil\.ReadFile\b",              "HIGH",     "Go file read"),
        (r"\bFileInputStream|BufferedReader\s*\(",                      "MEDIUM",   "Java file read"),
        (r"\bopen\s*\([^)]*['\"][rRaAbB]['\"]",                        "HIGH",     "Python file open for reading"),
    ],
    "CLI": [
        (r"\bargv\s*\[",                                                "MEDIUM",   "C/C++ argv"),
        (r"\bargparse\b|\bArgumentParser\b",                           "MEDIUM",   "Python argparse"),
        (r"\bgetopt\s*\(",                                              "MEDIUM",   "C getopt"),
        (r"\bos\.Args\b",                                               "MEDIUM",   "Go os.Args"),
        (r"\bflag\.(?:String|Int|Bool|Float|Duration|Parse)\b",        "MEDIUM",   "Go flag package"),
        (r"\bclick\.\w+|@click\.",                                      "MEDIUM",   "Python Click CLI"),
        (r"\btyper\.\w+|@typer\.",                                      "MEDIUM",   "Python Typer CLI"),
        (r"\bprocess\.argv\b",                                          "MEDIUM",   "Node.js process.argv"),
        (r"\bcommand_line_args|sys\.argv\b",                           "MEDIUM",   "Python sys.argv"),
        (r"\bCommands?\.Args\b|cobra\.",                               "MEDIUM",   "Go Cobra CLI"),
    ],
    "ENVIRONMENT": [
        (r"\bgetenv\s*\(",                                              "MEDIUM",   "C getenv"),
        (r"\bos\.environ\b|os\.getenv\b",                              "MEDIUM",   "Python os.environ"),
        (r"\bos\.Getenv\b",                                             "MEDIUM",   "Go os.Getenv"),
        (r"\bSystem\.getenv\b",                                         "MEDIUM",   "Java System.getenv"),
        (r"\bprocess\.env\b",                                           "MEDIUM",   "Node.js process.env"),
        (r"\bENV\[|ENV\.fetch\b",                                       "MEDIUM",   "Ruby ENV"),
        (r"\bgetenv\b|environ\b",                                       "MEDIUM",   "Generic getenv"),
    ],
    "SERIALIZATION": [
        (r"\bpickle\.(?:loads?|Unpickler)\b",                          "CRITICAL", "Python pickle (arbitrary code exec)"),
        (r"\byaml\.load\s*\([^,)]*\)",                                  "CRITICAL", "PyYAML load without safe Loader"),
        (r"\byaml\.(?:safe_load|full_load)\b",                         "HIGH",     "PyYAML load"),
        (r"\bjson\.(?:loads?|load)\b",                                  "HIGH",     "JSON deserialization"),
        (r"\b(?:json\.Unmarshal|xml\.Unmarshal|yaml\.Unmarshal|toml\.Unmarshal)\b", "HIGH", "Go deserialization"),
        (r"\b(?:ObjectInputStream|readObject)\s*\(",                   "CRITICAL", "Java object deserialization"),
        (r"\bdeserializ\w*\s*\(",                                       "HIGH",     "Generic deserialization"),
        (r"\bunmarshal\w*\s*\(",                                        "HIGH",     "Generic unmarshal"),
        (r"\beval\s*\(",                                                "CRITICAL", "eval() — executes arbitrary code"),
        (r"\bexec\s*\(",                                                "CRITICAL", "exec() — executes arbitrary code"),
        (r"\b(?:marshal\.Loads?|msgpack\.unpack|cbor\.Unmarshal)\b",   "HIGH",     "Binary deserialization"),
        (r"\bXML\.parse\b|DOMParser\b|SAXParser\b|XMLDecoder\b",       "HIGH",     "XML parsing (XXE risk)"),
        (r"\bjson5?\.parse\b",                                          "HIGH",     "JS JSON parse"),
    ],
    "IPC": [
        (r"\b(?:pipe|mkfifo)\s*\(",                                     "HIGH",     "Named/anonymous pipe"),
        (r"\b(?:mmap|shm_open|shmget)\s*\(",                           "HIGH",     "Shared memory"),
        (r"\b(?:dbus|DBus|GDBusConnection)\b",                         "MEDIUM",   "D-Bus IPC"),
        (r"\b(?:grpc|thrift|avro|capnp)\b",                            "MEDIUM",   "RPC framework"),
        (r"\bos\.pipe\b",                                               "MEDIUM",   "Python os.pipe"),
        (r"\bunix\.(?:Socket|Dial|Listen)\b|net\.UnixConn\b",         "HIGH",     "Unix domain socket"),
        (r"\bposix_mq_open\b|mq_open\b",                               "HIGH",     "POSIX message queue"),
    ],
    "USER_INPUT": [
        (r"\b(?:gets|scanf)\s*\(",                                      "CRITICAL", "Unbounded C input — no length check"),
        (r"\bfgets\s*\(",                                               "HIGH",     "C fgets (verify size arg)"),
        (r"\breadline\s*\(",                                            "HIGH",     "readline (C/Python)"),
        (r"\binput\s*\(",                                               "MEDIUM",   "Python input()"),
        (r"\bConsole\.ReadLine\b|Console\.Read\b",                     "MEDIUM",   "C# console input"),
        (r"\bfmt\.Scan\b|bufio\.NewScanner\b|bufio\.NewReader\b",      "MEDIUM",   "Go stdin read"),
        (r"\bSTDIN\b|STDIN\.gets\b|\$stdin\b",                         "MEDIUM",   "Ruby STDIN"),
        (r"\bprocess\.stdin\b|readline\.createInterface\b",            "MEDIUM",   "Node.js stdin"),
        (r"\bsys\.stdin\b",                                             "MEDIUM",   "Python sys.stdin"),
    ],
}

# Trust Boundaries — where privilege or trust level changes
# Each tuple: (regex_string, human_description)
_BOUNDARY_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "PRIVILEGE": [
        (r"\b(?:setuid|setgid|seteuid|setegid|setresuid|setresgid)\s*\(", "setuid/setgid — drops or elevates UID/GID"),
        (r"\bCAP_(?:SYS_ADMIN|NET_ADMIN|DAC_OVERRIDE|SETUID|SETGID|SYS_PTRACE|SYS_MODULE)\b", "Linux capability"),
        (r"\bprctl\s*\(\s*PR_SET_",                                       "prctl — modifies process attributes"),
        (r"\b(?:sudo|RunAs|runas)\b",                                     "Sudo / RunAs elevation"),
        (r"\b(?:elevate|privilege_drop|drop_privileges?)\b",              "Explicit privilege change"),
        (r"\bSetuid|setFileOwner|chown\s*\(",                            "File ownership change"),
        (r"\bAccessControl|RequirePermission|check_permission\b",         "Permission enforcement point"),
    ],
    "SANDBOX": [
        (r"\bseccomp\b",                                                  "seccomp syscall filter"),
        (r"\b(?:chroot|pivot_root)\s*\(",                                 "chroot — filesystem isolation"),
        (r"\bclone\s*\([^)]*CLONE_NEW",                                   "Linux namespace creation"),
        (r"\bunshare\s*\(",                                               "unshare — namespace isolation"),
        (r"\b(?:landlock_create_ruleset|landlock_restrict_self)\b",       "Landlock sandboxing"),
        (r"\b(?:pledge|unveil)\s*\(",                                     "OpenBSD pledge/unveil"),
        (r"\b(?:jail|jail_attach)\s*\(",                                  "FreeBSD jail"),
        (r"\b(?:cgroup|docker|containerd|runc|nsjail)\b",                "Container/cgroup boundary"),
        (r"\bsandbox_init\b|SandboxPolicy\b",                            "macOS/generic sandbox init"),
    ],
    "AUTH": [
        (r"\b(?:authenticate|check_auth|verify_token|assert_auth)\b",    "Authentication check"),
        (r"\b(?:jwt\.verify|jwt\.decode|verify_jwt)\b",                  "JWT verification"),
        (r"\b(?:hash_password|verify_password|check_password|bcrypt|argon2|pbkdf2)\b", "Password verification"),
        (r"\bsession\[|session\.get\b|session_start\b",                 "Session access"),
        (r"\b(?:BasicAuth|BearerToken|APIKey|api_key)\b",                "Auth scheme boundary"),
        (r"\bpam_authenticate\b|PAM_AUTH\b",                             "PAM authentication"),
        (r"\b(?:authorize|authz|check_permission|require_auth)\b",       "Authorization check"),
        (r"\bSSHD_AUTH|sshd\b.*auth",                                    "SSH authentication"),
    ],
    "KERNEL": [
        (r"\bsyscall\s*\(",                                               "Direct syscall (C)"),
        (r"\bsyscall\.(?:Syscall|RawSyscall|Syscall6)\b",                "Go syscall"),
        (r"\bioctl\s*\(",                                                 "ioctl — kernel control"),
        (r"\b(?:ebpf|bpf_prog_load|BPF_PROG_LOAD|bpf_syscall)\b",       "eBPF program"),
        (r"\bptrace\s*\(\s*PTRACE_",                                     "ptrace — process tracing"),
        (r"\b(?:mprotect|mlock|madvise)\s*\(",                          "Memory protection change"),
        (r"\bkmod_load|init_module|finit_module\b",                      "Kernel module load"),
        (r"\bkqueue|kev\b|kevent\b",                                     "kqueue kernel event"),
    ],
}

# Dangerous Sinks — where tainted data causes harm
_SINK_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    "CODE_EXEC": [
        (r"\b(?:execve?|execl[pe]?|execlp|execvpe?)\s*\(",              "CRITICAL", "POSIX exec — replaces process image"),
        (r"\bsystem\s*\(",                                              "CRITICAL", "system() — shell execution"),
        (r"\bpopen\s*\(",                                               "CRITICAL", "popen() — shell pipe"),
        (r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\b", "HIGH",     "Python subprocess"),
        (r"\bos\.(?:system|popen|execv[ep]?|spawnl?[ep]?)\b",          "CRITICAL", "Python os exec family"),
        (r"\bRuntime\.exec\b|ProcessBuilder\b",                        "CRITICAL", "Java process execution"),
        (r"\beval\s*\(",                                                "CRITICAL", "eval() — arbitrary code"),
        (r"\bexec\s*\(",                                                "CRITICAL", "exec() — arbitrary code"),
        (r"\bexec\.Command\b|os/exec\b",                               "HIGH",     "Go exec.Command"),
        (r"\b(?:shell_exec|passthru|proc_open|system)\s*\(",           "CRITICAL", "PHP shell functions"),
        (r"\bchildProcess\.(?:exec|spawn|execFile)\b",                  "HIGH",     "Node.js child_process"),
        (r"\b`[^`\n]{1,200}`",                                         "HIGH",     "Backtick shell execution"),
        (r"\bcommand_injection|cmd_injection\b",                        "CRITICAL", "Explicit injection (comment/var)"),
    ],
    "MEMORY": [
        (r"\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(",                  "CRITICAL", "Unbounded string op — classic overflow"),
        (r"\bgets\s*\(",                                                "CRITICAL", "gets() — always unsafe"),
        (r"\b(?:memcpy|memmove|bcopy)\s*\(",                           "HIGH",     "Memory copy — verify bounds"),
        (r"\b(?:malloc|realloc|calloc)\s*\(",                          "HIGH",     "Heap allocation — check return"),
        (r"\balloca\s*\(",                                              "HIGH",     "Stack allocation — overflow risk"),
        (r"\b(?:strncpy|strncat|snprintf)\s*\(",                       "MEDIUM",   "Bounded string op — verify length"),
        (r"\bmemset\s*\(",                                              "MEDIUM",   "memset — verify size"),
        (r"\bunsafe\.(?:Pointer|Slice|String|Add)\b",                  "HIGH",     "Go unsafe pointer arithmetic"),
        (r"\bptr::(?:copy|write|read)\b",                              "HIGH",     "Rust unsafe memory op"),
        (r"\bffi::\w+|std::mem::transmute\b",                          "HIGH",     "Rust FFI/transmute"),
        (r"\b__builtin_memcpy\b|__builtin_strcpy\b",                   "HIGH",     "Compiler builtin memory op"),
    ],
    "FILE_WRITE": [
        (r"\b(?:fwrite|fputs|fprintf)\s*\(",                           "HIGH",     "C file write"),
        (r"\bwrite\s*\([^)]{0,60}(?:fd|sock|file|pipe)",              "HIGH",     "POSIX write to fd"),
        (r"\bopen\s*\([^)]*(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)",      "HIGH",     "File opened for writing (O_WRONLY)"),
        (r"\bos\.(?:rename|replace|remove|unlink|symlink|link)\b",     "MEDIUM",   "Python filesystem mutation"),
        (r"\bos\.(?:Create|OpenFile|WriteFile)\b|ioutil\.WriteFile\b", "HIGH",     "Go file write"),
        (r"\bFile\.write\b|open\s*\([^)]*['\"](?:w|a|x|r\+)",         "HIGH",     "Python file write/append"),
        (r"\bFileWriter\b|Files\.write\b|PrintWriter\b",               "HIGH",     "Java file write"),
        (r"\bFile\.open.*['\"]w|IO\.write\b",                          "HIGH",     "Ruby file write"),
        (r"\bfs\.(?:writeFile|appendFile|write|rename|unlink)\b",      "HIGH",     "Node.js fs write"),
    ],
    "SQL": [
        (r"\bcursor\.execute\s*\(",                                     "CRITICAL", "Python DB execute (check parameterization)"),
        (r"\b(?:execute|executemany)\s*\(",                            "HIGH",     "DB execute"),
        (r"\bdb\.(?:Exec|Query|QueryRow|QueryContext)\s*\(",           "HIGH",     "Go DB query"),
        (r"\b(?:executeQuery|executeUpdate|execute)\s*\(",             "HIGH",     "JDBC execute"),
        (r"\bPDO::(?:query|exec)\b|mysqli_query\b",                    "HIGH",     "PHP SQL"),
        (r"\bactiverecord|where\s*\(['\"].*\+",                        "CRITICAL", "ORM string concatenation in query"),
        (r"\bknex\.\w+|sequelize\.\w+\b",                              "MEDIUM",   "JS ORM query"),
        (r"\braw_query|rawQuery|nativeQuery\b",                        "CRITICAL", "Raw/native DB query"),
        (r'[\'"]SELECT\b.*\+|[\'"]INSERT\b.*\+|[\'"]UPDATE\b.*\+|[\'"]DELETE\b.*\+', "CRITICAL", "SQL string concatenation"),
    ],
    "NETWORK_OUT": [
        (r"\b(?:send|sendto|sendmsg)\s*\(",                            "HIGH",     "Raw socket send"),
        (r"\bwrite\s*\([^)]{0,60}(?:sock|conn|client|peer)",          "HIGH",     "Write to socket fd"),
        (r"\b(?:conn|w|sock|c)\.Write\s*\(",                          "HIGH",     "Go network write"),
        (r"\b(?:response\.write|resp\.Write|w\.Write)\b",             "MEDIUM",   "HTTP response write"),
        (r"\bsocket\.(?:emit|send|write)\b",                          "MEDIUM",   "WebSocket send"),
        (r"\brequests\.(?:post|put|patch)\b|urllib\.request\.urlopen\b", "MEDIUM", "Python HTTP out"),
        (r"\bhttp\.Post\b|http\.Do\b",                                 "MEDIUM",   "Go HTTP client"),
    ],
}

# Compile all patterns once at module load
def _compile_patterns(
    raw: dict[str, list[tuple[str, str, str | None]]],
) -> dict[str, list[tuple[re.Pattern[str], str, str]]]:
    compiled: dict[str, list[tuple[re.Pattern[str], str, str]]] = {}
    for category, entries in raw.items():
        compiled[category] = []
        for pat, *rest in entries:
            try:
                compiled[category].append((re.compile(pat, re.IGNORECASE), rest[0], rest[1] if len(rest) > 1 else ""))
            except re.error:
                pass
    return compiled


def _compile_boundary_patterns(
    raw: dict[str, list[tuple[str, str]]],
) -> dict[str, list[tuple[re.Pattern[str], str]]]:
    compiled: dict[str, list[tuple[re.Pattern[str], str]]] = {}
    for category, entries in raw.items():
        compiled[category] = []
        for pat, desc in entries:
            try:
                compiled[category].append((re.compile(pat, re.IGNORECASE), desc))
            except re.error:
                pass
    return compiled


_COMPILED_ENTRIES:     dict[str, list[tuple[re.Pattern[str], str, str]]] = _compile_patterns(_ENTRY_PATTERNS)       # type: ignore[arg-type]
_COMPILED_SINKS:       dict[str, list[tuple[re.Pattern[str], str, str]]] = _compile_patterns(_SINK_PATTERNS)        # type: ignore[arg-type]
_COMPILED_BOUNDARIES:  dict[str, list[tuple[re.Pattern[str], str]]]      = _compile_boundary_patterns(_BOUNDARY_PATTERNS)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class Match:
    file:     str
    line:     int
    category: str
    risk:     str         # CRITICAL / HIGH / MEDIUM  (entries/sinks only)
    desc:     str         # human description of the pattern
    text:     str         # matched line content (stripped)
    context:  list[str]   # surrounding lines

@dataclass
class Flow:
    entry_desc:   str
    entry_file:   str
    entry_line:   int
    sink_desc:    str
    sink_file:    str
    sink_line:    int
    data_path:    str
    sanitization: str
    exploitability: str   # DIRECT / INDIRECT / THEORETICAL
    cwe:          str
    attack_scenario: str = ""


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def _collect_files(repo_path: Path, extensions: frozenset[str]) -> list[Path]:
    files: list[Path] = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            p = Path(root) / name
            if p.suffix.lower() not in extensions:
                continue
            try:
                if p.stat().st_size <= MAX_FILE_BYTES:
                    files.append(p)
            except OSError:
                pass
    return files


def _read_file(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _context(lines: list[str], idx: int) -> list[str]:
    start = max(0, idx - CONTEXT_LINES)
    end   = min(len(lines), idx + CONTEXT_LINES + 1)
    return [f"{start + i + 1:4d}  {lines[start + i]}" for i in range(end - start)]


# ---------------------------------------------------------------------------
# Phase 1 — Entry point scanner
# ---------------------------------------------------------------------------

def scan_entry_points(files: list[Path], repo_path: Path) -> list[Match]:
    results: list[Match] = []
    counts: dict[str, int] = {}

    for path in files:
        lines = _read_file(path)
        rel   = str(path.relative_to(repo_path))
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            for category, patterns in _COMPILED_ENTRIES.items():
                if counts.get(category, 0) >= MAX_PER_CATEGORY:
                    continue
                for regex, risk, desc in patterns:
                    if regex.search(line):
                        results.append(Match(
                            file=rel, line=lineno, category=category,
                            risk=risk, desc=desc, text=stripped,
                            context=_context(lines, lineno - 1),
                        ))
                        counts[category] = counts.get(category, 0) + 1
                        break  # one match per line per category

    results.sort(key=lambda m: (_RISK_ORDER.get(m.risk, 9), m.file, m.line))
    return results


# ---------------------------------------------------------------------------
# Phase 2 — Trust boundary scanner
# ---------------------------------------------------------------------------

def scan_trust_boundaries(files: list[Path], repo_path: Path) -> list[Match]:
    results: list[Match] = []
    seen: set[tuple[str, int]] = set()

    for path in files:
        lines = _read_file(path)
        rel   = str(path.relative_to(repo_path))
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            for category, patterns in _COMPILED_BOUNDARIES.items():
                for regex, desc in patterns:
                    if regex.search(line):
                        key = (rel, lineno)
                        if key not in seen:
                            seen.add(key)
                            results.append(Match(
                                file=rel, line=lineno, category=category,
                                risk="HIGH", desc=desc, text=stripped,
                                context=_context(lines, lineno - 1),
                            ))
                        break

    results.sort(key=lambda m: (m.category, m.file, m.line))
    return results


# ---------------------------------------------------------------------------
# Phase 3 — Dangerous sink scanner
# ---------------------------------------------------------------------------

def scan_sinks(files: list[Path], repo_path: Path) -> list[Match]:
    results: list[Match] = []
    counts: dict[str, int] = {}

    for path in files:
        lines = _read_file(path)
        rel   = str(path.relative_to(repo_path))
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            for category, patterns in _COMPILED_SINKS.items():
                if counts.get(category, 0) >= MAX_PER_CATEGORY:
                    continue
                for regex, risk, desc in patterns:
                    if regex.search(line):
                        results.append(Match(
                            file=rel, line=lineno, category=category,
                            risk=risk, desc=desc, text=stripped,
                            context=_context(lines, lineno - 1),
                        ))
                        counts[category] = counts.get(category, 0) + 1
                        break

    results.sort(key=lambda m: (_RISK_ORDER.get(m.risk, 9), m.file, m.line))
    return results


# ---------------------------------------------------------------------------
# Phase 4 — Flow candidate selection + LLM analysis
# ---------------------------------------------------------------------------

def _select_flow_candidates(
    entries: list[Match],
    sinks:   list[Match],
) -> list[str]:
    """
    Return up to MAX_FLOW_FILES file paths that contain both entry points
    and sinks, ranked by combined risk score.
    """
    _risk_val = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

    entry_files: dict[str, int] = {}
    for m in entries:
        entry_files[m.file] = entry_files.get(m.file, 0) + _risk_val.get(m.risk, 0)

    sink_files: dict[str, int] = {}
    for m in sinks:
        sink_files[m.file] = sink_files.get(m.file, 0) + _risk_val.get(m.risk, 0)

    # Files with both entries and sinks
    both = {f: entry_files[f] * sink_files[f]
            for f in entry_files if f in sink_files}

    # If fewer than MAX_FLOW_FILES overlap, fill with highest-risk sink files
    if len(both) < MAX_FLOW_FILES:
        for f, score in sorted(sink_files.items(), key=lambda x: -x[1]):
            if f not in both and len(both) < MAX_FLOW_FILES:
                both[f] = score

    ranked = sorted(both, key=lambda f: -both[f])
    return ranked[:MAX_FLOW_FILES]


_FLOW_TOOL: dict[str, Any] = {
    "name": "map_flows",
    "description": (
        "Map data flows between entry points and dangerous sinks found in a source file. "
        "For each exploitable path, describe how tainted data moves from the entry to the sink, "
        "whether any sanitization exists, and how directly it is exploitable."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "flows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entry_description": {
                            "type": "string",
                            "description": "Short label for the entry point (e.g. 'recv() on line 42')",
                        },
                        "entry_line": {"type": "integer"},
                        "sink_description": {
                            "type": "string",
                            "description": "Short label for the dangerous sink (e.g. 'strcpy() on line 87')",
                        },
                        "sink_line": {"type": "integer"},
                        "data_path": {
                            "type": "string",
                            "description": (
                                "Trace of how data flows from entry to sink, "
                                "naming the key variables, function calls, or struct fields involved."
                            ),
                        },
                        "sanitization": {
                            "type": "string",
                            "description": (
                                "Any input validation, bounds checking, type coercion, or encoding "
                                "between entry and sink. Use 'none' if absent."
                            ),
                        },
                        "exploitability": {
                            "type": "string",
                            "enum": ["DIRECT", "INDIRECT", "THEORETICAL"],
                            "description": (
                                "DIRECT: tainted input reaches sink with no meaningful barrier. "
                                "INDIRECT: some processing but no security-relevant sanitization. "
                                "THEORETICAL: exploitable only under specific additional conditions."
                            ),
                        },
                        "cwe": {
                            "type": "string",
                            "description": "Most applicable CWE (e.g. CWE-120, CWE-78, CWE-89).",
                        },
                        "attack_scenario": {
                            "type": "string",
                            "description": "1-2 sentence description of how an attacker would exploit this.",
                        },
                    },
                    "required": [
                        "entry_description", "entry_line",
                        "sink_description", "sink_line",
                        "data_path", "sanitization",
                        "exploitability", "cwe",
                    ],
                },
            }
        },
        "required": ["flows"],
    },
}


def _analyze_file_flows(
    client:      anthropic.Anthropic,
    model:       str,
    file_path:   Path,
    rel_path:    str,
    repo_path:   Path,
    entries_in:  list[Match],
    sinks_in:    list[Match],
) -> list[Flow]:
    """Ask Claude to trace entry→sink flows in a single file."""
    lines = _read_file(file_path)
    content = "\n".join(lines)
    snippet = content[:MAX_SNIPPET_CHARS]
    if len(content) > MAX_SNIPPET_CHARS:
        snippet += f"\n\n… [{len(content) - MAX_SNIPPET_CHARS:,} chars truncated]"

    entry_list = "\n".join(
        f"  Line {m.line} [{m.category}/{m.risk}] {m.desc}: {m.text[:80]}"
        for m in entries_in
    )
    sink_list = "\n".join(
        f"  Line {m.line} [{m.category}/{m.risk}] {m.desc}: {m.text[:80]}"
        for m in sinks_in
    )

    prompt = (
        "You are a senior offensive security researcher performing a white-box data flow audit.\n\n"
        f"File: `{rel_path}`\n\n"
        "The following entry points (where untrusted data enters) were detected:\n"
        f"{entry_list or '  (none in this file)'}\n\n"
        "The following dangerous sinks (where data causes harm) were detected:\n"
        f"{sink_list or '  (none in this file)'}\n\n"
        "Analyse the source code below. Call `map_flows` with every data flow you can trace "
        "from an entry point to a dangerous sink. If no exploitable flows exist, return an "
        "empty flows array. Do NOT invent flows — only report what the code actually shows.\n\n"
        f"```\n{snippet}\n```"
    )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            tools=[_FLOW_TOOL],
            tool_choice={"type": "tool", "name": "map_flows"},
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIError:
        return []

    flows: list[Flow] = []
    for block in response.content:
        if block.type == "tool_use" and block.name == "map_flows":
            for f in block.input.get("flows", []):
                flows.append(Flow(
                    entry_desc   = f.get("entry_description", ""),
                    entry_file   = rel_path,
                    entry_line   = int(f.get("entry_line", 0)),
                    sink_desc    = f.get("sink_description", ""),
                    sink_file    = rel_path,
                    sink_line    = int(f.get("sink_line", 0)),
                    data_path    = f.get("data_path", ""),
                    sanitization = f.get("sanitization", "unknown"),
                    exploitability = f.get("exploitability", "THEORETICAL"),
                    cwe          = f.get("cwe", ""),
                    attack_scenario = f.get("attack_scenario", ""),
                ))
    return flows


def analyze_flows(
    client:    anthropic.Anthropic,
    model:     str,
    repo_path: Path,
    candidates: list[str],
    entries:   list[Match],
    sinks:     list[Match],
    log:       Any,
) -> list[Flow]:
    """Run flow analysis across all candidate files; return sorted flows."""
    entry_by_file: dict[str, list[Match]] = {}
    for m in entries:
        entry_by_file.setdefault(m.file, []).append(m)

    sink_by_file: dict[str, list[Match]] = {}
    for m in sinks:
        sink_by_file.setdefault(m.file, []).append(m)

    all_flows: list[Flow] = []
    _exploit_order = {"DIRECT": 0, "INDIRECT": 1, "THEORETICAL": 2}

    for rel in candidates:
        abs_path = repo_path / rel
        if not abs_path.is_file():
            continue
        log(f"[*] Flow analysis: {rel} …")
        file_flows = _analyze_file_flows(
            client    = client,
            model     = model,
            file_path = abs_path,
            rel_path  = rel,
            repo_path = repo_path,
            entries_in = entry_by_file.get(rel, []),
            sinks_in   = sink_by_file.get(rel, []),
        )
        log(f"    {len(file_flows)} flow(s) identified")
        all_flows.extend(file_flows)

    all_flows.sort(key=lambda f: _exploit_order.get(f.exploitability, 9))
    return all_flows


# ---------------------------------------------------------------------------
# Report building + saving
# ---------------------------------------------------------------------------

def _match_to_dict(m: Match) -> dict[str, Any]:
    return {
        "file":     m.file,
        "line":     m.line,
        "category": m.category,
        "risk":     m.risk,
        "desc":     m.desc,
        "text":     m.text,
        "context":  m.context,
    }


def _flow_to_dict(f: Flow) -> dict[str, Any]:
    return {
        "entry_desc":    f.entry_desc,
        "entry_file":    f.entry_file,
        "entry_line":    f.entry_line,
        "sink_desc":     f.sink_desc,
        "sink_file":     f.sink_file,
        "sink_line":     f.sink_line,
        "data_path":     f.data_path,
        "sanitization":  f.sanitization,
        "exploitability": f.exploitability,
        "cwe":           f.cwe,
        "attack_scenario": f.attack_scenario,
    }


def build_report(
    repo_path:   Path,
    lang:        str | None,
    model:       str,
    files:       list[Path],
    entries:     list[Match],
    boundaries:  list[Match],
    sinks:       list[Match],
    flows:       list[Flow],
) -> dict[str, Any]:
    entry_risk_counts = {r: sum(1 for m in entries if m.risk == r) for r in ("CRITICAL", "HIGH", "MEDIUM")}
    sink_risk_counts  = {r: sum(1 for m in sinks  if m.risk == r) for r in ("CRITICAL", "HIGH", "MEDIUM")}

    return {
        "scanner":   "glasswing-surface",
        "version":   "1.0.0",
        "model":     model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target":    str(repo_path),
        "lang":      lang or "all",
        "summary": {
            "files_scanned":     len(files),
            "entry_points":      len(entries),
            "trust_boundaries":  len(boundaries),
            "dangerous_sinks":   len(sinks),
            "flows_analyzed":    len(flows),
            "entry_by_risk":     entry_risk_counts,
            "sink_by_risk":      sink_risk_counts,
        },
        "entry_points":     [_match_to_dict(m) for m in entries],
        "trust_boundaries": [_match_to_dict(m) for m in boundaries],
        "dangerous_sinks":  [_match_to_dict(m) for m in sinks],
        "flows":            [_flow_to_dict(f) for f in flows],
    }


def save_report(report: dict[str, Any], repo_path: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w\-]", "_", repo_path.name) or "repo"
    date_str  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path  = output_dir / f"surface_{safe_name}_{date_str}.json"
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
_MAG  = "\033[95m"
_BLU  = "\033[94m"


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOR:
        return text
    return "".join(codes) + text + _R


_RISK_COLOR = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "MEDIUM":   _YEL,
}

_EXPLOIT_COLOR = {
    "DIRECT":      _RED + _BOLD,
    "INDIRECT":    _YEL,
    "THEORETICAL": _CYN,
}

_CAT_COLOR = {
    # Entry categories
    "NETWORK":       _BLU,
    "FILE":          _CYN,
    "CLI":           _GRN,
    "ENVIRONMENT":   _GRN,
    "SERIALIZATION": _RED,
    "IPC":           _MAG,
    "USER_INPUT":    _YEL,
    # Boundary categories
    "PRIVILEGE":     _RED,
    "SANDBOX":       _MAG,
    "AUTH":          _BLU,
    "KERNEL":        _RED + _BOLD,
    # Sink categories
    "CODE_EXEC":     _RED + _BOLD,
    "MEMORY":        _RED,
    "FILE_WRITE":    _YEL,
    "SQL":           _RED,
    "NETWORK_OUT":   _CYN,
}

_HR_W = 72


def _hr() -> str:
    return "─" * _HR_W


def _risk_badge(risk: str) -> str:
    return _c(f"[{risk}]", _RISK_COLOR.get(risk, ""))


def _cat_badge(cat: str) -> str:
    return _c(f"{cat}", _CAT_COLOR.get(cat, ""))


def print_surface_report(report: dict[str, Any]) -> None:
    """Render a surface mapper report to stdout."""
    s   = report.get("summary", {})
    ent = report.get("entry_points", [])
    bnd = report.get("trust_boundaries", [])
    snk = report.get("dangerous_sinks", [])
    flo = report.get("flows", [])

    # ── Header ──────────────────────────────────────────────────────────
    target   = Path(report.get("target", "?")).name
    lang_str = report.get("lang", "all")
    print(_hr())
    print(_c(f" GLASSWING SURFACE MAP — {target}  [{lang_str}]", _BOLD))
    print(_hr())
    print(f"  {'Target':<18}{report.get('target','?')}")
    print(f"  {'Files scanned':<18}{s.get('files_scanned', 0)}")
    er = s.get('entry_by_risk', {})
    sr = s.get('sink_by_risk', {})
    print(
        f"  {'Entry points':<18}{s.get('entry_points', 0)}"
        f"  {_c(str(er.get('CRITICAL',0))+' CRIT', _RED+_BOLD)}"
        f"  {_c(str(er.get('HIGH',0))+' HIGH', _RED)}"
        f"  {_c(str(er.get('MEDIUM',0))+' MED', _YEL)}"
    )
    print(f"  {'Trust boundaries':<18}{s.get('trust_boundaries', 0)}")
    print(
        f"  {'Dangerous sinks':<18}{s.get('dangerous_sinks', 0)}"
        f"  {_c(str(sr.get('CRITICAL',0))+' CRIT', _RED+_BOLD)}"
        f"  {_c(str(sr.get('HIGH',0))+' HIGH', _RED)}"
        f"  {_c(str(sr.get('MEDIUM',0))+' MED', _YEL)}"
    )
    print(f"  {'Flows traced':<18}{s.get('flows_analyzed', 0)}")

    # ── Entry Points ─────────────────────────────────────────────────────
    print(_hr())
    print(_c(" ENTRY POINTS", _BOLD) + f"  {_c('(top 20 by risk)', _DIM)}")
    print(_hr())

    if ent:
        for m in ent[:20]:
            badge = _risk_badge(m["risk"])
            cat   = _cat_badge(m["category"])
            loc   = f"{m['file']}:{m['line']}"
            print(f"  {badge:<28}  {cat:<22}  {_c(loc, _DIM)}")
            print(f"  {'':>2}{_c(m['text'][:80], _DIM)}")
    else:
        print(f"  {_c('No entry points detected.', _DIM)}")

    # ── Trust Boundaries ─────────────────────────────────────────────────
    print(_hr())
    print(_c(" TRUST BOUNDARIES", _BOLD))
    print(_hr())

    if bnd:
        prev_cat = None
        for m in bnd[:30]:
            if m["category"] != prev_cat:
                print(f"  {_c('── ' + m['category'], _CAT_COLOR.get(m['category'], ''))}")
                prev_cat = m["category"]
            loc = f"{m['file']}:{m['line']}"
            print(f"    {_c(loc, _DIM):<50}  {m['desc'][:48]}")
    else:
        print(f"  {_c('No trust boundaries detected.', _DIM)}")

    # ── Dangerous Sinks ──────────────────────────────────────────────────
    print(_hr())
    print(_c(" DANGEROUS SINKS", _BOLD) + f"  {_c('(top 20 by risk)', _DIM)}")
    print(_hr())

    if snk:
        for m in snk[:20]:
            badge = _risk_badge(m["risk"])
            cat   = _cat_badge(m["category"])
            loc   = f"{m['file']}:{m['line']}"
            print(f"  {badge:<28}  {cat:<22}  {_c(loc, _DIM)}")
            print(f"  {'':>2}{_c(m['text'][:80], _DIM)}")
    else:
        print(f"  {_c('No dangerous sinks detected.', _DIM)}")

    # ── Top Flows ────────────────────────────────────────────────────────
    print(_hr())
    print(_c(" TOP DATA FLOWS TO INVESTIGATE", _BOLD))
    print(_hr())

    if flo:
        for i, f in enumerate(flo[:5], 1):
            exploit_col = _EXPLOIT_COLOR.get(f["exploitability"], "")
            cwe_str     = f.get("cwe", "")
            print(
                f"\n  [{i}] {_c(f['exploitability'], exploit_col)}"
                + (f"   {_c(cwe_str, _DIM)}" if cwe_str else "")
            )
            # Entry → Sink
            print(f"  {'Entry':<10}{_c(f['entry_file'] + ':' + str(f['entry_line']), _CYN)}"
                  f"  {f['entry_desc'][:55]}")
            print(f"  {'Sink':<10}{_c(f['sink_file'] + ':' + str(f['sink_line']), _RED)}"
                  f"  {f['sink_desc'][:55]}")
            # Data path
            path_lines = textwrap.wrap(f["data_path"], width=60)
            print(f"  {'Flow':<10}{path_lines[0] if path_lines else ''}")
            for line in path_lines[1:]:
                print(f"  {'':>10}{line}")
            # Sanitization
            san = f.get("sanitization", "unknown")
            san_col = _GRN if san.lower() not in ("none", "unknown", "") else _RED
            print(f"  {'Sanitize':<10}{_c(san[:70], san_col)}")
            # Attack scenario
            scenario = f.get("attack_scenario", "")
            if scenario:
                for line in textwrap.wrap(scenario, width=60):
                    print(f"  {'':>10}{_c(line, _DIM)}")
    else:
        print(f"\n  {_c('No data flows traced.', _DIM)}")
        print(f"  {_c('(No files contained both entry points and dangerous sinks)', _DIM)}")

    print(f"\n{_hr()}")


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class SurfaceMapper:
    def __init__(
        self,
        repo_path:  str | Path,
        lang:       str | None = None,
        model:      str  = DEFAULT_MODEL,
        verbose:    bool = False,
        output_dir: Path = REPORTS_DIR,
    ) -> None:
        self.repo_path  = Path(repo_path).resolve()
        self.lang       = lang
        self.model      = model
        self.verbose    = verbose
        self.output_dir = output_dir
        self.client     = anthropic.Anthropic()

        if not self.repo_path.is_dir():
            raise ValueError(f"Not a directory: {self.repo_path}")

        # Resolve extension filter
        if lang:
            key = lang.lower().replace("-", "").replace("_", "")
            if key not in _LANG_EXTENSIONS:
                known = ", ".join(sorted(_LANG_EXTENSIONS))
                raise ValueError(f"Unknown language '{lang}'. Known: {known}, all")
            self._extensions = _LANG_EXTENSIONS[key]
        else:
            self._extensions = SCANNABLE_EXTENSIONS

    def _log(self, msg: str) -> None:
        print(msg, flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}", flush=True)

    def run(self) -> dict[str, Any]:
        # ── Collect ───────────────────────────────────────────────────────
        self._log(f"[*] Collecting files from {self.repo_path} …")
        files = _collect_files(self.repo_path, self._extensions)
        self._log(f"    {len(files)} file(s) selected"
                  + (f" [{self.lang}]" if self.lang else ""))

        if not files:
            self._log("[!] No files found — check --target and --lang.")
            return {}

        # ── Phase 1: Entry points ─────────────────────────────────────────
        self._log("[*] Phase 1 — Scanning for entry points …")
        entries = scan_entry_points(files, self.repo_path)
        ec = {r: sum(1 for m in entries if m.risk == r) for r in ("CRITICAL", "HIGH", "MEDIUM")}
        self._log(f"    {len(entries)} entry point(s): "
                  f"CRITICAL={ec['CRITICAL']}  HIGH={ec['HIGH']}  MEDIUM={ec['MEDIUM']}")
        for cat in _ENTRY_PATTERNS:
            n = sum(1 for m in entries if m.category == cat)
            if n:
                self._vlog(f"{cat}: {n}")

        # ── Phase 2: Trust boundaries ─────────────────────────────────────
        self._log("[*] Phase 2 — Mapping trust boundaries …")
        boundaries = scan_trust_boundaries(files, self.repo_path)
        self._log(f"    {len(boundaries)} boundary(s) identified")
        for cat in _BOUNDARY_PATTERNS:
            n = sum(1 for m in boundaries if m.category == cat)
            if n:
                self._vlog(f"{cat}: {n}")

        # ── Phase 3: Sinks ────────────────────────────────────────────────
        self._log("[*] Phase 3 — Scanning for dangerous sinks …")
        sinks = scan_sinks(files, self.repo_path)
        sc = {r: sum(1 for m in sinks if m.risk == r) for r in ("CRITICAL", "HIGH", "MEDIUM")}
        self._log(f"    {len(sinks)} sink(s): "
                  f"CRITICAL={sc['CRITICAL']}  HIGH={sc['HIGH']}  MEDIUM={sc['MEDIUM']}")
        for cat in _SINK_PATTERNS:
            n = sum(1 for m in sinks if m.category == cat)
            if n:
                self._vlog(f"{cat}: {n}")

        # ── Phase 4: Flow analysis ────────────────────────────────────────
        candidates = _select_flow_candidates(entries, sinks)
        self._log(f"[*] Phase 4 — Flow analysis across {len(candidates)} candidate file(s) …")

        flows = analyze_flows(
            client     = self.client,
            model      = self.model,
            repo_path  = self.repo_path,
            candidates = candidates,
            entries    = entries,
            sinks      = sinks,
            log        = self._log,
        )

        direct_count = sum(1 for f in flows if f.exploitability == "DIRECT")
        self._log(f"    {len(flows)} flow(s) traced  "
                  f"({direct_count} DIRECT, "
                  f"{sum(1 for f in flows if f.exploitability == 'INDIRECT')} INDIRECT, "
                  f"{sum(1 for f in flows if f.exploitability == 'THEORETICAL')} THEORETICAL)")

        # ── Save + print ──────────────────────────────────────────────────
        report   = build_report(self.repo_path, self.lang, self.model, files,
                                entries, boundaries, sinks, flows)
        out_path = save_report(report, self.repo_path, self.output_dir)
        self._log(f"\n[+] Report saved → {out_path}\n")
        print_surface_report(report)
        return report


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> "argparse.ArgumentParser":
    import argparse
    parser = argparse.ArgumentParser(
        prog="glasswing-surface",
        description="Attack surface mapper — Phase 2 of the Glasswing offensive pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/surface_mapper.py --target ./kafel --lang c\n"
            "  python src/surface_mapper.py --target ./myapp --lang python\n"
            "  python src/surface_mapper.py --target ./repo --verbose\n"
        ),
    )
    parser.add_argument("--target", "-t", required=True, metavar="PATH",
                        help="Local repository path to map.")
    parser.add_argument("--lang", "-l", default=None, metavar="LANG",
                        help="Language filter (c, python, go, etc.). Default: all.")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Claude model (default: {DEFAULT_MODEL}).")
    parser.add_argument("--output-dir", default=str(REPORTS_DIR), metavar="DIR",
                        help=f"Report output directory (default: {REPORTS_DIR}).")
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
        mapper = SurfaceMapper(
            repo_path  = args.target,
            lang       = args.lang,
            model      = args.model,
            verbose    = args.verbose,
            output_dir = Path(args.output_dir),
        )
        mapper.run()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
