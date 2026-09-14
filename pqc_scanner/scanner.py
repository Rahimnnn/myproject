"""
scanner.py

Orchestrates the hybrid regex + AST detection pipeline (Objective 2 of the
proposal). For Python files: regex provides fast candidate matches, and the
AST pass confirms/refines them, boosting confidence and suppressing matches
that regex flagged inside comments or unrelated strings. For Java and C files:
regex is the primary method in this prototype (see java_detector.py and
c_detector.py).

Progress is reported through the `pqc_scanner.scanner` logger: one INFO line
per file scanned, DEBUG for how the two passes agreed, and TRACE for every
individual finding. See `logging_setup.py`.
"""

import logging
import time
from pathlib import Path

from .detectors import regex_detector, ast_detector, java_detector, c_detector
from .logging_setup import format_bytes, format_duration, get_logger
from .models import Finding, ScanResult

log = get_logger(__name__)

PYTHON_EXTENSIONS = {".py"}
JAVA_EXTENSIONS = {".java"}
C_EXTENSIONS = {".c", ".h"}
SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | JAVA_EXTENSIONS | C_EXTENSIONS

# How often to emit a running progress line during a large directory scan.
_PROGRESS_EVERY = 25


def _log_findings(path: Path, findings: list[Finding], elapsed: float) -> None:
    if not findings:
        log.debug("  no findings in %s (%s)", path.name, format_duration(elapsed))
        return

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.algorithm] = counts.get(finding.algorithm, 0) + 1
    summary = ", ".join(f"{algo} x{n}" for algo, n in sorted(counts.items()))
    log.info("  -> %d finding(s) in %s: %s", len(findings), path.name, summary)

    for finding in sorted(findings, key=lambda f: f.line_number):
        log.trace("     line %d  %-6s  via %-9s conf=%.2f  | %s",
                  finding.line_number, finding.algorithm,
                  finding.detection_method, finding.confidence,
                  finding.code_snippet[:100])


def _scan_python_file(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []

    regex_matches = regex_detector.scan_text(source)
    regex_by_line = {(algo, line) for algo, line, _ in regex_matches}

    ast_matches: list[ast_detector.AstFinding] = []
    ast_ok = True
    try:
        ast_matches = ast_detector.analyze_python_source(source)
    except SyntaxError as exc:
        ast_ok = False  # fall back to regex-only for this file
        log.warning("  AST parse failed for %s (line %s: %s) -- "
                    "falling back to regex-only, confidence reduced",
                    path.name, exc.lineno, exc.msg)

    ast_by_line = {(m.algorithm, m.line_number) for m in ast_matches}

    # Confirmed by both regex and AST -> high confidence
    confirmed = regex_by_line & ast_by_line
    # AST-only (e.g. aliased imports regex missed) -> high confidence
    ast_only = ast_by_line - regex_by_line
    # Regex-only (AST parse failed, or pattern regex catches that AST class
    # doesn't model, e.g. string-based Cipher.getInstance) -> medium confidence
    regex_only = regex_by_line - ast_by_line

    log.debug("  python passes on %s: regex=%d ast=%d -> confirmed=%d "
              "ast_only=%d regex_only=%d",
              path.name, len(regex_by_line), len(ast_by_line),
              len(confirmed), len(ast_only), len(regex_only))

    lines = source.splitlines()

    def line_text(n: int) -> str:
        return lines[n - 1].strip() if 1 <= n <= len(lines) else ""

    for algo, line in confirmed:
        findings.append(Finding(
            algorithm=algo, file_path=str(path), line_number=line,
            code_snippet=line_text(line), detection_method="regex+ast",
            confidence=0.98, language="python",
        ))
    for algo, line in ast_only:
        findings.append(Finding(
            algorithm=algo, file_path=str(path), line_number=line,
            code_snippet=line_text(line), detection_method="ast",
            confidence=0.95, language="python",
        ))
    for algo, line in regex_only:
        conf = 0.70 if ast_ok else 0.85  # lower confidence if AST could have confirmed but didn't
        findings.append(Finding(
            algorithm=algo, file_path=str(path), line_number=line,
            code_snippet=line_text(line), detection_method="regex",
            confidence=conf, language="python",
        ))

    return findings


def _scan_java_file(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for algo, line, snippet in java_detector.analyze_java_source(source):
        findings.append(Finding(
            algorithm=algo, file_path=str(path), line_number=line,
            code_snippet=snippet, detection_method="regex",
            confidence=0.75, language="java",
        ))
    log.debug("  java regex pass on %s: %d match(es)", path.name, len(findings))
    return findings


def _scan_c_file(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for algo, line, snippet in c_detector.analyze_c_source(source):
        findings.append(Finding(
            algorithm=algo, file_path=str(path), line_number=line,
            code_snippet=snippet, detection_method="regex",
            confidence=0.75, language="c",
        ))
    log.debug("  c regex pass on %s: %d match(es)", path.name, len(findings))
    return findings


def scan_file(path: Path) -> list[Finding]:
    started = time.perf_counter()
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        log.warning("  unreadable, skipping: %s (%s)", path, exc)
        return []

    log.debug("  read %s (%s, %d lines)", path.name,
              format_bytes(len(source.encode("utf-8", errors="ignore"))),
              source.count("\n") + 1)

    if path.suffix in PYTHON_EXTENSIONS:
        findings = _scan_python_file(path, source)
    elif path.suffix in JAVA_EXTENSIONS:
        findings = _scan_java_file(path, source)
    elif path.suffix in C_EXTENSIONS:
        findings = _scan_c_file(path, source)
    else:
        log.debug("  unsupported extension '%s', skipping %s", path.suffix, path.name)
        return []

    _log_findings(path, findings, time.perf_counter() - started)
    return findings


def _collect_candidates(root: Path) -> list[Path]:
    """Walk the tree, collecting every file with a supported extension."""
    candidates: list[Path] = []
    seen = 0
    walk_started = time.perf_counter()

    for path in root.rglob("*"):
        seen += 1
        if path.suffix in SUPPORTED_EXTENSIONS:
            candidates.append(path)
        else:
            log.trace("skipping unsupported entry %s", path)

    log.debug("walk of %s took %s: %d entr(ies) seen, %d supported",
              root, format_duration(time.perf_counter() - walk_started),
              seen, len(candidates))
    return candidates


def scan_path(target: str) -> ScanResult:
    """
    Scan a single file or a directory tree (recursively) for legacy
    cryptographic algorithm usage.
    """
    result = ScanResult()
    root = Path(target)
    started = time.perf_counter()

    if not root.exists():
        log.error("scan target does not exist: %s", root)
        result.errors.append(f"{root}: no such file or directory")
        return result

    if root.is_file():
        log.info("Scanning single file: %s", root)
        if root.suffix not in SUPPORTED_EXTENSIONS:
            log.warning("'%s' is not a supported source extension (%s); "
                        "the file will be read but no detector applies to it",
                        root.suffix or "(none)", ", ".join(sorted(SUPPORTED_EXTENSIONS)))
        candidates = [root]
    else:
        log.info("Scanning directory tree: %s", root.resolve())
        candidates = _collect_candidates(root)

    by_language: dict[str, int] = {}
    for path in candidates:
        key = ("python" if path.suffix in PYTHON_EXTENSIONS
               else "java" if path.suffix in JAVA_EXTENSIONS
               else "c" if path.suffix in C_EXTENSIONS else "other")
        by_language[key] = by_language.get(key, 0) + 1
    breakdown = ", ".join(f"{n} {lang}" for lang, n in sorted(by_language.items()))
    log.info("Found %d source file(s) to scan%s",
             len(candidates), f" ({breakdown})" if breakdown else "")

    if not candidates:
        log.warning("No supported source files (%s) under %s",
                    ", ".join(sorted(SUPPORTED_EXTENSIONS)), root)
        return result

    total = len(candidates)
    width = len(str(total))
    for index, path in enumerate(candidates, start=1):
        log.info("[%*d/%d] %s", width, index, total, path)
        result.files_scanned += 1
        try:
            result.findings.extend(scan_file(path))
        except Exception as exc:  # keep scanning even if one file misbehaves
            log.error("  scan failed for %s: %s", path, exc, exc_info=log.isEnabledFor(logging.DEBUG))
            result.errors.append(f"{path}: {exc}")

        if total > _PROGRESS_EVERY and index % _PROGRESS_EVERY == 0 and index != total:
            log.info("Progress: %d/%d file(s) (%.0f%%), %d finding(s) so far, %s elapsed",
                     index, total, 100 * index / total, len(result.findings),
                     format_duration(time.perf_counter() - started))

    elapsed = time.perf_counter() - started
    rate = result.files_scanned / elapsed if elapsed else 0.0
    log.info("Scan complete: %d file(s), %d finding(s), %d error(s) in %s (%.0f files/s)",
             result.files_scanned, len(result.findings), len(result.errors),
             format_duration(elapsed), rate)

    if result.errors:
        log.warning("%d file(s) could not be scanned:", len(result.errors))
        for message in result.errors:
            log.warning("  %s", message)

    return result
