"""
cryptoapi_bench.py

Adapter bb that converts the CryptoAPI-Bench dataset
(https://github.com/CryptoGuardOSS/cryptoapi-bench,
newer 171-case version: https://github.com/CryptoAPI-Bench/CryptoAPI-Bench)
into a ground-truth file compatible with pqc_scanner.evaluate.

IMPORTANT -- read this before running:
This adapter was written by inspecting the benchmark's public README and
paper (Afrose, Rahaman & Yao, 2019), not by downloading the actual
`CryptoAPI-Bench_details.xlsx` file (this environment has no internet
access). The benchmark's README states the file "contains the summary of
secure and nonsecure code and pointed out the vulnerability", but the exact
column names are not documented publicly. This script therefore:

  1. Scans every cell in the spreadsheet, rather than assuming fixed column
     names, looking for (a) a cell that looks like a Java filename and
     (b) keyword hints for which legacy algorithm the row concerns.
  2. Falls back to scanning the .java source files directly for algorithm
     keywords if the spreadsheet parse doesn't yield usable rows -- this is
     less precise (file-level only) but always works.

Because CryptoAPI-Bench is a *misuse* benchmark (it also covers hardcoded
secrets, certificate validation, weak PRNGs, etc. that are outside this
project's 10-algorithm scope), this adapter only keeps rows/files that
relate to one of our target algorithms: RSA, ECC, DSA, DH, ElGamal, RC4,
DES, 3DES, MD5, SHA-1.

Ground truth here is FILE-LEVEL (no line numbers), since the benchmark is
organised as one/few small case files per vulnerability rather than
line-annotated production code. Use `evaluate.py`'s file-level comparison
mode for this dataset (it auto-detects ground-truth entries with no "line"
key).

Usage:
    python -m pqc_scanner.adapters.cryptoapi_bench \\
        /path/to/cloned/cryptoapi-bench \\
        --out ground_truth_cryptoapi_bench.json

    # then evaluate:
    python -m pqc_scanner.evaluate \\
        /path/to/cloned/cryptoapi-bench/src/main/java/org/cryptoapi/bench \\
        ground_truth_cryptoapi_bench.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

from ..logging_setup import configure_logging, get_logger

try:
    import openpyxl
except ImportError:
    openpyxl = None

log = get_logger("adapters.cryptoapi_bench")


# Keyword -> canonical algorithm name (must match pqc_scanner.algorithms_db keys)
_ALGORITHM_KEYWORDS: dict[str, list[str]] = {
    "RSA": [r"\bRSA\b"],
    "ECC": [r"\bECC\b", r"\bEC\b", r"\bECDSA\b", r"\bECDH\b", r"elliptic"],
    "DSA": [r"\bDSA\b"],
    "DH": [r"\bDiffieHellman\b", r"\bDH\b"],
    "ElGamal": [r"\bElGamal\b"],
    "RC4": [r"\bRC4\b", r"\bARCFOUR\b"],
    "3DES": [r"\b3DES\b", r"\bDESede\b", r"\bTripleDES\b"],
    "DES": [r"(?<!3)(?<!Triple)\bDES\b(?!ede)"],
    "MD5": [r"\bMD5\b"],
    "SHA-1": [r"\bSHA-?1\b"],
}
_COMPILED_KEYWORDS = {
    algo: [re.compile(p, re.IGNORECASE) for p in patterns]
    for algo, patterns in _ALGORITHM_KEYWORDS.items()
}


def _match_algorithm(text: str) -> str | None:
    """Return the first matching canonical algorithm name found in text, if any."""
    for algo, patterns in _COMPILED_KEYWORDS.items():
        for pattern in patterns:
            if pattern.search(text):
                return algo
    return None


def _rows_from_xlsx(xlsx_path: Path) -> list[dict]:
    """
    Best-effort parse of the details spreadsheet. Returns a list of
    {"file": <java filename found in row>, "algorithm": <matched algo>}
    for every row where both a filename-like cell and an algorithm keyword
    were found together.
    """
    if openpyxl is None:
        log.warning("openpyxl is not installed (pip install openpyxl); "
                    "skipping spreadsheet parse, falling back to source-file scan")
        return []

    if not xlsx_path.exists():
        log.warning("Spreadsheet not found at %s; falling back to source-file scan",
                    xlsx_path)
        return []

    log.info("Parsing benchmark spreadsheet: %s", xlsx_path)
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    log.debug("Workbook has %d sheet(s): %s", len(wb.worksheets),
              ", ".join(sheet.title for sheet in wb.worksheets))
    entries: list[dict] = []

    for sheet in wb.worksheets:
        for row in sheet.iter_rows(values_only=True):
            cells = [str(c) for c in row if c is not None]
            if not cells:
                continue
            row_text = " | ".join(cells)

            filename = None
            for cell in cells:
                if cell.strip().endswith(".java"):
                    filename = cell.strip()
                    break

            if filename is None:
                continue

            algo = _match_algorithm(row_text)
            if algo is None:
                continue

            entries.append({"file": filename, "algorithm": algo})

    return entries


def _fallback_scan_source(java_src_root: Path) -> list[dict]:
    """
    Fallback: scan each .java file's own content/filename for algorithm
    keywords. Less precise than the spreadsheet (no per-row case labels),
    but requires no spreadsheet parsing at all.
    """
    log.info("Falling back to keyword scan of .java sources under %s", java_src_root)
    entries: list[dict] = []
    scanned = 0
    for java_file in java_src_root.rglob("*.java"):
        scanned += 1
        text = java_file.read_text(encoding="utf-8", errors="ignore")
        found = set()
        for algo, patterns in _COMPILED_KEYWORDS.items():
            if any(p.search(text) for p in patterns):
                found.add(algo)
        for algo in found:
            entries.append({"file": str(java_file), "algorithm": algo})
        if found:
            log.debug("  %s -> %s", java_file.name, ", ".join(sorted(found)))
    log.info("Keyword scan read %d .java file(s), producing %d entr(ies)",
             scanned, len(entries))
    return entries


def build_ground_truth(repo_root: str, out_path: str) -> list[dict]:
    repo_root_path = Path(repo_root)
    xlsx_path = repo_root_path / "CryptoAPI-Bench_details.xlsx"
    java_src_root = repo_root_path / "src" / "main" / "java" / "org" / "cryptoapi" / "bench"

    if not java_src_root.exists():
        # Newer repo layout may differ; fall back to scanning the whole repo tree.
        java_src_root = repo_root_path

    entries = _rows_from_xlsx(xlsx_path)

    if not entries:
        log.warning("No usable rows extracted from the spreadsheet -- "
                    "using direct source-file keyword scan instead")
        entries = _fallback_scan_source(java_src_root)
    else:
        log.info("Extracted %d row(s) from the spreadsheet", len(entries))

    # De-duplicate
    unique = {(e["file"], e["algorithm"]) for e in entries}
    result = [{"file": f, "algorithm": a} for f, a in sorted(unique)]

    log.debug("De-duplicated %d entr(ies) down to %d", len(entries), len(result))
    Path(out_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    log.info("Wrote %d ground-truth entr(ies) to %s", len(result), out_path)
    print(f"Wrote {len(result)} ground-truth entries to {out_path}")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a pqc_scanner-compatible ground-truth file from "
                     "a locally cloned CryptoAPI-Bench repository."
    )
    parser.add_argument("repo_root", help="Path to the cloned cryptoapi-bench repository")
    parser.add_argument("--out", default="ground_truth_cryptoapi_bench.json",
                         help="Output ground-truth JSON path")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase log verbosity (-v, -vv)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Log only warnings and errors")
    parser.add_argument("--log-file", default=None,
                        help="Also write a full DEBUG log of the run to this file")
    args = parser.parse_args(argv)

    configure_logging(verbosity=args.verbose, quiet=args.quiet, log_file=args.log_file)

    build_ground_truth(args.repo_root, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
