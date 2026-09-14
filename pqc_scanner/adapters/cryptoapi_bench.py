

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

    for algo, patterns in _COMPILED_KEYWORDS.items():
        for pattern in patterns:
            if pattern.search(text):
                return algo
    return None


def _rows_from_xlsx(xlsx_path: Path) -> list[dict]:

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

        java_src_root = repo_root_path

    entries = _rows_from_xlsx(xlsx_path)

    if not entries:
        log.warning("No usable rows extracted from the spreadsheet -- "
                    "using direct source-file keyword scan instead")
        entries = _fallback_scan_source(java_src_root)
    else:
        log.info("Extracted %d row(s) from the spreadsheet", len(entries))


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
