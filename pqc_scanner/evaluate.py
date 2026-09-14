"""
evaluate.py

Evaluation harness for Objective 4: computes precision, recall, and F1-score
against a manually labelled ground-truth file.

Ground truth format (JSON):
[
  {"file": "samples/legacy_auth.py", "line": 11, "algorithm": "RSA"},
  {"file": "samples/legacy_auth.py", "line": 16, "algorithm": "MD5"},
  ...
]

Usage:
    python -m pqc_scanner.evaluate <scan-target> <ground_truth.json>
"""

import argparse
import json
import sys
from pathlib import Path

from .logging_setup import configure_logging, get_logger
from .scanner import scan_path

log = get_logger("evaluate")


def _ground_truth_is_line_level(entries: list[dict]) -> bool:
    """Line-level datasets (our own hand-labelled samples) include a 'line'
    key on every entry. File-level datasets (e.g. CryptoAPI-Bench, where
    ground truth is per test-case file rather than per line) omit it."""
    return bool(entries) and all("line" in e for e in entries)


def load_ground_truth(path: str) -> tuple[set, bool]:
    """
    Returns (truth_set, is_line_level).
    Line-level: set of (file, line, ALGORITHM).
    File-level: set of (file, ALGORITHM).
    """
    data = json.loads(open(path, encoding="utf-8").read())
    if _ground_truth_is_line_level(data):
        return (
            {(e["file"], e["line"], e["algorithm"].upper()) for e in data},
            True,
        )
    return (
        {(e["file"], e["algorithm"].upper()) for e in data},
        False,
    )


def _normalize_path(path_str: str) -> str:
    """Compare paths by filename + immediate parent only, so ground-truth
    entries recorded with a different path prefix than the local scan
    target still match (useful when the dataset was labelled on a
    different machine or a different clone location)."""
    p = Path(path_str)
    return str(Path(p.parent.name) / p.name) if p.parent.name else p.name


def evaluate(scan_target: str, ground_truth_path: str, path_normalize: bool = True) -> dict:
    result = scan_path(scan_target)
    truth, is_line_level = load_ground_truth(ground_truth_path)
    log.info("Loaded %d %s ground-truth entr(ies) from %s",
             len(truth), "line-level" if is_line_level else "file-level",
             ground_truth_path)

    if is_line_level:
        predicted = {
            (f.file_path, f.line_number, f.algorithm.upper()) for f in result.findings
        }
        if path_normalize:
            predicted = {(_normalize_path(f), l, a) for f, l, a in predicted}
            truth = {(_normalize_path(f), l, a) for f, l, a in truth}
    else:
        # File-level: a finding "counts" as correct if the algorithm was
        # detected anywhere in the file, regardless of exact line.
        predicted = {(f.file_path, f.algorithm.upper()) for f in result.findings}
        if path_normalize:
            predicted = {(_normalize_path(f), a) for f, a in predicted}
            truth = {(_normalize_path(f), a) for f, a in truth}

    true_positives = predicted & truth
    false_positives = predicted - truth
    false_negatives = truth - predicted

    log.info("Comparing %d prediction(s) against %d truth entr(ies): "
             "TP=%d FP=%d FN=%d",
             len(predicted), len(truth), len(true_positives),
             len(false_positives), len(false_negatives))
    for item in sorted(false_positives, key=str):
        log.debug("  false positive: %s", item)
    for item in sorted(false_negatives, key=str):
        log.debug("  false negative: %s", item)

    precision = len(true_positives) / len(predicted) if predicted else 0.0
    recall = len(true_positives) / len(truth) if truth else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "granularity": "line-level" if is_line_level else "file-level",
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "meets_90pct_target": precision >= 0.90 and recall >= 0.90,
        "false_positive_details": sorted(false_positives, key=str),
        "false_negative_details": sorted(false_negatives, key=str),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate scanner against ground truth")
    parser.add_argument("target", help="File or directory that was scanned")
    parser.add_argument("ground_truth", help="Path to ground-truth JSON file")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase log verbosity (-v, -vv)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Log only warnings and errors")
    parser.add_argument("--log-file", default=None,
                        help="Also write a full DEBUG log of the run to this file")
    args = parser.parse_args(argv)

    configure_logging(verbosity=args.verbose, quiet=args.quiet, log_file=args.log_file)

    metrics = evaluate(args.target, args.ground_truth)
    log.info("precision=%.4f recall=%.4f f1=%.4f (%s target %s)",
             metrics["precision"], metrics["recall"], metrics["f1_score"],
             metrics["granularity"],
             "met" if metrics["meets_90pct_target"] else "NOT met")
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
