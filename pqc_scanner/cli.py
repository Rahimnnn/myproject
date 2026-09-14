"""
cli.py

Command-line entry point tying the scanner, recommender, and report
generator together, with an optional LLM-driven replacement pass.

Usage:
    python -m pqc_scanner.cli <path-to-file-or-directory> [--out-prefix report]
                             [--replace] [--dry-run] [--model MODEL]
                             [--api-key KEY] [--no-backup] [--verify-cmd CMD]
                             [-v | -vv | --quiet] [--log-file PATH] [--log-json]

Produces <out-prefix>.json and <out-prefix>.pdf in the current directory.

Progress is logged to stderr as the run proceeds — one line per file scanned,
with `-v` for detector internals and `-vv` for every individual match. stdout
carries only the final summary, so it stays pipeable. `--log-file` keeps a
full DEBUG transcript of the run regardless of the console verbosity, which is
what you want when a scan is part of a CI job or an audit trail.

By default the tool only *detects and recommends* — it runs fully offline and
never touches your source files. Passing --replace additionally rewrites every
affected file in one coordinated, project-aware pass (see rewriter.py); this
requires the `anthropic` package and an ANTHROPIC_API_KEY. Use --dry-run to
preview the migration (and its token cost) without changing anything.
"""

import argparse
import sys
import time

from . import __version__
from .logging_setup import configure_logging, format_duration, get_logger
from .rewriter import DEFAULT_MODEL, RewriteUnavailable, apply_rewrites
from .recommender import build_assessment
from .report_generator import to_json, to_pdf
from .scanner import scan_path

log = get_logger("cli")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pqc-scanner",
        description="Detect legacy cryptographic algorithms and recommend "
                    "NIST post-quantum alternatives.",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--out-prefix", default="pqc_report",
        help="Output filename prefix for the .json and .pdf reports (default: pqc_report)",
    )
    parser.add_argument(
        "--replace", action="store_true",
        help="Rewrite affected source files (project-aware, in one coordinated "
             "call) replacing legacy algorithms with their PQC/modern "
             "alternative. Requires 'anthropic' and ANTHROPIC_API_KEY.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="With --replace, preview the migration and its token cost without "
             "writing any files.",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Model used for --replace (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--api-key", default=None,
        help="Anthropic API key for --replace (falls back to ANTHROPIC_API_KEY).",
    )
    parser.add_argument(
        "--no-backup", action="store_true",
        help="With --replace, do NOT write <file>.bak backups before overwriting "
             "(disables automatic rollback on validation failure).",
    )
    parser.add_argument(
        "--verify-cmd", default=None,
        help="With --replace, a shell command to validate the project after "
             "rewriting (e.g. 'python -m pytest -q'). A non-zero exit rolls back "
             "the whole batch. Python syntax is always checked regardless.",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase log verbosity: -v adds detector internals and timings, "
             "-vv adds every individual pattern match.",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress the console summary and all logging below WARNING.",
    )
    parser.add_argument(
        "--log-file", default=None,
        help="Also write a full DEBUG log of the run to this file.",
    )
    parser.add_argument(
        "--log-json", action="store_true",
        help="Emit logs as one JSON object per line instead of formatted text.",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable coloured log output (also honoured via NO_COLOR).",
    )
    args = parser.parse_args(argv)

    configure_logging(
        verbosity=args.verbose,
        quiet=args.quiet,
        log_file=args.log_file,
        json_logs=args.log_json,
        color=False if args.no_color else None,
    )

    started = time.perf_counter()
    log.info("pqc-scanner %s starting", __version__)
    log.debug("Target: %s | out-prefix: %s | replace: %s | dry-run: %s | model: %s",
              args.target, args.out_prefix, args.replace, args.dry_run, args.model)
    if args.log_file:
        log.info("Full run log: %s", args.log_file)

    scan_result = scan_path(args.target)
    assessment = build_assessment(scan_result)

    replacement = None
    if args.replace:
        if not scan_result.findings:
            log.info("Nothing to replace: the scan found no legacy algorithms")
            if not args.quiet:
                print("No legacy algorithms detected — nothing to replace.")
        else:
            try:
                replacement = apply_rewrites(
                    scan_result,
                    model=args.model,
                    api_key=args.api_key,
                    backup=not args.no_backup,
                    dry_run=args.dry_run,
                    verify_cmd=args.verify_cmd,
                )
            except RewriteUnavailable as exc:
                log.error("Replacement unavailable: %s", exc)
                log.error("No files were modified; reports were still generated")

    json_path = f"{args.out_prefix}.json"
    pdf_path = f"{args.out_prefix}.pdf"
    log.info("Generating reports with prefix '%s'", args.out_prefix)
    to_json(assessment, json_path, replacement=replacement)
    to_pdf(assessment, pdf_path, scan_target=args.target, replacement=replacement)

    if not args.quiet:
        print(f"Scanned {assessment.files_scanned} file(s), "
              f"{assessment.total_findings} finding(s) across "
              f"{len(assessment.algorithms_detected)} algorithm(s).")
        for algo in assessment.algorithms_detected:
            print(f"  [{algo.severity:>8}] {algo.algorithm:<8} "
                  f"x{algo.occurrences:<3} -> {algo.pqc_alternative}")

        if replacement is not None:
            _print_replacement(replacement)

        print(f"\nReports written to {json_path} and {pdf_path}")

    log.info("Finished in %s", format_duration(time.perf_counter() - started))
    return 1 if scan_result.errors else 0


def _print_replacement(run) -> None:
    cost = (f"~${run.estimated_cost_usd:.4f} "
            f"({run.input_tokens} in / {run.output_tokens} out tokens)")
    if run.dry_run:
        print(f"\nDRY RUN — no files changed. Estimated cost of this preview: {cost}")
        for rw in run.rewrites:
            print(f"  [PROPOSED] {rw.file_path} ({', '.join(rw.algorithms_addressed)})")
        if run.cross_file_notes:
            print(f"  cross-file: {run.cross_file_notes}")
        print("  Review the diffs in the JSON report, then re-run without --dry-run.")
        return

    if run.reverted:
        print(f"\nMigration REVERTED — all files rolled back. Cost: {cost}")
        print(f"  reason: {run.validation_summary.splitlines()[0]}")
        return

    modified = [r for r in run.rewrites if r.modified]
    failed = [r for r in run.rewrites if not r.modified]
    print(f"\nRewrote {len(modified)} file(s); {len(failed)} not modified. Cost: {cost}")
    print(f"  validation: {run.validation_summary}")
    for rw in modified:
        status = "verified" if rw.verified else "NEEDS REVIEW"
        print(f"  [{status:>12}] {rw.file_path} ({', '.join(rw.algorithms_addressed)})")
        if rw.remaining_algorithms:
            print(f"                 still present after rewrite: "
                  f"{', '.join(rw.remaining_algorithms)}")
    for rw in failed:
        print(f"  [{'not modified':>12}] {rw.file_path} — {rw.changes_summary}")


if __name__ == "__main__":
    sys.exit(main())
