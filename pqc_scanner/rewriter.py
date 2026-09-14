"""
rewriter.py

Optional LLM-driven code *replacement* (as opposed to the text-only
recommendation produced by `recommender.py`).

Unlike a naive per-file rewrite, this migrates the whole project in a single,
**project-aware** call: every affected file is sent together so the model can
keep cross-file dependencies consistent (shared helper signatures, imports,
serialised formats, and the choice of PQC library). The batch is then applied
and validated atomically — if validation fails, every file is rolled back from
its `.bak`.

This capability is strictly opt-in: it is only reached via the CLI's
`--replace` flag. The default scan/recommend/report pipeline never imports
`anthropic` at runtime (the import here is deferred), so the tool stays
offline-only unless replacement is explicitly requested.

Safety model (see also `System.md` §5.5):
  - `--dry-run` performs the migration call and reports the proposed diffs and
    token cost, but writes nothing.
  - Otherwise each original is copied to `<file>.bak` before it is overwritten
    (unless `--no-backup`).
  - After applying, rewritten files are validated (Python syntax by default,
    plus an optional `--verify-cmd` such as a test command). On failure the
    entire batch is reverted from the backups.
  - Each rewritten file is also re-scanned with the existing detectors; a file
    is `verified` only when none of its targeted algorithms remain.
  - Every rewrite is a *suggested* migration requiring cryptographic review;
    PQC swaps are frequently not behaviour-preserving.
"""

import difflib
import subprocess
import sys
import time
from pathlib import Path

from .algorithms_db import get_profile
from .logging_setup import format_bytes, format_duration, get_logger
from .models import CodeRewrite, ReplacementRun, ScanResult
from .scanner import C_EXTENSIONS, PYTHON_EXTENSIONS, scan_file

log = get_logger(__name__)

DEFAULT_MODEL = "claude-opus-4-8"

# Opus 4.8 pricing, USD per token (input $5 / output $25 per 1M).
_INPUT_COST_PER_TOKEN = 5.0 / 1_000_000
_OUTPUT_COST_PER_TOKEN = 25.0 / 1_000_000

_PROJECT_TOOL = {
    "name": "emit_project_migration",
    "description": (
        "Return the complete migrated source for every affected file in the "
        "project, keeping cross-file usage consistent, plus a summary of the "
        "coordinated changes and any caveats."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "migrated_files": {
                "type": "array",
                "description": "One entry per file that was provided, in any order.",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "The exact path label given for this file.",
                        },
                        "migrated_source": {
                            "type": "string",
                            "description": (
                                "COMPLETE migrated contents of the file, ready to "
                                "write verbatim. Preserve unrelated code, structure "
                                "and comments; update imports."
                            ),
                        },
                        "changes_summary": {
                            "type": "string",
                            "description": "What changed in this file and why.",
                        },
                    },
                    "required": ["path", "migrated_source", "changes_summary"],
                },
            },
            "cross_file_notes": {
                "type": "string",
                "description": (
                    "How consistency was maintained across files (shared "
                    "signatures, imports, formats, library choice)."
                ),
            },
            "caveats": {
                "type": "string",
                "description": (
                    "Behavioural/cryptographic caveats a reviewer must check "
                    "(new dependencies, changed primitives, key/format changes, "
                    "wire-incompatibility). Say 'none' only if genuinely none."
                ),
            },
            "confidence": {
                "type": "string",
                "enum": ["high", "medium", "low"],
                "description": "Confidence the coordinated migration is correct and complete.",
            },
        },
        "required": ["migrated_files", "cross_file_notes", "caveats", "confidence"],
    },
}


class RewriteUnavailable(RuntimeError):
    """Raised when the LLM path cannot run (missing dependency or credentials)."""


def _make_client(api_key: str | None):
    log.debug("Initialising Anthropic client (key source: %s)",
              "--api-key" if api_key else "ANTHROPIC_API_KEY environment")
    try:
        import anthropic
    except ImportError as exc:  # deferred import keeps the default path offline
        log.error("The 'anthropic' package is not installed; --replace cannot run")
        raise RewriteUnavailable(
            "The --replace feature needs the 'anthropic' package. "
            "Install it with: pip install anthropic"
        ) from exc

    try:
        client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        log.debug("Anthropic client ready (SDK %s)",
                  getattr(anthropic, "__version__", "unknown"))
        return client
    except Exception as exc:
        log.error("Could not initialise the Anthropic client: %s", exc)
        raise RewriteUnavailable(
            "Could not initialise the Anthropic client. Set ANTHROPIC_API_KEY "
            "in your environment (or pass --api-key). Original error: " + str(exc)
        ) from exc


def _language_for(path: Path) -> str:
    if path.suffix in PYTHON_EXTENSIONS:
        return "python"
    if path.suffix in C_EXTENSIONS:
        return "c"
    return "java"


def _build_project_prompt(files: list[dict]) -> str:
    blocks = []
    for f in files:
        targets = []
        for algo in f["algorithms"]:
            profile = get_profile(algo)
            if profile is None:
                continue
            targets.append(f"      - {algo} -> {profile.pqc_alternative} ({profile.standard})")
        targets_text = "\n".join(targets) or "      - (use modern standardised equivalents)"
        blocks.append(
            f"### FILE: {f['path']}  [{f['language']}]\n"
            f"    Detected legacy algorithms and required targets:\n"
            f"{targets_text}\n"
            f"```\n{f['source']}\n```"
        )
    files_text = "\n\n".join(blocks)

    return (
        "You are migrating an entire project away from legacy, quantum-vulnerable "
        "cryptography. The files below belong to ONE project and may depend on each "
        "other (shared helper functions, imported names, serialised key/hash "
        "formats).\n\n"
        "Migrate ALL of them together and consistently:\n"
        "  1. Replace every detected legacy algorithm with its required target.\n"
        "  2. Keep cross-file usage consistent: if you change a function's "
        "signature, return type, import, or a serialised format in one file, "
        "update every other file that depends on it so the project still works.\n"
        "  3. Pick ONE library/approach for a given primitive and use it uniformly "
        "across all files.\n"
        "  4. Return the COMPLETE migrated source for every file via the "
        "emit_project_migration tool, echoing each file's exact path label.\n"
        "  5. Where a true post-quantum primitive is not a drop-in replacement "
        "(e.g. RSA/ECC encryption -> ML-KEM is a KEM, not a cipher), implement the "
        "closest correct modern equivalent and explain the semantic difference in "
        "'caveats'. Name any new third-party dependency in 'caveats'.\n"
        "  6. Do NOT leave any detected legacy algorithm in any file.\n\n"
        f"{files_text}"
    )


def _extract_tool_input(response) -> dict:
    log.debug("Model response blocks: %s",
              ", ".join(getattr(b, "type", "?") for b in response.content) or "none")
    for block in response.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "emit_project_migration":
            return dict(block.input)
    log.error("Model returned no emit_project_migration tool call (stop_reason=%s)",
              getattr(response, "stop_reason", "unknown"))
    raise RewriteUnavailable(
        "The model did not return a migration via the expected tool. Try re-running."
    )


def _call_model(client, model: str, files: list[dict]):
    """Single project-aware, streamed migration call. Returns (payload, usage)."""
    prompt = _build_project_prompt(files)
    log.info("Requesting project migration from %s: %d file(s), prompt %s",
             model, len(files), format_bytes(len(prompt.encode("utf-8"))))
    for f in files:
        log.debug("  sending %s [%s] targeting %s", f["path"], f["language"],
                  ", ".join(f["algorithms"]))
    log.trace("Full migration prompt:\n%s", prompt)

    started = time.perf_counter()
    with client.messages.stream(
        model=model,
        max_tokens=64000,
        thinking={"type": "adaptive"},
        tools=[_PROJECT_TOOL],
        tool_choice={"type": "auto"},
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        response = stream.get_final_message()

    log.info("Model responded in %s (stop_reason=%s)",
             format_duration(time.perf_counter() - started),
             getattr(response, "stop_reason", "unknown"))
    return _extract_tool_input(response), response.usage


def _validate_python_syntax(paths: list[Path]) -> str:
    """Compile each rewritten .py file. Returns '' on success, else an error string."""
    py_files = [p for p in paths if p.suffix in PYTHON_EXTENSIONS]
    if not py_files:
        log.debug("No Python files among the rewrites; skipping syntax check")
        return ""
    log.info("Validating Python syntax of %d rewritten file(s)", len(py_files))
    proc = subprocess.run(
        [sys.executable, "-m", "py_compile", *[str(p) for p in py_files]],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        log.error("Python syntax check FAILED (exit %d)", proc.returncode)
        return f"Python syntax check failed:\n{proc.stderr.strip()}"
    log.info("Python syntax check passed")
    return ""


def _run_verify_cmd(verify_cmd: str) -> str:
    """Run a user-supplied validation command. Returns '' on success, else an error."""
    log.info("Running verification command: %s", verify_cmd)
    started = time.perf_counter()
    proc = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
    elapsed = format_duration(time.perf_counter() - started)
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip()[-1500:]
        log.error("Verification command FAILED after %s (exit %d)", elapsed, proc.returncode)
        log.debug("Verification output tail:\n%s", tail)
        return f"Validation command failed (exit {proc.returncode}):\n{tail}"
    log.info("Verification command passed in %s", elapsed)
    return ""


def apply_rewrites(
    scan_result: ScanResult,
    model: str = DEFAULT_MODEL,
    api_key: str | None = None,
    backup: bool = True,
    dry_run: bool = False,
    verify_cmd: str | None = None,
) -> ReplacementRun:
    """
    Migrate every affected file in one coordinated LLM call, then (unless
    dry-run) apply and validate the batch atomically, rolling back all files
    on validation failure. Raises RewriteUnavailable only if the client cannot
    be created or the model returns no migration; per-file issues are reported.
    """
    log.info("Starting %s of %d finding(s) with model %s",
             "DRY RUN migration" if dry_run else "migration",
             len(scan_result.findings), model)
    client = _make_client(api_key)
    run = ReplacementRun(dry_run=dry_run)

    # Gather the affected files.
    files: list[dict] = []
    read_errors: list[CodeRewrite] = []
    for file_path, findings in scan_result.by_file().items():
        path = Path(file_path)
        algorithms = sorted({f.algorithm for f in findings})
        language = findings[0].language if findings else _language_for(path)
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            log.error("  cannot read %s for migration: %s", file_path, exc)
            read_errors.append(CodeRewrite(
                file_path=file_path, language=language, algorithms_addressed=algorithms,
                changes_summary=f"Could not read file: {exc}", caveats="File was not modified.",
                confidence="low", modified=False, verified=False,
                remaining_algorithms=algorithms, backup_path=None, diff="",
            ))
            continue
        files.append({"path": file_path, "path_obj": path, "language": language,
                      "algorithms": algorithms, "source": source})
        log.debug("  queued %s [%s] %s (%s)", file_path, language,
                  ", ".join(algorithms),
                  format_bytes(len(source.encode("utf-8"))))

    if not files:
        log.error("No readable affected files; nothing to migrate")
        run.rewrites = read_errors
        return run

    log.info("Gathered %d file(s) for migration (%d unreadable)",
             len(files), len(read_errors))

    payload, usage = _call_model(client, model, files)

    run.overall_summary = payload.get("cross_file_notes", "")
    run.cross_file_notes = payload.get("cross_file_notes", "")
    shared_caveats = payload.get("caveats", "")
    confidence = payload.get("confidence", "medium")
    run.input_tokens = getattr(usage, "input_tokens", 0) or 0
    run.output_tokens = getattr(usage, "output_tokens", 0) or 0
    run.estimated_cost_usd = round(
        run.input_tokens * _INPUT_COST_PER_TOKEN
        + run.output_tokens * _OUTPUT_COST_PER_TOKEN, 4,
    )
    log.info("Token usage: %d in / %d out -> estimated cost $%.4f",
             run.input_tokens, run.output_tokens, run.estimated_cost_usd)
    log.debug("Model confidence in the coordinated migration: %s", confidence)
    if shared_caveats:
        log.warning("Caveats reported by the model: %s", shared_caveats)

    # Index the model's returned files by path (exact, then basename fallback).
    returned = {m["path"]: m for m in payload.get("migrated_files", []) if "path" in m}
    by_basename = {Path(k).name: v for k, v in returned.items()}
    log.debug("Model returned migrated source for %d of %d file(s)",
              len(returned), len(files))

    rewrites: list[CodeRewrite] = list(read_errors)
    written: list[tuple[Path, str]] = []  # (path, backup_path) for possible revert

    for f in files:
        match = returned.get(f["path"]) or by_basename.get(f["path_obj"].name)
        if match is None:
            log.warning("  no migration returned for %s -- left unchanged", f["path"])
            rewrites.append(CodeRewrite(
                file_path=f["path"], language=f["language"],
                algorithms_addressed=f["algorithms"],
                changes_summary="Model did not return a migration for this file.",
                caveats=shared_caveats, confidence=confidence, modified=False,
                verified=False, remaining_algorithms=f["algorithms"],
                backup_path=None, diff="",
            ))
            continue

        migrated = match.get("migrated_source", "")
        diff = "".join(difflib.unified_diff(
            f["source"].splitlines(keepends=True),
            migrated.splitlines(keepends=True),
            fromfile=f"{f['path']} (original)", tofile=f"{f['path']} (migrated)",
        ))
        combined_caveats = "; ".join(c for c in (shared_caveats,) if c)
        added = sum(1 for ln in diff.splitlines()
                    if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in diff.splitlines()
                      if ln.startswith("-") and not ln.startswith("---"))

        if dry_run:
            log.info("  [proposed] %s: +%d/-%d line(s)", f["path"], added, removed)
            log.trace("  diff for %s:\n%s", f["path"], diff)
            rewrites.append(CodeRewrite(
                file_path=f["path"], language=f["language"],
                algorithms_addressed=f["algorithms"],
                changes_summary=match.get("changes_summary", ""),
                caveats=combined_caveats, confidence=confidence, modified=False,
                verified=False, remaining_algorithms=[], backup_path=None, diff=diff,
            ))
            continue

        path = f["path_obj"]
        backup_path = None
        if backup:
            backup_path = str(path) + ".bak"
            Path(backup_path).write_text(f["source"], encoding="utf-8")
            log.debug("  backed up %s -> %s", path.name, backup_path)
        else:
            log.warning("  no backup for %s (--no-backup): rollback impossible",
                        path.name)
        path.write_text(migrated, encoding="utf-8")
        log.info("  [written]  %s: +%d/-%d line(s), %s", f["path"], added, removed,
                 format_bytes(len(migrated.encode("utf-8"))))
        log.trace("  diff for %s:\n%s", f["path"], diff)
        written.append((path, backup_path))

        rewrites.append(CodeRewrite(
            file_path=f["path"], language=f["language"],
            algorithms_addressed=f["algorithms"],
            changes_summary=match.get("changes_summary", ""),
            caveats=combined_caveats, confidence=confidence, modified=True,
            verified=False, remaining_algorithms=[], backup_path=backup_path, diff=diff,
        ))

    run.rewrites = rewrites

    if dry_run or not written:
        run.validation_summary = "Dry run — no files written." if dry_run else "No files written."
        log.info("%s", run.validation_summary)
        return run

    # --- Validate the applied batch, revert all on failure ---
    log.info("Validating the applied batch of %d file(s)", len(written))
    written_paths = [p for p, _ in written]
    error = _validate_python_syntax(written_paths)
    if not error and verify_cmd:
        error = _run_verify_cmd(verify_cmd)

    if error:
        can_revert = all(bak for _, bak in written)
        if can_revert:
            log.error("Validation failed -- rolling back %d file(s)", len(written))
            for path, bak in written:
                path.write_text(Path(bak).read_text(encoding="utf-8"), encoding="utf-8")
                log.info("  restored %s from %s", path, bak)
            run.reverted = True
            run.validation_summary = (
                f"{error}\n\nAll {len(written)} file(s) were rolled back from backups."
            )
            for rw in run.rewrites:
                if rw.modified:
                    rw.modified = False
                    rw.verified = False
                    rw.remaining_algorithms = rw.algorithms_addressed
                    rw.caveats = ("Reverted after failed validation. " + rw.caveats).strip()
        else:
            log.error("Validation failed and backups are disabled -- %d file(s) "
                      "remain modified and may be broken", len(written))
            run.validation_summary = (
                f"{error}\n\nCould NOT roll back (backups disabled via --no-backup); "
                f"files remain modified and may be broken."
            )
        return run

    # Validation passed — re-scan each written file to verify the legacy algo is gone.
    run.validation_summary = "Validation passed."
    if verify_cmd:
        run.validation_summary = "Validation passed (syntax + verify command)."
    log.info("Re-scanning rewritten file(s) to confirm the legacy algorithms are gone")
    for rw in run.rewrites:
        if not rw.modified:
            continue
        remaining = {fnd.algorithm for fnd in scan_file(Path(rw.file_path))}
        still = sorted(set(rw.algorithms_addressed) & remaining)
        rw.verified = not still
        rw.remaining_algorithms = still
        if still:
            log.warning("  %s still contains %s after rewrite -- needs review",
                        rw.file_path, ", ".join(still))
        else:
            log.info("  %s verified clean of %s", rw.file_path,
                     ", ".join(rw.algorithms_addressed))

    verified = sum(1 for rw in run.rewrites if rw.verified)
    log.info("Migration complete: %d/%d rewritten file(s) verified clean",
             verified, len(written))
    return run
