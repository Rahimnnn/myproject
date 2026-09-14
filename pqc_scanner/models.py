"""
models.py

Shared data structures used across the detection, recommendation, and
reporting modules.
"""

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single detected instance of a legacy cryptographic algorithm."""
    algorithm: str
    file_path: str
    line_number: int
    code_snippet: str
    detection_method: str   # "regex" or "ast" or "regex+ast"
    confidence: float       # 0.0 - 1.0
    language: str           # "python", "java", or "c"


@dataclass
class ScanResult:
    """Aggregated result of scanning one or more files."""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def by_algorithm(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.algorithm, []).append(f)
        return grouped

    def by_file(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.file_path, []).append(f)
        return grouped


@dataclass
class CodeRewrite:
    """The outcome of an LLM-driven migration of one source file.

    Produced only by the opt-in `--replace` path. The original file is copied
    to `backup_path` (unless backups are disabled) before being overwritten
    with the migrated source. `verified` is True when a re-scan of the
    rewritten file no longer detects any of the algorithms it set out to
    replace; `remaining_algorithms` lists any that survived.
    """
    file_path: str
    language: str
    algorithms_addressed: list[str]
    changes_summary: str
    caveats: str
    confidence: str            # "high" | "medium" | "low"
    modified: bool             # True only if the file was actually overwritten (and kept)
    verified: bool
    remaining_algorithms: list[str]
    backup_path: str | None
    diff: str


@dataclass
class ReplacementRun:
    """The outcome of a whole-project `--replace` pass.

    The migration is performed as a single, project-aware LLM call (all
    affected files together) so cross-file dependencies stay consistent, then
    applied and validated as one atomic batch: if validation fails, every file
    is rolled back from its `.bak`.
    """
    rewrites: list[CodeRewrite] = field(default_factory=list)
    dry_run: bool = False
    reverted: bool = False
    overall_summary: str = ""
    cross_file_notes: str = ""
    validation_summary: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
