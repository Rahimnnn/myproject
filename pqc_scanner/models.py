

from dataclasses import dataclass, field


@dataclass
class Finding:

    algorithm: str
    file_path: str
    line_number: int
    code_snippet: str
    detection_method: str   
    confidence: float       
    language: str           


@dataclass
class ScanResult:

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

    file_path: str
    language: str
    algorithms_addressed: list[str]
    changes_summary: str
    caveats: str
    confidence: str            
    modified: bool             
    verified: bool
    remaining_algorithms: list[str]
    backup_path: str | None
    diff: str


@dataclass
class ReplacementRun:

    rewrites: list[CodeRewrite] = field(default_factory=list)
    dry_run: bool = False
    reverted: bool = False
    overall_summary: str = ""
    cross_file_notes: str = ""
    validation_summary: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
