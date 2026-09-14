

from dataclasses import dataclass, field

from .algorithms_db import get_profile, Severity
from .logging_setup import get_logger
from .models import ScanResult

log = get_logger(__name__)


@dataclass
class AlgorithmAssessment:
    algorithm: str
    occurrences: int
    files_affected: list[str]
    severity: str
    category: str
    quantum_threat: str
    pqc_alternative: str
    standard: str
    rationale: str
    average_confidence: float


@dataclass
class SecurityAssessmentReport:
    total_findings: int
    files_scanned: int
    algorithms_detected: list[AlgorithmAssessment] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}


def build_assessment(scan_result: ScanResult) -> SecurityAssessmentReport:
    grouped = scan_result.by_algorithm()
    assessments: list[AlgorithmAssessment] = []
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}

    log.info("Building assessment for %d finding(s) across %d algorithm(s)",
             len(scan_result.findings), len(grouped))

    for algo, findings in grouped.items():
        profile = get_profile(algo)
        if profile is None:
            log.warning("  no profile in algorithms_db for '%s' -- "
                        "%d finding(s) omitted from the assessment",
                        algo, len(findings))
            continue  # unrecognised algorithm key; skip defensively

        files_affected = sorted({f.file_path for f in findings})
        avg_conf = sum(f.confidence for f in findings) / len(findings)

        assessments.append(AlgorithmAssessment(
            algorithm=algo,
            occurrences=len(findings),
            files_affected=files_affected,
            severity=profile.severity.value,
            category=profile.category,
            quantum_threat=profile.quantum_threat,
            pqc_alternative=profile.pqc_alternative,
            standard=profile.standard,
            rationale=profile.rationale,
            average_confidence=round(avg_conf, 2),
        ))
        severity_counts[profile.severity.value] += len(findings)

        log.debug("  %-8s %-8s x%-3d in %d file(s), avg confidence %.2f -> %s (%s)",
                  profile.severity.value, algo, len(findings), len(files_affected),
                  avg_conf, profile.pqc_alternative, profile.standard)


    assessments.sort(
        key=lambda a: (_SEVERITY_ORDER.get(Severity(a.severity), 99), -a.occurrences)
    )

    log.info("Assessment ready: %s",
             ", ".join(f"{n} {sev}" for sev, n in severity_counts.items() if n)
             or "no findings")

    return SecurityAssessmentReport(
        total_findings=len(scan_result.findings),
        files_scanned=scan_result.files_scanned,
        algorithms_detected=assessments,
        severity_counts=severity_counts,
        errors=scan_result.errors,
    )
