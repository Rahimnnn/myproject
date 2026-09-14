

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    category: str
    quantum_threat: str
    severity: Severity
    pqc_alternative: str
    standard: str
    rationale: str



ALGORITHM_TAXONOMY: dict[str, AlgorithmProfile] = {
    "RSA": AlgorithmProfile(
        name="RSA",
        category="Public-key encryption / digital signatures",
        quantum_threat="Shor's algorithm (integer factorisation)",
        severity=Severity.CRITICAL,
        pqc_alternative="ML-KEM (Kyber) for encryption; ML-DSA (Dilithium) for signatures",
        standard="FIPS 203 / FIPS 204",
        rationale="RSA key exchange and signatures are fully broken by a "
                   "sufficiently large quantum computer running Shor's algorithm.",
    ),
    "ECC": AlgorithmProfile(
        name="ECC",
        category="Public-key cryptography (encryption/signatures/key exchange)",
        quantum_threat="Shor's algorithm (discrete logarithm on elliptic curves)",
        severity=Severity.CRITICAL,
        pqc_alternative="ML-KEM (Kyber) for key exchange; ML-DSA (Dilithium) for signatures",
        standard="FIPS 203 / FIPS 204",
        rationale="Elliptic-curve discrete-log problems are solved in polynomial "
                   "time by Shor's algorithm, breaking ECDH and ECDSA alike.",
    ),
    "DSA": AlgorithmProfile(
        name="DSA",
        category="Digital signatures",
        quantum_threat="Shor's algorithm (discrete logarithm)",
        severity=Severity.CRITICAL,
        pqc_alternative="ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)",
        standard="FIPS 204 / FIPS 205",
        rationale="Classical DSA signatures rely on the hardness of the discrete "
                   "logarithm problem, which Shor's algorithm solves efficiently.",
    ),
    "DH": AlgorithmProfile(
        name="DH",
        category="Key exchange",
        quantum_threat="Shor's algorithm (discrete logarithm)",
        severity=Severity.CRITICAL,
        pqc_alternative="ML-KEM (Kyber)",
        standard="FIPS 203",
        rationale="Diffie-Hellman key agreement is broken by Shor's algorithm; "
                   "ML-KEM provides a drop-in quantum-resistant key encapsulation mechanism.",
    ),
    "ElGamal": AlgorithmProfile(
        name="ElGamal",
        category="Public-key encryption",
        quantum_threat="Shor's algorithm (discrete logarithm)",
        severity=Severity.CRITICAL,
        pqc_alternative="ML-KEM (Kyber)",
        standard="FIPS 203",
        rationale="ElGamal's security rests on the discrete logarithm problem, "
                   "broken by Shor's algorithm.",
    ),
    "RC4": AlgorithmProfile(
        name="RC4",
        category="Symmetric stream cipher",
        quantum_threat="Not quantum-specific; classically broken (statistical biases)",
        severity=Severity.HIGH,
        pqc_alternative="AES-256-GCM or ChaCha20-Poly1305",
        standard="IETF RFC 7465 (deprecation)",
        rationale="RC4 has well-documented statistical biases and is deprecated by "
                   "IETF regardless of the quantum threat model.",
    ),
    "DES": AlgorithmProfile(
        name="DES",
        category="Symmetric block cipher",
        quantum_threat="Grover's algorithm (quadratic key-search speedup)",
        severity=Severity.CRITICAL,
        pqc_alternative="AES-256",
        standard="NIST SP 800-131A Rev. 2",
        rationale="DES's 56-bit key is already brute-forceable classically; "
                   "Grover's algorithm halves the effective security margin further.",
    ),
    "3DES": AlgorithmProfile(
        name="3DES",
        category="Symmetric block cipher",
        quantum_threat="Grover's algorithm (quadratic key-search speedup)",
        severity=Severity.HIGH,
        pqc_alternative="AES-256",
        standard="NIST SP 800-131A Rev. 2",
        rationale="3DES was deprecated by NIST in 2023; Grover's algorithm reduces "
                   "its effective security margin against quantum adversaries.",
    ),
    "MD5": AlgorithmProfile(
        name="MD5",
        category="Cryptographic hash function",
        quantum_threat="Grover's algorithm (search speedup) + classical collision attacks",
        severity=Severity.CRITICAL,
        pqc_alternative="SHA-256 or SHA-3-256",
        standard="NIST FIPS 180-4 / FIPS 202",
        rationale="MD5 has practical collision attacks independent of quantum "
                   "computing and is unsuitable for any security-relevant use.",
    ),
    "SHA-1": AlgorithmProfile(
        name="SHA-1",
        category="Cryptographic hash function",
        quantum_threat="Grover's algorithm (reduces effective security to ~80 bits)",
        severity=Severity.HIGH,
        pqc_alternative="SHA-256 or SHA-3-256",
        standard="NIST FIPS 180-4 / FIPS 202",
        rationale="SHA-1 has demonstrated collision attacks (SHAttered) and is "
                   "deprecated by NIST; Grover's algorithm reduces its margin further.",
    ),
}


def get_profile(algorithm_name: str) -> AlgorithmProfile | None:

    key_map = {k.upper(): k for k in ALGORITHM_TAXONOMY}
    key = key_map.get(algorithm_name.upper())
    return ALGORITHM_TAXONOMY.get(key) if key else None
