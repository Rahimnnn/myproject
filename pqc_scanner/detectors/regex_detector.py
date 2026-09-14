"""
regex_detector.py

Lightweight, language-agnostic first-pass detection using regular expressions.
This implements the "regex" half of the hybrid detection approach described
in the proposal (Objective 2). Regex matches are treated as *candidates*:
in the Python pipeline they are confirmed/refined by AST analysis; for Java
(where no AST parser is used in this prototype) regex is the primary method.

Patterns are intentionally written to match common API usage and import
statements rather than arbitrary substrings, to reduce false positives from
variable names/comments (see Rahaman et al., 2019 discussion in the proposal).

Python and Java share one pattern set (their crypto APIs read as method calls
and imports). C is different: legacy C code calls the OpenSSL/libcrypto API
directly (`MD5_Init`, `DES_set_key`, `RSA_generate_key`, the `EVP_*` family),
so it has its own pattern set and its own entry point (`scan_c_text`).
"""

import re
from dataclasses import dataclass

from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class RegexPattern:
    algorithm: str
    pattern: re.Pattern
    description: str


def _compile(patterns: dict[str, list[str]]) -> list[RegexPattern]:
    compiled = []
    for algo, raw_patterns in patterns.items():
        for raw in raw_patterns:
            compiled.append(
                RegexPattern(
                    algorithm=algo,
                    pattern=re.compile(raw, re.IGNORECASE),
                    description=raw,
                )
            )
    return compiled


# Patterns shared by both languages (import / API-call style usage)
_COMMON_PATTERNS: dict[str, list[str]] = {
    "RSA": [
        r"\bRSA\.(generate|new|import_key|importKey)\b",
        r"\bfrom\s+Crypto\.PublicKey\s+import\s+RSA\b",
        r"\bKeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']\s*\)",
        r"\bCipher\.getInstance\(\s*[\"']RSA",
    ],
    "ECC": [
        r"\bec\.generate_private_key\b",
        r"\bECC\.(generate|import_key)\b",
        r"\bKeyPairGenerator\.getInstance\(\s*[\"'](EC|ECDSA|ECDH)[\"']\s*\)",
        r"\bSECP256[R1K1]\b",
    ],
    "DSA": [
        r"\bDSA\.(generate|new)\b",
        r"\bKeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']\s*\)",
        r"\bSignature\.getInstance\(\s*[\"']SHA\d*withDSA[\"']\s*\)",
    ],
    "DH": [
        r"\bdh\.generate_parameters\b",
        r"\bKeyAgreement\.getInstance\(\s*[\"']DH[\"']\s*\)",
        r"\bDiffieHellman\b",
    ],
    "ElGamal": [
        r"\bElGamal\.(generate|new)\b",
    ],
    "RC4": [
        r"\bARC4\.new\b",
        r"\bCipher\.getInstance\(\s*[\"']RC4[\"']\s*\)",
        r"\bARCFOUR\b",
    ],
    "DES": [
        r"\bDES\.new\b",
        r"\bCipher\.getInstance\(\s*[\"']DES(?!ede)[\"'/]",
        r"\balgorithms\.TripleDES\b(?!.*3)",  # fallback, refined by AST
    ],
    "3DES": [
        r"\bDES3\.new\b",
        r"\bCipher\.getInstance\(\s*[\"']DESede",
        r"\balgorithms\.TripleDES\b",
    ],
    "MD5": [
        r"\bhashlib\.md5\b",
        r"\bMessageDigest\.getInstance\(\s*[\"']MD5[\"']\s*\)",
        r"\bMD5\.new\b",
    ],
    "SHA-1": [
        r"\bhashlib\.sha1\b",
        r"\bMessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']\s*\)",
        r"\bSHA1\.new\b",
    ],
}

COMPILED_PATTERNS = _compile(_COMMON_PATTERNS)


# C / OpenSSL (libcrypto) patterns. Legacy C rarely uses a uniform "getInstance"
# style surface, so these target the concrete low-level function names plus the
# EVP_* algorithm selectors. Kept separate from the Python/Java set because the
# API names don't overlap and mixing them would only add false positives.
_C_PATTERNS: dict[str, list[str]] = {
    "RSA": [
        r"\bRSA_generate_key(_ex)?\b",
        r"\bRSA_new\b",
        r"\bPEM_read_(bio_)?RSA\w*\b",
        r"\bEVP_PKEY_RSA\b",
    ],
    "ECC": [
        r"\bEC_KEY_new(_by_curve_name)?\b",
        r"\bEC_KEY_generate_key\b",
        r"\bEVP_PKEY_EC\b",
        r"\bNID_secp256k1\b",
        r"\bNID_X9_62_prime256v1\b",
    ],
    "DSA": [
        r"\bDSA_generate_key\b",
        r"\bDSA_generate_parameters(_ex)?\b",
        r"\bDSA_new\b",
        r"\bEVP_PKEY_DSA\b",
    ],
    "DH": [
        r"\bDH_generate_key\b",
        r"\bDH_generate_parameters(_ex)?\b",
        r"\bDH_new\b",
        r"\bEVP_PKEY_DH\b",
    ],
    "ElGamal": [
        r"\bElGamal\b",
    ],
    "RC4": [
        r"\bRC4_set_key\b",
        r"\bRC4\s*\(",
        r"\bEVP_rc4\b",
    ],
    "DES": [
        # Single-DES only: DES_ede*/EVP_des_ede* are 3DES and handled below.
        r"\bDES_(set_key(_checked|_unchecked)?|ecb_encrypt|cbc_encrypt|ncbc_encrypt|cfb_encrypt|crypt)\b",
        r"\bEVP_des_(ecb|cbc|cfb\w*|ofb)\b",
    ],
    "3DES": [
        r"\bDES_ede3_\w+\b",
        r"\bEVP_des_ede3?(_\w+)?\b",
    ],
    "MD5": [
        r"\bMD5_(Init|Update|Final)\b",
        r"\bMD5\s*\(",
        r"\bEVP_md5\b",
    ],
    "SHA-1": [
        r"\bSHA1_(Init|Update|Final)\b",
        r"\bSHA1\s*\(",
        r"\bEVP_sha1\b",
    ],
}

COMPILED_C_PATTERNS = _compile(_C_PATTERNS)


def _scan(source: str, compiled: list[RegexPattern]) -> list[tuple[str, int, str]]:
    matches: list[tuple[str, int, str]] = []
    lines = source.splitlines()
    comment_lines = 0
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip obvious comment-only lines to cut false positives
        # (`#` Python, `//`/`*`/`/*` Java and C line/block comments).
        if stripped.startswith(("#", "//", "*", "/*")):
            comment_lines += 1
            continue
        for rp in compiled:
            if rp.pattern.search(line):
                matches.append((rp.algorithm, idx, stripped))
                log.trace("       regex hit %s at line %d via /%s/",
                          rp.algorithm, idx, rp.description)
    log.debug("    regex pass: %d line(s), %d comment line(s) skipped, "
              "%d pattern(s) applied, %d match(es)",
              len(lines), comment_lines, len(compiled), len(matches))
    return matches


def scan_text(source: str) -> list[tuple[str, int, str]]:
    """
    Scan raw source text for Python/Java regex matches.

    Returns a list of (algorithm, line_number, matched_line_text) tuples.
    """
    return _scan(source, COMPILED_PATTERNS)


def scan_c_text(source: str) -> list[tuple[str, int, str]]:
    """Scan raw C source text against the OpenSSL/libcrypto pattern set."""
    return _scan(source, COMPILED_C_PATTERNS)
