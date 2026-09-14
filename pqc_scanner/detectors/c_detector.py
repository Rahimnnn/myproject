"""
c_detector.py

C source scanning. Like the Java prototype, this uses regex matching rather
than a full AST pass. C is the harder case for AST analysis: legacy sources
depend on the C preprocessor (macros, conditional compilation, platform
headers) and frequently will not parse cleanly without the exact build flags,
so a `pycparser`/`tree-sitter` pass is documented as future work. The patterns
target the OpenSSL/libcrypto API surface (the low-level `*_Init`/`*_set_key`
functions and the `EVP_*` algorithm selectors) — see `regex_detector.py`.
"""

from .regex_detector import scan_c_text


def analyze_c_source(source: str) -> list[tuple[str, int, str]]:
    """Return (algorithm, line_number, matched_line) tuples for C source."""
    return scan_c_text(source)
