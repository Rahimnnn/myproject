"""
java_detector.py

Java source scanning. This prototype uses regex matching against the JCA/JCE
API surface (Cipher.getInstance, MessageDigest.getInstance, KeyPairGenerator,
Signature, KeyAgreement) since a full javalang/ANTLR-based AST pass is
out of scope for this prototype build. This corresponds to the "Java"
language target in Objective 2; the proposal's dissertation should document
this as an area for AST-based refinement using a library such as `javalang`.
"""

from .regex_detector import scan_text


def analyze_java_source(source: str) -> list[tuple[str, int, str]]:
    """Return (algorithm, line_number, matched_line) tuples for Java source."""
    return scan_text(source)
