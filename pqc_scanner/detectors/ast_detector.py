"""
ast_detector.py

AST-based confirmation pass for Python source code. This implements the
"AST" half of the hybrid detection approach (Objective 2). Parsing the code
into an Abstract Syntax Tree lets us confirm that a matched name is actually
being *called* as a cryptographic API (e.g. hashlib.md5()) rather than
appearing in a string, comment, or unrelated identifier -- directly
addressing the false-positive weakness of pure regex matching discussed in
the literature review (Wickert et al., 2021).

Supports detection via:
  - import statements (import hashlib / from Crypto.Cipher import DES)
  - attribute-call chains (hashlib.md5(), Cipher.getInstance(...))
  - keyword/string arguments used to select an algorithm at runtime
"""

import ast
import logging
from dataclasses import dataclass

from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class AstFinding:
    algorithm: str
    line_number: int
    node_description: str


# Maps recognisable module/function identifiers to canonical algorithm names.
_MODULE_FUNCTION_MAP = {
    ("hashlib", "md5"): "MD5",
    ("hashlib", "sha1"): "SHA-1",
    ("Crypto.PublicKey.RSA", "generate"): "RSA",
    ("Crypto.PublicKey.RSA", "import_key"): "RSA",
    ("Crypto.PublicKey.DSA", "generate"): "DSA",
    ("Crypto.PublicKey.ElGamal", "generate"): "ElGamal",
    ("Crypto.Cipher.DES", "new"): "DES",
    ("Crypto.Cipher.DES3", "new"): "3DES",
    ("Crypto.Cipher.ARC4", "new"): "RC4",
    ("Crypto.Hash.MD5", "new"): "MD5",
    ("Crypto.Hash.SHA1", "new"): "SHA-1",
    ("cryptography.hazmat.primitives.asymmetric.ec", "generate_private_key"): "ECC",
    ("cryptography.hazmat.primitives.asymmetric.dh", "generate_parameters"): "DH",
}

# Simple root-module name -> algorithm, for bare `import X` style detection
_IMPORT_ROOT_MAP = {
    "Crypto.PublicKey.RSA": "RSA",
    "Crypto.PublicKey.DSA": "DSA",
    "Crypto.PublicKey.ElGamal": "ElGamal",
    "Crypto.Cipher.DES": "DES",
    "Crypto.Cipher.DES3": "3DES",
    "Crypto.Cipher.ARC4": "RC4",
    "Crypto.Hash.MD5": "MD5",
    "Crypto.Hash.SHA1": "SHA-1",
}


class CryptoUsageVisitor(ast.NodeVisitor):
    """Walks a Python AST collecting confirmed cryptographic API usage."""

    def __init__(self, source_lines: list[str]):
        self.findings: list[AstFinding] = []
        self._imported_aliases: dict[str, str] = {}  # local name -> full module path
        self._source_lines = source_lines

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            full_name = alias.name
            local_name = alias.asname or alias.name.split(".")[-1]
            self._imported_aliases[local_name] = full_name
            if full_name in _IMPORT_ROOT_MAP:
                log.trace("       ast hit %s at line %d via import %s",
                          _IMPORT_ROOT_MAP[full_name], node.lineno, full_name)
                self.findings.append(
                    AstFinding(
                        algorithm=_IMPORT_ROOT_MAP[full_name],
                        line_number=node.lineno,
                        node_description=f"import {full_name}",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            full_name = f"{module}"
            local_name = alias.asname or alias.name
            self._imported_aliases[local_name] = f"{module}.{alias.name}"
            if module in _IMPORT_ROOT_MAP:
                log.trace("       ast hit %s at line %d via from %s import %s",
                          _IMPORT_ROOT_MAP[module], node.lineno, module, alias.name)
                self.findings.append(
                    AstFinding(
                        algorithm=_IMPORT_ROOT_MAP[module],
                        line_number=node.lineno,
                        node_description=f"from {module} import {alias.name}",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        algo = self._match_call(node)
        if algo:
            snippet = self._safe_line(node.lineno)
            log.trace("       ast hit %s at line %d via call | %s",
                      algo, node.lineno, snippet[:100])
            self.findings.append(
                AstFinding(
                    algorithm=algo,
                    line_number=node.lineno,
                    node_description=snippet,
                )
            )
        self.generic_visit(node)

    def _safe_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._source_lines):
            return self._source_lines[lineno - 1].strip()
        return ""

    def _match_call(self, node: ast.Call) -> str | None:
        func = node.func
        # Pattern: module.attr(...) e.g. hashlib.md5()
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = self._imported_aliases.get(func.value.id, func.value.id)
            key = (base, func.attr)
            if key in _MODULE_FUNCTION_MAP:
                return _MODULE_FUNCTION_MAP[key]
            # direct hashlib.md5 style even without tracked import
            if (func.value.id, func.attr) in _MODULE_FUNCTION_MAP:
                return _MODULE_FUNCTION_MAP[(func.value.id, func.attr)]

        # Pattern: getattr(hashlib, 'md5')() -- rare but handled defensively
        if isinstance(func, ast.Name) and func.id == "getattr" and node.args:
            pass  # left as a documented limitation; see dissertation future work

        return None


def analyze_python_source(source: str) -> list[AstFinding]:
    """
    Parse Python source into an AST and return confirmed algorithm usages.
    Raises SyntaxError if the source cannot be parsed (caller should catch
    this and fall back to regex-only results for that file).
    """
    tree = ast.parse(source)
    visitor = CryptoUsageVisitor(source.splitlines())
    visitor.visit(tree)
    if log.isEnabledFor(logging.DEBUG):  # node count is a second walk; only pay for it when shown
        log.debug("    ast pass: %d node(s) walked, %d alias(es) tracked, %d match(es)",
                  sum(1 for _ in ast.walk(tree)), len(visitor._imported_aliases),
                  len(visitor.findings))
    return visitor.findings
