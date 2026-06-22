# cryptoanalyzer/utils/ast_utils.py

"""
AST utility functions for CryptoAnalyzer.

These helpers simplify common AST inspection tasks such as:
  - Reconstructing full dotted names from Attribute nodes
  - Identifying string/bytes constants
  - Detecting calls to specific functions or methods
  - Finding assignments to a given variable
  - Extracting literal values from AST nodes
"""

import ast
from typing import Optional, Union, List


def get_full_attr_name(node: ast.AST) -> str:
    """
    Given an ast.Attribute or ast.Name node, reconstruct the full dotted name.

    For example:
      - For `hashlib.md5`, called on the Attribute node for “md5”, returns "hashlib.md5".
      - For `Crypto.Cipher.DES.new`, called on the Attribute node for “new”, returns "Crypto.Cipher.DES.new".
      - For a bare Name node (e.g. `md5`), returns "md5".

    :param node: ast.Attribute or ast.Name
    :return: Dot-separated string of attribute names
    """
    parts: List[str] = []

    # Walk through Attribute nodes
    current = node
    while isinstance(current, ast.Attribute):
        parts.insert(0, current.attr)
        current = current.value

    # If the base is a Name, include it
    if isinstance(current, ast.Name):
        parts.insert(0, current.id)

    return ".".join(parts)


def get_constant_value(node: ast.AST) -> Optional[Union[str, int, bytes, float]]:
    """
    If the node is a Constant (string, bytes, number), return its Python value.
    Otherwise return None.

    Example:
      - Constant(value="secret") → "secret"
      - Constant(value=42)       → 42
      - Constant(value=b"\x00")  → b"\x00"

    :param node: ast.AST node
    :return: The literal value or None if not a literal Constant
    """
    if isinstance(node, ast.Constant):
        return node.value
    return None


def is_string_literal(node: ast.AST) -> bool:
    """
    Return True if the node represents a string literal.

    :param node: ast.AST node
    :return: True if node is Constant and its value is a str
    """
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_bytes_literal(node: ast.AST) -> bool:
    """
    Return True if the node represents a bytes literal.

    :param node: ast.AST node
    :return: True if node is Constant and its value is bytes or bytearray
    """
    return isinstance(node, ast.Constant) and isinstance(node.value, (bytes, bytearray))


def is_call_to(node: ast.AST, module_name: str, func_name: str) -> bool:
    """
    Return True if the node is a Call to module_name.func_name or alias.func_name.

    This does not resolve aliases declared via 'import as'; it only matches
    direct Attribute and Name nodes. For example:
      - is_call_to(node, "hashlib", "md5") matches `hashlib.md5(...)`
      - is_call_to(node, "Crypto.Cipher.DES", "new") matches `Crypto.Cipher.DES.new(...)`
      - is_call_to(node, "", "md5") matches `md5(...)` (bare import)

    :param node: ast.AST node (expected to be ast.Call)
    :param module_name: e.g. "hashlib" or "Crypto.Cipher.DES"
    :param func_name: e.g. "md5" or "new"
    :return: True if node is a Call to the desired function
    """
    if not isinstance(node, ast.Call):
        return False

    func = node.func

    # Case A: Attribute chain, e.g. module_name.func_name
    if isinstance(func, ast.Attribute):
        full = get_full_attr_name(func)
        expected = f"{module_name}.{func_name}" if module_name else func_name
        return full == expected

    # Case B: Name, e.g. 'md5' imported directly
    if isinstance(func, ast.Name) and not module_name:
        return func.id == func_name

    return False


def find_assignments_to_name(tree: ast.AST, var_name: str) -> List[ast.Assign]:
    """
    Return a list of ast.Assign nodes where the target is a Name matching var_name.

    Example: find_assignments_to_name(tree, "iv") will find all assignments like `iv = ...`.

    :param tree: AST of a module
    :param var_name: Variable name to look for
    :return: List of ast.Assign nodes
    """
    matches: List[ast.Assign] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == var_name:
                    matches.append(node)
    return matches


def find_function_defs(tree: ast.AST, func_name: str) -> List[ast.FunctionDef]:
    """
    Return a list of ast.FunctionDef nodes whose name matches func_name.

    :param tree: AST of a module
    :param func_name: Name of the function to find
    :return: List of ast.FunctionDef nodes
    """
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == func_name]


def extract_string_from_dict_key(node: ast.Dict) -> List[str]:
    """
    If the AST node is a dictionary literal, return a list of its string keys.
    Non-string keys are ignored.

    Example:
      For {"password": "123", "user": "admin"}, returns ["password", "user"].

    :param node: ast.Dict node
    :return: List of string keys
    """
    keys: List[str] = []
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.append(key.value)
    return keys


def extract_string_from_list(node: ast.List) -> List[str]:
    """
    If the AST node is a list literal of strings, return a list of those strings.
    Other element types are ignored.

    :param node: ast.List node
    :return: List of string elements
    """
    strings: List[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            strings.append(elt.value)
    return strings


def is_name_or_attr(node: ast.AST, names: List[str]) -> bool:
    """
    Return True if the node (Name or Attribute) matches any of the given names.

    - For a Name node, checks if node.id.lower() is in names.
    - For an Attribute node, checks if the final attribute (.attr) lowercased is in names.

    Example:
      is_name_or_attr(node, ["random", "secrets"]) matches both `random.random()` and `secrets.token_hex()`.

    :param node: ast.AST node
    :param names: List of lowercase names to match
    :return: True if node corresponds to any of the names
    """
    if isinstance(node, ast.Name):
        return node.id.lower() in names
    if isinstance(node, ast.Attribute):
        return node.attr.lower() in names
    return False
