"""Targeted tests for individual detection rules using small code snippets."""

import ast

import pytest

from cryptoanalyzer.rules.enc_trans.weak_enc.weak_hash import Cwe328WeakHashRule
from cryptoanalyzer.rules.key_mgmt.hardcoded_creds.hardcoded_credentials import (
    Cwe798HardcodedCredentialsRule,
)


def _run(rule, source):
    """Parse a snippet and return the rule's findings for it."""
    tree = ast.parse(source)
    return rule.check(tree, "<snippet>")


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib\nhashlib.md5(b'x')",
        "import hashlib\nhashlib.sha1(b'x')",
        "from hashlib import md5\nmd5(b'x')",
        "from hashlib import sha1\nsha1(b'x')",
    ],
)
def test_weak_hash_flags_known_weak_primitives(source):
    assert _run(Cwe328WeakHashRule(), source), f"expected a finding for: {source!r}"


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib\nhashlib.sha256(b'x')",
        "import hmac\nimport hashlib\nhmac.new(b'k', b'm', digestmod=hashlib.sha256)",
    ],
)
def test_weak_hash_ignores_strong_primitives(source):
    assert not _run(Cwe328WeakHashRule(), source), f"unexpected finding for: {source!r}"


def test_hardcoded_credentials_rule_metadata():
    """A rule must expose a stable name and at least one CWE id."""
    rule = Cwe798HardcodedCredentialsRule()
    assert rule.name
    assert rule.cwe_ids
    assert all(c.startswith("CWE-") for c in rule.cwe_ids)
