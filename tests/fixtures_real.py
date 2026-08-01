"""Real, GitHub-verified provenance used by the e2e gate tests.

These constants are not invented: they were resolved against the live GitHub
API for ``python/cpython`` at tag ``v3.11.0``. The offline e2e test pins them;
the opt-in live test re-verifies them so drift is caught.
"""

from __future__ import annotations

REPO_SLUG = "python/cpython"
TAG = "v3.11.0"
# Commit that v3.11.0 dereferences to (verified via /git/tags + /contents).
COMMIT_SHA = "deaf509e8fc6e0363bd6f26d52ad42f976ec42f2"
PATH = "Lib/urllib/parse.py"
# git blob SHA (sha1 of "blob <len>\0<bytes>"), verified via /contents.
BLOB_SHA = "d70a6943f0a73924ae56187db691792aa1f3ffc5"
BLOB_SIZE = 42540
# Symbols known to exist in that exact blob.
KNOWN_SYMBOLS = ("urlencode", "doseq")
