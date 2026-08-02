"""Real, GitHub-verified package resolution fixtures (ADR-001 P4).

These constants were resolved against live registry + GitHub APIs. The offline
e2e test pins them; the opt-in live test re-verifies so drift is caught.
"""

from __future__ import annotations

PYPI_NAME = "requests"
PYPI_VERSION = "2.28.1"
PYPI_SLUG = "psf/requests"
PYPI_TAG = "v2.28.1"
PYPI_COMMIT_SHA = "4d394574f5555a8ddcc38f707e0c9f57f55d9a3b"

CRATES_NAME = "serde"
CRATES_VERSION = "1.0.152"
CRATES_SLUG = "serde-rs/serde"
CRATES_TAG = "v1.0.152"
CRATES_COMMIT_SHA = "ccf9c6fc072378ea8c4f15df1024e258d35d6e61"

GO_MODULE = "github.com/stretchr/testify"
GO_VERSION = "v1.8.1"
GO_SLUG = "stretchr/testify"
GO_TAG = "v1.8.1"
GO_COMMIT_SHA = "b747d7c5f853d017ddbc5e623d026d7fc2770a58"

RUST_KNOWN_SYMBOLS = ("Serialize", "Deserialize")
RUST_PATH = "serde/src/lib.rs"

GO_KNOWN_SYMBOLS = ("assert", "require")
GO_PATH = "assert/assertions.go"
