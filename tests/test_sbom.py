from __future__ import annotations

from leitir.sbom import infer_license


def test_manifest_license_wins_over_files(tmp_path):
    (tmp_path / "LICENSE-MIT").write_text("SPDX-License-Identifier: Apache-2.0")
    assert infer_license({"license": "BSD-3-Clause"}, tmp_path) == (
        infer_license({"license": {"type": "BSD-3-Clause"}}, tmp_path)
    )
    result = infer_license({"license": "BSD-3-Clause"}, tmp_path)
    assert (result.identifier, result.method, result.confidence) == ("BSD-3-Clause", "manifest", "high")


def test_license_file_content_scan(tmp_path):
    (tmp_path / "LICENSE").write_text("SPDX-License-Identifier: Apache-2.0\n")
    result = infer_license({}, tmp_path)
    assert (result.identifier, result.method, result.confidence) == ("Apache-2.0", "license-file", "high")


def test_copying_content_scan(tmp_path):
    (tmp_path / "COPYING").write_text("# SPDX-License-Identifier: GPL-3.0-only\n")
    assert infer_license({}, tmp_path).method == "copying-file"


def test_conflicting_license_file_content_is_unknown(tmp_path):
    (tmp_path / "LICENSE").write_text("SPDX-License-Identifier: MIT\n")
    (tmp_path / "COPYING").write_text("SPDX-License-Identifier: GPL-3.0-only\n")

    result = infer_license({}, tmp_path)

    assert (result.identifier, result.method, result.confidence) == (None, "unknown", "low")


def test_filename_heuristic_and_unknown(tmp_path):
    (tmp_path / "LICENSE-MIT").write_text("license text without a machine identifier")
    result = infer_license({}, tmp_path)
    assert (result.identifier, result.method, result.confidence) == ("MIT", "filename", "medium")
    (tmp_path / "LICENSE-MIT").unlink()
    assert infer_license({}, tmp_path).identifier is None
    assert infer_license({}, tmp_path).method == "unknown"


def test_license_inference_is_deterministic(tmp_path):
    (tmp_path / "z").mkdir()
    (tmp_path / "z" / "LICENSE").write_text("SPDX-License-Identifier: MIT")
    (tmp_path / "LICENSE").write_text("SPDX-License-Identifier: ISC")
    assert infer_license({}, tmp_path) == infer_license({}, tmp_path)
    assert infer_license({}, tmp_path).identifier is None
