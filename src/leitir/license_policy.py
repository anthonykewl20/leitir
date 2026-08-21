"""Fail-closed license policy for source-bearing BTS payloads.

Unlike :mod:`leitir.sbom`, this module has no filesystem API.  Its complete
world is the caller-supplied set of digest-verified bytes.  That makes REUSE
scope, evidence selection, and NOTICE discovery reviewable and reproducible.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import re
import tomllib
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise

from .bts_errors import BTSRejectReason

SPDX_GRAMMAR_ID = "spdx-expression-2.3-leitir-v1"
OBLIGATIONS_SCHEMA_VERSION = "leitir-bts-obligations-v1"
LICENSE_POLICY_AUTHORITY = "leitir-maintainers"
LICENSE_POLICY_ID = "leitir-bts-license-policy"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PATH = re.compile(r"(?!/)(?!.*(?:^|/)\.\.?/)(?!.*\\)[^\x00\r\n]+")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")
_HEADER = re.compile(
    rb"(?im)^[ \t]*(?:[#*/;<!-]+[ \t]*)?SPDX-License-Identifier:[ \t]*([^\r\n*<>]+)"
)
_TEXT_FIELDS: tuple[tuple[bytes, str], ...] = (
    (b"SPDX-FileCopyrightText", "copyright"),
    (b"SPDX-FileNotice", "notice"),
    (b"SPDX-FileContributor", "contributor"),
    (b"SPDX-FileAttributionText", "attribution"),
)
_REVIEWED = ("0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT")

# A deliberately pinned subset of the SPDX 2.3 lists.  It covers the reviewed
# set and common deferred expressions, so syntax and policy support are distinct.
_LICENSE_IDS = (
    "0BSD",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-2.0",
    "Artistic-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC-BY-4.0",
    "CC0-1.0",
    "EPL-1.0",
    "EPL-2.0",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
)
_EXCEPTION_IDS = (
    "Autoconf-exception-2.0",
    "Autoconf-exception-3.0",
    "Bison-exception-2.2",
    "Classpath-exception-2.0",
    "GCC-exception-2.0",
    "GCC-exception-3.1",
    "LLVM-exception",
    "OpenJDK-assembly-exception-1.0",
)

# These bytes are policy artifacts, not inferred donor text.  Their hashes are
# part of LicensePolicy.content_digest and become exact payload obligations.
_LICENSE_TEXTS = {
    "0BSD": b"Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n",
    "MIT": b"Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n",
    "ISC": b"Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n",
    "BSD-2-Clause": b"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n\n1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES.\n",
    "BSD-3-Clause": b"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n\n1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES.\n",
    "Apache-2.0": b"Apache License\nVersion 2.0, January 2004\nhttps://www.apache.org/licenses/LICENSE-2.0\n",
}


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_path(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or _PATH.fullmatch(value) is None or any(
        part in {"", ".", ".."} for part in value.split("/")
    ):
        raise ValueError(f"{name} must be a strict relative POSIX path")


def _require_digest(value: str, name: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase sha256 digest")


@dataclass(frozen=True, slots=True, order=True)
class VerifiedBytes:
    """One manifest-listed regular file whose bytes have already been locked."""

    path: str
    content: bytes
    sha256: str
    package_scope: str = "."

    def __post_init__(self) -> None:
        _require_path(self.path, "path")
        if self.package_scope != ".":
            _require_path(self.package_scope, "package_scope")
        if not isinstance(self.content, bytes):
            raise TypeError("content must be bytes")
        _require_digest(self.sha256, "sha256")
        if self.sha256 != _sha(self.content):
            raise ValueError("verified byte digest mismatch")

    @classmethod
    def create(cls, path: str, content: bytes, package_scope: str = ".") -> VerifiedBytes:
        return cls(path, content, _sha(content), package_scope)


@dataclass(frozen=True, slots=True)
class BundledSource:
    """A source-bearing packet member and its complete verified package view."""

    source_record_id: str
    packet_path: str
    source_path: str
    source_bytes: bytes
    source_bytes_sha256: str
    package_scope: str
    verified_files: tuple[VerifiedBytes, ...]
    contributing_source_record_ids: tuple[str, ...] = ()
    modified_from_sha256: str | None = None

    def __post_init__(self) -> None:
        if _ID.fullmatch(self.source_record_id) is None:
            raise ValueError("source_record_id is invalid")
        _require_path(self.packet_path, "packet_path")
        _require_path(self.source_path, "source_path")
        if self.package_scope != ".":
            _require_path(self.package_scope, "package_scope")
        if not isinstance(self.source_bytes, bytes) or self.source_bytes_sha256 != _sha(self.source_bytes):
            raise ValueError("source bytes are not digest verified")
        if not isinstance(self.verified_files, tuple) or not all(isinstance(item, VerifiedBytes) for item in self.verified_files):
            raise TypeError("verified_files must be a tuple of VerifiedBytes")
        files = tuple(sorted(self.verified_files, key=lambda item: item.path.encode("utf-8")))
        if any(left.path == right.path for left, right in pairwise(files)):
            raise ValueError("verified_files contains duplicate paths")
        exact = tuple(item for item in files if item.path == self.source_path and item.package_scope == self.package_scope)
        if len(exact) != 1 or exact[0].content != self.source_bytes or exact[0].sha256 != self.source_bytes_sha256:
            raise ValueError("source is not present exactly once in verified_files")
        contributors = tuple(sorted(self.contributing_source_record_ids or (self.source_record_id,)))
        if len(contributors) != len(set(contributors)) or not all(_ID.fullmatch(item) for item in contributors):
            raise ValueError("contributing source record IDs are invalid")
        if self.modified_from_sha256 is not None:
            _require_digest(self.modified_from_sha256, "modified_from_sha256")
        object.__setattr__(self, "verified_files", files)
        object.__setattr__(self, "contributing_source_record_ids", contributors)

    @classmethod
    def create(
        cls,
        *,
        source_record_id: str,
        packet_path: str,
        source_path: str,
        source_bytes: bytes,
        verified_files: tuple[VerifiedBytes, ...] = (),
        package_scope: str = ".",
        contributing_source_record_ids: tuple[str, ...] = (),
        modified_from_sha256: str | None = None,
    ) -> BundledSource:
        own = VerifiedBytes.create(source_path, source_bytes, package_scope)
        files = verified_files if any(item.path == source_path for item in verified_files) else (*verified_files, own)
        return cls(
            source_record_id,
            packet_path,
            source_path,
            source_bytes,
            own.sha256,
            package_scope,
            files,
            contributing_source_record_ids,
            modified_from_sha256,
        )


VerifiedSource = BundledSource


class EvidenceTier(str, Enum):  # noqa: UP042 - serialized contract
    FILE_HEADER = "file_header"
    ADJACENT_LICENSE = "adjacent_license"
    REUSE_TOML = "reuse_toml"
    DEP5 = "dep5"


class EvidenceStatus(str, Enum):  # noqa: UP042 - serialized contract
    SELECTED = "selected"
    SHADOWED = "shadowed"


@dataclass(frozen=True, slots=True, order=True)
class LicenseEvidence:
    evidence_record_id: str
    source_record_id: str
    source_path: str
    source_sha256: str
    evidence_path: str
    evidence_sha256: str
    start_line: int
    end_line: int
    tier: EvidenceTier
    parser_rule_id: str
    package_scope: str
    canonical_expression: str
    status: EvidenceStatus
    policy_digest: str

    def _payload(self) -> dict[str, object]:
        return {
            "canonical_expression": self.canonical_expression,
            "end_line": self.end_line,
            "evidence_path": self.evidence_path,
            "evidence_record_id": self.evidence_record_id,
            "evidence_sha256": self.evidence_sha256,
            "package_scope": self.package_scope,
            "parser_rule_id": self.parser_rule_id,
            "policy_digest": self.policy_digest,
            "source_path": self.source_path,
            "source_record_id": self.source_record_id,
            "source_sha256": self.source_sha256,
            "start_line": self.start_line,
            "status": self.status.value,
            "tier": self.tier.value,
        }


class ResolutionState(str, Enum):  # noqa: UP042 - serialized contract
    RESOLVED = "resolved"
    MISSING = "missing"
    MALFORMED = "malformed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class LicenseResolution:
    source_record_id: str
    expression: str | None
    method: str
    confidence: str
    state: ResolutionState
    detail_code: str
    evidence: tuple[LicenseEvidence, ...]


class _SpdxSyntax(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Expr:
    op: str
    value: str = ""
    children: tuple[_Expr, ...] = ()


_TOKEN = re.compile(
    r"DocumentRef-[A-Za-z0-9.-]+:LicenseRef-[A-Za-z0-9.-]+|LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.-]*\+?|\(|\)|AND|OR|WITH"
)


class _Parser:
    def __init__(self, text: str) -> None:
        if not text or any(ord(char) < 32 and char != "\t" for char in text):
            raise _SpdxSyntax("invalid SPDX control character")
        for operator in re.finditer(r"(?<![A-Za-z0-9.-])(AND|OR|WITH)(?![A-Za-z0-9.-])", text):
            if operator.start() == 0 or operator.end() == len(text) or text[operator.start() - 1] not in " \t" or text[operator.end()] not in " \t":
                raise _SpdxSyntax("SPDX operators require whitespace")
        self.tokens: list[str] = []
        position = 0
        while position < len(text):
            whitespace = re.match(r"[ \t]+", text[position:])
            if whitespace:
                position += len(whitespace.group())
                continue
            token = _TOKEN.match(text, position)
            if token is None:
                raise _SpdxSyntax("invalid SPDX token")
            self.tokens.append(token.group())
            position = token.end()
        self.index = 0

    def parse(self) -> _Expr:
        result = self._or()
        if self.index != len(self.tokens):
            raise _SpdxSyntax("unexpected SPDX token")
        return result

    def _take(self, token: str) -> bool:
        if self.index < len(self.tokens) and self.tokens[self.index] == token:
            self.index += 1
            return True
        return False

    def _or(self) -> _Expr:
        items = [self._and()]
        while self._take("OR"):
            items.append(self._and())
        return _Expr("OR", children=tuple(items)) if len(items) > 1 else items[0]

    def _and(self) -> _Expr:
        items = [self._with()]
        while self._take("AND"):
            items.append(self._with())
        return _Expr("AND", children=tuple(items)) if len(items) > 1 else items[0]

    def _with(self) -> _Expr:
        primary = self._primary()
        if not self._take("WITH"):
            return primary
        if primary.op != "LICENSE" or primary.value.endswith("+"):
            raise _SpdxSyntax("WITH requires a simple license")
        if self.index >= len(self.tokens) or self.tokens[self.index] not in _EXCEPTION_IDS:
            raise _SpdxSyntax("unknown SPDX exception")
        exception = self.tokens[self.index]
        self.index += 1
        return _Expr("WITH", children=(primary, _Expr("EXCEPTION", exception)))

    def _primary(self) -> _Expr:
        if self._take("("):
            value = self._or()
            if not self._take(")"):
                raise _SpdxSyntax("unclosed SPDX group")
            return value
        if self.index >= len(self.tokens):
            raise _SpdxSyntax("missing SPDX operand")
        token = self.tokens[self.index]
        self.index += 1
        if token.startswith("LicenseRef-") or ":LicenseRef-" in token:
            return _Expr("REF", token)
        plus = token.endswith("+")
        license_id = token[:-1] if plus else token
        if license_id not in _LICENSE_IDS:
            raise _SpdxSyntax("unknown SPDX license ID")
        return _Expr("LICENSE", token)


def _render_expr(expression: _Expr, parent: int = 0) -> str:
    precedence = {"OR": 1, "AND": 2, "WITH": 3, "LICENSE": 4, "REF": 4, "EXCEPTION": 4}
    own = precedence[expression.op]
    if expression.op in {"LICENSE", "REF", "EXCEPTION"}:
        result = expression.value
    elif expression.op == "WITH":
        result = f"{_render_expr(expression.children[0], own)} WITH {expression.children[1].value}"
    else:
        flattened: list[_Expr] = []
        for child in expression.children:
            flattened.extend(child.children if child.op == expression.op else (child,))
        result = f" {expression.op} ".join(_render_expr(child, own) for child in flattened)
    return f"({result})" if own < parent else result


def canonicalize_spdx_expression(expression: str) -> str:
    """Parse and canonicalize one expression under the pinned SPDX grammar."""

    if not isinstance(expression, str):
        raise ValueError("SPDX expression must be text")
    try:
        return _render_expr(_Parser(expression.strip()).parse())
    except _SpdxSyntax as exc:
        raise ValueError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class LicensePolicy:
    """Maintainer-pinned compatibility, grammar, and obligation policy."""

    authority: str
    policy_id: str
    policy_version: str
    spdx_grammar_id: str
    spdx_license_ids: tuple[str, ...]
    spdx_exception_ids: tuple[str, ...]
    reviewed_expressions: tuple[str, ...]
    compatibility_rule_ids: tuple[tuple[str, str], ...]
    license_text_digests: tuple[tuple[str, str], ...]
    content_digest: str

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "authority": self.authority,
            "compatibility_rule_ids": [list(item) for item in self.compatibility_rule_ids],
            "evidence_precedence": [tier.value for tier in EvidenceTier],
            "license_text_digests": [list(item) for item in self.license_text_digests],
            "obligations_schema_version": OBLIGATIONS_SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "reviewed_expressions": list(self.reviewed_expressions),
            "spdx_exception_ids": list(self.spdx_exception_ids),
            "spdx_grammar_id": self.spdx_grammar_id,
            "spdx_license_ids": list(self.spdx_license_ids),
        }
        if include_digest:
            payload["content_digest"] = self.content_digest
        return payload

    def __post_init__(self) -> None:
        if (self.authority, self.policy_id, self.spdx_grammar_id) != (
            LICENSE_POLICY_AUTHORITY,
            LICENSE_POLICY_ID,
            SPDX_GRAMMAR_ID,
        ):
            raise ValueError("unsupported license policy identity")
        if tuple(sorted(self.reviewed_expressions)) != self.reviewed_expressions or set(self.reviewed_expressions) != set(_REVIEWED):
            raise ValueError("license policy reviewed catalog mismatch")
        _require_digest(self.content_digest, "content_digest")
        if self.content_digest != _sha(_canonical_bytes(self._payload(False))):
            raise ValueError("license policy content digest mismatch")

    @classmethod
    def create(cls, policy_version: str = "v1") -> LicensePolicy:
        rules = tuple((expression, f"singleton-permissive-{expression.lower()}-v1") for expression in sorted(_REVIEWED))
        texts = tuple((expression, _sha(_LICENSE_TEXTS[expression])) for expression in sorted(_REVIEWED))
        payload = {
            "authority": LICENSE_POLICY_AUTHORITY,
            "compatibility_rule_ids": [list(item) for item in rules],
            "evidence_precedence": [tier.value for tier in EvidenceTier],
            "license_text_digests": [list(item) for item in texts],
            "obligations_schema_version": OBLIGATIONS_SCHEMA_VERSION,
            "policy_id": LICENSE_POLICY_ID,
            "policy_version": policy_version,
            "reviewed_expressions": list(sorted(_REVIEWED)),
            "spdx_exception_ids": list(sorted(_EXCEPTION_IDS)),
            "spdx_grammar_id": SPDX_GRAMMAR_ID,
            "spdx_license_ids": list(sorted(_LICENSE_IDS)),
        }
        return cls(
            LICENSE_POLICY_AUTHORITY,
            LICENSE_POLICY_ID,
            policy_version,
            SPDX_GRAMMAR_ID,
            tuple(sorted(_LICENSE_IDS)),
            tuple(sorted(_EXCEPTION_IDS)),
            tuple(sorted(_REVIEWED)),
            rules,
            texts,
            _sha(_canonical_bytes(payload)),
        )


# Construct without calling __post_init__ with a placeholder digest.
def _default_policy() -> LicensePolicy:
    return LicensePolicy.create()


DEFAULT_LICENSE_POLICY = _default_policy()
PINNED_LICENSE_POLICY = DEFAULT_LICENSE_POLICY


@dataclass(frozen=True, slots=True)
class RecipientLicensePolicy:
    policy_id: str
    policy_version: str
    use_category: str
    allowed_spdx_expressions: tuple[str, ...]
    prohibited_spdx_expressions: tuple[str, ...]
    content_digest: str

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "allowed_spdx_expressions": list(self.allowed_spdx_expressions),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "prohibited_spdx_expressions": list(self.prohibited_spdx_expressions),
            "use_category": self.use_category,
        }
        if include_digest:
            payload["content_digest"] = self.content_digest
        return payload

    def __post_init__(self) -> None:
        if not all(_ID.fullmatch(item) for item in (self.policy_id, self.policy_version, self.use_category)):
            raise ValueError("recipient policy identity is invalid")
        allowed = tuple(sorted(canonicalize_spdx_expression(item) for item in self.allowed_spdx_expressions))
        prohibited = tuple(sorted(canonicalize_spdx_expression(item) for item in self.prohibited_spdx_expressions))
        if len(set(allowed)) != len(allowed) or len(set(prohibited)) != len(prohibited) or set(allowed) & set(prohibited):
            raise ValueError("recipient policy is duplicate or contradictory")
        object.__setattr__(self, "allowed_spdx_expressions", allowed)
        object.__setattr__(self, "prohibited_spdx_expressions", prohibited)
        _require_digest(self.content_digest, "recipient content_digest")
        if self.content_digest != _sha(_canonical_bytes(self._payload(False))):
            raise ValueError("recipient policy content digest mismatch")

    @classmethod
    def create(
        cls,
        *,
        policy_id: str,
        policy_version: str,
        use_category: str,
        allowed_spdx_expressions: tuple[str, ...],
        prohibited_spdx_expressions: tuple[str, ...] = (),
    ) -> RecipientLicensePolicy:
        allowed = tuple(sorted(canonicalize_spdx_expression(item) for item in allowed_spdx_expressions))
        prohibited = tuple(sorted(canonicalize_spdx_expression(item) for item in prohibited_spdx_expressions))
        payload = {
            "allowed_spdx_expressions": list(allowed),
            "policy_id": policy_id,
            "policy_version": policy_version,
            "prohibited_spdx_expressions": list(prohibited),
            "use_category": use_category,
        }
        return cls(policy_id, policy_version, use_category, allowed, prohibited, _sha(_canonical_bytes(payload)))


def _line(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


@dataclass(frozen=True, slots=True)
class _RawEvidence:
    expression: str
    path: str
    digest: str
    line: int
    tier: EvidenceTier
    rule: str


def _header_evidence(source: BundledSource) -> tuple[list[_RawEvidence], str | None]:
    matches = list(_HEADER.finditer(source.source_bytes))
    if not matches:
        return [], None
    if len(matches) != 1:
        return [], "duplicate_file_header"
    match = matches[0]
    try:
        expression = canonicalize_spdx_expression(match.group(1).decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        return [], "malformed_file_header"
    return [
        _RawEvidence(
            expression,
            source.source_path,
            source.source_bytes_sha256,
            _line(source.source_bytes, match.start()),
            EvidenceTier.FILE_HEADER,
            "reuse-3.3-file-header-v1",
        )
    ], None


def _sidecar_evidence(source: BundledSource) -> tuple[list[_RawEvidence], str | None]:
    sidecars = [item for item in source.verified_files if item.path == source.source_path + ".license"]
    if not sidecars:
        return [], None
    if len(sidecars) != 1:
        return [], "duplicate_adjacent_license"
    item = sidecars[0]
    matches = list(_HEADER.finditer(item.content))
    if len(matches) != 1:
        return [], "malformed_adjacent_license"
    match = matches[0]
    try:
        expression = canonicalize_spdx_expression(match.group(1).decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        return [], "malformed_adjacent_license"
    return [_RawEvidence(expression, item.path, item.sha256, _line(item.content, match.start()), EvidenceTier.ADJACENT_LICENSE, "reuse-3.3-adjacent-license-v1")], None


def _scope_relative(source: BundledSource) -> str:
    if source.package_scope == ".":
        return source.source_path
    prefix = source.package_scope + "/"
    if not source.source_path.startswith(prefix):
        raise ValueError("source path is outside package scope")
    return source.source_path.removeprefix(prefix)


def _annotation_paths(value: object) -> tuple[str, ...] | None:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return tuple(value)
    return None


def _reuse_evidence(source: BundledSource) -> tuple[list[_RawEvidence], str | None]:
    files = [item for item in source.verified_files if item.package_scope == source.package_scope and item.path == ("REUSE.toml" if source.package_scope == "." else f"{source.package_scope}/REUSE.toml")]
    if not files:
        return [], None
    if len(files) != 1:
        return [], "duplicate_reuse_toml"
    item = files[0]
    try:
        payload = tomllib.loads(item.content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return [], "malformed_reuse_toml"
    if set(payload) - {"version", "annotations"} or payload.get("version") != 1 or not isinstance(payload.get("annotations"), list):
        return [], "malformed_reuse_toml"
    relative = _scope_relative(source)
    results: list[_RawEvidence] = []
    for annotation in payload["annotations"]:
        if not isinstance(annotation, dict):
            return [], "malformed_reuse_toml"
        paths = _annotation_paths(annotation.get("path"))
        expression = annotation.get("SPDX-License-Identifier")
        if paths is None or not isinstance(expression, str):
            return [], "malformed_reuse_toml"
        if any(fnmatch.fnmatchcase(relative, pattern) for pattern in paths):
            try:
                canonical = canonicalize_spdx_expression(expression)
            except ValueError:
                return [], "malformed_reuse_toml"
            results.append(_RawEvidence(canonical, item.path, item.sha256, 1, EvidenceTier.REUSE_TOML, "reuse-3.3-reuse-toml-v1"))
    if len({result.expression for result in results}) > 1:
        return [], "conflicting_reuse_toml"
    return results[:1], None


def _dep5_records(data: bytes) -> list[dict[str, str]]:
    text = data.decode("utf-8")
    records: list[dict[str, str]] = []
    for block in re.split(r"\n[ \t]*\n", text):
        fields: dict[str, str] = {}
        current: str | None = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and current is not None:
                fields[current] += "\n" + line.strip()
                continue
            if ":" not in line:
                raise ValueError("malformed DEP5 line")
            key, value = line.split(":", 1)
            if key in fields:
                raise ValueError("duplicate DEP5 field")
            fields[key] = value.strip()
            current = key
        if fields:
            records.append(fields)
    return records


def _dep5_evidence(source: BundledSource) -> tuple[list[_RawEvidence], str | None]:
    expected = ".reuse/dep5" if source.package_scope == "." else f"{source.package_scope}/.reuse/dep5"
    files = [item for item in source.verified_files if item.package_scope == source.package_scope and item.path == expected]
    if not files:
        return [], None
    if len(files) != 1:
        return [], "duplicate_dep5"
    item = files[0]
    try:
        records = _dep5_records(item.content)
    except (UnicodeDecodeError, ValueError):
        return [], "malformed_dep5"
    relative = _scope_relative(source)
    results: list[_RawEvidence] = []
    for record in records:
        if "Files" not in record:
            continue
        if any(fnmatch.fnmatchcase(relative, pattern) for pattern in record["Files"].split()):
            expression = record.get("License", "").splitlines()[0].strip()
            try:
                canonical = canonicalize_spdx_expression(expression)
            except ValueError:
                return [], "malformed_dep5"
            results.append(_RawEvidence(canonical, item.path, item.sha256, 1, EvidenceTier.DEP5, "reuse-3.3-dep5-v1"))
    if len({result.expression for result in results}) > 1:
        return [], "conflicting_dep5"
    return results[:1], None


def resolve_source_license(source: BundledSource, policy: LicensePolicy = DEFAULT_LICENSE_POLICY) -> LicenseResolution:
    """Resolve one source using only its digest-verified package byte view."""

    if not isinstance(source, BundledSource) or not isinstance(policy, LicensePolicy):
        raise TypeError("source and policy must be typed verified records")
    tiers = (_header_evidence(source), _sidecar_evidence(source), _reuse_evidence(source), _dep5_evidence(source))
    for _, error in tiers:
        if error is not None:
            state = ResolutionState.AMBIGUOUS if error.startswith(("duplicate", "conflicting")) else ResolutionState.MALFORMED
            return LicenseResolution(source.source_record_id, None, "unknown", "low", state, error, ())
    selected_index = next((index for index, (items, _) in enumerate(tiers) if items), None)
    if selected_index is None:
        return LicenseResolution(source.source_record_id, None, "unknown", "low", ResolutionState.MISSING, "license_evidence_missing", ())
    evidence: list[LicenseEvidence] = []
    for index, (items, _) in enumerate(tiers):
        status = EvidenceStatus.SELECTED if index == selected_index else EvidenceStatus.SHADOWED
        for raw in items:
            identity = _sha(_canonical_bytes([source.source_record_id, raw.path, raw.digest, raw.line, raw.tier.value, raw.expression]))
            evidence.append(
                LicenseEvidence(
                    identity,
                    source.source_record_id,
                    source.source_path,
                    source.source_bytes_sha256,
                    raw.path,
                    raw.digest,
                    raw.line,
                    raw.line,
                    raw.tier,
                    raw.rule,
                    source.package_scope,
                    raw.expression,
                    status,
                    policy.content_digest,
                )
            )
    ordered = tuple(sorted(evidence, key=lambda item: (list(EvidenceTier).index(item.tier), item.evidence_path, item.start_line)))
    selected = next(item for item in ordered if item.status is EvidenceStatus.SELECTED)
    return LicenseResolution(source.source_record_id, selected.canonical_expression, selected.tier.value, "high", ResolutionState.RESOLVED, "resolved", ordered)


class ObligationKind(str, Enum):  # noqa: UP042 - serialized contract
    COPYRIGHT = "copyright"
    NOTICE = "notice"
    CONTRIBUTOR = "contributor"
    ATTRIBUTION = "attribution"
    LICENSE_TEXT = "license_text"
    SOURCE_DISCLOSURE = "source_disclosure"
    MODIFICATION_MARKING = "modification_marking"
    COPYLEFT_BOUNDARY = "copyleft_boundary"


class DisclosureScope(str, Enum):  # noqa: UP042 - serialized contract
    FILE = "file"
    DERIVATIVE = "derivative"
    LINKED_WORK = "linked_work"
    COMBINED_WORK = "combined_work"
    NETWORK_SERVICE = "network_service"


class DisclosureAction(str, Enum):  # noqa: UP042 - serialized contract
    INCLUDE_SOURCE = "include_source"
    PROVIDE_OFFER = "provide_offer"
    PROVIDE_ACCESS = "provide_access"


class CopyleftBoundary(str, Enum):  # noqa: UP042 - serialized contract
    NONE = "none"
    FILE = "file"
    LIBRARY = "library"
    COMBINED_WORK = "combined_work"
    NETWORK = "network"


@dataclass(frozen=True, slots=True)
class ObligationProvenance:
    source_record_id: str
    evidence_record_id: str
    evidence_path: str
    evidence_sha256: str
    start_line: int | None
    end_line: int | None
    policy_rule_id: str
    bundled_license_policy_digest: str

    def _payload(self) -> dict[str, object]:
        return {
            "bundled_license_policy_digest": self.bundled_license_policy_digest,
            "end_line": self.end_line,
            "evidence_path": self.evidence_path,
            "evidence_record_id": self.evidence_record_id,
            "evidence_sha256": self.evidence_sha256,
            "policy_rule_id": self.policy_rule_id,
            "source_record_id": self.source_record_id,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class TextObligation:
    kind: ObligationKind
    subject_file: str
    normalized_text: str
    exact_evidence_sha256: str
    provenance: ObligationProvenance

    def __post_init__(self) -> None:
        if self.kind not in {ObligationKind.COPYRIGHT, ObligationKind.NOTICE, ObligationKind.CONTRIBUTOR, ObligationKind.ATTRIBUTION}:
            raise ValueError("invalid text obligation kind")
        if not self.normalized_text or self.normalized_text == "NOASSERTION":
            raise ValueError("empty or unsupported text obligation")

    def _payload(self) -> dict[str, object]:
        return {"exact_evidence_sha256": self.exact_evidence_sha256, "kind": self.kind.value, "normalized_text": self.normalized_text, "provenance": self.provenance._payload(), "subject_file": self.subject_file}


@dataclass(frozen=True, slots=True)
class LicenseTextObligation:
    kind: ObligationKind
    subject_file: str
    expression: str
    payload_path: str
    payload_sha256: str
    provenance: ObligationProvenance

    def __post_init__(self) -> None:
        if self.kind is not ObligationKind.LICENSE_TEXT:
            raise ValueError("invalid license text obligation kind")

    def _payload(self) -> dict[str, object]:
        return {"expression": self.expression, "kind": self.kind.value, "payload_path": self.payload_path, "payload_sha256": self.payload_sha256, "provenance": self.provenance._payload(), "subject_file": self.subject_file}


@dataclass(frozen=True, slots=True)
class SourceDisclosureObligation:
    kind: ObligationKind
    subject_file: str
    scope: DisclosureScope
    action: DisclosureAction
    trigger_use_category: str
    source_set_digest: str
    provenance: ObligationProvenance

    def __post_init__(self) -> None:
        if self.kind is not ObligationKind.SOURCE_DISCLOSURE:
            raise ValueError("invalid source disclosure obligation kind")

    def _payload(self) -> dict[str, object]:
        return {"action": self.action.value, "kind": self.kind.value, "provenance": self.provenance._payload(), "scope": self.scope.value, "source_set_digest": self.source_set_digest, "subject_file": self.subject_file, "trigger_use_category": self.trigger_use_category}


@dataclass(frozen=True, slots=True)
class ModificationMarkingObligation:
    kind: ObligationKind
    subject_file: str
    required: bool
    marking_location: str
    original_bytes_sha256: str
    derivative_bytes_sha256: str
    provenance: ObligationProvenance

    def __post_init__(self) -> None:
        if self.kind is not ObligationKind.MODIFICATION_MARKING:
            raise ValueError("invalid modification marking obligation kind")

    def _payload(self) -> dict[str, object]:
        return {"derivative_bytes_sha256": self.derivative_bytes_sha256, "kind": self.kind.value, "marking_location": self.marking_location, "original_bytes_sha256": self.original_bytes_sha256, "provenance": self.provenance._payload(), "required": self.required, "subject_file": self.subject_file}


@dataclass(frozen=True, slots=True)
class CopyleftBoundaryObligation:
    kind: ObligationKind
    subject_file: str
    boundary: CopyleftBoundary
    network_copyleft: bool
    covered_set_digest: str
    provenance: ObligationProvenance

    def __post_init__(self) -> None:
        if self.kind is not ObligationKind.COPYLEFT_BOUNDARY:
            raise ValueError("invalid copyleft boundary obligation kind")

    def _payload(self) -> dict[str, object]:
        return {"boundary": self.boundary.value, "covered_set_digest": self.covered_set_digest, "kind": self.kind.value, "network_copyleft": self.network_copyleft, "provenance": self.provenance._payload(), "subject_file": self.subject_file}


ObligationRecord = TextObligation | LicenseTextObligation | SourceDisclosureObligation | ModificationMarkingObligation | CopyleftBoundaryObligation


@dataclass(frozen=True, slots=True)
class CompatibilityDecision:
    source_record_id: str
    canonical_expression: str
    recipient_use_category: str
    recipient_policy_digest: str
    policy_rule_id: str
    decision: str
    provenance_evidence_ids: tuple[str, ...]

    def _payload(self) -> dict[str, object]:
        return {"canonical_expression": self.canonical_expression, "decision": self.decision, "policy_rule_id": self.policy_rule_id, "provenance_evidence_ids": list(self.provenance_evidence_ids), "recipient_policy_digest": self.recipient_policy_digest, "recipient_use_category": self.recipient_use_category, "source_record_id": self.source_record_id}


@dataclass(frozen=True, slots=True)
class SourceObligationSet:
    packet_path: str
    source_record_id: str
    source_path: str
    source_bytes_sha256: str
    selected_license_evidence_id: str
    contributing_source_record_ids: tuple[str, ...]
    compatibility: CompatibilityDecision
    obligation_record_ids: tuple[str, ...]

    def _payload(self) -> dict[str, object]:
        return {"compatibility": self.compatibility._payload(), "contributing_source_record_ids": list(self.contributing_source_record_ids), "obligation_record_ids": list(self.obligation_record_ids), "packet_path": self.packet_path, "selected_license_evidence_id": self.selected_license_evidence_id, "source_bytes_sha256": self.source_bytes_sha256, "source_path": self.source_path, "source_record_id": self.source_record_id}


@dataclass(frozen=True, slots=True)
class Obligations:
    """Authoritative, closed obligations manifest for this evaluation."""

    schema_version: str
    recipient_license_policy_digest: str
    bundled_license_policy_digest: str
    license_evidence: tuple[LicenseEvidence, ...]
    source_sets: tuple[SourceObligationSet, ...]
    obligations: tuple[ObligationRecord, ...]
    obligations_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != OBLIGATIONS_SCHEMA_VERSION:
            raise ValueError("unsupported obligations schema")
        _require_digest(self.recipient_license_policy_digest, "recipient policy digest")
        _require_digest(self.bundled_license_policy_digest, "bundled policy digest")
        _require_digest(self.obligations_digest, "obligations digest")
        if not all(isinstance(item, LicenseEvidence) for item in self.license_evidence):
            raise TypeError("invalid license evidence record")
        if not all(isinstance(item, SourceObligationSet) for item in self.source_sets):
            raise TypeError("invalid source obligation set")
        for item in self.obligations:
            _obligation_payload(item)
        if self.obligations_digest != _sha(_canonical_bytes(self._payload(False))):
            raise ValueError("obligations digest mismatch")

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "bundled_license_policy_digest": self.bundled_license_policy_digest,
            "license_evidence": [item._payload() for item in self.license_evidence],
            "obligations": [_obligation_payload(item) for item in self.obligations],
            "recipient_license_policy_digest": self.recipient_license_policy_digest,
            "schema_version": self.schema_version,
            "source_sets": [item._payload() for item in self.source_sets],
        }
        if include_digest:
            payload["obligations_digest"] = self.obligations_digest
        return payload

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self._payload())

    def to_json(self) -> str:
        return self.to_bytes().decode("utf-8")


ObligationsManifest = Obligations


def _obligation_payload(value: ObligationRecord) -> dict[str, object]:
    # The explicit union check prevents a caller-created prose/extension record.
    if not isinstance(value, (TextObligation, LicenseTextObligation, SourceDisclosureObligation, ModificationMarkingObligation, CopyleftBoundaryObligation)):
        raise TypeError("unsupported obligation record")
    return value._payload()


class LicenseDecisionStatus(str, Enum):  # noqa: UP042 - serialized contract
    PASS = "pass"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class LicenseDecision:
    status: LicenseDecisionStatus
    reason: BTSRejectReason | None
    detail_code: str
    detail: str
    resolutions: tuple[LicenseResolution, ...]
    obligations: Obligations | None
    decision_digest: str

    @property
    def accepted(self) -> bool:
        return self.status is LicenseDecisionStatus.PASS

    @property
    def obligations_json(self) -> bytes | None:
        return None if self.obligations is None else self.obligations.to_bytes()

    @property
    def attribution_md(self) -> bytes | None:
        return None if self.obligations is None else render_attribution(self.obligations)


def _decision(
    status: LicenseDecisionStatus,
    reason: BTSRejectReason | None,
    detail_code: str,
    detail: str,
    resolutions: tuple[LicenseResolution, ...],
    obligations: Obligations | None,
) -> LicenseDecision:
    payload = {
        "detail": detail,
        "detail_code": detail_code,
        "obligations_digest": None if obligations is None else obligations.obligations_digest,
        "reason": None if reason is None else reason.value,
        "resolutions": [[item.source_record_id, item.expression, item.method, item.state.value, item.detail_code] for item in resolutions],
        "status": status.value,
    }
    return LicenseDecision(status, reason, detail_code, detail, resolutions, obligations, _sha(_canonical_bytes(payload)))


def _reject_decision(
    reason: BTSRejectReason,
    detail_code: str,
    detail: str,
    resolutions: tuple[LicenseResolution, ...],
) -> LicenseDecision:
    return _decision(LicenseDecisionStatus.REJECT, reason, detail_code, detail, resolutions, None)


def _extract_text_obligations(source: BundledSource, selected: LicenseEvidence, rule_id: str, policy: LicensePolicy) -> list[ObligationRecord]:
    records: list[ObligationRecord] = []

    def append_text(kind_value: str, text: str, path: str, digest: str, line: int, exact_digest: str) -> None:
        normalized = " ".join(text.split())
        provenance = ObligationProvenance(source.source_record_id, selected.evidence_record_id, path, digest, line, line, rule_id, policy.content_digest)
        records.append(TextObligation(ObligationKind(kind_value), source.packet_path, normalized, exact_digest, provenance))

    def scan_spdx_fields(item: VerifiedBytes) -> None:
        for marker, kind_value in _TEXT_FIELDS:
            pattern = re.compile(rb"(?im)^[ \t]*(?:[#*/;<!-]+[ \t]*)?" + re.escape(marker) + rb":[ \t]*([^\r\n*<>]+)")
            for match in pattern.finditer(item.content):
                try:
                    text = match.group(1).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError("malformed SPDX text obligation") from exc
                append_text(kind_value, text, item.path, item.sha256, _line(item.content, match.start()), _sha(match.group(0)))

    source_file = next(item for item in source.verified_files if item.path == source.source_path)
    scan_spdx_fields(source_file)
    for item in source.verified_files:
        if item.path == source.source_path + ".license":
            scan_spdx_fields(item)

    reuse_path = "REUSE.toml" if source.package_scope == "." else f"{source.package_scope}/REUSE.toml"
    for item in source.verified_files:
        if item.package_scope != source.package_scope or item.path != reuse_path:
            continue
        payload = tomllib.loads(item.content.decode("utf-8"))
        relative = _scope_relative(source)
        for annotation in payload.get("annotations", []):
            assert isinstance(annotation, dict)  # validated by the resolver
            paths = _annotation_paths(annotation.get("path"))
            if paths is None or not any(fnmatch.fnmatchcase(relative, pattern) for pattern in paths):
                continue
            for marker, kind_value in _TEXT_FIELDS:
                key = marker.decode("ascii")
                values = annotation.get(key, [])
                if isinstance(values, str):
                    values = [values]
                if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                    raise ValueError(f"malformed {key} obligation")
                for value in values:
                    append_text(kind_value, value, item.path, item.sha256, 1, _sha(value.encode("utf-8")))

    dep5_path = ".reuse/dep5" if source.package_scope == "." else f"{source.package_scope}/.reuse/dep5"
    for item in source.verified_files:
        if item.package_scope != source.package_scope or item.path != dep5_path:
            continue
        for record in _dep5_records(item.content):
            patterns = record.get("Files", "").split()
            if patterns and any(fnmatch.fnmatchcase(_scope_relative(source), pattern) for pattern in patterns):
                for copyright_text in record.get("Copyright", "").splitlines():
                    if copyright_text.strip():
                        append_text("copyright", copyright_text, item.path, item.sha256, 1, _sha(copyright_text.encode("utf-8")))
    notice_names = re.compile(r"NOTICE(?:[._-][A-Za-z0-9.-]+)?")
    for item in source.verified_files:
        basename = item.path.rsplit("/", 1)[-1]
        parent = item.path.rsplit("/", 1)[0] if "/" in item.path else ""
        expected_parent = "" if source.package_scope == "." else source.package_scope
        if item.package_scope == source.package_scope and parent == expected_parent and notice_names.fullmatch(basename):
            try:
                text = "\n".join(line.rstrip() for line in item.content.decode("utf-8").replace("\r\n", "\n").split("\n")).strip()
            except UnicodeDecodeError as exc:
                raise ValueError("malformed NOTICE bytes") from exc
            if not text:
                raise ValueError("empty NOTICE bytes")
            provenance = ObligationProvenance(source.source_record_id, selected.evidence_record_id, item.path, item.sha256, 1, item.content.count(b"\n") + 1, rule_id, policy.content_digest)
            records.append(TextObligation(ObligationKind.NOTICE, source.packet_path, text, item.sha256, provenance))
    return records


def _record_id(record: ObligationRecord) -> str:
    return _sha(_canonical_bytes(_obligation_payload(record)))


def evaluate_license_policy(
    sources: tuple[BundledSource, ...],
    recipient_policy: RecipientLicensePolicy,
    policy: LicensePolicy = DEFAULT_LICENSE_POLICY,
) -> LicenseDecision:
    """Evaluate every bundled source and materialize a closed manifest or reject."""

    if not isinstance(sources, tuple) or not sources or not all(isinstance(item, BundledSource) for item in sources):
        raise TypeError("sources must be a non-empty tuple of BundledSource")
    if not isinstance(recipient_policy, RecipientLicensePolicy) or not isinstance(policy, LicensePolicy):
        raise TypeError("recipient and bundled policies must be typed policies")
    ordered_sources = tuple(sorted(sources, key=lambda item: (item.packet_path.encode(), item.source_record_id)))
    if len({item.packet_path for item in ordered_sources}) != len(ordered_sources) or len({item.source_record_id for item in ordered_sources}) != len(ordered_sources):
        raise ValueError("duplicate source packet path or record ID")
    resolutions = tuple(resolve_source_license(source, policy) for source in ordered_sources)

    # B9 precedence: explicit recipient prohibition is known incompatibility,
    # even when the bundled v1 obligations catalog deliberately defers it.
    for source, resolution in zip(ordered_sources, resolutions, strict=True):
        if resolution.expression is not None and resolution.expression in recipient_policy.prohibited_spdx_expressions:
            detail = f"donor expression {resolution.expression}; recipient policy {recipient_policy.content_digest} ({recipient_policy.use_category}); rule recipient-explicit-prohibition-v1; source {source.packet_path}"
            return _reject_decision(BTSRejectReason.REJECT_LICENSE_INCOMPATIBLE, "recipient_policy_disallows", detail, resolutions)
    for source, resolution in zip(ordered_sources, resolutions, strict=True):
        if resolution.state is not ResolutionState.RESOLVED:
            detail = f"source {source.packet_path}: {resolution.detail_code}; recipient policy {recipient_policy.content_digest}"
            return _reject_decision(BTSRejectReason.REJECT_LICENSE_UNKNOWN, resolution.detail_code, detail, resolutions)
        assert resolution.expression is not None
        if resolution.expression not in policy.reviewed_expressions:
            detail = f"donor expression {resolution.expression}; recipient policy {recipient_policy.content_digest} ({recipient_policy.use_category}); no reviewed v1 compatibility rule"
            return _reject_decision(BTSRejectReason.REJECT_LICENSE_UNKNOWN, "compatibility_rule_missing", detail, resolutions)
        if resolution.expression not in recipient_policy.allowed_spdx_expressions:
            rule_id = dict(policy.compatibility_rule_ids)[resolution.expression]
            detail = f"donor expression {resolution.expression}; recipient policy {recipient_policy.content_digest} ({recipient_policy.use_category}); rule {rule_id}; source {source.packet_path}"
            return _reject_decision(BTSRejectReason.REJECT_LICENSE_INCOMPATIBLE, "recipient_policy_disallows", detail, resolutions)

    evidence = tuple(item for resolution in resolutions for item in resolution.evidence)
    obligation_records: list[ObligationRecord] = []
    source_sets: list[SourceObligationSet] = []
    try:
        for source, resolution in zip(ordered_sources, resolutions, strict=True):
            expression = resolution.expression
            assert expression is not None
            selected = next(item for item in resolution.evidence if item.status is EvidenceStatus.SELECTED)
            rule_id = dict(policy.compatibility_rule_ids)[expression]
            provenance = ObligationProvenance(source.source_record_id, selected.evidence_record_id, selected.evidence_path, selected.evidence_sha256, selected.start_line, selected.end_line, rule_id, policy.content_digest)
            records = _extract_text_obligations(source, selected, rule_id, policy)
            text_digest = dict(policy.license_text_digests)[expression]
            records.append(LicenseTextObligation(ObligationKind.LICENSE_TEXT, source.packet_path, expression, f"licenses/{text_digest.removeprefix('sha256:')}.license", text_digest, provenance))
            covered_digest = _sha(_canonical_bytes(list(source.contributing_source_record_ids)))
            records.append(CopyleftBoundaryObligation(ObligationKind.COPYLEFT_BOUNDARY, source.packet_path, CopyleftBoundary.NONE, False, covered_digest, provenance))
            if expression == "Apache-2.0" and source.modified_from_sha256 is not None:
                records.append(ModificationMarkingObligation(ObligationKind.MODIFICATION_MARKING, source.packet_path, True, "modified-source-prominent-notice", source.modified_from_sha256, source.source_bytes_sha256, provenance))
            identified = tuple(sorted((_record_id(record), record) for record in records))
            obligation_records.extend(record for _, record in identified)
            compatibility = CompatibilityDecision(source.source_record_id, expression, recipient_policy.use_category, recipient_policy.content_digest, rule_id, "compatible", tuple(sorted(item.evidence_record_id for item in resolution.evidence)))
            source_sets.append(SourceObligationSet(source.packet_path, source.source_record_id, source.source_path, source.source_bytes_sha256, selected.evidence_record_id, source.contributing_source_record_ids, compatibility, tuple(identity for identity, _ in identified)))
    except ValueError as exc:
        return _reject_decision(BTSRejectReason.REJECT_LICENSE_OBLIGATION_MISSING, "typed_obligation_unmaterializable", str(exc), resolutions)
    obligation_records.sort(key=lambda item: (_record_id(item), _obligation_payload(item)["subject_file"]))
    source_sets.sort(key=lambda item: (item.packet_path.encode(), item.source_record_id))
    manifest_payload = {
        "bundled_license_policy_digest": policy.content_digest,
        "license_evidence": [item._payload() for item in evidence],
        "obligations": [_obligation_payload(item) for item in obligation_records],
        "recipient_license_policy_digest": recipient_policy.content_digest,
        "schema_version": OBLIGATIONS_SCHEMA_VERSION,
        "source_sets": [item._payload() for item in source_sets],
    }
    manifest = Obligations(
        OBLIGATIONS_SCHEMA_VERSION,
        recipient_policy.content_digest,
        policy.content_digest,
        evidence,
        tuple(source_sets),
        tuple(obligation_records),
        _sha(_canonical_bytes(manifest_payload)),
    )
    return _decision(LicenseDecisionStatus.PASS, None, "compatible", "all bundled sources are compatible", resolutions, manifest)


def render_attribution(obligations: Obligations) -> bytes:
    """Deterministically render ``ATTRIBUTION.md`` solely from the manifest."""

    if not isinstance(obligations, Obligations):
        raise TypeError("obligations must be an Obligations manifest")
    lines = [
        "# Attribution",
        "",
        "Generated from authoritative `obligations.json`. This is not legal advice.",
        "",
        f"Obligations digest: `{obligations.obligations_digest}`",
        "",
        "## Bundled sources",
        "",
    ]
    record_by_id = {_record_id(record): record for record in obligations.obligations}
    for source_set in obligations.source_sets:
        lines.extend([f"### `{source_set.packet_path}`", "", f"- SPDX license: `{source_set.compatibility.canonical_expression}`", f"- Source record: `{source_set.source_record_id}`", "- Obligations:"])
        for record_id in source_set.obligation_record_ids:
            record = record_by_id[record_id]
            if isinstance(record, TextObligation):
                rendered = record.normalized_text.replace("\\", "\\\\").replace("`", "\\`").replace("\n", " ")
                lines.append(f"  - {record.kind.value}: {rendered}")
            elif isinstance(record, LicenseTextObligation):
                lines.append(f"  - license text: `{record.payload_path}` (`{record.payload_sha256}`)")
            elif isinstance(record, ModificationMarkingObligation):
                lines.append(f"  - modification marking: `{record.marking_location}`")
            elif isinstance(record, CopyleftBoundaryObligation):
                lines.append(f"  - copyleft boundary: `{record.boundary.value}`; network copyleft: `{str(record.network_copyleft).lower()}`")
            elif isinstance(record, SourceDisclosureObligation):
                lines.append(f"  - source disclosure: `{record.scope.value}` / `{record.action.value}`")
        lines.append("")
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def license_payloads(policy: LicensePolicy = DEFAULT_LICENSE_POLICY) -> tuple[tuple[str, bytes], ...]:
    """Return exact policy-approved license payloads by deterministic packet path."""

    if policy.content_digest != DEFAULT_LICENSE_POLICY.content_digest:
        raise ValueError("license payload catalog is unavailable for this policy")
    return tuple((f"licenses/{_sha(data).removeprefix('sha256:')}.license", data) for _, data in sorted(_LICENSE_TEXTS.items()))


# ---------------------------------------------------------------------------
# License routing guidance (issue #190): transplant-ok | study-only.
#
# Routing is advisory output only: it never gates materialization, never
# claims legal clearance, and never invents a license.  It is a pure function
# of caller-supplied detected license expressions plus boolean tree markers
# (proprietary text marker, enterprise carve-out segment).  All detection
# I/O happens in the caller, so this module keeps its no-filesystem-API
# contract.  Inconclusive detection routes fail-closed to ``study-only`` with
# reason ``license-undetermined`` — there is no neutral routing value.

ROUTING_SCHEMA_VERSION = "leitir-license-routing-v1"
TRANSPLANT_OK = "transplant-ok"
STUDY_ONLY = "study-only"
REASON_LICENSE_UNDETERMINED = "license-undetermined"
REASON_PROPRIETARY = "proprietary"
REASON_ENTERPRISE_CARVE_OUT = "enterprise-tree-carve-out"

logger = logging.getLogger(__name__)

# Maintained routing policy table: the maintainer-reviewed permissive catalog
# routes transplant-ok; copyleft-family IDs (strong and weak) route
# study-only; anything detected but unclassified routes fail-closed
# study-only/license-undetermined.
_ROUTING_PERMISSIVE_IDS: frozenset[str] = frozenset(_REVIEWED)
_ROUTING_COPYLEFT_IDS: frozenset[str] = frozenset(
    {
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "EPL-1.0",
        "EPL-2.0",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
    }
)

# Narrow, deliberate declaration markers only: copyleft license texts
# legitimately *mention* proprietary works (e.g. GPLv3 §10), so a bare word
# match would misroute.  A hit requires an explicit proprietary declaration
# phrase, which standard permissive and copyleft texts never contain.
_PROPRIETARY_MARKERS: tuple[re.Pattern[bytes], ...] = (
    re.compile(rb"(?i)\bproprietary\s+and\s+confidential\b"),
    re.compile(rb"(?i)\bproprietary\s+software\b"),
    re.compile(rb"(?i)\bproprietary\s+licen[cs]e\b"),
    re.compile(rb"(?im)^[^\r\n]{0,120}\b(?:is|are|remains)\s+proprietary\b"),
    re.compile(rb"(?im)^[^\r\n]{0,120}\bproprietary\b[^\r\n]{0,100}\ball\s+rights\s+reserved\b"),
)

# GPL-family license headers are matched case-sensitively against their
# canonical FSF publication wording (title + exact release date) so mentions
# of the GPL inside permissive appendices do not misroute.
_GPL_FAMILY_HEADERS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "GPL-3.0",
        re.compile(rb"GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+.{0,400}?Version\s+3(?:\.0)?,\s*29\s+June\s+2007", re.DOTALL),
    ),
    (
        "GPL-2.0",
        re.compile(rb"GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+.{0,400}?Version\s+2(?:\.0)?,\s*June\s+1991", re.DOTALL),
    ),
    (
        "AGPL-3.0-only",
        re.compile(rb"GNU\s+AFFERO\s+GENERAL\s+PUBLIC\s+LICENSE\s+.{0,400}?Version\s+3(?:\.0)?,\s*19\s+November\s+2007", re.DOTALL),
    ),
    (
        "LGPL-3.0-only",
        re.compile(rb"GNU\s+LESSER\s+GENERAL\s+PUBLIC\s+LICENSE\s+.{0,400}?Version\s+3(?:\.0)?,\s*29\s+June\s+2007", re.DOTALL),
    ),
    (
        "LGPL-2.1-only",
        re.compile(rb"GNU\s+LESSER\s+GENERAL\s+PUBLIC\s+LICENSE\s+.{0,400}?Version\s+2\.1,\s*February\s+1999", re.DOTALL),
    ),
)

_EXPRESSION_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")


@dataclass(frozen=True, slots=True)
class LicenseRouting:
    """Advisory transplant-vs-study routing for one surfaced source."""

    verdict: str
    reason: str

    def as_field(self) -> dict[str, str]:
        return {"verdict": self.verdict, "reason": self.reason}


def validate_routing_policy_table(permissive: frozenset[str], copyleft: frozenset[str]) -> None:
    """Fail closed when the maintained routing policy table is malformed."""

    overlap = sorted(permissive & copyleft)
    if overlap:
        raise ValueError(f"license routing policy table is malformed: IDs in both routing classes: {', '.join(overlap)}")
    unknown = sorted((permissive | copyleft) - set(_LICENSE_IDS))
    if unknown:
        raise ValueError(f"license routing policy table is malformed: IDs outside the pinned SPDX catalog: {', '.join(unknown)}")


validate_routing_policy_table(_ROUTING_PERMISSIVE_IDS, _ROUTING_COPYLEFT_IDS)


def _expression_license_ids(value: object) -> tuple[str, ...]:
    """Extract pinned SPDX license IDs (and LicenseRef markers) from one value."""

    if not isinstance(value, str):
        return ()
    return tuple(
        token
        for token in _EXPRESSION_TOKEN.findall(value)
        if token in _LICENSE_IDS or token.startswith("LicenseRef-")
    )


def detect_routing_evidence(texts: tuple[bytes, ...]) -> tuple[tuple[str, ...], bool]:
    """Detect routing evidence from caller-supplied license-file bytes.

    Returns ``(spdx_ids, proprietary_marker)`` where ``spdx_ids`` is the
    sorted, deduplicated union of SPDX-License-Identifier markers and
    GPL-family canonical header matches.  Pure; no I/O.
    """

    identifiers: set[str] = set()
    proprietary = False
    for view in texts:
        for match in _HEADER.finditer(view):
            try:
                expression = match.group(1).decode("ascii").strip()
            except UnicodeDecodeError:
                continue
            identifiers.update(token for token in _EXPRESSION_TOKEN.findall(expression) if token in _LICENSE_IDS)
        for identifier, pattern in _GPL_FAMILY_HEADERS:
            if pattern.search(view) is not None:
                identifiers.add(identifier)
        if any(pattern.search(view) is not None for pattern in _PROPRIETARY_MARKERS):
            proprietary = True
    return tuple(sorted(identifiers)), proprietary


def routing_for_source(
    expressions: tuple[object, ...],
    *,
    proprietary_marker: bool = False,
    enterprise_carve_out: bool = False,
) -> LicenseRouting:
    """Route one surfaced source: pure function of detections plus policy table.

    Precedence (most restrictive segment wins): a proprietary marker, an
    enterprise carve-out segment, then per-expression classification.  The
    reason lists every license contributor in a fixed severity order
    (``copyleft:*`` sorted, ``license-undetermined``, ``permissive:*``
    sorted).  Empty, non-text, unclassifiable, or LicenseRef-only expressions
    are undetermined contributors: they can only push toward ``study-only``.
    """

    if proprietary_marker:
        return LicenseRouting(STUDY_ONLY, REASON_PROPRIETARY)
    if enterprise_carve_out:
        return LicenseRouting(STUDY_ONLY, REASON_ENTERPRISE_CARVE_OUT)
    copyleft: set[str] = set()
    permissive: set[str] = set()
    undetermined = not expressions
    for value in expressions:
        tokens = _expression_license_ids(value)
        classified = tuple(token for token in tokens if token in _ROUTING_PERMISSIVE_IDS or token in _ROUTING_COPYLEFT_IDS)
        # A LicenseRef marker is a non-standard license term: even when the
        # expression also names classified IDs, the whole expression stays an
        # undetermined contributor (fail-closed under AND semantics).
        if not classified or any(token.startswith("LicenseRef-") for token in tokens):
            undetermined = True
        for token in classified:
            (copyleft if token in _ROUTING_COPYLEFT_IDS else permissive).add(token)
    if not copyleft and not permissive:
        return LicenseRouting(STUDY_ONLY, REASON_LICENSE_UNDETERMINED)
    if copyleft or undetermined:
        components = [f"copyleft:{identifier}" for identifier in sorted(copyleft)]
        if undetermined:
            components.append(REASON_LICENSE_UNDETERMINED)
        components.extend(f"permissive:{identifier}" for identifier in sorted(permissive))
        return LicenseRouting(STUDY_ONLY, ",".join(components))
    return LicenseRouting(TRANSPLANT_OK, ",".join(f"permissive:{identifier}" for identifier in sorted(permissive)))


def undetermined_routing() -> LicenseRouting:
    """The fail-closed degrade routing used when evaluation cannot proceed."""

    return LicenseRouting(STUDY_ONLY, REASON_LICENSE_UNDETERMINED)


__all__ = [
    "DEFAULT_LICENSE_POLICY",
    "LICENSE_POLICY_AUTHORITY",
    "LICENSE_POLICY_ID",
    "OBLIGATIONS_SCHEMA_VERSION",
    "PINNED_LICENSE_POLICY",
    "REASON_ENTERPRISE_CARVE_OUT",
    "REASON_LICENSE_UNDETERMINED",
    "REASON_PROPRIETARY",
    "ROUTING_SCHEMA_VERSION",
    "SPDX_GRAMMAR_ID",
    "STUDY_ONLY",
    "TRANSPLANT_OK",
    "BundledSource",
    "CompatibilityDecision",
    "CopyleftBoundary",
    "CopyleftBoundaryObligation",
    "DisclosureAction",
    "DisclosureScope",
    "EvidenceStatus",
    "EvidenceTier",
    "LicenseDecision",
    "LicenseDecisionStatus",
    "LicenseEvidence",
    "LicensePolicy",
    "LicenseResolution",
    "LicenseRouting",
    "LicenseTextObligation",
    "ModificationMarkingObligation",
    "ObligationKind",
    "ObligationProvenance",
    "ObligationRecord",
    "Obligations",
    "ObligationsManifest",
    "RecipientLicensePolicy",
    "ResolutionState",
    "SourceDisclosureObligation",
    "SourceObligationSet",
    "TextObligation",
    "VerifiedBytes",
    "VerifiedSource",
    "canonicalize_spdx_expression",
    "detect_routing_evidence",
    "evaluate_license_policy",
    "license_payloads",
    "render_attribution",
    "resolve_source_license",
    "routing_for_source",
    "undetermined_routing",
    "validate_routing_policy_table",
]
