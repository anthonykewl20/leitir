"""Registry source-artifact verification and semantic tree parity."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import logging
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from leitir import _http
from leitir.credentials import Credentials
from leitir.materialize import (
    ARCHIVE_MAX_COMPRESSED_BYTES,
    MANIFEST_NAME,
    UnsafeArchiveError,
    _extract_tarball,
)

logger = logging.getLogger(__name__)


class ChecksumMismatchError(Exception):
    """A downloaded artifact does not match its registry checksum."""


@dataclass(frozen=True, slots=True)
class ArtifactInfo:
    artifact_kind: str
    url: str
    algorithm: str
    digest: str
    checksum: str

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError("registry artifact URL must use HTTPS")


@dataclass(frozen=True, slots=True)
class ParityResult:
    parity: str
    files_compared: int
    only_in_git: int
    only_in_artifact: int
    artifact_kind: str | None = None
    checksum: str | None = None

    def __post_init__(self) -> None:
        if self.parity not in {"exact", "drift", "unknown"}:
            raise ValueError("invalid parity verdict")
        if min(self.files_compared, self.only_in_git, self.only_in_artifact) < 0:
            raise ValueError("parity file counts must be non-negative")

    def manifest_fields(self) -> dict[str, object]:
        return {
            "parity": self.parity,
            "files_compared": self.files_compared,
            "only_in_git": self.only_in_git,
            "only_in_artifact": self.only_in_artifact,
        }


UNKNOWN_PARITY = ParityResult("unknown", 0, 0, 0)


def artifact_from_metadata(
    ecosystem: str, name: str, version: str, payload: object
) -> ArtifactInfo | None:
    """Select and validate the registry's source artifact metadata."""
    if not isinstance(payload, dict):
        return None
    if ecosystem == "npm":
        versions = payload.get("versions")
        selected = versions.get(version) if isinstance(versions, dict) else payload
        dist = selected.get("dist") if isinstance(selected, dict) else None
        url = dist.get("tarball") if isinstance(dist, dict) else None
        integrity = dist.get("integrity") if isinstance(dist, dict) else None
        if not isinstance(url, str) or not isinstance(integrity, str):
            return None
        token = next((item for item in integrity.split() if item.startswith("sha512-")), None)
        if token is None:
            return None
        try:
            digest = base64.b64decode(token[7:], validate=True).hex()
        except (binascii.Error, ValueError):
            return None
        try:
            return ArtifactInfo("npm-tarball", url, "sha512", digest, token)
        except ValueError:
            return None
    if ecosystem == "pypi":
        urls = payload.get("urls")
        if not isinstance(urls, list):
            return None
        candidates = sorted(
            (item for item in urls if isinstance(item, dict) and item.get("packagetype") == "sdist"),
            key=lambda item: str(item.get("url", "")),
        )
        for item in candidates:
            url = item.get("url")
            digests = item.get("digests")
            pypi_digest = digests.get("sha256") if isinstance(digests, dict) else None
            if isinstance(url, str) and isinstance(pypi_digest, str):
                try:
                    return ArtifactInfo(
                        "sdist",
                        url,
                        "sha256",
                        pypi_digest.lower(),
                        f"sha256:{pypi_digest.lower()}",
                    )
                except ValueError:
                    continue
        return None
    if ecosystem == "crates":
        selected = payload.get("version")
        if not isinstance(selected, dict):
            versions = payload.get("versions")
            selected = next(
                (item for item in versions if isinstance(item, dict) and str(item.get("num")) == version),
                None,
            ) if isinstance(versions, list) else None
        if not isinstance(selected, dict):
            return None
        checksum = selected.get("checksum")
        url = selected.get("download_url")
        if not isinstance(url, str) or not url.startswith("https://"):
            url = f"https://crates.io/api/v1/crates/{name}/{version}/download"
        if not isinstance(checksum, str):
            return None
        return ArtifactInfo("crate", url, "sha256", checksum.lower(), f"sha256:{checksum.lower()}")
    return None


def _extract_zip(data: bytes, destination: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if not infos:
            raise UnsafeArchiveError("archive is empty")
        paths: list[tuple[zipfile.ZipInfo, PurePosixPath | None]] = []
        roots: set[str] = set()
        seen: set[PurePosixPath] = set()
        for info in infos:
            # ZipInfo normalizes the platform separator in ``filename``.  On
            # Windows that can conceal a raw backslash-bearing member, so
            # validate the pre-normalization archive name instead.
            name = info.orig_filename
            if not name or "\\" in name:
                raise UnsafeArchiveError("invalid archive member path")
            path = PurePosixPath(name)
            if path.is_absolute() or PureWindowsPath(name).drive or ".." in path.parts:
                raise UnsafeArchiveError("archive member escapes its target")
            parts = tuple(part for part in path.parts if part not in ("", "."))
            if not parts:
                raise UnsafeArchiveError("invalid archive member path")
            roots.add(parts[0])
            relative = PurePosixPath(*parts[1:]) if len(parts) > 1 else None
            if relative == PurePosixPath(MANIFEST_NAME):
                raise UnsafeArchiveError("archive contains Leitir's reserved manifest path")
            if relative is not None and relative in seen:
                raise UnsafeArchiveError("archive contains duplicate member paths")
            if relative is not None:
                seen.add(relative)
            mode = (info.external_attr >> 16) & 0o170000
            if mode not in (0, 0o040000, 0o100000):
                raise UnsafeArchiveError("archive contains a link or special file")
            paths.append((info, relative))
        if len(roots) != 1:
            raise UnsafeArchiveError("archive does not have the expected single top-level directory")
        destination.mkdir(parents=True, exist_ok=True)
        for info, relative in paths:
            if relative is None:
                if not info.is_dir():
                    raise UnsafeArchiveError("archive top-level member is not a directory")
                continue
            output = destination.joinpath(*relative.parts)
            if info.is_dir():
                output.mkdir(parents=True, exist_ok=True)
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, output.open("xb") as target:
                    shutil.copyfileobj(source, target)


def extract_artifact(data: bytes, destination: Path) -> None:
    """Safely extract a registry tarball or zip, stripping its root directory."""
    if zipfile.is_zipfile(io.BytesIO(data)):
        _extract_zip(data, destination)
    else:
        _extract_tarball(data, destination, "artifact", "0" * 40)


def compare_trees(git_tree: Path, artifact_tree: Path) -> ParityResult:
    """Compare sorted regular-file universes and bytes."""
    def files(root: Path) -> dict[str, Path]:
        return {
            path.relative_to(root).as_posix(): path
            for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
            if path.is_file()
            and not path.is_symlink()
            and path.relative_to(root).as_posix() != MANIFEST_NAME
        }

    git_files = files(git_tree)
    artifact_files = files(artifact_tree)
    logger.debug("parity comparing git=%s artifact=%s git_files=%d artifact_files=%d", git_tree, artifact_tree, len(git_files), len(artifact_files))
    common = sorted(set(git_files) & set(artifact_files))
    differs = any(git_files[path].read_bytes() != artifact_files[path].read_bytes() for path in common)
    only_git = len(set(git_files) - set(artifact_files))
    only_artifact = len(set(artifact_files) - set(git_files))
    verdict = "exact" if not differs and only_git == 0 and only_artifact == 0 else "drift"
    if logger.isEnabledFor(logging.DEBUG):
        mismatches = [
            path for path in common
            if git_files[path].read_bytes() != artifact_files[path].read_bytes()
        ]
        logger.debug("parity outcome=%s mismatched=%d sample=%s only_git=%d only_artifact=%d", verdict, len(mismatches), mismatches[:5], only_git, only_artifact)
    return ParityResult(verdict, len(common), only_git, only_artifact)


class RegistryArtifactFetcher:
    """Retrying HTTPS transport for registry metadata and artifacts."""

    def __init__(
        self,
        *,
        timeout: int = 60,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
        get_json: Callable[[str], object] | None = None,
        get_bytes: Callable[[str], bytes] | None = None,
        max_bytes: int | None = None,
    ) -> None:
        self._timeout = timeout
        self._get_json_override = get_json
        self._get_bytes_override = get_bytes
        self._max_bytes = max_bytes
        self._credentials = Credentials()
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _request_json(self, url: str) -> object:
        logger.debug("artifact metadata request url=%s", url)
        if self._get_json_override is not None:
            return self._get_json_override(url)
        from urllib.request import Request

        headers = self._credentials.headers(
            url, {"Accept": "application/json", "User-Agent": "leitir"}
        )
        with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as response:
            if not response.geturl().startswith("https://"):
                raise ValueError("registry redirect must use HTTPS")
            return json.load(response)

    def _request_bytes(self, url: str) -> bytes:
        logger.debug("artifact download request url=%s", url)
        if self._get_bytes_override is not None:
            data = self._get_bytes_override(url)
            if self._max_bytes is not None and len(data) > self._max_bytes:
                raise ValueError("artifact download exceeds compressed size limit")
            return data
        from urllib.request import Request

        headers = self._credentials.headers(
            url, {"Accept": "application/octet-stream", "User-Agent": "leitir"}
        )
        with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as response:
            if not response.geturl().startswith("https://"):
                raise ValueError("artifact redirect must use HTTPS")
            if self._max_bytes is None:
                return response.read()
            data = response.read(self._max_bytes + 1)
            if len(data) > self._max_bytes:
                raise ValueError("artifact download exceeds compressed size limit")
            return data

    def metadata(self, ecosystem: str, name: str, version: str) -> object:
        from urllib.parse import quote

        urls = {
            "npm": f"https://registry.npmjs.org/{quote(name, safe='')}/{quote(version, safe='')}",
            "pypi": f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json",
            "crates": f"https://crates.io/api/v1/crates/{quote(name, safe='')}/{quote(version, safe='')}",
        }
        return self._retry(lambda: self._request_json(urls[ecosystem]))

    def fetch(self, artifact: ArtifactInfo) -> bytes:
        return self._retry(lambda: self._request_bytes(artifact.url))


def package_parity(
    ecosystem: str,
    name: str,
    version: str,
    git_tree: Path,
    *,
    artifact: ArtifactInfo | None = None,
    metadata: object | None = None,
    fetcher: RegistryArtifactFetcher | None = None,
) -> ParityResult:
    """Fetch, authenticate, extract, and compare one package source artifact."""
    if ecosystem not in {"npm", "pypi", "crates"}:
        logger.debug("parity outcome=unknown ecosystem=%s", ecosystem)
        return UNKNOWN_PARITY
    logger.debug("parity package ecosystem=%s name=%s version=%s", ecosystem, name, version)
    client = fetcher or RegistryArtifactFetcher(max_bytes=ARCHIVE_MAX_COMPRESSED_BYTES)
    try:
        if artifact is None:
            if metadata is None:
                metadata = client.metadata(ecosystem, name, version)
            artifact = artifact_from_metadata(ecosystem, name, version, metadata)
        if artifact is None:
            return UNKNOWN_PARITY
        data = client.fetch(artifact)
    except Exception:
        if artifact is None:
            return UNKNOWN_PARITY
        return ParityResult(
            "unknown",
            0,
            0,
            0,
            artifact.artifact_kind,
            artifact.checksum,
        )
    actual = hashlib.new(artifact.algorithm, data).hexdigest()
    logger.debug("parity checksum expected=%s actual=%s", artifact.digest, actual)
    if actual.lower() != artifact.digest.lower():
        raise ChecksumMismatchError(
            f"{artifact.artifact_kind} checksum mismatch: expected {artifact.checksum}"
        )
    temporary = Path(tempfile.mkdtemp(prefix="leitir-parity-"))
    try:
        extract_artifact(data, temporary)
        compared = compare_trees(git_tree, temporary)
        return ParityResult(
            compared.parity,
            compared.files_compared,
            compared.only_in_git,
            compared.only_in_artifact,
            artifact.artifact_kind,
            artifact.checksum,
        )
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


__all__ = [
    "UNKNOWN_PARITY",
    "ArtifactInfo",
    "ChecksumMismatchError",
    "ParityResult",
    "RegistryArtifactFetcher",
    "artifact_from_metadata",
    "compare_trees",
    "extract_artifact",
    "package_parity",
]
