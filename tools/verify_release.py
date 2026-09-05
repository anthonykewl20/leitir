"""Validate a padded release tag against the actual CI-built distributions."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path

_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.([0-9]{3})")
_MAX_METADATA = 1024 * 1024


def _check_metadata(data: bytes, version: str) -> None:
    if len(data) > _MAX_METADATA:
        raise ValueError("distribution metadata exceeds the size bound")
    message = BytesParser().parsebytes(data)
    if message.get_all("Name") != ["leitir"] or message.get_all("Version") != [version]:
        raise ValueError("distribution Name/Version headers do not match the release")


def verify_release(tag: str, dist: Path, project: Path) -> dict[str, object]:
    if not tag.startswith("v") or _VERSION.fullmatch(tag[1:]) is None:
        raise ValueError("release tag must be vMAJOR.MINOR.PATCH with exactly three patch digits")
    public = tag[1:]
    normalized = ".".join(str(int(part)) for part in public.split("."))
    metadata = tomllib.loads(project.read_text(encoding="utf-8"))["project"]
    if metadata.get("name") != "leitir" or metadata.get("version") != public:
        raise ValueError("project name/version does not match the release tag")
    wheel_name = f"leitir-{normalized}-py3-none-any.whl"
    sdist_name = f"leitir-{normalized}.tar.gz"
    paths = sorted(dist.iterdir())
    if [path.name for path in paths] != sorted([wheel_name, sdist_name]):
        raise ValueError("distribution directory must contain exactly the matching wheel and sdist")
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("distribution artifacts must be regular files, not symbolic links")
    with zipfile.ZipFile(dist / wheel_name) as wheel:
        names = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
        expected = f"leitir-{normalized}.dist-info/METADATA"
        if names != [expected] or wheel.getinfo(expected).file_size > _MAX_METADATA:
            raise ValueError("wheel metadata path/count/size does not match the release")
        _check_metadata(wheel.read(expected), normalized)
    with tarfile.open(dist / sdist_name, "r:gz") as sdist:
        prefix = f"leitir-{normalized}/"
        for relative in ("PKG-INFO", "pyproject.toml"):
            members = [item for item in sdist.getmembers() if item.name == prefix + relative]
            if len(members) != 1 or not members[0].isfile() or members[0].size > _MAX_METADATA:
                raise ValueError(f"sdist {relative} path/count/type/size does not match the release")
            stream = sdist.extractfile(members[0])
            if stream is None:
                raise ValueError(f"sdist {relative} is unreadable")
            with stream:
                data = stream.read(_MAX_METADATA + 1)
            if relative == "PKG-INFO":
                _check_metadata(data, normalized)
            else:
                source_project = tomllib.loads(data.decode("utf-8"))["project"]
                if source_project.get("name") != "leitir" or source_project.get("version") != public:
                    raise ValueError("sdist project name/version does not match the release tag")
    digests: dict[str, str] = {}
    for path in paths:
        with path.open("rb") as stream:
            digests[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "tag": tag,
        "public_version": public,
        "distribution_version": normalized,
        "sha256": digests,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--project", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args()
    try:
        result = verify_release(args.tag, args.dist, args.project)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"release verification rejected: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
