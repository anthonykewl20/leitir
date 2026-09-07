"""Verify retained archive bytes and final hosted command journals without extraction."""
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath


def verify(directory: Path) -> None:
    manifest = json.loads((directory / "artifact-manifest.json").read_text())
    archive = directory / "raw-evidence.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["archive_sha256"]:
        raise ValueError("archive digest mismatch")
    expected = {item["path"]: item for item in manifest["files"]}
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != set(expected):
            raise ValueError("archive file inventory mismatch")
        contents: dict[str, bytes] = {}
        for member in members:
            stream = tar.extractfile(member) if member.isfile() else None
            if stream is None:
                raise ValueError("non-regular archive entry")
            data = stream.read()
            item = expected[member.name]
            if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError(f"file digest mismatch: {member.name}")
            contents[member.name] = data
    for platform in ("linux", "windows"):
        prefix = f"hosted-final-{platform}/"
        journals = sorted(name for name in contents if name.startswith(prefix) and name.endswith("/commands.json"))
        if not journals:
            raise ValueError(f"no final journals for {platform}")
        count = 0
        for name in journals:
            for record in json.loads(contents[name]):
                if record["exit_code"] != record["expected_exit"]:
                    raise ValueError(f"unexpected command exit: {name}")
                for stream_name in ("stdout", "stderr"):
                    path = str(PurePosixPath(name).parent / record[stream_name])
                    if hashlib.sha256(contents[path]).hexdigest() != record[f"{stream_name}_sha256"]:
                        raise ValueError(f"command stream digest mismatch: {path}")
                count += 1
        print(f"{platform}: {len(journals)} journals, {count} commands verified")
    print(f"Archive verified: {len(contents)} files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=Path(__file__).parent)
    verify(parser.parse_args().directory)
