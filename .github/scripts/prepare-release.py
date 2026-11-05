#!/usr/bin/env python3
"""Require matching versions, complete archives/binaries, and GitHub asset digests."""
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile
import zipfile

TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"]


def digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(65536), b""):
        result.update(block)
    return result.hexdigest()


def prepare(tag, folder=None, metadata=None):
    version = re.search(r'^version\s*=\s*"([^"\n]+)"\s*$', Path("Cargo.toml").read_text(), re.M).group(1)
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or tag != "v" + version:
        raise ValueError("Release tag must match Cargo.toml's stable package version")
    if folder is None:
        return
    folder = Path(folder)
    expected = {}
    for target in TARGETS:
        windows = target.endswith("windows-msvc")
        binary = "custos-" + target + (".exe" if windows else "")
        archive = "custos-" + target + (".zip" if windows else ".tar.gz")
        with folder.joinpath(binary).open("rb") as stream:
            expected[binary] = digest(stream)
        with folder.joinpath(archive).open("rb") as stream:
            expected[archive] = digest(stream)
        if windows:
            with zipfile.ZipFile(folder / archive) as package:
                with package.open("custos.exe") as executable:
                    inside = digest(executable)
        else:
            with tarfile.open(folder / archive, "r:gz") as package:
                member = package.getmember("custos")
                if not member.isfile():
                    raise ValueError("Archive executable must be a regular file")
                with package.extractfile(member) as executable:
                    inside = digest(executable)
        if inside != expected[binary]:
            raise ValueError("Archive and updater executable differ: " + target)
    if metadata is not None:
        release = json.loads(Path(metadata).read_text())
        if release["tag_name"] != tag:
            raise ValueError("GitHub release tag mismatch")
        assets = {asset["name"]: asset for asset in release["assets"]}
        for name, checksum in expected.items():
            asset = assets[name]
            if asset.get("state") != "uploaded" or asset.get("digest") != "sha256:" + checksum:
                raise ValueError("GitHub digest missing or mismatched: " + name)
    folder.joinpath("SHA256SUMS").write_text("".join(checksum + "  " + name + "\n"
        for name, checksum in sorted(expected.items())), encoding="ascii")
    print("Verified 10 platform assets; SHA256SUMS ready")


if __name__ == "__main__":
    prepare(*sys.argv[1:])
