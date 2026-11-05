#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("prepare-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseContract(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.previous = Path.cwd()
        os.chdir(self.root)
        self.root.joinpath("Cargo.toml").write_text('[package]\nversion = "0.5.0"\n')
        self.assets = []
        for target in release.TARGETS:
            windows = target.endswith("windows-msvc")
            contents = (target + " executable fixture\n").encode()
            binary = "custos-" + target + (".exe" if windows else "")
            archive = "custos-" + target + (".zip" if windows else ".tar.gz")
            self.root.joinpath(binary).write_bytes(contents)
            if windows:
                with zipfile.ZipFile(archive, "w") as package:
                    package.writestr("custos.exe", contents)
            else:
                with tarfile.open(archive, "w:gz") as package:
                    member = tarfile.TarInfo("custos")
                    member.size = len(contents)
                    package.addfile(member, io.BytesIO(contents))
            for name in [binary, archive]:
                self.assets.append({"name": name, "state":"uploaded",
                    "digest":"sha256:" + hashlib.sha256(self.root.joinpath(name).read_bytes()).hexdigest()})
        self.root.joinpath("metadata.json").write_text(json.dumps({"tag_name":"v0.5.0", "assets":self.assets}))

    def tearDown(self):
        os.chdir(self.previous)
        self.folder.cleanup()

    def test_complete_release_generates_ten_checksums(self):
        release.prepare("v0.5.0", ".", "metadata.json")
        self.assertEqual(len(self.root.joinpath("SHA256SUMS").read_text().splitlines()), 10)

    def test_missing_platform_cannot_publish(self):
        self.root.joinpath("custos-x86_64-pc-windows-msvc.exe").unlink()
        with self.assertRaises(FileNotFoundError):
            release.prepare("v0.5.0", ".", "metadata.json")
        self.assertFalse(self.root.joinpath("SHA256SUMS").exists())

    def test_modified_updater_binary_cannot_publish(self):
        self.root.joinpath("custos-aarch64-apple-darwin").write_bytes(b"wrong build")
        with self.assertRaisesRegex(ValueError, "differ"):
            release.prepare("v0.5.0", ".", "metadata.json")

    def test_wrong_version_and_missing_digest_cannot_publish(self):
        with self.assertRaises(ValueError):
            release.prepare("v0.5.1", ".", "metadata.json")
        self.assets[0]["digest"] = None
        self.root.joinpath("metadata.json").write_text(json.dumps({"tag_name":"v0.5.0", "assets":self.assets}))
        with self.assertRaisesRegex(ValueError, "digest"):
            release.prepare("v0.5.0", ".", "metadata.json")


if __name__ == "__main__":
    unittest.main()
