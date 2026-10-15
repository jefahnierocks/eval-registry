"""Keep disposable Git fixtures independent of their invoking commit hook."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def reference_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
    )
    return env


def reference_git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        env=reference_environment(),
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout


def metadata(root: Path) -> dict[str, bytes]:
    gitdir = root / ".git"
    names = ["config", "index", "HEAD", "packed-refs"]
    names.extend(
        path.relative_to(gitdir).as_posix()
        for path in (gitdir / "refs").rglob("*")
        if path.is_file()
    )
    return {
        name: (gitdir / name).read_bytes()
        for name in names
        if (gitdir / name).is_file()
    }


class FixtureIsolationTests(unittest.TestCase):
    def test_fixture_git_ignores_each_inherited_repository_binding(self) -> None:
        source = Path(__file__).with_name("test_repository_security.py")
        spec = importlib.util.spec_from_file_location(
            "fixture_security_under_test", source
        )
        assert spec is not None and spec.loader is not None
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        for names in (("GIT_DIR",), ("GIT_INDEX_FILE",), ("GIT_DIR", "GIT_INDEX_FILE")):
            with (
                self.subTest(bindings=names),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                foreign = root / "foreign"
                foreign.mkdir()
                reference_git(foreign, "init", "--quiet")
                (foreign / "sentinel.txt").write_text("inert fixture sentinel\n")
                reference_git(foreign, "add", "sentinel.txt")
                # This inert temporary repository has no hooks or user configuration.
                reference_git(
                    foreign,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture sentinel",
                )
                before = metadata(foreign)
                before_refs = reference_git(foreign, "show-ref", "--head")
                target = root / "target"
                target.mkdir()
                values = {
                    "GIT_DIR": str(foreign / ".git"),
                    "GIT_INDEX_FILE": str(foreign / ".git/index"),
                }
                poisoned = reference_environment()
                poisoned.update({key: values[key] for key in names})
                with patch.dict(os.environ, poisoned, clear=True):
                    fixture.git(target, "init", "--quiet")
                    (target / "fixture.txt").write_text("inert isolated fixture\n")
                    fixture.git(target, "add", "fixture.txt")
                self.assertTrue((target / ".git").is_dir())
                self.assertEqual(
                    reference_git(target, "ls-files", "-z"), b"fixture.txt\0"
                )
                self.assertEqual(metadata(foreign), before)
                self.assertEqual(
                    reference_git(foreign, "show-ref", "--head"), before_refs
                )
                self.assertEqual(
                    reference_git(foreign, "ls-files", "-z"), b"sentinel.txt\0"
                )


if __name__ == "__main__":
    unittest.main()
