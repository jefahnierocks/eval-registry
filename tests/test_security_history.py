"""Native regression for findings introduced only in a merge and later removed."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def isolated_environment() -> dict[str, str]:
    names = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT")
    result = {name: os.environ[name] for name in names if name in os.environ}
    result.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return result


class NativeMergeHistoryTests(unittest.TestCase):
    def test_removed_merge_only_finding_is_detected(self) -> None:
        binary = shutil.which("gitleaks")
        self.assertIsNotNone(binary, "Pinned native scanner is required, not optional")
        with tempfile.TemporaryDirectory(prefix="security-merge-test-") as directory:
            root = Path(directory).resolve()
            environment = isolated_environment()

            def run(arguments: list[str], payload: bytes | None = None) -> int:
                result = subprocess.run(
                    arguments,
                    cwd=root,
                    input=payload,
                    capture_output=True,
                    check=False,
                    timeout=90,
                    env=environment,
                )
                # Never relay even redacted native output or detector input.
                return result.returncode

            self.assertEqual(
                run(["git", "init", "--quiet", "--initial-branch=main"]), 0
            )
            stream = bytearray()

            def blob(mark: int, content: bytes) -> None:
                stream.extend(
                    f"blob\nmark :{mark}\ndata {len(content)}\n".encode()
                    + content
                    + b"\n"
                )

            def commit(
                mark: int,
                branch: str,
                message: str,
                parent: int | None = None,
                merge: int | None = None,
                operations: str = "",
            ) -> None:
                stream.extend(
                    f"commit refs/heads/{branch}\nmark :{mark}\n"
                    "committer Synthetic Test <synthetic@example.invalid> 1700000000 +0000\n"
                    f"data {len(message)}\n{message}\n".encode()
                )
                if parent is not None:
                    stream.extend(f"from :{parent}\n".encode())
                if merge is not None:
                    stream.extend(f"merge :{merge}\n".encode())
                stream.extend(operations.encode() + b"\n")

            blob(1, b"non-secret baseline\n")
            commit(2, "main", "baseline", operations="M 100644 :1 README.md\n")
            self.assertEqual(run(["git", "fast-import", "--quiet"], bytes(stream)), 0)
            self.assertEqual(run(["git", "read-tree", "--reset", "-u", "HEAD"]), 0)
            (root / "scripts").mkdir()
            shutil.copyfile(
                SOURCE_ROOT / "scripts/check_repository_security.py",
                root / "scripts/check_repository_security.py",
            )
            (root / ".mise.toml").write_text('[tools]\ngitleaks = "8.30.1"\n')
            source_ledger = SOURCE_ROOT / ".gitleaksignore"
            if source_ledger.is_file():
                shutil.copyfile(source_ledger, root / ".gitleaksignore")
            checker = [sys.executable, "-B", "scripts/check_repository_security.py"]
            self.assertEqual(run(checker), 0, "Clean synthetic repository must pass")

            # These bytes are invented invalid detector input, never a credential.
            # The curl-shaped text is passed only to the scanner, never executed.
            payload = (
                'curl -H "Authorization: Bearer '
                + "invalid-key-"
                + "1234567890"
                + '" https://example.invalid\n'
            ).encode()
            native_environment = dict(environment)
            native_environment["GITLEAKS_CONFIG_TOML"] = "[extend]\nuseDefault = true\n"
            positive = subprocess.run(
                [
                    str(binary),
                    "stdin",
                    "--redact=100",
                    "--no-banner",
                    "--ignore-gitleaks-allow",
                    "--gitleaks-ignore-path",
                    os.devnull,
                ],
                cwd=root,
                input=payload,
                capture_output=True,
                check=False,
                timeout=90,
                env=native_environment,
            )
            self.assertEqual(
                positive.returncode, 1, "Native positive control must detect"
            )
            stream.clear()
            blob(1, b"non-secret baseline\n")
            commit(2, "main", "baseline", operations="M 100644 :1 README.md\n")
            blob(3, b"synthetic side branch\n")
            commit(4, "side", "side", 2, operations="M 100644 :3 side.txt\n")
            blob(5, b"synthetic main branch\n")
            commit(6, "main", "main", 2, operations="M 100644 :5 main.txt\n")
            blob(7, payload)
            commit(8, "main", "merge fixture", 6, 4, "M 100644 :7 merge-only.txt\n")
            commit(9, "main", "remove fixture", 8, operations="D merge-only.txt\n")
            self.assertEqual(run(["git", "fast-import", "--quiet"], bytes(stream)), 0)
            self.assertEqual(run(["git", "read-tree", "--reset", "-u", "HEAD"]), 0)
            self.assertFalse((root / "merge-only.txt").exists())
            self.assertEqual(run(["git", "diff", "--exit-code"]), 0)
            self.assertEqual(run(["git", "diff", "--cached", "--exit-code"]), 0)
            self.assertEqual(run(checker), 1, "Merge-only historical finding must fail")

            # Git-local conversion must not hide historical source from detection.
            self.assertEqual(
                run(
                    ["git", "config", "diff.securityfixture.textconv", "/usr/bin/true"]
                ),
                0,
            )
            (root / ".git/info/attributes").write_text(
                "merge-only.txt diff=securityfixture\n"
            )
            self.assertEqual(
                run(checker), 1, "Git-local text conversion must not hide the finding"
            )


if __name__ == "__main__":
    unittest.main()
