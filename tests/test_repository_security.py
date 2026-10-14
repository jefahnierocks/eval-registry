from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_repository_security.py"
SPEC = importlib.util.spec_from_file_location("repository_security", SCRIPT)
assert SPEC and SPEC.loader
security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security)


def git(repo: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout


class SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        git(self.repo, "init", "--quiet")
        (self.repo / ".gitignore").write_text("private/\n")
        (self.repo / ".mise.toml").write_text('[tools]\ngitleaks = "8.30.1"\n')
        git(self.repo, "add", ".gitignore", ".mise.toml")

    def write(self, name: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("generic engineering text\n")
        git(self.repo, "add", "--force", name)

    def test_legitimate_similar_names_and_nul_paths_pass(self) -> None:
        for name in ("src/private.py", "private-notes.md", "private", "a b\nc.md"):
            self.write(name)
        security.check_private_paths(self.repo)

    def test_root_nested_and_mixed_case_private_paths_refuse(self) -> None:
        for parent, name in enumerate(("private/x", "nested/PRIVATE/x", "Private/x")):
            with self.subTest(name=name):
                path = f"case-{parent}/{name}"
                self.write(path)
                with self.assertRaisesRegex(
                    security.SecurityError, "private directory"
                ):
                    security.check_private_paths(self.repo)
                git(self.repo, "rm", "--cached", "--force", path)
                (self.repo / path).unlink()

    def test_ignore_covers_root_and_nested_private(self) -> None:
        for name in ("private/x", "nested/private/x"):
            git(self.repo, "check-ignore", "--quiet", name)

    def test_git_failure_and_malformed_output_refuse(self) -> None:
        with (
            mock.patch.object(security.subprocess, "run", side_effect=OSError),
            self.assertRaises(security.SecurityError),
        ):
            security.check_private_paths(self.repo)
        with (
            mock.patch.object(security, "git_output", return_value=b"truncated"),
            self.assertRaises(security.SecurityError),
        ):
            security.check_private_paths(self.repo)

    def test_ambient_suppression_is_rejected_without_value_output(self) -> None:
        for variable in (
            "GITLEAKS_CONFIG",
            "GITLEAKS_CONFIG_TOML",
            "GITLEAKS_ENABLE_RULE",
        ):
            with (
                self.subTest(variable=variable),
                mock.patch.dict(os.environ, {variable: "synthetic-never-output"}),
            ):
                with self.assertRaises(security.SecurityError) as caught:
                    security.scanner_binary(self.repo)
                self.assertNotIn("synthetic-never-output", str(caught.exception))

    def test_missing_and_wrong_scanner_refuse(self) -> None:
        with (
            mock.patch.object(security.shutil, "which", return_value=None),
            self.assertRaises(security.SecurityError),
        ):
            security.scanner_binary(self.repo)
        with (
            mock.patch.object(security.shutil, "which", return_value="synthetic"),
            mock.patch.object(
                security.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, b"0.0.0", b""),
            ),
            self.assertRaises(security.SecurityError),
        ):
            security.scanner_binary(self.repo)

    def test_failure_output_never_reaches_diagnostics(self) -> None:
        output = io.StringIO()
        result = subprocess.CompletedProcess(
            [], 2, b"synthetic-source-bytes", b"synthetic-error"
        )
        with (
            mock.patch.object(security.subprocess, "run", return_value=result),
            redirect_stderr(output),
            self.assertRaises(security.SecurityError),
        ):
            security.run_scanner(
                "synthetic", self.repo, Path("config"), Path("ignore"), "stdin"
            )
        self.assertEqual(output.getvalue(), "")

    def test_all_history_and_separate_diffs_use_unsuppressible_native_rules(
        self,
    ) -> None:
        scans: list[tuple[tuple[str, ...], bytes | None]] = []
        diffs: list[tuple[str, ...]] = []

        def inspect(repo: Path, *arguments: str) -> bytes:
            self.assertEqual(repo, self.repo)
            if arguments == ("rev-parse", "--is-shallow-repository"):
                return b"false\n"
            diffs.append(arguments)
            return b"staged" if "--cached" in arguments else b"inverse unstaged"

        def scan(binary, repo, config, ignore, *arguments, source=None):
            self.assertEqual(binary, "synthetic")
            self.assertEqual(repo, self.repo)
            self.assertEqual(config.read_text(), "[extend]\nuseDefault = true\n")
            self.assertEqual(ignore, Path(os.devnull))
            scans.append((arguments, source))

        with (
            mock.patch.object(security, "scanner_binary", return_value="synthetic"),
            mock.patch.object(security, "git_output", side_effect=inspect),
            mock.patch.object(security, "run_scanner", side_effect=scan),
        ):
            security.check_secrets(self.repo)
        self.assertEqual(
            scans,
            [
                (
                    (
                        "git",
                        "--log-opts=--all --full-history --no-ext-diff --no-textconv --no-renames --diff-merges=first-parent",
                        ".",
                    ),
                    None,
                ),
                (("stdin",), b"staged"),
                (("stdin",), b"inverse unstaged"),
            ],
        )
        self.assertIn("--cached", diffs[0])
        self.assertIn("HEAD", diffs[0])
        self.assertNotIn("--cached", diffs[1])
        self.assertNotIn("HEAD", diffs[1])

    def test_scanner_config_files_and_shallow_history_refuse(self) -> None:
        for name in (".gitleaks.toml", ".gitleaksignore"):
            path = self.repo / name
            path.write_text("generic synthetic configuration")
            with self.assertRaises(security.SecurityError):
                security.scanner_binary(self.repo)
            path.unlink()
        with (
            mock.patch.object(security, "scanner_binary", return_value="synthetic"),
            mock.patch.object(security, "git_output", return_value=b"true\n"),
            self.assertRaisesRegex(security.SecurityError, "complete Git history"),
        ):
            security.check_secrets(self.repo)

    def test_subprocess_environment_excludes_suppression_and_credentials(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SYNTHETIC_CREDENTIAL": "not-for-output", "GIT_CONFIG_COUNT": "1"},
        ):
            environment = security.command_environment()
        self.assertNotIn("SYNTHETIC_CREDENTIAL", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")

    def test_scanner_flags_disable_inline_and_ignore_suppression(self) -> None:
        with mock.patch.object(
            security.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, b"", b""),
        ) as run:
            security.run_scanner(
                "synthetic",
                self.repo,
                Path("config"),
                Path("ignore"),
                "stdin",
                source=b"fixture",
            )
        argv = run.call_args.args[0]
        for option in (
            "--ignore-gitleaks-allow",
            "--redact=100",
            "--exit-code=1",
            "--max-target-megabytes=0",
        ):
            self.assertIn(option, argv)
        self.assertEqual(run.call_args.kwargs["input"], b"fixture")


class NativeDetectorTests(unittest.TestCase):
    def test_pinned_native_detector_rejects_synthetic_token(self) -> None:
        # Construct inert, deliberately invalid engineering data at runtime.
        candidate = (
            "ghp_"
            + hashlib.sha256(b"eval-registry offline detector canary").hexdigest()[:36]
        )
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".mise.toml").write_text('[tools]\ngitleaks = "8.30.1"\n')
            config = repo / "native.toml"
            config.write_text("[extend]\nuseDefault = true\n")
            ignore = repo / "ignore"
            ignore.write_text("")
            binary = security.scanner_binary(repo)
            with self.assertRaises(security.SecurityError) as caught:
                security.run_scanner(
                    binary, repo, config, ignore, "stdin", source=candidate.encode()
                )
            self.assertEqual(caught.exception.exit_code, 1)
            security.run_scanner(
                binary,
                repo,
                config,
                ignore,
                "stdin",
                source=b"ordinary public engineering text",
            )


if __name__ == "__main__":
    unittest.main()
