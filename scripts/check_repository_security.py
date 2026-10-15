#!/usr/bin/env python3
"""Check Git paths and delegate detection to pinned, unmodified Gitleaks rules."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

import tomllib

ROOT = Path(__file__).resolve().parents[1]
SCANNER_VERSION = "8.30.1"


class SecurityError(RuntimeError):
    """A security check refused without exposing source content."""

    def __init__(self, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def command_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    return environment


def git_output(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            capture_output=True,
            check=False,
            timeout=30,
            env=command_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SecurityError("Git inspection failed") from exc
    if result.returncode:
        raise SecurityError("Git inspection failed")
    return result.stdout


def check_private_paths(repo: Path) -> None:
    names = git_output(repo, "ls-files", "--cached", "-z")
    if names and not names.endswith(b"\0"):
        raise SecurityError("Git path enumeration is malformed")
    for raw in names.split(b"\0"):
        if not raw:
            continue
        try:
            name = raw.decode("utf-8")
        except UnicodeError as exc:
            raise SecurityError("Git path encoding is unsafe") from exc
        parts = name.split("/")
        if (
            PurePosixPath(name).is_absolute()
            or "\\" in name
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise SecurityError("Git path is unsafe")
        if any(part.casefold() == "private" for part in parts[:-1]):
            raise SecurityError("private directory in Git index is forbidden")


def scanner_binary(repo: Path) -> str:
    if any(name.startswith("GITLEAKS_") for name in os.environ):
        raise SecurityError("ambient scanner configuration is forbidden")
    for name in (".gitleaks.toml", ".gitleaksignore"):
        try:
            (repo / name).lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SecurityError("scanner configuration metadata failed") from exc
        raise SecurityError("repository scanner suppression configuration is forbidden")
    try:
        pin = tomllib.loads((repo / ".mise.toml").read_text())["tools"]["gitleaks"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SecurityError("scanner pin is missing or invalid") from exc
    if pin != SCANNER_VERSION:
        raise SecurityError("scanner pin differs from the reviewed version")
    binary = shutil.which("gitleaks")
    if binary is None:
        raise SecurityError("pinned Gitleaks is unavailable")
    try:
        result = subprocess.run(
            [binary, "version"],
            capture_output=True,
            check=False,
            timeout=10,
            env=command_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SecurityError("scanner version check failed") from exc
    if result.returncode or result.stdout.strip() != SCANNER_VERSION.encode():
        raise SecurityError("scanner version differs from the reviewed pin")
    return binary


def run_scanner(
    binary: str,
    repo: Path,
    config: Path,
    ignore: Path,
    *arguments: str,
    source: bytes | None = None,
) -> None:
    try:
        result = subprocess.run(
            [
                binary,
                *arguments,
                "--config",
                str(config),
                "--gitleaks-ignore-path",
                str(ignore),
                "--ignore-gitleaks-allow",
                "--redact=100",
                "--no-banner",
                "--no-color",
                "--exit-code=1",
                "--max-target-megabytes=0",
                "--timeout=300",
            ],
            cwd=repo,
            input=source,
            capture_output=True,
            check=False,
            timeout=310,
            env=command_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SecurityError("scanner execution failed") from exc
    # Even fully redacted detector output can contain source names or snippets.
    # Keep diagnostics value-blind; neither diff input nor subprocess output is logged.
    if result.returncode:
        raise SecurityError(
            "Gitleaks refused the source or could not complete", result.returncode
        )


def check_secrets(repo: Path) -> None:
    binary = scanner_binary(repo)
    if git_output(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise SecurityError("complete Git history is required")
    with tempfile.TemporaryDirectory(prefix="registry-security-") as temporary:
        tools = Path(temporary)
        config = tools / "native.toml"
        config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        ignore = Path(os.devnull)
        run_scanner(
            binary,
            repo,
            config,
            ignore,
            "git",
            "--log-opts=--all --full-history --no-ext-diff --no-textconv --no-renames --diff-merges=first-parent",
            ".",
        )
        for arguments in (
            (
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "HEAD",
            ),
            ("diff", "--no-ext-diff", "--no-textconv", "--no-renames"),
        ):
            source = git_output(repo, *arguments)
            if source:
                run_scanner(binary, repo, config, ignore, "stdin", source=source)


def main() -> int:
    try:
        check_private_paths(ROOT)
        check_secrets(ROOT)
    except SecurityError as exc:
        print(f"repository security: FAIL: {exc}", file=sys.stderr)
        return 1
    print("repository security: PASS (native history, staged and unstaged scans)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
