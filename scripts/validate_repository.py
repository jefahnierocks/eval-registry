#!/usr/bin/env python3
"""Validate the inert D2 repository scaffold without external dependencies or I/O."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    "README.md",
    "AGENTS.md",
    "policy/authorization-state.json",
    "docs/architecture.md",
    "docs/verification-policy.md",
    "docs/append-only-review.md",
    "docs/agent-identity-approval-roadmap.md",
    "docs/authorization-state-versioning.md",
    "schemas/authorization-state.v1.schema.json",
    "schemas/authorization-state.v2.schema.json",
    "schemas/registration-receipt.v1.schema.json",
    "schemas/attempt-disposition.v1.schema.json",
    "schemas/verification-result.v1.schema.json",
    ".github/CODEOWNERS",
    ".github/pull_request_template.md",
    ".github/workflows/validate.yml",
    "scripts/validate_pr_attestation.py",
}

GENERIC_PUBLIC_BOUNDARY_MARKERS = (
    "/" + "Users/",
    "/" + "home/",
    "C:" + "\\Users\\",
    "op:" + "//",
    "BEGIN " + "PRIVATE KEY",
    "BEGIN " + "OPENSSH PRIVATE KEY",
)

FORBIDDEN_D2_PREFIXES = ("records/", "receipts/", "dispositions/", "bundles/", "trust/")

FORBIDDEN_WORKFLOW_MARKERS = (
    "id-token: write",
    "cosign sign",
    "cosign attest",
    "rekor-cli",
    "openssl ts",
    "curl ",
    "wget ",
    "gh api",
    "secrets.",
)


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_text(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {value}")
        ),
    )


def load_json(path: Path) -> Any:
    return parse_json_text(path.read_text(encoding="utf-8"))


AUTHORIZATION_STATE_KEYS = {
    "eval-registry.authorization-state.v1": frozenset(
        {
            "schema_version",
            "stage",
            "repository_creation_approved",
            "signer_workflow_approved",
            "external_authorities_approved",
            "record_publication_approved",
            "effective_date",
        }
    ),
    "eval-registry.authorization-state.v2": frozenset(
        {
            "schema_version",
            "stage",
            "repository_creation_approved",
            "pull_request_review_mode",
            "signer_workflow_approved",
            "external_authorities_approved",
            "record_publication_approved",
            "effective_date",
        }
    ),
}


def validate_authorization_state_contract(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["authorization state is not an object"]
    version = value.get("schema_version")
    if not isinstance(version, str):
        return ["authorization-state schema_version is not a string"]
    expected_keys = AUTHORIZATION_STATE_KEYS.get(version)
    if expected_keys is None:
        return [f"unknown authorization-state contract: {version!r}"]
    if frozenset(value) != expected_keys:
        return [f"authorization state does not match closed contract {version}"]
    return []


def validate_authorization_state(value: Any) -> list[str]:
    contract_errors = validate_authorization_state_contract(value)
    if contract_errors:
        return contract_errors
    expected = {
        "schema_version": "eval-registry.authorization-state.v2",
        "stage": "d2_scaffold",
        "repository_creation_approved": True,
        "pull_request_review_mode": "solo_maintainer_attestation_v1",
        "signer_workflow_approved": False,
        "external_authorities_approved": False,
        "record_publication_approved": False,
        "effective_date": "2026-07-13",
    }
    return (
        []
        if value == expected
        else ["authorization state is not the exact D2 scaffold state"]
    )


def is_record_path(relative_path: str) -> bool:
    return any(relative_path.startswith(prefix) for prefix in FORBIDDEN_D2_PREFIXES)


class SourceInspectionError(RuntimeError):
    """Source names or metadata could not be safely inspected."""


def _refuse_forbidden_roots() -> None:
    for prefix in FORBIDDEN_D2_PREFIXES:
        try:
            (ROOT / prefix.removesuffix("/")).lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SourceInspectionError("D2 root metadata inspection failed") from exc
        raise SourceInspectionError("D2 forbids a record/trust root")


def _tracked_source_files() -> list[Path]:
    """List Git source names, vet the entire snapshot, then permit content reads."""
    _refuse_forbidden_roots()
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            check=False,
            timeout=30,
            env={
                **{
                    name: os.environ[name]
                    for name in (
                        "PATH",
                        "HOME",
                        "TMPDIR",
                        "LANG",
                        "LC_ALL",
                        "SYSTEMROOT",
                    )
                    if name in os.environ
                },
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceInspectionError("Git source enumeration failed") from exc
    if result.returncode or (result.stdout and not result.stdout.endswith(b"\0")):
        raise SourceInspectionError("Git source enumeration failed")
    try:
        names = sorted(
            {raw.decode("utf-8") for raw in result.stdout.split(b"\0") if raw}
        )
    except UnicodeError as exc:
        raise SourceInspectionError("source path encoding is unsafe") from exc
    paths: list[Path] = []
    # Validate every name before even inspecting its target's metadata.
    for name in names:
        parts = name.split("/")
        if (
            PurePosixPath(name).is_absolute()
            or "\\" in name
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise SourceInspectionError("source path is unsafe")
        if any(part.casefold() == "private" for part in parts[:-1]):
            raise SourceInspectionError("private source directory is forbidden")
    for name in names:
        parts = name.split("/")
        path = ROOT
        for index, part in enumerate(parts):
            path = path / part
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise SourceInspectionError(
                    "source metadata is missing or unreadable"
                ) from exc
            if stat.S_ISLNK(mode):
                raise SourceInspectionError("source symlink is forbidden")
            expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
            if not expected(mode):
                raise SourceInspectionError(
                    "source entry is not a regular file or directory"
                )
        paths.append(path)
    return paths


def validate_repository() -> list[str]:
    errors: list[str] = []
    try:
        source_files = _tracked_source_files()
    except SourceInspectionError as exc:
        return [str(exc)]
    present = {path.relative_to(ROOT).as_posix() for path in source_files}

    missing = sorted(REQUIRED_FILES - present)
    errors.extend(f"missing required file: {path}" for path in missing)

    forbidden_files = sorted(path for path in present if is_record_path(path))
    errors.extend(
        f"D2 forbids record/trust material path: {path}" for path in forbidden_files
    )

    for relative in sorted(path for path in present if path.endswith(".json")):
        try:
            value = load_json(ROOT / relative)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            errors.append("invalid exact JSON in a source file")
            continue
        if relative.startswith("schemas/"):
            if not isinstance(value, dict):
                errors.append(f"schema is not an object: {relative}")
            elif value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                errors.append(f"schema draft is not pinned in {relative}")
            elif value.get("additionalProperties") is not False:
                errors.append(f"top-level schema is not closed: {relative}")

    if "policy/authorization-state.json" in present:
        try:
            state = load_json(ROOT / "policy/authorization-state.json")
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            errors.append("cannot read exact authorization state")
        else:
            if validate_authorization_state(state):
                errors.append("authorization state violates the closed D2 contract")

    for path in source_files:
        relative = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append("unreadable or non-UTF-8 source is forbidden in D2")
            continue
        for marker in GENERIC_PUBLIC_BOUNDARY_MARKERS:
            if marker.casefold() in text.casefold():
                errors.append(f"public-boundary marker in {relative}: {marker!r}")

        if relative.startswith(".github/workflows/"):
            lowered = text.casefold()
            for marker in FORBIDDEN_WORKFLOW_MARKERS:
                if marker.casefold() in lowered:
                    errors.append(
                        f"D2 workflow activation marker in {relative}: {marker!r}"
                    )

    return errors


def main() -> int:
    errors = validate_repository()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("eval-registry D2 scaffold validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
