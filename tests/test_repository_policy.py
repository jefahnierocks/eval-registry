from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_module("validate_repository", "scripts/validate_repository.py")
append_only = load_module("check_append_only", "scripts/check_append_only.py")
attestation = load_module(
    "validate_pr_attestation", "scripts/validate_pr_attestation.py"
)

HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"
AUTHOR = "verlyn13"


def valid_attestation_body() -> str:
    declarations = "\n".join(
        f"- [x] {declaration}" for declaration in attestation.REQUIRED_DECLARATIONS
    )
    return (
        f"{attestation.START}\n"
        f"review_mode: {attestation.REVIEW_MODE}\n"
        f"reviewed_by: {AUTHOR}\n"
        f"reviewed_head_sha: {HEAD_SHA}\n\n"
        f"{declarations}\n"
        f"{attestation.END}"
    )


def pull_request_event(body: str | None = None) -> dict[str, object]:
    return {
        "pull_request": {
            "body": valid_attestation_body() if body is None else body,
            "head": {"sha": HEAD_SHA},
            "user": {"login": AUTHOR},
        }
    }


class ExactJsonTests(unittest.TestCase):
    def test_duplicate_keys_are_refused(self) -> None:
        with self.assertRaises(validator.DuplicateKeyError):
            validator.parse_json_text('{"stage":"d2_scaffold","stage":"d3"}')

    def test_nonfinite_numbers_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            validator.parse_json_text('{"value":NaN}')


class AuthorizationTests(unittest.TestCase):
    def test_repository_state_is_exact_d2(self) -> None:
        state = validator.load_json(ROOT / "policy/authorization-state.json")
        self.assertEqual(validator.validate_authorization_state(state), [])

    def test_record_publication_cannot_be_enabled_silently(self) -> None:
        state = validator.load_json(ROOT / "policy/authorization-state.json")
        state["record_publication_approved"] = True
        self.assertNotEqual(validator.validate_authorization_state(state), [])

    def test_historical_v1_shape_is_known_but_not_current(self) -> None:
        historical_v1 = {
            "schema_version": "eval-registry.authorization-state.v1",
            "stage": "d2_scaffold",
            "repository_creation_approved": True,
            "signer_workflow_approved": False,
            "external_authorities_approved": False,
            "record_publication_approved": False,
            "effective_date": "2026-07-13",
        }
        self.assertEqual(
            validator.validate_authorization_state_contract(historical_v1), []
        )
        self.assertNotEqual(validator.validate_authorization_state(historical_v1), [])

    def test_v1_cannot_carry_the_v2_review_field(self) -> None:
        state = validator.load_json(ROOT / "policy/authorization-state.json")
        state["schema_version"] = "eval-registry.authorization-state.v1"
        self.assertNotEqual(validator.validate_authorization_state_contract(state), [])

    def test_v2_requires_the_review_field(self) -> None:
        state = validator.load_json(ROOT / "policy/authorization-state.json")
        del state["pull_request_review_mode"]
        self.assertNotEqual(validator.validate_authorization_state_contract(state), [])

    def test_nonstring_authorization_version_is_refused(self) -> None:
        self.assertNotEqual(
            validator.validate_authorization_state_contract(
                {"schema_version": ["eval-registry.authorization-state.v2"]}
            ),
            [],
        )

    def test_authorization_state_schemas_are_distinct_and_closed(self) -> None:
        v1 = validator.load_json(ROOT / "schemas/authorization-state.v1.schema.json")
        v2 = validator.load_json(ROOT / "schemas/authorization-state.v2.schema.json")
        self.assertFalse(v1["additionalProperties"])
        self.assertFalse(v2["additionalProperties"])
        self.assertEqual(
            set(v1["required"]),
            set(
                validator.AUTHORIZATION_STATE_KEYS[
                    "eval-registry.authorization-state.v1"
                ]
            ),
        )
        self.assertEqual(
            set(v2["required"]),
            set(
                validator.AUTHORIZATION_STATE_KEYS[
                    "eval-registry.authorization-state.v2"
                ]
            ),
        )
        self.assertNotIn("pull_request_review_mode", v1["required"])
        self.assertIn("pull_request_review_mode", v2["required"])

    def test_all_record_namespaces_are_frozen(self) -> None:
        self.assertTrue(
            validator.is_record_path("records/registrations/x/statement.json")
        )
        self.assertTrue(
            validator.is_record_path("records/dispositions/x/statement.json")
        )
        self.assertTrue(validator.is_record_path("trust/policy.json"))
        self.assertFalse(
            validator.is_record_path("schemas/registration-receipt.v1.schema.json")
        )


class SoloMaintainerAttestationTests(unittest.TestCase):
    def test_exact_head_attestation_is_accepted(self) -> None:
        attestation.validate_event(pull_request_event())

    def test_stale_head_is_refused(self) -> None:
        event = pull_request_event()
        pull_request = event["pull_request"]
        assert isinstance(pull_request, dict)
        head = pull_request["head"]
        assert isinstance(head, dict)
        head["sha"] = "f" * 40
        with self.assertRaisesRegex(attestation.AttestationError, "stale"):
            attestation.validate_event(event)

    def test_author_mismatch_is_refused(self) -> None:
        event = pull_request_event()
        pull_request = event["pull_request"]
        assert isinstance(pull_request, dict)
        user = pull_request["user"]
        assert isinstance(user, dict)
        user["login"] = "another-actor"
        with self.assertRaisesRegex(attestation.AttestationError, "author login"):
            attestation.validate_event(event)

    def test_unchecked_declaration_is_refused(self) -> None:
        body = valid_attestation_body().replace(
            "- [x] I reviewed", "- [ ] I reviewed", 1
        )
        with self.assertRaisesRegex(attestation.AttestationError, "unchecked"):
            attestation.validate_event(pull_request_event(body))

    def test_duplicate_block_is_refused(self) -> None:
        body = f"{valid_attestation_body()}\n{valid_attestation_body()}"
        with self.assertRaisesRegex(attestation.AttestationError, "exactly one"):
            attestation.validate_event(pull_request_event(body))


class AppendOnlyTests(unittest.TestCase):
    def test_schema_and_record_modification_is_refused(self) -> None:
        problems = append_only.violations(
            [
                ("M", "schemas/registration-receipt.v1.schema.json"),
                ("D", "records/registrations/x/statement.json"),
            ]
        )
        self.assertEqual(len(problems), 2)

    def test_additions_are_permitted_by_diff_guard(self) -> None:
        self.assertEqual(
            append_only.violations(
                [
                    ("A", "schemas/registration-receipt.v2.schema.json"),
                    ("A", "records/registrations/x/statement.json"),
                ]
            ),
            [],
        )


class GitSourceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git("init", "--quiet")
        self.write("README.md", "Public engineering fixture.\n")
        state = (ROOT / "policy/authorization-state.json").read_text()
        self.write("policy/authorization-state.json", state)
        self.write(".gitignore", ".venv/\n.cache/\nprivate/\n")
        self.git("add", "README.md", "policy/authorization-state.json", ".gitignore")

    def git(self, *arguments: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout

    def write(self, name: str, content: str = "public text\n") -> Path:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def validate(self) -> list[str]:
        with (
            mock.patch.object(validator, "ROOT", self.repo),
            mock.patch.object(
                validator,
                "REQUIRED_FILES",
                {"README.md", "policy/authorization-state.json"},
            ),
        ):
            return validator.validate_repository()

    def assert_refused_without_read(self) -> None:
        with mock.patch.object(
            Path, "read_text", side_effect=AssertionError("content read")
        ) as read:
            self.assertTrue(self.validate())
        read.assert_not_called()

    def test_clean_fixture_and_legitimate_similar_names_pass(self) -> None:
        self.write("private-notes.md")
        self.write("notprivate/example.md")
        self.write("private")
        self.assertEqual(self.validate(), [])

    def test_tracked_and_nonignored_new_public_markers_are_checked(self) -> None:
        for marker in validator.GENERIC_PUBLIC_BOUNDARY_MARKERS:
            for tracked in (False, True):
                with self.subTest(marker=marker, tracked=tracked):
                    self.write("boundary.md", marker)
                    if tracked:
                        self.git("add", "boundary.md")
                    self.assertTrue(
                        any(
                            "public-boundary marker" in error
                            for error in self.validate()
                        )
                    )

    def test_every_existing_workflow_marker_is_preserved(self) -> None:
        for marker in validator.FORBIDDEN_WORKFLOW_MARKERS:
            with self.subTest(marker=marker):
                self.write(".github/workflows/probe.yml", marker)
                self.assertTrue(
                    any(
                        "workflow activation marker" in error
                        for error in self.validate()
                    )
                )

    def test_spaces_newline_and_duplicate_nul_entries_remain_whole(self) -> None:
        name = "engineering notes\nsecond line.md"
        self.write(name)
        self.git("add", name)
        with mock.patch.object(validator, "ROOT", self.repo):
            actual = validator._tracked_source_files()
            self.assertIn(self.repo / name, actual)
            repeated = (name.encode() + b"\0") * 2
            result = subprocess.CompletedProcess([], 0, repeated, b"")
            with mock.patch.object(validator.subprocess, "run", return_value=result):
                self.assertEqual(validator._tracked_source_files(), [self.repo / name])

    def test_ignored_tool_cache_is_not_opened_but_tracked_cache_is_checked(
        self,
    ) -> None:
        guarded = {
            self.write(".venv/poison.md", validator.GENERIC_PUBLIC_BOUNDARY_MARKERS[0]),
            self.write(
                ".cache/poison.md", validator.GENERIC_PUBLIC_BOUNDARY_MARKERS[0]
            ),
        }
        original = Path.read_text

        def read(path, *args, **kwargs):
            if path in guarded:
                raise AssertionError("ignored tool content opened")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", read):
            self.assertEqual(self.validate(), [])
        self.git("add", "--force", ".cache/poison.md")
        self.assertTrue(
            any("public-boundary marker" in error for error in self.validate())
        )

    def test_private_paths_refuse_before_any_read(self) -> None:
        for index, name in enumerate(("private/x", "nested/PRIVATE/x", "Private/x")):
            with self.subTest(name=name):
                prefix = f"case-{index}/"
                self.write(prefix + name)
                self.git("add", "--force", prefix + name)
                self.assert_refused_without_read()
                self.git("rm", "--cached", "--force", prefix + name)
                (self.repo / (prefix + name)).unlink()

    def test_untracked_nonignored_mixed_case_private_refuses(self) -> None:
        self.git("config", "core.ignorecase", "false")
        self.write("nested/PrIvAtE/x")
        self.assert_refused_without_read()

    def test_forbidden_roots_refuse_when_empty_ignored_or_symlinked(self) -> None:
        for prefix in validator.FORBIDDEN_D2_PREFIXES:
            root = self.repo / prefix.removesuffix("/")
            with self.subTest(prefix=prefix, kind="ignored empty directory"):
                with (self.repo / ".gitignore").open("a") as handle:
                    handle.write(prefix + "\n")
                root.mkdir()
                self.assert_refused_without_read()
                root.rmdir()
            with self.subTest(prefix=prefix, kind="regular file"):
                root.write_text("generic engineering placeholder")
                self.assert_refused_without_read()
                root.unlink()
            with self.subTest(prefix=prefix, kind="dangling symlink"):
                root.symlink_to(self.repo / "absent")
                self.assert_refused_without_read()
                root.unlink()

    def test_leaf_and_ancestor_symlinks_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.md"
            target.write_text("generic engineering text")
            link = self.repo / "link.md"
            link.symlink_to(target)
            self.assert_refused_without_read()
            link.unlink()
            tracked = self.write("docs/example.md")
            self.git("add", "docs/example.md")
            tracked.unlink()
            tracked.parent.rmdir()
            tracked.parent.symlink_to(Path(outside), target_is_directory=True)
            self.assert_refused_without_read()

    def test_missing_tracked_and_nonregular_files_refuse(self) -> None:
        tracked = self.write("tracked.md")
        self.git("add", "tracked.md")
        tracked.unlink()
        self.assert_refused_without_read()
        tracked.mkdir()
        self.assert_refused_without_read()
        tracked.rmdir()
        os.mkfifo(tracked)
        self.assert_refused_without_read()

    def test_git_error_malformed_or_unsafe_names_refuse_without_content(self) -> None:
        results = [
            subprocess.CompletedProcess([], 2, b"", b"not-for-output"),
            subprocess.CompletedProcess([], 0, b"truncated", b""),
            subprocess.CompletedProcess([], 0, b"../outside\0", b""),
            subprocess.CompletedProcess([], 0, b"/absolute\0", b""),
            subprocess.CompletedProcess([], 0, b"a//b\0", b""),
        ]
        for result in results:
            with (
                self.subTest(output=result.stdout),
                mock.patch.object(validator.subprocess, "run", return_value=result),
            ):
                self.assert_refused_without_read()
        with mock.patch.object(validator.subprocess, "run", side_effect=OSError):
            self.assert_refused_without_read()

    def test_authorization_file_has_no_independent_read_fallback(self) -> None:
        state = self.repo / "policy/authorization-state.json"
        state.unlink()
        self.assert_refused_without_read()
        state.symlink_to(self.repo / "README.md")
        self.assert_refused_without_read()

    def test_invalid_json_diagnostic_does_not_repeat_input(self) -> None:
        self.write("sample.json", '{"not-for-output":1,"not-for-output":2}')
        errors = self.validate()
        self.assertTrue(errors)
        self.assertNotIn("not-for-output", "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
