"""Offline binding and refusal tests: no Git reader, gate, audit or network."""

import argparse
import copy
import hashlib
import importlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "project_manifest_binding_under_test", ROOT / "scripts/check_project_manifest.py"
)
BINDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BINDING)


@contextmanager
def released(root=ROOT):
    loader, diagnostics = BINDING.captured_release(root)
    with loader.installed():
        validation = importlib.import_module(BINDING.PREFIX + ".validation")
        yield validation, diagnostics


class ManifestBindingTests(unittest.TestCase):
    def temporary_root(self, *, vendor=False):
        temporary = tempfile.TemporaryDirectory(prefix="manifest-binding-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        if vendor:
            shutil.copytree(ROOT / "vendor", root / "vendor")
        return root

    def record(self):
        with released() as (api, _):
            tree = api.TreeSnapshot((api.TreeEntry(BINDING.STATUS_FILE, "file"),))
            declaration = (ROOT / "project.yaml").read_bytes()
            parsed = api.check_candidate(declaration)
            self.assertEqual(parsed.exit_code, 0)
            result = api.check_declaration(
                declaration,
                tree=tree,
                reference_date=parsed.record["status"]["as_of"],
            )
            self.assertEqual(result.exit_code, 0, result.diagnostics())
            self.assertEqual(
                result.diagnostics()["complete_v1_validity"], "not_checked"
            )
            return copy.deepcopy(result.record)

    def native_copy(self):
        root = self.temporary_root()
        for relative in (".mise.toml", BINDING.STATUS_FILE, BINDING.GATE_FILE):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        return root

    def test_current_declaration_and_separate_native_source_bytes(self):
        assessment, observation = BINDING.native_assessment(self.record(), "worktree")
        self.assertEqual(assessment, "matched")
        self.assertEqual(observation["scope"], "current-worktree-source-only")
        self.assertEqual(
            observation["sha256"],
            {
                name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in (".mise.toml", BINDING.STATUS_FILE, BINDING.GATE_FILE)
            },
        )

    def test_incomplete_or_redirected_authority_tree_refused(self):
        with released() as (api, _):
            for tree in (
                api.TreeSnapshot(()),
                api.TreeSnapshot((api.TreeEntry(BINDING.STATUS_FILE, "symlink"),)),
                api.TreeSnapshot((api.TreeEntry(BINDING.STATUS_FILE, "file"),), False),
            ):
                with self.subTest(tree=tree):
                    result = api.check_declaration(
                        (ROOT / "project.yaml").read_bytes(),
                        tree=tree,
                        reference_date="2026-10-17",
                    )
                    self.assertNotEqual(result.exit_code, 0)

    def test_full_shape_rejects_missing_and_unknown_fields(self):
        data = (ROOT / "project.yaml").read_bytes()
        with released() as (api, _):
            tree = api.TreeSnapshot((api.TreeEntry(BINDING.STATUS_FILE, "file"),))
            for invalid in (
                data.replace(b'spec_version: "1"\n', b""),
                data + b"unknown_field: null\n",
                b"name: legacy-shape\n",
                data.replace(b"  host_requirements: []\n", b""),
            ):
                with self.subTest(data=invalid[:30]):
                    self.assertNotEqual(
                        api.check_declaration(
                            invalid, tree=tree, reference_date="2026-10-17"
                        ).exit_code,
                        0,
                    )

    def test_owner_invariants_reject_plausible_but_wrong_commands_and_claims(self):
        record = self.record()
        changes = (
            ("project", "id", "another-public-project"),
            ("status", "operational_state", "active"),
            ("authority", "status_of_record", "OTHER.md"),
            ("development", "platforms", ["linux"]),
        )
        for section, key, value in changes:
            changed = copy.deepcopy(record)
            changed[section][key] = value
            with self.subTest(key=key), self.assertRaises(BINDING.Refusal):
                BINDING.native_declaration(changed)
        record["development"]["commands"]["check"]["target"] = "different-check"
        with self.assertRaises(BINDING.Refusal):
            BINDING.native_declaration(record)

    def test_status_authority_and_mirror_can_advance_without_validator_edit(self):
        root, record = self.native_copy(), self.record()
        authority = root / BINDING.STATUS_FILE
        old_line = (
            f"Interface source phase ({record['status']['as_of']}): "
            f"{record['status']['local_phase']}."
        )
        record["status"].update(as_of="2026-10-18", local_phase="New source-only phase")
        authority.write_text(
            authority.read_text().replace(
                old_line, "Interface source phase (2026-10-18): New source-only phase."
            )
        )
        self.assertEqual(
            BINDING.native_assessment(record, "worktree", root)[0], "matched"
        )
        authority.write_text(authority.read_text() + "\n" + old_line + "\n")
        with self.assertRaises(BINDING.Refusal) as caught:
            BINDING.native_assessment(record, "worktree", root)
        self.assertEqual(caught.exception.code, "STATUS_DRIFT")

    def test_selected_modes_do_not_read_or_qualify_different_working_configuration(
        self,
    ):
        root, record = self.native_copy(), self.record()
        (root / ".mise.toml").write_text('[tasks.check]\nrun = "different-command"\n')
        for mode in ("staged", "rev"):
            with (
                self.subTest(mode=mode),
                patch.object(
                    BINDING,
                    "read_regular",
                    side_effect=AssertionError("working bytes read"),
                ),
            ):
                self.assertEqual(
                    BINDING.native_assessment(record, mode, root), ("not_checked", None)
                )
        with self.assertRaises((BINDING.Refusal, KeyError)):
            BINDING.native_assessment(record, "worktree", root)

    def test_native_source_readback_refuses_drift(self):
        root, record = self.native_copy(), self.record()
        original = BINDING.read_regular
        reads = 0

        def changed(path, maximum=1_048_576):
            nonlocal reads
            reads += 1
            value = original(path, maximum)
            return value + b"\n" if reads > 3 else value

        with (
            patch.object(BINDING, "read_regular", side_effect=changed),
            self.assertRaises(BINDING.Refusal) as caught,
        ):
            BINDING.native_assessment(record, "worktree", root)
        self.assertEqual(caught.exception.code, "NATIVE_SOURCE_CHANGED")

    def test_auto_install_guards_refuse_each_individual_relaxation(self):
        record = self.record()
        for setting in ("auto_install", "exec_auto_install", "task.run_auto_install"):
            root = self.native_copy()
            path = root / ".mise.toml"
            text = path.read_text()
            lines = text.splitlines(keepends=True)
            path.write_text(
                "".join(
                    line.replace("false", "true")
                    if line.startswith(setting + " = ")
                    else line
                    for line in lines
                )
            )
            with (
                self.subTest(setting=setting),
                self.assertRaises(BINDING.Refusal) as caught,
            ):
                BINDING.native_assessment(record, "worktree", root)
            self.assertEqual(caught.exception.code, "NATIVE_TASK")

    def test_release_has_22_authenticated_leaves_and_only_library_imports(self):
        loader, diagnostics = BINDING.captured_release()
        self.assertIsInstance(diagnostics, dict)
        vendor = ROOT / "vendor/project-manifest"
        leaves = [p for p in (vendor / "release-1").rglob("*") if p.is_file()]
        self.assertEqual(len(leaves) + 1, 22)
        self.assertEqual(len(loader.sources), 4)
        with loader.installed():
            importlib.import_module(BINDING.PREFIX + ".acquire")
            for denied in ("cli", "__main__", "unexpected"):
                with self.subTest(module=denied), self.assertRaises(BINDING.Refusal):
                    importlib.import_module(BINDING.PREFIX + "." + denied)
        self.assertFalse(any(name.startswith(BINDING.PREFIX) for name in sys.modules))

    def test_untrusted_bootstrap_is_rejected_before_execution(self):
        root = self.temporary_root(vendor=True)
        (root / "vendor/project-manifest/bootstrap/release_verifier.py").write_text(
            "raise AssertionError('untrusted bootstrap executed')\n"
        )
        with self.assertRaises(BINDING.Refusal) as caught:
            BINDING.captured_release(root)
        self.assertEqual(caught.exception.code, "BOOTSTRAP_BINDING")

    def test_release_descriptor_payload_extra_and_missing_file_refusals(self):
        for kind in ("descriptor", "payload", "extra", "missing"):
            with self.subTest(kind=kind):
                root = self.temporary_root(vendor=True)
                release = root / "vendor/project-manifest/release-1"
                if kind == "descriptor":
                    path = release / "release.json"
                    path.write_bytes(path.read_bytes() + b"\n")
                elif kind == "payload":
                    path = release / "src/project_manifest/candidate.py"
                    path.write_bytes(path.read_bytes() + b"\n")
                elif kind == "extra":
                    (release / "unexpected.py").write_text("pass\n")
                else:
                    (release / "src/project_manifest/cli.py").unlink()
                with self.assertRaises(BINDING.Refusal):
                    BINDING.captured_release(root)

    def test_symlink_and_hardlink_bootstrap_refused(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                root = self.temporary_root(vendor=True)
                path = root / "vendor/project-manifest/bootstrap/release_verifier.py"
                original = root / "original.py"
                path.rename(original)
                if kind == "symlink":
                    path.symlink_to(original)
                else:
                    os.link(original, path)
                with self.assertRaises((BINDING.Refusal, OSError)):
                    BINDING.captured_release(root)

    def test_runtime_import_uses_captured_bytes_after_filesystem_changes(self):
        root = self.temporary_root(vendor=True)
        loader, _ = BINDING.captured_release(root)
        path = (
            root / "vendor/project-manifest/release-1/src/project_manifest/candidate.py"
        )
        path.write_text("raise AssertionError('later filesystem bytes executed')\n")
        with loader.installed():
            api = importlib.import_module(BINDING.PREFIX + ".candidate")
            self.assertEqual(
                api.check_candidate((ROOT / "project.yaml").read_bytes()).exit_code, 0
            )

    def test_ambient_library_module_refused_and_not_removed(self):
        loader, _ = BINDING.captured_release()
        sentinel = types.ModuleType(BINDING.PREFIX)
        with patch.dict(sys.modules, {BINDING.PREFIX: sentinel}):
            with self.assertRaises(BINDING.Refusal), loader.installed():
                self.fail("ambient module accepted")
            self.assertIs(sys.modules[BINDING.PREFIX], sentinel)

    def test_observation_is_called_once_and_diagnostics_are_not_reconstructed(self):
        sentinel = types.SimpleNamespace(diagnostics={"released": object()})
        api = types.SimpleNamespace(
            observe_released_repository=lambda *a, **k: sentinel
        )
        request = {
            "mode": "staged",
            "rev": None,
            "reference_date": "2026-10-17",
            "common_dir": "/explicit/authority",
        }
        with patch.object(
            api, "observe_released_repository", wraps=api.observe_released_repository
        ) as call:
            result = BINDING.observe_once(api, ROOT, request)
        call.assert_called_once_with(str(ROOT), **request)
        self.assertIs(result, sentinel)
        self.assertIs(result.diagnostics, sentinel.diagnostics)

    def test_cli_envelope_preserves_nested_diagnostics_and_selected_scope(self):
        diagnostics = {
            "scope": "synthetic-released-observation",
            "complete_v1_validity": "not_checked",
            "opaque_nested_field": {
                "exit_code": 0,
                "remaining": ["native_conformance"],
            },
        }
        observation = types.SimpleNamespace(
            exit_code=0, record=self.record(), diagnostics=diagnostics
        )
        stdout = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(BINDING, "select_git"),
            patch.object(BINDING, "observe_once", return_value=observation) as observe,
            redirect_stdout(stdout),
        ):
            code = BINDING.main(["--mode", "staged", "--reference-date", "2026-10-17"])
        self.assertEqual(code, 0)
        observe.assert_called_once()
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["observation"], diagnostics)
        self.assertEqual(report["native_source_contract"], "not_checked")
        self.assertIsNone(report["native_source_observation"])
        self.assertEqual(report["runtime_acceptance"], "not_checked")
        self.assertEqual(report["publication_acceptance"], "not_checked")

    def test_ci_observation_binds_full_event_revision(self):
        revision = "a" * 40
        args = argparse.Namespace(
            mode=None, rev=None, reference_date="2026-10-17", git_common_dir=None
        )
        env = {"GITHUB_ACTIONS": "true", "GITHUB_SHA": revision}
        request = BINDING.observation_request(args, env)
        self.assertEqual((request["mode"], request["rev"]), ("rev", revision))
        for mode, rev in (
            ("staged", None),
            ("worktree", None),
            ("rev", "b" * 40),
            ("rev", "HEAD"),
        ):
            args.mode, args.rev = mode, rev
            with self.subTest(mode=mode, rev=rev), self.assertRaises(BINDING.Refusal):
                BINDING.observation_request(args, env)

    def test_explicit_common_directory_and_reference_date_are_preserved(self):
        args = argparse.Namespace(
            mode="staged",
            rev=None,
            reference_date="2026-10-17",
            git_common_dir="/explicit/authority",
        )
        self.assertEqual(
            BINDING.observation_request(args, {}),
            {
                "mode": "staged",
                "rev": None,
                "reference_date": "2026-10-17",
                "common_dir": "/explicit/authority",
            },
        )

    def test_native_git_rejects_script_shims_without_executing_them(self):
        path = self.temporary_root() / "git"
        path.write_text("#!/bin/sh\nexit 99\n")
        path.chmod(0o700)
        with self.assertRaises(BINDING.Refusal) as caught:
            BINDING.select_git(str(path))
        self.assertEqual(caught.exception.code, "NATIVE_GIT")


class PreparationSourceTests(unittest.TestCase):
    """The setup helper is imported only; no download/build/setup is performed."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "manifest_preparation_under_test", ROOT / "scripts/prepare_manifest_git.py"
        )
        self.preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.preparation)

    def test_non_ci_host_refused_before_download(self):
        with (
            patch.object(
                self.preparation.platform, "system", return_value="Unsupported"
            ),
            patch.object(self.preparation, "urlopen") as download,
            self.assertRaises(ValueError),
        ):
            self.preparation.main()
        download.assert_not_called()

    def test_owned_group_is_cleaned_after_success_failure_and_timeout(self):
        for result in (0, 1, None):
            with self.subTest(result=result):
                child = types.SimpleNamespace(
                    pid=123456, poll=lambda result=result: result, wait=lambda **kw: 0
                )
                saved = object()
                with (
                    patch.object(
                        self.preparation.signal, "signal", return_value=saved
                    ) as handlers,
                    patch.object(
                        self.preparation.subprocess, "Popen", return_value=child
                    ) as spawn,
                    patch.object(self.preparation.os, "killpg") as terminate,
                ):
                    if result == 0:
                        self.preparation.run_owned(["synthetic-no-execution"], ROOT, 0)
                    else:
                        with self.assertRaises(ValueError):
                            self.preparation.run_owned(
                                ["synthetic-no-execution"], ROOT, 0
                            )
                spawn.assert_called_once_with(
                    ["synthetic-no-execution"], cwd=ROOT, start_new_session=True
                )
                terminate.assert_called_once_with(
                    child.pid, self.preparation.signal.SIGKILL
                )
                self.assertEqual(handlers.call_count, 6)
                self.assertTrue(
                    all(call.args[1] is saved for call in handlers.call_args_list[-3:])
                )

    def test_spawn_failure_restores_signal_handlers(self):
        saved = object()
        with (
            patch.object(
                self.preparation.signal, "signal", return_value=saved
            ) as handlers,
            patch.object(
                self.preparation.subprocess, "Popen", side_effect=OSError("synthetic")
            ),
            patch.object(self.preparation.os, "killpg") as terminate,
            self.assertRaises(OSError),
        ):
            self.preparation.run_owned(["synthetic-no-execution"], ROOT, 0)
        terminate.assert_not_called()
        self.assertEqual(handlers.call_count, 6)

    def test_signal_during_spawn_is_deferred_until_group_is_registered(self):
        handlers = {}
        child = types.SimpleNamespace(pid=123456, poll=lambda: 0, wait=lambda **kw: 0)

        def install(number, handler):
            handlers[number] = handler

        def spawn(*args, **kwargs):
            handlers[self.preparation.signal.SIGTERM](
                self.preparation.signal.SIGTERM, None
            )
            return child

        with (
            patch.object(self.preparation.signal, "signal", side_effect=install),
            patch.object(self.preparation.subprocess, "Popen", side_effect=spawn),
            patch.object(self.preparation.os, "killpg") as terminate,
            self.assertRaises(ValueError),
        ):
            self.preparation.run_owned(["synthetic-no-execution"], ROOT, 0)
        terminate.assert_called_once_with(child.pid, self.preparation.signal.SIGKILL)

    def test_cleanup_errors_still_reap_and_restore_signal_handlers(self):
        for fail_kill in (True, False):
            with self.subTest(fail_kill=fail_kill):
                waits = []
                saved = object()

                def wait(*, waits=waits, fail_kill=fail_kill, **kwargs):
                    waits.append(kwargs)
                    if not fail_kill:
                        raise self.preparation.subprocess.TimeoutExpired("synthetic", 2)
                    return 0

                child = types.SimpleNamespace(pid=123456, poll=lambda: 0, wait=wait)
                with (
                    patch.object(
                        self.preparation.signal, "signal", return_value=saved
                    ) as handlers,
                    patch.object(
                        self.preparation.subprocess, "Popen", return_value=child
                    ),
                    patch.object(
                        self.preparation.os,
                        "killpg",
                        side_effect=OSError("synthetic") if fail_kill else None,
                    ),
                    self.assertRaises(
                        (OSError, self.preparation.subprocess.TimeoutExpired)
                    ),
                ):
                    self.preparation.run_owned(["synthetic-no-execution"], ROOT, 0)
                self.assertEqual(waits, [{"timeout": 2}])
                self.assertEqual(handlers.call_count, 6)
                self.assertTrue(
                    all(call.args[1] is saved for call in handlers.call_args_list[-3:])
                )


if __name__ == "__main__":
    unittest.main()
