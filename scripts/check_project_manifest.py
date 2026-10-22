"""Inspect one declaration through this repository's pinned public Release 1.

The released reader never executes declared commands. Its diagnostics remain
unchanged; this caller reports source conformance separately from acceptance.
"""

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
):
    print('{"exit_code":2,"finding":"ISOLATED_RUNTIME_REQUIRED"}')
    raise SystemExit(2)

import argparse
import hashlib
import importlib.abc
import importlib.util
import json
import os
import re
import shutil
import stat
import types
from contextlib import contextmanager
from pathlib import Path

import tomllib

ROOT = Path(__file__).absolute().parent.parent
PROJECT_ID = "eval-registry"
DISPLAY_NAME = "Evaluation Registry"
STATUS_FILE = "README.md"
GATE_FILE = "scripts/run-validation.sh"
CHECK_TASK = 'export PATH="$PWD/.venv/bin:$PATH"\nbash scripts/run-validation.sh'
APPROVED_RELEASE = {
    "origin": "jefahnierocks/project-manifest",
    "format": "project-manifest-release-1",
    "release_id": "1",
    "source_revision": "56e3920089726e585eaa0fd7f4dc94e6938a1e0c",
    "table_digest": "f7ff9dd0972af5d3a6a3348c3e092de1a6acd97fa3975e13e522cf80ce5e7df2",
    "bootstrap_sha256": "2ccf58e0da97bbbd9dae173d1cca047d465c4a2d950ee6e56052309a9689cf4f",
}
MODULES = ("__init__", "candidate", "validation", "acquire")
PREFIX = "owned_manifest_reference"
EXPECTED_TOOLS = {"python": "3.13.15", "uv": "0.13.0", "gitleaks": "8.30.1"}


class Refusal(Exception):
    def __init__(self, code, exit_code=2):
        self.code = code
        self.exit_code = exit_code


def require(condition, code, exit_code=2):
    if not condition:
        raise Refusal(code, exit_code)


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("ARGUMENTS")


def read_regular(path, maximum=1_048_576):
    """Capture bounded single-link bytes without following any symlink."""
    require(path.is_absolute() and ".." not in path.parts, "FILE_LAYOUT")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        leaf = os.open(
            path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd
        )
        try:
            before = os.fstat(leaf)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size <= maximum,
                "FILE_LAYOUT",
            )
            chunks, total = [], 0
            while chunk := os.read(leaf, min(65536, maximum + 1 - total)):
                total += len(chunk)
                require(total <= maximum, "FILE_BOUND")
                chunks.append(chunk)
            fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )

            def identity(info):
                return tuple(getattr(info, field) for field in fields)

            require(
                identity(before)
                == identity(os.fstat(leaf))
                == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False))
                and total == before.st_size,
                "FILE_CHANGED",
            )
            return b"".join(chunks)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


class CapturedModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """A closed library namespace; neither CLI nor filesystem fallback exists."""

    def __init__(self, sources):
        self.sources = sources

    def find_spec(self, fullname, path=None, target=None):
        if fullname == PREFIX or fullname.startswith(PREFIX + "."):
            require(fullname in self.sources, "MODULE_SET")
            return importlib.util.spec_from_loader(
                fullname, self, is_package=fullname == PREFIX
            )
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = "<approved-public-release/" + module.__name__ + ">"
        exec(  # noqa: S102 - Captured bytes match the authenticated release descriptor.
            compile(self.sources[module.__name__], module.__file__, "exec"),
            module.__dict__,
        )

    @contextmanager
    def installed(self):
        def names():
            return [
                name
                for name in sys.modules
                if name == PREFIX or name.startswith(PREFIX + ".")
            ]

        require(not names(), "AMBIENT_MODULE")
        sys.meta_path.insert(0, self)
        try:
            yield
        finally:
            sys.meta_path.remove(self)
            for name in names():
                del sys.modules[name]


def captured_release(root=ROOT):
    vendor = root / "vendor/project-manifest"
    bootstrap = read_regular(vendor / "bootstrap/release_verifier.py", 32768)
    require(
        hashlib.sha256(bootstrap).hexdigest() == APPROVED_RELEASE["bootstrap_sha256"],
        "BOOTSTRAP_BINDING",
    )
    name = "_owned_manifest_bootstrap"
    require(name not in sys.modules, "AMBIENT_BOOTSTRAP")
    verifier = types.ModuleType(name)
    sys.modules[name] = verifier
    try:
        exec(  # noqa: S102 - Bootstrap SHA-256 matches APPROVED_RELEASE above.
            compile(bootstrap, "<approved-public-bootstrap>", "exec"), verifier.__dict__
        )
        release = vendor / "release-1"
        result = verifier.verify_release(
            str(release),
            expected_digest=APPROVED_RELEASE["table_digest"],
            expected_format=APPROVED_RELEASE["format"],
        )
        require(
            result.exit_code == 0 and result.descriptor is not None, "RELEASE_BINDING"
        )
        descriptor = result.descriptor
        require(
            all(
                descriptor[key] == APPROVED_RELEASE[key]
                for key in ("origin", "format", "release_id", "source_revision")
            )
            and descriptor["observation_protocol"]
            == "project-manifest-git-observation-1",
            "RELEASE_IDENTITY",
        )
        rows = {row["path"]: row for row in descriptor["files"]}
        sources = {}
        for module in MODULES:
            path = "src/project_manifest/" + module + ".py"
            data = read_regular(release / path)
            require(
                len(data) == rows[path]["bytes"]
                and hashlib.sha256(data).hexdigest() == rows[path]["sha256"],
                "CAPTURE_BINDING",
            )
            sources[PREFIX if module == "__init__" else PREFIX + "." + module] = data
        return CapturedModules(sources), result.diagnostics()
    finally:
        del sys.modules[name]


def select_git(explicit):
    selected = explicit or shutil.which("git")
    require(selected is not None and Path(selected).is_absolute(), "NATIVE_GIT")
    path = Path(selected).resolve(strict=True)
    require(
        path.name == "git" and path.is_file() and os.access(path, os.X_OK), "NATIVE_GIT"
    )
    with path.open("rb") as stream:
        magic = stream.read(4)
    require(
        magic
        in (
            b"\x7fELF",
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        ),
        "NATIVE_GIT",
    )
    os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")


def observation_request(args, environment):
    mode = args.mode or "worktree"
    revision = args.rev
    if environment.get("GITHUB_ACTIONS") == "true":
        expected = environment.get("GITHUB_SHA", "")
        require(
            re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected)
            and args.mode in (None, "rev")
            and revision in (None, expected),
            "CI_REVISION",
        )
        mode, revision = "rev", expected
    require(
        (
            mode == "rev"
            and isinstance(revision, str)
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision)
        )
        or (mode != "rev" and revision is None),
        "REVISION",
    )
    return {
        "mode": mode,
        "rev": revision,
        "reference_date": args.reference_date,
        "common_dir": args.git_common_dir,
    }


def native_declaration(record):
    """Compare accepted declaration values with the owner-defined source role."""
    commands = {
        role: None
        for role in (
            "setup",
            "check",
            "test",
            "build",
            "dev",
            "format_check",
            "format_write",
        )
    }
    commands["check"] = {"runner": "mise", "target": "check"}
    require(
        record["project"]
        == {
            "id": PROJECT_ID,
            "display_name": DISPLAY_NAME,
            "owner_entity": "jefahnierocks",
        }
        and record["role"] == "canonical"
        and record["canonical"] is None
        and record["peers"] == []
        and record["authority"] == {"status_of_record": STATUS_FILE}
        and record["presentation"]
        == {
            "visibility": "public-available",
            "public_alias": None,
            "link_policy": "link-ok",
        }
        and record["status"]["posture"] == "public-repo"
        and record["status"]["operational_state"] == "unknown"
        and record["development"]
        == {
            "platforms": [],
            "commands": commands,
            "environment": {"owner": "mise", "template": None, "secret_launcher": None},
            "stacks": {},
            "host_requirements": [],
        },
        "NATIVE_DECLARATION",
        1,
    )


def native_source_contract(record, root=ROOT):
    """Separate current-working-byte check, never revision/index evidence."""
    native_declaration(record)
    source_bytes = {
        path: read_regular(root / path)
        for path in (".mise.toml", STATUS_FILE, GATE_FILE)
    }
    config = tomllib.loads(source_bytes[".mise.toml"].decode("utf-8"))
    settings = config.get("settings", {})
    task = config.get("tasks", {}).get("check", {})
    require(
        config["tools"] == EXPECTED_TOOLS
        and settings.get("auto_install") is False
        and settings.get("exec_auto_install") is False
        and settings.get("task", {}).get("run_auto_install") is False
        and task.get("run") == CHECK_TASK
        and task.get("env") == {"MISE_EXEC_AUTO_INSTALL": "0"},
        "NATIVE_TASK",
        1,
    )
    status = source_bytes[STATUS_FILE].decode("utf-8")
    authority = re.findall(
        r"^Interface source phase \((\d{4}-\d{2}-\d{2})\): ([^\r\n]+)\.$",
        status,
        re.MULTILINE,
    )
    require(
        authority == [(record["status"]["as_of"], record["status"]["local_phase"])],
        "STATUS_DRIFT",
        1,
    )
    gate = source_bytes[GATE_FILE].decode("utf-8")
    require(
        "python3 -I -S -B scripts/check_project_manifest.py --reference-date" in gate,
        "NATIVE_GATE_BINDING",
        1,
    )

    require(
        all(read_regular(root / path) == data for path, data in source_bytes.items()),
        "NATIVE_SOURCE_CHANGED",
    )
    return {
        "scope": "current-worktree-source-only",
        "sha256": {
            path: hashlib.sha256(data).hexdigest()
            for path, data in source_bytes.items()
        },
    }


def native_assessment(record, mode, root=ROOT):
    native_declaration(record)
    if mode != "worktree":
        return "not_checked", None
    return "matched", native_source_contract(record, root)


def observe_once(api, root, request):
    return api.observe_released_repository(str(root), **request)


def main(argv=None):
    report = {
        "scope": PROJECT_ID + "-project-manifest-1",
        "exit_code": 2,
        "approved_release": APPROVED_RELEASE,
        "bytes_verified": False,
        "binding": None,
        "observation": None,
        "native_source_contract": "not_checked",
        "native_source_observation": None,
        "native_conformance": "not_checked",
        "producer_admission": "not_checked",
        "runtime_acceptance": "not_checked",
        "publication_acceptance": "not_checked",
        "findings": [],
    }
    try:
        parser = Arguments(description=__doc__)
        parser.add_argument("--reference-date", required=True)
        parser.add_argument("--mode", choices=("worktree", "staged", "rev"))
        parser.add_argument("--rev")
        parser.add_argument("--git", default=os.environ.get("PROJECT_MANIFEST_GIT"))
        parser.add_argument(
            "--git-common-dir", default=os.environ.get("PROJECT_MANIFEST_COMMON_DIR")
        )
        args = parser.parse_args(argv)
        require(sys.version_info[:3] == (3, 13, 15), "PROJECT_PYTHON_PIN")
        request = observation_request(args, os.environ)
        loader, report["binding"] = captured_release()
        report["bytes_verified"] = True
        select_git(args.git)
        with loader.installed():
            api = __import__(
                PREFIX + ".acquire", fromlist=["observe_released_repository"]
            )
            observed = observe_once(api, ROOT, request)
            report["observation"] = observed.diagnostics
            report["exit_code"] = observed.exit_code
            if observed.exit_code == 0:
                assessment, evidence = native_assessment(
                    observed.record, request["mode"]
                )
                report["native_source_contract"] = assessment
                report["native_source_observation"] = evidence
    except Refusal as error:
        report.update(exit_code=error.exit_code, findings=[error.code])
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        report.update(exit_code=2, findings=["GATE_UNAVAILABLE"])
    print(json.dumps(report, sort_keys=True))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
