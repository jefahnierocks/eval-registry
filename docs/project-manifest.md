# Specification 1 source candidate

`project.yaml` declares source ownership and one native `mise run check` alias.
It is not host admission, signer authority, record-publication approval or a baseline
upgrade. The existing producer-approved public-safe host binding remains open.

The dated `Interface source phase (DATE): ...` line in `README.md` owns the short
phase/date summary. Mirror those two values in `project.yaml`; do not turn the
validator into another status authority. Detailed historical findings stay in
the status document. Empty platform and host-requirement lists establish no
portability claim. The operational state is deliberately `unknown`.

## Independent binding

The repository owns its independent 22-file Release 1 copy. The adapter first
hashes the separately pinned bootstrap, then authenticates the release descriptor
and every payload leaf. It captures and re-hashes the four allowed library
modules before importing from memory. The release CLI and `__main__` are never
imported. The upstream MIT license and unchanged documentation are retained.
Repository-owned guidance lives outside the closed release directory.

The adapter performs exactly one released Git observation, with an explicit UTC
reference date. It preserves released diagnostics unchanged under `observation`.
The outer report keeps binding, native-source evidence, producer admission,
runtime acceptance and publication acceptance separate. Exit zero is not complete
Specification 1 validity or operational acceptance.

With already prepared Python 3.13.15 and native Git at least 2.56.0:

```sh
python3 -I -S -B scripts/check_project_manifest.py --reference-date 2026-10-17
python3 -I -S -B scripts/check_project_manifest.py --mode staged --reference-date 2026-10-17
python3 -I -S -B scripts/check_project_manifest.py --mode rev --rev FULL_OBJECT_ID --reference-date 2026-10-17
```

Choose the actual reference date explicitly. `--git` (or `PROJECT_MANIFEST_GIT`)
selects an already prepared native binary, not a mise or shell shim. Linked
worktrees additionally require owner-supplied `--git-common-dir` (or
`PROJECT_MANIFEST_COMMON_DIR`) authority. The reader does not derive that
permission from the `.git` pointer. Unsupported storage, ambient Git overrides,
intent-to-add entries and missing tools are refusals, not setup requests.

Worktree mode separately hashes `.mise.toml`, `README.md` and the canonical gate
and checks their current source contract. This is not part of the released Git
snapshot. Staged and revision modes leave `native_source_contract` as
`not_checked`; they never substitute working bytes for selected bytes. The full
native gate, source custody and independent review must bind the intended source
separately. CI selects the exact `GITHUB_SHA` revision and retains this distinction.
Untracked files are outside released Git acquisition until intentionally staged.

## Preparation and qualification

Source checks have all three project-local mise automatic-install settings
disabled, plus `MISE_EXEC_AUTO_INSTALL=0`. They do not trust mise configuration,
download Git, sync dependencies or install pip-audit. Setup is a separate reviewed
operation; preserve Python 3.13.15, uv 0.13.0, Gitleaks 8.30.1 and hash-locked
Ruff 0.16.7. Use this candidate's own environment, never another checkout's
virtual environment. After preparation is authorized:

```sh
uv venv --python 3.13.15 .venv
uv pip sync --python .venv/bin/python --require-hashes requirements-dev.txt
```

CI prepares Git 2.56.0 in a unique runner-owned prefix using
`scripts/prepare_manifest_git.py`. That explicit Linux x86_64 preparation verifies
the fixed official HTTPS-published tarball SHA-256, bounds extraction/builds and
does not replace runner Git. It does not claim tar-signature verification.
Checkout does not persist credentials. The source workflow covers all pushes
and pull requests; exact-head maintainer attestation and append-only history
checks remain required on pull requests. No publication workflow is introduced.

Qualification sequence: review source and preparation; prepare exact tools;
format/lint with locked Ruff; run focused refusal tests; intentionally stage only
reviewed source; observe working and index state; run the complete canonical
offline gate including native security, policy validation, tests and lint;
independently review; create the candidate commit;
qualify that exact head locally and in hosted CI before any merge/publication.
Existing signing, hook, security, attestation and human gates are not bypassed.
The D2 authorization state stays authoritative; signer, external-authority and
record-publication lanes remain closed.
None of those later acceptance lanes follows from the offline binding tests.
