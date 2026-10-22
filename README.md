# Eval Registry

Interface source phase (2026-10-17): D2 public scaffold; Specification 1 source candidate; signer, external authority and record publication remain closed.

This interface candidate is not qualified or published. Existing source, host-binding,
scientific and operational holds remain in force. Empty platform declarations make
no portability claim; the operational-state field makes no live-state assertion.

Eval Registry is a public commitment-plane repository for discoverable, append-only evaluation
registration records. It is intentionally separate from evaluation execution, model serving,
deployment lifecycle, evidence analysis, and trace storage.

## Source status

As of 2026-10-14, source defines provisional **Governed** adoption of the
Jefahnierocks child-repo baseline 0.1.0, an exact helper toolchain and one offline
validation gate. The remaining baseline gap is a producer-approved public-safe
host-contract binding. No private producer identity or policy copy is published.
This source status does not claim remote CI success, deployment, credentials,
external authority admission or record publication.

## Current authorization state

As of 2026-09-14, only the D2 scaffold is authorized and present:

- the public repository and its charter;
- versioned record schemas;
- a fail-closed verification policy;
- an append-only review policy and validation-only CI; and
- default-branch protection.

The 2026-09-14 maintenance pass revalidated the unchanged authorization state, repository structure, and all 17 policy tests. It added no record, signer, trust, or publication authority.

The repository is **not operational**. No signer identity, issuer, trust roots, timestamp authority,
or transparency-log endpoint has been selected or configured. No registration receipt,
disposition, incident record, or recovery record may be added. Those actions require later,
separate authorization.

The machine-readable state is [policy/authorization-state.json](policy/authorization-state.json),
currently `eval-registry.authorization-state.v2`. Its version history and compatibility rule are in
[docs/authorization-state-versioning.md](docs/authorization-state-versioning.md).

## Review posture

The repository has one eligible maintainer. Pull requests remain mandatory, but GitHub cannot
count an author's approval of their own pull request. The accepted temporary review mode is
`solo_maintainer_attestation_v1`: the author reviews the final diff and records an attestation
bound to the exact pull-request head SHA. CI refuses a missing, malformed, unchecked, or stale
attestation. This is transparent self-review, **not independent approval**.

Signed commits, required validation, resolved discussions, linear history, blocked deletion and
force pushes, and a no-bypass default-branch ruleset remain mandatory. The initial D2 bootstrap
predates this pull-request workflow and is recorded as a one-time historical exception.

The temporary mode will be replaced after a separately accepted agent-identity submission and
approval system can prove actor and credential separation. See
[docs/agent-identity-approval-roadmap.md](docs/agent-identity-approval-roadmap.md). That future
work does not open D3 or D4.

## Proof boundary

Git is a reviewable discovery index, not a precedence authority. A future registration package is
valid only when an independent verifier checks all of the following from exact bytes:

1. the signature over the exact statement bytes;
2. the pinned signer identity, issuer, and trust policy;
3. an RFC 3161 timestamp whose message imprint binds the exact signature bytes;
4. transparency-log inclusion against a pinned signed checkpoint; and
5. the package digests and schema constraints.

The verified RFC 3161 time is the sole precedence anchor. Git timestamps, caller-supplied times,
transparency-log integration times, and a package's own `verification_result` are never trust
inputs.

Even a valid future receipt is a self-binding control. It can prove that committed bytes existed
no later than an externally verified time; it cannot prove that no earlier unregistered work or
abandoned attempt existed.

## Public-content boundary

This repository may contain schemas, public verification policy, opaque identifiers, hiding
commitments, and future authorized signed bundles. It must never contain private plans, commitment
nonces, assignment schedules, outcomes, model responses, promotion decisions, secret material,
sensitive system identities, or private workspace/repository names.

## Layout

- `schemas/` — versioned signed-record, authorization-state, and verifier-output schemas;
  published versions are immutable.
- `policy/` — machine-readable authorization posture.
- `docs/` — architecture, verification, and append-only review contracts.
- `scripts/` — standard-library-only structural and diff validators.
- `.github/` — validation-only CI and review metadata; no signing workflow exists.

Record, bundle, and trust-policy directories are deliberately absent while the repository is in
`d2_scaffold` state.

## Validate locally

Review `.mise.toml`, then use its exact Python, uv and Gitleaks versions.
Installing tools outside this checkout is owner-only. The following dependency
setup downloads only the reviewed, hash-locked helper package into local caches:

```sh
export UV_CACHE_DIR="$PWD/.cache/uv"
uv venv --python 3.13.15 .venv
uv pip sync --python .venv/bin/python --require-hashes requirements-dev.txt
export PATH="$PWD/.venv/bin:$PATH"
bash scripts/run-validation.sh
```

The pinned Gitleaks executable must also be on PATH. Missing or wrong versions
fail closed. The canonical gate checks the agent contract, public/D2 source
boundary, policy tests, formatting, all reachable Git history, and staged and
unstaged source independently. It makes no external-service or credential calls.
The native detector test uses an inert constructed token in a temporary directory.
No record, trust or publication fixture is added to this repository.

Git-listed source includes nonignored new files; ignored tool caches and private
content are not traversed. Tracked cache files remain subject to validation.
Stage exact intended new source before the final secret scan. Local scanner
configuration, ignore lists, inline detector allowances and ambient scanner
configuration cannot weaken the gate. Full Git history is required.

For an intentional helper-dependency update, regenerate the lock with pinned uv:

```sh
uv pip compile --python 3.13.15 --python-version 3.13.15 --universal --generate-hashes requirements-dev.in --output-file requirements-dev.txt
```

Tool-managed caches are `.venv/`, `.cache/uv/`, `.cache/tools/`, `.ruff_cache/`,
`.pytest_cache/` and `__pycache__/`. Do not inspect ignored working content as
part of validation. See [AGENTS.md](AGENTS.md) for the operating floor.

Credential access, provider/trust setup, publication, repository settings and
external tool installation are owner-only and remain subject to authorization
state. The exact-head human review attestation remains a separate required PR
check after engineering validation. An agent's review never fills that attestation.

## Ownership and license

The canonical repository is [jefahnierocks/eval-registry](https://github.com/jefahnierocks/eval-registry).
Source is licensed under [Apache-2.0](LICENSE). Organization ownership and licensing
do not open signer, external-authority, or record-publication permissions; the
authorization-state contract remains authoritative.

See [Specification 1 source binding and qualification](docs/project-manifest.md)
for the independent release, prepared-tool boundaries and remaining gates.
