# Eval Registry

Eval Registry is a public commitment-plane repository for discoverable, append-only evaluation
registration records. It is intentionally separate from evaluation execution, model serving,
deployment lifecycle, evidence analysis, and trace storage.

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

```sh
python3 scripts/validate_repository.py
python3 -m unittest discover -s tests -v
```

No command above contacts an external service.

## Ownership and license

The canonical repository is [jefahnierocks/eval-registry](https://github.com/jefahnierocks/eval-registry).
Source is licensed under [Apache-2.0](LICENSE). Organization ownership and licensing
do not open signer, external-authority, or record-publication permissions; the
authorization-state contract remains authoritative.
