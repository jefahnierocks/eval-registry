# Project Manifest Release 1 binding

This repository independently vendors the public MIT release from
`jefahnierocks/project-manifest`. The repo-owned
`../../scripts/check_project_manifest.py` adapter pins the reviewed bootstrap,
release-table digest and source revision; no shared installed reader is used.

- Source revision: `56e3920089726e585eaa0fd7f4dc94e6938a1e0c`
- Bootstrap SHA-256: `2ccf58e0da97bbbd9dae173d1cca047d465c4a2d950ee6e56052309a9689cf4f`
- Domain-separated table SHA-256: `f7ff9dd0972af5d3a6a3348c3e092de1a6acd97fa3975e13e522cf80ce5e7df2`
- Released format: `project-manifest-release-1`
- Observation protocol: `project-manifest-git-observation-1`

The 22 immutable vendor leaves are the independently authenticated bootstrap,
release descriptor and 20 payload files. `release-1/LICENSE` is the upstream MIT
license. This README is repository-owned guidance outside that closed payload.
Never reformat or patch the pinned bytes. A different release needs fresh review.
The Python library import closure excludes the authenticated CLI modules.

This is an interface source candidate. Byte binding, declaration checks, native
command acceptance, public host binding, scientific authority, hosted checks and
publication are separate. No command discovered in a declaration is executed.
Prepared Python 3.13.15 and native Git at least 2.56 are required; checks never
install or repair them. Linked worktrees require explicit common-directory
permission supplied at invocation, never a machine-specific path in source.
