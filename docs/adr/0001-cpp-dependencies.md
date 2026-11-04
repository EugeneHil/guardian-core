# ADR-0001: C++ dependencies of guardian-core

> Formerly Warden.

## Status

Accepted (2026-10-21)

## Context

guardian-core is a cross-platform C++17 library. It needs a JSON parser for
policy and configuration at its boundary, and a unit-test framework. CLAUDE.md
forbids new dependencies without an ADR, and builds must be reproducible.

## Decision

- **nlohmann/json `v3.12.0`**: header-only, no system install, and usable
  without exceptions at our boundary (parse with `allow_exceptions = false`
  and check `is_discarded()`). Linked `PRIVATE` by the library targets that
  need it.
- **GoogleTest `v1.17.0`**: test-only. Never linked into `guardian_core`.
- Both are fetched with CMake `FetchContent` from `cmake/Dependencies.cmake`,
  pinned to release tags (`GIT_TAG vX.Y.Z`, `GIT_SHALLOW TRUE`), declared
  `SYSTEM` so third-party warnings do not break our warnings-as-errors policy.
  Branch names and floating tags are not allowed.
- Bump procedure: verify the new tag exists (`git ls-remote --tags <repo>
  <tag>`), change the pin, run the full test suite on all presets, and
  mention the bump in the PR description. A new dependency needs a new ADR.

## Consequences

- Builds need network access on first configure (or a populated FetchContent
  cache); later configures reuse `build/<preset>/_deps`.
- Upgrades are explicit, reviewable one-line changes.
- Consumers embedding guardian-core as a subproject inherit these pins.
