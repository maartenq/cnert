# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

Add entries under [Unreleased] as you work; `task release` stamps them
into a dated version section.

## [Unreleased]

## [0.10.3] - 2026-07-17

### Added

- Internal only: a `CHANGELOG.md`, and a release flow that stamps
  `[Unreleased]` notes into a dated section within the release commit.

## [0.10.2] - 2026-07-17

### Changed

- Internal only: no functional changes to the library. Release tooling
  now builds with `uv` instead of Poetry; added a documented one-command
  release flow (`task release`) and `AGENTS.md`; set the Ruff
  `target-version` to `py312`.

### Fixed

- `git:check` task always failed on a clean tree due to a shell
  precedence bug.

## [0.10.1] - 2026-07-17

### Changed

- `__version__` is now read from the installed package metadata instead
  of a hardcoded string, so it always matches the released version.

### Removed

- Dropped the no-op `backend=default_backend()` arguments (ignored by
  `cryptography` since 3.1) and the `default_backend` import.

## [0.10.0] - 2026-07-17

### Added

- Support for Python 3.14.

[Unreleased]: https://github.com/maartenq/cnert/compare/0.10.3...HEAD
[0.10.3]: https://github.com/maartenq/cnert/releases/tag/0.10.3
[0.10.2]: https://github.com/maartenq/cnert/releases/tag/0.10.2
[0.10.1]: https://github.com/maartenq/cnert/releases/tag/0.10.1
[0.10.0]: https://github.com/maartenq/cnert/releases/tag/0.10.0
