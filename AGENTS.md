# AGENTS.md

Guidance for coding agents and contributors working in this repo.
(`CLAUDE.md` is a symlink to this file.)

## Project

Cnert is a small library for creating TLS private keys, CSRs, private
CAs, and certificates for testing. All source lives in one module:
`src/cnert/__init__.py`. Tests are in `tests/`, docs in `docs/`.

- Python `>=3.12`; environment and packaging managed by `uv`.
- `__version__` is read from installed package metadata — never hardcode
  it. The version source of truth is `[project].version` in
  `pyproject.toml`.

## Spec-driven development (OpenSpec)

Feature work goes through [OpenSpec](https://openspec.dev/):
`openspec/specs/` describes what IS built, `openspec/changes/` what
SHOULD change, and project context plus artifact rules live in
`openspec/config.yaml`. There is no spec baseline yet; the first
proposals build it up.

Cycle: `/opsx:new` (or `propose`) -> `apply` -> `verify` -> `archive`.
Skip it only for chores that change no behaviour (dependency bumps,
formatting, release commits).

## Common tasks

Run via [`task`](https://taskfile.dev) (`taskfile.yaml`):

| Command | Purpose |
| --- | --- |
| `task install` | Sync the virtualenv with `uv` |
| `task test` | Run pytest (`task test -- -k name` to filter) |
| `task lint` | `ruff format --diff` + `ruff check` |
| `task check` | Lint + type check |
| `task cov` | Coverage report + HTML |
| `task docs:serve` | Serve docs locally |
| `task version` | Show current version |
| `task release -- patch\|minor\|major` | Cut a release |

## Conventions

- Formatting: `ruff format` / `ruff check`, 79-col lines, double quotes.
  Code must be clean under both before finishing.
- Commits: Conventional Commits (`feat:`, `fix:`, `chore:`, ...),
  imperative mood, explain *why*. No AI/co-author attribution trailers.

## Releasing

Bump first, commit, then tag — the tag must equal `pyproject.toml`'s
version and point at the bump commit. Use `task release -- patch` (or
`minor`/`major`); it enforces this. Full details, including CI behaviour
and pre-releases, are in [`docs/releasing.md`](docs/releasing.md).
