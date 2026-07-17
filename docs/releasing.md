# Releasing

Cnert releases are cut from a git tag. Pushing a version tag runs
[`release.yaml`](https://github.com/maartenq/cnert/blob/main/.github/workflows/release.yaml),
which builds with `uv` and publishes to PyPI (trusted publishing) and
GitHub Releases.

## Version source

The single source of truth is `[project].version` in `pyproject.toml`
(kept in sync in `uv.lock`). `src/cnert/__init__.py` reads
`__version__` from the installed package metadata, so it never needs a
manual edit.

The rule that avoids tag/version drift:

> **The tag must equal `pyproject.toml`'s version, and must point at the
> commit that sets it.** Bump first, commit, then tag.

## Release in one command

```console
task release -- patch    # 0.10.1 -> 0.10.2
task release -- minor    # 0.10.1 -> 0.11.0
task release -- major    # 0.10.1 -> 1.0.0
```

`task release` refuses to run on a dirty tree, then: bumps
`pyproject.toml` + `uv.lock`, commits `chore: bump version to X.Y.Z`,
creates an annotated tag `X.Y.Z`, and pushes the commit and tag. The
tag push triggers the release workflow.

## Manual steps (equivalent)

```console
task bump -- patch                       # edits pyproject.toml + uv.lock
git commit -am "chore: bump version to $(uv version --short)"
git tag -a "$(uv version --short)" -m "$(uv version --short)"
git push --follow-tags
```

## What CI does

1. **details** — parse version and suffix from the tag.
2. **check_pypi** — abort unless the version is newer than PyPI's latest.
3. **setup_and_build** — `uv version <tag>`, then `uv build`.
4. **pypi_publish** — upload to PyPI via trusted publishing
   (`release` environment, OIDC; no API token).
5. **github_release** — create the GitHub Release with generated notes.

## Pre-releases

The workflow also accepts pre-release tags: `X.Y.Za[N]`, `X.Y.Zb[N]`,
`X.Y.ZrcN` (e.g. `1.0.0rc1`). Set the matching version first, e.g.
`uv version 1.0.0rc1`, then commit, tag, and push as above.
