# Contributing

valetkey gives MCP clients a browser that is logged in to one site and contained to the hosts that
site needs. It is a Python package managed with uv.

## Setup

```sh
just setup
```

That runs `uv sync` and installs the git hooks with prek.

## Before every commit

```sh
just check   # prek: ruff, ty, vale, zizmor and file hygiene
just test    # pytest with branch coverage
```

Both must pass. Coverage must stay at 90% or above.

To run the CI workflow locally, use `just ci`. It needs Docker and
[act](https://github.com/nektos/act). Run one job with `just ci -j integration`; `.actrc` starts the
containers privileged, which bubblewrap needs.

`just test-integration` runs only the tests that need bubblewrap, a browser and a desktop, and
fails when one of them skips.

## Code

- Python 3.14. Every function is typed, and `ty check` passes with no warnings.
- Ruff runs with every rule enabled. Fix the code rather than adding a `noqa`, and explain any
  ignore you add to `pyproject.toml`.
- Every Python file starts with `# SPDX-License-Identifier: Apache-2.0`.
- Prefer the standard library. Add a dependency only when it removes real work, with `uv add`, at
  its latest version.
- Pin GitHub Actions to a full commit SHA, with the version in a comment.

## Tests

- Tests live in `tests/` and run with pytest.
- Tests that need bubblewrap, Chromium or agent-browser are marked `integration` and skip when
  any of them is missing.
- Test behavior through public functions, not private details.

## Writing

Vale checks Markdown files and Python comments. Write plain, specific prose: say what the code
does and why. No filler words, stock phrases, praise words, emoji, references to planning tools or
issue numbers, or mentions of the tools used to write the code. Keep sentences under 35 words, use
at most one em dash per paragraph, and write headings in sentence case.

## README

`README.md` is for users, and it stays short. A hook caps it at 700 words of prose and 8 sections.
It also rejects boilerplate sections ("Features", "Overview", "Why valetkey"), list items that
open with a bold label, lists nested more than one level, horizontal rules and more than 3 badges.
When something needs more room than that, it belongs in its own page, not the README.

Two more hooks keep it current:

- Blocks between `<!-- begin: valetkey ARGS -->` and `<!-- end: valetkey ARGS -->` hold the
  output of `valetkey ARGS`, and the stated Python version must match `requires-python`. When a
  block is stale the commit fails; run `uv run python tools/readme_check.py facts --fix` and
  review the result. To document a new command's help, add a pair of markers for it.
- A `feat` commit or a breaking change (`!`, `BREAKING CHANGE:`) must stage `README.md`. If the
  README is still accurate, add a `Docs: none` trailer to the commit message instead. A hook
  checks each commit, and CI checks every commit in a pull request. A pull request labeled
  `skip-readme` passes without README changes.

## Changelog

`CHANGELOG.md` records what changed for users, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. New entries go under
`## [Unreleased]`, in the sections Added, Changed, Deprecated, Removed, Fixed and Security.

An entry belongs there when a user can notice the change: a command, option or MCP tool, a
config or file location, a requirement, behavior, or a security fix. Refactors, tests, CI,
tooling, dependency updates that change nothing for users, and wording fixes stay out.

Write each entry as one sentence from the user's side: start with a capital letter, end with a
full stop, and stay under 40 words. A lint rejects internal words (refactor, tests, CI, bump)
and vague ones (various, minor).

The commit type decides whether the changelog must change:

- `feat`, `fix`, `perf`, `revert` and breaking changes must update `CHANGELOG.md`. When users
  would not notice the change, add a `Changelog: skip` trailer instead.
- Every other type must leave `CHANGELOG.md` alone. To reword entries or cut a release, use the
  `changelog` or `release` scope, as in `docs(changelog): …` or `chore(release): 0.2.0`.

A hook checks each commit, and CI checks every commit in a pull request. A pull request labeled
`skip-changelog` passes without new entries.

To release, run `just release X.Y.Z` on a clean worktree. It turns `## [Unreleased]` into the new
version with today's date, sets the package version with `uv version`, commits the changelog,
`pyproject.toml` and `uv.lock` as `chore(release): X.Y.Z`, and creates a signed tag `vX.Y.Z` that
carries the release notes. It never pushes: it prints the push command for you to run. The lint
fails when the newest release in the changelog differs from the version in `pyproject.toml`.

## Commits

- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:` and so on). A
  hook checks the format.
- Keep each commit small and focused, and sign it.
- Do not push.
