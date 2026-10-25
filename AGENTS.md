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
[act](https://github.com/nektos/act).

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
does and why. No filler words, emoji, references to planning tools or issue numbers, or mentions
of the tools used to write the code.

## README

`README.md` is for users. Two hooks keep it current:

- Blocks between `<!-- begin: valetkey ARGS -->` and `<!-- end: valetkey ARGS -->` hold the
  output of `valetkey ARGS`, and the stated Python version must match `requires-python`. When a
  block is stale the commit fails; run `uv run python tools/readme_check.py facts --fix` and
  review the result. To document a new command's help, add a pair of markers for it.
- A `feat` commit or a breaking change (`!`, `BREAKING CHANGE:`) must stage `README.md`. If the
  README is still accurate, add a `Docs: none` trailer to the commit message instead.

## Commits

- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:` and so on). A
  hook checks the format.
- Keep each commit small and focused, and sign it.
- Do not push.
