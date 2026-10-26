# List the recipes.
default:
    @just --list

# Install dependencies and the git hooks.
setup:
    uv sync
    uv run prek install

# Format and fix what can be fixed automatically.
fmt:
    uv run ruff format
    uv run ruff check --fix

# Run every check the CI runs.
check:
    uv run prek run --all-files

# Run the tests with coverage, on every core. Pass `-n 0` to run them one at a time.
test *args:
    uv run pytest -n auto --dist loadfile {{ args }}

# Download the noVNC viewer files the remote login display serves, checked against tools/novnc.lock.
novnc:
    uv run python tools/fetch_novnc.py

# Run the tests that need bubblewrap, a browser and a desktop; a skipped one fails. Every core is
# used, and each browser and compositor is the test's own; `-n 0` runs them one at a time.
test-integration *args:
    uv run pytest -m integration --require-integration -rs --no-cov -n auto --dist loadfile {{ args }}

# Cut a release from the changelog: version, commit and signed tag. Does not push.
release version:
    uv run python tools/release.py {{ version }}

# Build the sdist and wheel.
build:
    uv build

# Run the CI workflow locally in containers.
ci *args:
    act {{ args }}
