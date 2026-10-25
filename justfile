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

# Run the tests with coverage.
test *args:
    uv run pytest {{ args }}

# Build the sdist and wheel.
build:
    uv build

# Run the CI workflow locally in containers.
ci *args:
    act {{ args }}
