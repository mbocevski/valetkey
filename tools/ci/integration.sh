#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run the integration tests inside an Arch Linux container, as the CI job does.
#
#   docker run --rm --privileged -v "$PWD:/src:ro" -e AGENT_BROWSER_VERSION=... \
#     -e AGENT_BROWSER_SHA256=... IMAGE bash /src/tools/ci/integration.sh
#
# The source is mounted read-only and copied, so nothing in the checkout changes. The
# container runs as root and Chromium will not, so the tests run as a throwaway user with
# the owner's id.
set -euo pipefail

: "${AGENT_BROWSER_VERSION:?}" "${AGENT_BROWSER_SHA256:?}"

pacman -Syu --noconfirm --needed \
  bubblewrap chromium dbus foot grim iproute2 libnotify mako python strace sway uv wayvnc waypipe wtype

curl -fsSL -o /tmp/agent-browser \
  "https://github.com/vercel-labs/agent-browser/releases/download/v${AGENT_BROWSER_VERSION}/agent-browser-linux-x64"
echo "${AGENT_BROWSER_SHA256}  /tmp/agent-browser" | sha256sum --check -
# Where the Arch package puts it, with the link the package adds: the tests look there.
install -Dm 0755 /tmp/agent-browser /usr/lib/agent-browser/bin/agent-browser
ln -s /usr/lib/agent-browser/bin/agent-browser /usr/bin/agent-browser
agent-browser --version

owner=$(stat -c %u /src)
useradd --create-home --uid "$owner" ci
mkdir /work
tar -C /src --exclude=.venv --exclude=.git -cf - . | tar -C /work -xf -
chown -R ci /work

run_as_ci() {
  runuser -u ci -- env HOME=/home/ci PATH="$PATH" UV_LOCKED=1 "$@"
}

cd /work
run_as_ci uv sync
run_as_ci uv run python tools/fetch_novnc.py
# A skipped integration test fails the run: a skip here means something was not installed.
# One test starts a transient service with the unit file's hardening, which needs a systemd
# user manager, and a container has none, so it runs on a developer's machine only.
run_as_ci uv run pytest -m integration --require-integration -rs --no-cov \
  --deselect tests/test_cli.py::test_bubblewrap_still_works_under_the_service_hardening
