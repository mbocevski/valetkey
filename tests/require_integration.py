# SPDX-License-Identifier: Apache-2.0
"""The ``--require-integration`` option: integration tests that cannot run are failures.

Integration tests skip when bubblewrap, a browser or a desktop is missing, which is right on a
developer's machine. In CI a skip means the job tested nothing, so with this option a skipped
integration test fails, and so does a run in which no integration test passed.
"""

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add ``--require-integration``."""
    parser.addoption(
        "--require-integration",
        action="store_true",
        help="fail integration tests that skip, and fail a run in which none passed",
    )


def _required(config: pytest.Config) -> bool:
    return bool(config.getoption("--require-integration"))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Turn the skip of an integration test into a failure, and count the passes."""
    report = yield
    if item.get_closest_marker("integration") is None or not _required(item.config):
        return report
    if report.skipped:
        reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else report.longrepr
        report.outcome = "failed"
        report.longrepr = f"integration test skipped, and --require-integration is set: {reason}"
    elif report.passed and report.when == "call":
        item.config.stash[_PASSED] = item.config.stash.get(_PASSED, 0) + 1
    return report


_PASSED = pytest.StashKey[int]()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail a run that was asked for integration tests and ran none."""
    if _required(session.config) and not session.config.stash.get(_PASSED, 0):
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(
                "--require-integration is set, but no integration test passed", red=True
            )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED if exitstatus == 0 else exitstatus
