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
    """Turn the skip of an integration test into a failure.

    Under ``pytest-xdist`` this runs in the worker that ran the test, and the report that comes
    back to the controller is already a failure.
    """
    report = yield
    if item.get_closest_marker("integration") is None or not _required(item.config):
        return report
    if report.skipped:
        reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else report.longrepr
        report.outcome = "failed"
        report.longrepr = f"integration test skipped, and --require-integration is set: {reason}"
    return report


class _Passes:
    """Counts the integration tests that passed, from the reports the process that reports gets.

    That is the only process there is, or the controller when tests run in parallel: a report is
    marked with the markers of its test, so the count does not need the test item.
    """

    def __init__(self) -> None:
        self.count = 0

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when == "call" and report.passed and "integration" in report.keywords:
            self.count += 1


_PASSES = pytest.StashKey[_Passes]()


def pytest_configure(config: pytest.Config) -> None:
    """Start counting the passes of integration tests."""
    passes = config.stash[_PASSES] = _Passes()
    config.pluginmanager.register(passes, "require-integration-passes")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail a run that was asked for integration tests and ran none.

    A ``pytest-xdist`` worker sees only the tests it was given, and may be given none that is an
    integration test, so only the controller, or a plain run, decides.
    """
    config = session.config
    if hasattr(config, "workerinput") or not _required(config):
        return
    if not config.stash[_PASSES].count:
        reporter = config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(
                "--require-integration is set, but no integration test passed", red=True
            )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED if exitstatus == 0 else exitstatus
