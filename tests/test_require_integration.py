# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

TESTS = """
import pytest

@pytest.mark.integration
def test_runs():
    pass

@pytest.mark.integration
@pytest.mark.skipif(True, reason="no bubblewrap")
def test_skips():
    pass

@pytest.mark.integration
def test_skips_inside():
    pytest.skip("no browser")

def test_unmarked_skip():
    pytest.skip("ordinary skip")
"""


@pytest.fixture
def project(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeini("[pytest]\nmarkers = integration: needs the real tools\n")
    pytester.makeconftest('pytest_plugins = ["require_integration"]')
    pytester.makepyfile(TESTS)
    return pytester


def test_without_the_option_skips_stay_skips(project: pytest.Pytester) -> None:
    result = project.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, skipped=3)


def test_with_the_option_skipped_integration_tests_fail(project: pytest.Pytester) -> None:
    result = project.runpytest("--require-integration")
    result.assert_outcomes(passed=1, failed=1, errors=1, skipped=1)
    result.stdout.fnmatch_lines(["*no bubblewrap*", "*no browser*"])


def test_a_run_with_no_passing_integration_test_fails(project: pytest.Pytester) -> None:
    result = project.runpytest("--require-integration", "-k", "unmarked")
    result.assert_outcomes(skipped=1)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*no integration test passed*"])


def test_a_clean_run_passes(project: pytest.Pytester) -> None:
    result = project.runpytest("--require-integration", "-k", "test_runs")
    result.assert_outcomes(passed=1)
    assert result.ret == pytest.ExitCode.OK


@pytest.fixture
def parallel(project: pytest.Pytester) -> pytest.Pytester:
    """The same project, with the plugin beside the tests: a worker is a new process, and finds
    it there as it finds the test configuration, where the main process finds it through
    ``pythonpath``."""
    plugin = (Path(__file__).parent / "require_integration.py").read_text(encoding="utf-8")
    project.makepyfile(require_integration=plugin)
    return project


def test_in_parallel_skipped_integration_tests_still_fail(parallel: pytest.Pytester) -> None:
    result = parallel.runpytest("--require-integration", "-n", "2", "-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, failed=1, errors=1, skipped=1)
    result.stdout.fnmatch_lines(["*no bubblewrap*", "*no browser*"])


def test_in_parallel_a_run_with_no_passing_integration_test_fails(
    parallel: pytest.Pytester,
) -> None:
    result = parallel.runpytest("--require-integration", "-n", "2", "-k", "unmarked")
    result.assert_outcomes(skipped=1)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*no integration test passed*"])


def test_in_parallel_a_clean_run_passes_when_a_worker_got_no_integration_test(
    parallel: pytest.Pytester,
) -> None:
    parallel.makepyfile(
        test_more="""
        def test_a():
            pass

        def test_b():
            pass
        """
    )
    result = parallel.runpytest(
        "--require-integration",
        "-n",
        "3",
        "--dist",
        "loadfile",
        "-k",
        "test_runs or test_a or test_b",
    )
    result.assert_outcomes(passed=3)
    assert result.ret == pytest.ExitCode.OK
