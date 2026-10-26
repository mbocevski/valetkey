# SPDX-License-Identifier: Apache-2.0

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
