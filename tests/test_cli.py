# SPDX-License-Identifier: Apache-2.0

import runpy
import subprocess
import sys

import pytest

from valetkey import __version__
from valetkey.cli import main


def test_without_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: valetkey" in capsys.readouterr().out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"valetkey {__version__}"


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--no-such-option"])
    assert exit_info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_module_entry_point(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["valetkey"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("valetkey", run_name="__main__")
    assert exit_info.value.code == 0
    assert "usage: valetkey" in capsys.readouterr().out


def test_runs_as_a_module_in_a_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "valetkey", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == f"valetkey {__version__}"
