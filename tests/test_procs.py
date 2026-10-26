# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path

import pytest

from valetkey import procs

PROFILE = "/state/profiles/demo"
MAIN = ["/usr/lib/chromium/chromium", f"--user-data-dir={PROFILE}", "--headless=new"]


def test_command_lines_reads_a_process_table(tmp_path: Path) -> None:
    (tmp_path / "12").mkdir()
    (tmp_path / "12" / "cmdline").write_bytes(b"chromium\0--user-data-dir=/p\0")
    (tmp_path / "13").mkdir()  # no cmdline: the process ended
    (tmp_path / str(os.getpid())).mkdir()
    (tmp_path / str(os.getpid()) / "cmdline").write_bytes(b"me\0")
    (tmp_path / "self").mkdir()
    assert procs.command_lines(tmp_path) == [["chromium", "--user-data-dir=/p", ""]]


def test_command_lines_of_this_machine_are_not_empty() -> None:
    assert procs.command_lines()


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["tool", PROFILE], True),
        (["tool", f"--user-data-dir={PROFILE}"], True),
        (["tool", "--profile", PROFILE], True),
        (["tool", f"{PROFILE}/Default"], False),
        (["tool", "/state/profiles/other"], False),
        (["tool", "--flag=", ""], False),
        ([], False),
    ],
)
def test_uses_path(arguments: list[str], *, expected: bool) -> None:
    assert procs.uses_path(arguments, Path(PROFILE)) is expected


def test_uses_path_compares_resolved_paths(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(profile)
    assert procs.uses_path([f"--user-data-dir={alias}"], profile)


def test_the_main_browser_process_counts_and_its_helpers_do_not() -> None:
    profile = Path(PROFILE)
    helpers = [
        [*MAIN, "--type=renderer"],
        [*MAIN, "--type=zygote"],
        ["/usr/lib/chromium/chrome_crashpad_handler", "--database=/x"],
        ["bwrap", "--bind", PROFILE, PROFILE],  # names the profile but is no browser
        ["chromium", "--user-data-dir=/state/profiles/other"],
    ]
    assert not procs.browser_running(profile, helpers)
    assert procs.browser_running(profile, [*helpers, MAIN])
    assert not procs.browser_running(profile, [])
