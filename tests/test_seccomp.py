# SPDX-License-Identifier: Apache-2.0

import os
import re
import struct
from pathlib import Path

import pytest

from valetkey import seccomp

UNISTD = Path("/usr/include/asm/unistd_64.h")
EPERM = 1
ALLOW = seccomp.RET_ALLOW
DENY = seccomp.RET_EPERM


def run_filter(program: bytes, number: int, arch: int = seccomp.AUDIT_ARCH_X86_64) -> int:
    """Run a classic BPF program on a ``seccomp_data`` of ``number`` and ``arch``; return its value.

    Only what the program uses is understood: a 32-bit absolute load, a jump on equal or on
    greater-or-equal against a constant, and a return of a constant. Anything else fails.
    """
    data = {seccomp.OFFSET_NR: number, seccomp.OFFSET_ARCH: arch}
    instructions = [struct.unpack("=HBBI", program[i : i + 8]) for i in range(0, len(program), 8)]
    accumulator = 0
    counter = 0
    for _ in range(len(instructions) + 1):
        code, jump_true, jump_false, operand = instructions[counter]
        counter += 1
        if code == seccomp.LD_ABS:
            accumulator = data[operand]
        elif code == seccomp.JEQ:
            counter += jump_true if accumulator == operand else jump_false
        elif code == seccomp.JGE:
            counter += jump_true if accumulator >= operand else jump_false
        elif code == seccomp.RET:
            return operand
        else:
            message = f"unknown instruction {code:#x}"
            raise AssertionError(message)
    message = "the program does not end"
    raise AssertionError(message)


def test_every_denied_call_gets_eperm_and_every_other_is_allowed() -> None:
    program = seccomp.program()
    assert len(program) == 8 * 38  # 6 checks, 30 comparisons and 2 returns
    denied = set(seccomp.DENIED.values())
    assert len(denied) == len(seccomp.DENIED) == 30
    for number in range(600):
        expected = DENY if number in denied else ALLOW
        assert run_filter(program, number) == expected, number


def test_eperm_is_the_errno_the_filter_returns() -> None:
    assert DENY == 0x00050000 | EPERM  # SECCOMP_RET_ERRNO | EPERM


def test_a_foreign_architecture_is_refused_whatever_the_number() -> None:
    program = seccomp.program()
    for arch in (0x40000003, 0xC00000B7, 0):  # i386, aarch64, none
        for number in (0, 1, 101, 250, 500):
            assert run_filter(program, number, arch) == DENY


def test_an_x32_call_number_is_refused() -> None:
    program = seccomp.program()
    for number in (seccomp.X32_BIT, seccomp.X32_BIT | 1, seccomp.X32_BIT | 250, 0x7FFFFFFF):
        assert run_filter(program, number) == DENY


def test_ptrace_is_allowed_only_when_asked() -> None:
    ptrace = seccomp.DENIED["ptrace"]
    assert run_filter(seccomp.program(), ptrace) == DENY
    allowing = seccomp.program(allow_ptrace=True)
    assert run_filter(allowing, ptrace) == ALLOW
    assert len(allowing) == len(seccomp.program()) - 8
    for name, number in seccomp.DENIED.items():
        if name != "ptrace":
            assert run_filter(allowing, number) == DENY


def test_the_filter_has_no_jump_too_long_for_a_byte() -> None:
    program = seccomp.program()
    for offset in range(0, len(program), 8):
        _code, jump_true, jump_false, _operand = struct.unpack(
            "=HBBI", program[offset : offset + 8]
        )
        assert jump_true < 256 > jump_false
    assert len(seccomp.DENIED) < 255


@pytest.mark.skipif(not UNISTD.is_file(), reason="the kernel headers are not installed")
def test_the_numbers_are_those_of_the_kernel_header() -> None:
    header = {
        match.group(1): int(match.group(2))
        for match in re.finditer(r"#define __NR_(\w+) (\d+)", UNISTD.read_text())
    }
    assert {name: header[name] for name in seccomp.DENIED} == seccomp.DENIED


def test_what_is_denied_is_what_the_module_says() -> None:
    assert {"ptrace", "keyctl", "bpf", "userfaultfd", "perf_event_open", "mount", "kexec_load"} <= (
        set(seccomp.DENIED)
    )
    assert seccomp.denied() == sorted(seccomp.DENIED.values())
    assert seccomp.DENIED["ptrace"] not in seccomp.denied(allow_ptrace=True)
    # Nested user namespaces stay possible: Chromium makes one for its own sandbox.
    assert "unshare" not in seccomp.DENIED
    assert "clone" not in seccomp.DENIED
    assert "setns" not in seccomp.DENIED


@pytest.mark.parametrize(
    ("machine", "expected"), [("x86_64", True), ("aarch64", False), ("", False)]
)
def test_the_filter_is_for_x86_64_only(machine: str, *, expected: bool) -> None:
    assert seccomp.available(machine) is expected


def test_the_descriptor_holds_the_program_from_its_start() -> None:
    descriptor = seccomp.open_filter()
    assert descriptor is not None
    try:
        assert os.read(descriptor, 4096) == seccomp.program()
    finally:
        os.close(descriptor)


def test_another_architecture_gets_no_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(seccomp.platform, "machine", lambda: "aarch64")
    assert seccomp.open_filter() is None


def test_a_failed_write_closes_the_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[int] = []
    real = os.memfd_create

    def recording(name: str) -> int:
        opened.append(real(name))
        return opened[-1]

    def failing(_descriptor: int, _data: bytes) -> int:
        raise OSError

    monkeypatch.setattr(os, "memfd_create", recording)
    monkeypatch.setattr(os, "write", failing)
    with pytest.raises(OSError):  # noqa: PT011 - the error is whatever the write raised
        seccomp.open_filter()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(opened[0])


def test_only_tests_leave_ptrace_out_of_the_filter() -> None:
    """Production code never sets the option; the one that does is a test of strace."""
    source = Path(seccomp.__file__).parent
    users = {
        path.name
        for path in source.glob("*.py")
        if re.search(r"allow_ptrace\s*=\s*(?!False\b)\w", path.read_text())
        and path.name not in {"sandbox.py", "sessions.py", "seccomp.py"}
    }
    assert users == set()
    # Where it is declared or handed on, the default is off, and nothing in the package sets it.
    for name in ("sandbox.py", "sessions.py", "seccomp.py"):
        text = (source / name).read_text()
        assert not re.search(r"allow_ptrace\s*=\s*True", text), name
