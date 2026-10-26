# SPDX-License-Identifier: Apache-2.0
"""A syscall deny-list for the browser's sandbox, as a classic BPF program built by hand.

The sandbox already runs without capabilities, with no new privileges and in namespaces of its
own. This filter closes what is left for code that has taken over the browser and looks for a
kernel bug: the system calls a browser has no use for and that have been the way into the
kernel before. Each one returns ``EPERM`` (``SECCOMP_RET_ERRNO``) instead of killing the process,
so a program that tries one fails the way it does without the right.

What is denied: the keyring, ``bpf``, ``userfaultfd``, ``perf_event_open``, the old and the new
mount calls, ``pivot_root``, ``process_vm_readv`` and ``process_vm_writev``, ``ptrace``, module
loading, ``kexec``, ``iopl`` and ``ioperm``, swap, ``reboot`` and ``acct``. Nested user
namespaces stay possible, because Chromium makes one for its own sandbox.

No system call of Chromium or agent-browser was found among them, by tracing a real session
without a filter. The program takes 38 instructions, and the cost of a call through it could not
be measured against none.

The numbers are those of x86_64. The program starts by checking the architecture and the x32
bit of the call number, so another ABI is refused, not mistaken for these numbers. On any other
CPU :func:`open_filter` returns ``None`` and the sandbox runs without a filter; ``valetkey
doctor`` says so.

bubblewrap reads the program from a file descriptor (``--seccomp FD``) and applies it after its
own setup, just before it runs the browser's first command, so every process in the sandbox has it.
"""

import os
import platform
import struct

MACHINE = "x86_64"
"""The CPU architecture the numbers below are for."""
DENIED: dict[str, int] = {
    "ptrace": 101,
    "pivot_root": 155,
    "acct": 163,
    "mount": 165,
    "umount2": 166,
    "swapon": 167,
    "swapoff": 168,
    "reboot": 169,
    "iopl": 172,
    "ioperm": 173,
    "init_module": 175,
    "delete_module": 176,
    "kexec_load": 246,
    "add_key": 248,
    "request_key": 249,
    "keyctl": 250,
    "perf_event_open": 298,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "finit_module": 313,
    "kexec_file_load": 320,
    "bpf": 321,
    "userfaultfd": 323,
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "fspick": 433,
    "mount_setattr": 442,
}
"""The denied system calls and their x86_64 numbers (``asm/unistd_64.h``)."""

# The few instructions of classic BPF the program uses (linux/bpf_common.h and linux/seccomp.h).
LD_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS: load a 32-bit word of the call's data
JEQ = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
JGE = 0x35  # BPF_JMP | BPF_JGE | BPF_K
RET = 0x06  # BPF_RET | BPF_K
OFFSET_NR = 0  # the call number in the data a filter sees
OFFSET_ARCH = 4  # the architecture in the same data
AUDIT_ARCH_X86_64 = 0xC000003E
X32_BIT = 0x40000000
RET_ALLOW = 0x7FFF0000
RET_EPERM = 0x00050000 | 1  # SECCOMP_RET_ERRNO with EPERM
_INSTRUCTION = struct.Struct("=HBBI")


def available(machine: str | None = None) -> bool:
    """Tell whether the filter's numbers are those of this machine (or of ``machine``)."""
    return (platform.machine() if machine is None else machine) == MACHINE


def _instruction(code: int, jump_true: int, jump_false: int, operand: int) -> bytes:
    return _INSTRUCTION.pack(code, jump_true, jump_false, operand)


def denied(*, allow_ptrace: bool = False) -> list[int]:
    """Return the denied call numbers, sorted; ``allow_ptrace`` leaves ``ptrace`` out."""
    return sorted(
        number for name, number in DENIED.items() if not (allow_ptrace and name == "ptrace")
    )


def program(*, allow_ptrace: bool = False) -> bytes:
    """Return the BPF program: refuse a foreign ABI, then each denied number, else allow.

    ``allow_ptrace`` is for the tests that trace the browser with ``strace``. Nothing else in the
    package sets it.
    """
    numbers = denied(allow_ptrace=allow_ptrace)
    refuse = [
        _instruction(LD_ABS, 0, 0, OFFSET_ARCH),
        _instruction(JEQ, 1, 0, AUDIT_ARCH_X86_64),
        _instruction(RET, 0, 0, RET_EPERM),  # another architecture
        _instruction(LD_ABS, 0, 0, OFFSET_NR),
        _instruction(JGE, 0, 1, X32_BIT),
        _instruction(RET, 0, 0, RET_EPERM),  # an x32 call number
    ]
    # A hit jumps over the remaining comparisons and the allow, to the refusal after it.
    compare = [
        _instruction(JEQ, len(numbers) - index, 0, number) for index, number in enumerate(numbers)
    ]
    ending = [_instruction(RET, 0, 0, RET_ALLOW), _instruction(RET, 0, 0, RET_EPERM)]
    return b"".join([*refuse, *compare, *ending])


def open_filter(*, allow_ptrace: bool = False) -> int | None:
    """Return a file descriptor that holds the program, for ``bwrap --seccomp``, or ``None``.

    ``None`` means this machine is not an x86_64 one. The caller passes the descriptor to the
    child (``pass_fds``) and closes it afterwards.
    """
    if not available():
        return None
    descriptor = os.memfd_create("valetkey-seccomp")
    try:
        os.write(descriptor, program(allow_ptrace=allow_ptrace))
        os.lseek(descriptor, 0, os.SEEK_SET)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor
