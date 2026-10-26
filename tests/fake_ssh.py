# SPDX-License-Identifier: Apache-2.0
"""A stand-in for ``ssh`` that needs no server, key or network, for the bridge's tests.

It takes the options valetkey uses (``-S``, ``-T``, ``-o``, ``-R``), the host, and the command,
and acts like the part of ssh the bridge relies on:

* ``-R REMOTE:LOCAL`` listens on the unix socket ``REMOTE`` and hands every connection to the
  unix socket ``LOCAL``. Like sshd it fails if ``REMOTE`` already exists, which ends the
  connection with status 255, and it never removes the socket, however it ends.
* The command runs in ``/bin/sh -c``, on this machine, with the environment in the JSON in
  ``FAKE_SSH_REMOTE_ENV`` added, so the "server" can have its own runtime directory. Its standard
  input is a pipe that stays open for as long as this process lives, so the command sees
  end-of-file when this process is killed, as a command run by sshd does when the link drops.
* ``FAKE_SSH_LOG``, if set, gets one line of JSON per call: the words it was given.

Run it as ``python fake_ssh.py OPTIONS HOST COMMAND...``.
"""

import asyncio
import contextlib
import json
import os
import signal
import sys
from pathlib import Path


def parse(arguments: list[str]) -> tuple[list[str], str, list[str]]:
    """Split ``arguments`` into the ``-R`` specs, the host and the command."""
    forwards: list[str] = []
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        if arguments[index] in {"-S", "-o", "-R"}:
            if arguments[index] == "-R":
                forwards.append(arguments[index + 1])
            index += 2
        else:
            index += 1
    return forwards, arguments[index], arguments[index + 1 :]


async def pump(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
    with contextlib.suppress(OSError):
        while data := await source.read(65536):
            sink.write(data)
            await sink.drain()
    with contextlib.suppress(OSError):
        sink.close()


async def forward(local: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        far_reader, far_writer = await asyncio.open_unix_connection(local)
    except OSError:
        writer.close()
        return
    await asyncio.gather(pump(reader, far_writer), pump(far_reader, writer))


async def main(arguments: list[str]) -> int:
    forwards, _host, command = parse(arguments)
    log = os.environ.get("FAKE_SSH_LOG")
    if log:
        with Path(log).open("a", encoding="utf-8") as handle:  # noqa: ASYNC230 - a test stand-in
            handle.write(json.dumps(arguments) + "\n")
    servers = []
    for spec in forwards:
        remote, local = spec.split(":", 1)
        if Path(remote).exists() or not Path(remote).parent.is_dir():  # noqa: ASYNC240
            sys.stderr.write(f"Error: remote port forwarding failed for listen path {remote}\n")
            return 255
        servers.append(
            await asyncio.start_unix_server(
                lambda r, w, local=local: forward(local, r, w),
                path=remote,
            )
        )
    environment = {**os.environ, **json.loads(os.environ.get("FAKE_SSH_REMOTE_ENV", "{}"))}
    process = await asyncio.create_subprocess_exec(
        "/bin/sh",
        "-c",
        " ".join(command),
        stdin=asyncio.subprocess.PIPE,
        env=environment,
    )
    loop = asyncio.get_running_loop()
    ended = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, ended.set)
    waiting = asyncio.ensure_future(process.wait())
    stopping = asyncio.ensure_future(ended.wait())
    await asyncio.wait({waiting, stopping}, return_when=asyncio.FIRST_COMPLETED)
    if process.stdin is not None:
        process.stdin.close()  # what sshd does to the command when the link goes
    if not waiting.done():
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), 10)
        return 255
    return process.returncode or 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
