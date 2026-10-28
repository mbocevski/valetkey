# SPDX-License-Identifier: Apache-2.0
"""A private headless sway for tests that need a window: its own runtime directory and sockets."""

import asyncio
import json
import os
import subprocess
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class Sway:
    """A private headless sway: its own runtime directory, its own sockets."""

    def __init__(self, runtime: Path) -> None:
        self.runtime = runtime
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(runtime),
            "XDG_RUNTIME_DIR": str(runtime),
            "WLR_BACKENDS": "headless",
            "WLR_LIBINPUT_NO_DEVICES": "1",
            "WLR_RENDERER": "pixman",
        }
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def display(self) -> Path:
        (found,) = (p for p in self.runtime.glob("wayland-*") if p.suffix != ".lock")
        return found

    def start(self) -> None:
        config = self.runtime / "config"
        config.write_text("output HEADLESS-1 resolution 1280x800\n", encoding="utf-8")
        log = (self.runtime / "sway.log").open("wb")
        self.process = subprocess.Popen(  # noqa: S603  # fixed argument list
            ["sway", "--config", str(config)],  # noqa: S607  # resolved from PATH
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        log.close()
        deadline = time.monotonic() + 20
        while not (list(self.runtime.glob("sway-ipc.*.sock")) and self._socket_ready()):
            assert time.monotonic() < deadline, "sway did not start"
            assert self.process.poll() is None, (self.runtime / "sway.log").read_text()
            time.sleep(0.05)

    def _socket_ready(self) -> bool:
        return any(
            path.is_socket() for path in self.runtime.glob("wayland-*") if path.suffix != ".lock"
        )

    async def msg(self, *args: str) -> str:
        env = self.env | {"SWAYSOCK": str(next(self.runtime.glob("sway-ipc.*.sock")))}
        process = await asyncio.create_subprocess_exec(
            "swaymsg",
            *args,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await process.communicate()
        return out.decode()

    async def close(self, app_id: str, limit: float = 60) -> None:
        """Close a window of ``app_id`` once there is one, as the person does.

        A browser's page can load well before the compositor has its window when the machine is
        busy, and closing a window that is not there closes nothing and says so: nothing then ever
        closes the window that appears a moment later. So this tries again until a window is closed.
        """
        deadline = time.monotonic() + limit
        while True:
            reply = json.loads(await self.msg(f"[app_id={app_id}]", "kill"))
            if any(item.get("success") for item in reply):
                return
            assert time.monotonic() < deadline, f"no {app_id} window to close"
            await asyncio.sleep(0.2)

    async def windows(self) -> list[dict[str, Any]]:
        def walk(node: dict[str, Any]) -> list[dict[str, Any]]:
            found = [node] if node.get("app_id") else []
            for child in (*node.get("nodes", []), *node.get("floating_nodes", [])):
                found += walk(child)
            return found

        return walk(json.loads(await self.msg("-t", "get_tree", "-r")))

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(10)
