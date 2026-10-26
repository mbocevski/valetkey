# SPDX-License-Identifier: Apache-2.0
"""One contained browser per site, driven through agent-browser.

A session owns everything for one site: the network namespace (see ``valetkey.sandbox``), the
forwarder inside it, agent-browser's daemon and Chrome. Callers never pass a launch option.

How it is arranged:

* The namespace is a PID namespace, so its first command is a *holder*, a shell script that
  lives as long as the session. It starts the forwarder, waits until it listens, runs the first
  ``agent-browser open`` with every launch option, writes that command's answer to a file and
  then waits. agent-browser's daemon is born inside the namespace, so its Chrome has no
  network but the forwarder, and it dies with the holder.
* Every later call runs on the host and reaches the daemon through its unix socket. These calls
  carry **no** launch option: agent-browser relaunches Chrome on a throwaway profile when a
  call to a running daemon disagrees with how it was launched. One function,
  :func:`call_command`, builds all of them.
* agent-browser's socket directory is namespaced per site (``--namespace``), and only that
  site's directory is bound into the sandbox, so one browser cannot see another's daemon.
* The holder is started from a thread of its own that lives as long as the session, because
  the kernel ties ``--die-with-parent`` to the thread that started the process. If valetkey
  dies, the thread dies with it and the whole namespace goes.
"""

import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, replace
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

from valetkey import procs, profiles, sandbox, seccomp, sites

if TYPE_CHECKING:
    from types import TracebackType

logger = logging.getLogger(__name__)

MIN_VERSION = (0, 39, 0)
"""The oldest agent-browser this module drives. The README, the PKGBUILD and ``doctor`` repeat
it, and ``tools/version_check.py`` and ``tools/readme_check.py`` keep them in step."""
TESTED_VERSION = (0, 39, 4)
"""The agent-browser version the behavior here was checked against. The CI workflow installs this
version, and ``tools/version_check.py`` checks that it does."""

SESSION_NAME = "s"
"""agent-browser's session name. Short on purpose: its socket path may not pass 103 bytes."""
DRIVER_DIR = "agent-browser"
READY_FILE = "ready.json"
DEFAULT_EXECUTABLE = "/usr/bin/chromium"
PROBE_TIMEOUT = 2.0
STOP_GRACE = 5.0
"""Seconds the holder gets after SIGTERM before SIGKILL."""
DEFAULT_TIMEOUT = 60.0
"""Seconds to wait for the first page, and for each later call."""

SAVE_LIMIT = 100 * 1024 * 1024
"""The most bytes :meth:`Session.save` takes from one address: 100 MiB."""
MAX_IMAGES = 30
"""The most pictures :meth:`Session.images` lists."""
MAX_ADDRESS = 2000
"""A picture's address longer than this is left out of the list: it would not be a plain one."""

_BRIDGE_ATTEMPTS = 100
_REF = re.compile(r"@?(e\d+)")
_VERSION = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.png")
_LOG_TAIL = 2000
_SRCSET_CANDIDATE = re.compile(r"\s*(\S+?)(?:\s+(\d+(?:\.\d+)?)[wx]\s*(?:,|$)|\s*(?:,\s|,$|$))")

# Run in a tab that has the address open, as the page there. The address is fetched again from
# that tab (its own origin, its cookies, the session's proxy) and handed to the browser's download
# manager, which writes it into the downloads folder like any file the page offers.
_SAVE_SCRIPT = """(async () => {
  const limit = LIMIT;
  const response = await fetch(location.href, {credentials: 'include'});
  if (!response.ok) throw new Error('the server answered ' + response.status);
  if (Number(response.headers.get('content-length')) > limit) {
    throw new Error('the file is larger than ' + limit + ' bytes');
  }
  const blob = await response.blob();
  if (blob.size > limit) throw new Error('the file is larger than ' + limit + ' bytes');
  let name = '';
  try { name = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || ''); }
  catch (error) { name = ''; }
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = name || 'download';
  (document.body || document.documentElement).append(link);
  link.click();
  return 'saved';
})()"""

# The pictures and videos on the page, the biggest first, as JSON text: the address of the
# largest candidate of a srcset (or the one the browser chose), HTTP and HTTPS ones only.
_IMAGES_SCRIPT = r"""(() => {
  const absolute = (value) => {
    try {
      const url = new URL(value, document.baseURI);
      return (url.protocol === 'http:' || url.protocol === 'https:') ? url.href : '';
    } catch (error) { return ''; }
  };
  const largest = (srcset) => {
    let best = '', size = -1;
    for (const part of srcset.split(',')) {
      const [address, descriptor] = part.trim().split(/\s+/);
      const value = descriptor ? parseFloat(descriptor) : 0;
      if (address && value > size) { best = address; size = value; }
    }
    return best;
  };
  const found = [];
  for (const img of document.images) {
    const url = absolute((img.srcset && largest(img.srcset)) || img.currentSrc || img.src);
    const width = img.naturalWidth, height = img.naturalHeight;
    if (url && width * height >= 2500) {
      found.push({kind: 'image', alt: img.alt || img.title || '', url, width, height});
    }
  }
  for (const video of document.querySelectorAll('video')) {
    const url = absolute(video.currentSrc || video.src || video.poster);
    if (url) {
      found.push({kind: 'video', alt: video.title || '', url,
                  width: video.videoWidth, height: video.videoHeight});
    }
  }
  found.sort((a, b) => b.width * b.height - a.width * a.height);
  return JSON.stringify(found.slice(0, LIMIT));
})()"""


class SessionError(RuntimeError):
    """A session could not start, or is not running."""


class AgentBrowserError(RuntimeError):
    """agent-browser reported a failure. The message is its own."""


class VersionError(SessionError):
    """The installed agent-browser is older than :data:`MIN_VERSION`."""


# -- results -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Page:
    """Where the browser is after a navigation."""

    url: str
    title: str


@dataclass(frozen=True, slots=True)
class Ref:
    """An interactive element in a snapshot."""

    role: str
    name: str


@dataclass(frozen=True, slots=True)
class Snapshot:
    """The accessibility tree of the page. ``refs`` maps ``e1``, ``e2``… to elements."""

    url: str
    tree: str
    refs: dict[str, Ref]


# -- versions ------------------------------------------------------------------------------


def parse_version(text: str) -> tuple[int, int, int]:
    """Return the ``(major, minor, patch)`` in the output of ``agent-browser --version``.

    Raises ``ValueError`` when there is none.
    """
    match = _VERSION.search(text)
    if match is None:
        message = f"no version number in {text!r}"
        raise ValueError(message)
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def version_text(version: tuple[int, int, int]) -> str:
    """Return ``version`` as ``MAJOR.MINOR.PATCH``."""
    return ".".join(map(str, version))


def short_version_text(version: tuple[int, int, int]) -> str:
    """Return ``version`` as ``MAJOR.MINOR`` when its patch number is 0, as people say a minimum."""
    major, minor, patch = version
    return f"{major}.{minor}" if patch == 0 else version_text(version)


def is_untested(version: tuple[int, int, int]) -> bool:
    """Tell whether ``version`` is newer than the one valetkey was tested with."""
    return version > TESTED_VERSION


_warned: set[tuple[int, int, int]] = set()
"""The untested versions this process has already warned about."""


def check_version(version: tuple[int, int, int], *, warn: bool = True) -> None:
    """Fail for a version below :data:`MIN_VERSION`; warn once for one above the tested one.

    The warning is logged once per process and version, so a daemon that starts many sessions
    does not repeat it. ``warn=False`` leaves it to the caller, as ``doctor`` does.

    Raises:
        VersionError: when ``version`` is older than the minimum.

    """
    text = version_text(version)
    if version < MIN_VERSION:
        minimum = version_text(MIN_VERSION)
        message = f"agent-browser {text} is too old; valetkey needs {minimum} or newer"
        raise VersionError(message)
    if warn and is_untested(version) and version not in _warned:
        _warned.add(version)
        tested = version_text(TESTED_VERSION)
        logger.warning("agent-browser %s is newer than %s, the version tested", text, tested)


def installed_version(binary: str = "agent-browser") -> tuple[int, int, int]:
    """Run ``binary --version`` and return what it reports.

    Raises:
        SessionError: when the program is missing or prints no version.

    """
    try:
        result = subprocess.run(  # noqa: S603  # fixed argument list, no shell
            [binary, "--version"], capture_output=True, text=True, check=True, timeout=30
        )
        return parse_version(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        message = f"cannot read the version of {binary}: {error}"
        raise SessionError(message) from error


# -- paths ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionPaths:
    """Where one site's session keeps its files. Every one of them is per site."""

    site: str
    directory: Path
    """valetkey's own runtime directory for the site. Never bound into the sandbox."""
    proxy_socket: Path
    """Where the proxy for this site listens. Its directory is bound into the sandbox."""
    log_file: Path
    """Output of the holder, the forwarder, agent-browser's daemon and Chrome."""
    config_file: Path
    """An empty agent-browser config, so no user or project config changes a later call."""
    driver_dir: Path
    """agent-browser's namespaced directory. The only part of its runtime directory that is
    bound into the sandbox: the daemon's socket, and the file the first ``open`` writes."""
    ready_file: Path
    profile_dir: Path
    downloads_dir: Path
    """Where finished downloads end up, and the only part of the downloads that people see."""
    incoming_dir: Path
    """Inside ``downloads_dir``, hidden. The browser downloads into it, and the daemon moves each
    finished file out under a name that is free (see :mod:`valetkey.downloads`)."""
    screenshots_dir: Path
    """Inside ``downloads_dir``, hidden, so a screenshot is not mistaken for a download."""


def session_paths(roots: sites.Roots, site: str) -> SessionPaths:
    """Return the paths for ``site``'s session. Nothing is created.

    Raises:
        RuntimeDirUnavailableError: when ``XDG_RUNTIME_DIR`` is unset.
        ValueError: when ``site`` is not a valid site name.

    """
    app_dir = sites.runtime_path(roots)
    key = sites.storage_key(site)
    directory = app_dir / "sessions" / key
    driver_dir = app_dir.parent / DRIVER_DIR / "namespaces" / key
    return SessionPaths(
        site=site,
        directory=directory,
        proxy_socket=directory / "proxy" / "proxy.sock",
        log_file=directory / "session.log",
        config_file=directory / "agent-browser.json",
        driver_dir=driver_dir,
        ready_file=driver_dir / READY_FILE,
        profile_dir=sites.profile_path(roots, site),
        downloads_dir=sites.downloads_path(roots, site),
        incoming_dir=sites.downloads_path(roots, site) / ".incoming",
        screenshots_dir=sites.downloads_path(roots, site) / ".screenshots",
    )


# -- commands ------------------------------------------------------------------------------


def _identity_env(paths: SessionPaths, runtime: Path) -> dict[str, str]:
    """Return the variables that name a session; with the platform basics, all a call needs."""
    return {
        "XDG_RUNTIME_DIR": str(runtime),
        "AGENT_BROWSER_SESSION": SESSION_NAME,
        "AGENT_BROWSER_NAMESPACE": sites.storage_key(paths.site),
        "AGENT_BROWSER_IDLE_TIMEOUT_MS": "0",
    }


def agent_args(flags: list[str]) -> list[str]:
    """Return Chrome flags that go through ``--args``.

    The proxy and the user agent have flags of their own in agent-browser, so they are left
    out here rather than passed twice.
    """
    return [f for f in flags if not f.startswith(("--proxy-server=", "--user-agent="))]


def launch_command(
    binary: str, paths: SessionPaths, start_url: str, executable: str, chrome_major: int
) -> list[str]:
    """Return the first ``open``: the only command that carries launch options."""
    flags = sandbox.chrome_flags(chrome_major)
    user_agent = next(f for f in flags if f.startswith("--user-agent=")).split("=", 1)[1]
    return [
        binary,
        "--json",
        "--profile",
        str(paths.profile_dir),
        "--download-path",
        str(paths.incoming_dir),
        "--proxy",
        f"http://{sandbox.PROXY_ADDRESS}",
        "--user-agent",
        user_agent,
        # Newline-separated, because several Chrome flags contain commas.
        "--args",
        "\n".join(agent_args(flags)),
        "--executable-path",
        executable,
        "--idle-timeout",
        "0",
        "open",
        _check_url(start_url),
    ]


def holder_script(paths: SessionPaths, binary: str, open_command: list[str], runtime: Path) -> str:
    """Return the shell script that is the first command in the namespace.

    It starts the forwarder, waits until it accepts connections, runs ``open_command`` with the
    session's identity in its environment, writes the answer to ``paths.ready_file`` and then
    waits for the forwarder, which is to say until it is killed.
    """
    bridge = shlex.join(sandbox.bridge_command(paths.proxy_socket))
    environment = " ".join(
        f"{name}={shlex.quote(value)}" for name, value in _identity_env(paths, runtime).items()
    )
    ready = shlex.quote(str(paths.ready_file))
    host, port = sandbox.PROXY_ADDRESS.split(":")
    return "\n".join(
        [
            f"{bridge} &",
            "bridge=$!",
            "attempt=0",
            f"until (exec 3<>/dev/tcp/{host}/{port}) 2>/dev/null; do",
            '  kill -0 "$bridge" 2>/dev/null || exit 71',
            "  attempt=$((attempt + 1))",
            f'  [ "$attempt" -gt {_BRIDGE_ATTEMPTS} ] && exit 70',
            "  sleep 0.1",
            "done",
            f"{environment} {shlex.join([binary, *open_command[1:]])} > {ready}.tmp",
            "status=$?",
            f"mv {ready}.tmp {ready}",
            '[ "$status" -eq 0 ] || exit "$status"',
            "wait",
        ]
    )


OWN_FLAGS = frozenset({"-i", "--clear"})
"""The only option-like arguments valetkey itself passes after a verb (``snapshot -i``,
``network requests --clear``)."""


def call_command(
    binary: str, paths: SessionPaths, runtime: Path, *verb: str
) -> tuple[list[str], dict[str, str]]:
    """Return the argument list and environment of every call made after the first ``open``.

    This is the only place that builds them. They carry the session's identity and nothing
    that configures how the browser launches.

    agent-browser reads any argument that looks like one of its options as that option, wherever
    it comes from, and has no ``--`` to end the options. An option can relaunch the browser on
    another profile (``--headed``, ``--profile``) or point the call at another session
    (``--session``). So no argument after the verb may start with a dash unless it is one of
    :data:`OWN_FLAGS`; anything else is refused here, whatever the caller meant it to be.

    Raises:
        ValueError: when an argument after the verb starts with a dash and is not ours.

    """
    for argument in verb[1:]:
        if argument.startswith("-") and argument not in OWN_FLAGS:
            message = (
                f"refusing to pass {argument[:40]!r} to agent-browser: it looks like an option"
            )
            raise ValueError(message)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin"),
        "HOME": os.environ.get("HOME", str(paths.directory)),
        "LANG": "C.UTF-8",
        **_identity_env(paths, runtime),
        # Inside the namespace there is no user or project config to ignore; out here there is.
        "AGENT_BROWSER_CONFIG": str(paths.config_file),
    }
    return [binary, "--json", *verb], environment


# -- results -------------------------------------------------------------------------------


def parse_response(text: str) -> dict[str, Any]:
    """Return the ``data`` of an agent-browser ``--json`` answer.

    Raises:
        AgentBrowserError: when the answer is not JSON, or reports a failure.

    """
    try:
        answer = json.loads(text)
    except json.JSONDecodeError as error:
        message = f"agent-browser answered with something other than JSON: {text[:200]!r}"
        raise AgentBrowserError(message) from error
    if not isinstance(answer, dict):
        message = f"unexpected answer from agent-browser: {text[:200]!r}"
        raise AgentBrowserError(message)
    if answer.get("success") is not True:
        raise AgentBrowserError(str(answer.get("error") or "agent-browser failed"))
    data = answer.get("data")
    return data if isinstance(data, dict) else {}


def parse_page(data: dict[str, Any]) -> Page:
    """Build a :class:`Page` from the data of ``open``."""
    return Page(url=str(data.get("url", "")), title=str(data.get("title", "")))


def parse_snapshot(data: dict[str, Any]) -> Snapshot:
    """Build a :class:`Snapshot` from the data of ``snapshot``."""
    refs = {
        str(name): Ref(role=str(info.get("role", "")), name=str(info.get("name", "")))
        for name, info in (data.get("refs") or {}).items()
    }
    return Snapshot(url=str(data.get("origin", "")), tree=str(data.get("snapshot", "")), refs=refs)


def _check_url(url: str) -> str:
    """Return ``url`` if it is an HTTP or HTTPS URL; raise ``ValueError`` otherwise."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        message = f"only http and https URLs can be opened, got {url!r}"
        raise ValueError(message)
    return url


def largest_candidate(srcset: str) -> str:
    """Return the address of the largest candidate in an ``srcset`` attribute.

    Each candidate is an address and, optionally, a width (``800w``) or density (``2x``). The
    biggest number wins, and the first of equals; with no numbers, the first. An address may hold
    a comma, so candidates end at a comma followed by white space or the end. Returns ``""`` for
    a value with no address.
    """
    best, size = "", -1.0
    for match in _SRCSET_CANDIDATE.finditer(srcset.strip()):
        address, number = match.group(1), float(match.group(2) or 0)
        if address and number > size:
            best, size = address, number
    return best.rstrip(",")


def _check_ref(ref: str) -> str:
    """Return ``ref`` as ``@eN``; raise ``ValueError`` if it is not a snapshot reference."""
    match = _REF.fullmatch(ref)
    if match is None:
        message = f"not a reference from a snapshot: {ref!r}"
        raise ValueError(message)
    return f"@{match.group(1)}"


# -- the session ---------------------------------------------------------------------------


class Session:
    """A running, contained browser for one site.

    Create it with :meth:`start`. Use it as a context manager, or call :meth:`close`.
    """

    def __init__(
        self, paths: SessionPaths, runtime: Path, binary: str, timeout: float, first: Page
    ) -> None:
        """Wrap a running holder; use :meth:`start` instead of calling this."""
        self.paths = paths
        self.first_page = first
        self._runtime = runtime
        self._binary = binary
        self._timeout = timeout
        self._holder: subprocess.Popen[bytes] | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._closed = False
        self._watch_browser = False

    @classmethod
    def start(  # noqa: PLR0913  # each argument is a distinct thing a caller decides
        cls,
        roots: sites.Roots,
        site: str,
        start_url: str,
        *,
        proxy_socket: Path | None = None,
        executable: str = DEFAULT_EXECUTABLE,
        binary: str = "agent-browser",
        timeout: float = DEFAULT_TIMEOUT,
        watch_browser: bool = False,
        allow_ptrace: bool = False,
    ) -> Self:
        """Start the browser for ``site`` and load ``start_url``.

        ``allow_ptrace`` leaves ``ptrace`` out of the syscall filter, for the tests that trace
        the browser with ``strace``. Nothing but a test passes it.

        With ``watch_browser``, :meth:`is_alive` also looks for the browser's own process once
        the first page has loaded, so a browser that was killed on its own counts as gone.

        ``proxy_socket`` defaults to ``session_paths(...).proxy_socket``. Only one session per
        site may run at a time, and the caller makes sure of it: any files an earlier,
        crashed session left are deleted.

        Raises:
            SessionError: when the browser does not come up (the message ends with the log).
            AgentBrowserError: when the first page fails to load.
            VersionError: when agent-browser is too old.

        """
        check_version(installed_version(binary))
        paths = session_paths(roots, site)
        if proxy_socket is not None:
            paths = replace(paths, proxy_socket=proxy_socket)
        binary_path = _resolve_binary(binary)
        runtime = sites.runtime_path(roots).parent
        chrome_major = sandbox.installed_chrome_major(executable)
        _prepare(roots, paths)
        open_command = launch_command(binary_path, paths, start_url, executable, chrome_major)
        script = holder_script(paths, binary_path, open_command, runtime)
        session = cls(paths, runtime, binary_path, timeout, Page(start_url, ""))
        box = sandbox.Sandbox(
            profile_dir=paths.profile_dir,
            writable_dirs=(paths.incoming_dir, paths.screenshots_dir),
            proxy_socket=paths.proxy_socket,
            log_file=paths.log_file,
            runtime_dir=runtime,
            shared_dir=paths.driver_dir,
            policy_dir=sandbox.write_chrome_policy(paths.directory / "chrome-policy"),
            allow_ptrace=allow_ptrace,
        )
        try:
            session._launch(box, ["/usr/bin/bash", "-c", script])
            session.first_page = parse_page(session._await_first_page())
            session._watch_browser = watch_browser
        except BaseException:
            session.close()
            raise
        return session

    # -- lifecycle --

    def _launch(self, box: sandbox.Sandbox, command: list[str]) -> None:
        started = threading.Event()
        failure: list[BaseException] = []

        def hold() -> None:
            try:
                self._holder = sandbox.start(box, command)
            except OSError as error:
                failure.append(error)
            finally:
                started.set()
            if self._holder is not None:
                self._holder.wait()

        self._thread = threading.Thread(target=hold, name=f"valetkey-{self.paths.site}")
        self._thread.start()
        started.wait()
        if failure:
            message = f"cannot start the sandbox: {failure[0]}"
            raise SessionError(message) from failure[0]

    def _await_first_page(self) -> dict[str, Any]:
        deadline = time.monotonic() + self._timeout
        while not self.paths.ready_file.exists():
            if not self.is_alive():
                message = f"the browser exited before it loaded a page\n{self._log_tail()}"
                raise SessionError(message)
            if time.monotonic() > deadline:
                message = f"no page after {self._timeout:g} seconds\n{self._log_tail()}"
                raise SessionError(message)
            time.sleep(0.05)
        return parse_response(self.paths.ready_file.read_text())

    def _log_tail(self) -> str:
        try:
            return self.paths.log_file.read_text(errors="replace")[-_LOG_TAIL:]
        except OSError:
            return ""

    def is_alive(self) -> bool:
        """Whether the session runs: the holder does and, when asked for, so does the browser.

        A killed daemon leaves its socket file behind, so the files say nothing; the processes
        do. When only Chrome is killed, the holder keeps running, so the browser is looked up in
        the host's process table by its profile directory.
        """
        if self._holder is None or self._holder.poll() is not None:
            return False
        return not self._watch_browser or (
            self._driver_answers()
            and procs.browser_running(self.paths.profile_dir, procs.command_lines())
        )

    def close(self) -> None:
        """End the session: close the browser, stop everything in the namespace, delete files.

        Safe to call again. The profile and downloads stay.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self.is_alive():
            with contextlib.suppress(AgentBrowserError, SessionError):
                self._call("close", timeout=15)
        self._stop_holder()
        if self._thread is not None:
            self._thread.join(10)
        shutil.rmtree(self.paths.driver_dir, ignore_errors=True)
        shutil.rmtree(self.paths.directory / "chrome-policy", ignore_errors=True)
        for leftover in (self.paths.log_file, self.paths.config_file):
            leftover.unlink(missing_ok=True)
        # The proxy's own directory goes only if the proxy is already gone from it.
        driver_root = self.paths.driver_dir.parent.parent
        for directory in (
            self.paths.proxy_socket.parent,
            self.paths.directory,
            self.paths.directory.parent,
            self.paths.driver_dir.parent,
            driver_root,
        ):
            with contextlib.suppress(OSError):
                directory.rmdir()

    def _stop_holder(self) -> None:
        holder = self._holder
        if holder is None or holder.poll() is not None:
            return
        holder.send_signal(signal.SIGTERM)
        try:
            holder.wait(STOP_GRACE)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait()

    def __enter__(self) -> Self:
        """Return the session; leaving the ``with`` block closes it."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the session."""
        self.close()

    # -- verbs --

    def _call(self, *verb: str, timeout: float | None = None) -> dict[str, Any]:
        if self._closed and verb[0] != "close":
            message = "the session is closed"
            raise SessionError(message)
        argv, environment = call_command(self._binary, self.paths, self._runtime, *verb)
        self._require_driver()
        filter_fd = seccomp.open_filter()
        argv = self._isolated(argv, environment, filter_fd)
        try:
            result = subprocess.run(  # noqa: S603  # built by call_command, no shell
                argv,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout or self._timeout,
                stdin=subprocess.DEVNULL,
                pass_fds=() if filter_fd is None else (filter_fd,),
            )
        except subprocess.TimeoutExpired as error:
            message = f"agent-browser {verb[0]} timed out"
            raise AgentBrowserError(message) from error
        finally:
            if filter_fd is not None:
                os.close(filter_fd)
        return parse_response(result.stdout or "{}")

    def _isolated(
        self, argv: list[str], environment: dict[str, str], seccomp_fd: int | None
    ) -> list[str]:
        """Wrap ``argv`` so that it runs without a network and ends with the call.

        :meth:`_require_driver` makes the sandbox's daemon the one this call talks to. If it
        stopped between that check and the call anyway, agent-browser would start a daemon and a
        browser of its own. Here they have no network, and nothing outlives the call.
        """
        return sandbox.isolated_call_argv(
            argv,
            environment,
            runtime_dir=self._runtime,
            driver_dir=self.paths.driver_dir,
            read_only=[Path(self._binary), self.paths.config_file],
            seccomp_fd=seccomp_fd,
        )

    def _require_driver(self) -> None:
        """Raise ``SessionError`` unless agent-browser's daemon in the sandbox answers.

        The sandbox can write the daemon's directory and kill the daemon. Without a daemon,
        the call below would start one on the host, and a browser with it, outside the sandbox
        and the proxy. So the call is made only when something is listening where the sandboxed
        daemon listens. The throwaway namespace of :meth:`_isolated` covers the moment between
        this check and the call.
        """
        if not self._driver_answers():
            message = "the browser's driver in the sandbox is gone; end the session and open again"
            raise SessionError(message)

    def _driver_answers(self) -> bool:
        path = self.paths.driver_dir / "run" / f"{SESSION_NAME}.sock"
        try:
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(PROBE_TIMEOUT)
                probe.connect(str(path))
        except OSError:
            return False
        return True

    def open(self, url: str) -> Page:
        """Navigate to an HTTP or HTTPS ``url``."""
        return parse_page(self._call("open", _check_url(url)))

    def snapshot(self) -> Snapshot:
        """Return the page's interactive elements, with references for ``click`` and ``fill``."""
        return parse_snapshot(self._call("snapshot", "-i"))

    def outline(self) -> str:
        """Return the whole accessibility tree as text: every node, with names and page text.

        The interactive snapshot leaves out plain text and headings. This one has them, so it
        answers "is this text on the page" and "did the page change at all".
        """
        return parse_snapshot(self._call("snapshot")).tree

    def click(self, ref: str) -> None:
        """Click the element ``ref`` (``e3`` or ``@e3``) from the latest snapshot."""
        self._call("click", _check_ref(ref))

    def fill(self, ref: str, text: str) -> None:
        """Replace the contents of the field ``ref`` with ``text``.

        agent-browser reads a word that looks like one of its own options as that option, even
        in the text to type (``--json`` is dropped, ``--session x`` changes the session, and
        ``--headed`` would relaunch the browser), and it has no ``--`` to end the options: it
        types the ``--`` itself. So text that starts with a dash is typed with a space in front,
        which no option starts with, and the space is then deleted from the start of the field.
        """
        target = _check_ref(ref)
        if not text.startswith("-"):
            self._call("fill", target, text)
            return
        self._call("fill", target, f" {text}")
        self._call("press", "Control+Home")
        self._call("press", "Delete")

    def password_fields(self) -> int:
        """Count the password fields on the page, visible or not.

        The accessibility tree does not say which text box is a password field, so this asks the
        browser to count ``input[type=password]``.
        """
        return int(self._call("get", "count", "input[type=password]").get("count") or 0)

    def clear_requests(self) -> None:
        """Forget the network requests logged so far, so the next count starts from here."""
        self._call("network", "requests", "--clear")

    def attachments(self) -> int:
        """Count the successful responses logged since the last clear that said ``attachment``.

        A response with ``Content-Disposition: attachment`` is one the browser turns into a
        download, whether or not a file then arrives. Only the headers are looked at.
        """
        logged = self._call("network", "requests").get("requests") or []
        count = 0
        for request in logged:
            headers = {
                str(k).lower(): str(v) for k, v in (request.get("responseHeaders") or {}).items()
            }
            disposition = headers.get("content-disposition", "").lstrip().lower()
            if (
                disposition.startswith("attachment")
                and HTTPStatus.OK <= int(request.get("status") or 0) < HTTPStatus.MULTIPLE_CHOICES
            ):
                count += 1
        return count

    def resource_url(self, ref: str) -> str:
        """Return the address that the element ``ref`` stands for, as the page wrote it.

        The first of ``srcset`` (its largest candidate), ``src``, ``href`` and ``poster`` that the
        element has. A picture's own address, a link's target, a video's source or its poster. It
        may be relative to the page.

        Raises:
            SessionError: when the element has none of them.

        """
        target = _check_ref(ref)
        for name in ("srcset", "src", "href", "poster"):
            value = self._call("get", "attr", target, name).get("value")
            if isinstance(value, str) and value.strip():
                address = largest_candidate(value) if name == "srcset" else value.strip()
                if address:
                    return address
        message = "that element has no address to save: no srcset, src, href or poster"
        raise SessionError(message)

    def images(self) -> list[dict[str, Any]]:
        """List the pictures and videos on the page, the biggest first, with their addresses.

        Each has a kind, an alt text, an address, a width and a height. Pictures under 50 by 50
        pixels, and addresses that are not HTTP or HTTPS, are left out. Everything in them came
        from the page, which can say anything in its own script, so the shape is checked here.
        """
        raw = self._call("eval", _IMAGES_SCRIPT.replace("LIMIT", str(MAX_IMAGES))).get("result")
        try:
            found = json.loads(raw) if isinstance(raw, str) else []
        except json.JSONDecodeError:
            return []
        if not isinstance(found, list):
            return []
        listed: list[dict[str, Any]] = []
        for item in found[:MAX_IMAGES]:
            if not isinstance(item, dict):
                continue
            url, alt = item.get("url"), item.get("alt")
            if not isinstance(url, str) or not url or len(url) > MAX_ADDRESS:
                continue
            numbers = [item.get("width"), item.get("height")]
            width, height = (
                n if isinstance(n, int) and not isinstance(n, bool) else 0 for n in numbers
            )
            kind = "video" if item.get("kind") == "video" else "image"
            listed.append(
                {
                    "kind": kind,
                    "alt": alt[:200] if isinstance(alt, str) else "",
                    "url": url,
                    "width": max(width, 0),
                    "height": max(height, 0),
                }
            )
        return listed

    def save(self, url: str) -> None:
        """Save what an HTTP or HTTPS address serves into the downloads folder.

        The address is opened in a tab of its own, so the page the person or the agent is on does
        not move, and fetched again from there, so it goes through the session's proxy with the
        session's cookies, and a host the site may not reach is refused as it is for navigation.
        The browser then writes it as it writes any download. An address that is an attachment is
        saved by the browser the moment the tab is opened. The tab is closed in the end, whatever
        happened, and the first one is active again.

        Raises:
            AgentBrowserError: when the browser cannot load the address, or the server does not
                answer 200, or the file is over :data:`SAVE_LIMIT`.
            ValueError: when ``url`` is not an HTTP or HTTPS address.

        """
        _check_url(url)
        known, active = self._tabs()
        try:
            try:
                self._call("tab", "new", url)
            except AgentBrowserError as error:
                if "ERR_ABORTED" not in str(error):
                    raise
                return  # the address is a download, which the browser has started by itself
            self._call("eval", _SAVE_SCRIPT.replace("LIMIT", str(SAVE_LIMIT)))
        finally:
            self._close_tabs_but(known, active)

    def _tabs(self) -> tuple[set[str], str | None]:
        """Return the ids of the open tabs and the id of the one in front."""
        tabs = self._call("tab", "list").get("tabs") or []
        ids = {str(tab["tabId"]) for tab in tabs if isinstance(tab, dict) and "tabId" in tab}
        front = next(
            (str(t["tabId"]) for t in tabs if isinstance(t, dict) and t.get("active")), None
        )
        return ids, front

    def _close_tabs_but(self, known: set[str], active: str | None) -> None:
        """Close every tab that was not in ``known``, and bring ``active`` to the front again."""
        with contextlib.suppress(AgentBrowserError, SessionError):
            ids, _ = self._tabs()
            for tab in sorted(ids - known):
                self._call("tab", "close", tab)
            if active is not None:
                self._call("tab", active)

    def press_enter(self) -> None:
        """Press Enter in the focused element, for example to submit the field just filled."""
        self._call("press", "Enter")

    def current_url(self) -> str:
        """Return the URL of the page."""
        return str(self._call("get", "url").get("url", ""))

    def screenshot(self, name: str = "screenshot.png") -> Path:
        """Save a PNG named ``name`` in the hidden screenshots directory and return its path."""
        if not _FILE_NAME.fullmatch(name):
            message = f"not a plain .png file name: {name!r}"
            raise ValueError(message)
        path = self.paths.screenshots_dir / name
        self._call("screenshot", str(path))
        return path


def _resolve_binary(binary: str) -> str:
    """Return the absolute path of ``binary``, which must be under ``/usr`` to run inside."""
    found = shutil.which(binary)
    if found is None:
        message = f"{binary} is not installed"
        raise SessionError(message)
    resolved = str(Path(found).resolve())
    if not resolved.startswith("/usr/"):
        message = f"{resolved} is outside /usr, which is all the sandbox can see of the system"
        raise SessionError(message)
    return resolved


def _prepare(roots: sites.Roots, paths: SessionPaths) -> None:
    """Create the directories a session needs and clear what an earlier session left.

    The proxy's directory is left alone: the proxy is already listening there.
    """
    shutil.rmtree(paths.driver_dir, ignore_errors=True)
    for leftover in (paths.log_file, paths.config_file):
        leftover.unlink(missing_ok=True)
    sites.ensure_runtime(roots)
    profiles.prepare(sites.ensure_profile(roots, paths.site))
    sites.ensure_downloads(roots, paths.site)
    _fresh_private_dir(paths.incoming_dir)
    paths.screenshots_dir.mkdir(mode=0o700, exist_ok=True)
    for directory in (paths.directory, paths.proxy_socket.parent, paths.driver_dir):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths.config_file.write_text("{}\n")


def _fresh_private_dir(path: Path) -> None:
    """Make ``path`` an empty directory, mode ``0700``, without following any link.

    What an earlier session left is removed: a directory with its contents (links inside it are
    removed, not followed), or a file or link in its place.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(path)
        else:
            path.unlink()
    path.mkdir(mode=0o700)
    path.chmod(0o700)
