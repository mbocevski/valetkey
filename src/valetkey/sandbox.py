# SPDX-License-Identifier: Apache-2.0
"""Run a browser inside a network namespace that has no way out except one unix socket.

Chrome flags do not contain a browser. With only ``--proxy-server`` set, WebRTC still reaches
STUN servers over UDP, plain DNS goes to the system resolver, mDNS goes out, and loopback
bypasses the proxy. A network namespace with no interfaces does contain it: anything that does
not go through the forwarder fails with ``ENETUNREACH``.

The namespace is built with bubblewrap. The forwarder (see ``valetkey.nsbridge``) listens on
loopback inside the namespace and connects to the proxy's unix socket, which crosses the
boundary because unix sockets are paths on disk.

The filesystem is as small as Chromium allows: read-only system directories, a private empty
runtime directory, a throwaway home, and read-write access to only the directories passed in.
The environment is cleared. Credentials sockets (SSH and GPG agents, the Docker socket, the
system D-Bus, the resolver) and the rest of the user's home do not exist inside.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import valetkey
from valetkey import sites

PROXY_ADDRESS = "127.0.0.1:3128"
"""Where the forwarder listens inside the namespace, and what the browser uses as its proxy."""

SANDBOX_HOME = "/home/valetkey"
"""The throwaway home directory inside the namespace (a tmpfs, empty at every start)."""

_SYSTEM_PATHS = ("/bin", "/sbin", "/lib", "/lib64")
"""Top-level paths that are symlinks into ``/usr`` on merged-usr systems."""

_ETC_ENTRIES = (
    "ld.so.cache",  # the dynamic linker finds Chromium's libraries through this
    "ld.so.conf",
    "ld.so.conf.d",
    "fonts",  # font configuration; without it every page renders with no fonts
    "ssl",  # CA bundle and OpenSSL config, for HTTPS through the proxy
    "ca-certificates",  # /etc/ssl/certs links into here
    "passwd",  # Chromium looks up the current user
    "group",
    "nsswitch.conf",
    "localtime",
    "os-release",
)
"""The parts of ``/etc`` Chromium and Python need. Nothing else is bound: no ``/etc/hosts``,
no resolver configuration, no machine ID, no user databases beyond passwd and group."""

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/{major}.0.0.0 Safari/537.36"
)
_VERSION = re.compile(r"\b(\d+)\.\d+\.\d+\.\d+\b")


def parse_chrome_major(version_output: str) -> int:
    """Return the major version in the output of ``chromium --version``.

    Raises ``ValueError`` when the output holds no version number.
    """
    match = _VERSION.search(version_output)
    if match is None:
        message = f"no version number in {version_output!r}"
        raise ValueError(message)
    return int(match.group(1))


def installed_chrome_major(executable: str = "chromium") -> int:
    """Run ``executable --version`` and return its major version."""
    result = subprocess.run(  # noqa: S603  # fixed argument list, executable is a program name
        [executable, "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return parse_chrome_major(result.stdout)


BACKGROUND_HOSTS = frozenset({"update.googleapis.com"})
"""Hosts Chrome still contacts at start-up whatever the flags say, so a proxy can treat them as
known noise rather than as hosts the page needs. ``update.googleapis.com`` is the component
updater asking for a foreground update; no flag or policy stops it. Every other background
request is stopped by the flags below and by :data:`CHROME_POLICY`, so a host that is refused
for a page is a host the page asked for."""

CHROME_POLICY = {"DefaultSearchProviderEnabled": False}
"""Chrome enterprise policy applied to every contained browser.

Without a default search engine Chrome stops contacting ``www.google.com`` on its own: the new
tab page's Google bar and doodle, and the check whether AI mode is available. No command-line
flag does this, and the requests used to look like a page that needs ``www.google.com``, which
reCAPTCHA does."""

_POLICY_DESTINATIONS = ("/etc/chromium/policies", "/etc/opt/chrome/policies")
"""Where Chromium and Google Chrome read policy from. Each reads only its own."""


def write_chrome_policy(directory: Path) -> Path:
    """Write :data:`CHROME_POLICY` under ``directory`` as ``managed/valetkey.json`` and return it.

    Pass the directory as ``Sandbox.policy_dir``.
    """
    managed = directory / "managed"
    managed.mkdir(parents=True, exist_ok=True)
    (managed / "valetkey.json").write_text(json.dumps(CHROME_POLICY) + "\n", encoding="utf-8")
    return directory


def chrome_flags(major: int) -> list[str]:
    """Return the Chrome command-line flags every contained browser starts with.

    ``major`` is the installed Chrome major version, which the user agent repeats so that
    headless Chrome does not announce itself as ``HeadlessChrome``.
    """
    return [
        f"--proxy-server=http://{PROXY_ADDRESS}",
        # Without this, Chrome skips the proxy for loopback. The namespace's own loopback
        # has nothing on it but the forwarder, so sending it through the proxy is harmless.
        "--proxy-bypass-list=<-loopback>",
        "--disable-background-networking",
        "--disable-component-update",
        "--enable-features=NavigationPredictorPreconnectHoldback",
        "--disable-sync",
        "--disable-default-apps",
        "--no-pings",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
        "--disable-breakpad",
        "--metrics-recording-only",
        "--no-service-autorun",
        "--disable-extensions",
        "--disable-search-engine-choice-screen",
        "--disable-component-extensions-with-background-pages",
        "--disable-features=NetworkTimeServiceQuerying,OptimizationHints,MediaRouter,Translate,PreconnectToSearch,SearchEnginePreconnect,NetworkPrediction,LoadingPredictor,PreconnectFromKeyedService,AutofillServerCommunication,SafeBrowsingHashPrefixRealTimeLookups,SafeBrowsingHashPrefixRealTimeLookupsSamplePing",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-session-crashed-bubble",
        "--hide-crash-restore-bubble",
        "--disable-blink-features=AutomationControlled",
        f"--user-agent={_USER_AGENT.format(major=major)}",
    ]


@dataclass(frozen=True, slots=True)
class Sandbox:
    """The directories one contained browser may touch.

    Every path is bound at the same location inside the namespace as outside, so a path
    that one side prints is valid for the other.
    """

    profile_dir: Path
    """Chrome's user data directory. Read-write."""
    downloads_dir: Path
    """Where downloads land. Read-write."""
    proxy_socket: Path
    """The proxy's unix socket. Its parent directory is bound read-write, so that directory
    should hold nothing else, and the socket may be recreated while the sandbox runs."""
    log_file: Path
    """Receives the output of everything started inside. The sandbox itself never sees it."""
    runtime_dir: Path
    """``$XDG_RUNTIME_DIR`` inside. Starts empty; nothing of the host's runtime directory
    (agent sockets, the session bus) is visible."""
    shared_dir: Path | None = None
    """A directory both sides use, such as the socket directory of the browser driver. Bound
    read-write. When it lies under ``runtime_dir`` it appears at the same path inside."""
    etc_entries: tuple[str, ...] = ()
    """Entries of ``/etc`` to bind read-only. Empty means ``default_etc_entries()``."""
    wayland_socket: Path | None = None
    """The compositor socket of a Wayland session, for a browser with a visible window. That
    one socket file is bound read-write (a socket needs both) at ``runtime_dir`` under its own
    name, and ``WAYLAND_DISPLAY`` is set to the name. Nothing else of the host's runtime
    directory appears. ``None`` means no display, which is what every headless session wants."""
    policy_dir: Path | None = None
    """A directory made by :func:`write_chrome_policy`. Bound read-only where the browser reads
    its policy from."""
    die_with_parent: bool = True
    """Kill the sandbox when the process that started it dies. See ``bwrap_argv``."""


def default_runtime_dir() -> Path:
    """Return the host's ``$XDG_RUNTIME_DIR``.

    The sandbox uses the same path for its private one, so a driver that finds its sockets
    under ``$XDG_RUNTIME_DIR`` looks in the same place on both sides.

    Raises:
        RuntimeDirUnavailableError: when ``XDG_RUNTIME_DIR`` is unset. There is no fallback,
            matching :func:`valetkey.sites.runtime_path`.

    """
    runtime = sites.roots_from_env().runtime
    if runtime is None:
        msg = "XDG_RUNTIME_DIR is not set; log in through a session that provides it"
        raise sites.RuntimeDirUnavailableError(msg)
    return runtime


def default_etc_entries(etc: Path = Path("/etc")) -> tuple[str, ...]:
    """Return the entries of ``_ETC_ENTRIES`` that exist under ``etc``."""
    return tuple(name for name in _ETC_ENTRIES if (etc / name).exists())


def python_roots() -> tuple[Path, ...]:
    """Return the directories outside ``/usr`` that the running interpreter needs.

    That is the virtualenv, the interpreter's own prefix when it is not a system one, and the
    directory holding the ``valetkey`` package, so that ``python -m valetkey.nsbridge`` runs
    inside the namespace.
    """
    package_root = Path(valetkey.__file__).resolve().parent.parent
    candidates = (Path(sys.prefix), Path(sys.base_prefix), package_root)
    roots: list[Path] = []
    for candidate in candidates:
        if candidate.is_relative_to("/usr") or candidate in roots:
            continue
        roots.append(candidate)
    return tuple(roots)


_MAX_LINKS = 20


def interpreter_link_args(
    executable: Path | None = None, bound: tuple[Path, ...] | None = None
) -> list[str]:
    """Return ``--symlink`` arguments for the links on the way to the interpreter.

    ``uv`` points a virtual environment at ``cpython-3.14-linux-…``, which is itself a link to
    ``cpython-3.14.9-linux-…``, and only the resolved directory is bound. Without the link
    recreated, the path in the environment dangles inside the namespace. Each link is recreated
    as a link, so nothing but the link itself becomes visible: no directory around it is bound.

    Links under ``/usr`` or inside a bound directory exist already and are skipped.
    ``executable`` defaults to ``sys.executable`` and ``bound`` to ``python_roots()``.
    """
    path = Path(sys.executable if executable is None else executable)
    roots = python_roots() if bound is None else bound
    args: list[str] = []
    seen: set[Path] = set()
    for _ in range(_MAX_LINKS):
        link = next((p for p in (*reversed(path.parents), path) if p.is_symlink()), None)
        if link is None:
            break
        target = link.readlink()
        inside = link.is_relative_to("/usr") or any(link.is_relative_to(r) for r in roots)
        if link not in seen and not inside:
            args += ["--symlink", str(target), str(link)]
            seen.add(link)
        path = Path(os.path.normpath(link.parent / target / path.relative_to(link)))
    return args


def system_link_args(root: Path = Path("/")) -> list[str]:
    """Return bwrap arguments that recreate ``/bin``, ``/lib`` and friends.

    On merged-usr systems these are symlinks into ``/usr`` and are recreated as symlinks;
    elsewhere they are real directories and are bound read-only.
    """
    args: list[str] = []
    for name in _SYSTEM_PATHS:
        path = root / name.lstrip("/")
        if path.is_symlink():
            args += ["--symlink", str(path.readlink()), name]
        elif path.is_dir():
            args += ["--ro-bind", name, name]
    return args


def bwrap_argv(
    sandbox: Sandbox,
    command: list[str],
    *,
    roots: tuple[Path, ...] | None = None,
    system_links: list[str] | None = None,
    interpreter_links: list[str] | None = None,
) -> list[str]:
    """Return the full ``bwrap`` command line that runs ``command`` inside the namespace.

    ``roots`` (default ``python_roots()``), ``system_links`` and ``interpreter_links`` (both
    default to what the host has) exist so tests can build the same line on any machine.

    The sandbox is a PID namespace: when the first command exits, bubblewrap kills everything
    else inside. So a session starts one long-lived command (a shell that runs the forwarder,
    then the browser driver) and the processes it starts, such as the driver's daemon, live
    exactly as long as it does. ``die_with_parent`` extends that to the starting process:
    if valetkey dies, the browser goes with it instead of lingering logged in. The kernel
    ties this to the thread that called ``Popen``, so start the sandbox from a thread that
    lives as long as the session.
    """
    etc_entries = sandbox.etc_entries or default_etc_entries()
    home = SANDBOX_HOME
    argv = ["bwrap", "--unshare-all", "--new-session", "--hostname", "valetkey"]
    if sandbox.die_with_parent:
        argv.append("--die-with-parent")
    argv += ["--ro-bind", "/usr", "/usr"]
    argv += system_links if system_links is not None else system_link_args()
    for name in etc_entries:
        argv += ["--ro-bind", f"/etc/{name}", f"/etc/{name}"]
    argv += ["--dev", "/dev", "--proc", "/proc"]
    # Every tmpfs comes before every bind below, so a bind under /tmp or the runtime
    # directory is not hidden by a later tmpfs.
    argv += ["--tmpfs", "/tmp"]  # noqa: S108  # path inside the namespace, not on the host
    argv += ["--tmpfs", str(sandbox.runtime_dir), "--tmpfs", home]
    python = python_roots() if roots is None else roots
    for root in python:
        argv += ["--ro-bind", str(root), str(root)]
    argv += (
        interpreter_links if interpreter_links is not None else interpreter_link_args(bound=python)
    )
    writable = [
        sandbox.profile_dir,
        sandbox.downloads_dir,
        sandbox.proxy_socket.parent,
        *([sandbox.shared_dir] if sandbox.shared_dir else []),
    ]
    for path in dict.fromkeys(writable):
        argv += ["--bind", str(path), str(path)]
    if sandbox.policy_dir is not None:
        for destination in _POLICY_DESTINATIONS:
            argv += ["--ro-bind", str(sandbox.policy_dir), destination]
    wayland_name = None
    if sandbox.wayland_socket is not None:
        wayland_name = sandbox.wayland_socket.name
        argv += ["--bind", str(sandbox.wayland_socket), str(sandbox.runtime_dir / wayland_name)]
    argv += ["--clearenv"]
    environment = {
        "PATH": "/usr/bin",
        "HOME": home,
        "XDG_RUNTIME_DIR": str(sandbox.runtime_dir),
        "LANG": "C.UTF-8",
    }
    if wayland_name is not None:
        environment["WAYLAND_DISPLAY"] = wayland_name
    for name, value in environment.items():
        argv += ["--setenv", name, value]
    argv += ["--chdir", home, *command]
    return argv


def start(sandbox: Sandbox, command: list[str]) -> subprocess.Popen[bytes]:
    """Start ``command`` inside the namespace and return the running ``Popen``.

    Output goes to ``sandbox.log_file``, never to a pipe: background processes inside inherit
    it, and a reader of a pipe would not see end-of-file until the last of them exits.
    """
    sandbox.log_file.parent.mkdir(parents=True, exist_ok=True)
    with sandbox.log_file.open("ab") as log:
        return subprocess.Popen(  # noqa: S603  # argument list, no shell
            bwrap_argv(sandbox, command),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )


def bridge_command(proxy_socket: Path) -> list[str]:
    """Return the command that runs the forwarder inside the namespace."""
    return [
        sys.executable,
        "-m",
        "valetkey.nsbridge",
        "--listen",
        PROXY_ADDRESS,
        "--connect",
        str(proxy_socket),
    ]
