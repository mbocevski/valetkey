# SPDX-License-Identifier: Apache-2.0
"""The ``valetkey`` command."""

import asyncio
import contextlib
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path  # the command-line framework reads the annotation at runtime
from typing import TYPE_CHECKING, Annotated, Any

from cyclopts import App, Parameter

from valetkey import (
    __version__,
    client,
    daemon,
    login,
    mcp_server,
    procs,
    sandbox,
    sessions,
    sites,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

app = App(
    name="valetkey",
    help="A logged-in browser for MCP clients, contained to the sites it may reach.",
    version=f"valetkey {__version__}",
    help_formatter="plain",
)


def _say(text: str) -> None:
    sys.stdout.write(f"{text}\n")


class CommandError(Exception):
    """A request valetkey refuses; the message is shown to the person."""


def _fail(error: CommandError) -> int:
    sys.stderr.write(f"valetkey: {error}\n")
    return 1


CONNECT_TIMEOUT = 1.0
"""Seconds to wait for a running daemon to accept a connection."""
ANSWER_TIMEOUT = 10.0
"""Seconds to wait for the daemon to answer a quick request such as ``reload_policy``."""
CLOSE_TIMEOUT = 60.0
"""Seconds to wait for the daemon to close a session, which ends a browser."""


def _ask_daemon(
    roots: sites.Roots, op: str, *, timeout: float | None = None, **args: str
) -> dict[str, Any] | None:
    """Ask the running daemon to do ``op`` and return its answer, or ``None`` if none is running.

    This never starts a daemon: it looks for the daemon's lock first (see
    :func:`valetkey.client.daemon_holds_lock`) and connects only when one holds it.

    Raises:
        DaemonError: when the daemon answers with an error, does not answer in time, or goes
            away in the middle of the request.

    """
    if roots.runtime is None:
        return None
    path = client.socket_path(roots)
    if not client.daemon_holds_lock(path):
        return None
    wait = ANSWER_TIMEOUT if timeout is None else timeout

    async def ask() -> dict[str, Any]:
        connection = await asyncio.wait_for(client.Client.connect(path), CONNECT_TIMEOUT)
        async with connection:
            return await asyncio.wait_for(connection.call(op, **args), wait)

    try:
        return asyncio.run(ask())
    except TimeoutError:
        message = f"valetkeyd did not answer within {wait:g} seconds"
        code = "timeout"
        raise client.DaemonError(code, message) from None
    except client.DaemonError as error:
        if error.code == "not_running":  # it ended between the lock and the connection
            return None
        raise


def save_and_reload(roots: sites.Roots, site: str, policy: sites.Policy | None) -> bool:
    """Save ``policy`` (when there is one), then tell a running daemon to read it again.

    Returns whether a live session of ``site`` now uses the saved policy. Anything that changes a
    site's policy by hand goes through here, so a running session follows at once. The file is
    saved before the daemon is asked, so a daemon that fails or does not answer is only a warning.
    """
    if policy is not None:
        sites.save_policy(roots, policy)
    try:
        reply = _ask_daemon(roots, "reload_policy", site=site)
    except client.DaemonError as error:
        sys.stderr.write(
            f"valetkey: {site}: the change is saved, but the running daemon did not apply it "
            f"({error.message}).\n"
        )
        return False
    return reply is not None and bool(reply.get("live"))


def _say_applied(site: str, *, applied: bool) -> None:
    if applied:
        _say(f"{site}: applied to the running session.")


def _known_sites(roots: sites.Roots) -> list[str]:
    """Return the names of the sites that have a policy file, sorted."""
    directory = sites.policy_path(roots, "x").parent
    names = [path.stem for path in directory.glob("*.json") if path.is_file()]
    return sorted(name for name in names if _valid_name(name))


def _valid_name(name: str) -> bool:
    try:
        sites.validate_site_name(name)
    except ValueError:
        return False
    return True


def _unknown_site(roots: sites.Roots, site: str) -> CommandError:
    known = _known_sites(roots)
    listing = ", ".join(known) if known else "none yet"
    return CommandError(f"no site named {site!r}. Known sites: {listing}")


def _load(roots: sites.Roots, site: str) -> sites.Policy:
    """Read the policy of ``site``, or raise a :class:`CommandError` that says what is wrong."""
    try:
        sites.validate_site_name(site)
    except ValueError as error:
        raise CommandError(str(error)) from error
    try:
        return sites.load_policy(roots, site)
    except FileNotFoundError as error:
        raise _unknown_site(roots, site) from error
    except sites.PolicyError as error:
        raise CommandError(str(error)) from error


def _host(value: str) -> str:
    try:
        return sites.host_of(value)
    except ValueError as error:
        raise CommandError(str(error)) from error


def _learned(policy: sites.Policy) -> str | None:
    return None if policy.learned is None else policy.learned.strftime("%Y-%m-%dT%H:%M:%SZ")


@app.command(name="sites")
def list_sites(
    *,
    as_json: Annotated[
        bool, Parameter(name="--json", negative="", help="Print a JSON array instead of a table.")
    ] = False,
) -> int:
    """List the sites valetkey knows.

    Each line shows the site name, the host it starts at, how many hosts are allowed and
    excluded, when the hosts were last learned, the private address ranges it may reach (a
    dash for none), and whether a login profile exists. With --json, each site is an object with
    the keys site, host, allowed, excluded, learned (a UTC time, or null), ``private_networks`` (a
    list) and profile (true or false).
    """
    roots = sites.roots_from_env()
    rows: list[dict[str, object]] = []
    for name in _known_sites(roots):
        try:
            policy = sites.load_policy(roots, name)
        except sites.PolicyError as error:
            sys.stderr.write(f"valetkey: skipping {name}: {error}\n")
            continue
        rows.append(
            {
                "site": name,
                "host": sites.host_of(policy.start),
                "allowed": len(policy.allow),
                "excluded": len(policy.excluded),
                "learned": _learned(policy),
                "private_networks": list(policy.private_networks),
                "profile": sites.profile_path(roots, name).is_dir(),
            }
        )
    if as_json:
        _say(json.dumps(rows, indent=2))
    elif not rows:
        _say("No sites yet.")
    else:
        _print_sites(rows)
    return 0


def _print_sites(rows: list[dict[str, object]]) -> None:
    body = [
        [
            str(row["site"]),
            str(row["host"]),
            str(row["allowed"]),
            str(row["excluded"]),
            str(row["learned"] or "never"),
            ", ".join(map(str, row["private_networks"] or ())) or "-",  # ty: ignore[invalid-argument-type]
            "yes" if row["profile"] else "no",
        ]
        for row in rows
    ]
    _print_table(["SITE", "HOST", "ALLOWED", "EXCLUDED", "LEARNED", "NETWORKS", "PROFILE"], body)


def _print_table(header: list[str], body: list[list[str]]) -> None:
    widths = [max(len(line[column]) for line in [header, *body]) for column in range(len(header))]
    for line in [header, *body]:
        _say(
            "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        )


PrivateNetwork = Annotated[
    str | None,
    Parameter(
        name="--private-network",
        help="A private address range such as 10.20.0.0/24, instead of a host.",
    ),
]


def _private_network_change(site: str, network: str, *, add: bool) -> int:
    """List (or remove) a private address range for ``site`` and say what happened."""
    roots = sites.roots_from_env()
    try:
        policy = _load(roots, site)
        try:
            changed, done = (sites.add_private_network if add else sites.remove_private_network)(
                policy, network
            )
        except ValueError as error:
            raise CommandError(str(error)) from error
    except CommandError as error:
        return _fail(error)
    applied = save_and_reload(roots, site, changed if done else None)
    name = sites.private_network(network)
    if add:
        _say(
            f"{site}: hosts it allows may now resolve inside {name}."
            if done
            else f"{site}: {name} was already listed."
        )
    else:
        _say(f"{site}: {name} is no longer listed." if done else f"{site}: {name} was not listed.")
    _say_applied(site, applied=applied)
    return 0


def _host_or_network(host: str | None, network: str | None) -> None:
    if (host is None) == (network is None):
        msg = "give a host, or --private-network and a range, but not both"
        raise CommandError(msg)


@app.command
def allow(site: str, host: str | None = None, *, network: PrivateNetwork = None) -> int:
    """Allow a host, and its subdomains, for a site.

    Any excluded entry that would block the host is removed. Allowing a host that is already
    listed changes nothing. With ``--private-network`` and a range such as ``10.20.0.0/24``
    instead of a host, the site's allowed hosts may also resolve to addresses in that range,
    which they otherwise may not because it is private. Use the narrowest range that holds the
    address. Only private ranges are accepted, none wider than /8 (IPv6: /48).

    Parameters
    ----------
    site
        The site name, as shown by ``valetkey sites``.
    host
        A host name, or a URL on it.
    network
        A private address range such as ``10.20.0.0/24``, instead of a host.

    """
    try:
        _host_or_network(host, network)
    except CommandError as error:
        return _fail(error)
    if network is not None:
        return _private_network_change(site, network, add=True)
    roots = sites.roots_from_env()
    try:
        policy = _load(roots, site)
        name = _host(str(host))
        changed, added, removed = sites.allow_host(policy, name)
        if not (added or removed):
            changed = None
    except CommandError as error:
        return _fail(error)
    applied = save_and_reload(roots, site, changed)
    _say(f"{site}: {name} is allowed." if added else f"{site}: {name} was already allowed.")
    if removed:
        _say(f"{site}: no longer excluding {', '.join(removed)}.")
    _say_applied(site, applied=applied)
    return 0


@app.command
def deny(site: str, host: str | None = None, *, network: PrivateNetwork = None) -> int:
    """Stop allowing a host for a site.

    The host's own entry is removed from the allowed hosts. If a wider allowed entry still
    covers the host (``app.example.com`` under ``example.com``), the host is also added to the
    excluded hosts, so it stays blocked. Otherwise nothing more is needed. With
    ``--private-network`` and a range instead of a host, the range is no longer listed.

    Parameters
    ----------
    site
        The site name, as shown by ``valetkey sites``.
    host
        A host name, or a URL on it.
    network
        A private address range such as ``10.20.0.0/24``, instead of a host.

    """
    try:
        _host_or_network(host, network)
    except CommandError as error:
        return _fail(error)
    if network is not None:
        return _private_network_change(site, network, add=False)
    roots = sites.roots_from_env()
    try:
        policy = _load(roots, site)
        name = _host(str(host))
        allowed = tuple(entry for entry in policy.allow if entry != name)
        covered = sites.host_matches(name, allowed)
        excluded = policy.excluded
        if covered and name not in excluded:
            excluded = (*excluded, name)
        changed = (
            replace(policy, allow=allowed, excluded=excluded)
            if allowed != policy.allow or excluded != policy.excluded
            else None
        )
    except CommandError as error:
        return _fail(error)
    applied = save_and_reload(roots, site, changed)
    removed = allowed != policy.allow
    if removed:
        _say(f"{site}: {name} is no longer allowed.")
    if covered:
        _say(f"{site}: a wider allowed entry still covers {name}, so it is now excluded.")
    if not removed and not covered:
        _say(f"{site}: {name} was not allowed. Nothing changed.")
    _say_applied(site, applied=applied)
    return 0


_command_lines = procs.command_lines


def _profile_in_use(profile: Path) -> bool:
    """Tell whether a running process has ``profile`` in its arguments.

    Browsers run in their own sandbox and process namespace, so Chromium's lock file names a
    process number that means nothing here. The host's process table does show them. An argument
    counts when it, or the part after ``=``, resolves to the profile directory, as in
    ``--user-data-dir=PATH``.
    """
    return any(procs.uses_path(arguments, profile) for arguments in _command_lines())


def _forget_targets(roots: sites.Roots, site: str) -> list[Path]:
    """Return what exists of ``site``'s files, and refuse a directory that is not a real one.

    A directory that is a symlink, or that sits inside one, could lead outside valetkey's own
    directories, so nothing is deleted when one is found.
    """
    found: list[Path] = []
    for path in (sites.profile_path(roots, site), sites.downloads_path(roots, site)):
        if path.parent.is_symlink() or path.is_symlink():
            message = f"{path} is a symlink; not deleting through it"
            raise CommandError(message)
        if path.exists():
            found.append(path)
    policy = sites.policy_path(roots, site)
    if policy.parent.is_symlink():
        message = f"{policy.parent} is a symlink; not deleting through it"
        raise CommandError(message)
    if policy.exists() or policy.is_symlink():
        found.append(policy)
    return found


def _daemon_state(roots: sites.Roots, site: str) -> str | None:
    """Return what a running daemon is doing for ``site`` (``idle``, ``login`` or ``session``).

    ``None`` means no daemon is running, so the process table is the only guard.
    """
    try:
        reply = _ask_daemon(roots, "sites")
    except client.DaemonError as error:
        message = f"could not ask the running daemon about {site}: {error.message}"
        raise CommandError(message) from error
    if reply is None:
        return None
    entry = next((e for e in reply.get("sites", []) if e.get("site") == site), None)
    return str(entry["state"]) if entry else "idle"


def _close_session(roots: sites.Roots, site: str) -> None:
    try:
        _ask_daemon(roots, "close", timeout=CLOSE_TIMEOUT, site=site)
    except client.DaemonError as error:
        message = f"could not close the {site} session: {error.message}"
        raise CommandError(message) from error


def _forget_checks(roots: sites.Roots, site: str, *, yes: bool) -> list[Path] | None:
    """Return what to delete for ``site``, or None when the person declines."""
    try:
        sites.validate_site_name(site)
    except ValueError as error:
        message = str(error)
        raise CommandError(message) from error
    targets = _forget_targets(roots, site)
    if not targets:
        raise _unknown_site(roots, site)
    state = _daemon_state(roots, site)
    if state == "login":
        message = f"a login window for {site} is open; close it first"
        raise CommandError(message)
    profile = sites.profile_path(roots, site)
    if state != "session" and _profile_in_use(profile):
        message = f"the browser for {site} is open; close that session first"
        raise CommandError(message)
    if not yes and not _confirmed(site):
        return None
    if state == "session":
        _close_session(roots, site)
        if _profile_in_use(profile):
            message = (
                f"a browser outside valetkey's daemon is still using {site}'s profile; "
                "close it first"
            )
            raise CommandError(message)
    return targets


def _confirmed(site: str) -> bool:
    if not sys.stdin.isatty():
        message = "input is not a terminal; add --yes to forget without asking"
        raise CommandError(message)
    prompt = f"Forget {site}? This deletes its login, policy and downloads. [y/N] "
    return input(prompt).strip().lower() in {"y", "yes"}


@app.command
def forget(site: str, *, yes: Annotated[bool, Parameter(name="--yes", negative="")] = False) -> int:
    """Delete a site's policy, login profile and downloads.

    It asks first, and refuses when input is not a terminal unless --yes is given. If valetkeyd
    is running it closes the site's session before deleting. It refuses while a login window is
    open, and while a browser that valetkeyd does not own is using the profile.

    Parameters
    ----------
    site
        The site name, as shown by ``valetkey sites``.
    yes
        Delete without asking.

    """
    roots = sites.roots_from_env()
    try:
        targets = _forget_checks(roots, site, yes=yes)
    except CommandError as error:
        return _fail(error)
    if targets is None:
        _say("Nothing was deleted.")
        return 1
    for path in targets:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
    _say(f"Forgot {site}.")
    return 0


@app.command(name="mcp")
def run_mcp() -> int:
    """Serve the browser tools to an MCP client over standard input and output.

    Point an MCP client at this command. It starts valetkeyd if that is not running yet.
    """
    mcp_server.serve()
    return 0


@app.command(name="daemon")
def run_daemon(
    *, socket: Annotated[Path | None, Parameter(help="Listen on this socket path.")] = None
) -> int:
    """Run the valetkeyd daemon in the foreground.

    It owns every session for the user. It listens on a Unix socket in the runtime directory
    until it gets SIGTERM or SIGINT.
    Under systemd socket activation it uses the socket systemd passes in.
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="valetkeyd: %(message)s")
    try:
        server = daemon.Daemon(sites.roots_from_env())
        return asyncio.run(daemon.run(server, socket))
    except (daemon.AlreadyRunningError, sites.RuntimeDirUnavailableError) as error:
        sys.stderr.write(f"valetkeyd: {error}\n")
        return 1


# -- systemd units -------------------------------------------------------------------------

UNIT_NAMES = ("valetkeyd.socket", "valetkeyd.service")
UNIT_MARKER = "# Written by `valetkey install-units`."
"""The first words of every unit file valetkey writes. A file without them is not valetkey's."""
EXECUTABLE_PLACEHOLDER = "@EXECUTABLE@"
SOCKET_UNIT = "valetkeyd.socket"
SYSTEM_UNIT_DIRS = (Path("/etc/systemd/user"), Path("/usr/lib/systemd/user"))
"""Where a package puts the units. Files in the person's own directory take precedence."""
NEXT_COMMANDS = (
    "systemctl --user daemon-reload",
    f"systemctl --user enable --now {SOCKET_UNIT}",
)


def unit_template(name: str) -> str:
    """Return the text of the packaged unit file ``name``, placeholders included."""
    return resources.files("valetkey").joinpath("units", name).read_text(encoding="utf-8")


def exec_start_word(path: str) -> str:
    """Quote ``path`` for a systemd ``ExecStart=`` line.

    systemd expands ``%`` and ``$`` and splits on spaces, so those are doubled or quoted. A
    path with a newline cannot be written at all.
    """
    if "\n" in path or "\0" in path:
        message = f"cannot write {path!r} into a unit file"
        raise CommandError(message)
    word = path.replace("%", "%%").replace("$", "$$")
    if any(c in word for c in " \t\"'\\"):
        word = '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return word


def render_unit(name: str, executable: str) -> str:
    """Return the unit file ``name`` with ``executable`` filled in."""
    return unit_template(name).replace(EXECUTABLE_PLACEHOLDER, exec_start_word(executable))


def is_ours(path: Path) -> bool:
    """Tell whether ``path`` is a unit file that ``install-units`` wrote."""
    try:
        return path.read_text(encoding="utf-8").startswith(UNIT_MARKER)
    except OSError, UnicodeDecodeError:
        return False


def unit_directory(roots: sites.Roots) -> Path:
    """Return the directory of the person's systemd user units."""
    return roots.config / "systemd" / "user"


def valetkey_executable(which: Callable[[str], str | None] = shutil.which) -> str:
    """Return the absolute path of the ``valetkey`` program, as found on ``PATH``.

    The path is not resolved further, so a ``uv tool`` link in ``~/.local/bin`` keeps working
    after the tool is upgraded.
    """
    found = which("valetkey")
    if found is None:
        message = "valetkey is not on PATH; install it with `uv tool install valetkey` first"
        raise CommandError(message)
    return str(Path(found).absolute())


def plan_units(directory: Path, executable: str, *, force: bool) -> dict[str, str]:
    """Return the text of each unit file to write, or refuse to replace a file that is not ours."""
    files = {name: render_unit(name, executable) for name in UNIT_NAMES}
    foreign = [
        str(directory / name)
        for name in UNIT_NAMES
        if (directory / name).exists() and not is_ours(directory / name) and not force
    ]
    if foreign:
        message = (
            f"{', '.join(foreign)} exist and valetkey did not write them; "
            "use --force to replace them"
        )
        raise CommandError(message)
    return files


@app.command
def install_units(
    *,
    dry_run: Annotated[
        bool,
        Parameter(name="--dry-run", negative="", help="Print the files instead of writing them."),
    ] = False,
    force: Annotated[
        bool,
        Parameter(name="--force", negative="", help="Replace files that valetkey did not write."),
    ] = False,
) -> int:
    """Write the systemd user units that run the valetkey daemon.

    The units go to the systemd user directory (``$XDG_CONFIG_HOME/systemd/user``). The command
    refuses to replace a file it did not write, and prints the commands that start the
    socket. It never runs them.
    """
    directory = unit_directory(sites.roots_from_env())
    try:
        files = plan_units(directory, valetkey_executable(), force=force)
    except CommandError as error:
        return _fail(error)
    if dry_run:
        for name, text in files.items():
            _say(f"Would write {directory / name}:\n\n{text}")
        _say("Nothing was written.")
        return 0
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
        _say(f"Wrote {directory / name}")
    packaged = next(
        (d for d in SYSTEM_UNIT_DIRS if all((d / name).is_file() for name in UNIT_NAMES)), None
    )
    if packaged is not None:
        _say(f"\nNote: the units in {packaged} are replaced by these copies.")
    _say("\nTo start the daemon, run:\n")
    for command in NEXT_COMMANDS:
        _say(f"    {command}")
    return 0


# -- doctor --------------------------------------------------------------------------------


LABELS = {"ok": "ok", "fail": "FAIL", "warn": "warn", "info": "info"}


@dataclass(frozen=True, slots=True)
class Check:
    """The result of one check: ``status`` is ``ok``, ``fail``, ``warn`` or ``info``."""

    name: str
    status: str
    detail: str


def _run(args: Sequence[str]) -> tuple[int, str]:
    """Run ``args`` and return its exit status and its combined output (-1 if it did not run)."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argument lists, no shell
            list(args), capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as error:
        return -1, str(error)
    return result.returncode, result.stdout + result.stderr


@dataclass(frozen=True, slots=True)
class System:
    """Everything ``doctor`` asks the machine, so tests can answer instead."""

    which: Callable[[str], str | None] = shutil.which
    run: Callable[[Sequence[str]], tuple[int, str]] = _run
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    wayland: Callable[[], Path] = login.find_wayland_socket
    unit_dirs: tuple[Path, ...] = field(
        default_factory=lambda: (unit_directory(sites.roots_from_env()), *SYSTEM_UNIT_DIRS)
    )


def _last_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[-1] if lines else "no output"


def _tool_version(system: System, tool: str) -> tuple[str | None, str]:
    """Return the path of ``tool`` and its ``--version`` output."""
    path = system.which(tool)
    if path is None:
        return None, ""
    return path, system.run([path, "--version"])[1]


def check_bwrap(system: System) -> list[Check]:
    """Check that bubblewrap is installed and that it can make the namespaces valetkey needs."""
    path, output = _tool_version(system, "bwrap")
    if path is None:
        missing = "bwrap not found; install bubblewrap"
        return [Check("bwrap", "fail", missing), Check("namespaces", "fail", "bwrap is missing")]
    words = output.split()
    version = words[-1] if words else "version unknown"
    probe = [
        path,
        "--unshare-all",
        "--ro-bind",
        "/usr",
        "/usr",
        *sandbox.system_link_args(),
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "/usr/bin/true",
    ]
    status, text = system.run(probe)
    if status == 0:
        namespaces = Check("namespaces", "ok", "unprivileged user namespaces work")
    else:
        detail = f"bwrap cannot make a sandbox: {_last_line(text)}"
        namespaces = Check("namespaces", "fail", detail)
    return [Check("bwrap", "ok", f"bwrap {version}"), namespaces]


def check_chromium(system: System) -> Check:
    """Check that Chromium is installed and report its major version."""
    path, output = _tool_version(system, "chromium")
    if path is None:
        return Check("chromium", "fail", "chromium not found")
    try:
        major = sandbox.parse_chrome_major(output)
    except ValueError:
        return Check("chromium", "fail", f"cannot read the version of {path}")
    return Check("chromium", "ok", f"chromium {major}")


def check_agent_browser(system: System) -> Check:
    """Check that agent-browser is installed and new enough; warn when it is newer than tested."""
    path, output = _tool_version(system, "agent-browser")
    if path is None:
        return Check("agent-browser", "fail", "agent-browser not found")
    try:
        version = sessions.parse_version(output)
        sessions.check_version(version, warn=False)
    except ValueError:
        return Check("agent-browser", "fail", f"cannot read the version of {path}")
    except sessions.VersionError as error:
        return Check("agent-browser", "fail", str(error))
    text = sessions.version_text(version)
    if sessions.is_untested(version):
        tested = sessions.version_text(sessions.TESTED_VERSION)
        detail = (
            f"agent-browser {text} is newer than {tested}, the version valetkey was tested with"
        )
        return Check("agent-browser", "warn", detail)
    return Check("agent-browser", "ok", f"agent-browser {text}")


def check_runtime_dir(system: System) -> Check:
    """Check that ``XDG_RUNTIME_DIR`` is set, which the daemon and its sockets need."""
    value = system.environ.get("XDG_RUNTIME_DIR", "")
    if value and Path(value).is_absolute():
        return Check("runtime-dir", "ok", f"XDG_RUNTIME_DIR={value}")
    return Check("runtime-dir", "fail", "XDG_RUNTIME_DIR is not set to an absolute path")


def check_display(system: System) -> Check:
    """Look for a Wayland display; only logging in needs one, so a miss is a warning."""
    try:
        socket = system.wayland()
    except login.DisplayError as error:
        return Check("display", "warn", f"no Wayland display ({error}); logging in needs one")
    return Check("display", "ok", f"Wayland display {socket}")


def check_units(system: System) -> list[Check]:
    """Report, without judging, whether the units are installed and the socket is active.

    ``systemctl is-active`` exits 0 for active, 3 for any other state and 4 for an unknown unit.
    Any other status means it could not ask the user manager.
    """
    found = next(
        (d for d in system.unit_dirs if all((d / name).is_file() for name in UNIT_NAMES)), None
    )
    if found is None:
        installed = Check(
            "units", "info", "systemd units not installed; run `valetkey install-units`"
        )
    else:
        installed = Check("units", "info", f"systemd units installed in {found}")
    status, output = system.run(["systemctl", "--user", "is-active", SOCKET_UNIT])
    if status not in (0, 3, 4) or not output.strip():
        detail = "systemd user session not reachable"
    else:
        detail = f"{SOCKET_UNIT} is {_last_line(output)}"
    return [installed, Check("socket", "info", detail)]


def run_checks(system: System) -> list[Check]:
    """Run every check and return the results in the order they are shown."""
    return [
        *check_bwrap(system),
        check_chromium(system),
        check_agent_browser(system),
        check_runtime_dir(system),
        check_display(system),
        *check_units(system),
    ]


@app.command
def doctor(
    *,
    as_json: Annotated[
        bool, Parameter(name="--json", negative="", help="Print a JSON array instead of lines.")
    ] = False,
) -> int:
    """Check that this machine can run valetkey.

    Each check prints one line: ok, FAIL, warn or info. Required checks are bubblewrap and
    user namespaces, Chromium, agent-browser 0.39 or newer, and XDG_RUNTIME_DIR. A missing
    Wayland display is a warning, because only logging in needs one, and so is an agent-browser
    newer than 0.39.2, the version valetkey was tested with. The state of the systemd units is
    shown for information. The exit status is 1 when a required check fails. With
    --json, each check is an object with the keys check, status (ok, fail, warn or info) and
    detail.
    """
    checks = run_checks(System())
    if as_json:
        rows = [{"check": c.name, "status": c.status, "detail": c.detail} for c in checks]
        _say(json.dumps(rows, indent=2))
    else:
        for check in checks:
            _say(f"{LABELS[check.status]:<6}{check.detail}")
    return 1 if any(c.status == "fail" for c in checks) else 0


# -- what is running ---------------------------------------------------------------------


async def _daemon_status() -> dict[str, Any]:
    """Ask the running daemon what is open. It is never started for this."""
    async with await client.Client.connect() as connection:
        return await connection.call("status")


def _activity_rows(activity: dict[str, Any]) -> list[list[str]]:
    return [
        [kind, entry["site"], entry["since"] or "-", entry.get("host") or "-"]
        for kind, key in (("session", "sessions"), ("login", "logins"))
        for entry in activity.get(key, [])
    ]


@app.command(name="status")
def show_status(
    *,
    as_json: Annotated[
        bool, Parameter(name="--json", negative="", help="Print JSON instead of a table.")
    ] = False,
) -> int:
    """Show the browser sessions and login windows that are open.

    The daemon reports what its own processes are doing, and nothing can hide a session from
    it. A browser that was killed disappears within a second or two. The daemon is not started:
    when none runs, this says so and exits 0.

    With --json the output is an object with two lists. "sessions" holds objects with the keys
    site, since, contained and host. "logins" holds objects with the keys site and since. since is
    a UTC time like 2026-10-26T09:00:00Z. contained is always true. host is the host of the page
    the browser was last reported at, never the whole address, which may carry a token.
    """
    try:
        activity = asyncio.run(_daemon_status())
    except client.DaemonError as error:
        if error.code == "not_running":
            _say("valetkeyd is not running")
            return 0
        return _fail(CommandError(error.message))
    except sites.RuntimeDirUnavailableError as error:
        return _fail(CommandError(str(error)))
    if as_json:
        _say(json.dumps(activity, indent=2))
        return 0
    rows = _activity_rows(activity)
    if not rows:
        _say("No browser sessions or login windows are open.")
        return 0
    _print_table(["KIND", "SITE", "SINCE", "HOST"], rows)
    return 0


async def _watch_daemon() -> int:
    try:
        connection = await client.Client.connect()
    except client.DaemonError as error:
        return _fail(CommandError(error.message))
    async with connection:
        try:
            async for event in connection.watch():
                _say(json.dumps(event, separators=(",", ":")))
                sys.stdout.flush()
        except client.DaemonError as error:
            if error.code != "connection_lost":
                return _fail(CommandError(error.message))
    return 0


@app.command
def watch() -> int:
    """Print one JSON line for every change to the sessions and login windows.

    The first line is a snapshot of what is open, as `status --json` shows it, with "event" set
    to "snapshot" and an "at" time. After that each line has the keys event, site and at, where
    event is session_started, session_ended, login_opened or login_closed. Bars and indicators
    can read the lines as they come. The command runs until it is interrupted or the daemon
    stops; it exits 1 when no daemon is running, and does not start one.
    """
    try:
        return asyncio.run(_watch_daemon())
    except KeyboardInterrupt:
        return 0
    except sites.RuntimeDirUnavailableError as error:
        return _fail(CommandError(str(error)))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command named in ``argv`` (default: ``sys.argv``) and return its exit status.

    Usage errors exit with status 2 after printing the error.
    """
    tokens = sys.argv[1:] if argv is None else argv
    status = app(tokens, result_action="return_int_as_exit_code_else_zero")
    return int(status)
