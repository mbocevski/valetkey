# SPDX-License-Identifier: Apache-2.0
"""The ``valetkey`` command."""

import asyncio
import contextlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path  # the command-line framework reads the annotation at runtime
from typing import TYPE_CHECKING, Annotated, Any

from cyclopts import App, Parameter

from valetkey import (
    __version__,
    approvals,
    client,
    daemon,
    display,
    login,
    mcp_server,
    procs,
    sandbox,
    seccomp,
    sessions,
    sites,
)
from valetkey import (
    bridge as bridging,
)
from valetkey.wayland import MANAGER, WaylandError, compositor_globals

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
    """Return the names of the sites and accounts that have a policy file, sorted."""
    return sites.known_sites(roots)


def _unknown_site(roots: sites.Roots, site: str) -> CommandError:
    known = _known_sites(roots)
    listing = ", ".join(known) if known else "none yet"
    return CommandError(f"no site named {site!r}. Known sites: {listing}")


def _resolve(roots: sites.Roots, site: str) -> str:
    """Return the account ``site`` names, or raise a :class:`CommandError` that says why not.

    A name without an account is the account of a site that has just one, and is refused for a
    site that has several (see :func:`valetkey.sites.resolve_account`).
    """
    try:
        return sites.resolve_account(roots, site)
    except ValueError as error:
        raise CommandError(str(error)) from error


def _load(roots: sites.Roots, site: str) -> sites.Policy:
    """Read the policy of ``site``, or raise a :class:`CommandError` that says what is wrong.

    The policy's own ``site`` is the account that was meant, which is what to save and print.
    """
    name = _resolve(roots, site)
    try:
        return sites.load_policy(roots, name)
    except FileNotFoundError as error:
        raise _unknown_site(roots, name) from error
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

    Each line shows the site name, the host it starts at, how many hosts are allowed, excluded
    by a login and denied by you, when the hosts were last learned, the private address ranges it
    may reach (a dash for none), and whether a login profile exists. With --json, each site is an
    object with the keys site, account (the part after the colon of ``sitex:work``, or null),
    host, allowed, excluded, denied, learned (a UTC time, or null), ``private_networks`` (a list)
    and profile (true or false). A site with several accounts has a line for each.
    """
    roots = sites.roots_from_env()
    rows: list[dict[str, object]] = []
    found = _known_sites(roots)
    for name in found:
        try:
            policy = sites.load_policy(roots, name)
        except sites.PolicyError as error:
            sys.stderr.write(f"valetkey: skipping {name}: {error}\n")
            continue
        shown = sites.listed_name(name, found)
        rows.append(
            {
                "site": shown,
                "account": shown.partition(sites.ACCOUNT_SEPARATOR)[2] or None,
                "host": sites.host_of(policy.start),
                "allowed": len(policy.allow),
                "excluded": len(policy.excluded),
                "denied": len(policy.denied),
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
            str(row["denied"]),
            str(row["learned"] or "never"),
            ", ".join(map(str, row["private_networks"] or ())) or "-",  # ty: ignore[invalid-argument-type]
            "yes" if row["profile"] else "no",
        ]
        for row in rows
    ]
    _print_table(
        ["SITE", "HOST", "ALLOWED", "EXCLUDED", "DENIED", "LEARNED", "NETWORKS", "PROFILE"], body
    )


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


PrivateNetworks = Annotated[
    list[str] | None,
    Parameter(
        name="--private-network",
        negative_iterable="",
        help="A private address range the site may reach, such as 10.20.0.0/24. Repeat it.",
    ),
]


Force = Annotated[bool, Parameter(negative="", help="Replace the policy of an existing site.")]


CopyHosts = Annotated[
    str | None,
    Parameter(
        name="--copy-hosts-from",
        help="Start with the host lists of this other account of the site.",
    ),
]


@app.command
def add(
    site: str,
    start: str,
    *,
    network: PrivateNetworks = None,
    copy_hosts_from: CopyHosts = None,
    force: Force = False,
) -> int:
    """Create a site or another account of one before its first login.

    A site is normally created by logging in. A site whose host resolves to a private address
    cannot be logged in to that way, because the login proxy refuses private addresses unless
    the person lists their range. This writes the site's policy with its start URL, its start
    host and the ranges, and nothing else; then log in to it. Only you can do this: a client
    cannot create a site or list a range. It refuses a site that already exists, unless
    ``--force``, which replaces the policy and keeps the login profile.

    A site can have more than one account, each with its own login, policy and downloads. Name
    one ``sitex:work``. With ``--copy-hosts-from`` the new account starts with the allowed,
    excluded and denied hosts of another account of the site, and with nothing else of it: not
    its private ranges, which are a permission of their own, and not what its login learned.

    Parameters
    ----------
    site
        The new site's name, with an account after a colon for another account of a site
        (``sitex:work``): lowercase letters, digits and hyphens. An account starts with a letter.
    start
        The URL the login starts at.
    network
        A private address range such as ``10.20.0.0/24``. Repeat it for more.
    copy_hosts_from
        An existing account of the site whose host lists to start with.
    force
        Replace the policy of an existing site.

    """
    roots = sites.roots_from_env()
    try:
        policy = _new_site(roots, site, start, network or [], copy_hosts_from, force=force)
    except CommandError as error:
        return _fail(error)
    applied = save_and_reload(roots, site, policy)
    _say(f"{site}: added, starting at {policy.start}.")
    if copy_hosts_from:
        _say(
            f"{site}: copied {len(policy.allow) - 1} allowed and "
            f"{len(policy.excluded) + len(policy.denied)} left-out hosts from {copy_hosts_from}."
        )
    for entry in policy.private_networks:
        _say(f"{site}: hosts it allows may resolve inside {entry}.")
    _say(f"{site}: now ask your client to log in to {site}.")
    _say_applied(site, applied=applied)
    return 0


def _new_site(  # noqa: PLR0913 - one thing each: the name, the start, the ranges, the copy
    roots: sites.Roots,
    site: str,
    start_url: str,
    networks: list[str],
    copy_from: str | None,
    *,
    force: bool,
) -> sites.Policy:
    """Build the policy ``valetkey add`` writes, or raise ``CommandError``."""
    try:
        sites.validate_site_name(site)
        start = login.normalize_start_url(start_url)
        listed = tuple(dict.fromkeys(sites.private_network(entry) for entry in networks))
        host = sites.host_of(start)
    except ValueError as error:
        raise CommandError(str(error)) from error
    allow, excluded, denied = (host,), (), ()
    if copy_from is not None:
        source = _load(roots, copy_from)
        allow = tuple(dict.fromkeys((host, *source.allow)))
        excluded = tuple(e for e in source.excluded if not sites.excluded_conflicts(e, allow))
        denied = tuple(e for e in source.denied if not sites.excluded_conflicts(e, allow))
    policy = sites.Policy(site, start, allow, excluded, private_networks=listed, denied=denied)
    taken = sites.policy_path(roots, site).exists() or sites.profile_path(roots, site).exists()
    if taken and not force:
        msg = (
            f"{site} already exists. To change it, use `valetkey allow` and `valetkey deny`; "
            "`--force` replaces its policy."
        )
        raise CommandError(msg)
    return policy


def _private_network_change(site: str, network: str, *, add: bool) -> int:
    """List (or remove) a private address range for ``site`` and say what happened."""
    roots = sites.roots_from_env()
    try:
        policy = _load(roots, site)
        site = policy.site
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
        The site name, as shown by ``valetkey sites``, with its account (``sitex:work``) when
        the site has more than one.
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
        site = policy.site
        name = _host(str(host))
        changed, added, removed = sites.allow_host(policy, name)
        if not (added or removed):
            changed = None
    except CommandError as error:
        return _fail(error)
    applied = save_and_reload(roots, site, changed)
    _say(f"{site}: {name} is allowed." if added else f"{site}: {name} was already allowed.")
    if removed:
        _say(f"{site}: no longer excluding or denying {', '.join(removed)}.")
    _say_applied(site, applied=applied)
    return 0


@app.command
def deny(site: str, host: str | None = None, *, network: PrivateNetwork = None) -> int:
    """Stop allowing a host for a site, and keep it blocked.

    The host's own entry is removed from the allowed hosts and the host is added to the denied
    hosts, which block it even under a wider allowed entry (``app.example.com`` under
    ``example.com``). A login never allows a denied host again; ``valetkey allow`` does. With
    ``--private-network`` and a range instead of a host, the range is no longer listed.

    Parameters
    ----------
    site
        The site name, as shown by ``valetkey sites``, with its account (``sitex:work``) when
        the site has more than one.
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
        site = policy.site
        name = _host(str(host))
        denied_policy = sites.deny_host(policy, name)
        allowed, denied = denied_policy.allow, denied_policy.denied
        changed = denied_policy if denied_policy != policy else None
    except CommandError as error:
        return _fail(error)
    applied = save_and_reload(roots, site, changed)
    if allowed != policy.allow:
        _say(f"{site}: {name} is no longer allowed.")
    if denied != policy.denied:
        _say(f"{site}: {name} is denied, so a login will not allow it again.")
    if changed is None:
        _say(f"{site}: {name} was already denied and not allowed. Nothing changed.")
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
        site = _resolve(roots, site)
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
BRIDGE_UNIT_NAMES = ("valetkey-bridge@.service",)
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
BRIDGE_NEXT_COMMANDS = (
    "systemctl --user daemon-reload",
    "systemctl --user enable --now valetkey-bridge@SERVER.service",
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
        message = (
            "valetkey is not on PATH; install it first, from the Arch package "
            "(`makepkg -si` in packaging/arch) or with `uv tool install .` in a checkout"
        )
        raise CommandError(message)
    return str(Path(found).absolute())


def plan_units(
    directory: Path, executable: str, *, force: bool, names: tuple[str, ...] = UNIT_NAMES
) -> dict[str, str]:
    """Return the text of each unit file to write, or refuse to replace a file that is not ours."""
    files = {name: render_unit(name, executable) for name in names}
    foreign = [
        str(directory / name)
        for name in names
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
    bridge: Annotated[
        bool,
        Parameter(
            name="--bridge",
            negative="",
            help="Write the unit of the bridge for logins from a server, on your laptop.",
        ),
    ] = False,
) -> int:
    """Write the systemd user units that run the valetkey daemon.

    The units go to the systemd user directory (``$XDG_CONFIG_HOME/systemd/user``). The command
    refuses to replace a file it did not write, and prints the commands that start the
    socket. It never runs them. With --bridge it writes the one unit that runs the bridge
    for logins from a server, ``valetkey-bridge@.service``, and not the daemon's units.
    """
    directory = unit_directory(sites.roots_from_env())
    names = BRIDGE_UNIT_NAMES if bridge else UNIT_NAMES
    try:
        files = plan_units(directory, valetkey_executable(), force=force, names=names)
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
        (d for d in SYSTEM_UNIT_DIRS if all((d / name).is_file() for name in names)), None
    )
    if packaged is not None:
        _say(f"\nNote: the units in {packaged} are replaced by these copies.")
    if bridge:
        _say("\nTo start the bridge, replace SERVER with its ssh host name and run:\n")
    else:
        _say("\nTo start the daemon, run:\n")
    for command in BRIDGE_NEXT_COMMANDS if bridge else NEXT_COMMANDS:
        _say(f"    {command}")
    return 0


# -- the bridge ----------------------------------------------------------------------------


@app.command
def bridge(
    host: str,
    *,
    remote_runtime: Annotated[
        Path | None,
        Parameter(
            name="--remote-runtime",
            help="The server's XDG_RUNTIME_DIR, such as /run/user/1000. Asked for by default.",
        ),
    ] = None,
) -> int:
    """Take login windows from a server onto this desktop, until stopped.

    Run it on the machine you sit at, as the service ``valetkey-bridge@HOST`` (see
    ``valetkey install-units --bridge``). It starts waypipe here and keeps an ssh connection to
    HOST, which needs valetkey, key-based login and no password. A login that valetkeyd on HOST
    starts then opens as a window here. waypipe always runs with a security context, so the
    server's programs cannot capture your screen. A dropped connection is tried again, after
    waits of up to a minute.

    Parameters
    ----------
    host
        The server, as ssh knows it.
    remote_runtime
        The server's runtime directory.

    """
    roots = sites.roots_from_env()
    stop = asyncio.Event()

    async def serve() -> None:
        bridging.install_stop_signals(stop)
        await bridging.run_bridge(host, roots, remote_runtime=remote_runtime, stop=stop)

    try:
        asyncio.run(serve())
    except (bridging.BridgeError, sites.RuntimeDirUnavailableError) as error:
        return _fail(CommandError(str(error)))
    return 0


@app.command(name="bridge-hold", show=False)
def bridge_hold(
    name: str | None = None,
    *,
    print_runtime: Annotated[
        bool, Parameter(name="--print-runtime", negative="", help="Print the runtime directory.")
    ] = False,
) -> int:
    """Hold a bridge connection open for valetkeyd; ssh runs this, you do not.

    It registers the socket that the bridge forwards, keeps it registered while the connection
    lasts and removes the socket when the connection ends. With --print-runtime it only prints
    the runtime directory (making sure ``valetkey`` exists in it) and exits.

    Parameters
    ----------
    name
        The random part of the connection's socket name.
    print_runtime
        Print the runtime directory and exit.

    """
    roots = sites.roots_from_env()
    try:
        if print_runtime:
            sites.ensure_runtime(roots)
            _say(str(roots.runtime))
            return 0
        if name is None:
            return _fail(CommandError("give the connection name, or --print-runtime"))
        stop = asyncio.Event()

        async def serve() -> int:
            bridging.install_stop_signals(stop)
            return await bridging.hold(name, roots, stop=stop)

        return asyncio.run(serve())
    except (bridging.BridgeError, CommandError, sites.RuntimeDirUnavailableError) as error:
        return _fail(CommandError(str(error)))


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


def remote_logins_enabled() -> bool:
    """Tell whether the config allows a login with no screen to be shown in a browser."""
    try:
        return approvals.load_config(sites.roots_from_env()).novnc
    except approvals.ConfigError:
        return False


@dataclass(frozen=True, slots=True)
class System:
    """Everything ``doctor`` asks the machine, so tests can answer instead."""

    which: Callable[[str], str | None] = shutil.which
    run: Callable[[Sequence[str]], tuple[int, str]] = _run
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    wayland: Callable[[], Path] = login.find_wayland_socket
    offered: Callable[[Path], Mapping[str, int]] = compositor_globals
    """The interfaces the compositor at a socket offers."""
    remote_logins: Callable[[], bool] = remote_logins_enabled
    """Whether the config turns on showing a login with no screen in a browser."""
    viewer: Callable[[], Path] = display.novnc_root
    """The directory of noVNC viewer files; raises when they are not installed."""
    runtime_fallback: Callable[[], Path | None] = sites.fallback_runtime_dir
    """The runtime directory used when ``XDG_RUNTIME_DIR`` is missing, or ``None``."""
    machine: Callable[[], str] = platform.machine
    """The CPU architecture, which decides whether the syscall filter applies."""
    roots: sites.Roots = field(default_factory=sites.roots_from_env)
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
    """Check that the daemon has a runtime directory for its sockets.

    ``XDG_RUNTIME_DIR`` is the one. A client that starts programs with a reduced environment
    leaves it out, and ``/run/user/UID`` stands in when it is the user's own private directory;
    that works but is worth knowing, so it is a warning.
    """
    value = system.environ.get("XDG_RUNTIME_DIR", "")
    if value and Path(value).is_absolute():
        return Check("runtime-dir", "ok", f"XDG_RUNTIME_DIR={value}")
    fallback = system.runtime_fallback()
    if fallback is not None:
        detail = (
            f"XDG_RUNTIME_DIR is not set; valetkey uses {fallback}. If your MCP client starts "
            "programs with a reduced environment, see docs/troubleshooting.md"
        )
        return Check("runtime-dir", "warn", detail)
    detail = (
        "XDG_RUNTIME_DIR is not set to an absolute path, and there is no private /run/user "
        "directory of yours to use instead; set it in the environment of the program that "
        "starts valetkey"
    )
    return Check("runtime-dir", "fail", detail)


def check_display(system: System) -> Check:
    """Look for a Wayland display; only logging in needs one, so a miss is a warning."""
    try:
        socket = system.wayland()
    except login.DisplayError as error:
        return Check("display", "warn", f"no Wayland display ({error}); logging in needs one")
    return Check("display", "ok", f"Wayland display {socket}")


def check_security_context(system: System) -> list[Check]:
    """Say whether the compositor can restrict the login window; nothing if there is no display.

    Without ``wp_security_context_manager_v1`` the login window still opens, on the compositor's
    own socket, and can use screen capture, virtual input and clipboard managers.
    """
    try:
        socket = system.wayland()
    except login.DisplayError:
        return []  # the display check already says so
    try:
        interfaces = system.offered(socket)
    except WaylandError as error:
        detail = f"could not ask the Wayland compositor: {error}"
        return [Check("security-context", "warn", detail)]
    if MANAGER in interfaces:
        return [
            Check("security-context", "ok", "the Wayland compositor restricts the login window")
        ]
    return [Check("security-context", "warn", login.UNRESTRICTED_SHORT)]


def check_remote_login(system: System) -> list[Check]:
    """Check what a login shown in a browser needs; nothing unless the config turns it on."""
    if not system.remote_logins():
        return []
    try:
        system.viewer()
    except display.RemoteDisplayError as error:
        return [Check("remote-login", "fail", str(error))]
    missing = [tool for tool in ("sway", "wayvnc") if system.which(tool) is None]
    if missing:
        detail = f"remote logins are on but {' and '.join(missing)} not found"
        return [Check("remote-login", "fail", detail)]
    problem = display.wayvnc_problem(
        system.run([system.which("wayvnc") or "wayvnc", "--version"])[1]
    )
    if problem is not None:
        return [Check("remote-login", "fail", problem)]
    return [Check("remote-login", "ok", "a login with no screen is shown in a browser")]


def check_seccomp(system: System) -> Check:
    """Say whether the sandbox gets its syscall filter, which is built for x86_64 only."""
    machine = system.machine()
    if seccomp.available(machine):
        count = len(seccomp.DENIED)
        return Check(
            "seccomp", "ok", f"the sandbox refuses {count} system calls a browser has no use for"
        )
    detail = f"no syscall filter for {machine or 'this CPU'}; the sandbox runs without one"
    return Check("seccomp", "warn", detail)


def check_config(system: System) -> list[Check]:
    """Check ``config.json``, if there is one: it names a program, so it must be safe to trust."""
    try:
        config = approvals.load_config(system.roots)
    except approvals.ConfigError as error:
        return [Check("config", "fail", f"config.json is ignored: {error}")]
    if config.approve_command is None:
        return []
    return [Check("config", "ok", "config.json is yours and nobody else can write to it")]


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
        *check_security_context(system),
        *check_remote_login(system),
        check_seccomp(system),
        *check_config(system),
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
    Wayland display is a warning, because only logging in needs one, and so is a compositor
    without security-context support, where the login window is not restricted, and an
    agent-browser newer than 0.39.4, the version valetkey was tested with, and so is a CPU other
    than x86_64, where the sandbox has no syscall filter. The state of the systemd units is shown
    for information. A `config.json` that others can write to is ignored and
    fails. The exit status is 1 when a required check fails. With
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


async def _daemon_status(*, links: bool) -> dict[str, Any]:
    """Ask the running daemon what is open. It is never started for this."""
    async with await client.Client.connect() as connection:
        return await connection.call("status", links=links)


def _activity_rows(activity: dict[str, Any]) -> list[list[str]]:
    return [
        [
            kind,
            entry.get("site") or entry["bridge"],
            entry["since"] or "-",
            entry.get("host") or "-",
        ]
        for kind, key in (("session", "sessions"), ("login", "logins"), ("bridge", "bridges"))
        for entry in activity.get(key, [])
    ]


@app.command(name="status")
def show_status(
    *,
    as_json: Annotated[
        bool, Parameter(name="--json", negative="", help="Print JSON instead of a table.")
    ] = False,
    show_links: Annotated[
        bool,
        Parameter(
            name="--show-links",
            negative="",
            help="With --json, also print the link of a login shown in a web browser.",
        ),
    ] = False,
) -> int:
    """Show the browser sessions, login windows and bridges that are open.

    The daemon reports what its own processes are doing, and nothing can hide a session from
    it. A browser that was killed disappears within a second or two. The daemon is not started:
    when none runs, this says so and exits 0.

    With --json the output is an object with three lists. "sessions" holds objects with the keys
    site, since, contained and host. "logins" holds objects with the keys site and since.
    "bridges" holds objects with the keys bridge and since, one for each laptop connected to
    take login windows. since is a UTC time like 2026-10-26T09:00:00Z. contained is always true.
    host is the host of the page the browser was last reported at, never the whole address,
    which may carry a token.

    A login shown in a web browser has a link that works like a password: whoever opens it can
    type into the login window. The table prints it under the table, with the ssh command that
    makes it reachable. --json leaves it out unless --show-links is given, so a script that
    logs its input does not keep it.
    """
    try:
        activity = asyncio.run(_daemon_status(links=show_links or not as_json))
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
    for entry in activity.get("logins", []):
        if remote := entry.get("remote"):
            _say(f"\nThe {entry['site']} login is shown in a web browser.")
            _say(f"On the machine you will use, run: {remote['ssh']}")
            _say(f"Then open: {remote['url']}")
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
    """Print one JSON line for every change to the sessions, login windows and bridges.

    The first line is a snapshot of what is open, as `status --json` shows it, with "event" set
    to "snapshot" and an "at" time. After that each line has the keys event, site and at, where
    event is session_started, session_ended, login_opened or login_closed. For a bridge the key
    is bridge instead of site, and event is bridge_connected or bridge_disconnected. Bars and
    indicators can read the lines as they come. The command runs until it is interrupted or the
    daemon stops; it exits 1 when no daemon is running, and does not start one.
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
