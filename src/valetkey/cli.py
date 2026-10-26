# SPDX-License-Identifier: Apache-2.0
"""The ``valetkey`` command."""

import asyncio
import contextlib
import json
import logging
import os
import shutil
import sys
from pathlib import Path  # the command-line framework reads the annotation at runtime
from typing import TYPE_CHECKING, Annotated

from cyclopts import App, Parameter

from valetkey import __version__, daemon, sites

if TYPE_CHECKING:
    from collections.abc import Sequence

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
    excluded, when the hosts were last learned, and whether a login profile exists. With
    --json, each site is an object with the keys site, host, allowed, excluded, learned (a UTC
    time, or null) and profile (true or false).
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
                "profile": sites.profile_path(roots, name).is_dir(),
            }
        )
    if as_json:
        _say(json.dumps(rows, indent=2))
    elif not rows:
        _say("No sites yet.")
    else:
        _print_table(rows)
    return 0


def _print_table(rows: list[dict[str, object]]) -> None:
    header = ["SITE", "HOST", "ALLOWED", "EXCLUDED", "LEARNED", "PROFILE"]
    body = [
        [
            str(row["site"]),
            str(row["host"]),
            str(row["allowed"]),
            str(row["excluded"]),
            str(row["learned"] or "never"),
            "yes" if row["profile"] else "no",
        ]
        for row in rows
    ]
    widths = [max(len(line[column]) for line in [header, *body]) for column in range(len(header))]
    for line in [header, *body]:
        _say(
            "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        )


@app.command
def allow(site: str, host: str) -> int:
    """Allow a host, and its subdomains, for a site.

    Any excluded entry that would block the host is removed. Allowing a host that is already
    listed changes nothing.

    Parameters
    ----------
    site
        The site name, as shown by ``valetkey sites``.
    host
        A host name, or a URL on it.

    """
    roots = sites.roots_from_env()
    try:
        policy = _load(roots, site)
        name = _host(host)
        added = name not in policy.allow
        allowed = (*policy.allow, name) if added else policy.allow
        kept = tuple(e for e in policy.excluded if not sites.excluded_conflicts(e, [name]))
        removed = [e for e in policy.excluded if e not in kept]
        if added or removed:
            sites.save_policy(
                roots, sites.Policy(policy.site, policy.start, allowed, kept, policy.learned)
            )
    except CommandError as error:
        return _fail(error)
    _say(f"{site}: {name} is allowed." if added else f"{site}: {name} was already allowed.")
    if removed:
        _say(f"{site}: no longer excluding {', '.join(removed)}.")
    return 0


@app.command
def deny(site: str, host: str) -> int:
    """Stop allowing a host for a site.

    The host's own entry is removed from the allowed hosts. If a wider allowed entry still
    covers the host (``app.example.com`` under ``example.com``), the host is also added to the
    excluded hosts, so it stays blocked. Otherwise nothing more is needed.

    Parameters
    ----------
    site
        The site name, as shown by ``valetkey sites``.
    host
        A host name, or a URL on it.

    """
    roots = sites.roots_from_env()
    try:
        policy = _load(roots, site)
        name = _host(host)
        allowed = tuple(entry for entry in policy.allow if entry != name)
        covered = sites.host_matches(name, allowed)
        excluded = policy.excluded
        if covered and name not in excluded:
            excluded = (*excluded, name)
        if allowed != policy.allow or excluded != policy.excluded:
            sites.save_policy(
                roots, sites.Policy(policy.site, policy.start, allowed, excluded, policy.learned)
            )
    except CommandError as error:
        return _fail(error)
    removed = allowed != policy.allow
    if removed:
        _say(f"{site}: {name} is no longer allowed.")
    if covered:
        _say(f"{site}: a wider allowed entry still covers {name}, so it is now excluded.")
    if not removed and not covered:
        _say(f"{site}: {name} was not allowed. Nothing changed.")
    return 0


def _command_lines(proc: Path = Path("/proc")) -> list[list[str]]:
    """Return the arguments of every process the host can see, sandboxed ones included."""
    lines: list[list[str]] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or entry.name == str(os.getpid()):
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue  # the process ended, or belongs to someone else
        lines.append(raw.decode(errors="replace").split("\0"))
    return lines


def _profile_in_use(profile: Path) -> bool:
    """Tell whether a running process has ``profile`` in its arguments.

    Browsers run in their own sandbox and process namespace, so Chromium's lock file names a
    process number that means nothing here. The host's process table does show them. An argument
    counts when it, or the part after ``=``, resolves to the profile directory, as in
    ``--user-data-dir=PATH``.
    """
    target = profile.resolve()
    for arguments in _command_lines():
        for argument in arguments:
            for candidate in {argument, argument.partition("=")[2]}:
                if candidate and Path(candidate).resolve() == target:
                    return True
    return False


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
    if _profile_in_use(sites.profile_path(roots, site)):
        message = f"the browser for {site} is open; close that session first"
        raise CommandError(message)
    if not yes and not _confirmed(site):
        return None
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

    It asks first, and refuses when input is not a terminal unless --yes is given. It also
    refuses while the site's browser is open: close that session first.

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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command named in ``argv`` (default: ``sys.argv``) and return its exit status.

    Usage errors exit with status 2 after printing the error.
    """
    tokens = sys.argv[1:] if argv is None else argv
    status = app(tokens, result_action="return_int_as_exit_code_else_zero")
    return int(status)
