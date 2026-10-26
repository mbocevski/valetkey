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
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path  # the command-line framework reads the annotation at runtime
from typing import TYPE_CHECKING, Annotated

from cyclopts import App, Parameter

from valetkey import __version__, daemon, login, mcp_server, sandbox, sessions, sites

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
    """Check that agent-browser is installed and new enough."""
    path, output = _tool_version(system, "agent-browser")
    if path is None:
        return Check("agent-browser", "fail", "agent-browser not found")
    try:
        version = sessions.parse_version(output)
        sessions.check_version(version)
    except ValueError:
        return Check("agent-browser", "fail", f"cannot read the version of {path}")
    except sessions.VersionError as error:
        return Check("agent-browser", "fail", str(error))
    return Check("agent-browser", "ok", f"agent-browser {'.'.join(map(str, version))}")


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
    Wayland display is a warning, because only logging in needs one. The state of the systemd
    units is shown for information. The exit status is 1 when a required check fails. With
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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command named in ``argv`` (default: ``sys.argv``) and return its exit status.

    Usage errors exit with status 2 after printing the error.
    """
    tokens = sys.argv[1:] if argv is None else argv
    status = app(tokens, result_action="return_int_as_exit_code_else_zero")
    return int(status)
