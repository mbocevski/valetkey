# SPDX-License-Identifier: Apache-2.0
"""What a site is, where its files live, and which hosts it may reach.

A site has a short name such as ``sitex``. The name picks a policy file, a browser profile and a
downloads directory, so it is validated strictly: it can never point outside its own directory.

Files follow the XDG base directory layout:

* policy: ``$XDG_CONFIG_HOME/valetkey/sites/<site>.json``
* profile: ``$XDG_STATE_HOME/valetkey/profiles/<site>/``
* downloads: ``$XDG_STATE_HOME/valetkey/downloads/<site>/``
* runtime files: ``$XDG_RUNTIME_DIR/valetkey/``

Directories valetkey creates are mode ``0700``. A directory that already exists and is open to
the group or others is tightened to ``0700``. One that is not a real directory (for example a
symlink) or that belongs to another user is rejected.

Every function that touches the disk takes a :class:`Roots`, so tests and callers can point it at
any directory. :func:`roots_from_env` builds one from the environment.
"""

import contextlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

APP_DIR = "valetkey"
MAX_NAME_LENGTH = 48
_DERIVED_LABEL_LENGTH = 40
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
_LEARNED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_LEARNED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_POLICY_KEYS = ("site", "start", "allow", "excluded", "learned")

# Suffixes made of two labels under which people register their own name (``example.co.uk``).
# This is a small stand-in for the public suffix list: a host under any other suffix is taken to
# have a one-label suffix. Pass your own set to the functions that take ``suffixes`` to replace it.
TWO_LEVEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "ac.uk",
        "co.uk",
        "gov.uk",
        "ltd.uk",
        "me.uk",
        "org.uk",
        "plc.uk",
        "com.au",
        "edu.au",
        "gov.au",
        "net.au",
        "org.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "co.in",
        "co.kr",
        "co.za",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.sg",
        "com.tr",
    }
)


class PolicyError(ValueError):
    """A policy file is unreadable as JSON or does not follow the policy format."""


class RuntimeDirUnavailableError(RuntimeError):
    """``XDG_RUNTIME_DIR`` is not set, so there is nowhere safe for runtime files."""


@dataclass(frozen=True, slots=True)
class Roots:
    """The base directories valetkey stores files under.

    ``runtime`` is ``None`` when ``XDG_RUNTIME_DIR`` is unset; :func:`runtime_path` then fails.
    """

    config: Path
    state: Path
    runtime: Path | None


def roots_from_env(environ: Mapping[str, str] | None = None) -> Roots:
    """Read the XDG base directories from ``environ`` (default: ``os.environ``).

    An unset, empty or relative value falls back to the XDG default, as the specification asks.
    There is no default for the runtime directory.
    """
    env = os.environ if environ is None else environ
    home = Path(env.get("HOME") or Path.home())
    return Roots(
        config=_absolute_or(env.get("XDG_CONFIG_HOME"), home / ".config"),
        state=_absolute_or(env.get("XDG_STATE_HOME"), home / ".local" / "state"),
        runtime=_absolute_or(env.get("XDG_RUNTIME_DIR"), None),
    )


def _absolute_or[T: Path | None](value: str | None, default: T) -> Path | T:
    if value and Path(value).is_absolute():
        return Path(value)
    return default


# -- hosts and names -----------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Return ``host`` the way hosts are compared: lowercase, no brackets, no trailing dot.

    Only ASCII is lowercased, so a look-alike character never folds into a plain letter.
    """
    text = host.lower() if host.isascii() else host
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text.removesuffix(".")


def is_ip_literal(host: str) -> bool:
    """Tell whether ``host`` is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_plausible_host(host: str) -> bool:
    """Tell whether ``host`` is a lowercase hostname or IP address with no scheme, path or port."""
    return bool(_HOST_RE.fullmatch(host)) or (host == normalize_host(host) and is_ip_literal(host))


def host_of(value: str) -> str:
    """Return the normalized host in ``value``, which is a host name or a URL.

    ``https://sitex.com/login`` and ``sitex.com:8443`` both give ``sitex.com``.

    Raises:
        ValueError: when no plausible host can be read from ``value``.

    """
    text = value.strip()
    if "://" not in text:
        text = "//" + text
    try:
        raw = urlsplit(text).hostname
    except ValueError as exc:
        msg = f"cannot read a host from {value!r}: {exc}"
        raise ValueError(msg) from exc
    host = normalize_host(raw or "")
    if not is_plausible_host(host):
        msg = f"cannot read a host from {value!r}"
        raise ValueError(msg)
    return host


def registrable_domain(host: str, suffixes: frozenset[str] = TWO_LEVEL_SUFFIXES) -> str:
    """Return the part of ``host`` a person registers: ``app.sitex.co.uk`` gives ``sitex.co.uk``.

    The rule is the last two labels, or the last three when those two form one of ``suffixes``.
    A single label or an IP address comes back unchanged.
    """
    host = normalize_host(host)
    if is_ip_literal(host):
        return host
    labels = host.split(".")
    keep = 3 if ".".join(labels[-2:]) in suffixes else 2
    return ".".join(labels[-keep:])


def validate_site_name(name: str) -> str:
    """Return ``name`` if it is a safe site name, and raise ``ValueError`` if not.

    A name is 1 to :data:`MAX_NAME_LENGTH` characters of lowercase ASCII letters, digits and
    hyphens, and it does not start with a hyphen. That rules out ``.``, ``..``, separators and
    anything non-ASCII, so a name cannot leave its directory.
    """
    if not (
        isinstance(name, str)
        and len(name) <= MAX_NAME_LENGTH
        and _NAME_RE.fullmatch(name)
        and name.isascii()
    ):
        msg = (
            f"invalid site name {name!r}: use 1 to {MAX_NAME_LENGTH} lowercase letters, digits "
            "or hyphens, starting with a letter or digit"
        )
        raise ValueError(msg)
    return name


def site_name_for(value: str, suffixes: frozenset[str] = TWO_LEVEL_SUFFIXES) -> str:
    """Derive a site name from a host or URL: the first label of its registrable domain.

    ``sitex.com`` and ``https://app.sitex.com/login`` give ``sitex``, and ``app.sitex.co.uk``
    gives ``sitex``. Long labels are cut to keep room for a collision suffix.

    Raises:
        ValueError: when ``value`` has no host, or the host is an IP address (it has no name).

    """
    domain = registrable_domain(host_of(value), suffixes)
    if is_ip_literal(domain):
        msg = f"an IP address has no site name: {domain}"
        raise ValueError(msg)
    return validate_site_name(domain.split(".")[0][:_DERIVED_LABEL_LENGTH].rstrip("-"))


def choose_site_name(
    roots: Roots, value: str, suffixes: frozenset[str] = TWO_LEVEL_SUFFIXES
) -> str:
    """Pick the site name for the host or URL in ``value``, avoiding other sites on disk.

    Start from :func:`site_name_for`. A name is free when it has no policy file and no profile
    directory. A name already used for the same registrable domain is returned as is, so naming
    a site twice finds the same site. Otherwise try ``name-2``, ``name-3`` and so on.
    """
    domain = registrable_domain(host_of(value), suffixes)
    base = site_name_for(value, suffixes)
    candidate = base
    number = 1
    while True:
        if not (policy_path(roots, candidate).exists() or profile_path(roots, candidate).exists()):
            return candidate
        if _site_domain(roots, candidate, suffixes) == domain:
            return candidate
        number += 1
        candidate = f"{base}-{number}"


def _site_domain(roots: Roots, site: str, suffixes: frozenset[str]) -> str | None:
    try:
        policy = load_policy(roots, site)
    except OSError, PolicyError:
        return None
    return registrable_domain(host_of(policy.start), suffixes)


# -- paths ---------------------------------------------------------------------------------


def policy_path(roots: Roots, site: str) -> Path:
    """Return the path of ``site``'s policy file. Nothing is created."""
    return roots.config / APP_DIR / "sites" / f"{validate_site_name(site)}.json"


def profile_path(roots: Roots, site: str) -> Path:
    """Return the path of ``site``'s browser profile directory. Nothing is created."""
    return roots.state / APP_DIR / "profiles" / validate_site_name(site)


def downloads_path(roots: Roots, site: str) -> Path:
    """Return the path of ``site``'s downloads directory. Nothing is created."""
    return roots.state / APP_DIR / "downloads" / validate_site_name(site)


def runtime_path(roots: Roots) -> Path:
    """Return the runtime directory, ``$XDG_RUNTIME_DIR/valetkey``. Nothing is created.

    Raises:
        RuntimeDirUnavailableError: when ``XDG_RUNTIME_DIR`` was not set. There is no fallback,
            because sockets and other runtime files must not land in a shared directory.

    """
    if roots.runtime is None:
        msg = "XDG_RUNTIME_DIR is not set; log in through a session that provides it"
        raise RuntimeDirUnavailableError(msg)
    return roots.runtime / APP_DIR


def ensure_profile(roots: Roots, site: str) -> Path:
    """Create ``site``'s profile directory (mode ``0700``) if needed and return it."""
    path = profile_path(roots, site)
    return _private_tree(roots.state, path)


def ensure_downloads(roots: Roots, site: str) -> Path:
    """Create ``site``'s downloads directory (mode ``0700``) if needed and return it."""
    path = downloads_path(roots, site)
    return _private_tree(roots.state, path)


def ensure_runtime(roots: Roots) -> Path:
    """Create the runtime directory (mode ``0700``) if needed and return it."""
    path = runtime_path(roots)
    return _private_tree(path.parent, path)


def _private_tree(base: Path, path: Path) -> Path:
    """Make every directory from ``base`` (exclusive) down to ``path`` private, creating them.

    ``base`` is an XDG directory the user owns; it is created if missing but never changed.
    """
    base.mkdir(parents=True, exist_ok=True)
    current = base
    for part in path.relative_to(base).parts:
        current /= part
        _private_dir(current)
    return path


def _private_dir(path: Path) -> None:
    with contextlib.suppress(FileExistsError):
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        msg = f"{path} is not a real directory"
        raise NotADirectoryError(msg)
    if info.st_uid != os.getuid():
        msg = f"{path} belongs to another user"
        raise PermissionError(msg)
    if info.st_mode & 0o077:
        path.chmod(0o700)


# -- policy --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Policy:
    """The hosts one site may reach.

    ``allow`` lists hosts the browser may connect to, each also covering its subdomains.
    ``excluded`` lists hosts that were seen and judged not needed (trackers, error reporting); a
    host under an excluded entry is refused even when an ``allow`` entry also covers it.
    ``learned`` is when the lists were last built, in UTC with whole seconds, or ``None``.

    Construction validates every field and raises ``ValueError`` on a bad one.
    """

    site: str
    start: str
    allow: tuple[str, ...]
    excluded: tuple[str, ...] = ()
    learned: datetime | None = None

    def __post_init__(self) -> None:
        """Validate the fields."""
        validate_site_name(self.site)
        _validate_start(self.start)
        for entries in (self.allow, self.excluded):
            for entry in entries:
                if not (isinstance(entry, str) and is_plausible_host(entry)):
                    msg = (
                        f"not a plausible host name (lowercase, no scheme, path or port): {entry!r}"
                    )
                    raise ValueError(msg)
        learned = self.learned
        if learned is not None and (learned.utcoffset() != timedelta(0) or learned.microsecond):
            msg = "learned must be a UTC time with whole seconds"
            raise ValueError(msg)


def _validate_start(start: str) -> None:
    try:
        parts = urlsplit(start)
        host = parts.hostname
        _ = parts.port
        has_credentials = "@" in parts.netloc
    except ValueError as exc:
        msg = f"start is not a valid URL: {start!r}"
        raise ValueError(msg) from exc
    if parts.scheme not in {"http", "https"} or has_credentials or host is None:
        msg = f"start must be an http or https URL with a host and no credentials: {start!r}"
        raise ValueError(msg)
    if not is_plausible_host(normalize_host(host)):
        msg = f"start has no plausible host: {start!r}"
        raise ValueError(msg)


@lru_cache(maxsize=256)
def _index(entries: tuple[str, ...]) -> tuple[frozenset[str], frozenset[str]]:
    """Split ``entries`` into all of them and the ones that are not IP addresses."""
    return frozenset(entries), frozenset(e for e in entries if not is_ip_literal(e))


def host_matches(host: str, entries: Iterable[str]) -> bool:
    """Tell whether ``host`` equals an entry or is a subdomain of one, on a dot boundary.

    ``login.sitex.com`` matches ``sitex.com``; ``notsitex.com`` does not. Case, a trailing dot
    and IPv6 brackets are ignored. An IP address matches only an identical entry, and an empty or
    malformed host never matches.
    """
    host = normalize_host(host)
    if not host:
        return False
    exact, domains = _index(tuple(entries))
    if host in exact:
        return True
    if not _HOST_RE.fullmatch(host) or is_ip_literal(host):
        return False
    position = host.find(".")
    while position != -1:
        if host[position + 1 :] in domains:
            return True
        position = host.find(".", position + 1)
    return False


def excluded_conflicts(excluded: str, allow: Iterable[str]) -> bool:
    """Tell whether the ``excluded`` entry would block an ``allow`` entry.

    An excluded entry overrides ``allow`` and covers its subdomains, so it blocks an allow entry
    that equals it or sits under it. An entry under an allowed one is not a conflict: it carves
    one host out of a wider allowed domain.
    """
    return any(host_matches(entry, [excluded]) for entry in allow)


def allows(policy: Policy, host: str) -> bool:
    """Tell whether ``policy`` lets the browser connect to ``host``.

    True when ``host`` matches an ``allow`` entry (see :func:`host_matches`) and no ``excluded``
    entry. Pure and cheap: meant to be called for every connection.
    """
    return host_matches(host, policy.allow) and not host_matches(host, policy.excluded)


def load_policy(roots: Roots, site: str) -> Policy:
    """Read and validate ``site``'s policy file.

    The file must be a JSON object with exactly the keys ``site``, ``start``, ``allow``,
    ``excluded`` and ``learned``. Missing keys and unknown keys are both errors, and ``site``
    must equal the file name.

    Raises:
        FileNotFoundError: when the site has no policy file.
        PolicyError: when the file is not valid.

    """
    path = policy_path(roots, site)
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or set(data) != set(_POLICY_KEYS):
            msg = f"expected an object with exactly the keys {', '.join(_POLICY_KEYS)}"
            raise PolicyError(msg)
        if data["site"] != site:
            msg = f"site is {data['site']!r} but the file is named for {site!r}"
            raise PolicyError(msg)
        return Policy(
            site=_text(data, "site"),
            start=_text(data, "start"),
            allow=_hosts(data, "allow"),
            excluded=_hosts(data, "excluded"),
            learned=_learned(data["learned"]),
        )
    except ValueError as exc:
        msg = f"{path}: {exc}"
        raise PolicyError(msg) from exc


def _text(data: dict[str, Any], key: str) -> str:
    value = data[key]
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise PolicyError(msg)
    return value


def _hosts(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        msg = f"{key} must be a list of strings"
        raise PolicyError(msg)
    return tuple(value)


def _learned(value: object) -> datetime | None:
    if value is None:
        return None
    if not (isinstance(value, str) and _LEARNED_RE.fullmatch(value)):
        msg = "learned must be null or a UTC time like 2026-10-25T21:40:00Z"
        raise PolicyError(msg)
    return datetime.fromisoformat(value)


def policy_json(policy: Policy) -> str:
    """Return ``policy`` as the text of its file: fixed key order, 2-space indent, final newline."""
    learned = policy.learned
    data = {
        "site": policy.site,
        "start": policy.start,
        "allow": list(policy.allow),
        "excluded": list(policy.excluded),
        "learned": None if learned is None else learned.strftime(_LEARNED_FORMAT),
    }
    return json.dumps(data, indent=2) + "\n"


def save_policy(roots: Roots, policy: Policy) -> Path:
    """Write ``policy`` to its file atomically and return the path.

    The text goes to a temporary file in the same directory, is flushed to disk, then replaces
    the old file in one step, so a reader sees the old or the new policy and never a partial one.
    The file is mode ``0600`` and its directories ``0700``. If the write fails, the old file is
    left as it was and the temporary file is removed.
    """
    path = policy_path(roots, policy.site)
    directory = _private_tree(roots.config, path.parent)
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=f".{policy.site}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(policy_json(policy))
            handle.flush()
            os.fsync(handle.fileno())
        Path(name).replace(path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    _sync_directory(directory)
    return path


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
