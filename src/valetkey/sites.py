# SPDX-License-Identifier: Apache-2.0
"""What a site is, where its files live, and which hosts it may reach.

A site has a short name such as ``sitex``. A site can have several accounts, each a name of its
own: ``sitex`` is the account valetkey always had, and ``sitex:work`` is another, with its own
policy, login profile and downloads. The name picks a policy file, a browser profile and a
downloads directory, so it is validated strictly: it can never point outside its own directory.
On disk the colon becomes a dot, the *storage key* (``sitex.work``), which cannot be mistaken for
another name because neither part may hold a dot. The files of an account-less name are exactly
what valetkey 1 wrote, so nothing moves.

Files follow the XDG base directory layout:

* policy: ``$XDG_CONFIG_HOME/valetkey/sites/<key>.json``
* profile: ``$XDG_STATE_HOME/valetkey/profiles/<key>/``
* downloads: ``$XDG_STATE_HOME/valetkey/downloads/<key>/``
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
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

APP_DIR = "valetkey"
MAX_NAME_LENGTH = 48
"""The longest name, account included. agent-browser's socket path caps at 103 bytes, and the
path of a session already uses 99 of them for a name this long."""
_DERIVED_LABEL_LENGTH = 31
"""A name made from a host is cut here, which leaves 16 characters for ``.account``."""
ACCOUNT_SEPARATOR = ":"
FIRST_ACCOUNT = "main"
"""What the account-less ``sitex`` is called once its site has more accounts: ``sitex:main``.

It is a way to write the name, not a name: nothing is stored under it, and no account may be
given this label."""
_PART = r"[a-z0-9][a-z0-9-]*"
_ACCOUNT_PART = r"[a-z][a-z0-9-]*"
"""An account starts with a letter, so that ``intranet:8080`` is a host and a port."""
_NAME_RE = re.compile(rf"{_PART}(?:{ACCOUNT_SEPARATOR}{_ACCOUNT_PART})?")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
_LEARNED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_LEARNED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_POLICY_KEYS = ("site", "start", "allow", "excluded", "learned")
MAX_LOGIN_COOKIES = 20
"""The most cookies a policy records for a login."""
_LOGIN_COOKIE_RE = re.compile(r"\.?[a-z0-9][a-z0-9.-]* [\x21-\x7e]{1,128}")
_OPTIONAL_POLICY_KEYS = (
    "denied",
    "login_cookies",
    "login_pages",
    "microphone",
    "microphone_source",
    "private_networks",
)

# Ranges a site may be given for its private-network addresses: the RFC 1918 blocks, the unique
# local addresses of RFC 4193, and the shared address space of RFC 6598 (100.64.0.0/10). The last
# is what mesh VPNs and carrier-grade NAT hand out, so an intranet reached over one lives there;
# it is never routed on the public internet.
_PRIVATE_SUPERNETS = tuple(
    ipaddress.ip_network(text)
    for text in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
MIN_PRIVATE_PREFIX = {4: 8, 6: 48}
"""The shortest prefix a listed range may have, by IP version. A /8 is already 16 million
addresses; an IPv6 site prefix is a /48 (RFC 4193)."""
NEVER_ALLOWED_ADDRESSES = tuple(
    ipaddress.ip_address(text) for text in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)
"""The cloud metadata services (Amazon on IPv4 and IPv6, Alibaba). Three of them sit inside the
ranges a site may list, and a page that reaches one can read the machine's credentials, so they
are refused whatever is listed."""

PUBLIC_SUFFIX_LIST = Path("/usr/share/publicsuffix/public_suffix_list.dat")
"""The public suffix list, from the distribution's package (``publicsuffix-list`` on Arch and
Fedora, ``publicsuffix`` on Debian and Ubuntu). valetkey ships no copy of it."""
MISSING_LIST_MESSAGE = (
    "The public suffix list is missing: install publicsuffix-list (Arch, Fedora) "
    "or publicsuffix (Debian, Ubuntu)."
)


class SuffixListError(RuntimeError):
    """The public suffix list is missing or unreadable, so no registrable domain can be told."""


@dataclass(frozen=True, slots=True)
class SuffixList:
    """The rules of a public suffix list: what is shared, and so never one site's own.

    ``rules`` are the plain suffixes (``co.uk``, ``github.io``), ``wildcards`` the parents of
    ``*.`` rules (``ck`` for ``*.ck``) and ``exceptions`` the ``!`` rules (``www.ck``).
    """

    rules: frozenset[str] = frozenset()
    wildcards: frozenset[str] = frozenset()
    exceptions: frozenset[str] = frozenset()

    @classmethod
    def parse(cls, text: str) -> SuffixList:
        """Read the list format: one rule a line, ``//`` comments, ``*`` and ``!`` rules.

        Both sections of the list count. A rule written in Unicode is kept in its ``xn--`` form,
        which is how hosts are written here; one that cannot be converted is left out.
        """
        rules: set[str] = set()
        wildcards: set[str] = set()
        exceptions: set[str] = set()
        for line in text.splitlines():
            rule = line.split(maxsplit=1)[0].lower() if line.strip() else ""
            if not rule or rule.startswith("//"):
                continue
            kind = rules
            if rule.startswith("!"):
                kind, rule = exceptions, rule[1:]
            elif rule.startswith("*."):
                kind, rule = wildcards, rule[2:]
            try:
                kind.add(rule.encode("idna").decode("ascii"))
            except UnicodeError:
                continue
        return cls(frozenset(rules), frozenset(wildcards), frozenset(exceptions))

    def _suffix_labels(self, labels: list[str]) -> int:
        """Return how many trailing labels of ``labels`` are the public suffix."""
        longest = 1  # the default rule: an unlisted last label is a suffix
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            if candidate in self.exceptions:
                return len(labels) - start - 1
            parent = ".".join(labels[start + 1 :])
            if candidate in self.rules or (parent and parent in self.wildcards):
                longest = max(longest, len(labels) - start)
        return longest

    def registrable(self, host: str) -> str:
        """Return ``host`` cut to one label above its public suffix, or whole if it has none."""
        labels = host.split(".")
        keep = self._suffix_labels(labels) + 1
        return host if keep > len(labels) else ".".join(labels[-keep:])

    def is_suffix(self, host: str) -> bool:
        """Tell whether ``host`` is itself a public suffix that the list names."""
        if host in self.exceptions:
            return False
        parent = host.partition(".")[2]
        return host in self.rules or (bool(parent) and parent in self.wildcards)


@lru_cache(maxsize=4)
def _read_suffixes(path: Path) -> SuffixList:
    try:
        parsed = SuffixList.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise SuffixListError(MISSING_LIST_MESSAGE) from error
    if not parsed.rules:
        raise SuffixListError(MISSING_LIST_MESSAGE)
    return parsed


def system_suffixes() -> SuffixList:
    """Return the system's public suffix list, read once per process.

    Raises:
        SuffixListError: when the file is missing, unreadable or has no rules. There is no
            built-in list to fall back on, because a guess could allow a whole shared suffix.

    """
    return _read_suffixes(PUBLIC_SUFFIX_LIST)


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


USER_RUNTIME_ROOT = Path("/run/user")
"""Where the login manager makes each user's runtime directory, ``/run/user/UID``."""


def fallback_runtime_dir(uid: int | None = None, root: Path | None = None) -> Path | None:
    """Return the runtime directory the login manager made for ``uid``, if it can be trusted.

    A program started with a reduced environment, as some desktop clients do, has no
    ``XDG_RUNTIME_DIR``, though ``/run/user/UID`` is right there. It is used only when it is a
    real directory (not a link), belongs to ``uid`` and is private (mode ``0700``): the same
    properties that make ``XDG_RUNTIME_DIR`` safe for sockets. Otherwise there is none.
    """
    uid = os.getuid() if uid is None else uid
    path = (USER_RUNTIME_ROOT if root is None else root) / str(uid)
    try:
        found = path.lstat()
    except OSError:
        return None
    private = stat.S_IMODE(found.st_mode) == stat.S_IRWXU
    return path if stat.S_ISDIR(found.st_mode) and found.st_uid == uid and private else None


def roots_from_env(environ: Mapping[str, str] | None = None) -> Roots:
    """Read the XDG base directories from ``environ`` (default: ``os.environ``).

    An unset, empty or relative value falls back to the XDG default, as the specification asks.
    The runtime directory has no default, with one exception: the process's own environment
    without ``XDG_RUNTIME_DIR`` uses :func:`fallback_runtime_dir`. A given ``environ`` never does.
    """
    env = os.environ if environ is None else environ
    home = Path(env.get("HOME") or Path.home())
    runtime = _absolute_or(env.get("XDG_RUNTIME_DIR"), None)
    if runtime is None and environ is None:
        runtime = fallback_runtime_dir()
    return Roots(
        config=_absolute_or(env.get("XDG_CONFIG_HOME"), home / ".config"),
        state=_absolute_or(env.get("XDG_STATE_HOME"), home / ".local" / "state"),
        runtime=runtime,
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


HOST_CLIP = 200
"""Characters of a host that is not a plausible host name that a message may show."""


def shown_host(host: str) -> str:
    """Return ``host`` as it is, or clipped and quoted when it is not a plausible host name.

    A host a page chose reaches the agent in text, so anything that is not a plain host name is
    shown as a quoted, clipped string that cannot pass for a sentence of its own.
    """
    if is_plausible_host(host):
        return host
    return json.dumps(host[:HOST_CLIP] + ("…" if len(host) > HOST_CLIP else ""), ensure_ascii=False)


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


def page_key(url: str) -> str | None:
    """Return ``host/path`` for an HTTP or HTTPS ``url``, or ``None`` for anything else.

    The host is normalized, and the query, the fragment, the port, any credentials and a
    trailing slash on the path are left out, so two URLs of the same page compare equal. The
    root path is ``/``.
    """
    try:
        parts = urlsplit(url)
        host = normalize_host(parts.hostname or "")
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not is_plausible_host(host):
        return None
    path = parts.path.rstrip("/") or "/"
    return f"{host}{path}" if path != "/" else f"{host}/"


def is_page_key(value: str) -> bool:
    """Tell whether ``value`` is what :func:`page_key` returns."""
    host, slash, path = value.partition("/")
    return bool(
        slash
        and is_plausible_host(host)
        and value.isprintable()
        and not any(c in value for c in "?# ")
        and (path == "" or not path.endswith("/"))
        and "//" not in value
    )


def registrable_domain(host: str, suffixes: SuffixList | None = None) -> str:
    """Return the part of ``host`` a person registers: ``app.sitex.co.uk`` gives ``sitex.co.uk``.

    The rule is one label above the public suffix, so ``myapp.github.io`` stays whole: no one
    owns ``github.io``. ``suffixes`` is the system's list unless given. A single label, a public
    suffix on its own and an IP address come back unchanged.

    Raises:
        SuffixListError: when ``suffixes`` is not given and the system has no list.

    """
    host = normalize_host(host)
    if is_ip_literal(host):
        return host
    return (suffixes or system_suffixes()).registrable(host)


def is_public_suffix(host: str, suffixes: SuffixList | None = None) -> bool:
    """Tell whether ``host`` is a public suffix such as ``co.uk`` or ``github.io``.

    Raises:
        SuffixListError: when ``suffixes`` is not given and the system has no list.

    """
    host = normalize_host(host)
    return not is_ip_literal(host) and (suffixes or system_suffixes()).is_suffix(host)


SUFFIX_ALLOW_MESSAGE = (
    "{host} is a public suffix shared by many unrelated sites. Allow the full host name instead."
)


def validate_site_name(name: str) -> str:
    """Return ``name`` if it is a safe site name, and raise ``ValueError`` if not.

    A name is a site, or a site and an account joined by a colon. Each part is lowercase ASCII
    letters, digits and hyphens, and does not start with a hyphen; an account starts with a
    letter. The whole name is 1 to :data:`MAX_NAME_LENGTH` characters, and no account is called
    :data:`FIRST_ACCOUNT`. That rules out ``.``, ``..``, separators and anything non-ASCII, so a
    name cannot leave its directory.
    """
    if not (
        isinstance(name, str)
        and len(name) <= MAX_NAME_LENGTH
        and _NAME_RE.fullmatch(name)
        and name.isascii()
        and not name.endswith(f"{ACCOUNT_SEPARATOR}{FIRST_ACCOUNT}")
    ):
        msg = (
            f"invalid site name {name!r}: use 1 to {MAX_NAME_LENGTH} lowercase letters, digits "
            "or hyphens, starting with a letter or digit, with an account after a colon "
            f"that starts with a letter (sitex:work; the account {FIRST_ACCOUNT} is taken)"
        )
        raise ValueError(msg)
    return name


def is_login_cookie(entry: str) -> bool:
    """Tell whether ``entry`` is a cookie as a policy writes it: ``host name``."""
    return isinstance(entry, str) and _LOGIN_COOKIE_RE.fullmatch(entry) is not None


def split_site_name(name: str) -> tuple[str, str | None]:
    """Return the site and the account of ``name``; the account is ``None`` for ``sitex``."""
    site, _, account = validate_site_name(name).partition(ACCOUNT_SEPARATOR)
    return site, account or None


def listed_name(name: str, known: list[str]) -> str:
    """Return how to write the name of an account in a list of the ``known`` ones.

    That is ``name``, except that the account-less ``sitex`` is written ``sitex:main`` once the
    site has another account, because a bare ``sitex`` is then refused.
    """
    site, account = split_site_name(name)
    if account is None and any(split_site_name(n)[0] == site and n != site for n in known):
        return f"{site}{ACCOUNT_SEPARATOR}{FIRST_ACCOUNT}"
    return name


def account_name(site: str, account: str | None) -> str:
    """Return the name of ``account`` of ``site``, or of the account-less name when ``None``.

    The account :data:`FIRST_ACCOUNT` is the account-less name too.
    """
    if account in (None, FIRST_ACCOUNT):
        return validate_site_name(site)
    return validate_site_name(f"{site}{ACCOUNT_SEPARATOR}{account}")


def storage_key(site: str) -> str:
    """Return what the files of ``site`` are named: the name with its colon as a dot."""
    return validate_site_name(site).replace(ACCOUNT_SEPARATOR, ".")


def site_from_key(key: str) -> str:
    """Return the site name whose files are named ``key``.

    Raises:
        ValueError: when ``key`` is not the storage key of any site name.

    """
    if "." in key.replace(".", "", 1):
        msg = f"not the storage key of a site: {key!r}"
        raise ValueError(msg)
    return validate_site_name(key.replace(".", ACCOUNT_SEPARATOR))


def known_sites(roots: Roots) -> list[str]:
    """Return the names of the sites and accounts that have a policy file, sorted."""
    directory = policy_path(roots, "x").parent
    names = []
    for path in directory.glob("*.json") if directory.is_dir() else ():
        if path.is_file():
            with contextlib.suppress(ValueError):
                names.append(site_from_key(path.stem))
    return sorted(names)


class AmbiguousAccountError(ValueError):
    """A site has several accounts and the name given did not say which."""


def resolve_account(roots: Roots, name: str) -> str:
    """Return the account ``name`` means.

    A name with an account is that account. A name without one is the account-less name valetkey
    1 had, and it still works for a site with a single account, whatever that account is called.
    Once a site has more than one account it must be said which, because acting as the wrong
    person is worse than one refused call.

    Raises:
        AmbiguousAccountError: when ``name`` has no account and its site has several.
        ValueError: when ``name`` is not a valid site name.

    """
    site, _, account = name.partition(ACCOUNT_SEPARATOR)
    if account == FIRST_ACCOUNT:
        return validate_site_name(site)
    site, account = split_site_name(name)
    if account is not None:
        return name
    accounts = sorted(
        (n for n in known_sites(roots) if split_site_name(n)[0] == site),
        key=lambda n: (split_site_name(n)[1] is not None, n),
    )
    if len(accounts) > 1:
        written = ", ".join(listed_name(n, accounts) for n in accounts)
        msg = f"{site} has accounts {written}. Say which."
        raise AmbiguousAccountError(msg)
    return accounts[0] if accounts else name


def site_name_for(value: str, suffixes: SuffixList | None = None) -> str:
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


def choose_site_name(roots: Roots, value: str, suffixes: SuffixList | None = None) -> str:
    """Pick the site name for the host or URL in ``value``, avoiding other sites on disk.

    Start from :func:`site_name_for`. A name is free when no account of it has a policy file or a
    profile directory. A name already used for the same registrable domain is returned as is, so
    naming a site twice finds the same site. Otherwise try ``name-2``, ``name-3`` and so on. The
    name has no account; the caller adds one or picks among the accounts the site has.
    """
    domain = registrable_domain(host_of(value), suffixes)
    base = site_name_for(value, suffixes)
    candidate = base
    number = 1
    while True:
        accounts = _accounts_on_disk(roots, candidate)
        if not accounts:
            return candidate
        if _site_domain(roots, accounts, suffixes) == domain:
            return candidate
        number += 1
        candidate = f"{base}-{number}"


def _accounts_on_disk(roots: Roots, site: str) -> list[str]:
    """Return the accounts of ``site`` that have a policy file or a profile directory."""
    names = {name for name in known_sites(roots) if split_site_name(name)[0] == site}
    profiles = profile_path(roots, site).parent
    for path in profiles.iterdir() if profiles.is_dir() else ():
        with contextlib.suppress(ValueError):
            name = site_from_key(path.name)
            if split_site_name(name)[0] == site:
                names.add(name)
    return sorted(names)


def _site_domain(roots: Roots, accounts: list[str], suffixes: SuffixList | None) -> str | None:
    """Return the registrable domain of the first of ``accounts`` whose policy can be read."""
    for name in accounts:
        try:
            policy = load_policy(roots, name)
        except OSError, PolicyError:
            continue
        return registrable_domain(host_of(policy.start), suffixes)
    return None


# -- paths ---------------------------------------------------------------------------------


def policy_path(roots: Roots, site: str) -> Path:
    """Return the path of ``site``'s policy file. Nothing is created."""
    return roots.config / APP_DIR / "sites" / f"{storage_key(site)}.json"


def profile_path(roots: Roots, site: str) -> Path:
    """Return the path of ``site``'s browser profile directory. Nothing is created."""
    return roots.state / APP_DIR / "profiles" / storage_key(site)


def downloads_path(roots: Roots, site: str) -> Path:
    """Return the path of ``site``'s downloads directory. Nothing is created."""
    return roots.state / APP_DIR / "downloads" / storage_key(site)


def runtime_path(roots: Roots) -> Path:
    """Return the runtime directory, ``$XDG_RUNTIME_DIR/valetkey``. Nothing is created.

    Raises:
        RuntimeDirUnavailableError: when ``XDG_RUNTIME_DIR`` was not set and ``/run/user/UID`` is
            not a private directory of the user. There is no other fallback, because sockets and
            other runtime files must not land in a shared directory.

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
    ``excluded`` lists hosts that a login saw and left out (trackers, error reporting, anything
    the pages used that it did not allow); a login builds it again each time. ``denied`` lists
    hosts the person turned down, with ``valetkey deny``; a login never changes it and never
    allows a host it blocks. A host under an entry of either list is refused even when an
    ``allow`` entry also covers it. A policy file written before ``denied`` existed has none.
    ``learned`` is when the lists were last built, in UTC with whole seconds, or ``None``.
    ``login_pages`` are the pages (as :func:`page_key` writes them, ``host/path``) a form was
    submitted from during the login, other than the start page and the page the login ended
    on. A start URL that ends on one of them means the login has expired. It is optional, and a
    policy written before it existed has none.
    ``login_cookies`` are the cookies (``host name``, never a value) that the login set on the
    site's own hosts and that look like its sign-in: if none of them is in the profile when the
    site is opened, the login has gone (see :mod:`valetkey.cookies`). It is optional.
    ``private_networks`` are the address ranges (``10.20.0.0/16``) in which a host the site
    allows may resolve although they are private, see :func:`private_network`. Only the person
    sets them. It is optional too.
    ``microphone`` says that the site's sessions may record the person's microphone, through a
    private audio graph (see :mod:`valetkey.audio`). Only the person turns it on, and it is off
    when the key is missing. It is written only when it is on.
    ``microphone_source`` names the source on the person's audio server that the microphone
    copies, instead of the default one. Only the person sets it, with ``valetkey mic``; it is
    only ever set while ``microphone`` is on, and is written only when set.
    ``ignored`` are the ``allow`` entries that :func:`load_policy` dropped because each is a
    public suffix (``github.io``), which would let the site reach every unrelated host under
    it. It is never written to the file.

    Construction validates every field and raises ``ValueError`` on a bad one.
    """

    site: str
    start: str
    allow: tuple[str, ...]
    excluded: tuple[str, ...] = ()
    learned: datetime | None = None
    login_pages: tuple[str, ...] = ()
    private_networks: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    login_cookies: tuple[str, ...] = ()
    microphone: bool = False
    microphone_source: str | None = None
    ignored: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate the fields."""
        validate_site_name(self.site)
        _validate_start(self.start)
        for entries in (self.allow, self.excluded, self.denied):
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
        for page in self.login_pages:
            if not (isinstance(page, str) and is_page_key(page)):
                msg = f"not a page like host/path, without query or fragment: {page!r}"
                raise ValueError(msg)
        if len(self.login_cookies) > MAX_LOGIN_COOKIES or not all(
            isinstance(entry, str) and _LOGIN_COOKIE_RE.fullmatch(entry)
            for entry in self.login_cookies
        ):
            msg = "login_cookies must be at most 20 entries like 'host name'"
            raise ValueError(msg)
        _validate_source(self.microphone, self.microphone_source)
        for network in self.private_networks:
            if not (isinstance(network, str) and private_network(network) == network):
                msg = f"not a private range written as 10.20.0.0/16: {network!r}"
                raise ValueError(msg)


_SOURCE_RE = re.compile(r"[A-Za-z0-9_.:@+-]{1,200}")


def validate_source(name: str) -> str:
    """Return ``name`` if it can name a source on an audio server, else raise ``ValueError``.

    Source names are letters, digits and ``_ . : @ + -``, as the names of devices and of the
    monitor of an output are (``alsa_input.usb-Mic-00.analog-stereo``, ``mix.monitor``). The
    limit also keeps the name safe to write into a configuration file.
    """
    if not (isinstance(name, str) and _SOURCE_RE.fullmatch(name)):
        msg = f"not an audio source name (letters, digits and _ . : @ + - only): {name!r}"
        raise ValueError(msg)
    return name


def _validate_source(microphone: bool, source: str | None) -> None:  # noqa: FBT001
    if source is None:
        return
    validate_source(source)
    if not microphone:
        msg = "microphone_source is only for a site with the microphone on"
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


def allow_host(policy: Policy, host: str) -> tuple[Policy, bool, list[str]]:
    """Return ``policy`` with ``host`` allowed, whether that was a change, and what was un-excluded.

    The host is added to ``allow`` (it then covers its subdomains). Every ``excluded`` entry that
    would block it is removed in the same step, because an excluded entry overrides ``allow``
    and covers its subdomains: that is the host itself or a wider entry above it. Nothing else
    in the policy changes. ``host`` must already be normalized (see :func:`host_of`).
    """
    added = host not in policy.allow
    allow = (*policy.allow, host) if added else policy.allow
    excluded = tuple(e for e in policy.excluded if not excluded_conflicts(e, [host]))
    denied = tuple(e for e in policy.denied if not excluded_conflicts(e, [host]))
    removed = [e for e in (*policy.excluded, *policy.denied) if e not in (*excluded, *denied)]
    return replace(policy, allow=allow, excluded=excluded, denied=denied), added, removed


def private_network(text: str) -> str:
    """Return ``text`` as a range a site may list, in its one canonical spelling.

    The range must be written with a prefix length and no host bits (``10.20.0.0/16``), lie
    inside the private address space (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) and be no
    wider than ``MIN_PRIVATE_PREFIX``. Loopback, link-local and the like are outside that space,
    so they can never be listed.

    Raises:
        ValueError: when it is none of that.

    """
    if not isinstance(text, str) or "/" not in text:
        msg = f"write the range with a prefix length, such as 10.20.0.0/24: {text!r}"
        raise ValueError(msg)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        msg = f"not a network such as 10.20.0.0/24 (no host bits set): {text!r}"
        raise ValueError(msg) from exc
    if not any(
        network.version == wide.version and network.subnet_of(wide)  # ty: ignore[invalid-argument-type]
        for wide in _PRIVATE_SUPERNETS
    ):
        msg = f"{text} is not in a private range (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)"
        raise ValueError(msg)
    if network.prefixlen < MIN_PRIVATE_PREFIX[network.version]:
        msg = f"{text} is too wide: use /{MIN_PRIVATE_PREFIX[network.version]} or narrower"
        raise ValueError(msg)
    return str(network)


def add_private_network(policy: Policy, text: str) -> tuple[Policy, bool]:
    """Return ``policy`` with the range ``text`` listed, and whether that was a change.

    Raises:
        ValueError: when ``text`` is not a range a site may list (see :func:`private_network`).

    """
    network = private_network(text)
    if network in policy.private_networks:
        return policy, False
    return replace(policy, private_networks=(*policy.private_networks, network)), True


def remove_private_network(policy: Policy, text: str) -> tuple[Policy, bool]:
    """Return ``policy`` without the range ``text``, and whether that was a change.

    Raises:
        ValueError: when ``text`` is not a range written like the listed ones.

    """
    network = private_network(text)
    kept = tuple(entry for entry in policy.private_networks if entry != network)
    if kept == policy.private_networks:
        return policy, False
    return replace(policy, private_networks=kept), True


def deny_host(policy: Policy, host: str) -> Policy:
    """Return ``policy`` with ``host`` denied: no longer allowed, and blocked from now on.

    The host's own ``allow`` entry is removed, and the host is added to ``denied`` unless it is
    there. A ``denied`` entry blocks the host and its subdomains even when a wider ``allow``
    entry covers them (``cdn.example.com`` denied with ``example.com`` allowed), so a host
    carved out of an allowed domain stays out. ``host`` must already be normalized (see
    :func:`host_of`).
    """
    allow = tuple(entry for entry in policy.allow if entry != host)
    denied = policy.denied if host in policy.denied else (*policy.denied, host)
    return replace(policy, allow=allow, denied=denied)


def allows(policy: Policy, host: str) -> bool:
    """Tell whether ``policy`` lets the browser connect to ``host``.

    True when ``host`` matches an ``allow`` entry (see :func:`host_matches`) and no ``excluded``
    or ``denied`` entry. Pure and cheap: meant to be called for every connection.
    """
    return host_matches(host, policy.allow) and not (
        host_matches(host, policy.excluded) or host_matches(host, policy.denied)
    )


def load_policy(roots: Roots, site: str, suffixes: SuffixList | None = None) -> Policy:
    """Read and validate ``site``'s policy file.

    The file must be a JSON object with the keys ``site``, ``start``, ``allow``, ``excluded``
    and ``learned``, and may also have ``denied``, ``login_cookies``, ``login_pages``,
    ``microphone``, ``microphone_source`` and ``private_networks``. A
    file without ``denied`` is one from before it existed: it has none, and its ``excluded``
    entries stay what a login left out, built again by the next login. Missing keys and
    unknown keys are both errors, and ``site`` must equal the file name. An ``allow`` entry that
    is a public suffix is left out and named in ``ignored``; with no suffix list on the machine
    the entries are kept, since the policy was written down before and its session must open.

    Raises:
        FileNotFoundError: when the site has no policy file.
        PolicyError: when the file is not valid.

    """
    path = policy_path(roots, site)
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
        keys = set(data) if isinstance(data, dict) else set()
        if not isinstance(data, dict) or not (
            set(_POLICY_KEYS) <= keys <= {*_POLICY_KEYS, *_OPTIONAL_POLICY_KEYS}
        ):
            msg = (
                f"expected an object with the keys {', '.join(_POLICY_KEYS)} "
                f"and perhaps {', '.join(_OPTIONAL_POLICY_KEYS)}"
            )
            raise PolicyError(msg)
        if data["site"] != site:
            msg = f"site is {data['site']!r} but the file is named for {site!r}"
            raise PolicyError(msg)
        allow, ignored = _split_suffixes(_hosts(data, "allow"), suffixes)
        return Policy(
            site=_text(data, "site"),
            start=_text(data, "start"),
            allow=allow,
            ignored=ignored,
            excluded=_hosts(data, "excluded"),
            denied=_hosts(data, "denied") if "denied" in data else (),
            learned=_learned(data["learned"]),
            login_pages=_hosts(data, "login_pages") if "login_pages" in data else (),
            login_cookies=_hosts(data, "login_cookies") if "login_cookies" in data else (),
            private_networks=(
                _hosts(data, "private_networks") if "private_networks" in data else ()
            ),
            microphone=_flag(data, "microphone"),
            microphone_source=data.get("microphone_source"),
        )
    except ValueError as exc:
        msg = f"{path}: {exc}"
        raise PolicyError(msg) from exc


def _split_suffixes(
    allow: tuple[str, ...], suffixes: SuffixList | None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the ``allow`` entries that are not public suffixes, and those that are."""
    try:
        found = suffixes or system_suffixes()
    except SuffixListError:
        return allow, ()
    ignored = tuple(entry for entry in allow if is_public_suffix(entry, found))
    return tuple(entry for entry in allow if entry not in ignored), ignored


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


def _flag(data: dict[str, Any], key: str) -> bool:
    """Return the optional true-or-false ``key`` of a policy file; a missing key is false."""
    value = data.get(key, False)
    if not isinstance(value, bool):
        msg = f"{key} must be true or false"
        raise PolicyError(msg)
    return value


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
        "denied": list(policy.denied),
        "learned": None if learned is None else learned.strftime(_LEARNED_FORMAT),
    }
    if policy.login_pages:
        data["login_pages"] = list(policy.login_pages)
    if policy.login_cookies:
        data["login_cookies"] = list(policy.login_cookies)
    if policy.private_networks:
        data["private_networks"] = list(policy.private_networks)
    if policy.microphone:
        data["microphone"] = True
    if policy.microphone_source is not None:
        data["microphone_source"] = policy.microphone_source
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
    descriptor, name = tempfile.mkstemp(
        dir=directory, prefix=f".{storage_key(policy.site)}.", suffix=".tmp"
    )
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
