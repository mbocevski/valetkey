# SPDX-License-Identifier: Apache-2.0
import json
import os
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from valetkey import sites
from valetkey.sites import (
    Policy,
    PolicyError,
    Roots,
    RuntimeDirUnavailableError,
    account_name,
    allows,
    choose_site_name,
    downloads_path,
    ensure_downloads,
    ensure_profile,
    ensure_runtime,
    host_matches,
    host_of,
    is_plausible_host,
    known_sites,
    listed_name,
    load_policy,
    normalize_host,
    policy_json,
    policy_path,
    profile_path,
    registrable_domain,
    resolve_account,
    roots_from_env,
    runtime_path,
    save_policy,
    site_from_key,
    site_name_for,
    split_site_name,
    storage_key,
    validate_site_name,
)

DISK_FULL = "disk full"
HAND_WRITTEN = """{
  "site": "sitex",
  "start": "https://sitex.com/",
  "allow": [
    "sitex.com",
    "login.okta.com"
  ],
  "excluded": [
    "o123.ingest.sentry.io"
  ],
  "learned": "2026-10-25T21:40:00Z"
}
"""


@pytest.fixture
def roots(tmp_path: Path) -> Roots:
    return Roots(config=tmp_path / "config", state=tmp_path / "state", runtime=tmp_path / "run")


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def policy(site: str = "sitex", **changes: Any) -> Policy:  # noqa: ANN401 - fields vary per test
    fields: dict[str, Any] = {
        "site": site,
        "start": f"https://{site}.com/",
        "allow": (f"{site}.com",),
    }
    fields.update(changes)
    return Policy(**fields)


def write_policy_file(roots: Roots, site: str, text: str) -> Path:
    path = policy_path(roots, site)
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return path


# -- environment and paths -----------------------------------------------------------------


def test_roots_from_env_uses_the_xdg_variables(tmp_path: Path) -> None:
    env = {
        "HOME": "/home/x",
        "XDG_CONFIG_HOME": str(tmp_path / "c"),
        "XDG_STATE_HOME": str(tmp_path / "s"),
        "XDG_RUNTIME_DIR": str(tmp_path / "r"),
    }
    assert roots_from_env(env) == Roots(tmp_path / "c", tmp_path / "s", tmp_path / "r")


def test_roots_from_env_defaults_under_home_and_has_no_runtime_default() -> None:
    found = roots_from_env({"HOME": "/home/x"})
    assert found == Roots(Path("/home/x/.config"), Path("/home/x/.local/state"), None)


def test_roots_from_env_ignores_empty_and_relative_values() -> None:
    env = {"HOME": "/h", "XDG_CONFIG_HOME": "", "XDG_STATE_HOME": "rel", "XDG_RUNTIME_DIR": "r"}
    assert roots_from_env(env) == Roots(Path("/h/.config"), Path("/h/.local/state"), None)


def test_roots_from_env_reads_the_process_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    found = roots_from_env()
    assert found.config == tmp_path / ".config"
    assert found.runtime == tmp_path / "run"


def test_roots_from_env_falls_back_to_the_user_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert roots_from_env({}).config == tmp_path / ".config"


def test_paths_follow_the_documented_layout(roots: Roots) -> None:
    assert policy_path(roots, "sitex") == roots.config / "valetkey/sites/sitex.json"
    assert profile_path(roots, "sitex") == roots.state / "valetkey/profiles/sitex"
    assert downloads_path(roots, "sitex") == roots.state / "valetkey/downloads/sitex"
    assert runtime_path(roots) == Path(f"{roots.runtime}/valetkey")


def test_runtime_path_fails_without_a_runtime_dir() -> None:
    with pytest.raises(RuntimeDirUnavailableError, match="XDG_RUNTIME_DIR"):
        runtime_path(Roots(Path("/c"), Path("/s"), None))
    with pytest.raises(RuntimeDirUnavailableError):
        ensure_runtime(Roots(Path("/c"), Path("/s"), None))


def test_path_functions_reject_bad_names(roots: Roots) -> None:
    for function in (policy_path, profile_path, downloads_path):
        with pytest.raises(ValueError, match="invalid site name"):
            function(roots, "../evil")


def test_ensure_creates_private_directories(roots: Roots) -> None:
    for path in (
        ensure_profile(roots, "sitex"),
        ensure_downloads(roots, "sitex"),
        ensure_runtime(roots),
    ):
        assert path.is_dir()
        assert mode(path) == 0o700
    assert mode(roots.state / "valetkey" / "profiles") == 0o700
    assert mode(roots.state / "valetkey") == 0o700


def test_ensure_tightens_an_open_directory(roots: Roots) -> None:
    path = profile_path(roots, "sitex")
    path.mkdir(parents=True)
    path.chmod(0o755)
    path.parent.chmod(0o750)
    assert ensure_profile(roots, "sitex") == path
    assert mode(path) == 0o700
    assert mode(path.parent) == 0o700


def test_ensure_is_idempotent_and_keeps_contents(roots: Roots) -> None:
    path = ensure_profile(roots, "sitex")
    (path / "cookie").write_text("x", encoding="utf-8")
    ensure_profile(roots, "sitex")
    assert (path / "cookie").read_text(encoding="utf-8") == "x"


def test_ensure_rejects_a_symlink_and_a_file(roots: Roots, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = profile_path(roots, "linked")
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    with pytest.raises(NotADirectoryError):
        ensure_profile(roots, "linked")
    plain = profile_path(roots, "plain")
    plain.write_text("", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        ensure_profile(roots, "plain")


def test_ensure_rejects_a_directory_of_another_user(
    roots: Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_profile(roots, "sitex")
    monkeypatch.setattr(os, "getuid", lambda: roots.state.stat().st_uid + 1)
    with pytest.raises(PermissionError, match="another user"):
        ensure_profile(roots, "sitex")


# -- names ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "name"),
    [
        ("sitex.com", "sitex"),
        ("SiteX.COM.", "sitex"),
        ("https://sitex.com/login", "sitex"),
        ("https://user@app.sitex.com:8443/a?b#c", "sitex"),
        ("app.sitex.co.uk", "sitex"),
        ("http://www.sitex.com.au/x", "sitex"),
        ("localhost", "localhost"),
        ("a.b.c.d.example.org", "example"),
        ("xn--bcher-kva.example", "xn--bcher-kva"),
        ("sitex.com:8080/path", "sitex"),
        ("[::1]", None),
        ("1.2.3.4", None),
    ],
)
def test_site_name_for(value: str, name: str | None) -> None:
    if name is None:
        with pytest.raises(ValueError, match="IP address"):
            site_name_for(value)
    else:
        assert site_name_for(value) == name


def test_site_name_for_cuts_a_long_label() -> None:
    name = site_name_for(f"{'a' * 31}-{'b' * 20}.com")
    assert name == "a" * 31
    assert validate_site_name(name) == name


def test_site_name_for_takes_custom_suffixes() -> None:
    assert site_name_for("app.sitex.example.com") == "example"
    assert site_name_for("app.sitex.example.com", frozenset({"example.com"})) == "sitex"


@pytest.mark.parametrize("value", ["", "   ", "http://", "https:///path", "http://[::1", "a b.com"])
def test_site_name_for_rejects_values_without_a_host(value: str) -> None:
    with pytest.raises(ValueError, match="cannot read a host"):
        site_name_for(value)


def test_host_of_reads_hosts_and_urls() -> None:
    assert host_of(" HTTPS://App.SiteX.com:443/x ") == "app.sitex.com"
    assert host_of("http://[::1]:8080/") == "::1"
    assert host_of("sitex.com/login") == "sitex.com"


def test_registrable_domain() -> None:
    assert registrable_domain("app.sitex.co.uk") == "sitex.co.uk"
    assert registrable_domain("a.b.sitex.com.") == "sitex.com"
    assert registrable_domain("sitex.com") == "sitex.com"
    assert registrable_domain("localhost") == "localhost"
    assert registrable_domain("10.0.0.1") == "10.0.0.1"


@pytest.mark.parametrize("name", ["a", "sitex", "site-x", "a-", "0", "9lives", "a" * 48])
def test_valid_site_names(name: str) -> None:
    assert validate_site_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../x",
        "x/..",
        "a/b",
        "/etc",
        "a\\b",
        "\\",
        "-x",
        "-",
        "Sitex",
        "site x",
        "site_x",
        "site.x",
        "sitex:",
        ":work",
        "sitex:-work",
        "sitex:work:home",
        "sitex:Work",
        "sitex:8080",
        "sitex:1work",
        "sitex:main",
        "x\n",
        "x\0",
        "a" * 49,
        "sité",
        "\uff53itex",
        "sitex\u202e",
        "\u212a",
        "\u2179",
        "\u0663",
    ],
)
def test_invalid_site_names_are_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="invalid site name"):
        validate_site_name(name)


def test_validate_site_name_rejects_non_strings() -> None:
    with pytest.raises(ValueError, match="invalid site name"):
        validate_site_name(None)  # ty: ignore[invalid-argument-type]


def test_choose_site_name_uses_a_free_name(roots: Roots) -> None:
    assert choose_site_name(roots, "https://sitex.com/") == "sitex"


def test_choose_site_name_reuses_a_site_for_the_same_domain(roots: Roots) -> None:
    save_policy(roots, policy("sitex"))
    assert choose_site_name(roots, "app.sitex.com") == "sitex"


def test_choose_site_name_numbers_a_different_domain(roots: Roots) -> None:
    save_policy(roots, policy("sitex"))
    assert choose_site_name(roots, "sitex.org") == "sitex-2"
    save_policy(roots, policy("sitex-2", start="https://sitex.org/", allow=("sitex.org",)))
    assert choose_site_name(roots, "sitex.net") == "sitex-3"
    assert choose_site_name(roots, "sitex.org") == "sitex-2"


def test_choose_site_name_treats_a_profile_without_policy_as_taken(roots: Roots) -> None:
    ensure_profile(roots, "sitex")
    assert choose_site_name(roots, "sitex.com") == "sitex-2"


def test_choose_site_name_treats_a_broken_policy_as_another_domain(roots: Roots) -> None:
    write_policy_file(roots, "sitex", "not json")
    assert choose_site_name(roots, "sitex.com") == "sitex-2"


# -- accounts ------------------------------------------------------------------------------


def test_a_name_may_carry_an_account() -> None:
    assert validate_site_name("sitex:work") == "sitex:work"
    assert split_site_name("sitex:work") == ("sitex", "work")
    assert split_site_name("sitex") == ("sitex", None)
    assert account_name("sitex", "work") == "sitex:work"
    assert account_name("sitex", None) == account_name("sitex", "main") == "sitex"
    with pytest.raises(ValueError, match="invalid site name"):
        account_name("sitex", "Work")


def test_the_account_less_name_is_written_main_once_the_site_has_another() -> None:
    assert listed_name("sitex", ["sitex"]) == "sitex"
    assert listed_name("sitex", ["sitex", "sitexy"]) == "sitex"
    assert listed_name("sitex", ["sitex", "sitex:work"]) == "sitex:main"
    assert listed_name("sitex:work", ["sitex", "sitex:work"]) == "sitex:work"
    assert listed_name("sitex:work", ["sitex:work"]) == "sitex:work"


def test_a_name_with_an_account_is_cut_at_48_characters() -> None:
    assert validate_site_name("a" * 24 + ":" + "b" * 23)
    with pytest.raises(ValueError, match="invalid site name"):
        validate_site_name("a" * 24 + ":" + "b" * 24)


def test_an_account_has_its_own_files_and_a_bare_name_keeps_the_old_ones(roots: Roots) -> None:
    assert storage_key("sitex") == "sitex"
    assert storage_key("sitex:work") == "sitex.work"
    assert policy_path(roots, "sitex").name == "sitex.json"
    assert policy_path(roots, "sitex:work").name == "sitex.work.json"
    assert profile_path(roots, "sitex:work").name == "sitex.work"
    assert downloads_path(roots, "sitex:work").name == "sitex.work"
    save_policy(roots, policy("sitex:work", start="https://sitex.com/", allow=("sitex.com",)))
    assert load_policy(roots, "sitex:work").site == "sitex:work"
    assert not policy_path(roots, "sitex").exists()


@pytest.mark.parametrize(
    ("key", "name"), [("sitex", "sitex"), ("sitex.work", "sitex:work"), ("a-1.b-2", "a-1:b-2")]
)
def test_site_from_key_undoes_storage_key(key: str, name: str) -> None:
    assert site_from_key(key) == name
    assert storage_key(name) == key


@pytest.mark.parametrize("key", ["a.b.c", ".x", "x.", "Sitex", "a b"])
def test_site_from_key_rejects_what_is_no_key(key: str) -> None:
    with pytest.raises(ValueError, match=r"storage key|invalid site name"):
        site_from_key(key)


def test_known_sites_lists_every_account_and_skips_strays(roots: Roots) -> None:
    assert known_sites(roots) == []
    for name in ("sitex", "sitex:work", "another"):
        save_policy(roots, policy(name, start="https://x.com/", allow=("x.com",)))
    directory = policy_path(roots, "x").parent
    (directory / "a.b.c.json").write_text("{}")
    (directory / "notes.txt").write_text("")
    (directory / "dir.json").mkdir()
    assert known_sites(roots) == ["another", "sitex", "sitex:work"]


def test_a_bare_name_is_the_only_account_of_a_site(roots: Roots) -> None:
    assert resolve_account(roots, "sitex") == "sitex"
    save_policy(roots, policy("sitex:work", start="https://sitex.com/", allow=("sitex.com",)))
    assert resolve_account(roots, "sitex") == "sitex:work"
    assert resolve_account(roots, "sitex:work") == "sitex:work"
    assert resolve_account(roots, "sitex:home") == "sitex:home"


def test_a_bare_name_is_refused_once_a_site_has_several_accounts(roots: Roots) -> None:
    save_policy(roots, policy("sitex"))
    save_policy(roots, policy("sitex:work", start="https://sitex.com/", allow=("sitex.com",)))
    save_policy(roots, policy("sitexy"))
    with pytest.raises(sites.AmbiguousAccountError) as error:
        resolve_account(roots, "sitex")
    assert str(error.value) == "sitex has accounts sitex:main, sitex:work. Say which."
    assert resolve_account(roots, "sitex:main") == "sitex"
    assert resolve_account(roots, "sitex:work") == "sitex:work"
    assert resolve_account(roots, "sitexy") == "sitexy"


def test_choose_site_name_counts_every_account_as_the_site(roots: Roots) -> None:
    save_policy(roots, policy("sitex:work", start="https://sitex.com/", allow=("sitex.com",)))
    assert choose_site_name(roots, "app.sitex.com") == "sitex"
    assert choose_site_name(roots, "sitex.org") == "sitex-2"
    ensure_profile(roots, "other:home")
    (profile_path(roots, "other").parent / "a.b.c").mkdir(parents=True, exist_ok=True)
    assert choose_site_name(roots, "other.com") == "other-2"


def test_choose_site_name_skips_an_account_whose_policy_is_broken(roots: Roots) -> None:
    write_policy_file(roots, "sitex:work", "not json")
    save_policy(roots, policy("sitex:home", start="https://sitex.com/", allow=("sitex.com",)))
    assert choose_site_name(roots, "sitex.com") == "sitex"


# -- host matching -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("sitex.com", True),
        ("SITEX.COM", True),
        ("sitex.com.", True),
        ("login.sitex.com", True),
        ("a.b.c.sitex.com", True),
        ("notsitex.com", False),
        ("sitex.com.evil.org", False),
        ("sitex.co", False),
        ("com", False),
        ("evil-sitex.com", False),
        (".sitex.com", False),
        ("a..sitex.com", False),
        ("", False),
        (".", False),
        ("sitex.com:443", False),
        ("sitex.com/", False),
        ("sitex.com\u212a", False),
    ],
)
def test_host_matching_on_a_dot_boundary(host: str, expected: bool) -> None:  # noqa: FBT001
    assert host_matches(host, ["sitex.com"]) is expected


def test_ip_literals_match_only_exactly() -> None:
    entries = ["10.0.0.1", "0.1", "sitex.com"]
    assert host_matches("10.0.0.1", entries)
    assert not host_matches("10.0.0.1", ["0.0.1", "1"])
    assert not host_matches("10.0.0.2", entries)
    assert not host_matches("[::1]", entries)
    assert not host_matches("::1", ["1"])


def test_ip_entries_are_not_suffixes_of_domains() -> None:
    assert not host_matches("x.10.0.0.1", ["10.0.0.1"])
    assert host_matches("10.0.0.1", ["10.0.0.1"])


def test_ipv6_brackets_are_stripped() -> None:
    assert normalize_host("[::1]") == "::1"
    assert normalize_host("[2001:DB8::1]") == "2001:db8::1"


def test_normalize_host() -> None:
    assert normalize_host("SiteX.COM.") == "sitex.com"
    assert normalize_host("") == ""
    assert normalize_host("\u212a") == "\u212a"


def test_plausible_hosts() -> None:
    for good in ("sitex.com", "a-b.c1.io", "localhost", "10.0.0.1", "2001:db8::1", "::1"):
        assert is_plausible_host(good), good
    for bad in (
        "",
        "Sitex.com",
        "https://sitex.com",
        "sitex.com/x",
        "sitex.com:80",
        "-a.com",
        "a-.com",
        "a..com",
        ".a.com",
        "a.com.",
        "*.a.com",
        "a_b.com",
        "a b",
        "é.com",
        "a" * 64 + ".com",
        ("a" * 60 + ".") * 5 + "com",
        "[::1]",
        "::G",
    ):
        assert not is_plausible_host(bad), bad


def test_allows_checks_allow_and_excluded() -> None:
    pol = policy(
        allow=("sitex.com", "login.okta.com"),
        excluded=("track.sitex.com", "o1.ingest.sentry.io"),
    )
    assert allows(pol, "sitex.com")
    assert allows(pol, "cdn.sitex.com")
    assert allows(pol, "LOGIN.okta.com.")
    assert not allows(pol, "okta.com")
    assert not allows(pol, "track.sitex.com")
    assert not allows(pol, "x.track.sitex.com")
    assert not allows(pol, "o1.ingest.sentry.io")
    assert not allows(pol, "notsitex.com")
    assert not allows(pol, "")


def test_allows_nothing_with_an_empty_policy() -> None:
    assert not allows(policy(allow=()), "sitex.com")


# -- policy model --------------------------------------------------------------------------


def test_policy_is_immutable() -> None:
    pol = policy()
    with pytest.raises(AttributeError):
        pol.site = "other"  # ty: ignore[invalid-assignment]


@pytest.mark.parametrize(
    "changes",
    [
        {"site": "../x"},
        {"start": "ftp://sitex.com/"},
        {"start": "sitex.com"},
        {"start": "https:///x"},
        {"start": "https://u:p@sitex.com/"},
        {"start": "https://sitex.com:bad/"},
        {"start": "https://[::1/"},
        {"start": "https://a b.com/"},
        {"allow": ("Sitex.com",)},
        {"allow": ("https://sitex.com",)},
        {"allow": ("sitex.com/x",)},
        {"allow": ("sitex.com:443",)},
        {"allow": ("",)},
        {"allow": (5,)},
        {"excluded": ("*.x.com",)},
        {"learned": datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2)))},
        {"learned": datetime(2026, 1, 1)},  # noqa: DTZ001
        {"learned": datetime(2026, 1, 1, 0, 0, 0, 5, tzinfo=UTC)},
    ],
)
def test_policy_rejects_bad_fields(changes: dict[str, Any]) -> None:
    with pytest.raises((ValueError, AttributeError)):
        policy(**changes)


def test_policy_accepts_http_ports_and_ip_starts() -> None:
    assert policy(start="http://127.0.0.1:8080/app").start == "http://127.0.0.1:8080/app"
    assert policy(start="https://[::1]:8443/").start == "https://[::1]:8443/"


# -- load and save -------------------------------------------------------------------------


def test_hand_written_file_loads(roots: Roots) -> None:
    write_policy_file(roots, "sitex", HAND_WRITTEN)
    loaded = load_policy(roots, "sitex")
    assert loaded == Policy(
        site="sitex",
        start="https://sitex.com/",
        allow=("sitex.com", "login.okta.com"),
        excluded=("o123.ingest.sentry.io",),
        learned=datetime(2026, 10, 25, 21, 40, tzinfo=UTC),
    )


def test_round_trip_is_stable(roots: Roots) -> None:
    path = write_policy_file(roots, "sitex", HAND_WRITTEN)
    loaded = load_policy(roots, "sitex")
    assert policy_json(loaded) == HAND_WRITTEN
    path.unlink()
    assert save_policy(roots, loaded) == path
    assert path.read_text(encoding="utf-8") == HAND_WRITTEN
    assert load_policy(roots, "sitex") == loaded


def test_null_learned_and_empty_lists_round_trip(roots: Roots) -> None:
    original = policy(allow=(), excluded=(), learned=None)
    save_policy(roots, original)
    assert load_policy(roots, "sitex") == original
    assert '"learned": null' in policy_json(original)


def test_save_sets_modes(roots: Roots) -> None:
    path = save_policy(roots, policy())
    assert mode(path) == 0o600
    assert mode(path.parent) == 0o700
    assert mode(path.parent.parent) == 0o700
    assert [p.name for p in path.parent.iterdir()] == ["sitex.json"]


def test_save_replaces_the_old_file(roots: Roots) -> None:
    save_policy(roots, policy())
    save_policy(roots, policy(allow=("sitex.com", "cdn.example.net")))
    assert load_policy(roots, "sitex").allow == ("sitex.com", "cdn.example.net")


def test_failed_write_leaves_the_old_file_intact(
    roots: Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = save_policy(roots, policy())
    before = path.read_bytes()

    def fail(_descriptor: int) -> None:
        raise OSError(DISK_FULL)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="disk full"):
        save_policy(roots, policy(allow=("other.example",)))
    monkeypatch.undo()
    assert path.read_bytes() == before
    assert [p.name for p in path.parent.iterdir()] == ["sitex.json"]


def test_failed_first_write_leaves_no_file(roots: Roots, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_source: object, _target: object) -> None:
        raise OSError(DISK_FULL)

    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        save_policy(roots, policy())
    monkeypatch.undo()
    assert list(policy_path(roots, "sitex").parent.iterdir()) == []


def test_missing_file_raises_file_not_found(roots: Roots) -> None:
    with pytest.raises(FileNotFoundError):
        load_policy(roots, "sitex")


def good(**changes: object) -> str:
    data: dict[str, object] = json.loads(HAND_WRITTEN)
    data.update(changes)
    return json.dumps(data)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "Expecting value"),
        ("{", "Expecting"),
        ("[]", "expected an object with the keys"),
        ("null", "expected an object with the keys"),
        ('{"site": "sitex"}', "expected an object with the keys"),
        (good(extra=1), "expected an object with the keys"),
        (good(site="other"), "named for"),
        (good(site=5), "named for"),
        (good(start=5), "start must be a string"),
        (good(start="ftp://sitex.com"), "http or https"),
        (good(allow="sitex.com"), "allow must be a list"),
        (good(allow=["sitex.com", 5]), "allow must be a list"),
        (good(allow=["Sitex.com"]), "plausible host"),
        (good(excluded=None), "excluded must be a list"),
        (good(learned="yesterday"), "learned must be"),
        (good(learned=5), "learned must be"),
        (good(learned="2026-10-25T21:40:00+00:00"), "learned must be"),
        (good(learned="2026-13-25T21:40:00Z"), "month"),
    ],
)
def test_invalid_policy_files_are_rejected(roots: Roots, text: str, message: str) -> None:
    write_policy_file(roots, "sitex", text)
    with pytest.raises(PolicyError, match=message) as info:
        load_policy(roots, "sitex")
    assert "sitex.json" in str(info.value)


def test_invalid_utf8_is_a_policy_error(roots: Roots) -> None:
    path = write_policy_file(roots, "sitex", "")
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(ValueError, match="codec"):
        load_policy(roots, "sitex")


def test_module_exports_are_importable() -> None:
    assert {"co.uk", "com.au"} <= sites.TWO_LEVEL_SUFFIXES


@pytest.mark.parametrize(
    ("excluded", "allow", "expected"),
    [
        ("okta.com", ["login.okta.com"], True),
        ("login.okta.com", ["login.okta.com"], True),
        ("static.login.okta.com", ["login.okta.com"], False),
        ("example.org", ["login.okta.com"], False),
        ("okta.com", [], False),
        ("192.0.2.7", ["192.0.2.7"], True),
        ("0.2.7", ["192.0.2.7"], False),
    ],
)
def test_excluded_conflicts(excluded: str, allow: list[str], *, expected: bool) -> None:
    assert sites.excluded_conflicts(excluded, allow) is expected


# -- pages and login pages -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "key"),
    [
        ("https://SiteX.com/", "sitex.com/"),
        ("https://sitex.com", "sitex.com/"),
        ("http://sitex.com:8080/login?next=/a#frag", "sitex.com/login"),
        ("https://user:pw@sitex.com/a/b/", "sitex.com/a/b"),
        ("https://sitex.com/a//b", "sitex.com/a//b"),
        ("https://sitex.com./x", "sitex.com/x"),
        ("https://[::1]/x", "::1/x"),
        ("ftp://sitex.com/x", None),
        ("about:blank", None),
        ("chrome-error://chromewebdata/", None),
        ("https:///x", None),
        ("https://exa mple.com/", None),
        ("http://[::1/", None),
        ("", None),
    ],
)
def test_page_key(url: str, key: str | None) -> None:
    assert sites.page_key(url) == key


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("sitex.com/", True),
        ("sitex.com/login", True),
        ("login.okta.com/signin/v2/identifier", True),
        ("sitex.com", False),
        ("sitex.com/login/", False),
        ("sitex.com/login?x=1", False),
        ("sitex.com/login#top", False),
        ("sitex.com/a b", False),
        ("sitex.com//x", False),
        ("Sitex.com/login", False),
        ("/login", False),
        ("", False),
        ("sitex.com/\nx", False),
    ],
)
def test_is_page_key(value: str, valid: bool) -> None:  # noqa: FBT001
    assert sites.is_page_key(value) is valid


def test_login_pages_round_trip_and_are_left_out_when_there_are_none(roots: Roots) -> None:
    plain = policy()
    assert "login_pages" not in sites.policy_json(plain)
    with_pages = policy(login_pages=("sitex.com/login", "login.okta.com/signin"))
    save_policy(roots, with_pages)
    assert load_policy(roots, "sitex").login_pages == ("sitex.com/login", "login.okta.com/signin")
    assert json.loads(sites.policy_json(with_pages))["login_pages"] == [
        "sitex.com/login",
        "login.okta.com/signin",
    ]


def test_a_policy_file_from_before_login_pages_still_loads(roots: Roots) -> None:
    write_policy_file(roots, "sitex", HAND_WRITTEN)
    assert load_policy(roots, "sitex").login_pages == ()


@pytest.mark.parametrize("pages", [("sitex.com",), ("sitex.com/login?x=1",), ("",), (5,)])
def test_bad_login_pages_are_rejected(pages: tuple[object, ...]) -> None:
    with pytest.raises(ValueError, match="host/path"):
        policy(login_pages=pages)


def test_login_pages_must_be_a_list_of_strings(roots: Roots) -> None:
    write_policy_file(roots, "sitex", good(login_pages="sitex.com/login"))
    with pytest.raises(PolicyError, match="login_pages must be a list of strings"):
        load_policy(roots, "sitex")


def test_allow_host_adds_it_and_drops_every_exclusion_that_covers_it() -> None:
    policy = sites.Policy(
        "s", "https://s.test/", ("s.test",), ("sitexassets.net", "cdn.sitexassets.net", "o.test"),
        datetime(2026, 1, 1, tzinfo=UTC), ("s.test/login",),
    )  # fmt: skip
    changed, added, removed = sites.allow_host(policy, "cdn.sitexassets.net")
    assert (added, removed) == (True, ["sitexassets.net", "cdn.sitexassets.net"])
    assert changed.allow == ("s.test", "cdn.sitexassets.net")
    assert changed.excluded == ("o.test",)
    assert (changed.start, changed.learned, changed.login_pages) == (
        policy.start,
        policy.learned,
        policy.login_pages,
    )
    assert sites.allows(changed, "cdn.sitexassets.net")


def test_allow_host_for_an_allowed_host_changes_nothing() -> None:
    policy = sites.Policy("s", "https://s.test/", ("s.test",), (), datetime(2026, 1, 1, tzinfo=UTC))
    assert sites.allow_host(policy, "s.test") == (policy, False, [])


# -- private networks ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("10.20.0.0/16", "10.20.0.0/16"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("172.16.0.0/12", "172.16.0.0/12"),
        ("192.168.1.7/32", "192.168.1.7/32"),
        ("100.64.0.0/10", "100.64.0.0/10"),
        ("FD12:3456:789A::/48", "fd12:3456:789a::/48"),
        ("fd12:3456:789a:1::/64", "fd12:3456:789a:1::/64"),
    ],
)
def test_private_network_accepts_and_canonicalises(text: str, canonical: str) -> None:
    assert sites.private_network(text) == canonical


@pytest.mark.parametrize(
    "text",
    [
        "10.20.0.0", "10.20.0.1/24", "10.0.0.0/7", "0.0.0.0/0", "8.8.8.0/24", "127.0.0.0/8",
        "127.0.0.1/32", "169.254.169.254/32", "169.254.0.0/16", "224.0.0.0/8", "172.15.0.0/16",
        "172.32.0.0/16", "192.169.0.0/16", "100.128.0.0/16", "::1/128", "fe80::/64", "fc00::/7",
        "fd00::/8", "fd00::/47", "2001:db8::/48", "::ffff:10.0.0.0/104", "", "/8", "10.0.0.0/",
        "a/b", "10.0.0.0/33", 5, None, ["10.0.0.0/8"],
    ],
)  # fmt: skip
def test_private_network_refuses_the_rest(text: Any) -> None:  # noqa: ANN401
    with pytest.raises(ValueError, match=r"."):
        sites.private_network(text)


def test_policy_with_private_networks_round_trips(tmp_path: Path) -> None:
    roots = sites.Roots(tmp_path / "c", tmp_path / "s", tmp_path / "r")
    policy = sites.Policy(
        "intra", "https://wiki.corp.test/", ("corp.test",), (), None, ("corp.test/login",),
        ("10.20.0.0/16", "fd12:3456:789a::/48"),
    )  # fmt: skip
    sites.save_policy(roots, policy)
    assert sites.load_policy(roots, "intra") == policy
    assert '"private_networks": [\n    "10.20.0.0/16"' in sites.policy_json(policy)


def test_a_policy_without_the_field_is_still_valid_and_writes_none(tmp_path: Path) -> None:
    roots = sites.Roots(tmp_path / "c", tmp_path / "s", tmp_path / "r")
    plain = sites.Policy("intra", "https://wiki.corp.test/", ("corp.test",))
    sites.save_policy(roots, plain)
    assert "private_networks" not in sites.policy_path(roots, "intra").read_text(encoding="utf-8")
    assert sites.load_policy(roots, "intra").private_networks == ()


@pytest.mark.parametrize(
    "value",
    [["10.20.0.1/16"], ["8.8.8.0/24"], ["10.20.0.0"], [5], "10.20.0.0/16", ["FD12:3456:789A::/48"]],
)
def test_a_policy_file_with_a_bad_range_is_rejected(tmp_path: Path, value: Any) -> None:  # noqa: ANN401
    roots = sites.Roots(tmp_path / "c", tmp_path / "s", tmp_path / "r")
    sites.save_policy(roots, sites.Policy("intra", "https://wiki.corp.test/", ("corp.test",)))
    path = sites.policy_path(roots, "intra")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["private_networks"] = value
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(sites.PolicyError):
        sites.load_policy(roots, "intra")


def test_a_policy_object_with_a_bad_range_is_rejected() -> None:
    with pytest.raises(ValueError, match="private range"):
        sites.Policy("s", "https://s.test/", ("s.test",), private_networks=("8.8.8.0/24",))


def test_add_and_remove_a_private_network() -> None:
    policy = sites.Policy("s", "https://s.test/", ("s.test",))
    added, done = sites.add_private_network(policy, "10.20.0.0/24")
    assert (done, added.private_networks) == (True, ("10.20.0.0/24",))
    again, done = sites.add_private_network(added, "10.20.0.0/24")
    assert (done, again) == (False, added)
    both, _ = sites.add_private_network(added, "192.168.0.0/24")
    assert both.private_networks == ("10.20.0.0/24", "192.168.0.0/24")
    removed, done = sites.remove_private_network(both, "10.20.0.0/24")
    assert (done, removed.private_networks) == (True, ("192.168.0.0/24",))
    same, done = sites.remove_private_network(removed, "10.20.0.0/24")
    assert (done, same) == (False, removed)
    assert both.allow == policy.allow
    with pytest.raises(ValueError, match=r"."):
        sites.add_private_network(policy, "8.8.8.0/24")
    with pytest.raises(ValueError, match=r"."):
        sites.remove_private_network(policy, "nonsense")


# -- the runtime directory when the environment lost it ----------------------------------------


def make_user_runtime(root: Path, uid: int, mode: int = 0o700) -> Path:
    directory = root / str(uid)
    directory.mkdir(parents=True)
    directory.chmod(mode)
    return directory


def test_the_login_managers_runtime_dir_stands_in_when_it_is_private_and_ours(
    tmp_path: Path,
) -> None:
    mine = make_user_runtime(tmp_path, os.getuid())
    assert sites.fallback_runtime_dir(root=tmp_path) == mine


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o777, 0o500])
def test_a_runtime_dir_others_can_enter_or_that_is_not_0700_is_not_used(
    tmp_path: Path, mode: int
) -> None:
    make_user_runtime(tmp_path, os.getuid(), mode)
    assert sites.fallback_runtime_dir(root=tmp_path) is None


def test_a_missing_foreign_or_linked_runtime_dir_is_not_used(tmp_path: Path) -> None:
    assert sites.fallback_runtime_dir(root=tmp_path) is None  # nothing there
    make_user_runtime(tmp_path, os.getuid() + 1)
    assert sites.fallback_runtime_dir(root=tmp_path) is None  # another user's
    (tmp_path / "elsewhere").mkdir(mode=0o700)
    (tmp_path / str(os.getuid())).symlink_to(tmp_path / "elsewhere")
    assert sites.fallback_runtime_dir(root=tmp_path) is None  # a link is not a real directory
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / str(os.getuid())).write_text("a file", encoding="utf-8")
    assert sites.fallback_runtime_dir(root=tmp_path / "plain") is None


def test_a_directory_that_belongs_to_another_uid_is_not_used(tmp_path: Path) -> None:
    make_user_runtime(tmp_path, os.getuid())
    other = os.getuid() + 1
    (tmp_path / str(other)).symlink_to(tmp_path / str(os.getuid()), target_is_directory=True)
    # Asked for another user's directory, what is found is ours and so not theirs.
    assert sites.fallback_runtime_dir(uid=other, root=tmp_path) is None


def test_the_process_environment_without_a_runtime_dir_uses_the_stand_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mine = make_user_runtime(tmp_path, os.getuid())
    monkeypatch.setattr(sites, "USER_RUNTIME_ROOT", tmp_path)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert roots_from_env().runtime == mine
    assert sites.runtime_path(roots_from_env()) == mine / "valetkey"
    monkeypatch.setenv("XDG_RUNTIME_DIR", "relative")
    assert roots_from_env().runtime == mine
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "set"))
    assert roots_from_env().runtime == tmp_path / "set"  # a variable that is set wins


def test_a_given_environment_never_uses_the_stand_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_user_runtime(tmp_path, os.getuid())
    monkeypatch.setattr(sites, "USER_RUNTIME_ROOT", tmp_path)
    assert roots_from_env({"HOME": "/h"}).runtime is None
    with pytest.raises(sites.RuntimeDirUnavailableError):
        sites.runtime_path(roots_from_env({"HOME": "/h"}))


def test_no_stand_in_leaves_the_error_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sites, "USER_RUNTIME_ROOT", tmp_path)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert roots_from_env().runtime is None
