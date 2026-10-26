# SPDX-License-Identifier: Apache-2.0

import shutil
import sqlite3
import subprocess
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from valetkey import learn, sites

if TYPE_CHECKING:
    from pathlib import Path

START = "https://app.sitex.com/login"
NOW = datetime(2026, 10, 26, 9, 30, 15, 999999, tzinfo=UTC)

LINK, TYPED, AUTO_SUBFRAME, MANUAL_SUBFRAME = 0, 1, 3, 4
CHAIN_START, CHAIN_END = 0x10000000, 0x20000000
SERVER_REDIRECT = 0x80000000
FROM_API = 0x08000000

# The schema Chromium 156 writes, reduced to the columns the code reads and the ones it
# joins on.
SCHEMA = """
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
    visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
    last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL,
    visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL);
"""

type Visit = tuple[str, int]


def signed(value: int) -> int:
    """Return ``value`` as SQLite stores Chromium's 32-bit flags: sign-extended."""
    return value - (1 << 32) if value & 0x80000000 else value


def build(path: Path, visits: list[Visit], *, wal: bool = False) -> sqlite3.Connection:
    database = sqlite3.connect(path)
    if wal:
        database.execute("PRAGMA journal_mode=WAL")
        database.execute("PRAGMA wal_autocheckpoint=0")
    database.executescript(SCHEMA)
    for number, (url, transition) in enumerate(visits, start=1):
        database.execute(
            "INSERT INTO urls(url, last_visit_time) VALUES (?, ?)",
            (url, number),
        )
        database.execute(
            "INSERT INTO visits(url, visit_time, transition) VALUES (?, ?, ?)",
            (number, number, signed(transition)),
        )
    database.commit()
    return database


def history(tmp_path: Path, visits: list[Visit]) -> Path:
    path = tmp_path / "History"
    build(path, visits).close()
    return path


def test_same_domain_login(tmp_path: Path) -> None:
    path = history(
        tmp_path,
        [
            ("https://app.sitex.com/login", TYPED),
            ("https://app.sitex.com/home", LINK),
            ("https://www.sitex.com/", LINK),
        ],
    )
    hosts = learn.navigation_hosts(path)
    assert hosts == {"app.sitex.com", "www.sitex.com"}
    assert learn.classify(START, ["app.sitex.com", "cdn.sitex.com"], hosts) == learn.Classification(
        allow=("sitex.com",), excluded=()
    )


def test_redirect_chain_through_an_sso_provider(tmp_path: Path) -> None:
    path = history(
        tmp_path,
        [
            ("https://app.sitex.com/login", TYPED | CHAIN_START | FROM_API),
            ("https://login.okta.com/sso?x=1", LINK | SERVER_REDIRECT | FROM_API),
            ("https://login.okta.com/signin", LINK | SERVER_REDIRECT),
            ("https://app.sitex.com/home", LINK | CHAIN_END | SERVER_REDIRECT),
        ],
    )
    hosts = learn.navigation_hosts(path)
    result = learn.classify(START, ["app.sitex.com", "login.okta.com", "okta.com"], hosts)
    assert result.allow == ("login.okta.com", "sitex.com")
    assert result.excluded == ()


def test_popup_sso_is_a_separate_top_level_visit(tmp_path: Path) -> None:
    path = history(
        tmp_path,
        [("https://app.sitex.com/", TYPED), ("https://accounts.google.com/o/oauth2/auth", LINK)],
    )
    result = learn.classify(START, [], learn.navigation_hosts(path))
    assert result.allow == ("accounts.google.com", "sitex.com")


def test_navigation_hosts_the_proxy_never_saw_still_count() -> None:
    result = learn.classify(START, ["app.sitex.com"], ["login.okta.com"])
    assert result.allow == ("login.okta.com", "sitex.com")


def test_beacons_seen_by_the_proxy_are_excluded(tmp_path: Path) -> None:
    path = history(tmp_path, [("https://app.sitex.com/login", TYPED)])
    seen = ["app.sitex.com", "t.tracker.example", "cdn.metrics.io", "t.tracker.example"]
    result = learn.classify(START, seen, learn.navigation_hosts(path))
    assert result.allow == ("sitex.com",)
    assert result.excluded == ("cdn.metrics.io", "t.tracker.example")


def test_subframe_only_hosts_are_excluded(tmp_path: Path) -> None:
    path = history(
        tmp_path,
        [
            ("https://app.sitex.com/login", TYPED),
            ("https://ads.example/frame", AUTO_SUBFRAME),
            ("https://widgets.example/frame", MANUAL_SUBFRAME | CHAIN_END),
            ("https://pay.sitex.com/frame", AUTO_SUBFRAME),
        ],
    )
    hosts = learn.navigation_hosts(path)
    assert hosts == {"app.sitex.com"}
    result = learn.classify(START, ["ads.example", "widgets.example"], hosts)
    assert result.excluded == ("ads.example", "widgets.example")


def test_odd_urls_in_history_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "History"
    database = build(
        path,
        [
            ("chrome://newtab/", TYPED),
            ("file:///etc/hosts", TYPED),
            ("data:text/html,hi", TYPED),
            ("https://", LINK),
            ("https://APP.SitEx.com./", LINK),
            ("http://192.0.2.7:8080/", LINK),
        ],
    )
    database.execute("INSERT INTO urls(url, last_visit_time) VALUES (NULL, 1)")
    database.execute("INSERT INTO visits(url, visit_time) VALUES (7, 1)")
    database.commit()
    database.close()
    assert learn.navigation_hosts(path) == {"app.sitex.com", "192.0.2.7"}


def test_ip_literals_are_third_parties_and_exact() -> None:
    result = learn.classify(START, ["192.0.2.7", "198.51.100.1", "[2001:db8::1]"], ["192.0.2.7"])
    assert result.allow == ("192.0.2.7", "sitex.com")
    assert result.excluded == ("198.51.100.1", "2001:db8::1")


def test_ip_start_url_is_covered_only_by_itself() -> None:
    result = learn.classify("http://192.0.2.7:3000/", ["192.0.2.7", "192.0.2.8"], [])
    assert result.allow == ("192.0.2.7",)
    assert result.excluded == ("192.0.2.8",)


def test_two_level_suffixes_and_custom_suffixes() -> None:
    result = learn.classify("https://app.sitex.co.uk/", ["x.sitex.co.uk", "other.co.uk"], [])
    assert result == learn.Classification(allow=("sitex.co.uk",), excluded=("other.co.uk",))
    custom = learn.classify("https://app.sitex.test.example/", [], [], suffixes=frozenset())
    assert custom.allow == ("test.example",)


def test_a_background_host_under_an_allowed_provider_is_not_excluded() -> None:
    result = learn.classify(START, ["static.login.okta.com", "login.okta.com"], ["login.okta.com"])
    assert result.allow == ("login.okta.com", "sitex.com")
    assert result.excluded == ()


def test_a_background_parent_of_an_allowed_provider_is_not_excluded() -> None:
    seen = ["accounts.google.com", "google.com", "ads.example"]
    result = learn.classify(START, seen, ["accounts.google.com"])
    assert result.allow == ("accounts.google.com", "sitex.com")
    assert result.excluded == ("ads.example",)


def test_relogin_drops_an_old_excluded_parent_of_an_allowed_host() -> None:
    old = policy(allow=("sitex.com",), excluded=("google.com", "t.example"))
    new = learn.Classification(("accounts.google.com", "sitex.com"), ())
    result = learn.merge(old, new, START, NOW)
    assert result.excluded == ("t.example",)
    assert sites.allows(result, "accounts.google.com")


@pytest.mark.parametrize(
    "seen",
    [[], ["google.com", "com"], ["okta.com", "login.okta.com", "x.sitex.com", "sitex.com"]],
)
def test_every_classified_allow_host_is_allowed_after_merge(seen: list[str]) -> None:
    navigated = ["accounts.google.com", "login.okta.com", "192.0.2.7"]
    classification = learn.classify(START, [*seen, "192.0.2.7"], navigated)
    old = policy(excluded=("google.com", "okta.com", "192.0.2.7", "sitex.com", "t.example"))
    for before in (None, old):
        saved = learn.merge(before, classification, START, NOW)
        assert all(sites.allows(saved, host) for host in classification.allow)
        assert all(sites.allows(saved, host) for host in navigated)


def test_invalid_hosts_are_ignored() -> None:
    result = learn.classify(START, ["", "bad host", "beacon.example"], ["???"])
    assert result == learn.Classification(allow=("sitex.com",), excluded=("beacon.example",))


def test_classify_is_sorted_and_deterministic() -> None:
    first = learn.classify(START, ["b.example", "a.example", "c.example"], ["z.sso.example"])
    second = learn.classify(START, ["c.example", "b.example", "a.example"], ["z.sso.example"])
    assert first == second
    assert first.excluded == ("a.example", "b.example", "c.example")


def test_missing_history_gives_no_hosts(tmp_path: Path) -> None:
    assert learn.navigation_hosts(tmp_path / "nope" / "History") == set()


def test_history_is_read_from_a_copy(tmp_path: Path) -> None:
    path = history(tmp_path, [("https://app.sitex.com/", TYPED)])
    before = path.read_bytes()
    learn.navigation_hosts(path)
    assert path.read_bytes() == before
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["History"]


def test_a_database_with_a_pending_wal_is_copied_with_it(tmp_path: Path) -> None:
    path = tmp_path / "History"
    live = build(path, [("https://app.sitex.com/", TYPED)], wal=True)
    live.execute("INSERT INTO urls(url, last_visit_time) VALUES ('https://login.okta.com/', 9)")
    live.execute("INSERT INTO visits(url, visit_time, transition) VALUES (2, 9, 0)")
    live.commit()
    assert path.with_name("History-wal").stat().st_size > 0
    # The live connection is still open, so everything committed exists only in the -wal file:
    # the main file alone has no tables.
    main_file_only = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
    with closing(main_file_only), pytest.raises(sqlite3.OperationalError):
        main_file_only.execute("SELECT count(*) FROM visits")
    assert learn.navigation_hosts(path) == {"app.sitex.com", "login.okta.com"}
    live.close()


def test_a_locked_database_is_still_readable(tmp_path: Path) -> None:
    path = tmp_path / "History"
    live = build(path, [("https://app.sitex.com/", TYPED)])
    live.execute("BEGIN EXCLUSIVE")
    try:
        assert learn.navigation_hosts(path) == {"app.sitex.com"}
    finally:
        live.rollback()
        live.close()


def test_a_file_that_is_not_a_database_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "History"
    path.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(sqlite3.DatabaseError):
        learn.navigation_hosts(path)


def policy(**changes: object) -> sites.Policy:
    fields: dict[str, object] = {
        "site": "sitex",
        "start": "https://sitex.com/",
        "allow": ("sitex.com", "sso.old.example"),
        "excluded": ("t.example", "login.okta.com"),
        "learned": datetime(2026, 1, 1, tzinfo=UTC),
    }
    return sites.Policy(**{**fields, **changes})  # ty: ignore[invalid-argument-type]


def test_first_login_builds_a_policy() -> None:
    result = learn.merge(None, learn.Classification(("sitex.com",), ("t.example",)), START, NOW)
    assert result == sites.Policy(
        site="sitex",
        start=START,
        allow=("sitex.com",),
        excluded=("t.example",),
        learned=datetime(2026, 10, 26, 9, 30, 15, tzinfo=UTC),
    )


def test_relogin_keeps_approved_hosts_and_clears_them_from_excluded() -> None:
    new = learn.Classification(("login.okta.com", "sitex.com"), ("ads.example",))
    result = learn.merge(policy(), new, START, NOW)
    assert result.allow == ("login.okta.com", "sitex.com", "sso.old.example")
    assert result.excluded == ("ads.example", "t.example")
    assert result.start == START
    assert not sites.allows(result, "t.example")
    assert sites.allows(result, "login.okta.com")
    assert sites.allows(result, "sso.old.example")


def test_relogin_keeps_a_host_the_person_carved_out_of_an_allowed_domain() -> None:
    old = policy(allow=("sitex.com",), excluded=("static.sitex.com",))
    result = learn.merge(old, learn.Classification(("sitex.com",), ()), START, NOW)
    assert result.excluded == ("static.sitex.com",)
    assert not sites.allows(result, "static.sitex.com")


def test_merge_names_the_site_and_converts_the_time() -> None:
    empty = learn.Classification(("sitex.com",), ())
    assert learn.merge(None, empty, START, NOW, site="custom").site == "custom"
    assert learn.merge(policy(site="kept"), empty, START, NOW).site == "kept"
    local = datetime(2026, 10, 26, 11, 0, 0, 5, tzinfo=timezone(timedelta(hours=2)))
    assert learn.merge(None, empty, START, local).learned == datetime(
        2026, 10, 26, 9, 0, 0, tzinfo=UTC
    )


def line(allow: tuple[str, ...], excluded: tuple[str, ...] = (), **changes: object) -> str:
    result = learn.Classification(allow, excluded)
    return learn.summary(policy(allow=allow, excluded=excluded, **changes), result)


def test_summary_names_every_host_up_to_four() -> None:
    assert line(("sitex.com",)) == "Saved your sitex login. Sessions will be limited to sitex.com."
    assert line(("login.okta.com", "sitex.com"), ("a.example", "b.example")) == (
        "Saved your sitex login. Sessions will be limited to sitex.com and login.okta.com. "
        "Left out 2 hosts that only loaded in the background."
    )
    assert line(("a.example", "b.example", "sitex.com", "z.example")).endswith(
        "limited to sitex.com, a.example, b.example and z.example."
    )


def test_summary_trims_a_long_list() -> None:
    allow = ("a.example", "b.example", "c.example", "d.example", "sitex.com")
    assert line(allow) == (
        "Saved your sitex login. Sessions will be limited to sitex.com, a.example, "
        "b.example and 2 more."
    )


def test_summary_counts_one_host_and_ignores_older_exclusions() -> None:
    result = learn.Classification(("sitex.com",), ("new.example", "approved.example"))
    saved = policy(allow=("sitex.com",), excluded=("new.example", "old.example"))
    assert learn.summary(saved, result).endswith(
        "Left out 1 host that only loaded in the background."
    )


def test_summary_with_nothing_allowed() -> None:
    saved = policy(allow=(), excluded=())
    assert "limited to no hosts." in learn.summary(saved, learn.Classification((), ()))


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("chromium") is None, reason="needs chromium")
def test_real_chromium_history_has_the_columns_the_query_reads(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    subprocess.run(  # noqa: S603 - a fixed command in a throwaway profile
        [  # noqa: S607 - chromium from PATH
            "chromium",
            "--headless=new",
            "--no-sandbox",
            f"--user-data-dir={profile}",
            "--virtual-time-budget=3000",
            "--dump-dom",
            "data:text/html,hi",
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    path = profile / "Default" / "History"
    if not path.is_file():
        pytest.skip("this Chromium wrote no history")
    assert isinstance(learn.navigation_hosts(path), set)


# -- the pages a login submitted a form from -----------------------------------------------

FORM_SUBMIT = 7
type Step = tuple[str, int, int | None]
"""A visit: the URL, the transition, and the 1-based number of the visit it came from."""


def history_of_steps(tmp_path: Path, steps: list[Step]) -> Path:
    path = tmp_path / "History"
    database = build(path, [(url, transition) for url, transition, _ in steps])
    for number, (_, _, origin) in enumerate(steps, start=1):
        database.execute("UPDATE visits SET from_visit = ? WHERE id = ?", (origin, number))
    database.commit()
    database.close()
    return path


def test_the_login_page_is_where_the_form_was_submitted_from(tmp_path: Path) -> None:
    path = history_of_steps(
        tmp_path,
        [
            ("https://sitex.com/", TYPED | CHAIN_START, None),
            ("https://sitex.com/login?next=%2F", TYPED | CHAIN_END | SERVER_REDIRECT, 1),
            ("https://sitex.com/app", FORM_SUBMIT | CHAIN_START | CHAIN_END, 2),
        ],
    )
    assert learn.login_pages(path, "https://sitex.com/") == ("sitex.com/login",)


def test_every_page_of_a_sign_in_flow_counts_but_not_the_pages_around_it(tmp_path: Path) -> None:
    path = history_of_steps(
        tmp_path,
        [
            ("https://sitex.com/", TYPED, None),
            ("https://login.okta.com/signin?x=1#top", LINK, 1),
            ("https://login.okta.com/mfa/", FORM_SUBMIT, 2),
            ("https://login.okta.com/done", FORM_SUBMIT, 3),
            ("https://sitex.com/callback?code=abc", LINK, 4),
            ("https://sitex.com/app/", LINK, 5),
        ],
    )
    assert learn.login_pages(path, "https://sitex.com/") == (
        "login.okta.com/mfa",
        "login.okta.com/signin",
    )


def test_the_start_page_and_the_final_page_are_never_login_pages(tmp_path: Path) -> None:
    path = history_of_steps(
        tmp_path,
        [
            ("https://sitex.com/", TYPED, None),
            ("https://sitex.com/login", LINK, 1),
            ("https://sitex.com/app", FORM_SUBMIT, 1),
            ("https://sitex.com/app", LINK, 3),
            ("https://sitex.com/search?q=x", FORM_SUBMIT, 4),
            ("https://sitex.com/app", LINK, 5),
        ],
    )
    # "/" held a form and so did "/app", the page the login ended on; neither can be a login page.
    assert learn.login_pages(path, "https://sitex.com/") == ()


def test_a_form_in_a_frame_is_not_a_login_page(tmp_path: Path) -> None:
    path = history_of_steps(
        tmp_path,
        [
            ("https://sitex.com/", TYPED, None),
            ("https://ads.example.com/frame", AUTO_SUBFRAME, 1),
            ("https://sitex.com/thanks", FORM_SUBMIT, 2),
            ("https://sitex.com/app", LINK, 3),
        ],
    )
    assert learn.login_pages(path, "https://sitex.com/") == ()


def test_pages_that_are_not_web_pages_are_ignored(tmp_path: Path) -> None:
    path = history_of_steps(
        tmp_path,
        [
            ("https://sitex.com/", TYPED, None),
            ("chrome://settings/", LINK, 1),
            ("https://sitex.com/app", FORM_SUBMIT, 2),
        ],
    )
    assert learn.login_pages(path, "https://sitex.com/") == ()


def test_no_history_means_no_login_pages(tmp_path: Path) -> None:
    assert learn.login_pages(tmp_path / "missing", "https://sitex.com/") == ()
    assert learn.login_pages(history_of_steps(tmp_path, []), "https://sitex.com/") == ()


def test_a_history_without_visit_origins_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "History"
    database = sqlite3.connect(path)
    database.executescript(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT);"
        "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,"
        " transition INTEGER);"
    )
    database.close()
    with pytest.raises(sqlite3.DatabaseError):
        learn.login_pages(path, "https://sitex.com/")


def test_merge_records_the_login_pages_and_keeps_old_ones_when_there_are_none() -> None:
    new = learn.Classification(("sitex.com",), ())
    first = learn.merge(None, new, START, NOW, pages=["sitex.com/login", "sitex.com/login"])
    assert first.login_pages == ("sitex.com/login",)
    kept = learn.merge(first, new, START, NOW)
    assert kept.login_pages == ("sitex.com/login",)
    replaced = learn.merge(first, new, START, NOW, pages=["login.okta.com/signin"])
    assert replaced.login_pages == ("login.okta.com/signin",)


def test_merge_keeps_the_ranges_the_person_listed_and_never_adds_any() -> None:
    new = learn.Classification(("sitex.com", "10.20.1.5.nip.test"), ())
    listed = learn.merge(policy(private_networks=("10.20.0.0/24",)), new, START, NOW)
    assert listed.private_networks == ("10.20.0.0/24",)
    assert learn.merge(None, new, START, NOW).private_networks == ()
    assert learn.merge(policy(), new, START, NOW).private_networks == ()
