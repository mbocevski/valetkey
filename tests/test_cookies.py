# SPDX-License-Identifier: Apache-2.0
import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING

from cookie_jar import BEGAN, FUTURE, NOW, PAST, SUBMITTED, cookie, history_with_a_form, jar

from valetkey import cookies, learn, sites

if TYPE_CHECKING:
    from pathlib import Path


def own(host: str) -> bool:
    return sites.host_matches(host, ["sitex.com"])


def record(profile: Path) -> tuple[str, ...]:
    return cookies.recorded(profile, profile / "Default" / "History", since=BEGAN, now=NOW, own=own)


def test_the_cookies_a_login_set_and_that_look_like_its_sign_in_are_recorded(
    tmp_path: Path,
) -> None:
    history_with_a_form(tmp_path)
    jar(
        tmp_path,
        cookie("app.sitex.com", "sessionid"),
        cookie(".sitex.com", "remember", secure=True, http_only=False, expires=FUTURE),
        cookie("app.sitex.com", "theme", http_only=False),  # not a sign-in: neither flag
        cookie("app.sitex.com", "_ga"),  # analytics
        cookie("app.sitex.com", "OptanonConsent"),  # consent
        cookie("app.sitex.com", "anon", created=BEGAN + timedelta(seconds=6)),  # before the form
        cookie("app.sitex.com", "old", expires=PAST),  # already run out
        cookie("login.idp.test", "sid"),  # another site's
        cookie("app.sitex.com", "bad name"),  # not a cookie name this code will write
    )
    assert record(tmp_path) == (".sitex.com remember", "app.sitex.com sessionid")


def test_the_margin_keeps_a_cookie_stamped_a_moment_before_the_form_page(tmp_path: Path) -> None:
    history_with_a_form(tmp_path)
    jar(
        tmp_path,
        cookie("app.sitex.com", "close", created=SUBMITTED - timedelta(seconds=1)),
        cookie("app.sitex.com", "early", created=SUBMITTED - timedelta(seconds=5)),
    )
    assert record(tmp_path) == ("app.sitex.com close",)


def test_without_a_form_in_the_history_every_sign_in_looking_cookie_counts(tmp_path: Path) -> None:
    jar(
        tmp_path,
        cookie("app.sitex.com", "early", created=BEGAN + timedelta(seconds=1)),
        cookie("app.sitex.com", "before", created=BEGAN - timedelta(seconds=1)),  # an old login
    )
    assert record(tmp_path) == ("app.sitex.com early",)
    (tmp_path / "Default" / "History").write_bytes(b"not a database")
    assert record(tmp_path) == ("app.sitex.com early",)


def test_at_most_twenty_are_recorded(tmp_path: Path) -> None:
    jar(tmp_path, *(cookie("app.sitex.com", f"s{n:02d}") for n in range(30)))
    found = record(tmp_path)
    assert len(found) == sites.MAX_LOGIN_COOKIES
    assert found == tuple(f"app.sitex.com s{n:02d}" for n in range(20))


def test_nothing_is_recorded_from_a_missing_or_unreadable_database(tmp_path: Path) -> None:
    assert record(tmp_path) == ()
    path = cookies.database(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not a database")
    assert record(tmp_path) == ()


def test_the_cookies_table_is_all_that_is_read(tmp_path: Path) -> None:
    path = jar(tmp_path, cookie("app.sitex.com", "sessionid"))
    with closing(sqlite3.connect(path)) as database:
        database.execute("CREATE VIEW sneaky AS SELECT * FROM cookies")
        database.commit()
    assert record(tmp_path) == ()  # a view is not trusted: the database is refused


# -- gone -----------------------------------------------------------------------------------

LOGIN = ("app.sitex.com sessionid", "app.sitex.com wordpress_logged_in_a1")


def gone(profile: Path, recorded: tuple[str, ...] = LOGIN) -> bool:
    return cookies.gone(profile, recorded, now=NOW)


def test_a_login_is_gone_when_none_of_its_cookies_is_in_the_profile(tmp_path: Path) -> None:
    jar(tmp_path, cookie("app.sitex.com", "anonymous"), cookie("app.sitex.com", "theme"))
    assert gone(tmp_path)


def test_a_login_is_gone_when_the_profile_has_no_cookie_database(tmp_path: Path) -> None:
    assert gone(tmp_path)


def test_a_login_is_gone_when_every_cookie_of_it_has_run_out(tmp_path: Path) -> None:
    jar(
        tmp_path,
        cookie("app.sitex.com", "sessionid", expires=PAST),
        cookie("app.sitex.com", "wordpress_logged_in_a1", expires=PAST),
    )
    assert gone(tmp_path)


def test_a_cookie_that_is_still_there_keeps_the_login(tmp_path: Path) -> None:
    jar(tmp_path, cookie("app.sitex.com", "sessionid"))
    assert not gone(tmp_path)
    jar_path = cookies.database(tmp_path)
    jar_path.unlink()
    jar(tmp_path, cookie("app.sitex.com", "sessionid", expires=FUTURE))
    assert not gone(tmp_path)


def test_a_rotated_name_does_not_lose_the_login_while_another_cookie_stays(tmp_path: Path) -> None:
    jar(
        tmp_path,
        cookie("app.sitex.com", "wordpress_logged_in_b2"),  # the site rotated this one's name
        cookie("app.sitex.com", "sessionid"),  # and this one is still there
    )
    assert not gone(tmp_path)


def test_nothing_recorded_or_an_unreadable_database_says_nothing(tmp_path: Path) -> None:
    assert not gone(tmp_path, ())
    path = cookies.database(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not a database")
    assert not gone(tmp_path)


def test_the_host_must_match_as_the_browser_wrote_it(tmp_path: Path) -> None:
    jar(tmp_path, cookie(".sitex.com", "sessionid"))
    assert gone(tmp_path, ("app.sitex.com sessionid",))
    assert not gone(tmp_path, (".sitex.com sessionid",))


# -- the history's first form ----------------------------------------------------------------


def test_the_first_form_of_the_history_is_when_the_sign_in_was_submitted(tmp_path: Path) -> None:
    history = history_with_a_form(tmp_path)
    assert learn.first_submit(history, since=BEGAN) == learn.chrome_time(SUBMITTED)
    assert learn.first_submit(history, since=SUBMITTED + timedelta(seconds=1)) is None
    assert learn.first_submit(tmp_path / "none", since=BEGAN) is None


def test_a_row_that_is_not_text_is_skipped_by_both_readers(tmp_path: Path) -> None:
    path = jar(tmp_path, cookie("app.sitex.com", "sessionid"), cookie("app.sitex.com", "other"))
    with closing(sqlite3.connect(path)) as database:
        database.execute("UPDATE cookies SET name = x'ff00' WHERE name = 'other'")
        database.commit()
    assert record(tmp_path) == ("app.sitex.com sessionid",)
    assert gone(tmp_path, ("app.sitex.com sessionid",)) is False
    assert gone(tmp_path, ("app.sitex.com other",)) is True  # that cookie has no usable name
