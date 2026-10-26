# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING

import pytest

from valetkey import expiry, sites

if TYPE_CHECKING:
    from collections.abc import Callable

START = "https://sitex.com/"


def policy(*pages: str, start: str = START) -> sites.Policy:
    return sites.Policy("sitex", start, ("sitex.com",), login_pages=pages)


def asked(count: int) -> tuple[list[int], Callable[[], int]]:
    calls: list[int] = []

    def password_fields() -> int:
        calls.append(1)
        return count

    return calls, password_fields


@pytest.mark.parametrize(
    "landed",
    [
        "https://sitex.com/login?next=%2F",
        "https://SITEX.com/login/",
        "https://sitex.com/login#top",
        "https://login.okta.com/signin",
    ],
)
def test_ending_on_a_recorded_login_page_is_expiry(landed: str) -> None:
    calls, fields = asked(0)
    why = expiry.login_expired(
        policy("sitex.com/login", "login.okta.com/signin"),
        landed,
        fields,
    )
    assert why is not None
    assert "sign-in page seen during the login" in why
    assert calls == []  # the page was enough


def test_a_start_page_that_is_not_redirected_is_never_expiry() -> None:
    calls, fields = asked(1)
    pages = policy("sitex.com/", "sitex.com/login")
    for landed in (START, "https://sitex.com", "https://sitex.com/?utm=1", "https://sitex.com/#a"):
        assert expiry.login_expired(pages, landed, fields) is None
    assert calls == []


def test_a_redirect_to_a_normal_page_is_not_expiry() -> None:
    calls, fields = asked(0)
    why = expiry.login_expired(policy("sitex.com/login"), "https://sitex.com/home", fields)
    assert why is None
    assert calls == [1]  # it did look for a password field


def test_a_redirect_to_a_page_with_a_password_field_is_expiry_even_without_recorded_pages() -> None:
    calls, fields = asked(2)
    why = expiry.login_expired(policy(), "https://sso.sitex.com/enter", fields)
    assert why == "the start page redirected to a page with a password field"
    assert calls == [1]


def test_a_start_page_with_a_login_box_is_not_expiry_without_a_redirect() -> None:
    calls, fields = asked(1)
    assert expiry.login_expired(policy(), START, fields) is None
    assert calls == []


@pytest.mark.parametrize("landed", ["", "about:blank", "chrome-error://chromewebdata/", "ftp://x/"])
def test_a_page_that_is_not_a_web_page_says_nothing(landed: str) -> None:
    calls, fields = asked(1)
    assert expiry.login_expired(policy("sitex.com/login"), landed, fields) is None
    assert calls == []
