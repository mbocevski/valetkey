# SPDX-License-Identifier: Apache-2.0
import hashlib
import io
import logging
import urllib.request
from typing import TYPE_CHECKING

import conventional
import pytest
import update_trackers

from valetkey import trackers

if TYPE_CHECKING:
    from pathlib import Path

LISTED = [
    "aa.agkn.com",
    "adsby.bidtheatre.com",
    "bat.bing.com",
    "www.google-analytics.com",
    "stats.g.doubleclick.net",
    "static.hotjar.com",
    "ads.linkedin.com",
    "x.doubleclick.net",
]
PROTECTED = [
    # Identity providers.
    "login.okta.com",
    "dev-123.okta.com",
    "ok9static.oktacdn.com",
    "tenant.auth0.com",
    "cdn.auth0.com",
    "login.microsoftonline.com",
    "aadcdn.msauth.net",
    "login.live.com",
    "accounts.google.com",
    "appleid.apple.com",
    "github.com",
    "login.salesforce.com",
    # CDNs and static hosts.
    "ssl.gstatic.com",
    "fonts.gstatic.com",
    "fonts.googleapis.com",
    "d111111abcdef8.cloudfront.net",
    "a248.e.akamai.net",
    "static.akamaized.net",
    "a.akamaihd.net",
    "global.fastly.net",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "bucket.s3.amazonaws.com",
    "cdn.shopify.com",
    # Payments.
    "js.stripe.com",
    "www.paypal.com",
    "www.paypalobjects.com",
    "x.klarna.com",
    "checkoutshopper-live.adyen.com",
    "pay.google.com",
    # Things a page embeds on purpose.
    "www.google.com",
    "www.recaptcha.net",
    "hcaptcha.com",
    "www.youtube.com",
    "player.vimeo.com",
    "connect.facebook.net",
    "www.linkedin.com",
    "platform.twitter.com",
]
"""Hosts that a sign-in or a page needs: no layer of the sorting may call any of them tracking."""


@pytest.mark.parametrize("host", LISTED)
def test_the_known_ad_and_tracking_hosts_are_tracking(host: str) -> None:
    assert trackers.is_tracking(host)


@pytest.mark.parametrize("host", PROTECTED)
def test_an_identity_provider_a_cdn_or_a_payment_service_is_never_tracking(host: str) -> None:
    assert not trackers.is_tracking(host)


def test_no_domain_of_the_lists_covers_a_protected_host() -> None:
    domains = trackers.listed() | trackers.SUPPLEMENT
    for host in PROTECTED:
        labels = host.split(".")
        covering = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        assert not [d for d in covering if d in domains], host


def test_a_listed_domain_covers_its_subdomains_and_only_those() -> None:
    assert trackers.is_tracking("agkn.com")
    assert trackers.is_tracking("x.y.agkn.com")
    assert not trackers.is_tracking("notagkn.com")
    assert not trackers.is_tracking("agkn.com.example.org")


def test_the_supplement_covers_what_the_list_lacks() -> None:
    assert trackers.is_tracking("o1.ingest.sentry.io")
    assert trackers.is_tracking("api.segment.io")
    assert trackers.is_tracking("c.bannerflow.net")
    assert trackers.is_tracking("click.prod.mplat-ppcprotect.com")


def test_a_host_name_that_says_what_it_is_counts_even_when_no_list_has_it() -> None:
    assert trackers.is_tracking("ads.nowhere-known.example")
    assert trackers.is_tracking("track-2.nowhere-known.example")
    assert not trackers.is_tracking("adsense-help.nowhere-known.example")


def test_an_address_is_never_tracking() -> None:
    assert not trackers.is_tracking("10.0.0.1")
    assert not trackers.is_tracking("[2001:db8::1]")


def test_the_vendored_list_is_the_one_the_lock_names() -> None:
    data = (conventional.ROOT / "src" / "valetkey" / trackers.DATA).read_bytes()
    digest, count, *_ = (conventional.ROOT / "tools" / "trackers.lock").read_text().split()
    assert hashlib.sha256(data).hexdigest() == digest
    assert len(trackers.listed()) == int(count)
    assert b"Peter Lowe" in data  # the author's credit stays in the file
    assert len(trackers.listed()) > update_trackers.MINIMUM


def test_the_parser_reads_hosts_lines_and_rejects_anything_else() -> None:
    text = "# a comment\n\n127.0.0.1 a.example\n127.0.0.1 b.example \n"
    assert trackers.parse(text) == {"a.example", "b.example"}
    for bad in ("0.0.0.0 a.example", "a.example", "127.0.0.1 a.example extra", "127.0.0.1 A B"):
        with pytest.raises(ValueError, match=r"not '127\.0\.0\.1 DOMAIN'"):
            trackers.parse(bad)


def test_an_unreadable_list_leaves_the_other_layers_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class Missing:
        def joinpath(self, _name: str) -> Missing:
            return self

        def read_text(self, *, encoding: str) -> str:
            del encoding
            raise FileNotFoundError

    monkeypatch.setattr(trackers.resources, "files", lambda _package: Missing())
    trackers.listed.cache_clear()
    try:
        with caplog.at_level(logging.WARNING):
            assert trackers.listed() == frozenset()
            assert not trackers.is_tracking("aa.agkn.com")
            assert trackers.is_tracking("o1.ingest.sentry.io")
            assert trackers.is_tracking("ads.example.org")
        assert "could not be read" in caplog.text
    finally:
        trackers.listed.cache_clear()


# -- tools/update_trackers.py ---------------------------------------------------------------


def make_list(count: int = update_trackers.MINIMUM + 5) -> str:
    lines = "".join(f"127.0.0.1 d{n}.example\n" for n in range(count))
    return f"# header\n# last updated:   Fri, 23 Oct 2026 09:37:39 GMT\n#\n{lines}"


def test_an_update_writes_the_list_as_served_and_locks_its_digest(tmp_path: Path) -> None:
    body = make_list().encode()
    destination, lock = tmp_path / "adservers.txt", tmp_path / "trackers.lock"
    count, updated = update_trackers.update(destination, lock, lambda _url: body)
    assert (count, updated) == (update_trackers.MINIMUM + 5, "Fri, 23 Oct 2026 09:37:39 GMT")
    assert destination.read_bytes() == body
    assert lock.read_text() == (
        f"{hashlib.sha256(body).hexdigest()} {count} {updated} {update_trackers.URL}\n"
    )


@pytest.mark.parametrize(
    "body",
    [
        make_list(3).encode(),
        make_list().replace("# last updated", "# nothing").encode(),
        (make_list() + "0.0.0.0 evil.example\n").encode(),
        b"\xff\xfe",
    ],
)
def test_a_list_that_does_not_look_right_writes_nothing(tmp_path: Path, body: bytes) -> None:
    destination, lock = tmp_path / "adservers.txt", tmp_path / "trackers.lock"
    with pytest.raises(update_trackers.UpdateError):
        update_trackers.update(destination, lock, lambda _url: body)
    assert not destination.exists()
    assert not lock.exists()


def test_the_command_reports_success_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(update_trackers, "DESTINATION", tmp_path / "adservers.txt")
    monkeypatch.setattr(update_trackers, "LOCK", tmp_path / "trackers.lock")
    assert update_trackers.main([], lambda _url: make_list().encode()) == 0
    assert "1005 domains, updated Fri, 23 Oct 2026" in capsys.readouterr().out
    assert update_trackers.main([], lambda _url: b"nope") == 1
    assert "update_trackers:" in capsys.readouterr().err
    assert update_trackers.main(["extra"]) == 2


def test_download_reads_the_body_of_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, float]] = []

    def fake(url: str, timeout: float) -> io.BytesIO:
        seen.append((url, timeout))
        return io.BytesIO(b"body")

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert update_trackers.download("https://example.org/x") == b"body"
    assert seen == [("https://example.org/x", update_trackers.TIMEOUT)]


# -- the browser's own hosts ----------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["edgedl.me.gvt1.com", "gvt1.com", "r1---sn-abc.gvt1.com", "update.googleapis.com"],
)
def test_the_hosts_the_browser_contacts_for_its_updates_are_background(host: str) -> None:
    assert trackers.is_browser_background(host)
    assert not trackers.is_tracking(host)


@pytest.mark.parametrize(
    "host",
    [
        "www.googleapis.com",
        "accounts.google.com",
        "www.google.com",
        "notgvt1.com",
        "gvt1.com.example.org",
    ],
)
def test_other_google_hosts_are_not_background(host: str) -> None:
    assert not trackers.is_browser_background(host)


@pytest.mark.parametrize("host", PROTECTED)
def test_no_protected_host_is_taken_for_the_browsers_own(host: str) -> None:
    assert not trackers.is_browser_background(host)
