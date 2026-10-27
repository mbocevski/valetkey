# SPDX-License-Identifier: Apache-2.0
import itertools
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

import pytest
from environment import unusable_reason
from proxy_stub import PageServer, ProxyStub

from valetkey import clicks, sessions, sites
from valetkey.clicks import (
    ClickError,
    Clock,
    Expect,
    Target,
    build_target,
    names_in,
    parse_expectation,
    resolve,
    verified_click,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


def refs(**elements: tuple[str, str]) -> dict[str, sessions.Ref]:
    return {ref: sessions.Ref(role, name) for ref, (role, name) in elements.items()}


# -- describing the click ------------------------------------------------------------------


def test_a_reference_means_what_it_was_in_the_callers_snapshot() -> None:
    known = {"e3": ("button", "Save  now")}
    target = build_target({"ref": "e3"}, known)
    assert target == Target(name="Save now", role="button", ref="e3", fold=False)
    assert build_target({"ref": "@e3"}, known) == target


def test_text_with_or_without_a_role() -> None:
    assert build_target({"text": " Close  dialog "}, {}) == Target("Close dialog", fold=True)
    assert build_target({"text": "Go", "role": "link"}, {}) == Target("Go", "link", fold=True)


@pytest.mark.parametrize(
    ("args", "code"),
    [
        ({}, "bad_request"),
        ({"ref": "e1", "text": "x"}, "bad_request"),
        ({"ref": "e1", "role": "button"}, "bad_request"),
        ({"ref": ""}, "bad_request"),
        ({"text": "   "}, "bad_request"),
        ({"text": 5}, "bad_request"),
        ({"text": "x", "role": ""}, "bad_request"),
        ({"ref": "3"}, "bad_request"),
        ({"ref": "button"}, "bad_request"),
        ({"ref": "e9"}, "unknown_ref"),
    ],
)
def test_bad_click_arguments(args: dict[str, Any], code: str) -> None:
    with pytest.raises(ClickError) as info:
        build_target(args, {"e1": ("button", "Go")})
    assert info.value.code == code


def test_the_unknown_reference_says_to_take_a_snapshot() -> None:
    with pytest.raises(ClickError, match="take a new snapshot first"):
        build_target({"ref": "e9"}, {})


def test_expectations() -> None:
    assert parse_expectation(None) is None
    assert parse_expectation({"text_appears": "Saved"}) == Expect("text_appears", "Saved")
    assert parse_expectation({"text_gone": "Menu"}) == Expect("text_gone", "Menu")
    assert parse_expectation({"url_changes": True}) == Expect("url_changes")
    assert Expect("text_gone", "x").to_json() == {"kind": "text_gone", "text": "x"}


@pytest.mark.parametrize(
    "raw",
    [
        {},
        [],
        "text_appears",
        {"text_appears": "a", "text_gone": "b"},
        {"text_appears": ""},
        {"text_gone": "  "},
        {"text_appears": 5},
        {"url_changes": False},
        {"url_changes": "yes"},
        {"url_changes": 1},
        {"something": "x"},
    ],
)
def test_bad_expectations(raw: object) -> None:
    with pytest.raises(ClickError) as info:
        parse_expectation(raw)
    assert info.value.code == "bad_request"


def test_names_come_from_the_quoted_parts_of_the_tree() -> None:
    tree = (
        '- heading "Tabs" [level=1, ref=e1]\n'
        '- button "Close \\"dialog\\"" [ref=e2]\n'
        "- generic\n"
        '  - StaticText "Saved \\u2713"\n'
        '- link "Bad \\q escape" [ref=e5]'
    )
    assert names_in(tree) == ["Tabs", 'Close "dialog"', "Saved ✓", "Bad \\q escape"]
    assert "ref" not in " ".join(names_in(tree))


# -- finding the element -------------------------------------------------------------------


def test_a_reference_that_is_still_what_it_was_is_used_as_it_is() -> None:
    fresh = refs(e1=("button", "Delete"), e2=("button", "Delete"), e3=("button", "Save"))
    target = Target("Delete", "button", ref="e2")
    # Two buttons share the name, but e2 is still alive with that name, so it is the same one.
    assert resolve(fresh, target)[0] == "e2"


def test_a_stale_reference_finds_the_element_by_role_and_name() -> None:
    fresh = refs(e1=("menuitem", "Delete property"), e4=("tab", "Details"), e5=("tab", "Overview"))
    # e1 was the "Details" tab in the caller's snapshot; the page has been redrawn since.
    ref, element = resolve(fresh, Target("Details", "tab", ref="e1"))
    assert (ref, element.name) == ("e4", "Details")


def test_a_reference_that_now_means_something_else_is_not_clicked() -> None:
    fresh = refs(e1=("menuitem", "Delete property"))
    with pytest.raises(ClickError) as info:
        resolve(fresh, Target("Details", "tab", ref="e1"))
    assert info.value.code == "target_not_found"
    assert info.value.details == {"candidates": []}


def test_nothing_that_matches_is_refused_with_the_near_names() -> None:
    fresh = refs(
        e1=("button", "Save draft"),
        e2=("button", "Save and close"),
        e3=("link", "Save"),
        e4=("button", "Cancel"),
    )
    with pytest.raises(ClickError) as info:
        resolve(fresh, Target("save", "button", fold=True))
    error = info.value
    assert error.code == "target_not_found"
    assert "nothing on the page is a button with that name" in str(error)
    assert error.details["candidates"] == [
        {"role": "button", "name": "Save draft"},
        {"role": "button", "name": "Save and close"},
    ]


def test_near_names_are_limited() -> None:
    fresh = {f"e{n}": sessions.Ref("button", f"Item {n}") for n in range(20)}
    with pytest.raises(ClickError) as info:
        resolve(fresh, Target("Item", None))
    assert len(info.value.details["candidates"]) == clicks.MAX_CANDIDATES
    assert "an element" in str(info.value)


def test_several_matches_are_refused_not_guessed() -> None:
    fresh = refs(e1=("button", "Delete"), e2=("button", "Delete"), e3=("link", "Delete"))
    with pytest.raises(ClickError) as info:
        resolve(fresh, Target("Delete", "button"))
    assert info.value.code == "target_ambiguous"
    assert "2 elements match a button" in str(info.value)
    assert len(info.value.details["candidates"]) == 2
    # Without a role all three match.
    with pytest.raises(ClickError, match="3 elements match an element"):
        resolve(fresh, Target("Delete", None))


def test_text_ignores_case_and_a_snapshots_names_do_not() -> None:
    fresh = refs(e1=("button", "Save"))
    assert resolve(fresh, Target("save", "BUTTON", fold=True))[0] == "e1"
    with pytest.raises(ClickError):
        resolve(fresh, Target("save", "button", fold=False))


def test_an_exact_name_wins_over_names_that_hold_the_text() -> None:
    fresh = refs(e1=("link", "icon_user Orders icon_arrow"), e2=("link", "Orders"))
    assert resolve(fresh, Target("orders", "link", fold=True))[0] == "e2"


def test_the_one_name_that_holds_the_text_as_whole_words_is_clicked() -> None:
    fresh = refs(
        e1=("link", "icon_arialabel_user Mitt konto icon_arialabel_arrow-right-small"),
        e2=("link", "Kontoret"),
        e3=("button", "Cancel"),
    )
    ref, element = resolve(fresh, Target("mitt konto", None, fold=True))
    assert (ref, element.name) == (
        "e1",
        "icon_arialabel_user Mitt konto icon_arialabel_arrow-right-small",
    )
    assert resolve(fresh, Target("Mitt konto", "link", fold=True))[0] == "e1"


def test_a_text_that_is_only_part_of_a_word_does_not_match() -> None:
    fresh = refs(
        e1=("link", "icon_user Kontoret"), e2=("link", "icon_konto"), e3=("link", "konto2")
    )
    with pytest.raises(ClickError) as info:
        resolve(fresh, Target("konto", None, fold=True))
    assert info.value.code == "target_not_found"


def test_several_names_that_hold_the_text_are_refused_with_the_candidates() -> None:
    fresh = refs(
        e1=("link", "icon_a Orders icon_b"), e2=("link", "Your Orders"), e3=("link", "Help")
    )
    with pytest.raises(ClickError) as info:
        resolve(fresh, Target("Orders", None, fold=True))
    assert info.value.code == "target_not_found"
    assert info.value.details["candidates"] == [
        {"role": "link", "name": "icon_a Orders icon_b"},
        {"role": "link", "name": "Your Orders"},
    ]


def test_the_role_narrows_the_names_that_hold_the_text() -> None:
    fresh = refs(e1=("link", "icon_a Orders icon_b"), e2=("button", "Your Orders"))
    assert resolve(fresh, Target("Orders", "link", fold=True))[0] == "e1"
    assert resolve(fresh, Target("Orders", "button", fold=True))[0] == "e2"


def test_a_reference_is_never_matched_by_words() -> None:
    fresh = refs(e1=("link", "icon_a Orders icon_b"))
    with pytest.raises(ClickError):
        resolve(fresh, Target("Orders", "link", ref="e9"))  # an exact snapshot name, no fold


def test_names_are_compared_with_whitespace_made_single() -> None:
    fresh = refs(e1=("button", "Save\n  now"))
    assert resolve(fresh, Target("Save now", None))[0] == "e1"


# -- a page that can be scripted -----------------------------------------------------------


class FakeClock:
    """Time that only moves when something sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def clock(self) -> Clock:
        return Clock(self.monotonic, self.sleep)


@dataclass
class FakePage:
    """A page whose elements, text and URL can change as time passes or as it is clicked."""

    time: FakeClock
    elements: dict[str, sessions.Ref] = field(default_factory=dict)
    texts: list[str] = field(default_factory=list)
    url: str = "https://s.test/"
    clicks: list[tuple[str, float]] = field(default_factory=list)
    on_click: Callable[[FakePage, str], None] | None = None
    scheduled: list[tuple[float, Callable[[FakePage], None]]] = field(default_factory=list)
    looks: list[tuple[float, int]] = field(default_factory=list)
    """Each look (a full snapshot with the URL): when, and how many clicks came before it."""

    def _advance(self) -> None:
        due = [item for item in self.scheduled if item[0] <= self.time.now]
        self.scheduled = [item for item in self.scheduled if item not in due]
        for _, change in due:
            change(self)

    def at(self, seconds: float, change: Callable[[FakePage], None]) -> None:
        self.scheduled.append((self.time.now + seconds, change))

    def snapshot(self) -> sessions.Snapshot:
        self._advance()
        return sessions.Snapshot(self.url, "", dict(self.elements))

    def outline(self) -> str:
        self._advance()
        lines = [f'- {e.role} "{e.name}" [ref={r}]' for r, e in self.elements.items()]
        return "\n".join([*lines, *(f'- StaticText "{t}"' for t in self.texts)])

    def look(self) -> tuple[str, str]:
        self.looks.append((self.time.now, len(self.clicks)))
        return self.current_url(), self.outline()

    def click(self, ref: str) -> None:
        self._advance()
        self.clicks.append((ref, self.time.now))
        if self.on_click is not None:
            self.on_click(self, ref)

    def current_url(self) -> str:
        self._advance()
        return self.url


def page_with(**elements: tuple[str, str]) -> FakePage:
    time = FakeClock()
    return FakePage(time, refs(**elements))


def run(page: FakePage, target: Target, expect: Expect | None = None) -> clicks.ClickResult:
    return verified_click(page, target, expect, page.time.clock())


SAVE = Target("Save", "button", fold=True)
SAVED = Expect("text_appears", "Saved")


# -- the click -----------------------------------------------------------------------------


def test_a_click_without_an_expectation_is_made_once_and_not_checked() -> None:
    page = page_with(e1=("button", "Save"))
    result = run(page, SAVE)
    assert (result.role, result.name, result.attempts, result.outcome) == (
        "button",
        "Save",
        1,
        "unchecked",
    )
    assert result.expect is None
    assert [ref for ref, _ in page.clicks] == ["e1"]
    assert page.time.now == 0  # nothing was waited for


def test_a_click_that_did_nothing_is_not_repeated_without_an_expectation() -> None:
    page = page_with(e1=("button", "Save"))
    run(page, SAVE)
    assert len(page.clicks) == 1


def test_the_expectation_is_met_when_it_comes_true() -> None:
    page = page_with(e1=("button", "Save"))
    page.on_click = lambda p, _ref: p.texts.append("Saved")
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (1, "met")
    assert len(page.clicks) == 1


def test_a_text_that_is_absent_costs_exactly_the_presence_window() -> None:
    page = page_with(e1=("button", "Save"))
    run(page, SAVE, SAVED)
    first_click = page.clicks[0][1]
    assert clicks.PRESENCE_SECONDS == 0.8
    assert first_click == pytest.approx(0.8)


def test_a_text_that_is_already_there_is_noticed_at_once_for_a_gone_check() -> None:
    page = page_with(e1=("button", "Close"))
    page.texts.append("Menu")
    page.on_click = lambda p, _ref: p.texts.remove("Menu")
    result = run(page, Target("Close", "button", fold=True), Expect("text_gone", "Menu"))
    assert (result.attempts, result.outcome) == (1, "met")
    assert page.clicks[0][1] == 0


def test_an_outcome_that_was_already_true_verifies_nothing() -> None:
    page = page_with(e1=("button", "Save"))
    page.texts.append("Saved")
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (1, "already_true")
    assert len(page.clicks) == 1
    assert page.time.now == 0  # no waiting after the click, and no second click


def test_text_that_is_already_gone_is_already_true_too() -> None:
    page = page_with(e1=("button", "Save"))
    result = run(page, SAVE, Expect("text_gone", "Menu"))
    assert result.outcome == "already_true"
    assert page.clicks[0][1] == pytest.approx(0.8)  # absent for the whole presence window


def test_a_url_change_is_never_already_true() -> None:
    page = page_with(e1=("link", "Next"))
    page.on_click = lambda p, _ref: setattr(p, "url", "https://s.test/two")
    result = run(page, Target("Next", "link", fold=True), Expect("url_changes"))
    assert (result.attempts, result.outcome) == (1, "met")


def test_a_page_that_ignores_the_first_click_gets_a_second_one() -> None:
    page = page_with(e1=("button", "Save"))

    def second_click_works(p: FakePage, _ref: str) -> None:
        if len(p.clicks) == 2:
            p.texts.append("Saved")

    page.on_click = second_click_works
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (2, "met")
    assert len(page.clicks) == 2
    # The retry waited for the grace period first.
    assert page.clicks[1][1] - page.clicks[0][1] == pytest.approx(clicks.GRACE_SECONDS)


def test_a_page_that_redraws_while_waiting_is_not_clicked_again() -> None:
    page = page_with(e1=("button", "Save"))

    def redraw(p: FakePage) -> None:
        p.elements.pop("e1")
        p.elements["e7"] = sessions.Ref("button", "Save")

    page.at(1.0, redraw)
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (1, "not_met")
    assert len(page.clicks) == 1


def test_a_click_that_changed_anything_is_waited_on_and_never_repeated() -> None:
    page = page_with(e1=("button", "Save"))
    page.on_click = lambda p, _ref: p.texts.append("Saving")
    page.at(4.0, lambda p: p.texts.append("Saved"))
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (1, "met")
    assert len(page.clicks) == 1


def test_a_target_that_vanished_proves_the_click_worked() -> None:
    page = page_with(e1=("button", "Stop"))
    page.on_click = lambda p, _ref: p.elements.clear()
    page.at(3.5, lambda p: p.texts.append("Finished"))
    result = run(page, Target("Stop", "button", fold=True), Expect("text_appears", "Finished"))
    assert (result.attempts, result.outcome) == (1, "met")
    assert len(page.clicks) == 1


def test_a_delayed_effect_inside_the_grace_period_is_not_clicked_again() -> None:
    page = page_with(e1=("button", "Save"))
    page.at(clicks.PRESENCE_SECONDS + 1.2, lambda p: p.texts.append("Saved"))
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (1, "met")


def test_nothing_ever_happening_is_reported_after_one_retry() -> None:
    page = page_with(e1=("button", "Save"))
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (2, "not_met")
    assert len(page.clicks) == 2
    total = page.time.now - clicks.PRESENCE_SECONDS
    assert total == pytest.approx(clicks.SETTLE_SECONDS)


def test_a_change_without_the_expected_outcome_is_not_met_and_not_repeated() -> None:
    page = page_with(e1=("button", "Save"))
    page.on_click = lambda p, _ref: p.texts.append("Saving")
    result = run(page, SAVE, SAVED)
    assert (result.attempts, result.outcome) == (1, "not_met")
    assert len(page.clicks) == 1


def test_a_url_that_does_not_change_is_not_met() -> None:
    page = page_with(e1=("link", "Next"))
    result = run(page, Target("Next", "link", fold=True), Expect("url_changes"))
    assert (result.attempts, result.outcome) == (2, "not_met")


def test_the_click_goes_to_the_current_reference_not_the_stale_one() -> None:
    page = page_with(e8=("tab", "Details"), e9=("tab", "Overview"))
    result = run(page, Target("Details", "tab", ref="e6"))
    assert result.name == "Details"
    assert [ref for ref, _ in page.clicks] == ["e8"]


def test_a_target_that_cannot_be_found_is_refused_before_any_waiting() -> None:
    page = page_with(e1=("button", "Save"))
    with pytest.raises(ClickError) as info:
        run(page, Target("Nope", "button", fold=True), SAVED)
    assert info.value.code == "target_not_found"
    assert page.clicks == []
    assert page.time.now == 0


def test_an_ambiguous_target_is_never_clicked() -> None:
    page = page_with(e1=("button", "Delete"), e2=("button", "Delete"))
    with pytest.raises(ClickError) as info:
        run(page, Target("Delete", "button", fold=True))
    assert info.value.code == "target_ambiguous"
    assert page.clicks == []


def test_the_real_clock_is_the_default() -> None:
    assert clicks.REAL_CLOCK.monotonic() > 0
    clicks.REAL_CLOCK.sleep(0)


# -- a real browser, on a fixture page -----------------------------------------------------


_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

FIXTURE = """<!doctype html><title>Fixture</title>
<h1>Fixture</h1>
<div id="tabs"></div>
<button id="rerender">Redraw tabs</button>
<p id="selected">Nothing selected</p>
<div role="menu"><button role="menuitem" id="del-prop">Delete property</button></div>
<div id="dialog">Dialog is open
  <button id="close" aria-label="Close dialog"><svg width="10" height="10"></svg></button></div>
<button id="flaky">Flaky save</button>
<button id="slow">Slow save</button>
<button id="inert">Inert</button>
<p>Page ready</p>
<button class="d">Delete</button><button class="d">Delete</button>
<a href="/two">Next page</a>
<form id="form"><input id="q" aria-label="Query"></form>
<textarea id="notes" aria-label="Notes"></textarea>
<a href="/two" id="orders"><span>icon_user</span> Orders <span>icon_arrow</span></a>
<script>
// What happened is reported to the server, not written on the page, so the page itself stays
// exactly as it was when nothing visible changed.
const log = (line) => {
  new Image().src = '/hit/' + encodeURIComponent(line) + '?' + Math.random();
};
let order = ['Overview', 'Details'];
function tabs() {
  const box = document.getElementById('tabs');
  box.replaceChildren(...order.map((name) => {
    const b = document.createElement('button');
    b.textContent = name;
    b.onclick = () => { document.getElementById('selected').textContent = 'Selected: ' + name; };
    return b;
  }));
}
tabs();
document.getElementById('rerender').onclick = () => { order.reverse(); tabs(); };
document.getElementById('del-prop').onclick = () => log('property deleted');
document.getElementById('close').onclick = () => document.getElementById('dialog').remove();
let flaky = 0;
document.getElementById('flaky').onclick = () => {
  flaky += 1; log('flaky click ' + flaky);
  if (flaky >= 2) document.body.append('Flaky done');
};
let slow = 0;
document.getElementById('slow').onclick = () => {
  slow += 1; log('slow click ' + slow);
  document.body.append('Saving');
  setTimeout(() => document.body.append('Slow done'), 1300);
};
document.getElementById('inert').onclick = () => log('inert click');
document.querySelectorAll('.d').forEach((b) => { b.onclick = () => log('row deleted'); });
document.getElementById('form').onsubmit = (e) => {
  e.preventDefault(); document.body.append('Submitted: ' + document.getElementById('q').value);
};
</script>
"""
PAGES = {"/": FIXTURE, "/two": "<title>Two</title><h1>second page</h1>"}


START = "http://site.test/"


@pytest.fixture(scope="module")
def shared_browser() -> Iterator[tuple[sessions.Session, ProxyStub]]:
    """One real session for the module: starting a browser costs more than any test here."""
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        base = Path(directory)
        runtime = base / "rt"
        runtime.mkdir(mode=0o700)
        roots = sites.Roots(base / "cfg", base / "state", runtime)
        paths = sessions.session_paths(roots, "demo")
        paths.proxy_socket.parent.mkdir(parents=True)
        with (
            PageServer(PAGES) as pages,
            ProxyStub(paths.proxy_socket, pages.address) as proxy,
            sessions.Session.start(roots, "demo", START, timeout=60) as session,
        ):
            yield session, proxy


@pytest.fixture
def browser(shared_browser: tuple[sessions.Session, ProxyStub]) -> Browser:
    """The shared session on a freshly loaded fixture page.

    Loading the page again discards the page's state, so every test starts from the same page
    as it would in a browser of its own. ``hits`` counts only what the page reports from here on.
    """
    session, proxy = shared_browser
    session.open(START)
    return Browser(session, proxy, len(proxy.requests))


@dataclass
class Browser:
    """A real session on the fixture page, and the requests the page made to report on itself."""

    session: sessions.Session
    proxy: ProxyStub
    first: int = 0
    """How many requests the proxy had seen when this test's page loaded."""

    def hits(self) -> list[str]:
        """What the page's own scripts reported since the test began (``flaky click 1``, ...)."""
        time.sleep(0.5)  # a beacon is sent after the click returns
        found = []
        for head in list(self.proxy.requests)[self.first :]:
            target = head.split(maxsplit=2)[1]
            if "/hit/" in target:
                found.append(unquote(target.split("/hit/", 1)[1].split("?", 1)[0]))
        return found

    def text(self) -> str:
        """The names and text on the page."""
        return " | ".join(names_in(self.session.outline()))


@pytest.mark.integration
@needs_everything
def test_a_stale_reference_after_a_redraw_clicks_the_right_tab(browser: Browser) -> None:
    snapshot = browser.session.snapshot()
    tab = next(ref for ref, e in snapshot.refs.items() if e.name == "Details")
    redraw = next(ref for ref, e in snapshot.refs.items() if e.name == "Redraw tabs")
    known = {ref: (e.role, e.name) for ref, e in snapshot.refs.items()}
    browser.session.click(redraw)  # the tabs are replaced, in the other order
    assert browser.session.snapshot().refs.get(tab, sessions.Ref("", "")).name != "Details"
    target = build_target({"ref": tab}, known)
    result = verified_click(browser.session, target, Expect("text_appears", "Selected: Details"))
    assert (result.role, result.name, result.attempts, result.outcome) == (
        "button",
        "Details",
        1,
        "met",
    )
    assert "property deleted" not in browser.hits()


@pytest.mark.integration
@needs_everything
def test_an_icon_button_is_found_by_role_and_name(browser: Browser) -> None:
    target = build_target({"text": "close dialog", "role": "button"}, {})
    result = verified_click(browser.session, target, Expect("text_gone", "Dialog is open"))
    assert (result.name, result.outcome, result.attempts) == ("Close dialog", "met", 1)
    assert "Dialog is open" not in browser.text()


@pytest.mark.integration
@needs_everything
def test_a_retry_happens_only_when_nothing_changed(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The page reacts in milliseconds, so a half-second grace shows the same two things as the
    # real two seconds: a click that does nothing is repeated, and one that shows "Saving" is
    # waited on, not repeated. The slow page takes 1.3 s, so it is only done after the grace
    # (with the real two seconds it would be done inside it and never use the longer wait).
    monkeypatch.setattr(clicks, "GRACE_SECONDS", 0.5)
    monkeypatch.setattr(clicks, "SETTLE_SECONDS", 2.5)
    flaky = verified_click(
        browser.session, Target("Flaky save", "button"), Expect("text_appears", "Flaky done")
    )
    assert (flaky.attempts, flaky.outcome) == (2, "met")
    assert [h for h in browser.hits() if h.startswith("flaky")] == [
        "flaky click 1",
        "flaky click 2",
    ]

    started = time.monotonic()
    slow = verified_click(
        browser.session, Target("Slow save", "button"), Expect("text_appears", "Slow done")
    )
    assert (slow.attempts, slow.outcome) == (1, "met")  # it showed "Saving", so it was not repeated
    assert time.monotonic() - started < 6
    assert [h for h in browser.hits() if h.startswith("slow")] == ["slow click 1"]

    plain = verified_click(browser.session, Target("Inert", "button"))
    assert (plain.attempts, plain.outcome) == (1, "unchecked")
    assert browser.hits().count("inert click") == 1


@pytest.mark.integration
@needs_everything
def test_an_outcome_that_was_already_true_is_not_a_success(browser: Browser) -> None:
    result = verified_click(
        browser.session, Target("Inert", "button"), Expect("text_appears", "Page ready")
    )
    assert (result.attempts, result.outcome) == (1, "already_true")
    assert browser.hits().count("inert click") == 1


@pytest.mark.integration
@needs_everything
def test_the_presence_window_is_800_milliseconds_on_the_wall_clock(browser: Browser) -> None:
    started = time.monotonic()
    result = verified_click(
        browser.session, Target("Inert", "button"), Expect("text_gone", "Text that is not there")
    )
    elapsed = time.monotonic() - started
    assert result.outcome == "already_true"
    assert 0.8 <= elapsed < 3


@pytest.mark.integration
@needs_everything
def test_ambiguous_and_missing_targets_click_nothing(browser: Browser) -> None:
    with pytest.raises(ClickError) as info:
        verified_click(browser.session, Target("Delete", "button"))
    assert info.value.code == "target_ambiguous"
    with pytest.raises(ClickError) as info:
        verified_click(browser.session, Target("Nothing like this", None))
    assert info.value.code == "target_not_found"
    assert "row deleted" not in browser.hits()


@pytest.mark.integration
@needs_everything
def test_a_link_that_changes_the_url_is_verified(browser: Browser) -> None:
    result = verified_click(browser.session, Target("Next page", "link"), Expect("url_changes"))
    assert (result.attempts, result.outcome) == (1, "met")
    assert browser.session.current_url().endswith("/two")


@pytest.mark.integration
@needs_everything
def test_a_link_named_with_icon_words_is_clicked_by_its_text(browser: Browser) -> None:
    names = {e.name for e in browser.session.snapshot().refs.values() if e.role == "link"}
    assert "icon_user Orders icon_arrow" in names
    result = verified_click(
        browser.session, build_target({"text": "Orders"}, {}), Expect("url_changes")
    )
    assert (result.role, result.name, result.outcome) == (
        "link",
        "icon_user Orders icon_arrow",
        "met",
    )
    assert browser.session.current_url().endswith("/two")


def typed_value(browser: Browser) -> str:
    match = re.search(r'textbox "Query"[^\n]*?: (.*)', browser.session.outline())
    return match.group(1) if match else ""


@pytest.mark.integration
@needs_everything
def test_text_is_typed_exactly_as_given(browser: Browser) -> None:
    field = next(r for r, e in browser.session.snapshot().refs.items() if e.name == "Query")
    for text in ("Ada Lovelace", "--json", "--session other", "-x", "--headed", "- a dash"):
        browser.session.fill(field, text)
        assert typed_value(browser) == text
    assert browser.session.is_alive()


@pytest.mark.integration
@needs_everything
def test_typing_can_submit_with_enter(browser: Browser) -> None:
    field = next(r for r, e in browser.session.snapshot().refs.items() if e.name == "Query")
    browser.session.fill(field, "Ada")
    assert "Submitted: Ada" not in browser.text()
    browser.session.press_enter()
    assert "Submitted: Ada" in browser.text()


def browser_pids(session: sessions.Session) -> set[int]:
    """The main Chromium process of the session, found among the holder's descendants."""
    holder = session._holder  # noqa: SLF001 - the test needs the process tree
    assert holder is not None
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                parents[int(entry.name)] = int(
                    (entry / "stat").read_text().rsplit(")", 1)[1].split()[1]
                )
            except OSError, IndexError, ValueError:
                continue
    family, todo = set(), [holder.pid]
    while todo:
        current = todo.pop()
        for child, parent in parents.items():
            if parent == current and child not in family:
                family.add(child)
                todo.append(child)
    found = set()
    for pid in family:
        try:
            command = (
                (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ").decode()
            )
        except OSError:
            continue
        if (
            "chromium" in command
            and "--remote-debugging-port" in command
            and "--type=" not in command
        ):
            found.add(pid)
    return found


EDGES = [
    ("Query", "--headed"),
    ("Query", "-x"),
    ("Query", "a --headed b"),
    ("Query", "--session other"),
    ("Notes", "line1\n--headed"),
    ("Query", "--"),
    ("Query", ""),
    ("Query", "  two leading spaces"),
    ("Query", "  --headed"),
    ("Query", " -x"),
    ("Query", "-"),
    ("Notes", "-x\nsecond line"),
    ("Notes", "--profile=/tmp/elsewhere"),
]


@pytest.mark.integration
@needs_everything
def test_option_like_text_is_typed_literally_and_the_browser_is_left_alone(
    browser: Browser,
) -> None:
    session = browser.session
    refs_by_name = {e.name: ref for ref, e in session.snapshot().refs.items()}
    before = browser_pids(session)
    assert len(before) == 1
    for name, text in EDGES:
        ref = refs_by_name[name]
        session.fill(ref, text)
        read_back = session._call("get", "value", f"@{ref}")["value"]  # noqa: SLF001
        assert read_back == text, (name, text)
        assert browser_pids(session) == before, f"{text!r} restarted the browser"
        assert session.is_alive()
        assert session.current_url() == START


# -- what an unmet expectation costs ----------------------------------------------------------


def looks_after_the_first_click(page: FakePage) -> list[float]:
    return [moment for moment, clicked in page.looks if clicked >= 1]


def test_a_never_met_expectation_costs_at_most_fifteen_snapshots_in_the_settle_time() -> None:
    page = page_with(save=("button", "Save"))
    result = run(page, SAVE, Expect("text_appears", "Saved"))
    assert (result.outcome, result.attempts) == ("not_met", 2)
    looks = looks_after_the_first_click(page)
    assert len(looks) <= clicks.MAX_CHECKS
    assert page.time.now - page.clicks[0][1] <= clicks.SETTLE_SECONDS


def test_the_checks_back_off_from_a_tenth_of_a_second_to_half_a_second() -> None:
    page = page_with(save=("button", "Save"))
    run(page, SAVE, Expect("text_appears", "Saved"))
    first = page.clicks[0][1]
    gaps = [round(b - a, 2) for a, b in itertools.pairwise(looks_after_the_first_click(page))]
    assert gaps[:5] == [0.1, 0.25, 0.5, 0.5, 0.5]
    assert all(gap <= 0.5 for gap in gaps)
    assert page.time.now - first <= clicks.SETTLE_SECONDS


def test_a_click_that_changed_the_page_but_never_met_the_expectation_is_not_repeated() -> None:
    page = page_with(save=("button", "Save"))
    page.on_click = lambda p, _ref: p.texts.append("Something else")
    result = run(page, SAVE, Expect("text_appears", "Saved"))
    assert (result.outcome, result.attempts) == ("not_met", 1)
    assert len(looks_after_the_first_click(page)) <= clicks.MAX_CHECKS
    assert page.time.now - page.clicks[0][1] <= clicks.SETTLE_SECONDS


def test_the_checks_stop_at_the_limit_even_when_time_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clicks, "MAX_CHECKS", 4)
    page = page_with(save=("button", "Save"))
    page.on_click = lambda p, _ref: p.texts.append("Something else")
    result = run(page, SAVE, Expect("text_appears", "Saved"))
    assert result.outcome == "not_met"
    assert len(looks_after_the_first_click(page)) == 4
    assert page.time.now - page.clicks[0][1] < clicks.SETTLE_SECONDS


def test_a_page_that_looks_the_same_after_the_grace_is_clicked_again_and_looked_at_again() -> None:
    page = page_with(save=("button", "Save"))
    run(page, SAVE, Expect("text_appears", "Saved"))
    assert len(page.clicks) == 2
    assert page.clicks[1][1] == pytest.approx(page.clicks[0][1] + clicks.GRACE_SECONDS)
    assert any(moment == page.clicks[1][1] and clicked == 2 for moment, clicked in page.looks)
