# SPDX-License-Identifier: Apache-2.0
"""Clicks that find their target again and check what happened.

A plain click by reference has two ways to go wrong. A page can re-render between the snapshot
and the click, so that a reference now points at a different element (a tab once became a
"Delete property" menu). And a click can reach its target without doing anything, which looks
exactly like a click that worked.

:func:`verified_click` closes both:

* **Re-resolving.** The target is described by what the caller saw: the role and accessible name
  of a reference from their last snapshot, or visible text with an optional role. At click time
  it takes a fresh snapshot and clicks the one element that matches. A reference that is still
  there with the same role and name is the same element and is used as it is. Otherwise zero
  matches or several are refused, never guessed.
* **Expectation.** The caller may say what should follow: some text appears, some text goes, or
  the URL changes. The click is then checked against it. An outcome that was already true before
  the click verifies nothing, and is reported as such.
* **Hovering first.** Some pages show a row's actions only while the pointer is over the row. With
  ``hover``, a list of texts, the first that names exactly one element is hovered, and the target
  is looked for in a snapshot taken after that, so a click on what the hover revealed is one call.
  The pointer stays where the hover left it.
* **Retry.** With an expectation, and only when the first click provably changed nothing (same
  URL, same page outline after a short grace period), the click is made once more. A click that
  changed anything is waited on and never repeated. Without an expectation there is no retry,
  because repeating an unverified click is just clicking twice.

Presence is judged on accessible names and page text from the accessibility tree, not on inner
text, because an icon button has an empty inner text and a label as its name.

Everything here uses a :class:`Page`, so the logic is tested without a browser.
"""

import json
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NoReturn, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from valetkey import sessions

PRESENCE_SECONDS = 0.8
"""How long "is this here right now" is given: long enough for a control that is still being
drawn, short enough that an absent one does not slow a click."""
GRACE_SECONDS = 2.0
"""How long a click gets to show any effect before it is judged to have done nothing."""
SETTLE_SECONDS = 5.0
"""The most time an expectation gets after a click, retry included."""
POLL_SECONDS = 0.1
"""The wait before the second check. Later waits grow: see :data:`BACKOFF_SECONDS`."""
BACKOFF_SECONDS = (POLL_SECONDS, 0.25, 0.5)
"""The wait after the first check, after the second, and after every later one. Each check is a
full snapshot, which is a program started in the sandbox, so a slow page is not asked ten times a
second."""
MAX_CHECKS = 15
"""The most checks of an expectation after one click, whatever time is left."""
MAX_CANDIDATES = 5
MAX_HOVER = 5
"""The most entries ``hover`` may list."""
MAX_HOVER_LENGTH = 200
"""The longest an entry of ``hover`` may be."""

type Kind = Literal["text_appears", "text_gone", "url_changes"]
type Outcome = Literal["met", "not_met", "already_true", "unchecked"]

_REF = re.compile(r"@?(e\d+)")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


class ClickError(ValueError):
    """A click that was refused before it was made, with a short code for the caller."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        """Keep the code, the message and the details."""
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _refuse(code: str, message: str, details: dict[str, Any] | None = None) -> NoReturn:
    raise ClickError(code, message, details)


class Page(Protocol):
    """What a verified click needs of a browser. :class:`valetkey.sessions.Session` provides it."""

    def snapshot(self) -> sessions.Snapshot:
        """Return the interactive elements with their references."""

    def look(self) -> tuple[str, str]:
        """Return the page's URL and its whole accessibility tree as text, from one snapshot."""

    def click(self, ref: str) -> None:
        """Click ``ref``."""

    def hover(self, ref: str) -> None:
        """Move the pointer over ``ref`` and leave it there."""


@dataclass(frozen=True, slots=True)
class Clock:
    """Time, replaceable so that waiting can be tested without waiting."""

    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


REAL_CLOCK = Clock()


@dataclass(frozen=True, slots=True)
class Expect:
    """What should be true after the click. ``text`` is unused for ``url_changes``."""

    kind: Kind
    text: str = ""

    def to_json(self) -> dict[str, Any]:
        """Return the expectation as it travels between the daemon and its clients."""
        return {"kind": self.kind, "text": self.text}


@dataclass(frozen=True, slots=True)
class Target:
    """The element to click, as the caller described it.

    ``name`` and ``role`` are the accessible name and role to match. ``ref`` is set when the
    caller named a reference, and then it is only a shortcut: if it still has that role and
    name it is used, and if not the role and name are searched for.
    """

    name: str
    role: str | None = None
    ref: str | None = None
    fold: bool = False
    """Ignore case when comparing names, and take the one name that holds the text as whole words
    when none is equal (used for text the caller typed, not for a snapshot's). A click with
    ``exact`` leaves it off: only a name equal to the text, case included, is the target."""


@dataclass(frozen=True, slots=True)
class ClickResult:
    """What a verified click did."""

    role: str
    name: str
    attempts: int
    expect: Expect | None
    outcome: Outcome


# -- describing the target and the expectation -------------------------------------------------


def _text_arg(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        _refuse("bad_request", f'"{name}" must be a non-empty string')
    return value


def _flag_arg(value: object, name: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        _refuse("bad_request", f'"{name}" must be true or false')
    return value


def build_target(args: Mapping[str, Any], known: Mapping[str, tuple[str, str]]) -> Target:
    """Turn the arguments of a click into a :class:`Target`.

    ``known`` maps the references of the caller's last snapshot to ``(role, name)``.

    Raises:
        ClickError: ``bad_request`` unless exactly one of ``ref`` and ``text`` is given, or if
            ``role`` or ``exact`` is given with ``ref``; ``unknown_ref`` when the caller never saw
            that reference in a snapshot.

    """
    ref = _text_arg(args.get("ref"), "ref")
    text = _text_arg(args.get("text"), "text")
    role = _text_arg(args.get("role"), "role")
    exact = _flag_arg(args.get("exact"), "exact")
    if (ref is None) == (text is None):
        _refuse("bad_request", "give exactly one of ref and text")
    if text is None:
        if role is not None:
            _refuse("bad_request", "role goes with text; a reference already says what it is")
        if exact:
            _refuse("bad_request", "exact goes with text; a reference already says what it is")
        match = _REF.fullmatch(ref or "")
        if match is None:
            _refuse("bad_request", f"not a reference from a snapshot: {ref!r}")
        key = match.group(1)
        if key not in known:
            _refuse(
                "unknown_ref",
                f"{key} is not in the snapshot you last took of this site; "
                "take a new snapshot first",
            )
        found_role, found_name = known[key]
        return Target(name=normalize(found_name), role=found_role, ref=key)
    return Target(name=normalize(text), role=role, fold=not exact)


def parse_expectation(raw: object) -> Expect | None:
    """Parse the ``expect`` argument: ``None``, or an object with exactly one expectation.

    The forms are ``{"text_appears": "..."}``, ``{"text_gone": "..."}`` and
    ``{"url_changes": true}``.

    Raises:
        ClickError: ``bad_request`` for anything else.

    """
    if raw is None:
        return None
    if not isinstance(raw, dict) or len(raw) != 1:
        _refuse("bad_request", "expect takes exactly one of text_appears, text_gone, url_changes")
    ((key, value),) = raw.items()
    if key in {"text_appears", "text_gone"} and isinstance(value, str) and value.strip():
        return Expect(key, value)
    if key == "url_changes" and value is True:
        return Expect("url_changes")
    _refuse(
        "bad_request",
        "expect takes text_appears or text_gone with some text, or url_changes: true",
    )


def parse_hover(raw: object) -> tuple[str, ...]:
    """Parse the ``hover`` argument: ``None``, or one to five non-empty texts.

    Raises:
        ClickError: ``bad_request`` for anything else, including a text over 200 characters.

    """
    if raw is None:
        return ()
    if (
        not isinstance(raw, list)
        or not 1 <= len(raw) <= MAX_HOVER
        or not all(isinstance(item, str) and item.strip() for item in raw)
        or any(len(item) > MAX_HOVER_LENGTH for item in raw)
    ):
        _refuse(
            "bad_request",
            f"hover takes one to {MAX_HOVER} texts, each not empty and at most "
            f"{MAX_HOVER_LENGTH} characters",
        )
    return tuple(raw)


def normalize(text: str) -> str:
    """Return ``text`` with runs of whitespace made single spaces, as accessible names are read."""
    return " ".join(text.split())


# -- finding things --------------------------------------------------------------------------


def names_in(outline: str) -> list[str]:
    """Return every quoted name and text in an accessibility tree, without its annotations.

    Matching on these rather than on the tree text keeps reference numbers and roles from
    matching the caller's text by accident.
    """
    found = []
    for match in _QUOTED.finditer(outline):
        try:
            found.append(str(json.loads(f'"{match.group(1)}"')))
        except ValueError:
            found.append(match.group(1))
    return found


def _same(a: str, b: str, *, fold: bool) -> bool:
    return a.casefold() == b.casefold() if fold else a == b


def _matches(role: str, name: str, target: Target) -> bool:
    if target.role is not None and role.casefold() != target.role.casefold():
        return False
    return _same(normalize(name), target.name, fold=target.fold)


def _holds_words(name: str, target: Target) -> bool:
    """Tell whether ``name`` contains the target's text as whole words, in the right role.

    A word ends at a space or a mark, never inside a longer word: ``konto`` is in ``Mitt konto``
    and not in ``kontoret``, and ``orders`` is in ``icon_user Orders icon_arrow`` but not in
    ``icon_orders``.
    """
    pattern = rf"(?<!\w){re.escape(target.name.casefold())}(?!\w)"
    return re.search(pattern, normalize(name).casefold()) is not None


def resolve(refs: Mapping[str, sessions.Ref], target: Target) -> tuple[str, sessions.Ref]:
    """Pick the one element of a fresh snapshot that ``target`` means.

    An exact name wins. When none has that name and the text came from the caller (``fold``),
    the one element whose name holds the text as whole words is taken, as when a site builds names
    from icon labels (``icon_user Orders icon_arrow``). Several such elements are not guessed at.

    Raises:
        ClickError: ``target_not_found`` or ``target_ambiguous``, with the names that came
            close in ``details["candidates"]``.

    """
    if target.ref is not None:
        current = refs.get(target.ref)
        if current is not None and _matches(current.role, current.name, target):
            return target.ref, current
    matches = [
        (ref, element)
        for ref, element in refs.items()
        if _matches(element.role, element.name, target)
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches and target.fold:
        holding = [
            (ref, element)
            for ref, element in refs.items()
            if (target.role is None or element.role.casefold() == target.role.casefold())
            and _holds_words(element.name, target)
        ]
        if len(holding) == 1:
            return holding[0]
    what = f"a {target.role}" if target.role else "an element"
    if matches:
        details = {"candidates": [{"role": e.role, "name": e.name} for _, e in matches]}
        _refuse(
            "target_ambiguous",
            f"{len(matches)} elements match {what} with that name, so the click was not made; "
            "take a new snapshot and click by reference, or add a role to tell them apart",
            details,
        )
    near = [
        {"role": e.role, "name": e.name}
        for e in refs.values()
        if target.name.casefold() in normalize(e.name).casefold()
        and (target.role is None or e.role.casefold() == target.role.casefold())
    ]
    _refuse(
        "target_not_found",
        f"nothing on the page is {what} with that name, so the click was not made; "
        "take a new snapshot to see what is there now",
        {"candidates": near[:MAX_CANDIDATES]},
    )


def hover_over(page: Page, entries: tuple[str, ...], *, exact: bool = False) -> sessions.Ref:
    """Hover over the first of ``entries`` that names exactly one element, and return it.

    Each entry is matched like the text of a click (the exact name, then the name that holds it
    as whole words), with no role. With ``exact`` only a name equal to the entry, case included,
    matches. An entry that matches nothing, or several elements, is passed over; none of them left
    is a ``hover_not_found``.

    Raises:
        ClickError: ``hover_not_found``, naming the entries tried and the names that came close.

    """
    refs = page.snapshot().refs
    close: list[dict[str, str]] = []
    for entry in entries:
        try:
            ref, element = resolve(refs, Target(name=normalize(entry), fold=not exact))
        except ClickError as error:
            close.extend(c for c in error.details.get("candidates", []) if c not in close)
            continue
        page.hover(ref)
        return element
    tried = ", ".join(json.dumps(entry) for entry in entries)
    _refuse(
        "hover_not_found",
        f"nothing to hover over was found: {tried} matched no single element, so nothing was "
        "clicked; take a new snapshot to see what is there now",
        {"candidates": close[:MAX_CANDIDATES], "tried": list(entries)},
    )


# -- waiting and expecting ---------------------------------------------------------------------


class _Watch:
    """The checks of one click: what the page looked like last, how many looks were taken."""

    def __init__(self, page: Page, clock: Clock) -> None:
        self.page = page
        self.clock = clock
        self.url = ""
        self.outline = ""
        """The latest look: the URL and the outline."""
        self.checks = 0

    def until(
        self, test: Callable[[str, str], bool], seconds: float, *, look_now: bool = True
    ) -> bool:
        """Look until ``test(url, outline)`` is true, ``seconds`` have passed or the checks run out.

        A check is one snapshot. The first is at once (unless ``look_now`` is false, because the
        page was just looked at), the waits between checks grow (see :data:`BACKOFF_SECONDS`), and
        the last look is at the end of the time. After :data:`MAX_CHECKS` checks in all, it gives
        up whatever time is left.
        """
        deadline = self.clock.monotonic() + seconds
        while True:
            if look_now:
                self.url, self.outline = self.page.look()
                self.checks += 1
                if test(self.url, self.outline):
                    return True
            look_now = True
            remaining = deadline - self.clock.monotonic()
            if remaining <= 0 or self.checks >= MAX_CHECKS:
                return False
            wait = BACKOFF_SECONDS[min(max(self.checks, 1) - 1, len(BACKOFF_SECONDS) - 1)]
            self.clock.sleep(min(wait, remaining))


def _has_text(outline: str, text: str) -> bool:
    wanted = normalize(text).casefold()
    return any(wanted in normalize(name).casefold() for name in names_in(outline))


def _is_met(expect: Expect, url_before: str) -> Callable[[str, str], bool]:
    """Return the test of ``expect`` on what the page looks like."""

    def test(url: str, outline: str) -> bool:
        if expect.kind == "text_appears":
            return _has_text(outline, expect.text)
        if expect.kind == "text_gone":
            return not _has_text(outline, expect.text)
        return url != url_before

    return test


def _was_already_true(page: Page, expect: Expect, clock: Clock) -> bool:
    """Whether the expectation holds before the click. A URL change never does."""
    if expect.kind == "url_changes":
        return False
    seen = _Watch(page, clock).until(
        lambda _url, outline: _has_text(outline, expect.text), PRESENCE_SECONDS
    )
    return seen if expect.kind == "text_appears" else not seen


# -- the click -------------------------------------------------------------------------------


def verified_click(  # noqa: PLR0913 - one click, described by its parts
    page: Page,
    target: Target,
    expect: Expect | None = None,
    clock: Clock = REAL_CLOCK,
    hover: tuple[str, ...] = (),
    *,
    exact: bool = False,
) -> ClickResult:
    """Click ``target`` on ``page`` once, or twice if the first click provably did nothing.

    The sequence is: make sure the target can be found, check that the expectation is not already
    true (waiting up to :data:`PRESENCE_SECONDS`), resolve the target in a fresh snapshot, note
    the URL and the page outline, and click. Without an expectation that is all.

    With one, the expectation gets :data:`GRACE_SECONDS`. If it is not met and the URL and
    outline are exactly as before, the click is judged to have done nothing: the target is
    resolved again and clicked once more. If the page changed in any way, the click took effect
    and the expectation gets the rest of :data:`SETTLE_SECONDS` without another click.

    With ``hover``, the first of those texts that names one element is hovered first (see
    :func:`hover_over`; ``exact`` is for those texts, as it is for the target's text in
    :class:`Target`), and everything after is as above, on the page as the hover left it.

    Raises:
        ClickError: when the target cannot be found, or matches more than one element, or when
            nothing named by ``hover`` can be found.

    """
    hovered = hover_over(page, hover, exact=exact) if hover else None

    def find() -> tuple[str, sessions.Ref]:
        try:
            return resolve(page.snapshot().refs, target)
        except ClickError as error:
            if hovered is None or error.code != "target_not_found":
                raise
            message = (
                f"hovering over the {hovered.role} named {json.dumps(hovered.name)} worked, but "
                f"{error}"
            )
            raise ClickError(error.code, message, error.details) from None

    already_true = False
    if expect is not None:
        find()  # refuse now, before any waiting, if it is not there
        already_true = _was_already_true(page, expect, clock)
    ref, element = find()  # (again, because the page kept moving)
    url_before, outline_before = page.look()
    page.click(ref)
    attempts = 1
    if expect is None:
        return ClickResult(element.role, element.name, attempts, None, "unchecked")
    if already_true:
        return ClickResult(element.role, element.name, attempts, expect, "already_true")

    watch = _Watch(page, clock)
    test = _is_met(expect, url_before)
    if watch.until(test, GRACE_SECONDS):
        return ClickResult(element.role, element.name, attempts, expect, "met")
    unchanged = watch.url == url_before and watch.outline == outline_before
    budget = SETTLE_SECONDS - GRACE_SECONDS
    if unchanged:
        ref, element = find()
        page.click(ref)
        attempts = 2
    met = watch.until(test, budget, look_now=unchanged)
    return ClickResult(element.role, element.name, attempts, expect, "met" if met else "not_met")
