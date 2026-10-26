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
MAX_CANDIDATES = 5

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

    def outline(self) -> str:
        """Return the whole accessibility tree as text."""

    def click(self, ref: str) -> None:
        """Click ``ref``."""

    def current_url(self) -> str:
        """Return the page's URL."""


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
    """Ignore case when comparing names (used for text the caller typed, not for a snapshot's)."""


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


def build_target(args: Mapping[str, Any], known: Mapping[str, tuple[str, str]]) -> Target:
    """Turn the arguments of a click into a :class:`Target`.

    ``known`` maps the references of the caller's last snapshot to ``(role, name)``.

    Raises:
        ClickError: ``bad_request`` unless exactly one of ``ref`` and ``text`` is given, or if
            ``role`` is given with ``ref``; ``unknown_ref`` when the caller never saw that
            reference in a snapshot.

    """
    ref = _text_arg(args.get("ref"), "ref")
    text = _text_arg(args.get("text"), "text")
    role = _text_arg(args.get("role"), "role")
    if (ref is None) == (text is None):
        _refuse("bad_request", "give exactly one of ref and text")
    if text is None:
        if role is not None:
            _refuse("bad_request", "role goes with text; a reference already says what it is")
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
    return Target(name=normalize(text), role=role, fold=True)


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


def resolve(refs: Mapping[str, sessions.Ref], target: Target) -> tuple[str, sessions.Ref]:
    """Pick the one element of a fresh snapshot that ``target`` means.

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


# -- waiting and expecting ---------------------------------------------------------------------


def _wait_until(check: Callable[[], bool], seconds: float, clock: Clock) -> bool:
    """Call ``check`` until it is true or ``seconds`` have passed; the last look is at the end."""
    deadline = clock.monotonic() + seconds
    while not check():
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            return False
        clock.sleep(min(POLL_SECONDS, remaining))
    return True


def _has_text(page: Page, text: str) -> bool:
    wanted = normalize(text).casefold()
    return any(wanted in normalize(name).casefold() for name in names_in(page.outline()))


def _is_met(page: Page, expect: Expect, url_before: str) -> bool:
    if expect.kind == "text_appears":
        return _has_text(page, expect.text)
    if expect.kind == "text_gone":
        return not _has_text(page, expect.text)
    return page.current_url() != url_before


def _was_already_true(page: Page, expect: Expect, clock: Clock) -> bool:
    """Whether the expectation holds before the click. A URL change never does."""
    if expect.kind == "url_changes":
        return False
    seen = _wait_until(lambda: _has_text(page, expect.text), PRESENCE_SECONDS, clock)
    return seen if expect.kind == "text_appears" else not seen


# -- the click -------------------------------------------------------------------------------


def verified_click(
    page: Page, target: Target, expect: Expect | None = None, clock: Clock = REAL_CLOCK
) -> ClickResult:
    """Click ``target`` on ``page`` once, or twice if the first click provably did nothing.

    The sequence is: make sure the target can be found, check that the expectation is not already
    true (waiting up to :data:`PRESENCE_SECONDS`), resolve the target in a fresh snapshot, note
    the URL and the page outline, and click. Without an expectation that is all.

    With one, the expectation gets :data:`GRACE_SECONDS`. If it is not met and the URL and
    outline are exactly as before, the click is judged to have done nothing: the target is
    resolved again and clicked once more. If the page changed in any way, the click took effect
    and the expectation gets the rest of :data:`SETTLE_SECONDS` without another click.

    Raises:
        ClickError: when the target cannot be found, or matches more than one element.

    """
    already_true = False
    if expect is not None:
        resolve(page.snapshot().refs, target)  # refuse now, before any waiting, if it is not there
        already_true = _was_already_true(page, expect, clock)
    ref, element = resolve(page.snapshot().refs, target)  # (again, because the page kept moving)
    url_before, outline_before = page.current_url(), page.outline()
    page.click(ref)
    attempts = 1
    if expect is None:
        return ClickResult(element.role, element.name, attempts, None, "unchecked")
    if already_true:
        return ClickResult(element.role, element.name, attempts, expect, "already_true")

    if _wait_until(lambda: _is_met(page, expect, url_before), GRACE_SECONDS, clock):
        return ClickResult(element.role, element.name, attempts, expect, "met")
    unchanged = page.current_url() == url_before and page.outline() == outline_before
    budget = SETTLE_SECONDS - GRACE_SECONDS
    if unchanged:
        ref, element = resolve(page.snapshot().refs, target)
        page.click(ref)
        attempts = 2
    met = _wait_until(lambda: _is_met(page, expect, url_before), budget, clock)
    return ClickResult(element.role, element.name, attempts, expect, "met" if met else "not_met")
