# SPDX-License-Identifier: Apache-2.0
"""Tell the hosts that serve ads and tracking from the ones a page needs to work.

A login records every host the browser contacts, and a modern site contacts dozens. It allows all
of them except the ones that only advertise or watch the visitor (an ad network, an analytics
script, a tracking pixel): those it leaves out and counts. The test is a guess made from the host
name alone, in three layers, and a host is a tracker if any of them says so:

1. :func:`listed`, Peter Lowe's "Ad and tracking server domain list" (https://pgl.yoyo.org/
   adservers/), vendored as ``data/adservers.txt`` exactly as the site serves it. It is one
   person's list, kept by hand since 2003, of highest-level domains of ad servers, tracking
   servers, malware and spam servers, each checked weekly to still exist. An entry covers its
   subdomains. It names a shared host such as ``ads.linkedin.com`` in full and never a domain
   that a page needs, such as a CDN, an identity provider or a payment service. ``tools/
   update_trackers.py`` refreshes it, and ``tools/trackers.lock`` holds its SHA-256, which a test
   checks. The author has no formal licence; the list's page says to feel free to combine it with
   other lists and put it up on the web, which is what this does, with the author's credit kept
   in the file.
2. :data:`SUPPLEMENT`, a few analytics, session-replay and error-reporting domains that list does
   not hold. It is written by hand and short.
3. :data:`TRACKING_LABELS`, a pattern for host names that say what they are: a label such as
   ``ads``, ``analytics``, ``pixel``, ``telemetry`` or ``track2``, as in ``ads.example.com``.

No layer holds an identity provider, a CDN, a social sign-in, a font or a payment service, and a
test keeps it so. The cost of a mistake is small either way: a tracker the layers miss is allowed,
as any host the page used would be, and a host wrongly taken for one is left out and counted, and
``valetkey allow`` lets it in.
"""

import functools
import logging
import re
from importlib import resources

from valetkey import sites

logger = logging.getLogger(__name__)

DATA = "data/adservers.txt"
"""The vendored list, below this package."""
_ENTRY = re.compile(r"127\.0\.0\.1 ([a-z0-9][a-z0-9._-]*)")

SUPPLEMENT: frozenset[str] = frozenset(
    {
        "6sense.com",
        "adroll.com",
        "albacross.com",
        "amplitude.com",
        "bannerflow.net",
        "bidtheatre.com",
        "bombora.com",
        "bugsnag.com",
        "clarity.ms",
        "clicktale.net",
        "contentsquare.net",
        "ct.pinterest.com",
        "decibelinsight.net",
        "en25.com",
        "fwmrm.net",
        "glassboxdigital.io",
        "gumgum.com",
        "heap.io",
        "heapanalytics.com",
        "hotjar.io",
        "hs-scripts.com",
        "hscollectedforms.net",
        "kochava.com",
        "logrocket.com",
        "mouseflow.com",
        "mplat-ppcprotect.com",
        "newrelic.com",
        "ppcprotect.com",
        "pubmatic.com",
        "raygun.io",
        "rollbar.com",
        "rtbhouse.com",
        "sc-static.net",
        "segment.com",
        "segment.io",
        "sentry-cdn.com",
        "sentry.io",
        "serving-sys.com",
        "singular.net",
        "sitescout.com",
        "smaato.net",
        "snap.licdn.com",
        "tiqcdn.com",
        "tr.snapchat.com",
        "trackjs.com",
    }
)
"""Domains of ad, analytics, session-replay, click-fraud and error-reporting services that the
vendored list does not hold, each covering its subdomains. Add one when a login of a real site
allows a host that is plainly a tracker; a test keeps the sign-in providers and CDNs out."""

TRACKING_LABELS = re.compile(
    r"(?:ads?|adserver|adservice|analytics|beacon|metrics|pixel|telemetry|track|tracker|tracking)"
    r"(?:-?\d+)?"
)
"""A host-name label that says the host is for ads or tracking, such as ``ads``, ``track-2``."""


def parse(text: str) -> frozenset[str]:
    """Return the domains of a list in hosts format: ``127.0.0.1 domain`` lines and ``#`` comments.

    Raises:
        ValueError: when a line is neither, because a list that cannot be read is not guessed at.

    """
    found: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        entry = _ENTRY.fullmatch(line.strip())
        if entry is None:
            message = f"line {number} is not '127.0.0.1 DOMAIN': {line[:60]!r}"
            raise ValueError(message)
        found.add(entry.group(1))
    return frozenset(found)


@functools.cache
def listed() -> frozenset[str]:
    """Return the domains of the vendored list; an unreadable file means an empty list.

    An empty list leaves the other two layers, and is logged once, so a damaged install loses
    some sorting of what a login left out and nothing else.
    """
    try:
        return parse(resources.files("valetkey").joinpath(DATA).read_text(encoding="utf-8"))
    except OSError, ValueError:
        logger.warning("the list of ad and tracking domains could not be read", exc_info=True)
        return frozenset()


def is_tracking(host: str) -> bool:
    """Tell whether ``host`` looks like an ad or tracking service (see the module docs)."""
    host = sites.normalize_host(host)
    if sites.is_ip_literal(host):
        return False
    labels = host.split(".")
    domains = listed() | SUPPLEMENT
    if any(".".join(labels[start:]) in domains for start in range(len(labels) - 1)):
        return True
    return any(TRACKING_LABELS.fullmatch(label) for label in labels[:-1])
