# SPDX-License-Identifier: Apache-2.0
"""Tell the hosts that serve ads and tracking from the ones a page needs to work.

A login records every host the browser contacts, and a modern site contacts dozens. It allows all
of them except the ones that only advertise or watch the visitor (an ad network, an analytics
script, a tracking pixel): those it leaves out and counts. The test is a guess made from the host
name alone, and it has two parts:

* :data:`TRACKER_DOMAINS`, a short list of the registrable domains of well-known ad, analytics,
  tag-manager, session-replay and error-reporting services. It is written by hand, not copied
  from a block list, so it is small, stable and easy to audit. It names services that exist only
  to watch or advertise, and none that a page may need to work: no identity provider, no CDN, no
  social sign-in, no font or payment service.
* :data:`TRACKING_LABELS`, a pattern for host names that say what they are: a label such as
  ``ads``, ``analytics``, ``pixel``, ``telemetry`` or ``track2``, as in ``ads.example.com``. It
  catches the many small services the list cannot name, and the names are honest, because a host
  that calls itself ``analytics`` is one.

The cost of a mistake is small either way. A tracker the list misses is allowed, as any host the
page used would be. A host wrongly taken for a tracker is left out and counted, and
``valetkey allow`` lets it in.
"""

import re

from valetkey import sites

TRACKER_DOMAINS: frozenset[str] = frozenset(
    {
        "2o7.net",
        "adnxs.com",
        "adsrvr.org",
        "adform.net",
        "amplitude.com",
        "bugsnag.com",
        "clarity.ms",
        "crazyegg.com",
        "criteo.com",
        "criteo.net",
        "demdex.net",
        "doubleclick.net",
        "fullstory.com",
        "google-analytics.com",
        "googleadservices.com",
        "googlesyndication.com",
        "googletagmanager.com",
        "googletagservices.com",
        "heap.io",
        "heapanalytics.com",
        "hotjar.com",
        "hotjar.io",
        "hs-analytics.net",
        "hsadspixel.net",
        "inspectlet.com",
        "kissmetrics.com",
        "liveintent.com",
        "logrocket.com",
        "mathtag.com",
        "mixpanel.com",
        "mouseflow.com",
        "newrelic.com",
        "nr-data.net",
        "omtrdc.net",
        "optimizely.com",
        "outbrain.com",
        "pubmatic.com",
        "quantserve.com",
        "rubiconproject.com",
        "scorecardresearch.com",
        "segment.com",
        "segment.io",
        "sentry.io",
        "taboola.com",
    }
)
"""Registrable domains of services that exist to advertise or to watch visitors."""

TRACKING_LABELS = re.compile(
    r"(?:ads?|adserver|adservice|analytics|beacon|metrics|pixel|telemetry|track|tracker|tracking)"
    r"(?:-?\d+)?"
)
"""A host-name label that says the host is for ads or tracking, such as ``ads``, ``track-2``."""


def is_tracking(host: str) -> bool:
    """Tell whether ``host`` looks like an ad or tracking service (see the module docs)."""
    host = sites.normalize_host(host)
    if sites.is_ip_literal(host):
        return False
    if sites.registrable_domain(host) in TRACKER_DOMAINS:
        return True
    return any(TRACKING_LABELS.fullmatch(label) for label in host.split(".")[:-1])
