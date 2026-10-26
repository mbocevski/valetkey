# SPDX-License-Identifier: Apache-2.0
"""Notice that a saved login has stopped working.

When a site forgets a person, opening its start URL redirects to a sign-in page. So after a
session opens, the page it ended on is compared with what the login looked like:

* **A recorded login page.** During the login, the pages a form was submitted from were saved in
  the policy (``login_pages``, see :func:`valetkey.learn.login_pages`). If the start URL ended
  on one of them, the login has expired.
* **A password field after a redirect.** If the start URL was redirected to another page and
  that page has a password field, the login has expired. This covers sites whose login was not
  a form submission, and policies saved before ``login_pages`` existed.

Both need the page to differ from the start page. A start page that is not redirected is never
reported, whatever it contains: a site may well have a sign-in box on a public front page, and
a signed-in session that stays on the start URL has not expired.

The password field is found by asking the browser to count ``input[type=password]``. The
accessibility tree does not mark a password field: it is a text box with no name, and only the
bullets of a typed value give it away.
"""

from typing import TYPE_CHECKING

from valetkey import sites

if TYPE_CHECKING:
    from collections.abc import Callable


def login_expired(
    policy: sites.Policy, landed_url: str, password_fields: Callable[[], int]
) -> str | None:
    """Return why the login looks expired, or ``None`` when nothing says it is.

    ``landed_url`` is where opening ``policy.start`` ended. ``password_fields`` counts the
    password fields on that page; it is only called when it is needed.
    """
    landed, start = sites.page_key(landed_url), sites.page_key(policy.start)
    if landed is None or landed == start:
        return None
    if landed in policy.login_pages:
        return "the start page redirected to a sign-in page seen during the login"
    if password_fields() > 0:
        return "the start page redirected to a page with a password field"
    return None
