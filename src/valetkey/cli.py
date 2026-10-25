# SPDX-License-Identifier: Apache-2.0
"""The ``valetkey`` command."""

import sys
from typing import TYPE_CHECKING

from cyclopts import App

from valetkey import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence

app = App(
    name="valetkey",
    help="A logged-in browser for MCP clients, contained to the sites it may reach.",
    version=f"valetkey {__version__}",
    help_formatter="plain",
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command named in ``argv`` (default: ``sys.argv``) and return its exit status.

    Usage errors exit with status 2 after printing the error.
    """
    tokens = sys.argv[1:] if argv is None else argv
    status = app(tokens, result_action="return_int_as_exit_code_else_zero")
    return int(status)
