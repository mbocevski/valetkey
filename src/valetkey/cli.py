# SPDX-License-Identifier: Apache-2.0
"""The ``valetkey`` command."""

import argparse
from typing import TYPE_CHECKING

from valetkey import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for the ``valetkey`` command."""
    parser = argparse.ArgumentParser(
        prog="valetkey",
        description="A logged-in browser for MCP clients, contained to the sites it may reach.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse ``argv`` and run the requested command, returning the exit status."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
