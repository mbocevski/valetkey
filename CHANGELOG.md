# Changelog

Changes that affect users of valetkey. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `valetkey` command, which prints its version and help.
- The `valetkey sites` command, which lists your sites, with `--json` for scripts.
- The `valetkey allow` and `valetkey deny` commands, which add or remove a host a site may reach.
- The `valetkey forget` command, which deletes a site's policy, login and downloads after asking.
- The `valetkey install-units` command, which writes the systemd user units for the daemon.
- The `valetkey doctor` command, which checks that bubblewrap, Chromium and agent-browser are ready.
- The `valetkey mcp` command, an MCP server that gives a client browser tools for the sites you have logged in to.
- The `browser_click` tool can name an element by its text, finds it again when it clicks, and checks the outcome you expect.
- The `browser_type` tool can press Enter after typing.
- `browser_open` notices when a saved login has expired, ends the session and tells the client to log in again.
- `browser_sites` shows when you last logged in, and which hosts each site may reach and which were left out.
- Files a site downloads are saved in its downloads folder, never replacing an older file, and `browser_click` and `browser_navigate` list the new ones; `browser_downloads` lists the folder.
- The `browser_allow` tool, which asks you, in the client or through the `approve_command` in your config, before a refused host is allowed; nothing is allowed without a yes.
- The `valetkey daemon` command, which runs the background process that owns your sessions and logins.
- Chrome no longer contacts `www.google.com` on its own, so a page that needs it shows as a refused host on any load.
- The browser tools now say when a page's background requests were refused, such as Chrome's own update requests, in a separate quiet line.
- The `valetkey status` and `valetkey watch` commands, which show the open browser sessions and login windows, and a desktop notification when a session starts.
- `valetkey doctor` warns when the installed agent-browser is newer than the version valetkey was tested with, and the README names that version.
- A `PKGBUILD` in `packaging/arch` that builds an Arch Linux package with the daemon's systemd units.
- `valetkey allow SITE --private-network RANGE` and `valetkey deny` let a site's allowed hosts resolve to addresses in a private range you list, for that site only; `valetkey sites` shows the ranges.
- The `valetkey add` command, which creates a site with its private address ranges before the first login, so a site on a private network can be logged in to.
- The `valetkey bridge` command and `valetkey install-units --bridge`, which connect a laptop to a daemon on a server so login windows can open on the laptop; `valetkey status` and `watch` show connected bridges.

### Changed

- `valetkey allow` and `valetkey deny` now apply to a running session at once, and `valetkey forget` closes a running session before it deletes.
- The proxy refuses a host when any address it resolves to is private or otherwise not public, not only when all are, because a mixed answer is how DNS rebinding looks.

- The login window now runs in a Wayland security context where the compositor offers one, so it cannot capture the screen, type for you or manage the clipboard.
- `valetkey doctor` warns when the Wayland compositor cannot restrict the login window.

### Fixed

- A page can no longer stall every site by asking for many host names while name lookups are slow. A lookup over 5 seconds counts as a host that does not resolve.
- A browser session no longer falls back to a browser outside the sandbox when the sandboxed browser driver stops; the call fails and the session ends instead.
- The install instructions name the ways valetkey ships, the Arch package and `uv tool install .` from a checkout, and commands, MCP tools and security have pages in `docs/`.
- `valetkey allow` and `valetkey deny` no longer forget a site's login pages.
