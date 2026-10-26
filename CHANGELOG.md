# Changelog

Changes that affect users of valetkey. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- With no client prompt and no approval command, `browser_allow` asks with a desktop notification that has Allow and Deny buttons; `"notifications": false` in the config turns it off.
- A login allows the site owner's other domains, such as its CDN, and sorts the hosts it left out; a host you deny with `valetkey deny` stays denied through later logins.
- The `browser_save` tool, which saves a picture, a video or a linked file from the page into the site's downloads folder, through the site's own proxy; `browser_snapshot` can list the pictures with their addresses.
- A site can have more than one account, such as `sitex:work`, each with its own login, hosts and downloads; `browser_login` takes an `account`, and a bare site name is refused then.
- The browser's sandbox refuses 30 system calls a browser has no use for, such as `keyctl`, `bpf` and `mount`, on x86_64; `valetkey doctor` says when it cannot.
- `browser_login` on a machine with no screen can start a private display and return a link to a noVNC page, with the `ssh -L` command to reach it, when `remote_logins` is on in the config.
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
- With `remote_logins.waypipe` on in `config.json`, `browser_login` opens the login window on your laptop through a connected bridge when the server has no screen of its own.

### Changed

- `browser_allow` takes up to ten hosts in one call and asks about them in one question, with a box for each.
- The browser tools now say, with the standard MCP hints, which ones only read, which can change a page and which reach the web, so a client can ask you only when it matters.
- A login allows another site only if it showed you a page for two seconds. A host it only passed through by redirect is left out. The summary names both, with `valetkey deny` and `valetkey allow`.
- The link to a login shown in a web browser is no longer given to the agent. Your client shows it, or `valetkey status` does; it works once, and the page then sets a cookie that the WebSocket needs.
- Tool results show a page's address as its scheme and host, and put the path and query below it, cut to 200 characters and fenced as untrusted page data.
- `valetkey allow` and `valetkey deny` now apply to a running session at once, and `valetkey forget` closes a running session before it deletes.
- The proxy refuses a host when any address it resolves to is private or otherwise not public, not only when all are, because a mixed answer is how DNS rebinding looks.

- The login window now runs in a Wayland security context where the compositor offers one, so it cannot capture the screen, type for you or manage the clipboard.
- `valetkey doctor` warns when the Wayland compositor cannot restrict the login window.

### Fixed

- A site that signs you in only until the browser is closed, with a cookie that has no expiry, now stays signed in for the session. Sign in again once if a login did not carry over.
- `browser_allow` and the login link reach a client on the newer MCP protocol instead of ending in `could_not_ask` or sending you to `valetkey status`.
- Starting valetkey from an MCP client that gives it a reduced environment now works: it uses `/run/user/UID` when `XDG_RUNTIME_DIR` is missing, and the daemon it starts finds your desktop.
- The login window no longer shows Chromium's "unsupported command-line flag" bar. valetkey no longer passes it the flag that hides automation, which only the headless browsers need.
- An expired login is now noticed when its sign-in form posts to a redirect, as most single sign-on providers do. A callback is no longer taken for a sign-in page.
- `valetkey install-units` names the Arch package and `uv tool install .` when `valetkey` is not on your `PATH`, instead of a package that is not published.
- `valetkey bridge` never forwards your ssh agent or X11 to the server, whatever your ssh configuration says.
- A login no longer allows hosts that the browser profile visited before it began, so a host removed with `valetkey deny` does not come back at the next login.
- The daemon's service and each browser sandbox now have limits on open files, tasks and memory, so a runaway browser cannot take down your session.
- The bridge that carries the browser's connections to the proxy relays 128 at a time and closes the rest.
- A flood of connections to a site's proxy can no longer use up the daemon's file descriptors; the proxy serves 128 at a time and closes the rest.
- A login shown in a web browser no longer locks you out when your laptop sleeps. A new viewer replaces the old one, and a silent one is dropped after 90 seconds. At most 8 connections are served at once.
- Error messages from the browser, and the tails of logs shown in an error, are fenced and labelled as untrusted text, because they can repeat what a page chose.
- A login's browser history that a web page has tampered with can no longer hang the daemon, fill memory or put text of its own into what the agent reads.
- The browser can now write only into its two hidden folders in a site's downloads folder, not into the folder where finished downloads are kept.
- `config.json` is ignored, and `valetkey doctor` fails, when it belongs to another user or others can write to it, because it names a program the daemon runs.
- A browser can no longer remove or replace the proxy's socket, and closing a proxy whose socket was swapped no longer fails.
- The proxy forwards only the body a plain HTTP request announces, so a pipelined second request no longer reaches the first one's server. It refuses a request with an unclear length.
- The proxy refuses site-local IPv6 addresses (`fec0::/10`) and the 6to4 relay range, which it let through before.
- A page can no longer stall every site by asking for many host names while name lookups are slow. A lookup over 5 seconds counts as a host that does not resolve.
- A browser session no longer falls back to a browser outside the sandbox when the sandboxed browser driver stops; the call fails and the session ends instead.
- The install instructions name the ways valetkey ships, the Arch package and `uv tool install .` from a checkout, and commands, MCP tools and security have pages in `docs/`.
- `valetkey allow` and `valetkey deny` no longer forget a site's login pages.
