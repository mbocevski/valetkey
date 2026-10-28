# Changelog

Changes that affect users of valetkey. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `browser_sites` shows `microphone: on` for a site that has the microphone on, so an agent can tell whether `browser_microphone` needs to ask.
- `valetkey mic` turns on the microphone for a site, and `browser_microphone` lets an agent ask you to. A session then hears only the microphone, through a private audio graph, and `status`, `watch` and `sites` show it.
- `browser_snapshot` with a `selector` says how many elements the selector matches when it matches more than one, and that only the first is shown.
- `browser_click` and `browser_type` say what changed on the page, as lines taken out and put in, so an agent need not take a new snapshot after every step.
- `browser_snapshot` takes a `start_line`, so an agent can read on past the 40,000-character cut, and says which line to start from.
- `browser_snapshot` takes a `selector`, a CSS selector, to read only one part of the page, such as a form or a table, with refs you can act on.
- A browser session that nothing uses for 15 minutes is closed, keeping the login; `session_idle_minutes` in the config file sets the time (1 to 1440), and `valetkey status` shows when each session will close.
- `browser_open` notices a login that has expired without a redirect, by the sign-in cookies it recorded at login, before the browser starts.
- `valetkey sites SITE` prints one site's complete allowed, excluded and denied hosts, as text or with `--json`.
- The `browser_deny` tool, which asks you to stop a site reaching hosts it reaches now, and `browser_sites` takes a `site` to list its complete host lists.
- With no client prompt and no approval command, `browser_allow` asks with a desktop notification that has Allow and Deny buttons; `"notifications": false` in the config turns it off.
- A login allows every host it used, such as a sign-in provider and its CDN, except ads and tracking, which it counts; a host you deny with `valetkey deny` stays denied through later logins.
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

- `browser_click` by text now clicks the one element whose name holds the text as whole words, such as `icon_user Orders icon_arrow` for `Orders`. An exact name still wins, and an ambiguous text is refused.
- The browser starts with Chromium's page tools (WebMCP) turned off, so pages see no `ModelContext`; `valetkey doctor` fails an agent-browser that does not accept the option.
- `browser_snapshot` is 15 to 40% shorter: it leaves out unnamed layout nodes and text that repeats its parent's name, and nests one space per level, keeping every reference and all other text.
- A `browser_click` whose `expect` does not come true now takes one snapshot per check, with growing pauses, and at most 15 checks, so it starts far fewer browser programs in the same time.
- The public suffix list (`publicsuffix-list`, or `publicsuffix` on Debian and Ubuntu) is now required; `valetkey doctor` checks it, and `valetkey allow` and `valetkey add` refuse a public suffix.
- `browser_open` and `browser_navigate` label the page title as the title and tell the agent to call `browser_snapshot` to read the page.
- A login leaves out the ad and tracking hosts of Peter Lowe's list, kept in the package, and more of those a page loads; after an upgrade, restart your MCP client.
- A policy file without a `denied` list keeps its excluded hosts as left out, and the next login builds that list again.
- `browser_allow` takes up to ten hosts in one call and asks about them in one question, with a box for each.
- The browser tools now say, with the standard MCP hints, which ones only read, which can change a page and which reach the web, so a client can ask you only when it matters.
- The link to a login shown in a web browser is no longer given to the agent. Your client shows it, or `valetkey status` does; it works once, and the page then sets a cookie that the WebSocket needs.
- Tool results show a page's address as its scheme and host, and put the path and query below it, cut to 200 characters and fenced as untrusted page data.
- `valetkey allow` and `valetkey deny` now apply to a running session at once, and `valetkey forget` closes a running session before it deletes.
- The proxy refuses a host when any address it resolves to is private or otherwise not public, not only when all are, because a mixed answer is how DNS rebinding looks.

- The login window now runs in a Wayland security context where the compositor offers one, so it cannot capture the screen, type for you or manage the clipboard.
- `valetkey doctor` warns when the Wayland compositor cannot restrict the login window.

### Fixed

- `valetkey doctor` no longer warns that agent-browser 0.40.0 is newer than the version valetkey was tested with; valetkey is now tested with 0.40.0.
- A click that opens a very large menu now lists it, as lines with their references, and not as a new page; this holds with or without an expectation.
- A click that opens a menu on a long page lists the menu even when something far from it changes too. It counts any lines it leaves out, and no longer says the page changed a lot.
- The browser no longer asks the proxy for `update.googleapis.com` at the start of every session, so it is not listed among the refused background requests.
- A click or typing step says what changed on the page even after a snapshot of only one part, or none. The line about no expectation is left out when it does.
- `browser_screenshot` reads the picture only if it is a plain file of at most 20 MB, so a browser that swapped it for a link to another file cannot make the server return that file.
- A login at `myapp.github.io` or under `co.il` no longer allows the whole suffix or shares a profile with other sites under it; logins are refused without the public suffix list.
- `browser_open` and `browser_navigate` leave out the title block, `URL: (none)` and an empty refused list when no page loaded: an expired login, a refused start page or a URL that only started a download.
- `valetkey bridge` now stays connected through a real `ssh`: it gave ssh `/dev/null` as input, which ended the remote side at once, so the server never kept the bridge.
- `browser_snapshot` now includes the page's text, such as paragraphs, lists and tables, cuts a very long page with a note saying so, and takes `interactive` for the short list of elements to act on.
- `browser_login` no longer closes a running session when there is no screen to open the login on, and when a login window fails after the session was closed, the error says so.
- The check for a lost login no longer reports a login that is still there: it follows a cookie's last update, keeps the longest-lived cookies, and a new login replaces the old record.
- When downloads start but no file is saved, the result now lists each one's name and address, says if the page started them without a click, and explains names that repeat.
- Starting a browser on a heavily loaded machine no longer fails with "Failed to read: Resource temporarily unavailable". agent-browser stops waiting for a slow launch after 30 seconds, so valetkey launches once more.
- `browser_navigate` lists as refused only the hosts its own page asked for, not the beacons the previous page fired as it unloaded.
- `browser_navigate` and `browser_open` now begin with "The page did not load: HOST is not allowed for SITE" when the proxy refused the target's host, instead of the browser's tunnel error.
- `browser_login` closes the site's running session before it opens the login window, and says so, instead of failing with `session_running` and asking the agent to close it first.
- A page whose pictures, scripts or style sheets come with a download header no longer makes valetkey report downloads that started but saved nothing.
- An AVIF or HEIC picture is no longer listed as `video/mp4` in a download's type.
- A login no longer allows `passwordsleakcheck-pa.googleapis.com`, `c.bing.com` or `myvisitors.se`, and leaves out Facebook's hosts unless its window went to a Facebook page.
- A login no longer allows the browser's own update host, `edgedl.me.gvt1.com`, and the browser no longer checks for component updates, which `--disable-component-update` did not stop.
- `browser_save` now saves pictures that a site's server keeps scripts from reading, as picture services do, and ones behind a redirect. A `data:` or `blob:` address gets a clear reason.
- A site that signs you in only until the browser is closed, with a cookie that has no expiry, now stays signed in for the session. Sign in again once if a login did not carry over.
- The Arch package's version now includes the commit, so `makepkg -si` after a `git pull` builds the new code and no longer installs the package of an older commit.
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
