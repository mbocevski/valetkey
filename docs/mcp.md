# MCP clients

How to connect an MCP client, what the agent can do, and how it asks for more. Back to the
[README](../README.md).

## Connect a client

Add `valetkey mcp` to the client as a stdio server. In clients that read a JSON config:

```json
{"mcpServers": {"valetkey": {"command": "valetkey", "args": ["mcp"]}}}
```

Clients with a command line can add it the same way, with `valetkey mcp` as the command. With
the systemd socket enabled, the daemon starts on the first connection. Without it, `valetkey mcp`
starts `valetkey daemon` itself, and that daemon keeps running so several clients can share it.

## The tools

Start with `browser_sites`. The others act on one site by its name.

- `browser_sites` lists your sites, their state, the first hosts each may reach, and
  what the last login learned. With `site` it lists that site's complete host lists.
- `browser_login` opens a login window on your screen and returns at once. It closes the site's
  running browser first. Pass `account` to add another account to a site (see
  [accounts](#accounts)). With no screen it uses a connected bridge if `remote_logins.waypipe` is
  on, so the window opens on your laptop.
  Otherwise, with `remote_logins.novnc` on, the window is shown in a web browser. The link goes to
  you, never to the agent: your client shows it, or you run `valetkey status` (see
  [remote logins](remote.md)).
- `browser_open` starts the signed-in browser for a site, or joins the running one, and says if
  the login expired.
- `browser_snapshot` reads the page as a text tree with its text and a reference such as `e3`
  for each element to act on. A long page is cut, and `interactive` lists only those elements.
  `images` adds the biggest pictures and videos. `selector` reads one part of the page (see
  [below](#reading-one-part-of-a-page)).
- `browser_click` clicks an element by reference, or by visible text and role (see
  [clicking by text](#clicking-by-text)). It looks the element up again at click time, and
  checks an `expect` of `text_appears`, `text_gone` or `url_changes`. Only a click with an `expect`
  is repeated, and only if the first changed nothing.
- `browser_type` replaces the contents of a field, and presses Enter when `submit` is true.
- `browser_navigate` goes to an address on an allowed host.
- `browser_save` saves a picture, a video or a linked file into the downloads folder (see
  [Downloads](#downloads)).
- `browser_downloads` lists saved files; clicks and navigation list new ones.
- `browser_screenshot` returns an image.
- `browser_console` [reads a page's errors](#what-went-wrong-in-a-page).
- `browser_allow` asks you to let the site reach more hosts.
- `browser_deny` asks you to stop the site reaching hosts it reaches now (see
  [denying a host](#denying-a-host)).
- `browser_microphone` asks you to turn on the site's [microphone](#the-microphone).
- `browser_close` ends the site's browser. The login stays saved.

There is no script evaluation, no launch option, no upload, no cookie access and no way to delete
a site. Page text is labelled as untrusted.

## Limiting a server to some sites

`valetkey mcp --site sitex` serves the same tools but acts only on `sitex`. Repeat `--site` for
more sites. A bare site covers all its accounts, including ones added later; `sitex:work` covers
that one account. Without `--site` a server acts on every site.

```json
{"mcpServers": {"sitex": {"command": "valetkey", "args": ["mcp", "--site", "sitex"]}}}
```

`browser_sites` lists only those sites. Every tool that names another site fails with an error
that names the allowed ones, for example `site "other" is outside this server's scope (allowed:
sitex)`. `browser_login` cannot make a site or an account outside the list, and
`browser_allow`, `browser_deny` and `browser_microphone` work only for listed sites. The list is
fixed when the server starts, and no tool can change it. [Security](security.md#limiting-a-client-to-some-sites)
says how it is enforced and what it does not stop.

## What a result starts with

Every result starts with the site's name and the page's address. The address line shows only the
scheme and host, which valetkey reads the way the browser does. The path and query, which the page
chose, come below it, fenced and labelled as untrusted, cut to 200 characters, with the full length
when they were cut. Percent-encoded text is shown as it is, never decoded. When a page loaded,
`browser_open` and `browser_navigate` then give only its title, labelled as the title, with a line
that says to call `browser_snapshot` to read the page. When none loaded (an expired login, a
refused start page, or an address that only started a download), the title, `URL: (none)` and an
empty list of refused hosts are left out. A snapshot leaves out unnamed layout nodes and text that
repeats its parent's name, and nests one space per level; every reference and all other text
stay. One of more than 40,000 characters is cut at the end of a line, with a note of how much was
left out.

When a page could not load because its host is refused, the first line says so and names the host
and the site, as in `The page did not load: example.org is not allowed for sitex.` The refused
hosts and the advice follow. `browser_open` says the same when the host of the site's own start
page is refused, and adds that no session is running.

## Idle sessions

A session that nothing uses for 15 minutes is closed, the same way `browser_close` does it. The
login, the profile and the downloads stay, so `browser_open` starts it again, logged in, in a few
seconds. These count as use: any tool call that names the site, a call that is still running, a
question waiting for you, and a download that is still being written. So does a recording through
the microphone, which keeps a meeting open without tool calls. The time counts from its end.

The next call on that site, other than `browser_open`, returns an ordinary result, not an error:
`The sitex session was closed after 15 minutes without use. Call browser_open to start it again.`
The agent should open the site and go on.

Set the time with `session_idle_minutes` in `$XDG_CONFIG_HOME/valetkey/config.json`, from 1 to
1440. Any other value stops the daemon at start-up with a message that names the file. There is no
way to turn the limit off. `valetkey status` shows how long each session has been idle and when it
will close. `valetkey watch` reports the close as `session_ended` with `"reason": "idle"`.

## What a click or typing step returns

The result of `browser_click` and `browser_type` ends by saying what the step changed on the page,
so the agent need not read it again. It says that the page did not change, or gives the lines that
were taken out and put in, fenced as untrusted page data. That can be a menu that opened or an
error that appeared. Only the lines that differ are given, however far apart the changes are and however large. When
they come to more than 4,000 characters, the lines with a reference come first and the result
counts the rest. If none has a reference, it says the page changed a lot. A step that took the
browser to another page returns that page's title and says to call `browser_snapshot`. A
reference that appears in the changed lines can be clicked at once.

It does not matter what the agent read before: a snapshot of the whole page, of one part of it, or
nothing. If it has not read the whole page, valetkey takes the baseline itself just before the
step and tells the agent nothing about it. After another client has taken a snapshot, the result
says only that the page changed. The line about no expectation is left out of a click's result
when a change is reported.

## Hints for the client

Each tool carries the standard MCP hints, so a client can decide what to ask you about.
`browser_sites`, `browser_downloads`, `browser_snapshot` and `browser_screenshot` only read; the
first two touch nothing but valetkey's own state. `browser_click` and `browser_type` are marked
destructive, because a click or Enter can submit, send or delete. `browser_open`,
`browser_navigate`, `browser_allow`, `browser_deny`, `browser_microphone` and `browser_close` are
idempotent.
`browser_save` writes a file, so it is not read-only; it never overwrites one, so it is not
destructive. Every tool that touches a page is marked open world. They are hints, not promises.

## Accounts

A site can have several accounts, each its own login named like `sitex:work`. While a site has one
account the agent can use its bare name. Once it has several, a bare name is refused with the
names to choose from, because acting as the wrong account is worse than one refused call. The
account that existed first is `sitex:main`. Every answer starts with the account that acted.

The agent adds an account with `browser_login` and its `account` argument, for example
`site_or_url` `sitex` with `account` `work`. The new account starts at the same page, with its own
list of hosts. You can start it with the hosts of another account using
`valetkey add sitex:work START --copy-hosts-from sitex`. Only you can do that.

## Clicking by text

`browser_click` with `text` clicks the element whose name equals the text, ignoring case and
runs of spaces. When none does, it takes the one element whose name holds the text as whole words,
such as `icon_user Orders icon_arrow` for `Orders`, and refuses when several do. That can click
`Archived orders` for `Orders` when the page has no `Orders`. With `exact` true only a name equal
to the text matches, case included, and there is no whole-word fallback. A text that matches no
element is `target_not_found`, with the near names. `exact` needs `text`, and `role` still narrows.

## What went wrong in a page

A page that stays on its spinner or stays blank often has a refused host to blame, and the tools
name those. When none is refused, `browser_console` shows the rest, from the browser's own buffers:

- the page's errors, which are uncaught exceptions and unhandled rejections, with the message,
  the stack and the line and column;
- the console's warnings and errors, with the level (plain logs are left out);
- the requests that failed: no response (they failed or are still going, with how long ago they
  began), or a status of 400 or more. A request to a host the proxy refused is marked. The request
  for a worker's script, from a Worker or SharedWorker the page starts, always shows with no
  response, even when the worker started, because the browser's log never records its answer. It
  is not a failure by itself.

Each section lists at most 50 entries, oldest first, cut to 500 characters each, and says how many
more there were. The requests are those since the agent's last click or `browser_console` with
`clear`, because a click starts the log again. With `clear` true the buffers are emptied after
reading, so the next call shows only what came after. Everything in the lists was written by the
page, so it is fenced and marked as untrusted data. The tool reads only the session's own buffers.

## Hovering before a click

Some pages show a row's actions only while the pointer is over the row, so the action is not in
a snapshot until something is hovered. `browser_click` takes `hover`, a list of one to five texts
(each an element's visible text or accessible name, at most 200 characters). It hovers the first
text that names exactly one element, takes a fresh snapshot, and then looks up the target
(`text` or `ref`) and clicks it, all in one call. A text is matched like the `text` of a click, and
`role` does not apply to it, and `exact` applies to it as it does to `text`. The pointer stays where the hover left it, and `expect` is checked
after the click as usual.

If no text names one element, the click fails with `hover_not_found`, naming the texts it tried and
the closest names, and nothing is clicked. If the target is not on the page after the hover, the
click fails with `target_not_found`, saying the hover worked and over which element. A reference
from before the hover is used only if it still names the same element. Without `hover` a click
works as before.

## Reading one part of a page

`browser_snapshot` takes a `selector`: a CSS selector of 1 to 500 characters, with no newline, that
does not start with a dash. The tree is then only the part of the page under the first element it
matches, and the result has a `Scope:` line after the URL lines. When the selector matches more than
one element, the line says "the first of N matches". A selector for the element that holds them all,
such as a list or a table, shows more. The references of that tree are
added to the ones the client already has for the page, so a reference from an earlier whole-page
snapshot still works. A whole-page snapshot, or one of another page, starts the table again. A
selector that matches nothing is a `browser_error`: "No element on the page matches the selector".
`interactive`, `images` and the cut for a long tree work as they do for the whole page.

## Reading a long page

A tree over 40,000 characters is cut at the end of a line. The result then says how many lines were
left out, and `start_line=K` with the first of them. Call `browser_snapshot` with that `start_line`
to read on: the tree is taken again, the lines before `start_line` are dropped, and the cut applies
to the rest. A part after the first says that the page may have changed since the last part. A
`start_line` past the end of the tree is a `bad_request`. The references of the whole tree are
usable, including those on lines that were not shown.

## Downloads

Files a site downloads are saved in its downloads folder, `$XDG_STATE_HOME/valetkey/downloads/SITE`.
A new file never replaces an older one of the same name; it gets a number, as in `report (2).pdf`.
valetkey reads the first bytes of a file to report its type and never opens or runs it.
When two downloads under one name run at the same time, such as two hidden frames from one page,
the browser keeps only one of the files. The result then says that downloads started and one
file was saved, lists the names and addresses, and notes that some share a name.

`browser_save` takes a reference from the latest snapshot, which saves a link's target or a media
element's source, or an address. The picture addresses are listed by `browser_snapshot` with
`images` set. The result gives the name, size and type, never the file to the model.
valetkey opens the address in a tab of its own that is closed afterwards, with the site's login
and through its proxy, and takes the body from the browser's record of the exchange. So the
site's own security policy for scripts cannot block it, only hosts the site allows work, and a
refused host is reported as it is for navigation. The file is named after the address, with the
extension its type calls for, and goes into the folder under the same rules and limits as any
download, up to 100 MiB. An address that is `data:` or `blob:` is the file itself, held in the
page, so `browser_save` says so and does not try it. The agent has no other way to get a file off
the page.

## Asking for a host

When a page needs a host the site does not allow, the browser tools list it as refused. The agent
may call `browser_allow` with up to ten exact host names and a reason. Only a host that was
refused, or that is in the site's excluded or denied list (left out at login, or denied by you),
can be asked about. Nothing is allowed unless you say yes.

There are two ways to answer. A client that can show a question to you is asked first, and puts it
there: one question that lists the hosts, each with a box you can tick or clear. A host you clear
counts as a no. How the client asks depends on the MCP protocol version it speaks. valetkey handles
both the older request in the middle of a call and the newer result that asks for input.

Otherwise set `approve_command` in `$XDG_CONFIG_HOME/valetkey/config.json` to a program and its
arguments:

```json
{"approve_command": ["/home/me/bin/ask-valetkey"]}
```

The daemon runs it with one line of JSON on standard input:
`{"site": ..., "permission": "host", "host": ..., "seen_during_login": ..., "reason": ...}`.
The `permission` says what is asked: `host` here, and `microphone` for the question in
[the microphone](#the-microphone), which has no `host`. Check it, because a command that ignores
it would read a microphone request as a host request with no host. Exit status 0 means yes. Other statuses are
[listed below](#exit-statuses-of-the-approval-command). What it
prints is never shown to the agent. The reason is the agent's claim, so show it as one. The command
runs without a shell and gets a small environment: `PATH`, `HOME`, `XDG_RUNTIME_DIR`, `LANG`, and the
display and session bus variables (`WAYLAND_DISPLAY`, `DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`), which
it can use to show you a question.

With neither, a desktop notification asks, on a desktop whose notification daemon offers buttons
and with `notify-send` installed. It names the site and host, quotes the agent's reason, and has
Allow and Deny buttons. Closing it, or not answering for 60 seconds, counts as unanswered, never as
a no. Switch it off with `{"notifications": false}` in the same file.

If nothing can ask, the agent tells you to run `valetkey allow SITE HOST`.

## Exit statuses of the approval command

For a host or the microphone, the approval command says how the question ended with its exit
status:

- 0: yes.
- 1, and any status not listed here: no. For a host that is final, and a death by signal is a no.
- 75: nobody answered. The question counts as unanswered, as when the command runs longer than 60
  seconds, and nothing is remembered.
- 69: it could not ask anyone, for lack of a display, say. A notification asks instead. If that
  cannot ask either, the agent tells you the command to run.

## What `browser_allow` returns

Each host gets a result of its own, one line per host when there are several.

- `allowed`: you said yes, or the host was already allowed. The next navigation to it will load.
- `denied`: you said no. The agent must not ask again for that host, and the daemon refuses to
  ask again while it runs.
- `expired`: nobody answered, the question was dismissed, or the approval command took longer than
  60 seconds. The agent may ask again.
- `could_not_ask`: nobody could be asked from here, because no approval command is set or the one
  that is set could not run. The agent tells you the exact `valetkey allow` command to run.
- `not_eligible`: the host cannot be asked about, either because it was not refused for this site
  or because its name is allowed but it resolves to a private address. The message says which.

## Denying a host

The agent may call `browser_deny` with up to ten exact host names and a reason, to take hosts away
from a site. Only a host the site may reach now, or one the login left out, can be asked about.
Denying `cdn.example.com` leaves `example.com` allowed if it was: the exact host and its subdomains
are blocked, and the broader entry stays.

You are asked the way `browser_allow` asks: a form in the client with a box for each host, then
your `approve_command`, then a notification, and else the agent hands you
`valetkey deny SITE HOST`. The question says the site will no longer reach the hosts, and that this
lasts through later logins. The approval command gets `"action": "deny"` in its request, and yes
denies. The notification has Deny and Keep buttons.

Hosts you confirm move to the site's denied list and stop loading, in a running session too. The
results are `denied`, `declined` (you said no: the agent must not ask again), `expired`,
`could_not_ask` and `not_eligible`. Only you can allow a denied host again, with `valetkey allow`.

## The microphone

A session has no microphone until you turn one on for its site with `valetkey mic SITE on`. The
agent can ask with `browser_microphone`, giving the site and a reason. You are asked the way
`browser_allow` asks: a form in the client with one box, then your `approve_command`, then a
notification. Only a yes turns it on. A site that has it on answers `allowed` without asking. `browser_sites` shows `microphone: on` for such a site, and nothing for the rest.

The approval command gets `{"site": ..., "permission": "microphone", "reason": ...}`, with no
`host` and no `seen_during_login`. Its exit statuses are those above. The notification has Allow
and Deny buttons.

The results are `allowed`, `denied` (you said no), `expired` (nobody answered, or the question was
dismissed) and `could_not_ask` (nobody could be asked from here, so the agent tells you to run
`valetkey mic SITE on`). A no is not remembered: the agent may ask again, and you can say no
again. The agent cannot name an audio source: the microphone copies your default source, or the one you
set with `valetkey mic SITE on --source NAME`. The browser may record on the start page's origin and the site's own domain with its subdomains, and on no other host the site reaches. The setting applies to sessions that start afterwards. A running session keeps what it
started with, so the agent closes the site's browser and opens it again.

What the browser can hear, and nothing else it can reach, is described in
[Security](security.md#the-microphone).

## A client that cannot show questions

MCP lets a client show you a question or a link; the feature is called elicitation. Some clients
do not declare it, and valetkey checks what the client declared instead of assuming.

- To ask for a host, the daemon runs your `approve_command` if you set one, or else shows a
  notification with Allow and Deny. If it can do neither, `browser_allow` returns `could_not_ask` with the exact `valetkey allow SITE HOST` command
  (SITE names the account, such as `sitex:work`), and the agent tells you to run it. Nothing is
  allowed until you do, or the command says yes.
- For a login in a web browser, the client cannot show you the link, and the link never goes to
  the agent. The result of `browser_login` tells the agent to ask you to run `valetkey status` on
  that machine, which prints the link and the `ssh -L` line. See [remote logins](remote.md).
- A login on your own screen or laptop needs neither.

## Private networks

A host that resolves to a private address is refused even when its name is allowed. This is true of
an intranet site. `browser_allow` cannot change it. The agent tells you to run
`valetkey allow SITE --private-network RANGE` with the narrowest range that holds the address, such
as `10.20.0.7/32` or a `/24`. [Security](security.md) explains the rule.

`browser_login` follows the same rule. When the site's start host resolves to a private address it
may not reach, the call fails and tells the agent to ask you. For a site that does not exist yet,
the command is `valetkey add SITE START --private-network RANGE`. A login that was refused hosts for
their private address says so in what it learned, so the agent can pass it on. So does one that was
refused a connection for its port, because a login window proxies only port 443, and port 80 for
plain HTTP.

## Expired logins

After a session opens, valetkey compares the page it landed on with the login it saved. A start
page that sent the browser to a page you used during the login and left by submitting a form, or
to a page with a password field, means the login expired. A page that sent itself on at once does
not count. `browser_open` then says so, and the agent calls
`browser_login` again without asking first.

A site that shows its front page logged out, without a redirect, is caught another way. When you
log in, valetkey records the names of the sign-in cookies the site set, never their values. When
the site is opened, before the browser starts, it reads the profile again. If none of those
cookies is left, the login has expired and no browser is started. It says nothing when it is
unsure: when one is still there, or the profile cannot be read.

A login usually comes while the site's browser is still running. `browser_login` closes that
browser first, as `browser_close` does, and says so in its result, but only when a window can
open. With no screen, no connected bridge and no browser view, it fails with `no_display` and
leaves the browser running. A login window that is already open for the site is an error.
