# Security

What valetkey contains, what it does not, and who decides. Back to the [README](../README.md).

## What a session can reach

Each site's browser runs in its own Linux network namespace, which has only a loopback interface.
The browser's connections go to a small forwarder on that loopback, and the forwarder hands them to
one local socket: a proxy that valetkey runs for that site. The proxy checks every connection in
turn:

- The port must be 443 for an encrypted connection or 80 for plain HTTP.
- The host must be one the site's policy allows, or a subdomain of one, and must not be in its
  excluded or denied list. Either wins over an allowed entry.
- The proxy looks the host up itself and connects only to a public address. Every address the name
  resolves to must pass, so DNS rebinding cannot steer the browser at a service on your machine or
  your network.

Anything else is refused and recorded. The record holds the host, the port and a short reason, and
never a path, a query or a header, because on a logged-in site those carry credentials. The browser
cannot look up names itself or send WebRTC traffic, because the namespace has no route out. It names
the host to the proxy, which does the lookup.

The browser's files are limited too. System directories are read-only, the home directory is an
empty throwaway one, and the environment is cleared. The only places it can write that last are the
site's profile, its downloads folder, and the directories that hold the proxy's socket and the
browser driver's socket. Its temporary directory, home and runtime directory exist only in memory.
The SSH and GPG agents, the Docker socket, the session bus and the rest of your home are not there.

## Who decides

A host is added to a site's policy only when a person says yes. Three things can change a policy:

- Logging in. The site's own domain is allowed, with its subdomains. The public suffix list from
  your distribution decides what the domain is: a login at `myapp.github.io` allows that host, never
  all of `github.io`. Without the list, logins are refused. So is every other host the
  login used, such as a sign-in provider and its CDN, unless it looks like ads or tracking (see
  [what a login allows](#what-a-login-allows)). Only this login counts: pages the profile visited at
  an earlier login or session are not read again.
- You, with `valetkey allow` and `valetkey deny`. The login's summary names the hosts it allowed,
  so you can deny any you do not want. The proxy cannot tell a provider from a page made to look
  like one, so check the names.
- The agent's `browser_allow` and `browser_deny`, which only ask; the second only narrows. You
  answer in the client's own interface, in a notification, or through the approval command, and no
  tool takes "the person said yes" from the agent. See [MCP clients](mcp.md).

The microphone is a setting of the site that only you turn on, with `valetkey mic`, or by saying
yes to `browser_microphone` in the same ways.

Only a host that was refused for the site, or that is in its excluded or denied list, can be asked
about. The excluded list holds the hosts the last login left out, and the denied list the ones you
denied. A steered agent cannot fill your screen with questions about arbitrary hosts.

## What a login allows

Signing in goes through more than the site: a provider, its CDN, a token exchange. A session that
lost one of those hosts would lose its sign-in. So a login allows every host its proxy recorded
and every host the browser navigated to, each as itself. The exceptions are hosts that look like
ads or tracking, which it leaves out and counts. The Facebook hosts are left out too, unless the
login window went to a Facebook page. That keeps signing in with Facebook working.

That costs some trust. The proxy sees only host names, because HTTPS is opaque to it, so it cannot
tell a provider from a page that a site or an ad sent the login through. The summary names every
host in two groups, the site's own domains and the other services the pages used. Check the names,
and run `valetkey deny` for any you do not want.

A site's policy keeps two lists of blocked hosts. `excluded` is what the last login left out, and
the next login builds it again. `denied` is what you turned down with `valetkey deny`. A login
never changes it and never allows a host it blocks; `valetkey allow` lifts it. A policy written
before `denied` existed has none, and its excluded hosts are built again by the next login.

The sorting of ads and tracking reads the host name only. It uses Peter Lowe's list of ad and
tracking server domains (pgl.yoyo.org/adservers), kept in the package as the site serves it. It
adds a short list of more services, and names such as `ads` or `analytics`. A test keeps sign-in
providers, CDNs and payment services out of it. A tracker it misses is allowed, so check the
summary. The browser's own hosts are never allowed. It is told not to update its components and
not to check typed passwords against leaked ones. A host it still asks for on its own is left
out of every login.

## Private networks

A name that resolves to a private address is refused by default, even when the name is allowed.
This stops a page from reaching routers, other machines on your network and services on your own
machine.

Some addresses are refused whatever is listed: loopback, link-local, multicast, unspecified and
reserved addresses, and the cloud metadata services at `169.254.169.254`, `fd00:ec2::254` and
`100.100.100.200`. A page that reached one could read the credentials of the machine it runs on.

Only you can let a site reach a private range, with `valetkey allow SITE --private-network RANGE`.
The range must lie inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or
`fc00::/7`, and be no wider than a `/8` (a `/48` for IPv6). Use the narrowest range that holds the
address. The permission is for that site only, and the agent cannot grant it. For a site you have
not logged in to yet, run `valetkey add SITE START --private-network RANGE` first; a login keeps
the ranges, and an agent that asks to log in to an unknown private host is told to ask you.

## Trust boundary

valetkey defends against page content steering the browser tools. It does not defend against your
own user account.

The daemon cannot see the MCP client's interface, so for an answer given there it takes the word of
the `valetkey mcp` process that you accepted. That is the same trust the daemon gives every process
of your user: it checks the user ID of whoever connects to its socket, and nothing more. The agent
has no way to reach that operation, because the only tool that uses it does so after the client's
interface returned your answer.

A process of your user can edit the policy files with `valetkey allow` anyway. If the agent has a
shell on your account, it can do that too. Give the agent browser tools without a shell if that
matters to you.

## What containment does not cover

- Pages the browser already cached still render. A host that is no longer allowed does not have to
  be reached for a cached page to appear.
- Whatever an allowed host serves is readable by the agent, and whatever the agent types goes to
  that host. Allow only hosts you would trust with the session.
- Uploads are absent. No tool uploads a file, and the browser can see only its own profile and the
  site's downloads folder, not the rest of your files.
- While a login window is open, it can reach any public host on ports 80 and 443. That is how
  valetkey learns which hosts the site needs. The address checks still apply, so private
  addresses stay refused unless you listed their range for the site.
- A login window needs a Wayland session. An X11 client can read every keystroke and the whole
  screen, so valetkey refuses to open a login window on X11.
- Chrome can still make requests of its own. They are refused and listed on a separate line of
  the tool results. valetkey tells it not to check for updates, or typed passwords against leaked
  ones. Allow one only if a page needs it.

## The login window

The window you sign in with is an ordinary Chromium on your Wayland desktop, in the same kind of
sandbox as the agent's browsers. valetkey asks your compositor for a restricted socket for each
login and gives the window that one instead of the compositor's own. Through it the window cannot:

- capture the screen or other windows,
- type or click for you with a virtual keyboard or pointer,
- read or change the clipboard behind your back with a clipboard manager,
- list your other windows, lock the session or change your displays.

It still shows pages, takes your typing and does ordinary copy and paste, including from a
password manager. The compositor lists the window as a sandboxed client of `valetkey`, with the
site as its instance name. The socket is removed when the window closes.

Not every compositor can do this. When yours cannot, the login still opens on the compositor's own
socket, the daemon logs a warning, and `valetkey doctor` shows `warn` on the security-context line:
the window is then not restricted.

## The login window on your laptop

Off unless `remote_logins.waypipe` is true and a bridge is connected. The window still runs in
the same sandbox on the server. The daemon does not ask for a restricted socket for it, because
the server has no compositor to ask.

The restriction that applies is the one on your laptop. The bridge's `waypipe client` always runs
with `--secctx`, so your compositor treats everything the server draws as a sandboxed client and
refuses it screen capture, virtual input and clipboard managers. See the
[remote logins page](remote.md).

## The remote login display

Off unless `remote_logins.novnc` is true. The login window then runs on a private headless
display instead of yours, and a web server on `127.0.0.1` shows it. The link carries a random
token and works once: the first page load sets an `HttpOnly`, `SameSite=Strict` cookie that the
WebSocket needs. It takes one viewer at a time, and a new one replaces the old. It drops a viewer
that has been silent for 90 seconds, allows 8 connections, and refuses a foreign `Origin`. It
stops accepting connections after ten minutes, and it is gone when the window closes. Anyone who
opens the link first and can reach the loopback port, through your `ssh -L`, can type into the
login window, so treat it like the password. It is never given to the agent: the client shows it to you, or
`valetkey status` does. The [remote logins page](remote.md) has the details.

## Page content is untrusted

A page can contain text written to look like instructions. Everything that came from a page, such
as titles, the page's text tree and the path and query of its address, is fenced and labelled as
data. The address shows only its host as fact; the rest is cut to 200 characters. The agent is told never to
follow instructions found there and to tell you when a host is refused instead of working around it.
The browser's own error messages and the tails of its logs are fenced and labelled the same way,
because they can repeat what a page chose. The summary of a login holds only valetkey's words and
host names, never text from the login's history.

Chromium's experimental page tools (WebMCP), which let a page register actions for an agent, are
turned off in every session. Nothing in valetkey passes them on, so they would only add an API that
stock Chrome lacks, and a page can lie about what a tool does. A page then sees no `ModelContext`.

A login window can also tamper with the files it writes. valetkey reads its history and its
cookie database from a copy, read-only, with a size cap and a time limit, and refuses a file that
holds anything but plain tables. Of the cookies it keeps only a host and a name, never a value.

## The microphone

A session has no audio at all, not even a silent one, until you turn the microphone on for its
site. Page text is untrusted, so an agent can only ask, and a no changes nothing.

With it on, valetkey does not give the browser your audio server. That would let it record what
you play, list your devices and applications, change your defaults and load modules, one of
which opens a listening port on the host. Each session gets an audio graph of its own, started
for it and ended with it. The graph has two nodes: a microphone that pulls from your default
source, and a silent output for the call. Only that graph's socket is in the browser's sandbox.
Anything that has taken over the browser sees those two nodes. It cannot list yours, record
your sound, change a default or load a module, and nothing in your own audio configuration
changes. Chrome may record without a prompt, because nobody sees one, but only on the start page's origin and the site's own domain with its subdomains. A sign-in provider or CDN the site may reach cannot.

The graph runs in a jail of its own: no network, no devices, a read-only system, its own
directory, your audio socket, and the same syscall filter as the browser. When the browser is
killed, the daemon ends the session within a second or two, and the graph with it. The jail shares
the host's process namespace, because the audio server cannot tell its clients apart in one of its own. A
compromised audio server could therefore signal your other processes, and it has the full reach of
your audio socket. The browser has neither.

A recorder on your machine can find the capture stream of a session in `valetkey status --json`
(see [commands](commands.md#seeing-what-runs)), and listens to what the call plays through the
silent output. The setting shows in `status`, `watch`, `sites` and the start notification.

## Sessions that nobody uses

A session closes by itself after 15 minutes without use, so an agent that forgets to close one, or
a client that crashes, does not leave a logged-in browser running for good. The limit is
`session_idle_minutes` in `config.json`, at most 1440 (a day), and it cannot be switched off. The
site's own login expiry still applies, and the saved login stays on disk for the next open.

## Seeing what runs

`valetkey status` and `valetkey watch` show every open session and login window, taken from the
processes the daemon owns. Nothing hides a session from them, and a browser that was killed
disappears within a second or two.
