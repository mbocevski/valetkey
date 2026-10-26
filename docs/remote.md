# Logging in from another machine

When valetkeyd runs on a machine with no screen, `browser_login` has nowhere to open the login
window. Two optional ways get it in front of you: a bridge, which opens the window on your laptop's
desktop, and a noVNC display, which shows it in a browser tab. Back to the [README](../README.md).

## How the bridge works

You run `valetkey bridge SERVER` on the laptop, as a service. It starts waypipe there, and keeps an
ssh connection to the server that forwards a socket back to it. On the server, the connection runs
`valetkey bridge-hold`, which tells valetkeyd that a bridge is up. `valetkey status` lists it, and
`valetkey watch` reports when it comes and goes.

Nothing needs starting for each login. When the server has no screen of its own, a login opens on
the laptop through the newest connected bridge, once you turn that on (see below). The login is
as contained and recorded as a local one, and closing the window finishes it the same way.

## What you need

- A Wayland desktop on the laptop, with `waypipe` and `ssh`.
- `waypipe`, `setpriv` and `valetkey` on the server, and key-based ssh from the laptop to the
  server. The bridge cannot ask for a password.
- Your ssh agent, or a key without a passphrase, available to the service.

A hardware security key cannot be used this way, because the key is not forwarded.

## Start the bridge

On the laptop:

```fish
valetkey install-units --bridge
systemctl --user daemon-reload
systemctl --user enable --now valetkey-bridge@SERVER.service
```

Replace `SERVER` with the name you give ssh. The unit runs `valetkey bridge SERVER`, restarts it
if it fails, and stops it when you log out. Only one bridge runs per laptop. The bridge asks the
server for its runtime directory; pass `--remote-runtime` to name it instead.

A dropped connection is tried again after 1 second, then 2, 4 and so on up to a minute, each wait
shortened by a random amount. A connection that lasted a minute starts the waits again.

## Turn it on

Remote logins are off until the server's `config.json` says so. Edit
`$XDG_CONFIG_HOME/valetkey/config.json` on the server:

```json
{"remote_logins": {"waypipe": true}}
```

`browser_login` then chooses in this order. A screen on the server itself comes first. A connected
bridge comes next, if `waypipe` is on. A browser view comes last, if `novnc` is on. With none of
them, the login is refused and says why. The reply tells the agent where the window is.

## What it protects

- waypipe always runs with a security context, and there is no option to turn it off. Without one,
  a program on the server could capture everything on your screen. With one, your compositor lets
  it use only the interfaces it allows a sandboxed client, which do not include screen capture.
- A login window on the laptop gets no security context from the server, because the server has
  no compositor to ask. The one on the laptop applies instead, since everything waypipe forwards
  arrives through it.
- Each ssh connection is its own, with a socket named for that connection. ssh connection sharing
  would otherwise reuse an old forward and leave the new socket unbound.
- The socket sits in the server's private runtime directory. A process of your user on the server
  can open windows on the laptop, as it can already change a site's hosts, so keep an untrusted
  process away from that account.

## A second layer

If your compositor supports permission rules for each client, deny screen capture to
`/usr/bin/waypipe` as well, whatever else changes. Check your compositor's documentation for the
exact rule. It is a second layer behind the security context, not a replacement for it.

## Try it

On the server, `waypipe -s /run/user/1000/valetkey/bridge-NAME.sock server -- foot` opens a
terminal on the laptop. Use the name `valetkey status` shows and your own user number. From the
server, `grim` through the same socket is refused.

## The noVNC display

Off by default. Turn it on in `$XDG_CONFIG_HOME/valetkey/config.json`:

```json
{"remote_logins": {"novnc": true}}
```

It needs `sway` and `wayvnc` 0.9 or newer installed, and the viewer files that the package ships. From a source
checkout, run `just novnc` once to fetch them. Without them the login fails and says so, and
`valetkey doctor` shows `fail` on its `remote-login` line while the setting is on.

`browser_login` uses it only when no local display is available. For each login, valetkey starts
a private headless sway, in a directory only you can open, and a wayvnc that serves it. The only
program on that display is the login's Chromium, with its address bar visible. A small web server
on `127.0.0.1` serves the [noVNC](https://github.com/novnc/noVNC) viewer and passes the VNC traffic
on.

The tool result holds a link and an `ssh -L` line. On your own machine, run the `ssh` line first,
then open the link. The address is on the daemon's loopback, so the link only works through the
tunnel.

## What limits the link

- The link holds a random 192-bit token. A request with any other token gets a 404.
- Only one viewer at a time. A second one is refused while the first is connected.
- It stops accepting new connections ten minutes after the login starts.
- A page on another site cannot use it: a request whose `Origin` is not the viewer page gets a 403.
- The server answers only to a loopback host name.

## When it ends

Closing the login window ends everything: the web server, wayvnc, sway and the directory. So does
stopping the daemon. Nothing keeps listening afterwards.

## Licenses

The viewer is noVNC v1.7.0, under the Mozilla Public License 2.0, with its license texts. valetkey does not change
the files. They are not in the repository: `tools/fetch_novnc.py` downloads the release named in
`tools/novnc.lock` and checks its SHA-256 before unpacking, and the Arch package does the same
when it is built.
