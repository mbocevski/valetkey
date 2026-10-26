# Logging in from another machine

When valetkeyd runs on a server with no screen, login windows can open on your laptop instead.
This is optional and off until you start a bridge. Back to the [README](../README.md).

## How it works

You run `valetkey bridge SERVER` on the laptop, as a service. It starts waypipe there, and keeps an
ssh connection to the server that forwards a socket back to it. On the server, the connection runs
`valetkey bridge-hold`, which tells valetkeyd that a bridge is up. `valetkey status` lists it, and
`valetkey watch` reports when it comes and goes.

Nothing needs starting for each login. A later change makes `browser_login` use a connected bridge;
for now the bridge only connects and registers.

## What you need

- A Wayland desktop on the laptop, with `waypipe` and `ssh`.
- `waypipe` and `valetkey` on the server, and key-based ssh from the laptop to the server. The
  bridge cannot ask for a password.
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

## What it protects

- waypipe always runs with a security context, and there is no option to turn it off. Without one,
  a program on the server could capture everything on your screen. With one, your compositor lets
  it use only the interfaces it allows a sandboxed client, which do not include screen capture.
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
