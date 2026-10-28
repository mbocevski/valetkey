# Install

This page goes beyond the three commands in the [README](../README.md): what each install route
puts where, how to check the result, and how to remove it.

## Build the package

On Arch Linux and CachyOS, `packaging/arch/PKGBUILD` builds a package from the checkout:

```sh
cd packaging/arch
makepkg -si
```

The package version is `0.1.0.r` and the number of commits, then `.g` and the commit, such as
`0.1.0.r95.gabc1234`. So after a `git pull`, run `makepkg -si` again: the new commit is a new
version, and it builds the new code. Uncommitted changes add `.d` and a hash of them. If you want
to rebuild the same version, add `-f`.

The package installs valetkey with the exact dependencies in `uv.lock` into `/usr/lib/valetkey`,
so it does not depend on the Python packages your system has. `/usr/bin/valetkey` points into
that environment. The build downloads those dependencies and checks their hashes; it needs the
network.

It also installs the systemd user units to `/usr/lib/systemd/user`, so you only enable the
socket. `agent-browser` is not in the official repositories. The CachyOS repositories have it, and
the AUR package `agent-browser-bin` provides it.

## Install from a checkout

```sh
uv tool install .
valetkey install-units
systemctl --user daemon-reload
systemctl --user enable --now valetkeyd.socket
```

`uv tool install .` builds valetkey and its dependencies into a private environment of its own.
Install bubblewrap, Chromium and agent-browser with your system's package manager, or from the
agent-browser releases. Install the public suffix list too: `publicsuffix-list` on Arch and
Fedora, `publicsuffix` on Debian and Ubuntu. The Arch package depends on it.

The microphone (`valetkey mic`) also needs PipeWire with its PulseAudio server, WirePlumber and
`pactl`, which are `pipewire`, `pipewire-pulse`, `wireplumber` and `libpulse` on Arch. The Arch
package lists them as optional. `valetkey doctor` checks them once a site has the microphone on.

## The systemd units

`valetkey install-units` writes `valetkeyd.socket` and `valetkeyd.service` to
`$XDG_CONFIG_HOME/systemd/user`, which is `~/.config/systemd/user` by default. It fills in the
path of the `valetkey` program and prints the two `systemctl` commands without running them.
`--dry-run` prints the files and writes nothing. A file that valetkey did not write is never
replaced unless you pass `--force`. With `--bridge` it writes the unit that runs the bridge on a
laptop instead (see [Remote logins](remote.md)).

The socket starts the daemon when a client first connects, so nothing runs until a session is
wanted. The service runs with a restricted view of the system: it can write only valetkey's own
directories. A copy in `~/.config/systemd/user` takes precedence over the packaged units.

You do not need the units. Without them, `valetkey mcp` starts `valetkey daemon` itself when no
daemon is running, and that daemon keeps running so several clients can share it.

## Where valetkey keeps things

- Each site's allowed hosts: `$XDG_CONFIG_HOME/valetkey/sites/SITE.json`. Another account of a
  site has its own files, named with a dot (`sitex.work.json`).
- The optional settings: `$XDG_CONFIG_HOME/valetkey/config.json`. It holds the approval command,
  the notification switch, the remote login switches and `session_idle_minutes`.
- Each site's browser profile, which holds the login, and its downloads:
  `$XDG_STATE_HOME/valetkey/`.
- Sockets and logs of the running daemon: `$XDG_RUNTIME_DIR/valetkey/`.

`valetkey forget SITE` deletes a site's policy, profile and downloads. For one account of a site,
name it: `valetkey forget sitex:work`.

## Check the setup

`valetkey doctor` prints one line per check. It fails when bubblewrap, user namespaces, Chromium,
agent-browser, the public suffix list or the runtime directory are not usable. It also fails when
someone else can write `config.json`, and when the browser view is switched on without the tools
it needs. A missing Wayland display is a warning, because only logging in needs one, and so are a
compositor that cannot restrict the login window and a sandbox that cannot refuse system calls. So
is a saved site that lists a public suffix, which valetkey ignores: log in again to relearn its
hosts. See [Troubleshooting](troubleshooting.md) when a check fails.

## Upgrade and remove

After an upgrade, restart the daemon so that it runs the new version:

```sh
systemctl --user try-restart valetkeyd.service
```

Then restart your MCP client too, whatever it is: a terminal agent or a desktop app. The client
keeps its own `valetkey mcp` process running, and that process is still the old version until the
client starts it again.

To remove valetkey, run `valetkey forget` for each site, disable the socket with
`systemctl --user disable --now valetkeyd.socket`, delete the unit files if you wrote them, and
remove the package or run `uv tool uninstall valetkey`.
