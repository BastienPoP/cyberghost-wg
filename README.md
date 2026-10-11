# cyberghost-wg

[![tests](https://github.com/BastienPoP/cyberghost-wg/actions/workflows/tests.yml/badge.svg)](https://github.com/BastienPoP/cyberghost-wg/actions/workflows/tests.yml)

**WireGuard configurations for CyberGhost VPN, without the official client.**

CyberGhost only hands out WireGuard configurations through its own apps. Its
Linux client is an x86-64 binary that needs root and brings the tunnel up itself,
and [gluetun](https://github.com/qdm12/gluetun)'s built-in CyberGhost provider
only speaks OpenVPN. `cyberghost-wg` is a single Python script that makes the
same API calls as the official client and writes a standard `wg-quick`
configuration instead, which you can feed to gluetun (custom provider),
`wg-quick`, or anything else that speaks WireGuard. It runs
unprivileged, on any architecture, with nothing but Python.

> [!WARNING]
> **Unofficial.** This project is not affiliated with, endorsed by or supported
> by CyberGhost. It talks to the same private, undocumented API as the official
> Linux client (1.5.0), which can change or break at any time. You need an
> active CyberGhost subscription, and you are responsible for respecting its
> terms of service.

---

## Requirements

| You need | Check |
|---|---|
| Python 3.8 or later (standard library only) | `python3 --version` |
| An active CyberGhost subscription | – |
| Optional: `systemd-creds` from systemd 256 or later (250 as root), only to remember the credentials encrypted | `systemd-creds --version` |

Tested on Linux (Debian 13, arm64) with Python 3.8 and 3.13, with gluetun and
wg-quick; the test suite runs on Python 3.8 to 3.14. Nothing
in it is Linux-specific except remembering the credentials, but macOS, the BSDs
and Windows are untested: reports are welcome.

## Install

```bash
mkdir -p ~/.local/bin && cd ~/.local/bin
curl -fsSLO https://github.com/BastienPoP/cyberghost-wg/releases/download/v0.1.0/cyberghost-wg
curl -fsSLO https://github.com/BastienPoP/cyberghost-wg/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS && rm SHA256SUMS && chmod +x cyberghost-wg
cyberghost-wg --version
```

`sha256sum -c` must say `cyberghost-wg: OK`. Newer versions are listed on the
[releases page](https://github.com/BastienPoP/cyberghost-wg/releases).

If `cyberghost-wg` is not found, `~/.local/bin` is not in your `PATH`: add
`export PATH="$HOME/.local/bin:$PATH"` to `~/.profile`, or call it by its full
path. It is a single file: read it before running it.

## Quick start

```bash
cyberghost-wg login                                # once: account, device name, remember? (Enter)
cyberghost-wg conf -i                              # menus: type, country, city, server
```

Or, without menus, which is what scripts and services use:

```bash
cyberghost-wg countries --type torrent             # optional: where torrent servers exist
cyberghost-wg servers --country CH --type torrent  # optional: those servers, least loaded first
cyberghost-wg conf --country CH --type torrent -o wg0.conf
```

For a streaming service, give the service instead of the country:

```bash
cyberghost-wg services --country GB                # optional: the services with servers in GB
cyberghost-wg conf --service "BBC iPlayer" -o wg0.conf
```

`wg0.conf` is ready to use:

```ini
# CyberGhost zurich-s404-i06 (torrent, load 27%), generated 2026-10-11 14:59:25 +0200
[Interface]
PrivateKey = <generated locally, never sent anywhere>
Address = 10.6.140.57/32
DNS = 10.0.0.243, 10.0.0.242

[Peer]
PublicKey = <server key>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 84.17.52.97:1337
```

The `DNS` servers are the ones the server gives, so they vary.

> [!IMPORTANT]
> **Bring the tunnel up right away.** CyberGhost drops a registered key if it
> does not see a handshake within a few minutes. Generate a fresh configuration
> each time the tunnel starts, rather than keeping one around. See
> [How long a key lives](#how-long-a-key-lives).

When you no longer need it, `cyberghost-wg logout` deletes the device from your
account and removes the local files.

## Commands

| Command | What it does |
|---|---|
| `login` | Signs in and registers a device on the account (once). The device name, shown in your CyberGhost account, is asked in a terminal; `--name` sets it. Run it again at any time: it keeps the device, or registers a new one if the device was removed from the account. |
| `countries` | Lists the countries that have WireGuard servers of a type (`--type`). |
| `services` | Lists the streaming services that have WireGuard servers (232 in 37 countries in October 2026); `--country` narrows it. |
| `servers` | Lists the WireGuard servers of a country or of a streaming service, least loaded first. |
| `conf` | Generates a key pair, registers the public key on a server and writes the configuration. |
| `logout` | Deletes the device from the account and removes the local files. `--local` only removes the local files. |

Every command takes `-v` (`--verbose`), which shows each request and its HTTP
status, never a secret: add its output to bug reports. `countries`,
`services` and `servers` take `--json`, for scripts.

`servers` and `conf` take:

| Option | Default | Meaning |
|---|---|---|
| `--country CC` | `$CG_COUNTRY` | 2-letter country code, e.g. `CH`, `DE`, `US` |
| `--type TYPE` | `$CG_TYPE`, else `all` | `all`, `torrent`, `streaming`, `gaming` or `nospy`, see [Server types](#server-types) |
| `--service NAME` | – | Streaming service, e.g. `"Netflix UK"`; implies `--type streaming` |
| `--city NAME` | – | Only this city, e.g. `zurich` or `"new york"` |

`--service` takes the name shown by `services`, in any case, or a part of it
that matches only one service: `--service iplayer` works, `--service netflix`
does not, `--service netflix --country US` does. The country is not needed
otherwise: the service decides where its servers are. Streaming servers are the
ones CyberGhost optimizes for the service; whether the service lets you in is
up to it.

`conf` also takes:

| Option | Default | Meaning |
|---|---|---|
| `-i`, `--interactive` | – | Menus for whatever the other options leave open (see below) |
| `-o FILE` | stdout | Output file, written atomically with mode `0600` |
| `--tries N` | `3` | Servers to try, least loaded first, if one refuses the key |
| `--instance NAME` | – | Use this server (e.g. `zurich-s404-i06`) without listing servers |
| `--allowed-ips LIST` | `0.0.0.0/0, ::/0` | Networks sent through the tunnel (see below) |
| `--no-dns` | – | Leaves out the `DNS` line (see [wg-quick](#use-with-wg-quick)) |
| `--keep-hostname` | – | Writes the server hostname in `Endpoint` instead of its IPv4 address |

`Endpoint` is an IPv4 address by default because some clients, gluetun among
them, need one.

`AllowedIPs` tells WireGuard which destinations go through the tunnel; with
`wg-quick` it also sets the routes. The default sends everything. It includes
`::/0` although CyberGhost has no IPv6: IPv6 traffic then goes into the tunnel
and is dropped, instead of leaving the machine outside the VPN. Narrow it for
split tunneling, e.g. `--allowed-ips 0.0.0.0/0` if you want IPv6 to bypass the
VPN, or `--allowed-ips 203.0.113.0/24` to send only one network through it.
gluetun ignores this line and `DNS` too: it only reads
the keys, `Address` and `Endpoint`, and routes and resolves on its own.

Without `-o`, the configuration, private key included, goes to stdout. `conf`
refuses to do that when stdout is the systemd journal, which would keep the key.

Exit codes: `0` success, `1` error, `2` invalid command line, `130` interrupted.

### Server types

The same lists as in CyberGhost's apps:

| `--type` | CyberGhost app | Servers |
|---|---|---|
| `all` (default) | All servers | Every WireGuard server of the country |
| `torrent` | For torrenting | Servers that allow P2P; the API returns 10 per country |
| `streaming` | For streaming | The servers of one streaming service, given with `--service` |
| `gaming` | For gaming | CyberGhost's gaming servers, in a few countries (`countries --type gaming`: France, Germany, the UK and the US in October 2026) |
| `nospy` | NoSpy servers | CyberGhost's own servers in Bucharest, Romania; no `--country` needed |

Measured from France in October 2026, the gaming servers of Paris and Frankfurt
had the same latency and jitter as the other servers of the same city: for
games, the distance to the server matters more than its type.

### Interactive mode

`cyberghost-wg conf -i` asks, in turn, for the server type, the country (by
number or code), the streaming service for streaming servers, the city when
there are several, the server (automatic, or one
of the 10 least loaded) and where to write the file. Options given on the
command line are not asked again: `cyberghost-wg conf -i --type torrent
--country CH` only asks for the city, the server and the file.

Since the key only lives a few minutes unused, `-i` says so before the menus,
asks for confirmation before registering the key, and then prints the time by
which the tunnel must be up. It needs a terminal, and cannot be combined with
`--instance`.

## Credentials

The password is needed by `login`, then only when a command has to list
countries or servers and the session (24 hours) has expired. It is never
accepted as a command-line argument.

**Recommended:** let `login` remember it (it asks; `--remember` in scripts). The
username and password are then stored next to the state file, encrypted with
[`systemd-creds`](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html):
only your user (and root) can decrypt them on this machine, and `logout`
deletes them. Without a TPM2 chip, a full copy of the disk can decrypt them
too. This needs systemd 256 or later when not running as root (Debian 13,
Fedora 41, Ubuntu 24.10 and later); on older systems `login` says so and does
not offer it. Details in [How it works](#remembered-credentials).

Otherwise, or to override them, the credentials come from the first of these
that is set:

| Source | For |
|---|---|
| `--username USER --password-stdin` | a password manager: `pass show cyberghost \| cyberghost-wg login --username me@example.com --password-stdin` |
| `CG_USERNAME`, `CG_PASSWORD` | environment variables, e.g. `podman run -e` / `docker run -e` |
| `CG_USERNAME_FILE`, `CG_PASSWORD_FILE` | files, e.g. Podman or Docker secrets, which `inspect` does not show (setting both `CG_PASSWORD` and `CG_PASSWORD_FILE` is an error) |
| `$CREDENTIALS_DIRECTORY/cg-username`, `cg-password` | systemd `LoadCredential=` |
| remembered by `login --remember` | everything but `login` itself, and only for the remembered username |

With none of them, they are asked in the terminal. Variables and files hold the
password in clear text: keep them readable by you only.

### State file

`login` stores the device token and secret, and the current session token, in
`~/.config/cyberghost-wg/state.json` (mode `0600`, directory `0700`), with the
remembered credentials next to it. Use `--state` or `CG_WG_STATE` to put them
elsewhere.

**Protect it like your password.** The session token in it opens your whole
CyberGhost account for up to 24 hours: the account API lists every device on
the account *with its secret*, your phone and TV included. The device secret
lets anyone register keys on your account until the device is deleted. If the
file leaks, change your password and remove the devices from your CyberGhost
account.

`conf --instance NAME` only needs the device, never the session token or the
password.

## Use with gluetun

Generate the configuration just before starting gluetun, with the
[custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md):

```bash
cyberghost-wg conf --country CH --type torrent -o ./gluetun/wg0.conf
docker run -d --name gluetun --cap-add NET_ADMIN --device /dev/net/tun \
  -e VPN_SERVICE_PROVIDER=custom -e VPN_TYPE=wireguard \
  -v ./gluetun/wg0.conf:/gluetun/wireguard/wg0.conf:ro \
  qmcgaw/gluetun
```

gluetun brings its own kill switch and DNS (DNS over TLS by default), so the
`DNS` line of the configuration does not matter to it. To get a fresh key on
every start without thinking about it, see
[Start the tunnel with a fresh key](#start-the-tunnel-with-a-fresh-key).

## Use with wg-quick

```bash
cyberghost-wg conf --country CH -o cyberghost.conf
sudo wg-quick up ./cyberghost.conf
```

- **DNS:** `wg-quick` needs `resolvconf` to apply the `DNS` line. Without it,
  it stops with `resolvconf: command not found` and removes the interface.
  Install `openresolv`, which then points `/etc/resolv.conf` to CyberGhost's
  DNS while the tunnel is up (or use systemd-resolved's `resolvconf`), or
  generate with `--no-dns`. With `--no-dns` your usual DNS servers stay in use:
  through the tunnel if they are on the internet, but outside it if they are on
  your local network, such as your router's.
- **IPv6 disabled in the kernel:** `wg-quick` stops with
  `Error: IPv6 is disabled on nexthop device.`: generate with
  `--allowed-ips 0.0.0.0/0`.
- With IPv6 enabled, the default `AllowedIPs` sends IPv6 into the tunnel, where
  it is dropped: nothing leaks outside the VPN.
- `wg-quick` has no kill switch: if the tunnel goes down, traffic leaves
  outside it.

`wg-quick strip cyberghost.conf` gives the part `wg setconf` accepts, for setups
that create the interface themselves.

## Start the tunnel with a fresh key

A key only lives a few minutes until a tunnel uses it, so generate the
configuration each time the tunnel starts, not once at install. With systemd,
run `cyberghost-wg conf` in `ExecStartPre=`: if it fails, the tunnel does not
start with a dead key.

### Podman Quadlet

`~/.config/containers/systemd/gluetun.container`:

```ini
[Container]
Image=docker.io/qmcgaw/gluetun
AddCapability=NET_ADMIN
AddDevice=/dev/net/tun
Environment=VPN_SERVICE_PROVIDER=custom VPN_TYPE=wireguard
Volume=%h/.config/cyberghost-wg/wg0.conf:/gluetun/wireguard/wg0.conf:ro,Z

[Service]
ExecStartPre=%h/.local/bin/cyberghost-wg conf --country CH --type torrent -o %h/.config/cyberghost-wg/wg0.conf
Restart=on-failure
RestartSec=60

[Install]
WantedBy=default.target
```

```bash
cyberghost-wg login --remember     # once, as the same user
loginctl enable-linger "$USER"     # once: start at boot without logging in
systemctl --user daemon-reload && systemctl --user start gluetun
```

`Restart=` tries again a minute later when the network is not up yet at boot.
The remembered credentials let `ExecStartPre` sign in again when the session
expires; with `--instance NAME` instead of `--country`, no password is needed
at all, but the tunnel fails if that server is retired.

### Docker Compose

Compose has no pre-start hook: generate the configuration right before bringing
gluetun up, and recreate the container so that it reads the new file:

```bash
cyberghost-wg conf --country CH --type torrent -o ./gluetun/wg0.conf && docker compose up -d --force-recreate gluetun
```

Run the same line after a reboot: Docker restarts containers by itself, with
the old configuration, whose key is dead by then.

## How long a key lives

Observed in October 2026, on Zurich servers:

| Situation | What happens |
|---|---|
| Registered, never used | Refused after about 5 minutes |
| Used, then no traffic at all for 10 minutes | Still accepted |
| Used, then the device deleted (`logout`) | The tunnel kept working (6 minutes observed): `logout` stops new keys, not running tunnels |
| Used, then idle for hours | Not tested |

If a tunnel cannot reconnect after a long network outage, restarting it brings a
fresh key.

## How it works

These are the calls the official Linux client makes, and that `cyberghost-wg`
makes too:

| Step | Request |
|---|---|
| Sign in | `POST https://v2-api.cyberghostvpn.com/v2/my/account/jwt` |
| Register a device (once) | `POST /v2/my/devices`: returns a device token and secret |
| Check the device (at `login`) | `GET /v2/my/devices` |
| List countries | `GET /v2/my/servers/filters/75` (torrent) or `/73` (all), protocol `wireguard` |
| List servers | `GET /v2/my/servers/filters/71` (torrent), `/74` (all) or `/95` (NoSpy), protocol `wireguard` |
| List streaming services | `GET /v2/my/servers/filters/76`, protocol `wireguard` |
| List a service's servers | `GET /v2/my/servers/filters/72?filter_content_id=<service>`, protocol `wireguard` |
| Find the gaming servers | `GET /v2/my/servers/filters/86` gives the gaming group's hostname per country (`19-DE.cg-dialup.net`); its addresses pick the gaming servers out of `/74` |
| Register a key | `GET https://<server>.cg-dialup.net:1337/addKey?pubkey=…`, HTTP Basic auth with the device token and secret |
| Delete the device | `DELETE /v2/my/devices/<id>` |

Nothing is sent anywhere else. Differences with the official client:

- The key pair is generated locally (X25519, implemented in the script); only
  the public key leaves the machine.
- Server names and the `addKey` answer are strictly validated (server name,
  IPv4 address, 32-byte key, port, DNS addresses) before anything is written,
  so a tampered answer cannot inject directives such as `PostUp` into the
  configuration.
- `addKey` serves a certificate issued to the server's rack
  (`zurich-s404-i06` is served by `zurich-rack404.nodes.gen4.ninja`), signed by
  the CyberGhost root CA. The official client only checks the CA, which every
  CyberGhost server has a certificate from; `cyberghost-wg` also checks the
  rack, before sending the device secret. Python 3.13 rejects that 2017 CA in
  strict mode, so strict mode is turned off for this one connection.
- The least loaded server is chosen, rather than a random one.
- The password is only kept if you ask, and then encrypted with
  `systemd-creds` (the official client keeps it in clear text in
  `~/.cyberghost/config.ini`).
- The API limits the request rate: it answered HTTP 429 after 5 country
  lists in 2 seconds, while 16 server lists in 9 seconds went through, and
  lifted the block after about a minute. `cyberghost-wg` waits and tries once
  more, and keeps the account details it needs for the lifetime of the session
  to make fewer requests.
- OpenVPN, dedicated IPs and bringing the tunnel up are out of scope.

The script contains the application key the official client sends with every
request (it identifies the app, not you) and the CyberGhost root CA
certificate, which is public.

### Remembered credentials

`login --remember` runs `systemd-creds --user encrypt` (without `--user` as
root) once for the username and once for the password, and writes the results
to `cg-username.cred` and `cg-password.cred` next to the state file, mode
`0600`. When a session has to be opened, `systemd-creds --user decrypt` reads
them back; it works from a terminal and from a user service such as an
`ExecStartPre=` alike.

The encryption key combines:

- the machine's secret key, `/var/lib/systemd/credential.secret`, readable by
  root only and created by systemd on first use, or the TPM2 chip when there is
  one, or both;
- with `--user`, your numeric user ID, your user name and the machine ID.

So another user cannot decrypt the files, and a file copied to another machine
or another account is useless. Root can decrypt them. Without a TPM2 chip, the
secret key lives on the same disk, so a full copy of that disk can decrypt them
as well. Each file is also bound to its name (`cg-username`, `cg-password`):
renamed or swapped files are refused.

`systemd`'s own `LoadCredentialEncrypted=` is not used: in a user service it
needs to read the machine's secret key itself, which systemd 257 refuses.

## Troubleshooting

| Message | Meaning and fix |
|---|---|
| `refused the device (HTTP 401)` | This server does not accept the device; the next one is tried. If every server refuses it, the device was removed from the account (website, another `logout`): run `cyberghost-wg login`, which registers a new one. |
| `HTTP 429` | Too many requests: the API blocks for about a minute. `cyberghost-wg` already waited once; wait and try again. |
| `authentication refused` | Wrong username or password. If the password changed, run `login` again. |
| `API unreachable` | No network or DNS yet (at boot), after three attempts. With the Quadlet above, systemd tries again a minute later. |
| `systemd 255 is too old to remember the credentials` | Use another credential source (see [Credentials](#credentials)), or run as root. |
| `certificate issued to …, expected …` | The server's certificate does not match its name: the connection is refused, the next server is tried. If every server says so, CyberGhost changed its certificates: please open an issue. |
| The tunnel is up but nothing goes through | The key was registered more than a few minutes before the tunnel came up: generate a new configuration and connect right away. |
| `resolvconf: command not found` (wg-quick) | See [wg-quick](#use-with-wg-quick). |

Run the failing command again with `-v` and add its output to an issue.

## FAQ

**Can my account be banned for this?** It makes the same requests as the
official Linux client, a few at a time. CyberGhost's terms of service are yours
to read; nothing here is legal advice.

**Does the device count against my simultaneous connections?** The device
shows up in your CyberGhost account next to your other ones. Whether it counts
against the connection limit is untested.

**Can one device serve several tunnels at once?** Each `conf` registers its own
key; running several at once is untested.

**Port forwarding, OpenVPN, dedicated IPs?** Out of scope, and CyberGhost
offers no port forwarding.

**Routers (OpenWrt, OPNsense…)?** The script only needs Python; the key has to
be regenerated whenever the tunnel restarts, which those systems need a hook
for. Untested.

**Why does it send a Chrome User-Agent?** The official client does, and the
API is not documented: `cyberghost-wg` behaves like the official client
wherever it can.

## Limitations

- IPv4 only: CyberGhost's WireGuard servers give no IPv6 address.
- No port forwarding: CyberGhost does not offer it.
- Torrent servers: the API returns only 10 per country, a selection that changes
  over time. A server you pin with `--instance` can disappear from the list.

## Uninstall

```bash
cyberghost-wg logout                  # deletes the device from the account and the local files
rm ~/.local/bin/cyberghost-wg
```

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests run offline, without an account.

## License

[MIT](LICENSE). CyberGhost is a trademark of its owner, used here only to say
what this tool works with.
