# gluetun-cyberghost

**[gluetun](https://github.com/qdm12/gluetun) with CyberGhost over WireGuard,
and a fresh key on every start.**

gluetun is a VPN client container with a firewall "kill switch": the containers
that share its network only go out through the tunnel, and lose all access when
the tunnel is down, never falling back to your own IP. Its built-in CyberGhost
provider only speaks OpenVPN. This image adds
[`cyberghost-wg`](../README.md) to it, so that gluetun gets a CyberGhost
WireGuard configuration through its custom provider.

```
ghcr.io/bastienpop/gluetun-cyberghost:latest      linux/amd64, linux/arm64, linux/arm/v7
```

It works with Docker Compose and with rootless Podman (Quadlet); both are
described below and were tested.

## How it works

```
gluetun-cyberghost container (its own network)
 1. cyberghost-wg login   first start only: registers a device (state/)
 2. cyberghost-wg conf    fresh WireGuard key, least loaded server -> wg0.conf
 3. gluetun               firewall, WireGuard tunnel, DNS over TLS in the tunnel

client container (same network) --> tunnel --> CyberGhost server --> internet
                                X   outside the tunnel: blocked by gluetun's firewall
```

**A fresh key on every start.** CyberGhost refuses a registered key that no
tunnel has used within about 5 minutes, so a configuration kept from one start
to the next is dead. The image generates one every time the container starts,
right before gluetun. If that fails (network not up yet at boot, API rate
limit), the container exits and its restart policy tries again. This is what
makes it work after a reboot: Docker restarts the same container, which gets a
new key.

**No leak at start.** During step 2, gluetun's firewall is not up yet. Client
containers must only start once gluetun is *healthy*: `condition:
service_healthy` with Docker, `Notify=healthy` with Podman (see
[Connect a container to the tunnel](#connect-a-container-to-the-tunnel)).

**No IPv6.** CyberGhost has none. gluetun's firewall already blocks all IPv6,
but a client that sees an IPv6 address in its network tries it first for sites
that have one, and waits until it times out. IPv6 is therefore turned off in the
container's network (`net.ipv6.conf.all.disable_ipv6=1`). This cannot be done
in the image: `/proc/sys` is read-only inside a container, only the engine can
set it.

## Requirements

| You need | Check |
|---|---|
| Docker with Compose v2, or Podman 5 (Quadlet, `Notify=healthy`) | `docker compose version` / `podman --version` |
| The `wireguard` kernel module on the host: a container cannot load it. Without it, gluetun falls back to a slower userspace WireGuard | `lsmod \| grep ^wireguard` |
| The TUN device | `ls -l /dev/net/tun` |
| An active CyberGhost subscription. The first start registers a **device** on the account, which counts like your other devices | CyberGhost account → devices |

## Settings

Everything is in `vpn.env`, copied from [`vpn.env.example`](vpn.env.example),
which comments every line. Its values work as they are: torrent servers in
Switzerland, the least loaded one.

| Setting | Meaning |
|---|---|
| `CG_COUNTRY` | Country, 2-letter code (`CH`, `DE`, `NL`, `US`…) |
| `CG_TYPE` | `torrent` (servers that allow P2P), `all`, `gaming` or `nospy` (Bucharest, `CG_COUNTRY` ignored) |
| `CG_CITY` | Optional: only the servers of this city (`zurich`, `new york`) |
| `CG_SERVICE` | Optional: the servers of a streaming service (`BBC iPlayer`); replaces `CG_TYPE` |
| `CG_INSTANCE` | Optional: one server (`zurich-s404-i06`) instead of the least loaded; fails once CyberGhost retires it |
| `CG_DEVICE_NAME` | Name of the device in the CyberGhost account, used on the first start only (default `gluetun`) |
| `TZ` | Time zone of the logs |
| `DNS_UPSTREAM_RESOLVERS` | gluetun's DNS, over TLS through the tunnel: `quad9` (in the example), `cloudflare` (gluetun's default), `google`, `mullvad`… |
| `BLOCK_MALICIOUS`, `BLOCK_ADS`, `BLOCK_SURVEILLANCE` | DNS blocking (`on` / `off`) |
| `FIREWALL_OUTBOUND_SUBNETS` | Local networks reachable outside the tunnel (e.g. `192.168.1.0/24` for a NAS); empty: nothing outside |
| `WIREGUARD_MTU` | Packet size in the tunnel; lower it if some sites do not load |
| `LOG_LEVEL` | `debug`, `info`, `warning`, `error` |

> **No quotes** in `vpn.env`, even for a value with spaces (`CG_CITY=new york`):
> Podman would keep them in the value.

Any other gluetun setting can be added to the file (see its
[wiki](https://github.com/qdm12/gluetun-wiki)). `VPN_SERVICE_PROVIDER` and
`VPN_TYPE` are set by the image: leave them alone.

The credentials are **not** in `vpn.env`: they are Docker or Podman secrets,
read from `/run/secrets/cg_username` and `/run/secrets/cg_password`. The
password is needed on the first start, then whenever the CyberGhost session
(24 hours) has expired.

Simpler but less private: put `CG_USERNAME=` and `CG_PASSWORD=` in `vpn.env`,
and remove the secrets lines (`CG_USERNAME_FILE`, `CG_PASSWORD_FILE`,
`secrets:` / `Secret=`) from `compose.yaml` or the unit; setting a variable and
its `_FILE` together is an error. The password then shows in `docker inspect` /
`podman inspect` and in the environment of the container's processes, and
`vpn.env` must be kept private (mode `0600`).

## Docker Compose

Get this folder (or the whole repository), then, in it:

```bash
cp vpn.env.example vpn.env && nano vpn.env
mkdir -m 700 state secrets
read -rp 'CyberGhost username: ' u && printf '%s' "$u" > secrets/cg_username && unset u
read -rsp 'CyberGhost password: ' p && echo && printf '%s' "$p" > secrets/cg_password && unset p
chmod 600 secrets/*
docker compose up -d
docker compose logs -f gluetun
```

The `read` lines keep the password off the screen, out of the shell history and
out of the process list. `state/` receives `state.json` on the first start.

`docker compose up -d` pulls the image, and builds it from the repository when
it cannot be pulled; `docker compose up -d --build` always builds it (the
`build:` section expects the folder to be inside a clone of the repository).

**Without root containers: `userns-remap`.** By default, root in the container
is root on the host. With
[`userns-remap`](https://docs.docker.com/engine/security/userns-remap/) enabled
on the daemon, it becomes an unprivileged host user (the first ID of
`dockremap` in `/etc/subuid`), and `NET_ADMIN` only applies inside the
container. That user must be able to read `secrets/` and write to `state/`:
`sudo chown -R "$(awk -F: '$1=="dockremap"{print $2}' /etc/subuid)" state secrets`.
Untested.

## Podman (Quadlet)

Rootless, as your user. With the unit file of this folder:

```bash
mkdir -p ~/.config/containers/systemd ~/.config/gluetun-cyberghost
cp gluetun.container ~/.config/containers/systemd/
cp vpn.env.example ~/.config/gluetun-cyberghost/vpn.env && nano ~/.config/gluetun-cyberghost/vpn.env
mkdir -m 700 ~/.config/gluetun-cyberghost/state
read -rp 'CyberGhost username: ' u && printf '%s' "$u" | podman secret create cg_username - && unset u
read -rsp 'CyberGhost password: ' p && echo && printf '%s' "$p" | podman secret create cg_password - && unset p
loginctl enable-linger "$USER"        # once: start at boot without logging in
systemctl --user daemon-reload
systemctl --user start gluetun
journalctl --user -u gluetun -f
```

Podman secrets are not shown by `podman inspect`. Podman does not create the
`state` folder of a volume: `mkdir` it first. `systemctl --user start` returns
once gluetun is healthy (`Notify=healthy`), or fails after 3 minutes. The unit
starts with the machine (`WantedBy=default.target`); `systemctl enable` does not
apply to Quadlet units.

What the unit adds to a plain `podman run`:

| Line | Why |
|---|---|
| `Sysctl=net.ipv6.conf.all.disable_ipv6=1` | Rootless Podman (pasta) copies the host's IPv6 address and route into the container: without this line, clients try IPv6 first and time out (seen). Docker networks have no IPv6 by default |
| `HealthCmd=…` | Podman does not read the health check of the image |
| `Notify=healthy` | Units started after gluetun wait until the tunnel is up |
| `HealthOnFailure=kill` + `Restart=always` | A tunnel that stays down gets the container killed and started again by systemd, with a fresh key |

To build the image yourself instead of pulling it, from a clone of the
repository: `podman build -f gluetun/Dockerfile -t ghcr.io/bastienpop/gluetun-cyberghost:latest .`

## Check it works

In the logs, in this order:

- first start only: `Signed in. Device created: gluetun (id …)` and
  `State saved to /cyberghost-wg/state.json`;
- `OK: <server> (torrent, load NN%), address …, endpoint <IP>:1337`: the
  configuration is generated;
- `[wireguard] Using available kernelspace implementation`: kernel WireGuard,
  the fast one;
- `[ip getter] Public IP address is <IP> (<country>…)`: the tunnel is up, with
  the IP of the CyberGhost server.

Then, from a throwaway client (use `podman` the same way):

```bash
# Public IP: the CyberGhost server's, in the chosen country
docker run --rm --network container:gluetun alpine:3 wget -qO- https://ipinfo.io/json
# IPv6: must fail at once (can't connect to remote host: Address not available)
docker run --rm --network container:gluetun alpine:3 wget -T 10 -qO- https://ipv6.icanhazip.com
# Kill switch: with the tunnel removed, the client must have no access at all (bad address)
docker exec gluetun ip link delete tun0
docker run --rm --network container:gluetun alpine:3 wget -T 10 -qO- https://ipinfo.io/ip
```

gluetun brings the tunnel back by itself after the last test, within about a
minute.

## Connect a container to the tunnel

A container that shares gluetun's network has **no network of its own**: all
its traffic goes through the tunnel, and its ports are published **on gluetun**.

**Docker Compose**, in the same `compose.yaml`:

```yaml
  my-app:
    image: …
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    restart: unless-stopped
```

Ports go in `ports:` of the `gluetun` service. A client keeps the network that
gluetun had **when the client started**: when gluetun restarts, the client
stays `Up` but loses all access (no leak, but nothing goes through). Tested:

- `restart: true` makes Compose restart the client when **Compose** restarts
  gluetun (`docker compose restart gluetun`, `docker compose up -d` after a
  change);
- when **the Docker daemon** restarts gluetun after a crash, Compose is not
  involved: restart the client yourself (`docker compose restart my-app`);
- at boot, Docker starts gluetun, then the client, which works.

**Podman Quadlet**, in the client's unit:

```ini
[Container]
Network=gluetun.container
```

Quadlet adds `Requires=` and `After=gluetun.service`, and that is all it takes
(tested): the client starts once gluetun is healthy, and whenever gluetun
restarts, by hand or after a crash, systemd stops the client, starts gluetun
again, then the client. In between, the client has no access. Ports go in
`gluetun.container` (`PublishPort=127.0.0.1:8080:8080`).

## When the tunnel goes down

gluetun watches the tunnel. When it stops working, gluetun brings it back
itself, **with the same key**: that covers short outages. When the tunnel does
not come back (key refused after a long outage, server retired), gluetun ends up
*unhealthy*:

- **Podman**: `HealthOnFailure=kill` stops the container and systemd starts it
  30 seconds later, so with a fresh key on the least loaded server. Measured by
  blocking the server inside the container: 2 min 35 s of gluetun retrying,
  then the kill, then the tunnel back a minute later on another server.
- **Docker** does not restart an *unhealthy* container: gluetun keeps trying
  with the same key until you run `docker compose restart gluetun` (which also
  restarts the clients declared with `restart: true`).

Clients have no access during all that time.

## Docker and Podman compared

| | Docker Compose | Podman Quadlet |
|---|---|---|
| Credentials | Files in `secrets/` | Podman secrets |
| Health check | The image's (gluetun's), redefined in `compose.yaml` | Must be in the unit |
| IPv6 in the container | None on default networks; `sysctls:` makes sure | The host's (pasta): `Sysctl=` is required |
| Clients after gluetun restarts | Restarted by Compose with `restart: true`; **not** after a crash restarted by the daemon | Always restarted by systemd (`Requires=`) |
| Tunnel down for good | Stays down until `docker compose restart gluetun` | Killed and restarted with a fresh key |
| `NET_RAW` | Given by default: gluetun checks the tunnel with pings | Not given: gluetun checks with DNS queries and logs a `NET_RAW` notice, which is harmless |
| Root | Root on the host, unless `userns-remap` | Your user (rootless) |

**Throughput with rootless Podman** is limited by its user-mode network (pasta),
which carries the encrypted packets: 42 to 50 Mbit/s through the tunnel against
572 Mbit/s without it, measured on a 3-vCPU arm64 VM with kernel WireGuard. The
image is the same either way; rootful containers do not have this limit.

## Tested

Docker 29.9 with Compose v2, and Podman 5.4 rootless with Quadlet, on Debian 13
arm64 (October 2026): first start with device registration, CyberGhost IP seen
by a client, IPv6 blocked, kill switch, restarts (by hand, crash, reboot),
tunnel down for good. Not tested: `userns-remap`, amd64 and armv7 hosts.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `secret cg_username not found`, or no such file `secrets/cg_username` | The credentials are missing: see the install steps |
| `authentication refused` on the first start | Wrong username or password: recreate the secrets, then restart |
| `refused the device (HTTP 401)` from every server, after it worked | The device was removed from the account: delete `state/state.json` and restart; a new device is registered |
| `HTTP 429` | Too many requests to the CyberGhost API; it lifts after about a minute, and the restart policy tries again |
| Restarts in a loop with `give a 2-letter country code` | `CG_COUNTRY` empty or invalid in `vpn.env` |
| A `vpn.env` value is ignored | Quotes around it (Podman keeps them), or the container was not restarted |
| `(unhealthy)`, then a restart (Podman) | The tunnel stopped working: restarting with a fresh key is the intended fix. In a loop: server full or retired (`CG_INSTANCE`?), or no network |
| A client takes long to reach some sites, then fails | It tries IPv6: check the `Sysctl=` / `sysctls:` line |
| A client is `Up` but has no access (Docker) | gluetun restarted under it: `docker compose restart <client>` |
| `WARN [dns] … running TLS handshake with 9.9.9.9:853 … connection reset by peer` | Quad9 dropped a connection; gluetun retries and the lookup succeeds. Only a problem if it never stops: try another `DNS_UPSTREAM_RESOLVERS` |
| `listening for ICMP packets: not permitted: … NET_RAW` | Normal with Podman: gluetun checks the tunnel with DNS instead of pings |
| Slow | No `Using available kernelspace implementation` line: the `wireguard` module is missing on the host. Otherwise, see the throughput note above |

## Security

- `state/state.json` holds the device token and the CyberGhost session token.
  **The session opens your whole account** for 24 hours (the account API lists
  every device with its secret). If it leaks, change your CyberGhost password
  and remove the devices from your account.
- The credentials are secrets (files readable by you only with Docker).
  `vpn.env` holds no secret.
- The WireGuard private key only exists inside the container
  (`/gluetun/wireguard/wg0.conf`, mode `0600`) and changes on every start. The
  logs hold no key and no token.

## cyberghost-wg inside the container

The full tool is in the image, with the container's state and credentials:

```bash
docker exec gluetun cyberghost-wg countries --type torrent
docker exec gluetun cyberghost-wg servers --country CH --type torrent
```

## Uninstall

```bash
docker exec gluetun cyberghost-wg logout      # deletes the device from the account (podman exec with Podman)
docker compose down                            # Podman: systemctl --user stop gluetun, then remove the unit
```

`logout` does not cut the running tunnel: stopping gluetun does. Then delete
`state/`, `secrets/` (or `podman secret rm cg_username cg_password`) and the
image.
