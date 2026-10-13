# Contributing

Bug reports, fixes and new findings about the API are welcome. This file is
about changing the tool; the [README](README.md) is about using it. Security
issues go through [SECURITY.md](SECURITY.md), not public issues.

## Ground rules

- **One file, standard library only.** `cyberghost-wg` is installed by
  downloading a single script: no runtime dependency, no package to install.
- **Python 3.8 and later.** CI runs the tests on 3.8 to 3.14; avoid syntax and
  standard library features newer than 3.8 (no `match`, no `str.removeprefix`,
  no `X | Y` type unions).
- **Nothing from the network is trusted.** Anything the API or a server returns
  is validated before it becomes a hostname, a line of the configuration or a
  file name (see `INSTANCE_RE`, `parse_addkey`, `parse_allowed_ips`). A new
  field copied into the configuration needs the same treatment and a test with
  an injected newline.
- **Secrets stay secret.** No password on the command line, nothing secret in
  `-v` output or error messages, every file holding a secret written with
  `write_secret_file` (atomic, mode `0600`).
- **stdout is for output only.** Prompts, progress and errors go to stderr, so
  that `conf` without `-o` and `--json` stay usable in pipes.
- **The gluetun image stays thin.** `gluetun/` only adds the script and a
  short entrypoint to the gluetun image; anything a user of the bare script
  could use belongs in the script. The image copies the script from the
  repository, so both always match.
- **English** everywhere: code, comments, docs, commit messages.
- The README documents every user-visible option and behaviour; update it in
  the same change, and add a line to `CHANGELOG.md` under an `Unreleased`
  section.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests run offline: they replace `api`, `add_key`, `socket.getaddrinfo` or
`systemd_creds` with fakes, and never need an account. Every fix comes with a
test that fails without it.

## Trying it against the real API

This needs an active CyberGhost subscription. Use a throwaway state, so that
nothing touches a real setup, and remove the device when done:

```bash
export CG_WG_STATE=/tmp/cg-dev/state.json
./cyberghost-wg login --name cg-wg-dev       # the account owner types the password
./cyberghost-wg servers --country CH -v
./cyberghost-wg logout                       # deletes the device from the account
```

- **Rate limit:** the API answers HTTP 429 for about a minute after a burst,
  observed after 5 country lists in 2 seconds (16 server lists in 9 seconds
  went through). When probing the API, leave about 5 seconds between requests.
- **Keys die unused:** a key registered with `addKey` is refused after about
  5 minutes without a handshake. Generate the configuration right before
  bringing the tunnel up.
- **Bring tunnels up in a container**, not on your machine: a full tunnel
  replaces the default route, and on a remote machine it cuts your SSH session.
  The gluetun image built from the working tree does it with a throwaway state:

  ```bash
  podman build -f gluetun/Dockerfile -t cyberghost-wg-dev .
  mkdir -m 700 /tmp/cg-dev
  podman run --rm -it --name cg-dev --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 -e CG_COUNTRY=CH -e CG_TYPE=torrent \
    -v /tmp/cg-dev:/cyberghost-wg cyberghost-wg-dev   # the account owner types the password
  # in another terminal:
  podman run --rm --network container:cg-dev alpine:3 wget -qO- https://ipinfo.io/ip
  podman exec cg-dev cyberghost-wg logout
  ```

  Without `CG_USERNAME_FILE`, the first-start `login` asks for the credentials
  in the terminal (`-it`).

## What is known about the API

Nothing here is documented by CyberGhost: it was observed in October 2026, from
the official Linux client 1.5.0 and by probing. Base URL
`https://v2-api.cyberghostvpn.com/v2`, header `x-app-key`, then
`Authorization: Bearer <jwt>` once signed in.

| Request | Gives | Parameters it needs |
|---|---|---|
| `GET /my/servers/filters/73` | Countries with servers (`all`) | `filter_protocol`, `filter_user_plans_id`, `filter_user_id`, location |
| `GET /my/servers/filters/75` | Countries with torrent servers | `filter_protocol`, `filter_user_plans_id`, location |
| `GET /my/servers/filters/74` | Every server of a country (`all`) | `filter_protocol`, `filter_country`, `filter_user_id`, location |
| `GET /my/servers/filters/71` | Torrent servers of a country (10) | `filter_protocol`, `filter_country`, `filter_user_plans_id` |
| `GET /my/servers/filters/76` | Streaming services (`content_id`, `name`, `countrycode`) | `filter_protocol`, `filter_user_plans_id`, `filter_user_id`, location |
| `GET /my/servers/filters/72` | Servers of one streaming service (10) | the above plus `filter_content_id` |
| `GET /my/servers/filters/95` | NoSpy servers, all in Romania | `filter_protocol` (ignored, but required) |
| `GET /my/servers/filters/86` | Server groups; `Gaming servers` gives a hostname per country | `filter_protocol` |

"Location" is `filter_user_latitude` and `filter_user_longitude`, from
`GET /my/account`. Every filter wants `filter_protocol`, even those that ignore
it; a missing parameter gives HTTP 404 with the parameter's name. No match is
HTTP 204 with an empty body.

Quirks worth knowing before changing the code:

- **Country lists** carry only `countrycode`, no name: names come from the
  built-in ISO table.
- **Server names** are not always hostnames: `Nospybucharest-S409-i01` (and
  formerly `Nospyproxy…`) is `bucharest-s409-i01.cg-dialup.net`. Case varies
  (`Washington-S415-i31`, `NewYork-s406-i04`).
- **NoSpy rows** (filter 95) use `name`, `total_users`, `max_users` and have no
  `city`, where the other lists use `displayName`, `totalusers`, `Max_Users`
  and `city`.
- **Gaming servers** have no filter of their own. The `Gaming servers` group of
  filter 86 has a hostname per country (`19-DE.cg-dialup.net`) that resolves to
  the group's servers; matching those addresses against filter 74 gives their
  names (`frankfurt-s410`, `london-s455`, `newyork-s406`, `paris-s463` in
  October 2026).
- **Filters 89 and 98** list 13 countries and 21 racks: the dedicated-IP
  locations. Their servers refuse an ordinary device with HTTP 401.
- **Filters 62, 67, 68 and 70** return server lists whose meaning is unknown;
  they are not used.
- **`addKey`** (`https://<instance>.cg-dialup.net:1337/addKey?pubkey=…`, Basic
  auth with the device token and secret) answers 401 when that server does not
  take the device (dedicated IP) or when the device was deleted: one 401 says
  nothing about the other servers.
- **Its certificate** is issued by the CyberGhost root CA to the rack,
  `zurich-rack404.nodes.gen4.ninja` for `zurich-s404-i06`, and fails Python
  3.13's strict X.509 checks (non-critical basicConstraints).
- **`GET /my/devices`** returns the token and secret of every device of the
  account, which is why the session token in the state file is sensitive.
- **Deleting a device** stops new keys, not tunnels already up.
- The session token (JWT) lasts 24 hours.

New findings belong in this section, with the date they were observed.

## Releasing

1. Set `VERSION` in the script, rename `Unreleased` in `CHANGELOG.md` to
   `## X.Y.Z – YYYY-MM-DD`, and update the version in the README's install
   URLs.
2. Commit, push, and wait for the `tests` workflow to pass.
3. Tag and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "cyberghost-wg X.Y.Z" && git push origin vX.Y.Z
   ```

The `release` workflow runs the tests again, checks that the tag matches
`VERSION`, and publishes the release with the script, `SHA256SUMS` and the
CHANGELOG section as notes. The `image` workflow builds the gluetun image for
amd64, arm64 and armv7 and pushes it to `ghcr.io/bastienpop/gluetun-cyberghost`
as `X.Y.Z` and `latest`.

**gluetun updates** need no release: the base image is pinned in
`gluetun/Dockerfile`, and Dependabot opens a pull request when a new gluetun is
out. The pull request builds the image for every platform and runs its smoke
test, without publishing it; merging it runs the `image` workflow again, which
republishes `latest` (the `X.Y.Z` tags keep the gluetun they were released
with). Try the new gluetun first: its settings and log lines are documented in
`gluetun/README.md`.
