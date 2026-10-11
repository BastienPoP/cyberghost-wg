# Security

## Reporting a vulnerability

Please report it privately through
[GitHub security advisories](https://github.com/BastienPoP/cyberghost-wg/security/advisories/new),
not in a public issue. You should get an answer within a week.

Never include your CyberGhost password, your `state.json`, your `*.cred` files
or a generated configuration in a report: they give access to your account or
your tunnel. The output of a command run with `-v` is safe to share.

## What the script protects

- The password is never accepted as a command-line argument, and is only stored
  if you ask, encrypted with `systemd-creds`.
- The state file, the remembered credentials and the configurations are written
  atomically with mode `0600`, in a `0700` directory.
- The WireGuard private key is generated locally and never sent anywhere.
- Server names and the `addKey` answer are validated before anything is
  written to a configuration.
- The `addKey` certificate must chain to the CyberGhost root CA and name the
  server's rack, before the device secret is sent.

## Known limits

- The `addKey` certificate cannot be checked against a public CA: CyberGhost
  issues it from its own root CA, to the rack rather than the server name.
- The session token in the state file opens the whole account for up to 24
  hours (see "State file" in the README).
- Deleting the device stops new keys, not tunnels already up.
