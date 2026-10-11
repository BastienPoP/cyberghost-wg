@CONTRIBUTING.md

- Never ask for a CyberGhost password and never put one on a command line: the
  account owner runs `login` themselves, with `CG_WG_STATE` pointing to a
  throwaway state. Run `logout` at the end of a session that created a device.
- Never print or paste a state file, a `*.cred` file or a generated
  configuration: they hold the account session, the device secret or a private
  key.
- Everything in this repository is in English, commit messages included.
