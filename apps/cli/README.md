# Snowstead CLI authentication

Run `snowstead login` to sign in at https://snowstead.com. The CLI prints a
verification URL and an eight-character code, then opens your browser. Approve
access to your organization there. Its cache token is saved only after approval,
under the organization's slug in `~/.config/snowstead/config.json`. On Unix, the
config directory is owner-only, and the file is atomically replaced with mode 600.

For SSH or a headless machine, run `snowstead login --no-browser` and open the
printed URL on another device. Login expires after at most ten minutes. No
localhost callback is needed.

- `--name <profile>` overrides the organization slug used for the local profile.
- `--url <web-origin>` selects a different login website. HTTPS is required,
  except for HTTP loopback origins used in local development.
- `snowstead auth status [--server <profile>]` shows local configuration only;
  it does not verify the token remotely.
- `snowstead logout [--server <profile>]` removes that local profile, preserving
  the others. It does not revoke the remote token. If you remove the default,
  the first remaining profile in alphabetical order becomes the default.

For CI, set **both** `SNOWSTEAD_TOKEN` and `SNOWSTEAD_URL` (the cache base URL,
not the website). They override saved credentials for cache commands, without
changing the config. Use your CI secret store; do not put tokens in arguments.

For self-hosted caches or manually issued tokens, pipe the token from a secret
store or protected file:

```sh
snowstead login --token-stdin --url https://cache.example.com --name self-hosted < token-file
```

This saves the token without claiming remote validation. Positional login tokens
are no longer accepted. Verbose tracing remains opt-in with `--verbose`, goes to
stderr, and does not log authentication requests or credentials.
