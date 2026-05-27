# Signer Console

`signer-console` is a small admin UI for the trusted signer host. It is intended
to run on localhost behind OpenResty at:

```text
https://ssl-signer.js.gripe
```

Authentication uses account-system third-party login:

```text
https://account.js.gripe/login
```

The console calls:

```text
https://gateway.js.gripe/api/v1/myaccount/me
```

Only account-system users with `role = system_admin` can access the console.

## Account Client

Create an account-system API client:

```text
Name: SSL Signer Console
Redirect URI: https://ssl-signer.js.gripe/auth/account/callback
Scopes: accounts:read identities:resolve
```

Set the generated `client_id` in:

```text
/etc/myzerossl/signer-console.env
```

Do not commit the session secret or client secret.

## Capabilities

The console can:

- View configured edge signer clients.
- View revoked client ids.
- View recent signer audit log lines.
- Disable or enable a configured edge client.
- Revoke or unrevoke an edge client id.

Changes are written to:

```text
/etc/myzerossl/clients.json
/etc/myzerossl/revoked-clients.txt
```

Restart `keylessd-local` after manually editing those files. Console actions
take effect for the persisted files immediately; already loaded in-memory signer
state may require a restart for some manual changes.
