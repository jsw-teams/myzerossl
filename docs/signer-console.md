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

## Frontend

The console has three web views:

- `/`: public introduction page with SEO and Open Graph metadata.
- `/login`: account-system login entry page.
- `/console`: system administrator dashboard.

It also serves:

- `/favicon.png`: pixel-art black bear with a wrench.
- `/og.png`: same mascot image for Open Graph previews.
- `/llms.txt`: LLM-friendly service summary.
- `/robots.txt`: disallows indexing of the private console and allows
  `/llms.txt`.

Frontend behavior:

- Browser-language aware copy for Simplified Chinese, Traditional Chinese, and
  English.
- Responsive pixel-style layout for desktop, tablet, and narrow mobile screens.
- One-time edge token dialog with copy action. The token is removed from the DOM
  when the dialog is closed.
- Single background color and a sticky footer so large desktop viewports do not
  leave the footer floating mid-page.
- Tables use horizontal scrolling on small screens so long edge IDs, source
  addresses, and action buttons do not break the layout.
- Long labels and account identifiers wrap inside their containers.

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

- Review pending edge registration requests.
- Approve a pending edge and generate its token.
- Reject a pending edge registration.
- View configured edge signer clients.
- View revoked client ids.
- View recent signer audit log lines.
- Disable or enable a configured edge client.
- Revoke or unrevoke an edge client id.

Changes are written to:

```text
/etc/myzerossl/clients.json
/etc/myzerossl/revoked-clients.txt
/etc/myzerossl/edge-registrations.json
```

Restart `keylessd-local` after manually editing those files. Console actions
take effect for the persisted files immediately; already loaded in-memory signer
state may require a restart for some manual changes.

## Edge Registration Flow

A new edge VPS should not be added to `clients.json` automatically. It can only
submit a pending request:

```sh
curl -X POST https://ssl-signer.js.gripe/api/register \
  -H 'Content-Type: application/json' \
  --data '{"id":"tw-edge-2","label":"Taiwan edge replacement"}'
```

The request remains pending until a `system_admin` signs in to
`https://ssl-signer.js.gripe` and approves it. Approval generates a token once
and shows it in a console dialog instead of a browser alert. Copy it immediately
into the edge VPS `KEYLESS_TOKEN`; closing the dialog clears the token from the
page.

Production signer hosts should start with:

```json
{
  "clients": []
}
```

There are no default active edge clients.
