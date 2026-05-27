# Abuse Monitoring And Auto Revocation

The signer should not rely on one shared long-lived token for every edge VPS.
Use one client identity per edge node, then let `keylessd` rate-limit and
auto-disable only the node that behaves abnormally.

## Signer Files

Recommended local signer paths:

```text
/etc/myzerossl/clients.json
/etc/myzerossl/revoked-clients.txt
/var/log/myzerossl/signer-audit.jsonl
```

Create the directories before starting the local signer:

```sh
install -d -m 0750 /etc/myzerossl /var/log/myzerossl
```

`clients.json`:

```json
{
  "clients": [
    {
      "id": "tw-edge",
      "token": "replace-with-a-long-random-token-for-tw",
      "private_key": "/etc/openresty/ssl/alternate.example.net.key.pem",
      "private_keys": {
        "alt": "/etc/openresty/ssl/alternate.example.net.key.pem"
      },
      "rate_per_minute": 20000,
      "auto_disable_signs_per_minute": 0,
      "auto_disable_errors_per_minute": 0,
      "auto_revoke": false
    },
    {
      "id": "hk-edge",
      "token": "replace-with-a-long-random-token-for-hk",
      "rate_per_minute": 20000,
      "auto_disable_signs_per_minute": 0,
      "auto_disable_errors_per_minute": 0,
      "auto_revoke": false
    }
  ]
}
```

`private_key` and `private_keys` are optional. When both are omitted,
`keylessd` uses the default `KEYLESS_PRIVATE_KEY`. `private_key` changes the
default key for that client token. `private_keys` allows the same client token
to request named keys, such as `alt`, while keeping all private keys on the
trusted signer host.

Field behavior:

- `rate_per_minute`: soft limit. Further signing requests are rejected until
  the next minute window.
- `auto_disable_signs_per_minute`: optional hard per-minute threshold. If set,
  requests over the threshold are denied for the current window.
- `auto_disable_errors_per_minute`: optional hard error threshold. If set,
  requests over the threshold are denied for the current window.
- `auto_revoke`: when `true`, the auto-disable thresholds also append the
  client id to `revoked-clients.txt`. Leave this `false` for Cloudflare-facing
  edge nodes so a probe burst cannot permanently disable a healthy region.
- `disabled`: optional manual kill switch in `clients.json`.

## Edge Files

Each edge VPS receives only its own token:

```sh
KEYLESS_CLIENT_ID=tw-edge
KEYLESS_TOKEN=replace-with-a-long-random-token-for-tw
```

The client id is for logs and operator clarity. The signer authorizes by token
and maps the token to the configured client id.

## Automatic Revocation

Manual revocation appends the client id to:

```text
/etc/myzerossl/revoked-clients.txt
```

The client is denied immediately after restart because the revoked file is
loaded at startup. Automatic permanent revocation is disabled by default; enable
`auto_revoke` only for tightly controlled clients where a false positive is less
harmful than leaving the token active.

To manually revoke an edge:

```sh
printf '%s\n' tw-edge >> /etc/myzerossl/revoked-clients.txt
systemctl restart keylessd-local
```

To restore an edge after investigation, remove its line from
`revoked-clients.txt`, rotate its token in `clients.json`, update the edge VPS,
and restart `keylessd-local`.

## Audit Logs

`keylessd` writes JSON lines:

```json
{"time":"2026-05-27T00:00:00Z","client_id":"tw-edge","remote_addr":"127.0.0.1:12345","action":"sign","result":"ok"}
```

Watch recent activity:

```sh
tail -f /var/log/myzerossl/signer-audit.jsonl
```

Find auto-disable events:

```sh
grep 'auto-disabled' /var/log/myzerossl/signer-audit.jsonl
```

## Cloudflare Layer

If Cloudflare is trusted, keep `gateway.js.gripe/api/v1/ssl-signer` behind
Cloudflare and add WAF/rate-limit rules for that path. The signer should still
enforce its own per-client thresholds because an edge VPS compromise can leak
that node's token.
