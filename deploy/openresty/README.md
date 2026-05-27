# OpenResty Gateway Mount

Use this only on a trusted host that already terminates HTTPS for
`gateway.js.gripe`.

`keylessd-local.service` listens on:

```text
127.0.0.1:19443
```

Add this upstream in the `http` context before the `gateway.js.gripe` server:

```nginx
upstream ssl_signer_backend {
    server 127.0.0.1:19443;
    keepalive 8;
}
```

Then include the location file inside the HTTPS `server` block for
`gateway.js.gripe`:

```nginx
include /usr/local/openresty/nginx/conf/includes/gateway.ssl-signer.locations.inc;
```

This preserves the existing `gateway.js.gripe` TLS behavior. If that server is
behind a Cloudflare-only allowlist, this token-protected mount is only usable
through Cloudflare.

## Dedicated mTLS Edge Entry

For low-trust edge VPS nodes, prefer the dedicated mTLS listener in
`deploy/openresty/ssl-signer-mtls.conf`. It listens on `9443`, proxies only the
signer path, and does not alter the main `gateway.js.gripe` server used by other
services.

The mTLS listener rejects requests unless the client presents a certificate
signed by:

```text
/etc/myzerossl/keyless/edge-client-ca.crt
```

Generate one CA on the trusted signer host and issue a different client
certificate for every edge VPS. Keep the CA private key only on the trusted
host. Each edge receives only:

```text
/etc/myzerossl/keyless/ca.crt
/etc/myzerossl/keyless/edge-client.crt
/etc/myzerossl/keyless/edge-client.key
```

Install both files:

```text
/usr/local/openresty/nginx/conf/includes/gateway.ssl-signer.locations.inc
/usr/local/openresty/nginx/conf/conf.d/ssl-signer-mtls.conf
```

Then verify and reload:

```sh
/usr/local/openresty/nginx/sbin/nginx -t
systemctl reload openresty
```

The edge nodes should use:

```sh
KEYLESS_URL=https://gateway.js.gripe:9443/api/v1/ssl-signer
KEYLESS_CA=/etc/ssl/certs/ca-certificates.crt
KEYLESS_CLIENT_CERT=/etc/myzerossl/keyless/edge-client.crt
KEYLESS_CLIENT_KEY=/etc/myzerossl/keyless/edge-client.key
```

`KEYLESS_CA` verifies the signer HTTPS server certificate. Use the system CA
bundle for a public Let's Encrypt certificate, or a private server CA only if
the signer HTTPS certificate is privately issued.

If `gateway.js.gripe` is proxied by Cloudflare, configure edge nodes to resolve
`gateway.js.gripe` directly to the trusted signer origin IP, for example through
`/etc/hosts`. Cloudflare does not forward arbitrary client certificates to the
origin for this application-level mTLS check.

Keep `KEYLESS_TOKEN` private. The token remains useful as per-edge revocation
and audit identity even when mTLS is enabled. Do not commit it to this
repository.

## Admin Console

The optional admin console is exposed through:

```text
https://ssl-signer.js.gripe
```

Install `deploy/openresty/ssl-signer-console.conf` into `conf.d/` and run
`signer-console.service`. The console uses account-system third-party login and
only allows users with the `system_admin` role.
