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

Do not place the location include directly in `conf.d/*.conf`; that directory is
loaded at the top-level `http` context. Copy it to:

```text
/usr/local/openresty/nginx/conf/includes/gateway.ssl-signer.locations.inc
```

Then verify and reload:

```sh
/usr/local/openresty/nginx/sbin/nginx -t
systemctl reload openresty
```

The edge nodes should use:

```sh
KEYLESS_URL=https://gateway.js.gripe/api/v1/ssl-signer
```

Keep `KEYLESS_TOKEN` private. Do not commit it to this repository.

## Admin Console

The optional admin console is exposed through:

```text
https://ssl-signer.js.gripe
```

Install `deploy/openresty/ssl-signer-console.conf` into `conf.d/` and run
`signer-console.service`. The console uses account-system third-party login and
only allows users with the `system_admin` role.
