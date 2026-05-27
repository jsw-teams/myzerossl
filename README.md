# memecdn

`memecdn` is a low-trust Go edge CDN and Keyless SSL proxy. Edge VPS nodes keep
only the public certificate chain, cache static objects in memory, and compress
dynamic text responses for faster regional delivery. The private key stays on a
trusted signing server, and the edge asks that server to sign TLS handshake
payloads through Go's `crypto.Signer`.

This is designed for low-trust origin or edge VPS nodes, such as small Hong Kong
and Taiwan nodes behind Cloudflare Load Balancing.

## Topology

```text
Visitor
  -> Cloudflare Proxy / Load Balancer
  -> Hong Kong edge VPS or Taiwan edge VPS
       edgeproxy: public cert chain only, static cache, dynamic gzip
  -> trusted keyless signer
       keylessd: owns the certificate private key
  -> backend service
```

The signer is security-sensitive. Anyone who can make arbitrary signing requests
to it can complete TLS handshakes for the certificate. Protect it with mTLS,
firewall rules, private networking, and logs.

## Components

- `cmd/keylessd`: private-key signing API. Run this only on a trusted server.
- `cmd/edgeproxy`: low-trust HTTPS edge CDN proxy. Run this on untrusted edge
  VPS nodes.
- `cmd/signer-console`: pixel-style web console protected by account-system
  system administrator login.
- `deploy/systemd`: Debian 12 systemd unit templates.
- `scripts`: build and install helpers for Debian 12.
- `docs/abuse-monitoring.md`: per-edge client tokens, audit logging, and
  automatic revocation.
- `docs/signer-console.md`: account-system protected admin console.

## Build Release Binaries

Build on a Linux amd64 host:

```sh
git clone https://github.com/jsw-teams/memecdn.git
cd memecdn
./scripts/build-linux-amd64.sh
```

The binaries will be created at:

```text
dist/linux-amd64/keylessd
dist/linux-amd64/edgeproxy
dist/linux-amd64/signer-console
```

## Edge CDN Behavior

`edgeproxy` keeps the low-trust model: cache contents are disposable, and the
TLS private key never leaves the trusted signer.

Static cache:

- Caches only `GET` and `HEAD` responses with status `200`.
- Caches common static extensions such as CSS, JS, images, fonts, WASM, media,
  JSON, TXT, XML, and source maps.
- Skips responses with `Cache-Control: private`, `no-store`, or `no-cache`.
- Skips responses with `Set-Cookie` and requests with `Authorization`.
- Stores objects in an in-memory LRU cache. A restart drops the cache.
- Adds `X-Memecdn-Cache: MISS` when filling cache and `X-Memecdn-Cache: HIT`
  when serving from cache.

Dynamic compression:

- Uses fast gzip for dynamic `text/*`, JSON, JavaScript, and XML responses when
  the client sends `Accept-Encoding: gzip`.
- Skips static assets, `HEAD`, upgraded connections, and already-compressed
  responses.
- Adds `X-Memecdn-Compression: gzip` when compression is applied.

Edge tuning:

```sh
EDGE_CACHE_TTL=10m
EDGE_CACHE_MAX_BYTES=67108864
EDGE_CACHE_MAX_OBJECT_BYTES=4194304
```

These defaults are intentionally memory-bounded for 1C1G VPS nodes.

Quick validation after deployment:

```sh
# First static request should fill cache, second should hit.
curl -sk https://blog.example.com/assets/site.css -o /dev/null -D - \
  | grep -i x-memecdn-cache
curl -sk https://blog.example.com/assets/site.css -o /dev/null -D - \
  | grep -i x-memecdn-cache

# Dynamic text/HTML/JSON should be gzip-compressed when the client supports it.
curl -sk -H 'Accept-Encoding: gzip' https://blog.example.com/ -o /dev/null -D - \
  | grep -Ei 'content-encoding|x-memecdn-compression'
```

## Signer Console

The trusted host can expose a management console at:

```text
https://ssl-signer.js.gripe
```

The console includes:

- Public introduction page.
- account-system login page.
- system_admin-only dashboard.
- Pixel-art black bear wrench icon.
- Browser-language aware Simplified Chinese, Traditional Chinese, and English
  copy.
- Responsive layouts for desktop, tablet, and mobile viewports.
- A single-background pixel UI with a sticky footer and one-time edge install
  command dialog.
- SEO description and Open Graph metadata.
- `/llms.txt` for LLM-friendly service context.

New edge devices are not trusted automatically. They submit a pending
registration request and appear in the console. A system administrator must
approve the request before a signer client is generated. Approval shows a
one-time install command, not the real signer token. Run the command as root on
the matching edge VPS; it fetches the token through a one-time link, writes
`KEYLESS_TOKEN` into `/etc/myzerossl/edgeproxy.env`, and restarts `edgeproxy`.
The install command is cleared from the page when the dialog closes. A fresh production
`/etc/myzerossl/clients.json` should contain no active clients:

```json
{
  "clients": []
}
```

## Deploy The Trusted Signer

Run this on the trusted server that is allowed to hold the certificate private
key. If you already have `gateway.js.gripe` on this trusted host, you can expose
the signer at:

```text
https://gateway.js.gripe/api/v1/ssl-signer
```

In this mode `keylessd` listens on localhost HTTP and OpenResty provides the
public HTTPS entrypoint.

```sh
apt update
apt install -y ca-certificates

git clone https://github.com/jsw-teams/memecdn.git /opt/myzerossl
cd /opt/myzerossl
./scripts/build-linux-amd64.sh
./scripts/install-keylessd-debian12.sh
```

Place files:

```text
/etc/myzerossl/private/example.com.key
/etc/myzerossl/keyless/server.crt
/etc/myzerossl/keyless/server.key
/etc/myzerossl/keyless/edge-client-ca.crt
```

Edit:

```sh
nano /etc/myzerossl/keylessd.env
```

Example:

```sh
KEYLESS_LISTEN=127.0.0.1:19443
KEYLESS_PRIVATE_KEY=/etc/myzerossl/private/example.com.key
KEYLESS_TLS_CERT=
KEYLESS_TLS_KEY=
KEYLESS_CLIENT_CA=
KEYLESS_TOKEN=replace-with-a-long-random-secret
```

Start:

```sh
systemctl restart keylessd
systemctl status keylessd --no-pager -l
```

For the `gateway.js.gripe` OpenResty entrypoint, see
`deploy/openresty/README.md`. The edge nodes should then use:

```sh
KEYLESS_URL=https://gateway.js.gripe/api/v1/ssl-signer
KEYLESS_TOKEN=replace-with-the-same-long-random-secret
```

This repository also includes `deploy/systemd/keylessd-local.service` and
`deploy/env/keylessd-local.env.example` for this localhost signer mode.

For low-trust VPS nodes, do not use one shared token for every edge. Configure
one signer client per VPS with automatic abuse thresholds. See
`docs/abuse-monitoring.md`.

## Deploy The Taiwan Edge VPS

On the Taiwan VPS:

```sh
apt update
apt install -y ca-certificates git

git clone https://github.com/jsw-teams/memecdn.git /opt/myzerossl
cd /opt/myzerossl
./scripts/build-linux-amd64.sh
./scripts/install-edge-debian12.sh
```

Place files:

```text
/etc/myzerossl/certs/example.com.fullchain.crt
/etc/myzerossl/keyless/ca.crt
/etc/myzerossl/keyless/edge-client.crt
/etc/myzerossl/keyless/edge-client.key
```

The edge VPS does not receive `example.com.key`.

Edit:

```sh
nano /etc/myzerossl/edgeproxy.env
```

Example:

```sh
EDGE_LISTEN=:443
EDGE_BACKEND=http://127.0.0.1:8080
EDGE_CERT=/etc/myzerossl/certs/example.com.fullchain.crt
EDGE_CACHE_TTL=10m
EDGE_CACHE_MAX_BYTES=67108864
EDGE_CACHE_MAX_OBJECT_BYTES=4194304
KEYLESS_URL=https://10.0.0.10:9443
KEYLESS_CLIENT_ID=tw-edge
KEYLESS_CA=/etc/myzerossl/keyless/ca.crt
KEYLESS_CLIENT_CERT=/etc/myzerossl/keyless/edge-client.crt
KEYLESS_CLIENT_KEY=/etc/myzerossl/keyless/edge-client.key
KEYLESS_TOKEN=
```

Start:

```sh
systemctl restart edgeproxy
systemctl status edgeproxy --no-pager -l
```

## Deploy The Hong Kong Edge VPS

Repeat the same steps as the Taiwan edge VPS. Use a different mTLS client
certificate if possible, for example:

```text
/etc/myzerossl/keyless/hk-edge-client.crt
/etc/myzerossl/keyless/hk-edge-client.key
```

Then set `KEYLESS_CLIENT_CERT` and `KEYLESS_CLIENT_KEY` in
`/etc/myzerossl/edgeproxy.env` accordingly.

## Cloudflare Load Balancing

Create two origin endpoints in Cloudflare, one for the Taiwan edge VPS and one
for the Hong Kong edge VPS. Keep the actual origin IPs in Cloudflare and your
private deployment notes, not in this public README.

Recommended settings:

- Proxy status: proxied.
- SSL/TLS mode: Full strict.
- Health check path: `/healthz` on the backend you expose through `EDGE_BACKEND`.
- Steering: Random for active-active, or Geo steering if you want Taiwan/Hong
  Kong routing preferences.
- Cache static assets at Cloudflare to reduce origin bandwidth on 1C1G nodes.

## Notes For 1C1G / 5G VPS Nodes

- Run only `edgeproxy`, OpenResty, or a very small backend on these nodes.
- Do not build large Node/Astro projects on the VPS if disk is tight. Build
  elsewhere and deploy artifacts.
- Keep logs rotated. 5G disks fill quickly.
- Prefer Cloudflare cache for static files.
- Keep the private key off the edge. Only the public certificate chain belongs
  under `/etc/myzerossl/certs`.

## Local Lab

For quick local testing without mTLS:

```sh
./keylessd -listen 127.0.0.1:9443 -key ./example.com.key -token dev-secret
./edgeproxy \
  -listen :8443 \
  -backend http://127.0.0.1:8080 \
  -cert ./example.com.fullchain.crt \
  -keyless-url http://127.0.0.1:9443 \
  -token dev-secret
```

Use token-only mode only for labs. Production should use mTLS and firewall
controls.
