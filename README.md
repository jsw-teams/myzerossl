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
dist/linux-amd64/setup-wizard
```

## Web Setup Wizard

For first-time deployment on Debian 12, run the local-only web wizard as root:

```sh
./dist/linux-amd64/setup-wizard -listen 127.0.0.1:19500 -repo /opt/myzerossl
```

Then open it through an SSH tunnel from your workstation:

```sh
ssh -L 19500:127.0.0.1:19500 root@your-server
```

Visit `http://127.0.0.1:19500`, choose either:

- `edge 设备`: fill the trusted center console URL and signer verification URL.
  The wizard writes `edgeproxy.env`, installs the service, and configures
  zero-SSH self-enrollment.
- `高信任中心`: fill the private key path, console public URL, account-system
  settings, and public signer URL. The wizard deploys `keylessd-local` and
  `signer-console`, then prints the values edge devices should use.

The wizard refuses non-local listen addresses because it can write `/etc`,
install systemd units, and restart services.

## Edge CDN Behavior

`edgeproxy` keeps the low-trust model: cache contents are disposable, and the
TLS private key never leaves the trusted signer.

Static cache:

- Caches only `GET` and `HEAD` responses with status `200`.
- Caches only when the origin explicitly allows shared caching with
  `Cache-Control: public`, `s-maxage`, or `max-age`.
- Uses origin `s-maxage` first, then `max-age`; `EDGE_CACHE_TTL` is only the
  fallback TTL for explicitly public responses without an age directive.
- Skips responses with `Cache-Control: private`, `no-store`, or `no-cache`.
- Skips responses with `Set-Cookie` and requests with `Authorization`.
- Stores objects in an in-memory LRU cache. A restart drops the cache.
- Adds `X-Memecdn-Cache: MISS` when filling cache and `X-Memecdn-Cache: HIT`
  when serving from cache.

Dynamic compression:

- Uses fast gzip for dynamic `text/*`, JSON, JavaScript, and XML responses when
  the client sends `Accept-Encoding: gzip`.
- Skips `HEAD`, upgraded connections, and already-compressed responses.
- Adds `X-Memecdn-Compression: gzip` when compression is applied.

Edge tuning:

```sh
EDGE_CACHE_TTL=10m
EDGE_CACHE_MAX_BYTES=67108864
EDGE_CACHE_MAX_OBJECT_BYTES=4194304
```

These defaults are intentionally memory-bounded for 1C1G VPS nodes.

Set cache policy on the trusted origin or local OpenResty/app, not in
`edgeproxy`. For example:

```nginx
location /assets/ {
    add_header Cache-Control "public, max-age=600, s-maxage=600" always;
}
```

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
- A single-background pixel UI with a sticky footer and approval workflow for
  edge self-enrollment.
- SEO description and Open Graph metadata.
- `/llms.txt` for LLM-friendly service context.

New edge devices are not trusted automatically. They submit a pending
registration request and appear in the console. A system administrator must
approve the request before a signer client is generated. In the normal zero-SSH
flow, `edgeproxy` submits the request itself over HTTPS, polls for approval,
fetches its signer token through a one-time JSON endpoint, writes the token to a
local token file, and verifies it by connecting to the trusted signer. A fresh
production `/etc/myzerossl/clients.json` should contain no active clients:

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
KEYLESS_TOKEN_FILE=/var/lib/memecdn/keyless.token
EDGE_CACHE_TTL=10m
EDGE_CACHE_MAX_BYTES=67108864
EDGE_CACHE_MAX_OBJECT_BYTES=4194304
EDGE_REGISTER_URL=https://ssl-signer.js.gripe
EDGE_REGISTER_ID=tw-edge
EDGE_REGISTER_LABEL=Taiwan edge
EDGE_REGISTER_TOKEN=
EDGE_REGISTER_POLL=10s
KEYLESS_URL=https://10.0.0.10:9443
KEYLESS_CLIENT_ID=tw-edge
KEYLESS_CA=/etc/myzerossl/keyless/ca.crt
KEYLESS_CLIENT_CERT=/etc/myzerossl/keyless/edge-client.crt
KEYLESS_CLIENT_KEY=/etc/myzerossl/keyless/edge-client.key
KEYLESS_TOKEN=
```

When `KEYLESS_TOKEN` and `KEYLESS_TOKEN_FILE` are empty, `edgeproxy` registers
itself with the signer console using `EDGE_REGISTER_*`. After approval, it
fetches the signer token, writes it to `KEYLESS_TOKEN_FILE`, then connects to
`KEYLESS_URL`; that connection validates the token before the public HTTPS
listener starts. Once validation succeeds, the edge reports the install as
verified to the console. No SSH from the console to the edge is part of the
product flow.

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

When an edge self-enrolls, the trusted console can return `edge_config` such as
`KEYLESS_URL`. The edge uses that central value when the local env leaves it
blank; local env values remain explicit overrides or fallback settings.

## Cloudflare Load Balancing

Create two origin pools in Cloudflare, named by region. For the first batch:

- `HK`: Hong Kong/APAC optimized edge.
- `US`: trusted primary origin and global fallback.

Keep the actual origin IPs in Cloudflare and your private deployment notes, not
in this public README.

Recommended settings:

- Proxy status: proxied.
- SSL/TLS mode: Full strict.
- Monitor: `HC`, HTTPS `GET /healthz`, expected code `200`, request header
  `Host: js.gripe`.
- Health check path: `/healthz` on the backend you expose through `EDGE_BACKEND`.
- Steering: Proximity when region-level steering is unavailable. Keep `US` as
  the fallback pool so APAC can prefer `HK` while other regions and HK failures
  fall back to `US`.
- Session affinity: `ip_cookie` for steadier user routing.
- Adaptive routing: enabled for failover across healthy pools.
- Cache static assets at Cloudflare and set origin `Cache-Control` headers for
  memecdn edge cache hits on 1C1G nodes.

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
