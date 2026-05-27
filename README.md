# myzerossl

`myzerossl` is a Go Keyless SSL edge proxy. Edge VPS nodes keep only the public
certificate chain. The private key stays on a trusted signing server, and the
edge asks that server to sign TLS handshake payloads through Go's
`crypto.Signer`.

This is designed for low-trust origin or edge VPS nodes, such as small Hong Kong
and Taiwan nodes behind Cloudflare Load Balancing.

## Topology

```text
Visitor
  -> Cloudflare Proxy / Load Balancer
  -> HK edge VPS 45.196.218.152 or TW edge VPS 136.0.54.54
       edgeproxy: public cert chain only, no private key
  -> trusted keyless signer
       keylessd: owns the certificate private key
  -> backend service
```

The signer is security-sensitive. Anyone who can make arbitrary signing requests
to it can complete TLS handshakes for the certificate. Protect it with mTLS,
firewall rules, private networking, and logs.

## Components

- `cmd/keylessd`: private-key signing API. Run this only on a trusted server.
- `cmd/edgeproxy`: HTTPS reverse proxy. Run this on untrusted edge VPS nodes.
- `deploy/systemd`: Debian 12 systemd unit templates.
- `scripts`: build and install helpers for Debian 12.

## Build Release Binaries

Build on a Linux amd64 host:

```sh
git clone https://github.com/YOUR_ACCOUNT/myzerossl.git
cd myzerossl
./scripts/build-linux-amd64.sh
```

The binaries will be created at:

```text
dist/linux-amd64/keylessd
dist/linux-amd64/edgeproxy
```

## Deploy The Trusted Signer

Run this on the trusted server that is allowed to hold the certificate private
key:

```sh
apt update
apt install -y ca-certificates

git clone https://github.com/YOUR_ACCOUNT/myzerossl.git /opt/myzerossl
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
KEYLESS_LISTEN=10.0.0.10:9443
KEYLESS_PRIVATE_KEY=/etc/myzerossl/private/example.com.key
KEYLESS_TLS_CERT=/etc/myzerossl/keyless/server.crt
KEYLESS_TLS_KEY=/etc/myzerossl/keyless/server.key
KEYLESS_CLIENT_CA=/etc/myzerossl/keyless/edge-client-ca.crt
KEYLESS_TOKEN=
```

Start:

```sh
systemctl restart keylessd
systemctl status keylessd --no-pager -l
```

## Deploy The Taiwan Edge VPS

Target:

```text
136.0.54.54
```

On the Taiwan VPS:

```sh
apt update
apt install -y ca-certificates git

git clone https://github.com/YOUR_ACCOUNT/myzerossl.git /opt/myzerossl
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
KEYLESS_URL=https://10.0.0.10:9443
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

Target:

```text
45.196.218.152
```

Repeat the same steps as the Taiwan edge VPS. Use a different mTLS client
certificate if possible, for example:

```text
/etc/myzerossl/keyless/hk-edge-client.crt
/etc/myzerossl/keyless/hk-edge-client.key
```

Then set `KEYLESS_CLIENT_CERT` and `KEYLESS_CLIENT_KEY` in
`/etc/myzerossl/edgeproxy.env` accordingly.

## Cloudflare Load Balancing

Create two origin endpoints:

```text
TW edge: 136.0.54.54
HK edge: 45.196.218.152
```

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
