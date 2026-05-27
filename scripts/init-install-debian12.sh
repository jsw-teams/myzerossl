#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

prompt() {
  label="$1"
  default="${2:-}"
  if [ -n "$default" ]; then
    printf '%s [%s]: ' "$label" "$default" >&2
  else
    printf '%s: ' "$label" >&2
  fi
  read -r value
  if [ -z "$value" ]; then
    value="$default"
  fi
  printf '%s' "$value"
}

secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n'
  else
    dd if=/dev/urandom bs=48 count=1 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=\n'
  fi
}

write_env() {
  path="$1"
  shift
  tmp="$(mktemp)"
  while [ "$#" -gt 0 ]; do
    key="$1"
    value="$2"
    shift 2
    escaped="$(printf '%s' "$value" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    printf '%s="%s"\n' "$key" "$escaped" >> "$tmp"
  done
  install -m 0640 "$tmp" "$path"
  rm -f "$tmp"
}

ensure_build() {
  if [ ! -x dist/linux-amd64/edgeproxy ] || [ ! -x dist/linux-amd64/keylessd ] || [ ! -x dist/linux-amd64/signer-console ] || [ ! -x dist/linux-amd64/setup-wizard ]; then
    GOCACHE="${GOCACHE:-/tmp/memecdn-go-build}" ./scripts/build-linux-amd64.sh
  fi
}

ensure_user() {
  id myzerossl >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin myzerossl
}

install_edge() {
  ensure_build
  ensure_user

  console_url="$(prompt 'Trusted center console URL' 'https://ssl-signer.example.com')"
  keyless_url="$(prompt 'Trusted signer verification URL' 'https://gateway.example.com:9443/api/v1/ssl-signer')"
  edge_id="$(prompt 'Edge client id' "$(hostname)-edge")"
  edge_label="$(prompt 'Edge label' "$edge_id")"
  backend="$(prompt 'Backend origin URL' 'http://127.0.0.1:8080')"
  listen="$(prompt 'HTTPS listen addresses' ':443,:2053,:2083,:2087,:2096,:8443')"
  cert_path="$(prompt 'Public certificate chain path' '/etc/myzerossl/certs/example.com.fullchain.crt')"
  ca_path="$(prompt 'Trusted signer CA path' '/etc/ssl/certs/ca-certificates.crt')"
  client_cert="$(prompt 'mTLS client certificate path' '/etc/myzerossl/keyless/edge-client.crt')"
  client_key="$(prompt 'mTLS client key path' '/etc/myzerossl/keyless/edge-client.key')"
  install_token="$(secret)"

  install -d -m 0755 /etc/myzerossl /etc/myzerossl/certs /etc/myzerossl/keyless /var/log/myzerossl /var/lib/memecdn
  install -m 0755 dist/linux-amd64/edgeproxy /usr/local/bin/edgeproxy
  install -m 0644 deploy/systemd/edgeproxy.service /etc/systemd/system/edgeproxy.service
  write_env /etc/myzerossl/edgeproxy.env \
    EDGE_LISTEN "$listen" \
    EDGE_BACKEND "$backend" \
    EDGE_CERT "$cert_path" \
    KEYLESS_TOKEN_FILE "/var/lib/memecdn/keyless.token" \
    EDGE_CACHE_TTL "10m" \
    EDGE_CACHE_MAX_BYTES "67108864" \
    EDGE_CACHE_MAX_OBJECT_BYTES "4194304" \
    EDGE_REGISTER_URL "$console_url" \
    EDGE_REGISTER_ID "$edge_id" \
    EDGE_REGISTER_LABEL "$edge_label" \
    EDGE_REGISTER_TOKEN "$install_token" \
    EDGE_REGISTER_POLL "10s" \
    KEYLESS_URL "$keyless_url" \
    KEYLESS_CLIENT_ID "$edge_id" \
    KEYLESS_CA "$ca_path" \
    KEYLESS_CLIENT_CERT "$client_cert" \
    KEYLESS_CLIENT_KEY "$client_key" \
    KEYLESS_TOKEN ""

  chown -R root:myzerossl /etc/myzerossl
  chmod 0750 /etc/myzerossl /etc/myzerossl/certs /etc/myzerossl/keyless
  chmod 0640 /etc/myzerossl/edgeproxy.env
  chown -R myzerossl:myzerossl /var/log/myzerossl /var/lib/memecdn

  systemctl daemon-reload
  systemctl enable edgeproxy.service

  cat <<EOF

Edge configured.

Place these files before starting edgeproxy:
  $cert_path
  $client_cert
  $client_key

Then run:
  systemctl restart edgeproxy

The edge will register itself at:
  $console_url

Approve edge id "$edge_id" in the trusted console. After approval, edgeproxy
will fetch its signer token over HTTPS, store it in /var/lib/memecdn/keyless.token,
verify with the trusted signer, and then start serving traffic.
EOF
}

install_trusted() {
  ensure_build
  ensure_user

  private_key="$(prompt 'Certificate private key path' '/etc/openresty/ssl/js.gripe.key.pem')"
  console_url="$(prompt 'Console public URL' 'https://ssl-signer.example.com')"
  account_api="$(prompt 'account-system API base' 'https://gateway.example.com/api/v1/myaccount')"
  account_login="$(prompt 'account-system login URL' 'https://account.example.com/login')"
  account_client_id="$(prompt 'account-system client_id' '')"
  session_secret="$(prompt 'Console session secret' "$(secret)")"
  keyless_listen="$(prompt 'Local keyless listen address' '127.0.0.1:19443')"
  keyless_url="$(prompt 'Public keyless signer URL for edges' 'https://gateway.example.com:9443/api/v1/ssl-signer')"

  install -d -m 0755 /etc/myzerossl /etc/myzerossl/private /etc/myzerossl/keyless /var/log/myzerossl
  install -m 0755 dist/linux-amd64/keylessd /usr/local/bin/keylessd
  install -m 0755 dist/linux-amd64/signer-console /usr/local/bin/signer-console
  install -m 0644 deploy/systemd/keylessd-local.service /etc/systemd/system/keylessd-local.service
  install -m 0644 deploy/systemd/signer-console.service /etc/systemd/system/signer-console.service

  write_env /etc/myzerossl/keylessd-local.env \
    KEYLESS_LISTEN "$keyless_listen" \
    KEYLESS_PRIVATE_KEY "$private_key" \
    KEYLESS_TOKEN "" \
    KEYLESS_CLIENTS "/etc/myzerossl/clients.json" \
    KEYLESS_REVOKED "/etc/myzerossl/revoked-clients.txt" \
    KEYLESS_AUDIT "/var/log/myzerossl/signer-audit.jsonl"
  write_env /etc/myzerossl/signer-console.env \
    CONSOLE_LISTEN "127.0.0.1:19444" \
    CONSOLE_ACCOUNT_API "$account_api" \
    CONSOLE_ACCOUNT_LOGIN "$account_login" \
    CONSOLE_PUBLIC_URL "$console_url" \
    CONSOLE_CLIENT_ID "$account_client_id" \
    CONSOLE_SESSION_SECRET "$session_secret" \
    KEYLESS_CLIENTS "/etc/myzerossl/clients.json" \
    KEYLESS_REVOKED "/etc/myzerossl/revoked-clients.txt" \
    KEYLESS_AUDIT "/var/log/myzerossl/signer-audit.jsonl" \
    CONSOLE_REGISTRATIONS "/etc/myzerossl/edge-registrations.json"

  [ -f /etc/myzerossl/clients.json ] || printf '{\n  "clients": []\n}\n' > /etc/myzerossl/clients.json
  [ -f /etc/myzerossl/revoked-clients.txt ] || : > /etc/myzerossl/revoked-clients.txt
  [ -f /etc/myzerossl/edge-registrations.json ] || printf '{\n  "registrations": []\n}\n' > /etc/myzerossl/edge-registrations.json

  chown -R root:myzerossl /etc/myzerossl
  chmod 0750 /etc/myzerossl /etc/myzerossl/private /etc/myzerossl/keyless
  chmod 0640 /etc/myzerossl/keylessd-local.env /etc/myzerossl/signer-console.env /etc/myzerossl/clients.json /etc/myzerossl/revoked-clients.txt /etc/myzerossl/edge-registrations.json
  chown -R myzerossl:myzerossl /var/log/myzerossl

  systemctl daemon-reload
  systemctl enable keylessd-local.service signer-console.service
  systemctl restart keylessd-local.service signer-console.service

  cat <<EOF

Trusted center deployed.

Expose these local services through your reverse proxy:
  signer console: http://127.0.0.1:19444 -> $console_url
  keyless signer: http://$keyless_listen -> $keyless_url

Edge devices should use:
  EDGE_REGISTER_URL=$console_url
  KEYLESS_URL=$keyless_url
  KEYLESS_TOKEN_FILE=/var/lib/memecdn/keyless.token

On each edge, run this initializer and choose "edge". After the edge appears in
the console, approve it. The edge will fetch and verify its token without SSH.
EOF
}

role="${1:-}"
if [ -z "$role" ]; then
  role="$(prompt 'Registration type: edge or trusted' 'edge')"
fi

case "$role" in
  edge)
    install_edge
    ;;
  trusted|center|trusted-center)
    install_trusted
    ;;
  *)
    echo "unknown registration type: $role" >&2
    echo "usage: $0 [edge|trusted]" >&2
    exit 2
    ;;
esac
