#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

install -d -m 0755 /etc/myzerossl /etc/myzerossl/certs /etc/myzerossl/keyless /var/log/myzerossl
id myzerossl >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin myzerossl

install -m 0755 dist/linux-amd64/edgeproxy /usr/local/bin/edgeproxy
install -m 0644 deploy/systemd/edgeproxy.service /etc/systemd/system/edgeproxy.service

if [ ! -f /etc/myzerossl/edgeproxy.env ]; then
  install -m 0600 deploy/env/edgeproxy.env.example /etc/myzerossl/edgeproxy.env
fi

chown -R root:myzerossl /etc/myzerossl
chmod 0750 /etc/myzerossl /etc/myzerossl/certs /etc/myzerossl/keyless
chmod 0640 /etc/myzerossl/edgeproxy.env
chown -R myzerossl:myzerossl /var/log/myzerossl

systemctl daemon-reload
systemctl enable edgeproxy.service

echo "installed edgeproxy; edit /etc/myzerossl/edgeproxy.env and place cert files, then run:"
echo "  systemctl restart edgeproxy"
