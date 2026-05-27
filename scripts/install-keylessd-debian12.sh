#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

install -d -m 0755 /etc/myzerossl /etc/myzerossl/private /etc/myzerossl/keyless /var/log/myzerossl
id myzerossl >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin myzerossl

install -m 0755 dist/linux-amd64/keylessd /usr/local/bin/keylessd
install -m 0644 deploy/systemd/keylessd.service /etc/systemd/system/keylessd.service

if [ ! -f /etc/myzerossl/keylessd.env ]; then
  install -m 0600 deploy/env/keylessd.env.example /etc/myzerossl/keylessd.env
fi

chown -R root:myzerossl /etc/myzerossl
chmod 0750 /etc/myzerossl /etc/myzerossl/private /etc/myzerossl/keyless
chmod 0640 /etc/myzerossl/keylessd.env
chown -R myzerossl:myzerossl /var/log/myzerossl

systemctl daemon-reload
systemctl enable keylessd.service

echo "installed keylessd; edit /etc/myzerossl/keylessd.env and place key/cert files, then run:"
echo "  systemctl restart keylessd"
