#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist/linux-amd64

export GOCACHE="${GOCACHE:-/tmp/myzerossl-go-build}"

go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/linux-amd64/keylessd ./cmd/keylessd
go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/linux-amd64/edgeproxy ./cmd/edgeproxy
