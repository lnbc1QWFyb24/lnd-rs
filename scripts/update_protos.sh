#!/usr/bin/env bash
set -euo pipefail

# Fetch LND protos for a given release tag, mirroring lnc-core behavior
# Usage: scripts/update_protos.sh v0.17.5-beta

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <LND_RELEASE_TAG>" >&2
  exit 1
fi

LND_RELEASE_TAG="$1"
LND_URL="https://raw.githubusercontent.com/lightningnetwork/lnd"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_DIR="$ROOT_DIR/protos/lnd/$LND_RELEASE_TAG"

rm -rf "$ROOT_DIR/protos/lnd" && mkdir -p "$PROTO_DIR"

fetch() {
  local src="$1"; local dst="$2";
  echo "Fetch $src -> $dst"
  curl -sSfL "$src" --create-dirs -o "$dst"
}

fetch "$LND_URL/$LND_RELEASE_TAG/lnrpc/lightning.proto" "$PROTO_DIR/lightning.proto"
fetch "$LND_URL/$LND_RELEASE_TAG/lnrpc/signrpc/signer.proto" "$PROTO_DIR/signrpc/signer.proto"
fetch "$LND_URL/$LND_RELEASE_TAG/lnrpc/walletrpc/walletkit.proto" "$PROTO_DIR/walletrpc/walletkit.proto"

echo "Done. Set LND_TAG=$LND_RELEASE_TAG for build.rs or rely on first tag directory."
