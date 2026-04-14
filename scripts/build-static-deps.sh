#!/usr/bin/env bash
# Build ldns and protobuf-c as static -fPIC archives for embedding into the plugin .so.
# Usage: ./scripts/build-static-deps.sh [install-prefix]
#   Default prefix: /usr/local
set -euo pipefail

PREFIX="${1:-/usr/local}"
LDNS_VERSION="1.8.4"
PROTOBUF_C_VERSION="1.5.0"
JOBS="$(nproc)"

echo "==> Building static dependencies into ${PREFIX}"

# --- protobuf-c ---
echo "--- protobuf-c ${PROTOBUF_C_VERSION} ---"
cd /tmp
curl -sSL "https://github.com/protobuf-c/protobuf-c/releases/download/v${PROTOBUF_C_VERSION}/protobuf-c-${PROTOBUF_C_VERSION}.tar.gz" \
  | tar xz
cd "protobuf-c-${PROTOBUF_C_VERSION}"
./configure \
  --prefix="${PREFIX}" \
  --disable-shared \
  --enable-static \
  --with-pic \
  --disable-protoc \
  CFLAGS="-O2 -fPIC"
make -j"${JOBS}"
make install
cd /tmp && rm -rf "protobuf-c-${PROTOBUF_C_VERSION}"

# --- ldns ---
echo "--- ldns ${LDNS_VERSION} ---"
cd /tmp
curl -sSL "https://www.nlnetlabs.nl/downloads/ldns/ldns-${LDNS_VERSION}.tar.gz" \
  | tar xz
cd "ldns-${LDNS_VERSION}"
./configure \
  --prefix="${PREFIX}" \
  --disable-shared \
  --enable-static \
  --with-pic \
  --with-ssl \
  --disable-dane-ta-usage \
  --disable-gost \
  --disable-ecdsa \
  CFLAGS="-O2 -fPIC"
make -j"${JOBS}"
make install
cd /tmp && rm -rf "ldns-${LDNS_VERSION}"

echo "==> Static libraries installed to ${PREFIX}/lib"
echo "    $(ls -la ${PREFIX}/lib/libldns.a ${PREFIX}/lib/libprotobuf-c.a)"
