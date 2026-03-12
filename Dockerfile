ARG DEBIAN_VERSION=bookworm
FROM debian:${DEBIAN_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    pkg-config \
    protobuf-c-compiler \
    libprotobuf-c-dev \
    libldns-dev \
    flex \
    bison \
    libyaml-dev \
    libssl-dev \
    libnghttp2-dev \
    ca-certificates \
    cppcheck \
    && rm -rf /var/lib/apt/lists/*

# Clone Fluent Bit source (headers only — no full build needed)
ARG FLB_VERSION=v4.2.3
RUN git clone --depth 1 --branch ${FLB_VERSION} \
    https://github.com/fluent/fluent-bit.git /tmp/fluent-bit \
    && mkdir -p /tmp/fluent-bit/build \
    && cd /tmp/fluent-bit/build \
    && cmake \
    -DFLB_EXAMPLES=Off \
    -DFLB_SHARED_LIB=Off \
    -DFLB_PROXY_GO=Off \
    ..

WORKDIR /workspaces/fluent-bit
