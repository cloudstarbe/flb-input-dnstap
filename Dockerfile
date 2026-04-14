ARG UBUNTU_VERSION=20.04
FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies
# - cmake 3.20+ required by Fluent Bit's lib/cfl — installed from Kitware APT repo
# - libssl-dev for ldns's OpenSSL dependency
# - autoconf/automake/libtool/protobuf for building static deps from source
# - libprotobuf-c-dev and libldns-dev for standalone test builds only
# - remaining -dev packages are for Fluent Bit header generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    gpg \
    wget \
    && wget -qO- https://apt.kitware.com/keys/kitware-archive-latest.asc \
      | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ focal main" \
      > /etc/apt/sources.list.d/kitware.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    pkg-config \
    curl \
    ca-certificates \
    flex \
    bison \
    libyaml-dev \
    libssl-dev \
    libnghttp2-dev \
    libc-ares-dev \
    cppcheck \
    autoconf \
    automake \
    libtool \
    protobuf-compiler \
    libprotobuf-dev \
    libprotobuf-c-dev \
    libldns-dev \
    && rm -rf /var/lib/apt/lists/*

# Build static ldns and protobuf-c from source
COPY scripts/build-static-deps.sh /tmp/build-static-deps.sh
RUN /tmp/build-static-deps.sh /usr/local && rm /tmp/build-static-deps.sh

# Clone Fluent Bit source (headers only — no full build needed)
ARG FLB_VERSION=v4.2.4
RUN git clone --depth 1 --branch ${FLB_VERSION} \
    https://github.com/fluent/fluent-bit.git /tmp/fluent-bit \
    && mkdir -p /tmp/fluent-bit/build \
    && cd /tmp/fluent-bit/build \
    && cmake \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DFLB_EXAMPLES=Off \
    -DFLB_SHARED_LIB=Off \
    -DFLB_PROXY_GO=Off \
    ..

WORKDIR /workspaces/fluent-bit
