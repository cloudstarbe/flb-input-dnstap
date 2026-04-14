# flb-input-dnstap

[![Build](https://github.com/cloudstarbe/flb-input-dnstap/actions/workflows/build.yml/badge.svg)](https://github.com/cloudstarbe/flb-input-dnstap/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/cloudstarbe/flb-input-dnstap)](https://github.com/cloudstarbe/flb-input-dnstap/releases/latest)
[![License](https://img.shields.io/github/license/cloudstarbe/flb-input-dnstap)](LICENSE)

A Fluent Bit input plugin that receives [dnstap](https://dnstap.info/) logs from DNS servers via a Unix socket.

## Supported Fluent Bit Versions

| Fluent Bit | Status |
|------------|--------|
| 3.0.x      | ✅     |
| 3.1.x      | ✅     |
| 3.2.x      | ✅     |
| 4.0.x      | ✅     |
| 4.1.x      | ✅     |
| 4.2.x      | ✅     |

## Features

- Listens on a Unix socket (`AF_UNIX SOCK_STREAM`) for Frame Streams connections
- Decodes [dnstap](https://dnstap.info/) Protocol Buffers messages using `protobuf-c`
- Parses DNS wire-format messages using `ldns` for full query/response details
- Emits structured Fluent Bit log records with identity, addresses, ports, timestamps, qname, qtype, rcode, etc.
- Compatible with dnsdist, PowerDNS, BIND, Unbound, and any DNS server supporting dnstap

## Architecture

```text
┌──────────────┐  Unix Socket       ┌────────────────────────┐
│  DNS Server  │ ──(framestreams)─▶ │     flb-in_dnstap      │
│  (dnsdist,   │  SOCK_STREAM       │                        │
│   pdns, …)   │                    │  1. dnstap_parser      │
└──────────────┘                    │  2. protobuf-c decode  │
                                    │  3. ldns DNS parse     │
                                    │  4. log_event_encoder  │
                                    │     → FluentBit        │
                                    └────────────────────────┘
```

## Quick Start

### Install from Release

Pre-built binaries are available on the [Releases page](https://github.com/cloudstarbe/flb-input-dnstap/releases). Each release includes a `.so` file compiled natively per Fluent Bit version.

```bash
# Example: Downloading for Fluent Bit v4.2.3
wget https://github.com/cloudstarbe/flb-input-dnstap/releases/download/v1.0.0/flb-in_dnstap-flb4.2.3.so -O /usr/lib/fluent-bit/plugins/flb-in_dnstap.so
```

### Configure

Configure the plugin path in your `plugins.conf` file:

```ini
[PLUGINS]
    Path /usr/lib/fluent-bit/plugins/flb-in_dnstap.so
```

Configure the input element in your `fluent-bit.conf` file:

```ini
[SERVICE]
    Plugins_File /etc/fluent-bit/plugins.conf

[INPUT]
    Name                  dnstap
    socket_path           /var/run/dnstap.sock
    socket_permissions    0666

[OUTPUT]
    Name              stdout
    Match             *
```

### Configuration Options

| Key | Description | Default |
|-----|-------------|---------|
| `socket_path` | Path to the Unix socket | `/var/run/dnstap.sock` |
| `socket_permissions` | Octal permissions for the socket | *(not set)* |
| `max_connections` | Maximum concurrent dnstap connections | `256` |
| `use_dnstap_timestamp` | Use original wire timestamps from dnstap instead of current processing time | `false` |
| `Buffer_Chunk_Size` | Chunk size for the incoming Unix socket buffer | `32K` |
| `Buffer_Max_Size` | Maximum frame limit size for incoming Unix socket data | `2M` |

---

## Output Record Format

Each dnstap event produces a record with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `identity` | string | DNS server identity (NSID) |
| `version` | string | DNS server version |
| `message_type` | string | e.g., `CLIENT_QUERY`, `AUTH_RESPONSE` |
| `socket_family` | string | `INET` or `INET6` |
| `socket_protocol` | string | `UDP`, `TCP`, `DOT`, `DOH`, `DOQ` |
| `query_address` | string | IP address of query initiator |
| `response_address` | string | IP address of responder |
| `query_port` | integer | Transport port of initiator |
| `response_port` | integer | Transport port of responder |
| `query_time` | double | Query timestamp (seconds.nanoseconds) |
| `response_time` | double | Response timestamp (seconds.nanoseconds) |
| `qname` | string | DNS query name (e.g., `www.example.com.`) |
| `qtype` | string | DNS query type (e.g., `A`, `AAAA`, `MX`) |
| `qclass` | string | DNS query class (e.g., `IN`) |
| `rcode` | string | DNS response code (e.g., `NOERROR`, `NXDOMAIN`) |

---

## DNS Server Configuration Examples

### dnsdist
```lua
-- dnsdist.conf
logger = newFrameStreamUnixLogger("/var/run/dnstap.sock")
addAction(AllRule(), DnstapLogAction("dnsdist_server", logger))
addResponseAction(AllRule(), DnstapLogResponseAction("dnsdist_server", logger))
addCacheHitResponseAction(AllRule(), DnstapLogResponseAction("dnsdist_server", logger))
```

### PowerDNS Recursor
```ini
# recursor.conf
dnstapFrameStreamServer("/var/run/dnstap.sock")
```

### BIND 9
```
// named.conf
dnstap { all; };
dnstap-output unix "/var/run/dnstap.sock";
```

### Unbound
```yaml
# unbound.conf
dnstap:
  dnstap-enable: yes
  dnstap-socket-path: "/var/run/dnstap.sock"
  dnstap-send-identity: yes
  dnstap-send-version: yes
  dnstap-log-resolver-response-messages: yes
  dnstap-log-client-query-messages: yes
```

---

## Development

### Prerequisites

- CMake ≥ 3.12
- GCC or Clang with C99 support
- `libprotobuf-c-dev`, `protobuf-c-compiler` — Protocol Buffers C (dev container only)
- `libldns-dev` — LDNS Library (dev container only; statically linked in release builds)
- Fluent Bit source tree (for plugin build only, not for tests)

### Project Structure

```text
flb-input-dnstap/
├── in_dnstap/
│   ├── in_dnstap.c           # Plugin implementation
│   ├── in_dnstap.h           # Plugin context struct
│   ├── dnstap_parser.c       # Native Frame Streams parser
│   ├── dnstap_parser.h       # Parser definitions
│   ├── dnstap_decode.c       # Protobuf & DNS wire format decoder
│   ├── dnstap_decode.h       # Decoder data structures
│   ├── dnstap.pb-c.c/h       # Compiled protobuf-c source
│   └── CMakeLists.txt        # Plugin build target
├── tests/
│   ├── test_dnstap_parser.c  # Unit tests for parser (boundary & errors)
│   ├── test_dnstap_decode.c  # Unit tests for decoder (protocol & types)
│   ├── stubs/                # Minimal FLB compat headers
│   │   ├── flb_test_compat.h # SDS, memory, logging stubs
│   │   └── fluent-bit/       # Proxy headers for <fluent-bit/*.h>
│   └── CMakeLists.txt        # Standalone test build
├── proto/
│   └── dnstap.proto          # Original dnstap protobuf definition
├── .github/workflows/
│   ├── build.yml             # CI: build + test + sanitizer + cppcheck
│   ├── release.yml           # CD: tagged release publishing
│   └── reusable-build.yml    # Shared build steps across FLB matrix
├── Makefile                  # Docker wrapper commands for testing
├── Dockerfile                # Ubuntu-based build environment container
├── docker-compose.yml        # Docker compose service definition
├── scripts/
│   └── build-static-deps.sh  # Builds ldns + protobuf-c as static archives
├── CMakeLists.txt            # Root build with hardening flags
└── README.md
```

### Building the Plugin

#### Option A: Docker (recommended)

The easiest way to build and test the plugin is using the included `Makefile` which wraps `docker compose`.

```bash
# Default: Ubuntu 20.04 (focal)
docker compose build

# Compile the plugin (creates build/flb-in_dnstap.so)
make build

# Open an interactive shell inside the container
make shell
```

#### Option B: Local Build

Requires Fluent Bit source tree cloned and prepared:

```bash
mkdir -p build && cd build
cmake -DFLB_SOURCE=/path/to/fluent-bit -DPLUGIN_NAME=in_dnstap ../
make
```

### Running Tests

Tests are **standalone** — they don't require the Fluent Bit source tree.

**Option A: Using Docker & Makefile**
```bash
# Run unit tests
make test
```

**Option B: Local system**
```bash
# Install test dependencies
apt-get install -y libprotobuf-c-dev protobuf-c-compiler libldns-dev cmake build-essential

# Build and run
mkdir -p build-test && cd build-test
cmake ../tests
make
ctest --output-on-failure
```

### Running Tests with Sanitizers

```bash
make test-san
```
 *(Or locally via `cmake -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" ...`)*

### Static Analysis

```bash
make check
```

---

## CI/CD

### Build Pipeline (`build.yml`)

Triggered on push/PR to `main`. Runs parallel jobs based on `reusable-build.yml`:

| Job | Description |
|-----|-------------|
| **build** | Compiles plugin against 6 Fluent Bit versions (v3.0–v4.2) on `ubuntu:20.04`. Dependencies (ldns, protobuf-c) are statically linked — no runtime library requirements on target. |
| **static-analysis** | Runs `cppcheck` with warning/performance/portability checks |

*(Note: Unit assertions and sanitizers run as explicit steps inside the GitHub actions workflow during native compilation).*

### Release Pipeline (`release.yml`)

Triggered on `v*` tags. Builds all FLB versions and publishes dynamic `.so` artifacts (e.g. `flb-in_dnstap-flb4.2.3.so`) directly to GitHub Releases.

### Security Hardening

The build system applies defence-in-depth compiler and linker flags:

| Flag | Purpose |
|------|---------|
| `-Wall -Wextra -Wno-sign-compare` | Warnings |
| `-Wformat -Wformat-security` | Format string safety |
| `-fstack-protector-strong` | Stack canaries |
| `-fPIC` | Position-independent code (required for .so) |
| `-O2 -D_FORTIFY_SOURCE=2` | Release hardening |
| `-Wl,-z,relro,-z,now` | Full RELRO (read-only GOT after relocation) |

## License

See [LICENSE](LICENSE) for details.
