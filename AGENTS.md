# AGENTS.md

Instructions for AI coding agents (Gemini, Copilot, Cursor, etc.) working in this repository.

## Project

A Fluent Bit input plugin that ingests dnstap (DNS Tap) telemetry from DNS servers over a Unix socket. Supports dnsdist, PowerDNS, BIND, and Unbound.

**Language**: C (C99)
**Build system**: CMake 3.12+
**Target platform**: Linux (Debian 11 / Debian 12 / Debian 13 / Ubuntu 22.04+ / Ubuntu 24.04+)
**FLB version**: Fluent Bit v3.0.x through v4.2.x

> **Note:** The CI/CD pipelines compile artifacts natively on `debian:bookworm` (Debian 12) to guarantee `GLIBC_2.36` compatibility across all designated Linux targets.

## Build & Test

```bash
# Unit tests — standalone, no Fluent Bit source needed
mkdir -p build-test && cd build-test
cmake ../tests && make -j$(nproc)
ctest --output-on-failure

# Plugin build — requires Fluent Bit headers at FLB_SOURCE
mkdir -p build && cd build
cmake -DFLB_SOURCE=/path/to/fluent-bit ../ && make -j$(nproc)

# Static analysis
cppcheck --enable=all --error-exitcode=1 \
  --suppress=missingInclude \
  --suppress=*:in_dnstap/dnstap.pb-c.h \
  -i in_dnstap/dnstap.pb-c.c \
  in_dnstap/
```

## Source Map

| File | Responsibility |
|------|---------------|
| `in_dnstap/in_dnstap.c` | Plugin init/collect/exit callbacks, Fluent Bit log encoding |
| `in_dnstap/in_dnstap.h` | Plugin config struct (`flb_in_dnstap_config`) |
| `in_dnstap/dnstap_parser.c` | Native Frame Streams protocol parser |
| `in_dnstap/dnstap_parser.h` | Native parser definitions and FSTRM frame types |
| `in_dnstap/dnstap_decode.c` | Protobuf decode + IP/DNS wire-format parsing |
| `in_dnstap/dnstap_decode.h` | `struct dnstap_decoded` definition and API |
| `in_dnstap/dnstap.pb-c.{c,h}` | **Generated** — do not edit; regenerate from `proto/dnstap.proto` |
| `tests/test_dnstap_decode.c` | Unit tests for decode layer |
| `tests/test_dnstap_parser.c` | Unit tests for parser layer |
| `tests/stubs/flb_test_compat.h` | Minimal FLB stubs enabling standalone test builds |

## Architecture

```
Unix socket (AF_UNIX SOCK_STREAM)
        │
        ▼
dnstap_parser ← Native Frame Streams reader
        │
        ▼
dnstap_decode ← protobuf-c (unpack Dnstap__Dnstap)
              ← ldns       (parse DNS wire format → qname/qtype/qclass/rcode)
              ← inet_ntop  (binary IP → text)
        │
        ▼
in_dnstap (Fluent Bit plugin)
  flb_log_event_encoder → msgpack key-value record → FLB pipeline
```

2. **All `dnstap_decoded` strings are heap-allocated** — always call `dnstap_decoded_destroy()` even on partial decodes. The `memset` to zero after free is intentional.
4. **Use `ldns_rr_type2str()` / `ldns_rr_class2str()`** — never use `ldns_rr_type2buffer_str` + `ldns_buffer_begin` with `strdup`; the buffer is NOT null-terminated, causing out-of-bounds reads.
5. **Non-blocking event loop** — never block inside plugin callbacks; return `FLB_ENGINE_BUSY` if more data is queued.
6. **Security flags are mandatory** — `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, RELRO, NOW. Do not weaken these.
7. **Socket path validation** — use `lstat()` + `S_ISLNK()` before `unlink()` to prevent TOCTOU symlink attacks. Never skip this check.
8. **Connection limit** — `max_connections` (default 256) is a DoS guard; enforce it before accepting new connections.

## Adding New DNS Fields

1. Check `proto/dnstap.proto` and `in_dnstap/dnstap.pb-c.h` to confirm the protobuf field exists.
2. Add the field to `struct dnstap_decoded` in `dnstap_decode.h`.
3. Populate it in `dnstap_decode()` (`dnstap_decode.c`), following the existing `strdup`/`inet_ntop` patterns.
4. Free it in `dnstap_decoded_destroy()`.
5. Encode it in `encode_dnstap_record()` (`in_dnstap.c`) using `flb_log_event_encoder_*` API.
6. Add a unit test in `tests/test_dnstap_decode.c`.

## Compiler Flags Reference

| Flag | Purpose |
|------|---------|
| `-Wall -Wextra -Wno-sign-compare` | Warnings |
| `-Wformat -Wformat-security` | Format string safety |
| `-fstack-protector-strong` | Stack canaries |
| `-fPIC` | Position-independent code (required for .so) |
| `-O2 -D_FORTIFY_SOURCE=2` | Release hardening |
| `-Wl,-z,relro,-z,now` | RELRO + NOW (full RELRO) |
