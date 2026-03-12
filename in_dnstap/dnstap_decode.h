/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Copyright 2026 The flb-input-dnstap Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef DNSTAP_DECODE_H
#define DNSTAP_DECODE_H

#include <stdint.h>
#include <stddef.h>

/* Decoded dnstap record — all strings are owned by this struct and must
 * be freed with dnstap_decoded_destroy(). */
struct dnstap_decoded {
    /* Top-level Dnstap fields */
    char *identity;         /* DNS server identity (NULL if absent) */
    char *version;          /* DNS server version  (NULL if absent) */

    /* Message metadata (all heap-allocated, freed by destroy) */
    char *message_type;               /* e.g. "CLIENT_QUERY" */
    char *socket_family;              /* "INET" / "INET6" */
    char *socket_protocol;            /* "UDP" / "TCP" / ... */

    char *query_address;          /* dotted-decimal or IPv6 text */
    char *response_address;
    uint32_t query_port;
    uint32_t response_port;

    /* Timestamps */
    uint64_t query_time_sec;
    uint32_t query_time_nsec;
    uint64_t response_time_sec;
    uint32_t response_time_nsec;

    /* Parsed DNS fields (via ldns) */
    char *qname;                  /* e.g. "www.example.com." */
    char *qtype;                  /* e.g. "A", "AAAA"       */
    char *qclass;                 /* e.g. "IN"              */
    char *rcode;                  /* e.g. "NOERROR"         */
};

/* Decode a protobuf-encoded dnstap frame into a dnstap_decoded struct.
 * Returns 0 on success, -1 on error. On success, caller must call
 * dnstap_decoded_destroy() to free owned strings. */
int dnstap_decode(const uint8_t *buf, size_t len, struct dnstap_decoded *out);

/* Free all owned strings in a dnstap_decoded struct. */
void dnstap_decoded_destroy(struct dnstap_decoded *d);

/* Convert Message.Type enum to static string. Returns "UNKNOWN" for
 * unrecognized values. */
const char *dnstap_message_type_str(int type);

/* Convert SocketFamily enum to static string. */
const char *dnstap_socket_family_str(int family);

/* Convert SocketProtocol enum to static string. */
const char *dnstap_socket_protocol_str(int protocol);

#endif /* DNSTAP_DECODE_H */
