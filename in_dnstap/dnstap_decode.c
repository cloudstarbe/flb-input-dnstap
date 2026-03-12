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

#include "dnstap_decode.h"
#include "dnstap.pb-c.h"

#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <stdlib.h>
#include <string.h>

const char *dnstap_message_type_str(int type)
{
    switch (type) {
    case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:         return "AUTH_QUERY";
    case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:      return "AUTH_RESPONSE";
    case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:     return "RESOLVER_QUERY";
    case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:  return "RESOLVER_RESPONSE";
    case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:       return "CLIENT_QUERY";
    case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:    return "CLIENT_RESPONSE";
    case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:    return "FORWARDER_QUERY";
    case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE: return "FORWARDER_RESPONSE";
    case DNSTAP__MESSAGE__TYPE__STUB_QUERY:         return "STUB_QUERY";
    case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:      return "STUB_RESPONSE";
    case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:         return "TOOL_QUERY";
    case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:      return "TOOL_RESPONSE";
    case DNSTAP__MESSAGE__TYPE__UPDATE_QUERY:       return "UPDATE_QUERY";
    case DNSTAP__MESSAGE__TYPE__UPDATE_RESPONSE:    return "UPDATE_RESPONSE";
    default:                                        return "UNKNOWN";
    }
}

const char *dnstap_socket_family_str(int family)
{
    switch (family) {
    case DNSTAP__SOCKET_FAMILY__INET:  return "INET";
    case DNSTAP__SOCKET_FAMILY__INET6: return "INET6";
    default:                           return "UNKNOWN";
    }
}

const char *dnstap_socket_protocol_str(int protocol)
{
    switch (protocol) {
    case DNSTAP__SOCKET_PROTOCOL__UDP:         return "UDP";
    case DNSTAP__SOCKET_PROTOCOL__TCP:         return "TCP";
    case DNSTAP__SOCKET_PROTOCOL__DOT:         return "DOT";
    case DNSTAP__SOCKET_PROTOCOL__DOH:         return "DOH";
    case DNSTAP__SOCKET_PROTOCOL__DNSCryptUDP: return "DNSCryptUDP";
    case DNSTAP__SOCKET_PROTOCOL__DNSCryptTCP: return "DNSCryptTCP";
    case DNSTAP__SOCKET_PROTOCOL__DOQ:         return "DOQ";
    default:                                   return "UNKNOWN";
    }
}

/* Convert a binary IP address to a text string. Caller must free(). */
static char *ip_to_str(const uint8_t *data, size_t len)
{
    char buf[INET6_ADDRSTRLEN];
    const char *result = NULL;

    if (len == 4) {
        result = inet_ntop(AF_INET, data, buf, sizeof(buf));
    }
    else if (len == 16) {
        result = inet_ntop(AF_INET6, data, buf, sizeof(buf));
    }

    if (result) {
        return strdup(result);
    }
    return NULL;
}

/* Parse a wire-format DNS message using ldns and extract question fields.
 * Populates qname, qtype, qclass in out. For responses, also extracts rcode. */
static void parse_dns_message(const uint8_t *wire, size_t wire_len,
                              struct dnstap_decoded *out, int is_response)
{
    ldns_pkt *pkt = NULL;
    ldns_status status;

    status = ldns_wire2pkt(&pkt, wire, wire_len);
    if (status != LDNS_STATUS_OK || !pkt) {
        return;
    }

    /* Extract question section */
    ldns_rr_list *question = ldns_pkt_question(pkt);
    if (question && ldns_rr_list_rr_count(question) > 0) {
        ldns_rr *qrr = ldns_rr_list_rr(question, 0);

        if (!out->qname) {
            ldns_rdf *owner = ldns_rr_owner(qrr);
            if (owner) {
                out->qname = ldns_rdf2str(owner);
            }
        }

        if (!out->qtype) {
            out->qtype = ldns_rr_type2str(ldns_rr_get_type(qrr));
        }

        if (!out->qclass) {
            out->qclass = ldns_rr_class2str(ldns_rr_get_class(qrr));
        }
    }

    /* Extract rcode from response */
    if (is_response && !out->rcode) {
        ldns_pkt_rcode rc = ldns_pkt_get_rcode(pkt);
        ldns_lookup_table *lt = ldns_lookup_by_id(ldns_rcodes, (int)rc);
        if (lt && lt->name) {
            out->rcode = strdup(lt->name);
        }
    }

    ldns_pkt_free(pkt);
}

void dnstap_decoded_destroy(struct dnstap_decoded *d)
{
    if (!d) return;

    free(d->identity);
    free(d->version);
    free(d->message_type);
    free(d->socket_family);
    free(d->socket_protocol);
    free(d->query_address);
    free(d->response_address);
    free(d->qname);
    free(d->qtype);
    free(d->qclass);
    free(d->rcode);

    /* Zero out to prevent double-free on re-use */
    memset(d, 0, sizeof(*d));
}

int dnstap_decode(const uint8_t *buf, size_t len, struct dnstap_decoded *out)
{
    if (!buf || len == 0 || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Decode the top-level Dnstap message */
    Dnstap__Dnstap *dt = dnstap__dnstap__unpack(NULL, len, buf);
    if (!dt) {
        return -1;
    }

    /* Identity */
    if (dt->has_identity && dt->identity.len > 0) {
        out->identity = strndup((const char *)dt->identity.data, dt->identity.len);
    }

    /* Version */
    if (dt->has_version && dt->version.len > 0) {
        out->version = strndup((const char *)dt->version.data, dt->version.len);
    }

    /* Process the Message payload */
    Dnstap__Message *msg = dt->message;
    if (!msg) {
        dnstap__dnstap__free_unpacked(dt, NULL);
        return 0; /* Valid dnstap with no message is not an error */
    }

    out->message_type    = strdup(dnstap_message_type_str(msg->type));
    out->socket_family   = msg->has_socket_family
                           ? strdup(dnstap_socket_family_str(msg->socket_family))
                           : strdup("UNKNOWN");
    out->socket_protocol = msg->has_socket_protocol
                           ? strdup(dnstap_socket_protocol_str(msg->socket_protocol))
                           : strdup("UNKNOWN");

    /* Addresses */
    if (msg->has_query_address) {
        out->query_address = ip_to_str(msg->query_address.data,
                                       msg->query_address.len);
    }
    if (msg->has_response_address) {
        out->response_address = ip_to_str(msg->response_address.data,
                                          msg->response_address.len);
    }

    /* Ports */
    out->query_port    = msg->has_query_port    ? msg->query_port    : 0;
    out->response_port = msg->has_response_port ? msg->response_port : 0;

    /* Timestamps */
    out->query_time_sec     = msg->has_query_time_sec     ? msg->query_time_sec     : 0;
    out->query_time_nsec    = msg->has_query_time_nsec    ? msg->query_time_nsec    : 0;
    out->response_time_sec  = msg->has_response_time_sec  ? msg->response_time_sec  : 0;
    out->response_time_nsec = msg->has_response_time_nsec ? msg->response_time_nsec : 0;

    /* Parse wire-format DNS messages via ldns */
    if (msg->has_query_message && msg->query_message.len > 0) {
        parse_dns_message(msg->query_message.data,
                          msg->query_message.len, out, 0);
    }
    if (msg->has_response_message && msg->response_message.len > 0) {
        parse_dns_message(msg->response_message.data,
                          msg->response_message.len, out, 1);
    }

    dnstap__dnstap__free_unpacked(dt, NULL);
    return 0;
}
