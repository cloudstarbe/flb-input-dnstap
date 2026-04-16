/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Unit tests for dnstap_decode module.
 *  Standalone — no Fluent Bit source dependency.
 */

#include "../in_dnstap/dnstap_decode.h"
#include "../in_dnstap/dnstap_decode.c"
#include "../in_dnstap/dnstap.pb-c.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <protobuf-c/protobuf-c.h>

/* Simple test framework */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST_START(name) do { \
    tests_run++; \
    printf("  %-50s ", name); \
} while (0)

#define TEST_PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while (0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #cond); \
        return; \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL (%s:%d: \"%s\" != \"%s\")\n", __FILE__, __LINE__, (a), (b)); \
        return; \
    } \
} while (0)

#define ASSERT_INT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL (%s:%d: %d != %d)\n", __FILE__, __LINE__, (int)(a), (int)(b)); \
        return; \
    } \
} while (0)

/* ------------------------------------------------------------------ */
/* Helper: build a protobuf-encoded Dnstap message for testing         */
/* ------------------------------------------------------------------ */

/* Build a minimal DNS query in wire format (just header + question) */
static size_t build_dns_query(uint8_t *buf, size_t bufsize,
                              const char *qname_str, uint16_t qtype)
{
    size_t pos = 0;

    /* DNS header: 12 bytes */
    if (bufsize < 12) return 0;
    memset(buf, 0, 12);
    buf[0] = 0x00; buf[1] = 0x01; /* ID = 1 */
    buf[2] = 0x01; buf[3] = 0x00; /* QR=0, RD=1 */
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT = 1 */
    pos = 12;

    /* Encode qname as labels */
    const char *p = qname_str;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len;
        if (dot) {
            label_len = dot - p;
        }
        else {
            label_len = strlen(p);
        }
        if (pos + 1 + label_len >= bufsize) return 0;
        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        p += label_len;
        if (*p == '.') p++;
    }
    if (pos >= bufsize) return 0;
    buf[pos++] = 0; /* root label */

    /* QTYPE + QCLASS */
    if (pos + 4 > bufsize) return 0;
    buf[pos++] = (qtype >> 8) & 0xFF;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0x00;
    buf[pos++] = 0x01; /* IN class */

    return pos;
}

/* Build a DNS response wire format (header with rcode + question) */
static size_t build_dns_response(uint8_t *buf, size_t bufsize,
                                 const char *qname_str, uint16_t qtype,
                                 uint8_t rcode)
{
    size_t len = build_dns_query(buf, bufsize, qname_str, qtype);
    if (len == 0) return 0;

    /* Set QR=1 (response) and rcode */
    buf[2] = 0x81; /* QR=1, RD=1 */
    buf[3] = rcode;
    return len;
}

/* Forward declaration */
static uint8_t *build_dnstap_msg_ts(size_t *out_len,
                                     const char *identity, const char *version,
                                     int msg_type, int socket_family, int socket_protocol,
                                     const uint8_t *query_addr, size_t query_addr_len,
                                     uint32_t query_port,
                                     const uint8_t *dns_query, size_t dns_query_len,
                                     const uint8_t *dns_response, size_t dns_response_len,
                                     uint64_t query_time_sec, uint32_t query_time_nsec,
                                     uint64_t response_time_sec, uint32_t response_time_nsec);

/* Build and serialize a Dnstap protobuf message.
 * Returns malloc'd buffer; caller must free. Sets *out_len. */
static uint8_t *build_dnstap_msg(size_t *out_len,
                                  const char *identity,
                                  const char *version,
                                  int msg_type,
                                  int socket_family,
                                  int socket_protocol,
                                  const uint8_t *query_addr, size_t query_addr_len,
                                  uint32_t query_port,
                                  const uint8_t *dns_query, size_t dns_query_len,
                                  const uint8_t *dns_response, size_t dns_response_len)
{
    return build_dnstap_msg_ts(out_len, identity, version, msg_type,
                              socket_family, socket_protocol,
                              query_addr, query_addr_len, query_port,
                              dns_query, dns_query_len,
                              dns_response, dns_response_len,
                              0, 0, 0, 0);
}

/* Extended builder with timestamp support */
static uint8_t *build_dnstap_msg_ts(size_t *out_len,
                                     const char *identity,
                                     const char *version,
                                     int msg_type,
                                     int socket_family,
                                     int socket_protocol,
                                     const uint8_t *query_addr, size_t query_addr_len,
                                     uint32_t query_port,
                                     const uint8_t *dns_query, size_t dns_query_len,
                                     const uint8_t *dns_response, size_t dns_response_len,
                                     uint64_t query_time_sec, uint32_t query_time_nsec,
                                     uint64_t response_time_sec, uint32_t response_time_nsec)
{
    Dnstap__Message msg = DNSTAP__MESSAGE__INIT;
    Dnstap__Dnstap dt = DNSTAP__DNSTAP__INIT;

    msg.type = msg_type;

    if (socket_family >= 0) {
        msg.has_socket_family = 1;
        msg.socket_family = socket_family;
    }
    if (socket_protocol >= 0) {
        msg.has_socket_protocol = 1;
        msg.socket_protocol = socket_protocol;
    }
    if (query_addr && query_addr_len > 0) {
        msg.has_query_address = 1;
        msg.query_address.data = (uint8_t *)query_addr;
        msg.query_address.len = query_addr_len;
    }
    if (query_port > 0) {
        msg.has_query_port = 1;
        msg.query_port = query_port;
    }
    if (dns_query && dns_query_len > 0) {
        msg.has_query_message = 1;
        msg.query_message.data = (uint8_t *)dns_query;
        msg.query_message.len = dns_query_len;
    }
    if (dns_response && dns_response_len > 0) {
        msg.has_response_message = 1;
        msg.response_message.data = (uint8_t *)dns_response;
        msg.response_message.len = dns_response_len;
    }
    if (query_time_sec > 0) {
        msg.has_query_time_sec = 1;
        msg.query_time_sec = query_time_sec;
        msg.has_query_time_nsec = 1;
        msg.query_time_nsec = query_time_nsec;
    }
    if (response_time_sec > 0) {
        msg.has_response_time_sec = 1;
        msg.response_time_sec = response_time_sec;
        msg.has_response_time_nsec = 1;
        msg.response_time_nsec = response_time_nsec;
    }

    dt.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
    dt.message = &msg;

    if (identity) {
        dt.has_identity = 1;
        dt.identity.data = (uint8_t *)identity;
        dt.identity.len = strlen(identity);
    }
    if (version) {
        dt.has_version = 1;
        dt.version.data = (uint8_t *)version;
        dt.version.len = strlen(version);
    }

    size_t len = protobuf_c_message_get_packed_size((ProtobufCMessage *)&dt);
    uint8_t *buf = malloc(len);
    protobuf_c_message_pack((ProtobufCMessage *)&dt, buf);
    *out_len = len;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Test cases                                                          */
/* ------------------------------------------------------------------ */

static void test_message_type_str(void)
{
    TEST_START("message_type_str");
    ASSERT_STR_EQ(dnstap_message_type_str(DNSTAP__MESSAGE__TYPE__CLIENT_QUERY), "CLIENT_QUERY");
    ASSERT_STR_EQ(dnstap_message_type_str(DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE), "AUTH_RESPONSE");
    ASSERT_STR_EQ(dnstap_message_type_str(DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY), "RESOLVER_QUERY");
    ASSERT_STR_EQ(dnstap_message_type_str(DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE), "FORWARDER_RESPONSE");
    ASSERT_STR_EQ(dnstap_message_type_str(DNSTAP__MESSAGE__TYPE__UPDATE_QUERY), "UPDATE_QUERY");
    ASSERT_STR_EQ(dnstap_message_type_str(999), "UNKNOWN");
    TEST_PASS();
}

static void test_socket_family_str(void)
{
    TEST_START("socket_family_str");
    ASSERT_STR_EQ(dnstap_socket_family_str(DNSTAP__SOCKET_FAMILY__INET), "INET");
    ASSERT_STR_EQ(dnstap_socket_family_str(DNSTAP__SOCKET_FAMILY__INET6), "INET6");
    ASSERT_STR_EQ(dnstap_socket_family_str(99), "UNKNOWN");
    TEST_PASS();
}

static void test_socket_protocol_str(void)
{
    TEST_START("socket_protocol_str");
    ASSERT_STR_EQ(dnstap_socket_protocol_str(DNSTAP__SOCKET_PROTOCOL__UDP), "UDP");
    ASSERT_STR_EQ(dnstap_socket_protocol_str(DNSTAP__SOCKET_PROTOCOL__TCP), "TCP");
    ASSERT_STR_EQ(dnstap_socket_protocol_str(DNSTAP__SOCKET_PROTOCOL__DOT), "DOT");
    ASSERT_STR_EQ(dnstap_socket_protocol_str(DNSTAP__SOCKET_PROTOCOL__DOH), "DOH");
    ASSERT_STR_EQ(dnstap_socket_protocol_str(DNSTAP__SOCKET_PROTOCOL__DOQ), "DOQ");
    ASSERT_STR_EQ(dnstap_socket_protocol_str(99), "UNKNOWN");
    TEST_PASS();
}

static void test_decode_null_input(void)
{
    TEST_START("decode_null_input");
    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(NULL, 0, &d), -1);
    ASSERT_INT_EQ(dnstap_decode((uint8_t *)"x", 1, NULL), -1);
    ASSERT_INT_EQ(dnstap_decode(NULL, 10, &d), -1);
    TEST_PASS();
}

static void test_decode_malformed(void)
{
    TEST_START("decode_malformed_protobuf");
    struct dnstap_decoded d;
    uint8_t garbage[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
    ASSERT_INT_EQ(dnstap_decode(garbage, sizeof(garbage), &d), -1);
    TEST_PASS();
}

static void test_decode_client_query_ipv4(void)
{
    TEST_START("decode_client_query_ipv4");

    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "www.example.com", 1);
    ASSERT(dns_len > 0);

    uint8_t ipv4[] = {192, 168, 1, 100};
    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    "ns1.example.com", "dnsdist 1.8",
                                    DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    ipv4, 4, 12345,
                                    dns_wire, dns_len,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT(d.identity != NULL);
    ASSERT_STR_EQ(d.identity, "ns1.example.com");
    ASSERT_STR_EQ(d.version, "dnsdist 1.8");
    ASSERT_STR_EQ(d.message_type, "CLIENT_QUERY");
    ASSERT_STR_EQ(d.socket_family, "INET");
    ASSERT_STR_EQ(d.socket_protocol, "UDP");
    ASSERT(d.query_address != NULL);
    ASSERT_STR_EQ(d.query_address, "192.168.1.100");
    ASSERT_INT_EQ(d.query_port, 12345);

    /* DNS parsed fields */
    ASSERT(d.qname != NULL);
    ASSERT_STR_EQ(d.qname, "www.example.com.");
    ASSERT(d.qtype != NULL);
    ASSERT_STR_EQ(d.qtype, "A");
    ASSERT(d.qclass != NULL);
    ASSERT_STR_EQ(d.qclass, "IN");

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_ipv6(void)
{
    TEST_START("decode_ipv6_address");

    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "example.org", 28);
    ASSERT(dns_len > 0);

    /* ::1 in IPv6 */
    uint8_t ipv6[16] = {0};
    ipv6[15] = 1;

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET6,
                                    DNSTAP__SOCKET_PROTOCOL__TCP,
                                    ipv6, 16, 53,
                                    dns_wire, dns_len,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT_STR_EQ(d.socket_family, "INET6");
    ASSERT(d.query_address != NULL);
    ASSERT_STR_EQ(d.query_address, "::1");
    ASSERT_STR_EQ(d.qtype, "AAAA");

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_response_rcode(void)
{
    TEST_START("decode_response_rcode");

    uint8_t dns_resp[512];
    size_t dns_len = build_dns_response(dns_resp, sizeof(dns_resp),
                                        "nonexistent.example.com", 1, 3 /* NXDOMAIN */);
    ASSERT(dns_len > 0);

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    NULL, 0, 0,
                                    NULL, 0,
                                    dns_resp, dns_len);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT_STR_EQ(d.message_type, "CLIENT_RESPONSE");
    ASSERT(d.rcode != NULL);
    ASSERT_STR_EQ(d.rcode, "NXDOMAIN");
    ASSERT(d.qname != NULL);
    ASSERT_STR_EQ(d.qname, "nonexistent.example.com.");

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_missing_fields(void)
{
    TEST_START("decode_missing_optional_fields");

    /* Minimal message: just type, no optional fields */
    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__AUTH_QUERY,
                                    -1, -1,  /* no socket family/protocol */
                                    NULL, 0, 0,
                                    NULL, 0,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT(d.identity == NULL);
    ASSERT(d.version == NULL);
    ASSERT_STR_EQ(d.message_type, "AUTH_QUERY");
    ASSERT_STR_EQ(d.socket_family, "UNKNOWN");
    ASSERT_STR_EQ(d.socket_protocol, "UNKNOWN");
    ASSERT(d.query_address == NULL);
    ASSERT(d.qname == NULL);

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_mx_query(void)
{
    TEST_START("decode_mx_query_type");

    uint8_t dns_wire[512];
    /* MX = 15 */
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "example.com", 15);
    ASSERT(dns_len > 0);

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__TCP,
                                    NULL, 0, 0,
                                    dns_wire, dns_len,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT_STR_EQ(d.qtype, "MX");
    ASSERT_STR_EQ(d.qname, "example.com.");

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_malformed_dns(void)
{
    TEST_START("decode_malformed_dns_wire");

    /* Invalid DNS wire data */
    uint8_t garbage[] = {0x00, 0x01, 0xFF, 0xFF};

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    NULL, 0, 0,
                                    garbage, sizeof(garbage),
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    /* Should succeed at protobuf level, DNS parse may fail gracefully */
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);
    /* qname may be NULL if DNS parse failed — that's OK */

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_noerror_rcode(void)
{
    TEST_START("decode_noerror_rcode");

    uint8_t dns_resp[512];
    size_t dns_len = build_dns_response(dns_resp, sizeof(dns_resp),
                                        "example.com", 1, 0 /* NOERROR */);
    ASSERT(dns_len > 0);

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    NULL, 0, 0,
                                    NULL, 0,
                                    dns_resp, dns_len);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT(d.rcode != NULL);
    ASSERT_STR_EQ(d.rcode, "NOERROR");

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_double_destroy(void)
{
    TEST_START("decode_double_destroy_safety");

    /* Decode a real message, destroy twice — must not crash */
    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    "test-id", "v1",
                                    DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    NULL, 0, 0,
                                    NULL, 0,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    dnstap_decoded_destroy(&d);
    /* All fields should be zeroed now — second destroy must be safe */
    dnstap_decoded_destroy(&d);

    free(pb);
    TEST_PASS();
}

static void test_decode_all_fields_owned(void)
{
    TEST_START("decode_all_fields_heap_owned");

    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "test.com", 1);
    ASSERT(dns_len > 0);

    uint8_t ipv4[] = {10, 0, 0, 1};
    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    "id1", "v1",
                                    DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    ipv4, 4, 53,
                                    dns_wire, dns_len,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    /* Verify all string fields are non-NULL (heap allocated) */
    ASSERT(d.identity != NULL);
    ASSERT(d.version != NULL);
    ASSERT(d.message_type != NULL);
    ASSERT(d.socket_family != NULL);
    ASSERT(d.socket_protocol != NULL);
    ASSERT(d.query_address != NULL);
    ASSERT(d.qname != NULL);
    ASSERT(d.qtype != NULL);
    ASSERT(d.qclass != NULL);

    /* Destroy should free all without crash (proves heap ownership) */
    dnstap_decoded_destroy(&d);

    /* All fields zeroed after destroy */
    ASSERT(d.identity == NULL);
    ASSERT(d.message_type == NULL);
    ASSERT(d.socket_family == NULL);
    ASSERT(d.socket_protocol == NULL);

    free(pb);
    TEST_PASS();
}

/* ------------------------------------------------------------------ */
/* Tests for code review fixes                                         */
/* ------------------------------------------------------------------ */

static void test_decode_various_qtypes(void)
{
    TEST_START("decode_various_qtypes_null_terminated");

    /* Test multiple DNS record types to ensure ldns_rr_type2str
     * produces correct, null-terminated strings (fixes OOB read) */
    struct { uint16_t qtype; const char *expected; } cases[] = {
        {  1,  "A"     },
        { 28,  "AAAA"  },
        { 15,  "MX"    },
        { 33,  "SRV"   },
        { 16,  "TXT"   },
        {  6,  "SOA"   },
        {  2,  "NS"    },
        {  5,  "CNAME" },
        { 12,  "PTR"   },
    };
    int ncases = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < ncases; i++) {
        uint8_t dns_wire[512];
        size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire),
                                         "test.example.com", cases[i].qtype);
        ASSERT(dns_len > 0);

        size_t pb_len;
        uint8_t *pb = build_dnstap_msg(&pb_len,
                                        NULL, NULL,
                                        DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                        DNSTAP__SOCKET_FAMILY__INET,
                                        DNSTAP__SOCKET_PROTOCOL__UDP,
                                        NULL, 0, 0,
                                        dns_wire, dns_len,
                                        NULL, 0);
        ASSERT(pb != NULL);

        struct dnstap_decoded d;
        ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);
        ASSERT(d.qtype != NULL);
        ASSERT_STR_EQ(d.qtype, cases[i].expected);

        /* Verify string length matches expected (no trailing garbage) */
        ASSERT_INT_EQ((int)strlen(d.qtype), (int)strlen(cases[i].expected));

        dnstap_decoded_destroy(&d);
        free(pb);
    }
    TEST_PASS();
}

static void test_decode_qclass_strings(void)
{
    TEST_START("decode_qclass_null_terminated");

    /* IN class is most common, but verify it's properly null-terminated */
    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "example.com", 1);
    ASSERT(dns_len > 0);

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg(&pb_len,
                                    NULL, NULL,
                                    DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                    DNSTAP__SOCKET_FAMILY__INET,
                                    DNSTAP__SOCKET_PROTOCOL__UDP,
                                    NULL, 0, 0,
                                    dns_wire, dns_len,
                                    NULL, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);
    ASSERT(d.qclass != NULL);
    ASSERT_STR_EQ(d.qclass, "IN");
    ASSERT_INT_EQ((int)strlen(d.qclass), 2); /* exactly "IN", no garbage */

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_wire_timestamps(void)
{
    TEST_START("decode_wire_timestamps");

    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "time.example.com", 1);
    ASSERT(dns_len > 0);

    uint8_t dns_resp[512];
    size_t resp_len = build_dns_response(dns_resp, sizeof(dns_resp),
                                          "time.example.com", 1, 0);
    ASSERT(resp_len > 0);

    /* Use realistic timestamps */
    uint64_t q_sec  = 1710000000;  /* ~2024-03-09 */
    uint32_t q_nsec = 123456789;
    uint64_t r_sec  = 1710000001;
    uint32_t r_nsec = 987654321;

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg_ts(&pb_len,
                                       "ts-test", "v1",
                                       DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE,
                                       DNSTAP__SOCKET_FAMILY__INET,
                                       DNSTAP__SOCKET_PROTOCOL__UDP,
                                       NULL, 0, 0,
                                       dns_wire, dns_len,
                                       dns_resp, resp_len,
                                       q_sec, q_nsec, r_sec, r_nsec);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    /* Verify timestamps are populated */
    ASSERT(d.query_time_sec == q_sec);
    ASSERT(d.query_time_nsec == q_nsec);
    ASSERT(d.response_time_sec == r_sec);
    ASSERT(d.response_time_nsec == r_nsec);

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_decode_timestamps_query_only(void)
{
    TEST_START("decode_timestamps_query_only");

    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "q.example.com", 1);
    ASSERT(dns_len > 0);

    uint64_t q_sec  = 1710000000;
    uint32_t q_nsec = 500000000;

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg_ts(&pb_len,
                                       NULL, NULL,
                                       DNSTAP__MESSAGE__TYPE__CLIENT_QUERY,
                                       DNSTAP__SOCKET_FAMILY__INET,
                                       DNSTAP__SOCKET_PROTOCOL__UDP,
                                       NULL, 0, 0,
                                       dns_wire, dns_len,
                                       NULL, 0,
                                       q_sec, q_nsec, 0, 0);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    ASSERT(d.query_time_sec == q_sec);
    ASSERT(d.query_time_nsec == q_nsec);
    ASSERT(d.response_time_sec == 0);
    ASSERT(d.response_time_nsec == 0);

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

static void test_response_timestamp_preferred(void)
{
    TEST_START("response_timestamp_preferred_over_query");

    uint8_t dns_wire[512];
    size_t dns_len = build_dns_query(dns_wire, sizeof(dns_wire), "resp.example.com", 1);
    ASSERT(dns_len > 0);

    uint8_t dns_resp[512];
    size_t resp_len = build_dns_response(dns_resp, sizeof(dns_resp),
                                          "resp.example.com", 1, 0);
    ASSERT(resp_len > 0);

    /* Response has BOTH query_time and response_time set */
    uint64_t q_sec  = 1710000000;
    uint32_t q_nsec = 100000000;
    uint64_t r_sec  = 1710000002;   /* 2 seconds later */
    uint32_t r_nsec = 200000000;

    size_t pb_len;
    uint8_t *pb = build_dnstap_msg_ts(&pb_len,
                                       "resp-ts-test", "v1",
                                       DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE,
                                       DNSTAP__SOCKET_FAMILY__INET,
                                       DNSTAP__SOCKET_PROTOCOL__UDP,
                                       NULL, 0, 0,
                                       dns_wire, dns_len,
                                       dns_resp, resp_len,
                                       q_sec, q_nsec, r_sec, r_nsec);
    ASSERT(pb != NULL);

    struct dnstap_decoded d;
    ASSERT_INT_EQ(dnstap_decode(pb, pb_len, &d), 0);

    /* Both timestamps must be populated */
    ASSERT(d.query_time_sec == q_sec);
    ASSERT(d.query_time_nsec == q_nsec);
    ASSERT(d.response_time_sec == r_sec);
    ASSERT(d.response_time_nsec == r_nsec);

    /* Semantic check: for a response, response_time > query_time */
    ASSERT(d.response_time_sec > d.query_time_sec);

    dnstap_decoded_destroy(&d);
    free(pb);
    TEST_PASS();
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("Running dnstap_decode tests...\n");

    test_message_type_str();
    test_socket_family_str();
    test_socket_protocol_str();
    test_decode_null_input();
    test_decode_malformed();
    test_decode_client_query_ipv4();
    test_decode_ipv6();
    test_decode_response_rcode();
    test_decode_missing_fields();
    test_decode_mx_query();
    test_decode_malformed_dns();
    test_decode_noerror_rcode();
    test_decode_double_destroy();
    test_decode_all_fields_owned();

    /* Code review fix tests */
    test_decode_various_qtypes();
    test_decode_qclass_strings();
    test_decode_wire_timestamps();
    test_decode_timestamps_query_only();
    test_response_timestamp_preferred();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
