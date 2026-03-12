#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "flb_test_compat.h"
#include "in_dnstap.h"
#include "dnstap_parser.h"

int tests_passed = 0;
int tests_failed = 0;

static void test_assert(int condition, const char *msg) {
    if (condition) {
        printf("[PASS] %s\n", msg);
        tests_passed++;
    } else {
        printf("[FAIL] %s\n", msg);
        tests_failed++;
    }
}

// Stub out encode_dnstap_record for the unit test since it resides in in_dnstap.c
int encode_dnstap_record(struct flb_in_dnstap_config *ctx, const struct dnstap_decoded *d) {
    (void)ctx;
    (void)d;
    return 0;
}

int main(void) {
    printf("--- Running dnstap_parser_tests ---\n");

    struct flb_in_dnstap_config config = {0};
    config.ins = calloc(1, 1024); // Dummy instance
    
    struct flb_connection flb_conn = {0};
    flb_conn.fd = -1; /* Dummy fd, write() will just fail with EBADF which is fine */
    
    struct dnstap_conn conn = {0};
    conn.ctx = &config;
    conn.connection = &flb_conn;
    conn.buf_size = 1024;
    conn.buf_data = malloc(conn.buf_size);
    conn.buf_len = 0;

    // Test 1: Empty buffer
    int consumed = dnstap_parser_consume(&conn);
    test_assert(consumed == 0, "Empty buffer should consume 0 bytes");

    // Test 2: Incomplete frame length
    conn.buf_len = 2; // Only 2 bytes of the 4-byte length
    memset(conn.buf_data, 0, conn.buf_len);
    consumed = dnstap_parser_consume(&conn);
    test_assert(consumed == 0, "Incomplete frame length should consume 0 bytes");

    // Test 3: Ready Control Frame
    conn.buf_len = 0;
    uint32_t len = htonl(42); 
    uint32_t type = htonl(0); // Control frame
    uint32_t ctrl_type = htonl(FSTRM_CONTROL_READY);
    
    memcpy(conn.buf_data + conn.buf_len, &type, 4); conn.buf_len += 4;
    memcpy(conn.buf_data + conn.buf_len, &len, 4); conn.buf_len += 4;
    memcpy(conn.buf_data + conn.buf_len, &ctrl_type, 4); conn.buf_len += 4;

    // Fill the rest of the 42 bytes with dummy data
    memset(conn.buf_data + conn.buf_len, 0x00, 38);
    conn.buf_len += 38;

    consumed = dnstap_parser_consume(&conn);
    test_assert(consumed == 4 + 4 + 42, "Properly consumes a READY control frame");

    // Test 4: Stop Control Frame
    conn.buf_len = 0;
    len = htonl(42); 
    type = htonl(0); // Control frame
    ctrl_type = htonl(FSTRM_CONTROL_STOP);
    
    memcpy(conn.buf_data + conn.buf_len, &type, 4); conn.buf_len += 4;
    memcpy(conn.buf_data + conn.buf_len, &len, 4); conn.buf_len += 4;
    memcpy(conn.buf_data + conn.buf_len, &ctrl_type, 4); conn.buf_len += 4;

    memset(conn.buf_data + conn.buf_len, 0x00, 38);
    conn.buf_len += 38;

    consumed = dnstap_parser_consume(&conn);
    test_assert(consumed == 4 + 4 + 42, "Properly consumes a STOP control frame");

    // Test 5: Data frame exceeding buffer_max_size limit
    conn.buf_len = 0;
    conn.ctx->buffer_max_size = 100; /* Set very small limit */
    len = htonl(150); /* Payload of 150 > limit */
    memcpy(conn.buf_data + conn.buf_len, &len, 4); conn.buf_len += 4;
    consumed = dnstap_parser_consume(&conn);
    test_assert(consumed == -1, "Data frame exceeding max size should return -1 (fatal)");

    // Test 6: Control frame exceeding FSTRM_MAX_CTRL_FRAME_LEN
    conn.buf_len = 0;
    len = htonl(0); /* Format states 0 means Control Frame */
    uint32_t oversized_ctrl = htonl(8193); /* > 8192 (FSTRM_MAX_CTRL_FRAME_LEN) */
    memcpy(conn.buf_data + conn.buf_len, &len, 4); conn.buf_len += 4;
    memcpy(conn.buf_data + conn.buf_len, &oversized_ctrl, 4); conn.buf_len += 4;
    consumed = dnstap_parser_consume(&conn);
    test_assert(consumed == -1, "Control frame length exceeding max size should return -1 (fatal)");

    conn.ctx->buffer_max_size = 1048576; // Reset bound

    free(conn.buf_data);
    free(config.ins);

    printf("--- Results: %d passed, %d failed ---\n", tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
