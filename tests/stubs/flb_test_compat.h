/* Minimal Fluent Bit compatibility stubs for standalone tests.
 * These provide just enough FLB API surface for test code that
 * includes <fluent-bit/...> transitively via the plugin sources. */

#ifndef FLB_TEST_COMPAT_H
#define FLB_TEST_COMPAT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mk_list.h"

/* flb_sds — simple dynamic string stub */
typedef char *flb_sds_t;

static inline flb_sds_t flb_sds_create(const char *str) {
    return str ? strdup(str) : NULL;
}
static inline flb_sds_t flb_sds_create_len(const char *str, int len) {
    char *s = (char *)malloc(len + 1);
    if (s) { memcpy(s, str, len); s[len] = '\0'; }
    return s;
}
static inline size_t flb_sds_len(flb_sds_t s) {
    return s ? strlen(s) : 0;
}
static inline void flb_sds_destroy(flb_sds_t s) { free(s); }

/* Memory stubs */
#define flb_malloc   malloc
#define flb_calloc   calloc
#define flb_realloc  realloc
#define flb_free     free
#define flb_errno()  perror("flb")

/* Logging stubs */
#define flb_error(fmt, ...)  fprintf(stderr, "[error] " fmt "\n", ##__VA_ARGS__)
#define flb_warn(fmt, ...)   fprintf(stderr, "[warn]  " fmt "\n", ##__VA_ARGS__)
#define flb_info(fmt, ...)   fprintf(stderr, "[info]  " fmt "\n", ##__VA_ARGS__)
#define flb_debug(fmt, ...)  fprintf(stderr, "[debug] " fmt "\n", ##__VA_ARGS__)
#define flb_trace(fmt, ...)  ((void)0)

/* Simple test assertion macros */
#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

#define TEST_ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL: %s:%d: \"%s\" != \"%s\"\n", \
                __FILE__, __LINE__, (a), (b)); \
        exit(1); \
    } \
} while (0)

#define TEST_ASSERT_NULL(ptr) do { \
    if ((ptr) != NULL) { \
        fprintf(stderr, "FAIL: %s:%d: expected NULL\n", __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_ASSERT_NOT_NULL(ptr) do { \
    if ((ptr) == NULL) { \
        fprintf(stderr, "FAIL: %s:%d: unexpected NULL\n", __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_ASSERT_INT_EQ(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "FAIL: %s:%d: %d != %d\n", \
                __FILE__, __LINE__, (int)(a), (int)(b)); \
        exit(1); \
    } \
} while (0)

#endif /* FLB_TEST_COMPAT_H */
