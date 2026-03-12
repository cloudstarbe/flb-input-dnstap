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

#ifndef IN_DNSTAP_H
#define IN_DNSTAP_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct dnstap_conn {
    struct flb_connection *connection;
    char *buf_data;                         /* Connection data buffer */
    size_t buf_len;                         /* Length of data currently in buffer */
    size_t buf_size;                        /* Allocated size of buffer */
    struct flb_in_dnstap_config *ctx;
    struct mk_list _head;
};

struct flb_in_dnstap_config {
    char *socket_path;                      /* Unix socket path */
    char *socket_permissions;               /* Socket ACL string */
    int   socket_acl;                       /* Socket ACL numeric */
    int   collector_id;                     /* FluentBit collector id */
    int   max_connections;                  /* Max concurrent connections */
    int   active_connections;               /* Current connection count */
    int   use_dnstap_timestamp;             /* Use wire timestamps instead of current time */
    size_t buffer_chunk_size;               /* Buffer allocation chunk size */
    size_t buffer_max_size;                 /* Maximum connection buffer size */
    struct flb_downstream *downstream;      /* Client manager */
    struct mk_list connections;             /* Active client connections */
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

struct dnstap_decoded;

int encode_dnstap_record(struct flb_in_dnstap_config *ctx,
                         const struct dnstap_decoded *d);

#endif /* IN_DNSTAP_H */
