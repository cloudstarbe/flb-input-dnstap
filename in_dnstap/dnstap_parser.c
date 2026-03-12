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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "dnstap_parser.h"
#include "in_dnstap.h"
#include "dnstap_decode.h"

/* FSTRM Control Field Types */
#define FSTRM_CONTROL_FIELD_CONTENT_TYPE 0x01

static int write_all(int fd, const void *buf, size_t count) {
    const char *p = buf;
    while (count > 0) {
        ssize_t ret = write(fd, p, count);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ret == 0) return -1;
        p += ret;
        count -= ret;
    }
    return 0;
}

static void send_fstrm_accept(int fd) {
    /* 
     * FSTRM ACCEPT FRAME for "protobuf:dnstap.Dnstap" (22 bytes).
     * Format:
     * [0] Escape: 0x00 00 00 00 (Denotes Control Frame)
     * [1] Frame Length: 34 bytes (4 Type + 4 FieldType + 4 FieldLen + 22 String)
     * [2] Frame Type: FSTRM_CONTROL_ACCEPT (1)
     * [3] Field Type: FSTRM_CONTROL_FIELD_CONTENT_TYPE (1)
     * [4] Field Len: 22 bytes
     * [5] String: "protobuf:dnstap.Dnstap"
     */
    uint32_t buf[5];
    buf[0] = 0;
    buf[1] = htonl(34);
    buf[2] = htonl(FSTRM_CONTROL_ACCEPT);
    buf[3] = htonl(FSTRM_CONTROL_FIELD_CONTENT_TYPE);
    buf[4] = htonl(22);
    
    char accept_frame[42];
    memcpy(accept_frame, buf, 20);
    memcpy(accept_frame + 20, "protobuf:dnstap.Dnstap", 22);
    
    /* We write this directly to the non-blocking socket.
     * Use write_all to handle partial writes or EINTR. */
    (void) write_all(fd, accept_frame, 42); 
}

static void send_fstrm_finish(int fd) {
    /* 
     * FSTRM FINISH FRAME (No fields)
     * [0] Escape: 0x00 00 00 00
     * [1] Frame Length: 4 bytes
     * [2] Frame Type: FSTRM_CONTROL_FINISH (5)
     */
    uint32_t buf[3];
    buf[0] = 0;
    buf[1] = htonl(4);
    buf[2] = htonl(FSTRM_CONTROL_FINISH);
    
    (void) write_all(fd, buf, 12);
}

/* Processes as many FSTRM frames as possible from the active connection buffer.
 * Returns the number of bytes that were successfully fully processed. The caller
 * is responsible for memmove'ing the remaining buffer bytes down to index 0.
 *
 * Returns -1 on fatal error (protocol violation).
 */
int dnstap_parser_consume(struct dnstap_conn *conn) {
    int consumed = 0;
    
    while (1) {
        size_t available = conn->buf_len - consumed;
        if (available < sizeof(uint32_t)) {
            break; /* Need more data for the frame length header */
        }

        uint32_t len;
        memcpy(&len, conn->buf_data + consumed, sizeof(uint32_t));
        len = ntohl(len);

        if (len == 0) {
            /* This is a control frame. It is followed by the control length
             * header (32-bit) which describes the size of the control payload. */
            if (available < 2 * sizeof(uint32_t)) {
                break; /* Need more data for the control length header */
            }

            uint32_t ctrl_len;
            memcpy(&ctrl_len, conn->buf_data + consumed + sizeof(uint32_t), sizeof(uint32_t));
            ctrl_len = ntohl(ctrl_len);

            if (ctrl_len > FSTRM_MAX_CTRL_FRAME_LEN) {
                flb_plg_error(conn->ctx->ins, "fatal: FSTRM control frame extremely large (%u bytes)", ctrl_len);
                return -1;
            }

            /* Wait until the full control frame arrives */
            if (available < 2 * sizeof(uint32_t) + ctrl_len) {
                break;
            }

            /* Identify frame type purely for logging/debug.
             * The protocol says: FrameLength (== 0), ControlLength (ctrl_len), FrameType (if ctrl_len >= 4)
             */
            if (ctrl_len >= sizeof(uint32_t)) {
                uint32_t frame_type;
                memcpy(&frame_type, conn->buf_data + consumed + 2 * sizeof(uint32_t), sizeof(uint32_t));
                frame_type = ntohl(frame_type);
                
                if (frame_type == FSTRM_CONTROL_READY) {
                    flb_plg_info(conn->ctx->ins, "FSTRM READY frame received on fd=%d, sending ACCEPT", conn->connection->fd);
                    send_fstrm_accept(conn->connection->fd);
                } else if (frame_type == FSTRM_CONTROL_STOP) {
                    flb_plg_info(conn->ctx->ins, "FSTRM STOP frame received on fd=%d, sending FINISH", conn->connection->fd);
                    send_fstrm_finish(conn->connection->fd);
                }
            }

            /* Advance the consumed counter past the control frame.
             * FrameLength (4) + ControlLength (4) + Payload (ctrl_len) */
            consumed += (2 * sizeof(uint32_t) + ctrl_len);
            continue;
        } 
        
        /* This is a data frame, and 'len' is the payload size */
        if (len > conn->ctx->buffer_max_size || len > FSTRM_MAX_DATA_FRAME_LEN) {
            flb_plg_error(conn->ctx->ins, "fatal: FSTRM data frame huge (%u bytes), max bound is %zu", 
                          len, conn->ctx->buffer_max_size);
            return -1;
        }

        /* Wait until the full data payload arrives */
        if (available < sizeof(uint32_t) + len) {
            break;
        }

        /* We have a full data payload. Time to decode it! */
        const uint8_t *payload = (const uint8_t *)(conn->buf_data + consumed + sizeof(uint32_t));
        struct dnstap_decoded decoded;
        
        if (dnstap_decode(payload, len, &decoded) == 0) {
            if (encode_dnstap_record(conn->ctx, &decoded) != 0) {
                flb_plg_warn(conn->ctx->ins, "failed to encode dnstap record");
            }
            dnstap_decoded_destroy(&decoded);
        } else {
            flb_plg_warn(conn->ctx->ins, "failed to decode dnstap protobuf payload");
        }

        consumed += (sizeof(uint32_t) + len);
    }

    return consumed;
}
