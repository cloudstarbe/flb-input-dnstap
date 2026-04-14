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

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include "dnstap_decode.h"
#include "dnstap_parser.h"
#include "in_dnstap.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Forward declarations */
static int cb_dnstap_collect(struct flb_input_instance *in,
                             struct flb_config *config, void *in_context);
static int dnstap_conn_event(void *data);

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static int remove_existing_socket_file(const char *path) {
  struct stat st;

  /* Use lstat() to avoid following symlinks (TOCTOU mitigation) */
  if (lstat(path, &st) == -1) {
    if (errno == ENOENT)
      return 0;
    return -1;
  }
  if (S_ISLNK(st.st_mode))
    return -2; /* reject symlinks */
  if (!S_ISSOCK(st.st_mode))
    return -2;
  if (unlink(path) != 0)
    return -3;
  return 0;
}

/* Encode a single decoded dnstap record as a Fluent Bit log event */
int encode_dnstap_record(struct flb_in_dnstap_config *ctx,
                         const struct dnstap_decoded *d) {
  int ret;
  struct flb_log_event_encoder *enc = ctx->log_encoder;

  flb_log_event_encoder_reset(enc);

  ret = flb_log_event_encoder_begin_record(enc);
  if (ret != FLB_EVENT_ENCODER_SUCCESS)
    return -1;

  /* Set event timestamp: use wire time from dnstap if configured,
   * otherwise fall back to current processing time. */
  if (ctx->use_dnstap_timestamp &&
      (d->query_time_sec > 0 || d->response_time_sec > 0)) {
    struct flb_time tm;
    flb_time_zero(&tm);
    if (d->query_time_sec > 0) {
      tm.tm.tv_sec  = (time_t)d->query_time_sec;
      tm.tm.tv_nsec = (long)d->query_time_nsec;
    } else {
      tm.tm.tv_sec  = (time_t)d->response_time_sec;
      tm.tm.tv_nsec = (long)d->response_time_nsec;
    }
    ret = flb_log_event_encoder_set_timestamp(enc, &tm);
  } else {
    ret = flb_log_event_encoder_set_current_timestamp(enc);
  }
  if (ret != FLB_EVENT_ENCODER_SUCCESS)
    return -1;

  /* Identity */
  if (d->identity) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("identity"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->identity));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Version */
  if (d->version) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("version"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->version));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Message type */
  if (d->message_type) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("message_type"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->message_type));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Socket family */
  if (d->socket_family) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("socket_family"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->socket_family));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Socket protocol */
  if (d->socket_protocol) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("socket_protocol"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->socket_protocol));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Query address */
  if (d->query_address) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("query_address"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->query_address));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Response address */
  if (d->response_address) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("response_address"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->response_address));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Ports */
  if (d->query_port > 0) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("query_port"),
        FLB_LOG_EVENT_UINT32_VALUE(d->query_port));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }
  if (d->response_port > 0) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("response_port"),
        FLB_LOG_EVENT_UINT32_VALUE(d->response_port));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* Timestamps */
  if (d->query_time_sec > 0) {
    double qt = (double)d->query_time_sec + (double)d->query_time_nsec / 1e9;
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("query_time"),
        FLB_LOG_EVENT_DOUBLE_VALUE(qt));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }
  if (d->response_time_sec > 0) {
    double rt =
        (double)d->response_time_sec + (double)d->response_time_nsec / 1e9;
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("response_time"),
        FLB_LOG_EVENT_DOUBLE_VALUE(rt));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  /* DNS parsed fields */
  if (d->qname) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("qname"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->qname));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }
  if (d->qtype) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("qtype"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->qtype));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }
  if (d->qclass) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("qclass"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->qclass));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }
  if (d->rcode) {
    ret = flb_log_event_encoder_append_body_values(
        enc, FLB_LOG_EVENT_CSTRING_VALUE("rcode"),
        FLB_LOG_EVENT_CSTRING_VALUE(d->rcode));
    if (ret != FLB_EVENT_ENCODER_SUCCESS)
      return -1;
  }

  ret = flb_log_event_encoder_commit_record(enc);
  if (ret != FLB_EVENT_ENCODER_SUCCESS)
    return -1;

  flb_input_log_append(ctx->ins, NULL, 0, enc->output_buffer,
                       enc->output_length);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Connection management                                              */
/* ------------------------------------------------------------------ */

static struct dnstap_conn *dnstap_conn_add(struct flb_connection *connection,
                                           struct flb_in_dnstap_config *ctx) {
  int ret;
  struct dnstap_conn *conn;

  conn = flb_calloc(1, sizeof(*conn));
  if (!conn) {
    flb_errno();
    return NULL;
  }

  conn->connection = connection;
  conn->ctx = ctx;

  /* Allocate incoming data buffer */
  conn->buf_size = ctx->buffer_chunk_size;
  conn->buf_data = flb_malloc(conn->buf_size);
  if (!conn->buf_data) {
    flb_errno();
    flb_free(conn);
    return NULL;
  }
  /* Set up event loop integration using Fluent Bit's native MK_EVENT.
   * We must read directly via the socket because coroutines (flb_io_net_read)
   * require a dedicated thread collector, which is heavier than our event loop approach.
   */
  MK_EVENT_NEW(&connection->event);
  connection->user_data = conn;
  connection->event.type = FLB_ENGINE_EV_CUSTOM;
  connection->event.handler = dnstap_conn_event;

  ret = mk_event_add(flb_engine_evl_get(), connection->fd, FLB_ENGINE_EV_CUSTOM,
                     MK_EVENT_READ, &connection->event);
  if (ret == -1) {
    flb_plg_error(ctx->ins, "could not register connection event");
    flb_free(conn->buf_data);
    flb_free(conn);
    return NULL;
  }

  mk_list_add(&conn->_head, &ctx->connections);
  ctx->active_connections++;
  return conn;
}

static void dnstap_conn_del(struct dnstap_conn *conn) {
  if (!conn)
    return;

  conn->ctx->active_connections--;
  if (conn->buf_data) {
    flb_free(conn->buf_data);
  }
  flb_downstream_conn_release(conn->connection);
  mk_list_del(&conn->_head);
  flb_free(conn);
}

/* Event callback: read raw bytes and pass to native FSTRM parser.
 * This runs directly in the Fluent Bit engine event loop. */
static int dnstap_conn_event(void *data) {
  struct flb_connection *connection = (struct flb_connection *)data;
  struct dnstap_conn *conn = connection->user_data;
  struct flb_in_dnstap_config *ctx = conn->ctx;
  int bytes_read;
    int available;
    /* Calculate remaining buffer space */
    available = conn->buf_size - conn->buf_len;
    
    /* If buffer is full, we must expand it (up to max limit) */
    if (available < 1) {
        if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
            flb_plg_error(ctx->ins, "fd=%d exceeded Buffer_Max_Size limit (%zu bytes), dropping", 
                          connection->fd, ctx->buffer_max_size);
            dnstap_conn_del(conn);
            return 0;
        }

        size_t new_size = conn->buf_size + ctx->buffer_chunk_size;
        char *tmp = flb_realloc(conn->buf_data, new_size);
        if (!tmp) {
            flb_errno();
            dnstap_conn_del(conn);
            return 0;
        }
        
        conn->buf_data = tmp;
        conn->buf_size = new_size;
        available = conn->buf_size - conn->buf_len;
    }

    /* Native raw read (non-blocking). We do not use TLS or flb_io_net_read 
     * here because this callback is running directly in the event loop, 
     * not inside a spawned coroutine. */
    bytes_read = read(connection->fd,
                      conn->buf_data + conn->buf_len,
                      available);

    if (bytes_read == 0) {
        /* EOF */
        flb_plg_debug(ctx->ins, "fd=%d connection closed by peer", connection->fd);
        dnstap_conn_del(conn);
        return 0;
    } else if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Handled below by re-arming */
            bytes_read = 0; 
        } else {
            /* Socket Error */
            flb_plg_debug(ctx->ins, "fd=%d read error: %s", connection->fd, strerror(errno));
            dnstap_conn_del(conn);
            return 0;
        }
    }

    conn->buf_len += bytes_read;

    /* Consume as many complete FSTRM frames as possible from the buffer */
    if (bytes_read > 0) {
        int consumed = dnstap_parser_consume(conn);
        if (consumed < 0) {
            /* Protocol Violation / Fatal Parsing Error */
            flb_plg_error(ctx->ins, "fd=%d protocol violation, destroying connection", connection->fd);
            dnstap_conn_del(conn);
            return 0;
        }

    /* Shift unparsed bytes (if any) to the front of the buffer using memmove */
    if (consumed > 0 && consumed <= conn->buf_len) {
        size_t remaining = conn->buf_len - consumed;
        if (remaining > 0) {
            memmove(conn->buf_data, conn->buf_data + consumed, remaining);
        }
        conn->buf_len = remaining;
    }
    
    /* Always re-arm the custom event so it triggers on the next EPOLLIN */
    mk_event_add(flb_engine_evl_get(), connection->fd,
                 FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ,
                 &connection->event);
  }

  return 0;
}

/* ------------------------------------------------------------------ */
/* Plugin callbacks                                                   */
/* ------------------------------------------------------------------ */

/*
 * ABI compatibility fix: Bypass the inline `flb_input_config_map_set()`!
 * The inline function reads fields (`net_config_map` and `net_properties`)
 * which appear *after* `flb_net_setup` in `struct flb_input_instance`.
 * Fluent Bit v4.0.14 increased the size of `flb_net_setup` by 8 bytes.
 * When a plugin compiled for 4.0.14 is loaded in a 4.0.0 daemon, the
 * trailing fields are shifted, causing `flb_input_config_map_set` to
 * read uninitialized memory and crash trying to parse a garbage pointer.
 *
 * `config_map` and `properties` are defined before `net_setup`, so their
 * ABI offsets remain stable across these patch versions.
 */
static int safe_input_config_map_set(struct flb_input_instance *ins, void *context) {
  if (ins->config_map) {
    return flb_config_map_set(&ins->properties, ins->config_map, context);
  }
  return -1;
}

static int cb_dnstap_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data) {
  int ret;
  struct flb_in_dnstap_config *ctx;

  (void)data;

  ctx = flb_calloc(1, sizeof(*ctx));
  if (!ctx) {
    flb_errno();
    return -1;
  }
  ctx->ins = in;
  ctx->collector_id = -1;

  /* Load config map (using ABI-safe helper) */
  ret = safe_input_config_map_set(in, (void *)ctx);
  if (ret == -1) {
    flb_plg_error(in, "unable to load configuration");
    flb_free(ctx);
    return -1;
  }

  /* Parse and validate socket permissions */
  if (ctx->socket_permissions) {
    char *endptr;
    errno = 0;
    long perm = strtol(ctx->socket_permissions, &endptr, 8);
    if (errno != 0 || *endptr != '\0' || perm < 0 || perm > 07777) {
      flb_plg_error(in, "invalid socket_permissions: '%s'",
                    ctx->socket_permissions);
      flb_free(ctx);
      return -1;
    }
    ctx->socket_acl = (int)perm;
  }

  mk_list_init(&ctx->connections);
  flb_input_set_context(in, ctx);

  /* Remove existing socket file */
  ret = remove_existing_socket_file(ctx->socket_path);
  if (ret != 0) {
    if (ret == -2) {
      flb_plg_error(in, "%s exists and is not a unix socket", ctx->socket_path);
    } else {
      flb_plg_error(in, "could not remove existing socket %s",
                    ctx->socket_path);
    }
    flb_free(ctx);
    return -1;
  }

  /* Create downstream (Unix STREAM socket) */
  ctx->downstream =
      flb_downstream_create(FLB_TRANSPORT_UNIX_STREAM, in->flags,
                            ctx->socket_path, 0, NULL, config, &in->net_setup);
  if (!ctx->downstream) {
    flb_plg_error(in, "could not create downstream on unix://%s",
                  ctx->socket_path);
    flb_free(ctx);
    return -1;
  }
  flb_input_downstream_set(ctx->downstream, in);

  /* Set socket permissions */
  if (ctx->socket_permissions) {
    ret = chmod(ctx->socket_path, ctx->socket_acl);
    if (ret != 0) {
      flb_errno();
      flb_plg_error(in, "cannot set permission on '%s' to %04o",
                    ctx->socket_path, ctx->socket_acl);
      flb_downstream_destroy(ctx->downstream);
      flb_free(ctx);
      return -1;
    }
  }

  /* Create log event encoder */
  ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
  if (!ctx->log_encoder) {
    flb_plg_error(in, "could not initialize event encoder");
    flb_downstream_destroy(ctx->downstream);
    flb_free(ctx);
    return -1;
  }

  /* Register collector for incoming connections */
  ret = flb_input_set_collector_socket(in, cb_dnstap_collect,
                                       ctx->downstream->server_fd, config);
  if (ret == -1) {
    flb_plg_error(in, "could not set collector for dnstap input");
    flb_log_event_encoder_destroy(ctx->log_encoder);
    flb_downstream_destroy(ctx->downstream);
    flb_free(ctx);
    return -1;
  }
  ctx->collector_id = ret;

  flb_plg_info(in, "listening on unix://%s", ctx->socket_path);
  return 0;
}

/* Accept new connections */
static int cb_dnstap_collect(struct flb_input_instance *in,
                             struct flb_config *config, void *in_context) {
  struct flb_connection *connection;
  struct dnstap_conn *conn;
  struct flb_in_dnstap_config *ctx = in_context;

  (void)config;

  /* Enforce connection limit to prevent resource exhaustion.
   * max_connections <= 0 means unlimited. */
  if (ctx->max_connections > 0 &&
      ctx->active_connections >= ctx->max_connections) {
    flb_plg_warn(ctx->ins, "max connections (%d) reached, rejecting",
                 ctx->max_connections);
    return -1;
  }

  connection = flb_downstream_conn_get(ctx->downstream);
  if (!connection) {
    flb_plg_error(ctx->ins, "could not accept new connection");
    return -1;
  }

  flb_plg_info(ctx->ins, "new dnstap connection fd=%d", connection->fd);

  conn = dnstap_conn_add(connection, ctx);
  if (!conn) {
    flb_downstream_conn_release(connection);
    return -1;
  }

  return 0;
}

static int cb_dnstap_exit(void *data, struct flb_config *config) {
  struct mk_list *head, *tmp;
  struct flb_in_dnstap_config *ctx = data;

  (void)config;

  if (!ctx)
    return 0;

  mk_list_foreach_safe(head, tmp, &ctx->connections) {
    struct dnstap_conn *conn = mk_list_entry(head, struct dnstap_conn, _head);
    dnstap_conn_del(conn);
  }

  if (ctx->log_encoder) {
    flb_log_event_encoder_destroy(ctx->log_encoder);
  }
  if (ctx->collector_id != -1) {
    flb_input_collector_delete(ctx->collector_id, ctx->ins);
  }
  if (ctx->downstream) {
    flb_downstream_destroy(ctx->downstream);
  }

  /* Remove the socket file so restarts don't fail */
  if (ctx->socket_path) {
    if (unlink(ctx->socket_path) != 0 && errno != ENOENT) {
      flb_plg_warn(ctx->ins, "failed to unlink socket %s on exit: %s",
                   ctx->socket_path, strerror(errno));
    }
  }

  flb_free(ctx);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Config map & plugin registration                                   */
/* ------------------------------------------------------------------ */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "socket_path", "/var/run/dnstap.sock", 0, FLB_TRUE,
     offsetof(struct flb_in_dnstap_config, socket_path),
     "Path to the Unix socket for receiving dnstap frames"},
    {FLB_CONFIG_MAP_STR, "socket_permissions", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_in_dnstap_config, socket_permissions),
     "Set the permissions for the UNIX socket (octal, e.g. 0666)"},
    {FLB_CONFIG_MAP_INT, "max_connections", "256", 0, FLB_TRUE,
     offsetof(struct flb_in_dnstap_config, max_connections),
     "Maximum number of concurrent dnstap connections"},
    {FLB_CONFIG_MAP_BOOL, "use_dnstap_timestamp", "false", 0, FLB_TRUE,
     offsetof(struct flb_in_dnstap_config, use_dnstap_timestamp),
     "Use the original dnstap wire timestamp instead of current time"},
    {FLB_CONFIG_MAP_SIZE, "Buffer_Chunk_Size", "32K", 0, FLB_TRUE,
     offsetof(struct flb_in_dnstap_config, buffer_chunk_size),
     "Chunk size for the incoming Unix socket buffer (default: 32K)"},
    {FLB_CONFIG_MAP_SIZE, "Buffer_Max_Size", "2M", 0, FLB_TRUE,
     offsetof(struct flb_in_dnstap_config, buffer_max_size),
     "Maximum frame limit size for incoming Unix socket data (default: 2M)"},
    /* EOF */
    {0}};
#pragma GCC diagnostic pop

struct flb_input_plugin in_dnstap_plugin = {
    .name = "dnstap",
    .description = "Dnstap input via Unix socket (Native Frame Streams parser)",
    .cb_init = cb_dnstap_init,
    .cb_pre_run = NULL,
    .cb_collect = cb_dnstap_collect,
    .cb_flush_buf = NULL,
    .cb_exit = cb_dnstap_exit,
    .config_map = config_map,
    .flags = FLB_INPUT_NET_SERVER};
