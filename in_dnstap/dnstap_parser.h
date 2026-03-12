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

#ifndef DNSTAP_PARSER_H
#define DNSTAP_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define FSTRM_CONTROL_ACCEPT 0x01
#define FSTRM_CONTROL_START  0x02
#define FSTRM_CONTROL_STOP   0x03
#define FSTRM_CONTROL_READY  0x04
#define FSTRM_CONTROL_FINISH 0x05

/* Frame length limit (we can use config bounds later, but this is a sane hard limit for protocol checking) */
#define FSTRM_MAX_DATA_FRAME_LEN 1048576 /* 1MB */
#define FSTRM_MAX_CTRL_FRAME_LEN 8192    /* 8KB */

struct dnstap_conn;

/* Parses as many FSTRM frames as possible from the connection buffer.
 * Returns the number of bytes consumed (which should be memmoved out by the caller),
 * or -1 on fatal failure (caller should drop connection).
 */
int dnstap_parser_consume(struct dnstap_conn *conn);

#endif /* DNSTAP_PARSER_H */
