/*
 * (C) Copyright 2018 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _SNOW_ICE_SCTP_H
#define _SNOW_ICE_SCTP_H

#define INET
#define INET6
#include <usrsctp.h>

#include "ice/dtls.h"
#include "ice/ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DATA_CHANNEL_PPID_CONTROL           50
#define DATA_CHANNEL_PPID_DOMSTRING         51
#define DATA_CHANNEL_PPID_BINARY            52

#define DATA_CHANNEL_CLOSED     0
#define DATA_CHANNEL_CONNECTING 1
#define DATA_CHANNEL_OPEN       2
#define DATA_CHANNEL_CLOSING    3

#define DATA_CHANNEL_FLAGS_SEND_REQ 0x00000001
#define DATA_CHANNEL_FLAGS_SEND_RSP 0x00000002
#define DATA_CHANNEL_FLAGS_SEND_ACK 0x00000004

#define DATA_CHANNEL_OPEN_REQUEST  3
#define DATA_CHANNEL_OPEN_RESPONSE 1
#define DATA_CHANNEL_ACK           2

#define DATA_CHANNEL_RELIABLE                          0x00
#define DATA_CHANNEL_RELIABLE_UNORDERED                0x80
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT           0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED 0x81
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED            0x02
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED  0x82

#define SCTP_SOCKET_STATE_INIT       (0x01)
#define SCTP_SOCKET_STATE_OPEN       (0x02)
#define SCTP_SOCKET_STATE_CONNECTING (0x03)
#define SCTP_SOCKET_STATE_CONNECTED  (0x04)
#define SCTP_SOCKET_STATE_CLOSED     (0x05)

#define SCTP_BUFFER_SIZE (512)

// http://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-05
typedef struct snw_sctp_datachannel_open_request snw_sctp_datachannel_open_request_t;
struct snw_sctp_datachannel_open_request {
  uint8_t  msg_type;
  uint8_t  channel_type;
  uint16_t priority;
  uint32_t reliability_params;
  uint16_t label_length;
  uint16_t protocol_length;
  char     label[0];
};

typedef struct snw_sctp_datachannel_ack snw_sctp_datachannel_ack_t;
struct snw_sctp_datachannel_ack {
  uint8_t msg_type;
};


struct snw_sctp_channel {
  uint32_t id;
  uint32_t pr_value;
  uint16_t pr_policy;
  uint16_t stream;
  uint8_t  unordered;
  uint8_t  state;
  uint32_t flags;
};

struct snw_ice_sctp_ctx {
  dtls_ctx_t    *dtls;

  snw_sctp_channel_t channel;

  struct socket *sock;
  uint16_t sock_state;
  uint16_t local_port;
  uint16_t remote_port;
};

int
snw_ice_sctp_init(snw_ice_context_t *ctx);

snw_ice_sctp_ctx_t*
snw_ice_sctp_create(snw_ice_context_t *ice_ctx, dtls_ctx_t *dtls, uint16_t port);

void
snw_ice_sctp_free(snw_ice_sctp_ctx_t *sctp);

int
snw_ice_sctp_data_from_dtls(snw_ice_sctp_ctx_t *sctp, char *buf, int len);

void
snw_ice_sctp_send_data(snw_ice_sctp_ctx_t *sctp, char *buf, int len);

void
snw_ice_sctp_deinit();

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_SCTP_H_


