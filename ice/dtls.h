/*
 * (C) Copyright 2017 Jackie Dinh <jackiedinh8@gmail.com>
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

#ifndef _ICE_DTLS_H
#define _ICE_DTLS_H

#include <inttypes.h>
#include <srtp/srtp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ice/ice.h"
#include "ice/sctp.h"

/* dtls stuff */
#define DTLS_CIPHERS "ALL:NULL:eNULL:aNULL"
#define DTLS_BUFFER_SIZE 1500
#define DTLS_MTU_SIZE 1472
#define DTLS_ERR_STR ERR_reason_error_string(ERR_get_error())

/* srtp stuff */
#define SRTP_MASTER_KEY_LENGTH   16
#define SRTP_MASTER_SALT_LENGTH  14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)

/* dtls type */
enum  {
   DTLS_TYPE_ACTPASS = 0,
   DTLS_TYPE_SERVER,
   DTLS_TYPE_CLIENT,
};

enum {
   DTLS_STATE_CONNECTING = 0,
   DTLS_STATE_CONNECTED,
   DTLS_STATE_ERROR,
};

struct dtls_ctx {
   snw_ice_context_t *ctx;
   void              *component;

   int    type;
   int    state;

   /* handshake stuff */
   SSL *ssl;
   BIO *in_bio;
   BIO *out_bio;
   BIO *dtls_bio;

   /* srtp context */
   unsigned char material[SRTP_MASTER_LENGTH*2];
   srtp_t srtp_in;
   srtp_t srtp_out;

   /* sctp context */
   snw_ice_sctp_ctx_t *sctp;
};

int
dtls_init(snw_ice_context_t *ctx, char *server_pem, char *server_key);

dtls_ctx_t*
dtls_create(snw_ice_context_t *ice_ctx, void *component, int role);

void
dtls_free(dtls_ctx_t *dtls);

void
dtls_do_handshake(dtls_ctx_t *dtls);

int
dtls_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len);

int
dtls_send_sctp_outcoming_data(dtls_ctx_t *dtls, char *buf, int len);

void
dtls_send_sctp_data(dtls_ctx_t *dtls, char *buf, int len);

void
dtls_notify_sctp_data(dtls_ctx_t *dtls, char *buf, int len);

#endif

