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

#ifndef _SNOW_ICE_ICE_H_
#define _SNOW_ICE_ICE_H_

#include <arpa/inet.h>
#include <bsd/bsd.h>
#include <openssl/ssl.h>

#include "cice/event.h"
#include "core/cache.h"
#include "core/mempool.h"
#include "core/task.h"
#include "core/types.h"
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct snw_ice_handlers snw_ice_handlers_t;
struct snw_ice_handlers {
   uint32_t         msgtype;
   uint32_t         api;
   void           (*handler)(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);
   TAILQ_ENTRY(snw_ice_handlers) list;
};
typedef TAILQ_HEAD(ice_handlers_head, snw_ice_handlers) ice_handlers_head_t;

typedef struct snw_ice_api snw_ice_api_t;
struct snw_ice_api {
   uint32_t            msgtype;
   ice_handlers_head_t handlers;
   TAILQ_ENTRY(snw_ice_api) list;
};
typedef TAILQ_HEAD(ice_api_head, snw_ice_api) ice_api_head_t;

#define RECORD_FOLDER_LEN 256
struct snw_ice_context {
   void      *ctx;
   struct event_base  *ev_base;
   event_ctx_t        *ev_ctx;
   snw_log_t *log;

   int        rtcpmux_enabled;
   int        ice_lite_enabled;
   int        ipv6_enabled;
   int        ice_tcp_enabled;
   int        recording_enabled;
   const char *recording_folder;

   char       local_ip[INET6_ADDRSTRLEN];
   char       public_ip[INET6_ADDRSTRLEN];

   /* caches, efficiency in search */
   snw_hashbase_t *session_cache;
   snw_hashbase_t *subscribe_cache;

   /* mempools for fixed-size objects, fast in (de)allocation */
   snw_mempool_t  *stream_mempool;
   snw_mempool_t  *component_mempool;

   SSL_CTX        *ssl_ctx;
   char            local_fingerprint[160];

   ice_api_head_t  api_handlers;
   snw_task_ctx_t *task_ctx;
};

void
snw_ice_task_cb(snw_task_ctx_t *ctx, void *data);

void
ice_rtp_established(snw_ice_session_t *session);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_ICE_H_
