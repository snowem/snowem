/*
 * (C) Copyright 2016 Jackie Dinh <jackiedinh8@gmail.com>
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

#ifndef _SNOW_CORE_CORE_H_
#define _SNOW_CORE_CORE_H_

#include <stdio.h>
#include <time.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <evhttp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "cache.h"
#include "channel_mgr.h"
#include "flow.h"
#include "ice/ice.h"
#include "mempool.h"
#include "mq.h"
#include "module.h"
#include "task.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// shared mem info for message queues
#define SHAREDMEM_SIZE 33554432
#define ICE2CORE_KEY 1168647512
#define CORE2ICE_KEY 1168647513
#define NET2CORE_KEY 1168647514
#define CORE2NET_KEY 1168647515
#define HTTP2CORE_KEY 1168647516
#define CORE2HTTP_KEY 1168647517
#define TEST2CORE_KEY 1168647518
#define CORE2TEST_KEY 1168647519

typedef void (*dispatch_fn)(int fd, short int event,void* data);
struct snw_context {
   snw_log_t          *log;
   time_t              cur_time;
   struct event_base  *ev_base;
   SSL_CTX            *ssl_ctx;

   const char         *config_file;
   const char         *ice_cert_file;
   const char         *ice_key_file;

   const char         *wss_cert_file;
   const char         *wss_key_file;
   const char         *wss_ip;
   uint16_t            wss_port;

   const char         *base_path;
   const char         *main_log_file;
   const char         *ice_log_file;
   const char         *websocket_log_file;
   const char         *http_log_file;

   uint32_t            log_file_maxsize;
   uint32_t            log_rotate_num;
   uint32_t            log_level;

   uint32_t            ice_log_enabled:1;
   uint32_t            websocket_log_enabled:1;
   uint32_t            http_log_enabled:1;
   uint32_t            libevent_log_enabled:1;
   uint32_t            test_webserver_enabled:1;
   uint32_t            reserved:27;

   /* task contexts */
   snw_task_ctx_t *http_task;
   snw_task_ctx_t *net_task;
   snw_task_ctx_t *ice_task;

   /* caches */
   snw_hashbase_t *channel_cache;
   snw_hashbase_t *peer_cache;
   snw_hashbase_t *roominfo_cache;

   /* channel set */
   snw_set_t      *channel_mgr;

   /* mempool for fixed-size objects */
   snw_mempool_t *rcvvars_mp;

   module_head_t  modules;

   /* map from flowid to peerid */
   uint32_t flow2peer[SNW_CORE_FLOW_NUM_MAX];
};

#define SET_FLOW2PEER(flowid,peerid) \
  if (flowid > SNW_CORE_FLOW_BASE_IDX \
      && ((flowid - SNW_CORE_FLOW_BASE_IDX) < SNW_CORE_FLOW_NUM_MAX)) { \
    ctx->flow2peer[flowid-SNW_CORE_FLOW_BASE_IDX] = peerid; \
  }

#define GET_FLOW2PEER(flowid) \
  (flowid > SNW_CORE_FLOW_BASE_IDX \
      && ((flowid - SNW_CORE_FLOW_BASE_IDX) < SNW_CORE_FLOW_NUM_MAX)) ?  \
    ctx->flow2peer[flowid-SNW_CORE_FLOW_BASE_IDX] : 0;

snw_context_t*
snw_create_context();

void 
daemonize();

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_CORE_H_



