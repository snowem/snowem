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

#include <stdio.h>

#include "core/cache.h"
#include "core/log.h"
#include "ice.h"
#include "ice_session.h"
#include "ice_types.h"
#include "sdp.h"

int
ice_session_key(const void *item) {  
   snw_ice_session_t *so =  (snw_ice_session_t *)item;
   return so->streamid;
}

int
ice_session_eq(const void *arg1, const void *arg2) {  
   snw_ice_session_t *item1 = (snw_ice_session_t *)arg1;
   snw_ice_session_t *item2 = (snw_ice_session_t *)arg2;
   return (item1->streamid == item2->streamid);
}

int
ice_session_isempty(const void *arg) {
   snw_ice_session_t *item = (snw_ice_session_t *)arg;
   return (item->streamid == 0);
}

int            
ice_session_setempty(const void *arg) {
   snw_ice_session_t *item = (snw_ice_session_t *)arg;
   item->streamid = 0;
   return 0;
}

int
snw_ice_session_init(snw_ice_context_t *ctx) {
   ctx->session_cache = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx->session_cache == 0)
      return -1;

   return snw_cache_init(ctx->session_cache, ICE_SESSION_SHM_KEY, ICE_SESSION_HASHTIME,
            ICE_SESSION_HASHLEN, sizeof(snw_ice_session_t),
            CACHE_FLAG_CREATE | CACHE_FLAG_INIT, ice_session_eq,
            ice_session_key, ice_session_isempty, ice_session_setempty);
}

snw_ice_session_t*
snw_ice_session_get(snw_ice_context_t *ctx, uint32_t streamid, int *is_new) {
   snw_log_t *log = 0;
   snw_ice_session_t key;
   snw_ice_session_t *so;

   if (!ctx) return 0;
   log = ctx->log;

   key.streamid = streamid;
   so = CACHE_GET(ctx->session_cache, &key, is_new, snw_ice_session_t*);

   if (so == 0)
      return 0;

   if (!(*is_new)) {
      WARN(log,"get old session, streamid=%u, ice_ctx=%p", 
            streamid, so->ice_ctx);
      return so;
   }

   // reset new session
   DEBUG(log,"get new session, streamid=%u, is_new=%u, ice_ctx=%p", 
         streamid, *is_new, so->ice_ctx);
   memset(so, 0, sizeof(snw_ice_session_t));
   LIST_INIT(&so->streams);
   so->streamid = streamid;

   return so;
}

snw_ice_session_t*
snw_ice_session_search(snw_ice_context_t *ctx, uint32_t streamid) {
   snw_ice_session_t sitem;
   sitem.streamid = streamid;
   return (snw_ice_session_t*)snw_cache_search(ctx->session_cache, &sitem);
}

snw_ice_session_t*
snw_ice_session_insert(snw_ice_context_t *ctx, snw_ice_session_t *sitem) {
   return (snw_ice_session_t*)snw_cache_insert(ctx->session_cache, sitem);
}

int 
snw_ice_session_remove(snw_ice_context_t *ctx, snw_ice_session_t *sitem) {
   return snw_cache_remove(ctx->session_cache, sitem);
}


