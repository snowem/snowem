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

#include <stdlib.h>
#include <string.h>

#include "core/cache.h"
#include "core/log.h"
#include "ice.h"
#include "ice_subscribe.h"
#include "ice_types.h"


int
ice_subscribe_key(const void *item) {  
   snw_ice_subscribe_t *so =  (snw_ice_subscribe_t *)item;
   return so->id;
}

int
ice_subscribe_eq(const void *arg1, const void *arg2) {  
   snw_ice_subscribe_t *item1 = (snw_ice_subscribe_t *)arg1;
   snw_ice_subscribe_t *item2 = (snw_ice_subscribe_t *)arg2;
   return (item1->id == item2->id);
}

int
ice_subscribe_isempty(const void *arg) {
   snw_ice_subscribe_t *item = (snw_ice_subscribe_t *)arg;
   return (item->id == 0);
}

int
ice_subscribe_setempty(const void *arg) {
   snw_ice_subscribe_t *item = (snw_ice_subscribe_t *)arg;
   item->id = 0;
   return 0;
}

int
snw_ice_subscribe_init(snw_ice_context_t *ctx) {
   ctx->subscribe_cache = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx->subscribe_cache == 0)
      return -1;

   return snw_cache_init(ctx->subscribe_cache, ICE_SUBSCRIBE_SHM_KEY, ICE_SUBSCRIBE_HASHTIME, 
            ICE_SUBSCRIBE_HASHLEN, sizeof(snw_ice_subscribe_t),
            CACHE_FLAG_CREATE | CACHE_FLAG_INIT, ice_subscribe_eq, 
            ice_subscribe_key, ice_subscribe_isempty, ice_subscribe_setempty);
}

snw_ice_subscribe_t*
snw_ice_subscribe_get(snw_ice_context_t *ctx, uint32_t id, int *is_new) {
   snw_ice_subscribe_t key;
   snw_ice_subscribe_t *so;

   key.id = id;
   so = CACHE_GET(ctx->subscribe_cache, &key, is_new, snw_ice_subscribe_t*);

   if (so == 0) return 0;

   if (!(*is_new)) return so;

   // reset new subscribe
   memset(so, 0, sizeof(snw_ice_subscribe_t));
   so->id = id;

   return so;
}

snw_ice_subscribe_t*
snw_ice_subscribe_search(snw_ice_context_t *ctx, uint32_t id) {
   snw_ice_subscribe_t sitem;
   sitem.id = id;
   return (snw_ice_subscribe_t*)snw_cache_search(ctx->subscribe_cache, &sitem);
}

snw_ice_subscribe_t*
snw_ice_subscribe_insert(snw_ice_context_t *ctx, snw_ice_subscribe_t *sitem) {
   return (snw_ice_subscribe_t*)snw_cache_insert(ctx->subscribe_cache, sitem);
}

int
snw_ice_subscribe_remove(snw_ice_context_t *ctx, snw_ice_subscribe_t *sitem) {
   return snw_cache_remove(ctx->subscribe_cache, sitem);
}

#ifdef SNW_ENABLE_DEBUG
void
snw_print_subscribe_info(snw_ice_context_t *ctx, snw_ice_subscribe_t *c) {
   static char buffer[SNW_ICE_SUBSCRIBE_USER_NUM_MAX * 11];
   int i = 0;
   int j = 0;

   if (!ctx) return;

   memset(buffer,0, SNW_ICE_SUBSCRIBE_USER_NUM_MAX * 11);
   for(i=0,j=0; i< SNW_ICE_SUBSCRIBE_USER_NUM_MAX; i++) {
     if(c->players[i] == 0) continue;
     sprintf(buffer + j*10, "%9u ", c->players[i]);
     j++;
   }
   DEBUG(ctx->log, "subscribe info, id=%u, idx=%u, players= %s",
         c->id, c->idx, buffer);
   return;

}
#endif

void
snw_subscribe_add_subscriber(snw_ice_context_t *ice_ctx, 
      uint32_t publishid, uint32_t streamid) {
   snw_log_t *log = 0;
   snw_ice_subscribe_t *subscribe = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   subscribe = (snw_ice_subscribe_t*)snw_ice_subscribe_search(ice_ctx, publishid);
   if (!subscribe) {
     ERROR(log, "publisher not found, publishid=%u", publishid);
     return;
   }

   if (subscribe->idx >= SNW_ICE_SUBSCRIBE_USER_NUM_MAX) {
      ERROR(log, "subscribe info full, streamid=%u, publishid=%u", streamid, publishid);
      return;
   }
   subscribe->players[subscribe->idx] = streamid;
   subscribe->idx++;

#ifdef SNW_ENABLE_DEBUG
   snw_print_subscribe_info(ice_ctx,subscribe); 
#endif

   return;
}

void
snw_subscribe_remove_subscriber(snw_ice_context_t *ice_ctx, 
      uint32_t publishid, uint32_t streamid) {
   snw_log_t *log = 0;
   snw_ice_subscribe_t *subscribe = 0;
   int found = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   DEBUG(log, "removing from subscribe, streamid=%u, publishid=%u", 
        streamid, publishid);
   subscribe = (snw_ice_subscribe_t*)snw_ice_subscribe_search(ice_ctx,publishid);
   if (!subscribe) return;

   for (uint32_t i=0; i<subscribe->idx; i++) {
      if (subscribe->players[i] == streamid) {
         found = 1;
         subscribe->idx--;
         subscribe->players[i] = subscribe->players[subscribe->idx];
         subscribe->players[subscribe->idx] = 0;
         break;
      }
   }

#ifdef SNW_ENABLE_DEBUG
   snw_print_subscribe_info(ice_ctx,subscribe); 
#endif

   if (!found) {
      WARN(log, "not found, streamid=%u, publishid=%u", streamid, publishid);
      return;
   }

   return;
}
