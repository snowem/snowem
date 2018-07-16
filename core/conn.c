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

#include "cache.h"
#include "conn.h"
#include "log.h"

int
conn_key(const void *item)
{  
   snw_conn_t *so =  (snw_conn_t *)item;
   return so->flowid;
}

int
conn_eq(const void *arg1, const void *arg2)
{  
   snw_conn_t *item1 = (snw_conn_t *)arg1;
   snw_conn_t *item2 = (snw_conn_t *)arg2;
   return (item1->flowid == item2->flowid);
}

int
conn_isempty(const void *arg)
{
   snw_conn_t *item = (snw_conn_t *)arg;
   return (item->flowid == 0);
}

int            
conn_setempty(const void *arg)
{
   snw_conn_t *item = (snw_conn_t *)arg;
   item->flowid = 0;
   return 0;
}


snw_hashbase_t*
snw_conn_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   ret = snw_cache_init(ctx, CORE_PEER_SHM_KEY, 
           CORE_PEER_HASHTIME, CORE_PEER_HASHLEN,
           sizeof(snw_conn_t), CACHE_FLAG_CREATE | CACHE_FLAG_INIT, 
           conn_eq, conn_key, conn_isempty, conn_setempty);

   if (ret < 0) return 0;

   return ctx;
}

snw_conn_t*
snw_conn_get(snw_hashbase_t *ctx, uint32_t flowid, int *is_new) {
   snw_conn_t key;
   snw_conn_t *so;
  
   if (!ctx) return 0;
    
   key.flowid = flowid;
   so = CACHE_GET(ctx, &key, is_new, snw_conn_t*);

   if (so == 0)
      return 0;

   if (!(*is_new)) {
      return so;
   }

   // reset new session
   memset(so, 0, sizeof(snw_conn_t));
   so->flowid = flowid;

   return so;
}

snw_conn_t*
snw_conn_search(snw_hashbase_t *ctx, uint32_t flowid) {
   snw_conn_t sitem;
   sitem.flowid = flowid;
   return (snw_conn_t*)snw_cache_search(ctx, &sitem);
}

snw_conn_t*
snw_conn_insert(snw_hashbase_t *ctx, snw_conn_t *sitem) {
   return (snw_conn_t*)snw_cache_insert(ctx, sitem);
}

int 
snw_conn_remove(snw_hashbase_t *ctx, snw_conn_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}



