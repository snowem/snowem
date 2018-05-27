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
#include "log.h"
#include "peer.h"

int
peer_key(const void *item)
{  
   snw_peer_t *so =  (snw_peer_t *)item;
   return so->flowid;
}

int
peer_eq(const void *arg1, const void *arg2)
{  
   snw_peer_t *item1 = (snw_peer_t *)arg1;
   snw_peer_t *item2 = (snw_peer_t *)arg2;
   return (item1->flowid == item2->flowid);
}

int
peer_isempty(const void *arg)
{
   snw_peer_t *item = (snw_peer_t *)arg;
   return (item->flowid == 0);
}

int            
peer_setempty(const void *arg)
{
   snw_peer_t *item = (snw_peer_t *)arg;
   item->flowid = 0;
   return 0;
}


snw_hashbase_t*
snw_peer_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   ret = snw_cache_init(ctx, CORE_PEER_SHM_KEY, 
           CORE_PEER_HASHTIME, CORE_PEER_HASHLEN,
           sizeof(snw_peer_t), CACHE_FLAG_CREATE | CACHE_FLAG_INIT, 
           peer_eq, peer_key, peer_isempty, peer_setempty);

   if (ret < 0) return 0;

   return ctx;
}

snw_peer_t*
snw_peer_get(snw_hashbase_t *ctx, uint32_t flowid, int *is_new) {
   snw_peer_t key;
   snw_peer_t *so;
  
   if (!ctx) return 0;
    
   key.flowid = flowid;
   so = CACHE_GET(ctx, &key, is_new, snw_peer_t*);

   if (so == 0)
      return 0;

   if (!(*is_new)) {
      return so;
   }

   // reset new session
   memset(so, 0, sizeof(snw_peer_t));
   so->flowid = flowid;

   return so;
}

/*CACHE_SEARCH(ctx, sitem, snw_peer_t*);*/
snw_peer_t*
snw_peer_search(snw_hashbase_t *ctx, uint32_t flowid) {
   snw_peer_t sitem;
   sitem.flowid = flowid;
   return (snw_peer_t*)snw_cache_search(ctx, &sitem);
}

/*CACHE_INSERT(ctx, sitem, snw_peer_t*);*/
snw_peer_t*
snw_peer_insert(snw_hashbase_t *ctx, snw_peer_t *sitem) {
   return (snw_peer_t*)snw_cache_insert(ctx, sitem);
}

/*CACHE_REMOVE(ctx, sitem, snw_peer_t*);*/
int 
snw_peer_remove(snw_hashbase_t *ctx, snw_peer_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}


/*void
peer_remove(uint32_t key)
{
   hashbase_t *base = g_handle_base;
   snw_peer_t *item = 0;
   char *table = 0;
   int   value = 0;
   uint32_t      i;

   if ( base == NULL )
      return;

   if ( key == 0 )
      return;

   table = (char*)base->hb_cache;

   for ( i=0; i < base->hb_time; i++ ) {
      value = key % base->hb_base[i];
      item = (snw_peer_t*)(table
                   + i*base->hb_len*base->hb_objsize
                   + value*base->hb_objsize);
      if ( item->flowid == key ) {
         item->flowid = 0;
      }
   }

   return;
}*/


