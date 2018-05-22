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
#include "core/stream.h"

int
stream_key(const void *item)
{  
   snw_stream_t *so =  (snw_stream_t *)item;
   return so->id;
}

int
stream_eq(const void *arg1, const void *arg2)
{  
   snw_stream_t *item1 = (snw_stream_t *)arg1;
   snw_stream_t *item2 = (snw_stream_t *)arg2;
   return (item1->id == item2->id);
}

int
stream_isempty(const void *arg)
{
   snw_stream_t *item = (snw_stream_t *)arg;
   return (item->id == 0);
}

int            
stream_setempty(const void *arg)
{
   snw_stream_t *item = (snw_stream_t *)arg;
   item->id = 0;
   return 0;
}


snw_hashbase_t*
snw_stream_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   ret = snw_cache_init(ctx, CORE_STREAM_SHM_KEY, 
           CORE_STREAM_HASHTIME, CORE_STREAM_HASHLEN,
           sizeof(snw_stream_t), CACHE_FLAG_CREATE | CACHE_FLAG_INIT, 
           stream_eq, stream_key, stream_isempty, stream_setempty);

   if (ret < 0) return 0;

   return ctx;
}

snw_stream_t*
snw_stream_get(snw_hashbase_t *ctx, uint32_t id, int *is_new) {
   snw_stream_t key;
   snw_stream_t *so;
  
   if (!ctx) return 0;
    
   key.id = id;
   so = CACHE_GET(ctx, &key, is_new, snw_stream_t*);

   if (so == 0)
      return 0;

   if (!(*is_new)) {
      return so;
   }

   // reset new session
   memset(so, 0, sizeof(snw_stream_t));
   so->id = id;

   return so;
}

/*CACHE_SEARCH(ctx, sitem, snw_stream_t*);*/
snw_stream_t*
snw_stream_search(snw_hashbase_t *ctx, uint32_t id) {
   snw_stream_t sitem;
   sitem.id = id;
   return (snw_stream_t*)snw_cache_search(ctx, &sitem);
}

/*CACHE_INSERT(ctx, sitem, snw_stream_t*);*/
snw_stream_t*
snw_stream_insert(snw_hashbase_t *ctx, snw_stream_t *sitem) {
   return (snw_stream_t*)snw_cache_insert(ctx, sitem);
}

/*CACHE_REMOVE(ctx, sitem, snw_stream_t*);*/
int 
snw_stream_remove(snw_hashbase_t *ctx, snw_stream_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}


/*void
stream_remove(uint32_t key)
{
   hashbase_t *base = g_handle_base;
   snw_stream_t *item = 0;
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
      item = (snw_stream_t*)(table
                   + i*base->hb_len*base->hb_objsize
                   + value*base->hb_objsize);
      if ( item->id == key ) {
         item->id = 0;
      }
   }

   return;
}*/


