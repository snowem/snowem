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

#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "channel.h"
#include "types.h"

int
channel_key(const void *item)
{  
   snw_channel_t *so =  (snw_channel_t *)item;
   return so->id;
}

int
channel_eq(const void *arg1, const void *arg2)
{  
   snw_channel_t *item1 = (snw_channel_t *)arg1;
   snw_channel_t *item2 = (snw_channel_t *)arg2;
   return (item1->id == item2->id);
}

int
channel_isempty(const void *arg)
{
   snw_channel_t *item = (snw_channel_t *)arg;
   return (item->id == 0);
}

int
channel_setempty(const void *arg)
{
   snw_channel_t *item = (snw_channel_t *)arg;
   item->id = 0;
   return 0;
}

snw_hashbase_t*
snw_channel_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   ret = snw_cache_init(ctx, CORE_CHANNEL_SHM_KEY, CORE_CHANNEL_HASHTIME, 
         CORE_CHANNEL_HASHLEN, sizeof(snw_channel_t),
         CACHE_FLAG_CREATE | CACHE_FLAG_INIT, channel_eq, 
         channel_key, channel_isempty, channel_setempty);
   if (ret < 0) return 0;

   return ctx;
}

snw_channel_t*
snw_channel_get(snw_hashbase_t *ctx, uint32_t id, int *is_new) {
   snw_channel_t key;
   snw_channel_t *so;
   
   key.id = id;
   so = CACHE_GET(ctx, &key, is_new, snw_channel_t*);

   if (so == 0) return 0;

   if (!(*is_new)) return so;

   // reset new channel
   memset(so, 0, sizeof(snw_channel_t));
   so->id = id;

   return so;
}

snw_channel_t*
snw_channel_search(snw_hashbase_t *ctx, uint32_t id) {
   snw_channel_t sitem;
   sitem.id = id;
   return (snw_channel_t*)snw_cache_search(ctx, &sitem);
}

snw_channel_t*
snw_channel_insert(snw_hashbase_t *ctx, snw_channel_t *sitem) {
   return (snw_channel_t*)snw_cache_insert(ctx, sitem);
}

int 
snw_channel_remove(snw_hashbase_t *ctx, snw_channel_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}

void
snw_list_add_item(snw_list_t *l, uint32_t id) {
  if (!l) return;

  l->list[l->idx] = id;
  l->idx++;

  return;
}

void
snw_list_remove_item(snw_list_t *l, uint32_t id) {
  int i = 0;

  if (!l) return;
  
  for (i=0; i < l->idx; i++) {
    if (l->list[i] == id)
      break;
  }
  if (l->idx <= i) return;
  l->list[i] = l->list[l->idx];
  l->idx--;

  return;
}


