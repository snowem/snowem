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
#include "roominfo.h"
#include "types.h"

char g_empty_roominfo[ROOM_NAME_LEN];

int
roominfo_hash(char *str, int len) {
   unsigned char *ustr = (unsigned char*)str;
   int hash = 5381;
   for (int i=0; i<len; i++)
      hash = ((hash << 5) + hash) + ustr[i]; /* hash * 33 + c */
   return hash;
}

inline int
roominfo_key(const void *item) {  
   snw_roominfo_t *so =  (snw_roominfo_t *)item;
   return so->id;
}

inline int
roominfo_eq(const void *arg1, const void *arg2) {  
   snw_roominfo_t *item1 = (snw_roominfo_t *)arg1;
   snw_roominfo_t *item2 = (snw_roominfo_t *)arg2;

   return !strncmp(item1->name,item2->name,ROOM_NAME_LEN);
}

inline int
roominfo_isempty(const void *arg) {
   snw_roominfo_t *item = (snw_roominfo_t *)arg;
   return !strncmp(item->name,g_empty_roominfo,ROOM_NAME_LEN);
}

inline int            
roominfo_setempty(const void *arg)
{
   snw_roominfo_t *item = (snw_roominfo_t *)arg;
   memset(item, 0, sizeof(*item));
   return 0;
}

snw_hashbase_t*
snw_roominfo_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   ret = snw_cache_init(ctx, CORE_ROOMINFO_SHM_KEY, CORE_ROOMINFO_HASHTIME, 
         CORE_ROOMINFO_HASHLEN, sizeof(snw_roominfo_t),
         CACHE_FLAG_CREATE | CACHE_FLAG_INIT, roominfo_eq, 
         roominfo_key, roominfo_isempty, roominfo_setempty);
   if (ret < 0) return 0;
   memset(g_empty_roominfo,0,ROOM_NAME_LEN);
   return ctx;
}

snw_roominfo_t*
snw_roominfo_get(snw_hashbase_t *ctx, const char *name, int len, int *is_new) {
   snw_roominfo_t key;
   snw_roominfo_t *so = 0;

   if (!ctx || len >= ROOM_NAME_LEN) return 0;
  
   *is_new = 0; 
   memset(&key, 0, sizeof(key));
   key.id = roominfo_hash((char*)name,len);
   memcpy(key.name,name,len);
   so = CACHE_GET(ctx, &key, is_new, snw_roominfo_t*);
   if (so == 0) return 0;
   if (!(*is_new)) return so;

   // reset new room
   memset(so, 0, sizeof(snw_roominfo_t));
   so->id = key.id;
   memcpy(so->name,name,len);

   return so;
}

snw_roominfo_t*
snw_roominfo_search(snw_hashbase_t *ctx, const char *name, int len) {
   snw_roominfo_t sitem;
   memset(&sitem,0,sizeof(sitem));
   if (len >= ROOM_NAME_LEN) return 0;
   sitem.id = roominfo_hash((char*)name,len);
   memcpy(sitem.name,name,len);
   return (snw_roominfo_t*)snw_cache_search(ctx, &sitem);
}

snw_roominfo_t*
snw_roominfo_insert(snw_hashbase_t *ctx, snw_roominfo_t *sitem) {
   return (snw_roominfo_t*)snw_cache_insert(ctx, sitem);
}

/*CACHE_REMOVE(ctx, sitem, snw_roominfo_t*);*/
int 
snw_roominfo_remove(snw_hashbase_t *ctx, snw_roominfo_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}





