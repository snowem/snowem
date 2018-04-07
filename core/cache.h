/*
 * (C) Copyright 2015 Jackie Dinh <jackiedinh8@gmail.com>
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

#ifndef _SNOW_CORE_CACHE_H_
#define _SNOW_CORE_CACHE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CACHE_FLAG_CREATE (1<<0)
#define CACHE_FLAG_INIT   (1<<1)

typedef int (*eqfn) (const void *, const void *);
typedef int (*keyfn) (const void *);
typedef int (*isemptyfn) (const void *);
typedef int (*setemptyfn) (const void *);

typedef struct snw_hashbase snw_hashbase_t;
struct snw_hashbase {
   uint32_t   hb_pid;
   uint32_t   hb_time;
   uint32_t   hb_len;
   uint32_t   hb_objsize;
   uint32_t  *hb_base;
   uint32_t   hb_size;
   char      *hb_cache;
   eqfn       hb_eqfn;
   keyfn      hb_keyfn;
   isemptyfn  hb_isemptyfn;
   setemptyfn hb_setemptyfn;
};

int
snw_cache_init(snw_hashbase_t *base, uint32_t key, 
      uint32_t hashtime, uint32_t hashlen, uint32_t objsize, 
      uint32_t create, eqfn equal_fn, keyfn key_fn,
      isemptyfn isempty_fn, setemptyfn setempty_fn);

void*
snw_cache_get(snw_hashbase_t *base, void *sitem, int *is_new);

void*
snw_cache_search(snw_hashbase_t *base, void *sitem);

void*
snw_cache_insert(snw_hashbase_t *base, void *sitem);

int
snw_cache_remove(snw_hashbase_t *base, void *sitem);

int
snw_cache_finit(snw_hashbase_t *base);

void*
snw_cache_search_new(snw_hashbase_t *base, void *sitem, eqfn _eqfn);

#define CACHE_GET(base, item, is_new, type) (type)(snw_cache_get(base, item, is_new));
#define CACHE_SEARCH(base, item, type) (type)(snw_cache_search(base, item));
#define CACHE_INSERT(base, item, type) (type)snw_cache_insert(base, item);
#define CACHE_REMOVE(base, item) snw_cache_remove(base, item);

/*
int 
snw_cache_size();

void 
snw_cache_status(float& fHashPercent,int& iHashTimeFree);

void 
snw_cache_itemcount();
*/

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_CACHE_H_
