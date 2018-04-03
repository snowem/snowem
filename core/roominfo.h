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

#ifndef _SNOW_CORE_ROOMINFO_H_
#define _SNOW_CORE_ROOMINFO_H_

#include <stdint.h>

#include "types.h"

typedef struct snw_roominfo snw_roominfo_t;
struct snw_roominfo {
   uint32_t id;
   char     name[64];
   uint32_t channelid;
   uint64_t expired_ts;
   uint64_t last_ts;
};

snw_hashbase_t*
snw_roominfo_init();

snw_roominfo_t*
snw_roominfo_get(snw_hashbase_t *ctx, const char* name, int len, int *is_new);

snw_roominfo_t*
snw_roominfo_search(snw_hashbase_t *ctx, const char *name, int len);

snw_roominfo_t*
snw_roominfo_insert(snw_hashbase_t *ctx, snw_roominfo_t *sitem);

int 
snw_roominfo_remove(snw_hashbase_t *ctx, snw_roominfo_t *sitem);

#endif //_SNOW_CORE_ROOMINFO_H_


