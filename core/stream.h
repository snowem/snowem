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

#ifndef _SNOW_CORE_STREAM_H_
#define _SNOW_CORE_STREAM_H_

#include <stdint.h>

#include "types.h"

typedef struct snw_stream snw_stream_t;
struct snw_stream {
   uint32_t id; //streamid
   uint32_t flowid;
   int      type;
   int      state;
};

snw_hashbase_t*
snw_stream_init();

snw_stream_t*
snw_stream_get(snw_hashbase_t *ctx, uint32_t peerid, int *is_new);

snw_stream_t*
snw_stream_search(snw_hashbase_t *ctx, uint32_t peerid);

snw_stream_t*
snw_stream_insert(snw_hashbase_t *ctx, snw_stream_t *sitem);

int 
snw_stream_remove(snw_hashbase_t *ctx, snw_stream_t *sitem);

#endif //_SNOW_CORE_PEER_H_


