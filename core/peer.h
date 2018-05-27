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

#ifndef _SNOW_CORE_PEER_H_
#define _SNOW_CORE_PEER_H_

#include <stdint.h>

#include "types.h"

enum {
   PEER_TYPE_UNKNOWN = 0,
   PEER_TYPE_PUBLISHER = 1,
   PEER_TYPE_PLAYER = 2,
   PEER_TYPE_P2P = 3,
};


typedef struct snw_peer snw_peer_t;
struct snw_peer {
   uint32_t flowid;
   uint32_t peerid;
   uint32_t channelid;
   int      peer_type;
};

snw_hashbase_t*
snw_peer_init();

snw_peer_t*
snw_peer_get(snw_hashbase_t *ctx, uint32_t peerid, int *is_new);

snw_peer_t*
snw_peer_search(snw_hashbase_t *ctx, uint32_t peerid);

snw_peer_t*
snw_peer_insert(snw_hashbase_t *ctx, snw_peer_t *sitem);

int 
snw_peer_remove(snw_hashbase_t *ctx, snw_peer_t *sitem);

#endif //_SNOW_CORE_PEER_H_


