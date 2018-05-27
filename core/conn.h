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


typedef struct snw_conn snw_conn_t;
struct snw_conn {
   uint32_t flowid;
   uint32_t channelid;
   uint32_t srctype;
   uint32_t ipaddr;
   uint16_t port;
};

snw_hashbase_t*
snw_conn_init();

snw_conn_t*
snw_conn_get(snw_hashbase_t *ctx, uint32_t peerid, int *is_new);

snw_conn_t*
snw_conn_search(snw_hashbase_t *ctx, uint32_t peerid);

snw_conn_t*
snw_conn_insert(snw_hashbase_t *ctx, snw_conn_t *sitem);

int 
snw_conn_remove(snw_hashbase_t *ctx, snw_conn_t *sitem);

#endif //_SNOW_CORE_PEER_H_


