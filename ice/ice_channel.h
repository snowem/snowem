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

#ifndef _SNOW_ICE_CHANNEL_H_
#define _SNOW_ICE_CHANNEL_H_

#include "core/types.h"
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNW_ICE_CHANNEL_USER_NUM_MAX 500
typedef struct snw_play_list snw_play_list_t;
struct snw_play_list {
   uint32_t idx;
   uint32_t list[SNW_ICE_CHANNEL_USER_NUM_MAX];
};

typedef struct snw_ice_channel snw_ice_channel_t;
struct snw_ice_channel {
   uint32_t id;     //channelid
   uint32_t peerid; //owner's peerid

   uint32_t idx;
   uint32_t players[SNW_ICE_CHANNEL_USER_NUM_MAX];
};

int
snw_ice_channel_init(snw_ice_context_t *ctx);

snw_ice_channel_t*
snw_ice_channel_get(snw_ice_context_t *ctx, uint32_t id, int *is_new);

snw_ice_channel_t*
snw_ice_channel_search(snw_ice_context_t *ctx, uint32_t id);

snw_ice_channel_t*
snw_ice_channel_insert(snw_ice_context_t *ctx, snw_ice_channel_t *sitem);

int 
snw_ice_channel_remove(snw_ice_context_t *ctx, snw_ice_channel_t *sitem);

void
snw_print_channel_info(snw_ice_context_t *ctx, snw_ice_channel_t *c);

void
snw_channel_add_subscriber(snw_ice_context_t *ctx, uint32_t channelid, uint32_t flowid);

void
snw_channel_remove_subscriber(snw_ice_context_t *ctx, uint32_t channelid, uint32_t flowid);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_CHANNEL_H_
