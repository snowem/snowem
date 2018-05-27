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
#ifndef _SNOW_CORE_CHANNEL_H_
#define _SNOW_CORE_CHANNEL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/queue.h>

#include "cache.h"
#include "types.h"

#define SNW_CORE_CHANNEL_USER_NUM_MAX 100
#define SNW_CORE_CHANNEL_STREAM_NUM_MAX 10
#define SNW_SUBCHANNEL_NUM_MAX 10

typedef struct snw_peer_list snw_peer_list_t;
struct snw_peer_list {
   uint32_t peers[SNW_CORE_CHANNEL_USER_NUM_MAX];
   LIST_ENTRY(snw_peer_list) list;
};
typedef LIST_HEAD(peerlist_head, snw_flow) peerlist_head_t;

/* Channel type */
enum {
   SNW_BCST_CHANNEL_TYPE = 0,
   SNW_CALL_CHANNEL_TYPE = 1,
   SNW_CONF_CHANNEL_TYPE = 2,
};

typedef struct snw_subchannel snw_subchannel_t;
struct snw_subchannel {
  uint32_t peerid;
  uint32_t channelid;
};

#define MAX_LIST_NUM 10
typedef struct snw_list snw_list_t;
struct snw_list {
  snw_list_t *next;
  uint32_t total;
  uint32_t idx;
  uint32_t list[MAX_LIST_NUM];
};

void
snw_list_add_item(snw_list_t *l, uint32_t id);

void
snw_list_remove_item(snw_list_t *l, uint32_t id);

typedef struct snw_channel snw_channel_t;
struct snw_channel {
   uint32_t id;       //channelid
   uint32_t type;     //channel type

   //TODO: remove the following block
   uint32_t flowid;   //owner's flowid
   uint32_t peerid;   //owner's peerid
   uint32_t parentid; //parent channel's id
   char     name[ROOM_NAME_LEN];
   snw_subchannel_t subchannels[SNW_SUBCHANNEL_NUM_MAX];
   int      idx;
   uint32_t peers[SNW_CORE_CHANNEL_USER_NUM_MAX];
   ///////////////////////////////////

   int        lastidx;
   uint32_t   flows[SNW_CORE_CHANNEL_USER_NUM_MAX];
   snw_list_t streams; //list of stream ids
};

snw_hashbase_t*
snw_channel_init();

snw_channel_t*
snw_channel_get(snw_hashbase_t *ctx, uint32_t id, int *is_new);

snw_channel_t*
snw_channel_search(snw_hashbase_t *ctx, uint32_t id);

snw_channel_t*
snw_channel_insert(snw_hashbase_t *ctx, snw_channel_t *sitem);

int 
snw_channel_remove(snw_hashbase_t *ctx, snw_channel_t *sitem);



#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_CHANNEL_H_
