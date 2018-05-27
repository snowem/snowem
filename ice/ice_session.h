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

#ifndef _SNOW_ICE_SESSION_H_
#define _SNOW_ICE_SESSION_H_

#include <stdint.h>

#include "cice/agent.h"
#include "ice/ice_channel.h"
#include "ice/ice_stream.h"
#include "ice/ice_types.h"
#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif


enum {
   ICE_CONTROLLED_MODE = 0,
   ICE_CONTROLLING_MODE = 1,
};

enum {
   PEER_TYPE_UNKNOWN = 0,
   PEER_TYPE_PUBLISHER = 1,
   PEER_TYPE_PLAYER = 2,
   PEER_TYPE_P2P = 3,
};

struct snw_ice_session {
   uint32_t streamid;
   uint32_t flowid;
   uint32_t channelid;
   uint32_t publishid;

   snw_ice_context_t *ice_ctx;
   agent_t           *agent;
   int                stream_type;
   uint32_t           flags;

   int                streams_gathering_done;
   int                streams_num;
   int                control_mode;

   //snw_ice_stream_t   streams;
   ice_stream_head_t streams;
   snw_ice_stream_t  *audio_stream;
   snw_ice_stream_t  *video_stream;

   char              *local_sdp;
   char              *remote_sdp;

   int64_t            curtime;
   int64_t            lasttime;  //FIXME: remove it

   char remote_hashing[16];
   char remote_fingerprint[256];
   char remote_user[32];
   char remote_pass[64];

   snw_ice_channel_t  *channel;

   //rtp context
   snw_rtp_ctx_t       rtp_ctx;
};


int
snw_ice_session_init(snw_ice_context_t *ctx);

snw_ice_session_t*
snw_ice_session_get(snw_ice_context_t *ctx, uint32_t flowid, int *is_new);

snw_ice_session_t*
snw_ice_session_search(snw_ice_context_t *ctx, uint32_t flowid);

snw_ice_session_t*
snw_ice_session_insert(snw_ice_context_t *ctx, snw_ice_session_t *sitem);

int 
snw_ice_session_remove(snw_ice_context_t *ctx, snw_ice_session_t *sitem);

#ifdef __cplusplus
}
#endif


#endif //_SNOW_ICE_SESSION_H_


