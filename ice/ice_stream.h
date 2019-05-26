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

#ifndef _SNOW_ICE_STREAM_H_
#define _SNOW_ICE_STREAM_H_

#include <bsd/bsd.h>
#include <inttypes.h>

#include "core/core.h"
#include "ice/dtls.h"
#include "ice/ice_component.h"
#include "ice/ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_ice_stream {
   snw_ice_session_t *session;

   uint32_t id;
   uint32_t local_audio_ssrc;
   uint32_t local_video_ssrc;
   uint32_t remote_audio_ssrc;
   uint32_t remote_video_ssrc;

   int dtls_type;

   char remote_hashing[16];
   char remote_fingerprint[256];
   char remote_user[32];
   char remote_pass[64];

   ice_component_head_t  components;
   snw_ice_component_t  *rtp_component;
   snw_ice_component_t  *rtcp_component;

   uint8_t gathering_done:1;
   uint8_t is_disable:1;
   uint8_t is_video:1;
   uint8_t reserved:5;

   LIST_ENTRY(snw_ice_stream) list;
};
typedef LIST_HEAD(ice_stream_head, snw_ice_stream) ice_stream_head_t;

void
snw_ice_stream_mempool_init(snw_ice_context_t *ctx);

snw_ice_stream_t*
snw_ice_stream_allocate(snw_ice_context_t *ctx);

void
snw_ice_stream_deallocate(snw_ice_context_t *ctx, snw_ice_stream_t* p);

snw_ice_stream_t* 
snw_ice_stream_find(ice_stream_head_t *head, uint32_t id);

void
snw_ice_stream_insert(ice_stream_head_t *head, snw_ice_stream_t *item);

void
snw_ice_stream_free(ice_stream_head_t *streams, snw_ice_stream_t *stream);

void
snw_ice_stream_print_ssrc(snw_ice_context_t *ctx, snw_ice_stream_t *s, const char *info);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_STREAM_H_



