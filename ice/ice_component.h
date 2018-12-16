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

#ifndef _SNOW_ICE_COMPONENT_H_
#define _SNOW_ICE_COMPONENT_H_

#include <stdint.h>

#include "cice/agent.h"
#include "core/bsd_queue.h"
#include "core/core.h"
#include "ice/dtls.h"
#include "ice/ice_types.h"
//#include "ice/vp8.h"
#include "rtp/packet.h"
#include "rtp/rtp.h"
#include "rtp/rtp_nack.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_ice_component {
   uint32_t          id;
   int               state;
   int               is_started;

   dtls_ctx_t       *dtls;
   snw_ice_stream_t *stream;
   candidate_head_t  remote_candidates;
   int64_t           fir_latest;
   uint8_t           fir_seq;

   //TODO: store them in rtp_nack module
   rtp_slidewin_t    a_slidewin;
   rtp_slidewin_t    v_slidewin;

   //callbacks
   void (*recv_sctp_data)(void *component, char *buffer, int len);

   LIST_ENTRY(snw_ice_component) list;
};
typedef LIST_HEAD(ice_component_head, snw_ice_component) ice_component_head_t;

void
snw_component_mempool_init(snw_ice_context_t *ctx);

snw_ice_component_t*
snw_component_allocate(snw_ice_context_t *ctx);

void
snw_component_deallocate(snw_ice_context_t *ctx, snw_ice_component_t* p);

snw_ice_component_t*
snw_component_find(ice_component_head_t *head, uint32_t id);

void
snw_component_insert(ice_component_head_t *head, snw_ice_component_t *item);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_COMPONENT_H_




