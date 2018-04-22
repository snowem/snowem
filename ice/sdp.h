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

#ifndef _SNOW_ICE_SDP_H
#define _SNOW_ICE_SDP_H
   
#include <inttypes.h>
#include <sofia-sip/sdp.h>

#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ice_sdp_attr ice_sdp_attr_t;
struct ice_sdp_attr {
   int audio;
   int video;
   //int data;
   int bundle;
   int rtcpmux;
   int trickle;
};

int
snw_ice_sdp_init(snw_ice_context_t *ctx);

void
snw_ice_sdp_deinit(void);

int
snw_ice_get_sdp_attr(snw_ice_context_t *ctx, const char *sdp, ice_sdp_attr_t *sdp_attr);

sdp_parser_t*
snw_ice_sdp_get_parser(snw_ice_context_t *ctx, const char *sdp);

int 
snw_ice_sdp_handle_answer(snw_ice_session_t *session, const char *sdp);

char*
snw_ice_sdp_create(snw_ice_session_t *session);

int
snw_ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate/*, int trickle*/);

void 
snw_ice_try_start_component(snw_ice_session_t *session, snw_ice_stream_t *stream, 
      snw_ice_component_t *component, candidate_t *candidate);

candidate_t*
snw_ice_remote_candidate_new(char *type, char *transport);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_SDP_H_


