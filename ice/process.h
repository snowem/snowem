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

#ifndef _SNOW_ICE_PROCESS_H_
#define _SNOW_ICE_PROCESS_H_

#include "core/core.h"
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OPUS_PT   111
#define VP8_PT    100

void 
ice_setup_remote_candidates(snw_ice_session_t *session, uint32_t stream_id, uint32_t component_id);

void
ice_srtp_handshake_done(snw_ice_session_t *session, snw_ice_component_t *component);

void 
send_rtp_pkt(snw_ice_session_t *session, int control, int video, char* buf, int len);

void
snw_ice_create_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_connect_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_publish_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_play_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_stop_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_auth_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_control_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_sdp_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_candidate_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

void
snw_ice_fir_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_PROCESS_H_
