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

#ifndef _SNOW_ICE_ICETYPES_H_
#define _SNOW_ICE_ICETYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct snw_ice_session snw_ice_session_t;
typedef struct snw_ice_stream snw_ice_stream_t;
typedef struct snw_ice_component snw_ice_component_t;
typedef struct snw_ice_context snw_ice_context_t;
typedef struct dtls_ctx dtls_ctx_t;

#define ICE_SESSION_SHM_KEY   0x091001
#define ICE_SESSION_HASHTIME  10
#define ICE_SESSION_HASHLEN   100

#define ICE_CHANNEL_SHM_KEY   0x091002
#define ICE_CHANNEL_HASHTIME  10
#define ICE_CHANNEL_HASHLEN   100

#define ENABLE_SNW_DEBUG
#define PRINT_CANDIDATE(c_)\
{\
   char address[SNW_ADDRESS_STRING_LEN];\
   int port = address_get_port(&(c_->addr));\
   address_to_string(&(c_->addr), (char *)&address);\
   DEBUG("Address:    %s:%d", address, port);\
   DEBUG("Priority:   %d", c_->priority);\
   DEBUG("Foundation: %s", c_->foundation);\
   DEBUG("Username:   %s", c_->username);\
   DEBUG("Password:   %s", c_->password);\
} while(0);

#define ICE_DEBUG2(...) do {} while(0)
#define ICE_ERROR2(...) do {} while(0)

#define ICE_BUFSIZE   8192
#define ICE_USEC_PER_SEC 10000

//status
#define WEBRTC_START           0x0001
#define WEBRTC_READY           0x0002

//features
#define WEBRTC_BUNDLE          0x0004
#define WEBRTC_RTCPMUX         0x0008
#define WEBRTC_TRICKLE         0x0010
#define WEBRTC_GATHER_DONE     0x0020
#define WEBRTC_AUDIO           0x0040
#define WEBRTC_VIDEO           0x0080

// client role
#define ICE_PUBLISHER          0x0100
#define ICE_SUBSCRIBER         0x0200
#define ICE_REPLAY             0x0400


#define IS_FLAG(f,i) ((f->flags & i) != 0)
#define SET_FLAG(f,i) (f->flags |= i)
#define CLEAR_FLAG(f,i) (f->flags &= ~i)


#define RTP_PROFILE       "RTP/SAVPF"
#define RTP_OPUS_FORMAT   "111"
#define RTP_VP8_FORMAT    "100"
#define NO_FORMAT         "0"

#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_ICETYPES_H_



