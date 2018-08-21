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

#ifndef _SNOW_RTP_RTP_H_
#define _SNOW_RTP_RTP_H_

#include "core/types.h"
#include "core/log.h"
#include "ice/ice.h"
#include "recording/recording.h"

#ifdef ENABLE_RTMP
#include "rtmp/rtmp.h"
#endif

#include "rtp/rtcp_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTP_VERSION         2
#define RTP_HEADER_SIZE     12
#define MIN_RTP_HEADER_SIZE RTP_HEADER_SIZE

#pragma pack(push, 1)
typedef struct rtp_hdr rtp_hdr_t;
struct rtp_hdr {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t v:2;
	uint16_t p:1;
	uint16_t x:1;
	uint16_t cc:4;
	uint16_t m:1;
	uint16_t pt:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t cc:4;
	uint16_t x:1;
	uint16_t p:1;
	uint16_t v:2;
	uint16_t pt:7;
	uint16_t m:1;
#endif
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
	uint32_t csrc[1];
};

/* RTP extension */
typedef struct rtp_hdr_ext rtp_hdr_ext_t;
struct rtp_hdr_ext {
	uint16_t type;
	uint16_t len;
};
#pragma pack(pop)


#define M_FLAGS_INIT (1<<0)

#define MODULE_SET_FLAG(m,flag) (m).flags &= flag;
#define MODULE_CLEAR_FLAG(m,flag) (m).flags &= ~flag;
#define MODULE_IS_FLAG(m,flag) ((m).flags & flag)

struct snw_rtp_module {
   const char  *name;
   void  *ctx;
   int    pkt_type;
   int    flags;
   int  (*init)(void *ctx);
   int  (*handle_pkg_in)(void *ctx, char *buffer, int len);
   int  (*handle_pkg_out)(void *ctx, char *buffer, int len);
   int  (*fini)();

   snw_rtp_module_t *next;
};

/* packet type */
#define   RTP_AUDIO  (1<<0)
#define   RTP_VIDEO  (1<<1)
#define   RTP_RTCP   (1<<2)
#define   RTP_RECORD (1<<3)

/* recoring commands */
#define RTP_RECORD_START 1
#define RTP_RECORD_STOP  2

typedef struct snw_record_cmd snw_record_cmd_t;
struct snw_record_cmd {
  uint32_t cmd;
  //to be defined
};

typedef struct snw_rtp_ctx snw_rtp_ctx_t;
struct snw_rtp_ctx {
   void      *session;
   void      *stream;
   void      *component;
   snw_log_t *log;

   int        pkt_type;
   int64_t    epoch_curtime;
   int64_t    ntp_curtime;

   rtcp_stats_head_t    sender_stats;
   rtcp_stats_head_t    receiver_stats;

   //callbacks
   void (*send_pkt)(void *ctx, int control, int video, char *buffer, int len);

   //recording setting
   snw_record_ctx_t     *record_ctx;

   //rtmp setting
#ifdef ENABLE_RTMP
   snw_rtmp_ctx_t     *rtmp_ctx;
#endif
};

int
snw_rtp_init(snw_ice_context_t *ctx);

void
print_rtp_header(snw_log_t *log, char *buf, int buflen, const char *msg);

int
snw_rtp_get_pkt_type(char* buf, int len);

int
snw_rtp_handle_pkg_in(snw_rtp_ctx_t *ctx, char *buffer, int len);

int
snw_rtp_handle_pkg_out(snw_rtp_ctx_t *ctx, char *buffer, int len);

int
snw_rtp_ctx_init(snw_rtp_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_RTP_H_



