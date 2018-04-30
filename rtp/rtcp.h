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

#ifndef _SNOW_RTP_RTCP_H_
#define _SNOW_RTP_RTCP_H_

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>

#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTCP_VERSION      2
#define RTCP_LEN_IN_WORDS 4
#define RTCP_HDR_LEN      4
#define RTCP_PKT_NUM_MAX  31

/* rtcp payload type */
#define RTCP_FIR   192
#define RTCP_SR    200
#define RTCP_RR    201
#define RTCP_SDES  202
#define RTCP_BYE   203
#define RTCP_APP   204
 
#define RTCP_RTPFB 205
#define RTCP_RTPFB_GENERIC_FMT      1
#define RTCP_RTPFB_TPLR_FMT         7 //rfc 6642
#define RTCP_RTPFB_PAUSE_RESUME_FMT 9 //rfc 7728

#define RTCP_RTPFB_MSG_LEN     16

#define REPORT_BLOCK_LEN       24
#define RTCP_EMPTY_RR_MSG_LEN  (RTCP_HDR_LEN + 4)
#define RTCP_RR_MSG_LEN        (RTCP_HDR_LEN + 4 + REPORT_BLOCK_LEN)
#define RTCP_EMPTY_SR_MSG_LEN  (RTCP_HDR_LEN + 24)
#define RTCP_SR_MSG_LEN        (RTCP_HDR_LEN + 24 + REPORT_BLOCK_LEN)

/* see rfc4858, rfc5104 */
#define RTCP_PSFB  206
#define RTCP_PSFB_PLI_FMT       1
#define RTCP_PSFB_SLI_FMT       2
#define RTCP_PSFB_RPSI_FMT      3
#define RTCP_PSFB_FIR_FMT       4
#define RTCP_PSFB_TSTR_FMT      5
#define RTCP_PSFB_TSTN_FMT      6
#define RTCP_PSFB_VBCM_FMT      7
#define RTCP_PSFB_TPLR_FMT      8 // rfc 6642
// https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03
#define RTCP_PSFB_REMB_FMT      15 

#define RTCP_PSFB_PLI_MSG_LEN   12
#define RTCP_PSFB_FIR_MSG_LEN   20

/* sdes names */
#define RTCP_SDES_END   0
#define RTCP_SDES_CNAME 1
#define RTCP_SDES_NAME  2
#define RTCP_SDES_EMAIL 3
#define RTCP_SDES_PHONE 4
#define RTCP_SDES_LOC   5
#define RTCP_SDES_TOOL  6
#define RTCP_SDES_NOTE  7
#define RTCP_SDES_PRIV  8  

#pragma pack(push, 1)
typedef struct rtcp_hdr rtcp_hdr_t;
struct rtcp_hdr 
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t v:2;
	uint8_t p:1;
	uint8_t rc:5;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t rc:5;
	uint8_t p:1;
	uint8_t v:2;
#endif
	uint8_t  pt;
	uint16_t len;
};

typedef struct snw_report_block snw_report_block_t;
struct snw_report_block
{
	uint32_t ssrc;
#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t frac_lost:8;
	uint32_t cum_lost:24;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t cum_lost:24;
	uint32_t frac_lost:8;
#endif
	uint32_t hi_seqno;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t dlsr;
};

typedef struct snw_rtcp_sr snw_rtcp_sr_t;
struct snw_rtcp_sr
{
	uint32_t ssrc;
	uint64_t ntp_ts;
	uint32_t rtp_ts;
	uint32_t pkt_cnt;
	uint32_t byte_cnt;
	snw_report_block_t rb[1];
};

typedef struct snw_rtcp_rr snw_rtcp_rr_t;
struct snw_rtcp_rr
{
	uint32_t       ssrc;
	snw_report_block_t rb[1];
};

typedef struct snw_rtcp_nack snw_rtcp_nack_t;
struct snw_rtcp_nack
{
	uint16_t pid;
	uint16_t blp;
};

typedef struct snw_rtcp_fir snw_rtcp_fir_t;
struct snw_rtcp_fir
{
	uint32_t ssrc;
	uint32_t seqno;
};


typedef struct snw_rtcp_fb snw_rtcp_fb_t;
struct snw_rtcp_fb
{
	uint32_t ssrc;
	uint32_t media;
	union fci {
      snw_rtcp_nack_t nack[1];
      snw_rtcp_fir_t  fir[1];
   } fci;
};

typedef struct rtcp_pkt rtcp_pkt_t;
struct rtcp_pkt {
   rtcp_hdr_t hdr;
   union pkt {
      snw_rtcp_sr_t   sr;
      snw_rtcp_rr_t   rr;

      /* feedback msg */
      snw_rtcp_fb_t   fb;
   } pkt;
};
#pragma pack(pop)

void
print_rtcp_header(snw_log_t *log, char *buf, int buflen, const char *msg);

int
snw_rtcp_has_payload_type(char *buf, int len, int8_t type);

//TODO: move to rtp_utils.c/h?
uint32_t
snw_rtcp_get_ssrc(snw_rtp_ctx_t *ctx, char *buf, int len);

int
snw_rtcp_gen_fir(char *buf, int len, uint32_t local_ssrc, 
       uint32_t remote_ssrc, int seqnr);

int
snw_rtcp_gen_pli(char *buf, int len,
      uint32_t local_ssrc, uint32_t remote_ssrc);

uint32_t
snw_rtcp_gen_nack(char *buf, int len,
      uint32_t local_ssrc, uint32_t remote_ssrc, uint32_t payload);

uint32_t
snw_rtcp_gen_rr(char *buf, int len,
      uint32_t ssrc, snw_report_block_t *rb);

uint32_t
snw_rtcp_gen_sr(char *buf, int len, snw_rtcp_sr_t *sr);

#ifdef __cplusplus
}
#endif

#endif
