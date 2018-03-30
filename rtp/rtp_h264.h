#ifndef _SNOW_RTP_H264_H_
#define _SNOW_RTP_H264_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rtp/rtp.h"

/* h264 payload type */
#define H264_PT_RSV0        0
#define H264_PT_NAT_UNIT_1  1
#define H264_PT_NAT_UNIT_2  2
#define H264_PT_NAT_UNIT_3  3
#define H264_PT_NAT_UNIT_4  4
#define H264_PT_NAT_UNIT_5  5
#define H264_PT_NAT_UNIT_6  6
#define H264_PT_NAT_UNIT_7  7
#define H264_PT_NAT_UNIT_8  8
#define H264_PT_NAT_UNIT_9  9
#define H264_PT_NAT_UNIT_10 10
#define H264_PT_NAT_UNIT_11 11
#define H264_PT_NAT_UNIT_12 12
#define H264_PT_NAT_UNIT_13 13
#define H264_PT_NAT_UNIT_14 14
#define H264_PT_NAT_UNIT_15 15
#define H264_PT_NAT_UNIT_16 16
#define H264_PT_NAT_UNIT_17 17
#define H264_PT_NAT_UNIT_18 18
#define H264_PT_NAT_UNIT_19 19
#define H264_PT_NAT_UNIT_20 20
#define H264_PT_NAT_UNIT_21 21
#define H264_PT_NAT_UNIT_22 22
#define H264_PT_NAT_UNIT_23 23
#define H264_PT_STAPA       24
#define H264_PT_STAPB       25
#define H264_PT_MTAP16      26
#define H264_PT_MTAP24      27
#define H264_PT_FUA         28
#define H264_PT_FUB         29
#define H264_PT_RSV1        30
#define H264_PT_RSV2        31

#pragma pack(push, 1)
typedef struct fua_indicator fua_indicator_t;
struct fua_indicator {
#if __BYTE_ORDER == __BIG_ENDIAN
   uint8_t f:1;
   uint8_t nir:2;
   uint8_t type:5;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t type:5;
   uint8_t nir:2;
   uint8_t f:1;
#endif
};

typedef struct fua_hdr fua_hdr_t;
struct fua_hdr {
#if __BYTE_ORDER == __BIG_ENDIAN
   uint8_t s:1;
   uint8_t e:1;
   uint8_t r:1;
   uint8_t type:5;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t type:5;
   uint8_t r:1;
   uint8_t e:1;
   uint8_t s:1;
#endif
};
#pragma pack(pop)

int snw_rtp_h264_init(void *ctx);
int snw_rtp_h264_handle_pkg_in(void *ctx, char *buffer, int len);
int snw_rtp_h264_handle_pkg_out(void *ctx, char *buffer, int len);
int snw_rtp_h264_fini();

extern snw_rtp_module_t g_rtp_h264_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_H264_H_



